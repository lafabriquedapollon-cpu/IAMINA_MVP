import 'dart:convert';

import 'package:drift/drift.dart';
import 'package:uuid/uuid.dart';

import '../../core/domain/glucose_quantity_evidence.dart';
import '../../core/domain/glucose_quantity_storage_envelope.dart';
import 'database.dart';

/// D5-06a isolated persistence candidate. This is NOT an admission guard.
/// Only synthetic native owner fixtures are permitted here. Do not expose
/// the database or this store to widgets, network sync, or patient runtime.
/// A future migration requires D1's durable admission and deletion contract.
final class GlucoseQuantityCandidateStore {
  final AppDatabase _db;
  final int _owner;
  final String _vaultId;
  GlucoseQuantityCandidateStore._(this._db, this._owner, this._vaultId);

  static const _tables = {
    'd5_glucose_evidence_candidate_v1',
    'd5_glucose_vault_identity_v1',
    'd5_glucose_tombstones_v1',
  };
  static final _uuidPattern = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
  );

  /// Explicit initialization is permitted only for an empty synthetic vault.
  /// Reopening never repairs missing tables or reassigns an existing owner.
  /// The marker detects accidental file misassociation, not malicious SQL.
  static Future<GlucoseQuantityCandidateStore> openSynthetic(
    AppDatabase db, {
    bool initialize = false,
  }) async {
    final owner = db.patientVaultScope?.nativeDjangoUserId;
    if (owner == null || !{900001, 900002}.contains(owner)) {
      throw StateError('Synthetic isolated owner required');
    }
    return db.transaction(() async {
      final rows = await db.customSelect(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
        "('d5_glucose_evidence_candidate_v1', 'd5_glucose_vault_identity_v1', 'd5_glucose_tombstones_v1')",
      ).get();
      final present = rows.map((r) => r.read<String>('name')).toSet();
      if (initialize) {
        if (present.isNotEmpty) throw StateError('Candidate vault already initialized or incomplete');
        // Do not adopt any existing clinical rows (including legacy data).
        for (final table in const [
          'log_entries', 'patient_profiles', 'chat_messages',
          'medication_events', 'reminders', 'patient_treatment_declarations_v1',
        ]) {
          if ((await db.customSelect('SELECT 1 FROM $table LIMIT 1').get()).isNotEmpty) {
            throw StateError('Nonempty vault cannot be initialized');
          }
        }
        await db.customStatement('''
          CREATE TABLE d5_glucose_vault_identity_v1 (
            singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
            owner_id INTEGER NOT NULL CHECK (owner_id IN (900001, 900002)),
            vault_id TEXT NOT NULL UNIQUE
          )
        ''');
        await db.customStatement('''
          CREATE TABLE d5_glucose_evidence_candidate_v1 (
            client_uuid TEXT NOT NULL PRIMARY KEY,
            owner_id INTEGER NOT NULL CHECK (owner_id IN (900001, 900002)),
            envelope_json TEXT NOT NULL
          )
        ''');
        await db.customStatement('''
          CREATE TABLE d5_glucose_tombstones_v1 (
            client_uuid TEXT NOT NULL PRIMARY KEY,
            owner_id INTEGER NOT NULL CHECK (owner_id IN (900001, 900002))
          )
        ''');
        await db.customStatement(
          'INSERT INTO d5_glucose_vault_identity_v1 (singleton, owner_id, vault_id) VALUES (1, ?, ?)',
          [owner, const Uuid().v4()],
        );
      } else if (present.length != _tables.length || !present.containsAll(_tables)) {
        throw StateError('Candidate vault incomplete or uninitialized');
      }
      final identity = await db.customSelect(
        'SELECT singleton, owner_id, vault_id FROM d5_glucose_vault_identity_v1',
      ).get();
      if (identity.length != 1 || identity.single.read<int>('singleton') != 1 ||
          identity.single.read<int>('owner_id') != owner ||
          !_uuidPattern.hasMatch(identity.single.read<String>('vault_id'))) {
        throw StateError('Candidate vault identity mismatch');
      }
      for (final table in const [
        'd5_glucose_evidence_candidate_v1', 'd5_glucose_tombstones_v1',
      ]) {
        final foreign = await db.customSelect(
          'SELECT 1 FROM $table WHERE owner_id != ? LIMIT 1',
          variables: [Variable<int>(owner)],
        ).get();
        if (foreign.isNotEmpty) throw StateError('Evidence owner mismatch');
      }
      return GlucoseQuantityCandidateStore._(
        db, owner, identity.single.read<String>('vault_id'),
      );
    });
  }

  Future<void> _checkIdentity() async {
    final rows = await _db.customSelect(
      'SELECT singleton, owner_id, vault_id FROM d5_glucose_vault_identity_v1',
    ).get();
    if (rows.length != 1 || rows.single.read<int>('singleton') != 1 ||
        rows.single.read<int>('owner_id') != _owner ||
        rows.single.read<String>('vault_id') != _vaultId) {
      throw StateError('Candidate vault identity mismatch');
    }
  }

  Future<bool> _isDeleted(String uuid) async {
    final rows = await _db.customSelect(
      'SELECT owner_id FROM d5_glucose_tombstones_v1 WHERE client_uuid = ?',
      variables: [Variable<String>(uuid)],
    ).get();
    if (rows.isEmpty) return false;
    if (rows.length != 1 || rows.single.read<int>('owner_id') != _owner) {
      throw StateError('Tombstone owner mismatch');
    }
    return true;
  }

  Future<LogEntryData?> _log(String uuid) =>
      (_db.select(_db.logEntries)..where((r) => r.clientUuid.equals(uuid)))
          .getSingleOrNull();

  Future<List<QueryRow>> _rows(String uuid) => _db.customSelect(
    'SELECT owner_id, envelope_json FROM d5_glucose_evidence_candidate_v1 WHERE client_uuid = ?',
    variables: [Variable<String>(uuid)],
  ).get();

  /// Never attach evidence to an existing legacy UUID or overwrite a reading.
  /// Both rows commit together or neither does.
  Future<void> insert({
    required String uuid,
    required DateTime loggedAt,
    required GlucoseQuantityEvidence evidence,
  }) async {
    final envelope = GlucoseQuantityStorageEnvelope.encode(
      clientUuid: uuid, evidence: evidence,
    );
    final canonical = evidence.canonicalMgDl!;
    await _db.transaction(() async {
      await _checkIdentity();
      if (await _isDeleted(uuid)) throw StateError('Deleted measurement identity');
      if (await _log(uuid) != null || (await _rows(uuid)).isNotEmpty) {
        throw StateError('Existing measurement identity');
      }
      await _db.into(_db.logEntries).insert(LogEntriesCompanion.insert(
        clientUuid: uuid, createdAt: loggedAt.toUtc(),
        loggedAt: Value(loggedAt.toUtc()), bloodSugar: canonical,
        source: const Value('manual'),
        // Deliberately excluded from the legacy pending-sync query.
        syncStatus: const Value('d5_candidate_local'),
      ));
      await _db.customStatement('''
        INSERT INTO d5_glucose_evidence_candidate_v1
          (client_uuid, owner_id, envelope_json) VALUES (?, ?, ?)
      ''', [uuid, _owner, jsonEncode(envelope)]);
    });
  }

  /// Legacy rows return unclassified evidence. Corrupt, orphaned, mismatched
  /// or candidate rows with missing metadata fail closed instead.
  Future<GlucoseQuantityEvidence?> read(String uuid) =>
      _db.transaction(() async {
        await _checkIdentity();
        final row = await _log(uuid);
        final metadata = await _rows(uuid);
        if (await _isDeleted(uuid)) {
          if (row != null || metadata.isNotEmpty) {
            throw StateError('Deleted measurement reappeared');
          }
          return null;
        }
        if (metadata.isEmpty) {
          if (row?.syncStatus == 'd5_candidate_local') {
            throw StateError('Candidate evidence missing');
          }
          return row == null ? null :
              GlucoseQuantityEvidence.unknownLegacy(storedValue: row.bloodSugar);
        }
        if (row == null || metadata.length != 1 ||
            metadata.single.read<int>('owner_id') != _owner ||
            row.syncStatus != 'd5_candidate_local' || row.source != 'manual') {
          throw StateError('Evidence association mismatch');
        }
        final json = jsonDecode(metadata.single.read<String>('envelope_json'));
        if (json is! Map<String, dynamic>) {
          throw const FormatException('Invalid glucose envelope');
        }
        final evidence = GlucoseQuantityStorageEnvelope.decode(
          expectedClientUuid: uuid, envelope: Map<String, Object?>.from(json),
        )!;
        if (evidence.canonicalMgDl != row.bloodSugar) {
          throw StateError('Canonical measurement mismatch');
        }
        return evidence;
      });

  /// A legacy record is never deleted through this candidate port.
  Future<void> delete(String uuid) => _db.transaction(() async {
    final evidence = await read(uuid);
    if (evidence == null || !evidence.hasExplicitSourceUnit) {
      throw StateError('Candidate measurement required');
    }
    await _db.customStatement(
      'INSERT INTO d5_glucose_tombstones_v1 (client_uuid, owner_id) VALUES (?, ?)',
      [uuid, _owner],
    );
    await _db.customStatement(
      'DELETE FROM d5_glucose_evidence_candidate_v1 WHERE client_uuid = ? AND owner_id = ?',
      [uuid, _owner],
    );
    final removed = await (_db.delete(_db.logEntries)
        ..where((r) => r.clientUuid.equals(uuid))).go();
    if (removed != 1) throw StateError('Measurement deletion mismatch');
  });
}
