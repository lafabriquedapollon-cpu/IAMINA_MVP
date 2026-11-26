import 'dart:convert';

import 'package:drift/drift.dart';

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
  GlucoseQuantityCandidateStore._(this._db, this._owner);

  static Future<GlucoseQuantityCandidateStore> openSynthetic(AppDatabase db) async {
    final owner = db.patientVaultScope?.nativeDjangoUserId;
    if (owner == null || !{900001, 900002}.contains(owner)) {
      throw StateError('Synthetic isolated owner required');
    }
    final store = GlucoseQuantityCandidateStore._(db, owner);
    await db.transaction(() async {
      await db.customStatement('''
        CREATE TABLE IF NOT EXISTS d5_glucose_evidence_candidate_v1 (
          client_uuid TEXT NOT NULL PRIMARY KEY,
          owner_id INTEGER NOT NULL CHECK (owner_id IN (900001, 900002)),
          envelope_json TEXT NOT NULL
        )
      ''');
      final foreign = await db.customSelect(
        'SELECT 1 FROM d5_glucose_evidence_candidate_v1 WHERE owner_id != ? LIMIT 1',
        variables: [Variable<int>(owner)],
      ).get();
      if (foreign.isNotEmpty) throw StateError('Evidence owner mismatch');
    });
    return store;
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
        final row = await _log(uuid);
        final metadata = await _rows(uuid);
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
      'DELETE FROM d5_glucose_evidence_candidate_v1 WHERE client_uuid = ? AND owner_id = ?',
      [uuid, _owner],
    );
    final removed = await (_db.delete(_db.logEntries)
        ..where((r) => r.clientUuid.equals(uuid))).go();
    if (removed != 1) throw StateError('Measurement deletion mismatch');
  });
}
