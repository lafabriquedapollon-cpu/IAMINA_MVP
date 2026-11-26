// D1-I1 synthetic browser executable only. No real auth, legacy storage,
// clinical providers, network API, or production vault admission.
import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:amina/data/drift/database.dart';
import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/core/domain/glucose_quantity_storage_envelope.dart';
import 'package:amina/core/domain/glucose_display_projection.dart';
import 'package:amina/data/drift/patient_vault_scope.dart';
import 'package:amina/data/drift/patient_treatment_declaration_store.dart';
import 'package:drift/drift.dart';
import 'package:drift/wasm.dart';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show listEquals;
import 'package:amina/services/auth_service.dart';
import 'package:amina/services/app_lock_service.dart';
import 'package:amina/services/d1_admission_guard_adapter.dart';
import 'package:amina/services/app_lock_authenticator.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sqlite3/wasm.dart';

@JS('d1Snapshot')
external set _snapshotFn(JSFunction function);
@JS('d1Mutate')
external set _mutateFn(JSFunction function);
@JS('d1LegacySnapshot')
external set _legacyFn(JSFunction function);
@JS('d1FullInspect')
external set _fullInspectFn(JSFunction function);
@JS('d1Inspect')
external set _inspectFn(JSFunction function);
@JS('d1GlucoseDeleted')
external set _glucoseDeletedFn(JSFunction function);
@JS('d1GlucoseChange')
external set _glucoseChangeFn(JSFunction function);
@JS('d1JournalPage')
external set _journalPageFn(JSFunction function);
@JS('d1GlucoseRead')
external set _glucoseReadFn(JSFunction function);
@JS('d1GlucoseInsert')
external set _glucoseInsertFn(JSFunction function);
@JS('d1EvidenceRead')
external set _evidenceReadFn(JSFunction function);
@JS('d1EvidenceChange')
external set _evidenceChangeFn(JSFunction function);
@JS('d1EvidenceState')
external set _evidenceStateFn(JSFunction function);
@JS('d1TreatmentRead')
external set _treatmentReadFn(JSFunction function);
@JS('d1TreatmentChange')
external set _treatmentChangeFn(JSFunction function);

// This synthetic entrypoint is built only by the isolated browser harness.
@JS('d1BoundLogin')
external set _boundLoginFn(JSFunction function);
@JS('d1BoundProof')
external set _boundProofFn(JSFunction function);
@JS('d1BoundEpoch')
external set _boundEpochFn(JSFunction function);
@JS('d1BoundLock')
external set _boundLockFn(JSFunction function);

const _fixtureCredential = AppLockCredential(
  credentialId: 'synthetic-bound-credential', publicKeySpki: 'fixture',
  rpId: 'localhost', origin: 'https://localhost', signCount: 1,
);

class _MemorySecureStorage implements FlutterSecureStorage {
  final Map<String, String> values = {
    'iamina_app_lock_credential_v1': _fixtureCredential.encode(),
    'iamina_app_lock_required_v1': 'required',
  };
  Future<String?> _read(String key) async => values[key];
  Future<void> _write(String key, String? value) async {
    if (value == null) { values.remove(key); } else { values[key] = value; }
  }
  Future<void> _delete(String key) async { values.remove(key); }
  @override
  dynamic noSuchMethod(Invocation invocation) {
    final key = invocation.namedArguments[#key];
    if (key is String) {
      if (invocation.memberName == #read) return _read(key);
      if (invocation.memberName == #write) {
        return _write(key, invocation.namedArguments[#value] as String?);
      }
      if (invocation.memberName == #delete) return _delete(key);
    }
    return super.noSuchMethod(invocation);
  }
}

class _ProbeAuthenticator implements AppLockAuthenticator {
  int counter = 1;
  @override
  Future<AppLockCapability> capability() async => AppLockCapability.supported;
  @override
  Future<AppLockCredential> enroll() async => _fixtureCredential;
  @override
  Future<AppLockAssertion> unlock(AppLockCredential credential) async =>
      AppLockAssertion(signCount: ++counter);
}

AuthService? _boundAuth;
AppLockService? _boundLock;

Future<void> _boundLogin(int owner) async {
  _require(_owners.contains(owner), 'Synthetic owner required');
  if (_boundAuth == null) {
    final storage = _MemorySecureStorage();
    final auth = AuthService(storage: storage, httpClient: MockClient((request) async {
      final email = jsonDecode(request.body)['email'];
      final id = email == 'a@example.invalid' ? 900001 :
          email == 'b@example.invalid' ? 900002 : null;
      if (id == null || !request.url.path.endsWith('/auth/login')) {
        return http.Response('{}', 403);
      }
      return http.Response(jsonEncode({
        'access_token': 'iamina.fixture_$id:abc123:signature_$id',
        'user': {'id': id},
      }), 200);
    }));
    await auth.initialize();
    final lock = AppLockService(authService: auth, storage: storage,
        authenticator: _ProbeAuthenticator());
    await lock.initialize();
    _boundAuth = auth;
    _boundLock = lock;
  }
  await _boundAuth!.signInWithEmail(
      owner == 900001 ? 'a@example.invalid' : 'b@example.invalid', 'synthetic');
}

Future<JSFunction> _boundProof(int owner) async {
  final lock = _boundLock!;
  final ticket = await lock.issueVaultAdmissionProof();
  final guard = lock.consumeVaultAdmissionProof(ticket, owner: owner);
  final adapter = D1AdmissionGuardAdapter(guard);
  return ((JSString phase, JSNumber id, JSNumber epoch, JSFunction? callback) {
    final o = id.toDartDouble, e = epoch.toDartDouble;
    bool valid(double n) => n.isFinite && n > 0 &&
        n <= 9007199254740991 && n == n.truncateToDouble();
    if (!valid(o) || !valid(e)) return false.toJS;
    return adapter.dispatch(phase.toDart, o.toInt(), e.toInt(),
        onRetired: callback == null ? null : () { callback.callAsFunction(); }).toJS;
  }).toJS;
}

const _filename = 'vault.sqlite';
const _path = '/vault.sqlite';
const _marker = 'D1_I1_SYNTHETIC_NOT_PATIENT';
const _glucoseMarker = 'D1_I5C_SYNTHETIC_GLUCOSE';
const _evidenceMarker = 'CONV_02_SYNTHETIC_EXPLICIT_GLUCOSE';
const _evidenceTable = 'd1_d5_fixture_evidence_v1';
const _evidenceDeletedTable = 'd1_d5_fixture_deleted_v1';
const _evidenceReceiptTable = 'd1_d5_fixture_receipt_v1';
final _fixtureUuid = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
const _owners = [900001, 900002];

void _require(bool value, String reason) {
  if (!value) throw StateError(reason);
}

class _MemoryVault {
  final InMemoryFileSystem fs;
  final AppDatabase db;
  final int owner;
  _MemoryVault(this.fs, this.db, this.owner);

  static Future<_MemoryVault> open(int owner, Uint8List? input) async {
    _require(_owners.contains(owner), 'Synthetic scope required');
    final sqlite = await WasmSqlite3.loadFromUrl(Uri.base.resolve('sqlite3.wasm'));
    final fs = InMemoryFileSystem();
    sqlite.registerVirtualFileSystem(fs, makeDefault: true);
    if (input != null) {
      _require(input.length >= 100 && input.length <= 32 * 1024 * 1024,
          'Invalid SQLite input');
      final file = fs.xOpen(Sqlite3Filename(_path),
          SqlFlag.SQLITE_OPEN_CREATE | SqlFlag.SQLITE_OPEN_READWRITE).file;
      try {
        file.xWrite(input, 0);
      } finally {
        file.xClose();
      }
      // Validate the decrypted file before Drift can run migrations.
      final raw = sqlite.open(_filename, mode: OpenMode.readOnly);
      try {
        _require(raw.select('PRAGMA integrity_check').single.values.single == 'ok',
            'Integrity failure');
        _require(raw.select('PRAGMA user_version').single.values.single == 12,
            'Unexpected schema');
        final owners = raw.select('SELECT user_id FROM patient_profiles');
        _require(owners.length == 1 && owners.single['user_id'] == owner,
            'Wrong SQLite owner');
      } finally {
        raw.dispose();
      }
    }
    final scope = PatientVaultScope.nativeDjango(owner);
    final db = AppDatabase.testPatientVault(
      WasmDatabase(sqlite3: sqlite, path: _filename), scope,
    );
    return _MemoryVault(fs, db, owner);
  }

  Future<Map<String, Object?>> inspect() async {
    final profiles = await db.select(db.patientProfiles).get();
    _require(profiles.length == 1 && profiles.single.userId == owner,
        'Profile owner mismatch');
    final rows = await db.select(db.logEntries).get();
    _require(rows.isNotEmpty &&
        rows.every((row) =>
          (row.mealDescription == _marker && row.clientUuid.startsWith('d1-i1-$owner-')) ||
          (row.mealDescription == _glucoseMarker && _fixtureUuid.hasMatch(row.clientUuid) &&
           row.source == 'manual' && row.bloodSugar.isFinite && row.bloodSugar > 0 &&
           row.loggedAt != null && row.insulinUnits == null && row.syncStatus == 'pending') ||
          (row.mealDescription == _evidenceMarker && _fixtureUuid.hasMatch(row.clientUuid) &&
           row.source == 'manual' && row.bloodSugar.isFinite && row.bloodSugar > 0 &&
           row.loggedAt != null && row.insulinUnits == null && row.syncStatus == 'd5_candidate_local')), 'Synthetic rows mismatch');
    await _validateEvidenceRows(db, owner, rows);
    await _validateEvidenceMutationState(db, owner, rows);
    if (await _hasTombstones(db)) {
      final deleted = await db.customSelect('SELECT uuid FROM d1_fixture_deleted_glucose ORDER BY uuid').get();
      for (final entry in deleted) {
        final uuid = entry.data['uuid'];
        _require(uuid is String && _fixtureUuid.hasMatch(uuid) &&
            await _fixtureGlucose(db, uuid) == null, 'Invalid tombstone');
      }
    }
    final integrity = await db.customSelect('PRAGMA integrity_check').getSingle();
    final schema = await db.customSelect('PRAGMA user_version').getSingle();
    _require(integrity.data.values.single == 'ok' &&
        schema.data.values.single == 12, 'Schema or integrity failure');
    return {
      'owner': owner, 'schema': 12, 'integrity': 'ok',
      'rows': rows.length,
      'raw': rows.map((row) => row.bloodSugar).toList()..sort(),
      'ids': rows.map((row) => row.clientUuid).toList()..sort(),
    };
  }

  void wipe() {
    // Best-effort memory cleanup, not a guarantee of JS/WASM memory erasure.
    for (final buffer in fs.fileData.values) {
      if (buffer != null) buffer.fillRange(0, buffer.length, 0);
    }
    fs.fileData.clear();
  }
}

Future<Uint8List> _snapshot(Uint8List? previous, int owner, [String? operation]) async {
  if (operation != null) {
    _require(RegExp(r'^[a-z0-9-]{8,64}$').hasMatch(operation), 'Invalid operation ID');
    _require(previous != null, 'Existing checkpoint required');
  }
  final vault = await _MemoryVault.open(owner, previous);
  var closed = false;
  try {
    final db = vault.db;
    if (previous != null) await vault.inspect();
    await db.transaction(() async {
      if (previous == null) {
        await db.into(db.patientProfiles).insert(PatientProfilesCompanion.insert(
          userId: Value(owner), updatedAt: DateTime.utc(2026, 11, 25),
        ));
      }
      final next = await db.countLogs() + 1;
      final id = operation == null ? 'd1-i1-$owner-$next' : 'd1-i1-$owner-op-$operation';
      _require((await (db.select(db.logEntries)..where((row) => row.clientUuid.equals(id))).get()).isEmpty,
          'Duplicate operation');
      await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
        createdAt: DateTime.utc(2026, 11, 25, 0, next),
        bloodSugar: 100.25 + next,
        clientUuid: id,
        mealDescription: const Value(_marker),
      ));
    });
    await vault.inspect();
    await db.close();
    closed = true;
    // SQLite is closed: no outstanding transaction or journal is serialized.
    _require(vault.fs.fileData.keys.every((key) => key == _path),
        'Unexpected SQLite auxiliary file');
    final bytes = vault.fs.fileData[_path];
    _require(bytes != null && bytes.length >= 100, 'Missing SQLite file');
    return Uint8List.fromList(bytes!);
  } finally {
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<String> _inspect(Uint8List bytes, int owner) async {
  final vault = await _MemoryVault.open(owner, bytes);
  try {
    return jsonEncode(await vault.inspect());
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// A populated owner-scoped v12 fixture. No historical real data is read.
Future<Uint8List> _legacySnapshot(int owner) async {
  final initial = await _snapshot(null, owner);
  final vault = await _MemoryVault.open(owner, initial);
  var closed = false;
  try {
    final db = vault.db;
    await db.transaction(() async {
      await db.customStatement("UPDATE patient_profiles SET preferred_language = 'ar', unit_preference = 'mg/dL' WHERE user_id = ?", [owner]);
      await db.customStatement("UPDATE log_entries SET sync_status = 'pending', sync_attempts = 2 WHERE client_uuid = ?", ['d1-i1-$owner-1']);
      await db.customStatement("INSERT INTO chat_messages (conversation_id, role, message, created_at) VALUES (?, ?, ?, ?)", ['synthetic-conversation', 'user', _marker, 1795564800]);
      await db.customStatement("INSERT INTO medication_events (label, dose, unit, taken_at, created_at) VALUES (?, ?, ?, ?, ?)", ['synthetic-medication', 1.25, 'synthetic-unit', 1795564800, 1795564800]);
      await db.customStatement("INSERT INTO reminders (title, due_at, enabled, created_at) VALUES (?, ?, ?, ?)", [_marker, 1795564800, 0, 1795564800]);
      await db.customStatement("INSERT INTO patient_treatment_declarations_v1 (user_id, declaration_state, codes_json, provenance, updated_at_utc, sync_status, local_generation) VALUES (?, ?, ?, ?, ?, ?, ?)", [owner, 'unsure', '[]', 'patient_declared', '2026-11-25T00:00:00Z', 'pending', 3]);
    });
    await vault.inspect();
    await db.close();
    closed = true;
    _require(vault.fs.fileData.keys.every((key) => key == _path),
        'Unexpected SQLite auxiliary file');
    return Uint8List.fromList(vault.fs.fileData[_path]!);
  } finally {
    initial.fillRange(0, initial.length, 0);
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<String> _fullInspect(Uint8List bytes, int owner) async {
  final vault = await _MemoryVault.open(owner, bytes);
  try {
    await vault.inspect();
    final db = vault.db;
    final tables = <String, List<Map<String, Object?>>>{};
    for (final table in [
      'patient_profiles','log_entries','chat_messages','medication_events',
      'reminders','patient_treatment_declarations_v1',
    ]) {
      tables[table] = (await db.customSelect('SELECT * FROM $table ORDER BY 1').get())
          .map((r) => r.data).toList();
    }
    if (await _hasTombstones(db)) {
      tables[_tombstoneTable] = (await db.customSelect(
          'SELECT uuid FROM d1_fixture_deleted_glucose ORDER BY uuid').get())
          .map((r) => r.data).toList();
    }
    if (await _hasEvidence(db)) {
      tables[_evidenceTable] = (await db.customSelect('SELECT * FROM $_evidenceTable ORDER BY client_uuid').get()).map((r) => r.data).toList();
    }
    for (final table in [_evidenceDeletedTable, _evidenceReceiptTable]) {
      if (await _hasFixtureTable(db, table)) {
        tables[table] = (await db.customSelect('SELECT * FROM $table ORDER BY 1').get()).map((r) => r.data).toList();
      }
    }
    _require(tables['patient_profiles']!.length == 1 &&
        tables['patient_profiles']!.single['user_id'] == owner,
        'Profile owner mismatch');
    _require(tables['patient_treatment_declarations_v1']!.every((r) => r['user_id'] == owner),
        'Treatment declaration owner mismatch');
    _require((await db.customSelect('PRAGMA foreign_key_check').get()).isEmpty,
        'Foreign key check failed');
    return jsonEncode(tables);
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Map<String, Object?>? _declarationJson(PatientTreatmentDeclarationRecord? record) {
  if (record == null) return null;
  return {
    'owner': record.ownerId, 'state': record.state, 'codes': record.codes,
    'generation': record.localGeneration, 'syncStatus': record.syncStatus,
    'version': record.version, 'provenance': record.provenance,
  };
}

// Isolated synthetic bridge to the real patient-declaration store. No DB
// escapes the operation; no network, provider, or clinical recommendation.
Future<String> _readTreatment(Uint8List input, int owner) async {
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final record = await PatientTreatmentDeclarationStore(vault.db).read();
    _require(record == null || record.ownerId == owner, 'Declaration owner mismatch');
    return jsonEncode(_declarationJson(record));
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<Uint8List> _changeTreatment(
    Uint8List input, int owner, String state, String codesJson) async {
  final raw = jsonDecode(codesJson);
  _require(raw is List && raw.every((item) => item is String), 'Invalid codes');
  final codes = (raw as List).cast<String>().toList(growable: false);
  validatePatientTreatmentDeclarationV1(state: state, codes: codes);
  final vault = await _MemoryVault.open(owner, input);
  var closed = false;
  try {
    await vault.inspect();
    final store = PatientTreatmentDeclarationStore(vault.db);
    final before = await store.read();
    // This tranche has no conflict resolution or remote synchronization.
    _require(before == null || (before.ownerId == owner && before.syncStatus == 'pending'),
        'Unsupported declaration sync state');
    await store.write(state: state, codes: codes);
    final after = await store.read();
    _require(after != null && after.ownerId == owner && after.state == state &&
        listEquals(after.codes, codes) && after.localGeneration == (before?.localGeneration ?? 0) + 1 &&
        after.syncStatus == 'pending', 'Declaration invariant failed');
    await vault.inspect();
    await vault.db.close();
    closed = true;
    _require(vault.fs.fileData.keys.every((key) => key == _path),
        'Unexpected SQLite auxiliary file');
    return Uint8List.fromList(vault.fs.fileData[_path]!);
  } finally {
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// Bounded, snapshot-local journal query. Legacy rows have no explicit
// source-unit evidence and are excluded, not silently interpreted as mg/dL.
Future<String> _journalPage(Uint8List input, int owner, int start, int end,
    int limit, int offset) async {
  _require(start > 0 && end > start && end <= 4102444800 &&
      limit >= 1 && limit <= 50 && offset >= 0 && offset <= 10000,
      'Invalid journal range');
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final db = vault.db;
    final from = DateTime.fromMillisecondsSinceEpoch(start * 1000, isUtc: true);
    final until = DateTime.fromMillisecondsSinceEpoch(end * 1000, isUtc: true);
    final rows = await (db.select(db.logEntries)
      ..where((t) => t.mealDescription.equals(_glucoseMarker) &
          t.loggedAt.isBiggerOrEqualValue(from) & t.loggedAt.isSmallerThanValue(until))
      ..orderBy([
        (t) => OrderingTerm(expression: t.loggedAt, mode: OrderingMode.desc),
        (t) => OrderingTerm(expression: t.createdAt, mode: OrderingMode.desc),
        (t) => OrderingTerm(expression: t.clientUuid, mode: OrderingMode.asc),
      ])
      ..limit(limit + 1, offset: offset)).get();
    for (final row in rows) {
      _require(_fixtureUuid.hasMatch(row.clientUuid) && row.loggedAt != null &&
          row.bloodSugar.isFinite && row.bloodSugar > 0 && row.source == 'manual' &&
          row.insulinUnits == null && row.syncStatus == 'pending',
          'Unexpected measurement row');
    }
    _require(rows.length <= limit || offset + limit <= 10000,
        'Journal pagination bound exceeded');
    return jsonEncode({
      'rows': rows.take(limit).map((row) => {
        'uuid': row.clientUuid, 'mgDl': row.bloodSugar,
        'loggedAtSeconds': row.loggedAt!.millisecondsSinceEpoch ~/ 1000,
        'source': row.source, 'syncStatus': row.syncStatus,
      }).toList(),
      'nextOffset': rows.length > limit ? offset + limit : null,
    });
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// Auxiliary table exists only in this synthetic probe, not in product schema.
const _tombstoneTable = 'd1_fixture_deleted_glucose';
Future<bool> _hasTombstones(AppDatabase db) async =>
    (await db.customSelect("SELECT name FROM sqlite_master WHERE type='table' AND name='d1_fixture_deleted_glucose'").get()).isNotEmpty;

Future<bool> _isDeleted(AppDatabase db, String uuid) async {
  _require(_fixtureUuid.hasMatch(uuid), 'Invalid measurement UUID');
  if (await _evidenceDeleted(db, uuid)) return true;
  if (!await _hasTombstones(db)) return false;
  final rows = await db.customSelect(
      'SELECT uuid FROM d1_fixture_deleted_glucose WHERE uuid = ?',
      variables: [Variable<String>(uuid)]).get();
  _require(rows.length <= 1, 'Duplicate tombstone');
  return rows.isNotEmpty;
}

Future<bool> _glucoseDeleted(Uint8List input, int owner, String uuid) async {
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final deleted = await _isDeleted(vault.db, uuid);
    _require(!deleted || await _fixtureGlucose(vault.db, uuid) == null,
        'Deleted measurement present');
    return deleted;
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<Uint8List> _changeGlucose(Uint8List input, int owner, String uuid,
    String action, double mgDl, int seconds) async {
  _require(_fixtureUuid.hasMatch(uuid) &&
      (action == 'delete' || (action == 'edit' && mgDl.isFinite && mgDl > 0 &&
          seconds > 0 && seconds <= 4102444800)), 'Invalid measurement change');
  final vault = await _MemoryVault.open(owner, input);
  var closed = false;
  try {
    await vault.inspect();
    final db = vault.db;
    final count = await db.countLogs();
    final row = await _fixtureGlucose(db, uuid);
    _require(row != null && !await _isDeleted(db, uuid), 'Measurement unavailable');
    final original = row!;
    final id = original.id;
    await db.transaction(() async {
      if (action == 'delete') {
        await db.customStatement('CREATE TABLE IF NOT EXISTS d1_fixture_deleted_glucose (uuid TEXT NOT NULL PRIMARY KEY)');
        await db.customStatement('INSERT INTO d1_fixture_deleted_glucose (uuid) VALUES (?)', [uuid]);
        await db.deleteLog(id);
        _require(await _fixtureGlucose(db, uuid) == null &&
            await _isDeleted(db, uuid) && await db.countLogs() == count - 1,
            'Deletion invariant failed');
      } else {
        final time = DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
        await db.updateLog(id, LogEntriesCompanion(
          bloodSugar: Value(mgDl), loggedAt: Value(time),
        ));
        final after = await _fixtureGlucose(db, uuid);
        _require(after != null && after.id == id &&
            after.createdAt == original.createdAt && after.bloodSugar == mgDl &&
            after.loggedAt!.millisecondsSinceEpoch == seconds * 1000 &&
            await db.countLogs() == count && !await _isDeleted(db, uuid),
            'Edit invariant failed');
      }
    });
    await vault.inspect();
    await db.close();
    closed = true;
    _require(vault.fs.fileData.keys.every((key) => key == _path),
        'Unexpected SQLite auxiliary file');
    return Uint8List.fromList(vault.fs.fileData[_path]!);
  } finally {
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<LogEntryData?> _fixtureGlucose(AppDatabase db, String uuid) async {
  _require(_fixtureUuid.hasMatch(uuid), 'Invalid measurement UUID');
  final row = await (db.select(db.logEntries)
      ..where((r) => r.clientUuid.equals(uuid))).getSingleOrNull();
  _require(row == null || (row.mealDescription == _glucoseMarker &&
      row.source == 'manual' && row.loggedAt != null &&
      row.bloodSugar.isFinite && row.bloodSugar > 0 &&
      row.insulinUnits == null && row.syncStatus == 'pending'),
      'Unexpected measurement row');
  return row;
}

Future<String> _readGlucose(Uint8List input, int owner, String uuid) async {
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final row = await _fixtureGlucose(vault.db, uuid);
    return jsonEncode(row == null ? null : {
      'uuid': row.clientUuid, 'mgDl': row.bloodSugar,
      'loggedAtSeconds': row.loggedAt!.millisecondsSinceEpoch ~/ 1000,
      'syncStatus': row.syncStatus, 'source': row.source,
    });
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// Actual Drift insertion primitive, explicit mg/dL fixture only.
Future<Uint8List> _insertGlucose(Uint8List input, int owner, String uuid,
    double mgDl, int seconds) async {
  _require(_fixtureUuid.hasMatch(uuid) && mgDl.isFinite && mgDl > 0 &&
      seconds > 0 && seconds <= 4102444800, 'Invalid measurement');
  final vault = await _MemoryVault.open(owner, input);
  var closed = false;
  try {
    await vault.inspect();
    final db = vault.db;
    final count = await db.countLogs();
    _require(!await _isDeleted(db, uuid), 'Measurement UUID deleted');
    _require(await _fixtureGlucose(db, uuid) == null, 'Duplicate measurement UUID');
    final time = DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
    await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
      createdAt: time, loggedAt: Value(time), bloodSugar: mgDl,
      clientUuid: uuid, mealDescription: const Value(_glucoseMarker),
    ));
    final row = await _fixtureGlucose(db, uuid);
    _require(row != null && row.bloodSugar == mgDl &&
        row.loggedAt!.millisecondsSinceEpoch == seconds * 1000 &&
        await db.countLogs() == count + 1, 'Measurement invariant failed');
    await vault.inspect();
    await db.close();
    closed = true;
    _require(vault.fs.fileData.keys.every((key) => key == _path),
        'Unexpected SQLite auxiliary file');
    return Uint8List.fromList(vault.fs.fileData[_path]!);
  } finally {
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// D1/D5 isolated Web checkpoint adapter. This is not a production migration.
// The encrypted D1 checkpoint owns the durable identity, revision and CAS.
// Only explicit new readings get D5 evidence; old ports cannot edit them.
Future<bool> _hasEvidence(AppDatabase db) async =>
    (await db.customSelect("SELECT name FROM sqlite_master WHERE type='table' AND name='$_evidenceTable'").get()).isNotEmpty;

GlucoseQuantityEvidence _decodeEvidence(QueryRow meta, LogEntryData row, int owner) {
  _require(meta.read<int>('owner_id') == owner &&
      meta.read<String>('client_uuid') == row.clientUuid &&
      row.mealDescription == _evidenceMarker, 'Evidence association mismatch');
  final raw = jsonDecode(meta.read<String>('envelope_json'));
  _require(raw is Map<String, dynamic>, 'Invalid evidence envelope');
  final evidence = GlucoseQuantityStorageEnvelope.decode(
    expectedClientUuid: row.clientUuid,
    envelope: Map<String, Object?>.from(raw as Map),
  )!;
  _require(evidence.canonicalMgDl == row.bloodSugar, 'Evidence canonical mismatch');
  return evidence;
}

Future<void> _validateEvidenceRows(AppDatabase db, int owner, List<LogEntryData> rows) async {
  final marked = {for (final row in rows.where((r) => r.mealDescription == _evidenceMarker)) row.clientUuid: row};
  if (!await _hasEvidence(db)) {
    _require(marked.isEmpty, 'Evidence metadata missing');
    return;
  }
  final metadata = await db.customSelect('SELECT client_uuid, owner_id, envelope_json FROM $_evidenceTable').get();
  _require(metadata.length == marked.length, 'Evidence cardinality mismatch');
  final seen = <String>{};
  for (final meta in metadata) {
    final uuid = meta.read<String>('client_uuid');
    final row = marked[uuid];
    _require(row != null && seen.add(uuid) && !await _isDeleted(db, uuid), 'Evidence orphan or tombstone');
    _decodeEvidence(meta, row!, owner);
  }
}

Future<String> _readEvidence(Uint8List input, int owner, String uuid) async {
  _require(_fixtureUuid.hasMatch(uuid), 'Invalid measurement UUID');
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final db = vault.db;
    final row = await (db.select(db.logEntries)..where((r) => r.clientUuid.equals(uuid))).getSingleOrNull();
    if (row == null || row.mealDescription != _evidenceMarker) return 'null';
    final meta = await db.customSelect('SELECT client_uuid, owner_id, envelope_json FROM $_evidenceTable WHERE client_uuid = ?',
      variables: [Variable<String>(uuid)]).getSingle();
    final evidence = _decodeEvidence(meta, row, owner);
    return jsonEncode({
      'uuid': uuid, 'originalValue': evidence.originalRawValue,
      'originalUnit': evidence.originalUnit!.ucumCode,
      'mgDl': evidence.canonicalMgDl,
      'loggedAtSeconds': row.loggedAt!.millisecondsSinceEpoch ~/ 1000,
      'provenance': 'user_entered',
      'displayMgDl': GlucoseDisplayProjection.fromEvidence(evidence, GlucoseSourceUnit.mgDl)?.numericText,
      'displayMmolL': GlucoseDisplayProjection.fromEvidence(evidence, GlucoseSourceUnit.mmolL)?.numericText,
    });
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

Future<bool> _hasFixtureTable(AppDatabase db, String table) async =>
    (await db.customSelect("SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
      variables: [Variable<String>(table)]).get()).isNotEmpty;

Future<bool> _evidenceDeleted(AppDatabase db, String uuid) async {
  if (!await _hasFixtureTable(db, _evidenceDeletedTable)) return false;
  final rows = await db.customSelect('SELECT client_uuid FROM $_evidenceDeletedTable WHERE client_uuid = ?',
      variables: [Variable<String>(uuid)]).get();
  _require(rows.length <= 1, 'Duplicate evidence tombstone');
  return rows.isNotEmpty;
}

Future<Map<String, Object?>?> _evidenceReceipt(AppDatabase db, int owner) async {
  if (!await _hasFixtureTable(db, _evidenceReceiptTable)) return null;
  final rows = await db.customSelect('SELECT * FROM $_evidenceReceiptTable').get();
  _require(rows.length == 1, 'Evidence receipt cardinality');
  final row = rows.single;
  final action = row.read<String>('action');
  final uuid = row.read<String>('client_uuid');
  final revision = row.read<int>('base_revision');
  _require(row.read<int>('singleton') == 1 && row.read<int>('owner_id') == owner &&
      _fixtureUuid.hasMatch(uuid) && ['insert','edit','delete'].contains(action) &&
      revision > 0 && revision < 0xffffffff, 'Invalid evidence receipt');
  return {'action':action,'uuid':uuid,'baseRevision':revision};
}

Future<void> _validateEvidenceMutationState(AppDatabase db, int owner, List<LogEntryData> rows) async {
  final live = {for (final row in rows) row.clientUuid: row};
  if (await _hasFixtureTable(db, _evidenceDeletedTable)) {
    final deleted = await db.customSelect('SELECT * FROM $_evidenceDeletedTable').get();
    final seen = <String>{};
    for (final row in deleted) {
      final uuid = row.read<String>('client_uuid');
      _require(_fixtureUuid.hasMatch(uuid) && row.read<int>('owner_id') == owner &&
          seen.add(uuid) && !live.containsKey(uuid), 'Invalid evidence tombstone');
    }
  }
  final receipt = await _evidenceReceipt(db, owner);
  if (receipt != null) {
    final uuid = receipt['uuid'] as String;
    _require(receipt['action'] == 'delete'
        ? await _evidenceDeleted(db, uuid)
        : live[uuid]?.mealDescription == _evidenceMarker, 'Evidence receipt mismatch');
  }
}

Future<String> _evidenceState(Uint8List input, int owner, String uuid) async {
  _require(_fixtureUuid.hasMatch(uuid), 'Invalid measurement UUID');
  final vault = await _MemoryVault.open(owner, input);
  try {
    await vault.inspect();
    final db = vault.db;
    final row = await (db.select(db.logEntries)..where((r) => r.clientUuid.equals(uuid))).getSingleOrNull();
    final deleted = await _evidenceDeleted(db, uuid);
    return jsonEncode({
      'state': deleted ? 'deleted' : row == null ? (await _isDeleted(db, uuid) ? 'legacy_deleted' : 'missing') :
          row.mealDescription == _evidenceMarker ? 'explicit' : 'legacy',
      'receipt': await _evidenceReceipt(db, owner),
    });
  } finally {
    try { await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

// All mutation state is included in the encrypted checkpoint CAS. A receipt
// contains no glucose value, unit or timestamp; only the last evidence operation.
Future<Uint8List> _changeEvidence(Uint8List input, int owner, String uuid,
    String action, int revision, double original, String unitCode, int seconds) async {
  final unit = GlucoseSourceUnit.fromExplicitUcumCode(unitCode);
  _require(_fixtureUuid.hasMatch(uuid) && revision > 0 && revision < 0xffffffff &&
      (action == 'delete' || (['insert','edit'].contains(action) && unit != null &&
        seconds > 0 && seconds <= 4102444800)), 'Invalid evidence mutation');
  final evidence = action == 'delete' ? null :
      GlucoseQuantityEvidence.userEntry(originalValue: original, declaredUnit: unit!);
  final envelope = evidence == null ? null :
      GlucoseQuantityStorageEnvelope.encode(clientUuid: uuid, evidence: evidence);
  final vault = await _MemoryVault.open(owner, input);
  var closed = false;
  try {
    await vault.inspect();
    final db = vault.db;
    await db.transaction(() async {
      final row = await (db.select(db.logEntries)..where((r) => r.clientUuid.equals(uuid))).getSingleOrNull();
      _require(!await _isDeleted(db, uuid), 'Existing or deleted measurement identity');
      if (action == 'insert') {
        _require(row == null, 'Existing or deleted measurement identity');
        await db.customStatement('CREATE TABLE IF NOT EXISTS $_evidenceTable (client_uuid TEXT NOT NULL PRIMARY KEY, owner_id INTEGER NOT NULL, envelope_json TEXT NOT NULL)');
        final time = DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
        await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
          clientUuid: uuid, createdAt: time, loggedAt: Value(time),
          bloodSugar: evidence!.canonicalMgDl!, mealDescription: const Value(_evidenceMarker),
          syncStatus: const Value('d5_candidate_local'),
        ));
        await db.customStatement('INSERT INTO $_evidenceTable (client_uuid, owner_id, envelope_json) VALUES (?, ?, ?)',
          [uuid, owner, jsonEncode(envelope)]);
      } else {
        _require(row != null && row.mealDescription == _evidenceMarker, 'Explicit evidence unavailable');
        final originalRow = row!;
        final id = originalRow.id;
        if (action == 'delete') {
          await db.customStatement('CREATE TABLE IF NOT EXISTS $_evidenceDeletedTable (client_uuid TEXT NOT NULL PRIMARY KEY, owner_id INTEGER NOT NULL)');
          await db.customStatement('INSERT INTO $_evidenceDeletedTable (client_uuid, owner_id) VALUES (?, ?)', [uuid, owner]);
          await db.customStatement('DELETE FROM $_evidenceTable WHERE client_uuid = ? AND owner_id = ?', [uuid, owner]);
          await db.deleteLog(id);
        } else {
          final time = DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
          await db.updateLog(id, LogEntriesCompanion(
            bloodSugar: Value(evidence!.canonicalMgDl!), loggedAt: Value(time),
          ));
          await db.customStatement('UPDATE $_evidenceTable SET envelope_json = ? WHERE client_uuid = ? AND owner_id = ?',
            [jsonEncode(envelope), uuid, owner]);
          final after = await (db.select(db.logEntries)..where((r) => r.clientUuid.equals(uuid))).getSingle();
          _require(after.id == id && after.createdAt == originalRow.createdAt, 'Evidence identity changed');
        }
      }
      await db.customStatement('CREATE TABLE IF NOT EXISTS $_evidenceReceiptTable (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1), owner_id INTEGER NOT NULL, client_uuid TEXT NOT NULL, action TEXT NOT NULL, base_revision INTEGER NOT NULL)');
      await db.customStatement('INSERT OR REPLACE INTO $_evidenceReceiptTable (singleton, owner_id, client_uuid, action, base_revision) VALUES (1, ?, ?, ?, ?)', [owner, uuid, action, revision]);
    });
    await vault.inspect();
    await db.close();
    closed = true;
    _require(vault.fs.fileData.keys.every((key) => key == _path), 'Unexpected SQLite auxiliary file');
    return Uint8List.fromList(vault.fs.fileData[_path]!);
  } finally {
    try { if (!closed) await vault.db.close(); }
    finally { vault.wipe(); }
  }
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  _boundLoginFn = ((JSNumber owner) =>
      _boundLogin(owner.toDartInt).then((_) => true.toJS).toJS).toJS;
  _boundProofFn = ((JSNumber owner) => _boundProof(owner.toDartInt).toJS).toJS;
  _boundEpochFn = (() => AuthService.authEpoch.toJS).toJS;
  _boundLockFn = (() { _boundLock!.lock(); }).toJS;
  _snapshotFn = ((JSUint8Array? bytes, JSNumber owner) =>
      _snapshot(bytes?.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  _mutateFn = ((JSUint8Array bytes, JSNumber owner, JSString operation) =>
      _snapshot(bytes.toDart, owner.toDartInt, operation.toDart).then((value) => value.toJS).toJS).toJS;
  _legacyFn = ((JSNumber owner) =>
      _legacySnapshot(owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  _glucoseDeletedFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid) =>
      _glucoseDeleted(bytes.toDart, owner.toDartInt, uuid.toDart)
          .then((value) => value.toJS).toJS).toJS;
  _glucoseChangeFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid,
      JSString action, JSNumber mgDl, JSNumber seconds) =>
      _changeGlucose(bytes.toDart, owner.toDartInt, uuid.toDart,
          action.toDart, mgDl.toDartDouble, seconds.toDartInt)
          .then((value) => value.toJS).toJS).toJS;
  _journalPageFn = ((JSUint8Array bytes, JSNumber owner, JSNumber start,
      JSNumber end, JSNumber limit, JSNumber offset) =>
      _journalPage(bytes.toDart, owner.toDartInt, start.toDartInt,
          end.toDartInt, limit.toDartInt, offset.toDartInt)
          .then((value) => value.toJS).toJS).toJS;
  _glucoseReadFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid) =>
      _readGlucose(bytes.toDart, owner.toDartInt, uuid.toDart)
          .then((value) => value.toJS).toJS).toJS;
  _glucoseInsertFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid,
      JSNumber mgDl, JSNumber seconds) =>
      _insertGlucose(bytes.toDart, owner.toDartInt, uuid.toDart,
          mgDl.toDartDouble, seconds.toDartInt)
          .then((value) => value.toJS).toJS).toJS;
  _evidenceReadFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid) =>
      _readEvidence(bytes.toDart, owner.toDartInt, uuid.toDart).then((value) => value.toJS).toJS).toJS;
  _evidenceStateFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid) =>
      _evidenceState(bytes.toDart, owner.toDartInt, uuid.toDart).then((value) => value.toJS).toJS).toJS;
  _evidenceChangeFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid, JSString action, JSNumber revision, JSNumber original, JSString unit, JSNumber seconds) =>
      _changeEvidence(bytes.toDart, owner.toDartInt, uuid.toDart, action.toDart, revision.toDartInt, original.toDartDouble, unit.toDart, seconds.toDartInt)
          .then((value) => value.toJS).toJS).toJS;
  _treatmentReadFn = ((JSUint8Array bytes, JSNumber owner) =>
      _readTreatment(bytes.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  _treatmentChangeFn = ((JSUint8Array bytes, JSNumber owner, JSString state, JSString codes) =>
      _changeTreatment(bytes.toDart, owner.toDartInt, state.toDart, codes.toDart)
          .then((value) => value.toJS).toJS).toJS;
  _fullInspectFn = ((JSUint8Array bytes, JSNumber owner) =>
      _fullInspect(bytes.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  _inspectFn = ((JSUint8Array bytes, JSNumber owner) =>
      _inspect(bytes.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  runApp(const MaterialApp(home: Scaffold(
    body: Center(child: Text('D1-I1 synthetic Drift checkpoint probe')),
  )));
}
