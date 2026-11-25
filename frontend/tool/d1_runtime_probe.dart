// D1-I1 synthetic browser executable only. No real auth, legacy storage,
// clinical providers, network API, or production vault admission.
import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:amina/data/drift/database.dart';
import 'package:amina/data/drift/patient_vault_scope.dart';
import 'package:amina/data/drift/patient_treatment_declaration_store.dart';
import 'package:drift/drift.dart';
import 'package:drift/wasm.dart';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show listEquals;
import 'package:amina/services/auth_service.dart';
import 'package:amina/services/app_lock_service.dart';
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
@JS('d1GlucoseRead')
external set _glucoseReadFn(JSFunction function);
@JS('d1GlucoseInsert')
external set _glucoseInsertFn(JSFunction function);
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
  return ((JSString phase, JSNumber id, JSNumber epoch, JSFunction? callback) {
    final o = id.toDartInt, e = epoch.toDartInt;
    return (switch (phase.toDart) {
      'claim' => guard.claim(o, e),
      'pending' => guard.checkPending(o, e),
      'activate' => guard.activate(o, e),
      'session' => guard.checkSession(o, e),
      'watch' => callback != null && guard.watchRetirement(o, e, () { callback.callAsFunction(); }),
      _ => false,
    }).toJS;
  }).toJS;
}

const _filename = 'vault.sqlite';
const _path = '/vault.sqlite';
const _marker = 'D1_I1_SYNTHETIC_NOT_PATIENT';
const _glucoseMarker = 'D1_I5C_SYNTHETIC_GLUCOSE';
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
    final rows = await db.getRecentLogs();
    _require(rows.isNotEmpty &&
        rows.every((row) =>
          (row.mealDescription == _marker && row.clientUuid.startsWith('d1-i1-$owner-')) ||
          (row.mealDescription == _glucoseMarker && _fixtureUuid.hasMatch(row.clientUuid) &&
           row.source == 'manual' && row.bloodSugar.isFinite && row.bloodSugar > 0 &&
           row.loggedAt != null && row.insulinUnits == null && row.syncStatus == 'pending')), 'Synthetic rows mismatch');
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
  _glucoseReadFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid) =>
      _readGlucose(bytes.toDart, owner.toDartInt, uuid.toDart)
          .then((value) => value.toJS).toJS).toJS;
  _glucoseInsertFn = ((JSUint8Array bytes, JSNumber owner, JSString uuid,
      JSNumber mgDl, JSNumber seconds) =>
      _insertGlucose(bytes.toDart, owner.toDartInt, uuid.toDart,
          mgDl.toDartDouble, seconds.toDartInt)
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
