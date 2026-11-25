// D1-I1 synthetic browser executable only. No real auth, legacy storage,
// clinical providers, network API, or production vault admission.
import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:amina/data/drift/database.dart';
import 'package:amina/data/drift/patient_vault_scope.dart';
import 'package:drift/drift.dart';
import 'package:drift/wasm.dart';
import 'package:flutter/material.dart';
import 'package:sqlite3/wasm.dart';

@JS('d1Snapshot')
external set _snapshotFn(JSFunction function);
@JS('d1Inspect')
external set _inspectFn(JSFunction function);

const _filename = 'vault.sqlite';
const _path = '/vault.sqlite';
const _marker = 'D1_I1_SYNTHETIC_NOT_PATIENT';
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
        rows.every((row) => row.mealDescription == _marker &&
          row.clientUuid.startsWith('d1-i1-$owner-')), 'Synthetic rows mismatch');
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

Future<Uint8List> _snapshot(Uint8List? previous, int owner) async {
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
      await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
        createdAt: DateTime.utc(2026, 11, 25, 0, next),
        bloodSugar: 100.25 + next,
        clientUuid: 'd1-i1-$owner-$next',
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

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  _snapshotFn = ((JSUint8Array? bytes, JSNumber owner) =>
      _snapshot(bytes?.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  _inspectFn = ((JSUint8Array bytes, JSNumber owner) =>
      _inspect(bytes.toDart, owner.toDartInt).then((value) => value.toJS).toJS).toJS;
  runApp(const MaterialApp(home: Scaffold(
    body: Center(child: Text('D1-I1 synthetic Drift checkpoint probe')),
  )));
}
