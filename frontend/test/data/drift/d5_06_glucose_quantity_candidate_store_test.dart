import 'dart:io';

import 'package:amina/core/domain/glucose_display_projection.dart';
import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/data/drift/database.dart';
import 'package:amina/data/drift/glucose_quantity_candidate_store.dart';
import 'package:amina/data/drift/patient_vault_scope.dart';
import 'package:drift/drift.dart' as drift;
import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';

final at = DateTime.utc(2026, 11, 26, 12);
const id = 'd5-synthetic-001';
final quantity = GlucoseQuantityEvidence.userEntry(
  originalValue: 7.83, declaredUnit: GlucoseSourceUnit.mmolL,
);
AppDatabase dbFor(int owner, {File? file}) => AppDatabase.testPatientVault(
  file == null ? NativeDatabase.memory() : NativeDatabase(file),
  PatientVaultScope.nativeDjango(owner),
);
Future<void> insert(GlucoseQuantityCandidateStore store, {String uuid = id}) =>
    store.insert(uuid: uuid, loggedAt: at, evidence: quantity);
Future<void> legacy(AppDatabase db) => db.into(db.logEntries).insert(
  LogEntriesCompanion.insert(
    clientUuid: 'legacy', createdAt: at, bloodSugar: 5,
    source: const drift.Value('manual'),
  ),
).then((_) {});

void main() {
  late AppDatabase db;
  late GlucoseQuantityCandidateStore store;
  setUp(() async {
    db = dbFor(900001);
    store = await GlucoseQuantityCandidateStore.openSynthetic(db, initialize: true);
  });
  tearDown(() async => db.close());

  test('actual SQLite insert and read preserve original unit and value', () async {
    await insert(store);
    final raw = (await db.select(db.logEntries).get()).single;
    expect(raw.bloodSugar, closeTo(141.0620697, 1e-10));
    expect(raw.syncStatus, 'd5_candidate_local');
    expect(await db.getPendingLogs(), isEmpty);
    final restored = (await store.read(id))!;
    expect(restored.originalRawValue, 7.83);
    expect(restored.originalUnit, GlucoseSourceUnit.mmolL);
    expect(GlucoseDisplayProjection.fromEvidence(restored, GlucoseSourceUnit.mgDl)?.numericText, '141');
    expect(GlucoseDisplayProjection.fromEvidence(restored, GlucoseSourceUnit.mmolL)?.numericText, '7.8');
  });

  test('legacy row unchanged, no unit inferred, no adoption or deletion', () async {
    await legacy(db);
    final unknown = (await store.read('legacy'))!;
    expect(unknown.originalRawValue, 5.0);
    expect(unknown.originalUnit, isNull);
    expect(unknown.canonicalMgDl, isNull);
    await expectLater(insert(store, uuid: 'legacy'), throwsStateError);
    await expectLater(store.delete('legacy'), throwsStateError);
    expect((await db.select(db.logEntries).get()).single.bloodSugar, 5.0);
    expect((await db.getPendingLogs()).single.clientUuid, 'legacy');
  });

  test('duplicate UUID fails without changing the existing reading', () async {
    await insert(store);
    await expectLater(insert(store), throwsStateError);
    expect((await db.select(db.logEntries).get()).length, 1);
    expect((await store.read(id))!.originalRawValue, 7.83);
  });

  test('SQL failure rolls back both rows', () async {
    await db.customStatement("""
      CREATE TRIGGER d5_force_insert_failure BEFORE INSERT ON d5_glucose_evidence_candidate_v1
      BEGIN SELECT RAISE(ABORT, 'fixture rollback'); END
    """);
    await expectLater(insert(store), throwsA(isA<Exception>()));
    expect(await db.select(db.logEntries).get(), isEmpty);
    expect(await store.read(id), isNull);
  });

  test('missing metadata, altered canonical, malformed envelope fail closed', () async {
    await insert(store);
    await db.customStatement('UPDATE log_entries SET blood_sugar = 100 WHERE client_uuid = ?', [id]);
    await expectLater(store.read(id), throwsStateError);
    await db.customStatement('UPDATE log_entries SET blood_sugar = ? WHERE client_uuid = ?', [quantity.canonicalMgDl, id]);
    await db.customStatement("UPDATE d5_glucose_evidence_candidate_v1 SET envelope_json = '{}' WHERE client_uuid = ?", [id]);
    await expectLater(store.read(id), throwsFormatException);
    await db.customStatement('DELETE FROM d5_glucose_evidence_candidate_v1 WHERE client_uuid = ?', [id]);
    await expectLater(store.read(id), throwsStateError);
  });

  test('candidate deletion is atomic and leaves legacy unchanged', () async {
    await legacy(db);
    await insert(store);
    await db.customStatement("""
      CREATE TRIGGER d5_force_delete_failure BEFORE DELETE ON log_entries
      WHEN OLD.client_uuid = 'd5-synthetic-001'
      BEGIN SELECT RAISE(ABORT, 'fixture rollback'); END
    """);
    await expectLater(store.delete(id), throwsA(isA<Exception>()));
    expect((await store.read(id))!.originalRawValue, 7.83);
    expect(await db.customSelect('SELECT client_uuid FROM d5_glucose_tombstones_v1').get(), isEmpty);
    await db.customStatement('DROP TRIGGER d5_force_delete_failure');
    await store.delete(id);
    expect(await store.read(id), isNull);
    expect((await db.select(db.logEntries).get()).single.clientUuid, 'legacy');
  });

  test('file restart preserves evidence, wrong owner cannot reopen it', () async {
    final dir = await Directory.systemTemp.createTemp('d5-candidate-');
    final file = File('${dir.path}/candidate.sqlite');
    try {
      var disk = dbFor(900001, file: file);
      try {
        final port = await GlucoseQuantityCandidateStore.openSynthetic(disk, initialize: true);
        await insert(port);
      } finally { await disk.close(); }
      disk = dbFor(900001, file: file);
      try {
        final port = await GlucoseQuantityCandidateStore.openSynthetic(disk);
        expect((await port.read(id))!.originalRawValue, 7.83);
      } finally { await disk.close(); }
      disk = dbFor(900002, file: file);
      try {
        await expectLater(GlucoseQuantityCandidateStore.openSynthetic(disk), throwsStateError);
      } finally { await disk.close(); }
    } finally { await dir.delete(recursive: true); }
  });

  test('isolated B cannot read A and nonfixture/legacy scopes are refused', () async {
    await insert(store);
    final b = dbFor(900002);
    final nonfixture = dbFor(100);
    final unscoped = AppDatabase(NativeDatabase.memory());
    try {
      final other = await GlucoseQuantityCandidateStore.openSynthetic(b, initialize: true);
      expect(await other.read(id), isNull);
      await insert(other);
      expect((await store.read(id))!.originalRawValue, 7.83);
      await other.delete(id);
      expect((await store.read(id))!.originalRawValue, 7.83);
      await expectLater(GlucoseQuantityCandidateStore.openSynthetic(nonfixture), throwsStateError);
      await expectLater(GlucoseQuantityCandidateStore.openSynthetic(unscoped), throwsStateError);
    } finally {
      await b.close(); await nonfixture.close(); await unscoped.close();
    }
  });

  test('empty vault is bound before any reading, survives restart, cannot be reassigned', () async {
    final dir = await Directory.systemTemp.createTemp('d5-empty-');
    final file = File('${dir.path}/candidate.sqlite');
    try {
      var disk = dbFor(900001, file: file);
      String vaultId;
      try {
        await expectLater(GlucoseQuantityCandidateStore.openSynthetic(disk), throwsStateError);
        await GlucoseQuantityCandidateStore.openSynthetic(disk, initialize: true);
        vaultId = (await disk.customSelect('SELECT vault_id FROM d5_glucose_vault_identity_v1').getSingle()).read<String>('vault_id');
        await expectLater(GlucoseQuantityCandidateStore.openSynthetic(disk, initialize: true), throwsStateError);
      } finally { await disk.close(); }
      disk = dbFor(900002, file: file);
      try {
        await expectLater(GlucoseQuantityCandidateStore.openSynthetic(disk), throwsStateError);
        await expectLater(GlucoseQuantityCandidateStore.openSynthetic(disk, initialize: true), throwsStateError);
      } finally { await disk.close(); }
      disk = dbFor(900001, file: file);
      try {
        final restored = await GlucoseQuantityCandidateStore.openSynthetic(disk);
        expect(await restored.read(id), isNull);
        expect((await disk.customSelect('SELECT vault_id FROM d5_glucose_vault_identity_v1').getSingle()).read<String>('vault_id'), vaultId);
      } finally { await disk.close(); }
    } finally { await dir.delete(recursive: true); }
  });

  test('unbound nonempty or partial preexisting vault is never adopted', () async {
    final old = dbFor(900001);
    final partial = dbFor(900001);
    try {
      await legacy(old);
      await expectLater(GlucoseQuantityCandidateStore.openSynthetic(old, initialize: true), throwsStateError);
      expect((await old.select(old.logEntries).get()).single.bloodSugar, 5.0);
      expect(await old.customSelect("SELECT name FROM sqlite_master WHERE name LIKE 'd5_glucose_%'").get(), isEmpty);
      await partial.customStatement('CREATE TABLE d5_glucose_evidence_candidate_v1 (client_uuid TEXT PRIMARY KEY)');
      await expectLater(GlucoseQuantityCandidateStore.openSynthetic(partial, initialize: true), throwsStateError);
      await expectLater(GlucoseQuantityCandidateStore.openSynthetic(partial), throwsStateError);
    } finally { await old.close(); await partial.close(); }
  });

  test('lost identity rejects all operations and cannot be repaired', () async {
    await insert(store);
    await db.customStatement('DELETE FROM d5_glucose_vault_identity_v1');
    await expectLater(store.read(id), throwsStateError);
    await expectLater(insert(store, uuid: 'new'), throwsStateError);
    await expectLater(store.delete(id), throwsStateError);
    await expectLater(GlucoseQuantityCandidateStore.openSynthetic(db), throwsStateError);
    await expectLater(GlucoseQuantityCandidateStore.openSynthetic(db, initialize: true), throwsStateError);
    expect((await db.select(db.logEntries).get()).single.clientUuid, id);
  });

  test('replacement vault identity invalidates previously opened handle', () async {
    await insert(store);
    await db.customStatement("UPDATE d5_glucose_vault_identity_v1 SET vault_id = 'ac123456-1234-4abc-8def-000000000011'");
    await expectLater(store.read(id), throwsStateError);
    await expectLater(store.delete(id), throwsStateError);
  });

  test('tombstone remains after file restart and forbids UUID reuse', () async {
    final dir = await Directory.systemTemp.createTemp('d5-tombstone-');
    final file = File('${dir.path}/candidate.sqlite');
    try {
      var disk = dbFor(900001, file: file);
      try {
        final port = await GlucoseQuantityCandidateStore.openSynthetic(disk, initialize: true);
        await insert(port);
        await port.delete(id);
        expect(await port.read(id), isNull);
        final row = (await disk.customSelect('SELECT * FROM d5_glucose_tombstones_v1').getSingle()).data;
        expect(row, {'client_uuid': id, 'owner_id': 900001});
        await expectLater(insert(port), throwsStateError);
        await expectLater(port.delete(id), throwsStateError);
      } finally { await disk.close(); }
      disk = dbFor(900001, file: file);
      try {
        final port = await GlucoseQuantityCandidateStore.openSynthetic(disk);
        await expectLater(insert(port), throwsStateError);
        expect(await port.read(id), isNull);
        expect(await disk.select(disk.logEntries).get(), isEmpty);
        await insert(port, uuid: 'new');
        expect((await port.read('new'))!.originalRawValue, 7.83);
      } finally { await disk.close(); }
    } finally { await dir.delete(recursive: true); }
  });

  test('tombstone insertion failure rolls back deletion', () async {
    await insert(store);
    await db.customStatement("""
      CREATE TRIGGER d5_fail_tombstone BEFORE INSERT ON d5_glucose_tombstones_v1
      BEGIN SELECT RAISE(ABORT, 'fixture rollback'); END
    """);
    await expectLater(store.delete(id), throwsA(isA<Exception>()));
    expect((await store.read(id))!.originalRawValue, 7.83);
    expect(await db.customSelect('SELECT client_uuid FROM d5_glucose_tombstones_v1').get(), isEmpty);
  });

  test('resurrected row and cross-owner tombstone fail closed', () async {
    await insert(store);
    await store.delete(id);
    await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
      clientUuid: id, createdAt: at, bloodSugar: 100,
    ));
    await expectLater(store.read(id), throwsStateError);
    await expectLater(insert(store), throwsStateError);
    await db.customStatement(
      'INSERT INTO d5_glucose_tombstones_v1 (client_uuid, owner_id) VALUES (?, ?)',
      ['foreign', 900002],
    );
    await expectLater(store.read('foreign'), throwsStateError);
    await expectLater(GlucoseQuantityCandidateStore.openSynthetic(db), throwsStateError);
  });
}
