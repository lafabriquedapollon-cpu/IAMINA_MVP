// Synthetic D5-02: independent time-window and raw-source oracles.
// Exercises actual Drift queries in memory, never a patient vault or network.
import 'dart:async';

import 'package:amina/data/drift/database.dart';
import 'package:amina/data/drift/dashboard_trend_queries.dart';
import 'package:drift/drift.dart' as drift;
import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';

final end = DateTime.utc(2026, 11, 26, 12);
final start = DateTime.utc(2026, 11, 25, 12);

Future<void> putLog(
  AppDatabase db,
  String uuid,
  DateTime created,
  DateTime? logged, {
  String source = 'manual',
  double glucose = 100,
}) async {
  await db.into(db.logEntries).insert(LogEntriesCompanion.insert(
    clientUuid: uuid,
    createdAt: created,
    bloodSugar: glucose,
    loggedAt: drift.Value(logged),
    source: drift.Value(source),
  ));
}

Set<String> ids(List<LogEntryData> rows) =>
    rows.map((row) => row.clientUuid).toSet();

Future<void> putMedication(
  AppDatabase db, String label, DateTime taken, DateTime created,
) async {
  await db.into(db.medicationEvents).insert(MedicationEventsCompanion.insert(
    label: label, takenAt: taken, createdAt: created,
  ));
}

void main() {
  late AppDatabase db;
  setUp(() { db = AppDatabase(NativeDatabase.memory()); });
  tearDown(() async { await db.close(); });

  test('four window memberships: inclusive edges and loggedAt precedence', () async {
    await putLog(db, 'end', DateTime.utc(2026, 11, 27), end, glucose: 101);
    await putLog(db, '24-edge', end, start, source: 'manual', glucose: 102);
    await putLog(db, '24-before', end, DateTime.utc(2026, 11, 25, 11, 59, 59));
    await putLog(db, '7-edge', end, DateTime.utc(2026, 11, 19, 12));
    await putLog(db, '7-before', end, DateTime.utc(2026, 11, 19, 11, 59, 59));
    await putLog(db, '14-edge', end, DateTime.utc(2026, 11, 12, 12));
    await putLog(db, '14-before', end, DateTime.utc(2026, 11, 12, 11, 59, 59));
    await putLog(db, '30-edge', end, DateTime.utc(2026, 10, 27, 12));
    await putLog(db, '30-before', end, DateTime.utc(2026, 10, 27, 11, 59, 59));
    await putLog(db, 'future', start, DateTime.utc(2026, 11, 26, 12, 0, 1));
    await putLog(db, 'legacy-in', DateTime.utc(2026, 11, 26, 9), null, source: 'legacy-unknown');
    await putLog(db, 'legacy-out', DateTime.utc(2026, 10, 26), null);
    await putLog(db, 'offset', DateTime.utc(2026, 11, 27),
      DateTime.parse('2026-11-26T13:00:00+01:00'), source: 'imported', glucose: 103);

    final expected = <int, Set<String>>{
      1: {'end', '24-edge', 'legacy-in', 'offset'},
      7: {'end', '24-edge', '24-before', '7-edge', 'legacy-in', 'offset'},
      14: {'end', '24-edge', '24-before', '7-edge', '7-before', '14-edge', 'legacy-in', 'offset'},
      30: {'end', '24-edge', '24-before', '7-edge', '7-before', '14-edge', '14-before', '30-edge', 'legacy-in', 'offset'},
    };
    for (final days in expected.keys) {
      final rows = await db.watchDashboardTrendLogs(end.subtract(Duration(days: days)), end).first;
      expect(ids(rows), expected[days], reason: 'window ${days}d');
      expect(rows.length, expected[days]!.length);
    }
    final rows = await db.watchDashboardTrendLogs(start, end).first;
    final byId = {for (final row in rows) row.clientUuid: row};
    expect(byId['end']!.loggedAt!.toUtc(), end);
    expect(byId['offset']!.loggedAt!.toUtc(), end);
    expect(byId['offset']!.createdAt.toUtc(), DateTime.utc(2026, 11, 27));
    expect(byId['offset']!.source, 'imported');
    expect(byId['offset']!.bloodSugar, 103);
    expect(byId['24-edge']!.source, 'manual');
    expect(byId['legacy-in']!.source, 'legacy-unknown');
    expect(byId['legacy-in']!.loggedAt, isNull);
    expect(byId['legacy-in']!.createdAt.toUtc(), DateTime.utc(2026, 11, 26, 9));
  });

  test('raw source and raw value are preserved, not inferred from magnitude', () async {
    for (final (uuid, source, value) in [
      ('a', 'manual', 5.0),
      ('b', 'cgm', 180.0),
      ('c', 'not_cgm', 5.0),
      ('d', 'imported', 180.0),
      ('e', 'unverified', 180.0),
      ('f', '', 5.0),
    ]) {
      await putLog(db, uuid, end, start, source: source, glucose: value);
    }
    final rows = await db.watchDashboardTrendLogs(start, end).first;
    expect({for (final row in rows) row.clientUuid: (row.source, row.bloodSugar)}, {
      'a': ('manual', 5.0), 'b': ('cgm', 180.0), 'c': ('not_cgm', 5.0),
      'd': ('imported', 180.0), 'e': ('unverified', 180.0), 'f': ('', 5.0),
    });
    // This proves raw round-trip only, not that source text establishes authority.
  });

  test('medication events use takenAt, sorted, never mixed into glucose rows', () async {
    await putLog(db, 'log', end, end);
    await putMedication(db, 'end', end, DateTime.utc(2026, 11, 27));
    await putMedication(db, 'before', DateTime.utc(2026, 11, 25, 11, 59, 59), end);
    await putMedication(db, 'middle', DateTime.utc(2026, 11, 25, 18), start);
    await putMedication(db, 'start', start, end);
    await putMedication(db, 'future', DateTime.utc(2026, 11, 26, 12, 0, 1), start);
    final events = await db.watchDashboardMedicationEvents(start, end).first;
    expect(events.map((e) => e.label).toList(), ['start', 'middle', 'end']);
    expect(events.map((e) => e.takenAt.toUtc()).toList(), [
      start, DateTime.utc(2026, 11, 25, 18), end,
    ]);
    expect(ids(await db.watchDashboardTrendLogs(start, end).first), {'log'});
  });

  test('reactive query observes empty, insert, move out of range and removal', () async {
    final iterator = StreamIterator(db.watchDashboardTrendLogs(start, end));
    try {
      expect(await iterator.moveNext(), isTrue);
      expect(iterator.current, isEmpty);
      var next = iterator.moveNext();
      await putLog(db, 'reactive', end, start);
      expect(await next, isTrue);
      expect(ids(iterator.current), {'reactive'});
      next = iterator.moveNext();
      await (db.update(db.logEntries)..where((row) => row.clientUuid.equals('reactive')))
          .write(LogEntriesCompanion(loggedAt: drift.Value(DateTime.utc(2026, 11, 26, 12, 0, 1))));
      expect(await next, isTrue);
      expect(iterator.current, isEmpty);
      next = iterator.moveNext();
      await (db.update(db.logEntries)..where((row) => row.clientUuid.equals('reactive')))
          .write(LogEntriesCompanion(loggedAt: drift.Value(start)));
      expect(await next, isTrue);
      expect(ids(iterator.current), {'reactive'});
      next = iterator.moveNext();
      await (db.delete(db.logEntries)..where((row) => row.clientUuid.equals('reactive'))).go();
      expect(await next, isTrue);
      expect(iterator.current, isEmpty);
    } finally {
      await iterator.cancel();
    }
  });

  test('empty and disjoint windows never manufacture records', () async {
    expect(await db.watchDashboardTrendLogs(start, end).first, isEmpty);
    expect(await db.watchDashboardMedicationEvents(start, end).first, isEmpty);
    await putLog(db, 'old', DateTime.utc(2026, 10, 1), null);
    await putMedication(db, 'old', DateTime.utc(2026, 10, 1), end);
    expect(await db.watchDashboardTrendLogs(start, end).first, isEmpty);
    expect(await db.watchDashboardMedicationEvents(start, end).first, isEmpty);
  });
}
