// D5-03: descriptive observations, not clinical validation.
// Known gaps are characterization assertions, never acceptance of the policy.
import 'dart:ui' as ui;

import 'package:amina/core/localization/dashboard_trend_localized_copy.dart';
import 'package:amina/data/drift/database.dart';
import 'package:amina/features/dashboard/widgets/dashboard_trend_painter.dart';
import 'package:amina/features/dashboard/widgets/dashboard_trend_section.dart';
import 'package:amina/features/dashboard/widgets/dashboard_trend_view.dart';
import 'package:amina/l10n/app_localizations.dart';
import 'package:amina/l10n/app_localizations_ar.dart';
import 'package:amina/l10n/app_localizations_en.dart';
import 'package:amina/l10n/app_localizations_fr.dart';
import 'package:drift/drift.dart' as drift;
import 'package:drift/native.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

LogEntryData reading(int id, double value, DateTime at, {DateTime? created, bool fallback = false}) =>
    LogEntryData(
      id: id, createdAt: created ?? at, loggedAt: fallback ? null : at,
      bloodSugar: value, source: 'manual', syncStatus: 'pending',
      clientUuid: 'synthetic-$id', isSick: false, isStressed: false,
      isTired: false, isActive: false, ramadanMode: false,
      syncAttempts: 0, errorSync: false,
    );

// Captures actual drawing calls, not a second implementation of aggregation.
// Text is intentionally not compared: this is a VM numeric geometry test.
class RecordingCanvas implements Canvas {
  final lines = <(Offset, Offset)>[];
  final circles = <Offset>[];

  @override
  void drawLine(Offset p1, Offset p2, Paint paint) => lines.add((p1, p2));
  @override
  void drawCircle(Offset c, double radius, Paint paint) => circles.add(c);
  @override
  void drawParagraph(ui.Paragraph paragraph, Offset offset) {}
  @override
  void drawPath(Path path, Paint paint) {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

DashboardTrendPainter painter(List<LogEntryData> rows, {List<MedicationEventData> medications = const []}) =>
    DashboardTrendPainter(
      logs: rows, medications: medications, start: DateTime(2026, 11, 1),
      end: DateTime(2026, 11, 8), low: null, high: null,
      selectedLogId: -1, unit: 'mg/dL', locale: 'en_US',
      isDark: false, dailySummary: true,
    );

bool near(double a, double b) => (a - b).abs() < 0.00001;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final day1 = DateTime(2026, 11, 1, 12);
  final day2 = DateTime(2026, 11, 2, 12);
  final day5 = DateTime(2026, 11, 5, 12);
  // Fixed independent oracle: day1 80/120/160, day2 90/150 (median 120),
  // day5 single 210. Overall arithmetic sample mean = 135.
  final rows = [
    reading(6, 210, day5),
    reading(3, 160, day1, created: day5),
    reading(5, 150, day2),
    reading(1, 80, day1),
    reading(4, 90, day2, fallback: true),
    reading(2, 120, day1),
  ];

  test('real painter: odd/even/singleton median and observed extrema', () {
    final canvas = RecordingCanvas();
    painter(rows).paint(canvas, const Size(600, 250));
    // Independent numeric coordinates for plot [46,12]-[590,220], range 0..300.
    // Expected day x: 67.76, 318, 568.24. Expected y values:
    // 80=164.5333333; 90=157.6; 120=136.8; 150=116;
    // 160=109.0666667; 210=74.4.
    const x = [67.76, 318.0, 568.24];
    const medians = [136.8, 136.8, 74.4];
    const mins = [164.5333333333, 157.6, 74.4];
    const maxs = [109.0666666667, 116.0, 74.4];
    for (var i = 0; i < x.length; i++) {
      expect(canvas.circles.any((c) => near(c.dx, x[i]) && near(c.dy, medians[i])), isTrue,
        reason: 'median geometry for observed day $i');
      expect(canvas.lines.any((l) => near(l.$1.dx, x[i]) && near(l.$2.dx, x[i]) &&
        near(l.$1.dy, maxs[i]) && near(l.$2.dy, mins[i])), isTrue,
        reason: 'min/max geometry for observed day $i');
    }
    expect(canvas.circles.map((c) => c.dx).toSet().length, 3);
    expect(rows.map((r) => r.id).toList(), [6, 3, 5, 1, 4, 2]);
  });

  test('empty painter draws no synthetic measurements', () {
    final canvas = RecordingCanvas();
    painter([]).paint(canvas, const Size(600, 250));
    expect(canvas.circles, isEmpty);
    expect(canvas.lines, isEmpty);
  });

  test('OPEN GAP: missing days compressed and treatment snapped to observed day', () {
    final canvas = RecordingCanvas();
    final treatment = MedicationEventData(
      id: 1, label: 'synthetic recorded event', takenAt: DateTime(2026, 11, 3, 12),
      createdAt: day5,
    );
    painter(rows, medications: [treatment]).paint(canvas, const Size(600, 250));
    // Day 1->2 and day 2->5 have equal x spacing despite different time gaps.
    expect(318.0 - 67.76, closeTo(568.24 - 318.0, 1e-10));
    expect(canvas.circles.any((c) => near(c.dx, 67.76) && near(c.dy, 136.8)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, 318) && near(c.dy, 136.8)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, 568.24) && near(c.dy, 74.4)), isTrue);
    // Day 3 has no measurement; legacy painter snaps treatment to day 2.
    expect(canvas.circles.any((c) => near(c.dx, 318) && near(c.dy, 13)), isTrue);
    // No assertion here endorses a time-faithful axis or clinical causality.
  });

  test('real source labels FR/AR/EN and explicit substring ambiguity', () {
    for (final (locale, manual, imported, recorded) in [
      (AppLocalizationsFr(), 'Manuel', 'Importé', 'Enregistré'),
      (AppLocalizationsAr(), 'يدوي', 'مستورد', 'مسجل'),
      (AppLocalizationsEn(), 'Manual', 'Imported', 'Recorded'),
    ]) {
      expect(locale.dashboardTrendSourceLabel('manual'), manual);
      expect(locale.dashboardTrendSourceLabel(' CGM '), 'CGM');
      expect(locale.dashboardTrendSourceLabel('imported'), imported);
      expect(locale.dashboardTrendSourceLabel(''), recorded);
      expect(locale.dashboardTrendSourceLabel('unknown'), recorded);
      // OPEN GAP: a token containing cgm/import is not evidence of origin.
      expect(locale.dashboardTrendSourceLabel('not_cgm'), 'CGM');
      expect(locale.dashboardTrendSourceLabel('not_imported'), imported);
    }
  });

  testWidgets('actual section computes sample mean and never authorizes target', (tester) async {
    // Construct and open the DB inside the same real-async zone as seeding.
    // A DB constructed in FakeAsync can leave its internal completers there
    // while runAsync waits outside that zone.
    AppDatabase? opened;
    try {
      final db = await tester.runAsync(() async {
        final database = AppDatabase(NativeDatabase.memory());
        opened = database;
        final now = DateTime.now();
        print('D5_03_WIDGET seed-start');
        for (final (id, value, days) in [
          (1, 80.0, 5), (2, 120.0, 5), (3, 160.0, 5),
          (4, 90.0, 4), (5, 150.0, 4), (6, 210.0, 1),
        ]) {
          final at = now.subtract(Duration(days: days));
          await database.into(database.logEntries).insert(LogEntriesCompanion.insert(
            clientUuid: 'synthetic-$id', createdAt: at,
            loggedAt: drift.Value(at), bloodSugar: value,
          )).timeout(const Duration(seconds: 5));
        }
        print('D5_03_WIDGET seed-complete');
        return database;
      });
      expect(db, isNotNull, reason: 'real-zone fixture initialization');
      print('D5_03_WIDGET mount-start');
      await tester.pumpWidget(Provider<AppDatabase>.value(
        value: db!,
        child: MaterialApp(
          locale: const Locale('en'),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: SingleChildScrollView(
            child: DashboardTrendSection(unit: 'mg/dL', low: 70, high: 180),
          )),
        ),
      ));
      final finder = find.byType(DashboardTrendSummary);
      for (var i = 0; i < 50 && finder.evaluate().isEmpty; i++) {
        await tester.runAsync(() async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
        });
        await tester.pump(const Duration(milliseconds: 30));
      }
      expect(finder, findsOneWidget);
      final summary = tester.widget<DashboardTrendSummary>(finder);
      expect(summary.average, 135.0);
      expect(summary.count, 6);
      expect(summary.recent.bloodSugar, 210.0);
      expect(summary.inTarget, isNull);
      expect(find.descendant(of: finder, matching: find.text('135')), findsOneWidget);
      expect(find.descendant(of: finder, matching: find.text('—')), findsOneWidget);
      expect(tester.takeException(), isNull);
      print('D5_03_WIDGET assertions-complete');
    } finally {
      print('D5_03_WIDGET unmount-start');
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump();
      final database = opened;
      if (database != null) {
        print('D5_03_WIDGET close-start');
        // Initiate close in the widget zone, then advance microtasks while
        // real-async database callbacks drain. Do not block either zone.
        var closed = false;
        Object? closeError;
        final closing = database.close().then<void>((_) {
          closed = true;
        }, onError: (Object error, StackTrace stack) {
          closeError = error;
          closed = true;
        });
        for (var i = 0; i < 100 && !closed; i++) {
          await tester.pump(const Duration(milliseconds: 20));
          await tester.runAsync(() async {
            await Future<void>.delayed(const Duration(milliseconds: 10));
          });
        }
        expect(closed, isTrue, reason: 'DB close must complete after stream disposal');
        expect(closeError, isNull);
        await closing;
        print('D5_03_WIDGET close-complete');
      }
    }
  }, timeout: const Timeout(Duration(seconds: 60)));
}
