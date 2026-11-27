// D5-03: descriptive observations, not clinical validation.
// Known gaps are characterization assertions, never acceptance of the policy.
import 'dart:ui' as ui;
import 'dart:io';
import 'package:flutter/rendering.dart' show RenderRepaintBoundary;
import 'package:flutter/services.dart' show FontLoader;

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

LogEntryData reading(int id, double value, DateTime at, {DateTime? created, bool fallback = false, String source = 'manual'}) =>
    LogEntryData(
      id: id, createdAt: created ?? at, loggedAt: fallback ? null : at,
      bloodSugar: value, source: source, syncStatus: 'pending',
      clientUuid: 'synthetic-$id', isSick: false, isStressed: false,
      isTired: false, isActive: false, ramadanMode: false,
      syncAttempts: 0, errorSync: false,
    );

// Captures actual drawing calls, not a second implementation of aggregation.
// Text is intentionally not compared: this is a VM numeric geometry test.
class RecordingCanvas implements Canvas {
  final lines = <(Offset, Offset)>[];
  final circles = <Offset>[];
  final paths = <Rect>[];

  @override
  void drawLine(Offset p1, Offset p2, Paint paint) => lines.add((p1, p2));
  @override
  void drawCircle(Offset c, double radius, Paint paint) => circles.add(c);
  @override
  void drawParagraph(ui.Paragraph paragraph, Offset offset) {}
  @override
  void drawPath(Path path, Paint paint) => paths.add(path.getBounds());
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

DashboardTrendPainter painter(List<LogEntryData> rows, {List<MedicationEventData> medications = const []}) =>
    DashboardTrendPainter(
      logs: rows, medications: medications, start: DateTime.utc(2026, 11, 1),
      end: DateTime.utc(2026, 11, 8), low: null, high: null,
      selectedLogId: -1, unit: 'mg/dL', locale: 'en_US',
      isDark: false, dailySummary: true,
    );

bool near(double a, double b) => (a - b).abs() < 0.00001;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final day1 = DateTime.utc(2026, 11, 1, 12);
  final day2 = DateTime.utc(2026, 11, 2, 12);
  final day5 = DateTime.utc(2026, 11, 5, 12);
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
    // Day centres at 0.5, 1.5 and 4.5 elapsed days of a seven-day range.
    // Expected y values:
    // 80=164.5333333; 90=157.6; 120=136.8; 150=116;
    // 160=109.0666667; 210=74.4.
    const x = [46 + 544 * .5 / 7, 46 + 544 * 1.5 / 7, 46 + 544 * 4.5 / 7];
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

  test('H1 temporal geometry: gaps preserved and treatment exact', () {
    final canvas = RecordingCanvas();
    final treatment = MedicationEventData(
      id: 1, label: 'synthetic recorded event', takenAt: DateTime.utc(2026, 11, 3, 12),
      createdAt: day5,
    );
    painter(rows, medications: [treatment]).paint(canvas, const Size(600, 250));
    // Independent geometry, elapsed days rather than index of observations.
    const x1 = 46 + 544 * .5 / 7;
    const x2 = 46 + 544 * 1.5 / 7;
    const x3 = 46 + 544 * 2.5 / 7;
    const x5 = 46 + 544 * 4.5 / 7;
    expect(canvas.circles.any((c) => near(c.dx, x1) && near(c.dy, 136.8)), isTrue,
        reason: 'H1 actual day 1 centre');
    expect(canvas.circles.any((c) => near(c.dx, x2) && near(c.dy, 136.8)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, x5) && near(c.dy, 74.4)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, x3) && near(c.dy, 13)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, x2) && near(c.dy, 13)), isFalse);
    expect(canvas.circles.where((c) => c.dy > 20).map((c) => c.dx).toSet().length, 3);
    expect(canvas.paths, hasLength(1));
    expect(canvas.paths.single.left, closeTo(x1, .001));
    expect(canvas.paths.single.right, closeTo(x2, .001),
        reason: 'no connecting trajectory across the missing days');
  });

  test('H1 range edges, UTC civil dates and exact event time', () {
    final start = DateTime.utc(2026, 10, 31, 18);
    final end = DateTime.utc(2026, 11, 2, 6);
    final data = [
      reading(1, 120, DateTime.utc(2026, 10, 31, 19)),
      reading(2, 150, DateTime.utc(2026, 11, 2, 2)),
      reading(3, 999, start.subtract(const Duration(seconds: 1))),
      reading(4, 999, end.add(const Duration(seconds: 1))),
    ];
    final events = [
      MedicationEventData(id: 1, label: 'fixture', takenAt: DateTime.utc(2026, 11, 1, 3), createdAt: end),
      MedicationEventData(id: 2, label: 'outside', takenAt: start.subtract(const Duration(seconds: 1)), createdAt: end),
      MedicationEventData(id: 3, label: 'edge', takenAt: end, createdAt: end),
    ];
    final canvas = RecordingCanvas();
    DashboardTrendPainter(logs: data, medications: events, start: start, end: end,
      low: null, high: null, selectedLogId: -1, unit: 'mg/dL', locale: 'en_US',
      isDark: false, dailySummary: true).paint(canvas, const Size(600, 250));
    // Range is 36h; the two partial civil days span six hours each.
    expect(canvas.circles.any((c) => near(c.dx, 46 + 544 * 3 / 36) && near(c.dy, 136.8)), isTrue);
    expect(canvas.circles.any((c) => near(c.dx, 46 + 544 * 33 / 36) && near(c.dy, 116)), isTrue);
    final markers = canvas.circles.where((c) => near(c.dy, 13)).toList();
    expect(markers, hasLength(2));
    expect(markers.any((c) => near(c.dx, 46 + 544 * 9 / 36)), isTrue);
    expect(markers.any((c) => near(c.dx, 590)), isTrue);
    expect(canvas.paths, isEmpty);
  });

  testWidgets('H1 tap uses painted time and refuses empty days FR AR', (tester) async {
    addTearDown(() async { await tester.binding.setSurfaceSize(null); });
    for (final locale in [const Locale('fr'), const Locale('ar')]) {
      for (final width in [390.0, 430.0, 1280.0]) {
        await tester.binding.setSurfaceSize(Size(width, 600));
        final selected = <int>[];
        await tester.pumpWidget(MaterialApp(
          locale: locale, localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(body: SizedBox(width: width, height: 250,
            child: DashboardTrendPlot(logs: rows, medications: const [],
              start: DateTime.utc(2026, 11, 1), end: DateTime.utc(2026, 11, 8),
              low: null, high: null, selectedLogId: -1, unit: 'mg/dL',
              locale: locale.languageCode == 'ar' ? 'ar-MA' : 'fr-FR',
              dailySummary: true, onSelect: selected.add))),
        ));
        await tester.pumpAndSettle();
        final rect = tester.getRect(find.byType(DashboardTrendPlot));
        Offset point(double days) => Offset(rect.left + 46 + (rect.width - 56) * days / 7, rect.top + 100);
        await tester.tapAt(point(.5)); // three tied times, stable lowest ID
        await tester.tapAt(point(1.5));
        await tester.tapAt(point(2.5)); // empty day
        await tester.tapAt(point(4.5));
        await tester.tapAt(Offset(rect.left + 10, rect.top + 100)); // axis, not data
        expect(selected, [1, 4, 6], reason: '${locale.languageCode} $width');
        expect(tester.takeException(), isNull);
      }
    }
  });

  testWidgets('H1 intraday tap retains real timestamps and excludes margins', (tester) async {
    addTearDown(() async { await tester.binding.setSurfaceSize(null); });
    await tester.binding.setSurfaceSize(const Size(390, 844));
    final start = DateTime.utc(2026, 11, 1);
    final end = start.add(const Duration(hours: 24));
    final logs = [
      reading(5, 150, start.add(const Duration(hours: 18))),
      reading(2, 100, start.add(const Duration(hours: 6))),
      reading(1, 120, start.subtract(const Duration(seconds: 1))),
    ];
    final selected = <int>[];
    await tester.pumpWidget(MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Scaffold(body: SizedBox(width: 390, height: 250,
        child: DashboardTrendPlot(logs: logs, medications: const [],
          start: start, end: end, low: null, high: null, selectedLogId: -1,
          unit: 'mg/dL', locale: 'en_US', dailySummary: false, onSelect: selected.add))),
    ));
    await tester.pumpAndSettle();
    final rect = tester.getRect(find.byType(DashboardTrendPlot));
    await tester.tapAt(Offset(rect.left + 46 + (rect.width - 56) * .25, rect.top + 100));
    await tester.tapAt(Offset(rect.left + 46 + (rect.width - 56) * .75, rect.top + 100));
    await tester.tapAt(Offset(rect.left + 5, rect.top + 100));
    expect(selected, [2, 5]);
    expect(tester.takeException(), isNull);
  });

  testWidgets('H1 visual proof of real plot', (tester) async {
    final directory = Platform.environment['H1_CAPTURE_DIR']!;
    addTearDown(() async { await tester.binding.setSurfaceSize(null); });
    for (final family in ['Inter', 'NotoSansArabic', 'Roboto', 'NotoSansSymbols']) {
      final bytes = File('assets/fonts/$family.ttf').readAsBytesSync();
      final loader = FontLoader(family)..addFont(Future.value(bytes.buffer.asByteData()));
      await tester.runAsync(loader.load);
    }
    final treatment = MedicationEventData(
      id: 1, label: 'synthetic recorded event', takenAt: DateTime.utc(2026, 11, 3, 12), createdAt: day5,
    );
    for (final locale in [const Locale('fr'), const Locale('ar')]) {
      for (final (width, height) in [(390.0, 844.0), (430.0, 932.0), (1280.0, 860.0)]) {
        await tester.binding.setSurfaceSize(Size(width, height));
        final key = GlobalKey();
        await tester.pumpWidget(MaterialApp(
          locale: locale, localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: ThemeData(fontFamily: locale.languageCode == 'ar' ? 'NotoSansArabic' : 'Inter'),
          home: Scaffold(body: RepaintBoundary(key: key, child: SizedBox(
            width: width, height: height, child: ColoredBox(color: Colors.white,
              child: Column(children: [
                SizedBox(height: 250, child: DashboardTrendPlot(logs: rows,
                  medications: [treatment], start: DateTime.utc(2026, 11, 1),
                  end: DateTime.utc(2026, 11, 8), low: null, high: null, selectedLogId: 6,
                  unit: 'mg/dL', locale: locale.languageCode == 'ar' ? 'ar-MA' : 'fr-FR',
                  dailySummary: true, onSelect: (_) {})),
                const DashboardTrendLegend(unit: 'mg/dL', low: null, high: null,
                  dailySummary: true, medicationCount: 1),
              ])),
          ))),
        ));
        await tester.pumpAndSettle();
        final boundary = key.currentContext!.findRenderObject() as RenderRepaintBoundary;
        await tester.runAsync(() async {
          final image = await boundary.toImage(pixelRatio: 1);
          try {
            final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
            if (bytes == null) throw StateError('Missing screenshot bytes');
            final output = File('$directory/${locale.languageCode}-${width.toInt()}.png');
            await output.parent.create(recursive: true);
            await output.writeAsBytes(bytes.buffer.asUint8List(bytes.offsetInBytes, bytes.lengthInBytes));
          } finally { image.dispose(); }
        });
        expect(File('$directory/${locale.languageCode}-${width.toInt()}.png').lengthSync(), greaterThan(1000));
        expect(tester.takeException(), isNull);
      }
    }
    await tester.pumpWidget(const SizedBox.shrink());
  }, skip: Platform.environment['H1_CAPTURE_DIR'] == null);

  test('source tags are exact, localized and never verified provenance', () {
    for (final (locale, manual, cgm, imported, recorded) in [
      (AppLocalizationsFr(), 'Manuel (non vérifié)', 'CGM (non vérifié)', 'Import (non vérifié)', 'Enregistré'),
      (AppLocalizationsAr(), 'يدوي (غير موثق)', 'CGM (غير موثق)', 'استيراد (غير موثق)', 'مسجل'),
      (AppLocalizationsEn(), 'Manual (unverified)', 'CGM (unverified)', 'Import (unverified)', 'Recorded'),
    ]) {
      expect(locale.dashboardTrendSourceLabel('manual'), manual);
      expect(locale.dashboardTrendSourceLabel(' MANUAL '), manual);
      expect(locale.dashboardTrendSourceLabel(' CGM '), cgm);
      expect(locale.dashboardTrendSourceLabel('imported'), imported);
      for (final unknown in [
        '', 'unknown', 'not_cgm', 'not_imported', 'cgm_verified',
        'manual_device', 'cgm-import', 'import', 'imported_csv',
        'verified_cgm', 'cgm\u200b', 'manual cgm',
      ]) {
        expect(locale.dashboardTrendSourceLabel(unknown), recorded, reason: unknown);
      }
    }
  });

  testWidgets('real selection card refuses ambiguous source tags at Web widths', (tester) async {
    addTearDown(() async {
      await tester.binding.setSurfaceSize(null);
    });
    for (final (locale, manual, cgm, imported, recorded) in [
      (const Locale('fr'), 'Manuel (non vérifié)', 'CGM (non vérifié)', 'Import (non vérifié)', 'Enregistré'),
      (const Locale('ar'), 'يدوي (غير موثق)', 'CGM (غير موثق)', 'استيراد (غير موثق)', 'مسجل'),
      (const Locale('en'), 'Manual (unverified)', 'CGM (unverified)', 'Import (unverified)', 'Recorded'),
    ]) {
      for (final width in [390.0, 430.0, 768.0, 1280.0]) {
        await tester.binding.setSurfaceSize(Size(width, 900));
        for (final (source, label) in [
          ('not_cgm', recorded), ('not_imported', recorded),
          ('manual', manual), ('cgm', cgm), ('imported', imported),
        ]) {
          final log = reading(1, 120, day1, source: source);
          await tester.pumpWidget(MaterialApp(
            locale: locale,
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: SingleChildScrollView(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: DashboardTrendSelectionCard(
                  log: log, unit: 'mg/dL', locale: locale.languageCode,
                ),
              ),
            )),
          ));
          await tester.pumpAndSettle();
          final card = find.byType(DashboardTrendSelectionCard);
          final sourceLabel = find.descendant(of: card, matching: find.text(label));
          expect(sourceLabel, findsOneWidget,
              reason: '${locale.languageCode} / $width / $source');
          final cardBounds = tester.getRect(card);
          final labelBounds = tester.getRect(sourceLabel);
          expect(labelBounds.left, greaterThanOrEqualTo(cardBounds.left));
          expect(labelBounds.right, lessThanOrEqualTo(cardBounds.right));
          expect(labelBounds.top, greaterThanOrEqualTo(cardBounds.top));
          expect(labelBounds.bottom, lessThanOrEqualTo(cardBounds.bottom));
          expect(Directionality.of(tester.element(card)),
              locale.languageCode == 'ar' ? TextDirection.rtl : TextDirection.ltr);
          expect(log.source, source);
          expect(log.bloodSugar, 120.0);
          expect(tester.takeException(), isNull,
              reason: 'layout at ${locale.languageCode} / $width / $source');
        }
      }
    }
    await tester.pumpWidget(const SizedBox.shrink());
  }, timeout: const Timeout(Duration(seconds: 60)));

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
