import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../../core/theme/amina_visual_language.dart';
import '../../../core/theme/app_theme.dart' show kOfflineFontFallbacks;
import '../../../data/drift/database.dart';

// One elapsed-time projection shared by painting and hit testing.
// Calendar grouping uses the range's zone, not the input DateTime's zone.
// UTC day keys encode civil dates only; day boundaries use the real zone,
// so daylight-saving transitions do not become synthetic 24-hour days.
class DashboardTrendTimeAxis {
  final DateTime start;
  final DateTime end;
  final double left;
  final double right;

  const DashboardTrendTimeAxis({
    required this.start,
    required this.end,
    required this.left,
    required this.right,
  });

  bool get valid => end.isAfter(start) && right > left;
  bool includes(DateTime at) =>
      valid && !at.isBefore(start) && !at.isAfter(end);

  DateTime dayKey(DateTime at) {
    final zoned = start.isUtc ? at.toUtc() : at.toLocal();
    return DateTime.utc(zoned.year, zoned.month, zoned.day);
  }

  DateTime _boundary(DateTime day) => start.isUtc
      ? DateTime.utc(day.year, day.month, day.day)
      : DateTime(day.year, day.month, day.day);

  DateTime dayCenter(DateTime day) {
    final from = _boundary(day);
    final until = _boundary(day.add(const Duration(days: 1)));
    final clippedStart = from.isBefore(start) ? start : from;
    final clippedEnd = until.isAfter(end) ? end : until;
    return clippedStart.add(Duration(
      microseconds: clippedEnd.difference(clippedStart).inMicroseconds ~/ 2,
    ));
  }

  Iterable<DateTime> get days sync* {
    if (!valid) return;
    final last = dayKey(end);
    for (var day = dayKey(start); !day.isAfter(last);
        day = day.add(const Duration(days: 1))) {
      yield day;
    }
  }

  double xFor(DateTime at) {
    final fraction = at.difference(start).inMicroseconds /
        end.difference(start).inMicroseconds;
    return left + fraction.clamp(0.0, 1.0).toDouble() * (right - left);
  }

  DateTime? timeAt(double x) {
    if (!valid || !x.isFinite || x < left || x > right) return null;
    final fraction = (x - left) / (right - left);
    return start.add(Duration(
      microseconds: (end.difference(start).inMicroseconds * fraction).round(),
    ));
  }

  int? selectLog(List<LogEntryData> logs, double x, {required bool daily}) {
    final target = timeAt(x);
    if (target == null) return null;
    final day = dayKey(target);
    LogEntryData? nearest;
    int? distance;
    for (final log in logs) {
      final at = log.loggedAt ?? log.createdAt;
      if (!includes(at) || (daily && dayKey(at) != day)) continue;
      final delta = at.difference(target).inMicroseconds.abs();
      if (distance == null || delta < distance ||
          (delta == distance && log.id < nearest!.id)) {
        nearest = log;
        distance = delta;
      }
    }
    return nearest?.id;
  }
}

class DashboardTrendPainter extends CustomPainter {
  final List<LogEntryData> logs;
  final List<MedicationEventData> medications;
  final DateTime start;
  final DateTime end;
  final double? low;
  final double? high;
  final int selectedLogId;
  final String unit;
  final String locale;
  final bool isDark;
  final bool dailySummary;

  const DashboardTrendPainter({
    required this.logs,
    required this.medications,
    required this.start,
    required this.end,
    required this.low,
    required this.high,
    required this.selectedLogId,
    required this.unit,
    required this.locale,
    required this.isDark,
    required this.dailySummary,
  });

  static const double leftInset = 46;
  static const double rightInset = 10;

  DateTime _recordedAt(LogEntryData log) => log.loggedAt ?? log.createdAt;

  String _valueLabel(double mgDl) => unit == 'mmol/L'
      ? (mgDl / 18.0).toStringAsFixed(1)
      : mgDl.toStringAsFixed(0);

  @override
  void paint(Canvas canvas, Size size) {
    const top = 12.0;
    const bottom = 30.0;
    final rect = Rect.fromLTRB(
      leftInset,
      top,
      size.width - rightInset,
      size.height - bottom,
    );
    final axis = DashboardTrendTimeAxis(
      start: start, end: end, left: rect.left, right: rect.right,
    );
    if (rect.height <= 0 || !axis.valid) return;
    final visible = logs.where((log) => axis.includes(_recordedAt(log))).toList();
    if (visible.isEmpty) return;

    final bounds = _valueBounds(visible);
    final minY = bounds.$1;
    final maxY = bounds.$2;

    double yFor(double value) =>
        rect.bottom - ((value - minY) / (maxY - minY)) * rect.height;

    _paintTargetBand(canvas, rect, yFor);
    _paintGridAndAxes(canvas, rect, minY, maxY, axis);
    _paintMedicationEvents(canvas, rect, axis);

    if (dailySummary) {
      _paintDailySummary(canvas, yFor, axis, visible);
    } else {
      _paintRecordedPoints(canvas, axis.xFor, yFor, visible);
    }
  }

  (double, double) _valueBounds(List<LogEntryData> visible) {
    final values = <double>[
      ...visible.map((log) => log.bloodSugar),
      if (low != null) low!,
      if (high != null) high!,
    ];
    final observedMax = values.reduce(math.max);
    final maxY = math.max(300.0, (observedMax / 50).ceil() * 50.0).toDouble();
    return (0.0, maxY);
  }

  void _paintTargetBand(
    Canvas canvas,
    Rect rect,
    double Function(double) yFor,
  ) {
    if (low == null || high == null || low! >= high!) return;
    final top = yFor(high!).clamp(rect.top, rect.bottom).toDouble();
    final bottom = yFor(low!).clamp(rect.top, rect.bottom).toDouble();
    final bandRect = Rect.fromLTRB(rect.left, top, rect.right, bottom);
    canvas.drawRect(
      bandRect,
      Paint()..color = AminaVisualLanguage.mintSurface.withValues(alpha: .55),
    );
    final edgePaint = Paint()
      ..color = AminaVisualLanguage.mintBorder.withValues(alpha: .78)
      ..strokeWidth = 1;
    _drawDashedLine(
      canvas,
      Offset(rect.left, top),
      Offset(rect.right, top),
      edgePaint,
    );
    _drawDashedLine(
      canvas,
      Offset(rect.left, bottom),
      Offset(rect.right, bottom),
      edgePaint,
    );
  }

  void _paintGridAndAxes(
    Canvas canvas,
    Rect rect,
    double minY,
    double maxY,
    DashboardTrendTimeAxis axis,
  ) {
    final gridPaint = Paint()
      ..color = (isDark ? Colors.white : const Color(0xFF123E35))
          .withValues(alpha: .08)
      ..strokeWidth = 1;
    final axisStyle = TextStyle(
      fontSize: 9.5,
      fontFamily: locale.toLowerCase().startsWith('ar') ? 'NotoSansArabic' : 'Inter',
      fontFamilyFallback: kOfflineFontFallbacks,
      color: (isDark ? Colors.white : const Color(0xFF42655D))
          .withValues(alpha: .78),
    );

    final ticks = _axisTicks(minY, maxY);
    for (final value in ticks) {
      final fraction = (value - minY) / (maxY - minY);
      final y = rect.bottom - fraction * rect.height;
      canvas.drawLine(Offset(rect.left, y), Offset(rect.right, y), gridPaint);
      final painter = TextPainter(
        text: TextSpan(text: _valueLabel(value), style: axisStyle),
        textDirection: ui.TextDirection.ltr,
      )..layout(maxWidth: leftInset - 6);
      painter.paint(
        canvas,
        Offset(leftInset - painter.width - 7, y - painter.height / 2),
      );
    }

    if (dailySummary) {
      final days = axis.days.toList(growable: false);
      final maxLabels = math.max(2, math.min(6, (rect.width / 72).floor()));
      final labelStride = math.max(1, ((days.length - 1) / (maxLabels - 1)).ceil());
      double? lastLabelX;
      for (var i = 0; i < days.length; i++) {
        final day = days[i];
        final x = axis.xFor(axis.dayCenter(day));
        final guide = Paint()
          ..color = (isDark ? Colors.white : const Color(0xFF123E35))
              .withValues(alpha: .045)
          ..strokeWidth = 1;
        canvas.drawLine(Offset(x, rect.top), Offset(x, rect.bottom), guide);
        final showLabel = i % labelStride == 0 || i == days.length - 1;
        if (showLabel && (lastLabelX == null || x - lastLabelX >= 72)) {
          lastLabelX = x;
          _paintXAxisLabel(
            canvas,
            DateFormat('d MMM', locale).format(day),
            x,
            rect,
            axisStyle,
          );
        }
      }
      return;
    }

    final range = end.difference(start);
    final times = [
      start,
      start.add(Duration(milliseconds: range.inMilliseconds ~/ 2)),
      end,
    ];
    for (var i = 0; i < times.length; i++) {
      final label = DateFormat('HH:mm', locale).format(times[i]);
      final x = rect.left + rect.width * (i / 2);
      _paintXAxisLabel(canvas, label, x, rect, axisStyle, edgeIndex: i);
    }
  }

  List<double> _axisTicks(double minY, double maxY) {
    if (minY == 0 && maxY == 300) return const [0, 70, 132, 210, 300];
    final step = (maxY - minY) / 4;
    return [minY, minY + step, minY + step * 2, minY + step * 3, maxY];
  }

  void _paintXAxisLabel(
    Canvas canvas,
    String label,
    double x,
    Rect rect,
    TextStyle style, {
    int? edgeIndex,
  }) {
    final painter = TextPainter(
      text: TextSpan(text: label, style: style),
      textDirection: ui.TextDirection.ltr,
    )..layout(maxWidth: rect.width);
    var dx = x - painter.width / 2;
    if (edgeIndex == 0) dx = rect.left;
    if (edgeIndex == 2) dx = rect.right - painter.width;
    dx = dx.clamp(rect.left, rect.right - painter.width).toDouble();
    painter.paint(canvas, Offset(dx, rect.bottom + 8));
  }

  void _paintMedicationEvents(
    Canvas canvas,
    Rect rect,
    DashboardTrendTimeAxis axis,
  ) {
    if (medications.isEmpty) return;
    final paint = Paint()
      ..color = const Color(0xFFC9852B).withValues(alpha: .8)
      ..strokeWidth = 1.5;
    for (final event in medications) {
      if (!axis.includes(event.takenAt)) continue;
      final x = axis.xFor(event.takenAt);
      canvas.drawLine(Offset(x, rect.top), Offset(x, rect.top + 8), paint);
      canvas.drawCircle(Offset(x, rect.top + 1), 2.2, paint);
    }
  }

  void _paintDailySummary(
    Canvas canvas,
    double Function(double) yFor,
    DashboardTrendTimeAxis axis,
    List<LogEntryData> visible,
  ) {
    final summaries = _dailySummaries(axis, visible);
    if (summaries.isEmpty) return;

    final whiskerPaint = Paint()
      ..color = AminaVisualLanguage.forestDeep.withValues(alpha: .46)
      ..strokeWidth = 1.7
      ..strokeCap = StrokeCap.round;
    final linePaint = Paint()
      ..color = AminaVisualLanguage.forestDeep
      ..strokeWidth = 2.1
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    final pointPaint = Paint()..color = AminaVisualLanguage.forestDeep;
    final selectedPaint = Paint()..color = AminaVisualLanguage.actionGreen;

    final points = <Offset>[];
    for (var i = 0; i < summaries.length; i++) {
      final summary = summaries[i];
      final x = axis.xFor(axis.dayCenter(summary.day));
      final yMin = yFor(summary.min);
      final yMax = yFor(summary.max);
      canvas.drawLine(Offset(x, yMax), Offset(x, yMin), whiskerPaint);
      points.add(Offset(x, yFor(summary.median)));
    }

    if (points.length > 1) {
      final path = Path();
      var hasSegment = false;
      for (var i = 0; i < points.length - 1; i++) {
        // Missing days are not measurements: leave the interval blank.
        if (summaries[i + 1].day.difference(summaries[i].day).inDays != 1) {
          continue;
        }
        final current = points[i];
        final next = points[i + 1];
        final midX = (current.dx + next.dx) / 2;
        path.moveTo(current.dx, current.dy);
        path.cubicTo(midX, current.dy, midX, next.dy, next.dx, next.dy);
        hasSegment = true;
      }
      if (hasSegment) canvas.drawPath(path, linePaint);
    }

    for (var i = 0; i < summaries.length; i++) {
      final summary = summaries[i];
      final point = points[i];
      final selected = summary.logIds.contains(selectedLogId);
      final latest = i == summaries.length - 1;

      if (selected || latest) {
        canvas.drawCircle(
          point,
          selected ? 8.0 : 7.0,
          Paint()..color = AminaVisualLanguage.mintSurface,
        );
      }
      canvas.drawCircle(
        point,
        selected ? 5.2 : latest ? 4.8 : 4.2,
        selected || latest ? selectedPaint : pointPaint,
      );
      if (latest) {
        canvas.drawCircle(
          point,
          9.5,
          Paint()
            ..color = AminaVisualLanguage.actionGreen
            ..style = PaintingStyle.stroke
            ..strokeWidth = 1.5,
        );
      }
    }
  }

  List<_DailySummary> _dailySummaries(
    DashboardTrendTimeAxis axis, List<LogEntryData> visible,
  ) {
    final byDay = <DateTime, List<LogEntryData>>{};
    for (final log in visible) {
      final day = axis.dayKey(_recordedAt(log));
      byDay.putIfAbsent(day, () => <LogEntryData>[]).add(log);
    }
    final days = byDay.keys.toList()..sort();
    return days.map((day) {
      final dayLogs = byDay[day]!
        ..sort((a, b) => a.bloodSugar.compareTo(b.bloodSugar));
      final values = dayLogs.map((log) => log.bloodSugar).toList(growable: false);
      final median = values.length.isOdd
          ? values[values.length ~/ 2]
          : (values[values.length ~/ 2 - 1] + values[values.length ~/ 2]) / 2;
      return _DailySummary(
        day: day,
        median: median,
        min: values.first,
        max: values.last,
        logIds: dayLogs.map((log) => log.id).toSet(),
      );
    }).toList(growable: false);
  }

  void _paintRecordedPoints(
    Canvas canvas,
    double Function(DateTime) xFor,
    double Function(double) yFor,
    List<LogEntryData> visible,
  ) {
    final pointPaint = Paint()
      ..color = AminaVisualLanguage.forestDeep.withValues(alpha: .78);
    final selectedPaint = Paint()..color = AminaVisualLanguage.actionGreen;
    final latestId = visible
        .reduce((a, b) => _recordedAt(a).isAfter(_recordedAt(b)) ? a : b)
        .id;

    for (final log in visible) {
      final point = Offset(xFor(_recordedAt(log)), yFor(log.bloodSugar));
      final selected = log.id == selectedLogId;
      final latest = log.id == latestId;
      if (selected || latest) {
        canvas.drawCircle(
          point,
          selected ? 7 : 6.2,
          Paint()..color = AminaVisualLanguage.mintSurface,
        );
      }
      canvas.drawCircle(
        point,
        selected ? 4.8 : latest ? 4.4 : 3.0,
        selected || latest ? selectedPaint : pointPaint,
      );
    }
  }

  void _drawDashedLine(
    Canvas canvas,
    Offset startOffset,
    Offset endOffset,
    Paint paint,
  ) {
    const dash = 5.0;
    const gap = 4.0;
    var x = startOffset.dx;
    while (x < endOffset.dx) {
      final endX = math.min(x + dash, endOffset.dx);
      canvas.drawLine(
        Offset(x, startOffset.dy),
        Offset(endX, endOffset.dy),
        paint,
      );
      x += dash + gap;
    }
  }

  @override
  bool shouldRepaint(covariant DashboardTrendPainter oldDelegate) {
    return oldDelegate.logs != logs ||
        oldDelegate.medications != medications ||
        oldDelegate.start != start ||
        oldDelegate.end != end ||
        oldDelegate.low != low ||
        oldDelegate.high != high ||
        oldDelegate.selectedLogId != selectedLogId ||
        oldDelegate.unit != unit ||
        oldDelegate.locale != locale ||
        oldDelegate.isDark != isDark ||
        oldDelegate.dailySummary != dailySummary;
  }
}

class _DailySummary {
  final DateTime day;
  final double median;
  final double min;
  final double max;
  final Set<int> logIds;

  const _DailySummary({
    required this.day,
    required this.median,
    required this.min,
    required this.max,
    required this.logIds,
  });
}
