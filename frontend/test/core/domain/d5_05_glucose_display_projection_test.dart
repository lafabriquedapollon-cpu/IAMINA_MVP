import 'dart:convert';
import 'dart:io';

import 'package:amina/core/domain/glucose_display_projection.dart';
import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final fixture = jsonDecode(
    File('test/fixtures/d5_05_display_oracles.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final cases = fixture['cases'] as List<dynamic>;
  test('candidate fixture inventory', () {
    expect(fixture['status'], 'CANDIDATE_NOT_RUNTIME');
    expect(cases.length, 19);
  });
  for (final entry in cases) {
    final row = entry as Map<String, dynamic>;
    test('decimal projection ${row['raw']} ${row['sourceUnit']} -> ${row['displayUnit']}', () {
      final source = GlucoseSourceUnit.fromExplicitUcumCode(row['sourceUnit'] as String)!;
      final target = GlucoseSourceUnit.fromExplicitUcumCode(row['displayUnit'] as String)!;
      final raw = double.parse(row['raw'] as String);
      final evidence = GlucoseQuantityEvidence.userEntry(originalValue: raw, declaredUnit: source);
      final canonical = evidence.canonicalMgDl;
      for (var i = 0; i < 5; i++) {
        final projection = GlucoseDisplayProjection.fromEvidence(evidence, target);
        expect(projection?.numericText, row['display']);
        expect(projection?.unit, row['display'] == null ? null : target);
        GlucoseDisplayProjection.fromEvidence(evidence, source);
        expect(evidence.originalRawValue, raw);
        expect(evidence.originalUnit, source);
        expect(evidence.canonicalMgDl, canonical);
      }
    });
  }
  test('legacy and corrupt legacy never produce a numeric or unit projection', () {
    for (final raw in [5.0, 90.98, 0.0, -1.0, double.nan, double.infinity]) {
      final evidence = GlucoseQuantityEvidence.unknownLegacy(storedValue: raw);
      for (final unit in GlucoseSourceUnit.values) {
        expect(GlucoseDisplayProjection.fromEvidence(evidence, unit), isNull);
      }
      expect(evidence.originalUnit, isNull);
      expect(evidence.canonicalMgDl, isNull);
      if (raw.isNaN) {
        expect(evidence.originalRawValue.isNaN, isTrue);
      } else {
        expect(evidence.originalRawValue, raw);
      }
    }
  });
}
