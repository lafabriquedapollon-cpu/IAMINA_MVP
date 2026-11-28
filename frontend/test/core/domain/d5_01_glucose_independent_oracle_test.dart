// Independent numeric fixtures; no production conversion policy change.
import 'dart:convert';
import 'dart:io';

import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/core/utils/glucose_formatter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final fixture = jsonDecode(
    File('test/fixtures/d5_01_glucose_oracles.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final cases = fixture['cases'] as List<dynamic>;
  test('independent fixture inventory', () {
    expect(cases.length, 14);
  });
  for (final entry in cases) {
    final row = entry as Map<String, dynamic>;
    test('NIST oracle ${row['raw']} ${row['sourceUnit']}', () {
      final unit = GlucoseSourceUnit.fromExplicitUcumCode(row['sourceUnit'] as String)!;
      final raw = double.parse(row['raw'] as String);
      final evidence = GlucoseQuantityEvidence.userEntry(
        originalValue: raw, declaredUnit: unit,
      );
      expect(evidence.canonicalMgDl, closeTo(double.parse(row['mgDl'] as String), 1e-10));
      expect(evidence.displayValue(GlucoseSourceUnit.mmolL), closeTo(double.parse(row['mmolL'] as String), 1e-10));
      expect(evidence.displayValue(GlucoseSourceUnit.mgDl), closeTo(double.parse(row['mgDl'] as String), 1e-10));
      expect(evidence.displayValue(unit), raw);
      expect(evidence.originalRawValue, raw);
      expect(evidence.originalUnit, unit);
      expect(evidence.provenance, GlucoseValueProvenance.userEntered);
    });
  }
  test('legacy divergence is observable, not approved', () {
    final d = fixture['legacyDivergence'] as Map<String, dynamic>;
    final raw = double.parse(d['rawMgDl'] as String);
    final evidence = GlucoseQuantityEvidence.userEntry(
      originalValue: raw, declaredUnit: GlucoseSourceUnit.mgDl,
    );
    expect(evidence.displayValue(GlucoseSourceUnit.mmolL)!.toStringAsFixed(1), d['stagedDisplay']);
    expect(GlucoseFormatter.format(raw, 'mmol/L'), "${d['legacyDisplay']} mmol/L");
    expect(d['status'], 'UNRESOLVED_POLICY');
  });
  test('unknown legacy data never becomes canonical', () {
    for (final value in [90.0, 5.0, 0.0, double.nan, double.infinity]) {
      final entry = GlucoseQuantityEvidence.unknownLegacy(storedValue: value);
      expect(entry.originalUnit, isNull);
      expect(entry.canonicalMgDl, isNull);
      expect(entry.displayValue(GlucoseSourceUnit.mmolL), isNull);
      expect(entry.displayValue(GlucoseSourceUnit.mgDl), isNull);
    }
  });
  test('invalid input, overflow and underflow fail closed', () {
    for (final value in [0.0, -1.0, double.nan, double.infinity, double.negativeInfinity]) {
      for (final unit in GlucoseSourceUnit.values) {
        expect(() => GlucoseQuantityEvidence.userEntry(originalValue: value, declaredUnit: unit), throwsArgumentError);
      }
    }
    expect(() => GlucoseConversionContract.toMgDl(1e308, GlucoseSourceUnit.mmolL), throwsArgumentError);
    expect(() => GlucoseConversionContract.convert(double.minPositive, GlucoseSourceUnit.mmolL), throwsArgumentError);
  });
}
