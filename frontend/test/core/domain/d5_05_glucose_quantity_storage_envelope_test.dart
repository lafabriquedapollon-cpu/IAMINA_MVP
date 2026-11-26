import 'dart:convert';

import 'package:amina/core/domain/glucose_display_projection.dart';
import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/core/domain/glucose_quantity_storage_envelope.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const id = 'synthetic-glucose-001';
  final evidence = GlucoseQuantityEvidence.userEntry(
    originalValue: 7.83, declaredUnit: GlucoseSourceUnit.mmolL,
  );
  final envelope = GlucoseQuantityStorageEnvelope.encode(
    clientUuid: id, evidence: evidence,
  );
  GlucoseQuantityEvidence? read(Map<String, Object?>? data, {String uuid = id}) =>
      GlucoseQuantityStorageEnvelope.decode(
        expectedClientUuid: uuid, envelope: data,
      );

  test('fixed versioned envelope, original data only', () {
    expect(envelope, {
      'version': 'v1', 'client_uuid': id, 'original_value': '7.83',
      'original_unit': 'mmol/L', 'provenance': 'user_entered',
      'conversion_policy': 'glucose-molar-mass-v1',
    });
    expect(() => envelope['original_value'] = '9.0', throwsUnsupportedError);
  });

  for (final (value, unit) in [
    (7.83, GlucoseSourceUnit.mmolL),
    (90.98, GlucoseSourceUnit.mgDl),
    (90.0, GlucoseSourceUnit.mgDl),
    (0.25, GlucoseSourceUnit.mmolL),
    (1e-7, GlucoseSourceUnit.mgDl),
    (1e100, GlucoseSourceUnit.mgDl),
  ]) {
    test('JSON round trip preserves $value / ${unit.ucumCode}', () {
      final source = GlucoseQuantityEvidence.userEntry(
        originalValue: value, declaredUnit: unit,
      );
      final encoded = GlucoseQuantityStorageEnvelope.encode(
        clientUuid: id, evidence: source,
      );
      final restored = read(Map<String, Object?>.from(
        jsonDecode(jsonEncode(encoded)) as Map,
      ))!;
      expect(restored.originalRawValue, value);
      expect(restored.originalUnit, unit);
      expect(restored.provenance, GlucoseValueProvenance.userEntered);
      expect(restored.canonicalMgDl, source.canonicalMgDl);
      for (final target in GlucoseSourceUnit.values) {
        expect(GlucoseDisplayProjection.fromEvidence(restored, target)?.numericText,
            GlucoseDisplayProjection.fromEvidence(source, target)?.numericText);
      }
    });
  }

  test('absence is distinct from malformed data, legacy cannot be encoded', () {
    expect(read(null), isNull);
    expect(() => read({}), throwsFormatException);
    for (final value in [5.0, 90.98, double.nan, double.infinity]) {
      final legacy = GlucoseQuantityEvidence.unknownLegacy(storedValue: value);
      expect(() => GlucoseQuantityStorageEnvelope.encode(
        clientUuid: id, evidence: legacy,
      ), throwsArgumentError);
      expect(legacy.originalUnit, isNull);
    }
  });

  test('wrong record identity and invalid identity fail closed', () {
    expect(() => read(envelope, uuid: 'synthetic-glucose-002'), throwsFormatException);
    for (final invalid in ['', ' ', ' x', 'x\n', 'a' * 129]) {
      expect(() => read(envelope, uuid: invalid), throwsArgumentError);
      expect(() => GlucoseQuantityStorageEnvelope.encode(
        clientUuid: invalid, evidence: evidence,
      ), throwsArgumentError);
    }
  });

  test('required fields and unknown fields are rejected', () {
    for (final key in envelope.keys) {
      expect(() => read({...envelope}..remove(key)), throwsFormatException,
          reason: key);
    }
    expect(() => read({...envelope, 'canonical_mg_dl': 140.0}), throwsFormatException);
    expect(() => read({...envelope, 'device_verified': true}), throwsFormatException);
  });

  test('invalid versions, policy, provenance and unit fail closed', () {
    for (final (key, value) in <(String, Object?)>[
      ('version', 'v2'), ('version', 1), ('version', 1.0), ('version', '1'),
      ('conversion_policy', 'legacy'), ('provenance', 'device_verified'),
      ('provenance', 'legacy_unknown'), ('original_unit', 'mg/dl'),
      ('original_unit', 'MMOL/L'), ('original_unit', null),
      ('client_uuid', null),
    ]) {
      expect(() => read({...envelope, key: value}), throwsFormatException,
          reason: '$key / $value');
    }
  });

  test('raw field requires a positive finite canonical round-trip string', () {
    for (final raw in <Object?>[
      null, 7.83, '', ' 7.83', '7.830', '+7.83', 'NaN', 'Infinity',
      '-1.0', '0.0', '-0.0', '90.0', '1e999', '1e-999', '0' * 33,
    ]) {
      expect(() => read({...envelope, 'original_value': raw}),
          throwsFormatException, reason: '$raw');
    }
    expect(() => read({...envelope, 'original_value': '1e+308'}),
        throwsFormatException, reason: 'canonical mg/dL overflows');
  });
}
