import 'glucose_quantity_evidence.dart';

/// D5-05b: staged persistence format, NOT a database or authorization layer.
/// A caller must establish the authenticated owner and the record identity
/// before using this codec. The record binding is not a signature or MAC.
/// No legacy value, source tag, or display preference can create an envelope.
final class GlucoseQuantityStorageEnvelope {
  const GlucoseQuantityStorageEnvelope._();

  static const int schemaVersion = 1;
  static const String conversionPolicy = 'glucose-molar-mass-v1';
  static const String _declared = 'user_entered';
  static const Set<String> _keys = {
    'version', 'client_uuid', 'original_value', 'original_unit',
    'provenance', 'conversion_policy',
  };

  /// Original numeric representation is the shortest round-trip decimal
  /// of the existing double, not necessarily the original input text.
  /// Derived/rounded values are intentionally NOT persisted here.
  static Map<String, Object> encode({
    required String clientUuid,
    required GlucoseQuantityEvidence evidence,
  }) {
    if (!_validIdentity(clientUuid) || !evidence.hasExplicitSourceUnit) {
      throw ArgumentError('Explicit source unit and record identity required');
    }
    return Map<String, Object>.unmodifiable({
      'version': schemaVersion,
      'client_uuid': clientUuid,
      'original_value': evidence.originalRawValue.toString(),
      'original_unit': evidence.originalUnit!.ucumCode,
      'provenance': _declared,
      'conversion_policy': conversionPolicy,
    });
  }

  /// Null means the legacy record has no envelope. A present but malformed
  /// envelope is rejected, not silently downgraded to legacy.
  /// Exact record binding prevents accidental cross-record association.
  /// This method cannot authenticate storage, device provenance or ownership.
  static GlucoseQuantityEvidence? decode({
    required String expectedClientUuid,
    required Map<String, Object?>? envelope,
  }) {
    if (!_validIdentity(expectedClientUuid)) {
      throw ArgumentError('Invalid expected record identity');
    }
    if (envelope == null) return null;
    if (envelope.length != _keys.length ||
        !envelope.keys.every(_keys.contains) ||
        envelope['version'] is! int ||
        envelope['version'] != schemaVersion ||
        envelope['client_uuid'] != expectedClientUuid ||
        envelope['provenance'] != _declared ||
        envelope['conversion_policy'] != conversionPolicy) {
      throw const FormatException('Unsupported or mismatched glucose envelope');
    }
    final raw = envelope['original_value'];
    final unitCode = envelope['original_unit'];
    if (raw is! String || raw.length > 32 || unitCode is! String) {
      throw const FormatException('Invalid glucose envelope field type');
    }
    final unit = GlucoseSourceUnit.fromExplicitUcumCode(unitCode);
    final value = double.tryParse(raw);
    if (unit == null || value == null || !value.isFinite ||
        value <= 0 || value.toString() != raw) {
      throw const FormatException('Invalid or noncanonical glucose evidence');
    }
    try {
      return GlucoseQuantityEvidence.userEntry(
        originalValue: value, declaredUnit: unit,
      );
    } on ArgumentError {
      throw const FormatException('Unrepresentable glucose evidence');
    }
  }

  static bool _validIdentity(String id) =>
      id.isNotEmpty && id.length <= 128 && id.trim() == id &&
      !id.contains(RegExp(r'[\x00-\x1f\x7f]'));
}
