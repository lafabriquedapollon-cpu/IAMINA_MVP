import 'glucose_quantity_evidence.dart';

/// D5-05a candidate display policy. Not connected to patient runtime.
/// Rounds the decimal representation of an already validated double once,
/// using integer arithmetic. It is not a calculation or persistence format.
/// Unknown units and positive readings below display resolution are unavailable.
final class GlucoseDisplayProjection {
  const GlucoseDisplayProjection._(this.numericText, this.unit);

  final String numericText;
  final GlucoseSourceUnit unit;
  static const String policyVersion = 'd5-display-v1-candidate';

  static GlucoseDisplayProjection? fromEvidence(
    GlucoseQuantityEvidence evidence,
    GlucoseSourceUnit displayUnit,
  ) {
    if (!evidence.hasExplicitSourceUnit) return null;
    final source = evidence.originalUnit!;
    var (numerator, denominator) = _positiveDecimal(evidence.originalRawValue);
    // Derive the exact decimal ratio from the single staged factor.
    final (factorNumerator, factorDenominator) =
        _positiveDecimal(GlucoseConversionContract.mgDlPerMmolL);
    if (source != displayUnit) {
      if (source == GlucoseSourceUnit.mmolL) {
        numerator *= factorNumerator;
        denominator *= factorDenominator;
      } else {
        numerator *= factorDenominator;
        denominator *= factorNumerator;
      }
    }
    final decimals = displayUnit == GlucoseSourceUnit.mmolL ? 1 : 0;
    final scale = BigInt.from(10).pow(decimals);
    final scaled = numerator * scale;
    final quotient = scaled ~/ denominator;
    final remainder = scaled % denominator;
    final rounded = quotient +
        (remainder * BigInt.two >= denominator ? BigInt.one : BigInt.zero);
    // A fabricated zero is not a valid display of a positive reading.
    if (rounded == BigInt.zero) return null;
    final digits = rounded.toString().padLeft(decimals + 1, '0');
    final text = decimals == 0
        ? digits
        : '${digits.substring(0, digits.length - decimals)}.'
            '${digits.substring(digits.length - decimals)}';
    return GlucoseDisplayProjection._(text, displayUnit);
  }

  // This preserves the shortest round-trip decimal of the double, not
  // the original lexical precision of an input that has already been parsed.
  static (BigInt, BigInt) _positiveDecimal(double value) {
    final match = RegExp(r'^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$')
        .firstMatch(value.toString());
    if (!value.isFinite || value <= 0 || match == null) {
      throw ArgumentError.value(value, 'value', 'Expected positive finite decimal');
    }
    final fraction = match.group(2) ?? '';
    final exponent = int.parse(match.group(3) ?? '0') - fraction.length;
    final digits = BigInt.parse(match.group(1)! + fraction);
    final ten = BigInt.from(10);
    return exponent >= 0
        ? (digits * ten.pow(exponent), BigInt.one)
        : (digits, ten.pow(-exponent));
  }
}
