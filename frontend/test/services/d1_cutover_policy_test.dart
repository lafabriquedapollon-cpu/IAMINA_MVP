import 'package:amina/data/drift/database.dart';
import 'package:amina/data/drift/patient_vault_scope.dart';
import 'package:amina/services/d1_cutover_policy.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('cutover blocks both persistent factories before construction', () {
    expect(kD1CutoverCandidate, isTrue);
    expect(() => AppDatabase.defaults(), throwsStateError);
    expect(() => AppDatabase.forPatientVault(PatientVaultScope.nativeDjango(900001)), throwsStateError);
    expect(() => AppDatabase.forPatientVault(PatientVaultScope.deviceLocal(
      '12345678-1234-4234-8234-123456789abc',
    )), throwsStateError);
    expect(() => AppDatabase.forPatientVault(PatientVaultScope.auditOnly()), throwsStateError);
  }, skip: !kD1CutoverCandidate ? 'Requires explicit cutover candidate define' : false);
}
