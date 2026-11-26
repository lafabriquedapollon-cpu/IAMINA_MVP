/// Explicit candidate build switch, not proof of encrypted storage.
/// Old builds cannot be fenced by this client-side switch. Do not activate
/// the clinical runtime until the durable vault and admission are qualified.
const bool kD1CutoverCandidate = bool.fromEnvironment(
  'IAMINA_D1_CUTOVER_CANDIDATE',
  defaultValue: false,
);

/// Called before driftDatabase constructs any persistent legacy executor.
/// The synthetic memory-only constructor remains available to isolated probes.
String requireD1LegacyDatabaseAllowed(String name) {
  if (kD1CutoverCandidate) {
    throw StateError('Legacy database blocked during encrypted vault cutover');
  }
  return name;
}
