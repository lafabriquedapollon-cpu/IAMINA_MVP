// Isolated browser executable: no Flutter host, patient state or fallback.
import 'dart:js_interop';
import '../lib/services/app_lock_authenticator.dart';
import '../lib/services/d1_prf_possession_web.dart';

@JS('d1PrfInteropPending')
external JSBoolean _pending();
@JS('d1PrfInteropRun')
external set _run(JSFunction value);
@JS('d1PrfVaultInteropRun')
external set _vaultRun(JSFunction value);

Future<JSString> _probe(JSString credential, JSNumber owner) async {
  try {
    final possession = await const D1WebPrfAcquirer().acquire(
        AppLockCredential.decode(credential.toDart), owner.toDartInt,
        () => _pending().toDart);
    final wasLive = possession.isLive;
    possession.revoke();
    possession.revoke();
    return (wasLive && !possession.isLive ? 'PASS' : 'ERROR').toJS;
  } on AppLockException {
    return 'REFUSED'.toJS;
  } catch (_) {
    return 'ERROR'.toJS;
  }
}

Future<JSString> _vaultProbe(JSString credential, JSNumber owner) async {
  const acquirer = D1WebPrfAcquirer();
  bool pending = true, active = false;
  final possession = await acquirer.acquire(
      AppLockCredential.decode(credential.toDart), owner.toDartInt,
      () => pending && _pending().toDart);
  D1WebPrfLease? lease;
  try {
    lease = await acquirer.openBoundLease(possession, owner: owner.toDartInt,
        epoch: 2, generation: 2, acquisitionId: List.filled(64,'d').join(),
        isPending: () => pending, isSessionCurrent: () => active);
    if (!await lease.verifyCurrent()) return 'ERROR'.toJS;
    pending = false; active = true;
    final data = await lease.readEvidence('ac123456-1234-4abc-8def-000000000001');
    if (!data.contains('7.83') || !data.contains('mmol/L')) return 'ERROR'.toJS;
    possession.revoke();
    if (await lease.verifyCurrent()) return 'ERROR'.toJS;
    await lease.retire();
    return 'PASS'.toJS;
  } catch (_) {
    return 'ERROR'.toJS;
  } finally {
    pending = false; active = false;
    possession.revoke();
    if (lease != null) await lease.retire();
  }
}

void main() {
  _vaultRun = ((JSString credential, JSNumber owner) =>
      _vaultProbe(credential, owner).toJS).toJS;
  _run = ((JSString credential, JSNumber owner) =>
      _probe(credential, owner).toJS).toJS;
}
