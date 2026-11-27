// Isolated browser executable: no Flutter host, patient state or fallback.
import 'dart:js_interop';
import '../lib/services/app_lock_authenticator.dart';
import '../lib/services/d1_prf_possession_web.dart';

@JS('d1PrfInteropPending')
external JSBoolean _pending();
@JS('d1PrfInteropRun')
external set _run(JSFunction value);

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

void main() {
  _run = ((JSString credential, JSNumber owner) =>
      _probe(credential, owner).toJS).toJS;
}
