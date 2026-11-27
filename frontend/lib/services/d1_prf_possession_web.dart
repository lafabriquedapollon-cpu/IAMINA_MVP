// Isolated Web candidate. No host imports or script installation in main.
// B2b must compose the exact bridge with the durable vault in the same realm.
import 'dart:js_interop';
import 'app_lock_authenticator.dart';
import 'd1_prf_possession.dart';

@JS('iaminaD1PrfBridge.acquire')
external JSPromise<JSObject> _acquire(JSString credential, JSNumber owner,
    JSFunction pending);
@JS('iaminaD1PrfBridge.isLive')
external JSBoolean _isLive(JSObject token);
@JS('iaminaD1PrfBridge.revoke')
external void _revoke(JSObject token);

final class D1WebPrfAcquirer implements D1PrfAcquirer {
  const D1WebPrfAcquirer();

  @override
  Future<D1PrfPossession> acquire(AppLockCredential credential, int owner,
      bool Function() isPending) async {
    _WebPossession? possession;
    try {
      if (!isPending()) throw const AppLockException('vault_prf_possession_refused');
      final pending = (() => isPending().toJS).toJS;
      final token = await _acquire(credential.encode().toJS, owner.toJS, pending).toDart;
      possession = _WebPossession(token);
      if (!isPending() || !possession.isLive) {
        throw const AppLockException('vault_prf_possession_refused');
      }
      return possession;
    } catch (_) {
      possession?.revoke();
      throw const AppLockException('vault_prf_possession_refused');
    }
  }
}

final class _WebPossession implements D1PrfPossession {
  final JSObject _token;
  bool _revoked = false;
  _WebPossession(this._token);

  @override
  bool get isLive {
    if (_revoked) return false;
    try { return _isLive(_token).toDart; }
    catch (_) { return false; }
  }

  @override
  void revoke() {
    if (_revoked) return;
    _revoked = true;
    try { _revoke(_token); } catch (_) { /* local authority stays revoked */ }
  }
}
