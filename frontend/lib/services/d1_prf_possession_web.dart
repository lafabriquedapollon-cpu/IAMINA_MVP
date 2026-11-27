// Isolated Web candidate. No host imports or script installation in main.
// B2b must compose the exact bridge with the durable vault in the same realm.
import 'dart:async';
import 'dart:js_interop';
import 'dart:convert';
import 'app_lock_authenticator.dart';
import 'd1_prf_possession.dart';

@JS('iaminaD1PrfBridge.acquire')
external JSPromise<JSObject> _acquire(JSString credential, JSNumber owner,
    JSFunction pending, JSString? acquisitionId);
@JS('iaminaD1PrfBridge.isLive')
external JSBoolean _isLive(JSObject token);
@JS('iaminaD1PrfBridge.revoke')
external void _revoke(JSObject token);
@JS('iaminaD1PrfBridge.openLease')
external JSPromise<JSObject> _openLease(JSObject token, JSString identity,
    JSFunction pending, JSFunction session);
@JS('iaminaD1PrfBridge.verifyLease')
external JSPromise<JSBoolean> _verifyLease(JSObject token);
@JS('iaminaD1PrfBridge.readEvidence')
external JSPromise<JSString> _readEvidence(JSObject token, JSString uuid);
@JS('iaminaD1PrfBridge.retireLease')
external JSPromise<JSBoolean> _retireLease(JSObject token);

final class D1WebPrfAcquirer implements D1PrfAcquirer {
  const D1WebPrfAcquirer();

  // The opaque handle never crosses this library as a JSObject or raw key.
  Future<D1WebPrfLease> openBoundLease(D1PrfPossession possession, {
    required int owner, required int epoch, required int generation,
    required String acquisitionId, required bool Function() isPending,
    required bool Function() isSessionCurrent,
  }) async {
    D1WebPrfLease? lease;
    try {
      if (possession is! _WebPossession || !possession.isLive || !isPending()) {
        throw const AppLockException('vault_prf_possession_refused');
      }
      final identity = jsonEncode({'owner':owner,'epoch':epoch,
        'generation':generation,'acquisitionId':acquisitionId});
      final token = await _openLease(possession._token, identity.toJS,
          (() => isPending().toJS).toJS,
          (() => isSessionCurrent().toJS).toJS).toDart;
      lease = D1WebPrfLease._(token);
      if (!isPending() || !possession.isLive) {
        throw const AppLockException('vault_prf_possession_refused');
      }
      return lease;
    } catch (_) {
      if (lease != null) await lease.retire();
      throw const AppLockException('vault_prf_possession_refused');
    }
  }

  @override
  Future<D1PrfPossession> acquire(AppLockCredential credential, int owner,
      bool Function() isPending, {String? acquisitionId}) async {
    _WebPossession? possession;
    try {
      if (!isPending()) throw const AppLockException('vault_prf_possession_refused');
      // A suspended authenticator cannot keep AppLock proof-in-flight forever.
      // The callback invalidates any late JS result before releasing the wait.
      var expired = false;
      final pending = (() => (!expired && isPending()).toJS).toJS;
      final work = _acquire(credential.encode().toJS, owner.toJS, pending, acquisitionId?.toJS).toDart;
      final token = await work.timeout(const Duration(seconds: 25),
        onTimeout: () {
          expired = true;
          unawaited(work.then<void>((lateToken) {
            try { _revoke(lateToken); } catch (_) { /* already locally expired */ }
          }, onError: (Object _, StackTrace __) {}));
          throw const AppLockException('vault_prf_possession_refused');
        });
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

final class D1WebPrfLease {
  final JSObject _token;
  bool _retired = false;
  D1WebPrfLease._(this._token);

  Future<bool> verifyCurrent() async {
    if (_retired) return false;
    try {
      final result = (await _verifyLease(_token).toDart).toDart;
      return !_retired && result;
    } catch (_) { return false; }
  }

  Future<String> readEvidence(String uuid) async {
    if (_retired) throw const AppLockException('vault_prf_possession_refused');
    try {
      final result = (await _readEvidence(_token, uuid.toJS).toDart).toDart;
      if (_retired) throw const AppLockException('vault_prf_possession_refused');
      return result;
    } catch (_) {
      throw const AppLockException('vault_prf_possession_refused');
    }
  }

  Future<void> retire() async {
    _retired = true;
    if (!(await _retireLease(_token).toDart).toDart) {
      throw const AppLockException('vault_prf_possession_refused');
    }
  }
}
