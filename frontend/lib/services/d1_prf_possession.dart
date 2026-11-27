// Trusted composition contract, not a clinical/session authority. Only the
// isolated PRF adapter creates real handles. Never expose raw PRF or keys.
import 'app_lock_authenticator.dart';

abstract interface class D1PrfPossession {
  bool get isLive;
  // Synchronous, idempotent and nonthrowing. Revocation cannot reissue a handle.
  void revoke();
}

abstract interface class D1PrfAcquirer {
  // Only resolves after verified PRF and the credential-global durable CAS.
  // Must recheck isPending around async work and discard late results.
  Future<D1PrfPossession> acquire(AppLockCredential credential, int owner,
      bool Function() isPending, {String? acquisitionId});
}
