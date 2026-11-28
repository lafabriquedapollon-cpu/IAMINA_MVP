// Internal dispatch contract for the existing opaque AppLock guard.
// No storage, key, proof minting or runtime session authority is granted here.
// A true result is only a process-local guard decision, not durable admission.
import 'app_lock_service.dart';

final class D1AdmissionGuardAdapter {
  final D1VaultAdmissionGuard _guard;
  const D1AdmissionGuardAdapter(this._guard);

  bool dispatch(String phase, int owner, int epoch, {void Function()? onRetired}) {
    return switch (phase) {
      'claim' => _guard.claim(owner, epoch),
      'pending' => _guard.checkPending(owner, epoch),
      'activate' => _guard.activate(owner, epoch),
      'session' => _guard.checkSession(owner, epoch),
      'watch' => onRetired != null && _guard.watchRetirement(owner, epoch, onRetired),
      _ => false,
    };
  }
}
