// CONV-03B1: runtime admission contract, not wired into main or legacy host.
// Durable possession, fencing and atomic authorization belong to the backend.
// No production implementation is admitted by this file alone.
import 'dart:async';

import '../core/domain/glucose_quantity_evidence.dart';
import 'app_lock_service.dart';
import 'auth_service.dart';

typedef D1RuntimeIdentity = ({int owner, int epoch, int generation});

/// Trusted internal composition boundary. Implementations must acquire a
/// possession-bound durable lease, never open a legacy DB or return raw keys.
/// Each read must itself enforce the durable fence, including after async work.
abstract interface class D1DurableRuntimeBackend {
  // On failure, the backend must clean up its own partial acquisition.
  // A mismatched lease must never be operated on by the coordinator.
  Future<D1DurableRuntimeLease> acquire(D1RuntimeIdentity identity);
}

abstract interface class D1DurableRuntimeLease {
  D1RuntimeIdentity get identity;
  Future<bool> verifyCurrent();
  Future<GlucoseQuantityEvidence?> readEvidence(String uuid);
  // Must retire only this lease, be idempotent and never revoke its successor.
  Future<void> retire();
}

final class D1RuntimeAdmissionException implements Exception {
  const D1RuntimeAdmissionException();
}

/// A read-only first slice. No DB, key, transport or generic mutation escape.
final class D1RuntimeSession {
  final D1RuntimeIdentity _identity;
  final D1VaultAdmissionGuard _guard;
  final D1DurableRuntimeLease _lease;
  bool _retired = false;
  Future<void>? _retirement;
  bool _durableRetirementFailed = false;

  // A failed durable retirement remains observable; never reopens the session.
  bool get durableRetirementFailed => _durableRetirementFailed;

  D1RuntimeSession._(this._identity, this._guard, this._lease);

  // Local authorization only; durable currency is checked on every read.
  bool get isActive => !_retired &&
      _guard.checkSession(_identity.owner, _identity.epoch);

  void _requireActive() {
    if (!isActive) throw const D1RuntimeAdmissionException();
  }

  Future<void> _verify() async {
    _requireActive();
    if (_lease.identity != _identity || !await _lease.verifyCurrent()) {
      throw const D1RuntimeAdmissionException();
    }
    _requireActive();
  }

  Future<GlucoseQuantityEvidence?> readEvidence(String uuid) async {
    try {
      await _verify();
      if (!RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$').hasMatch(uuid)) {
        throw const D1RuntimeAdmissionException();
      }
      _requireActive();
      final result = await _lease.readEvidence(uuid);
      await _verify();
      _requireActive();
      if (result != null && !result.hasExplicitSourceUnit) {
        throw const D1RuntimeAdmissionException();
      }
      return result;
    } catch (_) {
      await retire();
      throw const D1RuntimeAdmissionException();
    }
  }

  Future<void> retire() {
    _retired = true;
    return _retirement ??= Future<void>.sync(_lease.retire).then<void>(
      (_) { _durableRetirementFailed = false; },
      onError: (Object _, StackTrace __) {
        _durableRetirementFailed = true;
        _retirement = null; // explicit retry, never restore local authority
        throw const D1RuntimeAdmissionException();
      },
    );
  }
}

final class D1RuntimeAdmission {
  final AuthService _auth;
  final AppLockService _lock;
  final D1DurableRuntimeBackend _backend;
  D1RuntimeAdmission(this._auth, this._lock, this._backend);

  // The issuer's watcher invalidates local authority synchronously. Durable
  // retirement is asynchronous; failures are not treated as proof of release.
  Future<D1RuntimeSession> admit() async {
    final owner = _auth.boundNativeAccountId;
    final generation = _auth.verifiedNativeAdmissionGeneration;
    if (owner == null || generation == null) {
      throw const D1RuntimeAdmissionException();
    }
    final identity = (owner: owner, epoch: AuthService.authEpoch, generation: generation);
    final proof = await _lock.issueVaultAdmissionProof();
    final guard = _lock.consumeVaultAdmissionProof(proof, owner: owner);
    D1RuntimeSession? session;
    D1DurableRuntimeLease? lease;
    var retired = false;
    bool pending() => !retired &&
        _auth.verifiedNativeAdmissionGeneration == generation &&
        guard.checkPending(owner, identity.epoch);
    try {
      if (!guard.claim(owner, identity.epoch) ||
          !guard.watchRetirement(owner, identity.epoch, () {
            retired = true;
            final current = session;
            if (current != null) {
              unawaited(current.retire().catchError((Object _) {}));
            }
          }) || !pending()) {
        throw const D1RuntimeAdmissionException();
      }
      lease = await _backend.acquire(identity);
      if (!pending() || lease.identity != identity ||
          !await lease.verifyCurrent() || !pending() ||
          !guard.activate(owner, identity.epoch)) {
        throw const D1RuntimeAdmissionException();
      }
      session = D1RuntimeSession._(identity, guard, lease);
      if (!session.isActive) throw const D1RuntimeAdmissionException();
      return session;
    } catch (_) {
      if (session != null) {
        await session.retire();
      } else if (lease != null && lease.identity == identity) {
        await lease.retire();
      }
      throw const D1RuntimeAdmissionException();
    }
  }
}
