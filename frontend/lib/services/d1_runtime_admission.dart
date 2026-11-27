// CONV-03B1: runtime admission contract, not wired into main or legacy host.
// Durable possession, fencing and atomic authorization belong to the backend.
// No production implementation is admitted by this file alone.
import 'dart:async';
import 'dart:math';

import '../core/domain/glucose_quantity_evidence.dart';
import 'app_lock_service.dart';
import 'auth_service.dart';
import 'd1_prf_possession.dart';
import 'package:flutter/foundation.dart' show visibleForTesting;

typedef D1RuntimeIdentity = ({int owner, int epoch, int generation});

// Only the coordinator can construct or cancel an acquisition. The backend
// receives read-only authority checks, never the guard's claim/activate methods.
// This is an in-process contract, not protection against compromised origin JS.
final class D1RuntimeAcquisition {
  final D1RuntimeIdentity identity;
  final String acquisitionId;
  final bool Function() _pending;
  final bool Function() _session;
  final D1PrfPossession Function() _takePrf;
  final void Function() _revokePrf;
  final Completer<void> _cancelled = Completer<void>();

  D1RuntimeAcquisition._(this.identity, this.acquisitionId,
      this._pending, this._session, this._takePrf, this._revokePrf);

  static String _newId() {
    final random = Random.secure();
    return List.generate(32, (_) =>
        random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }

  bool get isPending => !_cancelled.isCompleted && _pending();
  bool get isSessionCurrent => !_cancelled.isCompleted && _session();
  bool get isCancelled => _cancelled.isCompleted;
  Future<void> get cancelled => _cancelled.future;

  D1PrfPossession takePrfPossession() {
    if (!isPending) throw const D1RuntimeAdmissionException();
    try { return _takePrf(); }
    catch (_) { throw const D1RuntimeAdmissionException(); }
  }

  void _cancel() {
    if (!_cancelled.isCompleted) {
      _cancelled.complete();
      _revokePrf();
    }
  }
}

/// Trusted internal composition boundary. Implementations must acquire a
/// possession-bound durable lease, never open a legacy DB or return raw keys.
/// Each read must itself enforce the durable fence, including after async work.
abstract interface class D1DurableRuntimeBackend {
  // On failure, the backend must clean up its own partial acquisition.
  // A mismatched lease must never be operated on by the coordinator.
  // Check acquisition.isPending inside the durable transaction, not merely
  // before it; cancellation is a signal, never evidence of durable retirement.
  Future<D1DurableRuntimeLease> acquire(D1RuntimeAcquisition acquisition);
}

abstract interface class D1DurableRuntimeLease {
  D1RuntimeIdentity get identity;
  // Persist this ID with the fence; compare it on all reads and retire CAS.
  String get acquisitionId;
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
  final D1RuntimeAcquisition _acquisition;
  final D1DurableRuntimeLease _lease;
  bool _retired = false;
  Future<void>? _retirement;
  bool _durableRetirementFailed = false;

  // A failed durable retirement remains observable; never reopens the session.
  bool get durableRetirementFailed => _durableRetirementFailed;

  D1RuntimeSession._(this._acquisition, this._lease);

  bool _matchesLease() => _lease.identity == _acquisition.identity &&
      _lease.acquisitionId == _acquisition.acquisitionId;

  // Local authorization only; durable currency is checked on every read.
  bool get isActive => !_retired && _acquisition.isSessionCurrent;

  void _requireActive() {
    if (!isActive) throw const D1RuntimeAdmissionException();
  }

  Future<void> _verify() async {
    _requireActive();
    if (!_matchesLease() || !await _lease.verifyCurrent() || !_matchesLease()) {
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
    _acquisition._cancel();
    return _retirement ??= Future<void>.sync(() {
      // A foreign/stale handle cannot be used for cleanup either.
      if (!_matchesLease()) throw const D1RuntimeAdmissionException();
      return _lease.retire();
    }).then<void>(
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
  final D1PrfAcquirer? _prf;
  D1RuntimeAdmission(this._auth, this._lock, this._backend,
      {required D1PrfAcquirer prf}) : _prf = prf;

  // Retains the prior abstract contract tests only. Never compose this
  // constructor into a real vault or product host.
  @visibleForTesting
  D1RuntimeAdmission.legacyFixture(this._auth, this._lock, this._backend)
      : _prf = null;

  // The issuer's watcher invalidates local authority synchronously. Durable
  // retirement is asynchronous; failures are not treated as proof of release.
  Future<D1RuntimeSession> admit() async {
    final owner = _auth.boundNativeAccountId;
    final generation = _auth.verifiedNativeAdmissionGeneration;
    if (owner == null || generation == null) {
      throw const D1RuntimeAdmissionException();
    }
    final identity = (owner: owner, epoch: AuthService.authEpoch, generation: generation);
    final acquisitionId = D1RuntimeAcquisition._newId();
    final prf = _prf;
    final proof = prf == null
        ? await _lock.issueVaultAdmissionProof()
        : await _lock.issuePrfVaultAdmissionProof(prf, acquisitionId: acquisitionId);
    final guard = _lock.consumeVaultAdmissionProof(proof, owner: owner);
    D1RuntimeSession? session;
    D1DurableRuntimeLease? lease;
    late final D1RuntimeAcquisition acquisition;
    try {
      acquisition = D1RuntimeAcquisition._(
          identity, acquisitionId,
          () => _auth.verifiedNativeAdmissionGeneration == generation &&
              guard.checkPending(owner, identity.epoch),
          () => guard.checkSession(owner, identity.epoch),
          () => guard.takePrfPossession(owner, identity.epoch),
          guard.revokePrfPossession);
    } catch (_) {
      guard.revokePrfPossession();
      throw const D1RuntimeAdmissionException();
    }
    bool matches(D1DurableRuntimeLease candidate) =>
        candidate.identity == identity &&
        candidate.acquisitionId == acquisition.acquisitionId;
    try {
      if (!guard.claim(owner, identity.epoch) ||
          !guard.watchRetirement(owner, identity.epoch, () {
            acquisition._cancel();
            final current = session;
            if (current != null) {
              unawaited(current.retire().catchError((Object _) {}));
            }
          }) || !acquisition.isPending) {
        throw const D1RuntimeAdmissionException();
      }
      lease = await _backend.acquire(acquisition);
      if (!acquisition.isPending || !matches(lease) ||
          !await lease.verifyCurrent() || !acquisition.isPending ||
          !matches(lease) || !guard.activate(owner, identity.epoch)) {
        throw const D1RuntimeAdmissionException();
      }
      session = D1RuntimeSession._(acquisition, lease);
      if (!session.isActive) throw const D1RuntimeAdmissionException();
      return session;
    } catch (_) {
      acquisition._cancel();
      if (session != null) {
        await session.retire();
      } else if (lease != null && matches(lease)) {
        await lease.retire();
      }
      throw const D1RuntimeAdmissionException();
    }
  }
}
