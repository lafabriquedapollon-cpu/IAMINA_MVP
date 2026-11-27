import 'dart:async';
import 'dart:convert';

import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/services/d1_runtime_admission.dart';
import 'package:amina/services/d1_prf_possession.dart';
import 'package:amina/services/app_lock_authenticator.dart';
import 'package:amina/services/app_lock_service.dart';
import 'package:amina/services/d1_admission_guard_adapter.dart';
import 'package:amina/services/auth_service.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _a = 900001;
const _b = 900002;
const _credentialKey = 'iamina_app_lock_credential_v1';
const _requiredKey = 'iamina_app_lock_required_v1';
const _tokenKey = 'iamina_native_access_token';
const _bindingKey = 'iamina_native_account_binding_v1';
const _credential = AppLockCredential(
  credentialId: 'fixture-credential',
  publicKeySpki: 'fixture-public-key',
  rpId: 'patient.example',
  origin: 'https://patient.example',
  signCount: 4,
);

String _token(int owner) => 'iamina.fixture_$owner:abc123:signature_$owner';
http.Response _login(int owner) => http.Response(jsonEncode({
  'access_token': _token(owner),
  'user': {'id': owner},
}), 200);

class _Authenticator implements AppLockAuthenticator {
  int calls = 0;
  Completer<AppLockAssertion>? pending;
  @override
  Future<AppLockCapability> capability() async => AppLockCapability.supported;
  @override
  Future<AppLockCredential> enroll() async => _credential;
  @override
  Future<AppLockAssertion> unlock(AppLockCredential credential) async {
    calls++;
    return pending == null
        ? const AppLockAssertion(signCount: 5)
        : await pending!.future;
  }
}

// Stall only the credential counter persistence, using the real mock store
// for all operations. No ability to complete a ticket before it commits.
class _GatedStorage implements FlutterSecureStorage {
  final entered = Completer<void>();
  final release = Completer<void>();
  final bool failWrite;
  final _delegate = const FlutterSecureStorage();

  _GatedStorage({this.failWrite = false});

  Future<void> _write(String key, String? value) async {
    if (key == _credentialKey) {
      if (!entered.isCompleted) entered.complete();
      await release.future;
      if (failWrite) throw StateError('synthetic storage failure');
    }
    await _delegate.write(key: key, value: value);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) {
    final key = invocation.namedArguments[#key];
    if (invocation.memberName == #read && key is String) {
      return _delegate.read(key: key);
    }
    if (invocation.memberName == #write && key is String) {
      return _write(key, invocation.namedArguments[#value] as String?);
    }
    if (invocation.memberName == #delete && key is String) {
      return _delegate.delete(key: key);
    }
    return super.noSuchMethod(invocation);
  }
}

class _Fixture {
  late final AuthService auth;
  late final AppLockService lock;
  final authenticator = _Authenticator();
  Duration elapsed = Duration.zero;
  Completer<http.Response>? pendingLogin;

  Future<void> start({bool signIn = true, FlutterSecureStorage? lockStorage}) async {
    auth = AuthService(httpClient: MockClient((request) async {
      if (request.url.path.endsWith('/logout')) return http.Response('{}', 200);
      final email = jsonDecode(request.body)['email'];
      if (pendingLogin != null) return await pendingLogin!.future;
      return _login(email == 'b@example.invalid' ? _b : _a);
    }));
    await auth.initialize();
    if (signIn) await auth.signInWithEmail('a@example.invalid', 'fixture');
    lock = AppLockService(authService: auth, authenticator: authenticator,
        storage: lockStorage, admissionElapsedForTesting: () => elapsed);
    await lock.initialize();
    addTearDown(() { lock.dispose(); auth.dispose(); });
  }
}


const _runtimeUuid = 'ac123456-1234-4abc-8def-000000000001';
final class _RuntimeLease implements D1DurableRuntimeLease {
  @override
  final D1RuntimeIdentity identity;
  @override
  final String acquisitionId;
  _RuntimeLease(this.identity, this.acquisitionId);
  bool current = true;
  int retireCalls = 0;
  int reads = 0;
  bool failRetirement = false;
  final readEntered = Completer<void>();
  Completer<GlucoseQuantityEvidence?>? delayedRead;
  @override
  Future<bool> verifyCurrent() async => current;
  @override
  Future<GlucoseQuantityEvidence?> readEvidence(String uuid) async {
    reads++;
    if (!readEntered.isCompleted) readEntered.complete();
    return delayedRead == null
      ? GlucoseQuantityEvidence.userEntry(originalValue: 7.83,
          declaredUnit: GlucoseSourceUnit.mmolL)
      : await delayedRead!.future;
  }
  @override
  Future<void> retire() async {
    retireCalls++;
    if (failRetirement) throw StateError('synthetic retirement failure');
    current = false;
  }
}

final class _RuntimeBackend implements D1DurableRuntimeBackend {
  int calls = 0;
  var entered = Completer<D1RuntimeAcquisition>();
  D1RuntimeAcquisition? lastAcquisition;
  Completer<D1DurableRuntimeLease>? delayed;
  _RuntimeLease? last;
  bool takePrf = false;
  D1PrfPossession? possession;
  @override
  Future<D1DurableRuntimeLease> acquire(D1RuntimeAcquisition acquisition) async {
    calls++;
    expect(acquisition.isPending, isTrue);
    expect(acquisition.isSessionCurrent, isFalse);
    lastAcquisition = acquisition;
    if (takePrf) possession = acquisition.takePrfPossession();
    if (!entered.isCompleted) entered.complete(acquisition);
    if (delayed != null) return delayed!.future;
    return last = _RuntimeLease(acquisition.identity, acquisition.acquisitionId);
  }
}

final class _PrfPossession implements D1PrfPossession {
  @override
  bool isLive = true;
  @override
  void revoke() { isLive = false; }
}

final class _Prf implements D1PrfAcquirer {
  int calls = 0;
  bool refuse = false;
  bool Function()? pending;
  AppLockCredential? credential;
  int? owner;
  final entered = Completer<void>();
  Completer<D1PrfPossession>? delayed;
  _PrfPossession? last;
  @override
  Future<D1PrfPossession> acquire(AppLockCredential c, int o,
      bool Function() isPending) async {
    calls++;
    credential = c;
    owner = o;
    pending = isPending;
    if (!entered.isCompleted) entered.complete();
    if (refuse) throw StateError('fixture refusal');
    return delayed == null ? (last = _PrfPossession()) : await delayed!.future;
  }
}

Matcher get _refusal => throwsA(isA<AppLockException>());

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => FlutterSecureStorage.setMockInitialValues({
    _credentialKey: _credential.encode(), _requiredKey: 'required',
  }));

  test('fresh assertion is persisted before a one-shot owner capability', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    expect(f.authenticator.calls, 1);
    final proof = await f.lock.issueVaultAdmissionProof();
    expect(f.authenticator.calls, 2);
    expect(AppLockCredential.decode((await const FlutterSecureStorage()
        .read(key: _credentialKey))!).signCount, 5);
    f.lock.consumeVaultAdmissionProof(proof, owner: _a);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
  });

  test('wrong owner burns proof; another service cannot consume it', () async {
    final f = _Fixture();
    await f.start();
    final proof = await f.lock.issueVaultAdmissionProof();
    final foreign = AppLockService(authService: f.auth,
        authenticator: _Authenticator());
    addTearDown(foreign.dispose);
    await foreign.initialize();
    expect(() => foreign.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _b), _refusal);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
  });

  test('monotonic deadline at 30 seconds; no clock rollback acceptance', () async {
    final f = _Fixture();
    await f.start();
    final first = await f.lock.issueVaultAdmissionProof();
    f.elapsed = const Duration(milliseconds: 29999);
    f.lock.consumeVaultAdmissionProof(first, owner: _a);
    final expired = await f.lock.issueVaultAdmissionProof();
    f.elapsed += const Duration(seconds: 30);
    expect(() => f.lock.consumeVaultAdmissionProof(expired, owner: _a), _refusal);
    final rollback = await f.lock.issueVaultAdmissionProof();
    f.elapsed -= const Duration(seconds: 1);
    expect(() => f.lock.consumeVaultAdmissionProof(rollback, owner: _a), _refusal);
  });

  test('expired platform assertion cannot mint a new ticket', () async {
    final f = _Fixture();
    await f.start();
    final pending = Completer<AppLockAssertion>();
    f.authenticator.pending = pending;
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, _refusal);
    f.elapsed = const Duration(seconds: 30);
    pending.complete(const AppLockAssertion(signCount: 6));
    await rejected;
  });

  test('cached bearer and local-only identity never qualify', () async {
    FlutterSecureStorage.setMockInitialValues({
      _credentialKey: _credential.encode(), _requiredKey: 'required',
      _tokenKey: _token(_a),
      _bindingKey: jsonEncode({'token': _token(_a), 'user_id': _a}),
    });
    final f = _Fixture();
    await f.start(signIn: false);
    expect(f.auth.boundNativeAccountId, _a);
    expect(f.auth.verifiedNativeAdmissionGeneration, isNull);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    await f.auth.signOut();
    await f.auth.enrollLocalDevice();
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    expect(f.authenticator.calls, 0);
  });

  test('new identity attempt retires old ticket before HTTP response', () async {
    final f = _Fixture();
    await f.start();
    final proof = await f.lock.issueVaultAdmissionProof();
    f.pendingLogin = Completer<http.Response>();
    final transition = f.auth.signInWithEmail('b@example.invalid', 'fixture');
    expect(f.auth.verifiedNativeAdmissionGeneration, isNull);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    f.pendingLogin!.complete(_login(_b));
    await transition;
    final b = await f.lock.issueVaultAdmissionProof();
    f.lock.consumeVaultAdmissionProof(b, owner: _b);
  });

  test('lock, background even with grace, and replacement retire tickets', () async {
    final f = _Fixture();
    await f.start();
    final first = await f.lock.issueVaultAdmissionProof();
    f.lock.lock();
    expect(() => f.lock.consumeVaultAdmissionProof(first, owner: _a), _refusal);
    final second = await f.lock.issueVaultAdmissionProof();
    f.lock.noteBackgrounded();
    expect(() => f.lock.consumeVaultAdmissionProof(second, owner: _a), _refusal);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    f.lock.noteResumed();
    final third = await f.lock.issueVaultAdmissionProof();
    final fourth = await f.lock.issueVaultAdmissionProof();
    expect(() => f.lock.consumeVaultAdmissionProof(third, owner: _a), _refusal);
    f.lock.consumeVaultAdmissionProof(fourth, owner: _a);
  });

  test('background and resume while assertion pending do not mint ticket', () async {
    final f = _Fixture();
    await f.start();
    final pending = Completer<AppLockAssertion>();
    f.authenticator.pending = pending;
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, _refusal);
    f.lock.noteBackgrounded();
    f.lock.noteResumed();
    pending.complete(const AppLockAssertion(signCount: 6));
    await rejected;
  });

  test('logout and audit retire authority and reject new tickets', () async {
    final f = _Fixture();
    await f.start();
    final proof = await f.lock.issueVaultAdmissionProof();
    await f.auth.signOut();
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    await f.auth.signInWithEmail('a@example.invalid', 'fixture');
    final audit = await f.lock.issueVaultAdmissionProof();
    f.auth.enterAuditSession();
    expect(() => f.lock.consumeVaultAdmissionProof(audit, owner: _a), _refusal);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
  });

  test('lock during secure counter persistence retires pending issuance', () async {
    final storage = _GatedStorage();
    final f = _Fixture();
    await f.start(lockStorage: storage);
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, _refusal);
    await storage.entered.future;
    expect(f.lock.isUnlocked, isFalse);
    f.lock.lock();
    storage.release.complete();
    await rejected;
    expect(f.lock.isUnlocked, isFalse);
    expect(AppLockCredential.decode((await const FlutterSecureStorage()
        .read(key: _credentialKey))!).signCount, 5);
  });

  test('failed credential counter persistence cannot mint a ticket', () async {
    final storage = _GatedStorage(failWrite: true);
    final f = _Fixture();
    await f.start(lockStorage: storage);
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, throwsStateError);
    await storage.entered.future;
    storage.release.complete();
    await rejected;
    expect(f.lock.isUnlocked, isFalse);
    expect(AppLockCredential.decode((await const FlutterSecureStorage()
        .read(key: _credentialKey))!).signCount, 4);
  });

  test('concurrent issuance retires both pending attempts; retry succeeds', () async {
    final f = _Fixture();
    await f.start();
    final pending = Completer<AppLockAssertion>();
    f.authenticator.pending = pending;
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, _refusal);
    await expectLater(f.lock.issueVaultAdmissionProof(), _refusal);
    pending.complete(const AppLockAssertion(signCount: 6));
    await rejected;
    f.authenticator.pending = null;
    final retry = await f.lock.issueVaultAdmissionProof();
    f.lock.consumeVaultAdmissionProof(retry, owner: _a);
  });

  test('detach invalidates a ticket before any later resume', () async {
    final f = _Fixture();
    await f.start();
    final proof = await f.lock.issueVaultAdmissionProof();
    f.lock.noteDetached();
    f.lock.noteResumed();
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
    final retry = await f.lock.issueVaultAdmissionProof();
    f.lock.consumeVaultAdmissionProof(retry, owner: _a);
  });

  test('live guard retirement is synchronous before a new login response', () async {
    final f = _Fixture();
    await f.start();
    final epoch = AuthService.authEpoch;
    final guard = f.lock.consumeVaultAdmissionProof(
        await f.lock.issueVaultAdmissionProof(), owner: _a);
    expect(guard.claim(_a, epoch), isTrue);
    var calls = 0;
    expect(guard.watchRetirement(_a, epoch, () { calls++; }), isTrue);
    expect(guard.watchRetirement(_a, epoch, () { fail('second watcher'); }), isFalse);
    expect(guard.activate(_a, epoch), isTrue);
    expect(guard.checkSession(_a, epoch), isTrue);
    f.pendingLogin = Completer<http.Response>();
    final transition = f.auth.signInWithEmail('b@example.invalid', 'fixture');
    expect(calls, 1);
    expect(guard.checkSession(_a, epoch), isFalse);
    expect(guard.activate(_a, epoch), isFalse);
    f.pendingLogin!.complete(_login(_b));
    await transition;
    f.lock.lock();
    expect(calls, 1);
  });

  test('pending guard retires on background and cannot revive on resume', () async {
    final f = _Fixture();
    await f.start();
    final epoch = AuthService.authEpoch;
    final guard = f.lock.consumeVaultAdmissionProof(
        await f.lock.issueVaultAdmissionProof(), owner: _a);
    expect(guard.claim(_a, epoch), isTrue);
    var calls = 0;
    expect(guard.watchRetirement(_a, epoch, () { calls++; }), isTrue);
    f.lock.noteBackgrounded();
    expect(calls, 1);
    f.lock.noteResumed();
    expect(guard.checkPending(_a, epoch), isFalse);
    expect(guard.activate(_a, epoch), isFalse);
    expect(guard.checkSession(_a, epoch), isFalse);
    f.lock.noteDetached();
    expect(calls, 1);
  });

  test('replacement proof retires old active guard exactly once', () async {
    final f = _Fixture();
    await f.start();
    final epoch = AuthService.authEpoch;
    final guard = f.lock.consumeVaultAdmissionProof(
        await f.lock.issueVaultAdmissionProof(), owner: _a);
    expect(guard.claim(_a, epoch), isTrue);
    var calls = 0;
    expect(guard.watchRetirement(_a, epoch, () { calls++; }), isTrue);
    expect(guard.activate(_a, epoch), isTrue);
    final replacement = f.lock.consumeVaultAdmissionProof(
        await f.lock.issueVaultAdmissionProof(), owner: _a);
    expect(calls, 1);
    expect(guard.checkSession(_a, epoch), isFalse);
    expect(replacement.claim(_a, epoch), isTrue);
    expect(replacement.activate(_a, epoch), isTrue);
    expect(replacement.checkSession(_a, epoch), isTrue);
  });

  test('adapter rejects unknown phases and routes one-shot guard through retirement', () async {
    final f = _Fixture();
    await f.start();
    final epoch = AuthService.authEpoch;
    final adapter = D1AdmissionGuardAdapter(f.lock.consumeVaultAdmissionProof(
      await f.lock.issueVaultAdmissionProof(), owner: _a));
    expect(adapter.dispatch('unknown', _a, epoch), isFalse);
    expect(adapter.dispatch('session', _a, epoch), isFalse);
    expect(adapter.dispatch('pending', _a, epoch), isFalse);
    expect(adapter.dispatch('claim', _a, epoch), isTrue);
    expect(adapter.dispatch('claim', _a, epoch), isFalse);
    expect(adapter.dispatch('watch', _a, epoch), isFalse);
    var retired = 0;
    expect(adapter.dispatch('watch', _a, epoch, onRetired: () { retired++; }), isTrue);
    expect(adapter.dispatch('watch', _a, epoch, onRetired: () { fail('second watcher'); }), isFalse);
    expect(adapter.dispatch('pending', _b, epoch), isFalse);
    expect(adapter.dispatch('pending', _a, epoch + 1), isFalse);
    expect(adapter.dispatch('pending', _a, epoch), isTrue);
    expect(adapter.dispatch('activate', _a, epoch), isTrue);
    expect(adapter.dispatch('session', _a, epoch), isTrue);
    f.lock.lock();
    expect(retired, 1);
    expect(adapter.dispatch('session', _a, epoch), isFalse);
    expect(adapter.dispatch('activate', _a, epoch), isFalse);
    f.lock.noteDetached();
    expect(retired, 1);
  });

  test('identity change during platform assertion rejects issuance', () async {
    final f = _Fixture();
    await f.start();
    final pending = Completer<AppLockAssertion>();
    f.authenticator.pending = pending;
    final issue = f.lock.issueVaultAdmissionProof();
    final rejected = expectLater(issue, _refusal);
    await f.auth.signInWithEmail('b@example.invalid', 'fixture');
    pending.complete(const AppLockAssertion(signCount: 6));
    await rejected;
    expect(f.lock.isUnlocked, isFalse);
  });

  test('CONV-03B1 guest cannot reach durable backend', () async {
    final f = _Fixture();
    await f.start(signIn: false);
    final backend = _RuntimeBackend();
    await expectLater(D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit(),
        throwsA(isA<D1RuntimeAdmissionException>()));
    expect(backend.calls, 0);
  });

  test('CONV-03B1 fresh identity and assertion expose only guarded evidence', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final session = await D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    expect(f.authenticator.calls, 1);
    expect(session.isActive, isTrue);
    final result = await session.readEvidence(_runtimeUuid);
    expect(result!.originalRawValue, 7.83);
    expect(result.originalUnit, GlucoseSourceUnit.mmolL);
    f.lock.lock();
    expect(session.isActive, isFalse);
    await expectLater(session.readEvidence(_runtimeUuid),
        throwsA(isA<D1RuntimeAdmissionException>()));
    expect(backend.last!.reads, 1);
    expect(backend.last!.retireCalls, 1);
  });

  test('CONV-03B1 late acquisition after lock is retired, never published', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend()..delayed = Completer<D1DurableRuntimeLease>();
    final pending = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    final refused = expectLater(pending, throwsA(isA<D1RuntimeAdmissionException>()));
    final acquisition = await backend.entered.future;
    f.lock.lock();
    expect(acquisition.isCancelled, isTrue);
    expect(acquisition.isPending, isFalse);
    await acquisition.cancelled;
    final lease = _RuntimeLease(acquisition.identity, acquisition.acquisitionId);
    backend.delayed!.complete(lease);
    await refused;
    expect(lease.retireCalls, 1);
    expect(lease.reads, 0);
  });

  test('CONV-03B1 wrong durable identity is refused without touching foreign lease', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend()..delayed = Completer<D1DurableRuntimeLease>();
    final pending = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    final refused = expectLater(pending, throwsA(isA<D1RuntimeAdmissionException>()));
    final acquisition = await backend.entered.future;
    final foreign = _RuntimeLease((owner: _b, epoch: acquisition.identity.epoch,
        generation: acquisition.identity.generation), acquisition.acquisitionId);
    backend.delayed!.complete(foreign);
    await refused;
    expect(foreign.retireCalls, 0);
    expect(foreign.reads, 0);
  });

  test('CONV-03B1 A-B-A late read cannot escape or retire successor', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final admission = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend);
    final a = await admission.admit();
    final old = backend.last!;
    old.delayedRead = Completer<GlucoseQuantityEvidence?>();
    final reading = a.readEvidence(_runtimeUuid);
    final refused = expectLater(reading, throwsA(isA<D1RuntimeAdmissionException>()));
    await old.readEntered.future.timeout(const Duration(seconds: 5));
    await f.auth.signInWithEmail('b@example.invalid', 'fixture');
    expect(a.isActive, isFalse);
    final b = await admission.admit();
    await f.auth.signInWithEmail('a@example.invalid', 'fixture');
    expect(b.isActive, isFalse);
    final next = await admission.admit();
    old.delayedRead!.complete(GlucoseQuantityEvidence.userEntry(
        originalValue: 7.83, declaredUnit: GlucoseSourceUnit.mmolL));
    await refused;
    expect(next.isActive, isTrue);
    expect(backend.last!.retireCalls, 0);
    expect(old.retireCalls, 1);
    await next.retire();
  });

  test('CONV-03B1 durable fence loss prevents read despite local unlock', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final session = await D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    backend.last!.current = false;
    await expectLater(session.readEvidence(_runtimeUuid),
        throwsA(isA<D1RuntimeAdmissionException>()));
    expect(backend.last!.reads, 0);
    expect(session.isActive, isFalse);
  });

  test('CONV-03B1 cached identity cannot reach durable backend', () async {
    FlutterSecureStorage.setMockInitialValues({
      _credentialKey: _credential.encode(), _requiredKey: 'required',
      _tokenKey: _token(_a),
      _bindingKey: jsonEncode({'token': _token(_a), 'user_id': _a}),
    });
    final f = _Fixture();
    await f.start(signIn: false);
    final backend = _RuntimeBackend();
    expect(f.auth.boundNativeAccountId, _a);
    await expectLater(D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit(),
        throwsA(isA<D1RuntimeAdmissionException>()));
    expect(backend.calls, 0);
    expect(f.authenticator.calls, 0);
  });

  test('CONV-03B1 expired durable acquisition cannot publish session', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend()..delayed = Completer<D1DurableRuntimeLease>();
    final pending = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    final refused = expectLater(pending, throwsA(isA<D1RuntimeAdmissionException>()));
    final acquisition = await backend.entered.future;
    f.elapsed = const Duration(seconds: 30);
    final lease = _RuntimeLease(acquisition.identity, acquisition.acquisitionId);
    backend.delayed!.complete(lease);
    await refused;
    expect(lease.retireCalls, 1);
    expect(lease.reads, 0);
  });

  test('CONV-03B1 failed retirement remains visible and cannot reopen local authority', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final session = await D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend).admit();
    final lease = backend.last!..failRetirement = true;
    await expectLater(session.retire(), throwsA(isA<D1RuntimeAdmissionException>()));
    expect(session.durableRetirementFailed, isTrue);
    expect(session.isActive, isFalse);
    lease.failRetirement = false;
    await session.retire();
    expect(session.durableRetirementFailed, isFalse);
    expect(session.isActive, isFalse);
    expect(lease.retireCalls, 2);
  });

  test('CONV-03B2a.1 same identity replacement has distinct acquisition fence', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final admission = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend);
    final first = await admission.admit();
    final firstRequest = backend.lastAcquisition!;
    final firstLease = backend.last!;
    expect(firstRequest.isPending, isFalse);
    expect(firstRequest.isSessionCurrent, isTrue);
    final second = await admission.admit();
    final secondRequest = backend.lastAcquisition!;
    expect(secondRequest.identity, firstRequest.identity);
    expect(secondRequest.acquisitionId, isNot(firstRequest.acquisitionId));
    expect(secondRequest.acquisitionId, matches(RegExp(r'^[a-f0-9]{64}$')));
    expect(firstRequest.isCancelled, isTrue);
    await firstRequest.cancelled;
    expect(first.isActive, isFalse);
    expect(second.isActive, isTrue);
    await first.retire();
    expect(firstLease.retireCalls, 1);
    expect(backend.last!.retireCalls, 0);
    await second.retire();
    expect(secondRequest.isCancelled, isTrue);
    expect(secondRequest.isSessionCurrent, isFalse);
  });

  test('CONV-03B2a.1 same owner stale acquisition is never read or revoked', () async {
    final f = _Fixture();
    await f.start();
    final backend = _RuntimeBackend();
    final admission = D1RuntimeAdmission.legacyFixture(f.auth, f.lock, backend);
    final first = await admission.admit();
    final oldLease = backend.last!;
    final oldRequest = backend.lastAcquisition!;
    backend.delayed = Completer<D1DurableRuntimeLease>();
    backend.entered = Completer<D1RuntimeAcquisition>();
    final pending = admission.admit();
    final refused = expectLater(pending, throwsA(isA<D1RuntimeAdmissionException>()));
    final next = await backend.entered.future.timeout(const Duration(seconds: 5));
    expect(next.acquisitionId, isNot(oldRequest.acquisitionId));
    expect(next.identity, oldRequest.identity);
    expect(first.isActive, isFalse);
    await first.retire();
    expect(oldLease.retireCalls, 1);
    backend.delayed!.complete(oldLease);
    await refused;
    expect(next.isCancelled, isTrue);
    expect(oldLease.retireCalls, 1);
    expect(oldLease.reads, 0);
  });

  test('B2a.3b one PRF proof and opaque one-shot handle, no legacy fallback', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock(); // existing UI precondition only
    final prf = _Prf();
    final backend = _RuntimeBackend()..takePrf = true;
    final session = await D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit();
    expect(prf.calls, 1);
    expect(f.authenticator.calls, 1);
    expect(prf.owner, _a);
    expect(prf.credential!.credentialId, _credential.credentialId);
    expect(prf.credential!.signCount, 5);
    expect(backend.possession, same(prf.last));
    expect(backend.possession!.isLive, isTrue);
    expect(session.isActive, isTrue);
    expect(() => backend.lastAcquisition!.takePrfPossession(), throwsA(isA<D1RuntimeAdmissionException>()));
    await session.retire();
    expect(prf.last!.isLive, isFalse);
    expect(session.isActive, isFalse);
  });

  test('B2a.3b locked UI refuses before invoking PRF or backend', () async {
    final f = _Fixture();
    await f.start();
    final prf = _Prf();
    final backend = _RuntimeBackend()..takePrf = true;
    await expectLater(D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit(), _refusal);
    expect(prf.calls, 0);
    expect(f.authenticator.calls, 0);
    expect(backend.calls, 0);
  });

  test('B2a.3b absent PRF never calls backend or legacy authenticator', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf()..refuse = true;
    final backend = _RuntimeBackend()..takePrf = true;
    await expectLater(D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit(), _refusal);
    expect(f.authenticator.calls, 1);
    expect(backend.calls, 0);
  });

  test('B2a.3b lock during PRF rejects late handle and revokes it', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf()..delayed = Completer<D1PrfPossession>();
    final backend = _RuntimeBackend()..takePrf = true;
    final result = D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit();
    final refused = expectLater(result, _refusal);
    await prf.entered.future;
    expect(prf.pending!(), isTrue);
    f.lock.lock();
    expect(prf.pending!(), isFalse);
    final late = _PrfPossession();
    prf.delayed!.complete(late);
    await refused;
    expect(late.isLive, isFalse);
    expect(backend.calls, 0);
  });

  test('B2a.3b backend without possession cannot activate', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf();
    final backend = _RuntimeBackend();
    await expectLater(D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit(),
        throwsA(isA<D1RuntimeAdmissionException>()));
    expect(prf.last!.isLive, isFalse);
    expect(backend.last!.retireCalls, 1);
  });

  test('B2a.3b wrong owner burns ticket and revokes PRF handle', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf();
    final proof = await f.lock.issuePrfVaultAdmissionProof(prf);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _b), _refusal);
    expect(prf.last!.isLive, isFalse);
    expect(() => f.lock.consumeVaultAdmissionProof(proof, owner: _a), _refusal);
  });

  test('B2a.3b replacement revokes old handle without touching successor', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf();
    final backend = _RuntimeBackend()..takePrf = true;
    final admission = D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf);
    final first = await admission.admit();
    final old = prf.last!;
    final next = await admission.admit();
    expect(old.isLive, isFalse);
    expect(first.isActive, isFalse);
    expect(prf.last!.isLive, isTrue);
    await first.retire();
    expect(next.isActive, isTrue);
    expect(prf.last!.isLive, isTrue);
    f.lock.noteBackgrounded();
    expect(prf.last!.isLive, isFalse);
    expect(next.isActive, isFalse);
  });

  test('B2a.3b expiry before PRF ACK rejects and revokes late handle', () async {
    final f = _Fixture();
    await f.start();
    await f.lock.unlock();
    final prf = _Prf()..delayed = Completer<D1PrfPossession>();
    final backend = _RuntimeBackend()..takePrf = true;
    final result = D1RuntimeAdmission(f.auth, f.lock, backend, prf: prf).admit();
    final refused = expectLater(result, _refusal);
    await prf.entered.future;
    f.elapsed = const Duration(seconds: 30);
    expect(prf.pending!(), isFalse);
    final late = _PrfPossession();
    prf.delayed!.complete(late);
    await refused;
    expect(late.isLive, isFalse);
    expect(backend.calls, 0);
  });

}
