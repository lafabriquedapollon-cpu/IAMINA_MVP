import 'dart:async';
import 'dart:convert';

import 'package:amina/services/app_lock_authenticator.dart';
import 'package:amina/services/app_lock_service.dart';
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
}
