import 'dart:async';
import 'dart:convert';

import 'package:amina/services/auth_service.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _tokenKey = 'iamina_native_access_token';
const _bindingKey = 'iamina_native_account_binding_v1';
const _enrolledKey = 'iamina_local_session_v1';
const _storage = FlutterSecureStorage();

String _fixtureToken(int owner) => 'iamina.fixture_$owner:abc123:signature_$owner';
http.Response _response(int owner) => http.Response(jsonEncode({
  'access_token': _fixtureToken(owner),
  'user': {'id': owner},
}), 200);

AuthService _auth(MockClient client, {FlutterSecureStorage? storage}) =>
    AuthService(httpClient: client, storage: storage);

Future<void> _expectEmpty(AuthService auth) async {
  expect(auth.isAuthenticated, isFalse);
  expect(auth.boundNativeAccountId, isNull);
  expect(auth.isRemoteCredentialVerified, isFalse);
  expect(auth.hasRemoteApiCredential, isFalse);
  expect(await _storage.read(key: _tokenKey), isNull);
  expect(await _storage.read(key: _bindingKey), isNull);
  expect(await _storage.read(key: _enrolledKey), isNull);
}

Future<void> _expectOwner(AuthService auth, int owner) async {
  expect(auth.isAuthenticated, isTrue);
  expect(auth.boundNativeAccountId, owner);
  expect(auth.isRemoteCredentialVerified, isTrue);
  expect(await auth.getIdToken(), _fixtureToken(owner));
  expect(await _storage.read(key: _tokenKey), _fixtureToken(owner));
  expect(jsonDecode((await _storage.read(key: _bindingKey))!), {
    'token': _fixtureToken(owner), 'user_id': owner,
  });
  expect(await _storage.read(key: _enrolledKey), 'enrolled');
}

// Delay exactly the first token write. The real mock storage still performs
// every read/write/delete, so the final persistent-state oracle is independent.
class _GatedStorage implements FlutterSecureStorage {
  final entered = Completer<void>();
  final release = Completer<void>();
  bool _gated = false;
  final bool failFirstTokenWrite;

  _GatedStorage({this.failFirstTokenWrite = false});

  Future<void> _write(String key, String? value) async {
    if (key == _tokenKey && !_gated) {
      _gated = true;
      entered.complete();
      await release.future;
      if (failFirstTokenWrite) throw StateError('synthetic storage failure');
    }
    await _storage.write(key: key, value: value);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) {
    final key = invocation.namedArguments[#key];
    if (invocation.memberName == #read && key is String) {
      return _storage.read(key: key);
    }
    if (invocation.memberName == #delete && key is String) {
      return _storage.delete(key: key);
    }
    if (invocation.memberName == #write && key is String) {
      return _write(key, invocation.namedArguments[#value] as String?);
    }
    return super.noSuchMethod(invocation);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  test('D1 late native login after logout cannot restore account or storage', () async {
    final response = Completer<http.Response>();
    final auth = _auth(MockClient((_) => response.future));
    addTearDown(auth.dispose);
    await auth.initialize();
    final attempt = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(attempt, throwsA(isA<AuthTransitionRetired>()));
    await auth.signOut();
    response.complete(_response(900001));
    await rejected;
    await _expectEmpty(auth);
  });

  test('D1 older native response cannot replace newer verified owner B', () async {
    final a = Completer<http.Response>();
    final b = Completer<http.Response>();
    final auth = _auth(MockClient((request) {
      final email = jsonDecode(request.body)['email'];
      return email == 'a@example.invalid' ? a.future : b.future;
    }));
    addTearDown(auth.dispose);
    await auth.initialize();
    final old = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(old, throwsA(isA<AuthTransitionRetired>()));
    final newer = auth.signInWithEmail('b@example.invalid', 'fixture');
    b.complete(_response(900002));
    await newer;
    a.complete(_response(900001));
    await rejected;
    await _expectOwner(auth, 900002);

    final restored = _auth(MockClient((_) async => throw StateError('unexpected HTTP')));
    addTearDown(restored.dispose);
    await restored.initialize();
    expect(restored.boundNativeAccountId, 900002);
    expect(restored.isRemoteCredentialVerified, isFalse);
  });

  test('D1 logout during native token write clears stale persistent credentials', () async {
    final storage = _GatedStorage();
    final auth = _auth(MockClient((_) async => _response(900001)), storage: storage);
    addTearDown(auth.dispose);
    await auth.initialize();
    final attempt = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(attempt, throwsA(isA<AuthTransitionRetired>()));
    await storage.entered.future;
    final logout = auth.signOut();
    expect(auth.isAuthenticated, isFalse);
    expect(auth.boundNativeAccountId, isNull);
    storage.release.complete();
    await rejected;
    await logout;
    await _expectEmpty(auth);
    final restored = _auth(MockClient((_) async => throw StateError('unexpected HTTP')));
    addTearDown(restored.dispose);
    await restored.initialize();
    await _expectEmpty(restored);
  });

  test('D1 newer native commit waits for retired A cleanup and persists only B', () async {
    final storage = _GatedStorage();
    final auth = _auth(MockClient((request) async {
      final email = jsonDecode(request.body)['email'];
      return _response(email == 'a@example.invalid' ? 900001 : 900002);
    }), storage: storage);
    addTearDown(auth.dispose);
    await auth.initialize();
    final old = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(old, throwsA(isA<AuthTransitionRetired>()));
    await storage.entered.future;
    final newer = auth.signInWithEmail('b@example.invalid', 'fixture');
    storage.release.complete();
    await rejected;
    await newer;
    await _expectOwner(auth, 900002);
  });

  test('D1 disposal during credential commit cannot publish stale identity', () async {
    final storage = _GatedStorage();
    final auth = _auth(MockClient((_) async => _response(900001)), storage: storage);
    await auth.initialize();
    final attempt = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(attempt, throwsA(isA<AuthTransitionRetired>()));
    await storage.entered.future;
    auth.dispose();
    storage.release.complete();
    await rejected;
    await _expectEmpty(auth);
  });

  test('D1 storage failure cleans partial identity and does not poison next commit', () async {
    final storage = _GatedStorage(failFirstTokenWrite: true);
    final auth = _auth(MockClient((request) async {
      final email = jsonDecode(request.body)['email'];
      return _response(email == 'a@example.invalid' ? 900001 : 900002);
    }), storage: storage);
    addTearDown(auth.dispose);
    await auth.initialize();
    final attempt = auth.signInWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(attempt, throwsStateError);
    await storage.entered.future;
    storage.release.complete();
    await rejected;
    await _expectEmpty(auth);
    await auth.signInWithEmail('b@example.invalid', 'fixture');
    await _expectOwner(auth, 900002);
  });

  test('D1 late native registration cannot restore account after logout', () async {
    final response = Completer<http.Response>();
    final auth = _auth(MockClient((_) => response.future));
    addTearDown(auth.dispose);
    await auth.initialize();
    if (!kRemoteAccountEnrollmentEnabled) {
      await expectLater(auth.registerWithEmail('a@example.invalid', 'fixture'),
          throwsStateError);
      await _expectEmpty(auth);
      return;
    }
    final attempt = auth.registerWithEmail('a@example.invalid', 'fixture');
    final rejected = expectLater(attempt, throwsA(isA<AuthTransitionRetired>()));
    await auth.signOut();
    response.complete(_response(900001));
    await rejected;
    await _expectEmpty(auth);
  });
}
