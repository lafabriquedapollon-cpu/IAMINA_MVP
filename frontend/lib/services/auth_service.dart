import 'dart:convert';
import 'dart:developer' as developer;

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';

import '../data/drift/patient_vault_scope.dart';

import 'auth_epoch.dart';
import 'firebase_migration_policy.dart';

const String kAuthBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://localhost:8000',
);

const bool kOfflineDemo = bool.fromEnvironment(
  'IAMINA_OFFLINE_DEMO',
  defaultValue: false,
);

const bool kRemoteAccountEnrollmentEnabled = bool.fromEnvironment(
  'IAMINA_REMOTE_ACCOUNT_ENROLLMENT',
  defaultValue: false,
);

// Sign-in to existing synthetic accounts is independent of account creation.
// Production retains its existing behavior through this default.
const bool kRemoteAccountSignInEnabled = bool.fromEnvironment(
  'IAMINA_REMOTE_ACCOUNT_SIGN_IN',
  defaultValue: kRemoteAccountEnrollmentEnabled,
);

/// For remote Web sign-in, always use the *current page's* exact origin.
/// Vercel immutable Preview URLs differ from branch aliases; sending login
/// credentials to an older alias breaks same-origin BFF/OIDC and CORS.
/// Non-Web or local-first clients preserve their configured transport.
String resolveAuthApiOrigin({
  required bool isWeb,
  required bool remoteAccountLogin,
  required Uri pageUri,
  required String configuredBaseUrl,
  bool useConfiguredLoopbackBackend = false,
}) {
  if (!isWeb || !remoteAccountLogin) return configuredBaseUrl;
  final host = pageUri.host.toLowerCase();
  final local = pageUri.scheme == 'http' &&
      (host == 'localhost' || host == '127.0.0.1');
  if (local && useConfiguredLoopbackBackend) {
    // Local D11 FUE serves Flutter on one loopback port and Django on another.
    // This exception never applies to a hosted Preview. Never forward patient
    // credentials from a local page to an arbitrary remote backend.
    final backend = Uri.tryParse(configuredBaseUrl);
    if (backend == null ||
        backend.scheme != 'http' ||
        (backend.host != 'localhost' && backend.host != '127.0.0.1') ||
        backend.userInfo.isNotEmpty) {
      throw StateError('Local remote login requires a loopback backend');
    }
    return configuredBaseUrl;
  }
  if (pageUri.scheme != 'https' && !local) {
    throw StateError('A secure browser origin is required for remote login');
  }
  if (host.isEmpty || pageUri.userInfo.isNotEmpty) {
    throw StateError('Missing secure patient origin');
  }
  return pageUri.origin;
}

/// Do not conflate invalid credentials (HTTP 401) with API or network faults.
class AuthCredentialsRejected implements Exception {
  const AuthCredentialsRejected();
}

/// A newer identity action retired this response. No account was admitted.
class AuthTransitionRetired implements Exception {
  const AuthTransitionRetired();
}

class AuthSignInServiceUnavailable implements Exception {
  final int statusCode;
  const AuthSignInServiceUnavailable(this.statusCode);
}

/// Only the Django-native rejection is evidence of incorrect credentials.
/// A Vercel SSO/OIDC 401 or HTML protection page must be reported as an
/// unavailable service, never as a wrong patient password.
bool _isNativeCredentialRejection(http.Response response) {
  if (response.statusCode != 401) return false;
  try {
    final payload = jsonDecode(response.body);
    return payload is Map &&
        payload['detail'] == 'Invalid authentication credential';
  } catch (_) {
    return false;
  }
}


bool demoUsesLocalAuditSession({
  required bool offlineDemo,
  required bool remoteAccountEnrollmentEnabled,
}) => offlineDemo || remoteAccountEnrollmentEnabled;

typedef AuthFailureLogger = void Function(
  String operation,
  String errorType,
  StackTrace stackTrace,
);

enum RegistrationFailureCode {
  weakPassword,
  accountExists,
  rejected,
}

class RegistrationFailure implements Exception {
  final RegistrationFailureCode code;
  final int statusCode;

  const RegistrationFailure(this.code, this.statusCode);
}

RegistrationFailure registrationFailureForStatus(int statusCode) {
  if (statusCode == 400) {
    return RegistrationFailure(
      RegistrationFailureCode.weakPassword,
      statusCode,
    );
  }
  if (statusCode == 409) {
    return RegistrationFailure(
      RegistrationFailureCode.accountExists,
      statusCode,
    );
  }
  return RegistrationFailure(
    RegistrationFailureCode.rejected,
    statusCode,
  );
}

class AuthService extends ChangeNotifier {
  static const _tokenKey = 'iamina_native_access_token';
  // Authenticated native ID and exact bearer must match. Legacy bearer: unknown ID.
  static const _nativeIdentityKey = 'iamina_native_account_binding_v1';
  static const _localSessionKey = 'iamina_local_session_v1';
  static const _localSessionValue = 'enrolled';
  static const _localDeviceIdKey = 'iamina_local_device_id_v1';
  static final RegExp _nativeBearerShape = RegExp(
    r'^iamina\.[A-Za-z0-9_.-]+:[A-Za-z0-9]+:[A-Za-z0-9_-]+$',
  );

  final FirebaseAuth? _firebaseAuth;
  final FlutterSecureStorage _storage;
  final http.Client _httpClient;
  final AuthFailureLogger _failureLogger;
  String? _nativeToken;
  int? _nativeAccountId;
  bool _localSessionEnrolled = false;
  bool _initialized = false;
  bool _auditSession = false;
  bool _remoteCredentialVerified = false;
  int _identityGeneration = 0;
  bool _disposed = false;
  Future<void> _identityStorageTail = Future<void>.value();

  int _beginIdentityTransition() {
    if (_disposed) throw const AuthTransitionRetired();
    return ++_identityGeneration;
  }

  void _requireIdentityTransition(int generation) {
    if (_disposed || generation != _identityGeneration) {
      throw const AuthTransitionRetired();
    }
  }

  // Native credential commits and removals must never interleave within this
  // service. Network requests are deliberately outside the storage lane.
  // This is not a cross-document lock or a crash-atomic storage transaction.
  Future<void> _serializeIdentityStorage(Future<void> Function() operation) {
    final pending = _identityStorageTail.then((_) => operation());
    _identityStorageTail = pending.then<void>(
      (_) {},
      onError: (Object _, StackTrace __) {},
    );
    return pending;
  }

  Future<void> _deleteNativeCredentialStorage({
    required bool clearEnrollment,
  }) async {
    await _storage.delete(key: _tokenKey);
    await _storage.delete(key: _nativeIdentityKey);
    if (clearEnrollment) await _storage.delete(key: _localSessionKey);
  }

  AuthService({
    FirebaseAuth? auth,
    FlutterSecureStorage? storage,
    http.Client? httpClient,
    AuthFailureLogger? failureLogger,
  })  : _firebaseAuth = _getAuthInstance(
          auth,
          failureLogger ?? _defaultFailureLogger,
        ),
        _storage = storage ?? const FlutterSecureStorage(),
        _httpClient = httpClient ?? http.Client(),
        _failureLogger = failureLogger ?? _defaultFailureLogger;

  static FirebaseAuth? _getAuthInstance(
    FirebaseAuth? provided,
    AuthFailureLogger failureLogger,
  ) {
    if (!kFirebaseMigrationEnabled) return null;
    try {
      return provided ?? FirebaseAuth.instance;
    } catch (error, stackTrace) {
      failureLogger(
        'firebase_instance',
        error.runtimeType.toString(),
        stackTrace,
      );
      return null;
    }
  }

  static void _defaultFailureLogger(
    String operation,
    String errorType,
    StackTrace stackTrace,
  ) {
    developer.log(
      'Safe auth fallback invoked for $errorType.',
      name: 'iamina.auth.$operation',
      stackTrace: stackTrace,
    );
  }

  static bool _isExpectedNativeBearerShape(String? token) =>
      token != null && _nativeBearerShape.hasMatch(token);

  static int get authEpoch => AuthEpoch.value;

  bool get isInitialized => _initialized;
  bool get isAuthenticated =>
      _auditSession ||
      _localSessionEnrolled ||
      (_firebaseAuth?.currentUser != null);
  bool get isRemoteCredentialVerified => _remoteCredentialVerified;
  /// Previously authenticated Django ID bound to this exact bearer.
  /// Offline restoration does not verify that the bearer is still active.
  int? get boundNativeAccountId =>
      _auditSession || _nativeToken == null ? null : _nativeAccountId;
  bool get hasRemoteApiCredential =>
      _nativeToken != null && _nativeToken!.isNotEmpty;
  bool get isAnonymous =>
      _auditSession ||
      (!_localSessionEnrolled &&
          _nativeToken == null &&
          (_firebaseAuth?.currentUser?.isAnonymous ?? false));
  bool get isAuditSession => _auditSession;
  User? get firebaseUser => _firebaseAuth?.currentUser;

  /// Offline, fail-closed lookup: never invent a remote identity from a local
  /// marker, Firebase hash, old bearer, or previous owner's SQLite profile.
  /// Selecting a vault is not proof of an active server login/app-lock unlock.
  Future<PatientVaultScope?> resolvePatientVaultScope() async {
    if (!_initialized) {
      throw StateError('Authentication must be initialized');
    }
    if (_auditSession) return PatientVaultScope.auditOnly();
    if (_nativeToken != null) {
      final accountId = _nativeAccountId;
      return accountId == null
          ? null
          : PatientVaultScope.nativeDjango(accountId);
    }
    if (_firebaseAuth?.currentUser != null) return null;
    if (!_localSessionEnrolled) return null;
    final deviceId = await _storage.read(key: _localDeviceIdKey);
    if (deviceId == null) return null;
    try {
      return PatientVaultScope.deviceLocal(deviceId);
    } on ArgumentError {
      return null;
    }
  }

  /// Inspect a dormant device-only vault for lock-recovery purposes only.
  /// This does NOT enroll a user or grant access to patient data.
  Future<PatientVaultScope?> dormantDeviceVaultForProtectedStateProbe() async {
    if (!_initialized || _auditSession) return null;
    final deviceId = await _storage.read(key: _localDeviceIdKey);
    if (deviceId == null) return null;
    try {
      return PatientVaultScope.deviceLocal(deviceId);
    } on ArgumentError {
      return null;
    }
  }

  Future<void> initialize() async {
    final generation = _beginIdentityTransition();
    await _serializeIdentityStorage(() async {
      _requireIdentityTransition(generation);
      var enrolled = false;
      String? token;
      int? accountId;
      try {
        enrolled = await _storage.read(key: _localSessionKey) == _localSessionValue;
        _requireIdentityTransition(generation);
        final storedToken = await _storage.read(key: _tokenKey);
        _requireIdentityTransition(generation);
        if (_isExpectedNativeBearerShape(storedToken)) {
          token = storedToken;
          // A cached binding restores the namespace, not verified authority.
          final binding = await _storage.read(key: _nativeIdentityKey);
          _requireIdentityTransition(generation);
          if (binding != null) {
            try {
              final parsed = jsonDecode(binding);
              if (parsed is Map<String, dynamic> &&
                  parsed['token'] == storedToken &&
                  parsed['user_id'] is int &&
                  (parsed['user_id'] as int) > 0) {
                accountId = parsed['user_id'] as int;
              }
            } on FormatException {
              // Invalid cached binding must never become a patient ID.
            }
          }
          if (!enrolled) {
            await _storage.write(key: _localSessionKey, value: _localSessionValue);
            _requireIdentityTransition(generation);
            enrolled = true;
          }
        } else if (storedToken != null) {
          await _deleteNativeCredentialStorage(clearEnrollment: false);
        }
      } catch (error, stackTrace) {
        _requireIdentityTransition(generation);
        _failureLogger('initialize', error.runtimeType.toString(), stackTrace);
        token = null;
        accountId = null;
        enrolled = false;
      }
      _requireIdentityTransition(generation);
      _nativeToken = token;
      _nativeAccountId = accountId;
      _localSessionEnrolled = enrolled;
      _remoteCredentialVerified = false;
      _initialized = true;
      _notifyAuthChanged();
    });
  }

  /// Enrol this installation for local-first use without contacting a server.
  /// This provides device-local continuity, not strong user authentication.
  Future<void> enrollLocalDevice() async {
    if (!_initialized) {
      throw StateError('Local enrollment requires initialized authentication');
    }
    final generation = _beginIdentityTransition();
    await _serializeIdentityStorage(() async {
      _requireIdentityTransition(generation);
      final existingId = await _storage.read(key: _localDeviceIdKey);
      _requireIdentityTransition(generation);
      if (existingId == null || existingId.isEmpty) {
        await _storage.write(key: _localDeviceIdKey, value: const Uuid().v4());
        _requireIdentityTransition(generation);
      }
      if (!_localSessionEnrolled) {
        await _storage.write(key: _localSessionKey, value: _localSessionValue);
        _requireIdentityTransition(generation);
      }
      _localSessionEnrolled = true;
      _remoteCredentialVerified = false;
      _notifyAuthChanged();
    });
  }

  void enterAuditSession() {
    if (!_initialized) {
      throw StateError('Audit session requires initialized authentication');
    }
    _beginIdentityTransition();
    _auditSession = true;
    _notifyAuthChanged();
  }

  Future<String?> getIdToken() async {
    if (_auditSession) return null;
    final native = _nativeToken;
    if (native != null && native.isNotEmpty) return native;
    return _firebaseAuth?.currentUser?.getIdToken();
  }

  Future<String?> refreshToken() async {
    if (_auditSession) return null;
    if (_nativeToken != null) {
      _beginIdentityTransition();
      _nativeToken = null;
      _nativeAccountId = null;
      _remoteCredentialVerified = false;
      final clearing = _serializeIdentityStorage(
        () => _deleteNativeCredentialStorage(clearEnrollment: false),
      );
      // Retire the session synchronously, before waiting for storage.
      _notifyAuthChanged();
      await clearing;
      return null;
    }
    return _firebaseAuth?.currentUser?.getIdToken(true);
  }

  Future<void> signInWithEmail(String email, String password) async {
    final generation = _beginIdentityTransition();
    final normalized = email.trim().toLowerCase();
    final nativeResponse = await _postJson(
      '/api/v1/auth/login',
      {'email': normalized, 'password': password},
    );
    _requireIdentityTransition(generation);
    if (nativeResponse.statusCode >= 200 && nativeResponse.statusCode < 300) {
      await _acceptAuthResponse(nativeResponse, generation);
      return;
    }
    final nativeInvalidCredentials = _isNativeCredentialRejection(nativeResponse);
    if (nativeInvalidCredentials && _firebaseAuth != null) {
      final credential = await _firebaseAuth.signInWithEmailAndPassword(
        email: normalized,
        password: password,
      );
      _requireIdentityTransition(generation);
      final firebaseToken = await credential.user?.getIdToken(true);
      _requireIdentityTransition(generation);
      if (firebaseToken == null || firebaseToken.isEmpty) {
        throw StateError('Firebase migration credential unavailable');
      }
      final exchange = await _postJson(
        '/api/v1/auth/firebase',
        {'id_token': firebaseToken},
      );
      _requireIdentityTransition(generation);
      if (exchange.statusCode >= 200 && exchange.statusCode < 300) {
        await _acceptAuthResponse(exchange, generation);
        return;
      }
    }
    if (nativeInvalidCredentials) {
      throw const AuthCredentialsRejected();
    }
    throw AuthSignInServiceUnavailable(nativeResponse.statusCode);
  }

  Future<void> registerWithEmail(String email, String password) async {
    if (!kRemoteAccountEnrollmentEnabled) {
      throw StateError('Remote account enrollment is disabled');
    }
    final generation = _beginIdentityTransition();
    final response = await _postJson(
      '/api/v1/auth/register',
      {'email': email.trim().toLowerCase(), 'password': password},
    );
    _requireIdentityTransition(generation);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw registrationFailureForStatus(response.statusCode);
    }
    await _acceptAuthResponse(response, generation);
  }

  Future<void> signOut() async {
    _beginIdentityTransition();
    _auditSession = false;
    final token = _nativeToken;

    // Local sign-out is authoritative. Never let optional remote revocation keep
    // an enrolled device authenticated while the network is slow or unavailable.
    _nativeToken = null;
    _nativeAccountId = null;
    _localSessionEnrolled = false;
    _remoteCredentialVerified = false;
    // Queue deletion before notifying listeners, but retire access immediately.
    // An already-started write must finish or fail before this removal runs.
    final clearing = _serializeIdentityStorage(
      () => _deleteNativeCredentialStorage(clearEnrollment: true),
    );
    _notifyAuthChanged();
    await clearing;
    // Preserve the stable local-only vault locator: deleting it orphaned
    // offline clinical records without removing their SQLite database.
    // The revoked session cannot resolve it until explicit re-enrollment;
    // the existing app-lock remains mandatory for reopening the vault.
    await _firebaseAuth?.signOut();

    if (token != null) {
      try {
        await _httpClient.post(
          Uri.parse('$_effectiveAuthBaseUrl/api/v1/auth/logout'),
          headers: {'Authorization': 'Bearer $token'},
        );
      } catch (error, stackTrace) {
        _failureLogger(
          'logout',
          error.runtimeType.toString(),
          stackTrace,
        );
      }
    }
  }

  Future<void> signInAnonymously() async {
    if (demoUsesLocalAuditSession(
      offlineDemo: kOfflineDemo,
      remoteAccountEnrollmentEnabled: kRemoteAccountEnrollmentEnabled,
    )) {
      enterAuditSession();
      return;
    }
    if (_firebaseAuth == null) {
      throw StateError('Firebase migration is disabled');
    }
    final generation = _beginIdentityTransition();
    await _firebaseAuth.signInAnonymously();
    _requireIdentityTransition(generation);
    _notifyAuthChanged();
  }

  Future<void> sendPasswordResetEmail(String email) async {
    final response = await _postJson(
      '/api/v1/auth/password/reset/request',
      {'email': email.trim().toLowerCase()},
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw StateError('Password recovery request failed');
    }
  }

  Future<void> confirmPasswordReset({
    required String uid,
    required String token,
    required String newPassword,
  }) async {
    final response = await _postJson(
      '/api/v1/auth/password/reset/confirm',
      {'uid': uid, 'token': token, 'new_password': newPassword},
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw StateError('Password recovery confirmation failed');
    }
  }

  String get _effectiveAuthBaseUrl => resolveAuthApiOrigin(
        isWeb: kIsWeb,
        remoteAccountLogin: kRemoteAccountSignInEnabled,
        pageUri: Uri.base,
        configuredBaseUrl: kAuthBaseUrl,
        useConfiguredLoopbackBackend: true,
      );

  Future<http.Response> _postJson(String path, Map<String, dynamic> body) {
    return _httpClient.post(
      Uri.parse('$_effectiveAuthBaseUrl$path'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
  }

  Future<void> _acceptAuthResponse(http.Response response, int generation) async {
    _requireIdentityTransition(generation);
    final payload = jsonDecode(response.body);
    if (payload is! Map<String, dynamic>) {
      throw StateError('Malformed authentication response');
    }
    final token = payload['access_token'];
    final user = payload['user'];
    final id = user is Map<String, dynamic> ? user['id'] : null;
    if (token is! String || !_isExpectedNativeBearerShape(token)) {
      throw StateError('Missing IAMINA access token');
    }
    if (id is! int || id <= 0) {
      throw StateError('Missing authenticated IAMINA user ID');
    }
    await _serializeIdentityStorage(() async {
      _requireIdentityTransition(generation);
      // Retire the previous account before the first persistence await.
      _nativeToken = null;
      _nativeAccountId = null;
      _remoteCredentialVerified = false;
      _localSessionEnrolled = false;
      _auditSession = false;
      _notifyAuthChanged();
      try {
        _requireIdentityTransition(generation);
        await _storage.write(
          key: _nativeIdentityKey,
          value: jsonEncode({'token': token, 'user_id': id}),
        );
        _requireIdentityTransition(generation);
        await _storage.write(key: _tokenKey, value: token);
        _requireIdentityTransition(generation);
        await _storage.write(key: _localSessionKey, value: _localSessionValue);
        _requireIdentityTransition(generation);
      } catch (_) {
        // A failed/retired commit never publishes an identity. Cleanup stays
        // in the same lane, before any newer native commit can write.
        await _deleteNativeCredentialStorage(clearEnrollment: true);
        rethrow;
      }
      _nativeToken = token;
      _nativeAccountId = id;
      _localSessionEnrolled = true;
      _remoteCredentialVerified = true;
      _notifyAuthChanged();
    });
  }

  void _notifyAuthChanged() {
    AuthEpoch.advance();
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _identityGeneration++;
    _nativeToken = null;
    _nativeAccountId = null;
    _remoteCredentialVerified = false;
    _localSessionEnrolled = false;
    _auditSession = false;
    _httpClient.close();
    super.dispose();
  }
}
