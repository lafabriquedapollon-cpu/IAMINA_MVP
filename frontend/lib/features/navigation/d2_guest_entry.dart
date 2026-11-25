import 'package:flutter/material.dart';

import 'd2_guest_shell.dart';

typedef D2Authenticate = Future<bool> Function(String email, String password, bool register);

/// Candidate admission boundary. No DB, patient providers, API client, or
/// auth object is constructed by this widget. Only explicit form submission
/// invokes the injected authentication operation. The pending route is
/// volatile and never grants access to a protected route by itself.
class D2GuestEntry extends StatefulWidget {
  final D2Authenticate? authenticate;
  final bool registrationAvailable;

  const D2GuestEntry({
    super.key,
    this.authenticate,
    this.registrationAvailable = false,
  });

  @override
  State<D2GuestEntry> createState() => _D2GuestEntryState();
}

class _D2GuestEntryState extends State<D2GuestEntry> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  String? _pending;
  bool _register = false;
  bool _busy = false;
  bool _verified = false;
  bool _failed = false;

  String _t(String fr, String ar, String en) =>
      switch (Localizations.localeOf(context).languageCode) {
        'ar' => ar,
        'en' => en,
        _ => fr,
      };

  void _request(String route) {
    setState(() {
      _pending = route;
      _register = false;
      _failed = false;
      _verified = false;
    });
  }

  void _cancel() {
    if (_busy || _verified) return;
    _email.clear();
    _password.clear();
    setState(() {
      _pending = null;
      _failed = false;
      _register = false;
    });
  }

  Future<void> _submit() async {
    final authenticate = widget.authenticate;
    if (_busy || _verified || authenticate == null || _pending == null ||
        (_register && !widget.registrationAvailable)) return;
    final email = _email.text.trim();
    final password = _password.text;
    if (email.isEmpty || password.isEmpty) {
      setState(() => _failed = true);
      return;
    }
    setState(() {
      _busy = true;
      _failed = false;
    });
    bool verified = false;
    try {
      verified = await authenticate(email, password, _register);
    } catch (_) {
      verified = false;
    }
    if (!mounted) return;
    _password.clear();
    if (verified) _email.clear();
    setState(() {
      _busy = false;
      _verified = verified;
      _failed = !verified;
    });
  }

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_pending == null) return D2GuestShell(onRequireIdentity: _request);
    final unavailable = widget.authenticate == null;
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
        title: Text(_t('Identification', 'تسجيل الدخول', 'Identity')),
        leading: !_busy && !_verified ? IconButton(
          key: const Key('d2-cancel'),
          tooltip: _t('Retour', 'رجوع', 'Back'),
          onPressed: _cancel,
          icon: const Icon(Icons.arrow_back),
        ) : null,
      ),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: ListView(
              shrinkWrap: true,
              padding: const EdgeInsets.all(24),
              children: [
                if (_verified)
                  Text(
                    _t('Identité vérifiée. Ouverture du coffre indisponible tant que la sécurité locale n’est pas validée.',
                       'تم التحقق من الهوية. فتح المخزن غير متاح قبل التحقق من الأمان المحلي.',
                       'Identity verified. Vault access is unavailable until local security is validated.'),
                    key: const Key('d2-admission-blocked'),
                  )
                else ...[
                  Text(_t('Connectez-vous pour continuer cette action.', 'سجّل الدخول لمتابعة هذا الإجراء.', 'Sign in to continue this action.')),
                  const SizedBox(height: 16),
                  if (unavailable)
                    Text(_t('Connexion indisponible dans cette version de test.', 'تسجيل الدخول غير متاح في هذه النسخة التجريبية.', 'Sign-in unavailable in this test build.'))
                  else ...[
                    TextField(
                      key: const Key('d2-email'),
                      controller: _email,
                      enabled: !_busy,
                      keyboardType: TextInputType.emailAddress,
                      decoration: InputDecoration(labelText: _t('E-mail', 'البريد الإلكتروني', 'Email')),
                    ),
                    TextField(
                      key: const Key('d2-password'),
                      controller: _password,
                      enabled: !_busy,
                      obscureText: true,
                      enableSuggestions: false,
                      autocorrect: false,
                      decoration: InputDecoration(labelText: _t('Mot de passe', 'كلمة المرور', 'Password')),
                    ),
                    if (_failed)
                      Text(_t('Identification non confirmée. Réessayez.', 'لم يتم تأكيد الهوية. حاول مجددًا.', 'Identity not confirmed. Try again.'), key: const Key('d2-auth-failed')),
                    const SizedBox(height: 16),
                    FilledButton(
                      key: const Key('d2-submit'),
                      onPressed: _busy ? null : _submit,
                      child: Text(_register
                        ? _t('Créer un compte', 'إنشاء حساب', 'Create account')
                        : _t('Se connecter', 'تسجيل الدخول', 'Sign in')),
                    ),
                    if (widget.registrationAvailable)
                      TextButton(
                        key: const Key('d2-toggle-register'),
                        onPressed: _busy ? null : () => setState(() {
                          _register = !_register;
                          _password.clear();
                          _failed = false;
                        }),
                        child: Text(_register
                          ? _t('Compte existant', 'حساب موجود', 'Existing account')
                          : _t('Créer un compte', 'إنشاء حساب', 'Create account')),
                      ),
                  ],
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
