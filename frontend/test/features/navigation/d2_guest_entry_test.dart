import 'package:amina/features/navigation/d2_guest_entry.dart';
import 'package:amina/l10n/app_localizations.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Widget app(D2Authenticate? authenticate, {bool registration = false}) => MaterialApp(
  locale: const Locale('fr'),
  supportedLocales: AppLocalizations.supportedLocales,
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  home: D2GuestEntry(authenticate: authenticate, registrationAvailable: registration),
);

Future<void> openGate(WidgetTester tester) async {
  await tester.tap(find.byKey(const ValueKey('d2-guest-action:/ajouter')));
  await tester.pumpAndSettle();
}

Future<void> fill(WidgetTester tester) async {
  await tester.enterText(find.byKey(const Key('d2-email')), 'synthetic@example.invalid');
  await tester.enterText(find.byKey(const Key('d2-password')), 'synthetic-only-secret');
}

void main() {
  testWidgets('guest and cancellation never invoke authentication', (tester) async {
    var calls = 0;
    await tester.pumpWidget(app((_, __, ___) async { calls++; return false; }));
    await tester.pumpAndSettle();
    await openGate(tester);
    expect(calls, 0);
    await tester.tap(find.byKey(const Key('d2-cancel')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('d2-guest-section')), findsOneWidget);
    expect(calls, 0);
  });

  testWidgets('failed login remains at gate; confirmed login cannot open vault', (tester) async {
    var calls = 0;
    await tester.pumpWidget(app((email, password, register) async {
      expect(email, 'synthetic@example.invalid');
      expect(register, isFalse);
      calls++;
      return calls == 2;
    }));
    await tester.pumpAndSettle();
    await openGate(tester);
    await fill(tester);
    await tester.tap(find.byKey(const Key('d2-submit')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('d2-auth-failed')), findsOneWidget);
    expect(find.byKey(const Key('d2-admission-blocked')), findsNothing);
    await fill(tester);
    await tester.tap(find.byKey(const Key('d2-submit')));
    await tester.pumpAndSettle();
    expect(calls, 2);
    expect(find.byKey(const Key('d2-admission-blocked')), findsOneWidget);
    expect(find.byKey(const Key('d2-guest-section')), findsNothing);
  });

  testWidgets('disabled identity has no submission; optional register is explicit', (tester) async {
    await tester.pumpWidget(app(null));
    await tester.pumpAndSettle();
    await openGate(tester);
    expect(find.byKey(const Key('d2-submit')), findsNothing);
    await tester.pumpWidget(const SizedBox());
    var registered = false;
    await tester.pumpWidget(app((_, __, register) async { registered = register; return true; }, registration: true));
    await tester.pumpAndSettle();
    await openGate(tester);
    await tester.tap(find.byKey(const Key('d2-toggle-register')));
    await tester.pumpAndSettle();
    await fill(tester);
    await tester.tap(find.byKey(const Key('d2-submit')));
    await tester.pumpAndSettle();
    expect(registered, isTrue);
    expect(find.byKey(const Key('d2-admission-blocked')), findsOneWidget);
  });
}
