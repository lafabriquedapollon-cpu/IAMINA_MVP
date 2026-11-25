import 'package:amina/features/navigation/d2_guest_shell.dart';
import 'package:amina/l10n/app_localizations.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  for (final locale in [const Locale('fr'), const Locale('ar'), const Locale('en')]) {
    for (final width in [390.0, 768.0, 1280.0]) {
      testWidgets('Guest navigation and protected intent: ${locale.languageCode} $width', (tester) async {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = Size(width, 844);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        final intents = <String>[];
        // Intentionally no Provider, API client, database, or auth service.
        await tester.pumpWidget(MaterialApp(
          locale: locale,
          supportedLocales: AppLocalizations.supportedLocales,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          home: D2GuestShell(onRequireIdentity: intents.add),
        ));
        await tester.pumpAndSettle();
        expect(intents, isEmpty);
        for (var i = 0; i < D2GuestSection.values.length; i++) {
          await tester.tap(find.byKey(ValueKey('d2-guest-nav-$i')));
          await tester.pumpAndSettle();
          expect(find.byKey(const Key('d2-guest-section')), findsOneWidget);
          expect(intents, isEmpty, reason: 'navigation alone is not an identity action');
        }
        await tester.tap(find.byKey(const ValueKey('d2-guest-action:/profile')));
        expect(intents, ['/profile']);
        await tester.tap(find.byKey(const ValueKey('d2-guest-nav-0')));
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const ValueKey('d2-guest-action:/companion')));
        expect(intents, ['/profile', '/companion']);
        await tester.tap(find.byKey(const ValueKey('d2-guest-action:/ajouter')));
        expect(intents, ['/profile', '/companion', '/ajouter']);
        expect(tester.takeException(), isNull);
      });
    }
  }
}
