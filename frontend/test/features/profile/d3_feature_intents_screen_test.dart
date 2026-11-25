import 'dart:async';
import 'package:amina/features/profile/d3_feature_intents_screen.dart';
import 'package:amina/l10n/app_localizations.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> envelope(String locale, {bool photo = false, int revision = 0, int? receipt = 7}) => {
  'global_receipt_id': receipt,
  'features': [
    for (final feature in ['photo', 'companion', 'habits'])
      {'feature': feature, 'intent_enabled': feature == 'photo' && photo,
       'revision': feature == 'photo' ? revision : 0,
       'activation_available': false, 'external_ai_authorized': false},
  ],
  'notices': {
    for (final feature in ['photo', 'companion', 'habits'])
      feature: {'locale': locale, 'version': 'd3-candidate-1',
        'hash': List.filled(64, 'a').join(), 'text': 'Exact synthetic notice $feature $locale'},
  },
};

Widget app(ValueNotifier<int> epoch, D3ReadIntents read, D3WriteIntent write, String locale) => MaterialApp(
  locale: Locale(locale), supportedLocales: AppLocalizations.supportedLocales,
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  home: D3FeatureIntentsScreen(scopeEpoch: epoch, read: read, write: write),
);

void main() {
  for (final locale in ['fr', 'ar']) {
    testWidgets('explicit notice grant and independent withdrawal $locale', (tester) async {
      final epoch = ValueNotifier(1);
      addTearDown(epoch.dispose);
      var enabled = false;
      var rev = 0;
      final writes = <Map<String, dynamic>>[];
      await tester.pumpWidget(app(epoch, (l) async => envelope(l, photo: enabled, revision: rev),
        (feature, body) async {
          expect(feature, 'photo');
          writes.add(body);
          enabled = body['enabled'] as bool;
          rev++;
        }, locale));
      await tester.pumpAndSettle();
      expect(find.byType(SwitchListTile), findsNWidgets(3));
      await tester.tap(find.byKey(const ValueKey('d3-photo')));
      await tester.pumpAndSettle();
      expect(writes, isEmpty);
      expect(find.text('Exact synthetic notice photo $locale'), findsOneWidget);
      await tester.tap(find.byKey(const Key('d3-confirm')));
      await tester.pumpAndSettle();
      expect(writes.single['expected_global_receipt_id'], 7);
      expect(writes.single['expected_revision'], 0);
      expect(tester.widget<SwitchListTile>(find.byKey(const ValueKey('d3-photo'))).value, isTrue);
      expect(tester.widget<SwitchListTile>(find.byKey(const ValueKey('d3-companion'))).value, isFalse);
      await tester.tap(find.byKey(const ValueKey('d3-photo')));
      await tester.pumpAndSettle();
      expect(writes.last, {'enabled': false, 'expected_revision': 1});
      expect(tester.widget<SwitchListTile>(find.byKey(const ValueKey('d3-photo'))).value, isFalse);
    });
  }

  testWidgets('late read from previous scope cannot publish', (tester) async {
    final epoch = ValueNotifier(1);
    addTearDown(epoch.dispose);
    final pending = Completer<Map<String, dynamic>>();
    await tester.pumpWidget(app(epoch, (_) => pending.future, (_, __) async {}, 'fr'));
    await tester.pump();
    epoch.value = 2;
    pending.complete(envelope('fr', photo: true));
    await tester.pumpAndSettle();
    expect(find.byType(SwitchListTile), findsNothing);
    expect(find.byKey(const Key('d3-unknown')), findsOneWidget);
  });

  testWidgets('missing receipt disables controls; unauthorized response is rejected', (tester) async {
    final epoch = ValueNotifier(1);
    addTearDown(epoch.dispose);
    await tester.pumpWidget(app(epoch, (l) async => envelope(l, receipt: null), (_, __) async { fail('unexpected write'); }, 'fr'));
    await tester.pumpAndSettle();
    expect(tester.widget<SwitchListTile>(find.byKey(const ValueKey('d3-photo'))).onChanged, isNull);
    await tester.pumpWidget(const SizedBox());
    await tester.pumpWidget(app(epoch, (l) async {
      final value = envelope(l);
      (value['features'] as List).first['external_ai_authorized'] = true;
      return value;
    }, (_, __) async {}, 'fr'));
    await tester.pumpAndSettle();
    expect(find.byType(SwitchListTile), findsNothing);
    expect(find.byKey(const Key('d3-unknown')), findsOneWidget);
  });
}
