import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import '../tool/d1_evidence_ui_candidate.dart';

void main() {
  const id = 'ac123456-1234-4abc-8def-000000000001';
  Map<String, dynamic> result(int revision, List<Map<String, dynamic>> rows) =>
      {'owner':900001,'revision':revision,'rows':rows};
  Map<String, dynamic> row(double value) => {
    'uuid':id,'originalValue':value,'originalUnit':'mmol/L',
    'displayMgDl':'141','displayMmolL':'7.8',
  };

  testWidgets('explicit unit required, native form forwards exact source and revision',
    (tester) async {
      final revoke = ValueNotifier<int>(0);
      final calls = <String>[];
      await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
        arabic:false,revoke:revoke,lock:(){},
        call:(action,args) async {
          calls.add(action);
          if (action=='open') return result(1,[]);
          expect(action,'insert');
          expect(args['revision'],1);
          expect(args['value'],7.83);
          expect(args['unit'],'mmol/L');
          return result(2,[row(7.83)]);
        },
      )));
      await tester.tap(find.text('Ouvrir profil A'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('evidence-value')),'7,83');
      await tester.ensureVisible(find.byKey(const Key('evidence-save')));
      await tester.tap(find.byKey(const Key('evidence-save')));
      await tester.pumpAndSettle();
      expect(calls,['open']);
      expect(find.text('Saisie ou opération refusée.'),findsOneWidget);
      await tester.ensureVisible(find.byKey(const ValueKey('mmol/L')));
      await tester.tap(find.byKey(const ValueKey('mmol/L')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('evidence-save')));
      await tester.tap(find.byKey(const Key('evidence-save')));
      await tester.pumpAndSettle();
      expect(calls,['open','insert']);
      expect(find.text('7.83 mmol/L'),findsOneWidget);
      revoke.value++;
      await tester.pumpAndSettle();
      expect(find.text('7.83 mmol/L'),findsNothing);
      expect(find.text('Coffre verrouillé'),findsOneWidget);
      await tester.pumpWidget(const SizedBox());
      revoke.dispose();
    });

  testWidgets('late open result cannot populate revoked screen', (tester) async {
    final revoke=ValueNotifier<int>(0);
    final pending=Completer<Map<String,dynamic>>();
    await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){},call:(_,__)=>pending.future,
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pump();
    revoke.value++;
    await tester.pump();
    pending.complete(result(2,[row(7.83)]));
    await tester.pumpAndSettle();
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    expect(find.text('7.83 mmol/L'),findsNothing);
    await tester.pumpWidget(const SizedBox());
    revoke.dispose();
  });
}
