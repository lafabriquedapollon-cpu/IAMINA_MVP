import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import '../tool/d1_evidence_ui_candidate.dart';

void main() {
  const id = 'ac123456-1234-4abc-8def-000000000001';
  Map<String, dynamic> result(Map<String, Object?> args, int revision,
      List<Map<String, dynamic>> rows, {String? fault}) {
    final owner = fault == 'owner' ? 900002 : args['owner'];
    return {'binding': {'owner':owner,
      'vault':fault == 'vault' ? 'wrong' : 'amina_vault_v1_native_$owner',
      'epoch':fault == 'epoch' ? 8 : 7,
      'identityGeneration':fault == 'identityGeneration' ? 4 : 3,
      'session':(args['session'] as int) + (fault == 'session' ? 1 : 0)},
      'generation':(args['generation'] as int) + (fault == 'generation' ? 1 : 0),
      'requestId':(args['requestId'] as int) + (fault == 'requestId' ? 1 : 0),
      'revision':revision,'rows':rows};
  }
  bool current(EvidenceUiBinding b) => b.epoch == 7 && b.identityGeneration == 3;
  Map<String, dynamic> row(double value) => {
    'uuid':id,'originalValue':value,'originalUnit':'mmol/L',
    'displayMgDl':'141','displayMmolL':'7.8',
  };

  testWidgets('explicit unit required, native form forwards exact source and revision',
    (tester) async {
      final revoke = ValueNotifier<int>(0);
      final calls = <String>[];
      await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
        arabic:false,revoke:revoke,lock:(){},isCurrent:current,
        call:(action,args) async {
          calls.add(action);
          if (action=='open') return result(args,1,[]);
          expect(action,'insert');
          expect(args['revision'],1);
          expect(args['value'],7.83);
          expect(args['unit'],'mmol/L');
          return result(args,2,[row(7.83)]);
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
    late Map<String,Object?> request;
    await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){},isCurrent:current,call:(_,args){request=args;return pending.future;},
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pump();
    revoke.value++;
    await tester.pump();
    pending.complete(result(request,2,[row(7.83)]));
    await tester.pumpAndSettle();
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    expect(find.text('7.83 mmol/L'),findsNothing);
    await tester.pumpWidget(const SizedBox());
    revoke.dispose();
  });

  for (final fault in ['owner','vault','epoch','identityGeneration','session','requestId','generation','malformed-row']) {
    testWidgets('H2 rejects $fault before publishing rows', (tester) async {
      final revoke=ValueNotifier<int>(0);
      var locks=0;
      await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
        arabic:false,revoke:revoke,lock:(){locks++;},isCurrent:current,
        call:(_,args) async => result(args,1,
          [fault=='malformed-row' ? {...row(7.83),'originalUnit':'unknown'} : row(7.83)],
          fault:fault),
      )));
      await tester.tap(find.text('Ouvrir profil A'));
      await tester.pumpAndSettle();
      expect(locks,1);
      expect(find.text('Coffre verrouillé'),findsOneWidget);
      expect(find.text('7.83 mmol/L'),findsNothing);
      expect(find.text('Profil B'),findsNothing);
      await tester.pumpWidget(const SizedBox());
      revoke.dispose();
    });
  }

  testWidgets('H2 late mutation ACK cannot overwrite newer owner', (tester) async {
    final revoke=ValueNotifier<int>(0);
    final pending=Completer<Map<String,dynamic>>();
    late Map<String,Object?> mutation;
    var locks=0;
    await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){locks++;},isCurrent:current,
      call:(action,args) async {
        if(action=='open') return result(args,1,[]);
        mutation=args;return pending.future;
      },
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('evidence-value')),'7.83');
    await tester.ensureVisible(find.byKey(const ValueKey('mmol/L')));
    await tester.tap(find.byKey(const ValueKey('mmol/L')));
    await tester.ensureVisible(find.byKey(const Key('evidence-save')));
    await tester.tap(find.byKey(const Key('evidence-save')));
    await tester.pump();
    revoke.value++;
    await tester.pump();
    await tester.tap(find.text('Ouvrir profil B'));
    await tester.pumpAndSettle();
    pending.complete(result(mutation,2,[row(7.83)]));
    await tester.pumpAndSettle();
    expect(find.text('Profil B'),findsOneWidget);
    expect(find.text('7.83 mmol/L'),findsNothing);
    expect(locks,0);
    await tester.pumpWidget(const SizedBox());
    revoke.dispose();
  });

  testWidgets('H2 refuses mutation revision mismatch', (tester) async {
    final revoke=ValueNotifier<int>(0);
    var locks=0;
    await tester.pumpWidget(MaterialApp(home: EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){locks++;},isCurrent:current,
      call:(action,args) async => action=='open'
        ? result(args,1,[]) : result(args,3,[row(7.83)]),
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('evidence-value')),'7.83');
    await tester.ensureVisible(find.byKey(const ValueKey('mmol/L')));
    await tester.tap(find.byKey(const ValueKey('mmol/L')));
    await tester.ensureVisible(find.byKey(const Key('evidence-save')));
    await tester.tap(find.byKey(const Key('evidence-save')));
    await tester.pumpAndSettle();
    expect(locks,1);
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    expect(find.text('7.83 mmol/L'),findsNothing);
    await tester.pumpWidget(const SizedBox());
    revoke.dispose();
  });

}
