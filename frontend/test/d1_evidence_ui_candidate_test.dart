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
      'revision':revision,'rows':rows,
      'start':args['start'],'end':args['end'],'limit':args['limit'],
      'offset':args['offset'],'nextOffset':rows.length==evidencePageSize? (args['offset'] as int)+evidencePageSize:null};
  }
  bool current(EvidenceUiBinding b) => b.epoch == 7 && b.identityGeneration == 3;
  Map<String, dynamic> row(double value) => {
    'uuid':id,'originalValue':value,'originalUnit':'mmol/L',
    'displayMgDl':'141','displayMmolL':'7.8',
    'loggedAtSeconds':1795564800,'createdAtSeconds':1795564801,
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
          expect((DateTime.now().millisecondsSinceEpoch~/1000)-(args['loggedAtSeconds'] as int), inInclusiveRange(0,5));
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


  test('H3 UTC offset, leap day, DST overlap and exclusive interval', () {
    int seconds(DateTime time)=>time.millisecondsSinceEpoch~/1000;
    expect(parseEvidenceTimestamp('2024-10-27T02:30:00+02:00'),seconds(DateTime.utc(2024,10,27,0,30)));
    expect(parseEvidenceTimestamp('2024-10-27T02:30:00+01:00'),seconds(DateTime.utc(2024,10,27,1,30)));
    expect(parseEvidenceTimestamp('2024-03-31T01:59:59+01:00'),seconds(DateTime.utc(2024,3,31,0,59,59)));
    expect(parseEvidenceTimestamp('2024-03-31T03:00:00+02:00'),seconds(DateTime.utc(2024,3,31,1)));
    expect(parseEvidenceTimestamp('2024-03-31T00:00:00+01:00'),seconds(DateTime.utc(2024,3,30,23)));
    expect(parseEvidenceTimestamp('2024-04-01T00:00:00+02:00')!-
      parseEvidenceTimestamp('2024-03-31T00:00:00+01:00')!,23*3600);
    expect(parseEvidenceTimestamp('2024-10-28T00:00:00+01:00')!-
      parseEvidenceTimestamp('2024-10-27T00:00:00+02:00')!,25*3600);
    expect(parseEvidenceTimestamp('2024-02-29T12:00:00+05:30'),seconds(DateTime.utc(2024,2,29,6,30)));
    for(final bad in ['2023-02-29T00:00:00Z','2024-02-30T00:00:00Z',
      '2024-10-27T02:30:00','2024-10-27T24:00:00Z','2024-10-27T02:30:60Z',
      '2024-10-27T02:30:00+14:01','2024-10-27T02:30:00-00:00',
      '1970-01-01T00:00:00Z','2100-01-01T00:00:00Z']) {
      expect(parseEvidenceTimestamp(bad),isNull,reason:bad);
    }
    expect(parseEvidenceTimestamp('1970-01-01T00:00:01Z'),1);
    expect(parseEvidenceTimestamp('2099-12-31T23:59:59Z'),evidenceEndSeconds-1);
    for(final value in [1,1795564800,evidenceEndSeconds-1]) {
      expect(parseEvidenceTimestamp(formatEvidenceTimestamp(value,local:false)),value);
    }
    final now=seconds(DateTime.now());
    expect(parseEvidenceTimestamp(formatEvidenceTimestamp(now)),now);
  });

  List<Map<String,dynamic>> pageRows(int offset, int count) => [
    for(var i=offset;i<offset+count;i++) {
      ...row(100+i.toDouble()),
      'uuid':'ac123456-1234-4abc-8def-'+(i+100).toString().padLeft(12,'0'),
      'loggedAtSeconds':1795564800-i,
    }
  ];

  testWidgets('H3 pagination keeps revision and rejects stale response', (tester) async {
    // Keep the pager within the synthetic viewport, independent of the
    // framework's default 800x600 and lazy ListView construction.
    tester.view.devicePixelRatio=1;
    tester.view.physicalSize=const Size(800,1000);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final offsets=<int>[];
    final revoke=ValueNotifier<int>(0);
    var locks=0;
    var stale=false;
    await tester.pumpWidget(MaterialApp(home:EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){locks++;},isCurrent:current,
      call:(action,args) async {
        expect(args['start'],evidenceStartSeconds);
        expect(args['end'],evidenceEndSeconds);
        expect(args['limit'],evidencePageSize);
        if(action=='open')return result(args,7,pageRows(0,10));
        expect(action,'page');
        expect(args['revision'],7);
        final offset=args['offset'] as int;
        offsets.add(offset);
        return result(args,stale?8:7,pageRows(offset,10));
      },
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pumpAndSettle();
    expect(find.text('Page 1'),findsOneWidget);
    await tester.ensureVisible(find.byKey(const Key('evidence-next')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('evidence-next')).hitTestable(),findsOneWidget);
    await tester.tap(find.byKey(const Key('evidence-next')));
    await tester.pumpAndSettle();
    expect(offsets,[10]);
    expect(locks,0);
    expect(find.text('Page 2'),findsOneWidget);
    await tester.ensureVisible(find.byKey(const Key('evidence-prev')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('evidence-prev')).hitTestable(),findsOneWidget);
    await tester.tap(find.byKey(const Key('evidence-prev')));
    await tester.pumpAndSettle();
    expect(find.text('Page 1'),findsOneWidget);
    expect(offsets,[10,0]);
    expect(locks,0);
    stale=true;
    await tester.ensureVisible(find.byKey(const Key('evidence-next')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('evidence-next')).hitTestable(),findsOneWidget);
    await tester.tap(find.byKey(const Key('evidence-next')));
    await tester.pumpAndSettle();
    expect(offsets,[10,0,10]);
    expect(locks,1);
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    await tester.pumpWidget(const SizedBox());revoke.dispose();
  });

  testWidgets('H3 edit preserves measurement instant and clears after revocation', (tester) async {
    tester.view.devicePixelRatio=1;
    tester.view.physicalSize=const Size(800,1000);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final revoke=ValueNotifier<int>(0);
    final measured=DateTime.utc(2024,10,27,1,30).millisecondsSinceEpoch~/1000;
    var edits=0;
    await tester.pumpWidget(MaterialApp(home:EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){},isCurrent:current,
      call:(action,args) async {
        if(action=='open')return result(args,1,[{...row(7.83),'loggedAtSeconds':measured}]);
        expect(action,'edit');
        expect(args['uuid'],id);
        expect(args['loggedAtSeconds'],measured);
        expect(args['revision'],1);
        edits++;
        return result(args,2,[{...row(8.2),'loggedAtSeconds':measured}]);
      },
    )));
    await tester.tap(find.text('Ouvrir profil A'));await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Modifier'));
    await tester.pumpAndSettle();
    expect(find.text('Modifier').hitTestable(),findsOneWidget);
    await tester.tap(find.text('Modifier'));await tester.pumpAndSettle();
    expect(find.text('Modifier la mesure'),findsOneWidget);
    await tester.enterText(find.byKey(const Key('evidence-value')),'8.2');
    await tester.ensureVisible(find.byKey(const Key('evidence-save')));
    await tester.tap(find.byKey(const Key('evidence-save')));await tester.pumpAndSettle();
    expect(edits,1);
    revoke.value++;await tester.pumpAndSettle();
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    expect(find.text(formatEvidenceTimestamp(measured)),findsNothing);
    await tester.pumpWidget(const SizedBox());revoke.dispose();
  });

}
