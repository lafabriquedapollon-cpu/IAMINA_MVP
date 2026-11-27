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
    // A widget contract test, not a viewport test: avoid lazy sliver clipping.
    // Real 390x844 pagination is independently required in both browser jobs.
    tester.view.devicePixelRatio=1;
    tester.view.physicalSize=const Size(800,2800);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final offsets=<int>[];
    final revoke=ValueNotifier<int>(0);
    var locks=0;
    late Completer<Map<String,dynamic>> pending;
    late Map<String,Object?> request;
    await tester.pumpWidget(MaterialApp(home:EvidenceUiCandidate(
      arabic:false,revoke:revoke,lock:(){locks++;},isCurrent:current,
      call:(action,args) {
        expect(args['start'],evidenceStartSeconds);
        expect(args['end'],evidenceEndSeconds);
        expect(args['limit'],evidencePageSize);
        if(action=='open')return Future.value(result(args,7,pageRows(0,10)));
        expect(action,'page');
        expect(args['revision'],7);
        offsets.add(args['offset'] as int);
        request=Map<String,Object?>.of(args);
        pending=Completer<Map<String,dynamic>>();
        return pending.future;
      },
    )));
    await tester.tap(find.text('Ouvrir profil A'));
    await tester.pumpAndSettle();
    expect(find.text('Page 1'),findsOneWidget);
    expect(find.text('100.0 mmol/L'),findsOneWidget);
    Future<void> navigate(String key,int offset,int revision) async {
      final button=find.byKey(Key(key));
      expect(button.hitTestable(),findsOneWidget);
      expect(tester.widget<TextButton>(button).onPressed,isNotNull);
      await tester.tap(button);
      await tester.pump();
      expect(offsets.last,offset);
      expect(pending.isCompleted,isFalse);
      final payload=result(request,revision,pageRows(offset,10));
      // Verify the synthetic transport result before delivering it.
      final parsed=EvidenceUiResult.fromJson(payload);
      expect(parsed.offset,offset);
      expect(parsed.revision,revision);
      pending.complete(payload);
      await tester.pump();
      await tester.pumpAndSettle();
    }
    await navigate('evidence-next',10,7);
    expect(offsets,[10]);
    expect(locks,0);
    expect(find.text('Page 2'),findsOneWidget);
    expect(find.text('110.0 mmol/L'),findsOneWidget);
    expect(find.text('100.0 mmol/L'),findsNothing);
    await navigate('evidence-prev',0,7);
    expect(offsets,[10,0]);
    expect(locks,0);
    expect(find.text('Page 1'),findsOneWidget);
    expect(find.text('100.0 mmol/L'),findsOneWidget);
    expect(find.text('110.0 mmol/L'),findsNothing);
    await navigate('evidence-next',10,8);
    expect(offsets,[10,0,10]);
    expect(locks,1);
    expect(find.text('Coffre verrouillé'),findsOneWidget);
    expect(find.text('100.0 mmol/L'),findsNothing);
    expect(find.text('110.0 mmol/L'),findsNothing);
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


  testWidgets('H3 named-zone display preserves UTC and rejects invalid projection', (tester) async {
    tester.view.devicePixelRatio=1;
    tester.view.physicalSize=const Size(800,1000);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final revoke=ValueNotifier<int>(0);
    final measured=DateTime.utc(2026,11,27,11,15,45).millisecondsSinceEpoch~/1000;
    Future<void> mount(String Function(int) projection) async {
      await tester.pumpWidget(MaterialApp(home:EvidenceUiCandidate(
        key:UniqueKey(),arabic:false,revoke:revoke,lock:(){},isCurrent:current,
        timestampProjection:projection,
        call:(action,args) async=>result(args,1,[{...row(7.83),'loggedAtSeconds':measured}]),
      )));
      await tester.tap(find.text('Ouvrir profil A'));await tester.pumpAndSettle();
    }
    await mount((_)=>'2026-11-27T12:15:45+01:00');
    expect(find.text('2026-11-27T12:15:45+01:00'),findsOneWidget);
    await mount((_)=>'2026-11-27T12:15:45+00:00'); // wrong UTC instant
    expect(find.text('2026-11-27T11:15:45+00:00'),findsOneWidget);
    expect(find.text('2026-11-27T12:15:45+00:00'),findsNothing);
    await tester.pumpWidget(const SizedBox());revoke.dispose();
  });

  // H5 complementary parser coverage. A single comma is decimal, never grouping.
  final validCases = <String,double>{
    '7.83':7.83, '7,83':7.83, '٧٫٨٣':7.83, '۷٫۸۳':7.83,
    ' 141 ':141.0, '١٤١':141.0,
  };
  for (final entry in validCases.entries) {
    test('H5 accepts explicit decimal '+entry.key, () {
      expect(parseEvidenceQuantity(entry.key,'mmol/L'),entry.value);
      expect(parseEvidenceQuantity(entry.key,'mg/dL'),entry.value);
    });
  }
  final rejectedFamilies = <String,List<String>>{
    'mixed or repeated separators':['7,8.3','7٫8,3','7..83','1,234,567'],
    'grouping and controls':['1 234','1\u00a0234','١٬٢٣٤','7\u200f.83'],
    'scientific notation and signs':['7e1','+7','-7','7E-1'],
    'invalid and nonfinite':['','0','0.0','NaN','Infinity','.7','7.','7/8'],
    'mixed digit scripts':['٧.83','۷٫٨٣'],
    'bounded length':[List.filled(65,'9').join()],
  };
  for (final family in rejectedFamilies.entries) {
    test('H5 rejects '+family.key, () {
      for (final raw in family.value) {
        expect(parseEvidenceQuantity(raw,'mg/dL'),isNull,reason:raw);
        expect(parseEvidenceQuantity(raw,'mmol/L'),isNull,reason:raw);
      }
    });
  }
  test('H5 refuses absent or unknown unit without guessing', () {
    for (final unit in <String?>[null,'','mg/dl','MMOL/L','unknown']) {
      expect(parseEvidenceQuantity('7.83',unit),isNull);
    }
  });
  for (final arabic in [false,true]) {
    testWidgets('H5 invalid entry does not mutate; localized recovery preserves source $arabic', (tester) async {
      tester.view.devicePixelRatio=1;
      tester.view.physicalSize=const Size(800,1200);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final revoke=ValueNotifier<int>(0);
      final calls=<String>[];
      await tester.pumpWidget(MaterialApp(home:EvidenceUiCandidate(
        arabic:arabic,revoke:revoke,lock:(){},isCurrent:current,
        call:(action,args) async {
          calls.add(action);
          if(action=='open')return result(args,7,[]);
          expect(action,'insert');
          expect(args['revision'],7);
          expect(args['value'],7.83);
          expect(args['unit'],'mmol/L');
          return result(args,8,[row(7.83)]);
        },
      )));
      await tester.tap(find.text(arabic?'فتح الملف A':'Ouvrir profil A'));
      await tester.pumpAndSettle();
      final field=find.byKey(const Key('evidence-value'));
      final save=find.byKey(const Key('evidence-save'));
      final unit=find.byKey(const ValueKey('mmol/L'));
      await tester.ensureVisible(unit);await tester.tap(unit);await tester.pumpAndSettle();
      for(final raw in ['7e1','1,2.3','0','٧.83']){
        await tester.enterText(field,raw);
        await tester.ensureVisible(save);await tester.tap(save);await tester.pumpAndSettle();
        expect(calls,['open']);
        expect(find.text(arabic?'تم رفض الإدخال أو العملية.':'Saisie ou opération refusée.'),findsOneWidget);
      }
      await tester.enterText(field,arabic?'٧٫٨٣':'7,83');
      await tester.ensureVisible(save);await tester.tap(save);await tester.pumpAndSettle();
      expect(calls,['open','insert']);
      expect(find.text('7.83 mmol/L'),findsOneWidget);
      revoke.value++;await tester.pumpAndSettle();
      expect(find.text('7.83 mmol/L'),findsNothing);
      await tester.pumpWidget(const SizedBox());revoke.dispose();
    });
  }

}
