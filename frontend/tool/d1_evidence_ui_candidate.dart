// CONV-02c.2: isolated synthetic qualification UI, never imported by lib/main.dart.
import 'package:flutter/material.dart';
import 'package:amina/core/domain/glucose_quantity_evidence.dart';
import 'package:amina/core/theme/app_theme.dart' show kOfflineFontFallbacks;

typedef EvidenceUiCall = Future<Map<String, dynamic>> Function(
    String action, Map<String, Object?> args);

// Correlation fields do not grant admission authority.
final class EvidenceUiBinding {
  final int owner, epoch, identityGeneration, session;
  final String vault;
  const EvidenceUiBinding({required this.owner, required this.epoch,
    required this.identityGeneration, required this.session, required this.vault});
  bool get valid => (owner == 900001 || owner == 900002) &&
      epoch > 0 && identityGeneration >= 0 && session > 0 &&
      vault == 'amina_vault_v1_native_$owner';
  bool matches(EvidenceUiBinding other) =>
      owner == other.owner && epoch == other.epoch &&
      identityGeneration == other.identityGeneration &&
      session == other.session && vault == other.vault;
  Map<String, Object?> toJson() => {
    'owner': owner, 'epoch': epoch, 'identityGeneration': identityGeneration,
    'session': session, 'vault': vault,
  };
  factory EvidenceUiBinding.fromJson(Map<String, dynamic> raw) =>
      EvidenceUiBinding(owner: raw['owner'] as int, epoch: raw['epoch'] as int,
        identityGeneration: raw['identityGeneration'] as int,
        session: raw['session'] as int, vault: raw['vault'] as String);
}

// Half-open UTC interval; an explicit offset is required for historical input.
const evidenceStartSeconds = 1;
const evidenceEndSeconds = 4102444800;
const evidencePageSize = 10;

// H5: explicit decimal grammar. No grouping, exponent, signs or mixed scripts.
double? parseEvidenceQuantity(String input, String? unit) {
  final source = GlucoseSourceUnit.fromExplicitUcumCode(unit);
  if (source == null) return null;
  final text = input.trim();
  if (text.isEmpty || text.length > 64) return null;
  final normalized = StringBuffer();
  int? alphabet;
  var separator = false;
  for (final rune in text.runes) {
    if (rune == 0x2e || rune == 0x2c || rune == 0x066b) {
      if (separator) return null;
      separator = true;
      normalized.write('.');
      continue;
    }
    final int base;
    if (rune >= 0x30 && rune <= 0x39) {
      base = 0x30;
    } else if (rune >= 0x0660 && rune <= 0x0669) {
      base = 0x0660;
    } else if (rune >= 0x06f0 && rune <= 0x06f9) {
      base = 0x06f0;
    } else {
      return null;
    }
    if (alphabet != null && alphabet != base) return null;
    alphabet = base;
    normalized.writeCharCode(0x30 + rune - base);
  }
  final decimal = normalized.toString();
  if (!RegExp(r'^\d+(\.\d+)?$').hasMatch(decimal)) return null;
  final value = double.tryParse(decimal);
  if (value == null || !value.isFinite || value <= 0) return null;
  try {
    GlucoseConversionContract.toMgDl(value, source);
  } on ArgumentError {
    return null;
  }
  return value;
}

bool validEvidenceSeconds(int seconds) =>
    seconds >= evidenceStartSeconds && seconds < evidenceEndSeconds;

int? parseEvidenceTimestamp(String input) {
  final match = RegExp(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$')
      .firstMatch(input.trim());
  if (match == null) return null;
  final p = [for (var i=1; i<=6; i++) int.parse(match.group(i)!)];
  final civil = DateTime.utc(p[0],p[1],p[2],p[3],p[4],p[5]);
  if (civil.year!=p[0] || civil.month!=p[1] || civil.day!=p[2] ||
      civil.hour!=p[3] || civil.minute!=p[4] || civil.second!=p[5]) return null;
  final zone=match.group(7)!;
  var minutes=0;
  if (zone!='Z') {
    final h=int.parse(zone.substring(1,3)), m=int.parse(zone.substring(4,6));
    if (h>14 || m>59 || (h==14 && m!=0) || zone=='-00:00') return null;
    minutes=(h*60+m)*(zone.startsWith('-')?-1:1);
  }
  final seconds=civil.millisecondsSinceEpoch~/1000-minutes*60;
  return validEvidenceSeconds(seconds) ? seconds : null;
}

String formatEvidenceTimestamp(int seconds, {bool local=true}) {
  final utc=DateTime.fromMillisecondsSinceEpoch(seconds*1000,isUtc:true);
  final date=local ? utc.toLocal() : utc;
  String two(int n)=>n.toString().padLeft(2,'0');
  final offset=date.timeZoneOffset.inMinutes;
  final abs=offset.abs();
  return date.year.toString().padLeft(4,'0')+'-'+two(date.month)+'-'+two(date.day)
      +'T'+two(date.hour)+':'+two(date.minute)+':'+two(date.second)
      +(offset<0?'-':'+')+two(abs~/60)+':'+two(abs%60);
}

int compareEvidenceRows(Map<String,dynamic> a, Map<String,dynamic> b) {
  final time=(b['loggedAtSeconds'] as int).compareTo(a['loggedAtSeconds'] as int);
  return time!=0 ? time : (a['uuid'] as String).compareTo(b['uuid'] as String);
}

final class EvidenceUiResult {
  final EvidenceUiBinding binding;
  final int generation, requestId, revision, offset;
  final int? nextOffset;
  final List<Map<String, dynamic>> rows;
  EvidenceUiResult._(this.binding, this.generation, this.requestId, this.revision,
    this.offset, this.nextOffset, this.rows);
  factory EvidenceUiResult.fromJson(Map<String, dynamic> raw) {
    final rows = (raw['rows'] as List).map((r) =>
        Map<String, dynamic>.unmodifiable(Map<String, dynamic>.from(r as Map))).toList();
    final seen = <String>{};
    for (final row in rows) {
      final uuid = row['uuid'], value = row['originalValue'];
      final logged = row['loggedAtSeconds'], created = row['createdAtSeconds'];
      if (uuid is! String ||
          !RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$').hasMatch(uuid) ||
          !seen.add(uuid) || value is! num || !value.isFinite || value <= 0 ||
          !['mg/dL', 'mmol/L'].contains(row['originalUnit']) ||
          row['displayMgDl'] is! String || row['displayMmolL'] is! String ||
          logged is! int || !validEvidenceSeconds(logged) ||
          created is! int || !validEvidenceSeconds(created)) {
        throw StateError('Invalid UI row');
      }
    }
    final offset=raw['offset'] as int, next=raw['nextOffset'] as int?;
    if (raw['start']!=evidenceStartSeconds || raw['end']!=evidenceEndSeconds ||
        raw['limit']!=evidencePageSize || offset<0 || offset>10000 ||
        offset%evidencePageSize!=0 || rows.length>evidencePageSize ||
        (next!=null && (next!=offset+evidencePageSize || next>10000 || rows.length!=evidencePageSize))) {
      throw StateError('Invalid UI journal page');
    }
    for(var i=1;i<rows.length;i++) {
      if(compareEvidenceRows(rows[i-1],rows[i])>=0) throw StateError('Invalid UI journal order');
    }
    return EvidenceUiResult._(
      EvidenceUiBinding.fromJson(Map<String, dynamic>.from(raw['binding'] as Map)),
      raw['generation'] as int, raw['requestId'] as int, raw['revision'] as int,
      offset, next, List.unmodifiable(rows));
  }
}

class EvidenceUiCandidate extends StatefulWidget {
  const EvidenceUiCandidate({super.key, required this.call,
    required this.revoke, required this.lock, required this.arabic, required this.isCurrent,
    this.timestampProjection});
  // Presentation only. This callback cannot change the stored UTC instant.
  final String Function(int)? timestampProjection;
  final EvidenceUiCall call;
  final bool Function(EvidenceUiBinding) isCurrent;
  final ValueNotifier<int> revoke;
  final VoidCallback lock;
  final bool arabic;

  @override
  State<EvidenceUiCandidate> createState() => _EvidenceUiCandidateState();
}

class _EvidenceUiCandidateState extends State<EvidenceUiCandidate> {
  final _value = TextEditingController();
  final _timestamp = TextEditingController();
  final _valueFocus = FocusNode();
  int _generation = 0, _requestSequence = 0;
  EvidenceUiBinding? _binding;
  int? get _owner => _binding?.owner;
  int? _revision, _nextOffset, _editingSeconds;
  int _offset=0;
  bool _customTime=false;
  String? _unit, _editing, _confirmDelete;
  bool _busy = false, _error = false;
  List<Map<String, dynamic>> _rows = [];
  String tr(String fr, String ar) => widget.arabic ? ar : fr;

  String _time(int seconds) {
    final projection=widget.timestampProjection;
    if(projection==null) return formatEvidenceTimestamp(seconds);
    try {
      final displayed=projection(seconds);
      if(parseEvidenceTimestamp(displayed)==seconds) return displayed;
    } catch (_) { /* explicitly offset UTC fallback */ }
    return formatEvidenceTimestamp(seconds,local:false);
  }

  @override
  void initState() {
    super.initState();
    widget.revoke.addListener(_clear);
  }

  void _clear() {
    _generation++;
    _valueFocus.unfocus();
    _value.clear();
    _timestamp.clear();
    if (mounted) {
      setState(() {
        _binding = null; _revision = null; _unit = null; _editing = null; _confirmDelete = null;
        _rows = []; _busy = false; _error = false;
        _offset=0; _nextOffset=null; _editingSeconds=null; _customTime=false;
      });
    }
  }

  void _lock() {
    _clear();
    widget.lock();
  }

  Future<void> _perform(String action, Map<String, Object?> args) async {
    if (_busy) return;
    final generation = _generation;
    final previous = _binding;
    final opening = action == 'open';
    final paging = action == 'page';
    final requestedOffset = paging ? args['offset'] as int : 0;
    final priorRevision = _revision;
    final owner = opening ? args['owner'] as int? : previous?.owner;
    final requestId = ++_requestSequence;
    setState(() { _busy = true; _error = false; });
    try {
      if (owner == null || (opening && previous != null) ||
          (!opening && (previous == null || !widget.isCurrent(previous)))) {
        throw StateError('UI authority required');
      }
      final session = opening ? requestId : previous!.session;
      final result = await widget.call(action, {
        ...args, 'owner': owner, 'generation': generation, 'requestId': requestId,
        'session': session, 'binding': previous?.toJson(),
        'start':evidenceStartSeconds, 'end':evidenceEndSeconds,
        'limit':evidencePageSize, 'offset':requestedOffset,
      });
      if (!mounted || generation != _generation) return;
      final response = EvidenceUiResult.fromJson(result);
      final binding = response.binding;
      if (!binding.valid || binding.owner != owner || binding.session != session ||
          response.generation != generation || response.requestId != requestId ||
          (previous != null && !previous.matches(binding)) ||
          !widget.isCurrent(binding) || response.revision <= 0 ||
          response.offset != requestedOffset ||
          (!opening && response.revision != priorRevision! + (paging ? 0 : 1))) {
        throw StateError('UI response binding refused');
      }
      if (paging && (_rows.isEmpty || response.rows.isEmpty ||
          response.rows.any((r)=>_rows.any((old)=>old['uuid']==r['uuid'])) ||
          (requestedOffset>_offset && compareEvidenceRows(_rows.last,response.rows.first)>=0) ||
          (requestedOffset<_offset && compareEvidenceRows(response.rows.last,_rows.first)>=0))) {
        throw StateError('Journal page boundary refused');
      }
      setState(() {
        _binding = binding;
        _revision = response.revision;
        _rows = response.rows;
        _offset=response.offset; _nextOffset=response.nextOffset;
        _busy = false;
        _confirmDelete = null;
        if (!paging) {
          _value.clear(); _unit = null; _editing = null;
          _timestamp.clear(); _customTime=false; _editingSeconds=null;
        }
      });
    } catch (_) {
      if (!mounted || generation != _generation) return;
      _lock();
      if (mounted) setState(() => _error = true);
    }
  }

  void _save() {
    final value = parseEvidenceQuantity(_value.text, _unit);
    final now=DateTime.now().millisecondsSinceEpoch~/1000;
    final seconds=_editingSeconds ?? (_customTime ? parseEvidenceTimestamp(_timestamp.text) : now);
    if (_unit == null || value == null || !value.isFinite || value <= 0 ||
        seconds==null || !validEvidenceSeconds(seconds) || seconds>now) {
      setState(() => _error = true);
      return;
    }
    _perform(_editing == null ? 'insert' : 'edit', {
      'revision': _revision, 'uuid': _editing, 'value': value, 'unit': _unit,
      'loggedAtSeconds': seconds,
    });
  }

  @override
  void dispose() {
    widget.revoke.removeListener(_clear);
    _generation++;
    _valueFocus.dispose();
    _value.dispose();
    _timestamp.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Bind the bundled families to both localized geometry and color styles.
    // The synthetic screen must render without requesting CDN fallbacks.
    final base = Theme.of(context);
    final family = widget.arabic ? 'NotoSansArabic' : 'Inter';
    TextTheme local(TextTheme theme) => theme.apply(
      fontFamily: family, fontFamilyFallback: kOfflineFontFallbacks,
    );
    final typography = base.typography;
    return Theme(data: base.copyWith(
      textTheme: local(base.textTheme),
      primaryTextTheme: local(base.primaryTextTheme),
      typography: typography.copyWith(
        black: local(typography.black), white: local(typography.white),
        englishLike: local(typography.englishLike), dense: local(typography.dense),
        tall: local(typography.tall),
      ),
    ), child: Builder(builder: _buildContent));
  }

  Widget _buildContent(BuildContext context) {
    return Directionality(
      textDirection: widget.arabic ? TextDirection.rtl : TextDirection.ltr,
      child: Scaffold(
        appBar: AppBar(
          title: Text(tr('Journal glycémique', 'سجل سكر الدم')),
          actions: [TextButton(onPressed: _lock,
            child: Text(tr('Verrouiller', 'قفل')))],
        ),
        body: SafeArea(child: Center(child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: ListView(padding: const EdgeInsets.all(20), children: [
            Text(tr('Qualification — données fictives uniquement', 'اختبار — بيانات وهمية فقط'),
              style: Theme.of(context).textTheme.labelLarge),
            const SizedBox(height: 12),
            if (_owner == null) ...[
              Text(tr('Coffre verrouillé', 'المخزن مقفل'),
                style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 12),
              FilledButton(onPressed: _busy ? null : () => _perform('open', {'owner': 900001}),
                child: Text(tr('Ouvrir profil A', 'فتح الملف A'))),
              FilledButton(onPressed: _busy ? null : () => _perform('open', {'owner': 900002}),
                child: Text(tr('Ouvrir profil B', 'فتح الملف B'))),
            ] else ...[
              Text(_owner == 900001 ? tr('Profil A', 'الملف A') : tr('Profil B', 'الملف B'),
                style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
              const SizedBox(height: 12),
              Card(semanticContainer: false, child: Padding(padding: const EdgeInsets.all(16), child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(_editing == null ? tr('Ajouter une mesure', 'إضافة قياس') : tr('Modifier la mesure', 'تعديل القياس'),
                    style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 12),
                  Semantics(identifier: 'evidence-value', child: TextField(
                    key: const Key('evidence-value'), controller: _value, enabled: !_busy,
                    focusNode: _valueFocus, textDirection: TextDirection.ltr,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      fontFamily: 'Inter', fontFamilyFallback: kOfflineFontFallbacks),
                    keyboardType: const TextInputType.numberWithOptions(decimal: true),
                    decoration: InputDecoration(labelText: tr('Valeur glycémique', 'قيمة السكر'),
                      helperText: tr('Décimales : 7,83 ou 7.83. Pas de milliers.', 'الكسور: ٧٫٨٣ أو 7.83. دون فصل الآلاف.'),
                      helperMaxLines: 2, border: const OutlineInputBorder()))),
                  const SizedBox(height: 12),
                  Text(tr('Unité de saisie (obligatoire)', 'وحدة الإدخال (إلزامية)')),
                  Wrap(spacing: 12, runSpacing: 8, children: [
                    for (final unit in ['mg/dL','mmol/L'])
                      Semantics(identifier: unit == 'mg/dL' ? 'evidence-mgdl' : 'evidence-mmoll',
                        child: ChoiceChip(key: ValueKey(unit), label: Text(unit), selected: _unit == unit,
                          materialTapTargetSize: MaterialTapTargetSize.padded,
                          onSelected: _busy ? null : (selected) => setState(() {
                            _unit = selected ? unit : null; _error = false;
                          }))),
                  ]),
                  const SizedBox(height: 12),
                  if (_editingSeconds != null)
                    Text(_time(_editingSeconds!), textDirection: TextDirection.ltr)
                  else ...[
                    TextButton(key: const Key('evidence-time-toggle'), onPressed: _busy ? null : () {
                      setState(() {
                        _customTime=!_customTime;
                        _timestamp.text=_customTime ? _time(DateTime.now().millisecondsSinceEpoch~/1000) : '';
                      });
                    }, child: Text(_customTime ? tr('Utiliser l’heure actuelle','استعمال الوقت الحالي') :
                      tr('Mesure antérieure (date et heure)','قياس سابق (التاريخ والوقت)'))),
                    if (_customTime) Semantics(identifier:'evidence-time', child: TextField(
                      key: const Key('evidence-time'), controller:_timestamp, enabled:!_busy,
                      textDirection:TextDirection.ltr, autocorrect:false, enableSuggestions:false,
                      decoration:InputDecoration(labelText:tr('Date et heure avec fuseau','التاريخ والوقت مع التوقيت'),
                        hintText:'2026-11-01T08:00:00+01:00'))),
                  ],
                  const SizedBox(height: 12),
                  Semantics(identifier: 'evidence-save', child: FilledButton(
                    key: const Key('evidence-save'), onPressed: _busy ? null : _save,
                    style: FilledButton.styleFrom(minimumSize: const Size(0,48)),
                    child: Text(tr('Enregistrer', 'حفظ')))),
                  if (_error) Semantics(identifier: 'evidence-input-error', liveRegion: true,
                    child: Padding(padding: const EdgeInsets.only(top: 8),
                      child: Text(tr('Saisie ou opération refusée.', 'تم رفض الإدخال أو العملية.'),
                        style: TextStyle(color: Theme.of(context).colorScheme.error)))),
                  if (_editing != null) TextButton(onPressed: _busy ? null : () => setState(() {
                    _editing = null; _unit = null; _value.clear();
                    _editingSeconds=null; _customTime=false; _timestamp.clear();
                  }), child: Text(tr('Annuler', 'إلغاء'))),
                ],
              ))),
              const SizedBox(height: 16),
              Text(tr('Mesures enregistrées', 'القياسات المسجلة'),
                style: Theme.of(context).textTheme.titleLarge),
              if (_rows.isEmpty) Text(tr('Aucune mesure explicite', 'لا توجد قياسات صريحة')),
              if (_offset>0 || _nextOffset!=null) ...[
                Text(tr('Page', 'صفحة')+' '+(_offset~/evidencePageSize+1).toString()),
                Wrap(spacing:8,children:[
                  TextButton(key:const Key('evidence-prev'),onPressed:_busy||_editing!=null||_offset==0?null:()=>_perform('page',{
                    'revision':_revision,'offset':_offset-evidencePageSize,
                  }),child:Text(tr('Précédent','السابق'))),
                  TextButton(key:const Key('evidence-next'),onPressed:_busy||_editing!=null||_nextOffset==null?null:()=>_perform('page',{
                    'revision':_revision,'offset':_nextOffset,
                  }),child:Text(tr('Suivant','التالي'))),
                ]),
              ],
              for (final row in _rows) Card(semanticContainer: false, child: Padding(padding: const EdgeInsets.all(12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('${row['originalValue']} ${row['originalUnit']}',
                    textDirection: TextDirection.ltr,
                    style: Theme.of(context).textTheme.titleMedium),
                  Text('${row['displayMgDl']} mg/dL · ${row['displayMmolL']} mmol/L',
                    textDirection: TextDirection.ltr),
                  Text(_time(row['loggedAtSeconds'] as int),
                    textDirection: TextDirection.ltr, style:Theme.of(context).textTheme.bodyMedium),
                  const SizedBox(height: 8),
                  Wrap(spacing: 12, runSpacing: 4, children: [
                    TextButton(style: TextButton.styleFrom(minimumSize: const Size(44,44)), onPressed: _busy ? null : () {
                      setState(() {
                        _confirmDelete = null; _editing = row['uuid'] as String; _unit = row['originalUnit'] as String;
                        _value.text = row['originalValue'].toString();
                        _editingSeconds=row['loggedAtSeconds'] as int;
                        _customTime=false; _timestamp.clear();
                      });
                      _valueFocus.requestFocus();
                    }, child: Text(tr('Modifier', 'تعديل'))),
                    TextButton(style: TextButton.styleFrom(minimumSize: const Size(44,44),
                      foregroundColor: Theme.of(context).colorScheme.error), onPressed: _busy ? null : () => setState(() {
                      _confirmDelete = row['uuid'] as String;
                    }), child: Text(tr('Supprimer', 'حذف'))),
                  ]),
                  if (_confirmDelete == row['uuid']) ...[
                    Text(tr('Confirmer la suppression de cette mesure ?', 'هل تريد تأكيد حذف هذا القياس؟')),
                    Wrap(spacing: 8, children: [
                      FilledButton(onPressed: _busy ? null : () => _perform('delete', {
                        'revision': _revision, 'uuid': row['uuid'],
                      }), child: Text(tr('Confirmer la suppression', 'تأكيد الحذف'))),
                      TextButton(onPressed: _busy ? null : () => setState(() {
                        _confirmDelete = null;
                      }), child: Text(tr('Conserver', 'احتفاظ'))),
                    ]),
                  ],
                ]),
              )),
            ],
            if (_owner == null && _error) Text(tr('Saisie ou opération refusée.', 'تم رفض الإدخال أو العملية.')),
            if (_busy) const LinearProgressIndicator(),
          ]),
        ))),
      ),
    );
  }
}
