// CONV-02c.2: isolated synthetic qualification UI, never imported by lib/main.dart.
import 'package:flutter/material.dart';

typedef EvidenceUiCall = Future<Map<String, dynamic>> Function(
    String action, Map<String, Object?> args);

class EvidenceUiCandidate extends StatefulWidget {
  const EvidenceUiCandidate({super.key, required this.call,
    required this.revoke, required this.lock, required this.arabic});
  final EvidenceUiCall call;
  final ValueNotifier<int> revoke;
  final VoidCallback lock;
  final bool arabic;

  @override
  State<EvidenceUiCandidate> createState() => _EvidenceUiCandidateState();
}

class _EvidenceUiCandidateState extends State<EvidenceUiCandidate> {
  final _value = TextEditingController();
  int _generation = 0;
  int? _owner, _revision;
  String? _unit, _editing, _confirmDelete;
  bool _busy = false, _error = false;
  List<Map<String, dynamic>> _rows = [];
  String tr(String fr, String ar) => widget.arabic ? ar : fr;

  @override
  void initState() {
    super.initState();
    widget.revoke.addListener(_clear);
  }

  void _clear() {
    _generation++;
    _value.clear();
    if (mounted) {
      setState(() {
        _owner = null; _revision = null; _unit = null; _editing = null; _confirmDelete = null;
        _rows = []; _busy = false; _error = false;
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
    setState(() { _busy = true; _error = false; });
    try {
      final result = await widget.call(action, args);
      if (!mounted || generation != _generation) return;
      final rows = (result['rows'] as List).map((r) =>
          Map<String, dynamic>.from(r as Map)).toList(growable: false);
      setState(() {
        _owner = result['owner'] as int;
        _revision = result['revision'] as int;
        _rows = rows;
        _busy = false;
        _value.clear(); _unit = null; _editing = null; _confirmDelete = null;
      });
    } catch (_) {
      if (!mounted || generation != _generation) return;
      _lock();
      if (mounted) setState(() => _error = true);
    }
  }

  void _save() {
    final raw = _value.text.trim().replaceAll(',', '.');
    final value = double.tryParse(raw);
    if (_unit == null || value == null || !value.isFinite || value <= 0) {
      setState(() => _error = true);
      return;
    }
    _perform(_editing == null ? 'insert' : 'edit', {
      'revision': _revision, 'uuid': _editing, 'value': value, 'unit': _unit,
    });
  }

  @override
  void dispose() {
    widget.revoke.removeListener(_clear);
    _generation++;
    _value.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
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
              Text(_owner == 900001 ? tr('Profil A', 'الملف A') : tr('Profil B', 'الملف B')),
              const SizedBox(height: 12),
              Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(_editing == null ? tr('Ajouter une mesure', 'إضافة قياس') : tr('Modifier la mesure', 'تعديل القياس'),
                    style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 12),
                  Semantics(identifier: 'evidence-value', child: TextField(
                    key: const Key('evidence-value'), controller: _value, enabled: !_busy,
                    keyboardType: const TextInputType.numberWithOptions(decimal: true),
                    decoration: InputDecoration(labelText: tr('Valeur glycémique', 'قيمة السكر'),
                      border: const OutlineInputBorder()))),
                  const SizedBox(height: 12),
                  Text(tr('Unité de saisie (obligatoire)', 'وحدة الإدخال (إلزامية)')),
                  Wrap(spacing: 8, children: [
                    for (final unit in ['mg/dL','mmol/L'])
                      Semantics(identifier: unit == 'mg/dL' ? 'evidence-mgdl' : 'evidence-mmoll',
                        child: ChoiceChip(key: ValueKey(unit), label: Text(unit), selected: _unit == unit,
                          onSelected: _busy ? null : (selected) => setState(() {
                            _unit = selected ? unit : null; _error = false;
                          }))),
                  ]),
                  const SizedBox(height: 12),
                  Semantics(identifier: 'evidence-save', child: FilledButton(
                    key: const Key('evidence-save'), onPressed: _busy ? null : _save,
                    child: Text(tr('Enregistrer', 'حفظ')))),
                  if (_error) Semantics(identifier: 'evidence-input-error', liveRegion: true,
                    child: Text(tr('Saisie ou opération refusée.', 'تم رفض الإدخال أو العملية.'))),
                  if (_editing != null) TextButton(onPressed: _busy ? null : () => setState(() {
                    _editing = null; _unit = null; _value.clear();
                  }), child: Text(tr('Annuler', 'إلغاء'))),
                ],
              ))),
              const SizedBox(height: 16),
              Text(tr('Mesures enregistrées', 'القياسات المسجلة'),
                style: Theme.of(context).textTheme.titleLarge),
              if (_rows.isEmpty) Text(tr('Aucune mesure explicite', 'لا توجد قياسات صريحة')),
              for (final row in _rows) Card(child: Padding(padding: const EdgeInsets.all(12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('${row['originalValue']} ${row['originalUnit']}',
                    textDirection: TextDirection.ltr,
                    style: Theme.of(context).textTheme.titleMedium),
                  Text('${row['displayMgDl']} mg/dL · ${row['displayMmolL']} mmol/L',
                    textDirection: TextDirection.ltr),
                  Wrap(children: [
                    TextButton(onPressed: _busy ? null : () => setState(() {
                      _confirmDelete = null; _editing = row['uuid'] as String; _unit = row['originalUnit'] as String;
                      _value.text = row['originalValue'].toString();
                    }), child: Text(tr('Modifier', 'تعديل'))),
                    TextButton(onPressed: _busy ? null : () => setState(() {
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
