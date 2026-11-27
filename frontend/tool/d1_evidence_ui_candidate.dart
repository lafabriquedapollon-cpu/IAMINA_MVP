// CONV-02c.2: isolated synthetic qualification UI, never imported by lib/main.dart.
import 'package:flutter/material.dart';
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

final class EvidenceUiResult {
  final EvidenceUiBinding binding;
  final int generation, requestId, revision;
  final List<Map<String, dynamic>> rows;
  EvidenceUiResult._(this.binding, this.generation, this.requestId, this.revision, this.rows);
  factory EvidenceUiResult.fromJson(Map<String, dynamic> raw) {
    final rows = (raw['rows'] as List).map((r) =>
        Map<String, dynamic>.unmodifiable(Map<String, dynamic>.from(r as Map))).toList();
    final seen = <String>{};
    for (final row in rows) {
      final uuid = row['uuid'], value = row['originalValue'];
      if (uuid is! String ||
          !RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$').hasMatch(uuid) ||
          !seen.add(uuid) || value is! num || !value.isFinite || value <= 0 ||
          !['mg/dL', 'mmol/L'].contains(row['originalUnit']) ||
          row['displayMgDl'] is! String || row['displayMmolL'] is! String) {
        throw StateError('Invalid UI row');
      }
    }
    if (rows.length > 50) throw StateError('Fixture capacity exceeded');
    return EvidenceUiResult._(
      EvidenceUiBinding.fromJson(Map<String, dynamic>.from(raw['binding'] as Map)),
      raw['generation'] as int, raw['requestId'] as int, raw['revision'] as int,
      List.unmodifiable(rows));
  }
}

class EvidenceUiCandidate extends StatefulWidget {
  const EvidenceUiCandidate({super.key, required this.call,
    required this.revoke, required this.lock, required this.arabic, required this.isCurrent});
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
  final _valueFocus = FocusNode();
  int _generation = 0, _requestSequence = 0;
  EvidenceUiBinding? _binding;
  int? get _owner => _binding?.owner;
  int? _revision;
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
    _valueFocus.unfocus();
    _value.clear();
    if (mounted) {
      setState(() {
        _binding = null; _revision = null; _unit = null; _editing = null; _confirmDelete = null;
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
    final previous = _binding;
    final opening = action == 'open';
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
      });
      if (!mounted || generation != _generation) return;
      final response = EvidenceUiResult.fromJson(result);
      final binding = response.binding;
      if (!binding.valid || binding.owner != owner || binding.session != session ||
          response.generation != generation || response.requestId != requestId ||
          (previous != null && !previous.matches(binding)) ||
          !widget.isCurrent(binding) || response.revision <= 0 ||
          (!opening && response.revision != _revision! + 1)) {
        throw StateError('UI response binding refused');
      }
      setState(() {
        _binding = binding;
        _revision = response.revision;
        _rows = response.rows;
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
    _valueFocus.dispose();
    _value.dispose();
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
              Text(_owner == 900001 ? tr('Profil A', 'الملف A') : tr('Profil B', 'الملف B')),
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
              for (final row in _rows) Card(semanticContainer: false, child: Padding(padding: const EdgeInsets.all(12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('${row['originalValue']} ${row['originalUnit']}',
                    textDirection: TextDirection.ltr,
                    style: Theme.of(context).textTheme.titleMedium),
                  Text('${row['displayMgDl']} mg/dL · ${row['displayMmolL']} mmol/L',
                    textDirection: TextDirection.ltr),
                  Wrap(children: [
                    TextButton(onPressed: _busy ? null : () {
                      setState(() {
                        _confirmDelete = null; _editing = row['uuid'] as String; _unit = row['originalUnit'] as String;
                        _value.text = row['originalValue'].toString();
                      });
                      _valueFocus.requestFocus();
                    }, child: Text(tr('Modifier', 'تعديل'))),
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
