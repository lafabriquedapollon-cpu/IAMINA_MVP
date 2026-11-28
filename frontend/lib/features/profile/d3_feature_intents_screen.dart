import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

typedef D3ReadIntents = Future<Map<String, dynamic>> Function(String locale);
typedef D3WriteIntent = Future<void> Function(String feature, Map<String, dynamic> body);

/// Isolated preference candidate. Transport must be supplied by the eventual
/// authenticated, unlocked account host; this screen never authorizes AI.
/// A scope change hides all old data synchronously and discards late responses.
class D3FeatureIntentsScreen extends StatefulWidget {
  final D3ReadIntents read;
  final D3WriteIntent write;
  final ValueListenable<int> scopeEpoch;

  const D3FeatureIntentsScreen({
    super.key, required this.read, required this.write, required this.scopeEpoch,
  });

  @override
  State<D3FeatureIntentsScreen> createState() => _D3FeatureIntentsScreenState();
}

class _D3FeatureIntentsScreenState extends State<D3FeatureIntentsScreen> {
  static const _features = ['photo', 'companion', 'habits'];
  Map<String, dynamic>? _snapshot;
  int _generation = 0;
  bool _busy = false;
  bool _confirming = false;
  bool _error = false;
  bool _retired = false;
  String? _locale;

  String _t(String fr, String ar, String en) => switch (_locale) {
    'ar' => ar, 'en' => en, _ => fr,
  };

  String _label(String feature) => switch (feature) {
    'photo' => _t('Photo IA', 'تحليل الصور بالذكاء الاصطناعي', 'Photo AI'),
    'companion' => _t('Compagnon IA', 'المساعد الذكي', 'AI companion'),
    _ => _t('Apprentissage de mes habitudes', 'تعلم عاداتي', 'Learning my habits'),
  };

  @override
  void initState() {
    super.initState();
    widget.scopeEpoch.addListener(_scopeChanged);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final language = Localizations.localeOf(context).languageCode;
    final next = ['fr', 'ar', 'en'].contains(language) ? language : 'fr';
    if (_locale != next) {
      _locale = next;
      if (!_retired) _invalidateAndRead();
    }
  }

  @override
  void didUpdateWidget(covariant D3FeatureIntentsScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.scopeEpoch != widget.scopeEpoch) {
      oldWidget.scopeEpoch.removeListener(_scopeChanged);
      widget.scopeEpoch.addListener(_scopeChanged);
      _scopeChanged();
    }
  }

  void _scopeChanged() {
    setState(() {
      _retired = true;
      _generation++;
      _snapshot = null;
      _busy = false;
      _confirming = false;
      _error = true;
    });
    // Terminal retirement for this State, including subsequent locale changes.
    // A fresh authorized host must mount a new keyed screen.
  }

  void _invalidateAndRead() {
    if (_retired) return;
    _generation++;
    _snapshot = null;
    _busy = false;
    _confirming = false;
    _error = false;
    unawaited(_load());
  }

  Map<String, dynamic> _validate(Map<String, dynamic> raw, String locale) {
    final features = raw['features'];
    final notices = raw['notices'];
    final receipt = raw['global_receipt_id'];
    if (features is! List || features.length != 3 || notices is! Map ||
        notices.length != 3 || (receipt != null && (receipt is! int || receipt <= 0))) {
      throw const FormatException('Invalid preference envelope');
    }
    final seen = <String>{};
    for (final item in features) {
      if (item is! Map || !_features.contains(item['feature']) ||
          !seen.add(item['feature'] as String) ||
          item['intent_enabled'] is! bool ||
          item['revision'] is! int || (item['revision'] as int) < 0 ||
          item['activation_available'] != false ||
          item['external_ai_authorized'] != false ||
          (receipt == null && item['intent_enabled'] == true)) {
        throw const FormatException('Invalid preference state');
      }
      final notice = notices[item['feature']];
      if (notice is! Map || notice['locale'] != locale ||
          notice['version'] is! String || notice['text'] is! String ||
          (notice['text'] as String).isEmpty || notice['hash'] is! String ||
          !RegExp(r'^[0-9a-f]{64}$').hasMatch(notice['hash'] as String)) {
        throw const FormatException('Invalid notice');
      }
    }
    return raw;
  }

  Future<void> _load() async {
    if (_retired) return;
    final generation = _generation;
    final epoch = widget.scopeEpoch.value;
    final locale = _locale!;
    setState(() { _busy = true; _error = false; });
    try {
      final value = _validate(await widget.read(locale), locale);
      if (!mounted || generation != _generation || epoch != widget.scopeEpoch.value) return;
      setState(() { _snapshot = value; _busy = false; });
    } catch (_) {
      if (!mounted || generation != _generation || epoch != widget.scopeEpoch.value) return;
      setState(() { _snapshot = null; _busy = false; _error = true; });
    }
  }

  Future<void> _change(Map item, bool enabled) async {
    final snapshot = _snapshot;
    if (_retired || _busy || _confirming || snapshot == null) return;
    final generation = _generation;
    final epoch = widget.scopeEpoch.value;
    final feature = item['feature'] as String;
    final receipt = snapshot['global_receipt_id'];
    final notice = Map<String, dynamic>.from((snapshot['notices'] as Map)[feature] as Map);
    if (enabled) {
      if (receipt == null) return;
      setState(() => _confirming = true);
      final accepted = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => AlertDialog(
          title: Text(_label(feature)),
          content: SingleChildScrollView(child: Text(notice['text'] as String)),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(_t('Annuler', 'إلغاء', 'Cancel'))),
            FilledButton(
              key: const Key('d3-confirm'),
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(_t('Confirmer ma préférence', 'تأكيد تفضيلي', 'Confirm preference')),
            ),
          ],
        ),
      );
      if (!mounted || generation != _generation || epoch != widget.scopeEpoch.value) return;
      if (accepted != true) {
        setState(() => _confirming = false);
        return;
      }
    }
    setState(() { _confirming = false; _busy = true; _error = false; _snapshot = null; });
    try {
      await widget.write(feature, {
        'enabled': enabled,
        'expected_revision': item['revision'],
        if (enabled) 'expected_global_receipt_id': receipt,
        if (enabled) 'notice': notice,
      });
      if (!mounted || generation != _generation || epoch != widget.scopeEpoch.value) return;
      await _load();
    } catch (_) {
      if (!mounted || generation != _generation || epoch != widget.scopeEpoch.value) return;
      setState(() { _busy = false; _snapshot = null; _error = true; });
    }
  }

  @override
  void dispose() {
    widget.scopeEpoch.removeListener(_scopeChanged);
    _generation++;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final snapshot = _snapshot;
    return Scaffold(
      appBar: AppBar(title: Text(_t('Préférences IA', 'تفضيلات الذكاء الاصطناعي', 'AI preferences'))),
      body: SafeArea(child: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Text(_t('Ces préférences ne déclenchent aucun traitement IA.', 'هذه التفضيلات لا تُفعّل أي معالجة بالذكاء الاصطناعي.', 'These preferences do not activate any AI processing.')),
          if (_busy) const LinearProgressIndicator(),
          if (_error) Text(_t('État non confirmé. Revenez à votre session sécurisée.', 'الحالة غير مؤكدة. عد إلى جلستك الآمنة.', 'Status not confirmed. Return to your secure session.'), key: const Key('d3-unknown')),
          if (snapshot != null)
            for (final item in snapshot['features'] as List)
              SwitchListTile(
                key: ValueKey('d3-${item['feature']}'),
                title: Text(_label(item['feature'] as String)),
                value: item['intent_enabled'] as bool,
                onChanged: _busy || _confirming || (snapshot['global_receipt_id'] == null && item['intent_enabled'] != true)
                    ? null : (enabled) => unawaited(_change(item as Map, enabled)),
              ),
        ],
      )),
    );
  }
}
