import 'package:flutter/material.dart';

/// D2 guest-only UI. No patient providers, database, API, storage, or AI calls.
/// These are genuine empty states, not a simulated patient or an audit profile.
/// Integration must mount this before any patient vault is constructed.
enum D2GuestSection { home, measurements, reports, profile }

String _copy(BuildContext context, String fr, String ar, String en) =>
    switch (Localizations.localeOf(context).languageCode) {
      'ar' => ar,
      'en' => en,
      _ => fr,
    };

class D2GuestShell extends StatefulWidget {
  final ValueChanged<String> onRequireIdentity;
  final D2GuestSection initialSection;

  const D2GuestShell({
    super.key,
    required this.onRequireIdentity,
    this.initialSection = D2GuestSection.home,
  });

  @override
  State<D2GuestShell> createState() => _D2GuestShellState();
}

class _D2GuestShellState extends State<D2GuestShell> {
  late D2GuestSection _section = widget.initialSection;

  @override
  Widget build(BuildContext context) {
    final labels = [
      _copy(context, 'Accueil', 'الرئيسية', 'Home'),
      _copy(context, 'Mesures', 'القياسات', 'Measurements'),
      _copy(context, 'Rapports', 'التقارير', 'Reports'),
      _copy(context, 'Profil', 'الملف الشخصي', 'Profile'),
    ];
    const icons = [Icons.home_outlined, Icons.show_chart, Icons.description_outlined, Icons.person_outline];
    final actions = switch (_section) {
      D2GuestSection.home => [
        ('/ajouter', _copy(context, 'Ajouter une mesure', 'إضافة قياس', 'Add a measurement')),
        ('/companion', _copy(context, 'Compagnon IA', 'المساعد الذكي', 'AI companion')),
        ('/notifications', _copy(context, 'Notifications', 'الإشعارات', 'Notifications')),
        ('/reminders', _copy(context, 'Rappels', 'التذكيرات', 'Reminders')),
      ],
      D2GuestSection.measurements => [
        ('/ajouter', _copy(context, 'Ajouter une mesure', 'إضافة قياس', 'Add a measurement')),
        ('/medications', _copy(context, 'Traitements', 'الأدوية', 'Medication')),
        ('/cgm', _copy(context, 'Capteurs', 'أجهزة الاستشعار', 'Sensors')),
      ],
      D2GuestSection.reports => [
        ('/summary', _copy(context, 'Voir mes rapports', 'عرض تقاريري', 'View my reports')),
        ('/importer', _copy(context, 'Importer un document', 'استيراد مستند', 'Import a document')),
      ],
      D2GuestSection.profile => [
        ('/profile', _copy(context, 'Accéder à mon profil', 'الوصول إلى ملفي', 'Access my profile')),
      ],
    };
    final selected = _section.index;
    void select(int index) => setState(() => _section = D2GuestSection.values[index]);
    final content = SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text(labels[selected], key: const Key('d2-guest-section'), style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 12),
          Text(_copy(context, 'Aucune donnée personnelle affichée.', 'لا تُعرض أي بيانات شخصية.', 'No personal data displayed.')),
          const SizedBox(height: 24),
          for (final action in actions)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: OutlinedButton(
                key: ValueKey('d2-guest-action:${action.$1}'),
                onPressed: () => widget.onRequireIdentity(action.$1),
                child: Text(action.$2),
              ),
            ),
        ],
      ),
    );
    final wide = MediaQuery.sizeOf(context).width >= 700;
    return Scaffold(
      appBar: AppBar(
        title: const Text('IAMINA'),
        actions: [
          TextButton(
            key: const Key('d2-guest-sign-in'),
            onPressed: () => widget.onRequireIdentity('/login'),
            child: Text(_copy(context, 'Se connecter', 'تسجيل الدخول', 'Sign in')),
          ),
        ],
      ),
      body: wide
          ? Row(children: [
              NavigationRail(
                selectedIndex: selected,
                onDestinationSelected: select,
                labelType: NavigationRailLabelType.all,
                destinations: [
                  for (var i = 0; i < labels.length; i++)
                    NavigationRailDestination(
                      icon: Icon(icons[i], key: ValueKey('d2-guest-nav-$i')),
                      label: Text(labels[i]),
                    ),
                ],
              ),
              Expanded(child: content),
            ])
          : content,
      bottomNavigationBar: wide ? null : NavigationBar(
        selectedIndex: selected,
        onDestinationSelected: select,
        destinations: [
          for (var i = 0; i < labels.length; i++)
            NavigationDestination(
              icon: Icon(icons[i], key: ValueKey('d2-guest-nav-$i')),
              label: labels[i],
            ),
        ],
      ),
    );
  }
}
