# IAMINA — snapshot de reprise (23/11/2026)

Ce dépôt de reprise a été reconstitué à partir de l’archive **v2 vérifiée** provenant du Lenovo.
Ce n’est PAS le HEAD de l’ancien dépôt original ; il s’agit d’un **nouveau commit racine** créé sans l’historique Git ancien.

- Original : `hraaaaf/IAMINA-MVP` (accès suspendu sur le compte source)
- SHA source d'origine rapporté : `36828afbe30333170ca417fa606084125d880bb5` (HEAD détaché, arbre propre)
- ZIP source : `c1f9b015c2008ce937dcb529d834e0c76a8fd8f5f06f304f790e853427beb79b` (SHA-256)
- Snapshot contient le code Flutter (`frontend/`) et Django (`backend/`), migrations, tests et docs ; fichiers locaux/env/bases de données et certaines fixtures exclus dans l'archive v2 source.
- Les **96 workflows** `.github/workflows/*` ont été déplacés, contenu octet pour octet, sous `ci-disabled/github-workflows/` afin qu'aucun job CI ne s'exécute au premier push, même si Actions est activé dans GitHub.
- Réactiver les workflows uniquement après revue CI/secret/deploy, **et** après avoir désactivé tout déploiement Vercel non explicitement approuvé.
- Les clés API Firebase intégrées à `frontend/lib/firebase_options.dart` sont des identifiants de configuration client ; vérifier restrictions/quotas avant publication ou lancement.
- La revue statique de secrets reste indicative ; pas de certification exhaustive de l'absence de secrets.
- **Dépôt privé exclusivement** et aucun déclenchement Vercel (preview compris).

## Publication (dans environnement sûr et authentifié)

1. Créer un dépôt **privé vide** sur le compte `lafabriquedapollon-cpu`, par exemple `IAMINA-MVP`, sans README.
2. Dans `Settings > Actions > General`, désactiver GitHub Actions avant tout push.
3. Vérifier avec `gh auth status` (ne jamais imprimer le token) que l'acteur est exactement `lafabriquedapollon-cpu`.
4. Cloner ce fichier `.bundle` localement, renommer `origin` en `snapshot-source` si nécessaire, ajouter le remote privé en `origin`, puis pousser **uniquement `main`**.
5. Relire `git ls-remote origin refs/heads/main` et comparer au commit local ; vérifier visibilité **private**, Actions désactivées, aucun déploiement Vercel lancé.
6. Créer ensuite la branche de développement **après** le baseline, jamais sur le dépôt Lenovo original.

**NE PAS inclure d'URI Neon, mots de passe, secrets, patients ou clés privées.**
