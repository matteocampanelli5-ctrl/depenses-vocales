# Kaching — suivi financier personnel

Web app de suivi financier pour un usage personnel et familial (sur
invitation uniquement) : dépenses et revenus dictés à la voix, comptes
bancaires, livrets et placements, prêts, et analyses sur plusieurs mois.
FastAPI (fonction serverless Vercel) + Supabase (Postgres) + une page
HTML/CSS/JS unique, embarquée dans le backend.

## Fonctionnalités

- **Saisie vocale** : « j'ai dépensé 12 euros au resto hier » → montant,
  catégorie et date extraits par l'IA (API Anthropic). Une dépense qui
  revient souvent dans « Autre » fait proposer une nouvelle catégorie.
- **Comptes et virements** : chaque opération peut être rattachée à son
  compte ; un virement entre deux comptes de l'utilisateur (ex : vers le
  Livret A) n'est compté ni en dépense ni en revenu.
- **Patrimoine** : livrets et placements (Livret A, Bricks, PEA…) dont le
  solde est calculé à partir des virements puis corrigé par le vrai solde
  quand l'utilisateur le saisit ; patrimoine net (comptes − prêts) et
  historique de patrimoine.
- **Prêts** : immobilier ou autre crédit, amortissement recalculé à partir
  de 4 valeurs, loyer perçu pour un bien loué.
- **Tableau de bord** : camemberts, évolution mensuelle, comparaison de deux
  mois, analyse sur 3, 6 et 12 mois (moyennes, taux d'épargne, mois en cours
  comparé à la moyenne), budgets par catégorie, bilan annuel.
- **Import** : relevés CSV, Excel (.xlsx, .xlsm) ou PDF de n'importe quelle
  banque, lus par l'IA avec validation ligne par ligne ; classeur Excel non
  standard importé onglet par onglet (opérations du mois, tableaux
  d'amortissement, historique d'endettement).
- **Export** : Excel avec graphiques, ou sauvegarde JSON complète.

## Structure

- `api/index.py` — point d'entrée Vercel : assemble les routeurs et pose les
  en-têtes de sécurité (CSP, HSTS…).
- `app/` — le backend, un module par responsabilité (`config`, `db`,
  `security`, `models`, `voice_nlp`, `workbook_parsing`…) et un routeur par
  domaine dans `app/routers/` (comptes, opérations, prêts, imports…).
- `frontend/index.html` — source du frontend. Après modification, lancer
  `build.py`, qui l'embarque (avec les icônes et Chart.js, auto-hébergé
  dans `frontend/vendor/`) dans `app/frontend_assets.py`.
- `supabase/schema.sql` — schéma complet ; `supabase/migration_*.sql` —
  migrations à exécuter une fois sur une base existante.
- `vercel.json` — configuration explicite `builds`/`routes`.

## Mettre à jour une installation existante

Toujours dans cet ordre : d'abord exécuter la ou les nouvelles migrations
(`supabase/migration_*.sql`) dans l'éditeur SQL de Supabase, puis déployer le
code. Le nouveau code s'appuie sur les tables et colonnes que la migration
ajoute : déployé avant elle, une partie de l'app répondrait en erreur.

## Variables d'environnement (à définir sur Vercel, jamais dans le code)

| Variable | Rôle |
|---|---|
| `SUPABASE_URL` | URL du projet Supabase |
| `SUPABASE_SERVICE_ROLE_KEY` | Clé service_role (secrète), utilisée uniquement côté serveur |
| `API_SECRET_KEY` | Clé de signature des jetons de session |
| `ANTHROPIC_API_KEY` | Clé de l'API Anthropic (saisie vocale, import par IA) |
| `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | Envoi des emails (invitations, mot de passe oublié) — facultatif |
| `APP_PUBLIC_URL` | URL publique de l'app, pour les liens envoyés par email |
| `ADMIN_ALERT_EMAIL` | Adresse qui reçoit les alertes techniques — facultatif |

## Sécurité

- Toutes les tables ont le RLS activé **sans aucune policy** : l'API REST
  publique de Supabase ne peut rien lire ni écrire. Seul le backend, avec la
  clé service_role, accède aux données, et chaque requête est limitée aux
  lignes de l'utilisateur connecté.
- Comptes sur invitation uniquement ; mots de passe hachés (PBKDF2-SHA256,
  310 000 itérations) ; jetons de session signés et révocables ;
  verrouillage après plusieurs échecs de connexion.
- Un fichier importé n'est jamais conservé : il est analysé pour la requête,
  puis seules les lignes validées par l'utilisateur sont enregistrées.
