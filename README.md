# Suivi de dépenses vocal

Web app personnelle de suivi de dépenses, pilotée à la voix. Même
architecture que MatNot : FastAPI (fonction serverless Vercel) + Supabase
(Postgres) + une seule page HTML/CSS/JS embarquée en base64 dans
`api/index.py`.

## Structure

- `api/index.py` — toute l'API + le frontend embarqué (voir le commentaire
  en tête de fichier : pourquoi tout est dans un seul fichier).
- `frontend/index.html` — source du frontend. Éditer ce fichier, puis lancer
  `build.py` pour régénérer l'embarquement dans `api/index.py`.
- `build.py` — régénère l'embarquement base64 (exécuté par Claude, pas besoin
  de le lancer soi-même).
- `supabase/schema.sql` — schéma des tables à coller dans l'éditeur SQL de
  Supabase.
- `vercel.json` — config explicite `builds`/`routes` (le mode "framework
  auto-détecté" de Vercel cause des bugs de routing avec ce projet).

## Variables d'environnement (à définir sur Vercel)

| Variable | Description |
|---|---|
| `SUPABASE_URL` | URL du projet Supabase |
| `SUPABASE_SERVICE_ROLE_KEY` | Clé **service_role** (secrète) de Supabase — jamais la clé anon/public. Elle contourne le RLS et ne doit vivre que côté serveur (ici : en variable d'environnement Vercel) |
| `API_SECRET_KEY` | Clé simple envoyée en header `X-API-Key` par le frontend pour protéger les routes `/api/*` |

### Pourquoi service_role et pas anon

Les tables ont le RLS (Row Level Security) **activé**, sans aucune policy
pour `anon`/`public`. L'API REST publique que Supabase génère automatiquement
pour chaque table (accessible avec la clé anon, qui est de toute façon
visible dans le code envoyé au navigateur) ne peut donc rien lire ni écrire.
Seul notre backend FastAPI, qui utilise la clé `service_role` (secrète,
jamais exposée au client), peut accéder aux données — et c'est lui qui
applique la protection `X-API-Key`.

## État actuel : étape 1 — squelette + pipeline de déploiement

Deux endpoints de test :
- `GET /api/health` — public, confirme que Vercel + FastAPI répondent.
- `GET /api/db-check` — protégé par `X-API-Key`, confirme que Supabase est
  bien configuré et que la table `expenses` est lisible.

Les fonctionnalités (dictée vocale, dashboard, dépenses récurrentes, export
Excel…) arrivent aux étapes suivantes.
