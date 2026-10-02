-- À exécuter dans Supabase : SQL Editor > New query > coller > Run.
-- Crée les tables du projet avec le Row-Level-Security (RLS) ACTIVÉ et
-- aucune policy pour anon/public : l'API REST publique de Supabase (celle
-- qui utilise la clé "anon", visible dans le code du navigateur) ne peut
-- donc rien lire ni écrire sur ces tables. Seul notre backend FastAPI, qui
-- utilise la clé secrète "service_role" (jamais envoyée au navigateur),
-- peut y accéder — et lui seul contourne le RLS.

-- Dépenses récurrentes (charges fixes mensuelles, dépenses ET revenus,
-- distingués par `type`). Créée avant `transactions` ci-dessous car cette
-- dernière la référence par clé étrangère.
create table if not exists recurring_expenses (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  name text not null,
  amount numeric(10, 2) not null,
  category text not null default 'autre',
  day_of_month integer check (day_of_month between 1 and 31),
  active boolean not null default true,
  start_date date,
  end_date date,
  created_at timestamptz not null default now()
);

alter table recurring_expenses enable row level security;

-- Transactions ponctuelles (dépenses ET revenus, distingués par `type`).
-- `recurring_expense_id` + `occurrence_month` ne sont remplis que pour les
-- transactions créées automatiquement à partir d'une charge récurrente (par
-- sync_recurring_occurrences côté backend) : ça les rattache à la charge
-- d'origine et empêche de créer deux fois la même occurrence pour un même
-- mois. Pour une transaction saisie à la main ou par la voix, ces deux
-- colonnes restent NULL.
create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  amount numeric(10, 2) not null,
  category text not null default 'autre',
  description text,
  expense_date date not null,
  recurring_expense_id uuid references recurring_expenses(id) on delete set null,
  occurrence_month date,
  created_at timestamptz not null default now()
);

-- Une même charge récurrente ne doit créer qu'une seule transaction par
-- mois. (NULL ne viole jamais une contrainte unique en Postgres, donc les
-- transactions manuelles, où ces deux colonnes sont NULL, ne sont pas
-- concernées par cette règle.)
create unique index if not exists transactions_recurring_occurrence_unique
  on transactions (recurring_expense_id, occurrence_month);

alter table transactions enable row level security;

-- Catégories créées par l'utilisateur depuis le bandeau de suggestion (une
-- description qui revient souvent sans catégorie dédiée). En base (et pas
-- juste dans le navigateur) pour suivre sur tous les appareils (téléphone,
-- tablette, ordinateur).
create table if not exists custom_categories (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  value text not null,
  label text not null,
  created_at timestamptz not null default now(),
  unique (type, value)
);

alter table custom_categories enable row level security;

-- Suggestions de catégorie ignorées ("Ignorer" dans le bandeau), pour ne
-- pas re-proposer la même chose à chaque fois — en base pour suivre sur
-- tous les appareils, comme les catégories personnalisées ci-dessus.
create table if not exists dismissed_category_suggestions (
  id uuid primary key default gen_random_uuid(),
  suggestion_key text not null unique,
  created_at timestamptz not null default now()
);

alter table dismissed_category_suggestions enable row level security;
