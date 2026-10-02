-- À exécuter dans Supabase : SQL Editor > New query > coller > Run.
-- Crée les tables du projet avec le Row-Level-Security (RLS) ACTIVÉ et
-- aucune policy pour anon/public : l'API REST publique de Supabase (celle
-- qui utilise la clé "anon", visible dans le code du navigateur) ne peut
-- donc rien lire ni écrire sur ces tables. Seul notre backend FastAPI, qui
-- utilise la clé secrète "service_role" (jamais envoyée au navigateur),
-- peut y accéder — et lui seul contourne le RLS.

-- Transactions ponctuelles (dépenses ET revenus, distingués par `type`)
create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  amount numeric(10, 2) not null,
  category text not null default 'autre',
  description text,
  expense_date date not null,
  created_at timestamptz not null default now()
);

alter table transactions enable row level security;

-- Dépenses récurrentes (charges fixes mensuelles) — utilisée à partir de
-- l'étape "Dépenses récurrentes" du projet, mais créée maintenant pour ne
-- pas avoir à revenir ici plus tard. Toujours des dépenses (pas de revenus
-- récurrents prévus pour l'instant), donc pas de colonne `type` ici.
create table if not exists recurring_expenses (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  amount numeric(10, 2) not null,
  category text not null default 'autre',
  day_of_month integer check (day_of_month between 1 and 31),
  active boolean not null default true,
  end_date date,
  created_at timestamptz not null default now()
);

alter table recurring_expenses enable row level security;
