-- À exécuter dans Supabase : SQL Editor > New query > coller > Run.
-- Crée les tables du projet avec le Row-Level-Security (RLS) ACTIVÉ et
-- aucune policy pour anon/public : l'API REST publique de Supabase (celle
-- qui utilise la clé "anon", visible dans le code du navigateur) ne peut
-- donc rien lire ni écrire sur ces tables. Seul notre backend FastAPI, qui
-- utilise la clé secrète "service_role" (jamais envoyée au navigateur),
-- peut y accéder — et lui seul contourne le RLS.
--
-- IMPORTANT : ce fichier est censé refléter TOUT ce qui existe réellement
-- dans la base Supabase, pas juste ce qui a été créé la première fois.
-- Chaque fois qu'une nouvelle table, colonne ou contrainte est ajoutée
-- directement dans l'éditeur SQL de Supabase, le même bout de SQL doit être
-- copié ici et poussé sur GitHub — sinon ce fichier devient trompeur, et en
-- cas de pépin (nouveau projet Supabase, restauration...) il manquera des
-- bouts sans que ça se voie. Chaque instruction utilise "if not exists" ou
-- "on conflict do nothing", donc relancer tout ce fichier d'un coup (même
-- sur une base qui a déjà toutes ces tables) ne touche à rien d'existant —
-- c'est volontaire, pour que ce soit toujours sans risque de le refaire
-- tourner en entier plutôt que de devoir retrouver seulement le bout
-- manquant dans l'historique de l'éditeur SQL.

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
-- `receipt_path` : chemin du fichier dans le bucket Storage "receipts" (en
-- pratique, juste l'id de la transaction) ; NULL si aucune photo de reçu
-- n'est attachée. `receipt_content_type` garde le type MIME d'origine
-- (image/jpeg, image/png...) pour resservir l'image avec le bon en-tête.
create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  amount numeric(10, 2) not null,
  category text not null default 'autre',
  description text,
  expense_date date not null,
  recurring_expense_id uuid references recurring_expenses(id) on delete set null,
  occurrence_month date,
  receipt_path text,
  receipt_content_type text,
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

-- Budget mensuel par catégorie de dépense (un seul budget par catégorie,
-- reconduit automatiquement chaque mois — pas de notion de "mois" ici,
-- juste un plafond comparé chaque mois aux dépenses réelles de ce mois-là).
create table if not exists budgets (
  id uuid primary key default gen_random_uuid(),
  category text not null unique,
  amount numeric(10, 2) not null,
  created_at timestamptz not null default now()
);

alter table budgets enable row level security;

-- Objectif d'épargne mensuel : une seule ligne globale (pas par catégorie,
-- contrairement aux budgets). Comparé côté frontend au solde réel du mois
-- en cours (revenus - dépenses).
create table if not exists savings_goal (
  id uuid primary key default gen_random_uuid(),
  monthly_target numeric(10, 2) not null,
  created_at timestamptz not null default now()
);

alter table savings_goal enable row level security;

-- Anti-brute-force sur /api/login : une seule ligne globale (app
-- mono-utilisateur, pas besoin de suivre par IP). failed_count compte les
-- échecs d'affilée ; locked_until, quand renseigné, bloque toute nouvelle
-- tentative jusqu'à cette date. Remis à zéro dès qu'un mot de passe correct
-- est saisi (voir _record_login_result côté backend).
create table if not exists login_rate_limit (
  id uuid primary key default gen_random_uuid(),
  failed_count int not null default 0,
  locked_until timestamptz
);

alter table login_rate_limit enable row level security;

-- Bucket de stockage pour les photos de reçus, privé (public = false) :
-- comme pour les tables, aucune policy pour anon/public n'est créée, donc
-- seul le backend (clé service_role, qui contourne toujours le RLS/Storage)
-- peut y lire ou écrire. "on conflict do nothing" pour pouvoir relancer ce
-- script sans erreur si le bucket existe déjà.
insert into storage.buckets (id, name, public)
values ('receipts', 'receipts', false)
on conflict (id) do nothing;
