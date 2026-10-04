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
--
-- MULTI-PROFIL : l'app est passée d'un seul mot de passe partagé à de vrais
-- comptes (un par personne). `app_users` est la nouvelle table de comptes ;
-- toutes les tables de données (transactions, budgets, etc.) ont désormais
-- une colonne `user_id` qui rattache chaque ligne à son propriétaire. Le
-- backend filtre TOUJOURS ses requêtes par user_id (voir api/index.py,
-- require_user) — le RLS ci-dessus ne fait pas ce travail à notre place
-- puisque la clé service_role le contourne systématiquement, donc
-- l'isolation entre comptes vient entièrement du code, pas de Postgres.

-- Nécessaire pour gen_random_bytes() (utilisé plus bas pour security_stamp).
-- Généralement déjà activée par défaut sur Supabase, mais sans danger à
-- relancer si c'est déjà le cas.
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Comptes utilisateurs
-- ---------------------------------------------------------------------------
-- Le tout premier compte créé (is_admin = true automatiquement côté backend,
-- voir /api/auth/signup) peut générer des liens d'invitation pour les
-- suivants — l'inscription est donc fermée par défaut (cercle fermé), pas
-- ouverte à n'importe qui qui tomberait sur l'URL de l'app.
create table if not exists app_users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  username text not null unique,
  password_hash text not null,
  is_admin boolean not null default false,
  email_verified boolean not null default false,
  -- Chaîne aléatoire embarquée dans chaque jeton de session émis pour ce
  -- compte (voir _create_session_token / require_user côté backend) : la
  -- changer (ce que fait /api/auth/reset-password) invalide d'un coup tous
  -- les jetons déjà émis, sans avoir à tenir de liste de jetons révoqués.
  security_stamp text not null default encode(gen_random_bytes(32), 'hex'),
  created_at timestamptz not null default now()
);

alter table app_users enable row level security;

-- Pour une base déjà créée avant l'ajout de security_stamp ci-dessus
-- (relancer ce fichier ne recrée pas la table si elle existe déjà).
alter table app_users add column if not exists security_stamp text not null default encode(gen_random_bytes(32), 'hex');

-- Jetons d'invitation (cercle fermé) : un lien généré par un admin, valable
-- 7 jours, à usage unique, optionnellement réservé à une adresse email
-- précise (`email`). Le jeton lui-même est stocké tel quel (pas haché,
-- contrairement aux jetons de reset/vérification ci-dessous) : il n'a de
-- valeur qu'avant d'être utilisé, et le flux ressemble à un simple code
-- d'invitation partagé par le parrain, pas à une preuve d'identité.
create table if not exists invite_tokens (
  id uuid primary key default gen_random_uuid(),
  token text not null unique,
  created_by uuid references app_users(id) on delete set null,
  email text,
  expires_at timestamptz not null,
  used_by uuid references app_users(id) on delete set null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table invite_tokens enable row level security;

-- Jetons de réinitialisation de mot de passe ("mot de passe oublié"), à
-- usage unique et de courte durée de vie.
create table if not exists password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table password_reset_tokens enable row level security;

-- Jetons de vérification d'adresse email, envoyés à l'inscription.
create table if not exists email_verification_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table email_verification_tokens enable row level security;

-- Anti-brute-force sur /api/auth/login : une ligne par adresse email (et non
-- plus une seule ligne globale pour toute l'app), pour qu'un verrouillage
-- après échecs répétés ne bloque qu'UN compte, pas tout le monde. Remplace
-- l'ancienne table login_rate_limit (supprimée plus bas).
create table if not exists login_attempts (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  failed_count int not null default 0,
  locked_until timestamptz
);

alter table login_attempts enable row level security;

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

-- Multi-profil : chaque charge récurrente appartient à un compte. Colonne
-- nullable pour l'instant (voir /api/admin/claim-orphan-data, qui rattache
-- les lignes existantes — créées avant le multi-profil — au premier compte
-- admin une fois qu'il s'inscrit).
alter table recurring_expenses add column if not exists user_id uuid references app_users(id) on delete cascade;
create index if not exists recurring_expenses_user_id_idx on recurring_expenses (user_id);

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

-- Multi-profil : chaque transaction appartient à un compte.
alter table transactions add column if not exists user_id uuid references app_users(id) on delete cascade;
create index if not exists transactions_user_id_idx on transactions (user_id);

-- Catégories créées par l'utilisateur depuis le bandeau de suggestion (une
-- description qui revient souvent sans catégorie dédiée). En base (et pas
-- juste dans le navigateur) pour suivre sur tous les appareils (téléphone,
-- tablette, ordinateur).
create table if not exists custom_categories (
  id uuid primary key default gen_random_uuid(),
  type text not null default 'expense' check (type in ('expense', 'income')),
  value text not null,
  label text not null,
  created_at timestamptz not null default now()
);

alter table custom_categories enable row level security;

-- Multi-profil : une même catégorie perso (type+valeur) peut exister pour
-- chaque compte indépendamment — la contrainte d'unicité passe donc de
-- globale (type, value) à (user_id, type, value).
alter table custom_categories add column if not exists user_id uuid references app_users(id) on delete cascade;
create index if not exists custom_categories_user_id_idx on custom_categories (user_id);
alter table custom_categories drop constraint if exists custom_categories_type_value_key;
drop index if exists custom_categories_type_value_key;
create unique index if not exists custom_categories_user_type_value_unique
  on custom_categories (user_id, type, value);

-- Suggestions de catégorie ignorées ("Ignorer" dans le bandeau), pour ne
-- pas re-proposer la même chose à chaque fois — en base pour suivre sur
-- tous les appareils, comme les catégories personnalisées ci-dessus.
create table if not exists dismissed_category_suggestions (
  id uuid primary key default gen_random_uuid(),
  suggestion_key text not null,
  created_at timestamptz not null default now()
);

alter table dismissed_category_suggestions enable row level security;

-- Multi-profil : la clé de suggestion ignorée est désormais unique par
-- compte, pas globalement.
alter table dismissed_category_suggestions add column if not exists user_id uuid references app_users(id) on delete cascade;
create index if not exists dismissed_suggestions_user_id_idx on dismissed_category_suggestions (user_id);
alter table dismissed_category_suggestions drop constraint if exists dismissed_category_suggestions_suggestion_key_key;
drop index if exists dismissed_category_suggestions_suggestion_key_key;
create unique index if not exists dismissed_suggestions_user_key_unique
  on dismissed_category_suggestions (user_id, suggestion_key);

-- Budget mensuel par catégorie de dépense (un seul budget par catégorie,
-- reconduit automatiquement chaque mois — pas de notion de "mois" ici,
-- juste un plafond comparé chaque mois aux dépenses réelles de ce mois-là).
create table if not exists budgets (
  id uuid primary key default gen_random_uuid(),
  category text not null,
  amount numeric(10, 2) not null,
  created_at timestamptz not null default now()
);

alter table budgets enable row level security;

-- Multi-profil : un budget par catégorie ET par compte (chacun a ses
-- propres plafonds), donc la contrainte unique passe de (category) à
-- (user_id, category).
alter table budgets add column if not exists user_id uuid references app_users(id) on delete cascade;
create index if not exists budgets_user_id_idx on budgets (user_id);
alter table budgets drop constraint if exists budgets_category_key;
drop index if exists budgets_category_key;
create unique index if not exists budgets_user_category_unique
  on budgets (user_id, category);

-- Objectif d'épargne mensuel : une seule ligne PAR COMPTE désormais (avant
-- le multi-profil, une seule ligne globale pour toute l'app). Comparé côté
-- frontend au solde réel du mois en cours (revenus - dépenses).
create table if not exists savings_goal (
  id uuid primary key default gen_random_uuid(),
  monthly_target numeric(10, 2) not null,
  created_at timestamptz not null default now()
);

alter table savings_goal enable row level security;

alter table savings_goal add column if not exists user_id uuid references app_users(id) on delete cascade;
create unique index if not exists savings_goal_user_id_unique on savings_goal (user_id);

-- Ancienne table d'anti-brute-force mono-utilisateur, remplacée par
-- login_attempts (ci-dessus), qui suit chaque compte séparément.
drop table if exists login_rate_limit;

-- Bucket de stockage pour les photos de reçus, privé (public = false) :
-- comme pour les tables, aucune policy pour anon/public n'est créée, donc
-- seul le backend (clé service_role, qui contourne toujours le RLS/Storage)
-- peut y lire ou écrire. "on conflict do nothing" pour pouvoir relancer ce
-- script sans erreur si le bucket existe déjà.
insert into storage.buckets (id, name, public)
values ('receipts', 'receipts', false)
on conflict (id) do nothing;
