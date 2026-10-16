-- ===========================================================================
-- Migration "suivi financier" (octobre 2026) — à exécuter UNE fois dans
-- Supabase > SQL Editor, AVANT de déployer la nouvelle version du code.
--
-- Sans risque à relancer : chaque instruction vérifie d'abord si la table ou
-- la colonne existe déjà ("if not exists"). Ne supprime aucune donnée.
--
-- Ajoute :
--   1. la table des prêts (property_loans) si elle manque encore, et le
--      loyer mensuel perçu pour un bien loué ;
--   2. les comptes (banques, livrets, placements) et les soldes relevés à la
--      main ;
--   3. l'historique de patrimoine déclaré (ex : relevés Endettement /
--      Patrimoine de Boursorama) ;
--   4. sur chaque opération : son compte, et l'autre compte quand c'est un
--      virement entre deux comptes de l'utilisateur ;
--   5. le prêt remboursé par une mensualité.
--
-- Comme pour toutes les autres tables : RLS activé sans aucune policy, donc
-- seule la clé service_role (le backend) peut lire ou écrire.
-- ===========================================================================

-- 1. Prêts ------------------------------------------------------------------
create table if not exists property_loans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  property_name text not null,
  principal_amount numeric(12, 2) not null check (principal_amount > 0),
  annual_rate_pct numeric(6, 3) not null check (annual_rate_pct >= 0),
  monthly_payment numeric(10, 2) not null check (monthly_payment > 0),
  start_date date not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
alter table property_loans enable row level security;
create index if not exists property_loans_user_id_idx on property_loans (user_id);

alter table property_loans add column if not exists monthly_rent numeric(10, 2) check (monthly_rent >= 0);

-- 2. Comptes et soldes relevés ----------------------------------------------
-- kind : bank (compte courant), savings (livret), investment (Bricks, PEA,
-- assurance-vie...), other.
create table if not exists accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 60),
  kind text not null default 'bank' check (kind in ('bank', 'savings', 'investment', 'other')),
  annual_rate_pct numeric(6, 3) check (annual_rate_pct >= 0 and annual_rate_pct <= 100),
  active boolean not null default true,
  created_at timestamptz not null default now()
);
alter table accounts enable row level security;
create index if not exists accounts_user_id_idx on accounts (user_id);

create table if not exists account_balances (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  account_id uuid not null references accounts(id) on delete cascade,
  balance_date date not null,
  balance numeric(14, 2) not null,
  created_at timestamptz not null default now()
);
alter table account_balances enable row level security;
create index if not exists account_balances_user_id_idx on account_balances (user_id);
create index if not exists account_balances_account_id_idx on account_balances (account_id);

-- 3. Historique de patrimoine déclaré -----------------------------------------
create table if not exists net_worth_snapshots (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  snapshot_date date not null,
  assets numeric(14, 2) not null check (assets >= 0),
  debts numeric(14, 2) not null check (debts >= 0),
  label text,
  created_at timestamptz not null default now()
);
alter table net_worth_snapshots enable row level security;
create index if not exists net_worth_snapshots_user_id_idx on net_worth_snapshots (user_id);

-- 4. Compte de chaque opération + virements entre comptes ------------------
-- Supprimer un compte ne supprime pas ses opérations : leur compte repasse
-- simplement à vide (on delete set null).
alter table transactions add column if not exists account_id uuid references accounts(id) on delete set null;
alter table transactions add column if not exists transfer_account_id uuid references accounts(id) on delete set null;
create index if not exists transactions_account_id_idx on transactions (account_id);
create index if not exists transactions_transfer_account_id_idx on transactions (transfer_account_id);

-- 5. Mensualités rattachées à un prêt -----------------------------------------
-- Une dépense de catégorie "Crédit / prêt" peut pointer vers le prêt qu'elle
-- rembourse (onglet Prêts). Supprimer le prêt ne supprime pas l'opération.
alter table transactions add column if not exists loan_id uuid references property_loans(id) on delete set null;
create index if not exists transactions_loan_id_idx on transactions (loan_id);

-- 6. Vérification (ne modifie rien) ------------------------------------------
-- Lignes créées avant le passage au multi-profil et jamais rattachées à un
-- compte : elles ne sont visibles par personne. Le résultat affiché doit
-- être 0 partout ; sinon, le signaler avant d'aller plus loin.
select 'transactions' as table_name, count(*) as lignes_sans_compte from transactions where user_id is null
union all select 'recurring_expenses', count(*) from recurring_expenses where user_id is null
union all select 'custom_categories', count(*) from custom_categories where user_id is null
union all select 'dismissed_category_suggestions', count(*) from dismissed_category_suggestions where user_id is null
union all select 'budgets', count(*) from budgets where user_id is null
union all select 'savings_goal', count(*) from savings_goal where user_id is null
union all select 'category_essentiality_ratings', count(*) from category_essentiality_ratings where user_id is null;
