-- Kaching : usage quotidien (plafond des livrets, projets de placement,
-- règles apprises à l'import, résumé mensuel). Idempotent : peut être relancé.

alter table accounts add column if not exists ceiling numeric(14,2);

create table if not exists investment_projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  account_id uuid references accounts(id) on delete set null,
  name text not null,
  invested_amount numeric(14,2) not null check (invested_amount > 0),
  annual_rate_pct numeric(6,3) not null default 0,
  start_date date not null,
  duration_months integer not null check (duration_months > 0),
  received_amount numeric(14,2) not null default 0,
  status text not null default 'active' check (status in ('active','finished')),
  created_at timestamptz not null default now()
);
alter table investment_projects enable row level security;
create index if not exists investment_projects_user_id_idx on investment_projects (user_id);

create table if not exists category_rules (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  tx_type text not null,
  rule_key text not null,
  category text not null,
  created_at timestamptz not null default now(),
  unique (user_id, tx_type, rule_key)
);
alter table category_rules enable row level security;
create index if not exists category_rules_user_id_idx on category_rules (user_id);

alter table app_users add column if not exists monthly_summary boolean not null default false;
alter table app_users add column if not exists last_summary_month text;
