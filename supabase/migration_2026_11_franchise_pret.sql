-- Prêts avec franchise (différé total) et assurance : trois colonnes facultatives.
-- deferral_months   : mois de franchise AVANT la 1re échéance (les intérêts sont
--                     ajoutés au capital pendant ce temps). 0 = pas de franchise.
-- duration_months   : nombre d'échéances de remboursement (la dernière absorbe
--                     les centimes d'arrondi). Vide = calculé automatiquement.
-- monthly_insurance : assurance emprunteur prélevée chaque mois (même pendant
--                     la franchise).
alter table property_loans add column if not exists deferral_months integer not null default 0 check (deferral_months >= 0 and deferral_months <= 240);
alter table property_loans add column if not exists duration_months integer check (duration_months >= 1 and duration_months <= 600);
alter table property_loans add column if not exists monthly_insurance numeric(10, 2) check (monthly_insurance >= 0);
