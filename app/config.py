"""Configuration (variables d'environnement Vercel) et constantes/helpers
partagés par plusieurs modules de l'application.

Ne jamais mettre de secret en dur ici : tout passe par os.environ.get(...),
avec une valeur par défaut vide (ou publique) quand c'est pertinent.
"""

import os
from datetime import date, datetime
from typing import Literal
from zoneinfo import ZoneInfo

PARIS_TZ = ZoneInfo("Europe/Paris")

TransactionType = Literal["expense", "income"]

EXPENSE_CATEGORIES = {"restaurant", "courses", "transport", "logement", "loisirs", "santé", "autre"}
INCOME_CATEGORIES = {"salaire", "freelance", "remboursement", "cadeau", "autre"}

# Libellés lisibles pour l'export Excel (les catégories sont stockées en base
# sous forme de slugs courts — "restaurant", "salaire"... — mais on veut un
# fichier lisible par un humain, pas les codes internes).
EXPENSE_CATEGORY_LABELS = {
    "restaurant": "Restaurant", "courses": "Courses", "transport": "Transport",
    "logement": "Logement", "loisirs": "Loisirs", "santé": "Santé", "autre": "Autre",
}
INCOME_CATEGORY_LABELS = {
    "salaire": "Salaire", "freelance": "Freelance", "remboursement": "Remboursement",
    "cadeau": "Cadeau", "autre": "Autre",
}


def category_label(category: str, tx_type: str) -> str:
    labels = INCOME_CATEGORY_LABELS if tx_type == "income" else EXPENSE_CATEGORY_LABELS
    return labels.get(category, category)


def today_paris() -> date:
    """Date du jour en heure locale Europe/Paris (pas UTC) — important près de
    minuit, où le jour calendaire à Paris peut différer du jour UTC."""
    return datetime.now(PARIS_TZ).date()


# ---------------------------------------------------------------------------
# Configuration (variables d'environnement à définir sur Vercel)
# ---------------------------------------------------------------------------
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
# Clé service_role (secrète) et non la clé anon (publique) : le RLS est
# activé sans aucune policy pour anon/public, donc seule service_role peut
# lire/écrire. Cette clé ne doit JAMAIS être envoyée au frontend — elle vit
# uniquement ici, côté serveur, comme variable d'environnement Vercel.
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Service d'envoi d'emails (vérification d'adresse, mot de passe oublié,
# invitations). Sans clé configurée, les emails ne partent simplement pas —
# l'opération elle-même n'est jamais bloquée (le lien utile est toujours
# renvoyé dans la réponse de l'API en secours).
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "Kaching <onboarding@resend.dev>")
# URL publique de l'appli (ex: https://kaching.vercel.app, SANS slash final),
# utilisée pour construire les liens envoyés par email.
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "")
# Adresse où envoyer les alertes techniques (ex: panne de l'API Anthropic) —
# doit être la même adresse que le compte Resend lui-même, seule autorisée
# en mode sandbox (sans nom de domaine vérifié). Optionnelle : sans elle, les
# alertes sont simplement désactivées (aucune erreur, juste pas d'email).
ADMIN_ALERT_EMAIL = os.environ.get("ADMIN_ALERT_EMAIL", "")


# ---------------------------------------------------------------------------
# Réinitialisation complète (données de test) — liste des tables scopées par
# user_id à vider/réclamer. Partagée entre /api/admin/claim-orphan-data
# (app/routers/admin.py) et /api/reset-all + /api/export/json
# (app/routers/admin.py et app/routers/export.py).
# ---------------------------------------------------------------------------
_RESET_TABLES = [
    "transactions",
    "recurring_expenses",
    "custom_categories",
    "dismissed_category_suggestions",
    "budgets",
    "savings_goal",
    "category_essentiality_ratings",
    "property_loans",
]
# UUID nil : ne correspond jamais à une ligne réelle, donc ce filtre revient
# à "toutes les lignes" — l'API Supabase (postgrest) exige un filtre sur delete.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"

# Photos de reçus : bucket Supabase Storage privé, partagé entre
# app/routers/transactions.py (upload/téléchargement/suppression d'un reçu) et
# app/routers/admin.py (nettoyage des reçus lors d'un reset complet).
RECEIPTS_BUCKET = "receipts"

# Limites d'import partagées entre app/models.py (bornes des modèles Pydantic
# *CommitRequest) et app/routers/imports.py (bornes appliquées pendant
# l'aperçu, avant le commit) — gardées ici pour une source unique de vérité,
# importable des deux côtés sans import circulaire entre ces deux modules.
MAX_BANK_IMPORT_COMMIT_ROWS = 2000
MAX_GENERIC_IMPORT_ENTRIES = 600
