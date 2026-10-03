"""
Point d'entrée unique de l'API (et du frontend) pour Vercel.

Tout est regroupé dans ce seul fichier .py : c'est volontaire. Vercel ne
garantit pas d'embarquer les fichiers non-Python présents à côté du point
d'entrée (ex: frontend/index.html) dans le paquet de la fonction serverless.
Le HTML du frontend est donc encodé en base64 et copié directement dans ce
fichier par build.py, qui régénère la section entre les marqueurs
BEGIN_FRONTEND_B64 / END_FRONTEND_B64 ci-dessous. Ne jamais éditer cette
section à la main — éditer frontend/index.html puis relancer build.py.
"""

import base64
import calendar
import csv
import hashlib
import hmac
import json
import os
import re
import time
import unicodedata
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI()


# En-têtes de sécurité appliqués à TOUTES les réponses :
# - X-Content-Type-Options: empêche un navigateur de deviner ("sniffer") un
#   autre type de contenu que celui déclaré — utile en particulier pour les
#   photos de reçus (uploadées par l'utilisateur) : sans ça, un fichier dont
#   le contenu ressemble à du HTML pourrait, sur certains navigateurs plus
#   anciens, être exécuté comme tel malgré son Content-Type image/*.
# - X-Frame-Options: interdit d'afficher le site dans une <iframe> sur un
#   autre site (protection contre le "clickjacking", notamment sur l'écran de
#   mot de passe).
# - Referrer-Policy: n'envoie pas l'URL complète de la page (potentiellement
#   avec des paramètres) comme referrer vers d'autres sites.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


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
# Mot de passe humain (choisi par toi) qui protège l'accès à l'app — tapé une
# fois sur l'écran de verrouillage du frontend. Jamais envoyé nulle part
# ailleurs qu'ici, contrairement à l'ancienne clé API qui était codée en dur
# dans le JS de la page (donc visible par n'importe qui via "Afficher le
# code source", sans aucun mot de passe).
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
# Clé service_role (secrète) et non la clé anon (publique) : le RLS est
# activé sans aucune policy pour anon/public, donc seule service_role peut
# lire/écrire. Cette clé ne doit JAMAIS être envoyée au frontend — elle vit
# uniquement ici, côté serveur, comme variable d'environnement Vercel.
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


# ---------------------------------------------------------------------------
# Authentification par mot de passe + jeton de session signé
# ---------------------------------------------------------------------------
# Principe : /api/login vérifie le mot de passe (APP_PASSWORD, jamais envoyé
# au frontend) et renvoie un jeton "<date d'expiration>.<signature>", signé
# avec API_SECRET_KEY (qui redevient un secret purement serveur). Vercel étant
# sans état entre les invocations, on ne garde aucune session en mémoire :
# n'importe quelle invocation peut revalider le jeton elle-même, en
# recalculant la signature et en comparant (comparaison à temps constant,
# comme pour le mot de passe, pour ne pas faciliter une attaque par mesure de
# temps). Un jeton ne peut pas être forgé sans connaître API_SECRET_KEY, qui
# ne quitte jamais le serveur.
SESSION_DURATION_SECONDS = 90 * 24 * 3600  # 90 jours


def _sign_session_expiry(expires_at: int) -> str:
    return hmac.new(API_SECRET_KEY.encode(), str(expires_at).encode(), hashlib.sha256).hexdigest()


def _create_session_token() -> str:
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    return f"{expires_at}.{_sign_session_expiry(expires_at)}"


def _verify_session_token(token: str) -> bool:
    if not token or not API_SECRET_KEY or "." not in token:
        return False
    expires_part, _, signature = token.partition(".")
    try:
        expires_at = int(expires_part)
    except ValueError:
        return False
    expected_signature = _sign_session_expiry(expires_at)
    if not hmac.compare_digest(signature, expected_signature):
        return False
    return time.time() < expires_at


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    """Exige un jeton de session valide (obtenu via /api/login), pas juste
    une clé statique visible dans le JS de la page."""
    if not _verify_session_token(x_api_key):
        raise HTTPException(status_code=401, detail="Session invalide ou expirée, reconnecte-toi")


class LoginRequest(BaseModel):
    password: str = Field(min_length=1)


@app.post("/api/login")
def login(req: LoginRequest) -> dict:
    if not APP_PASSWORD or not API_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="Configuration manquante : APP_PASSWORD / API_SECRET_KEY",
        )
    # Comparaison à temps constant (sur les octets, pour accepter un mot de
    # passe avec des accents sans lever d'erreur) : évite qu'une différence de
    # timing ne renseigne un attaquant sur le nombre de caractères corrects.
    if not hmac.compare_digest(req.password.encode(), APP_PASSWORD.encode()):
        raise HTTPException(status_code=401, detail="Mot de passe incorrect")
    return {"token": _create_session_token()}


def get_supabase_client():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(
            status_code=500,
            detail="Configuration Supabase manquante (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)",
        )
    from supabase import create_client

    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# ---------------------------------------------------------------------------
# Modèles de données
# ---------------------------------------------------------------------------
class TransactionIn(BaseModel):
    type: TransactionType = "expense"
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None
    expense_date: date | None = None  # None => aujourd'hui (Europe/Paris)


class TransactionUpdate(BaseModel):
    type: TransactionType | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    description: str | None = None
    expense_date: date | None = None


class RecurringExpenseIn(BaseModel):
    type: TransactionType = "expense"
    name: str = Field(min_length=1)
    amount: float = Field(gt=0)
    category: str = "autre"
    day_of_month: int = Field(ge=1, le=31)
    start_date: date | None = None  # None => pas de date de début, compte dès maintenant
    end_date: date | None = None  # None => pas de date de fin, se répète indéfiniment


class RecurringExpenseUpdate(BaseModel):
    type: TransactionType | None = None
    name: str | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    day_of_month: int | None = Field(default=None, ge=1, le=31)
    start_date: date | None = None
    end_date: date | None = None


class CustomCategoryIn(BaseModel):
    type: TransactionType = "expense"
    value: str = Field(min_length=1)
    label: str = Field(min_length=1)


class DismissedSuggestionIn(BaseModel):
    key: str = Field(min_length=1)


class BudgetIn(BaseModel):
    category: str = Field(min_length=1)
    amount: float = Field(gt=0)


class SavingsGoalIn(BaseModel):
    monthly_target: float = Field(gt=0)


class VoiceParseRequest(BaseModel):
    text: str = Field(min_length=1)


class VoiceParseResult(BaseModel):
    intent: str = "transaction"
    type: TransactionType
    amount: float
    category: str
    description: str | None
    expense_date: date
    is_correction: bool
    is_recurring: bool
    raw_date_expression: str | None
    # True si l'IA a un doute réel sur l'interprétation (montant approximatif,
    # catégorie incertaine, phrase ambiguë...) : le frontend doit alors
    # demander confirmation au lieu d'enregistrer directement.
    needs_confirmation: bool = False


class VoiceQuestionResult(BaseModel):
    """Réponse à une question posée à l'oral sur ses finances (ex: "combien
    j'ai dépensé en restaurant ce mois-ci ?"). `answer` est la phrase à
    afficher/prononcer ; `amount` est le nombre brut correspondant quand il a
    un sens (None pour budget_status, par exemple, qui liste des catégories)."""

    intent: str = "question"
    answer: str
    metric: str
    category: str | None = None
    period_label: str
    amount: float | None = None


class VoiceEditResult(BaseModel):
    """Résultat d'une modification vocale d'une transaction déjà enregistrée,
    désignée par position ("la dernière dépense", "le dernier revenu"), sans
    redicter son montant. `answer` est la phrase de confirmation à
    afficher/prononcer. Les champs de la transaction mise à jour sont inclus
    pour que le frontend puisse rafraîchir l'affichage sans requête de plus."""

    intent: str = "edit_last"
    answer: str
    # True si la modification n'a PAS encore été appliquée (doute de l'IA) :
    # le frontend doit alors afficher une bannière de confirmation plutôt que
    # de considérer que c'est déjà fait. Dans ce cas, transaction_id/type/
    # category/amount ci-dessous ne sont pas renseignés — seuls target/
    # requested_new_type/requested_new_category le sont (ce que l'IA a
    # compris vouloir changer, pas encore validé).
    pending: bool = False
    target: str | None = None
    requested_new_type: str | None = None
    requested_new_category: str | None = None
    transaction_id: str | None = None
    type: TransactionType | None = None
    category: str | None = None
    amount: float | None = None


# ---------------------------------------------------------------------------
# Analyse déterministe des expressions de date en français
# ---------------------------------------------------------------------------
# Important : l'IA ne doit JAMAIS calculer elle-même une date calendaire à
# partir d'une expression relative ("hier", "lundi prochain") — elle ne
# connaît pas la date du jour et se trompe. Elle se contente d'extraire
# l'expression telle quelle ; c'est cette fonction, déterministe, qui la
# convertit en vraie date, à partir de `today_paris()`.
_WEEKDAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]

_MONTHS = {
    "janvier": 1, "février": 2, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5,
    "juin": 6, "juillet": 7, "août": 8, "aout": 8, "septembre": 9,
    "octobre": 10, "novembre": 11, "décembre": 12, "decembre": 12,
}


def parse_french_date_expression(expr: str | None, reference: date) -> date | None:
    """Convertit une expression de date en français (dite à l'oral) en date
    réelle, de façon déterministe, par rapport à `reference` (= aujourd'hui).
    Retourne None si l'expression n'est pas reconnue (le code appelant doit
    alors utiliser `reference` par défaut plutôt que de deviner)."""
    if not expr:
        return None
    text = expr.strip().lower()
    text = text.replace("’", "'")

    if text in ("aujourd'hui", "aujourdhui", "ce jour"):
        return reference
    if text == "hier":
        return reference - timedelta(days=1)
    if text in ("avant-hier", "avant hier"):
        return reference - timedelta(days=2)
    if text == "demain":
        return reference + timedelta(days=1)
    if text in ("après-demain", "apres-demain", "après demain", "apres demain"):
        return reference + timedelta(days=2)

    m = re.match(r"^il y a (\d+) jours?$", text)
    if m:
        return reference - timedelta(days=int(m.group(1)))
    m = re.match(r"^il y a (\d+) semaines?$", text)
    if m:
        return reference - timedelta(weeks=int(m.group(1)))

    m = re.match(
        r"^(lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche)"
        r"(?:\s+(dernier|derni[eè]re|prochain|prochaine))?$",
        text,
    )
    if m:
        weekday_name, qualifier = m.group(1), m.group(2)
        target_weekday = _WEEKDAYS.index(weekday_name)
        delta = target_weekday - reference.weekday()
        if qualifier in ("prochain", "prochaine"):
            if delta <= 0:
                delta += 7
        else:
            # bare weekday ou "dernier" : occurrence la plus récente, aujourd'hui
            # inclus seulement pour un nom de jour sans qualificatif.
            if qualifier in ("dernier", "dernière", "derniere"):
                if delta >= 0:
                    delta -= 7
            else:
                if delta > 0:
                    delta -= 7
        return reference + timedelta(days=delta)

    # Date explicite "15 septembre" ou "15 septembre 2026"
    m = re.match(r"^(\d{1,2})(?:er)?\s+([a-zéû]+)(?:\s+(\d{4}))?$", text)
    if m and m.group(2) in _MONTHS:
        day = int(m.group(1))
        month = _MONTHS[m.group(2)]
        year = int(m.group(3)) if m.group(3) else reference.year
        try:
            candidate = date(year, month, day)
        except ValueError:
            return None
        if not m.group(3) and candidate > reference + timedelta(days=1):
            # Pas d'année précisée et la date tombe dans le futur : on suppose
            # qu'il s'agissait de l'année précédente (contexte : saisie de
            # dépenses passées, pas de planification future).
            try:
                candidate = date(year - 1, month, day)
            except ValueError:
                return None
        return candidate

    # Date numérique "15/09" ou "15/09/2026" (format français JJ/MM[/AAAA])
    m = re.match(r"^(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?$", text)
    if m:
        day, month = int(m.group(1)), int(m.group(2))
        if m.group(3):
            year = int(m.group(3))
            if year < 100:
                year += 2000
        else:
            year = reference.year
        try:
            candidate = date(year, month, day)
        except ValueError:
            return None
        if not m.group(3) and candidate > reference + timedelta(days=1):
            try:
                candidate = date(year - 1, month, day)
            except ValueError:
                return None
        return candidate

    return None


# ---------------------------------------------------------------------------
# Analyse déterministe des expressions de période (pour l'assistant vocal
# "question" — même principe que parse_french_date_expression ci-dessus :
# l'IA ne calcule JAMAIS elle-même une période, elle recopie l'expression
# telle quelle ; c'est cette fonction qui la convertit en bornes concrètes.
# ---------------------------------------------------------------------------
_MONTH_NAMES_FR = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
]


def parse_french_period_expression(expr: str | None, reference: date) -> dict:
    """Retourne {"kind": "month"|"year"|"all", "month_key"?, "year"?, "label"}.
    `label` est une expression française prête à insérer dans une phrase de
    réponse ("ce mois-ci", "le mois dernier", "cette année"...). Par défaut
    (expression absente ou non reconnue) : le mois en cours."""
    current_month_key = f"{reference.year:04d}-{reference.month:02d}"

    if not expr:
        return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}

    text = expr.strip().lower()
    text = text.replace("’", "'")
    text = re.sub(r"^(en|pour|sur|durant|pendant)\s+", "", text)

    if text in ("ce mois", "ce mois-ci", "ce mois ci"):
        return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}

    if text in (
        "le mois dernier", "mois dernier", "le mois précédent", "mois précédent",
        "le mois precedent", "mois precedent",
    ):
        prev_month = reference.month - 1 if reference.month > 1 else 12
        prev_year = reference.year if reference.month > 1 else reference.year - 1
        return {
            "kind": "month",
            "month_key": f"{prev_year:04d}-{prev_month:02d}",
            "label": "le mois dernier",
        }

    if text in ("cette année", "cette année-ci", "cette annee", "cette annee-ci"):
        return {"kind": "year", "year": str(reference.year), "label": "cette année"}

    if text in (
        "l'année dernière", "année dernière", "l'an dernier", "an dernier",
        "l'annee derniere", "annee derniere",
    ):
        return {"kind": "year", "year": str(reference.year - 1), "label": "l'année dernière"}

    if text in ("depuis le début", "depuis toujours", "au total", "depuis le debut", "toujours"):
        return {"kind": "all", "label": "au total"}

    # Mois explicite, avec ou sans année : "mars", "en mars 2026"
    m = re.match(r"^([a-zéû]+)(?:\s+(\d{4}))?$", text)
    if m and m.group(1) in _MONTHS:
        month = _MONTHS[m.group(1)]
        if m.group(2):
            year = int(m.group(2))
        else:
            year = reference.year
            if date(year, month, 1) > reference.replace(day=1):
                year -= 1
        month_name = _MONTH_NAMES_FR[month - 1]
        return {
            "kind": "month",
            "month_key": f"{year:04d}-{month:02d}",
            "label": f"en {month_name} {year}",
        }

    return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}


def filter_transactions_by_period(transactions: list[dict], period: dict) -> list[dict]:
    if period["kind"] == "all":
        return transactions
    if period["kind"] == "year":
        return [tx for tx in transactions if tx["expense_date"][:4] == period["year"]]
    return [tx for tx in transactions if tx["expense_date"][:7] == period["month_key"]]


def format_eur(amount: float) -> str:
    sign = "-" if amount < 0 else ""
    formatted = f"{abs(amount):,.2f}".replace(",", " ").replace(".", ",")
    return f"{sign}{formatted} €"


def compute_voice_answer(metric: str, category: str | None, period: dict, client) -> dict:
    """Calcule la réponse à une question vocale à partir des vraies données
    (jamais inventée par l'IA). Retourne {"answer": str, "amount": float|None}."""
    period_label = period["label"]
    transactions = (
        client.table("transactions").select("type, amount, category, expense_date").execute().data
    )

    if metric == "spent":
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "expense"
        ]
        if category:
            filtered = [tx for tx in filtered if tx["category"] == category]
        total = sum(float(tx["amount"]) for tx in filtered)
        if category:
            cat_label = category_label(category, "expense")
            answer = f"Tu as dépensé {format_eur(total)} en {cat_label.lower()} {period_label}."
        else:
            answer = f"Tu as dépensé {format_eur(total)} {period_label}."
        return {"answer": answer, "amount": total}

    if metric == "earned":
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "income"
        ]
        if category:
            filtered = [tx for tx in filtered if tx["category"] == category]
        total = sum(float(tx["amount"]) for tx in filtered)
        if category:
            cat_label = category_label(category, "income")
            answer = f"Tu as gagné {format_eur(total)} en {cat_label.lower()} {period_label}."
        else:
            answer = f"Tu as gagné {format_eur(total)} {period_label}."
        return {"answer": answer, "amount": total}

    if metric == "balance":
        filtered = filter_transactions_by_period(transactions, period)
        spent = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "expense")
        earned = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "income")
        balance = earned - spent
        detail = f"{format_eur(earned)} de revenus pour {format_eur(spent)} de dépenses"
        if balance >= 0:
            answer = f"Ton solde est positif de {format_eur(balance)} {period_label} ({detail})."
        else:
            answer = f"Ton solde est négatif de {format_eur(abs(balance))} {period_label} ({detail})."
        return {"answer": answer, "amount": balance}

    if metric == "budget_remaining":
        if not category:
            return {
                "answer": "Précise une catégorie pour que je te dise où tu en es sur son budget.",
                "amount": None,
            }
        budgets = client.table("budgets").select("*").eq("category", category).execute().data
        cat_label = category_label(category, "expense")
        if not budgets:
            return {"answer": f"Tu n'as pas encore défini de budget pour {cat_label.lower()}.", "amount": None}
        budget_amount = float(budgets[0]["amount"])
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period)
            if tx["type"] == "expense" and tx["category"] == category
        ]
        spent = sum(float(tx["amount"]) for tx in filtered)
        remaining = budget_amount - spent
        if remaining >= 0:
            answer = (
                f"Il te reste {format_eur(remaining)} sur ton budget {cat_label.lower()} {period_label} "
                f"(sur {format_eur(budget_amount)})."
            )
        else:
            answer = (
                f"Tu as dépassé ton budget {cat_label.lower()} de {format_eur(abs(remaining))} "
                f"{period_label} (budget de {format_eur(budget_amount)})."
            )
        return {"answer": answer, "amount": remaining}

    if metric == "budget_status":
        budgets = client.table("budgets").select("*").execute().data
        if not budgets:
            return {"answer": "Tu n'as pas encore défini de budget pour tes catégories.", "amount": None}
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "expense"
        ]
        totals: dict[str, float] = {}
        for tx in filtered:
            totals[tx["category"]] = totals.get(tx["category"], 0.0) + float(tx["amount"])
        over = []
        for b in budgets:
            spent = totals.get(b["category"], 0.0)
            over_amount = spent - float(b["amount"])
            if over_amount > 0:
                over.append((category_label(b["category"], "expense"), over_amount))
        if not over:
            answer = f"Aucun dépassement de budget {period_label} — bien joué !"
        else:
            over.sort(key=lambda pair: pair[1], reverse=True)
            parts = [f"{label} (+{format_eur(amt)})" for label, amt in over]
            answer = f"Tu dépasses ton budget {period_label} sur : {', '.join(parts)}."
        return {"answer": answer, "amount": None}

    if metric == "savings_progress":
        goal_rows = client.table("savings_goal").select("*").limit(1).execute().data
        if not goal_rows:
            return {"answer": "Tu n'as pas encore défini d'objectif d'épargne mensuel.", "amount": None}
        target = float(goal_rows[0]["monthly_target"])
        filtered = filter_transactions_by_period(transactions, period)
        spent = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "expense")
        earned = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "income")
        net = earned - spent
        if net >= target:
            answer = (
                f"Objectif atteint ! Tu as économisé {format_eur(net)} {period_label}, "
                f"pour un objectif de {format_eur(target)}."
            )
        elif net > 0:
            answer = (
                f"Tu as économisé {format_eur(net)} {period_label}, il te manque "
                f"{format_eur(target - net)} pour atteindre ton objectif de {format_eur(target)}."
            )
        else:
            answer = (
                f"Tu es en négatif de {format_eur(abs(net))} {period_label} : impossible d'épargner "
                f"pour l'instant (objectif : {format_eur(target)})."
            )
        return {"answer": answer, "amount": net}

    return {"answer": "Je n'ai pas compris ta question, tu peux réessayer ?", "amount": None}


# ---------------------------------------------------------------------------
# Extraction IA (API Anthropic) — transforme une phrase dictée en brouillon
# structuré, soit une transaction à enregistrer, soit une question sur ses
# finances. Ne touche jamais la base pour une transaction : c'est le frontend
# qui décide ensuite d'appeler POST ou PUT sur /api/transactions avec le
# résultat. Pour une question, en revanche, le calcul se fait ici même,
# côté serveur, à partir des vraies données — jamais inventé par l'IA.
# ---------------------------------------------------------------------------

# Mots de liaison français à retirer d'une description dictée à la voix (ex:
# "au casino" -> "casino", "gains au casino" -> "gains casino"), pour que les
# descriptions restent courtes et cohérentes avec le regroupement par
# mots-clés fait côté frontend (voir extractDescriptionKeywords dans
# frontend/index.html, qui ignore la même liste). On ne touche jamais une
# description saisie manuellement : uniquement celle que l'IA vocale extrait
# ci-dessous, une description tapée au clavier reflète un choix délibéré de
# l'utilisateur.
_DESCRIPTION_STOPWORDS = {
    "a", "à", "au", "aux", "de", "du", "des", "d", "le", "la", "les", "l",
    "un", "une", "ce", "cet", "cette", "ces", "mon", "ma", "mes",
    "ton", "ta", "tes", "son", "sa", "ses", "notre", "nos", "votre",
    "vos", "leur", "leurs", "chez", "sur", "dans", "pour", "avec",
    "et", "ou", "en", "par",
}


def _strip_description_stopwords(description: str) -> str:
    words = description.split()
    kept = [w for w in words if w.lower().strip(".,!?;:'\"-") not in _DESCRIPTION_STOPWORDS]
    cleaned = " ".join(kept)
    return cleaned or description  # si tout a été retiré (rare), on garde l'original


_VOICE_SYSTEM_PROMPT_TEMPLATE = """Tu analyses une phrase dictée à l'oral en français, qui concerne les finances personnelles de l'utilisateur. Elle est de l'une de ces trois natures :

1. Une dépense ou un revenu à enregistrer, ou une correction d'une transaction qui vient tout juste d'être dictée (la phrase précédente).
2. Une question sur ses finances (combien il a dépensé, où il en est sur un budget, son solde, son épargne...).
3. Une demande de modifier le TYPE et/ou la CATÉGORIE d'une transaction déjà enregistrée, désignée par position plutôt que redictée en entier (ex: "change la dernière dépense en revenu", "mets la dernière dépense dans la catégorie restaurant", "le dernier revenu, c'est en fait des freelance").

Si la phrase est interrogative — ou commence par des mots comme "combien", "quel", "quelle", "est-ce que", "comment", "où en est", "ai-je", "suis-je", "me reste-t-il", "qu'est-ce que" — c'est TOUJOURS une question (intent="question"), jamais une transaction, même si elle mentionne un montant ou une catégorie.

Si la phrase désigne une transaction déjà enregistrée par sa position ("la dernière dépense", "le dernier revenu", "la dernière transaction") SANS redicter de montant, c'est TOUJOURS intent="edit_last", jamais "transaction" — même si elle contient un mot comme "change" ou "corrige".

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon l'un de ces trois schémas :

### Si intent = "transaction"
{
  "intent": "transaction",
  "type": "expense" ou "income" — détermine-le UNIQUEMENT à partir du verbe qui décrit l'argent qui bouge (gagné/reçu/touché = income ; dépensé/payé/perdu = expense). Une phrase dictée à l'oral contient parfois, en plus, une instruction du type "mets-la/classe-la/range-la dans la catégorie X" pour préciser la catégorie : ignore cette partie pour le type, elle ne sert qu'à choisir "category", jamais à décider "expense" ou "income". Attention aussi aux approximations de reconnaissance vocale : "mets"/"met"/"mettez" (verbe mettre, utilisé dans cette instruction de catégorie) peuvent être mal transcrits en un mot proche phonétiquement comme "mais" — ne les confonds jamais avec une dépense,
  "amount": nombre (toujours positif),
  "category": une chaîne parmi __EXPENSE_CATEGORIES__ (si type=expense) ou __INCOME_CATEGORIES__ (si type=income) — cette liste inclut les catégories par défaut ET les catégories personnalisées déjà créées par l'utilisateur. Si la phrase contient une instruction explicite du genre "mets-la/classe-la/range-la dans la catégorie X", utilise X en priorité (en la faisant correspondre à la liste). Sinon, si une catégorie personnalisée correspond clairement au sujet de la phrase (ex: une catégorie "casino" existe et la phrase parle du casino), utilise-la plutôt que "autre",
  "raw_date_expression": l'expression de date EXACTEMENT telle que prononcée (ex: "hier", "lundi dernier", "le 3 septembre"), ou null si aucune date n'est mentionnée,
  "description": une description courte (sans le montant ni la date), construite UNIQUEMENT à partir des mots-clés réellement prononcés (ex: "j'ai perdu 40 euros au casino" -> "casino", PAS "perte casino" : n'invente pas un nom comme "perte" ou "gain" à partir d'un verbe ("j'ai perdu", "j'ai gagné") s'il n'a pas été prononcé tel quel), ou null si rien de pertinent à part la catégorie,
  "is_correction": true seulement si la phrase exprime explicitement une intention de corriger une transaction déjà enregistrée (ex: "corrige", "en fait c'était plutôt", "change le montant de..."), false dans tous les autres cas, y compris si la phrase ressemble à une dépense déjà saisie,
  "is_recurring": true si la phrase indique explicitement qu'il s'agit d'une charge qui se répète chaque mois (mots comme "récurrent", "récurrence", "abonnement", "tous les mois", "chaque mois", "mensuel"), false sinon,
  "needs_confirmation": true UNIQUEMENT si tu as un doute réel sur l'interprétation (montant approximatif ou peu clair, catégorie devinée sans élément solide, structure de phrase bizarre ou ambiguë, plusieurs lectures possibles) ; false si l'interprétation est claire et directe — ne mets pas true par excès de prudence, seulement en cas de doute véritable
}

### Si intent = "question"
{
  "intent": "question",
  "metric": une chaîne parmi :
    - "spent" : combien a été dépensé (au total, ou dans une catégorie précise) sur une période,
    - "earned" : combien a été gagné/reçu (au total, ou dans une catégorie précise) sur une période,
    - "balance" : le solde (revenus moins dépenses) sur une période,
    - "budget_remaining" : combien il reste sur le budget d'une catégorie précise, ce mois-ci,
    - "budget_status" : quelles catégories dépassent leur budget, ce mois-ci,
    - "savings_progress" : où en est l'utilisateur par rapport à son objectif d'épargne mensuel,
  "category": une chaîne parmi __ALL_CATEGORIES__ (celle qui est pertinente pour la question, catégories personnalisées incluses), ou null si la question ne porte pas sur une catégorie précise,
  "raw_period_expression": l'expression de période EXACTEMENT telle que prononcée (ex: "ce mois-ci", "le mois dernier", "cette année", "l'année dernière", "en septembre", "depuis le début"), ou null si aucune période n'est mentionnée (le mois en cours sera utilisé par défaut)
}

### Si intent = "edit_last"
{
  "intent": "edit_last",
  "target": "last_expense" (la dernière dépense) ou "last_income" (le dernier revenu) ou "last_transaction" (la dernière transaction tout court, sans préciser dépense ou revenu),
  "new_type": "expense" ou "income" si la phrase demande explicitement de changer le type (ex: "change cette dépense en revenu"), sinon null,
  "new_category": une chaîne parmi __ALL_CATEGORIES__ si la phrase demande explicitement de changer la catégorie (ex: "mets-la dans la catégorie restaurant", "c'est en fait du freelance"), sinon null,
  "needs_confirmation": true UNIQUEMENT si tu as un doute réel (la cible "last_expense"/"last_income"/"last_transaction" n'est pas claire, la nouvelle catégorie demandée ne correspond à rien de connu, phrase ambiguë) ; false si c'est clair
}
Si la phrase ne précise ni nouveau type ni nouvelle catégorie de façon exploitable, laisse les deux à null plutôt que d'inventer une valeur — un système déterministe gère ce cas côté serveur.

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même un montant, une date calendaire ou une période à partir d'une expression relative. Tu ne connais ni le solde de l'utilisateur ni la date du jour. Recopie les expressions telles quelles ; un système déterministe s'occupe de tous les calculs à partir des vraies données.
- Si la phrase ne mentionne aucune date (transaction) ou aucune période (question), le champ correspondant doit être null.
- is_correction doit rester false par défaut : en cas de doute, considère qu'il s'agit d'une nouvelle transaction plutôt que d'une correction.
- is_recurring doit rester false par défaut : ne le mets à true que si la récurrence est clairement exprimée à l'oral, jamais par déduction (ex: "le loyer" seul ne suffit pas, il faut un mot indiquant explicitement la répétition)."""


def _fetch_custom_categories(client) -> dict[str, dict[str, str]]:
    """Catégories personnalisées créées par l'utilisateur (bandeau de
    suggestion ou formulaire manuel), par type, sous forme {value: label}.
    Nécessaires pour que l'IA vocale puisse les proposer elle-même au lieu de
    toujours retomber sur "autre" pour une catégorie qu'elle ne connaît pas,
    et pour afficher un libellé lisible (pas juste le slug) dans les
    confirmations vocales."""
    rows = client.table("custom_categories").select("type, value, label").execute().data
    result: dict[str, dict[str, str]] = {"expense": {}, "income": {}}
    for row in rows:
        t = row.get("type")
        if t in result:
            result[t][row["value"]] = row["label"]
    return result


def _build_voice_system_prompt(expense_categories: set[str], income_categories: set[str]) -> str:
    all_categories = sorted(expense_categories | income_categories)
    return (
        _VOICE_SYSTEM_PROMPT_TEMPLATE
        .replace("__EXPENSE_CATEGORIES__", ", ".join(sorted(expense_categories)))
        .replace("__INCOME_CATEGORIES__", ", ".join(sorted(income_categories)))
        .replace("__ALL_CATEGORIES__", ", ".join(all_categories))
    )


def call_claude_extraction(text: str, expense_categories: set[str], income_categories: set[str]) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Configuration manquante : ANTHROPIC_API_KEY",
        )
    from anthropic import Anthropic

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            system=_build_voice_system_prompt(expense_categories, income_categories),
            messages=[{"role": "user", "content": text}],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Erreur API Anthropic : {exc}") from exc

    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    # Au cas où le modèle entoure sa réponse de ```json ... ``` malgré la consigne.
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}"
        ) from exc
    return data


_VOICE_QUESTION_METRICS = {
    "spent", "earned", "balance", "budget_remaining", "budget_status", "savings_progress",
}


def _finalize_transaction(data: dict, expense_categories: set[str], income_categories: set[str]) -> VoiceParseResult:
    """Valide et finalise un objet "transaction" (venant soit directement de
    l'IA, soit d'une correction après une bannière de confirmation) en un
    VoiceParseResult prêt à être renvoyé au frontend — qui se charge ensuite
    lui-même de l'enregistrer (POST/PUT /api/transactions)."""
    tx_type: TransactionType = "income" if data.get("type") == "income" else "expense"

    try:
        amount = float(data.get("amount"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")

    category = str(data.get("category") or "autre").strip().lower()
    allowed = income_categories if tx_type == "income" else expense_categories
    if category not in allowed:
        category = "autre"

    description = data.get("description")
    description = description.strip() if isinstance(description, str) and description.strip() else None
    if description:
        description = _strip_description_stopwords(description)

    raw_date_expression = data.get("raw_date_expression")
    raw_date_expression = raw_date_expression if isinstance(raw_date_expression, str) else None

    reference = today_paris()
    parsed_date = parse_french_date_expression(raw_date_expression, reference)
    expense_date = parsed_date or reference

    is_correction = bool(data.get("is_correction", False))
    is_recurring = bool(data.get("is_recurring", False))

    return VoiceParseResult(
        type=tx_type,
        amount=amount,
        category=category,
        description=description,
        expense_date=expense_date,
        is_correction=is_correction,
        is_recurring=is_recurring,
        raw_date_expression=raw_date_expression,
        needs_confirmation=bool(data.get("needs_confirmation", False)),
    )


def _preview_edit_last(data: dict) -> VoiceEditResult:
    """Aucune écriture en base : juste de quoi afficher une bannière de
    confirmation côté frontend (qui retrouve lui-même la transaction ciblée
    dans sa liste déjà chargée pour donner du contexte)."""
    return VoiceEditResult(
        answer="",
        pending=True,
        target=data.get("target"),
        requested_new_type=data.get("new_type"),
        requested_new_category=data.get("new_category"),
    )


def _finalize_edit_last(
    data: dict, client, expense_categories: set[str], income_categories: set[str], custom: dict
) -> VoiceEditResult:
    target = data.get("target")
    if target not in ("last_expense", "last_income", "last_transaction"):
        return VoiceEditResult(answer="Je n'ai pas compris quelle transaction modifier, tu peux réessayer ?")

    query = client.table("transactions").select("*").order("expense_date", desc=True).order("created_at", desc=True)
    if target == "last_expense":
        query = query.eq("type", "expense")
    elif target == "last_income":
        query = query.eq("type", "income")
    rows = query.limit(1).execute().data
    if not rows:
        return VoiceEditResult(answer="Je n'ai trouvé aucune transaction correspondante à modifier.")
    tx = rows[0]

    new_type = data.get("new_type")
    new_type = new_type if new_type in ("expense", "income") else None
    final_type: TransactionType = new_type or tx["type"]

    new_category = data.get("new_category")
    new_category = new_category.strip().lower() if isinstance(new_category, str) and new_category.strip() else None
    final_allowed = income_categories if final_type == "income" else expense_categories
    if new_category and new_category not in final_allowed:
        # Catégorie non reconnue (mal transcrite, inventée...) : on
        # l'ignore plutôt que de planter ou d'enregistrer n'importe quoi.
        new_category = None

    update_payload: dict = {}
    if new_type and new_type != tx["type"]:
        update_payload["type"] = new_type
        # Une catégorie de dépense n'a généralement aucun sens côté
        # revenu (et inversement) : si le type change sans nouvelle
        # catégorie valide donnée, on retombe sur "autre" plutôt que de
        # garder une catégorie qui n'existe pas pour ce type.
        if not new_category and tx["category"] not in final_allowed:
            update_payload["category"] = "autre"
    if new_category:
        update_payload["category"] = new_category

    if not update_payload:
        return VoiceEditResult(
            answer="Je n'ai rien trouvé de concret à changer (ni nouveau type, ni nouvelle catégorie reconnue).",
            transaction_id=tx["id"],
            type=tx["type"],
            category=tx["category"],
            amount=tx["amount"],
        )

    result = client.table("transactions").update(update_payload).eq("id", tx["id"]).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    updated = result.data[0]

    label = category_label(updated["category"], updated["type"]) if updated["category"] not in custom.get(updated["type"], {}) else custom[updated["type"]][updated["category"]]
    type_label = "revenu" if updated["type"] == "income" else "dépense"
    answer = f"C'est fait : {format_eur(updated['amount'])} classé en {type_label} / {label}."

    return VoiceEditResult(
        answer=answer,
        transaction_id=updated["id"],
        type=updated["type"],
        category=updated["category"],
        amount=updated["amount"],
    )


@app.post("/api/voice/parse", response_model=None)
def parse_voice_text(req: VoiceParseRequest, _: None = Depends(require_api_key)):
    client = get_supabase_client()
    custom = _fetch_custom_categories(client)
    expense_categories = EXPENSE_CATEGORIES | set(custom["expense"].keys())
    income_categories = INCOME_CATEGORIES | set(custom["income"].keys())

    data = call_claude_extraction(req.text, expense_categories, income_categories)

    if data.get("intent") == "question":
        metric = str(data.get("metric") or "").strip()
        if metric not in _VOICE_QUESTION_METRICS:
            return VoiceQuestionResult(
                answer="Je n'ai pas compris ta question, tu peux réessayer ?",
                metric="unknown",
                period_label="",
            )

        category = data.get("category")
        category = category.strip().lower() if isinstance(category, str) and category.strip() else None
        if metric == "earned":
            if category not in income_categories:
                category = None
        elif metric in ("spent", "budget_remaining"):
            if category not in expense_categories:
                category = None
        else:
            category = None

        raw_period_expression = data.get("raw_period_expression")
        raw_period_expression = raw_period_expression if isinstance(raw_period_expression, str) else None

        period = parse_french_period_expression(raw_period_expression, today_paris())

        # Les budgets et l'objectif d'épargne sont des notions "mensuelles"
        # sans historique propre (un seul montant, reconduit chaque mois) :
        # une question sur "cette année" ou "au total" n'a pas de sens pour
        # ces métriques, on retombe donc sur le mois en cours.
        if metric in ("budget_remaining", "budget_status", "savings_progress") and period["kind"] != "month":
            reference = today_paris()
            period = {
                "kind": "month",
                "month_key": f"{reference.year:04d}-{reference.month:02d}",
                "label": "ce mois-ci",
            }

        result = compute_voice_answer(metric, category, period, client)

        return VoiceQuestionResult(
            answer=result["answer"],
            metric=metric,
            category=category,
            period_label=period["label"],
            amount=result.get("amount"),
        )

    if data.get("intent") == "edit_last":
        if data.get("needs_confirmation"):
            return _preview_edit_last(data)
        return _finalize_edit_last(data, client, expense_categories, income_categories, custom)

    return _finalize_transaction(data, expense_categories, income_categories)


class VoiceConfirmRequest(BaseModel):
    """Réponse (vocale ou par bouton) à une bannière de confirmation affichée
    côté frontend. `pending` est repris tel quel depuis ce que /api/voice/parse
    avait renvoyé (ou une version simplifiée pour edit_last — voir le
    frontend). `reply_text` est rempli pour une réponse vocale (interprétée
    par l'IA) ; `decision` est rempli directement pour un bouton Confirmer/
    Annuler (aucun appel IA nécessaire dans ce cas, c'est explicite)."""

    kind: str
    pending: dict
    reply_text: str | None = None
    decision: str | None = None  # "confirm" ou "cancel", si rempli directement par un bouton


_VOICE_CONFIRM_SYSTEM_PROMPT_TEMPLATE = """L'application de finances de l'utilisateur avait compris l'action suivante, mais avait un doute et lui a demandé confirmation à l'oral :

__PENDING_JSON__

L'utilisateur vient de répondre à l'oral pour confirmer, annuler, ou corriger cette action. Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour :

{
  "decision": "confirm" si la réponse confirme que c'est bien ça (ex: "oui", "oui c'est ça", "c'est bon", "exact", "vas-y"),
             "cancel" si la réponse annule/refuse sans donner de correction exploitable (ex: "non", "annule", "laisse tomber", "non rien"),
             "correction" si la réponse indique explicitement ce qui doit changer,
  "updated": uniquement si decision="correction" — une copie EXACTE de l'objet ci-dessus (mêmes clés, mêmes types) avec UNIQUEMENT les champs mentionnés par la correction modifiés, tous les autres recopiés à l'identique. Absent sinon.
}

Catégories de dépense valables : __EXPENSE_CATEGORIES__
Catégories de revenu valables : __INCOME_CATEGORIES__"""


def call_claude_confirm(reply_text: str, pending: dict, expense_categories: set[str], income_categories: set[str]) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : ANTHROPIC_API_KEY")
    from anthropic import Anthropic

    system = (
        _VOICE_CONFIRM_SYSTEM_PROMPT_TEMPLATE
        .replace("__PENDING_JSON__", json.dumps(pending, ensure_ascii=False, default=str))
        .replace("__EXPENSE_CATEGORIES__", ", ".join(sorted(expense_categories)))
        .replace("__INCOME_CATEGORIES__", ", ".join(sorted(income_categories)))
    )

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            system=system,
            messages=[{"role": "user", "content": reply_text}],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Erreur API Anthropic : {exc}") from exc

    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}") from exc


@app.post("/api/voice/confirm", response_model=None)
def confirm_voice_action(req: VoiceConfirmRequest, _: None = Depends(require_api_key)):
    client = get_supabase_client()
    custom = _fetch_custom_categories(client)
    expense_categories = EXPENSE_CATEGORIES | set(custom["expense"].keys())
    income_categories = INCOME_CATEGORIES | set(custom["income"].keys())

    if req.decision in ("confirm", "cancel"):
        # Bouton "Confirmer"/"Annuler" tapé directement : pas d'ambiguïté à
        # lever, pas besoin d'appeler l'IA.
        decision = req.decision
        updated = req.pending
    else:
        if not req.reply_text:
            raise HTTPException(status_code=422, detail="reply_text requis en l'absence de decision")
        decision_data = call_claude_confirm(req.reply_text, req.pending, expense_categories, income_categories)
        decision = decision_data.get("decision")
        updated = decision_data.get("updated") or req.pending

    if decision == "cancel":
        return {"decision": "cancel"}

    # Qu'il s'agisse d'une simple confirmation ou d'une correction, cette
    # réponse est la résolution du doute : on ne redemande jamais une
    # deuxième confirmation sur la foi de cette réponse-là.
    updated = dict(updated)
    updated["needs_confirmation"] = False

    if req.kind == "edit_last":
        return _finalize_edit_last(updated, client, expense_categories, income_categories, custom)
    return _finalize_transaction(updated, expense_categories, income_categories)


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdCB7CiAgICBjb2xvci1zY2hlbWU6IGRhcms7CiAgICAtLWJnOiAjMGYxMTE1OwogICAgLS1zdXJmYWNlOiAjMWExZDI0OwogICAgLS1zdXJmYWNlLTI6ICMyMjI2MmY7CiAgICAtLWJvcmRlcjogIzJhMmUzODsKICAgIC0tdGV4dDogI2U2ZTZlNjsKICAgIC0tdGV4dC1kaW06ICM5YWEwYWM7CiAgICAtLWFjY2VudDogIzNiODJmNjsKICAgIC0tYWNjZW50LWRpbTogIzFkNGVkODsKICAgIC0tZGFuZ2VyOiAjZWY0NDQ0OwogICAgLS1zdWNjZXNzOiAjMjJjNTVlOwogICAgLS1yYWRpdXM6IDE0cHg7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgYm9keSB7CiAgICBtYXJnaW46IDA7CiAgICBtaW4taGVpZ2h0OiAxMDB2aDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKICAgIHBhZGRpbmctYm90dG9tOiA2cmVtOwogIH0KICBoZWFkZXIgewogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gMXJlbTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICB9CiAgaDEgeyBmb250LXNpemU6IDEuM3JlbTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC45cmVtOyBtYXJnaW46IDA7IH0KCiAgLnRhYnMgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgfQogIC50YWItYnRuIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDExMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnRhYi1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KCiAgLyogU3VyIHBldGl0IMOpY3JhbiwgbGEgYmFycmUgZCdvbmdsZXRzIGRldmllbnQgdW4gdGlyb2lyIChtZW51ICJidXJnZXIiKQogICAgIHBsdXTDtHQgcXVlIGRlIHMnw6ljcmFzZXIgZW4gcGx1c2lldXJzIGxpZ25lcyA6IHBsdXMgZGUgcGxhY2UgcG91ciBsZQogICAgIGNvbnRlbnUsIGV0IGRlcyBsaWJlbGzDqXMgdG91am91cnMgbGlzaWJsZXMgZW4gZW50aWVyLiAqLwogIC5tZW51LXRvZ2dsZS1idG4gewogICAgZGlzcGxheTogbm9uZTsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDFyZW07CiAgICB6LWluZGV4OiAzMDsKICAgIHdpZHRoOiA0MnB4OwogICAgaGVpZ2h0OiA0MnB4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS4ycmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAubmF2LWRyYXdlci1iYWNrZHJvcCB7CiAgICBkaXNwbGF5OiBub25lOwogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgei1pbmRleDogMjU7CiAgfQogIEBtZWRpYSAobWF4LXdpZHRoOiA2NDBweCkgewogICAgLm1lbnUtdG9nZ2xlLWJ0biB7IGRpc3BsYXk6IGZsZXg7IH0KICAgIGhlYWRlciB7IHBhZGRpbmctbGVmdDogMy43NXJlbTsgfQogICAgLnRhYnMgewogICAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICAgIHRvcDogMDsKICAgICAgbGVmdDogMDsKICAgICAgYm90dG9tOiAwOwogICAgICBmbGV4LXdyYXA6IG5vd3JhcDsKICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgICAgd2lkdGg6IDI0MHB4OwogICAgICBtYXgtd2lkdGg6IDgwdnc7CiAgICAgIG1hcmdpbjogMDsKICAgICAgcGFkZGluZzogNC41cmVtIDFyZW0gMS41cmVtOwogICAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgICAgYm9yZGVyLXJpZ2h0OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgICAgei1pbmRleDogMjY7CiAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtMTAwJSk7CiAgICAgIHRyYW5zaXRpb246IHRyYW5zZm9ybSAwLjJzIGVhc2U7CiAgICAgIG92ZXJmbG93LXk6IGF1dG87CiAgICB9CiAgICAudGFiLWJ0biB7IGZsZXg6IG5vbmU7IHdpZHRoOiAxMDAlOyB0ZXh0LWFsaWduOiBsZWZ0OyB9CiAgICBib2R5Lm5hdi1kcmF3ZXItb3BlbiAudGFicyB7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgwKTsgfQogICAgYm9keS5uYXYtZHJhd2VyLW9wZW4gLm5hdi1kcmF3ZXItYmFja2Ryb3AgeyBkaXNwbGF5OiBibG9jazsgfQogIH0KCiAgLnN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTAwcHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC45cmVtIDFyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAwLjI1cmVtOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUucG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b29sdGlwLWhvc3QgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGN1cnNvcjogaGVscDsgfQogIC5jdXN0b20tdG9vbHRpcCB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiA1MCU7CiAgICBib3R0b206IGNhbGMoMTAwJSArIDAuNnJlbSk7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg0cHgpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41NXJlbSAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB0ZXh0LWFsaWduOiBsZWZ0OwogICAgYm94LXNoYWRvdzogMCA4cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMzUpOwogICAgb3BhY2l0eTogMDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwogICAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjEycyBlYXNlLCB0cmFuc2Zvcm0gMC4xMnMgZWFzZTsKICAgIHotaW5kZXg6IDIwOwogIH0KICAuY3VzdG9tLXRvb2x0aXA6OmFmdGVyIHsKICAgIGNvbnRlbnQ6ICIiOwogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxMDAlOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYm9yZGVyOiA2cHggc29saWQgdHJhbnNwYXJlbnQ7CiAgICBib3JkZXItdG9wLWNvbG9yOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KICAuY3VzdG9tLXRvb2x0aXAudmlzaWJsZSB7CiAgICBvcGFjaXR5OiAxOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoMCk7CiAgICBwb2ludGVyLWV2ZW50czogYXV0bzsKICB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLndlZWstc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAtMC40cmVtIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQoKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxLjFyZW07CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudC1kaW0pOwogIH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gcCB7IG1hcmdpbjogMCAwIDAuN3JlbTsgZm9udC1zaXplOiAwLjg4cmVtOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBzZWxlY3QsCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idG4tcHJpbWFyeS1zbSwgLmJ0bi1zZWNvbmRhcnktc20gewogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuOHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KICAuYnRuLXNlY29uZGFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1yZWN1cnJpbmctYmFkZ2UgeyBmb250LXNpemU6IDAuNzVyZW07IG9wYWNpdHk6IDAuNzsgY3Vyc29yOiBoZWxwOyB9CiAgLnR4LXJlY2VpcHQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjc1cmVtOwogICAgb3BhY2l0eTogMC44NTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBwYWRkaW5nOiAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CgogIC8qIFPDqWxlY3RldXIgZHUgdGFibGVhdSBkZSBib3JkIDogdW4gc2V1bCBncmFwaGlxdWUvYmxvYyBhZmZpY2jDqSDDoCBsYSBmb2lzCiAgICAgKGF1IGxpZXUgZGVzIDcgZW1waWzDqXMpLCBjaG9pc2kgdmlhIHVuZSByYW5nw6llIGRlIHB1Y2VzIGTDqWZpbGFudGUuICovCiAgLmRhc2hib2FyZC1jaGlwLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjVyZW07CiAgICBvdmVyZmxvdy14OiBhdXRvOwogICAgcGFkZGluZy1ib3R0b206IDAuMjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogICAgLXdlYmtpdC1vdmVyZmxvdy1zY3JvbGxpbmc6IHRvdWNoOwogIH0KICAuZGFzaGJvYXJkLWNoaXAtcm93Ojotd2Via2l0LXNjcm9sbGJhciB7IGhlaWdodDogNHB4OyB9CiAgLmRhc2hib2FyZC1jaGlwIHsKICAgIGZsZXg6IG5vbmU7CiAgICBwYWRkaW5nOiAwLjVyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5kYXNoYm9hcmQtY2hpcC5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIC5kYXNoYm9hcmQtcm93LmRhc2gtaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQoKICAueWVhcmx5LXN1bW1hcnkgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogIH0KICAueWVhcmx5LXN0YXQgewogICAgZmxleDogMTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuN3JlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjJyZW07CiAgfQogIC55ZWFybHktc3RhdC1sYWJlbCB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC55ZWFybHktc3RhdC12YWx1ZSB7IGZvbnQtc2l6ZTogMS4wNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC55ZWFybHktc3RhdC12YWx1ZS5leHBlbnNlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnVwY29taW5nLW5vdGUgewogICAgd2lkdGg6IDk2cHg7CiAgICBmbGV4LXNocmluazogMDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC40cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjI1OwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CiAgLnVwY29taW5nLW5vdGUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1zd2F0Y2ggewogICAgd2lkdGg6IDI4cHg7CiAgICBoZWlnaHQ6IDE0cHg7CiAgICBib3JkZXI6IDEuNXB4IGRhc2hlZCB2YXIoLS1kYW5nZXIpOwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICB9CiAgLnVwY29taW5nLW5vdGUucG9zaXRpdmUgLnVwY29taW5nLXN3YXRjaCB7CiAgICBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOwogICAgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4yKTsKICB9CgogIC5yZWN1cnJpbmctc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjdXJyaW5nLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLmV4cG9ydC1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5leHBvcnQtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KCiAgLmV4cG9ydC1mb3JtYXQtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuNzVyZW07IH0KICAuZXhwb3J0LWZvcm1hdC1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmV4cG9ydC1mb3JtYXQtYnRuLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CgogIC8qIEltcG9ydCBkZSByZWxldsOpIGJhbmNhaXJlICovCiAgLmltcG9ydC1maWxlLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmltcG9ydC1maWxlLXJvdyBpbnB1dFt0eXBlPSJmaWxlIl0geyBmbGV4OiAxOyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5pbXBvcnQtZHJvcHpvbmUgewogICAgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41cmVtIDAuNzVyZW0gMC43NXJlbTsKICB9CiAgLmltcG9ydC1kcm9wem9uZS5kcmFnLW92ZXIgeyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjA4KTsgfQogIC5pbXBvcnQtZHJvcHpvbmUtaGludCB7IG1hcmdpbjogMC40cmVtIDAgMDsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB0ZXh0LWFsaWduOiBjZW50ZXI7IH0KICAuaW1wb3J0LXN1bW1hcnkgewogICAgbWFyZ2luOiAwLjlyZW0gMDsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjlyZW07CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgfQogIC5pbXBvcnQtc3VtbWFyeSBzdHJvbmcgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaW1wb3J0LXByZXZpZXcgeyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmltcG9ydC1wcmV2aWV3LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuaW1wb3J0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC42cmVtOwogICAgcGFkZGluZzogMC42cmVtIDA7CiAgICBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICB9CiAgLmltcG9ydC1yb3cuZXhjbHVkZWQgeyBvcGFjaXR5OiAwLjQ1OyB9CiAgLmltcG9ydC1yb3ctbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC5pbXBvcnQtcm93LWRlc2MgeyBmb250LXNpemU6IDAuODhyZW07IGZvbnQtd2VpZ2h0OiA1MDA7IH0KICAuaW1wb3J0LXJvdy1kZXNjIC5pbXBvcnQtcm93LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAuaW1wb3J0LXJvdy1kZXNjIC5pbXBvcnQtcm93LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuaW1wb3J0LXJvdy1tZXRhIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW4tdG9wOiAwLjFyZW07IH0KICAuaW1wb3J0LXJvdy1kdXAgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5pbXBvcnQtcm93IHNlbGVjdCB7IGZvbnQtc2l6ZTogMC44cmVtOyBtYXgtd2lkdGg6IDEzMHB4OyB9CiAgLmltcG9ydC1hY3Rpb25zLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIG1hcmdpbjogMC43NXJlbSAwOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogIH0KICAuaW1wb3J0LWFjdGlvbnMtcm93IGJ1dHRvbiB7IGJhY2tncm91bmQ6IG5vbmU7IGJvcmRlcjogbm9uZTsgY29sb3I6IHZhcigtLWFjY2VudCk7IGN1cnNvcjogcG9pbnRlcjsgZm9udC1zaXplOiAwLjgycmVtOyBwYWRkaW5nOiAwOyB9CgogIC8qIFNpbXVsYXRpb24gZGUgcGxhY2VtZW50ICjDqXBhcmduZSkgKi8KICAucGxhY2VtZW50LWlucHV0cyB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyIDFmcjsgZ2FwOiAwLjc1cmVtOyBtYXJnaW4tYm90dG9tOiAxcmVtOyB9CiAgLnBsYWNlbWVudC1pbnB1dHMgbGFiZWwgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjI1cmVtOyB9CiAgLnBsYWNlbWVudC1yZXN1bHQgewogICAgbWFyZ2luLXRvcDogMC45cmVtOwogICAgcGFkZGluZzogMC44cmVtIDAuOXJlbTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg4cmVtOwogIH0KICAucGxhY2VtZW50LXJlc3VsdCBzdHJvbmcgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc2F2aW5ncy1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5zYXZpbmdzLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5idWRnZXRzLXNhdmUtcm93IHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBmbGV4LWVuZDsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5zYXZpbmdzLWdvYWwtcm93IHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuc2F2aW5ncy1nb2FsLXJvdyBpbnB1dCB7IGZsZXg6IDE7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXJnaW46IDAuOHJlbSAwIDAuMzVyZW07CiAgfQogIC5zYXZpbmdzLXByb2dyZXNzLWxhYmVsIHN0cm9uZyB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuYWR2aWNlLWxpc3QgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgLmFkdmljZS1jYXJkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjdyZW0gMC44NXJlbTsKICAgIGZvbnQtc2l6ZTogMC45cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNDsKICB9CiAgLmFkdmljZS1jYXJkIC5hZHZpY2UtaWNvbiB7IGZvbnQtc2l6ZTogMS4xcmVtOyBmbGV4LXNocmluazogMDsgfQogIC5hZHZpY2UtY2FyZC5wb3NpdGl2ZSB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tc3VjY2Vzcyk7IH0KICAuYWR2aWNlLWNhcmQud2FybmluZyB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgI2Y1OWUwYjsgfQogIC5hZHZpY2UtY2FyZC5pbmZvIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1hY2NlbnQpOyB9CiAgLnJlY3VycmluZy1oaW50IHsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW46IDAgMCAwLjlyZW07CiAgfQoKICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjhyZW0gMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgaDQgeyBtYXJnaW46IDAgMCAwLjZyZW07IGZvbnQtc2l6ZTogMC45cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBiYXNlbGluZTsKICAgIHBhZGRpbmc6IDAuMzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgKyAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLm5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuZHVlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjc4cmVtOyBtYXJnaW4tbGVmdDogMC40cmVtOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuY29tcGFyZS1zZWxlY3RzIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjZyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc2VsZWN0IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40NXJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc3BhbiB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQoKICAuc2ltcGxlLXRhYmxlIHsgd2lkdGg6IDEwMCU7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQogIC5zaW1wbGUtdGFibGUgdGgsIC5zaW1wbGUtdGFibGUgdGQgeyBwYWRkaW5nOiAwLjVyZW0gMC42cmVtOyB0ZXh0LWFsaWduOiByaWdodDsgfQogIC5zaW1wbGUtdGFibGUgdGg6Zmlyc3QtY2hpbGQsIC5zaW1wbGUtdGFibGUgdGQ6Zmlyc3QtY2hpbGQgeyB0ZXh0LWFsaWduOiBsZWZ0OyB9CiAgLnNpbXBsZS10YWJsZSB0aGVhZCB0aCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtd2VpZ2h0OiA1MDA7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSB0Ym9keSB0ciArIHRyIHRkIHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyLnRvdGFsLXJvdyB0ZCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGJvcmRlci10b3A6IDJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zaW1wbGUtdGFibGUgLmRpZmYtbmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50cmVuZC11cCB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLWRvd24geyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHJlbmQtZmxhdCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KCiAgLmJ1ZGdldC1yb3cgeyBtYXJnaW4tYm90dG9tOiAwLjlyZW07IH0KICAuYnVkZ2V0LXJvdy1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjVyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjM1cmVtOwogIH0KICAuYnVkZ2V0LWNhdC1uYW1lIHsgY29sb3I6IHZhcigtLXRleHQpOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLmJ1ZGdldC1hbW91bnRzIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWlucHV0IHsKICAgIHdpZHRoOiA2NHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA2cHg7CiAgICBwYWRkaW5nOiAwLjI1cmVtIDAuNHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmJ1ZGdldC1iYXItdHJhY2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgaGVpZ2h0OiA4cHg7IG92ZXJmbG93OiBoaWRkZW47IH0KICAuYnVkZ2V0LWJhci1maWxsIHsgaGVpZ2h0OiAxMDAlOyBib3JkZXItcmFkaXVzOiA5OTlweDsgdHJhbnNpdGlvbjogd2lkdGggMC4ycyBlYXNlOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vayB7IGJhY2tncm91bmQ6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5idWRnZXQtYmFyLWZpbGwub3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IH0KICAuYnVkZ2V0LWhpc3Rvcnktc3RyaXAgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDRweDsgbWFyZ2luLXRvcDogMC40cmVtOyB9CiAgLmhpc3RvcnktZG90IHsKICAgIGZsZXg6IDE7CiAgICBoZWlnaHQ6IDZweDsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmhpc3RvcnktZG90Lm9rIHsgYmFja2dyb3VuZDogdmFyKC0tc3VjY2Vzcyk7IH0KICAuaGlzdG9yeS1kb3Qud2FybmluZyB7IGJhY2tncm91bmQ6ICNmNTllMGI7IH0KICAuaGlzdG9yeS1kb3Qub3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IH0KICAuaGlzdG9yeS1kb3QuZW1wdHkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBvcGFjaXR5OiAwLjU7IH0KICAucmVjLWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1hY2NlbnQpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC42cmVtOwogIH0KICAucmVjLWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnJlYy1jYXJkLmluY29tZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtY2FyZC5lbmRlZCB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG9wYWNpdHk6IDAuNjsgfQogIC5yZWMtbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC5yZWMtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IGZsZXgtd3JhcDogd3JhcDsgfQogIC5yZWMtbmFtZSB7IGZvbnQtc2l6ZTogMC45NXJlbTsgb3ZlcmZsb3c6IGhpZGRlbjsgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLXN1YiB7IGZvbnQtc2l6ZTogMC43OHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5lbmQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7CiAgICBjb2xvcjogI2ZjYTVhNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5zdGFydC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4xNSk7CiAgICBjb2xvcjogIzkzYzVmZDsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5yZWMtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuZmFiIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiAxLjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogICAgY29sb3I6IHdoaXRlOwogICAgZm9udC1zaXplOiAxLjhyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSg1OSwgMTMwLCAyNDYsIDAuNCk7CiAgfQogIC5mYWI6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQoKICAuZmFiLW1pYyB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogNS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDAsIDAsIDAsIDAuMyk7CiAgICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAuMnMsIGJvcmRlci1jb2xvciAwLjJzOwogIH0KICAuZmFiLW1pYzphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CiAgLmZhYi1taWMubGlzdGVuaW5nIHsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7CiAgICBhbmltYXRpb246IHB1bHNlIDEuMnMgaW5maW5pdGU7CiAgfQogIC5mYWItbWljLnByb2Nlc3NpbmcgeyBvcGFjaXR5OiAwLjY7IGN1cnNvcjogZGVmYXVsdDsgfQogIC5mYWItbWljOmRpc2FibGVkIHsgb3BhY2l0eTogMC4zNTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQogIEBrZXlmcmFtZXMgcHVsc2UgewogICAgMCUsIDEwMCUgeyBib3gtc2hhZG93OiAwIDAgMCAwIHJnYmEoMjM5LCA2OCwgNjgsIDAuNCk7IH0KICAgIDUwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDEwcHggcmdiYSgyMzksIDY4LCA2OCwgMCk7IH0KICB9CgogIC52b2ljZS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTU7CiAgfQogIC52b2ljZS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC52b2ljZS1iYW5uZXIuYW5zd2VyIHsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LXdlaWdodDogNjAwOyBsaW5lLWhlaWdodDogMS40OyB9CgogIC52b2ljZS1jb25maXJtLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYWNjZW50LCAjNGE3ZGZmKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjc1cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE2OwogIH0KICAudm9pY2UtY29uZmlybS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC52b2ljZS1jb25maXJtLWJhbm5lciBwIHsgbWFyZ2luOiAwIDAgMC42cmVtOyBsaW5lLWhlaWdodDogMS40OyB9CiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyIC52b2ljZS1jb25maXJtLWhpbnQgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC52b2ljZS1jb25maXJtLWNvbnRyb2xzIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IGp1c3RpZnktY29udGVudDogY2VudGVyOyB9CgogIC5tb2RhbC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogZmxleC1lbmQ7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwOwogIH0KICAubW9kYWwtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgI2lucHV0LW5ldy1jYXRlZ29yeS1uYW1lLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubW9kYWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXItcmFkaXVzOiAxOHB4IDE4cHggMCAwOwogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gY2FsYygxLjVyZW0gKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpOwogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuOXJlbTsKICB9CiAgLm1vZGFsIGgyIHsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC1zaXplOiAxLjFyZW07IH0KCiAgbGFiZWwgeyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuM3JlbTsgfQogIGlucHV0LCBzZWxlY3QgewogICAgd2lkdGg6IDEwMCU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjY1cmVtIDAuNzVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIGlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IH0KCiAgLnR5cGUtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IH0KICAudHlwZS1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNjVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImV4cGVuc2UiXSB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImluY29tZSJdIHsgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQoKICAubW9kYWwtYWN0aW9ucyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuY29uZmlybS1tb2RhbCB7IG1heC13aWR0aDogNDAwcHg7IH0KICAuY29uZmlybS1tb2RhbC1tZXNzYWdlIHsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LXNpemU6IDAuOTVyZW07IG1hcmdpbjogMDsgbGluZS1oZWlnaHQ6IDEuNDsgfQoKICAuaGlkZGVuLWZpbGUtaW5wdXQgeyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY2VpcHQtcHJldmlldy13cmFwIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjVyZW07CiAgICBhbGlnbi1pdGVtczogZmxleC1zdGFydDsKICAgIG1hcmdpbi1ib3R0b206IDAuNXJlbTsKICB9CiAgLnJlY2VpcHQtcHJldmlldy1pbWcgewogICAgbWF4LXdpZHRoOiAxMDAlOwogICAgbWF4LWhlaWdodDogMTYwcHg7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIG9iamVjdC1maXQ6IGNvbnRhaW47CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KCiAgLmxpZ2h0Ym94LW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuODUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDIwOwogICAgcGFkZGluZzogMS41cmVtOwogIH0KICAubGlnaHRib3gtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxpZ2h0Ym94LWltZyB7IG1heC13aWR0aDogMTAwJTsgbWF4LWhlaWdodDogODB2aDsgYm9yZGVyLXJhZGl1czogMTBweDsgfQogIC5saWdodGJveC1jbG9zZSB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDFyZW07CiAgICByaWdodDogMXJlbTsKICAgIHdpZHRoOiA0MHB4OwogICAgaGVpZ2h0OiA0MHB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS4xcmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSwgYnV0dG9uLnNlY29uZGFyeSB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC43NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIGJ1dHRvbi5wcmltYXJ5OmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CiAgYnV0dG9uLnNlY29uZGFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIGJ1dHRvbi5kYW5nZXIgeyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgY29sb3I6IHZhcigtLWRhbmdlcik7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWRhbmdlcik7IH0KICBidXR0b24uZGFuZ2VyOmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CgogIC5kYW5nZXItem9uZSB7CiAgICBib3JkZXItY29sb3I6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMzUpICFpbXBvcnRhbnQ7CiAgfQogIC5kYW5nZXItem9uZSBoMyB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b2FzdCB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHotaW5kZXg6IDIwOwogICAgbWF4LXdpZHRoOiA5MHZ3OwogIH0KICAudG9hc3QuZXJyb3IgeyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmNhNWE1OyB9CgogIC5sb2NrLXNjcmVlbiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5sb2NrLXNjcmVlbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxvY2stY2FyZCB7IG1heC13aWR0aDogMzIwcHg7IHdpZHRoOiAxMDAlOyB0ZXh0LWFsaWduOiBjZW50ZXI7IH0KICAubG9jay1lbW9qaSB7IGZvbnQtc2l6ZTogM3JlbTsgbWFyZ2luLWJvdHRvbTogMC41cmVtOyB9CiAgLmxvY2stY2FyZCBoMSB7IG1hcmdpbjogMCAwIDAuNXJlbTsgfQogIC5sb2NrLWNhcmQgcCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDEuMjVyZW07IGZvbnQtc2l6ZTogMC45cmVtOyB9CiAgLmxvY2stY2FyZCBpbnB1dCB7CiAgICB3aWR0aDogMTAwJTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLmxvY2stZXJyb3IgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgZm9udC1zaXplOiAwLjg1cmVtOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmxvY2stZXJyb3IuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogIDxkaXYgY2xhc3M9ImxvY2stc2NyZWVuIGhpZGRlbiIgaWQ9ImxvY2stc2NyZWVuIj4KICAgIDxkaXYgY2xhc3M9ImxvY2stY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImxvY2stZW1vamkiPvCfkrA8L2Rpdj4KICAgICAgPGgxPkthY2hpbmc8L2gxPgogICAgICA8cD5FbnRyZSBsZSBtb3QgZGUgcGFzc2UgcG91ciBhY2PDqWRlciDDoCB0ZXMgZG9ubsOpZXMuPC9wPgogICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJsb2NrLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlIiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiPgogICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InByaW1hcnkiIGlkPSJsb2NrLXVubG9jay1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+RMOpdmVycm91aWxsZXI8L2J1dHRvbj4KICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ibG9jay1lcnJvciI+PC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgaWQ9ImFwcC1yb290IiBoaWRkZW4+CiAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJtZW51LXRvZ2dsZS1idG4iIGlkPSJtZW51LXRvZ2dsZS1idG4iIGFyaWEtbGFiZWw9Ik91dnJpciBsZSBtZW51Ij7imLA8L2J1dHRvbj4KICA8ZGl2IGNsYXNzPSJuYXYtZHJhd2VyLWJhY2tkcm9wIiBpZD0ibmF2LWRyYXdlci1iYWNrZHJvcCI+PC9kaXY+CiAgPGhlYWRlcj4KICAgIDxoMT7wn5KwIEthY2hpbmc8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1zYXZpbmdzIiBkYXRhLXZpZXc9InNhdmluZ3MiPsOJcGFyZ25lPC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtY2hpcC1yb3ciIGlkPSJkYXNoYm9hcmQtY2hpcC1yb3ciPjwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWV4cGVuc2VzIj4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1pbmNvbWUiPgogICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIHJldmVudXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW4gcmV2ZW51IGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1idWRnZXRzIj4KICAgICAgICA8aDM+QnVkZ2V0cyBtZW5zdWVscyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEluZGlxdWUgdW4gbW9udGFudCBwb3VyIHVuZSBjYXTDqWdvcmllIGV0IGVucmVnaXN0cmUgYXZlYyDwn5K+IOKAlCBsYSBiYXJyZQogICAgICAgICAgY29tcGFyZSBlbnN1aXRlIHRlcyBkw6lwZW5zZXMgZHUgbW9pcyBlbiBjb3VycyDDoCBjZSBwbGFmb25kICh2ZXJ0LAogICAgICAgICAgb3JhbmdlIGF1LWRlbMOgIGRlIDcwJSwgcm91Z2UgYXUtZGVsw6AgZGUgMTAwJSkuIExhIHBldGl0ZSByYW5nw6llIGRlCiAgICAgICAgICBiYXJyZXMgZW4gZGVzc291cyBtb250cmUgbCdoaXN0b3JpcXVlIGRlcyA2IGRlcm5pZXJzIG1vaXMgKHN1cnZvbGUKICAgICAgICAgIG91IHRvdWNoZSB1bmUgYmFycmUgcG91ciB2b2lyIGxlIGTDqXRhaWwpLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJidWRnZXRzLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldHMtc2F2ZS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iaWNvbi1idG4iIGlkPSJidWRnZXRzLXNhdmUtYWxsLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgdG91cyBsZXMgYnVkZ2V0cyI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1ldm9sdXRpb24iPgogICAgICAgIDxoMz7DiXZvbHV0aW9uIG1lbnN1ZWxsZSAoZMOpcGVuc2VzIHZzIHJldmVudXMpPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWV2b2x1dGlvbiI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0iZGFzaC1yb3ctY29tcGFyZSI+CiAgICAgICAgPGgzPkNvbXBhcmVyIGRldXggbW9pczwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY29tcGFyZS1zZWxlY3RzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYSI+PC9zZWxlY3Q+CiAgICAgICAgICA8c3Bhbj52czwvc3Bhbj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYiI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgYXNzZXogZGUgbW9pcyBkaWZmw6lyZW50cyBwb3VyIGNvbXBhcmVyLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy10cmVuZCI+CiAgICAgICAgPGgzPk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgaWQ9InRyZW5kLXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InRyZW5kLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy15ZWFybHkiPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5CaWxhbiBhbm51ZWw8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0ieWVhcmx5LXllYXItc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3VtbWFyeSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+RMOpcGVuc2VzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWV4cGVuc2VzIiBjbGFzcz0ieWVhcmx5LXN0YXQtdmFsdWUgZXhwZW5zZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+UmV2ZW51czwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS10b3RhbC1pbmNvbWUiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBpbmNvbWUiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN0YXQiPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ieWVhcmx5LXN0YXQtbGFiZWwiPlNvbGRlIG5ldDwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS1uZXQiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC15ZWFybHkiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGRlIGRvbm7DqWVzIHBvdXIgY2V0dGUgYW5uw6llLgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIiBjbGFzcz0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGhpZGRlbiI+CiAgICAgICAgPGg0PlByb2NoYWluZXMgw6ljaMOpYW5jZXM8L2g0PgogICAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1lbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgQXVjdW5lIGTDqXBlbnNlIHLDqWN1cnJlbnRlIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZXhwb3J0IiBjbGFzcz0iZXhwb3J0LXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+RXhwb3J0ZXIgdGVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJleHBvcnQtZm9ybWF0LXRvZ2dsZSIgaWQ9ImV4cG9ydC1mb3JtYXQtdG9nZ2xlIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZXhwb3J0LWZvcm1hdC1idG4gYWN0aXZlIiBkYXRhLWZvcm1hdD0ieGxzeCI+RXhjZWwgKC54bHN4KTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJleHBvcnQtZm9ybWF0LWJ0biIgZGF0YS1mb3JtYXQ9Impzb24iPlNhdXZlZ2FyZGUgY29tcGzDqHRlIChKU09OKTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCIgaWQ9ImV4cG9ydC1mb3JtYXQtaGludCI+CiAgICAgICAgICBUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQtZG93bmxvYWQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnRlciB1biByZWxldsOpIGJhbmNhaXJlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciBsJ2luc3RhbnQsIHVuaXF1ZW1lbnQgbCdleHBvcnQgQ1NWIMKrIGV4cG9ydC1vcGVyYXRpb25zLi4uIMK7IGRlCiAgICAgICAgICBCb3Vyc29CYW5rLiBMZXMgbW9udGFudHMsIGRhdGVzIGV0IGRlc2NyaXB0aW9ucyBzb250IGFuYWx5c8OpcyBpY2kKICAgICAgICAgIG3Dqm1lIChyaWVuIG4nZXN0IGVudm95w6kgYWlsbGV1cnMpIDsgdHUgY2hvaXNpcyBlbnN1aXRlIGxpZ25lIHBhcgogICAgICAgICAgbGlnbmUgcXVvaSBpbXBvcnRlciBhdmFudCB0b3V0ZSDDqWNyaXR1cmUgZW4gYmFzZS4gTGUgbnVtw6lybyBkZQogICAgICAgICAgY29tcHRlIG4nZXN0IGphbWFpcyBsdS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWRyb3B6b25lIiBpZD0iaW1wb3J0LWRyb3B6b25lIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1maWxlLXJvdyI+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iaW1wb3J0LWZpbGUtaW5wdXQiIGFjY2VwdD0iLmNzdix0ZXh0L2NzdiI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJpbXBvcnQtYW5hbHl6ZS1idG4iPkFuYWx5c2VyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJpbXBvcnQtZHJvcHpvbmUtaGludCI+b3UgZ2xpc3NlLWTDqXBvc2UgbGUgZmljaGllciAuY3N2IGljaTwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJpbXBvcnQtc3VtbWFyeSIgY2xhc3M9ImltcG9ydC1zdW1tYXJ5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXByZXZpZXciIGNsYXNzPSJpbXBvcnQtcHJldmlldyBoaWRkZW4iPgogICAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWFjdGlvbnMtcm93Ij4KICAgICAgICAgICAgPHNwYW4gaWQ9ImltcG9ydC1zZWxlY3RlZC1jb3VudCI+PC9zcGFuPgogICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9ImltcG9ydC10b2dnbGUtYWxsLWJ0biI+VG91dCBjb2NoZXIgLyBkw6ljb2NoZXI8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXJvd3MtbGlzdCI+PC9kaXY+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iaW1wb3J0LWNvbW1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyBtYXJnaW4tdG9wOjAuNzVyZW07Ij5JbXBvcnRlciBsYSBzw6lsZWN0aW9uPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyBkYW5nZXItem9uZSI+CiAgICAgICAgPGgzPuKaoO+4jyBab25lIGRhbmdlcmV1c2U8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBTdXBwcmltZSBkw6lmaW5pdGl2ZW1lbnQgVE9VVEVTIGxlcyBkb25uw6llcyA6IHRyYW5zYWN0aW9ucywgY2hhcmdlcwogICAgICAgICAgcsOpY3VycmVudGVzLCBjYXTDqWdvcmllcyBwZXJzb25uYWxpc8OpZXMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcywKICAgICAgICAgIGJ1ZGdldHMsIHBob3RvcyBkZSByZcOndXMgZXQgb2JqZWN0aWYgZCfDqXBhcmduZS4gUGVuc2Ugw6AgZXhwb3J0ZXIgZW4KICAgICAgICAgIEV4Y2VsIGF2YW50IHNpIGJlc29pbiDigJQgaW1wb3NzaWJsZSDDoCBhbm51bGVyLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJkYW5nZXIiIGlkPSJidG4tcmVzZXQtYWxsIiBzdHlsZT0id2lkdGg6MTAwJTsiPlLDqWluaXRpYWxpc2VyIHRvdXRlIGwnYXBwbGljYXRpb248L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctc2F2aW5ncyIgY2xhc3M9InNhdmluZ3Mtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5PYmplY3RpZiBkJ8OpcGFyZ25lIG1lbnN1ZWw8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBMZSBtb250YW50IHF1ZSB0dSB2ZXV4IGdhcmRlciBkZSBjw7R0w6kgY2hhcXVlIG1vaXMgKHJldmVudXMgbW9pbnMKICAgICAgICAgIGTDqXBlbnNlcykuIENvbXBhcsOpIMOgIHRvbiBzb2xkZSByw6llbCBkdSBtb2lzIGVuIGNvdXJzLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLWdvYWwtcm93Ij4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJzYXZpbmdzLWdvYWwtaW5wdXQiIG1pbj0iMCIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IkV4IDogMTAwIj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9Imljb24tYnRuIiBpZD0ic2F2aW5ncy1nb2FsLXNhdmUtYnRuIiBhcmlhLWxhYmVsPSJFbnJlZ2lzdHJlciBsJ29iamVjdGlmIj7wn5K+PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wcm9ncmVzcy1zZWN0aW9uIiBjbGFzcz0ic2F2aW5ncy1wcm9ncmVzcyBoaWRkZW4iPgogICAgICAgICAgPGRpdiBjbGFzcz0ic2F2aW5ncy1wcm9ncmVzcy1sYWJlbCI+CiAgICAgICAgICAgIDxzcGFuPlNvbGRlIGR1IG1vaXMgZW4gY291cnM8L3NwYW4+CiAgICAgICAgICAgIDxzdHJvbmcgaWQ9InNhdmluZ3MtcHJvZ3Jlc3MtdGV4dCI+PC9zdHJvbmc+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldC1iYXItdHJhY2siPgogICAgICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXByb2dyZXNzLWJhciIgY2xhc3M9ImJ1ZGdldC1iYXItZmlsbCBvayI+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+Q29uc2VpbHM8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBCYXPDqXMgc3VyIHRlcyBidWRnZXRzIHBhciBjYXTDqWdvcmllIGV0IHRlcyB0ZW5kYW5jZXMgZGUgZMOpcGVuc2VzCiAgICAgICAgICAodm9pciBsJ29uZ2xldCBUYWJsZWF1IGRlIGJvcmQpLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLWFkdmljZS1saXN0IiBjbGFzcz0iYWR2aWNlLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtYWR2aWNlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzIGNlIG1vaXMtY2kgcG91ciB0ZSBkb25uZXIgZGVzIGNvbnNlaWxzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5TaW11bGF0aW9uIGRlIHBsYWNlbWVudDwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFByb2plY3Rpb24gc2kgdHUgcGxhY2VzIHVuZSBzb21tZSBzdXIgdW4gbGl2cmV0IG91IHVuIHBsYWNlbWVudCDDoAogICAgICAgICAgdGF1eCBmaXhlIChpbnTDqXLDqnRzIGNvbXBvc8OpcywgY2FsY3Vsw6lzIG1lbnN1ZWxsZW1lbnQpLiBMZSB0YXV4IHBhcgogICAgICAgICAgZMOpZmF1dCAoMyUpIGNvcnJlc3BvbmQgYXUgTGl2cmV0IEEg4oCUIGNoYW5nZS1sZSBwb3VyIHNpbXVsZXIgdW4KICAgICAgICAgIGF1dHJlIHBsYWNlbWVudC4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LWlucHV0cyI+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtaW5pdGlhbCI+TW9udGFudCBpbml0aWFsICjigqwpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC1pbml0aWFsIiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSI1MDAiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtbW9udGhseSI+VmVyc2VtZW50IG1lbnN1ZWwgKOKCrCk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LW1vbnRobHkiIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IjUwIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXJhdGUiPlRhdXggYW5udWVsICglKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQtcmF0ZSIgbWluPSIwIiBzdGVwPSIwLjEiIHZhbHVlPSIzIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXllYXJzIj5EdXLDqWUgKGFubsOpZXMpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC15ZWFycyIgbWluPSIxIiBzdGVwPSIxIiB2YWx1ZT0iNSI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXBsYWNlbWVudCI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LXJlc3VsdCIgaWQ9InBsYWNlbWVudC1yZXN1bHQiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICA8L21haW4+CgogIDxkaXYgY2xhc3M9InZvaWNlLWJhbm5lciBoaWRkZW4iIGlkPSJ2b2ljZS1iYW5uZXIiPjwvZGl2PgogIDxkaXYgY2xhc3M9InZvaWNlLWNvbmZpcm0tYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWNvbmZpcm0tYmFubmVyIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJmYWItbWljIiBpZD0iZmFiLW1pYyIgYXJpYS1sYWJlbD0iRGljdGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUsIG91IHBvc2VyIHVuZSBxdWVzdGlvbiIgdGl0bGU9IkRpY3RlIHVuZSBkw6lwZW5zZS91biByZXZlbnUsIG91IHBvc2UgdW5lIHF1ZXN0aW9uIChleCA6IMKrIGNvbWJpZW4gaidhaSBkw6lwZW5zw6kgZW4gcmVzdGF1cmFudCBjZSBtb2lzLWNpID8gwrspIj7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dAogICAgICAgICAgdHlwZT0idGV4dCIKICAgICAgICAgIGlkPSJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIKICAgICAgICAgIHBsYWNlaG9sZGVyPSJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIKICAgICAgICAgIGNsYXNzPSJoaWRkZW4iCiAgICAgICAgICBzdHlsZT0ibWFyZ2luLXRvcDogOHB4OyIKICAgICAgICA+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbD5SZcOndSAocGhvdG8sIG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iaW5wdXQtcmVjZWlwdC1maWxlIiBjbGFzcz0iaGlkZGVuLWZpbGUtaW5wdXQiIGFjY2VwdD0iaW1hZ2UvKiIgY2FwdHVyZT0iZW52aXJvbm1lbnQiPgogICAgICAgIDxkaXYgaWQ9InJlY2VpcHQtcHJldmlldy13cmFwIiBjbGFzcz0icmVjZWlwdC1wcmV2aWV3LXdyYXAgaGlkZGVuIj4KICAgICAgICAgIDxpbWcgaWQ9InJlY2VpcHQtcHJldmlldy1pbWciIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctaW1nIiBhbHQ9IlJlw6d1Ij4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcmVtb3ZlIj5TdXBwcmltZXIgbGEgcGhvdG88L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1yZWNlaXB0LXBpY2siIHN0eWxlPSJ3aWR0aDoxMDAlOyI+8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlYy1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJyZWMtbW9kYWwtdGl0bGUiPk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0icmVjLXR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtbmFtZSI+Tm9tPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InJlYy1pbnB1dC1uYW1lIiBwbGFjZWhvbGRlcj0iRXggOiBOZXRmbGl4LCBMb3llciwgU2FsYWlyZS4uLiI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZGF5Ij5Kb3VyIGR1IG1vaXM8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtZGF5IiBtaW49IjEiIG1heD0iMzEiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSIxIMOgIDMxIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPkRhdGUgZGUgZMOpYnV0IChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1zdGFydC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWVuZC1kYXRlIj5EYXRlIGRlIGZpbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtZW5kLWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0icmVjLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVjLWJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0iY29uZmlybS1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIGNvbmZpcm0tbW9kYWwiPgogICAgICA8aDIgaWQ9ImNvbmZpcm0tbW9kYWwtdGl0bGUiPkNvbmZpcm1lcjwvaDI+CiAgICAgIDxwIGlkPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiIGNsYXNzPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiPjwvcD4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iY29uZmlybS1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImNvbmZpcm0tYnRuLW9rIj5Db25maXJtZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibGlnaHRib3gtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LW92ZXJsYXkiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJsaWdodGJveC1jbG9zZSIgaWQ9InJlY2VpcHQtbGlnaHRib3gtY2xvc2UiIGFyaWEtbGFiZWw9IkZlcm1lciI+4pyVPC9idXR0b24+CiAgICA8aW1nIGNsYXNzPSJsaWdodGJveC1pbWciIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LWltZyIgYWx0PSJSZcOndSBlbiBwbGVpbiDDqWNyYW4iPgogIDwvZGl2PgogIDwvZGl2PgoKICA8c2NyaXB0PgogICAgLy8gTGUgamV0b24gZGUgc2Vzc2lvbiAob2J0ZW51IGFwcsOocyBhdm9pciB0YXDDqSBsZSBtb3QgZGUgcGFzc2Ugc3VyIGwnw6ljcmFuCiAgICAvLyBkZSB2ZXJyb3VpbGxhZ2UpIHJlbXBsYWNlIGwnYW5jaWVubmUgY2zDqSBBUEkgY29kw6llIGVuIGR1ciBpY2kg4oCUIGNlbGxlLWNpCiAgICAvLyDDqXRhaXQgdmlzaWJsZSBwYXIgbidpbXBvcnRlIHF1aSB2aWEgIkFmZmljaGVyIGxlIGNvZGUgc291cmNlIiwgc2FucwogICAgLy8gYXVjdW4gbW90IGRlIHBhc3NlLiBMZSBqZXRvbiBlc3Qgc2lnbsOpIGPDtHTDqSBzZXJ2ZXVyIGV0IGV4cGlyZSBhcHLDqHMgOTAKICAgIC8vIGpvdXJzIDsgaWwgbmUgcsOpdsOobGUgcmllbiBkZSBzZWNyZXQgZW4gbHVpLW3Dqm1lLgogICAgY29uc3QgVE9LRU5fU1RPUkFHRV9LRVkgPSAia2FjaGluZ19zZXNzaW9uX3Rva2VuIjsKICAgIGxldCBBUElfS0VZID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oVE9LRU5fU1RPUkFHRV9LRVkpIHx8ICIiOwoKICAgIGNvbnN0IGxvY2tTY3JlZW5FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLXNjcmVlbiIpOwogICAgY29uc3QgYXBwUm9vdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImFwcC1yb290Iik7CiAgICBjb25zdCBsb2NrUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLXBhc3N3b3JkLWlucHV0Iik7CiAgICBjb25zdCBsb2NrVW5sb2NrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stdW5sb2NrLWJ0biIpOwogICAgY29uc3QgbG9ja0Vycm9yRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9jay1lcnJvciIpOwoKICAgIGZ1bmN0aW9uIHNob3dMb2NrU2NyZWVuKCkgewogICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShUT0tFTl9TVE9SQUdFX0tFWSk7CiAgICAgIEFQSV9LRVkgPSAiIjsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IHRydWU7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbG9ja1Bhc3N3b3JkSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbG9ja1Bhc3N3b3JkSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93QXBwKCkgewogICAgICBsb2NrU2NyZWVuRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGFwcFJvb3RFbC5oaWRkZW4gPSBmYWxzZTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhdHRlbXB0VW5sb2NrKCkgewogICAgICBjb25zdCBwYXNzd29yZCA9IGxvY2tQYXNzd29yZElucHV0LnZhbHVlOwogICAgICBpZiAoIXBhc3N3b3JkKSByZXR1cm47CiAgICAgIGxvY2tFcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBsb2NrVW5sb2NrQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbG9ja1VubG9ja0J0bi50ZXh0Q29udGVudCA9ICJWw6lyaWZpY2F0aW9u4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9sb2dpbiIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgaGVhZGVyczogeyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0sCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBhc3N3b3JkIH0pLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKS5jYXRjaCgoKSA9PiAoe30pKTsKICAgICAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLmRldGFpbCB8fCAiTW90IGRlIHBhc3NlIGluY29ycmVjdCIpOwogICAgICAgIH0KICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSwgZGF0YS50b2tlbik7CiAgICAgICAgLy8gUmVjaGFyZ2VtZW50IGNvbXBsZXQgcGx1dMO0dCBxdWUgZGUgcsOpLWVuY2hhw65uZXIgbCdpbml0IG1hbnVlbGxlbWVudCA6CiAgICAgICAgLy8gcGx1cyBzaW1wbGUgZXQgcGx1cyBzw7tyIChvbiByZXBhcnQgYXZlYyB1biDDqXRhdCBwcm9wcmUsIEFQSV9LRVkgbHUKICAgICAgICAvLyBkZXB1aXMgbGUgbG9jYWxTdG9yYWdlIGNvbW1lIGF1IHRvdXQgcHJlbWllciBjaGFyZ2VtZW50KS4KICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIGxvY2tFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2UgfHwgIk1vdCBkZSBwYXNzZSBpbmNvcnJlY3QiOwogICAgICAgIGxvY2tFcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIGxvY2tVbmxvY2tCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBsb2NrVW5sb2NrQnRuLnRleHRDb250ZW50ID0gIkTDqXZlcnJvdWlsbGVyIjsKICAgICAgfQogICAgfQoKICAgIGxvY2tVbmxvY2tCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhdHRlbXB0VW5sb2NrKTsKICAgIGxvY2tQYXNzd29yZElucHV0LmFkZEV2ZW50TGlzdGVuZXIoImtleWRvd24iLCAoZSkgPT4gewogICAgICBpZiAoZS5rZXkgPT09ICJFbnRlciIpIGF0dGVtcHRVbmxvY2soKTsKICAgIH0pOwoKICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eC1saXN0Iik7CiAgICBjb25zdCBlbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHN1bW1hcnlCYWxhbmNlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1iYWxhbmNlIik7CiAgICBjb25zdCBzdW1tYXJ5RXhwZW5zZXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWV4cGVuc2VzIik7CiAgICBjb25zdCBzdW1tYXJ5SW5jb21lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1pbmNvbWUiKTsKCiAgICBjb25zdCBvdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgbW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLXRpdGxlIik7CiAgICBjb25zdCB0eXBlVG9nZ2xlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IGFtb3VudElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWFtb3VudCIpOwogICAgY29uc3QgY2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnkgPSBudWxsOyAvLyBjYXTDqWdvcmllIGRlIGxhIHRyYW5zYWN0aW9uIGF2YW50IMOpZGl0aW9uIChwb3VyIGTDqXRlY3RlciB1biBjaGFuZ2VtZW50KQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBob3RvIGRlIHJlw6d1IGVuIHBpw6hjZSBqb2ludGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IHJlY2VpcHRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtcmVjZWlwdC1maWxlIik7CiAgICBjb25zdCByZWNlaXB0UHJldmlld1dyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LXdyYXAiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtcHJldmlldy1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRQaWNrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZWNlaXB0LXBpY2siKTsKICAgIGNvbnN0IHJlY2VpcHRSZW1vdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcmVtb3ZlIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hPdmVybGF5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjZWlwdExpZ2h0Ym94SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtaW1nIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hDbG9zZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIik7CgogICAgLy8gRmljaGllciBjaG9pc2kgbWFpcyBwYXMgZW5jb3JlIGVudm95w6kgKHVuaXF1ZW1lbnQgZW4gY3LDqWF0aW9uLCB0YW50IHF1ZQogICAgLy8gbGEgdHJhbnNhY3Rpb24gbidhIHBhcyBlbmNvcmUgZCdpZCkgOyBlbiDDqWRpdGlvbiwgbCdlbnZvaSBlc3QgaW1tw6lkaWF0LgogICAgbGV0IHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICBsZXQgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgbGV0IGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNldFJlY2VpcHRQcmV2aWV3RnJvbUJsb2IoYmxvYikgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpOwogICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9IHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgUmVtcGxhY2VyIGxhIHBob3RvIjsKICAgIH0KCiAgICBmdW5jdGlvbiByZXNldFJlY2VpcHRVaSgpIHsKICAgICAgaWYgKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKSB7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgICAgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgICB9CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9ICIiOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3UiOwogICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgIHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgewogICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSByZXR1cm47CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKTsKICAgICAgICBoYXNFeGlzdGluZ1JlY2VpcHQgPSB0cnVlOwogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgLy8gUGFzIGdyYXZlIDogbCd1dGlsaXNhdGV1ciBwZXV0IGp1c3RlIHLDqWVzc2F5ZXIgZCdvdXZyaXIgbGEgZmljaGUuCiAgICAgIH0KICAgIH0KCiAgICByZWNlaXB0UGlja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHJlY2VpcHRGaWxlSW5wdXQuY2xpY2soKSk7CgogICAgcmVjZWlwdEZpbGVJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSByZWNlaXB0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHJldHVybjsKICAgICAgaWYgKCFmaWxlLnR5cGUuc3RhcnRzV2l0aCgiaW1hZ2UvIikpIHsKICAgICAgICBzaG93VG9hc3QoIkNob2lzaXMgdW5lIGltYWdlIChKUEVHLCBQTkcsIFdFQlAgb3UgSEVJQykiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiA4ICogMTAyNCAqIDEwMjQpIHsKICAgICAgICBzaG93VG9hc3QoIkltYWdlIHRyb3AgbG91cmRlICg4IE1vIG1heGltdW0pIiwgdHJ1ZSk7CiAgICAgICAgcmVjZWlwdEZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihmaWxlKTsKCiAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAvLyBUcmFuc2FjdGlvbiBkw6lqw6AgZXhpc3RhbnRlIDogb24gZW52b2llIHRvdXQgZGUgc3VpdGUsIGluZMOpcGVuZGFtbWVudAogICAgICAgIC8vIGR1IGJvdXRvbiAiRW5yZWdpc3RyZXIiIGR1IGZvcm11bGFpcmUuCiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgIH0pLnRoZW4oYXN5bmMgKHJlcykgPT4gewogICAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLmRldGFpbCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWApOwogICAgICAgICAgICB9CiAgICAgICAgICB9KTsKICAgICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgICAgICBzaG93VG9hc3QoIlBob3RvIGR1IHJlw6d1IGVucmVnaXN0csOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICAvLyBOb3V2ZWxsZSB0cmFuc2FjdGlvbiBwYXMgZW5jb3JlIGNyw6nDqWUgOiBvbiBnYXJkZSBsZSBmaWNoaWVyIGRlIGPDtHTDqSwKICAgICAgICAvLyBpbCBzZXJhIGVudm95w6kganVzdGUgYXByw6hzIGxhIGNyw6lhdGlvbiAodm9pciBidG4tc2F2ZSkuCiAgICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gZmlsZTsKICAgICAgfQogICAgfSk7CgogICAgcmVjZWlwdFJlbW92ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgaWYgKGVkaXRpbmdJZCAmJiBoYXNFeGlzdGluZ1JlY2VpcHQpIHsKICAgICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGxhIHBob3RvIGRlIGNlIHJlw6d1ID8iKSkpIHJldHVybjsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gc3VwcHJpbcOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICB9CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjZWlwdExpZ2h0Ym94KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7dHJhbnNhY3Rpb25JZH0vcmVjZWlwdGAsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pCiAgICAgICAgLnRoZW4oKHJlcykgPT4gewogICAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiSW1wb3NzaWJsZSBkZSBjaGFyZ2VyIGxhIHBob3RvIik7CiAgICAgICAgICByZXR1cm4gcmVzLmJsb2IoKTsKICAgICAgICB9KQogICAgICAgIC50aGVuKChibG9iKSA9PiB7CiAgICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9IHVybDsKICAgICAgICAgIHJlY2VpcHRMaWdodGJveE92ZXJsYXkuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgfSkKICAgICAgICAuY2F0Y2goKGVycikgPT4gc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY2VpcHRMaWdodGJveCgpIHsKICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgaWYgKHJlY2VpcHRMaWdodGJveEltZy5zcmMpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRMaWdodGJveEltZy5zcmMpOwogICAgICAgIHJlY2VpcHRMaWdodGJveEltZy5zcmMgPSAiIjsKICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRMaWdodGJveENsb3NlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWNlaXB0TGlnaHRib3gpOwogICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gcmVjZWlwdExpZ2h0Ym94T3ZlcmxheSkgY2xvc2VSZWNlaXB0TGlnaHRib3goKTsKICAgIH0pOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIC8vIENhdMOpZ29yaWVzIGNyw6nDqWVzIHBhciBsJ3V0aWxpc2F0ZXVyIGRlcHVpcyBsZSBiYW5kZWF1IGRlIHN1Z2dlc3Rpb24KICAgIC8vICh2b2lyIHBsdXMgYmFzKSwgZXQgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIDogc3RvY2vDqWVzIGPDtHTDqSBzZXJ2ZXVyCiAgICAvLyAodGFibGVzIGN1c3RvbV9jYXRlZ29yaWVzIC8gZGlzbWlzc2VkX2NhdGVnb3J5X3N1Z2dlc3Rpb25zKSBwbHV0w7R0CiAgICAvLyBxdWUgZGFucyBsZSBuYXZpZ2F0ZXVyLCBwb3VyIHN1aXZyZSBzdXIgdG91cyBsZXMgYXBwYXJlaWxzICh0w6lsw6lwaG9uZSwKICAgIC8vIHRhYmxldHRlLCBvcmRpbmF0ZXVyKSBwbHV0w7R0IHF1ZSBkZSBuZSBtYXJjaGVyIHF1ZSBsw6Agb8O5IGMnw6l0YWl0IGNyw6nDqS4KICAgIGxldCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoKTsKICAgIGxldCBhbGxCdWRnZXRzID0gW107CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEJ1ZGdldHMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgYWxsQnVkZ2V0cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgYnVkZ2V0cyA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9iamVjdGlmIGQnw6lwYXJnbmUgbWVuc3VlbCArIGNvbnNlaWxzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBsZXQgc2F2aW5nc0dvYWwgPSBudWxsOyAvLyB7IG1vbnRobHlfdGFyZ2V0IH0gb3UgbnVsbCBzaSBqYW1haXMgY29uZmlndXLDqQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRTYXZpbmdzR29hbCgpIHsKICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlIGwnb2JqZWN0aWYgZCfDqXBhcmduZSA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGVudHJpZXMgPSBPYmplY3QuZW50cmllcyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KTsKICAgICAgbGV0IHNhdmVkQ291bnQgPSAwOwogICAgICBsZXQgaGFkRXJyb3IgPSBmYWxzZTsKICAgICAgZm9yIChjb25zdCBbY2F0ZWdvcnksIGlucHV0XSBvZiBlbnRyaWVzKSB7CiAgICAgICAgY29uc3QgcmF3ID0gaW5wdXQudmFsdWU7CiAgICAgICAgaWYgKHJhdyA9PT0gIiIgfHwgcmF3ID09PSBudWxsKSBjb250aW51ZTsKICAgICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIocmF3KTsKICAgICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgY29udGludWU7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGF3YWl0IHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCk7CiAgICAgICAgICBzYXZlZENvdW50ICs9IDE7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBoYWRFcnJvciA9IHRydWU7CiAgICAgICAgfQogICAgICB9CiAgICAgIGlmIChoYWRFcnJvcikgewogICAgICAgIHNob3dUb2FzdCgiQ2VydGFpbnMgYnVkZ2V0cyBuJ29udCBwYXMgcHUgw6p0cmUgZW5yZWdpc3Ryw6lzIiwgdHJ1ZSk7CiAgICAgIH0gZWxzZSBpZiAoc2F2ZWRDb3VudCA9PT0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSBhdSBtb2lucyB1biBtb250YW50IGRlIGJ1ZGdldCB2YWxpZGUiLCB0cnVlKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBzaG93VG9hc3QoIkJ1ZGdldHMgZW5yZWdpc3Ryw6lzIik7CiAgICAgIH0KICAgICAgcmVuZGVyQnVkZ2V0cyhhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgY29uc3Qgc2F2aW5nc0dvYWxJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtaW5wdXQiKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gTnVtYmVyKHNhdmluZ3NHb2FsSW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSB1biBtb250YW50IGQnb2JqZWN0aWYgdmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgc2F2aW5nc0dvYWwgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9zYXZpbmdzLWdvYWwiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb250aGx5X3RhcmdldDogYW1vdW50IH0pLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdCgiT2JqZWN0aWYgZW5yZWdpc3Ryw6kiKTsKICAgICAgICByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3ModHJhbnNhY3Rpb25zKSB7CiAgICAgIGlmIChzYXZpbmdzR29hbCkgc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwoKICAgICAgLy8gU29sZGUgZHUgbW9pcyBlbiBjb3VycyAocmV2ZW51cyAtIGTDqXBlbnNlcyksIHRvdXQgY29uZm9uZHUuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGxldCBtb250aEluY29tZSA9IDA7CiAgICAgIGxldCBtb250aEV4cGVuc2VzID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBjdXJyZW50TW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgbW9udGhJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSBtb250aEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRoTmV0ID0gbW9udGhJbmNvbWUgLSBtb250aEV4cGVuc2VzOwoKICAgICAgY29uc3QgcHJvZ3Jlc3NTZWN0aW9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIpOwogICAgICBjb25zdCBwcm9ncmVzc1RleHQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy10ZXh0Iik7CiAgICAgIGNvbnN0IHByb2dyZXNzQmFyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtYmFyIik7CiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgY29uc3QgdGFyZ2V0ID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CiAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5tYXgoMCwgTWF0aC5taW4oKG1vbnRoTmV0IC8gdGFyZ2V0KSAqIDEwMCwgMTAwKSk7CiAgICAgICAgcHJvZ3Jlc3NUZXh0LnRleHRDb250ZW50ID0gYCR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0YXJnZXQpfWA7CiAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgaWYgKG1vbnRoTmV0IDwgMCkgY2xzID0gIm92ZXIiOwogICAgICAgIGVsc2UgaWYgKG1vbnRoTmV0IDwgdGFyZ2V0KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgcHJvZ3Jlc3NCYXIuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgIHByb2dyZXNzQmFyLnN0eWxlLndpZHRoID0gcGN0ICsgIiUiOwogICAgICB9IGVsc2UgewogICAgICAgIHByb2dyZXNzU2VjdGlvbi5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KTsKICAgICAgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbigpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFNpbXVsYXRpb24gZGUgcGxhY2VtZW50IChpbnTDqXLDqnRzIGNvbXBvc8OpcywgY2FsY3Vsw6lzIG1lbnN1ZWxsZW1lbnQpIOKAlAogICAgLy8gcHVyZW1lbnQgY8O0dMOpIGNsaWVudCA6IGF1Y3VuZSBkb25uw6llIHLDqWVsbGUgZGUgbCd1dGlsaXNhdGV1ciBuJ2VudHJlCiAgICAvLyBlbiBqZXUsIHNldWxlbWVudCBsZXMgNCBjaGFtcHMgZHUgZm9ybXVsYWlyZS4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGxldCBwbGFjZW1lbnRDaGFydCA9IG51bGw7CgogICAgZnVuY3Rpb24gY29tcHV0ZVBsYWNlbWVudFNlcmllcyhpbml0aWFsLCBtb250aGx5Q29udHJpYnV0aW9uLCBhbm51YWxSYXRlUGVyY2VudCwgeWVhcnMpIHsKICAgICAgY29uc3QgbW9udGhzID0gTWF0aC5tYXgoMSwgTWF0aC5yb3VuZCh5ZWFycyAqIDEyKSk7CiAgICAgIGNvbnN0IG1vbnRobHlSYXRlID0gTWF0aC5wb3coMSArIGFubnVhbFJhdGVQZXJjZW50IC8gMTAwLCAxIC8gMTIpIC0gMTsKICAgICAgbGV0IGJhbGFuY2UgPSBpbml0aWFsOwogICAgICBjb25zdCBzZXJpZXMgPSBbYmFsYW5jZV07CiAgICAgIGZvciAobGV0IG0gPSAxOyBtIDw9IG1vbnRoczsgbSsrKSB7CiAgICAgICAgYmFsYW5jZSA9IGJhbGFuY2UgKiAoMSArIG1vbnRobHlSYXRlKSArIG1vbnRobHlDb250cmlidXRpb247CiAgICAgICAgc2VyaWVzLnB1c2goYmFsYW5jZSk7CiAgICAgIH0KICAgICAgcmV0dXJuIHNlcmllczsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJQbGFjZW1lbnRTaW11bGF0aW9uKCkgewogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtcGxhY2VtZW50Iik7CiAgICAgIGlmICghY2FudmFzKSByZXR1cm47CiAgICAgIGNvbnN0IGluaXRpYWwgPSBNYXRoLm1heCgwLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1pbml0aWFsIikudmFsdWUpIHx8IDApOwogICAgICBjb25zdCBtb250aGx5ID0gTWF0aC5tYXgoMCwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtbW9udGhseSIpLnZhbHVlKSB8fCAwKTsKICAgICAgY29uc3QgcmF0ZSA9IE1hdGgubWF4KDAsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LXJhdGUiKS52YWx1ZSkgfHwgMCk7CiAgICAgIGNvbnN0IHllYXJzID0gTWF0aC5tYXgoMSwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQteWVhcnMiKS52YWx1ZSkgfHwgMSk7CgogICAgICBjb25zdCBzZXJpZXMgPSBjb21wdXRlUGxhY2VtZW50U2VyaWVzKGluaXRpYWwsIG1vbnRobHksIHJhdGUsIHllYXJzKTsKICAgICAgY29uc3QgbW9udGhzID0gc2VyaWVzLmxlbmd0aCAtIDE7CiAgICAgIGNvbnN0IGxhYmVscyA9IHNlcmllcy5tYXAoKF8sIGkpID0+ICgKICAgICAgICBpICUgMTIgPT09IDAgPyBgQW4gJHtpIC8gMTJ9YCA6ICIiCiAgICAgICkpOwoKICAgICAgaWYgKHBsYWNlbWVudENoYXJ0KSB7IHBsYWNlbWVudENoYXJ0LmRlc3Ryb3koKTsgcGxhY2VtZW50Q2hhcnQgPSBudWxsOyB9CiAgICAgIHBsYWNlbWVudENoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJsaW5lIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgbGFiZWw6ICJTb2xkZSBwcm9qZXTDqSIsCiAgICAgICAgICAgIGRhdGE6IHNlcmllcywKICAgICAgICAgICAgYm9yZGVyQ29sb3I6IENIQVJUX0NPTE9SU1sxXSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAicmdiYSgzNCwgMTk3LCA5NCwgMC4xNSkiLAogICAgICAgICAgICBmaWxsOiB0cnVlLAogICAgICAgICAgICB0ZW5zaW9uOiAwLjIsCiAgICAgICAgICAgIHBvaW50UmFkaXVzOiAwLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7IGxlZ2VuZDogeyBkaXNwbGF5OiBmYWxzZSB9IH0sCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjYWxsYmFjazogKHYpID0+IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh2KSB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwoKICAgICAgY29uc3QgZmluYWxCYWxhbmNlID0gc2VyaWVzW3Nlcmllcy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgdG90YWxDb250cmlidXRlZCA9IGluaXRpYWwgKyBtb250aGx5ICogbW9udGhzOwogICAgICBjb25zdCBpbnRlcmVzdEVhcm5lZCA9IGZpbmFsQmFsYW5jZSAtIHRvdGFsQ29udHJpYnV0ZWQ7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtcmVzdWx0IikuaW5uZXJIVE1MID0KICAgICAgICBgQXByw6hzICR7eWVhcnN9IGFuJHt5ZWFycyA+IDEgPyAicyIgOiAiIn0gOiA8c3Ryb25nPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGZpbmFsQmFsYW5jZSl9PC9zdHJvbmc+IGAgKwogICAgICAgIGAoZG9udCAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpbnRlcmVzdEVhcm5lZCl9IGQnaW50w6lyw6p0cywgcG91ciAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbENvbnRyaWJ1dGVkKX0gdmVyc8OpcykuYDsKICAgIH0KCiAgICBmb3IgKGNvbnN0IGlkIG9mIFsicGxhY2VtZW50LWluaXRpYWwiLCAicGxhY2VtZW50LW1vbnRobHkiLCAicGxhY2VtZW50LXJhdGUiLCAicGxhY2VtZW50LXllYXJzIl0pIHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbik7CiAgICB9CgogICAgLy8gQ29uc2VpbHMgOiBjcm9pc2UgZMOpcGFzc2VtZW50cyBkZSBidWRnZXQgKG9uZ2xldCBUYWJsZWF1IGRlIGJvcmQpIGV0CiAgICAvLyB0ZW5kYW5jZXMgcGFyIGNhdMOpZ29yaWUgcG91ciBwb2ludGVyIHZlcnMgY2UgcXVpIGFpZGUgbGUgcGx1cyDDoAogICAgLy8gYXR0ZWluZHJlIGwnb2JqZWN0aWYg4oCUIHBhcyB1bmUgSUEsIGp1c3RlIGRlcyByw6hnbGVzIHNpbXBsZXMgc3VyIGRlcwogICAgLy8gZG9ubsOpZXMgZMOpasOgIGNhbGN1bMOpZXMgYWlsbGV1cnMgZGFucyBsJ2FwcC4KICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCkgewogICAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtbGlzdCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtYWR2aWNlLWVtcHR5Iik7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgY29uc3QgYWR2aWNlID0gW107CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFsczogbW9udGhUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBjdXJyZW50TW9udGhLZXkpOwogICAgICBjb25zdCB0cmVuZHMgPSBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgY29uc3QgdHJlbmRCeUNhdGVnb3J5ID0gT2JqZWN0LmZyb21FbnRyaWVzKHRyZW5kcy5tYXAoKHQpID0+IFt0LmNhdGVnb3J5LCB0XSkpOwoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCwgdHJpw6llcyBwYXIgbW9udGFudCBkZQogICAgICAvLyBkw6lwYXNzZW1lbnQgZMOpY3JvaXNzYW50IOKAlCBjZSBzb250IGxlcyBsZXZpZXJzIGxlcyBwbHVzIHV0aWxlcy4KICAgICAgY29uc3Qgb3ZlckJ1ZGdldCA9IFtdOwogICAgICBmb3IgKGNvbnN0IGJ1ZGdldCBvZiBhbGxCdWRnZXRzKSB7CiAgICAgICAgY29uc3Qgc3BlbnQgPSBtb250aFRvdGFsc1tidWRnZXQuY2F0ZWdvcnldIHx8IDA7CiAgICAgICAgaWYgKHNwZW50ID4gYnVkZ2V0LmFtb3VudCkgewogICAgICAgICAgb3ZlckJ1ZGdldC5wdXNoKHsgY2F0ZWdvcnk6IGJ1ZGdldC5jYXRlZ29yeSwgc3BlbnQsIGJ1ZGdldDogYnVkZ2V0LmFtb3VudCwgb3Zlcjogc3BlbnQgLSBidWRnZXQuYW1vdW50IH0pOwogICAgICAgIH0KICAgICAgfQogICAgICBvdmVyQnVkZ2V0LnNvcnQoKGEsIGIpID0+IGIub3ZlciAtIGEub3Zlcik7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2Ygb3ZlckJ1ZGdldC5zbGljZSgwLCAzKSkgewogICAgICAgIGNvbnN0IGxhYmVsID0gZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tpdGVtLmNhdGVnb3J5XSB8fCBpdGVtLmNhdGVnb3J5KTsKICAgICAgICBjb25zdCB0cmVuZCA9IHRyZW5kQnlDYXRlZ29yeVtpdGVtLmNhdGVnb3J5XTsKICAgICAgICBsZXQgdGV4dCA9IGBUdSBhcyBkw6lwYXNzw6kgdG9uIGJ1ZGdldCA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0ub3Zlcil9IGNlIG1vaXMtY2kuYDsKICAgICAgICBpZiAodHJlbmQgJiYgdHJlbmQuZGlyZWN0aW9uID09PSAidXAiKSB7CiAgICAgICAgICB0ZXh0ICs9IGAgTGEgdGVuZGFuY2UgZXN0IMOgIGxhIGhhdXNzZSAoKyR7TWF0aC5yb3VuZCh0cmVuZC5yYXRpbyAqIDEwMCl9JSB2cyB0YSBtb3llbm5lKSDigJQgcsOpZHVpcmUgY2VzIGTDqXBlbnNlcyB0J2FpZGVyYWl0IGxlIHBsdXMgw6AgYXR0ZWluZHJlIHRvbiBvYmplY3RpZi5gOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0ZXh0ICs9IGAgRXNzYWllIGRlIHJhbWVuZXIgw6dhIHNvdXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5idWRnZXQpfSBsZSBtb2lzIHByb2NoYWluLmA7CiAgICAgICAgfQogICAgICAgIGFkdmljZS5wdXNoKHsgdHlwZTogIndhcm5pbmciLCBpY29uOiAi4pqg77iPIiwgdGV4dCB9KTsKICAgICAgfQoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gbmV0dGUgaGF1c3NlIG3Dqm1lIHNhbnMgYnVkZ2V0IGTDqXBhc3PDqSAob3Ugc2FucyBidWRnZXQKICAgICAgLy8gZMOpZmluaSBkdSB0b3V0KSA6IHVuIHNpZ25hbCB1dGlsZSBlbiBzb2kuCiAgICAgIGNvbnN0IHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCA9IHRyZW5kcwogICAgICAgIC5maWx0ZXIoKHQpID0+IHQuZGlyZWN0aW9uID09PSAidXAiICYmIHQuYXZlcmFnZSA+IDAgJiYgIW92ZXJCdWRnZXQuc29tZSgobykgPT4gby5jYXRlZ29yeSA9PT0gdC5jYXRlZ29yeSkpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGIucmF0aW8gLSBhLnJhdGlvKQogICAgICAgIC5zbGljZSgwLCAyKTsKICAgICAgZm9yIChjb25zdCB0IG9mIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCkgewogICAgICAgIGNvbnN0IGxhYmVsID0gZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KTsKICAgICAgICBhZHZpY2UucHVzaCh7CiAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICBpY29uOiAi8J+TiCIsCiAgICAgICAgICB0ZXh0OiBgVGVzIGTDqXBlbnNlcyBlbiA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IHNvbnQgZW4gaGF1c3NlIGRlICR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lIHBhciByYXBwb3J0IMOgIHRhIG1veWVubmUg4oCUIMOgIHN1cnZlaWxsZXIgc2kgdHUgdmV1eCDDqXBhcmduZXIgcGx1cy5gLAogICAgICAgIH0pOwogICAgICB9CgogICAgICAvLyBPYmplY3RpZiBhdHRlaW50IC8gZW4gYm9ubmUgdm9pZSBjZSBtb2lzLWNpLgogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgaWYgKG1vbnRoTmV0ID49IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KSB7CiAgICAgICAgICBhZHZpY2UudW5zaGlmdCh7CiAgICAgICAgICAgIHR5cGU6ICJwb3NpdGl2ZSIsCiAgICAgICAgICAgIGljb246ICLwn46JIiwKICAgICAgICAgICAgdGV4dDogYE9iamVjdGlmIGF0dGVpbnQgISBUdSBhcyBkw6lqw6AgbWlzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gZGUgY8O0dMOpIGNlIG1vaXMtY2ksIGF1LWRlbMOgIGRlIHRvbiBvYmplY3RpZiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCl9LmAsCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgaWYgKG92ZXJCdWRnZXQubGVuZ3RoID09PSAwICYmIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydC5sZW5ndGggPT09IDApIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogImluZm8iLAogICAgICAgICAgICBpY29uOiAi8J+RjSIsCiAgICAgICAgICAgIHRleHQ6IGBQYXMgZGUgZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCBjZSBtb2lzLWNpLiBJbCB0ZSByZXN0ZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCAtIG1vbnRoTmV0KX0gw6Agw6ljb25vbWlzZXIgcG91ciBhdHRlaW5kcmUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKGFkdmljZS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWR2aWNlKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gImFkdmljZS1jYXJkICIgKyBpdGVtLnR5cGU7CiAgICAgICAgY29uc3QgaWNvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBpY29uLmNsYXNzTmFtZSA9ICJhZHZpY2UtaWNvbiI7CiAgICAgICAgaWNvbi50ZXh0Q29udGVudCA9IGl0ZW0uaWNvbjsKICAgICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHRleHQuaW5uZXJIVE1MID0gaXRlbS50ZXh0OwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoaWNvbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZCh0ZXh0KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpIHsKICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiLCB7CiAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5LCBhbW91bnQgfSksCiAgICAgIH0pOwogICAgICBjb25zdCBpZHggPSBhbGxCdWRnZXRzLmZpbmRJbmRleCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gY2F0ZWdvcnkpOwogICAgICBpZiAoaWR4ID49IDApIGFsbEJ1ZGdldHNbaWR4XSA9IHVwZGF0ZWQ7CiAgICAgIGVsc2UgYWxsQnVkZ2V0cy5wdXNoKHVwZGF0ZWQpOwogICAgfQoKICAgIGNvbnN0IGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkgPSB7fTsKICAgIGNvbnN0IEJVREdFVF9ISVNUT1JZX01PTlRIUyA9IDY7CgogICAgLy8gTGVzIE4gZGVybmllcnMgbW9pcyAoY2zDqXMgIllZWVktTU0iKSwgZHUgcGx1cyBhbmNpZW4gYXUgcGx1cyByw6ljZW50LAogICAgLy8gZW4gZmluaXNzYW50IHBhciBlbmRNb250aEtleSBpbmNsdXMuCiAgICBmdW5jdGlvbiBsYXN0Tk1vbnRoS2V5cyhuLCBlbmRNb250aEtleSkgewogICAgICBjb25zdCBbeSwgbV0gPSBlbmRNb250aEtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBrZXlzID0gW107CiAgICAgIGZvciAobGV0IGkgPSBuIC0gMTsgaSA+PSAwOyBpLS0pIHsKICAgICAgICBjb25zdCBkID0gbmV3IERhdGUoeSwgbSAtIDEgLSBpLCAxKTsKICAgICAgICBrZXlzLnB1c2goZC5nZXRGdWxsWWVhcigpICsgIi0iICsgU3RyaW5nKGQuZ2V0TW9udGgoKSArIDEpLnBhZFN0YXJ0KDIsICIwIikpOwogICAgICB9CiAgICAgIHJldHVybiBrZXlzOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1saXN0Iik7CiAgICAgIGlmICghd3JhcCkgcmV0dXJuOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CgogICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KSkgZGVsZXRlIGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnlba2V5XTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UpIHsKICAgICAgICBjb25zdCBidWRnZXQgPSBhbGxCdWRnZXRzLmZpbmQoKGIpID0+IGIuY2F0ZWdvcnkgPT09IHZhbHVlKTsKICAgICAgICBjb25zdCBzcGVudCA9IHRvdGFsc1t2YWx1ZV0gfHwgMDsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJidWRnZXQtcm93IjsKCiAgICAgICAgY29uc3QgaGVhZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGhlYWQuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ctaGVhZCI7CgogICAgICAgIGNvbnN0IG5hbWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIG5hbWVTcGFuLmNsYXNzTmFtZSA9ICJidWRnZXQtY2F0LW5hbWUiOwogICAgICAgIG5hbWVTcGFuLnRleHRDb250ZW50ID0gbGFiZWw7CgogICAgICAgIGNvbnN0IGFtb3VudHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50cy5jbGFzc05hbWUgPSAiYnVkZ2V0LWFtb3VudHMiOwogICAgICAgIGNvbnN0IHNwZW50U3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBzcGVudFNwYW4udGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc3BlbnQpICsgIiAvICI7CiAgICAgICAgY29uc3QgaW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGlucHV0LnR5cGUgPSAibnVtYmVyIjsKICAgICAgICBpbnB1dC5jbGFzc05hbWUgPSAiYnVkZ2V0LWlucHV0IjsKICAgICAgICBpbnB1dC5taW4gPSAiMCI7CiAgICAgICAgaW5wdXQuc3RlcCA9ICIxIjsKICAgICAgICBpbnB1dC5wbGFjZWhvbGRlciA9ICLigJQiOwogICAgICAgIGlmIChidWRnZXQpIGlucHV0LnZhbHVlID0gYnVkZ2V0LmFtb3VudDsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKHNwZW50U3Bhbik7CiAgICAgICAgYW1vdW50cy5hcHBlbmRDaGlsZChpbnB1dCk7CiAgICAgICAgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVt2YWx1ZV0gPSBpbnB1dDsKCiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChhbW91bnRzKTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaGVhZCk7CgogICAgICAgIGlmIChidWRnZXQpIHsKICAgICAgICAgIGNvbnN0IHRyYWNrID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICB0cmFjay5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci10cmFjayI7CiAgICAgICAgICBjb25zdCBmaWxsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjb25zdCByYXRpbyA9IHNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWluKHJhdGlvICogMTAwLCAxMDApOwogICAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgICBpZiAocmF0aW8gPj0gMSkgY2xzID0gIm92ZXIiOwogICAgICAgICAgZWxzZSBpZiAocmF0aW8gPj0gMC43KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgICBmaWxsLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICAgIGZpbGwuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgICAgICB0cmFjay5hcHBlbmRDaGlsZChmaWxsKTsKICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZCh0cmFjayk7CgogICAgICAgICAgY29uc3Qgc3RyaXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHN0cmlwLmNsYXNzTmFtZSA9ICJidWRnZXQtaGlzdG9yeS1zdHJpcCI7CiAgICAgICAgICBmb3IgKGNvbnN0IGhpc3RLZXkgb2YgbGFzdE5Nb250aEtleXMoQlVER0VUX0hJU1RPUllfTU9OVEhTLCBjdXJyZW50TW9udGhLZXkpKSB7CiAgICAgICAgICAgIGNvbnN0IHsgdG90YWxzOiBoaXN0VG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgaGlzdEtleSk7CiAgICAgICAgICAgIGNvbnN0IGhpc3RTcGVudCA9IGhpc3RUb3RhbHNbdmFsdWVdIHx8IDA7CiAgICAgICAgICAgIGNvbnN0IGRvdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgICAgaWYgKGhpc3RTcGVudCA9PT0gMCkgewogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgZW1wdHkiOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgIGNvbnN0IGhpc3RSYXRpbyA9IGhpc3RTcGVudCAvIGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgICAgICAgbGV0IGhpc3RDbHMgPSAib2siOwogICAgICAgICAgICAgIGlmIChoaXN0UmF0aW8gPj0gMSkgaGlzdENscyA9ICJvdmVyIjsKICAgICAgICAgICAgICBlbHNlIGlmIChoaXN0UmF0aW8gPj0gMC43KSBoaXN0Q2xzID0gIndhcm5pbmciOwogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgIiArIGhpc3RDbHM7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgW2h5LCBobV0gPSBoaXN0S2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICAgIGNvbnN0IG1vbnRoTGFiZWwgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShoeSwgaG0gLSAxLCAxKSk7CiAgICAgICAgICAgIGNvbnN0IGRldGFpbFRleHQgPSBgJHttb250aExhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGhpc3RTcGVudCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYnVkZ2V0LmFtb3VudCl9YDsKICAgICAgICAgICAgZG90LnRpdGxlID0gZGV0YWlsVGV4dDsgLy8gYWZmaWNow6kgYXUgc3Vydm9sIHN1ciBvcmRpbmF0ZXVyCiAgICAgICAgICAgIC8vIFN1ciBtb2JpbGUgaWwgbid5IGEgcGFzIGRlIHN1cnZvbCA6IHVuIHRhcCBzdXIgbGEgYmFycmUgbW9udHJlCiAgICAgICAgICAgIC8vIGxlIG3Dqm1lIGTDqXRhaWwgZGFucyB1biB0b2FzdC4KICAgICAgICAgICAgZG90LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd1RvYXN0KGRldGFpbFRleHQpKTsKICAgICAgICAgICAgc3RyaXAuYXBwZW5kQ2hpbGQoZG90KTsKICAgICAgICAgIH0KICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZChzdHJpcCk7CiAgICAgICAgfQoKICAgICAgICB3cmFwLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIik7CiAgICAgICAgZm9yIChjb25zdCB7IHR5cGUsIHZhbHVlLCBsYWJlbCB9IG9mIGl0ZW1zKSB7CiAgICAgICAgICBpZiAoY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSAmJiAhY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHZhbHVlKSkgewogICAgICAgICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICAgICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGVzIGNhdMOpZ29yaWVzIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBrZXlzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIik7CiAgICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMgPSBuZXcgU2V0KGtleXMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIHVuZSBzdWdnZXN0aW9uIGTDqWrDoCB2dWUgcsOpYXBwYXJhw650IHVuZSBmb2lzLgogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2x1Z2lmeUNhdGVnb3J5KGxhYmVsKSB7CiAgICAgIHJldHVybiAoCiAgICAgICAgbGFiZWwKICAgICAgICAgIC5ub3JtYWxpemUoIk5GRCIpLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpIC8vIGVubMOodmUgbGVzIGFjY2VudHMKICAgICAgICAgIC50b0xvd2VyQ2FzZSgpCiAgICAgICAgICAudHJpbSgpCiAgICAgICAgICAucmVwbGFjZSgvW15hLXowLTldKy9nLCAiXyIpCiAgICAgICAgICAucmVwbGFjZSgvXl8rfF8rJC9nLCAiIikgfHwgImF1dHJlIgogICAgICApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVDdXN0b21DYXRlZ29yeSh0eXBlLCB2YWx1ZSwgbGFiZWwpIHsKICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkNhdMOpZ29yaWUgY3LDqcOpZSBpY2ksIG1haXMgcGFzIHNhdXZlZ2FyZMOpZSBzdXIgbGUgc2VydmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBjdXJyZW5jeUZvcm1hdHRlciA9IG5ldyBJbnRsLk51bWJlckZvcm1hdCgiZnItRlIiLCB7IHN0eWxlOiAiY3VycmVuY3kiLCBjdXJyZW5jeTogIkVVUiIgfSk7CiAgICBjb25zdCBkYXRlRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBkYXk6ICJudW1lcmljIiwgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKCiAgICAvLyDDiWNoYXBwZSB1bmUgdmFsZXVyIGF2YW50IGRlIGwnaW5zw6lyZXIgZGFucyB1biB0ZW1wbGF0ZSBIVE1MIGNvbnN0cnVpdAogICAgLy8gw6AgbGEgbWFpbiAoaW5uZXJIVE1MKSA6IG7DqWNlc3NhaXJlIHBhcnRvdXQgb8O5IHVuZSBkb25uw6llIHNhaXNpZSBwYXIKICAgIC8vIGwndXRpbGlzYXRldXIgcGV1dCBzJ3kgcmV0cm91dmVyIOKAlCBlbiBwYXJ0aWN1bGllciBsZSBsaWJlbGzDqSBkJ3VuZQogICAgLy8gY2F0w6lnb3JpZSBwZXJzb25uYWxpc8OpZSAodGV4dGUgbGlicmUsIGVucmVnaXN0csOpIGVuIGJhc2UpLCBwb3VyIMOpdml0ZXIKICAgIC8vIHF1J3VuIGxpYmVsbMOpIGR1IGdlbnJlIDxpbWcgc3JjPXggb25lcnJvcj0uLi4+IG5lIHMnZXjDqWN1dGUgY29tbWUgZHUKICAgIC8vIEhUTUwvSlMgYXUgbGlldSBkZSBzJ2FmZmljaGVyIGNvbW1lIGR1IHRleHRlIChpbmplY3Rpb24gWFNTIHN0b2Nrw6llKS4KICAgIGZ1bmN0aW9uIGVzY2FwZUh0bWwoc3RyKSB7CiAgICAgIHJldHVybiBTdHJpbmcoc3RyKS5yZXBsYWNlKC9bJjw+IiddL2csIChjaCkgPT4gKHsKICAgICAgICAiJiI6ICImYW1wOyIsICI8IjogIiZsdDsiLCAiPiI6ICImZ3Q7IiwgJyInOiAiJnF1b3Q7IiwgIiciOiAiJiMzOTsiLAogICAgICB9W2NoXSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gNDAxKSB7CiAgICAgICAgLy8gSmV0b24gYWJzZW50LCBpbnZhbGlkZSBvdSBleHBpcsOpIDogcmV0b3VyIMOgIGwnw6ljcmFuIGRlIHZlcnJvdWlsbGFnZQogICAgICAgIC8vIHBsdXTDtHQgcXVlIGQnYWZmaWNoZXIgdW5lIGVycmV1ciB0ZWNobmlxdWUgaW5jb21wcsOpaGVuc2libGUuCiAgICAgICAgc2hvd0xvY2tTY3JlZW4oKTsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoIlNlc3Npb24gZXhwaXLDqWUsIHJlY29ubmVjdGUtdG9pLiIpOwogICAgICB9CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgLy8gcmVzLnN0YXR1c1RleHQgZXN0IHNvdXZlbnQgdmlkZSAobmF2aWdhdGV1cnMgZW4gSFRUUC8yLCB1dGlsaXPDqSBwYXIKICAgICAgICAvLyBWZXJjZWwpLCBkb25jIG9uIG5lIHBldXQgcGFzIGNvbXB0ZXIgZGVzc3VzIGNvbW1lIG1lc3NhZ2UgcGFyCiAgICAgICAgLy8gZMOpZmF1dCA6IG9uIHJldG9tYmUgc3VyIGxlIGNvZGUgSFRUUCBwb3VyIG5lIGphbWFpcyBhZmZpY2hlciB1bgogICAgICAgIC8vIG1lc3NhZ2UgZCdlcnJldXIgdmlkZS4KICAgICAgICBsZXQgZGV0YWlsID0gcmVzLnN0YXR1c1RleHQgfHwgYEVycmV1ciBIVFRQICR7cmVzLnN0YXR1c31gOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGRhdGEuZGV0YWlsIHx8IGRldGFpbDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIHRocm93IG5ldyBFcnJvcihkZXRhaWwpOwogICAgICB9CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSAyMDQpIHJldHVybiBudWxsOwogICAgICByZXR1cm4gcmVzLmpzb24oKTsKICAgIH0KCiAgICBmdW5jdGlvbiB0b2RheUlzbygpIHsKICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IHR6ID0gZC5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKGQuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgc2VsZWN0ZWRWYWx1ZSA9IG51bGwpIHsKICAgICAgY2F0ZWdvcnlJbnB1dC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgaWYgKHZhbHVlID09PSAoc2VsZWN0ZWRWYWx1ZSB8fCAiYXV0cmUiKSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBjYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV3T3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgIG5ld09wdC52YWx1ZSA9ICJfX25ld19fIjsKICAgICAgbmV3T3B0LnRleHRDb250ZW50ID0gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiI7CiAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQobmV3T3B0KTsKCiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LnZhbHVlID0gIiI7CiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgfQoKICAgIGNhdGVnb3J5SW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICBuZXdDYXRlZ29yeU5hbWVJbnB1dC5jbGFzc0xpc3QudG9nZ2xlKCJoaWRkZW4iLCBjYXRlZ29yeUlucHV0LnZhbHVlICE9PSAiX19uZXdfXyIpOwogICAgICBpZiAoY2F0ZWdvcnlJbnB1dC52YWx1ZSA9PT0gIl9fbmV3X18iKSBuZXdDYXRlZ29yeU5hbWVJbnB1dC5mb2N1cygpOwogICAgfSk7CgogICAgZnVuY3Rpb24gc2V0VHlwZSh0eXBlKSB7CiAgICAgIGN1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgdHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBjYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICB0eXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0VHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5Nb2RhbCh0eCA9IG51bGwpIHsKICAgICAgLy8gT24gZGlzdGluZ3VlICJtb2RpZmllciIgKHR4IGEgdW4gaWQsIHZyYWllIMOpZGl0aW9uIGVuIGJhc2UpIGRlCiAgICAgIC8vICJwcsOpLXJlbXBsaXIgw6AgcGFydGlyIGQndW4gbW9kw6hsZSIgKGR1cGxpY2F0aW9uIDogdHggZm91cm5pIG1haXMgc2FucwogICAgICAvLyBpZCA9PiBvbiBjcsOpZSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gYXUgbGlldSBkJ8OpY3Jhc2VyIGwnb3JpZ2luYWxlKS4KICAgICAgY29uc3QgaXNFZGl0ID0gQm9vbGVhbih0eCAmJiB0eC5pZCk7CiAgICAgIGVkaXRpbmdJZCA9IGlzRWRpdCA/IHR4LmlkIDogbnVsbDsKICAgICAgZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnkgPSBpc0VkaXQgPyB0eC5jYXRlZ29yeSA6IG51bGw7CiAgICAgIG1vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJNb2RpZmllciBsYSB0cmFuc2FjdGlvbiIgOiAiTm91dmVsbGUgdHJhbnNhY3Rpb24iOwogICAgICBzYXZlQnRuLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIkVucmVnaXN0cmVyIiA6ICJBam91dGVyIjsKICAgICAgc2V0VHlwZSh0eCA/IHR4LnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICBhbW91bnRJbnB1dC52YWx1ZSA9IHR4ID8gdHguYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgdHggPyB0eC5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICBkZXNjcmlwdGlvbklucHV0LnZhbHVlID0gdHggPyAodHguZGVzY3JpcHRpb24gfHwgIiIpIDogIiI7CiAgICAgIGRhdGVJbnB1dC52YWx1ZSA9IHR4ID8gdHguZXhwZW5zZV9kYXRlIDogdG9kYXlJc28oKTsKCiAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIGlmIChpc0VkaXQgJiYgdHgucmVjZWlwdF9wYXRoKSB7CiAgICAgICAgbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHguaWQpOwogICAgICB9CgogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIGFtb3VudElucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpIHsKICAgICAgLy8gTcOqbWUgbW9udGFudC9jYXTDqWdvcmllL2Rlc2NyaXB0aW9uLCBtYWlzIGRhdMOpIGQnYXVqb3VyZCdodWkgZXQgc2FucwogICAgICAvLyBpZCA6IGxhIHNhdXZlZ2FyZGUgY3LDqWVyYSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gKHZvaXIgb3Blbk1vZGFsKS4KICAgICAgb3Blbk1vZGFsKHsgLi4udHgsIGlkOiBudWxsLCBleHBlbnNlX2RhdGU6IHRvZGF5SXNvKCkgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VNb2RhbCgpIHsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nSWQgPSBudWxsOwogICAgICBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IG51bGw7CiAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1hZGQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAicmVjdXJyaW5nIikgb3BlblJlY3VycmluZ01vZGFsKCk7CiAgICAgIGVsc2Ugb3Blbk1vZGFsKCk7CiAgICB9KTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZU1vZGFsKTsKICAgIG92ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheUVsKSBjbG9zZU1vZGFsKCk7IH0pOwoKICAgIHNhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQoYW1vdW50SW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgLy8gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiIgc8OpbGVjdGlvbm7DqSA6IG9uIGxhIGNyw6llIChzaSBlbGxlIG4nZXhpc3RlCiAgICAgIC8vIHBhcyBkw6lqw6Agc291cyBjZSBub20pIGF2YW50IGQnZW5yZWdpc3RyZXIgbGEgdHJhbnNhY3Rpb24gYXZlYy4KICAgICAgbGV0IGNhdGVnb3J5VmFsdWUgPSBjYXRlZ29yeUlucHV0LnZhbHVlOwogICAgICBpZiAoY2F0ZWdvcnlWYWx1ZSA9PT0gIl9fbmV3X18iKSB7CiAgICAgICAgY29uc3QgbmFtZSA9IG5ld0NhdGVnb3J5TmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICBpZiAoIW5hbWUpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRG9ubmUgdW4gbm9tIMOgIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiLCB0cnVlKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgY2F0ZWdvcnlWYWx1ZSA9IHNsdWdpZnlDYXRlZ29yeShuYW1lKTsKICAgICAgICBpZiAoIWNhdGVnb3JpZXNCeVR5cGVbY3VycmVudFR5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gY2F0ZWdvcnlWYWx1ZSkpIHsKICAgICAgICAgIGF3YWl0IHNhdmVDdXN0b21DYXRlZ29yeShjdXJyZW50VHlwZSwgY2F0ZWdvcnlWYWx1ZSwgbmFtZSk7CiAgICAgICAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoY3VycmVudFR5cGUsIGNhdGVnb3J5VmFsdWUpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBjdXJyZW50VHlwZSwKICAgICAgICBhbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5VmFsdWUsCiAgICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uSW5wdXQudmFsdWUudHJpbSgpIHx8IG51bGwsCiAgICAgICAgZXhwZW5zZV9kYXRlOiBkYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAgIGNvbnN0IHByZXZpb3VzQ2F0ZWdvcnkgPSBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeTsKICAgICAgICAgIGNvbnN0IGVkaXRlZElkID0gZWRpdGluZ0lkOwogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIG1vZGlmacOpZSIpOwoKICAgICAgICAgIC8vIFNpIGxhIGNhdMOpZ29yaWUgdmllbnQgZGUgY2hhbmdlciBtYW51ZWxsZW1lbnQsIG9uIHByb3Bvc2UgZGUKICAgICAgICAgIC8vIHJlcG9ydGVyIGxlIG3Dqm1lIGNoYW5nZW1lbnQgc3VyIGxlcyBhdXRyZXMgdHJhbnNhY3Rpb25zIGRvbnQgbGEKICAgICAgICAgIC8vIGRlc2NyaXB0aW9uIHBhcnRhZ2UgdW4gbW90LWNsw6kgc2lnbmlmaWNhdGlmIChleC4gImNhc2lubyIgLwogICAgICAgICAgLy8gImF1IGNhc2lubyIgLyAicGVydGUgYXUgY2FzaW5vIikgZXQgcXVpIMOpdGFpZW50IGRhbnMgbCdhbmNpZW5uZQogICAgICAgICAgLy8gY2F0w6lnb3JpZSDigJQgamFtYWlzIGF1dG9tYXRpcXVlLCB0b3Vqb3VycyBzdXIgY29uZmlybWF0aW9uLgogICAgICAgICAgaWYgKHByZXZpb3VzQ2F0ZWdvcnkgJiYgcGF5bG9hZC5jYXRlZ29yeSAhPT0gcHJldmlvdXNDYXRlZ29yeSAmJiBwYXlsb2FkLmRlc2NyaXB0aW9uKSB7CiAgICAgICAgICAgIGNvbnN0IGtleXdvcmRzID0gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMocGF5bG9hZC5kZXNjcmlwdGlvbik7CiAgICAgICAgICAgIGlmIChrZXl3b3Jkcy5zaXplID4gMCkgewogICAgICAgICAgICAgIGNvbnN0IHNpbWlsYXIgPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICAgICAgICAgKHQpID0+CiAgICAgICAgICAgICAgICAgIHQuaWQgIT09IGVkaXRlZElkICYmCiAgICAgICAgICAgICAgICAgIHQudHlwZSA9PT0gcGF5bG9hZC50eXBlICYmCiAgICAgICAgICAgICAgICAgIHQuY2F0ZWdvcnkgPT09IHByZXZpb3VzQ2F0ZWdvcnkgJiYKICAgICAgICAgICAgICAgICAga2V5d29yZHNJbnRlcnNlY3Qoa2V5d29yZHMsIGV4dHJhY3REZXNjcmlwdGlvbktleXdvcmRzKHQuZGVzY3JpcHRpb24pKQogICAgICAgICAgICAgICk7CiAgICAgICAgICAgICAgaWYgKHNpbWlsYXIubGVuZ3RoID4gMCkgewogICAgICAgICAgICAgICAgY29uc3QgbmV3TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1twYXlsb2FkLmNhdGVnb3J5XSB8fCBwYXlsb2FkLmNhdGVnb3J5OwogICAgICAgICAgICAgICAgY29uc3QgZXhhbXBsZURlc2MgPSBzaW1pbGFyWzBdLmRlc2NyaXB0aW9uIHx8ICIoc2FucyBkZXNjcmlwdGlvbikiOwogICAgICAgICAgICAgICAgY29uc3QgY29uZmlybWVkID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgICAgICAgICAgIGBBcHBsaXF1ZXIgYXVzc2kgbGEgY2F0w6lnb3JpZSAiJHtuZXdMYWJlbH0iIGF1eCAke3NpbWlsYXIubGVuZ3RofSBhdXRyZShzKSB0cmFuc2FjdGlvbihzKSBgICsKICAgICAgICAgICAgICAgICAgYHNpbWlsYWlyZShzKSAoZXguICIke2V4YW1wbGVEZXNjfSIpID9gCiAgICAgICAgICAgICAgICApOwogICAgICAgICAgICAgICAgaWYgKGNvbmZpcm1lZCkgewogICAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IHQgb2Ygc2ltaWxhcikgewogICAgICAgICAgICAgICAgICAgIGNvbnN0IGZpeFBheWxvYWQgPSB7IGNhdGVnb3J5OiBwYXlsb2FkLmNhdGVnb3J5IH07CiAgICAgICAgICAgICAgICAgICAgLy8gQ29tbWUgcG91ciBsYSBiYW5uacOocmUgZGUgc3VnZ2VzdGlvbiA6IGxhIGNhdMOpZ29yaWUKICAgICAgICAgICAgICAgICAgICAvLyBwb3J0ZSBtYWludGVuYW50IGwnaW5mbywgb24gcmV0aXJlIGxlIG1vdC1jbMOpIGRldmVudQogICAgICAgICAgICAgICAgICAgIC8vIHJlZG9uZGFudCBkZSBsYSBkZXNjcmlwdGlvbiBkZSBDRVMgdHJhbnNhY3Rpb25zLWzDoAogICAgICAgICAgICAgICAgICAgIC8vIChwYXMgY2VsbGUgcXUnb24gdmllbnQgZCfDqWRpdGVyIMOgIGxhIG1haW4pLgogICAgICAgICAgICAgICAgICAgIGNvbnN0IGNsZWFuZWQgPSBzdHJpcE1hdGNoZWRLZXl3b3Jkc0Zyb21EZXNjcmlwdGlvbih0LmRlc2NyaXB0aW9uLCBrZXl3b3Jkcyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKGNsZWFuZWQgIT09ICh0LmRlc2NyaXB0aW9uIHx8IG51bGwpKSBmaXhQYXlsb2FkLmRlc2NyaXB0aW9uID0gY2xlYW5lZDsKICAgICAgICAgICAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0LmlkfWAsIHsKICAgICAgICAgICAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShmaXhQYXlsb2FkKSwKICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICBzaG93VG9hc3QoYCR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIG1pc2Uocykgw6Agam91cmApOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoY3VycmVudFR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSBham91dMOpIiA6ICJEw6lwZW5zZSBham91dMOpZSIpOwogICAgICAgICAgaWYgKHBlbmRpbmdSZWNlaXB0RmlsZSkgewogICAgICAgICAgICAvLyBMYSBwaG90byBhIMOpdMOpIGNob2lzaWUgYXZhbnQgcXVlIGxhIHRyYW5zYWN0aW9uIG4nZXhpc3RlIDogb24KICAgICAgICAgICAgLy8gbCdlbnZvaWUgbWFpbnRlbmFudCBxdSdvbiBhIHVuIGlkLgogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgcGVuZGluZ1JlY2VpcHRGaWxlKTsKICAgICAgICAgICAgICBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtjcmVhdGVkLmlkfS9yZWNlaXB0YCwgewogICAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBjcsOpw6llLCBtYWlzIGwnZW52b2kgZGUgbGEgcGhvdG8gYSDDqWNob3XDqSIsIHRydWUpOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRyYW5zYWN0aW9uKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgdHJhbnNhY3Rpb24gPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIFRvdGF1eCBnbG9iYXV4IChTb2xkZS9Ew6lwZW5zZXMvUmV2ZW51cykgOiBjYWxjdWzDqXMgc3VyIFRPVVRFUyBsZXMKICAgIC8vIHRyYW5zYWN0aW9ucywgaW5kw6lwZW5kYW1tZW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSDigJQgdW4gZmlsdHJlCiAgICAvLyBzZXJ0IMOgIGNoZXJjaGVyIGRhbnMgbGEgbGlzdGUsIHBhcyDDoCByZWNhbGN1bGVyIGxlIHNvbGRlIHLDqWVsLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucykgewogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSB0b3RhbEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBlbHNlIHRvdGFsRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgYmFsYW5jZSA9IHRvdGFsSW5jb21lIC0gdG90YWxFeHBlbnNlczsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiYWxhbmNlKTsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC5jbGFzc05hbWUgPSAidmFsdWUgIiArIChiYWxhbmNlID49IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIHN1bW1hcnlFeHBlbnNlc0VsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsRXhwZW5zZXMpOwogICAgICBzdW1tYXJ5SW5jb21lRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgfQoKICAgIC8vIENvbnN0cnVjdGlvbiBkZSBsYSBsaXN0ZSBkZSBjYXJ0ZXMgYWZmaWNow6llIGRhbnMgbCdvbmdsZXQgSGlzdG9yaXF1ZSDigJQKICAgIC8vIHJlw6dvaXQgZMOpasOgIGxhIGxpc3RlIGZpbHRyw6llICh2b2lyIGFwcGx5SGlzdG9yeUZpbHRlcnMpLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25MaXN0KHRyYW5zYWN0aW9ucykgewogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGlmICh0cmFuc2FjdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGVtcHR5U3RhdGVFbC50ZXh0Q29udGVudCA9IGFsbFRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDAKICAgICAgICAgID8gIlJpZW4gcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgbGUgYm91dG9uICsgcG91ciBham91dGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUuIgogICAgICAgICAgOiAiQXVjdW4gcsOpc3VsdGF0IHBvdXIgY2VzIGZpbHRyZXMuIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAidHgtY2FyZCAiICsgdHgudHlwZTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInR4LW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gInR4LXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkYXRlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkYXRlU3Bhbi5jbGFzc05hbWUgPSAidHgtZGF0ZSI7CiAgICAgICAgZGF0ZVNwYW4udGV4dENvbnRlbnQgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh0eC5leHBlbnNlX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChiYWRnZSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGRhdGVTcGFuKTsKICAgICAgICBpZiAodHgucmVjdXJyaW5nX2V4cGVuc2VfaWQpIHsKICAgICAgICAgIGNvbnN0IHJlY0JhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgcmVjQmFkZ2UuY2xhc3NOYW1lID0gInR4LXJlY3VycmluZy1iYWRnZSI7CiAgICAgICAgICByZWNCYWRnZS50ZXh0Q29udGVudCA9ICLwn5SBIjsKICAgICAgICAgIHJlY0JhZGdlLnRpdGxlID0gIkNyw6nDqWUgYXV0b21hdGlxdWVtZW50IGRlcHVpcyB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChyZWNCYWRnZSk7CiAgICAgICAgfQogICAgICAgIGlmICh0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICAgIGNvbnN0IHJlY2VpcHRCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnR5cGUgPSAiYnV0dG9uIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjZWlwdC1iYWRnZSI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudGV4dENvbnRlbnQgPSAi8J+nviI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudGl0bGUgPSAiVm9pciBsYSBwaG90byBkdSByZcOndSI7CiAgICAgICAgICByZWNlaXB0QmFkZ2Uuc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlZvaXIgbGEgcGhvdG8gZHUgcmXDp3UiKTsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5SZWNlaXB0TGlnaHRib3godHguaWQpKTsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChyZWNlaXB0QmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gInR4LWRlc2NyaXB0aW9uIjsKICAgICAgICBkZXNjLnRleHRDb250ZW50ID0gdHguZGVzY3JpcHRpb24gfHwgIuKAlCI7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwoKICAgICAgICBjb25zdCBhbW91bnRFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudEVsLmNsYXNzTmFtZSA9ICJ0eC1hbW91bnQgIiArIHR4LnR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHgudHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0eC5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3Blbk1vZGFsKHR4KSk7CiAgICAgICAgY29uc3QgZHVwbGljYXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZHVwbGljYXRlQnRuLnRleHRDb250ZW50ID0gIvCfk4siOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiRHVwbGlxdWVyIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpKTsKICAgICAgICBjb25zdCBkZWxldGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkZWxldGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIGRhbmdlciI7CiAgICAgICAgZGVsZXRlQnRuLnRleHRDb250ZW50ID0gIvCfl5HvuI8iOwogICAgICAgIGRlbGV0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiU3VwcHJpbWVyIik7CiAgICAgICAgZGVsZXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZGVsZXRlVHJhbnNhY3Rpb24odHguaWQpKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGVkaXRCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZHVwbGljYXRlQnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSw6lzdW3DqSAiY2V0dGUgc2VtYWluZSIgKGluZMOpcGVuZGFudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzdGFydE9mV2Vla0lzbygpIHsKICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgZGF5ID0gbm93LmdldERheSgpOyAvLyAwID0gZGltYW5jaGUsIDEgPSBsdW5kaSwgLi4uCiAgICAgIGNvbnN0IGRpZmZUb01vbmRheSA9IGRheSA9PT0gMCA/IDYgOiBkYXkgLSAxOwogICAgICBjb25zdCBtb25kYXkgPSBuZXcgRGF0ZShub3cpOwogICAgICBtb25kYXkuc2V0RGF0ZShub3cuZ2V0RGF0ZSgpIC0gZGlmZlRvTW9uZGF5KTsKICAgICAgY29uc3QgdHogPSBtb25kYXkuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShtb25kYXkuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc3RhcnQgPSBzdGFydE9mV2Vla0lzbygpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJleHBlbnNlIiAmJiB0eC5leHBlbnNlX2RhdGUgPj0gc3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDw9IHRvZGF5KSB7CiAgICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIndlZWstc3VtbWFyeSIpLnRleHRDb250ZW50ID0KICAgICAgICBgQ2V0dGUgc2VtYWluZSAoZGVwdWlzIGx1bmRpKSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsKX0gZMOpcGVuc8Opc2A7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUmVjaGVyY2hlIGV0IGZpbHRyZXMgZGFucyBsJ2hpc3RvcmlxdWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCkgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5Iik7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgT2JqZWN0LmVudHJpZXMoYWxsQ2F0ZWdvcnlMYWJlbHMpKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBhcHBseUhpc3RvcnlGaWx0ZXJzKCkgewogICAgICBjb25zdCBzZWFyY2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLXNlYXJjaCIpLnZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCBjYXRlZ29yeSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZVN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLXN0YXJ0IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVFbmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtZW5kIikudmFsdWU7CgogICAgICBjb25zdCBmaWx0ZXJlZCA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoKHR4KSA9PiB7CiAgICAgICAgaWYgKGNhdGVnb3J5ICYmIHR4LmNhdGVnb3J5ICE9PSBjYXRlZ29yeSkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlU3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDwgZGF0ZVN0YXJ0KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVFbmQgJiYgdHguZXhwZW5zZV9kYXRlID4gZGF0ZUVuZCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChzZWFyY2gpIHsKICAgICAgICAgIGNvbnN0IGhheXN0YWNrID0gYCR7dHguZGVzY3JpcHRpb24gfHwgIiJ9ICR7YWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5fWAudG9Mb3dlckNhc2UoKTsKICAgICAgICAgIGlmICghaGF5c3RhY2suaW5jbHVkZXMoc2VhcmNoKSkgcmV0dXJuIGZhbHNlOwogICAgICAgIH0KICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgfSk7CiAgICAgIHJlbmRlclRyYW5zYWN0aW9uTGlzdChmaWx0ZXJlZCk7CiAgICB9CgogICAgWyJmaWx0ZXItc2VhcmNoIiwgImZpbHRlci1jYXRlZ29yeSIsICJmaWx0ZXItZGF0ZS1zdGFydCIsICJmaWx0ZXItZGF0ZS1lbmQiXS5mb3JFYWNoKChpZCkgPT4gewogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuYWRkRXZlbnRMaXN0ZW5lcigiaW5wdXQiLCBhcHBseUhpc3RvcnlGaWx0ZXJzKTsKICAgIH0pOwoKICAgIGxldCBhbGxUcmFuc2FjdGlvbnMgPSBbXTsKICAgIGxldCBjdXJyZW50VmlldyA9ICJoaXN0b3J5IjsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkVHJhbnNhY3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHRyYW5zYWN0aW9ucyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIpOwogICAgICAgIGFsbFRyYW5zYWN0aW9ucyA9IHRyYW5zYWN0aW9uczsKICAgICAgICByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKTsKICAgICAgICB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpOwogICAgICAgIGFwcGx5SGlzdG9yeUZpbHRlcnMoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5ncyh0cmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9uZ2xldHMgKEhpc3RvcmlxdWUgLyBUYWJsZWF1IGRlIGJvcmQpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzd2l0Y2hWaWV3KHZpZXcpIHsKICAgICAgY3VycmVudFZpZXcgPSB2aWV3OwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiaGlzdG9yeSIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXNhdmluZ3MiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1oaXN0b3J5Iikuc3R5bGUuZGlzcGxheSA9IHZpZXcgPT09ICJoaXN0b3J5IiA/ICJibG9jayIgOiAibm9uZSI7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXNhdmluZ3MiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gInNhdmluZ3MiKTsKICAgICAgaWYgKHZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgaWYgKHZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5ncyhhbGxUcmFuc2FjdGlvbnMpOwogICAgICBjbG9zZU5hdkRyYXdlcigpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiaGlzdG9yeSIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJkYXNoYm9hcmQiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygicmVjdXJyaW5nIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImV4cG9ydCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygic2F2aW5ncyIpKTsKCiAgICAvLyBNZW51ICJidXJnZXIiIChtb2JpbGUgdW5pcXVlbWVudCwgdm9pciBsZSBDU1MgQG1lZGlhIGFzc29jacOpKSA6IGxhCiAgICAvLyBiYXJyZSBkJ29uZ2xldHMgZGV2aWVudCB1biB0aXJvaXIgcGx1dMO0dCBxdWUgZGUgcyfDqWNyYXNlciBzdXIKICAgIC8vIHBsdXNpZXVycyBsaWduZXMuIEZlcm3DqSBhdXRvbWF0aXF1ZW1lbnQgZMOocyBxdSd1biBvbmdsZXQgZXN0IGNob2lzaQogICAgLy8gKHZvaXIgc3dpdGNoVmlldyBjaS1kZXNzdXMpIG91IGVuIHRvdWNoYW50IGxlIGZvbmQgYXNzb21icmkuCiAgICBmdW5jdGlvbiBjbG9zZU5hdkRyYXdlcigpIHsKICAgICAgZG9jdW1lbnQuYm9keS5jbGFzc0xpc3QucmVtb3ZlKCJuYXYtZHJhd2VyLW9wZW4iKTsKICAgIH0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtZW51LXRvZ2dsZS1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgZG9jdW1lbnQuYm9keS5jbGFzc0xpc3QudG9nZ2xlKCJuYXYtZHJhd2VyLW9wZW4iKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm5hdi1kcmF3ZXItYmFja2Ryb3AiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTmF2RHJhd2VyKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBUYWJsZWF1IGRlIGJvcmQgKGdyYXBoaXF1ZXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtb250aEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJsb25nIiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgbW9udGhTaG9ydEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IENIQVJUX0NPTE9SUyA9IFsiIzNiODJmNiIsICIjMjJjNTVlIiwgIiNlZjQ0NDQiLCAiI2Y1OWUwYiIsICIjYTg1NWY3IiwgIiMxNGI4YTYiLCAiI2VjNDg5OSIsICIjNjQ3NDhiIl07CgogICAgbGV0IGNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGluY29tZUNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsKICAgIGxldCB5ZWFybHlDaGFydCA9IG51bGw7CgogICAgZnVuY3Rpb24gbW9udGhLZXlPZihleHBlbnNlRGF0ZSkgewogICAgICByZXR1cm4gZXhwZW5zZURhdGUuc2xpY2UoMCwgNyk7IC8vICJZWVlZLU1NIgogICAgfQoKICAgIC8vIFVuZSBjaGFyZ2UgcsOpY3VycmVudGUgY29tcHRlIHBvdXIgdW4gbW9pcyBkb25uw6kgc2kgY2UgbW9pcyBlc3QgZGFucyBzYQogICAgLy8gcMOpcmlvZGUgZCdhY3Rpdml0w6kgOiBwYXMgYXZhbnQgc2EgZGF0ZSBkZSBkw6lidXQgKHNpIHBvc8OpZSksIHBhcyBhcHLDqHMKICAgIC8vIGxlIG1vaXMgZGUgc2EgZGF0ZSBkZSBmaW4gKHNpIHBvc8OpZSkuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkgewogICAgICBpZiAoaXRlbS5zdGFydF9kYXRlICYmIG1vbnRoS2V5IDwgaXRlbS5zdGFydF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChpdGVtLmVuZF9kYXRlICYmIG1vbnRoS2V5ID4gaXRlbS5lbmRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICAvLyBKb3VyIGR1IG1vaXMganVzcXUnYXVxdWVsIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgZXN0IGNvbnNpZMOpcsOpZSBjb21tZQogICAgLy8gImTDqWrDoCBwcsOpbGV2w6llIiBwb3VyIGxlIG1vaXMgYG1vbnRoS2V5YCA6IHRvdXMgbGVzIGpvdXJzIHBvdXIgdW4gbW9pcwogICAgLy8gZMOpasOgIHBhc3PDqSwgYXVjdW4gcG91ciB1biBtb2lzIGZ1dHVyLCBldCBsZSBqb3VyIGR1IGpvdXIgcG91ciBsZSBtb2lzCiAgICAvLyBlbiBjb3Vycy4gUGVybWV0IGRlIGRpc3Rpbmd1ZXIgY2UgcXVpIGVzdCBkw6lqw6AgYXJyaXbDqSBkZSBjZSBxdWkgZXN0CiAgICAvLyBzZXVsZW1lbnQgcHLDqXZ1IChleCA6IHVuIGFib25uZW1lbnQgcHLDqWxldsOpIGxlIDI1LCBvbiBlc3QgbGUgMikuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpIHsKICAgICAgaWYgKG1vbnRoS2V5IDwgY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMzE7CiAgICAgIGlmIChtb250aEtleSA+IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDA7CiAgICAgIHJldHVybiB0b2RheURheTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDApIG1vbnRoU2V0LmFkZChtb250aEtleU9mKHRvZGF5SXNvKCkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9ICIiOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9ICJBdWN1bmUgZG9ubsOpZSI7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIHNlbGVjdC52YWx1ZSA9IG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBtb250aHNbMF07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiKTsKICAgICAgY29uc3QgdXBjb21pbmdOb3RlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiKTsKICAgICAgY29uc3QgdXBjb21pbmdUZXh0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLXRleHQiKTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVW4gc2V1bCBzb2xkZSBuZXQgIsOgIHZlbmlyIiAocmV2ZW51cyByw6ljdXJyZW50cyDDoCB2ZW5pciBtb2lucyBkw6lwZW5zZXMKICAgICAgLy8gcsOpY3VycmVudGVzIMOgIHZlbmlyKSwgcGx1dMO0dCBxdWUgZGV1eCBjaGlmZnJlcyBzw6lwYXLDqXMgOiBwbHVzIHNpbXBsZQogICAgICAvLyDDoCBsaXJlIGQndW4gY291cCBkJ8WTaWwuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lIHNvbnQgUEFTCiAgICAgIC8vIGFqb3V0w6llcyBpY2kgOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlIHZyYWllcyB0cmFuc2FjdGlvbnMKICAgICAgLy8gKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcyBkYW5zIGB0b3RhbHNgCiAgICAgIC8vIGNpLWRlc3N1cyDigJQgbGVzIGFqb3V0ZXIgw6Agbm91dmVhdSBsZXMgY29tcHRlcmFpdCBlbiBkb3VibGUuCiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSBjdXRvZmYpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLnR5cGUgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgY29uc3QgbmV0VXBjb21pbmcgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgaWYgKG5ldFVwY29taW5nICE9PSAwKSB7CiAgICAgICAgY29uc3Qgc2lnbiA9IG5ldFVwY29taW5nID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICAgIHVwY29taW5nVGV4dEVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0VXBjb21pbmcpKX0gw6AgdmVuaXJgOwogICAgICAgIHVwY29taW5nTm90ZUVsLnRpdGxlID0gIlLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzL3Jlw6d1ZXMgY2UgbW9pcy1jaSAocmV2ZW51cyBtb2lucyBkw6lwZW5zZXMpIjsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QudG9nZ2xlKCJwb3NpdGl2ZSIsIG5ldFVwY29taW5nID4gMCk7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIGlmIChjYXRlZ29yeUNoYXJ0KSB7IGNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICAvLyBNw6ptZSBwcmluY2lwZSBxdWUgcmVuZGVyQ2F0ZWdvcnlDaGFydCwgY8O0dMOpIHJldmVudXMg4oCUIHBhcyBkZSBub3RlICLDoAogICAgLy8gdmVuaXIiIGljaSwgZWxsZSByZXN0ZSB1bmlxdWVtZW50IHN1ciBsZSBjYW1lbWJlcnQgZGVzIGTDqXBlbnNlcyBwb3VyCiAgICAvLyBuZSBwYXMgYWZmaWNoZXIgbGUgbcOqbWUgY2hpZmZyZSBuZXQgw6AgZGV1eCBlbmRyb2l0cy4KICAgIGZ1bmN0aW9uIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtaW5jb21lLWNhdGVnb3JpZXMtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiaW5jb21lIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBpZiAoaW5jb21lQ2F0ZWdvcnlDaGFydCkgeyBpbmNvbWVDYXRlZ29yeUNoYXJ0LmRlc3Ryb3koKTsgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiZG91Z2hudXQiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBkYXRhLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGxhYmVscy5tYXAoKF8sIGkpID0+IENIQVJUX0NPTE9SU1tpICUgQ0hBUlRfQ09MT1JTLmxlbmd0aF0pLAogICAgICAgICAgICBib3JkZXJDb2xvcjogIiMxYTFkMjQiLAogICAgICAgICAgICBib3JkZXJXaWR0aDogMiwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgcG9zaXRpb246ICJib3R0b20iLCBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiwgYm94V2lkdGg6IDEyLCBwYWRkaW5nOiAxMiwgZm9udDogeyBzaXplOiAxMSB9IH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkKX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1ldm9sdXRpb24iKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5Iik7CgogICAgICBjb25zdCBtb250aGx5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3Qga2V5ID0gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpOwogICAgICAgIGlmICghbW9udGhseVtrZXldKSBtb250aGx5W2tleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICAgIG1vbnRobHlba2V5XVt0eC50eXBlXSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBUb3Vqb3VycyBpbmNsdXJlIGxlIG1vaXMgZW4gY291cnMgKG3Dqm1lIHNhbnMgdHJhbnNhY3Rpb24pIHMnaWwgZXhpc3RlCiAgICAgIC8vIGRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgcG91ciBxdSdpbCBhcHBhcmFpc3NlIHNhbnMgYXR0ZW5kcmUgbGEKICAgICAgLy8gcHJlbWnDqHJlIHRyYW5zYWN0aW9uIGR1IG1vaXMuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lCiAgICAgIC8vIHNvbnQgcGx1cyBham91dMOpZXMgaWNpIMOgIGxhIG1haW4gOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlCiAgICAgIC8vIHZyYWllcyB0cmFuc2FjdGlvbnMgKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcwogICAgICAvLyBkYW5zIGBtb250aGx5YCB2aWEgbGEgYm91Y2xlIHN1ciBgdHJhbnNhY3Rpb25zYCBjaS1kZXNzdXMg4oCUIGNlIHF1aQogICAgICAvLyBuJ2VzdCBwYXMgZW5jb3JlIGFycml2w6kgZXN0IHLDqXN1bcOpIGFpbGxldXJzIChzb2xkZSBuZXQgIsOgIHZlbmlyIikuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCAmJiAhbW9udGhseVtjdXJyZW50TW9udGhLZXldKSB7CiAgICAgICAgbW9udGhseVtjdXJyZW50TW9udGhLZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgfQogICAgICBjb25zdCBtb250aHMgPSBPYmplY3Qua2V5cyhtb250aGx5KS5zb3J0KCk7CgogICAgICBpZiAoZXZvbHV0aW9uQ2hhcnQpIHsgZXZvbHV0aW9uQ2hhcnQuZGVzdHJveSgpOyBldm9sdXRpb25DaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjb25zdCBsYWJlbHMgPSBtb250aHMubWFwKChrZXkpID0+IHsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICByZXR1cm4gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgfSk7CgogICAgICBjb25zdCBkYXRhc2V0cyA9IFsKICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5leHBlbnNlKSwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICB7IGxhYmVsOiAiUmV2ZW51cyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uaW5jb21lKSwgYmFja2dyb3VuZENvbG9yOiAiIzIyYzU1ZSIgfSwKICAgICAgXTsKCiAgICAgIGV2b2x1dGlvbkNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJiYXIiLAogICAgICAgIGRhdGE6IHsgbGFiZWxzLCBkYXRhc2V0cyB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9LCBiZWdpbkF0WmVybzogdHJ1ZSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5kYXRhc2V0LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQueSl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbXBhcmVyIGRldXggbW9pcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHNlbGVjdEEgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIik7CiAgICAgIGNvbnN0IHNlbGVjdEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIik7CgogICAgICBmb3IgKGNvbnN0IHNlbGVjdCBvZiBbc2VsZWN0QSwgc2VsZWN0Ql0pIHsKICAgICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBpZiAobW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpKSBzZWxlY3QudmFsdWUgPSBwcmV2aW91c1ZhbHVlOwogICAgICB9CiAgICAgIC8vIFBhciBkw6lmYXV0IDogbW9pcyBlbiBjb3VycyB2cyBtb2lzIHByw6ljw6lkZW50LCBzaSBsZXMgZGV1eCBleGlzdGVudC4KICAgICAgaWYgKCFzZWxlY3RBLnZhbHVlICYmIG1vbnRocy5sZW5ndGggPiAwKSBzZWxlY3RBLnZhbHVlID0gbW9udGhzWzBdOwogICAgICBpZiAoIXNlbGVjdEIudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDEpIHNlbGVjdEIudmFsdWUgPSBtb250aHNbMV07CiAgICB9CgogICAgZnVuY3Rpb24gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIG1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgcmV0dXJuIHsgdG90YWxzLCB0b3RhbCB9OwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLWVtcHR5Iik7CiAgICAgIGNvbnN0IG1vbnRoQSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS52YWx1ZTsKICAgICAgY29uc3QgbW9udGhCID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLnZhbHVlOwoKICAgICAgaWYgKCFtb250aEEgfHwgIW1vbnRoQikgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgY29uc3QgeyB0b3RhbHM6IHRvdGFsc0EsIHRvdGFsOiBncmFuZEEgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHMoYWxsVHJhbnNhY3Rpb25zLCBtb250aEEpOwogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQiwgdG90YWw6IGdyYW5kQiB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQik7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBbLi4ubmV3IFNldChbLi4uT2JqZWN0LmtleXModG90YWxzQSksIC4uLk9iamVjdC5rZXlzKHRvdGFsc0IpXSldLnNvcnQoCiAgICAgICAgKGEsIGIpID0+ICh0b3RhbHNCW2JdIHx8IDApIC0gKHRvdGFsc0FbYV0gfHwgMCkKICAgICAgKTsKCiAgICAgIGNvbnN0IFt5YSwgbWFdID0gbW9udGhBLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IFt5YiwgbWJdID0gbW9udGhCLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGxhYmVsQSA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHlhLCBtYSAtIDEsIDEpKTsKICAgICAgY29uc3QgbGFiZWxCID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWIsIG1iIC0gMSwgMSkpOwoKICAgICAgLy8gRGlmZiA9IG1vbnRhbnQgZHUgbW9pcyBCIG1vaW5zIGNlbHVpIGR1IG1vaXMgQS4gUG91ciBkZXMgZMOpcGVuc2VzLAogICAgICAvLyBkw6lwZW5zZXIgUExVUyAoZGlmZiBwb3NpdGlmKSBlc3QgbGEgbWF1dmFpc2Ugbm91dmVsbGUg4oaSIHJvdWdlIDsgZW4KICAgICAgLy8gZMOpcGVuc2VyIE1PSU5TIChkaWZmIG7DqWdhdGlmKSDihpIgdmVydC4KICAgICAgZnVuY3Rpb24gZGlmZkNlbGwoYSwgYikgewogICAgICAgIGNvbnN0IGRpZmYgPSBiIC0gYTsKICAgICAgICBpZiAoTWF0aC5hYnMoZGlmZikgPCAwLjAxKSByZXR1cm4gYDx0ZD7igJQ8L3RkPmA7CiAgICAgICAgY29uc3QgY2xzID0gZGlmZiA+IDAgPyAiZGlmZi1uZWdhdGl2ZSIgOiAiZGlmZi1wb3NpdGl2ZSI7CiAgICAgICAgcmV0dXJuIGA8dGQgY2xhc3M9IiR7Y2xzfSI+JHtkaWZmID4gMCA/ICIrIiA6ICIifSR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGRpZmYpfTwvdGQ+YDsKICAgICAgfQoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD4ke2xhYmVsQX08L3RoPjx0aD4ke2xhYmVsQn08L3RoPjx0aD5EaWZmw6lyZW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYSA9IHRvdGFsc0FbY2F0XSB8fCAwOwogICAgICAgIGNvbnN0IGIgPSB0b3RhbHNCW2NhdF0gfHwgMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYil9PC90ZD4ke2RpZmZDZWxsKGEsIGIpfTwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8dHIgY2xhc3M9InRvdGFsLXJvdyI+PHRkPlRvdGFsIGTDqXBlbnNlczwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGdyYW5kQSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRCKX08L3RkPiR7ZGlmZkNlbGwoZ3JhbmRBLCBncmFuZEIpfTwvdHI+YDsKICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgcmVuZGVyTW9udGhDb21wYXJpc29uKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENhbGN1bGUsIHBvdXIgY2hhcXVlIGNhdMOpZ29yaWUgZGUgZMOpcGVuc2UsIGxhIG1veWVubmUgbWVuc3VlbGxlLCBsZQogICAgLy8gbW9udGFudCBkdSBtb2lzIGVuIGNvdXJzLCBldCBsYSB0ZW5kYW5jZSAoZGlyZWN0aW9uICsgcmF0aW8gdnMKICAgIC8vIG1veWVubmUpLiBQYXJ0YWfDqSBlbnRyZSBsZSB0YWJsZWF1ICJNb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllIgogICAgLy8gZXQgbGVzIGNvbnNlaWxzIGQnw6lwYXJnbmUsIHBvdXIgbmUgcGFzIGR1cGxpcXVlciBjZXR0ZSBsb2dpcXVlLgogICAgZnVuY3Rpb24gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aEtleXMgPSBbLi4ubmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSldLnNvcnQoKTsKICAgICAgaWYgKG1vbnRoS2V5cy5sZW5ndGggPT09IDApIHJldHVybiBbXTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlzW21vbnRoS2V5cy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgbmJNb250aHMgPSBtb250aEtleXMubGVuZ3RoOwoKICAgICAgLy8gdG90YWwgcGFyIGNhdMOpZ29yaWUsIGV0IHBhciBjYXTDqWdvcmllK21vaXMgKHBvdXIgaXNvbGVyIGxlIG1vaXMgZW4gY291cnMpCiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSA9PT0gY3VycmVudE1vbnRoS2V5KSB7CiAgICAgICAgICBjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9IChjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgcmV0dXJuIGNhdGVnb3JpZXMubWFwKChjYXQpID0+IHsKICAgICAgICBjb25zdCBhdmVyYWdlID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdIC8gbmJNb250aHM7CiAgICAgICAgY29uc3QgY3VycmVudCA9IGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbY2F0XSB8fCAwOwogICAgICAgIGxldCBkaXJlY3Rpb24gPSAic3RhYmxlIjsKICAgICAgICBsZXQgcmF0aW8gPSAwOwogICAgICAgIGlmIChhdmVyYWdlID4gMCkgewogICAgICAgICAgcmF0aW8gPSAoY3VycmVudCAtIGF2ZXJhZ2UpIC8gYXZlcmFnZTsKICAgICAgICAgIGlmIChyYXRpbyA+IDAuMTUpIGRpcmVjdGlvbiA9ICJ1cCI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA8IC0wLjE1KSBkaXJlY3Rpb24gPSAiZG93biI7CiAgICAgICAgfSBlbHNlIGlmIChjdXJyZW50ID4gMCkgewogICAgICAgICAgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHsgY2F0ZWdvcnk6IGNhdCwgYXZlcmFnZSwgY3VycmVudCwgcmF0aW8sIGRpcmVjdGlvbiB9OwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHJlbmQtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBpZiAodHJlbmRzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD5Nb3llbm5lL21vaXM8L3RoPjx0aD5DZSBtb2lzLWNpPC90aD48dGg+VGVuZGFuY2U8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCB0IG9mIHRyZW5kcykgewogICAgICAgIGxldCB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWZsYXQiPuKGkiBzdGFibGU8L3NwYW4+YDsKICAgICAgICBpZiAodC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRyZW5kSHRtbCA9IHQuYXZlcmFnZSA+IDAKICAgICAgICAgICAgPyBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgKyR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lPC9zcGFuPmAKICAgICAgICAgICAgOiBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgbm91dmVhdTwvc3Bhbj5gOwogICAgICAgIH0gZWxzZSBpZiAodC5kaXJlY3Rpb24gPT09ICJkb3duIikgewogICAgICAgICAgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC1kb3duIj7ihpMgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YDsKICAgICAgICB9CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2VzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodC5hdmVyYWdlKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmN1cnJlbnQpfTwvdGQ+PHRkPiR7dHJlbmRIdG1sfTwvdGQ+PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB3cmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQmlsYW4gYW5udWVsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBNT05USF9TSE9SVF9MQUJFTFMgPSBbCiAgICAgICJKYW4iLCAiRsOpdiIsICJNYXIiLCAiQXZyIiwgIk1haSIsICJKdWluIiwgIkp1aWwiLCAiQW/Du3QiLCAiU2VwIiwgIk9jdCIsICJOb3YiLCAiRMOpYyIsCiAgICBdOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlWWVhclNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFycyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiB0eC5leHBlbnNlX2RhdGUuc2xpY2UoMCwgNCkpKV0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3QgY3VycmVudFllYXIgPSBTdHJpbmcobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTsKICAgICAgaWYgKCF5ZWFycy5pbmNsdWRlcyhjdXJyZW50WWVhcikpIHllYXJzLnVuc2hpZnQoY3VycmVudFllYXIpOwoKICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgc2VsZWN0LmlubmVySFRNTCA9IHllYXJzLm1hcCgoeSkgPT4gYDxvcHRpb24gdmFsdWU9IiR7eX0iPiR7eX08L29wdGlvbj5gKS5qb2luKCIiKTsKICAgICAgc2VsZWN0LnZhbHVlID0geWVhcnMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkgPyBwcmV2aW91c1ZhbHVlIDogY3VycmVudFllYXI7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyWWVhcmx5T3ZlcnZpZXcodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKTsKICAgICAgY29uc3QgeWVhciA9IHNlbGVjdC52YWx1ZTsKICAgICAgaWYgKCF5ZWFyKSByZXR1cm47CgogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQteWVhcmx5Iik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LWVtcHR5Iik7CiAgICAgIGNvbnN0IHRhYmxlV3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktY2F0ZWdvcnktdGFibGUtd3JhcCIpOwoKICAgICAgY29uc3QgeWVhclRyYW5zYWN0aW9ucyA9IHRyYW5zYWN0aW9ucy5maWx0ZXIoKHR4KSA9PiB0eC5leHBlbnNlX2RhdGUuc2xpY2UoMCwgNCkgPT09IHllYXIpOwoKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBjb25zdCBleHBlbnNlQnlNb250aCA9IEFycmF5KDEyKS5maWxsKDApOwogICAgICBjb25zdCBpbmNvbWVCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB5ZWFyVHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgbW9udGhJbmRleCA9IE51bWJlcih0eC5leHBlbnNlX2RhdGUuc2xpY2UoNSwgNykpIC0gMTsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHsKICAgICAgICAgIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgaW5jb21lQnlNb250aFttb250aEluZGV4XSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICAgIGV4cGVuc2VCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwoKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS10b3RhbC1leHBlbnNlcyIpLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsRXhwZW5zZXMpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWluY29tZSIpLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgICAgY29uc3QgbmV0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LW5ldCIpOwogICAgICBuZXRFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChuZXQpOwogICAgICBuZXRFbC5jbGFzc05hbWUgPSAieWVhcmx5LXN0YXQtdmFsdWUgIiArIChuZXQgPj0gMCA/ICJpbmNvbWUiIDogImV4cGVuc2UiKTsKCiAgICAgIGlmICh5ZWFybHlDaGFydCkgeyB5ZWFybHlDaGFydC5kZXN0cm95KCk7IHllYXJseUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKHllYXJUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICB0YWJsZVdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgeWVhcmx5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzOiBNT05USF9TSE9SVF9MQUJFTFMsCiAgICAgICAgICBkYXRhc2V0czogWwogICAgICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogZXhwZW5zZUJ5TW9udGgsIGJhY2tncm91bmRDb2xvcjogIiNlZjQ0NDQiIH0sCiAgICAgICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogaW5jb21lQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiIzIyYzU1ZSIgfSwKICAgICAgICAgIF0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeDogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICAgIHk6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSB9LAogICAgICAgIH0sCiAgICAgIH0pOwoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD5Ub3RhbDwvdGg+PHRoPiUgZGUgbCdhbm7DqWU8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCBjYXQgb2YgY2F0ZWdvcmllcykgewogICAgICAgIGNvbnN0IGFtb3VudCA9IHRvdGFsc0J5Q2F0ZWdvcnlbY2F0XTsKICAgICAgICBjb25zdCBwY3QgPSB0b3RhbEV4cGVuc2VzID4gMCA/IE1hdGgucm91bmQoKGFtb3VudCAvIHRvdGFsRXhwZW5zZXMpICogMTAwKSA6IDA7CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2VzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGFtb3VudCl9PC90ZD48dGQ+JHtwY3R9JTwvdGQ+PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB0YWJsZVdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gcmVuZGVyWWVhcmx5T3ZlcnZpZXcoYWxsVHJhbnNhY3Rpb25zKSk7CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJCdWRnZXRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHBvcHVsYXRlQ29tcGFyZU1vbnRoU2VsZWN0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJNb250aENvbXBhcmlzb24oKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlclllYXJseU92ZXJ2aWV3KHRyYW5zYWN0aW9ucyk7CiAgICAgIHNldHVwRGFzaGJvYXJkQ2hpcHMoKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTw6lsZWN0ZXVyIGR1IHRhYmxlYXUgZGUgYm9yZCA6IHVuIHNldWwgYmxvYyBhZmZpY2jDqSDDoCBsYSBmb2lzIChzdXIgbGVzCiAgICAvLyA3IGVtcGlsw6lzKSBwb3VyIHF1ZSDDp2EgdGllbm5lIHN1ciB1biDDqWNyYW4gZGUgdMOpbMOpcGhvbmUgc2FucyBkw6lmaWxlcgogICAgLy8gc2FucyBmaW4uIExlcyBjYWxjdWxzL2dyYXBoaXF1ZXMgZXV4LW3Dqm1lcyBuZSBjaGFuZ2VudCBwYXMg4oCUIHNldWxlIGxhCiAgICAvLyB2aXNpYmlsaXTDqSBkZXMgYmxvY3MgZXN0IHBpbG90w6llIHBhciBsYSBwdWNlIGFjdGl2ZS4KICAgIGNvbnN0IERBU0hCT0FSRF9TRUNUSU9OUyA9IFsKICAgICAgeyBrZXk6ICJleHBlbnNlcyIsIGxhYmVsOiAiRMOpcGVuc2VzIiwgcm93SWQ6ICJkYXNoLXJvdy1leHBlbnNlcyIgfSwKICAgICAgeyBrZXk6ICJpbmNvbWUiLCBsYWJlbDogIlJldmVudXMiLCByb3dJZDogImRhc2gtcm93LWluY29tZSIgfSwKICAgICAgeyBrZXk6ICJidWRnZXRzIiwgbGFiZWw6ICJCdWRnZXRzIiwgcm93SWQ6ICJkYXNoLXJvdy1idWRnZXRzIiB9LAogICAgICB7IGtleTogImV2b2x1dGlvbiIsIGxhYmVsOiAiw4l2b2x1dGlvbiIsIHJvd0lkOiAiZGFzaC1yb3ctZXZvbHV0aW9uIiB9LAogICAgICB7IGtleTogImNvbXBhcmUiLCBsYWJlbDogIkNvbXBhcmVyIiwgcm93SWQ6ICJkYXNoLXJvdy1jb21wYXJlIiB9LAogICAgICB7IGtleTogInRyZW5kIiwgbGFiZWw6ICJUZW5kYW5jZXMiLCByb3dJZDogImRhc2gtcm93LXRyZW5kIiB9LAogICAgICB7IGtleTogInllYXJseSIsIGxhYmVsOiAiQW5uw6llIiwgcm93SWQ6ICJkYXNoLXJvdy15ZWFybHkiIH0sCiAgICBdOwogICAgbGV0IGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24gPSBEQVNIQk9BUkRfU0VDVElPTlNbMF0ua2V5OwogICAgbGV0IGRhc2hib2FyZENoaXBzQnVpbHQgPSBmYWxzZTsKCiAgICBmdW5jdGlvbiBzaG93RGFzaGJvYXJkU2VjdGlvbihrZXkpIHsKICAgICAgZGFzaGJvYXJkQWN0aXZlU2VjdGlvbiA9IGtleTsKICAgICAgZm9yIChjb25zdCBzZWN0aW9uIG9mIERBU0hCT0FSRF9TRUNUSU9OUykgewogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHNlY3Rpb24ucm93SWQpLmNsYXNzTGlzdC50b2dnbGUoImRhc2gtaGlkZGVuIiwgc2VjdGlvbi5rZXkgIT09IGtleSk7CiAgICAgIH0KICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLmRhc2hib2FyZC1jaGlwIikuZm9yRWFjaCgoY2hpcCkgPT4gewogICAgICAgIGNoaXAuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgY2hpcC5kYXRhc2V0LnNlY3Rpb24gPT09IGtleSk7CiAgICAgIH0pOwogICAgICAvLyBVbiBncmFwaGlxdWUgQ2hhcnQuanMgcmVjcsOpw6kgcGVuZGFudCBxdWUgc29uIGJsb2Mgw6l0YWl0IG1hc3F1w6kKICAgICAgLy8gKGRpc3BsYXk6bm9uZSkgc2UgcmV0cm91dmUgYXZlYyB1biBjYW5ldmFzIGRlIHRhaWxsZSBudWxsZSBldCBuZSBzZQogICAgICAvLyBjb3JyaWdlIHBhcyB0b3V0IHNldWwgZW4gcmVkZXZlbmFudCB2aXNpYmxlIOKAlCBvbiBmb3JjZSB1biByZXNpemUKICAgICAgLy8ganVzdGUgYXByw6hzIGwnYXZvaXIgYWZmaWNow6ksIHBvdXIgbGVzIDQgZ3JhcGhpcXVlcyBjb25jZXJuw6lzLgogICAgICBmb3IgKGNvbnN0IGNoYXJ0IG9mIFtjYXRlZ29yeUNoYXJ0LCBpbmNvbWVDYXRlZ29yeUNoYXJ0LCBldm9sdXRpb25DaGFydCwgeWVhcmx5Q2hhcnRdKSB7CiAgICAgICAgaWYgKGNoYXJ0KSBjaGFydC5yZXNpemUoKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldHVwRGFzaGJvYXJkQ2hpcHMoKSB7CiAgICAgIGlmIChkYXNoYm9hcmRDaGlwc0J1aWx0KSB7CiAgICAgICAgc2hvd0Rhc2hib2FyZFNlY3Rpb24oZGFzaGJvYXJkQWN0aXZlU2VjdGlvbik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IHJvdyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2hpcC1yb3ciKTsKICAgICAgZm9yIChjb25zdCBzZWN0aW9uIG9mIERBU0hCT0FSRF9TRUNUSU9OUykgewogICAgICAgIGNvbnN0IGNoaXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBjaGlwLnR5cGUgPSAiYnV0dG9uIjsKICAgICAgICBjaGlwLmNsYXNzTmFtZSA9ICJkYXNoYm9hcmQtY2hpcCI7CiAgICAgICAgY2hpcC5kYXRhc2V0LnNlY3Rpb24gPSBzZWN0aW9uLmtleTsKICAgICAgICBjaGlwLnRleHRDb250ZW50ID0gc2VjdGlvbi5sYWJlbDsKICAgICAgICBjaGlwLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0Rhc2hib2FyZFNlY3Rpb24oc2VjdGlvbi5rZXkpKTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoY2hpcCk7CiAgICAgIH0KICAgICAgZGFzaGJvYXJkQ2hpcHNCdWlsdCA9IHRydWU7CiAgICAgIHNob3dEYXNoYm9hcmRTZWN0aW9uKGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24pOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIERpY3TDqWUgdm9jYWxlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtaWNCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLW1pYyIpOwogICAgY29uc3Qgdm9pY2VCYW5uZXJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2b2ljZS1iYW5uZXIiKTsKCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgdHJhbnNhY3Rpb24gY3LDqcOpZSBQQVIgTEEgVk9JWCBkYW5zIGNldHRlIHNlc3Npb24gZGUKICAgIC8vIG5hdmlnYXRpb24gKHJlbWlzIMOgIHrDqXJvIHNpIG9uIHJlY2hhcmdlIGxhIHBhZ2UpLiBTZXJ0IHVuaXF1ZW1lbnQgw6AKICAgIC8vIGFwcGxpcXVlciB1bmUgY29ycmVjdGlvbiAoImVuIGZhaXQgYyfDqXRhaXQgcGx1dMO0dC4uLiIpIHN1ciBsYSBib25uZQogICAgLy8gdHJhbnNhY3Rpb24uIFNhbnMgw6dhLCBvdSBzaSBsYSBwaHJhc2Ugbidlc3QgcGFzIHVuZSBjb3JyZWN0aW9uLCBvbgogICAgLy8gY3LDqWUgdG91am91cnMgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIOKAlCBtaWV1eCB2YXV0IHVuIGRvdWJsb24gcXUndW5lCiAgICAvLyBkw6lwZW5zZSBjb3Jyb21wdWUgcGFyIGVycmV1ci4KICAgIGxldCBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gbnVsbDsKCiAgICBmdW5jdGlvbiBzZXRWb2ljZUJhbm5lcih0ZXh0KSB7CiAgICAgIGlmICghdGV4dCkgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJhbnN3ZXIiKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gIiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQW5zd2VyQmFubmVyKHRleHQpIHsKICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJhbnN3ZXIiKTsKICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICB9CgogICAgLy8gUHJvbm9uY2UgbGEgcsOpcG9uc2Ugw6AgdW5lIHF1ZXN0aW9uIHZvY2FsZSAoIkFzc2lzdGFudCB2b2NhbCBxdWVzdGlvbiIpLgogICAgLy8gUHVyIGJvbnVzIDogc2kgbGEgc3ludGjDqHNlIHZvY2FsZSBuJ2VzdCBwYXMgZGlzcG8gb3Ugw6ljaG91ZSwgbGEgcsOpcG9uc2UKICAgIC8vIHJlc3RlIGFmZmljaMOpZSBkYW5zIGxlIGJhbmRlYXUsIGRvbmMgb24gYXZhbGUgbCdlcnJldXIgc2FucyBibG9xdWVyLgogICAgZnVuY3Rpb24gc3BlYWtWb2ljZUFuc3dlcih0ZXh0KSB7CiAgICAgIGlmICghKCJzcGVlY2hTeW50aGVzaXMiIGluIHdpbmRvdykpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICB3aW5kb3cuc3BlZWNoU3ludGhlc2lzLmNhbmNlbCgpOwogICAgICAgIGNvbnN0IHV0dGVyYW5jZSA9IG5ldyBTcGVlY2hTeW50aGVzaXNVdHRlcmFuY2UodGV4dCk7CiAgICAgICAgdXR0ZXJhbmNlLmxhbmcgPSAiZnItRlIiOwogICAgICAgIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuc3BlYWsodXR0ZXJhbmNlKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50LgogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb25maXJtYXRpb24gdm9jYWxlIOKAlCBxdWFuZCBsJ0lBIGEgdW4gZG91dGUgc3VyIGwnaW50ZXJwcsOpdGF0aW9uCiAgICAvLyAobW9udGFudCBhcHByb3hpbWF0aWYsIGNhdMOpZ29yaWUgaW5jZXJ0YWluZS4uLiksIGVsbGUgZGVtYW5kZQogICAgLy8gY29uZmlybWF0aW9uIGF1IGxpZXUgZCdhcHBsaXF1ZXIgZGlyZWN0ZW1lbnQuIEwndXRpbGlzYXRldXIgcGV1dAogICAgLy8gcsOpcG9uZHJlIGVuIGFwcHV5YW50IHN1ciAiQ29uZmlybWVyIi8iQW5udWxlciIsIE9VIGVuIHLDqS1hcHB1eWFudCBzdXIKICAgIC8vIGxlIG1pY3JvIHBvdXIgcsOpcG9uZHJlIGRlIHZpdmUgdm9peCAoIm91aSBjJ2VzdCDDp2EiLCAibm9uLCBjaGFuZ2Ugw6dhCiAgICAvLyBlbiByZXN0YXVyYW50Ii4uLikg4oCUIGRhbnMgY2UgY2FzLCBsYSBkaWN0w6llIHN1aXZhbnRlIGVzdCBpbnRlcnByw6l0w6llCiAgICAvLyBjb21tZSB1bmUgcsOpcG9uc2Ugw6AgQ0VUVEUgY29uZmlybWF0aW9uIHBsdXTDtHQgcXVlIGNvbW1lIHVuZSBub3V2ZWxsZQogICAgLy8gdHJhbnNhY3Rpb24gKHZvaXIgcGVuZGluZ1ZvaWNlQWN0aW9uLCB2w6lyaWZpw6kgZGFucyBsZSBsaXN0ZW5lcgogICAgLy8gInJlc3VsdCIgZGUgbGEgcmVjb25uYWlzc2FuY2Ugdm9jYWxlIHVuIHBldSBwbHVzIGJhcykuCiAgICBsZXQgcGVuZGluZ1ZvaWNlQWN0aW9uID0gbnVsbDsgLy8geyBraW5kOiAidHJhbnNhY3Rpb24iIHwgImVkaXRfbGFzdCIsIGRhdGE6IHsuLi59IH0gb3UgbnVsbAogICAgY29uc3Qgdm9pY2VDb25maXJtQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtY29uZmlybS1iYW5uZXIiKTsKCiAgICBmdW5jdGlvbiBoaWRlVm9pY2VDb25maXJtQmFubmVyKCkgewogICAgICBwZW5kaW5nVm9pY2VBY3Rpb24gPSBudWxsOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuaW5uZXJIVE1MID0gIiI7CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd1ZvaWNlQ29uZmlybUJhbm5lcihraW5kLCBwYXJzZWQpIHsKICAgICAgcGVuZGluZ1ZvaWNlQWN0aW9uID0gewogICAgICAgIGtpbmQsCiAgICAgICAgZGF0YToKICAgICAgICAgIGtpbmQgPT09ICJ0cmFuc2FjdGlvbiIKICAgICAgICAgICAgPyBwYXJzZWQKICAgICAgICAgICAgOiB7CiAgICAgICAgICAgICAgICB0YXJnZXQ6IHBhcnNlZC50YXJnZXQsCiAgICAgICAgICAgICAgICBuZXdfdHlwZTogcGFyc2VkLnJlcXVlc3RlZF9uZXdfdHlwZSwKICAgICAgICAgICAgICAgIG5ld19jYXRlZ29yeTogcGFyc2VkLnJlcXVlc3RlZF9uZXdfY2F0ZWdvcnksCiAgICAgICAgICAgICAgfSwKICAgICAgfTsKCiAgICAgIGxldCBxdWVzdGlvbjsKICAgICAgaWYgKGtpbmQgPT09ICJ0cmFuc2FjdGlvbiIpIHsKICAgICAgICBjb25zdCB2ZXJiID0gcGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSIgOiAiRMOpcGVuc2UiOwogICAgICAgIGNvbnN0IGNhdExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbcGFyc2VkLmNhdGVnb3J5XSB8fCBwYXJzZWQuY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGVzY1BhcnQgPSBwYXJzZWQuZGVzY3JpcHRpb24gPyBgICgke3BhcnNlZC5kZXNjcmlwdGlvbn0pYCA6ICIiOwogICAgICAgIHF1ZXN0aW9uID0KICAgICAgICAgIGAke3ZlcmJ9IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpfSBlbiAke2NhdExhYmVsfSR7ZGVzY1BhcnR9LCBgICsKICAgICAgICAgIGBsZSAke2RhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHBhcnNlZC5leHBlbnNlX2RhdGUpKX0g4oCUIGMnZXN0IGJpZW4gw6dhID9gOwogICAgICB9IGVsc2UgewogICAgICAgIC8vIGVkaXRfbGFzdCA6IG9uIHJldHJvdXZlIGxhIHRyYW5zYWN0aW9uIGNpYmzDqWUgZGFucyBhbGxUcmFuc2FjdGlvbnMKICAgICAgICAvLyAoZMOpasOgIHRyacOpIHBhciBkYXRlIGTDqWNyb2lzc2FudGUpIHBvdXIgZG9ubmVyIHVuIGNvbnRleHRlIHV0aWxlLgogICAgICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKCh0KSA9PiB7CiAgICAgICAgICBpZiAocGFyc2VkLnRhcmdldCA9PT0gImxhc3RfZXhwZW5zZSIpIHJldHVybiB0LnR5cGUgPT09ICJleHBlbnNlIjsKICAgICAgICAgIGlmIChwYXJzZWQudGFyZ2V0ID09PSAibGFzdF9pbmNvbWUiKSByZXR1cm4gdC50eXBlID09PSAiaW5jb21lIjsKICAgICAgICAgIHJldHVybiB0cnVlOwogICAgICAgIH0pOwogICAgICAgIGNvbnN0IHRhcmdldCA9IGNhbmRpZGF0ZXNbMF07CiAgICAgICAgY29uc3QgdGFyZ2V0TGFiZWwgPSB0YXJnZXQKICAgICAgICAgID8gYCR7dGFyZ2V0LnR5cGUgPT09ICJpbmNvbWUiID8gImxlIHJldmVudSIgOiAibGEgZMOpcGVuc2UifSBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0YXJnZXQuYW1vdW50KX1gICsKICAgICAgICAgICAgKHRhcmdldC5kZXNjcmlwdGlvbiA/IGAgKCR7dGFyZ2V0LmRlc2NyaXB0aW9ufSlgIDogIiIpCiAgICAgICAgICA6ICJsYSB0cmFuc2FjdGlvbiBjb3JyZXNwb25kYW50ZSI7CiAgICAgICAgY29uc3QgY2hhbmdlcyA9IFtdOwogICAgICAgIGlmIChwYXJzZWQucmVxdWVzdGVkX25ld190eXBlKSB7CiAgICAgICAgICBjaGFuZ2VzLnB1c2goYHR5cGUgOiAke3BhcnNlZC5yZXF1ZXN0ZWRfbmV3X3R5cGUgPT09ICJpbmNvbWUiID8gInJldmVudSIgOiAiZMOpcGVuc2UifWApOwogICAgICAgIH0KICAgICAgICBpZiAocGFyc2VkLnJlcXVlc3RlZF9uZXdfY2F0ZWdvcnkpIHsKICAgICAgICAgIGNoYW5nZXMucHVzaChgY2F0w6lnb3JpZSA6ICR7YWxsQ2F0ZWdvcnlMYWJlbHNbcGFyc2VkLnJlcXVlc3RlZF9uZXdfY2F0ZWdvcnldIHx8IHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5fWApOwogICAgICAgIH0KICAgICAgICBxdWVzdGlvbiA9IGBNb2RpZmllciAke3RhcmdldExhYmVsfSDigJQgJHtjaGFuZ2VzLmpvaW4oIiwgIikgfHwgImF1Y3VuIGNoYW5nZW1lbnQgcmVjb25udSJ9IOKAlCBjJ2VzdCBiaWVuIMOnYSA/YDsKICAgICAgfQoKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwoKICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgdGV4dC50ZXh0Q29udGVudCA9IHF1ZXN0aW9uOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5hcHBlbmRDaGlsZCh0ZXh0KTsKCiAgICAgIGNvbnN0IGNvbnRyb2xzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGNvbnRyb2xzLmNsYXNzTmFtZSA9ICJ2b2ljZS1jb25maXJtLWNvbnRyb2xzIjsKCiAgICAgIGNvbnN0IGNvbmZpcm1CdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgY29uZmlybUJ0bi50ZXh0Q29udGVudCA9ICLinIUgQ29uZmlybWVyIjsKICAgICAgY29uZmlybUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICBjb25maXJtQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3VibWl0Vm9pY2VDb25maXJtRGVjaXNpb24oImNvbmZpcm0iKSk7CiAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGNvbmZpcm1CdG4pOwoKICAgICAgY29uc3QgY2FuY2VsQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGNhbmNlbEJ0bi50ZXh0Q29udGVudCA9ICLinYwgQW5udWxlciI7CiAgICAgIGNhbmNlbEJ0bi5jbGFzc05hbWUgPSAiYnRuLXNlY29uZGFyeS1zbSI7CiAgICAgIGNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN1Ym1pdFZvaWNlQ29uZmlybURlY2lzaW9uKCJjYW5jZWwiKSk7CiAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGNhbmNlbEJ0bik7CgogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5hcHBlbmRDaGlsZChjb250cm9scyk7CgogICAgICBjb25zdCBoaW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICBoaW50LmNsYXNzTmFtZSA9ICJ2b2ljZS1jb25maXJtLWhpbnQiOwogICAgICBoaW50LnRleHRDb250ZW50ID0gIvCfjqQgVHUgcGV1eCBhdXNzaSByw6lwb25kcmUgw6AgbGEgdm9peCBlbiByw6ktYXBwdXlhbnQgc3VyIGxlIG1pY3JvLiI7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmFwcGVuZENoaWxkKGhpbnQpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHN1Ym1pdFZvaWNlQ29uZmlybURlY2lzaW9uKGRlY2lzaW9uKSB7CiAgICAgIGlmICghcGVuZGluZ1ZvaWNlQWN0aW9uKSByZXR1cm47CiAgICAgIGNvbnN0IHsga2luZCwgZGF0YSB9ID0gcGVuZGluZ1ZvaWNlQWN0aW9uOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL2NvbmZpcm0iLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZGVjaXNpb24sIGtpbmQsIHBlbmRpbmc6IGRhdGEgfSksCiAgICAgICAgfSk7CiAgICAgICAgYXdhaXQgaGFuZGxlVm9pY2VDb25maXJtUmVzdWx0KHJlc3VsdCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGhhbmRsZVZvaWNlQ29uZmlybVJlc3VsdChyZXN1bHQpIHsKICAgICAgaGlkZVZvaWNlQ29uZmlybUJhbm5lcigpOwogICAgICBpZiAocmVzdWx0LmRlY2lzaW9uID09PSAiY2FuY2VsIikgewogICAgICAgIHNob3dUb2FzdCgiQW5udWzDqSIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICAvLyBTaW5vbiwgcmVzdWx0IGVzdCB1biByw6lzdWx0YXQgZMOpasOgIGZpbmFsaXPDqSAoVm9pY2VQYXJzZVJlc3VsdCBwb3VyCiAgICAgIC8vIHVuZSB0cmFuc2FjdGlvbiwgVm9pY2VFZGl0UmVzdWx0IHBvdXIgdW4gZWRpdF9sYXN0KSA6IG9uIGxlIHRyYWl0ZQogICAgICAvLyBleGFjdGVtZW50IGNvbW1lIHVuIHLDqXN1bHRhdCBkZSBkaWN0w6llIG5vcm1hbC4KICAgICAgYXdhaXQgaGFuZGxlVm9pY2VQYXJzZVJlc3VsdChyZXN1bHQpOwogICAgfQoKICAgIC8vIFBvaW50IGQnZW50csOpZSBjb21tdW4gcG91ciBsZSByw6lzdWx0YXQgZCd1bmUgZGljdMOpZSAiZnJhw65jaGUiIChlbnZvecOpZQogICAgLy8gw6AgL2FwaS92b2ljZS9wYXJzZSkgRVQgcG91ciBsZSByw6lzdWx0YXQgZMOpasOgIGZpbmFsaXPDqSBkJ3VuZQogICAgLy8gY29uZmlybWF0aW9uIOKAlCBsZXMgZGV1eCBjaGVtaW5zIHJldG9tYmVudCBzdXIgbGUgbcOqbWUgdHJhaXRlbWVudCB1bmUKICAgIC8vIGZvaXMgcXUnb24gc2FpdCBxdSdpbCBuJ3kgYSBwbHVzIGRlIGRvdXRlIMOgIGxldmVyLgogICAgYXN5bmMgZnVuY3Rpb24gaGFuZGxlVm9pY2VQYXJzZVJlc3VsdChwYXJzZWQpIHsKICAgICAgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJxdWVzdGlvbiIpIHsKICAgICAgICBzZXRWb2ljZUFuc3dlckJhbm5lcihwYXJzZWQuYW5zd2VyKTsKICAgICAgICBzcGVha1ZvaWNlQW5zd2VyKHBhcnNlZC5hbnN3ZXIpOwogICAgICB9IGVsc2UgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJlZGl0X2xhc3QiKSB7CiAgICAgICAgaWYgKHBhcnNlZC5wZW5kaW5nKSB7CiAgICAgICAgICBzaG93Vm9pY2VDb25maXJtQmFubmVyKCJlZGl0X2xhc3QiLCBwYXJzZWQpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUFuc3dlckJhbm5lcihwYXJzZWQuYW5zd2VyKTsKICAgICAgICAgIHNwZWFrVm9pY2VBbnN3ZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfQogICAgICB9IGVsc2UgaWYgKHBhcnNlZC5uZWVkc19jb25maXJtYXRpb24pIHsKICAgICAgICBzaG93Vm9pY2VDb25maXJtQmFubmVyKCJ0cmFuc2FjdGlvbiIsIHBhcnNlZCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgYXdhaXQgYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpOwogICAgICB9CiAgICB9CgogICAgY29uc3QgU3BlZWNoUmVjb2duaXRpb25DdG9yID0gd2luZG93LlNwZWVjaFJlY29nbml0aW9uIHx8IHdpbmRvdy53ZWJraXRTcGVlY2hSZWNvZ25pdGlvbjsKCiAgICBpZiAoIVNwZWVjaFJlY29nbml0aW9uQ3RvcikgewogICAgICBtaWNCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBtaWNCdG4udGl0bGUgPSAiRGljdMOpZSB2b2NhbGUgbm9uIGRpc3BvbmlibGUgc3VyIGNlIG5hdmlnYXRldXIgKHV0aWxpc2UgQ2hyb21lIG91IEVkZ2UpIjsKICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHJlY29nbml0aW9uID0gbmV3IFNwZWVjaFJlY29nbml0aW9uQ3RvcigpOwogICAgICByZWNvZ25pdGlvbi5sYW5nID0gImZyLUZSIjsKICAgICAgcmVjb2duaXRpb24uY29udGludW91cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5pbnRlcmltUmVzdWx0cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5tYXhBbHRlcm5hdGl2ZXMgPSAxOwoKICAgICAgbGV0IGlzTGlzdGVuaW5nID0gZmFsc2U7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJzdGFydCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IHRydWU7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoImxpc3RlbmluZyIpOwogICAgICAgIHNldFZvaWNlQmFubmVyKCJKZSB0J8OpY291dGXigKYiKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlbmQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZXJyb3IiLCAoZXZlbnQpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgIGlmIChldmVudC5lcnJvciA9PT0gIm5vLXNwZWVjaCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJSaWVuIGVudGVuZHUsIHLDqWVzc2FpZS4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDIwMDApOwogICAgICAgIH0gZWxzZSBpZiAoZXZlbnQuZXJyb3IgPT09ICJub3QtYWxsb3dlZCIgfHwgZXZlbnQuZXJyb3IgPT09ICJzZXJ2aWNlLW5vdC1hbGxvd2VkIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIk1pY3JvIHJlZnVzw6kg4oCUIGF1dG9yaXNlIGwnYWNjw6hzIGF1IG1pY3JvIGRhbnMgdG9uIG5hdmlnYXRldXIuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCA0MDAwKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIobnVsbCk7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBtaWNybyA6ICIgKyBldmVudC5lcnJvciwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInJlc3VsdCIsIGFzeW5jIChldmVudCkgPT4gewogICAgICAgIGNvbnN0IHRyYW5zY3JpcHQgPSBldmVudC5yZXN1bHRzWzBdWzBdLnRyYW5zY3JpcHQ7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoYCIke3RyYW5zY3JpcHR9ImApOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJwcm9jZXNzaW5nIik7CiAgICAgICAgbGV0IGJhbm5lckRlbGF5ID0gMTUwMDsKICAgICAgICB0cnkgewogICAgICAgICAgaWYgKHBlbmRpbmdWb2ljZUFjdGlvbikgewogICAgICAgICAgICAvLyBVbmUgYmFubmnDqHJlIGRlIGNvbmZpcm1hdGlvbiBlc3QgYWZmaWNow6llIDogY2V0dGUgZGljdMOpZSBlc3QKICAgICAgICAgICAgLy8gdW5lIHLDqXBvbnNlICgib3VpIiwgIm5vbiIsICJjaGFuZ2Ugw6dhIGVuLi4uIikgw6AgQ0VUVEUKICAgICAgICAgICAgLy8gY29uZmlybWF0aW9uLCBwYXMgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uLgogICAgICAgICAgICBjb25zdCB7IGtpbmQsIGRhdGEgfSA9IHBlbmRpbmdWb2ljZUFjdGlvbjsKICAgICAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvY29uZmlybSIsIHsKICAgICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHJlcGx5X3RleHQ6IHRyYW5zY3JpcHQsIGtpbmQsIHBlbmRpbmc6IGRhdGEgfSksCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBhd2FpdCBoYW5kbGVWb2ljZUNvbmZpcm1SZXN1bHQocmVzdWx0KTsKICAgICAgICAgICAgYmFubmVyRGVsYXkgPSA0MDAwOwogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgY29uc3QgcGFyc2VkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvcGFyc2UiLCB7CiAgICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0ZXh0OiB0cmFuc2NyaXB0IH0pLAogICAgICAgICAgICB9KTsKICAgICAgICAgICAgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJxdWVzdGlvbiIpIHsKICAgICAgICAgICAgICBiYW5uZXJEZWxheSA9IDYwMDA7CiAgICAgICAgICAgIH0gZWxzZSBpZiAocGFyc2VkLm5lZWRzX2NvbmZpcm1hdGlvbiB8fCBwYXJzZWQucGVuZGluZykgewogICAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gMTUwMDsgLy8gbGEgYmFubmnDqHJlIGRlIGNvbmZpcm1hdGlvbiBwcmVuZCBsZSByZWxhaXMgdmlzdWVsbGVtZW50CiAgICAgICAgICAgIH0gZWxzZSBpZiAocGFyc2VkLmludGVudCA9PT0gImVkaXRfbGFzdCIpIHsKICAgICAgICAgICAgICBiYW5uZXJEZWxheSA9IDQwMDA7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgYXdhaXQgaGFuZGxlVm9pY2VQYXJzZVJlc3VsdChwYXJzZWQpOwogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgYmFubmVyRGVsYXkpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICBtaWNCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgaWYgKGlzTGlzdGVuaW5nKSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdG9wKCk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIHRyeSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdGFydCgpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgLy8gc3RhcnQoKSBqZXR0ZSBzaSBkw6lqw6AgZMOpbWFycsOpIDsgb24gaWdub3JlLgogICAgICAgIH0KICAgICAgfSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU3VnZ2VzdGlvbnMgZGUgY2F0w6lnb3JpZSDigJQgdW5pcXVlbWVudCBhcHLDqHMgdW5lIHNhaXNpZSBwYXIgZGljdMOpZQogICAgLy8gdm9jYWxlICh1bmUgZmF1dGUgZGUgZnJhcHBlIGVuIHNhaXNpZSBtYW51ZWxsZSwgYydlc3QgdW5lIGVycmV1ciBkZQogICAgLy8gbCd1dGlsaXNhdGV1ciwgcGFzIGxhIHBlaW5lIGRlIGxlIHJlbGFuY2VyIGRlc3N1cykuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBDQVRFR09SWV9TVUdHRVNUSU9OX1RIUkVTSE9MRCA9IDM7CgogICAgLy8gTW90cyBkZSBsaWFpc29uIGZyYW7Dp2FpcyDDoCBpZ25vcmVyIDogImNhc2lubyIsICJhdSBjYXNpbm8iIGV0ICJwZXJ0ZSBhdQogICAgLy8gY2FzaW5vIiBkb2l2ZW50IMOqdHJlIHJlY29ubnVzIGNvbW1lIGxhIG3Dqm1lIGlkw6llIG1hbGdyw6kgbGVzIG1vdHMKICAgIC8vIGRpZmbDqXJlbnRzIGF1dG91ciwgZG9uYyBvbiBjb21wYXJlIGRlcyBtb3RzLWNsw6lzIHNpZ25pZmljYXRpZnMgcGx1dMO0dAogICAgLy8gcXVlIGxhIGRlc2NyaXB0aW9uIGNvbXBsw6h0ZSB0ZWxsZSBxdWVsbGUuCiAgICBjb25zdCBERVNDUklQVElPTl9TVE9QV09SRFMgPSBuZXcgU2V0KFsKICAgICAgImEiLCAiYXUiLCAiYXV4IiwgImRlIiwgImR1IiwgImRlcyIsICJkIiwgImxlIiwgImxhIiwgImxlcyIsICJsIiwKICAgICAgInVuIiwgInVuZSIsICJjZSIsICJjZXQiLCAiY2V0dGUiLCAiY2VzIiwgIm1vbiIsICJtYSIsICJtZXMiLAogICAgICAidG9uIiwgInRhIiwgInRlcyIsICJzb24iLCAic2EiLCAic2VzIiwgIm5vdHJlIiwgIm5vcyIsICJ2b3RyZSIsCiAgICAgICJ2b3MiLCAibGV1ciIsICJsZXVycyIsICJjaGV6IiwgInN1ciIsICJkYW5zIiwgInBvdXIiLCAiYXZlYyIsCiAgICAgICJldCIsICJvdSIsICJlbiIsICJwYXIiLAogICAgXSk7CgogICAgLy8gRXh0cmFpdCBsZXMgbW90cy1jbMOpcyBzaWduaWZpY2F0aWZzIGQndW5lIGRlc2NyaXB0aW9uIChhY2NlbnRzIGV0CiAgICAvLyBjYXNzZSBpZ25vcsOpcywgbW90cyBkZSBsaWFpc29uIGV0IG1vdHMgdHJvcCBjb3VydHMgw6ljYXJ0w6lzKS4KICAgIGZ1bmN0aW9uIGV4dHJhY3REZXNjcmlwdGlvbktleXdvcmRzKGRlc2MpIHsKICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IChkZXNjIHx8ICIiKQogICAgICAgIC5ub3JtYWxpemUoIk5GRCIpCiAgICAgICAgLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpIC8vIHJldGlyZSBsZXMgYWNjZW50cyAow6kgLT4gZSwgZXRjLikKICAgICAgICAudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgdG9rZW5zID0gbm9ybWFsaXplZC5zcGxpdCgvW15hLXowLTldKy8pLmZpbHRlcihCb29sZWFuKTsKICAgICAgcmV0dXJuIG5ldyBTZXQoCiAgICAgICAgdG9rZW5zLmZpbHRlcigodCkgPT4gdC5sZW5ndGggPj0gMyAmJiAhREVTQ1JJUFRJT05fU1RPUFdPUkRTLmhhcyh0KSkKICAgICAgKTsKICAgIH0KCiAgICBmdW5jdGlvbiBrZXl3b3Jkc0ludGVyc2VjdChhLCBiKSB7CiAgICAgIGZvciAoY29uc3QgdG9rZW4gb2YgYSkgewogICAgICAgIGlmIChiLmhhcyh0b2tlbikpIHJldHVybiB0cnVlOwogICAgICB9CiAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KCiAgICAvLyBSZXRpcmUgZCd1bmUgZGVzY3JpcHRpb24gbGVzIG1vdHMgcXVpIG9udCBzZXJ2aSDDoCBkw6l0ZWN0ZXIgbGEKICAgIC8vIGNhdMOpZ29yaWUgKGV4LiAiY2FzaW5vIiB1bmUgZm9pcyBxdWUgbGEgY2F0w6lnb3JpZSAiY2FzaW5vIiBleGlzdGUpIDoKICAgIC8vIHVuZSBmb2lzIHF1ZSBsYSBjYXTDqWdvcmllIHBvcnRlIGwnaW5mb3JtYXRpb24sIGxhIHLDqXDDqXRlciBkYW5zIGxhCiAgICAvLyBkZXNjcmlwdGlvbiBuJ2FwcG9ydGUgcGx1cyByaWVuLiBSZW52b2llIG51bGwgc2kgbGEgZGVzY3JpcHRpb24KICAgIC8vIGRldmllbnQgdmlkZSB1bmUgZm9pcyBjZXMgbW90cyByZXRpcsOpcy4KICAgIGZ1bmN0aW9uIHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKGRlc2NyaXB0aW9uLCBrZXl3b3JkcykgewogICAgICBpZiAoIWRlc2NyaXB0aW9uIHx8ICFrZXl3b3JkcyB8fCBrZXl3b3Jkcy5zaXplID09PSAwKSByZXR1cm4gZGVzY3JpcHRpb24gfHwgbnVsbDsKICAgICAgY29uc3Qgd29yZHMgPSBkZXNjcmlwdGlvbi5zcGxpdCgvXHMrLykuZmlsdGVyKEJvb2xlYW4pOwogICAgICBjb25zdCBrZXB0ID0gd29yZHMuZmlsdGVyKCh3KSA9PiB7CiAgICAgICAgY29uc3Qgbm9ybSA9IHcKICAgICAgICAgIC5ub3JtYWxpemUoIk5GRCIpCiAgICAgICAgICAucmVwbGFjZSgvW8yALc2vXS9nLCAiIikKICAgICAgICAgIC50b0xvd2VyQ2FzZSgpCiAgICAgICAgICAucmVwbGFjZSgvW15hLXowLTldL2csICIiKTsKICAgICAgICByZXR1cm4gIWtleXdvcmRzLmhhcyhub3JtKTsKICAgICAgfSk7CiAgICAgIGNvbnN0IGNsZWFuZWQgPSBrZXB0LmpvaW4oIiAiKS50cmltKCk7CiAgICAgIHJldHVybiBjbGVhbmVkIHx8IG51bGw7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gZGlzbWlzc1N1Z2dlc3Rpb24oa2V5KSB7CiAgICAgIGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzLmFkZChrZXkpOyAvLyBpbW3DqWRpYXQgY8O0dMOpIFVJLCBwYXMgYmVzb2luIGQnYXR0ZW5kcmUgbGUgc2VydmV1cgogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL2Rpc21pc3NlZC1zdWdnZXN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBrZXkgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgbGEgc3VnZ2VzdGlvbiByw6lhcHBhcmHDrnQgdW5lIGZvaXMgc3VyIHVuCiAgICAgICAgLy8gYXV0cmUgYXBwYXJlaWwgc2kgbGEgc2F1dmVnYXJkZSBzZXJ2ZXVyIGEgw6ljaG91w6kuCiAgICAgIH0KICAgIH0KCiAgICAvLyBSZWdhcmRlIHNpIGxhIGRlc2NyaXB0aW9uIGRlIGxhIHRyYW5zYWN0aW9uIHF1aSB2aWVudCBkJ8OqdHJlIGFqb3V0w6llCiAgICAvLyAob3UgY29ycmlnw6llKSDDoCBsYSB2b2l4IHJldmllbnQgc291dmVudCwgZXQgc2kgb3VpIDoKICAgIC8vIC0gc29pdCBlbGxlIGEgdG91am91cnMgw6l0w6kgcmFuZ8OpZSBkYW5zICJBdXRyZSIg4oaSIG9uIHByb3Bvc2UgZGUgY3LDqWVyCiAgICAvLyAgIHVuZSBjYXTDqWdvcmllIGTDqWRpw6llIChvdSBkZSBsYSByYXR0YWNoZXIgw6AgdW5lIGNhdMOpZ29yaWUgZXhpc3RhbnRlKSA7CiAgICAvLyAtIHNvaXQgZWxsZSBhIGNldHRlIGZvaXMgdW5lIGNhdMOpZ29yaWUgZGlmZsOpcmVudGUgZGUgZCdoYWJpdHVkZSDihpIgb24KICAgIC8vICAgZGVtYW5kZSBzaSBjZSBuJ2VzdCBwYXMgdW5lIGVycmV1ciA7CiAgICAvLyAtIHNvaXQgbGEgdHJhbnNhY3Rpb24gcXVpIHZpZW50IGQnw6p0cmUgYWpvdXTDqWUgZXN0IGTDqWrDoCBiaWVuIGNsYXNzw6llLAogICAgLy8gICBtYWlzIGQnYW5jaWVubmVzIHRyYW5zYWN0aW9ucyBzaW1pbGFpcmVzIHRyYcOubmVudCBkYW5zIHVuZSBhdXRyZQogICAgLy8gICBjYXTDqWdvcmllIChleC4gInBlcnRlIGF1IGNhc2lubyIgY2xhc3PDqWUgZW4gIkxvaXNpcnMiIGF2YW50IHF1ZQogICAgLy8gICAiY2FzaW5vIiBleGlzdGUgY29tbWUgY2F0w6lnb3JpZSkg4oaSIG9uIHByb3Bvc2UgZGUgbGVzIGFsaWduZXIuCiAgICBmdW5jdGlvbiBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihkZXNjcmlwdGlvbiwgdHlwZSkgewogICAgICBjb25zdCBrZXl3b3JkcyA9IGV4dHJhY3REZXNjcmlwdGlvbktleXdvcmRzKGRlc2NyaXB0aW9uKTsKICAgICAgaWYgKGtleXdvcmRzLnNpemUgPT09IDApIHJldHVybjsKCiAgICAgIGNvbnN0IHNhbWVEZXNjcmlwdGlvbiA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgKHR4KSA9PgogICAgICAgICAgdHgudHlwZSA9PT0gdHlwZSAmJgogICAgICAgICAga2V5d29yZHNJbnRlcnNlY3Qoa2V5d29yZHMsIGV4dHJhY3REZXNjcmlwdGlvbktleXdvcmRzKHR4LmRlc2NyaXB0aW9uKSkKICAgICAgKTsKICAgICAgaWYgKHNhbWVEZXNjcmlwdGlvbi5sZW5ndGggPCBDQVRFR09SWV9TVUdHRVNUSU9OX1RIUkVTSE9MRCkgcmV0dXJuOwoKICAgICAgY29uc3QgY291bnRzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2Ygc2FtZURlc2NyaXB0aW9uKSBjb3VudHNbdHguY2F0ZWdvcnldID0gKGNvdW50c1t0eC5jYXRlZ29yeV0gfHwgMCkgKyAxOwogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXMoY291bnRzKTsKICAgICAgY29uc3QgZG9taW5hbnQgPSBjYXRlZ29yaWVzLnJlZHVjZSgoYSwgYikgPT4gKGNvdW50c1thXSA+PSBjb3VudHNbYl0gPyBhIDogYikpOwogICAgICBjb25zdCBsYXRlc3QgPSBzYW1lRGVzY3JpcHRpb25bMF07IC8vIGFsbFRyYW5zYWN0aW9ucyBlc3QgdHJpw6kgcGFyIGRhdGUgZMOpY3JvaXNzYW50ZQoKICAgICAgLy8gQ2zDqSBzdGFibGUgYmFzw6llIHN1ciBsZXMgbW90cy1jbMOpcyAodHJpw6lzKSBwbHV0w7R0IHF1ZSBsYSBkZXNjcmlwdGlvbgogICAgICAvLyBleGFjdGUsIHBvdXIgcXVlIGxlICJJZ25vcmVyIiByZXN0ZSB2YWxhYmxlIG3Dqm1lIHNpIGxhIGZvcm11bGF0aW9uCiAgICAgIC8vIHZhcmllIHVuIHBldSBkJ3VuZSBmb2lzIMOgIGwnYXV0cmUuCiAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IFsuLi5rZXl3b3Jkc10uc29ydCgpLmpvaW4oIisiKTsKCiAgICAgIGxldCBzdWdnZXN0aW9uID0gbnVsbDsKICAgICAgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID4gMSAmJiBsYXRlc3QuY2F0ZWdvcnkgIT09IGRvbWluYW50KSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYG1pc21hdGNoOiR7dHlwZX06JHtzaWduYXR1cmV9OiR7bGF0ZXN0LmNhdGVnb3J5fWAsCiAgICAgICAgICBraW5kOiAibWlzbWF0Y2giLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICBkb21pbmFudCwKICAgICAgICAgIGN1cnJlbnQ6IGxhdGVzdC5jYXRlZ29yeSwKICAgICAgICAgIGtleXdvcmRzLAogICAgICAgICAgdHhJZHM6IHNhbWVEZXNjcmlwdGlvbi5maWx0ZXIoKHR4KSA9PiB0eC5jYXRlZ29yeSA9PT0gbGF0ZXN0LmNhdGVnb3J5KS5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgfTsKICAgICAgfSBlbHNlIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA9PT0gMSAmJiBkb21pbmFudCA9PT0gImF1dHJlIikgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBnZW5lcmljOiR7dHlwZX06JHtzaWduYXR1cmV9YCwKICAgICAgICAgIGtpbmQ6ICJnZW5lcmljIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAga2V5d29yZHMsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID4gMSAmJiBsYXRlc3QuY2F0ZWdvcnkgPT09IGRvbWluYW50KSB7CiAgICAgICAgLy8gTGEgdHJhbnNhY3Rpb24gbGEgcGx1cyByw6ljZW50ZSBlc3QgZMOpasOgIGJpZW4gY2xhc3PDqWUsIG1haXMKICAgICAgICAvLyBkJ2F1dHJlcyB0cmFuc2FjdGlvbnMgc2ltaWxhaXJlcyBzb250IHJlc3TDqWVzIGRhbnMgdW5lIGNhdMOpZ29yaWUKICAgICAgICAvLyBtaW5vcml0YWlyZSAodHlwaXF1ZW1lbnQgcGx1cyBhbmNpZW5uZXMsIGNsYXNzw6llcyBhdmFudCBxdWUgbGEKICAgICAgICAvLyBjYXTDqWdvcmllIGRvbWluYW50ZSBhY3R1ZWxsZSBuJ2V4aXN0ZSkgOiBvbiBwcm9wb3NlIGRlIGxlcyBhbGlnbmVyLgogICAgICAgIGNvbnN0IG91dGxpZXJzID0gc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ICE9PSBkb21pbmFudCk7CiAgICAgICAgaWYgKG91dGxpZXJzLmxlbmd0aCA+IDApIHsKICAgICAgICAgIGNvbnN0IG91dGxpZXJDYXRlZ29yaWVzID0gWy4uLm5ldyBTZXQob3V0bGllcnMubWFwKCh0eCkgPT4gdHguY2F0ZWdvcnkpKV07CiAgICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAgICBrZXk6IGByZWNvbmNpbGU6JHt0eXBlfToke3NpZ25hdHVyZX06JHtkb21pbmFudH1gLAogICAgICAgICAgICBraW5kOiAicmVjb25jaWxlIiwKICAgICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgICAgdHlwZSwKICAgICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICAgIG91dGxpZXJDYXRlZ29yaWVzLAogICAgICAgICAgICBrZXl3b3JkcywKICAgICAgICAgICAgdHhJZHM6IG91dGxpZXJzLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICAgIH07CiAgICAgICAgfQogICAgICB9CgogICAgICBpZiAoIXN1Z2dlc3Rpb24gfHwgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuaGFzKHN1Z2dlc3Rpb24ua2V5KSkgcmV0dXJuOwogICAgICBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pOwogICAgfQoKICAgIGZ1bmN0aW9uIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIik7CiAgICAgIGVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpIHsKICAgICAgbGV0IGlkc1RvRml4OwogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAicmVjb25jaWxlIikgewogICAgICAgIC8vIEljaSBzdWdnZXN0aW9uLnR4SWRzIGVzdCBkw6lqw6AgZXhhY3RlbWVudCBsJ2Vuc2VtYmxlIGRlcyBhbmNpZW5uZXMKICAgICAgICAvLyB0cmFuc2FjdGlvbnMgw6AgYWxpZ25lciAocGFzIGRlICJkZXJuacOocmUgdHJhbnNhY3Rpb24iIMOgIHBhcnQpIDogbGUKICAgICAgICAvLyB0ZXh0ZSBkZSBsYSBiYW5uacOocmUgbCdhbm5vbmNlIGTDqWrDoCwgcGFzIGJlc29pbiBkJ3VuZSBjb25maXJtYXRpb24KICAgICAgICAvLyBzdXBwbMOpbWVudGFpcmUuCiAgICAgICAgaWRzVG9GaXggPSBzdWdnZXN0aW9uLnR4SWRzOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IFtsYXRlc3RJZCwgLi4ub3RoZXJzXSA9IHN1Z2dlc3Rpb24udHhJZHM7CiAgICAgICAgaWRzVG9GaXggPSBbbGF0ZXN0SWRdOwogICAgICAgIGlmICgKICAgICAgICAgIG90aGVycy5sZW5ndGggPiAwICYmCiAgICAgICAgICAoYXdhaXQgc2hvd0NvbmZpcm0oYENvcnJpZ2VyIGF1c3NpIGxlcyAke290aGVycy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHByw6ljw6lkZW50ZShzKSBhdmVjIGxhIG3Dqm1lIGRlc2NyaXB0aW9uID9gKSkKICAgICAgICApIHsKICAgICAgICAgIGlkc1RvRml4LnB1c2goLi4ub3RoZXJzKTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIHRyeSB7CiAgICAgICAgZm9yIChjb25zdCBpZCBvZiBpZHNUb0ZpeCkgewogICAgICAgICAgY29uc3QgcGF5bG9hZCA9IHsgY2F0ZWdvcnk6IHRhcmdldFZhbHVlIH07CiAgICAgICAgICAvLyBMYSBjYXTDqWdvcmllIHBvcnRlIG1haW50ZW5hbnQgbCdpbmZvcm1hdGlvbiA6IG9uIHJldGlyZSBkZXMKICAgICAgICAgIC8vIGRlc2NyaXB0aW9ucyBsZShzKSBtb3QocyktY2zDqShzKSBxdWkgb250IHNlcnZpIMOgIGxhIGTDqXRlY3RlciwKICAgICAgICAgIC8vIHBvdXIgw6l2aXRlciBsYSByZWRvbmRhbmNlICJjYXNpbm8iIGVuIGNhdMOpZ29yaWUgRVQgZW4gbm90ZS4KICAgICAgICAgIGNvbnN0IHR4ID0gYWxsVHJhbnNhY3Rpb25zLmZpbmQoKHQpID0+IHQuaWQgPT09IGlkKTsKICAgICAgICAgIGlmICh0eCAmJiBzdWdnZXN0aW9uLmtleXdvcmRzKSB7CiAgICAgICAgICAgIGNvbnN0IGNsZWFuZWQgPSBzdHJpcE1hdGNoZWRLZXl3b3Jkc0Zyb21EZXNjcmlwdGlvbih0eC5kZXNjcmlwdGlvbiwgc3VnZ2VzdGlvbi5rZXl3b3Jkcyk7CiAgICAgICAgICAgIGlmIChjbGVhbmVkICE9PSAodHguZGVzY3JpcHRpb24gfHwgbnVsbCkpIHBheWxvYWQuZGVzY3JpcHRpb24gPSBjbGVhbmVkOwogICAgICAgICAgfQogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgICBzaG93VG9hc3QoYENhdMOpZ29yaWUgbWlzZSDDoCBqb3VyIDogJHt0YXJnZXRMYWJlbH1gKTsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd0NhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcihzdWdnZXN0aW9uKSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgICBlbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKCiAgICAgIGNvbnN0IGRlc2NMYWJlbCA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYFR1IGFzIHV0aWxpc8OpICIke2Rlc2NMYWJlbH0iICR7c3VnZ2VzdGlvbi50eElkcy5sZW5ndGh9IGZvaXMsIHRvdWpvdXJzIGNsYXNzw6kgZW4gYCArCiAgICAgICAgICBgIkF1dHJlIi4gQ3LDqWVyIHVuZSBjYXTDqWdvcmllIGTDqWRpw6llIChvdSBsYSByYXR0YWNoZXIgw6AgdW5lIGNhdMOpZ29yaWUgZXhpc3RhbnRlKSA/YDsKICAgICAgfSBlbHNlIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJyZWNvbmNpbGUiKSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3Qgb3V0bGllckxhYmVscyA9IHN1Z2dlc3Rpb24ub3V0bGllckNhdGVnb3JpZXMKICAgICAgICAgIC5tYXAoKGMpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NdIHx8IGMpCiAgICAgICAgICAuam9pbigiLCAiKTsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGAke3N1Z2dlc3Rpb24udHhJZHMubGVuZ3RofSB0cmFuc2FjdGlvbihzKSBzaW1pbGFpcmUocykgw6AgIiR7ZGVzY0xhYmVsfSIgc29udCBjbGFzc8OpZXMgZW4gYCArCiAgICAgICAgICBgIiR7b3V0bGllckxhYmVsc30iLCBhbG9ycyBxdWUgIiR7ZG9taW5hbnRMYWJlbH0iIGVzdCBtYWludGVuYW50IGxhIGNhdMOpZ29yaWUgaGFiaXR1ZWxsZS4gYCArCiAgICAgICAgICBgTGVzIGFsaWduZXIgc3VyICIke2RvbWluYW50TGFiZWx9IiA/YDsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBjdXJyZW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmN1cnJlbnRdIHx8IHN1Z2dlc3Rpb24uY3VycmVudDsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGAiJHtkZXNjTGFiZWx9IiBlc3QgaGFiaXR1ZWxsZW1lbnQgY2xhc3PDqSBlbiAiJHtkb21pbmFudExhYmVsfSIsIG1haXMgY2V0dGUgZm9pcyBgICsKICAgICAgICAgIGBjJ2VzdCAiJHtjdXJyZW50TGFiZWx9Ii4gUGFzIGQnZXJyZXVyIG91IHVuIG91YmxpID9gOwogICAgICB9CiAgICAgIGVsLmFwcGVuZENoaWxkKHRleHQpOwoKICAgICAgY29uc3QgY29udHJvbHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgY29udHJvbHMuY2xhc3NOYW1lID0gImNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMiOwoKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2VsZWN0Iik7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0pIHsKICAgICAgICAgIGlmICh2YWx1ZSA9PT0gImF1dHJlIikgY29udGludWU7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgY29uc3QgbmV3T3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICAgIG5ld09wdC50ZXh0Q29udGVudCA9ICIrIE5vdXZlbGxlIGNhdMOpZ29yaWXigKYiOwogICAgICAgIG5ld09wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG5ld09wdCk7CgogICAgICAgIGNvbnN0IG5ld05hbWVJbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgbmV3TmFtZUlucHV0LnR5cGUgPSAidGV4dCI7CiAgICAgICAgbmV3TmFtZUlucHV0LnBsYWNlaG9sZGVyID0gIk5vbSBkZSBsYSBub3V2ZWxsZSBjYXTDqWdvcmllIjsKICAgICAgICBuZXdOYW1lSW5wdXQudmFsdWUgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIiOwoKICAgICAgICBzZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgbmV3TmFtZUlucHV0LnN0eWxlLmRpc3BsYXkgPSBzZWxlY3QudmFsdWUgPT09ICJfX25ld19fIiA/ICJpbmxpbmUtYmxvY2siIDogIm5vbmUiOwogICAgICAgIH0pOwoKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChzZWxlY3QpOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKG5ld05hbWVJbnB1dCk7CgogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSAiQXBwbGlxdWVyIjsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgbGV0IHRhcmdldFZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICAgICAgbGV0IHRhcmdldExhYmVsOwogICAgICAgICAgaWYgKHRhcmdldFZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICAgICAgY29uc3QgbmFtZSA9IG5ld05hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgICAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkRvbm5lIHVuIG5vbSDDoCBsYSBjYXTDqWdvcmllIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICAgICAgICB0YXJnZXRWYWx1ZSA9IHNsdWdpZnlDYXRlZ29yeShuYW1lKTsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBuYW1lOwogICAgICAgICAgICBpZiAoIWNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHRhcmdldFZhbHVlKSkgewogICAgICAgICAgICAgIHNhdmVDdXN0b21DYXRlZ29yeShzdWdnZXN0aW9uLnR5cGUsIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdGFyZ2V0VmFsdWVdIHx8IHRhcmdldFZhbHVlOwogICAgICAgICAgfQogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICB9KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChhcHBseUJ0bik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9IGBDb3JyaWdlciBlbiAiJHtkb21pbmFudExhYmVsfSJgOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCBzdWdnZXN0aW9uLmRvbWluYW50LCBkb21pbmFudExhYmVsKTsKICAgICAgICB9KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChhcHBseUJ0bik7CiAgICAgIH0KCiAgICAgIGNvbnN0IGRpc21pc3NCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgZGlzbWlzc0J0bi50ZXh0Q29udGVudCA9ICJJZ25vcmVyIjsKICAgICAgZGlzbWlzc0J0bi5jbGFzc05hbWUgPSAiYnRuLXNlY29uZGFyeS1zbSI7CiAgICAgIGRpc21pc3NCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgfSk7CiAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGRpc21pc3NCdG4pOwoKICAgICAgZWwuYXBwZW5kQ2hpbGQoY29udHJvbHMpOwogICAgfQoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSBjaGFyZ2UgcsOpY3VycmVudGUgY3LDqcOpZSBQQVIgTEEgVk9JWCBkYW5zIGNldHRlCiAgICAvLyBzZXNzaW9uIChtw6ptZSBwcmluY2lwZSBxdWUgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCwgbWFpcyBwb3VyIHVuZQogICAgLy8gY29ycmVjdGlvbiBxdWkgc3VpdCBsYSBjcsOpYXRpb24gZCd1bmUgcsOpY3VycmVudGUgcGFyIGxhIHZvaXgpLgogICAgbGV0IGxhc3RWb2ljZVJlY3VycmluZ0lkID0gbnVsbDsKCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCkgewogICAgICBjb25zdCB2ZXJiID0gcGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSIgOiAiRMOpcGVuc2UiOwogICAgICBjb25zdCBhbW91bnRMYWJlbCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChwYXJzZWQuYW1vdW50KTsKCiAgICAgIC8vICJyw6ljdXJyZW50IiwgImFib25uZW1lbnQiLCAidG91cyBsZXMgbW9pcyIuLi4gZMOpdGVjdMOpIHBhciBsJ0lBIDogb24KICAgICAgLy8gY3LDqWUvY29ycmlnZSB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGF1IGxpZXUgZCd1bmUgdHJhbnNhY3Rpb24KICAgICAgLy8gcG9uY3R1ZWxsZSwgcXVlbCBxdWUgc29pdCBsJ29uZ2xldCBhY3R1ZWxsZW1lbnQgYWZmaWNow6kg4oCUIGxlIG1pY3JvCiAgICAgIC8vIGVzdCBnbG9iYWwsIHBhcyBsacOpIMOgIGwnb25nbGV0IFLDqWN1cnJlbnRlcy4KICAgICAgaWYgKHBhcnNlZC5pc19yZWN1cnJpbmcpIHsKICAgICAgICBjb25zdCByZWNQYXlsb2FkID0gewogICAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgICBuYW1lOiBwYXJzZWQuZGVzY3JpcHRpb24gfHwgKHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUgcsOpY3VycmVudCIgOiAiRMOpcGVuc2UgcsOpY3VycmVudGUiKSwKICAgICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgICBkYXlfb2ZfbW9udGg6IE51bWJlcihwYXJzZWQuZXhwZW5zZV9kYXRlLnNsaWNlKDgsIDEwKSksCiAgICAgICAgfTsKCiAgICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVJlY3VycmluZ0lkKSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS9yZWN1cnJpbmcvJHtsYXN0Vm9pY2VSZWN1cnJpbmdJZH1gLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHJlY1BheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgICBzaG93VG9hc3QoYENoYXJnZSByw6ljdXJyZW50ZSBjb3JyaWfDqWUgOiAke3JlY1BheWxvYWQubmFtZX0gKCR7YW1vdW50TGFiZWx9KWApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgewogICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVjUGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICAgIGxhc3RWb2ljZVJlY3VycmluZ0lkID0gY3JlYXRlZC5pZDsKICAgICAgICAgIHNob3dUb2FzdChgQ2hhcmdlIHLDqWN1cnJlbnRlIGFqb3V0w6llIDogJHtyZWNQYXlsb2FkLm5hbWV9ICgke2Ftb3VudExhYmVsfSlgKTsKICAgICAgICB9CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICBkZXNjcmlwdGlvbjogcGFyc2VkLmRlc2NyaXB0aW9uLAogICAgICAgIGV4cGVuc2VfZGF0ZTogcGFyc2VkLmV4cGVuc2VfZGF0ZSwKICAgICAgfTsKCiAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkKSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7bGFzdFZvaWNlVHJhbnNhY3Rpb25JZH1gLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KGBDb3JyaWfDqSA6ICR7dmVyYi50b0xvd2VyQ2FzZSgpfSBkZSAke2Ftb3VudExhYmVsfWApOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBjcmVhdGVkLmlkOwogICAgICAgIHNob3dUb2FzdChgJHt2ZXJifSBham91dMOpJHtwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiIiA6ICJlIn0gOiAke2Ftb3VudExhYmVsfWApOwogICAgICB9CiAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24ocGFyc2VkLmRlc2NyaXB0aW9uLCBwYXJzZWQudHlwZSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29uZmlybWF0aW9uIHN0eWzDqWUgKHJlbXBsYWNlIHdpbmRvdy5jb25maXJtLCBxdWkgYWZmaWNoZSB1bmUgcG9wdXAKICAgIC8vIG5hdGl2ZSBkdSBuYXZpZ2F0ZXVyIGhvcnMgY2hhcnRlIGdyYXBoaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IGNvbmZpcm1PdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1tb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBjb25maXJtTWVzc2FnZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tbW9kYWwtbWVzc2FnZSIpOwogICAgY29uc3QgY29uZmlybU9rQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tYnRuLW9rIik7CiAgICBjb25zdCBjb25maXJtQ2FuY2VsQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tYnRuLWNhbmNlbCIpOwogICAgbGV0IGNvbmZpcm1SZXNvbHZlID0gbnVsbDsKCiAgICBmdW5jdGlvbiBzaG93Q29uZmlybShtZXNzYWdlKSB7CiAgICAgIGNvbmZpcm1NZXNzYWdlRWwudGV4dENvbnRlbnQgPSBtZXNzYWdlOwogICAgICBjb25maXJtT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHsKICAgICAgICBjb25maXJtUmVzb2x2ZSA9IHJlc29sdmU7CiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlQ29uZmlybShyZXN1bHQpIHsKICAgICAgY29uZmlybU92ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgaWYgKGNvbmZpcm1SZXNvbHZlKSB7CiAgICAgICAgY29uZmlybVJlc29sdmUocmVzdWx0KTsKICAgICAgICBjb25maXJtUmVzb2x2ZSA9IG51bGw7CiAgICAgIH0KICAgIH0KCiAgICBjb25maXJtT2tCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBjbG9zZUNvbmZpcm0odHJ1ZSkpOwogICAgY29uZmlybUNhbmNlbEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGNsb3NlQ29uZmlybShmYWxzZSkpOwogICAgY29uZmlybU92ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gY29uZmlybU92ZXJsYXlFbCkgY2xvc2VDb25maXJtKGZhbHNlKTsKICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIETDqXBlbnNlcyByw6ljdXJyZW50ZXMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IHJlY0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWN1cnJpbmctbGlzdCIpOwogICAgY29uc3QgcmVjRW1wdHlTdGF0ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1lbXB0eS1zdGF0ZSIpOwogICAgY29uc3QgcmVjT3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1tb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCByZWNNb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLXRpdGxlIik7CiAgICBjb25zdCByZWNUeXBlVG9nZ2xlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLXR5cGUtdG9nZ2xlIik7CiAgICBjb25zdCByZWNOYW1lSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LW5hbWUiKTsKICAgIGNvbnN0IHJlY0Ftb3VudElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1hbW91bnQiKTsKICAgIGNvbnN0IHJlY0NhdGVnb3J5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCByZWNEYXlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZGF5Iik7CiAgICBjb25zdCByZWNTdGFydERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtc3RhcnQtZGF0ZSIpOwogICAgY29uc3QgcmVjRW5kRGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1lbmQtZGF0ZSIpOwogICAgY29uc3QgcmVjU2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLXNhdmUiKTsKCiAgICBsZXQgYWxsUmVjdXJyaW5nID0gW107CiAgICBsZXQgZWRpdGluZ1JlY3VycmluZ0lkID0gbnVsbDsKICAgIGxldCByZWNDdXJyZW50VHlwZSA9ICJleHBlbnNlIjsKCiAgICBmdW5jdGlvbiBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgc2VsZWN0ZWRWYWx1ZSA9IG51bGwpIHsKICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgaWYgKHZhbHVlID09PSAoc2VsZWN0ZWRWYWx1ZSB8fCAiYXV0cmUiKSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICByZWNDYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRSZWN1cnJpbmdUeXBlKHR5cGUpIHsKICAgICAgcmVjQ3VycmVudFR5cGUgPSB0eXBlOwogICAgICByZWNUeXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHR5cGUsIHJlY0NhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHJlY1R5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRSZWN1cnJpbmdUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3BlblJlY3VycmluZ01vZGFsKGl0ZW0gPSBudWxsKSB7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IGl0ZW0gPyBpdGVtLmlkIDogbnVsbDsKICAgICAgcmVjTW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXRlbSA/ICJNb2RpZmllciBsYSBjaGFyZ2UgcsOpY3VycmVudGUiIDogIk5vdXZlbGxlIGNoYXJnZSByw6ljdXJyZW50ZSI7CiAgICAgIHJlY1NhdmVCdG4udGV4dENvbnRlbnQgPSBpdGVtID8gIkVucmVnaXN0cmVyIiA6ICJBam91dGVyIjsKICAgICAgc2V0UmVjdXJyaW5nVHlwZShpdGVtID8gaXRlbS50eXBlIDogImV4cGVuc2UiKTsKICAgICAgcmVjTmFtZUlucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0ubmFtZSA6ICIiOwogICAgICByZWNBbW91bnRJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLmFtb3VudCA6ICIiOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXMocmVjQ3VycmVudFR5cGUsIGl0ZW0gPyBpdGVtLmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIHJlY0RheUlucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uZGF5X29mX21vbnRoIDogIiI7CiAgICAgIHJlY1N0YXJ0RGF0ZUlucHV0LnZhbHVlID0gaXRlbSAmJiBpdGVtLnN0YXJ0X2RhdGUgPyBpdGVtLnN0YXJ0X2RhdGUgOiAiIjsKICAgICAgcmVjRW5kRGF0ZUlucHV0LnZhbHVlID0gaXRlbSAmJiBpdGVtLmVuZF9kYXRlID8gaXRlbS5lbmRfZGF0ZSA6ICIiOwogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJlY05hbWVJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlUmVjdXJyaW5nTW9kYWwoKSB7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gbnVsbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlUmVjdXJyaW5nTW9kYWwpOwogICAgcmVjT3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSByZWNPdmVybGF5RWwpIGNsb3NlUmVjdXJyaW5nTW9kYWwoKTsgfSk7CgogICAgcmVjU2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgbmFtZSA9IHJlY05hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQocmVjQW1vdW50SW5wdXQudmFsdWUpOwogICAgICBjb25zdCBkYXkgPSBwYXJzZUludChyZWNEYXlJbnB1dC52YWx1ZSwgMTApOwoKICAgICAgaWYgKCFuYW1lKSB7IHNob3dUb2FzdCgiTGUgbm9tIGVzdCBvYmxpZ2F0b2lyZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWRheSB8fCBkYXkgPCAxIHx8IGRheSA+IDMxKSB7IHNob3dUb2FzdCgiSm91ciBkdSBtb2lzIGludmFsaWRlICgxIMOgIDMxKSIsIHRydWUpOyByZXR1cm47IH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcmVjQ3VycmVudFR5cGUsCiAgICAgICAgbmFtZSwKICAgICAgICBhbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IHJlY0NhdGVnb3J5SW5wdXQudmFsdWUsCiAgICAgICAgZGF5X29mX21vbnRoOiBkYXksCiAgICAgICAgc3RhcnRfZGF0ZTogcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgICBlbmRfZGF0ZTogcmVjRW5kRGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgIH07CgogICAgICByZWNTYXZlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoZWRpdGluZ1JlY3VycmluZ0lkKSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS9yZWN1cnJpbmcvJHtlZGl0aW5nUmVjdXJyaW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiQ2hhcmdlIHLDqWN1cnJlbnRlIG1vZGlmacOpZSIpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiQ2hhcmdlIHLDqWN1cnJlbnRlIGFqb3V0w6llIik7CiAgICAgICAgfQogICAgICAgIGNsb3NlUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICByZWNTYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVJlY3VycmluZyhpZCkgewogICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGNldHRlIGTDqXBlbnNlIHLDqWN1cnJlbnRlID8iKSkpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS9yZWN1cnJpbmcvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJEw6lwZW5zZSByw6ljdXJyZW50ZSBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJSZWN1cnJpbmcoaXRlbXMpIHsKICAgICAgcmVjTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICByZWNFbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9IGl0ZW1zLmxlbmd0aCA9PT0gMCA/ICJibG9jayIgOiAibm9uZSI7CgogICAgICBjb25zdCB0b2RheUtleSA9IHRvZGF5SXNvKCk7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgaXRlbXMpIHsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKICAgICAgICBjb25zdCBlbmRlZCA9IGl0ZW0uZW5kX2RhdGUgJiYgaXRlbS5lbmRfZGF0ZSA8IHRvZGF5S2V5OwogICAgICAgIGNvbnN0IG5vdFN0YXJ0ZWQgPSBpdGVtLnN0YXJ0X2RhdGUgJiYgaXRlbS5zdGFydF9kYXRlID4gdG9kYXlLZXk7CgogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJyZWMtY2FyZCAiICsgdHlwZSArIChlbmRlZCA/ICIgZW5kZWQiIDogIiIpOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAicmVjLW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gInJlYy10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1tpdGVtLmNhdGVnb3J5XSB8fCBpdGVtLmNhdGVnb3J5OwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChiYWRnZSk7CiAgICAgICAgaWYgKGl0ZW0uc3RhcnRfZGF0ZSkgewogICAgICAgICAgY29uc3Qgc3RhcnRCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIHN0YXJ0QmFkZ2UuY2xhc3NOYW1lID0gInN0YXJ0LWJhZGdlIjsKICAgICAgICAgIGNvbnN0IHN0YXJ0TGFiZWwgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShpdGVtLnN0YXJ0X2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgc3RhcnRCYWRnZS50ZXh0Q29udGVudCA9IG5vdFN0YXJ0ZWQgPyBgRMOocyBsZSAke3N0YXJ0TGFiZWx9YCA6IGBEZXB1aXMgbGUgJHtzdGFydExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoc3RhcnRCYWRnZSk7CiAgICAgICAgfQogICAgICAgIGlmIChpdGVtLmVuZF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBlbmRCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIGVuZEJhZGdlLmNsYXNzTmFtZSA9ICJlbmQtYmFkZ2UiOwogICAgICAgICAgY29uc3QgZW5kTGFiZWwgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShpdGVtLmVuZF9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICAgIGVuZEJhZGdlLnRleHRDb250ZW50ID0gZW5kZWQgPyBgVGVybWluw6kgbGUgJHtlbmRMYWJlbH1gIDogYEp1c3F1J2F1ICR7ZW5kTGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChlbmRCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBuYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbmFtZS5jbGFzc05hbWUgPSAicmVjLW5hbWUiOwogICAgICAgIG5hbWUudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CgogICAgICAgIGNvbnN0IHN1YiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHN1Yi5jbGFzc05hbWUgPSAicmVjLXN1YiI7CiAgICAgICAgc3ViLnRleHRDb250ZW50ID0gYExlICR7aXRlbS5kYXlfb2ZfbW9udGh9IGRlIGNoYXF1ZSBtb2lzYDsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobmFtZSk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChzdWIpOwoKICAgICAgICBjb25zdCBhbW91bnRFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudEVsLmNsYXNzTmFtZSA9ICJyZWMtYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gKHR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY3VycmluZ01vZGFsKGl0ZW0pKTsKICAgICAgICBjb25zdCBkZWxldGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkZWxldGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIGRhbmdlciI7CiAgICAgICAgZGVsZXRlQnRuLnRleHRDb250ZW50ID0gIvCfl5HvuI8iOwogICAgICAgIGRlbGV0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiU3VwcHJpbWVyIik7CiAgICAgICAgZGVsZXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZGVsZXRlUmVjdXJyaW5nKGl0ZW0uaWQpKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGVkaXRCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIHJlY0xpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIFRvdGFsIGRlcyBkw6lwZW5zZXMgcsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMgY2UgbW9pcy1jaSAoY2VsbGVzCiAgICAvLyBkb250IGxlIGpvdXIgZHUgbW9pcyBuJ2VzdCBwYXMgZW5jb3JlIHBhc3PDqSksIGFmZmljaMOpIMOgIGPDtHTDqSBkZXMgMwogICAgLy8gY2FydGVzIGR1IGhhdXQg4oCUIGluZMOpcGVuZGFudCBkdSBtb2lzIGNob2lzaSBkYW5zIGxlIHRhYmxlYXUgZGUgYm9yZCwKICAgIC8vIHRvdWpvdXJzICJsZSBtb2lzIHLDqWVsLCBtYWludGVuYW50Ii4KICAgIGZ1bmN0aW9uIHVwZGF0ZVVwY29taW5nU3VtbWFyeSgpIHsKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBsZXQgdXBjb21pbmdFeHBlbnNlID0gMDsKICAgICAgbGV0IHVwY29taW5nSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgY3VycmVudE1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IHRvZGF5RGF5KSBjb250aW51ZTsKICAgICAgICBpZiAoKGl0ZW0udHlwZSB8fCAiZXhwZW5zZSIpID09PSAiaW5jb21lIikgdXBjb21pbmdJbmNvbWUgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICBlbHNlIHVwY29taW5nRXhwZW5zZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IG5ldCA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nIik7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgaWYgKG5ldCA9PT0gMCkgewogICAgICAgIGVsLnRleHRDb250ZW50ID0gIuKAlCI7CiAgICAgICAgZWwuY2xhc3NOYW1lID0gInZhbHVlIjsKICAgICAgICB0b29sdGlwRWwuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgY2FyZEVsLmNsYXNzTGlzdC5yZW1vdmUoInRvb2x0aXAtaG9zdCIpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgc2lnbiA9IG5ldCA+IDAgPyAiKyIgOiAi4oiSIjsKICAgICAgZWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXQpKX1gOwogICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUgIiArIChuZXQgPiAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBjYXJkRWwuY2xhc3NMaXN0LmFkZCgidG9vbHRpcC1ob3N0Iik7CiAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPQogICAgICAgIGBEw6lwZW5zZXMgw6AgdmVuaXIgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh1cGNvbWluZ0V4cGVuc2UpfTxicj5gICsKICAgICAgICBgUmV2ZW51cyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nSW5jb21lKX1gOwogICAgfQoKICAgIC8vIFBldGl0ZSBidWxsZSBkZSBkw6l0YWlsIGZhw6dvbiAidG9vbHRpcCIgaGFiaWxsw6llIGF1eCBjb3VsZXVycyBkdSBzaXRlLAogICAgLy8gYXUgbGlldSBkdSB0aXRsZSBuYXRpZiBkdSBuYXZpZ2F0ZXVyIChncmlzL2JsYW5jLCBob3JzIGNoYXJ0ZSwgZXQKICAgIC8vIGludmlzaWJsZSBhdSB0YWN0aWxlKS4gQWZmaWNow6llIGF1IHN1cnZvbCAob3JkaW5hdGV1cikgZXQgYXUKICAgIC8vIHRhcC90YXAtZW4tZGVob3JzICh0w6lsw6lwaG9uZS90YWJsZXR0ZSkuCiAgICAoZnVuY3Rpb24gc2V0dXBTdW1tYXJ5VXBjb21pbmdUb29sdGlwKCkgewogICAgICBjb25zdCBjYXJkRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy1jYXJkIik7CiAgICAgIGNvbnN0IHRvb2x0aXBFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLXRvb2x0aXAiKTsKCiAgICAgIGZ1bmN0aW9uIHNob3coKSB7CiAgICAgICAgaWYgKHRvb2x0aXBFbC5pbm5lckhUTUwpIHRvb2x0aXBFbC5jbGFzc0xpc3QuYWRkKCJ2aXNpYmxlIik7CiAgICAgIH0KICAgICAgZnVuY3Rpb24gaGlkZSgpIHsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnJlbW92ZSgidmlzaWJsZSIpOwogICAgICB9CgogICAgICBjYXJkRWwuYWRkRXZlbnRMaXN0ZW5lcigibW91c2VlbnRlciIsIHNob3cpOwogICAgICBjYXJkRWwuYWRkRXZlbnRMaXN0ZW5lcigibW91c2VsZWF2ZSIsIGhpZGUpOwogICAgICBjYXJkRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICAgIGUuc3RvcFByb3BhZ2F0aW9uKCk7CiAgICAgICAgdG9vbHRpcEVsLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiKTsKICAgICAgfSk7CiAgICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgaGlkZSk7CiAgICB9KSgpOwoKICAgIC8vIFJhbcOobmUgdW4gam91ciBkdSBtb2lzICgxLTMxKSBhdSBkZXJuaWVyIGpvdXIgcsOpZWwgZHUgbW9pcyB2aXPDqSDigJQKICAgIC8vIMOpcXVpdmFsZW50IEpTIGRlIF9jbGFtcF9kYXkgY8O0dMOpIHNlcnZldXIsIHBvdXIgY2FsY3VsZXIgZGUgdnJhaWVzCiAgICAvLyBkYXRlcyAobmV3IERhdGUoLi4uKSkgcGx1dMO0dCBxdWUgZGUgY29tcGFyZXIgZGVzIGpvdXJzIHRvdXQgc2V1bHMuCiAgICBmdW5jdGlvbiBjbGFtcERheUpzKHllYXIsIG1vbnRoSW5kZXgsIGRheSkgewogICAgICBjb25zdCBsYXN0RGF5ID0gbmV3IERhdGUoeWVhciwgbW9udGhJbmRleCArIDEsIDApLmdldERhdGUoKTsKICAgICAgcmV0dXJuIE1hdGgubWluKGRheSwgbGFzdERheSk7CiAgICB9CgogICAgLy8gUHJvY2hhaW5lIG9jY3VycmVuY2UgZCd1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIMOgIHBhcnRpciBkJ2F1am91cmQnaHVpCiAgICAvLyAoc3RyaWN0ZW1lbnQgYXByw6hzIGF1am91cmQnaHVpKSA6IHJlZ2FyZGUgY2UgbW9pcy1jaSBwdWlzLCBzaSBiZXNvaW4sCiAgICAvLyBsZXMgZGV1eCBtb2lzIHN1aXZhbnRzIOKAlCB1dGlsZSBlbiBmaW4gZGUgbW9pcyBxdWFuZCBwbHVzIHJpZW4gbidlc3QKICAgIC8vIMOgIHZlbmlyIGRhbnMgbGUgbW9pcyBjb3VyYW50LgogICAgZnVuY3Rpb24gbmV4dE9jY3VycmVuY2VGb3JJdGVtKGl0ZW0sIHRvZGF5U3RyKSB7CiAgICAgIGNvbnN0IFt0eSwgdG0sIHRkXSA9IHRvZGF5U3RyLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IHRvZGF5RGF0ZSA9IG5ldyBEYXRlKHR5LCB0bSAtIDEsIHRkKTsKICAgICAgZm9yIChsZXQgb2Zmc2V0ID0gMDsgb2Zmc2V0IDw9IDI7IG9mZnNldCsrKSB7CiAgICAgICAgY29uc3QgYmFzZSA9IG5ldyBEYXRlKHR5LCB0bSAtIDEgKyBvZmZzZXQsIDEpOwogICAgICAgIGNvbnN0IHkgPSBiYXNlLmdldEZ1bGxZZWFyKCk7CiAgICAgICAgY29uc3QgbUlkeCA9IGJhc2UuZ2V0TW9udGgoKTsKICAgICAgICBjb25zdCBtb250aEtleSA9IGAke3l9LSR7U3RyaW5nKG1JZHggKyAxKS5wYWRTdGFydCgyLCAiMCIpfWA7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGNvbnN0IGRheSA9IGNsYW1wRGF5SnMoeSwgbUlkeCwgaXRlbS5kYXlfb2ZfbW9udGgpOwogICAgICAgIGNvbnN0IG9jY0RhdGUgPSBuZXcgRGF0ZSh5LCBtSWR4LCBkYXkpOwogICAgICAgIGlmIChvY2NEYXRlID4gdG9kYXlEYXRlKSByZXR1cm4gb2NjRGF0ZTsKICAgICAgfQogICAgICByZXR1cm4gbnVsbDsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKSB7CiAgICAgIGNvbnN0IHBhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInVwY29taW5nLXJlY3VycmluZy1wYW5lbCIpOwogICAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLWxpc3QiKTsKICAgICAgY29uc3QgdG9kYXkgPSB0b2RheUlzbygpOwoKICAgICAgY29uc3QgdXBjb21pbmcgPSBhbGxSZWN1cnJpbmcKICAgICAgICAubWFwKChpdGVtKSA9PiAoeyBpdGVtLCBkYXRlOiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXkpIH0pKQogICAgICAgIC5maWx0ZXIoKHgpID0+IHguZGF0ZSkKICAgICAgICAuc29ydCgoYSwgYikgPT4gYS5kYXRlIC0gYi5kYXRlKQogICAgICAgIC5zbGljZSgwLCAzKTsKCiAgICAgIGlmICh1cGNvbWluZy5sZW5ndGggPT09IDApIHsKICAgICAgICBwYW5lbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgcGFuZWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGZvciAoY29uc3QgeyBpdGVtLCBkYXRlIH0gb2YgdXBjb21pbmcpIHsKICAgICAgICBjb25zdCBkYXlzID0gTWF0aC5yb3VuZCgoZGF0ZSAtIG5ldyBEYXRlKG5ldyBEYXRlKCkuc2V0SG91cnMoMCwgMCwgMCwgMCkpKSAvIDg2NDAwMDAwKTsKICAgICAgICBjb25zdCBkdWVMYWJlbCA9IGRheXMgPD0gMSA/ICJkZW1haW4iIDogYGRhbnMgJHtkYXlzfSBqb3Vyc2A7CiAgICAgICAgY29uc3QgdHlwZSA9IGl0ZW0udHlwZSB8fCAiZXhwZW5zZSI7CgogICAgICAgIGNvbnN0IHJvdyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHJvdy5jbGFzc05hbWUgPSAidXBjb21pbmctcmVjdXJyaW5nLXJvdyI7CiAgICAgICAgY29uc3QgbGVmdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBsZWZ0LmNsYXNzTmFtZSA9ICJuYW1lIjsKICAgICAgICBsZWZ0LnRleHRDb250ZW50ID0gaXRlbS5uYW1lOwogICAgICAgIGNvbnN0IGR1ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZHVlU3Bhbi5jbGFzc05hbWUgPSAiZHVlIjsKICAgICAgICBkdWVTcGFuLnRleHRDb250ZW50ID0gYCR7ZGF0ZUZvcm1hdHRlci5mb3JtYXQoZGF0ZSl9IMK3ICR7ZHVlTGFiZWx9YDsKICAgICAgICBsZWZ0LmFwcGVuZENoaWxkKGR1ZVNwYW4pOwogICAgICAgIGNvbnN0IGFtb3VudCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnQuY2xhc3NOYW1lID0gImFtb3VudCAiICsgdHlwZTsKICAgICAgICBhbW91bnQudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGxlZnQpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChhbW91bnQpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChyb3cpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFJlY3VycmluZygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIpOwogICAgICAgIGFsbFJlY3VycmluZyA9IGl0ZW1zOwogICAgICAgIHJlbmRlclJlY3VycmluZyhpdGVtcyk7CiAgICAgICAgcmVuZGVyVXBjb21pbmdSZWN1cnJpbmdMaXN0KCk7CiAgICAgICAgdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRXhwb3J0IChFeGNlbCBvdSBzYXV2ZWdhcmRlIEpTT04gY29tcGzDqHRlLCB1biBzZXVsIGJvdXRvbiBhdmVjIHVuCiAgICAvLyBjaG9peCBkZSBmb3JtYXQgcGx1dMO0dCBxdWUgZGV1eCBncm9zIGJvdXRvbnMgc8OpcGFyw6lzKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgRVhQT1JUX0ZPUk1BVFMgPSB7CiAgICAgIHhsc3g6IHsKICAgICAgICBoaW50OiAiVG91dGVzIHRlcyB0cmFuc2FjdGlvbnMgKGTDqXBlbnNlcyBldCByZXZlbnVzKSBldCB0ZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4iLAogICAgICAgIHVybDogIi9hcGkvZXhwb3J0L3hsc3giLAogICAgICAgIGZpbGVuYW1lOiAoKSA9PiBgZGVwZW5zZXNfJHt0b2RheUlzbygpfS54bHN4YCwKICAgICAgICB0b2FzdFN1Y2Nlc3M6ICJFeHBvcnQgdMOpbMOpY2hhcmfDqSIsCiAgICAgIH0sCiAgICAgIGpzb246IHsKICAgICAgICBoaW50OiAiQWJzb2x1bWVudCB0b3V0ZXMgdGVzIGRvbm7DqWVzICh0cmFuc2FjdGlvbnMsIGNoYXJnZXMgcsOpY3VycmVudGVzLCBjYXTDqWdvcmllcyBwZXJzbywgYnVkZ2V0cywgb2JqZWN0aWYgZCfDqXBhcmduZSkuIMOAIGdhcmRlciBkZSBjw7R0w6kgOiBTdXBhYmFzZSBuZSBmYWl0IHBhcyBkZSBzYXV2ZWdhcmRlIGF1dG9tYXRpcXVlIGVuIG9mZnJlIGdyYXR1aXRlLCBjZSBmaWNoaWVyIGVzdCB0b24gZmlsZXQgZGUgc8OpY3VyaXTDqSBlbiBjYXMgZGUgcMOpcGluLiIsCiAgICAgICAgdXJsOiAiL2FwaS9leHBvcnQvanNvbiIsCiAgICAgICAgZmlsZW5hbWU6ICgpID0+IGBrYWNoaW5nLXNhdXZlZ2FyZGUtJHt0b2RheUlzbygpfS5qc29uYCwKICAgICAgICB0b2FzdFN1Y2Nlc3M6ICJTYXV2ZWdhcmRlIHTDqWzDqWNoYXJnw6llIiwKICAgICAgfSwKICAgIH07CiAgICBsZXQgY3VycmVudEV4cG9ydEZvcm1hdCA9ICJ4bHN4IjsKICAgIGNvbnN0IGV4cG9ydEZvcm1hdEhpbnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJleHBvcnQtZm9ybWF0LWhpbnQiKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJleHBvcnQtZm9ybWF0LXRvZ2dsZSIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLmV4cG9ydC1mb3JtYXQtYnRuIik7CiAgICAgIGlmICghYnRuKSByZXR1cm47CiAgICAgIGN1cnJlbnRFeHBvcnRGb3JtYXQgPSBidG4uZGF0YXNldC5mb3JtYXQ7CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoIi5leHBvcnQtZm9ybWF0LWJ0biIpLmZvckVhY2goKGIpID0+IHsKICAgICAgICBiLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGIgPT09IGJ0bik7CiAgICAgIH0pOwogICAgICBleHBvcnRGb3JtYXRIaW50RWwudGV4dENvbnRlbnQgPSBFWFBPUlRfRk9STUFUU1tjdXJyZW50RXhwb3J0Rm9ybWF0XS5oaW50OwogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQtZG93bmxvYWQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQtZG93bmxvYWQiKTsKICAgICAgY29uc3QgY29uZmlnID0gRVhQT1JUX0ZPUk1BVFNbY3VycmVudEV4cG9ydEZvcm1hdF07CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkfDqW7DqXJhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goY29uZmlnLnVybCwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiw4ljaGVjIGRlIGwnZXhwb3J0ICgiICsgcmVzLnN0YXR1cyArICIpIik7CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgICBjb25zdCBsaW5rID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYSIpOwogICAgICAgIGxpbmsuaHJlZiA9IHVybDsKICAgICAgICBsaW5rLmRvd25sb2FkID0gY29uZmlnLmZpbGVuYW1lKCk7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChsaW5rKTsKICAgICAgICBsaW5rLmNsaWNrKCk7CiAgICAgICAgbGluay5yZW1vdmUoKTsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICAgICAgc2hvd1RvYXN0KGNvbmZpZy50b2FzdFN1Y2Nlc3MpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBHYXJkZS1mb3UgZ2xvYmFsIGNvbnRyZSBsZSBjb21wb3J0ZW1lbnQgcGFyIGTDqWZhdXQgZHUgbmF2aWdhdGV1ciA6CiAgICAvLyBkw6lwb3NlciB1biBmaWNoaWVyIE4nSU1QT1JURSBPw5kgc3VyIGxhIHBhZ2UgKGVuIGRlaG9ycyBkJ3VuZSB6b25lCiAgICAvLyBwcsOpdnVlIHBvdXIgw6dhKSBmYWl0IG5vcm1hbGVtZW50IE5BVklHVUVSIGwnb25nbGV0IHZlcnMgY2UgZmljaGllcgogICAgLy8gbG9jYWwgKGZpbGU6Ly8uLi4pLCBxdWkgdGVudGUgZGUgbCdhZmZpY2hlciBjb21tZSB1bmUgcGFnZSDigJQgYXZlYyB1bgogICAgLy8gZ3JvcyBmaWNoaWVyIG91IHVuIGZvcm1hdCBpbmF0dGVuZHUsIMOnYSBwZXV0IHBsYW50ZXIgbCdvbmdsZXQKICAgIC8vICgiQcOvZSBhw69lIGHDr2UiKS4gT24gYmxvcXVlIGNlIGNvbXBvcnRlbWVudCBwYXJ0b3V0LCBldCBsYSB6b25lIGRlCiAgICAvLyBkw6lww7R0IGTDqWRpw6llIChwbHVzIGJhcykgcmVwcmVuZCBsYSBtYWluIHN1ciBsZSBmaWNoaWVyIGTDqXBvc8OpLgogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImRyYWdvdmVyIiwgKGUpID0+IGUucHJldmVudERlZmF1bHQoKSk7CiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiZHJvcCIsIChlKSA9PiBlLnByZXZlbnREZWZhdWx0KCkpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEltcG9ydCBkZSByZWxldsOpIGJhbmNhaXJlIChDU1YgQm91cnNvQmFuaykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIExlIGZpY2hpZXIgbidlc3QgamFtYWlzIGdhcmTDqSBhcHLDqHMgbCdhbmFseXNlIChuaSBpY2ksIG5pIGPDtHTDqQogICAgLy8gc2VydmV1cikgOiBzZXVsIGxlIHRhYmxlYXUgYGltcG9ydFByZXZpZXdSb3dzYCAoZMOpasOgIGRlcyB0cmFuc2FjdGlvbnMKICAgIC8vIGNhbmRpZGF0ZXMsIHBhcyBsZSBmaWNoaWVyIGJydXQpIHZpdCBlbiBtw6ltb2lyZSBsZSB0ZW1wcyBkZSBsYSByZXZ1ZS4KICAgIGxldCBpbXBvcnRQcmV2aWV3Um93cyA9IFtdOyAvLyBbeyAuLi5yb3csIHNlbGVjdGVkOiBib29sIH1dCiAgICBsZXQgaW1wb3J0Q2F0ZWdvcnlMYWJlbHMgPSB7IGV4cGVuc2U6IHt9LCBpbmNvbWU6IHt9IH07CiAgICBjb25zdCBNQVhfSU1QT1JUX0ZJTEVfU0laRV9CWVRFUyA9IDMgKiAxMDI0ICogMTAyNDsgLy8gZG9pdCByZXN0ZXIgYWxpZ27DqSBhdmVjIGxlIGJhY2tlbmQKCiAgICBjb25zdCBpbXBvcnREcm9wem9uZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1kcm9wem9uZSIpOwogICAgY29uc3QgaW1wb3J0RmlsZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1maWxlLWlucHV0Iik7CiAgICBjb25zdCBpbXBvcnRBbmFseXplQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1hbmFseXplLWJ0biIpOwogICAgY29uc3QgaW1wb3J0U3VtbWFyeUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1zdW1tYXJ5Iik7CiAgICBjb25zdCBpbXBvcnRQcmV2aWV3RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXByZXZpZXciKTsKICAgIGNvbnN0IGltcG9ydFJvd3NMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXJvd3MtbGlzdCIpOwogICAgY29uc3QgaW1wb3J0U2VsZWN0ZWRDb3VudEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1zZWxlY3RlZC1jb3VudCIpOwoKICAgIGZ1bmN0aW9uIHVwZGF0ZUltcG9ydFNlbGVjdGVkQ291bnQoKSB7CiAgICAgIGNvbnN0IG4gPSBpbXBvcnRQcmV2aWV3Um93cy5maWx0ZXIoKHIpID0+IHIuc2VsZWN0ZWQpLmxlbmd0aDsKICAgICAgaW1wb3J0U2VsZWN0ZWRDb3VudEVsLnRleHRDb250ZW50ID0gYCR7bn0gc8OpbGVjdGlvbm7DqWUke24gPiAxID8gInMiIDogIiJ9IHN1ciAke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aH1gOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWNvbW1pdC1idG4iKS5kaXNhYmxlZCA9IG4gPT09IDA7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVySW1wb3J0UHJldmlldygpIHsKICAgICAgaW1wb3J0Um93c0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCByb3cgb2YgaW1wb3J0UHJldmlld1Jvd3MpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93IiArIChyb3cuc2VsZWN0ZWQgPyAiIiA6ICIgZXhjbHVkZWQiKTsKCiAgICAgICAgY29uc3QgY2hlY2tib3ggPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGNoZWNrYm94LnR5cGUgPSAiY2hlY2tib3giOwogICAgICAgIGNoZWNrYm94LmNoZWNrZWQgPSByb3cuc2VsZWN0ZWQ7CiAgICAgICAgY2hlY2tib3guYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgcm93LnNlbGVjdGVkID0gY2hlY2tib3guY2hlY2tlZDsKICAgICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImV4Y2x1ZGVkIiwgIXJvdy5zZWxlY3RlZCk7CiAgICAgICAgICB1cGRhdGVJbXBvcnRTZWxlY3RlZENvdW50KCk7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LW1haW4iOwogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWRlc2MiOwogICAgICAgIGNvbnN0IGFtb3VudFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50U3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1hbW91bnQgIiArIHJvdy50eXBlOwogICAgICAgIGFtb3VudFNwYW4udGV4dENvbnRlbnQgPSAocm93LnR5cGUgPT09ICJleHBlbnNlIiA/ICItIiA6ICIrIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocm93LmFtb3VudCk7CiAgICAgICAgZGVzYy5hcHBlbmQoKHJvdy5kZXNjcmlwdGlvbiB8fCAiIikgKyAiIOKAlCAiKTsKICAgICAgICBkZXNjLmFwcGVuZENoaWxkKGFtb3VudFNwYW4pOwoKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWV0YS5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tZXRhIjsKICAgICAgICBsZXQgbWV0YVRleHQgPSBgJHtyb3cuZXhwZW5zZV9kYXRlfSDCtyAke3Jvdy5iYW5rX2xhYmVsfWA7CiAgICAgICAgaWYgKHJvdy5pc19pbnRlcm5hbF90cmFuc2ZlcikgbWV0YVRleHQgKz0gIiDCtyB2aXJlbWVudCBpbnRlcm5lIjsKICAgICAgICBtZXRhLnRleHRDb250ZW50ID0gbWV0YVRleHQ7CiAgICAgICAgaWYgKHJvdy5saWtlbHlfZHVwbGljYXRlKSB7CiAgICAgICAgICBjb25zdCBkdXBTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZHVwU3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kdXAiOwogICAgICAgICAgZHVwU3Bhbi50ZXh0Q29udGVudCA9ICIgwrcgZMOpasOgIHByw6lzZW50ZSA/IjsKICAgICAgICAgIG1ldGEuYXBwZW5kQ2hpbGQoZHVwU3Bhbik7CiAgICAgICAgfQoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobWV0YSk7CgogICAgICAgIGNvbnN0IGNhdFNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGNvbnN0IGxhYmVscyA9IHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyBpbXBvcnRDYXRlZ29yeUxhYmVscy5leHBlbnNlIDogaW1wb3J0Q2F0ZWdvcnlMYWJlbHMuaW5jb21lOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgT2JqZWN0LmVudHJpZXMobGFiZWxzKSkgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgaWYgKHZhbHVlID09PSByb3cuY2F0ZWdvcnkpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgICBjYXRTZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgY2F0U2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsgcm93LmNhdGVnb3J5ID0gY2F0U2VsZWN0LnZhbHVlOyB9KTsKCiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2hlY2tib3gpOwogICAgICAgIGVsLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGVsLmFwcGVuZENoaWxkKGNhdFNlbGVjdCk7CiAgICAgICAgaW1wb3J0Um93c0xpc3RFbC5hcHBlbmRDaGlsZChlbCk7CiAgICAgIH0KICAgICAgdXBkYXRlSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgfQoKICAgIC8vIEdsaXNzZXItZMOpcG9zZXIgZGlyZWN0ZW1lbnQgc3VyIGxhIGNhcnRlIChlbiBwbHVzIGR1IHPDqWxlY3RldXIKICAgIC8vIGNsYXNzaXF1ZSkgOiBvbiByZW1wbGFjZSBsZXMgZmljaGllcnMgZGUgbCdpbnB1dCB2aWEgRGF0YVRyYW5zZmVyLAogICAgLy8gcG91ciBxdWUgbGUgcmVzdGUgZHUgZmx1eCAoYm91dG9uIEFuYWx5c2VyKSByZXN0ZSBpbmNoYW5nw6kuCiAgICBpbXBvcnREcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyYWdvdmVyIiwgKGUpID0+IHsKICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICBpbXBvcnREcm9wem9uZUVsLmNsYXNzTGlzdC5hZGQoImRyYWctb3ZlciIpOwogICAgfSk7CiAgICBpbXBvcnREcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyYWdsZWF2ZSIsICgpID0+IHsKICAgICAgaW1wb3J0RHJvcHpvbmVFbC5jbGFzc0xpc3QucmVtb3ZlKCJkcmFnLW92ZXIiKTsKICAgIH0pOwogICAgaW1wb3J0RHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcm9wIiwgKGUpID0+IHsKICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICBpbXBvcnREcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgICBjb25zdCBmaWxlID0gZS5kYXRhVHJhbnNmZXIuZmlsZXMgJiYgZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBjb25zdCBkdCA9IG5ldyBEYXRhVHJhbnNmZXIoKTsKICAgICAgZHQuaXRlbXMuYWRkKGZpbGUpOwogICAgICBpbXBvcnRGaWxlSW5wdXQuZmlsZXMgPSBkdC5maWxlczsKICAgIH0pOwoKICAgIGltcG9ydEFuYWx5emVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSBpbXBvcnRGaWxlSW5wdXQuZmlsZXMgJiYgaW1wb3J0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHsgc2hvd1RvYXN0KCJDaG9pc2lzIGQnYWJvcmQgdW4gZmljaGllciAuY3N2IiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWZpbGUubmFtZS50b0xvd2VyQ2FzZSgpLmVuZHNXaXRoKCIuY3N2IikpIHsKICAgICAgICBzaG93VG9hc3QoIlNldWxzIGxlcyBmaWNoaWVycyAuY3N2IHNvbnQgYWNjZXB0w6lzIHBvdXIgbCdpbnN0YW50IiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiBNQVhfSU1QT1JUX0ZJTEVfU0laRV9CWVRFUykgewogICAgICAgIHNob3dUb2FzdCgiRmljaGllciB0cm9wIHZvbHVtaW5ldXggKDMgTW8gbWF4aW11bSkiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGltcG9ydEFuYWx5emVCdG4udGV4dENvbnRlbnQ7CiAgICAgIGltcG9ydEFuYWx5emVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBpbXBvcnRBbmFseXplQnRuLnRleHRDb250ZW50ID0gIkFuYWx5c2UgZW4gY291cnPigKYiOwogICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgaW1wb3J0UHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgZmlsZSk7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvaW1wb3J0L2JhbmstY3N2IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgY29uc3QgZXJyID0gYXdhaXQgcmVzLmpzb24oKS5jYXRjaCgoKSA9PiAoe30pKTsKICAgICAgICAgIHRocm93IG5ldyBFcnJvcihlcnIuZGV0YWlsIHx8IGDDiWNoZWMgZGUgbCdhbmFseXNlICgke3Jlcy5zdGF0dXN9KWApOwogICAgICAgIH0KICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICBpbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsKICAgICAgICAgIGV4cGVuc2U6IGRhdGEuZXhwZW5zZV9jYXRlZ29yaWVzIHx8IHt9LAogICAgICAgICAgaW5jb21lOiBkYXRhLmluY29tZV9jYXRlZ29yaWVzIHx8IHt9LAogICAgICAgIH07CiAgICAgICAgaW1wb3J0UHJldmlld1Jvd3MgPSBkYXRhLnJvd3MubWFwKChyb3cpID0+ICh7CiAgICAgICAgICAuLi5yb3csCiAgICAgICAgICBzZWxlY3RlZDogIXJvdy5pc19pbnRlcm5hbF90cmFuc2ZlciAmJiAhcm93Lmxpa2VseV9kdXBsaWNhdGUsCiAgICAgICAgfSkpOwoKICAgICAgICBsZXQgc3VtbWFyeSA9IGA8c3Ryb25nPiR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RofTwvc3Ryb25nPiBvcMOpcmF0aW9uJHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9IGTDqXRlY3TDqWUke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aCA+IDEgPyAicyIgOiAiIn1gOwogICAgICAgIGlmIChkYXRhLmFjY291bnRfYmFsYW5jZSAhPSBudWxsKSB7CiAgICAgICAgICBzdW1tYXJ5ICs9IGAg4oCUIHNvbGRlIGR1IGNvbXB0ZSBhdSAke2RhdGEuYWNjb3VudF9iYWxhbmNlX2RhdGV9IDogPHN0cm9uZz4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChkYXRhLmFjY291bnRfYmFsYW5jZSl9PC9zdHJvbmc+YDsKICAgICAgICB9CiAgICAgICAgaWYgKGRhdGEuc2tpcHBlZF9yb3dzKSBzdW1tYXJ5ICs9IGAgKCR7ZGF0YS5za2lwcGVkX3Jvd3N9IGxpZ25lJHtkYXRhLnNraXBwZWRfcm93cyA+IDEgPyAicyIgOiAiIn0gaWdub3LDqWUke2RhdGEuc2tpcHBlZF9yb3dzID4gMSA/ICJzIiA6ICIifSwgaWxsaXNpYmxlJHtkYXRhLnNraXBwZWRfcm93cyA+IDEgPyAicyIgOiAiIn0pYDsKICAgICAgICBzdW1tYXJ5ICs9ICIuIExlcyB2aXJlbWVudHMgaW50ZXJuZXMgZXQgZG91YmxvbnMgcHJvYmFibGVzIHNvbnQgZMOpY29jaMOpcyBwYXIgZMOpZmF1dCDigJQgdsOpcmlmaWUgYXZhbnQgZCdpbXBvcnRlci4iOwogICAgICAgIGltcG9ydFN1bW1hcnlFbC5pbm5lckhUTUwgPSBzdW1tYXJ5OwogICAgICAgIGltcG9ydFN1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBpbXBvcnRQcmV2aWV3RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgcmVuZGVySW1wb3J0UHJldmlldygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGltcG9ydEFuYWx5emVCdG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtdG9nZ2xlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgY29uc3QgYW55U2VsZWN0ZWQgPSBpbXBvcnRQcmV2aWV3Um93cy5zb21lKChyKSA9PiByLnNlbGVjdGVkKTsKICAgICAgZm9yIChjb25zdCByb3cgb2YgaW1wb3J0UHJldmlld1Jvd3MpIHJvdy5zZWxlY3RlZCA9ICFhbnlTZWxlY3RlZDsKICAgICAgcmVuZGVySW1wb3J0UHJldmlldygpOwogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1jb21taXQtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IHNlbGVjdGVkID0gaW1wb3J0UHJldmlld1Jvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKTsKICAgICAgaWYgKHNlbGVjdGVkLmxlbmd0aCA9PT0gMCkgcmV0dXJuOwogICAgICBjb25zdCBvayA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgIGBJbXBvcnRlciAke3NlbGVjdGVkLmxlbmd0aH0gdHJhbnNhY3Rpb24ke3NlbGVjdGVkLmxlbmd0aCA+IDEgPyAicyIgOiAiIn0gPyBWw6lyaWZpZSBiaWVuIGxlcyBjYXTDqWdvcmllcyBhdmFudCBkZSBjb25maXJtZXIuYAogICAgICApOwogICAgICBpZiAoIW9rKSByZXR1cm47CgogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWNvbW1pdC1idG4iKTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiSW1wb3J0IGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgICAgcm93czogc2VsZWN0ZWQubWFwKChyKSA9PiAoewogICAgICAgICAgICBleHBlbnNlX2RhdGU6IHIuZXhwZW5zZV9kYXRlLAogICAgICAgICAgICB0eXBlOiByLnR5cGUsCiAgICAgICAgICAgIGFtb3VudDogci5hbW91bnQsCiAgICAgICAgICAgIGNhdGVnb3J5OiByLmNhdGVnb3J5LAogICAgICAgICAgICBkZXNjcmlwdGlvbjogci5kZXNjcmlwdGlvbiwKICAgICAgICAgIH0pKSwKICAgICAgICB9OwogICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2ltcG9ydC9iYW5rLWNzdi9jb21taXQiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgJHtyZXN1bHQuaW5zZXJ0ZWR9IHRyYW5zYWN0aW9uJHtyZXN1bHQuaW5zZXJ0ZWQgPiAxID8gInMiIDogIiJ9IGltcG9ydMOpZSR7cmVzdWx0Lmluc2VydGVkID4gMSA/ICJzIiA6ICIifWApOwogICAgICAgIGltcG9ydFByZXZpZXdSb3dzID0gW107CiAgICAgICAgaW1wb3J0UHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIGltcG9ydFN1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGltcG9ydEZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IG9yaWdpbmFsVGV4dDsKICAgICAgfQogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZXNldC1hbGwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICAiU3VwcHJpbWVyIETDiUZJTklUSVZFTUVOVCB0b3V0ZXMgbGVzIGRvbm7DqWVzICh0cmFuc2FjdGlvbnMsIGNoYXJnZXMgcsOpY3VycmVudGVzLCBjYXTDqWdvcmllcyBwZXJzbywgYnVkZ2V0cywgc3VnZ2VzdGlvbnMgaWdub3LDqWVzKSA/IENldHRlIGFjdGlvbiBlc3QgaXJyw6l2ZXJzaWJsZS4iCiAgICAgICk7CiAgICAgIGlmICghb2spIHJldHVybjsKICAgICAgLy8gRG91YmxlIGNvbmZpcm1hdGlvbiB2dSBsZSBjYXJhY3TDqHJlIGlycsOpdmVyc2libGUgZXQgY29tcGxldCBkZSBsJ2FjdGlvbi4KICAgICAgY29uc3Qgb2syID0gYXdhaXQgc2hvd0NvbmZpcm0oIkRlcm5pw6hyZSBjb25maXJtYXRpb24gOiB2cmFpbWVudCB0b3V0IHLDqWluaXRpYWxpc2VyID8iKTsKICAgICAgaWYgKCFvazIpIHJldHVybjsKCiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVzZXQtYWxsIik7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJSw6lpbml0aWFsaXNhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVzZXQtYWxsIiwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiQXBwbGljYXRpb24gcsOpaW5pdGlhbGlzw6llIik7CiAgICAgICAgc2V0VGltZW91dCgoKSA9PiB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCksIDYwMCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gIlLDqWluaXRpYWxpc2VyIHRvdXRlIGwnYXBwbGljYXRpb24iOwogICAgICB9CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBQV0EgOiBpbnN0YWxsYXRpb24gc3VyIGwnw6ljcmFuIGQnYWNjdWVpbAogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgaWYgKCJzZXJ2aWNlV29ya2VyIiBpbiBuYXZpZ2F0b3IpIHsKICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImxvYWQiLCAoKSA9PiB7CiAgICAgICAgbmF2aWdhdG9yLnNlcnZpY2VXb3JrZXIucmVnaXN0ZXIoIi9zdy5qcyIpLmNhdGNoKCgpID0+IHt9KTsKICAgICAgfSk7CiAgICB9CgogICAgcG9wdWxhdGVDYXRlZ29yaWVzKCJleHBlbnNlIik7CiAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwoKICAgIC8vIFJpZW4gZGUgdG91dCDDp2EgKGNoYXJnZW1lbnQgZGVzIGRvbm7DqWVzLCByYWNjb3VyY2lzIFBXQS4uLikgbmUgZG9pdAogICAgLy8gZMOpbWFycmVyIGF2YW50IGQnYXZvaXIgdW4gamV0b24gZGUgc2Vzc2lvbiB2YWxpZGUg4oCUIHNpbm9uIGxhIHByZW1pw6hyZQogICAgLy8gcmVxdcOqdGUgw6ljaG91ZXJhaXQganVzdGUgYXZlYyB1bmUgNDAxIMOgIGxhIHBsYWNlIGRlIG1vbnRyZXIgbGUgdmVycm91LgogICAgaWYgKEFQSV9LRVkpIHsKICAgICAgc2hvd0FwcCgpOwogICAgICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgICAgICAvLyBDYXTDqWdvcmllcyBwZXJzbyArIHN1Z2dlc3Rpb25zIGlnbm9yw6llcyBkJ2Fib3JkLCBwb3VyIHF1ZSBsZXMKICAgICAgICAvLyBsaXN0ZXMgZMOpcm91bGFudGVzIGV0IGxlIGJhbmRlYXUgc29pZW50IGNvcnJlY3RzIGTDqHMgbGUgcHJlbWllcgogICAgICAgIC8vIHJlbmR1IHBsdXTDtHQgcXVlIGRlICJzYXV0ZXIiIHVuZSBmb2lzIGxlIHNlcnZldXIgcsOpcG9uZHUuCiAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoW2xvYWRDdXN0b21DYXRlZ29yaWVzKCksIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpLCBsb2FkQnVkZ2V0cygpLCBsb2FkU2F2aW5nc0dvYWwoKV0pOwogICAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIGxvYWRSZWN1cnJpbmcoKTsKCiAgICAgICAgLy8gUmFjY291cmNpcyBQV0EgKGFwcHVpIGxvbmcgc3VyIGwnaWPDtG5lIGRlIGwnYXBwIHVuZSBmb2lzIGluc3RhbGzDqWUpIDoKICAgICAgICAvLyAvP3Nob3J0Y3V0PWFkZCBvdXZyZSBkaXJlY3RlbWVudCBsZSBmb3JtdWxhaXJlIGQnYWpvdXQsIC8/c2hvcnRjdXQ9dm9pY2UKICAgICAgICAvLyBsYW5jZSBkaXJlY3RlbWVudCBsYSBkaWN0w6llIHZvY2FsZS4KICAgICAgICBjb25zdCBzaG9ydGN1dFBhcmFtID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoInNob3J0Y3V0Iik7CiAgICAgICAgaWYgKHNob3J0Y3V0UGFyYW0pIHsKICAgICAgICAgIC8vIE5ldHRvaWUgbCdVUkwgdG91dCBkZSBzdWl0ZSA6IHVuIHJlY2hhcmdlbWVudCBkZSBsYSBwYWdlIChvdSB1bgogICAgICAgICAgLy8gcGFydGFnZSBkdSBsaWVuKSBuZSBkb2l0IHBhcyByZWTDqWNsZW5jaGVyIGxlIHJhY2NvdXJjaS4KICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gImFkZCIpIHsKICAgICAgICAgICAgb3Blbk1vZGFsKCk7CiAgICAgICAgICB9IGVsc2UgaWYgKHNob3J0Y3V0UGFyYW0gPT09ICJ2b2ljZSIgJiYgIW1pY0J0bi5kaXNhYmxlZCkgewogICAgICAgICAgICBtaWNCdG4uY2xpY2soKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0pKCk7CiAgICB9IGVsc2UgewogICAgICBzaG93TG9ja1NjcmVlbigpOwogICAgfQogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
# END_FRONTEND_B64


@app.get("/", response_class=HTMLResponse)
def serve_frontend() -> HTMLResponse:
    if not FRONTEND_HTML_B64:
        return HTMLResponse(
            content="<h1>Frontend non généré</h1><p>Lance build.py.</p>",
            status_code=500,
        )
    html = base64.b64decode(FRONTEND_HTML_B64).decode("utf-8")
    # No-cache explicite : même installée en PWA (mode standalone, sans barre
    # d'adresse), l'app doit toujours recharger la dernière version publiée
    # au lieu de rester bloquée sur une version mise en cache par le
    # navigateur ou par Vercel.
    return HTMLResponse(content=html, headers={"Cache-Control": "no-cache, must-revalidate"})


# ---------------------------------------------------------------------------
# PWA : manifest, service worker et icônes (installation sur l'écran d'accueil)
# ---------------------------------------------------------------------------
# Icônes embarquées en base64 pour la même raison que le HTML ci-dessus :
# Vercel ne garantit pas d'inclure les fichiers non-Python du dépôt dans le
# paquet de la fonction serverless. Régénérées par build.py à partir de
# frontend/icons/*.png — ne pas éditer ces blocs à la main.
# BEGIN_ICON_192_B64
ICON_192_B64 = "iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAAALx0lEQVR4nO3de3BU5RkG8OdsNrub6+aeAAkkCgEErFB1jKIWnUJBqtZbvXQs49hWnXY0vYzttHamHZ1eKLXipYpOO9V2WqfUS4uC1isXFQHvGkgikSTkvuSe7Ca7e/oHaAPmspv9zn5n931+//Oel5n3Od939pycY8BmvLmFpu4eyDq93Z2G7h7G0toMh50AvaGI+4E59DSZeIchbgfj4FM04hUEyw/CwadYWB0Ey4pz8Eklq4KgvCgHn6ykOggOlcU4/GQ11TOmJE0cfNJBxWoQ8wrA4SddVMxeTAHg8JNusc7gtAPA4Se7iGUWpxUADj/ZzXRnMuoAcPjJrqYzm1EFgMNPdhftjEYcAA4/JYpoZjWiAHD4KdFEOrNTBoDDT4kqktlV+igEUaKZNAA8+1Oim2qGJwwAh5+SxWSzzC0QiTZuAHj2p2Qz0UxzBSDRPhcAnv0pWY0321wBSLTjAsCzPyW7E2ecKwCJ9lkAePYnKcbOOlcAEo0BINEcALc/JM+nM88VgERjAEg0BoBEYwBINIMXwCQZVwASjQEg0RgAEo0BINEYABKNASDRGAASjQEg0RgAEo0BINEYABKNASDRGAASjQEg0RgAEo0BINEYABKNASDRGAASjQEg0Zy6GxDDcMCdUw5P4SnwFCxAqrcMqRnFcGYWI8WdDYfTA8PpAQCYwQDCIT/CI4MIDrRjdKAVo/2t8Hfth7+zBoEjdTDDQc3/oeTAt0JYyJVTjqyKFcgsOwcZZVVwuDKV1DWDAQy27MHAoR0Y+ORV+LtqlNSViAFQLMWTg5wFlyJn4aVIK1kal2MGfHXoqXkCPTVPYHSgLS7HTBYMgCIu72zkL7sRuYuuhCM1XUsPZjiI3v1PoWvvJvh9B7T0kGgYgBg50/NRdFY1cpdcA8Nhl0sqE70H/o22Hb/GaH+L7mZsjQGYLsOB/KU3oLiqWtneXrVw0I+uPQ+g8837edE8AQZgGlw55ShdtQHpM0/X3UpEhjs+QPO22xDw1eluxXYYgCh5K9di1sr12vb502UGA2h56afo/vCfuluxFQYgUoYDJctvR8HpN+nuJCZd+x5G+45fwTRDuluxBQYgAobDidLV98BbuVZ3K0r01W1F07Pf5XUB+CjElAynG7MvfiRphh8Asuetxuy1D8JISdXdinYMwCQMIwVla+5DVsUK3a0ol3Xyl1G2eiMAQ3crWjEAk5hx4Z3IPnml7jYskz1vDUrO/bHuNrRiACaQf9o65C25Vncblis4/SbkLPya7ja0YQDGkVZ8KkrO+5nuNuJm5gV3weWdrbsNLRiAEzicaShbc5+oC0SHKwOlqzcChrxxkPc/nkJRVTVcOXN0txF36TOWIm/JNbrbiDveBxjDU7AQJ1+3xfKH2kwzhKHm3Rhseh3DXTUI+OoRDvQhFOiFkeKCw50FZ1o+0ooWwVO0GFkVF8LlLbO0JwAI+btR++cvIeTvsfxYdsEAjFF+2aPInHO+ZfVHB1rRtXcTevY/hdDwkaj+bVrJUuQvXYec+RdbulXp2vcw2rbfaVl9u2EAjsmYdSYqrrLmOZnw6BDad63HkfcegxkajamWO78SM1f8EhllVYq6O154dAgHHjkbIX+3JfXthtcAxxRVVVtSd6j1LdQ/tgq+t/8U8/ADQMBXi4Z/XYv2Xb+15FEGR2o68pfdoLyuXTEAOHpWzSg7W3ndvvptaNh8NUZ6G9UWNsPofPN+ND1ziyUhyFtynY3+uMdaDACA/NO+qbxmX92zaNxyM8xgQHntz45R/xwa//MdwAwrretMz0fWSRcqrWlX4gNgpLiQs+BSpTWH299F87Zq5YM5nv6DL6Dj9buV181ddJXymnYkPgBZ5SuU/kljeHQITVtuQTjoV1ZzKh2778VA4y6lNTPnnAdHaobSmnYkPgDZlRcprde+az1G+pqV1pyaidaXf670esBIcSFzznJl9ewq6X8GXVx9SHcL0/LB3dHfjS4661alj2731m1F196HlNWzIxmX+kJ0vHEPOt64R3cbCUX8FohkYwBINAaARGMASDQGgERjAEg0BoBEYwBItKS/EzyRGeffgfxlNyqpVfPHUxHy9yqpRfEldgVQ+gDcyKCyWhRfYgMAI0VZKTPMNy0nKrkBUPh6cMOhLkwUX2IDoHLb4nAl/3PzySrpL4IlPQ5N0RO7AhABDAAJxwCQaAwAicYAkGgMAInGAJBoDACJxteiJJH0WWcgrfhUZfUCvnoMHHpVWT07Svo7wVOpuOIf6t61b4Zx8PHLMdT6lpp6UUhxZ2HeulfgTC9QVrPlpTtw5N1HldWzI/FboN7aLeqKGQ7MWrleywf2is7+kdLhB46+eDfZiQ9AX91WmAqfDHXnzcXMC+L7iaHseauVv+Ld3/kRRvtblNa0I/EBCA770H/wRaU1cxdfjcIzblFacyKewlNQumqD8rrdH1rzuSi7ER8AADjyzl+U1yxefjuKqr6vvO5Y6TOWoeLKx5W/xtwMjaCn5kmlNe2KAQAw0LgTAV+d8rpFZ92KsjUbkeLOVl47d9GVKL/8b5bU7q19hh/Jk6ZjtzVvVfbOvwTzrn8B3sqLABgx13Nll2L2Vzdh1srfwZGaHnuDn2Oic88DFtS1J/E/g/6fgbnf2ApP4ULLjhDw1aJz74Poq98W9V+keQoXIu8L1yN30VWWfsCur37b0e+OCcEAjJE55zyUX/aY5ccxQyMYaNyJocN74O/8CIGeBoT8fQiP9MNwOI99Kb4AnsIFSCtajMyKC+DOPcn6vsJB1P/1K5ZsB+2KAThB2ZqN8M6/RHcbWnTt24S27XfpbiOueA1wgtZXfiHmAnCs0f4WdLzxB91txB0DcILgkA/Nz/0AgKCF0QyjeettIl/wxQCMo//gi+ja97DuNuKm4837MHh4t+42tGAAJtC+8zfob3hZdxuW6//4v5Z8aDtRMAATMMNBNG25GcNt7+huxTLD7e+h6dnvxeWL9nbFAEwiHBzGJ0+uw3D7+7pbUc7fWYNDT65DODisuxWtGIAphPzdaNh8dVLtkYfb30XD5q8jOOzT3Yp2DEAEwiMDOPTE9ejZ/7TuVmLW9/HzaNh8Db9ncAxvhEUpf9mNKDn3J5Y+jmANEx2770XHa7+HqJ94p8AATENayWkoXbUB7ry5uluJyGjfYTQ//0MMNr2muxXbYQCmyUhxoaiqGgXLvqXlTyAjYoZx5P2/o23HXSJvckWCAYiRyzsbxctvh7dyre5WjjNwaAfatt8Jf9d+3a3YGgOgiKdwIQq++G1451+s7/rADKP/4Ivo3PcQhg7v0dNDgmEAFHNmFiP3lCvgXXAJPPnz43LMkd4m9B54Gt0fbsZIT0NcjpksGAALufMrkVWxApmzz0H6rDPhcKYpqWuGgxhqfQuDjTvR/8l2DLe9raSuRAxAnBgOJ9x5c+EpWAB3wXy4skvhzCxGakYxHO4sOJweGCluwDBgBgMwg36ERgYRHOzA6EAbRvtbEPDVwt9VA7+vFmYwoPu/lBQYABKNd4JJNAaARGMASDQGgERjAEg0BoBEYwBINAaARGMASDQGgERjAEg0BoBEYwBINAaARGMASDQGgERjAEg0BoBEYwBINAaARGMASDRHb3dn7J8vJ0pAvd2dBlcAEo0BINEYABKNASDRHMDRiwHdjRDF06czzxWARGMASLTPAsBtEEkxdta5ApBoxwWAqwAluxNnnCsAifa5AHAVoGQ13mxzBSDRxg0AVwFKNhPNNFcAEm3CAHAVoGQx2SxPugIwBJToppphboFItCkDwFWAElUksxvRCsAQUKKJdGYj3gIxBJQoopnVqK4BGAKyu2hnNOqLYIaA7Go6szmtX4EYArKb6c7ktH8GZQjILmKZxZjuAzAEpFusMxjzjTCGgHRRMXtKh9ebW2iqrEc0HpUnXaWPQnA1IKupnjHLBparAalk1cnV8jM2g0CxsHpXEbctC4NA0YjXdjrue3YGgSYT7+tIrRetDAMBen88sd2vNgxFcrPbL4X/A0yRm3mg26LVAAAAAElFTkSuQmCC"
# END_ICON_192_B64
# BEGIN_ICON_512_B64
ICON_512_B64 = "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"
# END_ICON_512_B64
# BEGIN_ICON_512_MASKABLE_B64
ICON_512_MASKABLE_B64 = "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAaaElEQVR4nO3deZSddZ3n8e+9dWtJVWWpVIqELCRECCAooIDiirjgQreICjOtuLQ62uqZo7b2Gbu1+4zLtNPtaI+249h2zyC0oy0ugCsjaKvg1qCgICCQpYCQPZWkqlLbrTt/QM/h2CGpJFX1q6rv63VOzs0/1P3UOUXqfZ/7PM+tLOzqaQQAkEq19AAAYPoJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACA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QgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAAS+n/hQ40A9Qig2gAAAABJRU5ErkJggg=="
# END_ICON_512_MASKABLE_B64

PWA_MANIFEST = {
    "name": "Kaching",
    "short_name": "Kaching",
    "description": "Suivi de dépenses et revenus piloté à la voix.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#0f1115",
    "theme_color": "#0f1115",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
    # Raccourcis affichés par un appui long (ou clic droit) sur l'icône de
    # l'app une fois installée — ouvrent directement le formulaire d'ajout ou
    # la dictée vocale, sans repasser par le tableau de bord. Pris en charge
    # par Android/Chrome ; ignoré silencieusement là où ce n'est pas supporté
    # (notamment iOS/Safari), donc sans risque à ajouter.
    "shortcuts": [
        {
            "name": "Ajouter une dépense",
            "short_name": "Ajouter",
            "description": "Ouvrir directement le formulaire d'ajout",
            "url": "/?shortcut=add",
            "icons": [{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"}],
        },
        {
            "name": "Dicter",
            "short_name": "Dicter",
            "description": "Lancer directement la dictée vocale",
            "url": "/?shortcut=voice",
            "icons": [{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"}],
        },
    ],
}

# Service worker minimal : pas de cache hors-ligne pour l'instant (les
# données viennent de toute façon de l'API), juste ce qu'il faut pour que
# Chrome/Android considère le site comme installable (manifest + SW avec un
# gestionnaire fetch). Un passthrough simple, sans mise en cache, pour ne
# jamais servir de données périmées.
OFFLINE_HTML = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kaching — Pas de connexion</title>
<style>
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f1115;
    color: #e5e7eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    text-align: center;
    padding: 2rem;
    box-sizing: border-box;
  }
  .card { max-width: 360px; }
  .emoji { font-size: 3rem; margin-bottom: 1rem; }
  h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
  p { color: #9aa0ac; line-height: 1.5; margin: 0 0 1.5rem; }
  button {
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 0.75rem 1.5rem;
    font-size: 1rem;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="emoji">📡</div>
    <h1>Pas de connexion</h1>
    <p>Kaching a besoin d'internet pour accéder à tes données (elles sont stockées en ligne, pas sur ton téléphone). Vérifie ta connexion et réessaie.</p>
    <button onclick="location.reload()">Réessayer</button>
  </div>
</body>
</html>"""

# Cache minimal : juste de quoi afficher une page d'erreur propre si le
# téléphone n'a pas de réseau au lancement de l'app, plutôt que l'écran
# d'erreur générique du navigateur/système. Les données elles-mêmes ne sont
# JAMAIS mises en cache ici : seule la page /offline.html (statique) l'est,
# pour ne jamais risquer d'afficher des montants périmés.
PWA_SERVICE_WORKER = """
const OFFLINE_CACHE = "kaching-offline-v1";
const OFFLINE_URL = "/offline.html";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(OFFLINE_CACHE).then((cache) => cache.add(OFFLINE_URL))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  // Seules les navigations de page (ouverture/rechargement de l'app) ont un
  // filet de secours hors-ligne. Tout le reste (API, icônes...) reste un
  // passthrough pur, sans aucune mise en cache, pour ne jamais servir de
  // données périmées.
  if (event.request.mode === "navigate") {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }
  event.respondWith(fetch(event.request));
});
"""


@app.get("/offline.html", response_class=HTMLResponse)
def serve_offline_page() -> HTMLResponse:
    return HTMLResponse(content=OFFLINE_HTML, headers={"Cache-Control": "no-cache, must-revalidate"})


@app.get("/manifest.webmanifest")
def serve_manifest() -> Response:
    return Response(
        content=json.dumps(PWA_MANIFEST),
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/sw.js")
def serve_service_worker() -> Response:
    return Response(
        content=PWA_SERVICE_WORKER,
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/icon-192.png")
def serve_icon_192() -> Response:
    return Response(content=base64.b64decode(ICON_192_B64), media_type="image/png")


@app.get("/icon-512.png")
def serve_icon_512() -> Response:
    return Response(content=base64.b64decode(ICON_512_B64), media_type="image/png")


@app.get("/icon-512-maskable.png")
def serve_icon_512_maskable() -> Response:
    return Response(content=base64.b64decode(ICON_512_MASKABLE_B64), media_type="image/png")


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    """Public, sans dépendance à Supabase : confirme juste que le déploiement
    Vercel + le routing FastAPI fonctionnent."""
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/db-check")
def db_check(_: None = Depends(require_api_key)) -> dict:
    """Protégé par clé API : confirme que les identifiants Supabase sont
    corrects et que la table `transactions` est lisible via la clé
    service_role (qui contourne le RLS, activé sans policy pour anon/public)."""
    client = get_supabase_client()
    try:
        result = client.table("transactions").select("id", count="exact").limit(1).execute()
    except Exception as exc:  # noqa: BLE001 - on veut un message clair, pas une 500 opaque
        raise HTTPException(status_code=500, detail=f"Erreur Supabase : {exc}") from exc
    return {"status": "ok", "transactions_table_reachable": True, "row_count": result.count}


# ---------------------------------------------------------------------------
# Transactions ponctuelles (dépenses + revenus) — CRUD
# ---------------------------------------------------------------------------
@app.get("/api/transactions")
def list_transactions(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    sync_recurring_occurrences(client)
    result = (
        client.table("transactions")
        .select("*")
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


@app.post("/api/transactions", status_code=201)
def create_transaction(tx: TransactionIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    payload = {
        "type": tx.type,
        "amount": tx.amount,
        "category": (tx.category or "autre").strip() or "autre",
        "description": tx.description,
        "expense_date": (tx.expense_date or today_paris()).isoformat(),
    }
    result = client.table("transactions").insert(payload).execute()
    return result.data[0]


@app.put("/api/transactions/{transaction_id}")
def update_transaction(
    transaction_id: str, tx: TransactionUpdate, _: None = Depends(require_api_key)
) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    data = tx.model_dump(exclude_unset=True)
    for key, value in data.items():
        if key == "description":
            # Champ explicitement nullable : un description=null envoyé par
            # le client doit effacer la description (ex: nettoyage auto d'un
            # mot-clé devenu redondant avec la catégorie), contrairement aux
            # autres champs ci-dessous où null signifie juste "pas touché".
            payload["description"] = value
            continue
        if value is None:
            continue
        if isinstance(value, date):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = client.table("transactions").update(payload).eq("id", transaction_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return result.data[0]


@app.delete("/api/transactions/{transaction_id}", status_code=204)
def delete_transaction(transaction_id: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    result = client.table("transactions").delete().eq("id", transaction_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Photo de reçu en pièce jointe
# ---------------------------------------------------------------------------
# Stockée dans un bucket Supabase Storage privé ("receipts"), jamais exposée
# en public : comme pour les tables, seul ce backend (clé service_role)
# peut y lire/écrire. Le chemin de stockage est simplement l'id de la
# transaction (un seul reçu par transaction ; en réattacher un nouveau
# remplace l'ancien). Le type MIME d'origine est gardé en base pour pouvoir
# resservir l'image avec le bon Content-Type.
RECEIPTS_BUCKET = "receipts"
ALLOWED_RECEIPT_TYPES = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
MAX_RECEIPT_SIZE_BYTES = 8 * 1024 * 1024  # 8 Mo, large pour une photo de reçu au téléphone


@app.put("/api/transactions/{transaction_id}/receipt")
async def upload_receipt(
    transaction_id: str, file: UploadFile = File(...), _: None = Depends(require_api_key)
) -> dict:
    client = get_supabase_client()
    existing = client.table("transactions").select("id").eq("id", transaction_id).execute().data
    if not existing:
        raise HTTPException(status_code=404, detail="Transaction introuvable")

    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_RECEIPT_TYPES:
        raise HTTPException(status_code=400, detail="Format d'image non supporté (JPEG, PNG, WEBP ou HEIC uniquement)")

    data = await file.read()
    if len(data) > MAX_RECEIPT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Image trop lourde (8 Mo maximum)")

    try:
        client.storage.from_(RECEIPTS_BUCKET).upload(
            transaction_id,
            data,
            file_options={"content-type": content_type, "upsert": "true"},
        )
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(
            status_code=500,
            detail="Échec de l'envoi vers le stockage (le bucket 'receipts' existe-t-il bien dans Supabase ?)",
        ) from exc
    result = (
        client.table("transactions")
        .update({"receipt_path": transaction_id, "receipt_content_type": content_type})
        .eq("id", transaction_id)
        .execute()
    )
    return result.data[0]


@app.get("/api/transactions/{transaction_id}/receipt")
def get_receipt(transaction_id: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions")
        .select("receipt_path, receipt_content_type")
        .eq("id", transaction_id)
        .execute()
        .data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    content_type = rows[0].get("receipt_content_type") or "application/octet-stream"
    try:
        image_bytes = client.storage.from_(RECEIPTS_BUCKET).download(rows[0]["receipt_path"])
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(status_code=404, detail="Photo introuvable dans le stockage") from exc
    return Response(
        content=image_bytes,
        media_type=content_type,
        headers={"Cache-Control": "private, no-cache"},
    )


@app.delete("/api/transactions/{transaction_id}/receipt", status_code=204)
def delete_receipt(transaction_id: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions").select("receipt_path").eq("id", transaction_id).execute().data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    try:
        client.storage.from_(RECEIPTS_BUCKET).remove([rows[0]["receipt_path"]])
    except Exception:  # noqa: BLE001 - le fichier est peut-être déjà absent du bucket
        pass
    client.table("transactions").update(
        {"receipt_path": None, "receipt_content_type": None}
    ).eq("id", transaction_id).execute()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Dépenses récurrentes — CRUD
# ---------------------------------------------------------------------------
# En plus de la définition (type, nom, montant, catégorie, jour du mois,
# dates de début/fin optionnelles), chaque occurrence déjà arrivée (jour du
# mois <= aujourd'hui) est matérialisée en vraie ligne dans `transactions`
# par `sync_recurring_occurrences` ci-dessous — c'est ce qui la fait
# apparaître dans l'historique, les filtres, l'export Excel, etc. comme
# n'importe quelle transaction. `start_date`/`end_date` (optionnelles)
# bornent la période où la charge compte, sans avoir à revenir
# supprimer/désactiver la ligne à la main (ex : un abonnement qui ne démarre
# qu'en novembre).
def _clamp_day(year: int, month: int, day: int) -> int:
    """Ramène un jour du mois (1-31) au dernier jour réel du mois visé, pour
    les charges récurrentes posées sur un jour qui n'existe pas partout
    (ex : le 31 d'un mois à 30 jours, ou le 30 février)."""
    last_day = calendar.monthrange(year, month)[1]
    return min(day, last_day)


def _month_add(year: int, month: int, delta: int) -> tuple[int, int]:
    total = (year * 12 + (month - 1)) + delta
    return total // 12, total % 12 + 1


def sync_recurring_occurrences(client) -> None:
    """Crée, dans `transactions`, les occurrences de charges récurrentes déjà
    arrivées qui n'ont pas encore de ligne correspondante.

    Chaque occurrence (une charge récurrente pour un mois donné) est
    identifiée de façon unique par la paire (recurring_expense_id,
    occurrence_month), ce qui évite de la créer deux fois même si cette
    fonction est appelée à chaque chargement de page. On part de la date de
    début (si posée) ou du mois de création de la charge (sinon) — jamais
    plus tôt —, pour ne pas générer rétroactivement des mois antérieurs à
    l'existence de la charge récurrente.

    Important : on ne modifie ni ne supprime jamais une transaction déjà
    créée ici, même si la charge récurrente est ensuite éditée ou supprimée.
    Une fois matérialisée, une occurrence est un fait passé (de l'argent
    réellement dépensé/reçu ce mois-là), pas une projection à recalculer.
    """
    recurring_items = client.table("recurring_expenses").select("*").execute().data
    if not recurring_items:
        return

    today = today_paris()
    existing = client.table("transactions").select("recurring_expense_id, occurrence_month").execute().data
    existing_keys = {
        (row["recurring_expense_id"], row["occurrence_month"])
        for row in existing
        if row.get("recurring_expense_id")
    }

    new_rows: list[dict] = []
    for item in recurring_items:
        start_date = date.fromisoformat(item["start_date"]) if item.get("start_date") else None
        end_date = date.fromisoformat(item["end_date"]) if item.get("end_date") else None
        created_at = datetime.fromisoformat(item["created_at"]).date()
        year, month = (start_date.year, start_date.month) if start_date else (created_at.year, created_at.month)
        # On ne remonte jamais plus loin que le mois dernier, même si la
        # charge a été créée il y a longtemps : ça évite, au premier appel
        # après cette mise à jour, de faire apparaître d'un coup des mois et
        # des mois de transactions "fantômes" pour une charge ancienne.
        earliest = _month_add(today.year, today.month, -1)
        if (year, month) < earliest:
            year, month = earliest

        while (year, month) <= (today.year, today.month):
            day = _clamp_day(year, month, item["day_of_month"])
            occurrence_date = date(year, month, day)

            if occurrence_date > today:
                break  # les mois suivants seront encore plus loin dans le futur
            if end_date and occurrence_date > end_date:
                break  # charge terminée, rien au-delà
            if start_date and occurrence_date < start_date:
                year, month = _month_add(year, month, 1)
                continue

            occurrence_month = date(year, month, 1).isoformat()
            key = (item["id"], occurrence_month)
            if key not in existing_keys:
                new_rows.append({
                    "type": item["type"],
                    "amount": item["amount"],
                    "category": item["category"],
                    "description": item["name"],
                    "expense_date": occurrence_date.isoformat(),
                    "recurring_expense_id": item["id"],
                    "occurrence_month": occurrence_month,
                })
            year, month = _month_add(year, month, 1)

    if new_rows:
        client.table("transactions").insert(new_rows).execute()


@app.get("/api/recurring")
def list_recurring(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    result = client.table("recurring_expenses").select("*").order("day_of_month").execute()
    return result.data


@app.post("/api/recurring", status_code=201)
def create_recurring(item: RecurringExpenseIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    payload = {
        "type": item.type,
        "name": item.name.strip(),
        "amount": item.amount,
        "category": (item.category or "autre").strip() or "autre",
        "day_of_month": item.day_of_month,
        "start_date": item.start_date.isoformat() if item.start_date else None,
        "end_date": item.end_date.isoformat() if item.end_date else None,
        "active": True,
    }
    result = client.table("recurring_expenses").insert(payload).execute()
    return result.data[0]


@app.put("/api/recurring/{recurring_id}")
def update_recurring(
    recurring_id: str, item: RecurringExpenseUpdate, _: None = Depends(require_api_key)
) -> dict:
    client = get_supabase_client()
    # Contrairement à update_transaction, on NE saute PAS les valeurs None :
    # c'est ce qui permet d'effacer une date de fin déjà posée (renvoyer
    # end_date: null doit bien la retirer, pas être ignoré).
    payload: dict = {}
    data = item.model_dump(exclude_unset=True)
    for key, value in data.items():
        if isinstance(value, date):
            payload[key] = value.isoformat()
        elif isinstance(value, str):
            payload[key] = value.strip()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = client.table("recurring_expenses").update(payload).eq("id", recurring_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return result.data[0]


@app.delete("/api/recurring/{recurring_id}", status_code=204)
def delete_recurring(recurring_id: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    result = client.table("recurring_expenses").delete().eq("id", recurring_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Catégories personnalisées + suggestions ignorées
# ---------------------------------------------------------------------------
# En base (pas dans le navigateur) pour suivre l'utilisateur d'un appareil à
# l'autre (téléphone, tablette, ordinateur) : une catégorie créée depuis le
# bandeau de suggestion, ou une suggestion ignorée, doit se retrouver
# partout, pas seulement sur l'appareil où l'action a été faite.
@app.get("/api/custom-categories")
def list_custom_categories(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    return client.table("custom_categories").select("*").order("created_at").execute().data


@app.post("/api/custom-categories", status_code=201)
def create_custom_category(item: CustomCategoryIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    value = item.value.strip()
    label = item.label.strip()
    if not value or not label:
        raise HTTPException(status_code=400, detail="Valeur et libellé requis")

    # Idempotent : si la catégorie existe déjà (même type + valeur), on la
    # renvoie telle quelle plutôt que de planter sur la contrainte unique —
    # ça évite un souci si le bandeau est validé deux fois par erreur, ou
    # sur deux appareils en même temps.
    existing = (
        client.table("custom_categories")
        .select("*")
        .eq("type", item.type)
        .eq("value", value)
        .execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("custom_categories").insert(
        {"type": item.type, "value": value, "label": label}
    ).execute()
    return result.data[0]


@app.get("/api/dismissed-suggestions")
def list_dismissed_suggestions(_: None = Depends(require_api_key)) -> list[str]:
    client = get_supabase_client()
    rows = client.table("dismissed_category_suggestions").select("suggestion_key").execute().data
    return [row["suggestion_key"] for row in rows]


@app.post("/api/dismissed-suggestions", status_code=201)
def create_dismissed_suggestion(item: DismissedSuggestionIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    key = item.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="Clé requise")

    existing = (
        client.table("dismissed_category_suggestions").select("*").eq("suggestion_key", key).execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("dismissed_category_suggestions").insert({"suggestion_key": key}).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Budgets mensuels par catégorie
# ---------------------------------------------------------------------------
# Un seul budget par catégorie (pas par mois) : c'est un plafond reconduit
# automatiquement chaque mois, comparé aux dépenses réelles du mois en cours
# côté frontend.
@app.get("/api/budgets")
def list_budgets(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    return client.table("budgets").select("*").execute().data


@app.put("/api/budgets")
def upsert_budget(item: BudgetIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    category = item.category.strip().lower()

    existing = client.table("budgets").select("*").eq("category", category).execute().data
    if existing:
        result = client.table("budgets").update({"amount": item.amount}).eq("category", category).execute()
        return result.data[0]

    result = client.table("budgets").insert({"category": category, "amount": item.amount}).execute()
    return result.data[0]


@app.delete("/api/budgets/{category}", status_code=204)
def delete_budget(category: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    result = client.table("budgets").delete().eq("category", category).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Budget introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Objectif d'épargne mensuel (une seule ligne globale, pas par catégorie)
# ---------------------------------------------------------------------------
@app.get("/api/savings-goal")
def get_savings_goal(_: None = Depends(require_api_key)) -> dict | None:
    client = get_supabase_client()
    rows = client.table("savings_goal").select("*").limit(1).execute().data
    return rows[0] if rows else None


@app.put("/api/savings-goal")
def upsert_savings_goal(item: SavingsGoalIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    existing = client.table("savings_goal").select("id").limit(1).execute().data
    if existing:
        result = (
            client.table("savings_goal")
            .update({"monthly_target": item.monthly_target})
            .eq("id", existing[0]["id"])
            .execute()
        )
        return result.data[0]

    result = client.table("savings_goal").insert({"monthly_target": item.monthly_target}).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Réinitialisation complète (données de test)
# ---------------------------------------------------------------------------
# Supprime TOUT : transactions, charges récurrentes, catégories perso,
# suggestions ignorées et budgets. Irréversible, protégé par la clé API
# comme le reste, avec une confirmation forte côté frontend.
_RESET_TABLES = [
    "transactions",
    "recurring_expenses",
    "custom_categories",
    "dismissed_category_suggestions",
    "budgets",
    "savings_goal",
]
# UUID nil : ne correspond jamais à une ligne réelle, donc ce filtre revient
# à "toutes les lignes" — l'API Supabase (postgrest) exige un filtre sur delete.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


@app.delete("/api/reset-all", status_code=204)
def reset_all(_: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    for table_name in _RESET_TABLES:
        client.table(table_name).delete().neq("id", _NIL_UUID).execute()

    # Les photos de reçus vivent dans le Storage, pas dans une table : les
    # effacer séparément, sinon "tout réinitialiser" laisserait les anciennes
    # photos orphelines dans le bucket (non listées nulle part, mais toujours
    # stockées et comptant dans le quota Supabase).
    try:
        receipt_files = client.storage.from_(RECEIPTS_BUCKET).list(options={"limit": 1000})
        paths = [f["name"] for f in receipt_files if f.get("name")]
        if paths:
            client.storage.from_(RECEIPTS_BUCKET).remove(paths)
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas faire échouer le reset des tables
        pass

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Sauvegarde complète (JSON brut de toutes les tables) — Supabase ne fait pas
# de sauvegarde automatique en offre gratuite ; ce fichier est le filet de
# sécurité en cas de suppression accidentelle ou de pépin côté Supabase. Ne
# couvre pas les photos de reçus elles-mêmes (binaires), seulement les
# chemins qui y pointent (receipt_path) — les fichiers restent dans le bucket
# Storage, qui a sa propre durabilité côté Supabase.
# ---------------------------------------------------------------------------
@app.get("/api/export/json")
def export_json(_: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    sync_recurring_occurrences(client)

    backup: dict = {
        "app": "Kaching",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for table_name in _RESET_TABLES:
        backup[table_name] = client.table(table_name).select("*").execute().data

    payload = json.dumps(backup, indent=2, ensure_ascii=False, default=str)
    filename = f"kaching-sauvegarde-{today_paris().isoformat()}.json"
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Export Excel
# ---------------------------------------------------------------------------
@app.get("/api/export/xlsx")
def export_xlsx(_: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    sync_recurring_occurrences(client)
    transactions = (
        client.table("transactions")
        .select("*")
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    ).data
    recurring = (
        client.table("recurring_expenses").select("*").order("day_of_month").execute()
    ).data

    # Import différé : openpyxl n'est utile que pour cette seule route, pas
    # besoin de l'importer (et de ralentir le démarrage de la fonction) pour
    # le reste de l'API.
    from io import BytesIO

    from openpyxl import Workbook
    from openpyxl.chart import BarChart, PieChart, Reference
    from openpyxl.chart.series import DataPoint
    from openpyxl.chart.shapes import GraphicalProperties
    from openpyxl.styles import Font, PatternFill

    type_labels = {"expense": "Dépense", "income": "Revenu"}

    # Mêmes couleurs que le site (voir CHART_COLORS côté frontend) pour que
    # l'export ressemble au tableau de bord : rouge pour les dépenses, vert
    # pour les revenus, et la même palette cyclique pour les catégories.
    COLOR_EXPENSE = "EF4444"
    COLOR_INCOME = "22C55E"
    COLOR_ACCENT = "3B82F6"
    CHART_COLORS = ["3B82F6", "22C55E", "EF4444", "F59E0B", "A855F7", "14B8A6", "EC4899", "64748B"]
    HEADER_FILL = PatternFill(start_color="EEF2FF", end_color="EEF2FF", fill_type="solid")

    def category_colors(rows: list[tuple[str, float]]) -> list[DataPoint]:
        return [
            DataPoint(idx=i, spPr=GraphicalProperties(solidFill=CHART_COLORS[i % len(CHART_COLORS)]))
            for i in range(len(rows))
        ]

    # --- Agrégats pour le résumé (totaux, camemberts, évolution mensuelle) ---
    total_expenses = 0.0
    total_income = 0.0
    expense_category_totals: dict[str, float] = {}
    income_category_totals: dict[str, float] = {}
    monthly_totals: dict[str, dict[str, float]] = {}
    for tx in transactions:
        amount = float(tx["amount"])
        month_key = tx["expense_date"][:7]
        monthly_totals.setdefault(month_key, {"expense": 0.0, "income": 0.0})
        monthly_totals[month_key][tx["type"]] += amount
        if tx["type"] == "expense":
            total_expenses += amount
            expense_category_totals[tx["category"]] = expense_category_totals.get(tx["category"], 0.0) + amount
        else:
            total_income += amount
            income_category_totals[tx["category"]] = income_category_totals.get(tx["category"], 0.0) + amount
    expense_category_rows = sorted(expense_category_totals.items(), key=lambda kv: kv[1], reverse=True)
    income_category_rows = sorted(income_category_totals.items(), key=lambda kv: kv[1], reverse=True)
    month_keys = sorted(monthly_totals)
    solde = total_income - total_expenses

    wb = Workbook()
    ws_summary = wb.active
    ws_summary.title = "Résumé"
    ws_summary["A1"] = "Résumé financier"
    ws_summary["A1"].font = Font(bold=True, size=14, color=COLOR_ACCENT)

    ws_summary["A3"] = "Solde"
    ws_summary["B3"] = solde
    ws_summary["A4"] = "Total dépenses"
    ws_summary["B4"] = total_expenses
    ws_summary["A5"] = "Total revenus"
    ws_summary["B5"] = total_income
    ws_summary.cell(row=3, column=1).font = Font(bold=True)
    ws_summary.cell(row=3, column=2).font = Font(bold=True, color=COLOR_INCOME if solde >= 0 else COLOR_EXPENSE)
    ws_summary.cell(row=4, column=1).font = Font(bold=True, color=COLOR_EXPENSE)
    ws_summary.cell(row=4, column=2).font = Font(color=COLOR_EXPENSE)
    ws_summary.cell(row=5, column=1).font = Font(bold=True, color=COLOR_INCOME)
    ws_summary.cell(row=5, column=2).font = Font(color=COLOR_INCOME)

    def write_category_section(title: str, header_row: int, rows: list[tuple[str, float]], tx_type: str) -> int:
        """Écrit le titre de section + le tableau Catégorie/Montant à partir de
        `header_row`, et renvoie la dernière ligne utilisée (ou header_row si
        `rows` est vide, pour que l'appelant puisse quand même avancer)."""
        ws_summary.cell(row=header_row - 1, column=1, value=title).font = Font(bold=True, color=COLOR_ACCENT)
        ws_summary.cell(row=header_row, column=1, value="Catégorie")
        ws_summary.cell(row=header_row, column=2, value="Montant (€)")
        for col in (1, 2):
            cell = ws_summary.cell(row=header_row, column=col)
            cell.font = Font(bold=True)
            cell.fill = HEADER_FILL
        start_row = header_row + 1
        for i, (cat, amount) in enumerate(rows):
            row = start_row + i
            ws_summary.cell(row=row, column=1, value=category_label(cat, tx_type))
            ws_summary.cell(row=row, column=2, value=amount)
        return start_row + len(rows) - 1 if rows else header_row

    # Les deux camemberts sont anchorés à intervalle fixe en colonne D, assez
    # espacés (17 lignes) pour ne jamais se chevaucher quel que soit le
    # nombre de catégories listées en colonnes A/B à côté.
    cat_header_row = 7
    cat_end_row = write_category_section(
        "Dépenses par catégorie", cat_header_row, expense_category_rows, "expense"
    )
    if expense_category_rows:
        pie_expense = PieChart()
        pie_expense.title = "Répartition des dépenses par catégorie"
        data = Reference(ws_summary, min_col=2, min_row=cat_header_row + 1, max_row=cat_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=cat_header_row + 1, max_row=cat_end_row)
        pie_expense.add_data(data, titles_from_data=False)
        pie_expense.set_categories(cats)
        pie_expense.series[0].data_points = category_colors(expense_category_rows)
        pie_expense.height = 8
        pie_expense.width = 13
        ws_summary.add_chart(pie_expense, "D3")

    inc_header_row = cat_end_row + 3
    inc_end_row = write_category_section(
        "Revenus par catégorie", inc_header_row, income_category_rows, "income"
    )
    if income_category_rows:
        pie_income = PieChart()
        pie_income.title = "Répartition des revenus par catégorie"
        data = Reference(ws_summary, min_col=2, min_row=inc_header_row + 1, max_row=inc_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=inc_header_row + 1, max_row=inc_end_row)
        pie_income.add_data(data, titles_from_data=False)
        pie_income.set_categories(cats)
        pie_income.series[0].data_points = category_colors(income_category_rows)
        pie_income.height = 8
        pie_income.width = 13
        ws_summary.add_chart(pie_income, "D20")

    month_header_row = inc_end_row + 3
    ws_summary.cell(row=month_header_row - 1, column=1, value="Évolution mensuelle").font = Font(
        bold=True, color=COLOR_ACCENT
    )
    ws_summary.cell(row=month_header_row, column=1, value="Mois")
    ws_summary.cell(row=month_header_row, column=2, value="Dépenses")
    ws_summary.cell(row=month_header_row, column=3, value="Revenus")
    for col in (1, 2, 3):
        cell = ws_summary.cell(row=month_header_row, column=col)
        cell.font = Font(bold=True)
        cell.fill = HEADER_FILL
    month_start_row = month_header_row + 1
    for i, month_key in enumerate(month_keys):
        row = month_start_row + i
        ws_summary.cell(row=row, column=1, value=month_key)
        ws_summary.cell(row=row, column=2, value=monthly_totals[month_key]["expense"]).font = Font(color=COLOR_EXPENSE)
        ws_summary.cell(row=row, column=3, value=monthly_totals[month_key]["income"]).font = Font(color=COLOR_INCOME)
    month_end_row = month_start_row + len(month_keys) - 1

    if month_keys:
        bar = BarChart()
        bar.type = "col"
        bar.title = "Évolution mensuelle (dépenses vs revenus)"
        data = Reference(ws_summary, min_col=2, max_col=3, min_row=month_header_row, max_row=month_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=month_start_row, max_row=month_end_row)
        bar.add_data(data, titles_from_data=True)
        bar.set_categories(cats)
        bar.series[0].graphicalProperties.solidFill = COLOR_EXPENSE
        bar.series[1].graphicalProperties.solidFill = COLOR_INCOME
        bar.height = 8
        bar.width = 15
        ws_summary.add_chart(bar, "D37")

    for col_letter, width in zip("ABC", [24, 14, 14]):
        ws_summary.column_dimensions[col_letter].width = width

    # --- Transactions : deux blocs de colonnes séparés (dépenses / revenus) ---
    # plutôt qu'une seule liste mélangée triée par date — plus lisible, en
    # particulier avec beaucoup de lignes des deux types.
    ws_tx = wb.create_sheet("Transactions")
    expense_txs = [tx for tx in transactions if tx["type"] == "expense"]
    income_txs = [tx for tx in transactions if tx["type"] == "income"]

    def write_tx_block(title: str, start_col: int, rows: list[dict], color: str) -> None:
        col_letters = [chr(ord("A") + start_col - 1 + i) for i in range(4)]
        ws_tx.cell(row=1, column=start_col, value=title).font = Font(bold=True, color=COLOR_ACCENT)
        headers = ["Date", "Catégorie", "Montant (€)", "Description"]
        for i, header in enumerate(headers):
            cell = ws_tx.cell(row=2, column=start_col + i, value=header)
            cell.font = Font(bold=True)
            cell.fill = HEADER_FILL
        for r, tx in enumerate(rows):
            row = 3 + r
            ws_tx.cell(row=row, column=start_col, value=tx["expense_date"])
            ws_tx.cell(row=row, column=start_col + 1, value=category_label(tx["category"], tx["type"]))
            ws_tx.cell(row=row, column=start_col + 2, value=float(tx["amount"])).font = Font(color=color)
            ws_tx.cell(row=row, column=start_col + 3, value=tx.get("description") or "")
        for col_letter, width in zip(col_letters, [12, 14, 12, 42]):
            ws_tx.column_dimensions[col_letter].width = width

    write_tx_block("Dépenses", 1, expense_txs, COLOR_EXPENSE)  # colonnes A-D
    write_tx_block("Revenus", 6, income_txs, COLOR_INCOME)  # colonnes F-I (E = séparateur)

    ws_rec = wb.create_sheet("Récurrentes")
    ws_rec.append(["Type", "Nom", "Montant (€)", "Catégorie", "Jour du mois", "Date de début", "Date de fin"])
    for cell in ws_rec[1]:
        cell.font = Font(bold=True)
        cell.fill = HEADER_FILL
    for item in recurring:
        rec_type = item.get("type") or "expense"
        ws_rec.append([
            type_labels.get(rec_type, rec_type),
            item["name"],
            float(item["amount"]),
            category_label(item["category"], rec_type),
            item["day_of_month"],
            item.get("start_date") or "",
            item.get("end_date") or "",
        ])
        ws_rec.cell(row=ws_rec.max_row, column=3).font = Font(
            color=COLOR_INCOME if rec_type == "income" else COLOR_EXPENSE
        )
    for col_letter, width in zip("ABCDEFG", [10, 24, 12, 14, 12, 14, 14]):
        ws_rec.column_dimensions[col_letter].width = width

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    filename = f"depenses_{today_paris().isoformat()}.xlsx"
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Import de relevé bancaire (CSV export BoursoBank)
# ---------------------------------------------------------------------------
# Format ciblé pour l'instant : export "export-operations-....CSV" de
# BoursoBank — ";" comme séparateur, BOM UTF-8, et une bizarrerie de cet
# export : DEUX colonnes s'appellent toutes les deux "Solde" dans l'en-tête.
# La première est en réalité le MONTANT signé de l'opération (négatif =
# dépense, positif = revenu, décimale à la française avec une virgule) ; la
# dernière est le vrai solde du compte après l'opération (décimale avec un
# point). On ne lit jamais le numéro de compte (IBAN/RIB) : il n'est utile à
# rien ici et n'est jamais recopié dans la réponse. Le fichier n'est ni
# stocké sur disque ni envoyé à Supabase Storage — uniquement analysé en
# mémoire le temps de la requête, puis oublié.
_BOURSO_EXPECTED_HEADER_PREFIX = ["Date Opération", "Date Valeur", "Libellé"]
MAX_BANK_IMPORT_FILE_SIZE = 3 * 1024 * 1024  # 3 Mo : largement assez pour un relevé annuel
MAX_BANK_IMPORT_COMMIT_ROWS = 2000

# Catégorie BoursoBank ("Catégorie" fine, ou "Catégorie Parente" en repli),
# normalisée (accents/majuscules retirés) -> catégorie de dépense de l'appli.
# Uniquement pour les dépenses : les catégories bancaires côté revenus
# ("Virements reçus"...) ne correspondent à rien d'assez fiable chez nous,
# donc un revenu importé reste toujours en "autre" (à reclasser à la main —
# le système de suggestion par mot-clé prend ensuite le relais comme pour
# une saisie vocale ou manuelle).
_BOURSO_CATEGORY_MAP = {
    "peages": "transport",
    "carburant": "transport",
    "auto & moto": "transport",
    "alimentation": "courses",
    "vie quotidienne": "loisirs",
    "vie quotidienne - autres": "loisirs",
    "livres, cd/dvd, bijoux, jouets...": "loisirs",
    "mobilier, electromenager, decoration...": "loisirs",
    "electronique et informatique": "loisirs",
    "equipements sportifs et artistiques": "loisirs",
    "bricolage et jardinage": "loisirs",
}


def _normalize_bourso_key(text: str) -> str:
    stripped = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")
    return stripped.strip().lower()


def _is_bourso_internal_transfer(parent_category: str) -> bool:
    """Virement entre deux comptes de l'utilisateur lui-même (ex: vers son
    épargne) : ne doit pas compter comme une vraie dépense/un vrai revenu,
    donc décoché par défaut dans l'aperçu plutôt qu'importé directement."""
    return "mouvements internes" in _normalize_bourso_key(parent_category)


def _guess_category_from_bourso(
    category: str, parent_category: str, custom_expense: dict[str, str]
) -> str:
    guess = _BOURSO_CATEGORY_MAP.get(_normalize_bourso_key(category))
    if not guess:
        guess = _BOURSO_CATEGORY_MAP.get(_normalize_bourso_key(parent_category))
    if not guess:
        return "autre"
    valid = EXPENSE_CATEGORIES | set(custom_expense.keys())
    return guess if guess in valid else "autre"


def _parse_french_amount(raw: str) -> float | None:
    cleaned = raw.strip().replace("\xa0", "").replace(" ", "").replace(",", ".")
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


class BankImportRow(BaseModel):
    row_index: int
    expense_date: date
    type: TransactionType
    amount: float
    description: str
    category: str
    bank_label: str
    is_internal_transfer: bool
    likely_duplicate: bool


class BankImportCommitRow(BaseModel):
    expense_date: date
    type: TransactionType
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None


class BankImportCommitRequest(BaseModel):
    rows: list[BankImportCommitRow] = Field(min_length=1, max_length=MAX_BANK_IMPORT_COMMIT_ROWS)


@app.post("/api/import/bank-csv", response_model=None)
async def preview_bank_import(file: UploadFile = File(...), _: None = Depends(require_api_key)) -> dict:
    filename = (file.filename or "").lower()
    if not filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .csv sont acceptés pour l'instant (export BoursoBank)")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Fichier vide")
    if len(raw_bytes) > MAX_BANK_IMPORT_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (3 Mo maximum)")

    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw_bytes.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Encodage du fichier non reconnu") from exc

    reader = csv.reader(StringIO(text), delimiter=";")
    try:
        header = next(reader)
    except StopIteration:
        raise HTTPException(status_code=400, detail="Fichier vide") from None

    header_clean = [h.strip().strip('"') for h in header]
    if header_clean[:3] != _BOURSO_EXPECTED_HEADER_PREFIX:
        raise HTTPException(
            status_code=422,
            detail=(
                "Format non reconnu : seul l'export CSV BoursoBank "
                '("export-operations...") est supporté pour l\'instant'
            ),
        )

    solde_indices = [i for i, h in enumerate(header_clean) if h == "Solde"]
    try:
        idx_date = header_clean.index("Date Opération")
        idx_libelle = header_clean.index("Libellé")
        idx_libelle_suggere = header_clean.index("Libellé Suggéré")
        idx_categorie = header_clean.index("Catégorie")
        idx_categorie_parente = header_clean.index("Catégorie Parente")
        idx_libelle_compte = header_clean.index("Libellé Compte")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Colonnes attendues manquantes dans le fichier") from exc
    if len(solde_indices) < 2:
        raise HTTPException(status_code=422, detail="Colonnes attendues manquantes dans le fichier")
    idx_montant, idx_solde_reel = solde_indices[0], solde_indices[-1]

    client = get_supabase_client()
    custom = _fetch_custom_categories(client)

    rows_out: list[dict] = []
    skipped = 0
    account_label: str | None = None
    account_balance: float | None = None
    account_balance_date: date | None = None
    parsed_dates: list[date] = []

    for i, row in enumerate(reader):
        if len(row) <= max(idx_date, idx_libelle, idx_montant, idx_solde_reel):
            skipped += 1
            continue
        try:
            op_date = date.fromisoformat(row[idx_date].strip())
        except ValueError:
            skipped += 1
            continue
        amount_raw = _parse_french_amount(row[idx_montant])
        if amount_raw is None or amount_raw == 0:
            skipped += 1
            continue

        tx_type: TransactionType = "expense" if amount_raw < 0 else "income"
        amount = round(abs(amount_raw), 2)

        suggere = row[idx_libelle_suggere].strip() if idx_libelle_suggere < len(row) else ""
        brut = row[idx_libelle].strip() if idx_libelle < len(row) else ""
        description = suggere or brut or "Opération bancaire"
        category_raw = row[idx_categorie].strip() if idx_categorie < len(row) else ""
        parent_raw = row[idx_categorie_parente].strip() if idx_categorie_parente < len(row) else ""
        is_transfer = _is_bourso_internal_transfer(parent_raw)
        category = (
            _guess_category_from_bourso(category_raw, parent_raw, custom.get("expense", {}))
            if tx_type == "expense"
            else "autre"
        )

        parsed_dates.append(op_date)
        if account_balance_date is None or op_date >= account_balance_date:
            solde_raw = row[idx_solde_reel].strip() if idx_solde_reel < len(row) else ""
            try:
                account_balance = float(solde_raw.replace(",", "."))
                account_balance_date = op_date
            except ValueError:
                pass
        if account_label is None and idx_libelle_compte < len(row):
            account_label = row[idx_libelle_compte].strip() or None

        rows_out.append({
            "row_index": i,
            "expense_date": op_date,
            "type": tx_type,
            "amount": amount,
            "description": description,
            "category": category,
            "bank_label": parent_raw or category_raw or "Non catégorisé",
            "is_internal_transfer": is_transfer,
        })

    if not rows_out:
        raise HTTPException(status_code=422, detail="Aucune opération exploitable trouvée dans ce fichier")

    # Détection de doublons probables (même date + montant + type + libellé
    # déjà en base) : évite de réimporter deux fois le même relevé sans s'en
    # rendre compte. Les lignes repérées restent importables (ce n'est qu'une
    # alerte, pas un blocage) mais sont décochées par défaut côté frontend.
    min_date, max_date = min(parsed_dates), max(parsed_dates)
    existing = (
        client.table("transactions")
        .select("expense_date, amount, type, description")
        .gte("expense_date", min_date.isoformat())
        .lte("expense_date", max_date.isoformat())
        .execute()
    ).data
    existing_signatures = {
        (
            row["expense_date"],
            round(float(row["amount"]), 2),
            row["type"],
            (row.get("description") or "").strip().lower(),
        )
        for row in existing
    }
    for row in rows_out:
        sig = (row["expense_date"].isoformat(), row["amount"], row["type"], row["description"].strip().lower())
        row["likely_duplicate"] = sig in existing_signatures

    return {
        "rows": rows_out,
        "account_label": account_label,
        "account_balance": account_balance,
        "account_balance_date": account_balance_date,
        "skipped_rows": skipped,
        "expense_categories": {
            **{c: category_label(c, "expense") for c in EXPENSE_CATEGORIES},
            **custom.get("expense", {}),
        },
        "income_categories": {
            **{c: category_label(c, "income") for c in INCOME_CATEGORIES},
            **custom.get("income", {}),
        },
    }


@app.post("/api/import/bank-csv/commit", status_code=201)
def commit_bank_import(req: BankImportCommitRequest, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    payload = [
        {
            "type": row.type,
            "amount": row.amount,
            "category": (row.category or "autre").strip() or "autre",
            "description": row.description,
            "expense_date": row.expense_date.isoformat(),
        }
        for row in req.rows
    ]
    result = client.table("transactions").insert(payload).execute()
    return {"inserted": len(result.data)}
