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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdCB7CiAgICBjb2xvci1zY2hlbWU6IGRhcms7CiAgICAtLWJnOiAjMGYxMTE1OwogICAgLS1zdXJmYWNlOiAjMWExZDI0OwogICAgLS1zdXJmYWNlLTI6ICMyMjI2MmY7CiAgICAtLWJvcmRlcjogIzJhMmUzODsKICAgIC0tdGV4dDogI2U2ZTZlNjsKICAgIC0tdGV4dC1kaW06ICM5YWEwYWM7CiAgICAtLWFjY2VudDogIzNiODJmNjsKICAgIC0tYWNjZW50LWRpbTogIzFkNGVkODsKICAgIC0tZGFuZ2VyOiAjZWY0NDQ0OwogICAgLS1zdWNjZXNzOiAjMjJjNTVlOwogICAgLS1yYWRpdXM6IDE0cHg7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgYm9keSB7CiAgICBtYXJnaW46IDA7CiAgICBtaW4taGVpZ2h0OiAxMDB2aDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKICAgIHBhZGRpbmctYm90dG9tOiA2cmVtOwogIH0KICBoZWFkZXIgewogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gMXJlbTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICB9CiAgaDEgeyBmb250LXNpemU6IDEuM3JlbTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC45cmVtOyBtYXJnaW46IDA7IH0KCiAgLnRhYnMgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgfQogIC50YWItYnRuIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDExMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnRhYi1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KCiAgLyogU3VyIHBldGl0IMOpY3JhbiwgbGEgYmFycmUgZCdvbmdsZXRzIGRldmllbnQgdW4gdGlyb2lyIChtZW51ICJidXJnZXIiKQogICAgIHBsdXTDtHQgcXVlIGRlIHMnw6ljcmFzZXIgZW4gcGx1c2lldXJzIGxpZ25lcyA6IHBsdXMgZGUgcGxhY2UgcG91ciBsZQogICAgIGNvbnRlbnUsIGV0IGRlcyBsaWJlbGzDqXMgdG91am91cnMgbGlzaWJsZXMgZW4gZW50aWVyLiAqLwogIC5tZW51LXRvZ2dsZS1idG4gewogICAgZGlzcGxheTogbm9uZTsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDFyZW07CiAgICB6LWluZGV4OiAzMDsKICAgIHdpZHRoOiA0MnB4OwogICAgaGVpZ2h0OiA0MnB4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS4ycmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAubmF2LWRyYXdlci1iYWNrZHJvcCB7CiAgICBkaXNwbGF5OiBub25lOwogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgei1pbmRleDogMjU7CiAgfQogIEBtZWRpYSAobWF4LXdpZHRoOiA2NDBweCkgewogICAgLm1lbnUtdG9nZ2xlLWJ0biB7IGRpc3BsYXk6IGZsZXg7IH0KICAgIGhlYWRlciB7IHBhZGRpbmctbGVmdDogMy43NXJlbTsgfQogICAgLnRhYnMgewogICAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICAgIHRvcDogMDsKICAgICAgbGVmdDogMDsKICAgICAgYm90dG9tOiAwOwogICAgICBmbGV4LXdyYXA6IG5vd3JhcDsKICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgICAgd2lkdGg6IDI0MHB4OwogICAgICBtYXgtd2lkdGg6IDgwdnc7CiAgICAgIG1hcmdpbjogMDsKICAgICAgcGFkZGluZzogNC41cmVtIDFyZW0gMS41cmVtOwogICAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgICAgYm9yZGVyLXJpZ2h0OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgICAgei1pbmRleDogMjY7CiAgICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtMTAwJSk7CiAgICAgIHRyYW5zaXRpb246IHRyYW5zZm9ybSAwLjJzIGVhc2U7CiAgICAgIG92ZXJmbG93LXk6IGF1dG87CiAgICB9CiAgICAudGFiLWJ0biB7IGZsZXg6IG5vbmU7IHdpZHRoOiAxMDAlOyB0ZXh0LWFsaWduOiBsZWZ0OyB9CiAgICBib2R5Lm5hdi1kcmF3ZXItb3BlbiAudGFicyB7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgwKTsgfQogICAgYm9keS5uYXYtZHJhd2VyLW9wZW4gLm5hdi1kcmF3ZXItYmFja2Ryb3AgeyBkaXNwbGF5OiBibG9jazsgfQogIH0KCiAgLnN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTAwcHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC45cmVtIDFyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAwLjI1cmVtOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUucG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b29sdGlwLWhvc3QgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGN1cnNvcjogaGVscDsgfQogIC5jdXN0b20tdG9vbHRpcCB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiA1MCU7CiAgICBib3R0b206IGNhbGMoMTAwJSArIDAuNnJlbSk7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg0cHgpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41NXJlbSAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB0ZXh0LWFsaWduOiBsZWZ0OwogICAgYm94LXNoYWRvdzogMCA4cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMzUpOwogICAgb3BhY2l0eTogMDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwogICAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjEycyBlYXNlLCB0cmFuc2Zvcm0gMC4xMnMgZWFzZTsKICAgIHotaW5kZXg6IDIwOwogIH0KICAuY3VzdG9tLXRvb2x0aXA6OmFmdGVyIHsKICAgIGNvbnRlbnQ6ICIiOwogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxMDAlOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYm9yZGVyOiA2cHggc29saWQgdHJhbnNwYXJlbnQ7CiAgICBib3JkZXItdG9wLWNvbG9yOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KICAuY3VzdG9tLXRvb2x0aXAudmlzaWJsZSB7CiAgICBvcGFjaXR5OiAxOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoMCk7CiAgICBwb2ludGVyLWV2ZW50czogYXV0bzsKICB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLndlZWstc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAtMC40cmVtIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQoKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxLjFyZW07CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudC1kaW0pOwogIH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gcCB7IG1hcmdpbjogMCAwIDAuN3JlbTsgZm9udC1zaXplOiAwLjg4cmVtOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBzZWxlY3QsCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idG4tcHJpbWFyeS1zbSwgLmJ0bi1zZWNvbmRhcnktc20gewogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuOHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KICAuYnRuLXNlY29uZGFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1yZWN1cnJpbmctYmFkZ2UgeyBmb250LXNpemU6IDAuNzVyZW07IG9wYWNpdHk6IDAuNzsgY3Vyc29yOiBoZWxwOyB9CiAgLnR4LXJlY2VpcHQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjc1cmVtOwogICAgb3BhY2l0eTogMC44NTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBwYWRkaW5nOiAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CgogIC8qIFPDqWxlY3RldXIgZHUgdGFibGVhdSBkZSBib3JkIDogdW4gc2V1bCBncmFwaGlxdWUvYmxvYyBhZmZpY2jDqSDDoCBsYSBmb2lzCiAgICAgKGF1IGxpZXUgZGVzIDcgZW1waWzDqXMpLCBjaG9pc2kgdmlhIHVuZSByYW5nw6llIGRlIHB1Y2VzIGTDqWZpbGFudGUuICovCiAgLmRhc2hib2FyZC1jaGlwLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjVyZW07CiAgICBvdmVyZmxvdy14OiBhdXRvOwogICAgcGFkZGluZy1ib3R0b206IDAuMjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogICAgLXdlYmtpdC1vdmVyZmxvdy1zY3JvbGxpbmc6IHRvdWNoOwogIH0KICAuZGFzaGJvYXJkLWNoaXAtcm93Ojotd2Via2l0LXNjcm9sbGJhciB7IGhlaWdodDogNHB4OyB9CiAgLmRhc2hib2FyZC1jaGlwIHsKICAgIGZsZXg6IG5vbmU7CiAgICBwYWRkaW5nOiAwLjVyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5kYXNoYm9hcmQtY2hpcC5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIC5kYXNoYm9hcmQtcm93LmRhc2gtaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQoKICAueWVhcmx5LXN1bW1hcnkgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogIH0KICAueWVhcmx5LXN0YXQgewogICAgZmxleDogMTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuN3JlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjJyZW07CiAgfQogIC55ZWFybHktc3RhdC1sYWJlbCB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC55ZWFybHktc3RhdC12YWx1ZSB7IGZvbnQtc2l6ZTogMS4wNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC55ZWFybHktc3RhdC12YWx1ZS5leHBlbnNlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnVwY29taW5nLW5vdGUgewogICAgd2lkdGg6IDk2cHg7CiAgICBmbGV4LXNocmluazogMDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC40cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjI1OwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CiAgLnVwY29taW5nLW5vdGUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1zd2F0Y2ggewogICAgd2lkdGg6IDI4cHg7CiAgICBoZWlnaHQ6IDE0cHg7CiAgICBib3JkZXI6IDEuNXB4IGRhc2hlZCB2YXIoLS1kYW5nZXIpOwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICB9CiAgLnVwY29taW5nLW5vdGUucG9zaXRpdmUgLnVwY29taW5nLXN3YXRjaCB7CiAgICBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOwogICAgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4yKTsKICB9CgogIC5yZWN1cnJpbmctc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjdXJyaW5nLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLmV4cG9ydC1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5leHBvcnQtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KCiAgLmV4cG9ydC1mb3JtYXQtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuNzVyZW07IH0KICAuZXhwb3J0LWZvcm1hdC1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmV4cG9ydC1mb3JtYXQtYnRuLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CgogIC8qIEltcG9ydCBkZSByZWxldsOpIGJhbmNhaXJlICovCiAgLmltcG9ydC1maWxlLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmltcG9ydC1maWxlLXJvdyBpbnB1dFt0eXBlPSJmaWxlIl0geyBmbGV4OiAxOyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5pbXBvcnQtc3VtbWFyeSB7CiAgICBtYXJnaW46IDAuOXJlbSAwOwogICAgcGFkZGluZzogMC43cmVtIDAuOXJlbTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICB9CiAgLmltcG9ydC1zdW1tYXJ5IHN0cm9uZyB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pbXBvcnQtcHJldmlldyB7IG1hcmdpbi10b3A6IDAuNzVyZW07IH0KICAuaW1wb3J0LXByZXZpZXcuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5pbXBvcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjZyZW07CiAgICBwYWRkaW5nOiAwLjZyZW0gMDsKICAgIGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIH0KICAuaW1wb3J0LXJvdy5leGNsdWRlZCB7IG9wYWNpdHk6IDAuNDU7IH0KICAuaW1wb3J0LXJvdy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLmltcG9ydC1yb3ctZGVzYyB7IGZvbnQtc2l6ZTogMC44OHJlbTsgZm9udC13ZWlnaHQ6IDUwMDsgfQogIC5pbXBvcnQtcm93LWRlc2MgLmltcG9ydC1yb3ctYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5pbXBvcnQtcm93LWRlc2MgLmltcG9ydC1yb3ctYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5pbXBvcnQtcm93LW1ldGEgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbi10b3A6IDAuMXJlbTsgfQogIC5pbXBvcnQtcm93LWR1cCB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmltcG9ydC1yb3cgc2VsZWN0IHsgZm9udC1zaXplOiAwLjhyZW07IG1heC13aWR0aDogMTMwcHg7IH0KICAuaW1wb3J0LWFjdGlvbnMtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgbWFyZ2luOiAwLjc1cmVtIDA7CiAgICBmb250LXNpemU6IDAuODJyZW07CiAgfQogIC5pbXBvcnQtYWN0aW9ucy1yb3cgYnV0dG9uIHsgYmFja2dyb3VuZDogbm9uZTsgYm9yZGVyOiBub25lOyBjb2xvcjogdmFyKC0tYWNjZW50KTsgY3Vyc29yOiBwb2ludGVyOyBmb250LXNpemU6IDAuODJyZW07IHBhZGRpbmc6IDA7IH0KCiAgLyogU2ltdWxhdGlvbiBkZSBwbGFjZW1lbnQgKMOpcGFyZ25lKSAqLwogIC5wbGFjZW1lbnQtaW5wdXRzIHsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyBnYXA6IDAuNzVyZW07IG1hcmdpbi1ib3R0b206IDFyZW07IH0KICAucGxhY2VtZW50LWlucHV0cyBsYWJlbCB7IGZvbnQtc2l6ZTogMC43OHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuMjVyZW07IH0KICAucGxhY2VtZW50LXJlc3VsdCB7CiAgICBtYXJnaW4tdG9wOiAwLjlyZW07CiAgICBwYWRkaW5nOiAwLjhyZW0gMC45cmVtOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODhyZW07CiAgfQogIC5wbGFjZW1lbnQtcmVzdWx0IHN0cm9uZyB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zYXZpbmdzLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KCiAgLmJ1ZGdldHMtc2F2ZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5zYXZpbmdzLWdvYWwtcm93IGlucHV0IHsgZmxleDogMTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1hcmdpbjogMC44cmVtIDAgMC4zNXJlbTsKICB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5hZHZpY2UtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuYWR2aWNlLWNhcmQgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjg1cmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBsaW5lLWhlaWdodDogMS40OwogIH0KICAuYWR2aWNlLWNhcmQgLmFkdmljZS1pY29uIHsgZm9udC1zaXplOiAxLjFyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmFkdmljZS1jYXJkLnBvc2l0aXZlIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1zdWNjZXNzKTsgfQogIC5hZHZpY2UtY2FyZC53YXJuaW5nIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCAjZjU5ZTBiOyB9CiAgLmFkdmljZS1jYXJkLmluZm8geyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CgogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOHJlbSAxcmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbC5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoNCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgZm9udC1zaXplOiAwLjlyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGJhc2VsaW5lOwogICAgcGFkZGluZzogMC4zNXJlbSAwOwogICAgZm9udC1zaXplOiAwLjg4cmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyArIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAubmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5kdWUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuNzhyZW07IG1hcmdpbi1sZWZ0OiAwLjRyZW07IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC5jb21wYXJlLXNlbGVjdHMgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzZWxlY3QgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjQ1cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzcGFuIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CgogIC5zaW1wbGUtdGFibGUgeyB3aWR0aDogMTAwJTsgYm9yZGVyLWNvbGxhcHNlOiBjb2xsYXBzZTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CiAgLnNpbXBsZS10YWJsZSB0aCwgLnNpbXBsZS10YWJsZSB0ZCB7IHBhZGRpbmc6IDAuNXJlbSAwLjZyZW07IHRleHQtYWxpZ246IHJpZ2h0OyB9CiAgLnNpbXBsZS10YWJsZSB0aDpmaXJzdC1jaGlsZCwgLnNpbXBsZS10YWJsZSB0ZDpmaXJzdC1jaGlsZCB7IHRleHQtYWxpZ246IGxlZnQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoZWFkIHRoIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC13ZWlnaHQ6IDUwMDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyICsgdHIgdGQgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIudG90YWwtcm93IHRkIHsgZm9udC13ZWlnaHQ6IDYwMDsgYm9yZGVyLXRvcDogMnB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLXBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLXVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtZG93biB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50cmVuZC1mbGF0IHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQoKICAuYnVkZ2V0LXJvdyB7IG1hcmdpbi1ib3R0b206IDAuOXJlbTsgfQogIC5idWRnZXQtcm93LWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuMzVyZW07CiAgfQogIC5idWRnZXQtY2F0LW5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWFtb3VudHMgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuM3JlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtaW5wdXQgewogICAgd2lkdGg6IDY0cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDZweDsKICAgIHBhZGRpbmc6IDAuMjVyZW0gMC40cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnVkZ2V0LWJhci10cmFjayB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBoZWlnaHQ6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogIC5idWRnZXQtYmFyLWZpbGwgeyBoZWlnaHQ6IDEwMCU7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyB0cmFuc2l0aW9uOiB3aWR0aCAwLjJzIGVhc2U7IH0KICAuYnVkZ2V0LWJhci1maWxsLm9rIHsgYmFja2dyb3VuZDogdmFyKC0tc3VjY2Vzcyk7IH0KICAuYnVkZ2V0LWJhci1maWxsLndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5idWRnZXQtaGlzdG9yeS1zdHJpcCB7IGRpc3BsYXk6IGZsZXg7IGdhcDogNHB4OyBtYXJnaW4tdG9wOiAwLjRyZW07IH0KICAuaGlzdG9yeS1kb3QgewogICAgZmxleDogMTsKICAgIGhlaWdodDogNnB4OwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuaGlzdG9yeS1kb3Qub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5oaXN0b3J5LWRvdC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5oaXN0b3J5LWRvdC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5oaXN0b3J5LWRvdC5lbXB0eSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IG9wYWNpdHk6IDAuNTsgfQogIC5yZWMtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjZyZW07CiAgfQogIC5yZWMtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnN0YXJ0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjE1KTsKICAgIGNvbG9yOiAjOTNjNWZkOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnJlYy1hbW91bnQgeyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IDEuMDVyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5mYWItbWljIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiA1LjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS41cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoMCwgMCwgMCwgMC4zKTsKICAgIHRyYW5zaXRpb246IGJhY2tncm91bmQgMC4ycywgYm9yZGVyLWNvbG9yIDAuMnM7CiAgfQogIC5mYWItbWljOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KICAuZmFiLW1pYy5saXN0ZW5pbmcgewogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsKICAgIGFuaW1hdGlvbjogcHVsc2UgMS4ycyBpbmZpbml0ZTsKICB9CiAgLmZhYi1taWMucHJvY2Vzc2luZyB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmZhYi1taWM6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjM1OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgQGtleWZyYW1lcyBwdWxzZSB7CiAgICAwJSwgMTAwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDAgcmdiYSgyMzksIDY4LCA2OCwgMC40KTsgfQogICAgNTAlIHsgYm94LXNoYWRvdzogMCAwIDAgMTBweCByZ2JhKDIzOSwgNjgsIDY4LCAwKTsgfQogIH0KCiAgLnZvaWNlLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNTsKICB9CiAgLnZvaWNlLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnZvaWNlLWJhbm5lci5hbnN3ZXIgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtd2VpZ2h0OiA2MDA7IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KCiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGJvdHRvbTogOS41cmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1hY2NlbnQsICM0YTdkZmYpOwogICAgYm9yZGVyLXJhZGl1czogMTJweDsKICAgIHBhZGRpbmc6IDAuNzVyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTY7CiAgfQogIC52b2ljZS1jb25maXJtLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyIHAgeyBtYXJnaW46IDAgMCAwLjZyZW07IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KICAudm9pY2UtY29uZmlybS1iYW5uZXIgLnZvaWNlLWNvbmZpcm0taGludCB7IGZvbnQtc2l6ZTogMC43OHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgLnZvaWNlLWNvbmZpcm0tY29udHJvbHMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsganVzdGlmeS1jb250ZW50OiBjZW50ZXI7IH0KCiAgLm1vZGFsLW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LWVuZDsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTA7CiAgfQogIC5tb2RhbC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAjaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5tb2RhbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlci1yYWRpdXM6IDE4cHggMThweCAwIDA7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSBjYWxjKDEuNXJlbSArIGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKSk7CiAgICB3aWR0aDogMTAwJTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC45cmVtOwogIH0KICAubW9kYWwgaDIgeyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXNpemU6IDEuMXJlbTsgfQoKICBsYWJlbCB7IGZvbnQtc2l6ZTogMC44cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4zcmVtOyB9CiAgaW5wdXQsIHNlbGVjdCB7CiAgICB3aWR0aDogMTAwJTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNjVyZW0gMC43NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgaW5wdXQ6Zm9jdXMsIHNlbGVjdDpmb2N1cyB7IG91dGxpbmU6IG5vbmU7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQoKICAudHlwZS10b2dnbGUgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgfQogIC50eXBlLWJ0biB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC42NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iZXhwZW5zZSJdIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iaW5jb21lIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5jb25maXJtLW1vZGFsIHsgbWF4LXdpZHRoOiA0MDBweDsgfQogIC5jb25maXJtLW1vZGFsLW1lc3NhZ2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtc2l6ZTogMC45NXJlbTsgbWFyZ2luOiAwOyBsaW5lLWhlaWdodDogMS40OyB9CgogIC5oaWRkZW4tZmlsZS1pbnB1dCB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjZWlwdC1wcmV2aWV3LXdyYXAgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuNXJlbTsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OwogICAgbWFyZ2luLWJvdHRvbTogMC41cmVtOwogIH0KICAucmVjZWlwdC1wcmV2aWV3LWltZyB7CiAgICBtYXgtd2lkdGg6IDEwMCU7CiAgICBtYXgtaGVpZ2h0OiAxNjBweDsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgb2JqZWN0LWZpdDogY29udGFpbjsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgfQoKICAubGlnaHRib3gtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC44NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMjA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5saWdodGJveC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubGlnaHRib3gtaW1nIHsgbWF4LXdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiA4MHZoOyBib3JkZXItcmFkaXVzOiAxMHB4OyB9CiAgLmxpZ2h0Ym94LWNsb3NlIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMXJlbTsKICAgIHJpZ2h0OiAxcmVtOwogICAgd2lkdGg6IDQwcHg7CiAgICBoZWlnaHQ6IDQwcHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjFyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5LCBidXR0b24uc2Vjb25kYXJ5IHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjc1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogbm9uZTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CiAgYnV0dG9uLnByaW1hcnk6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KICBidXR0b24uc2Vjb25kYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgYnV0dG9uLmRhbmdlciB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tZGFuZ2VyKTsgfQogIGJ1dHRvbi5kYW5nZXI6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KCiAgLmRhbmdlci16b25lIHsKICAgIGJvcmRlci1jb2xvcjogcmdiYSgyMzksIDY4LCA2OCwgMC4zNSkgIWltcG9ydGFudDsKICB9CiAgLmRhbmdlci16b25lIGgzIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KCiAgLmxvY2stc2NyZWVuIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwMDsKICAgIHBhZGRpbmc6IDEuNXJlbTsKICB9CiAgLmxvY2stc2NyZWVuLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubG9jay1jYXJkIHsgbWF4LXdpZHRoOiAzMjBweDsgd2lkdGg6IDEwMCU7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogIC5sb2NrLWVtb2ppIHsgZm9udC1zaXplOiAzcmVtOyBtYXJnaW4tYm90dG9tOiAwLjVyZW07IH0KICAubG9jay1jYXJkIGgxIHsgbWFyZ2luOiAwIDAgMC41cmVtOyB9CiAgLmxvY2stY2FyZCBwIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luOiAwIDAgMS4yNXJlbTsgZm9udC1zaXplOiAwLjlyZW07IH0KICAubG9jay1jYXJkIGlucHV0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgbWFyZ2luLWJvdHRvbTogMC43NXJlbTsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjlyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICAubG9jay1lcnJvciB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyBmb250LXNpemU6IDAuODVyZW07IG1hcmdpbi10b3A6IDAuNzVyZW07IH0KICAubG9jay1lcnJvci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGRpdiBjbGFzcz0ibG9jay1zY3JlZW4gaGlkZGVuIiBpZD0ibG9jay1zY3JlZW4iPgogICAgPGRpdiBjbGFzcz0ibG9jay1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibG9jay1lbW9qaSI+8J+SsDwvZGl2PgogICAgICA8aDE+S2FjaGluZzwvaDE+CiAgICAgIDxwPkVudHJlIGxlIG1vdCBkZSBwYXNzZSBwb3VyIGFjY8OpZGVyIMOgIHRlcyBkb25uw6llcy48L3A+CiAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9ImxvY2stcGFzc3dvcmQtaW5wdXQiIHBsYWNlaG9sZGVyPSJNb3QgZGUgcGFzc2UiIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCI+CiAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9ImxvY2stdW5sb2NrLWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Ew6l2ZXJyb3VpbGxlcjwvYnV0dG9uPgogICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJsb2NrLWVycm9yIj48L3A+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBpZD0iYXBwLXJvb3QiIGhpZGRlbj4KICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Im1lbnUtdG9nZ2xlLWJ0biIgaWQ9Im1lbnUtdG9nZ2xlLWJ0biIgYXJpYS1sYWJlbD0iT3V2cmlyIGxlIG1lbnUiPuKYsDwvYnV0dG9uPgogIDxkaXYgY2xhc3M9Im5hdi1kcmF3ZXItYmFja2Ryb3AiIGlkPSJuYXYtZHJhd2VyLWJhY2tkcm9wIj48L2Rpdj4KICA8aGVhZGVyPgogICAgPGgxPvCfkrAgS2FjaGluZzwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgZXQgcmV2ZW51cywgYWpvdXTDqXMgb3Ugw6lkaXTDqXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4gYWN0aXZlIiBpZD0idGFiLWhpc3RvcnkiIGRhdGEtdmlldz0iaGlzdG9yeSI+SGlzdG9yaXF1ZTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWRhc2hib2FyZCIgZGF0YS12aWV3PSJkYXNoYm9hcmQiPlRhYmxlYXUgZGUgYm9yZDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXJlY3VycmluZyIgZGF0YS12aWV3PSJyZWN1cnJpbmciPlLDqWN1cnJlbnRlczwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWV4cG9ydCIgZGF0YS12aWV3PSJleHBvcnQiPkV4cG9ydDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXNhdmluZ3MiIGRhdGEtdmlldz0ic2F2aW5ncyI+w4lwYXJnbmU8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQgdG9vbHRpcC1ob3N0IiBpZD0ic3VtbWFyeS11cGNvbWluZy1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj7DgCB2ZW5pciBjZSBtb2lzLWNpPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LXVwY29taW5nIj7igJQ8L3A+CiAgICAgIDxkaXYgY2xhc3M9ImN1c3RvbS10b29sdGlwIiBpZD0ic3VtbWFyeS11cGNvbWluZy10b29sdGlwIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8cCBjbGFzcz0id2Vlay1zdW1tYXJ5IiBpZD0id2Vlay1zdW1tYXJ5Ij48L3A+CgogIDxkaXYgaWQ9ImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIiBjbGFzcz0iY2F0ZWdvcnktc3VnZ2VzdGlvbiBoaWRkZW4iPjwvZGl2PgoKICA8bWFpbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpc3RvcnkiPgogICAgICA8ZGl2IGNsYXNzPSJmaWx0ZXItYmFyIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImZpbHRlci1zZWFyY2giIHBsYWNlaG9sZGVyPSJSZWNoZXJjaGVyLi4uIj4KICAgICAgICA8c2VsZWN0IGlkPSJmaWx0ZXItY2F0ZWdvcnkiPjxvcHRpb24gdmFsdWU9IiI+VG91dGVzIGNhdMOpZ29yaWVzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmaWx0ZXItZGF0ZS1zdGFydCIgYXJpYS1sYWJlbD0iRHUiPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtZW5kIiBhcmlhLWxhYmVsPSJBdSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGlkPSJ0eC1saXN0IiBjbGFzcz0idHgtbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1kYXNoYm9hcmQiIGNsYXNzPSJkYXNoYm9hcmQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1jaGlwLXJvdyIgaWQ9ImRhc2hib2FyZC1jaGlwLXJvdyI+PC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0iZGFzaC1yb3ctZXhwZW5zZXMiPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIGTDqXBlbnNlcyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXRlZ29yeS1jaGFydC1yb3ciPgogICAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIgY2xhc3M9InVwY29taW5nLW5vdGUgaGlkZGVuIj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InVwY29taW5nLXN3YXRjaCI+PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLXRleHQiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1bmUgZMOpcGVuc2UgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWluY29tZSI+CiAgICAgICAgPGgzPlLDqXBhcnRpdGlvbiBkZXMgcmV2ZW51cyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1biByZXZlbnUgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWJ1ZGdldHMiPgogICAgICAgIDxoMz5CdWRnZXRzIG1lbnN1ZWxzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgSW5kaXF1ZSB1biBtb250YW50IHBvdXIgdW5lIGNhdMOpZ29yaWUgZXQgZW5yZWdpc3RyZSBhdmVjIPCfkr4g4oCUIGxhIGJhcnJlCiAgICAgICAgICBjb21wYXJlIGVuc3VpdGUgdGVzIGTDqXBlbnNlcyBkdSBtb2lzIGVuIGNvdXJzIMOgIGNlIHBsYWZvbmQgKHZlcnQsCiAgICAgICAgICBvcmFuZ2UgYXUtZGVsw6AgZGUgNzAlLCByb3VnZSBhdS1kZWzDoCBkZSAxMDAlKS4gTGEgcGV0aXRlIHJhbmfDqWUgZGUKICAgICAgICAgIGJhcnJlcyBlbiBkZXNzb3VzIG1vbnRyZSBsJ2hpc3RvcmlxdWUgZGVzIDYgZGVybmllcnMgbW9pcyAoc3Vydm9sZQogICAgICAgICAgb3UgdG91Y2hlIHVuZSBiYXJyZSBwb3VyIHZvaXIgbGUgZMOpdGFpbCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9ImJ1ZGdldHMtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0cy1zYXZlLXJvdyI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9ImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIiBhcmlhLWxhYmVsPSJFbnJlZ2lzdHJlciB0b3VzIGxlcyBidWRnZXRzIj7wn5K+PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWV2b2x1dGlvbiI+CiAgICAgICAgPGgzPsOJdm9sdXRpb24gbWVuc3VlbGxlIChkw6lwZW5zZXMgdnMgcmV2ZW51cyk8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtZXZvbHV0aW9uIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1jb21wYXJlIj4KICAgICAgICA8aDM+Q29tcGFyZXIgZGV1eCBtb2lzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjb21wYXJlLXNlbGVjdHMiPgogICAgICAgICAgPHNlbGVjdCBpZD0iY29tcGFyZS1tb250aC1hIj48L3NlbGVjdD4KICAgICAgICAgIDxzcGFuPnZzPC9zcGFuPgogICAgICAgICAgPHNlbGVjdCBpZD0iY29tcGFyZS1tb250aC1iIj48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImNvbXBhcmUtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBhc3NleiBkZSBtb2lzIGRpZmbDqXJlbnRzIHBvdXIgY29tcGFyZXIuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LXRyZW5kIj4KICAgICAgICA8aDM+TW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LXllYXJseSI+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLWhlYWQiPgogICAgICAgICAgPGgzPkJpbGFuIGFubnVlbDwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJ5ZWFybHkteWVhci1zZWxlY3QiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdW1tYXJ5Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5Ew6lwZW5zZXM8L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJ5ZWFybHktdG90YWwtZXhwZW5zZXMiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBleHBlbnNlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5SZXZlbnVzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWluY29tZSIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIGluY29tZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+U29sZGUgbmV0PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LW5ldCIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXllYXJseSI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZGUgZG9ubsOpZXMgcG91ciBjZXR0ZSBhbm7DqWUuCiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWNhdGVnb3J5LXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1yZWN1cnJpbmciIGNsYXNzPSJyZWN1cnJpbmctc2VjdGlvbiI+CiAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgQ2hhcmdlcyBmaXhlcyAoYWJvbm5lbWVudHMsIGxveWVyLCBzYWxhaXJl4oCmKSBjb21wdMOpZXMgYXV0b21hdGlxdWVtZW50CiAgICAgICAgY2hhcXVlIG1vaXMgZGFucyBsZSB0YWJsZWF1IGRlIGJvcmQg4oCUIHBhcyBiZXNvaW4gZGUgbGVzIHJlZGljdGVyLgogICAgICAgIE1ldHMgdW5lIGRhdGUgZGUgZMOpYnV0IHNpIHVuZSBjaGFyZ2UgbmUgZG9pdCBkw6ltYXJyZXIgcXVlIHBsdXMgdGFyZCwKICAgICAgICB1bmUgZGF0ZSBkZSBmaW4gc2kgZWxsZSBkb2l0IHMnYXJyw6p0ZXIgdW4gam91ci4KICAgICAgPC9wPgogICAgICA8ZGl2IGlkPSJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwiIGNsYXNzPSJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgaGlkZGVuIj4KICAgICAgICA8aDQ+UHJvY2hhaW5lcyDDqWNow6lhbmNlczwvaDQ+CiAgICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLWxpc3QiPjwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBBdWN1bmUgZMOpcGVuc2UgcsOpY3VycmVudGUgcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgKyBwb3VyIGVuIGFqb3V0ZXIgdW5lLgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1leHBvcnQiIGNsYXNzPSJleHBvcnQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5FeHBvcnRlciB0ZXMgZG9ubsOpZXM8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImV4cG9ydC1mb3JtYXQtdG9nZ2xlIiBpZD0iZXhwb3J0LWZvcm1hdC10b2dnbGUiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJleHBvcnQtZm9ybWF0LWJ0biBhY3RpdmUiIGRhdGEtZm9ybWF0PSJ4bHN4Ij5FeGNlbCAoLnhsc3gpPC9idXR0b24+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImV4cG9ydC1mb3JtYXQtYnRuIiBkYXRhLWZvcm1hdD0ianNvbiI+U2F1dmVnYXJkZSBjb21wbMOodGUgKEpTT04pPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50IiBpZD0iZXhwb3J0LWZvcm1hdC1oaW50Ij4KICAgICAgICAgIFRvdXRlcyB0ZXMgdHJhbnNhY3Rpb25zIChkw6lwZW5zZXMgZXQgcmV2ZW51cykgZXQgdGVzIGNoYXJnZXMKICAgICAgICAgIHLDqWN1cnJlbnRlcywgY2hhY3VuZSBkYW5zIHNvbiBwcm9wcmUgb25nbGV0LgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLWV4cG9ydC1kb3dubG9hZCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Uw6lsw6ljaGFyZ2VyPC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkltcG9ydGVyIHVuIHJlbGV2w6kgYmFuY2FpcmU8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBQb3VyIGwnaW5zdGFudCwgdW5pcXVlbWVudCBsJ2V4cG9ydCBDU1YgwqsgZXhwb3J0LW9wZXJhdGlvbnMuLi4gwrsgZGUKICAgICAgICAgIEJvdXJzb0JhbmsuIExlcyBtb250YW50cywgZGF0ZXMgZXQgZGVzY3JpcHRpb25zIHNvbnQgYW5hbHlzw6lzIGljaQogICAgICAgICAgbcOqbWUgKHJpZW4gbidlc3QgZW52b3nDqSBhaWxsZXVycykgOyB0dSBjaG9pc2lzIGVuc3VpdGUgbGlnbmUgcGFyCiAgICAgICAgICBsaWduZSBxdW9pIGltcG9ydGVyIGF2YW50IHRvdXRlIMOpY3JpdHVyZSBlbiBiYXNlLiBMZSBudW3DqXJvIGRlCiAgICAgICAgICBjb21wdGUgbidlc3QgamFtYWlzIGx1LgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJpbXBvcnQtZmlsZS1yb3ciPgogICAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbXBvcnQtZmlsZS1pbnB1dCIgYWNjZXB0PSIuY3N2LHRleHQvY3N2Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJpbXBvcnQtYW5hbHl6ZS1idG4iPkFuYWx5c2VyPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXN1bW1hcnkiIGNsYXNzPSJpbXBvcnQtc3VtbWFyeSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImltcG9ydC1wcmV2aWV3IiBjbGFzcz0iaW1wb3J0LXByZXZpZXcgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1hY3Rpb25zLXJvdyI+CiAgICAgICAgICAgIDxzcGFuIGlkPSJpbXBvcnQtc2VsZWN0ZWQtY291bnQiPjwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJpbXBvcnQtdG9nZ2xlLWFsbC1idG4iPlRvdXQgY29jaGVyIC8gZMOpY29jaGVyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgaWQ9ImltcG9ydC1yb3dzLWxpc3QiPjwvZGl2PgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImltcG9ydC1jb21taXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsgbWFyZ2luLXRvcDowLjc1cmVtOyI+SW1wb3J0ZXIgbGEgc8OpbGVjdGlvbjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJwd2EtaW5zdGFsbC1yb3ciIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICA8aDM+SW5zdGFsbGVyIGwnYXBwbGljYXRpb248L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBBam91dGUgbCdhcHAgc3VyIHRvbiDDqWNyYW4gZCdhY2N1ZWlsICh0w6lsw6lwaG9uZSwgdGFibGV0dGUgb3UKICAgICAgICAgIG9yZGluYXRldXIpIHBvdXIgbCdvdXZyaXIgZW4gdW4gZ2VzdGUsIGNvbW1lIHVuZSBhcHAgbmF0aXZlLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icHdhLWluc3RhbGwtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPvCfk7IgSW5zdGFsbGVyIGwnYXBwbGljYXRpb248L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0icHdhLWlvcy1oaW50LXJvdyIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIDxoMz5JbnN0YWxsZXIgbCdhcHBsaWNhdGlvbjwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFN1ciBpUGhvbmUvaVBhZCA6IGFwcHVpZSBzdXIgbCdpY8O0bmUgUGFydGFnZXIgZGUgU2FmYXJpLCBwdWlzCiAgICAgICAgICDCqyBTdXIgbCfDqWNyYW4gZCdhY2N1ZWlsIMK7LgogICAgICAgIDwvcD4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IGRhbmdlci16b25lIj4KICAgICAgICA8aDM+4pqg77iPIFpvbmUgZGFuZ2VyZXVzZTwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFN1cHByaW1lIGTDqWZpbml0aXZlbWVudCBUT1VURVMgbGVzIGRvbm7DqWVzIDogdHJhbnNhY3Rpb25zLCBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvbm5hbGlzw6llcywgc3VnZ2VzdGlvbnMgaWdub3LDqWVzLAogICAgICAgICAgYnVkZ2V0cywgcGhvdG9zIGRlIHJlw6d1cyBldCBvYmplY3RpZiBkJ8OpcGFyZ25lLiBQZW5zZSDDoCBleHBvcnRlciBlbgogICAgICAgICAgRXhjZWwgYXZhbnQgc2kgYmVzb2luIOKAlCBpbXBvc3NpYmxlIMOgIGFubnVsZXIuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9ImRhbmdlciIgaWQ9ImJ0bi1yZXNldC1hbGwiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+UsOpaW5pdGlhbGlzZXIgdG91dGUgbCdhcHBsaWNhdGlvbjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1zYXZpbmdzIiBjbGFzcz0ic2F2aW5ncy1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPk9iamVjdGlmIGQnw6lwYXJnbmUgbWVuc3VlbDwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIExlIG1vbnRhbnQgcXVlIHR1IHZldXggZ2FyZGVyIGRlIGPDtHTDqSBjaGFxdWUgbW9pcyAocmV2ZW51cyBtb2lucwogICAgICAgICAgZMOpcGVuc2VzKS4gQ29tcGFyw6kgw6AgdG9uIHNvbGRlIHLDqWVsIGR1IG1vaXMgZW4gY291cnMuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9InNhdmluZ3MtZ29hbC1yb3ciPgogICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InNhdmluZ3MtZ29hbC1pbnB1dCIgbWluPSIwIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iRXggOiAxMDAiPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iaWNvbi1idG4iIGlkPSJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iIGFyaWEtbGFiZWw9IkVucmVnaXN0cmVyIGwnb2JqZWN0aWYiPvCfkr48L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iIGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzIGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzLWxhYmVsIj4KICAgICAgICAgICAgPHNwYW4+U29sZGUgZHUgbW9pcyBlbiBjb3Vyczwvc3Bhbj4KICAgICAgICAgICAgPHN0cm9uZyBpZD0ic2F2aW5ncy1wcm9ncmVzcy10ZXh0Ij48L3N0cm9uZz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0LWJhci10cmFjayI+CiAgICAgICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3MtYmFyIiBjbGFzcz0iYnVkZ2V0LWJhci1maWxsIG9rIj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Db25zZWlsczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEJhc8OpcyBzdXIgdGVzIGJ1ZGdldHMgcGFyIGNhdMOpZ29yaWUgZXQgdGVzIHRlbmRhbmNlcyBkZSBkw6lwZW5zZXMKICAgICAgICAgICh2b2lyIGwnb25nbGV0IFRhYmxlYXUgZGUgYm9yZCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtYWR2aWNlLWxpc3QiIGNsYXNzPSJhZHZpY2UtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMgY2UgbW9pcy1jaSBwb3VyIHRlIGRvbm5lciBkZXMgY29uc2VpbHMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPlNpbXVsYXRpb24gZGUgcGxhY2VtZW50PC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUHJvamVjdGlvbiBzaSB0dSBwbGFjZXMgdW5lIHNvbW1lIHN1ciB1biBsaXZyZXQgb3UgdW4gcGxhY2VtZW50IMOgCiAgICAgICAgICB0YXV4IGZpeGUgKGludMOpcsOqdHMgY29tcG9zw6lzLCBjYWxjdWzDqXMgbWVuc3VlbGxlbWVudCkuIExlIHRhdXggcGFyCiAgICAgICAgICBkw6lmYXV0ICgzJSkgY29ycmVzcG9uZCBhdSBMaXZyZXQgQSDigJQgY2hhbmdlLWxlIHBvdXIgc2ltdWxlciB1bgogICAgICAgICAgYXV0cmUgcGxhY2VtZW50LgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJwbGFjZW1lbnQtaW5wdXRzIj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxsYWJlbCBmb3I9InBsYWNlbWVudC1pbml0aWFsIj5Nb250YW50IGluaXRpYWwgKOKCrCk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LWluaXRpYWwiIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IjUwMCI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxsYWJlbCBmb3I9InBsYWNlbWVudC1tb250aGx5Ij5WZXJzZW1lbnQgbWVuc3VlbCAo4oKsKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQtbW9udGhseSIgbWluPSIwIiBzdGVwPSIxIiB2YWx1ZT0iNTAiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtcmF0ZSI+VGF1eCBhbm51ZWwgKCUpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC1yYXRlIiBtaW49IjAiIHN0ZXA9IjAuMSIgdmFsdWU9IjMiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQteWVhcnMiPkR1csOpZSAoYW5uw6llcyk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LXllYXJzIiBtaW49IjEiIHN0ZXA9IjEiIHZhbHVlPSI1Ij4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtcGxhY2VtZW50Ij48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJwbGFjZW1lbnQtcmVzdWx0IiBpZD0icGxhY2VtZW50LXJlc3VsdCI+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGRpdiBjbGFzcz0idm9pY2UtY29uZmlybS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtY29uZmlybS1iYW5uZXIiPjwvZGl2PgogIDxidXR0b24gY2xhc3M9ImZhYi1taWMiIGlkPSJmYWItbWljIiBhcmlhLWxhYmVsPSJEaWN0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudSwgb3UgcG9zZXIgdW5lIHF1ZXN0aW9uIiB0aXRsZT0iRGljdGUgdW5lIGTDqXBlbnNlL3VuIHJldmVudSwgb3UgcG9zZSB1bmUgcXVlc3Rpb24gKGV4IDogwqsgY29tYmllbiBqJ2FpIGTDqXBlbnPDqSBlbiByZXN0YXVyYW50IGNlIG1vaXMtY2kgPyDCuykiPvCfjqQ8L2J1dHRvbj4KICA8YnV0dG9uIGNsYXNzPSJmYWIiIGlkPSJmYWItYWRkIiBhcmlhLWxhYmVsPSJBam91dGVyIj4rPC9idXR0b24+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0ibW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0ibW9kYWwtdGl0bGUiPk5vdXZlbGxlIHRyYW5zYWN0aW9uPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0idHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJpbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0CiAgICAgICAgICB0eXBlPSJ0ZXh0IgogICAgICAgICAgaWQ9ImlucHV0LW5ldy1jYXRlZ29yeS1uYW1lIgogICAgICAgICAgcGxhY2Vob2xkZXI9Ik5vbSBkZSBsYSBub3V2ZWxsZSBjYXTDqWdvcmllIgogICAgICAgICAgY2xhc3M9ImhpZGRlbiIKICAgICAgICAgIHN0eWxlPSJtYXJnaW4tdG9wOiA4cHg7IgogICAgICAgID4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGVzY3JpcHRpb24iPkRlc2NyaXB0aW9uIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImlucHV0LWRlc2NyaXB0aW9uIiBwbGFjZWhvbGRlcj0iRXggOiBkw6lqZXVuZXIgYXZlYyBQYXVsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGF0ZSI+RGF0ZTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJpbnB1dC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsPlJlw6d1IChwaG90bywgb3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbnB1dC1yZWNlaXB0LWZpbGUiIGNsYXNzPSJoaWRkZW4tZmlsZS1pbnB1dCIgYWNjZXB0PSJpbWFnZS8qIiBjYXB0dXJlPSJlbnZpcm9ubWVudCI+CiAgICAgICAgPGRpdiBpZD0icmVjZWlwdC1wcmV2aWV3LXdyYXAiIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctd3JhcCBoaWRkZW4iPgogICAgICAgICAgPGltZyBpZD0icmVjZWlwdC1wcmV2aWV3LWltZyIgY2xhc3M9InJlY2VpcHQtcHJldmlldy1pbWciIGFsdD0iUmXDp3UiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tcmVjZWlwdC1yZW1vdmUiPlN1cHByaW1lciBsYSBwaG90bzwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcGljayIgc3R5bGU9IndpZHRoOjEwMCU7Ij7wn5O3IEFqb3V0ZXIgdW5lIHBob3RvIGRlIHJlw6d1PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9InJlYy1tb2RhbC10aXRsZSI+Tm91dmVsbGUgZMOpcGVuc2UgcsOpY3VycmVudGU8L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJyZWMtdHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1uYW1lIj5Ob208L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0icmVjLWlucHV0LW5hbWUiIHBsYWNlaG9sZGVyPSJFeCA6IE5ldGZsaXgsIExveWVyLCBTYWxhaXJlLi4uIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InJlYy1pbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1kYXkiPkpvdXIgZHUgbW9pczwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1kYXkiIG1pbj0iMSIgbWF4PSIzMSIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IjEgw6AgMzEiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+RGF0ZSBkZSBkw6lidXQgKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZW5kLWRhdGUiPkRhdGUgZGUgZmluIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1lbmQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJyZWMtYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJyZWMtYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJjb25maXJtLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwgY29uZmlybS1tb2RhbCI+CiAgICAgIDxoMiBpZD0iY29uZmlybS1tb2RhbC10aXRsZSI+Q29uZmlybWVyPC9oMj4KICAgICAgPHAgaWQ9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSIgY2xhc3M9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSI+PC9wPgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJjb25maXJtLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iY29uZmlybS1idG4tb2siPkNvbmZpcm1lcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJsaWdodGJveC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImxpZ2h0Ym94LWNsb3NlIiBpZD0icmVjZWlwdC1saWdodGJveC1jbG9zZSIgYXJpYS1sYWJlbD0iRmVybWVyIj7inJU8L2J1dHRvbj4KICAgIDxpbWcgY2xhc3M9ImxpZ2h0Ym94LWltZyIgaWQ9InJlY2VpcHQtbGlnaHRib3gtaW1nIiBhbHQ9IlJlw6d1IGVuIHBsZWluIMOpY3JhbiI+CiAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBMZSBqZXRvbiBkZSBzZXNzaW9uIChvYnRlbnUgYXByw6hzIGF2b2lyIHRhcMOpIGxlIG1vdCBkZSBwYXNzZSBzdXIgbCfDqWNyYW4KICAgIC8vIGRlIHZlcnJvdWlsbGFnZSkgcmVtcGxhY2UgbCdhbmNpZW5uZSBjbMOpIEFQSSBjb2TDqWUgZW4gZHVyIGljaSDigJQgY2VsbGUtY2kKICAgIC8vIMOpdGFpdCB2aXNpYmxlIHBhciBuJ2ltcG9ydGUgcXVpIHZpYSAiQWZmaWNoZXIgbGUgY29kZSBzb3VyY2UiLCBzYW5zCiAgICAvLyBhdWN1biBtb3QgZGUgcGFzc2UuIExlIGpldG9uIGVzdCBzaWduw6kgY8O0dMOpIHNlcnZldXIgZXQgZXhwaXJlIGFwcsOocyA5MAogICAgLy8gam91cnMgOyBpbCBuZSByw6l2w6hsZSByaWVuIGRlIHNlY3JldCBlbiBsdWktbcOqbWUuCiAgICBjb25zdCBUT0tFTl9TVE9SQUdFX0tFWSA9ICJrYWNoaW5nX3Nlc3Npb25fdG9rZW4iOwogICAgbGV0IEFQSV9LRVkgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSkgfHwgIiI7CgogICAgY29uc3QgbG9ja1NjcmVlbkVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stc2NyZWVuIik7CiAgICBjb25zdCBhcHBSb290RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXBwLXJvb3QiKTsKICAgIGNvbnN0IGxvY2tQYXNzd29yZElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IGxvY2tVbmxvY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9jay11bmxvY2stYnRuIik7CiAgICBjb25zdCBsb2NrRXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLWVycm9yIik7CgogICAgZnVuY3Rpb24gc2hvd0xvY2tTY3JlZW4oKSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKFRPS0VOX1NUT1JBR0VfS0VZKTsKICAgICAgQVBJX0tFWSA9ICIiOwogICAgICBhcHBSb290RWwuaGlkZGVuID0gdHJ1ZTsKICAgICAgbG9ja1NjcmVlbkVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBsb2NrUGFzc3dvcmRJbnB1dC52YWx1ZSA9ICIiOwogICAgICBsb2NrUGFzc3dvcmRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dBcHAoKSB7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRVbmxvY2soKSB7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gbG9ja1Bhc3N3b3JkSW5wdXQudmFsdWU7CiAgICAgIGlmICghcGFzc3dvcmQpIHJldHVybjsKICAgICAgbG9ja0Vycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGxvY2tVbmxvY2tCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBsb2NrVW5sb2NrQnRuLnRleHRDb250ZW50ID0gIlbDqXJpZmljYXRpb27igKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2xvZ2luIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBoZWFkZXJzOiB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcGFzc3dvcmQgfSksCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8ICJNb3QgZGUgcGFzc2UgaW5jb3JyZWN0Iik7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRPS0VOX1NUT1JBR0VfS0VZLCBkYXRhLnRva2VuKTsKICAgICAgICAvLyBSZWNoYXJnZW1lbnQgY29tcGxldCBwbHV0w7R0IHF1ZSBkZSByw6ktZW5jaGHDrm5lciBsJ2luaXQgbWFudWVsbGVtZW50IDoKICAgICAgICAvLyBwbHVzIHNpbXBsZSBldCBwbHVzIHPDu3IgKG9uIHJlcGFydCBhdmVjIHVuIMOpdGF0IHByb3ByZSwgQVBJX0tFWSBsdQogICAgICAgIC8vIGRlcHVpcyBsZSBsb2NhbFN0b3JhZ2UgY29tbWUgYXUgdG91dCBwcmVtaWVyIGNoYXJnZW1lbnQpLgogICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgbG9ja0Vycm9yRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZSB8fCAiTW90IGRlIHBhc3NlIGluY29ycmVjdCI7CiAgICAgICAgbG9ja0Vycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgbG9ja1VubG9ja0J0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGxvY2tVbmxvY2tCdG4udGV4dENvbnRlbnQgPSAiRMOpdmVycm91aWxsZXIiOwogICAgICB9CiAgICB9CgogICAgbG9ja1VubG9ja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGF0dGVtcHRVbmxvY2spOwogICAgbG9ja1Bhc3N3b3JkSW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigia2V5ZG93biIsIChlKSA9PiB7CiAgICAgIGlmIChlLmtleSA9PT0gIkVudGVyIikgYXR0ZW1wdFVubG9jaygpOwogICAgfSk7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBuZXdDYXRlZ29yeU5hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIpOwogICAgY29uc3QgZGVzY3JpcHRpb25JbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kZXNjcmlwdGlvbiIpOwogICAgY29uc3QgZGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRhdGUiKTsKICAgIGNvbnN0IHNhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXNhdmUiKTsKCiAgICBsZXQgZWRpdGluZ0lkID0gbnVsbDsgLy8gbnVsbCA9IGNyw6lhdGlvbiwgc2lub24gaWQgZGUgbGEgdHJhbnNhY3Rpb24gw6lkaXTDqWUKICAgIGxldCBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IG51bGw7IC8vIGNhdMOpZ29yaWUgZGUgbGEgdHJhbnNhY3Rpb24gYXZhbnQgw6lkaXRpb24gKHBvdXIgZMOpdGVjdGVyIHVuIGNoYW5nZW1lbnQpCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUGhvdG8gZGUgcmXDp3UgZW4gcGnDqGNlIGpvaW50ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjZWlwdEZpbGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1yZWNlaXB0LWZpbGUiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3V3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LXByZXZpZXctd3JhcCIpOwogICAgY29uc3QgcmVjZWlwdFByZXZpZXdJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LWltZyIpOwogICAgY29uc3QgcmVjZWlwdFBpY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcGljayIpOwogICAgY29uc3QgcmVjZWlwdFJlbW92ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVjZWlwdC1yZW1vdmUiKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveE92ZXJsYXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1vdmVybGF5Iik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveENsb3NlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtY2xvc2UiKTsKCiAgICAvLyBGaWNoaWVyIGNob2lzaSBtYWlzIHBhcyBlbmNvcmUgZW52b3nDqSAodW5pcXVlbWVudCBlbiBjcsOpYXRpb24sIHRhbnQgcXVlCiAgICAvLyBsYSB0cmFuc2FjdGlvbiBuJ2EgcGFzIGVuY29yZSBkJ2lkKSA7IGVuIMOpZGl0aW9uLCBsJ2Vudm9pIGVzdCBpbW3DqWRpYXQuCiAgICBsZXQgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgIGxldCByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICBsZXQgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKSB7CiAgICAgIGlmIChyZWNlaXB0UHJldmlld09iamVjdFVybCkgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgIHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gcmVjZWlwdFByZXZpZXdPYmplY3RVcmw7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBSZW1wbGFjZXIgbGEgcGhvdG8iOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlc2V0UmVjZWlwdFVpKCkgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKTsKICAgICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICAgIH0KICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gIiI7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndSI7CiAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHJhbnNhY3Rpb25JZCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3RyYW5zYWN0aW9uSWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHJldHVybjsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGJsb2IpOwogICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAvLyBQYXMgZ3JhdmUgOiBsJ3V0aWxpc2F0ZXVyIHBldXQganVzdGUgcsOpZXNzYXllciBkJ291dnJpciBsYSBmaWNoZS4KICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRQaWNrQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gcmVjZWlwdEZpbGVJbnB1dC5jbGljaygpKTsKCiAgICByZWNlaXB0RmlsZUlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IHJlY2VpcHRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBpZiAoIWZpbGUudHlwZS5zdGFydHNXaXRoKCJpbWFnZS8iKSkgewogICAgICAgIHNob3dUb2FzdCgiQ2hvaXNpcyB1bmUgaW1hZ2UgKEpQRUcsIFBORywgV0VCUCBvdSBIRUlDKSIsIHRydWUpOwogICAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IDggKiAxMDI0ICogMTAyNCkgewogICAgICAgIHNob3dUb2FzdCgiSW1hZ2UgdHJvcCBsb3VyZGUgKDggTW8gbWF4aW11bSkiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGZpbGUpOwoKICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgIC8vIFRyYW5zYWN0aW9uIGTDqWrDoCBleGlzdGFudGUgOiBvbiBlbnZvaWUgdG91dCBkZSBzdWl0ZSwgaW5kw6lwZW5kYW1tZW50CiAgICAgICAgLy8gZHUgYm91dG9uICJFbnJlZ2lzdHJlciIgZHUgZm9ybXVsYWlyZS4KICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIGZpbGUpOwogICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgfSkudGhlbihhc3luYyAocmVzKSA9PiB7CiAgICAgICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8IGBFcnJldXIgSFRUUCAke3Jlcy5zdGF0dXN9YCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gdHJ1ZTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gZHUgcmXDp3UgZW5yZWdpc3Ryw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIC8vIE5vdXZlbGxlIHRyYW5zYWN0aW9uIHBhcyBlbmNvcmUgY3LDqcOpZSA6IG9uIGdhcmRlIGxlIGZpY2hpZXIgZGUgY8O0dMOpLAogICAgICAgIC8vIGlsIHNlcmEgZW52b3nDqSBqdXN0ZSBhcHLDqHMgbGEgY3LDqWF0aW9uICh2b2lyIGJ0bi1zYXZlKS4KICAgICAgICBwZW5kaW5nUmVjZWlwdEZpbGUgPSBmaWxlOwogICAgICB9CiAgICB9KTsKCiAgICByZWNlaXB0UmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBpZiAoZWRpdGluZ0lkICYmIGhhc0V4aXN0aW5nUmVjZWlwdCkgewogICAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgbGEgcGhvdG8gZGUgY2UgcmXDp3UgPyIpKSkgcmV0dXJuOwogICAgICAgIHRyeSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9L3JlY2VpcHRgLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICAgICAgc2hvd1RvYXN0KCJQaG90byBzdXBwcmltw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWNlaXB0TGlnaHRib3godHJhbnNhY3Rpb25JZCkgewogICAgICBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSkKICAgICAgICAudGhlbigocmVzKSA9PiB7CiAgICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCJJbXBvc3NpYmxlIGRlIGNoYXJnZXIgbGEgcGhvdG8iKTsKICAgICAgICAgIHJldHVybiByZXMuYmxvYigpOwogICAgICAgIH0pCiAgICAgICAgLnRoZW4oKGJsb2IpID0+IHsKICAgICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgICByZWNlaXB0TGlnaHRib3hJbWcuc3JjID0gdXJsOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB9KQogICAgICAgIC5jYXRjaCgoZXJyKSA9PiBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlUmVjZWlwdExpZ2h0Ym94KCkgewogICAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAocmVjZWlwdExpZ2h0Ym94SW1nLnNyYykgewogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdExpZ2h0Ym94SW1nLnNyYyk7CiAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9ICIiOwogICAgICB9CiAgICB9CgogICAgcmVjZWlwdExpZ2h0Ym94Q2xvc2VCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY2VpcHRMaWdodGJveCk7CiAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSByZWNlaXB0TGlnaHRib3hPdmVybGF5KSBjbG9zZVJlY2VpcHRMaWdodGJveCgpOwogICAgfSk7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgLy8gQ2F0w6lnb3JpZXMgY3LDqcOpZXMgcGFyIGwndXRpbGlzYXRldXIgZGVwdWlzIGxlIGJhbmRlYXUgZGUgc3VnZ2VzdGlvbgogICAgLy8gKHZvaXIgcGx1cyBiYXMpLCBldCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgOiBzdG9ja8OpZXMgY8O0dMOpIHNlcnZldXIKICAgIC8vICh0YWJsZXMgY3VzdG9tX2NhdGVnb3JpZXMgLyBkaXNtaXNzZWRfY2F0ZWdvcnlfc3VnZ2VzdGlvbnMpIHBsdXTDtHQKICAgIC8vIHF1ZSBkYW5zIGxlIG5hdmlnYXRldXIsIHBvdXIgc3VpdnJlIHN1ciB0b3VzIGxlcyBhcHBhcmVpbHMgKHTDqWzDqXBob25lLAogICAgLy8gdGFibGV0dGUsIG9yZGluYXRldXIpIHBsdXTDtHQgcXVlIGRlIG5lIG1hcmNoZXIgcXVlIGzDoCBvw7kgYyfDqXRhaXQgY3LDqcOpLgogICAgbGV0IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldCgpOwogICAgbGV0IGFsbEJ1ZGdldHMgPSBbXTsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQnVkZ2V0cygpIHsKICAgICAgdHJ5IHsKICAgICAgICBhbGxCdWRnZXRzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBidWRnZXRzIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsICsgY29uc2VpbHMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGxldCBzYXZpbmdzR29hbCA9IG51bGw7IC8vIHsgbW9udGhseV90YXJnZXQgfSBvdSBudWxsIHNpIGphbWFpcyBjb25maWd1csOpCgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFNhdmluZ3NHb2FsKCkgewogICAgICB0cnkgewogICAgICAgIHNhdmluZ3NHb2FsID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvc2F2aW5ncy1nb2FsIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGUgbCdvYmplY3RpZiBkJ8OpcGFyZ25lIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1zYXZlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZW50cmllcyA9IE9iamVjdC5lbnRyaWVzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpOwogICAgICBsZXQgc2F2ZWRDb3VudCA9IDA7CiAgICAgIGxldCBoYWRFcnJvciA9IGZhbHNlOwogICAgICBmb3IgKGNvbnN0IFtjYXRlZ29yeSwgaW5wdXRdIG9mIGVudHJpZXMpIHsKICAgICAgICBjb25zdCByYXcgPSBpbnB1dC52YWx1ZTsKICAgICAgICBpZiAocmF3ID09PSAiIiB8fCByYXcgPT09IG51bGwpIGNvbnRpbnVlOwogICAgICAgIGNvbnN0IGFtb3VudCA9IE51bWJlcihyYXcpOwogICAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSBjb250aW51ZTsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgc2F2ZUJ1ZGdldChjYXRlZ29yeSwgYW1vdW50KTsKICAgICAgICAgIHNhdmVkQ291bnQgKz0gMTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIGhhZEVycm9yID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KICAgICAgaWYgKGhhZEVycm9yKSB7CiAgICAgICAgc2hvd1RvYXN0KCJDZXJ0YWlucyBidWRnZXRzIG4nb250IHBhcyBwdSDDqnRyZSBlbnJlZ2lzdHLDqXMiLCB0cnVlKTsKICAgICAgfSBlbHNlIGlmIChzYXZlZENvdW50ID09PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIGF1IG1vaW5zIHVuIG1vbnRhbnQgZGUgYnVkZ2V0IHZhbGlkZSIsIHRydWUpOwogICAgICB9IGVsc2UgewogICAgICAgIHNob3dUb2FzdCgiQnVkZ2V0cyBlbnJlZ2lzdHLDqXMiKTsKICAgICAgfQogICAgICByZW5kZXJCdWRnZXRzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICBjb25zdCBzYXZpbmdzR29hbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1pbnB1dCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1zYXZlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIoc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIHVuIG1vbnRhbnQgZCdvYmplY3RpZiB2YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IG1vbnRobHlfdGFyZ2V0OiBhbW91bnQgfSksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJPYmplY3RpZiBlbnJlZ2lzdHLDqSIpOwogICAgICAgIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfSk7CgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5ncyh0cmFuc2FjdGlvbnMpIHsKICAgICAgaWYgKHNhdmluZ3NHb2FsKSBzYXZpbmdzR29hbElucHV0LnZhbHVlID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CgogICAgICAvLyBTb2xkZSBkdSBtb2lzIGVuIGNvdXJzIChyZXZlbnVzIC0gZMOpcGVuc2VzKSwgdG91dCBjb25mb25kdS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgbGV0IG1vbnRoSW5jb21lID0gMDsKICAgICAgbGV0IG1vbnRoRXhwZW5zZXMgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmIChtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IGN1cnJlbnRNb250aEtleSkgY29udGludWU7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSBtb250aEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBlbHNlIG1vbnRoRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbW9udGhOZXQgPSBtb250aEluY29tZSAtIG1vbnRoRXhwZW5zZXM7CgogICAgICBjb25zdCBwcm9ncmVzc1NlY3Rpb24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy1zZWN0aW9uIik7CiAgICAgIGNvbnN0IHByb2dyZXNzVGV4dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLXRleHQiKTsKICAgICAgY29uc3QgcHJvZ3Jlc3NCYXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy1iYXIiKTsKICAgICAgaWYgKHNhdmluZ3NHb2FsICYmIHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0ID4gMCkgewogICAgICAgIHByb2dyZXNzU2VjdGlvbi5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBjb25zdCB0YXJnZXQgPSBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldDsKICAgICAgICBjb25zdCBwY3QgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigobW9udGhOZXQgLyB0YXJnZXQpICogMTAwLCAxMDApKTsKICAgICAgICBwcm9ncmVzc1RleHQudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobW9udGhOZXQpfSAvICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRhcmdldCl9YDsKICAgICAgICBsZXQgY2xzID0gIm9rIjsKICAgICAgICBpZiAobW9udGhOZXQgPCAwKSBjbHMgPSAib3ZlciI7CiAgICAgICAgZWxzZSBpZiAobW9udGhOZXQgPCB0YXJnZXQpIGNscyA9ICJ3YXJuaW5nIjsKICAgICAgICBwcm9ncmVzc0Jhci5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci1maWxsICIgKyBjbHM7CiAgICAgICAgcHJvZ3Jlc3NCYXIuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgcHJvZ3Jlc3NTZWN0aW9uLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB9CgogICAgICByZW5kZXJTYXZpbmdzQWR2aWNlKHRyYW5zYWN0aW9ucywgbW9udGhOZXQpOwogICAgICByZW5kZXJQbGFjZW1lbnRTaW11bGF0aW9uKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU2ltdWxhdGlvbiBkZSBwbGFjZW1lbnQgKGludMOpcsOqdHMgY29tcG9zw6lzLCBjYWxjdWzDqXMgbWVuc3VlbGxlbWVudCkg4oCUCiAgICAvLyBwdXJlbWVudCBjw7R0w6kgY2xpZW50IDogYXVjdW5lIGRvbm7DqWUgcsOpZWxsZSBkZSBsJ3V0aWxpc2F0ZXVyIG4nZW50cmUKICAgIC8vIGVuIGpldSwgc2V1bGVtZW50IGxlcyA0IGNoYW1wcyBkdSBmb3JtdWxhaXJlLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgbGV0IHBsYWNlbWVudENoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBjb21wdXRlUGxhY2VtZW50U2VyaWVzKGluaXRpYWwsIG1vbnRobHlDb250cmlidXRpb24sIGFubnVhbFJhdGVQZXJjZW50LCB5ZWFycykgewogICAgICBjb25zdCBtb250aHMgPSBNYXRoLm1heCgxLCBNYXRoLnJvdW5kKHllYXJzICogMTIpKTsKICAgICAgY29uc3QgbW9udGhseVJhdGUgPSBNYXRoLnBvdygxICsgYW5udWFsUmF0ZVBlcmNlbnQgLyAxMDAsIDEgLyAxMikgLSAxOwogICAgICBsZXQgYmFsYW5jZSA9IGluaXRpYWw7CiAgICAgIGNvbnN0IHNlcmllcyA9IFtiYWxhbmNlXTsKICAgICAgZm9yIChsZXQgbSA9IDE7IG0gPD0gbW9udGhzOyBtKyspIHsKICAgICAgICBiYWxhbmNlID0gYmFsYW5jZSAqICgxICsgbW9udGhseVJhdGUpICsgbW9udGhseUNvbnRyaWJ1dGlvbjsKICAgICAgICBzZXJpZXMucHVzaChiYWxhbmNlKTsKICAgICAgfQogICAgICByZXR1cm4gc2VyaWVzOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclBsYWNlbWVudFNpbXVsYXRpb24oKSB7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1wbGFjZW1lbnQiKTsKICAgICAgaWYgKCFjYW52YXMpIHJldHVybjsKICAgICAgY29uc3QgaW5pdGlhbCA9IE1hdGgubWF4KDAsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LWluaXRpYWwiKS52YWx1ZSkgfHwgMCk7CiAgICAgIGNvbnN0IG1vbnRobHkgPSBNYXRoLm1heCgwLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1tb250aGx5IikudmFsdWUpIHx8IDApOwogICAgICBjb25zdCByYXRlID0gTWF0aC5tYXgoMCwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtcmF0ZSIpLnZhbHVlKSB8fCAwKTsKICAgICAgY29uc3QgeWVhcnMgPSBNYXRoLm1heCgxLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC15ZWFycyIpLnZhbHVlKSB8fCAxKTsKCiAgICAgIGNvbnN0IHNlcmllcyA9IGNvbXB1dGVQbGFjZW1lbnRTZXJpZXMoaW5pdGlhbCwgbW9udGhseSwgcmF0ZSwgeWVhcnMpOwogICAgICBjb25zdCBtb250aHMgPSBzZXJpZXMubGVuZ3RoIC0gMTsKICAgICAgY29uc3QgbGFiZWxzID0gc2VyaWVzLm1hcCgoXywgaSkgPT4gKAogICAgICAgIGkgJSAxMiA9PT0gMCA/IGBBbiAke2kgLyAxMn1gIDogIiIKICAgICAgKSk7CgogICAgICBpZiAocGxhY2VtZW50Q2hhcnQpIHsgcGxhY2VtZW50Q2hhcnQuZGVzdHJveSgpOyBwbGFjZW1lbnRDaGFydCA9IG51bGw7IH0KICAgICAgcGxhY2VtZW50Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImxpbmUiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBsYWJlbDogIlNvbGRlIHByb2pldMOpIiwKICAgICAgICAgICAgZGF0YTogc2VyaWVzLAogICAgICAgICAgICBib3JkZXJDb2xvcjogQ0hBUlRfQ09MT1JTWzFdLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICJyZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KSIsCiAgICAgICAgICAgIGZpbGw6IHRydWUsCiAgICAgICAgICAgIHRlbnNpb246IDAuMiwKICAgICAgICAgICAgcG9pbnRSYWRpdXM6IDAsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsgbGVnZW5kOiB7IGRpc3BsYXk6IGZhbHNlIH0gfSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNhbGxiYWNrOiAodikgPT4gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHYpIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CgogICAgICBjb25zdCBmaW5hbEJhbGFuY2UgPSBzZXJpZXNbc2VyaWVzLmxlbmd0aCAtIDFdOwogICAgICBjb25zdCB0b3RhbENvbnRyaWJ1dGVkID0gaW5pdGlhbCArIG1vbnRobHkgKiBtb250aHM7CiAgICAgIGNvbnN0IGludGVyZXN0RWFybmVkID0gZmluYWxCYWxhbmNlIC0gdG90YWxDb250cmlidXRlZDsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1yZXN1bHQiKS5pbm5lckhUTUwgPQogICAgICAgIGBBcHLDqHMgJHt5ZWFyc30gYW4ke3llYXJzID4gMSA/ICJzIiA6ICIifSA6IDxzdHJvbmc+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZmluYWxCYWxhbmNlKX08L3N0cm9uZz4gYCArCiAgICAgICAgYChkb250ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGludGVyZXN0RWFybmVkKX0gZCdpbnTDqXLDqnRzLCBwb3VyICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsQ29udHJpYnV0ZWQpfSB2ZXJzw6lzKS5gOwogICAgfQoKICAgIGZvciAoY29uc3QgaWQgb2YgWyJwbGFjZW1lbnQtaW5pdGlhbCIsICJwbGFjZW1lbnQtbW9udGhseSIsICJwbGFjZW1lbnQtcmF0ZSIsICJwbGFjZW1lbnQteWVhcnMiXSkgewogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuYWRkRXZlbnRMaXN0ZW5lcigiaW5wdXQiLCByZW5kZXJQbGFjZW1lbnRTaW11bGF0aW9uKTsKICAgIH0KCiAgICAvLyBDb25zZWlscyA6IGNyb2lzZSBkw6lwYXNzZW1lbnRzIGRlIGJ1ZGdldCAob25nbGV0IFRhYmxlYXUgZGUgYm9yZCkgZXQKICAgIC8vIHRlbmRhbmNlcyBwYXIgY2F0w6lnb3JpZSBwb3VyIHBvaW50ZXIgdmVycyBjZSBxdWkgYWlkZSBsZSBwbHVzIMOgCiAgICAvLyBhdHRlaW5kcmUgbCdvYmplY3RpZiDigJQgcGFzIHVuZSBJQSwganVzdGUgZGVzIHLDqGdsZXMgc2ltcGxlcyBzdXIgZGVzCiAgICAvLyBkb25uw6llcyBkw6lqw6AgY2FsY3Vsw6llcyBhaWxsZXVycyBkYW5zIGwnYXBwLgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KSB7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWFkdmljZS1saXN0Iik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtZW1wdHkiKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBjb25zdCBhZHZpY2UgPSBbXTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiBtb250aFRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBjb25zdCB0cmVuZEJ5Q2F0ZWdvcnkgPSBPYmplY3QuZnJvbUVudHJpZXModHJlbmRzLm1hcCgodCkgPT4gW3QuY2F0ZWdvcnksIHRdKSk7CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0LCB0cmnDqWVzIHBhciBtb250YW50IGRlCiAgICAgIC8vIGTDqXBhc3NlbWVudCBkw6ljcm9pc3NhbnQg4oCUIGNlIHNvbnQgbGVzIGxldmllcnMgbGVzIHBsdXMgdXRpbGVzLgogICAgICBjb25zdCBvdmVyQnVkZ2V0ID0gW107CiAgICAgIGZvciAoY29uc3QgYnVkZ2V0IG9mIGFsbEJ1ZGdldHMpIHsKICAgICAgICBjb25zdCBzcGVudCA9IG1vbnRoVG90YWxzW2J1ZGdldC5jYXRlZ29yeV0gfHwgMDsKICAgICAgICBpZiAoc3BlbnQgPiBidWRnZXQuYW1vdW50KSB7CiAgICAgICAgICBvdmVyQnVkZ2V0LnB1c2goeyBjYXRlZ29yeTogYnVkZ2V0LmNhdGVnb3J5LCBzcGVudCwgYnVkZ2V0OiBidWRnZXQuYW1vdW50LCBvdmVyOiBzcGVudCAtIGJ1ZGdldC5hbW91bnQgfSk7CiAgICAgICAgfQogICAgICB9CiAgICAgIG92ZXJCdWRnZXQuc29ydCgoYSwgYikgPT4gYi5vdmVyIC0gYS5vdmVyKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBvdmVyQnVkZ2V0LnNsaWNlKDAsIDMpKSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnkpOwogICAgICAgIGNvbnN0IHRyZW5kID0gdHJlbmRCeUNhdGVnb3J5W2l0ZW0uY2F0ZWdvcnldOwogICAgICAgIGxldCB0ZXh0ID0gYFR1IGFzIGTDqXBhc3PDqSB0b24gYnVkZ2V0IDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5vdmVyKX0gY2UgbW9pcy1jaS5gOwogICAgICAgIGlmICh0cmVuZCAmJiB0cmVuZC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRleHQgKz0gYCBMYSB0ZW5kYW5jZSBlc3Qgw6AgbGEgaGF1c3NlICgrJHtNYXRoLnJvdW5kKHRyZW5kLnJhdGlvICogMTAwKX0lIHZzIHRhIG1veWVubmUpIOKAlCByw6lkdWlyZSBjZXMgZMOpcGVuc2VzIHQnYWlkZXJhaXQgbGUgcGx1cyDDoCBhdHRlaW5kcmUgdG9uIG9iamVjdGlmLmA7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHRleHQgKz0gYCBFc3NhaWUgZGUgcmFtZW5lciDDp2Egc291cyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmJ1ZGdldCl9IGxlIG1vaXMgcHJvY2hhaW4uYDsKICAgICAgICB9CiAgICAgICAgYWR2aWNlLnB1c2goeyB0eXBlOiAid2FybmluZyIsIGljb246ICLimqDvuI8iLCB0ZXh0IH0pOwogICAgICB9CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBuZXR0ZSBoYXVzc2UgbcOqbWUgc2FucyBidWRnZXQgZMOpcGFzc8OpIChvdSBzYW5zIGJ1ZGdldAogICAgICAvLyBkw6lmaW5pIGR1IHRvdXQpIDogdW4gc2lnbmFsIHV0aWxlIGVuIHNvaS4KICAgICAgY29uc3QgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0ID0gdHJlbmRzCiAgICAgICAgLmZpbHRlcigodCkgPT4gdC5kaXJlY3Rpb24gPT09ICJ1cCIgJiYgdC5hdmVyYWdlID4gMCAmJiAhb3ZlckJ1ZGdldC5zb21lKChvKSA9PiBvLmNhdGVnb3J5ID09PSB0LmNhdGVnb3J5KSkKICAgICAgICAuc29ydCgoYSwgYikgPT4gYi5yYXRpbyAtIGEucmF0aW8pCiAgICAgICAgLnNsaWNlKDAsIDIpOwogICAgICBmb3IgKGNvbnN0IHQgb2YgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0KSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW3QuY2F0ZWdvcnldIHx8IHQuY2F0ZWdvcnkpOwogICAgICAgIGFkdmljZS5wdXNoKHsKICAgICAgICAgIHR5cGU6ICJpbmZvIiwKICAgICAgICAgIGljb246ICLwn5OIIiwKICAgICAgICAgIHRleHQ6IGBUZXMgZMOpcGVuc2VzIGVuIDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gc29udCBlbiBoYXVzc2UgZGUgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSUgcGFyIHJhcHBvcnQgw6AgdGEgbW95ZW5uZSDigJQgw6Agc3VydmVpbGxlciBzaSB0dSB2ZXV4IMOpcGFyZ25lciBwbHVzLmAsCiAgICAgICAgfSk7CiAgICAgIH0KCiAgICAgIC8vIE9iamVjdGlmIGF0dGVpbnQgLyBlbiBib25uZSB2b2llIGNlIG1vaXMtY2kuCiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBpZiAobW9udGhOZXQgPj0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogInBvc2l0aXZlIiwKICAgICAgICAgICAgaWNvbjogIvCfjokiLAogICAgICAgICAgICB0ZXh0OiBgT2JqZWN0aWYgYXR0ZWludCAhIFR1IGFzIGTDqWrDoCBtaXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobW9udGhOZXQpfSBkZSBjw7R0w6kgY2UgbW9pcy1jaSwgYXUtZGVsw6AgZGUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0gZWxzZSBpZiAob3ZlckJ1ZGdldC5sZW5ndGggPT09IDAgJiYgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0Lmxlbmd0aCA9PT0gMCkgewogICAgICAgICAgYWR2aWNlLnVuc2hpZnQoewogICAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICAgIGljb246ICLwn5GNIiwKICAgICAgICAgICAgdGV4dDogYFBhcyBkZSBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0IGNlIG1vaXMtY2kuIElsIHRlIHJlc3RlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0IC0gbW9udGhOZXQpfSDDoCDDqWNvbm9taXNlciBwb3VyIGF0dGVpbmRyZSB0b24gb2JqZWN0aWYgZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpfS5gLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBpZiAoYWR2aWNlLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhZHZpY2UpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAiYWR2aWNlLWNhcmQgIiArIGl0ZW0udHlwZTsKICAgICAgICBjb25zdCBpY29uID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGljb24uY2xhc3NOYW1lID0gImFkdmljZS1pY29uIjsKICAgICAgICBpY29uLnRleHRDb250ZW50ID0gaXRlbS5pY29uOwogICAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgdGV4dC5pbm5lckhUTUwgPSBpdGVtLnRleHQ7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChpY29uKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKHRleHQpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCkgewogICAgICBjb25zdCB1cGRhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIsIHsKICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnksIGFtb3VudCB9KSwKICAgICAgfSk7CiAgICAgIGNvbnN0IGlkeCA9IGFsbEJ1ZGdldHMuZmluZEluZGV4KChiKSA9PiBiLmNhdGVnb3J5ID09PSBjYXRlZ29yeSk7CiAgICAgIGlmIChpZHggPj0gMCkgYWxsQnVkZ2V0c1tpZHhdID0gdXBkYXRlZDsKICAgICAgZWxzZSBhbGxCdWRnZXRzLnB1c2godXBkYXRlZCk7CiAgICB9CgogICAgY29uc3QgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeSA9IHt9OwogICAgY29uc3QgQlVER0VUX0hJU1RPUllfTU9OVEhTID0gNjsKCiAgICAvLyBMZXMgTiBkZXJuaWVycyBtb2lzIChjbMOpcyAiWVlZWS1NTSIpLCBkdSBwbHVzIGFuY2llbiBhdSBwbHVzIHLDqWNlbnQsCiAgICAvLyBlbiBmaW5pc3NhbnQgcGFyIGVuZE1vbnRoS2V5IGluY2x1cy4KICAgIGZ1bmN0aW9uIGxhc3ROTW9udGhLZXlzKG4sIGVuZE1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IFt5LCBtXSA9IGVuZE1vbnRoS2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGtleXMgPSBbXTsKICAgICAgZm9yIChsZXQgaSA9IG4gLSAxOyBpID49IDA7IGktLSkgewogICAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSh5LCBtIC0gMSAtIGksIDEpOwogICAgICAgIGtleXMucHVzaChkLmdldEZ1bGxZZWFyKCkgKyAiLSIgKyBTdHJpbmcoZC5nZXRNb250aCgpICsgMSkucGFkU3RhcnQoMiwgIjAiKSk7CiAgICAgIH0KICAgICAgcmV0dXJuIGtleXM7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidWRnZXRzLWxpc3QiKTsKICAgICAgaWYgKCF3cmFwKSByZXR1cm47CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgY3VycmVudE1vbnRoS2V5KTsKCiAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpKSBkZWxldGUgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVtrZXldOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSkgewogICAgICAgIGNvbnN0IGJ1ZGdldCA9IGFsbEJ1ZGdldHMuZmluZCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gdmFsdWUpOwogICAgICAgIGNvbnN0IHNwZW50ID0gdG90YWxzW3ZhbHVlXSB8fCAwOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ciOwoKICAgICAgICBjb25zdCBoZWFkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZC5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdy1oZWFkIjsKCiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4uY2xhc3NOYW1lID0gImJ1ZGdldC1jYXQtbmFtZSI7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBsYWJlbDsKCiAgICAgICAgY29uc3QgYW1vdW50cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRzLmNsYXNzTmFtZSA9ICJidWRnZXQtYW1vdW50cyI7CiAgICAgICAgY29uc3Qgc3BlbnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHNwZW50U3Bhbi50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzcGVudCkgKyAiIC8gIjsKICAgICAgICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgaW5wdXQudHlwZSA9ICJudW1iZXIiOwogICAgICAgIGlucHV0LmNsYXNzTmFtZSA9ICJidWRnZXQtaW5wdXQiOwogICAgICAgIGlucHV0Lm1pbiA9ICIwIjsKICAgICAgICBpbnB1dC5zdGVwID0gIjEiOwogICAgICAgIGlucHV0LnBsYWNlaG9sZGVyID0gIuKAlCI7CiAgICAgICAgaWYgKGJ1ZGdldCkgaW5wdXQudmFsdWUgPSBidWRnZXQuYW1vdW50OwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoc3BlbnRTcGFuKTsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKGlucHV0KTsKICAgICAgICBidWRnZXRJbnB1dHNCeUNhdGVnb3J5W3ZhbHVlXSA9IGlucHV0OwoKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKG5hbWVTcGFuKTsKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKGFtb3VudHMpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChoZWFkKTsKCiAgICAgICAgaWYgKGJ1ZGdldCkgewogICAgICAgICAgY29uc3QgdHJhY2sgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHRyYWNrLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLXRyYWNrIjsKICAgICAgICAgIGNvbnN0IGZpbGwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIGNvbnN0IHJhdGlvID0gc3BlbnQgLyBidWRnZXQuYW1vdW50OwogICAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5taW4ocmF0aW8gKiAxMDAsIDEwMCk7CiAgICAgICAgICBsZXQgY2xzID0gIm9rIjsKICAgICAgICAgIGlmIChyYXRpbyA+PSAxKSBjbHMgPSAib3ZlciI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA+PSAwLjcpIGNscyA9ICJ3YXJuaW5nIjsKICAgICAgICAgIGZpbGwuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgICAgZmlsbC5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgICAgIHRyYWNrLmFwcGVuZENoaWxkKGZpbGwpOwogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHRyYWNrKTsKCiAgICAgICAgICBjb25zdCBzdHJpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgc3RyaXAuY2xhc3NOYW1lID0gImJ1ZGdldC1oaXN0b3J5LXN0cmlwIjsKICAgICAgICAgIGZvciAoY29uc3QgaGlzdEtleSBvZiBsYXN0Tk1vbnRoS2V5cyhCVURHRVRfSElTVE9SWV9NT05USFMsIGN1cnJlbnRNb250aEtleSkpIHsKICAgICAgICAgICAgY29uc3QgeyB0b3RhbHM6IGhpc3RUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBoaXN0S2V5KTsKICAgICAgICAgICAgY29uc3QgaGlzdFNwZW50ID0gaGlzdFRvdGFsc1t2YWx1ZV0gfHwgMDsKICAgICAgICAgICAgY29uc3QgZG90ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgICBpZiAoaGlzdFNwZW50ID09PSAwKSB7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCBlbXB0eSI7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgY29uc3QgaGlzdFJhdGlvID0gaGlzdFNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgICAgICBsZXQgaGlzdENscyA9ICJvayI7CiAgICAgICAgICAgICAgaWYgKGhpc3RSYXRpbyA+PSAxKSBoaXN0Q2xzID0gIm92ZXIiOwogICAgICAgICAgICAgIGVsc2UgaWYgKGhpc3RSYXRpbyA+PSAwLjcpIGhpc3RDbHMgPSAid2FybmluZyI7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCAiICsgaGlzdENsczsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBbaHksIGhtXSA9IGhpc3RLZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgICAgY29uc3QgbW9udGhMYWJlbCA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGh5LCBobSAtIDEsIDEpKTsKICAgICAgICAgICAgY29uc3QgZGV0YWlsVGV4dCA9IGAke21vbnRoTGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaGlzdFNwZW50KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChidWRnZXQuYW1vdW50KX1gOwogICAgICAgICAgICBkb3QudGl0bGUgPSBkZXRhaWxUZXh0OyAvLyBhZmZpY2jDqSBhdSBzdXJ2b2wgc3VyIG9yZGluYXRldXIKICAgICAgICAgICAgLy8gU3VyIG1vYmlsZSBpbCBuJ3kgYSBwYXMgZGUgc3Vydm9sIDogdW4gdGFwIHN1ciBsYSBiYXJyZSBtb250cmUKICAgICAgICAgICAgLy8gbGUgbcOqbWUgZMOpdGFpbCBkYW5zIHVuIHRvYXN0LgogICAgICAgICAgICBkb3QuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93VG9hc3QoZGV0YWlsVGV4dCkpOwogICAgICAgICAgICBzdHJpcC5hcHBlbmRDaGlsZChkb3QpOwogICAgICAgICAgfQogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHN0cmlwKTsKICAgICAgICB9CgogICAgICAgIHdyYXAuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRDdXN0b21DYXRlZ29yaWVzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiKTsKICAgICAgICBmb3IgKGNvbnN0IHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0gb2YgaXRlbXMpIHsKICAgICAgICAgIGlmIChjYXRlZ29yaWVzQnlUeXBlW3R5cGVdICYmICFjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdmFsdWUpKSB7CiAgICAgICAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgICAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgY2F0w6lnb3JpZXMgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGtleXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiKTsKICAgICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoa2V5cyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgdW5lIHN1Z2dlc3Rpb24gZMOpasOgIHZ1ZSByw6lhcHBhcmHDrnQgdW5lIGZvaXMuCiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzbHVnaWZ5Q2F0ZWdvcnkobGFiZWwpIHsKICAgICAgcmV0dXJuICgKICAgICAgICBsYWJlbAogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gZW5sw6h2ZSBsZXMgYWNjZW50cwogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC50cmltKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0rL2csICJfIikKICAgICAgICAgIC5yZXBsYWNlKC9eXyt8XyskL2csICIiKSB8fCAiYXV0cmUiCiAgICAgICk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc2F2ZUN1c3RvbUNhdGVnb3J5KHR5cGUsIHZhbHVlLCBsYWJlbCkgewogICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiQ2F0w6lnb3JpZSBjcsOpw6llIGljaSwgbWFpcyBwYXMgc2F1dmVnYXJkw6llIHN1ciBsZSBzZXJ2ZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIC8vIMOJY2hhcHBlIHVuZSB2YWxldXIgYXZhbnQgZGUgbCdpbnPDqXJlciBkYW5zIHVuIHRlbXBsYXRlIEhUTUwgY29uc3RydWl0CiAgICAvLyDDoCBsYSBtYWluIChpbm5lckhUTUwpIDogbsOpY2Vzc2FpcmUgcGFydG91dCBvw7kgdW5lIGRvbm7DqWUgc2Fpc2llIHBhcgogICAgLy8gbCd1dGlsaXNhdGV1ciBwZXV0IHMneSByZXRyb3V2ZXIg4oCUIGVuIHBhcnRpY3VsaWVyIGxlIGxpYmVsbMOpIGQndW5lCiAgICAvLyBjYXTDqWdvcmllIHBlcnNvbm5hbGlzw6llICh0ZXh0ZSBsaWJyZSwgZW5yZWdpc3Ryw6kgZW4gYmFzZSksIHBvdXIgw6l2aXRlcgogICAgLy8gcXUndW4gbGliZWxsw6kgZHUgZ2VucmUgPGltZyBzcmM9eCBvbmVycm9yPS4uLj4gbmUgcydleMOpY3V0ZSBjb21tZSBkdQogICAgLy8gSFRNTC9KUyBhdSBsaWV1IGRlIHMnYWZmaWNoZXIgY29tbWUgZHUgdGV4dGUgKGluamVjdGlvbiBYU1Mgc3RvY2vDqWUpLgogICAgZnVuY3Rpb24gZXNjYXBlSHRtbChzdHIpIHsKICAgICAgcmV0dXJuIFN0cmluZyhzdHIpLnJlcGxhY2UoL1smPD4iJ10vZywgKGNoKSA9PiAoewogICAgICAgICImIjogIiZhbXA7IiwgIjwiOiAiJmx0OyIsICI+IjogIiZndDsiLCAnIic6ICImcXVvdDsiLCAiJyI6ICImIzM5OyIsCiAgICAgIH1bY2hdKSk7CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd1RvYXN0KG1lc3NhZ2UsIGlzRXJyb3IgPSBmYWxzZSkgewogICAgICBjb25zdCB0b2FzdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICB0b2FzdC5jbGFzc05hbWUgPSAidG9hc3QiICsgKGlzRXJyb3IgPyAiIGVycm9yIiA6ICIiKTsKICAgICAgdG9hc3QudGV4dENvbnRlbnQgPSBtZXNzYWdlOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRvYXN0KTsKICAgICAgc2V0VGltZW91dCgoKSA9PiB0b2FzdC5yZW1vdmUoKSwgMzAwMCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCwgb3B0aW9ucyA9IHt9KSB7CiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKHBhdGgsIHsKICAgICAgICAuLi5vcHRpb25zLAogICAgICAgIGhlYWRlcnM6IHsKICAgICAgICAgICJYLUFQSS1LZXkiOiBBUElfS0VZLAogICAgICAgICAgLi4uKG9wdGlvbnMuYm9keSA/IHsgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiB9IDoge30pLAogICAgICAgICAgLi4uKG9wdGlvbnMuaGVhZGVycyB8fCB7fSksCiAgICAgICAgfSwKICAgICAgfSk7CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSA0MDEpIHsKICAgICAgICAvLyBKZXRvbiBhYnNlbnQsIGludmFsaWRlIG91IGV4cGlyw6kgOiByZXRvdXIgw6AgbCfDqWNyYW4gZGUgdmVycm91aWxsYWdlCiAgICAgICAgLy8gcGx1dMO0dCBxdWUgZCdhZmZpY2hlciB1bmUgZXJyZXVyIHRlY2huaXF1ZSBpbmNvbXByw6loZW5zaWJsZS4KICAgICAgICBzaG93TG9ja1NjcmVlbigpOwogICAgICAgIHRocm93IG5ldyBFcnJvcigiU2Vzc2lvbiBleHBpcsOpZSwgcmVjb25uZWN0ZS10b2kuIik7CiAgICAgIH0KICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAvLyByZXMuc3RhdHVzVGV4dCBlc3Qgc291dmVudCB2aWRlIChuYXZpZ2F0ZXVycyBlbiBIVFRQLzIsIHV0aWxpc8OpIHBhcgogICAgICAgIC8vIFZlcmNlbCksIGRvbmMgb24gbmUgcGV1dCBwYXMgY29tcHRlciBkZXNzdXMgY29tbWUgbWVzc2FnZSBwYXIKICAgICAgICAvLyBkw6lmYXV0IDogb24gcmV0b21iZSBzdXIgbGUgY29kZSBIVFRQIHBvdXIgbmUgamFtYWlzIGFmZmljaGVyIHVuCiAgICAgICAgLy8gbWVzc2FnZSBkJ2VycmV1ciB2aWRlLgogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgZGV0YWlsID0gZGF0YS5kZXRhaWwgfHwgZGV0YWlsOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICB9CgogICAgY2F0ZWdvcnlJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LmNsYXNzTGlzdC50b2dnbGUoImhpZGRlbiIsIGNhdGVnb3J5SW5wdXQudmFsdWUgIT09ICJfX25ld19fIik7CiAgICAgIGlmIChjYXRlZ29yeUlucHV0LnZhbHVlID09PSAiX19uZXdfXyIpIG5ld0NhdGVnb3J5TmFtZUlucHV0LmZvY3VzKCk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IGlzRWRpdCA/IHR4LmNhdGVnb3J5IDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwoKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgaWYgKGlzRWRpdCAmJiB0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICBsb2FkRXhpc3RpbmdSZWNlaXB0UHJldmlldyh0eC5pZCk7CiAgICAgIH0KCiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkgewogICAgICAvLyBNw6ptZSBtb250YW50L2NhdMOpZ29yaWUvZGVzY3JpcHRpb24sIG1haXMgZGF0w6kgZCdhdWpvdXJkJ2h1aSBldCBzYW5zCiAgICAgIC8vIGlkIDogbGEgc2F1dmVnYXJkZSBjcsOpZXJhIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiAodm9pciBvcGVuTW9kYWwpLgogICAgICBvcGVuTW9kYWwoeyAuLi50eCwgaWQ6IG51bGwsIGV4cGVuc2VfZGF0ZTogdG9kYXlJc28oKSB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICAgIGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5ID0gbnVsbDsKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICAvLyAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIiBzw6lsZWN0aW9ubsOpIDogb24gbGEgY3LDqWUgKHNpIGVsbGUgbidleGlzdGUKICAgICAgLy8gcGFzIGTDqWrDoCBzb3VzIGNlIG5vbSkgYXZhbnQgZCdlbnJlZ2lzdHJlciBsYSB0cmFuc2FjdGlvbiBhdmVjLgogICAgICBsZXQgY2F0ZWdvcnlWYWx1ZSA9IGNhdGVnb3J5SW5wdXQudmFsdWU7CiAgICAgIGlmIChjYXRlZ29yeVZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICBjb25zdCBuYW1lID0gbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgIGlmICghbmFtZSkgewogICAgICAgICAgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIsIHRydWUpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBjYXRlZ29yeVZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtjdXJyZW50VHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSBjYXRlZ29yeVZhbHVlKSkgewogICAgICAgICAgYXdhaXQgc2F2ZUN1c3RvbUNhdGVnb3J5KGN1cnJlbnRUeXBlLCBjYXRlZ29yeVZhbHVlLCBuYW1lKTsKICAgICAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgY2F0ZWdvcnlWYWx1ZSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlWYWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgY29uc3QgcHJldmlvdXNDYXRlZ29yeSA9IGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5OwogICAgICAgICAgY29uc3QgZWRpdGVkSWQgPSBlZGl0aW5nSWQ7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CgogICAgICAgICAgLy8gU2kgbGEgY2F0w6lnb3JpZSB2aWVudCBkZSBjaGFuZ2VyIG1hbnVlbGxlbWVudCwgb24gcHJvcG9zZSBkZQogICAgICAgICAgLy8gcmVwb3J0ZXIgbGUgbcOqbWUgY2hhbmdlbWVudCBzdXIgbGVzIGF1dHJlcyB0cmFuc2FjdGlvbnMgZG9udCBsYQogICAgICAgICAgLy8gZGVzY3JpcHRpb24gcGFydGFnZSB1biBtb3QtY2zDqSBzaWduaWZpY2F0aWYgKGV4LiAiY2FzaW5vIiAvCiAgICAgICAgICAvLyAiYXUgY2FzaW5vIiAvICJwZXJ0ZSBhdSBjYXNpbm8iKSBldCBxdWkgw6l0YWllbnQgZGFucyBsJ2FuY2llbm5lCiAgICAgICAgICAvLyBjYXTDqWdvcmllIOKAlCBqYW1haXMgYXV0b21hdGlxdWUsIHRvdWpvdXJzIHN1ciBjb25maXJtYXRpb24uCiAgICAgICAgICBpZiAocHJldmlvdXNDYXRlZ29yeSAmJiBwYXlsb2FkLmNhdGVnb3J5ICE9PSBwcmV2aW91c0NhdGVnb3J5ICYmIHBheWxvYWQuZGVzY3JpcHRpb24pIHsKICAgICAgICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhwYXlsb2FkLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgaWYgKGtleXdvcmRzLnNpemUgPiAwKSB7CiAgICAgICAgICAgICAgY29uc3Qgc2ltaWxhciA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgICAgICAgICAodCkgPT4KICAgICAgICAgICAgICAgICAgdC5pZCAhPT0gZWRpdGVkSWQgJiYKICAgICAgICAgICAgICAgICAgdC50eXBlID09PSBwYXlsb2FkLnR5cGUgJiYKICAgICAgICAgICAgICAgICAgdC5jYXRlZ29yeSA9PT0gcHJldmlvdXNDYXRlZ29yeSAmJgogICAgICAgICAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModC5kZXNjcmlwdGlvbikpCiAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgICBpZiAoc2ltaWxhci5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICBjb25zdCBuZXdMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BheWxvYWQuY2F0ZWdvcnldIHx8IHBheWxvYWQuY2F0ZWdvcnk7CiAgICAgICAgICAgICAgICBjb25zdCBleGFtcGxlRGVzYyA9IHNpbWlsYXJbMF0uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICAgICAgICAgICAgYEFwcGxpcXVlciBhdXNzaSBsYSBjYXTDqWdvcmllICIke25ld0xhYmVsfSIgYXV4ICR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIGAgKwogICAgICAgICAgICAgICAgICBgc2ltaWxhaXJlKHMpIChleC4gIiR7ZXhhbXBsZURlc2N9IikgP2AKICAgICAgICAgICAgICAgICk7CiAgICAgICAgICAgICAgICBpZiAoY29uZmlybWVkKSB7CiAgICAgICAgICAgICAgICAgIGZvciAoY29uc3QgdCBvZiBzaW1pbGFyKSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgZml4UGF5bG9hZCA9IHsgY2F0ZWdvcnk6IHBheWxvYWQuY2F0ZWdvcnkgfTsKICAgICAgICAgICAgICAgICAgICAvLyBDb21tZSBwb3VyIGxhIGJhbm5pw6hyZSBkZSBzdWdnZXN0aW9uIDogbGEgY2F0w6lnb3JpZQogICAgICAgICAgICAgICAgICAgIC8vIHBvcnRlIG1haW50ZW5hbnQgbCdpbmZvLCBvbiByZXRpcmUgbGUgbW90LWNsw6kgZGV2ZW51CiAgICAgICAgICAgICAgICAgICAgLy8gcmVkb25kYW50IGRlIGxhIGRlc2NyaXB0aW9uIGRlIENFUyB0cmFuc2FjdGlvbnMtbMOgCiAgICAgICAgICAgICAgICAgICAgLy8gKHBhcyBjZWxsZSBxdSdvbiB2aWVudCBkJ8OpZGl0ZXIgw6AgbGEgbWFpbikuCiAgICAgICAgICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKHQuZGVzY3JpcHRpb24sIGtleXdvcmRzKTsKICAgICAgICAgICAgICAgICAgICBpZiAoY2xlYW5lZCAhPT0gKHQuZGVzY3JpcHRpb24gfHwgbnVsbCkpIGZpeFBheWxvYWQuZGVzY3JpcHRpb24gPSBjbGVhbmVkOwogICAgICAgICAgICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3QuaWR9YCwgewogICAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGZpeFBheWxvYWQpLAogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgIHNob3dUb2FzdChgJHtzaW1pbGFyLmxlbmd0aH0gYXV0cmUocykgdHJhbnNhY3Rpb24ocykgbWlzZShzKSDDoCBqb3VyYCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgICBpZiAocGVuZGluZ1JlY2VpcHRGaWxlKSB7CiAgICAgICAgICAgIC8vIExhIHBob3RvIGEgw6l0w6kgY2hvaXNpZSBhdmFudCBxdWUgbGEgdHJhbnNhY3Rpb24gbidleGlzdGUgOiBvbgogICAgICAgICAgICAvLyBsJ2Vudm9pZSBtYWludGVuYW50IHF1J29uIGEgdW4gaWQuCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBwZW5kaW5nUmVjZWlwdEZpbGUpOwogICAgICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2NyZWF0ZWQuaWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICAgICAgYm9keTogZm9ybURhdGEsCiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIGNyw6nDqWUsIG1haXMgbCdlbnZvaSBkZSBsYSBwaG90byBhIMOpY2hvdcOpIiwgdHJ1ZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YXV4IGdsb2JhdXggKFNvbGRlL0TDqXBlbnNlcy9SZXZlbnVzKSA6IGNhbGN1bMOpcyBzdXIgVE9VVEVTIGxlcwogICAgLy8gdHJhbnNhY3Rpb25zLCBpbmTDqXBlbmRhbW1lbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlIOKAlCB1biBmaWx0cmUKICAgIC8vIHNlcnQgw6AgY2hlcmNoZXIgZGFucyBsYSBsaXN0ZSwgcGFzIMOgIHJlY2FsY3VsZXIgbGUgc29sZGUgcsOpZWwuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKSB7CiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgLy8gQ29uc3RydWN0aW9uIGRlIGxhIGxpc3RlIGRlIGNhcnRlcyBhZmZpY2jDqWUgZGFucyBsJ29uZ2xldCBIaXN0b3JpcXVlIOKAlAogICAgLy8gcmXDp29pdCBkw6lqw6AgbGEgbGlzdGUgZmlsdHLDqWUgKHZvaXIgYXBwbHlIaXN0b3J5RmlsdGVycykuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbkxpc3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgaWYgKHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnRleHRDb250ZW50ID0gYWxsVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMAogICAgICAgICAgPyAiUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4iCiAgICAgICAgICA6ICJBdWN1biByw6lzdWx0YXQgcG91ciBjZXMgZmlsdHJlcy4iOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJ0eC1jYXJkICIgKyB0eC50eXBlOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAidHgtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAidHgtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRhdGVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGRhdGVTcGFuLmNsYXNzTmFtZSA9ICJ0eC1kYXRlIjsKICAgICAgICBkYXRlU3Bhbi50ZXh0Q29udGVudCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHR4LmV4cGVuc2VfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZGF0ZVNwYW4pOwogICAgICAgIGlmICh0eC5yZWN1cnJpbmdfZXhwZW5zZV9pZCkgewogICAgICAgICAgY29uc3QgcmVjQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICByZWNCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjdXJyaW5nLWJhZGdlIjsKICAgICAgICAgIHJlY0JhZGdlLnRleHRDb250ZW50ID0gIvCflIEiOwogICAgICAgICAgcmVjQmFkZ2UudGl0bGUgPSAiQ3LDqcOpZSBhdXRvbWF0aXF1ZW1lbnQgZGVwdWlzIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY0JhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgICAgY29uc3QgcmVjZWlwdEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudHlwZSA9ICJidXR0b24iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWNlaXB0LWJhZGdlIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50ZXh0Q29udGVudCA9ICLwn6e+IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50aXRsZSA9ICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiVm9pciBsYSBwaG90byBkdSByZcOndSIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY2VpcHRMaWdodGJveCh0eC5pZCkpOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY2VpcHRCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWhpc3RvcnkiKS5zdHlsZS5kaXNwbGF5ID0gdmlldyA9PT0gImhpc3RvcnkiID8gImJsb2NrIiA6ICJub25lIjsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBpZiAodmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICBpZiAodmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIGNsb3NlTmF2RHJhd2VyKCk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJzYXZpbmdzIikpOwoKICAgIC8vIE1lbnUgImJ1cmdlciIgKG1vYmlsZSB1bmlxdWVtZW50LCB2b2lyIGxlIENTUyBAbWVkaWEgYXNzb2Npw6kpIDogbGEKICAgIC8vIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIHN1cgogICAgLy8gcGx1c2lldXJzIGxpZ25lcy4gRmVybcOpIGF1dG9tYXRpcXVlbWVudCBkw6hzIHF1J3VuIG9uZ2xldCBlc3QgY2hvaXNpCiAgICAvLyAodm9pciBzd2l0Y2hWaWV3IGNpLWRlc3N1cykgb3UgZW4gdG91Y2hhbnQgbGUgZm9uZCBhc3NvbWJyaS4KICAgIGZ1bmN0aW9uIGNsb3NlTmF2RHJhd2VyKCkgewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC5yZW1vdmUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1lbnUtdG9nZ2xlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC50b2dnbGUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibmF2LWRyYXdlci1iYWNrZHJvcCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VOYXZEcmF3ZXIpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwogICAgbGV0IHllYXJseUNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgLy8gVW5lIGNoYXJnZSByw6ljdXJyZW50ZSBjb21wdGUgcG91ciB1biBtb2lzIGRvbm7DqSBzaSBjZSBtb2lzIGVzdCBkYW5zIHNhCiAgICAvLyBww6lyaW9kZSBkJ2FjdGl2aXTDqSA6IHBhcyBhdmFudCBzYSBkYXRlIGRlIGTDqWJ1dCAoc2kgcG9zw6llKSwgcGFzIGFwcsOocwogICAgLy8gbGUgbW9pcyBkZSBzYSBkYXRlIGRlIGZpbiAoc2kgcG9zw6llKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSB7CiAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUgJiYgbW9udGhLZXkgPCBpdGVtLnN0YXJ0X2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUgJiYgbW9udGhLZXkgPiBpdGVtLmVuZF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIHJldHVybiB0cnVlOwogICAgfQoKICAgIC8vIEpvdXIgZHUgbW9pcyBqdXNxdSdhdXF1ZWwgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBlc3QgY29uc2lkw6lyw6llIGNvbW1lCiAgICAvLyAiZMOpasOgIHByw6lsZXbDqWUiIHBvdXIgbGUgbW9pcyBgbW9udGhLZXlgIDogdG91cyBsZXMgam91cnMgcG91ciB1biBtb2lzCiAgICAvLyBkw6lqw6AgcGFzc8OpLCBhdWN1biBwb3VyIHVuIG1vaXMgZnV0dXIsIGV0IGxlIGpvdXIgZHUgam91ciBwb3VyIGxlIG1vaXMKICAgIC8vIGVuIGNvdXJzLiBQZXJtZXQgZGUgZGlzdGluZ3VlciBjZSBxdWkgZXN0IGTDqWrDoCBhcnJpdsOpIGRlIGNlIHF1aSBlc3QKICAgIC8vIHNldWxlbWVudCBwcsOpdnUgKGV4IDogdW4gYWJvbm5lbWVudCBwcsOpbGV2w6kgbGUgMjUsIG9uIGVzdCBsZSAyKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSkgewogICAgICBpZiAobW9udGhLZXkgPCBjdXJyZW50TW9udGhLZXkpIHJldHVybiAzMTsKICAgICAgaWYgKG1vbnRoS2V5ID4gY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMDsKICAgICAgcmV0dXJuIHRvZGF5RGF5OwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCkgbW9udGhTZXQuYWRkKG1vbnRoS2V5T2YodG9kYXlJc28oKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gIiI7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gIkF1Y3VuZSBkb25uw6llIjsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgc2VsZWN0LnZhbHVlID0gbW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IG1vbnRoc1swXTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCB1cGNvbWluZ05vdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIpOwogICAgICBjb25zdCB1cGNvbWluZ1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCIpOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBjb25zdCBjdXRvZmYgPSByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBVbiBzZXVsIHNvbGRlIG5ldCAiw6AgdmVuaXIiIChyZXZlbnVzIHLDqWN1cnJlbnRzIMOgIHZlbmlyIG1vaW5zIGTDqXBlbnNlcwogICAgICAvLyByw6ljdXJyZW50ZXMgw6AgdmVuaXIpLCBwbHV0w7R0IHF1ZSBkZXV4IGNoaWZmcmVzIHPDqXBhcsOpcyA6IHBsdXMgc2ltcGxlCiAgICAgIC8vIMOgIGxpcmUgZCd1biBjb3VwIGQnxZNpbC4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUgc29udCBQQVMKICAgICAgLy8gYWpvdXTDqWVzIGljaSA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUgdnJhaWVzIHRyYW5zYWN0aW9ucwogICAgICAvLyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzIGRhbnMgYHRvdGFsc2AKICAgICAgLy8gY2ktZGVzc3VzIOKAlCBsZXMgYWpvdXRlciDDoCBub3V2ZWF1IGxlcyBjb21wdGVyYWl0IGVuIGRvdWJsZS4KICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IGN1dG9mZikgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIE3Dqm1lIHByaW5jaXBlIHF1ZSByZW5kZXJDYXRlZ29yeUNoYXJ0LCBjw7R0w6kgcmV2ZW51cyDigJQgcGFzIGRlIG5vdGUgIsOgCiAgICAvLyB2ZW5pciIgaWNpLCBlbGxlIHJlc3RlIHVuaXF1ZW1lbnQgc3VyIGxlIGNhbWVtYmVydCBkZXMgZMOpcGVuc2VzIHBvdXIKICAgIC8vIG5lIHBhcyBhZmZpY2hlciBsZSBtw6ptZSBjaGlmZnJlIG5ldCDDoCBkZXV4IGVuZHJvaXRzLgogICAgZnVuY3Rpb24gcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJpbmNvbWUiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGlmIChpbmNvbWVDYXRlZ29yeUNoYXJ0KSB7IGluY29tZUNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgICAgbW9udGhseVtrZXldW3R4LnR5cGVdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFRvdWpvdXJzIGluY2x1cmUgbGUgbW9pcyBlbiBjb3VycyAobcOqbWUgc2FucyB0cmFuc2FjdGlvbikgcydpbCBleGlzdGUKICAgICAgLy8gZGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBwb3VyIHF1J2lsIGFwcGFyYWlzc2Ugc2FucyBhdHRlbmRyZSBsYQogICAgICAvLyBwcmVtacOocmUgdHJhbnNhY3Rpb24gZHUgbW9pcy4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUKICAgICAgLy8gc29udCBwbHVzIGFqb3V0w6llcyBpY2kgw6AgbGEgbWFpbiA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUKICAgICAgLy8gdnJhaWVzIHRyYW5zYWN0aW9ucyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzCiAgICAgIC8vIGRhbnMgYG1vbnRobHlgIHZpYSBsYSBib3VjbGUgc3VyIGB0cmFuc2FjdGlvbnNgIGNpLWRlc3N1cyDigJQgY2UgcXVpCiAgICAgIC8vIG4nZXN0IHBhcyBlbmNvcmUgYXJyaXbDqSBlc3QgcsOpc3Vtw6kgYWlsbGV1cnMgKHNvbGRlIG5ldCAiw6AgdmVuaXIiKS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29tcGFyZXIgZGV1eCBtb2lzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3Qgc2VsZWN0QSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKTsKICAgICAgY29uc3Qgc2VsZWN0QiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKTsKCiAgICAgIGZvciAoY29uc3Qgc2VsZWN0IG9mIFtzZWxlY3RBLCBzZWxlY3RCXSkgewogICAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGlmIChtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkpIHNlbGVjdC52YWx1ZSA9IHByZXZpb3VzVmFsdWU7CiAgICAgIH0KICAgICAgLy8gUGFyIGTDqWZhdXQgOiBtb2lzIGVuIGNvdXJzIHZzIG1vaXMgcHLDqWPDqWRlbnQsIHNpIGxlcyBkZXV4IGV4aXN0ZW50LgogICAgICBpZiAoIXNlbGVjdEEudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDApIHNlbGVjdEEudmFsdWUgPSBtb250aHNbMF07CiAgICAgIGlmICghc2VsZWN0Qi52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMSkgc2VsZWN0Qi52YWx1ZSA9IG1vbnRoc1sxXTsKICAgIH0KCiAgICBmdW5jdGlvbiBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgbW9udGhLZXkpIHsKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICByZXR1cm4geyB0b3RhbHMsIHRvdGFsIH07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyTW9udGhDb21wYXJpc29uKCkgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtdGFibGUtd3JhcCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtZW1wdHkiKTsKICAgICAgY29uc3QgbW9udGhBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLnZhbHVlOwogICAgICBjb25zdCBtb250aEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikudmFsdWU7CgogICAgICBpZiAoIW1vbnRoQSB8fCAhbW9udGhCKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQSwgdG90YWw6IGdyYW5kQSB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNCLCB0b3RhbDogZ3JhbmRCIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhCKTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KFsuLi5PYmplY3Qua2V5cyh0b3RhbHNBKSwgLi4uT2JqZWN0LmtleXModG90YWxzQildKV0uc29ydCgKICAgICAgICAoYSwgYikgPT4gKHRvdGFsc0JbYl0gfHwgMCkgLSAodG90YWxzQVthXSB8fCAwKQogICAgICApOwoKICAgICAgY29uc3QgW3lhLCBtYV0gPSBtb250aEEuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgW3liLCBtYl0gPSBtb250aEIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgbGFiZWxBID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWEsIG1hIC0gMSwgMSkpOwogICAgICBjb25zdCBsYWJlbEIgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YiwgbWIgLSAxLCAxKSk7CgogICAgICAvLyBEaWZmID0gbW9udGFudCBkdSBtb2lzIEIgbW9pbnMgY2VsdWkgZHUgbW9pcyBBLiBQb3VyIGRlcyBkw6lwZW5zZXMsCiAgICAgIC8vIGTDqXBlbnNlciBQTFVTIChkaWZmIHBvc2l0aWYpIGVzdCBsYSBtYXV2YWlzZSBub3V2ZWxsZSDihpIgcm91Z2UgOyBlbgogICAgICAvLyBkw6lwZW5zZXIgTU9JTlMgKGRpZmYgbsOpZ2F0aWYpIOKGkiB2ZXJ0LgogICAgICBmdW5jdGlvbiBkaWZmQ2VsbChhLCBiKSB7CiAgICAgICAgY29uc3QgZGlmZiA9IGIgLSBhOwogICAgICAgIGlmIChNYXRoLmFicyhkaWZmKSA8IDAuMDEpIHJldHVybiBgPHRkPuKAlDwvdGQ+YDsKICAgICAgICBjb25zdCBjbHMgPSBkaWZmID4gMCA/ICJkaWZmLW5lZ2F0aXZlIiA6ICJkaWZmLXBvc2l0aXZlIjsKICAgICAgICByZXR1cm4gYDx0ZCBjbGFzcz0iJHtjbHN9Ij4ke2RpZmYgPiAwID8gIisiIDogIiJ9JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGlmZil9PC90ZD5gOwogICAgICB9CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPiR7bGFiZWxBfTwvdGg+PHRoPiR7bGFiZWxCfTwvdGg+PHRoPkRpZmbDqXJlbmNlPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgY2F0IG9mIGNhdGVnb3JpZXMpIHsKICAgICAgICBjb25zdCBhID0gdG90YWxzQVtjYXRdIHx8IDA7CiAgICAgICAgY29uc3QgYiA9IHRvdGFsc0JbY2F0XSB8fCAwOwogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHtlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiKX08L3RkPiR7ZGlmZkNlbGwoYSwgYil9PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDx0ciBjbGFzcz0idG90YWwtcm93Ij48dGQ+VG90YWwgZMOpcGVuc2VzPC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRBKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEIpfTwvdGQ+JHtkaWZmQ2VsbChncmFuZEEsIGdyYW5kQil9PC90cj5gOwogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ2FsY3VsZSwgcG91ciBjaGFxdWUgY2F0w6lnb3JpZSBkZSBkw6lwZW5zZSwgbGEgbW95ZW5uZSBtZW5zdWVsbGUsIGxlCiAgICAvLyBtb250YW50IGR1IG1vaXMgZW4gY291cnMsIGV0IGxhIHRlbmRhbmNlIChkaXJlY3Rpb24gKyByYXRpbyB2cwogICAgLy8gbW95ZW5uZSkuIFBhcnRhZ8OpIGVudHJlIGxlIHRhYmxlYXUgIk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUiCiAgICAvLyBldCBsZXMgY29uc2VpbHMgZCfDqXBhcmduZSwgcG91ciBuZSBwYXMgZHVwbGlxdWVyIGNldHRlIGxvZ2lxdWUuCiAgICBmdW5jdGlvbiBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoS2V5cyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKV0uc29ydCgpOwogICAgICBpZiAobW9udGhLZXlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIFtdOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleXNbbW9udGhLZXlzLmxlbmd0aCAtIDFdOwogICAgICBjb25zdCBuYk1vbnRocyA9IG1vbnRoS2V5cy5sZW5ndGg7CgogICAgICAvLyB0b3RhbCBwYXIgY2F0w6lnb3JpZSwgZXQgcGFyIGNhdMOpZ29yaWUrbW9pcyAocG91ciBpc29sZXIgbGUgbW9pcyBlbiBjb3VycykKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBjb25zdCBjdXJyZW50TW9udGhCeUNhdGVnb3J5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIikgY29udGludWU7CiAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpID09PSBjdXJyZW50TW9udGhLZXkpIHsKICAgICAgICAgIGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICByZXR1cm4gY2F0ZWdvcmllcy5tYXAoKGNhdCkgPT4gewogICAgICAgIGNvbnN0IGF2ZXJhZ2UgPSB0b3RhbHNCeUNhdGVnb3J5W2NhdF0gLyBuYk1vbnRoczsKICAgICAgICBjb25zdCBjdXJyZW50ID0gY3VycmVudE1vbnRoQnlDYXRlZ29yeVtjYXRdIHx8IDA7CiAgICAgICAgbGV0IGRpcmVjdGlvbiA9ICJzdGFibGUiOwogICAgICAgIGxldCByYXRpbyA9IDA7CiAgICAgICAgaWYgKGF2ZXJhZ2UgPiAwKSB7CiAgICAgICAgICByYXRpbyA9IChjdXJyZW50IC0gYXZlcmFnZSkgLyBhdmVyYWdlOwogICAgICAgICAgaWYgKHJhdGlvID4gMC4xNSkgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvIDwgLTAuMTUpIGRpcmVjdGlvbiA9ICJkb3duIjsKICAgICAgICB9IGVsc2UgaWYgKGN1cnJlbnQgPiAwKSB7CiAgICAgICAgICBkaXJlY3Rpb24gPSAidXAiOwogICAgICAgIH0KICAgICAgICByZXR1cm4geyBjYXRlZ29yeTogY2F0LCBhdmVyYWdlLCBjdXJyZW50LCByYXRpbywgZGlyZWN0aW9uIH07CiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRyZW5kLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC1lbXB0eSIpOwoKICAgICAgY29uc3QgdHJlbmRzID0gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh0cmVuZHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPk1veWVubmUvbW9pczwvdGg+PHRoPkNlIG1vaXMtY2k8L3RoPjx0aD5UZW5kYW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IHQgb2YgdHJlbmRzKSB7CiAgICAgICAgbGV0IHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZmxhdCI+4oaSIHN0YWJsZTwvc3Bhbj5gOwogICAgICAgIGlmICh0LmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdHJlbmRIdG1sID0gdC5hdmVyYWdlID4gMAogICAgICAgICAgICA/IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSArJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YAogICAgICAgICAgICA6IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSBub3V2ZWF1PC9zcGFuPmA7CiAgICAgICAgfSBlbHNlIGlmICh0LmRpcmVjdGlvbiA9PT0gImRvd24iKSB7CiAgICAgICAgICB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWRvd24iPuKGkyAke01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JTwvc3Bhbj5gOwogICAgICAgIH0KICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmF2ZXJhZ2UpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuY3VycmVudCl9PC90ZD48dGQ+JHt0cmVuZEh0bWx9PC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBCaWxhbiBhbm51ZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IE1PTlRIX1NIT1JUX0xBQkVMUyA9IFsKICAgICAgIkphbiIsICJGw6l2IiwgIk1hciIsICJBdnIiLCAiTWFpIiwgIkp1aW4iLCAiSnVpbCIsICJBb8O7dCIsICJTZXAiLCAiT2N0IiwgIk5vdiIsICJEw6ljIiwKICAgIF07CgogICAgZnVuY3Rpb24gcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0Iik7CiAgICAgIGNvbnN0IHllYXJzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSkpXS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBjdXJyZW50WWVhciA9IFN0cmluZyhuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCkpOwogICAgICBpZiAoIXllYXJzLmluY2x1ZGVzKGN1cnJlbnRZZWFyKSkgeWVhcnMudW5zaGlmdChjdXJyZW50WWVhcik7CgogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0geWVhcnMubWFwKCh5KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt5fSI+JHt5fTwvb3B0aW9uPmApLmpvaW4oIiIpOwogICAgICBzZWxlY3QudmFsdWUgPSB5ZWFycy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBjdXJyZW50WWVhcjsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFyID0gc2VsZWN0LnZhbHVlOwogICAgICBpZiAoIXllYXIpIHJldHVybjsKCiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC15ZWFybHkiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktZW1wdHkiKTsKICAgICAgY29uc3QgdGFibGVXcmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIik7CgogICAgICBjb25zdCB5ZWFyVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSA9PT0geWVhcik7CgogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGNvbnN0IGV4cGVuc2VCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IGluY29tZUJ5TW9udGggPSBBcnJheSgxMikuZmlsbCgwKTsKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHllYXJUcmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBtb250aEluZGV4ID0gTnVtYmVyKHR4LmV4cGVuc2VfZGF0ZS5zbGljZSg1LCA3KSkgLSAxOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgewogICAgICAgICAgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICBpbmNvbWVCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgZXhwZW5zZUJ5TW9udGhbbW9udGhJbmRleF0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICB0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBuZXQgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CgogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWV4cGVuc2VzIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktdG90YWwtaW5jb21lIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgICBjb25zdCBuZXRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktbmV0Iik7CiAgICAgIG5ldEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG5ldCk7CiAgICAgIG5ldEVsLmNsYXNzTmFtZSA9ICJ5ZWFybHktc3RhdC12YWx1ZSAiICsgKG5ldCA+PSAwID8gImluY29tZSIgOiAiZXhwZW5zZSIpOwoKICAgICAgaWYgKHllYXJseUNoYXJ0KSB7IHllYXJseUNoYXJ0LmRlc3Ryb3koKTsgeWVhcmx5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoeWVhclRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICB5ZWFybHlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHM6IE1PTlRIX1NIT1JUX0xBQkVMUywKICAgICAgICAgIGRhdGFzZXRzOiBbCiAgICAgICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBleHBlbnNlQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBpbmNvbWVCeU1vbnRoLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICAgICAgXSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogeyBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9IH0sCiAgICAgICAgfSwKICAgICAgfSk7CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPlRvdGFsPC90aD48dGg+JSBkZSBsJ2FubsOpZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYW1vdW50ID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdOwogICAgICAgIGNvbnN0IHBjdCA9IHRvdGFsRXhwZW5zZXMgPiAwID8gTWF0aC5yb3VuZCgoYW1vdW50IC8gdG90YWxFeHBlbnNlcykgKiAxMDApIDogMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYW1vdW50KX08L3RkPjx0ZD4ke3BjdH0lPC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiByZW5kZXJZZWFybHlPdmVydmlldyhhbGxUcmFuc2FjdGlvbnMpKTsKCiAgICBmdW5jdGlvbiByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKSB7CiAgICAgIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpOwogICAgICByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZVllYXJTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyWWVhcmx5T3ZlcnZpZXcodHJhbnNhY3Rpb25zKTsKICAgICAgc2V0dXBEYXNoYm9hcmRDaGlwcygpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFPDqWxlY3RldXIgZHUgdGFibGVhdSBkZSBib3JkIDogdW4gc2V1bCBibG9jIGFmZmljaMOpIMOgIGxhIGZvaXMgKHN1ciBsZXMKICAgIC8vIDcgZW1waWzDqXMpIHBvdXIgcXVlIMOnYSB0aWVubmUgc3VyIHVuIMOpY3JhbiBkZSB0w6lsw6lwaG9uZSBzYW5zIGTDqWZpbGVyCiAgICAvLyBzYW5zIGZpbi4gTGVzIGNhbGN1bHMvZ3JhcGhpcXVlcyBldXgtbcOqbWVzIG5lIGNoYW5nZW50IHBhcyDigJQgc2V1bGUgbGEKICAgIC8vIHZpc2liaWxpdMOpIGRlcyBibG9jcyBlc3QgcGlsb3TDqWUgcGFyIGxhIHB1Y2UgYWN0aXZlLgogICAgY29uc3QgREFTSEJPQVJEX1NFQ1RJT05TID0gWwogICAgICB7IGtleTogImV4cGVuc2VzIiwgbGFiZWw6ICJEw6lwZW5zZXMiLCByb3dJZDogImRhc2gtcm93LWV4cGVuc2VzIiB9LAogICAgICB7IGtleTogImluY29tZSIsIGxhYmVsOiAiUmV2ZW51cyIsIHJvd0lkOiAiZGFzaC1yb3ctaW5jb21lIiB9LAogICAgICB7IGtleTogImJ1ZGdldHMiLCBsYWJlbDogIkJ1ZGdldHMiLCByb3dJZDogImRhc2gtcm93LWJ1ZGdldHMiIH0sCiAgICAgIHsga2V5OiAiZXZvbHV0aW9uIiwgbGFiZWw6ICLDiXZvbHV0aW9uIiwgcm93SWQ6ICJkYXNoLXJvdy1ldm9sdXRpb24iIH0sCiAgICAgIHsga2V5OiAiY29tcGFyZSIsIGxhYmVsOiAiQ29tcGFyZXIiLCByb3dJZDogImRhc2gtcm93LWNvbXBhcmUiIH0sCiAgICAgIHsga2V5OiAidHJlbmQiLCBsYWJlbDogIlRlbmRhbmNlcyIsIHJvd0lkOiAiZGFzaC1yb3ctdHJlbmQiIH0sCiAgICAgIHsga2V5OiAieWVhcmx5IiwgbGFiZWw6ICJBbm7DqWUiLCByb3dJZDogImRhc2gtcm93LXllYXJseSIgfSwKICAgIF07CiAgICBsZXQgZGFzaGJvYXJkQWN0aXZlU2VjdGlvbiA9IERBU0hCT0FSRF9TRUNUSU9OU1swXS5rZXk7CiAgICBsZXQgZGFzaGJvYXJkQ2hpcHNCdWlsdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNob3dEYXNoYm9hcmRTZWN0aW9uKGtleSkgewogICAgICBkYXNoYm9hcmRBY3RpdmVTZWN0aW9uID0ga2V5OwogICAgICBmb3IgKGNvbnN0IHNlY3Rpb24gb2YgREFTSEJPQVJEX1NFQ1RJT05TKSB7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoc2VjdGlvbi5yb3dJZCkuY2xhc3NMaXN0LnRvZ2dsZSgiZGFzaC1oaWRkZW4iLCBzZWN0aW9uLmtleSAhPT0ga2V5KTsKICAgICAgfQogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIuZGFzaGJvYXJkLWNoaXAiKS5mb3JFYWNoKChjaGlwKSA9PiB7CiAgICAgICAgY2hpcC5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBjaGlwLmRhdGFzZXQuc2VjdGlvbiA9PT0ga2V5KTsKICAgICAgfSk7CiAgICAgIC8vIFVuIGdyYXBoaXF1ZSBDaGFydC5qcyByZWNyw6nDqSBwZW5kYW50IHF1ZSBzb24gYmxvYyDDqXRhaXQgbWFzcXXDqQogICAgICAvLyAoZGlzcGxheTpub25lKSBzZSByZXRyb3V2ZSBhdmVjIHVuIGNhbmV2YXMgZGUgdGFpbGxlIG51bGxlIGV0IG5lIHNlCiAgICAgIC8vIGNvcnJpZ2UgcGFzIHRvdXQgc2V1bCBlbiByZWRldmVuYW50IHZpc2libGUg4oCUIG9uIGZvcmNlIHVuIHJlc2l6ZQogICAgICAvLyBqdXN0ZSBhcHLDqHMgbCdhdm9pciBhZmZpY2jDqSwgcG91ciBsZXMgNCBncmFwaGlxdWVzIGNvbmNlcm7DqXMuCiAgICAgIGZvciAoY29uc3QgY2hhcnQgb2YgW2NhdGVnb3J5Q2hhcnQsIGluY29tZUNhdGVnb3J5Q2hhcnQsIGV2b2x1dGlvbkNoYXJ0LCB5ZWFybHlDaGFydF0pIHsKICAgICAgICBpZiAoY2hhcnQpIGNoYXJ0LnJlc2l6ZSgpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0dXBEYXNoYm9hcmRDaGlwcygpIHsKICAgICAgaWYgKGRhc2hib2FyZENoaXBzQnVpbHQpIHsKICAgICAgICBzaG93RGFzaGJvYXJkU2VjdGlvbihkYXNoYm9hcmRBY3RpdmVTZWN0aW9uKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1jaGlwLXJvdyIpOwogICAgICBmb3IgKGNvbnN0IHNlY3Rpb24gb2YgREFTSEJPQVJEX1NFQ1RJT05TKSB7CiAgICAgICAgY29uc3QgY2hpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGNoaXAudHlwZSA9ICJidXR0b24iOwogICAgICAgIGNoaXAuY2xhc3NOYW1lID0gImRhc2hib2FyZC1jaGlwIjsKICAgICAgICBjaGlwLmRhdGFzZXQuc2VjdGlvbiA9IHNlY3Rpb24ua2V5OwogICAgICAgIGNoaXAudGV4dENvbnRlbnQgPSBzZWN0aW9uLmxhYmVsOwogICAgICAgIGNoaXAuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93RGFzaGJvYXJkU2VjdGlvbihzZWN0aW9uLmtleSkpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChjaGlwKTsKICAgICAgfQogICAgICBkYXNoYm9hcmRDaGlwc0J1aWx0ID0gdHJ1ZTsKICAgICAgc2hvd0Rhc2hib2FyZFNlY3Rpb24oZGFzaGJvYXJkQWN0aXZlU2VjdGlvbik7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImFuc3dlciIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSAiIjsKICAgICAgfSBlbHNlIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VBbnN3ZXJCYW5uZXIodGV4dCkgewogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImFuc3dlciIpOwogICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgIH0KCiAgICAvLyBQcm9ub25jZSBsYSByw6lwb25zZSDDoCB1bmUgcXVlc3Rpb24gdm9jYWxlICgiQXNzaXN0YW50IHZvY2FsIHF1ZXN0aW9uIikuCiAgICAvLyBQdXIgYm9udXMgOiBzaSBsYSBzeW50aMOoc2Ugdm9jYWxlIG4nZXN0IHBhcyBkaXNwbyBvdSDDqWNob3VlLCBsYSByw6lwb25zZQogICAgLy8gcmVzdGUgYWZmaWNow6llIGRhbnMgbGUgYmFuZGVhdSwgZG9uYyBvbiBhdmFsZSBsJ2VycmV1ciBzYW5zIGJsb3F1ZXIuCiAgICBmdW5jdGlvbiBzcGVha1ZvaWNlQW5zd2VyKHRleHQpIHsKICAgICAgaWYgKCEoInNwZWVjaFN5bnRoZXNpcyIgaW4gd2luZG93KSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuY2FuY2VsKCk7CiAgICAgICAgY29uc3QgdXR0ZXJhbmNlID0gbmV3IFNwZWVjaFN5bnRoZXNpc1V0dGVyYW5jZSh0ZXh0KTsKICAgICAgICB1dHRlcmFuY2UubGFuZyA9ICJmci1GUiI7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5zcGVhayh1dHRlcmFuY2UpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQuCiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiB2b2NhbGUg4oCUIHF1YW5kIGwnSUEgYSB1biBkb3V0ZSBzdXIgbCdpbnRlcnByw6l0YXRpb24KICAgIC8vIChtb250YW50IGFwcHJveGltYXRpZiwgY2F0w6lnb3JpZSBpbmNlcnRhaW5lLi4uKSwgZWxsZSBkZW1hbmRlCiAgICAvLyBjb25maXJtYXRpb24gYXUgbGlldSBkJ2FwcGxpcXVlciBkaXJlY3RlbWVudC4gTCd1dGlsaXNhdGV1ciBwZXV0CiAgICAvLyByw6lwb25kcmUgZW4gYXBwdXlhbnQgc3VyICJDb25maXJtZXIiLyJBbm51bGVyIiwgT1UgZW4gcsOpLWFwcHV5YW50IHN1cgogICAgLy8gbGUgbWljcm8gcG91ciByw6lwb25kcmUgZGUgdml2ZSB2b2l4ICgib3VpIGMnZXN0IMOnYSIsICJub24sIGNoYW5nZSDDp2EKICAgIC8vIGVuIHJlc3RhdXJhbnQiLi4uKSDigJQgZGFucyBjZSBjYXMsIGxhIGRpY3TDqWUgc3VpdmFudGUgZXN0IGludGVycHLDqXTDqWUKICAgIC8vIGNvbW1lIHVuZSByw6lwb25zZSDDoCBDRVRURSBjb25maXJtYXRpb24gcGx1dMO0dCBxdWUgY29tbWUgdW5lIG5vdXZlbGxlCiAgICAvLyB0cmFuc2FjdGlvbiAodm9pciBwZW5kaW5nVm9pY2VBY3Rpb24sIHbDqXJpZmnDqSBkYW5zIGxlIGxpc3RlbmVyCiAgICAvLyAicmVzdWx0IiBkZSBsYSByZWNvbm5haXNzYW5jZSB2b2NhbGUgdW4gcGV1IHBsdXMgYmFzKS4KICAgIGxldCBwZW5kaW5nVm9pY2VBY3Rpb24gPSBudWxsOyAvLyB7IGtpbmQ6ICJ0cmFuc2FjdGlvbiIgfCAiZWRpdF9sYXN0IiwgZGF0YTogey4uLn0gfSBvdSBudWxsCiAgICBjb25zdCB2b2ljZUNvbmZpcm1CYW5uZXJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2b2ljZS1jb25maXJtLWJhbm5lciIpOwoKICAgIGZ1bmN0aW9uIGhpZGVWb2ljZUNvbmZpcm1CYW5uZXIoKSB7CiAgICAgIHBlbmRpbmdWb2ljZUFjdGlvbiA9IG51bGw7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5pbm5lckhUTUwgPSAiIjsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Vm9pY2VDb25maXJtQmFubmVyKGtpbmQsIHBhcnNlZCkgewogICAgICBwZW5kaW5nVm9pY2VBY3Rpb24gPSB7CiAgICAgICAga2luZCwKICAgICAgICBkYXRhOgogICAgICAgICAga2luZCA9PT0gInRyYW5zYWN0aW9uIgogICAgICAgICAgICA/IHBhcnNlZAogICAgICAgICAgICA6IHsKICAgICAgICAgICAgICAgIHRhcmdldDogcGFyc2VkLnRhcmdldCwKICAgICAgICAgICAgICAgIG5ld190eXBlOiBwYXJzZWQucmVxdWVzdGVkX25ld190eXBlLAogICAgICAgICAgICAgICAgbmV3X2NhdGVnb3J5OiBwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeSwKICAgICAgICAgICAgICB9LAogICAgICB9OwoKICAgICAgbGV0IHF1ZXN0aW9uOwogICAgICBpZiAoa2luZCA9PT0gInRyYW5zYWN0aW9uIikgewogICAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgICAgY29uc3QgY2F0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1twYXJzZWQuY2F0ZWdvcnldIHx8IHBhcnNlZC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkZXNjUGFydCA9IHBhcnNlZC5kZXNjcmlwdGlvbiA/IGAgKCR7cGFyc2VkLmRlc2NyaXB0aW9ufSlgIDogIiI7CiAgICAgICAgcXVlc3Rpb24gPQogICAgICAgICAgYCR7dmVyYn0gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCl9IGVuICR7Y2F0TGFiZWx9JHtkZXNjUGFydH0sIGAgKwogICAgICAgICAgYGxlICR7ZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUocGFyc2VkLmV4cGVuc2VfZGF0ZSkpfSDigJQgYydlc3QgYmllbiDDp2EgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgLy8gZWRpdF9sYXN0IDogb24gcmV0cm91dmUgbGEgdHJhbnNhY3Rpb24gY2libMOpZSBkYW5zIGFsbFRyYW5zYWN0aW9ucwogICAgICAgIC8vIChkw6lqw6AgdHJpw6kgcGFyIGRhdGUgZMOpY3JvaXNzYW50ZSkgcG91ciBkb25uZXIgdW4gY29udGV4dGUgdXRpbGUuCiAgICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoKHQpID0+IHsKICAgICAgICAgIGlmIChwYXJzZWQudGFyZ2V0ID09PSAibGFzdF9leHBlbnNlIikgcmV0dXJuIHQudHlwZSA9PT0gImV4cGVuc2UiOwogICAgICAgICAgaWYgKHBhcnNlZC50YXJnZXQgPT09ICJsYXN0X2luY29tZSIpIHJldHVybiB0LnR5cGUgPT09ICJpbmNvbWUiOwogICAgICAgICAgcmV0dXJuIHRydWU7CiAgICAgICAgfSk7CiAgICAgICAgY29uc3QgdGFyZ2V0ID0gY2FuZGlkYXRlc1swXTsKICAgICAgICBjb25zdCB0YXJnZXRMYWJlbCA9IHRhcmdldAogICAgICAgICAgPyBgJHt0YXJnZXQudHlwZSA9PT0gImluY29tZSIgPyAibGUgcmV2ZW51IiA6ICJsYSBkw6lwZW5zZSJ9IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRhcmdldC5hbW91bnQpfWAgKwogICAgICAgICAgICAodGFyZ2V0LmRlc2NyaXB0aW9uID8gYCAoJHt0YXJnZXQuZGVzY3JpcHRpb259KWAgOiAiIikKICAgICAgICAgIDogImxhIHRyYW5zYWN0aW9uIGNvcnJlc3BvbmRhbnRlIjsKICAgICAgICBjb25zdCBjaGFuZ2VzID0gW107CiAgICAgICAgaWYgKHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X3R5cGUpIHsKICAgICAgICAgIGNoYW5nZXMucHVzaChgdHlwZSA6ICR7cGFyc2VkLnJlcXVlc3RlZF9uZXdfdHlwZSA9PT0gImluY29tZSIgPyAicmV2ZW51IiA6ICJkw6lwZW5zZSJ9YCk7CiAgICAgICAgfQogICAgICAgIGlmIChwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeSkgewogICAgICAgICAgY2hhbmdlcy5wdXNoKGBjYXTDqWdvcmllIDogJHthbGxDYXRlZ29yeUxhYmVsc1twYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeV0gfHwgcGFyc2VkLnJlcXVlc3RlZF9uZXdfY2F0ZWdvcnl9YCk7CiAgICAgICAgfQogICAgICAgIHF1ZXN0aW9uID0gYE1vZGlmaWVyICR7dGFyZ2V0TGFiZWx9IOKAlCAke2NoYW5nZXMuam9pbigiLCAiKSB8fCAiYXVjdW4gY2hhbmdlbWVudCByZWNvbm51In0g4oCUIGMnZXN0IGJpZW4gw6dhID9gOwogICAgICB9CgogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICB0ZXh0LnRleHRDb250ZW50ID0gcXVlc3Rpb247CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmFwcGVuZENoaWxkKHRleHQpOwoKICAgICAgY29uc3QgY29udHJvbHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgY29udHJvbHMuY2xhc3NOYW1lID0gInZvaWNlLWNvbmZpcm0tY29udHJvbHMiOwoKICAgICAgY29uc3QgY29uZmlybUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBjb25maXJtQnRuLnRleHRDb250ZW50ID0gIuKchSBDb25maXJtZXIiOwogICAgICBjb25maXJtQnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgIGNvbmZpcm1CdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbigiY29uZmlybSIpKTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoY29uZmlybUJ0bik7CgogICAgICBjb25zdCBjYW5jZWxCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgY2FuY2VsQnRuLnRleHRDb250ZW50ID0gIuKdjCBBbm51bGVyIjsKICAgICAgY2FuY2VsQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgY2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3VibWl0Vm9pY2VDb25maXJtRGVjaXNpb24oImNhbmNlbCIpKTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoY2FuY2VsQnRuKTsKCiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKCiAgICAgIGNvbnN0IGhpbnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIGhpbnQuY2xhc3NOYW1lID0gInZvaWNlLWNvbmZpcm0taGludCI7CiAgICAgIGhpbnQudGV4dENvbnRlbnQgPSAi8J+OpCBUdSBwZXV4IGF1c3NpIHLDqXBvbmRyZSDDoCBsYSB2b2l4IGVuIHLDqS1hcHB1eWFudCBzdXIgbGUgbWljcm8uIjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQoaGludCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc3VibWl0Vm9pY2VDb25maXJtRGVjaXNpb24oZGVjaXNpb24pIHsKICAgICAgaWYgKCFwZW5kaW5nVm9pY2VBY3Rpb24pIHJldHVybjsKICAgICAgY29uc3QgeyBraW5kLCBkYXRhIH0gPSBwZW5kaW5nVm9pY2VBY3Rpb247CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvY29uZmlybSIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBkZWNpc2lvbiwga2luZCwgcGVuZGluZzogZGF0YSB9KSwKICAgICAgICB9KTsKICAgICAgICBhd2FpdCBoYW5kbGVWb2ljZUNvbmZpcm1SZXN1bHQocmVzdWx0KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gaGFuZGxlVm9pY2VDb25maXJtUmVzdWx0KHJlc3VsdCkgewogICAgICBoaWRlVm9pY2VDb25maXJtQmFubmVyKCk7CiAgICAgIGlmIChyZXN1bHQuZGVjaXNpb24gPT09ICJjYW5jZWwiKSB7CiAgICAgICAgc2hvd1RvYXN0KCJBbm51bMOpIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIC8vIFNpbm9uLCByZXN1bHQgZXN0IHVuIHLDqXN1bHRhdCBkw6lqw6AgZmluYWxpc8OpIChWb2ljZVBhcnNlUmVzdWx0IHBvdXIKICAgICAgLy8gdW5lIHRyYW5zYWN0aW9uLCBWb2ljZUVkaXRSZXN1bHQgcG91ciB1biBlZGl0X2xhc3QpIDogb24gbGUgdHJhaXRlCiAgICAgIC8vIGV4YWN0ZW1lbnQgY29tbWUgdW4gcsOpc3VsdGF0IGRlIGRpY3TDqWUgbm9ybWFsLgogICAgICBhd2FpdCBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHJlc3VsdCk7CiAgICB9CgogICAgLy8gUG9pbnQgZCdlbnRyw6llIGNvbW11biBwb3VyIGxlIHLDqXN1bHRhdCBkJ3VuZSBkaWN0w6llICJmcmHDrmNoZSIgKGVudm95w6llCiAgICAvLyDDoCAvYXBpL3ZvaWNlL3BhcnNlKSBFVCBwb3VyIGxlIHLDqXN1bHRhdCBkw6lqw6AgZmluYWxpc8OpIGQndW5lCiAgICAvLyBjb25maXJtYXRpb24g4oCUIGxlcyBkZXV4IGNoZW1pbnMgcmV0b21iZW50IHN1ciBsZSBtw6ptZSB0cmFpdGVtZW50IHVuZQogICAgLy8gZm9pcyBxdSdvbiBzYWl0IHF1J2lsIG4neSBhIHBsdXMgZGUgZG91dGUgw6AgbGV2ZXIuCiAgICBhc3luYyBmdW5jdGlvbiBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHBhcnNlZCkgewogICAgICBpZiAocGFyc2VkLmludGVudCA9PT0gInF1ZXN0aW9uIikgewogICAgICAgIHNldFZvaWNlQW5zd2VyQmFubmVyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgIHNwZWFrVm9pY2VBbnN3ZXIocGFyc2VkLmFuc3dlcik7CiAgICAgIH0gZWxzZSBpZiAocGFyc2VkLmludGVudCA9PT0gImVkaXRfbGFzdCIpIHsKICAgICAgICBpZiAocGFyc2VkLnBlbmRpbmcpIHsKICAgICAgICAgIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoImVkaXRfbGFzdCIsIHBhcnNlZCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQW5zd2VyQmFubmVyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgc3BlYWtWb2ljZUFuc3dlcihwYXJzZWQuYW5zd2VyKTsKICAgICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAocGFyc2VkLm5lZWRzX2NvbmZpcm1hdGlvbikgewogICAgICAgIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoInRyYW5zYWN0aW9uIiwgcGFyc2VkKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBhd2FpdCBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBTcGVlY2hSZWNvZ25pdGlvbkN0b3IgPSB3aW5kb3cuU3BlZWNoUmVjb2duaXRpb24gfHwgd2luZG93LndlYmtpdFNwZWVjaFJlY29nbml0aW9uOwoKICAgIGlmICghU3BlZWNoUmVjb2duaXRpb25DdG9yKSB7CiAgICAgIG1pY0J0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIG1pY0J0bi50aXRsZSA9ICJEaWN0w6llIHZvY2FsZSBub24gZGlzcG9uaWJsZSBzdXIgY2UgbmF2aWdhdGV1ciAodXRpbGlzZSBDaHJvbWUgb3UgRWRnZSkiOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgcmVjb2duaXRpb24gPSBuZXcgU3BlZWNoUmVjb2duaXRpb25DdG9yKCk7CiAgICAgIHJlY29nbml0aW9uLmxhbmcgPSAiZnItRlIiOwogICAgICByZWNvZ25pdGlvbi5jb250aW51b3VzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLmludGVyaW1SZXN1bHRzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLm1heEFsdGVybmF0aXZlcyA9IDE7CgogICAgICBsZXQgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInN0YXJ0IiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gdHJ1ZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgibGlzdGVuaW5nIik7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIkplIHQnw6ljb3V0ZeKApiIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVuZCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlcnJvciIsIChldmVudCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgaWYgKGV2ZW50LmVycm9yID09PSAibm8tc3BlZWNoIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIlJpZW4gZW50ZW5kdSwgcsOpZXNzYWllLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMjAwMCk7CiAgICAgICAgfSBlbHNlIGlmIChldmVudC5lcnJvciA9PT0gIm5vdC1hbGxvd2VkIiB8fCBldmVudC5lcnJvciA9PT0gInNlcnZpY2Utbm90LWFsbG93ZWQiKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiTWljcm8gcmVmdXPDqSDigJQgYXV0b3Jpc2UgbCdhY2PDqHMgYXUgbWljcm8gZGFucyB0b24gbmF2aWdhdGV1ci4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDQwMDApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcihudWxsKTsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIG1pY3JvIDogIiArIGV2ZW50LmVycm9yLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigicmVzdWx0IiwgYXN5bmMgKGV2ZW50KSA9PiB7CiAgICAgICAgY29uc3QgdHJhbnNjcmlwdCA9IGV2ZW50LnJlc3VsdHNbMF1bMF0udHJhbnNjcmlwdDsKICAgICAgICBzZXRWb2ljZUJhbm5lcihgIiR7dHJhbnNjcmlwdH0iYCk7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoInByb2Nlc3NpbmciKTsKICAgICAgICBsZXQgYmFubmVyRGVsYXkgPSAxNTAwOwogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAocGVuZGluZ1ZvaWNlQWN0aW9uKSB7CiAgICAgICAgICAgIC8vIFVuZSBiYW5uacOocmUgZGUgY29uZmlybWF0aW9uIGVzdCBhZmZpY2jDqWUgOiBjZXR0ZSBkaWN0w6llIGVzdAogICAgICAgICAgICAvLyB1bmUgcsOpcG9uc2UgKCJvdWkiLCAibm9uIiwgImNoYW5nZSDDp2EgZW4uLi4iKSDDoCBDRVRURQogICAgICAgICAgICAvLyBjb25maXJtYXRpb24sIHBhcyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24uCiAgICAgICAgICAgIGNvbnN0IHsga2luZCwgZGF0YSB9ID0gcGVuZGluZ1ZvaWNlQWN0aW9uOwogICAgICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9jb25maXJtIiwgewogICAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcmVwbHlfdGV4dDogdHJhbnNjcmlwdCwga2luZCwgcGVuZGluZzogZGF0YSB9KSwKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlQ29uZmlybVJlc3VsdChyZXN1bHQpOwogICAgICAgICAgICBiYW5uZXJEZWxheSA9IDQwMDA7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRleHQ6IHRyYW5zY3JpcHQgfSksCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBpZiAocGFyc2VkLmludGVudCA9PT0gInF1ZXN0aW9uIikgewogICAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNjAwMDsKICAgICAgICAgICAgfSBlbHNlIGlmIChwYXJzZWQubmVlZHNfY29uZmlybWF0aW9uIHx8IHBhcnNlZC5wZW5kaW5nKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSAxNTAwOyAvLyBsYSBiYW5uacOocmUgZGUgY29uZmlybWF0aW9uIHByZW5kIGxlIHJlbGFpcyB2aXN1ZWxsZW1lbnQKICAgICAgICAgICAgfSBlbHNlIGlmIChwYXJzZWQuaW50ZW50ID09PSAiZWRpdF9sYXN0IikgewogICAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNDAwMDsKICAgICAgICAgICAgfQogICAgICAgICAgICBhd2FpdCBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHBhcnNlZCk7CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfSBmaW5hbGx5IHsKICAgICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCBiYW5uZXJEZWxheSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTdWdnZXN0aW9ucyBkZSBjYXTDqWdvcmllIOKAlCB1bmlxdWVtZW50IGFwcsOocyB1bmUgc2Fpc2llIHBhciBkaWN0w6llCiAgICAvLyB2b2NhbGUgKHVuZSBmYXV0ZSBkZSBmcmFwcGUgZW4gc2Fpc2llIG1hbnVlbGxlLCBjJ2VzdCB1bmUgZXJyZXVyIGRlCiAgICAvLyBsJ3V0aWxpc2F0ZXVyLCBwYXMgbGEgcGVpbmUgZGUgbGUgcmVsYW5jZXIgZGVzc3VzKS4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEID0gMzsKCiAgICAvLyBNb3RzIGRlIGxpYWlzb24gZnJhbsOnYWlzIMOgIGlnbm9yZXIgOiAiY2FzaW5vIiwgImF1IGNhc2lubyIgZXQgInBlcnRlIGF1CiAgICAvLyBjYXNpbm8iIGRvaXZlbnQgw6p0cmUgcmVjb25udXMgY29tbWUgbGEgbcOqbWUgaWTDqWUgbWFsZ3LDqSBsZXMgbW90cwogICAgLy8gZGlmZsOpcmVudHMgYXV0b3VyLCBkb25jIG9uIGNvbXBhcmUgZGVzIG1vdHMtY2zDqXMgc2lnbmlmaWNhdGlmcyBwbHV0w7R0CiAgICAvLyBxdWUgbGEgZGVzY3JpcHRpb24gY29tcGzDqHRlIHRlbGxlIHF1ZWxsZS4KICAgIGNvbnN0IERFU0NSSVBUSU9OX1NUT1BXT1JEUyA9IG5ldyBTZXQoWwogICAgICAiYSIsICJhdSIsICJhdXgiLCAiZGUiLCAiZHUiLCAiZGVzIiwgImQiLCAibGUiLCAibGEiLCAibGVzIiwgImwiLAogICAgICAidW4iLCAidW5lIiwgImNlIiwgImNldCIsICJjZXR0ZSIsICJjZXMiLCAibW9uIiwgIm1hIiwgIm1lcyIsCiAgICAgICJ0b24iLCAidGEiLCAidGVzIiwgInNvbiIsICJzYSIsICJzZXMiLCAibm90cmUiLCAibm9zIiwgInZvdHJlIiwKICAgICAgInZvcyIsICJsZXVyIiwgImxldXJzIiwgImNoZXoiLCAic3VyIiwgImRhbnMiLCAicG91ciIsICJhdmVjIiwKICAgICAgImV0IiwgIm91IiwgImVuIiwgInBhciIsCiAgICBdKTsKCiAgICAvLyBFeHRyYWl0IGxlcyBtb3RzLWNsw6lzIHNpZ25pZmljYXRpZnMgZCd1bmUgZGVzY3JpcHRpb24gKGFjY2VudHMgZXQKICAgIC8vIGNhc3NlIGlnbm9yw6lzLCBtb3RzIGRlIGxpYWlzb24gZXQgbW90cyB0cm9wIGNvdXJ0cyDDqWNhcnTDqXMpLgogICAgZnVuY3Rpb24gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMoZGVzYykgewogICAgICBjb25zdCBub3JtYWxpemVkID0gKGRlc2MgfHwgIiIpCiAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikKICAgICAgICAucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gcmV0aXJlIGxlcyBhY2NlbnRzICjDqSAtPiBlLCBldGMuKQogICAgICAgIC50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCB0b2tlbnMgPSBub3JtYWxpemVkLnNwbGl0KC9bXmEtejAtOV0rLykuZmlsdGVyKEJvb2xlYW4pOwogICAgICByZXR1cm4gbmV3IFNldCgKICAgICAgICB0b2tlbnMuZmlsdGVyKCh0KSA9PiB0Lmxlbmd0aCA+PSAzICYmICFERVNDUklQVElPTl9TVE9QV09SRFMuaGFzKHQpKQogICAgICApOwogICAgfQoKICAgIGZ1bmN0aW9uIGtleXdvcmRzSW50ZXJzZWN0KGEsIGIpIHsKICAgICAgZm9yIChjb25zdCB0b2tlbiBvZiBhKSB7CiAgICAgICAgaWYgKGIuaGFzKHRva2VuKSkgcmV0dXJuIHRydWU7CiAgICAgIH0KICAgICAgcmV0dXJuIGZhbHNlOwogICAgfQoKICAgIC8vIFJldGlyZSBkJ3VuZSBkZXNjcmlwdGlvbiBsZXMgbW90cyBxdWkgb250IHNlcnZpIMOgIGTDqXRlY3RlciBsYQogICAgLy8gY2F0w6lnb3JpZSAoZXguICJjYXNpbm8iIHVuZSBmb2lzIHF1ZSBsYSBjYXTDqWdvcmllICJjYXNpbm8iIGV4aXN0ZSkgOgogICAgLy8gdW5lIGZvaXMgcXVlIGxhIGNhdMOpZ29yaWUgcG9ydGUgbCdpbmZvcm1hdGlvbiwgbGEgcsOpcMOpdGVyIGRhbnMgbGEKICAgIC8vIGRlc2NyaXB0aW9uIG4nYXBwb3J0ZSBwbHVzIHJpZW4uIFJlbnZvaWUgbnVsbCBzaSBsYSBkZXNjcmlwdGlvbgogICAgLy8gZGV2aWVudCB2aWRlIHVuZSBmb2lzIGNlcyBtb3RzIHJldGlyw6lzLgogICAgZnVuY3Rpb24gc3RyaXBNYXRjaGVkS2V5d29yZHNGcm9tRGVzY3JpcHRpb24oZGVzY3JpcHRpb24sIGtleXdvcmRzKSB7CiAgICAgIGlmICghZGVzY3JpcHRpb24gfHwgIWtleXdvcmRzIHx8IGtleXdvcmRzLnNpemUgPT09IDApIHJldHVybiBkZXNjcmlwdGlvbiB8fCBudWxsOwogICAgICBjb25zdCB3b3JkcyA9IGRlc2NyaXB0aW9uLnNwbGl0KC9ccysvKS5maWx0ZXIoQm9vbGVhbik7CiAgICAgIGNvbnN0IGtlcHQgPSB3b3Jkcy5maWx0ZXIoKHcpID0+IHsKICAgICAgICBjb25zdCBub3JtID0gdwogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikKICAgICAgICAgIC5yZXBsYWNlKC9bzIAtza9dL2csICIiKQogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0vZywgIiIpOwogICAgICAgIHJldHVybiAha2V5d29yZHMuaGFzKG5vcm0pOwogICAgICB9KTsKICAgICAgY29uc3QgY2xlYW5lZCA9IGtlcHQuam9pbigiICIpLnRyaW0oKTsKICAgICAgcmV0dXJuIGNsZWFuZWQgfHwgbnVsbDsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBkaXNtaXNzU3VnZ2VzdGlvbihrZXkpIHsKICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuYWRkKGtleSk7IC8vIGltbcOpZGlhdCBjw7R0w6kgVUksIHBhcyBiZXNvaW4gZCdhdHRlbmRyZSBsZSBzZXJ2ZXVyCiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGtleSB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSBsYSBzdWdnZXN0aW9uIHLDqWFwcGFyYcOudCB1bmUgZm9pcyBzdXIgdW4KICAgICAgICAvLyBhdXRyZSBhcHBhcmVpbCBzaSBsYSBzYXV2ZWdhcmRlIHNlcnZldXIgYSDDqWNob3XDqS4KICAgICAgfQogICAgfQoKICAgIC8vIFJlZ2FyZGUgc2kgbGEgZGVzY3JpcHRpb24gZGUgbGEgdHJhbnNhY3Rpb24gcXVpIHZpZW50IGQnw6p0cmUgYWpvdXTDqWUKICAgIC8vIChvdSBjb3JyaWfDqWUpIMOgIGxhIHZvaXggcmV2aWVudCBzb3V2ZW50LCBldCBzaSBvdWkgOgogICAgLy8gLSBzb2l0IGVsbGUgYSB0b3Vqb3VycyDDqXTDqSByYW5nw6llIGRhbnMgIkF1dHJlIiDihpIgb24gcHJvcG9zZSBkZSBjcsOpZXIKICAgIC8vICAgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGRlIGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpIDsKICAgIC8vIC0gc29pdCBlbGxlIGEgY2V0dGUgZm9pcyB1bmUgY2F0w6lnb3JpZSBkaWZmw6lyZW50ZSBkZSBkJ2hhYml0dWRlIOKGkiBvbgogICAgLy8gICBkZW1hbmRlIHNpIGNlIG4nZXN0IHBhcyB1bmUgZXJyZXVyIDsKICAgIC8vIC0gc29pdCBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZSBlc3QgZMOpasOgIGJpZW4gY2xhc3PDqWUsCiAgICAvLyAgIG1haXMgZCdhbmNpZW5uZXMgdHJhbnNhY3Rpb25zIHNpbWlsYWlyZXMgdHJhw65uZW50IGRhbnMgdW5lIGF1dHJlCiAgICAvLyAgIGNhdMOpZ29yaWUgKGV4LiAicGVydGUgYXUgY2FzaW5vIiBjbGFzc8OpZSBlbiAiTG9pc2lycyIgYXZhbnQgcXVlCiAgICAvLyAgICJjYXNpbm8iIGV4aXN0ZSBjb21tZSBjYXTDqWdvcmllKSDihpIgb24gcHJvcG9zZSBkZSBsZXMgYWxpZ25lci4KICAgIGZ1bmN0aW9uIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKGRlc2NyaXB0aW9uLCB0eXBlKSB7CiAgICAgIGNvbnN0IGtleXdvcmRzID0gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMoZGVzY3JpcHRpb24pOwogICAgICBpZiAoa2V5d29yZHMuc2l6ZSA9PT0gMCkgcmV0dXJuOwoKICAgICAgY29uc3Qgc2FtZURlc2NyaXB0aW9uID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigKICAgICAgICAodHgpID0+CiAgICAgICAgICB0eC50eXBlID09PSB0eXBlICYmCiAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModHguZGVzY3JpcHRpb24pKQogICAgICApOwogICAgICBpZiAoc2FtZURlc2NyaXB0aW9uLmxlbmd0aCA8IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEKSByZXR1cm47CgogICAgICBjb25zdCBjb3VudHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiBzYW1lRGVzY3JpcHRpb24pIGNvdW50c1t0eC5jYXRlZ29yeV0gPSAoY291bnRzW3R4LmNhdGVnb3J5XSB8fCAwKSArIDE7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBPYmplY3Qua2V5cyhjb3VudHMpOwogICAgICBjb25zdCBkb21pbmFudCA9IGNhdGVnb3JpZXMucmVkdWNlKChhLCBiKSA9PiAoY291bnRzW2FdID49IGNvdW50c1tiXSA/IGEgOiBiKSk7CiAgICAgIGNvbnN0IGxhdGVzdCA9IHNhbWVEZXNjcmlwdGlvblswXTsgLy8gYWxsVHJhbnNhY3Rpb25zIGVzdCB0cmnDqSBwYXIgZGF0ZSBkw6ljcm9pc3NhbnRlCgogICAgICAvLyBDbMOpIHN0YWJsZSBiYXPDqWUgc3VyIGxlcyBtb3RzLWNsw6lzICh0cmnDqXMpIHBsdXTDtHQgcXVlIGxhIGRlc2NyaXB0aW9uCiAgICAgIC8vIGV4YWN0ZSwgcG91ciBxdWUgbGUgIklnbm9yZXIiIHJlc3RlIHZhbGFibGUgbcOqbWUgc2kgbGEgZm9ybXVsYXRpb24KICAgICAgLy8gdmFyaWUgdW4gcGV1IGQndW5lIGZvaXMgw6AgbCdhdXRyZS4KICAgICAgY29uc3Qgc2lnbmF0dXJlID0gWy4uLmtleXdvcmRzXS5zb3J0KCkuam9pbigiKyIpOwoKICAgICAgbGV0IHN1Z2dlc3Rpb24gPSBudWxsOwogICAgICBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgbWlzbWF0Y2g6JHt0eXBlfToke3NpZ25hdHVyZX06JHtsYXRlc3QuY2F0ZWdvcnl9YCwKICAgICAgICAgIGtpbmQ6ICJtaXNtYXRjaCIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIGRvbWluYW50LAogICAgICAgICAgY3VycmVudDogbGF0ZXN0LmNhdGVnb3J5LAogICAgICAgICAga2V5d29yZHMsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ID09PSBsYXRlc3QuY2F0ZWdvcnkpLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID09PSAxICYmIGRvbWluYW50ID09PSAiYXV0cmUiKSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYGdlbmVyaWM6JHt0eXBlfToke3NpZ25hdHVyZX1gLAogICAgICAgICAga2luZDogImdlbmVyaWMiLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICBrZXl3b3JkcywKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24ubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSA9PT0gZG9taW5hbnQpIHsKICAgICAgICAvLyBMYSB0cmFuc2FjdGlvbiBsYSBwbHVzIHLDqWNlbnRlIGVzdCBkw6lqw6AgYmllbiBjbGFzc8OpZSwgbWFpcwogICAgICAgIC8vIGQnYXV0cmVzIHRyYW5zYWN0aW9ucyBzaW1pbGFpcmVzIHNvbnQgcmVzdMOpZXMgZGFucyB1bmUgY2F0w6lnb3JpZQogICAgICAgIC8vIG1pbm9yaXRhaXJlICh0eXBpcXVlbWVudCBwbHVzIGFuY2llbm5lcywgY2xhc3PDqWVzIGF2YW50IHF1ZSBsYQogICAgICAgIC8vIGNhdMOpZ29yaWUgZG9taW5hbnRlIGFjdHVlbGxlIG4nZXhpc3RlKSA6IG9uIHByb3Bvc2UgZGUgbGVzIGFsaWduZXIuCiAgICAgICAgY29uc3Qgb3V0bGllcnMgPSBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgIT09IGRvbWluYW50KTsKICAgICAgICBpZiAob3V0bGllcnMubGVuZ3RoID4gMCkgewogICAgICAgICAgY29uc3Qgb3V0bGllckNhdGVnb3JpZXMgPSBbLi4ubmV3IFNldChvdXRsaWVycy5tYXAoKHR4KSA9PiB0eC5jYXRlZ29yeSkpXTsKICAgICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICAgIGtleTogYHJlY29uY2lsZToke3R5cGV9OiR7c2lnbmF0dXJlfToke2RvbWluYW50fWAsCiAgICAgICAgICAgIGtpbmQ6ICJyZWNvbmNpbGUiLAogICAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgICB0eXBlLAogICAgICAgICAgICBkb21pbmFudCwKICAgICAgICAgICAgb3V0bGllckNhdGVnb3JpZXMsCiAgICAgICAgICAgIGtleXdvcmRzLAogICAgICAgICAgICB0eElkczogb3V0bGllcnMubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgICAgfTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGlmICghc3VnZ2VzdGlvbiB8fCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5oYXMoc3VnZ2VzdGlvbi5rZXkpKSByZXR1cm47CiAgICAgIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbik7CiAgICB9CgogICAgZnVuY3Rpb24gaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCkgewogICAgICBsZXQgaWRzVG9GaXg7CiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJyZWNvbmNpbGUiKSB7CiAgICAgICAgLy8gSWNpIHN1Z2dlc3Rpb24udHhJZHMgZXN0IGTDqWrDoCBleGFjdGVtZW50IGwnZW5zZW1ibGUgZGVzIGFuY2llbm5lcwogICAgICAgIC8vIHRyYW5zYWN0aW9ucyDDoCBhbGlnbmVyIChwYXMgZGUgImRlcm5pw6hyZSB0cmFuc2FjdGlvbiIgw6AgcGFydCkgOiBsZQogICAgICAgIC8vIHRleHRlIGRlIGxhIGJhbm5pw6hyZSBsJ2Fubm9uY2UgZMOpasOgLCBwYXMgYmVzb2luIGQndW5lIGNvbmZpcm1hdGlvbgogICAgICAgIC8vIHN1cHBsw6ltZW50YWlyZS4KICAgICAgICBpZHNUb0ZpeCA9IHN1Z2dlc3Rpb24udHhJZHM7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgW2xhdGVzdElkLCAuLi5vdGhlcnNdID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgICBpZHNUb0ZpeCA9IFtsYXRlc3RJZF07CiAgICAgICAgaWYgKAogICAgICAgICAgb3RoZXJzLmxlbmd0aCA+IDAgJiYKICAgICAgICAgIChhd2FpdCBzaG93Q29uZmlybShgQ29ycmlnZXIgYXVzc2kgbGVzICR7b3RoZXJzLmxlbmd0aH0gdHJhbnNhY3Rpb24ocykgcHLDqWPDqWRlbnRlKHMpIGF2ZWMgbGEgbcOqbWUgZGVzY3JpcHRpb24gP2ApKQogICAgICAgICkgewogICAgICAgICAgaWRzVG9GaXgucHVzaCguLi5vdGhlcnMpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgdHJ5IHsKICAgICAgICBmb3IgKGNvbnN0IGlkIG9mIGlkc1RvRml4KSB7CiAgICAgICAgICBjb25zdCBwYXlsb2FkID0geyBjYXRlZ29yeTogdGFyZ2V0VmFsdWUgfTsKICAgICAgICAgIC8vIExhIGNhdMOpZ29yaWUgcG9ydGUgbWFpbnRlbmFudCBsJ2luZm9ybWF0aW9uIDogb24gcmV0aXJlIGRlcwogICAgICAgICAgLy8gZGVzY3JpcHRpb25zIGxlKHMpIG1vdChzKS1jbMOpKHMpIHF1aSBvbnQgc2Vydmkgw6AgbGEgZMOpdGVjdGVyLAogICAgICAgICAgLy8gcG91ciDDqXZpdGVyIGxhIHJlZG9uZGFuY2UgImNhc2lubyIgZW4gY2F0w6lnb3JpZSBFVCBlbiBub3RlLgogICAgICAgICAgY29uc3QgdHggPSBhbGxUcmFuc2FjdGlvbnMuZmluZCgodCkgPT4gdC5pZCA9PT0gaWQpOwogICAgICAgICAgaWYgKHR4ICYmIHN1Z2dlc3Rpb24ua2V5d29yZHMpIHsKICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKHR4LmRlc2NyaXB0aW9uLCBzdWdnZXN0aW9uLmtleXdvcmRzKTsKICAgICAgICAgICAgaWYgKGNsZWFuZWQgIT09ICh0eC5kZXNjcmlwdGlvbiB8fCBudWxsKSkgcGF5bG9hZC5kZXNjcmlwdGlvbiA9IGNsZWFuZWQ7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIHNob3dUb2FzdChgQ2F0w6lnb3JpZSBtaXNlIMOgIGpvdXIgOiAke3RhcmdldExhYmVsfWApOwogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwoKICAgICAgY29uc3QgZGVzY0xhYmVsID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiKHNhbnMgZGVzY3JpcHRpb24pIjsKICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgVHUgYXMgdXRpbGlzw6kgIiR7ZGVzY0xhYmVsfSIgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gZm9pcywgdG91am91cnMgY2xhc3PDqSBlbiBgICsKICAgICAgICAgIGAiQXV0cmUiLiBDcsOpZXIgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpID9gOwogICAgICB9IGVsc2UgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gInJlY29uY2lsZSIpIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBvdXRsaWVyTGFiZWxzID0gc3VnZ2VzdGlvbi5vdXRsaWVyQ2F0ZWdvcmllcwogICAgICAgICAgLm1hcCgoYykgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY10gfHwgYykKICAgICAgICAgIC5qb2luKCIsICIpOwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCR7c3VnZ2VzdGlvbi50eElkcy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHNpbWlsYWlyZShzKSDDoCAiJHtkZXNjTGFiZWx9IiBzb250IGNsYXNzw6llcyBlbiBgICsKICAgICAgICAgIGAiJHtvdXRsaWVyTGFiZWxzfSIsIGFsb3JzIHF1ZSAiJHtkb21pbmFudExhYmVsfSIgZXN0IG1haW50ZW5hbnQgbGEgY2F0w6lnb3JpZSBoYWJpdHVlbGxlLiBgICsKICAgICAgICAgIGBMZXMgYWxpZ25lciBzdXIgIiR7ZG9taW5hbnRMYWJlbH0iID9gOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGN1cnJlbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uY3VycmVudF0gfHwgc3VnZ2VzdGlvbi5jdXJyZW50OwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCIke2Rlc2NMYWJlbH0iIGVzdCBoYWJpdHVlbGxlbWVudCBjbGFzc8OpIGVuICIke2RvbWluYW50TGFiZWx9IiwgbWFpcyBjZXR0ZSBmb2lzIGAgKwogICAgICAgICAgYGMnZXN0ICIke2N1cnJlbnRMYWJlbH0iLiBQYXMgZCdlcnJldXIgb3UgdW4gb3VibGkgP2A7CiAgICAgIH0KICAgICAgZWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAiY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyI7CgogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzZWxlY3QiKTsKICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXSkgewogICAgICAgICAgaWYgKHZhbHVlID09PSAiYXV0cmUiKSBjb250aW51ZTsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBuZXdPcHQudmFsdWUgPSAiX19uZXdfXyI7CiAgICAgICAgbmV3T3B0LnRleHRDb250ZW50ID0gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiI7CiAgICAgICAgbmV3T3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQobmV3T3B0KTsKCiAgICAgICAgY29uc3QgbmV3TmFtZUlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBuZXdOYW1lSW5wdXQudHlwZSA9ICJ0ZXh0IjsKICAgICAgICBuZXdOYW1lSW5wdXQucGxhY2Vob2xkZXIgPSAiTm9tIGRlIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiOwogICAgICAgIG5ld05hbWVJbnB1dC52YWx1ZSA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIiI7CgogICAgICAgIHNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICBuZXdOYW1lSW5wdXQuc3R5bGUuZGlzcGxheSA9IHNlbGVjdC52YWx1ZSA9PT0gIl9fbmV3X18iID8gImlubGluZS1ibG9jayIgOiAibm9uZSI7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKHNlbGVjdCk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQobmV3TmFtZUlucHV0KTsKCiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9ICJBcHBsaXF1ZXIiOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBsZXQgdGFyZ2V0VmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgICBsZXQgdGFyZ2V0TGFiZWw7CiAgICAgICAgICBpZiAodGFyZ2V0VmFsdWUgPT09ICJfX25ld19fIikgewogICAgICAgICAgICBjb25zdCBuYW1lID0gbmV3TmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgaWYgKCFuYW1lKSB7IHNob3dUb2FzdCgiRG9ubmUgdW4gbm9tIMOgIGxhIGNhdMOpZ29yaWUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgICAgICAgIHRhcmdldFZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IG5hbWU7CiAgICAgICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdGFyZ2V0VmFsdWUpKSB7CiAgICAgICAgICAgICAgc2F2ZUN1c3RvbUNhdGVnb3J5KHN1Z2dlc3Rpb24udHlwZSwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1t0YXJnZXRWYWx1ZV0gfHwgdGFyZ2V0VmFsdWU7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gYENvcnJpZ2VyIGVuICIke2RvbWluYW50TGFiZWx9ImA7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHN1Z2dlc3Rpb24uZG9taW5hbnQsIGRvbWluYW50TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfQoKICAgICAgY29uc3QgZGlzbWlzc0J0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBkaXNtaXNzQnRuLnRleHRDb250ZW50ID0gIklnbm9yZXIiOwogICAgICBkaXNtaXNzQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgZGlzbWlzc0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICB9KTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoZGlzbWlzc0J0bik7CgogICAgICBlbC5hcHBlbmRDaGlsZChjb250cm9scyk7CiAgICB9CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIGNoYXJnZSByw6ljdXJyZW50ZSBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUKICAgIC8vIHNlc3Npb24gKG3Dqm1lIHByaW5jaXBlIHF1ZSBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkLCBtYWlzIHBvdXIgdW5lCiAgICAvLyBjb3JyZWN0aW9uIHF1aSBzdWl0IGxhIGNyw6lhdGlvbiBkJ3VuZSByw6ljdXJyZW50ZSBwYXIgbGEgdm9peCkuCiAgICBsZXQgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgIGNvbnN0IGFtb3VudExhYmVsID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpOwoKICAgICAgLy8gInLDqWN1cnJlbnQiLCAiYWJvbm5lbWVudCIsICJ0b3VzIGxlcyBtb2lzIi4uLiBkw6l0ZWN0w6kgcGFyIGwnSUEgOiBvbgogICAgICAvLyBjcsOpZS9jb3JyaWdlIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgYXUgbGlldSBkJ3VuZSB0cmFuc2FjdGlvbgogICAgICAvLyBwb25jdHVlbGxlLCBxdWVsIHF1ZSBzb2l0IGwnb25nbGV0IGFjdHVlbGxlbWVudCBhZmZpY2jDqSDigJQgbGUgbWljcm8KICAgICAgLy8gZXN0IGdsb2JhbCwgcGFzIGxpw6kgw6AgbCdvbmdsZXQgUsOpY3VycmVudGVzLgogICAgICBpZiAocGFyc2VkLmlzX3JlY3VycmluZykgewogICAgICAgIGNvbnN0IHJlY1BheWxvYWQgPSB7CiAgICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICAgIG5hbWU6IHBhcnNlZC5kZXNjcmlwdGlvbiB8fCAocGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSByw6ljdXJyZW50IiA6ICJEw6lwZW5zZSByw6ljdXJyZW50ZSIpLAogICAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICAgIGRheV9vZl9tb250aDogTnVtYmVyKHBhcnNlZC5leHBlbnNlX2RhdGUuc2xpY2UoOCwgMTApKSwKICAgICAgICB9OwoKICAgICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2xhc3RWb2ljZVJlY3VycmluZ0lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVjUGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICAgIHNob3dUb2FzdChgQ2hhcmdlIHLDqWN1cnJlbnRlIGNvcnJpZ8OpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBjcmVhdGVkLmlkOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUgOiAke3JlY1BheWxvYWQubmFtZX0gKCR7YW1vdW50TGFiZWx9KWApOwogICAgICAgIH0KICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQpIHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtsYXN0Vm9pY2VUcmFuc2FjdGlvbklkfWAsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYENvcnJpZ8OpIDogJHt2ZXJiLnRvTG93ZXJDYXNlKCl9IGRlICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgc2hvd1RvYXN0KGAke3ZlcmJ9IGFqb3V0w6kke3BhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICIiIDogImUifSA6ICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0KICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihwYXJzZWQuZGVzY3JpcHRpb24sIHBhcnNlZC50eXBlKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb25maXJtYXRpb24gc3R5bMOpZSAocmVtcGxhY2Ugd2luZG93LmNvbmZpcm0sIHF1aSBhZmZpY2hlIHVuZSBwb3B1cAogICAgLy8gbmF0aXZlIGR1IG5hdmlnYXRldXIgaG9ycyBjaGFydGUgZ3JhcGhpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgY29uZmlybU92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IGNvbmZpcm1NZXNzYWdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1tb2RhbC1tZXNzYWdlIik7CiAgICBjb25zdCBjb25maXJtT2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tb2siKTsKICAgIGNvbnN0IGNvbmZpcm1DYW5jZWxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tY2FuY2VsIik7CiAgICBsZXQgY29uZmlybVJlc29sdmUgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNob3dDb25maXJtKG1lc3NhZ2UpIHsKICAgICAgY29uZmlybU1lc3NhZ2VFbC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4gewogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gcmVzb2x2ZTsKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VDb25maXJtKHJlc3VsdCkgewogICAgICBjb25maXJtT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAoY29uZmlybVJlc29sdmUpIHsKICAgICAgICBjb25maXJtUmVzb2x2ZShyZXN1bHQpOwogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gbnVsbDsKICAgICAgfQogICAgfQoKICAgIGNvbmZpcm1Pa0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGNsb3NlQ29uZmlybSh0cnVlKSk7CiAgICBjb25maXJtQ2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKGZhbHNlKSk7CiAgICBjb25maXJtT3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBjb25maXJtT3ZlcmxheUVsKSBjbG9zZUNvbmZpcm0oZmFsc2UpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgZMOpcGVuc2UgcsOpY3VycmVudGUgPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgLy8gUmFtw6huZSB1biBqb3VyIGR1IG1vaXMgKDEtMzEpIGF1IGRlcm5pZXIgam91ciByw6llbCBkdSBtb2lzIHZpc8OpIOKAlAogICAgLy8gw6lxdWl2YWxlbnQgSlMgZGUgX2NsYW1wX2RheSBjw7R0w6kgc2VydmV1ciwgcG91ciBjYWxjdWxlciBkZSB2cmFpZXMKICAgIC8vIGRhdGVzIChuZXcgRGF0ZSguLi4pKSBwbHV0w7R0IHF1ZSBkZSBjb21wYXJlciBkZXMgam91cnMgdG91dCBzZXVscy4KICAgIGZ1bmN0aW9uIGNsYW1wRGF5SnMoeWVhciwgbW9udGhJbmRleCwgZGF5KSB7CiAgICAgIGNvbnN0IGxhc3REYXkgPSBuZXcgRGF0ZSh5ZWFyLCBtb250aEluZGV4ICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgICByZXR1cm4gTWF0aC5taW4oZGF5LCBsYXN0RGF5KTsKICAgIH0KCiAgICAvLyBQcm9jaGFpbmUgb2NjdXJyZW5jZSBkJ3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgw6AgcGFydGlyIGQnYXVqb3VyZCdodWkKICAgIC8vIChzdHJpY3RlbWVudCBhcHLDqHMgYXVqb3VyZCdodWkpIDogcmVnYXJkZSBjZSBtb2lzLWNpIHB1aXMsIHNpIGJlc29pbiwKICAgIC8vIGxlcyBkZXV4IG1vaXMgc3VpdmFudHMg4oCUIHV0aWxlIGVuIGZpbiBkZSBtb2lzIHF1YW5kIHBsdXMgcmllbiBuJ2VzdAogICAgLy8gw6AgdmVuaXIgZGFucyBsZSBtb2lzIGNvdXJhbnQuCiAgICBmdW5jdGlvbiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXlTdHIpIHsKICAgICAgY29uc3QgW3R5LCB0bSwgdGRdID0gdG9kYXlTdHIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdG9kYXlEYXRlID0gbmV3IERhdGUodHksIHRtIC0gMSwgdGQpOwogICAgICBmb3IgKGxldCBvZmZzZXQgPSAwOyBvZmZzZXQgPD0gMjsgb2Zmc2V0KyspIHsKICAgICAgICBjb25zdCBiYXNlID0gbmV3IERhdGUodHksIHRtIC0gMSArIG9mZnNldCwgMSk7CiAgICAgICAgY29uc3QgeSA9IGJhc2UuZ2V0RnVsbFllYXIoKTsKICAgICAgICBjb25zdCBtSWR4ID0gYmFzZS5nZXRNb250aCgpOwogICAgICAgIGNvbnN0IG1vbnRoS2V5ID0gYCR7eX0tJHtTdHJpbmcobUlkeCArIDEpLnBhZFN0YXJ0KDIsICIwIil9YDsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgY29uc3QgZGF5ID0gY2xhbXBEYXlKcyh5LCBtSWR4LCBpdGVtLmRheV9vZl9tb250aCk7CiAgICAgICAgY29uc3Qgb2NjRGF0ZSA9IG5ldyBEYXRlKHksIG1JZHgsIGRheSk7CiAgICAgICAgaWYgKG9jY0RhdGUgPiB0b2RheURhdGUpIHJldHVybiBvY2NEYXRlOwogICAgICB9CiAgICAgIHJldHVybiBudWxsOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpIHsKICAgICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIik7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CgogICAgICBjb25zdCB1cGNvbWluZyA9IGFsbFJlY3VycmluZwogICAgICAgIC5tYXAoKGl0ZW0pID0+ICh7IGl0ZW0sIGRhdGU6IG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheSkgfSkpCiAgICAgICAgLmZpbHRlcigoeCkgPT4geC5kYXRlKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBhLmRhdGUgLSBiLmRhdGUpCiAgICAgICAgLnNsaWNlKDAsIDMpOwoKICAgICAgaWYgKHVwY29taW5nLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwYW5lbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwoKICAgICAgZm9yIChjb25zdCB7IGl0ZW0sIGRhdGUgfSBvZiB1cGNvbWluZykgewogICAgICAgIGNvbnN0IGRheXMgPSBNYXRoLnJvdW5kKChkYXRlIC0gbmV3IERhdGUobmV3IERhdGUoKS5zZXRIb3VycygwLCAwLCAwLCAwKSkpIC8gODY0MDAwMDApOwogICAgICAgIGNvbnN0IGR1ZUxhYmVsID0gZGF5cyA8PSAxID8gImRlbWFpbiIgOiBgZGFucyAke2RheXN9IGpvdXJzYDsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJ1cGNvbWluZy1yZWN1cnJpbmctcm93IjsKICAgICAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGxlZnQuY2xhc3NOYW1lID0gIm5hbWUiOwogICAgICAgIGxlZnQudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CiAgICAgICAgY29uc3QgZHVlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkdWVTcGFuLmNsYXNzTmFtZSA9ICJkdWUiOwogICAgICAgIGR1ZVNwYW4udGV4dENvbnRlbnQgPSBgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChkYXRlKX0gwrcgJHtkdWVMYWJlbH1gOwogICAgICAgIGxlZnQuYXBwZW5kQ2hpbGQoZHVlU3Bhbik7CiAgICAgICAgY29uc3QgYW1vdW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAiYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQobGVmdCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGFtb3VudCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkUmVjdXJyaW5nKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIik7CiAgICAgICAgYWxsUmVjdXJyaW5nID0gaXRlbXM7CiAgICAgICAgcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKTsKICAgICAgICByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKTsKICAgICAgICB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBFeHBvcnQgKEV4Y2VsIG91IHNhdXZlZ2FyZGUgSlNPTiBjb21wbMOodGUsIHVuIHNldWwgYm91dG9uIGF2ZWMgdW4KICAgIC8vIGNob2l4IGRlIGZvcm1hdCBwbHV0w7R0IHF1ZSBkZXV4IGdyb3MgYm91dG9ucyBzw6lwYXLDqXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBFWFBPUlRfRk9STUFUUyA9IHsKICAgICAgeGxzeDogewogICAgICAgIGhpbnQ6ICJUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2hhY3VuZSBkYW5zIHNvbiBwcm9wcmUgb25nbGV0LiIsCiAgICAgICAgdXJsOiAiL2FwaS9leHBvcnQveGxzeCIsCiAgICAgICAgZmlsZW5hbWU6ICgpID0+IGBkZXBlbnNlc18ke3RvZGF5SXNvKCl9Lnhsc3hgLAogICAgICAgIHRvYXN0U3VjY2VzczogIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIiwKICAgICAgfSwKICAgICAganNvbjogewogICAgICAgIGhpbnQ6ICJBYnNvbHVtZW50IHRvdXRlcyB0ZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBvYmplY3RpZiBkJ8OpcGFyZ25lKS4gw4AgZ2FyZGVyIGRlIGPDtHTDqSA6IFN1cGFiYXNlIG5lIGZhaXQgcGFzIGRlIHNhdXZlZ2FyZGUgYXV0b21hdGlxdWUgZW4gb2ZmcmUgZ3JhdHVpdGUsIGNlIGZpY2hpZXIgZXN0IHRvbiBmaWxldCBkZSBzw6ljdXJpdMOpIGVuIGNhcyBkZSBww6lwaW4uIiwKICAgICAgICB1cmw6ICIvYXBpL2V4cG9ydC9qc29uIiwKICAgICAgICBmaWxlbmFtZTogKCkgPT4gYGthY2hpbmctc2F1dmVnYXJkZS0ke3RvZGF5SXNvKCl9Lmpzb25gLAogICAgICAgIHRvYXN0U3VjY2VzczogIlNhdXZlZ2FyZGUgdMOpbMOpY2hhcmfDqWUiLAogICAgICB9LAogICAgfTsKICAgIGxldCBjdXJyZW50RXhwb3J0Rm9ybWF0ID0gInhsc3giOwogICAgY29uc3QgZXhwb3J0Rm9ybWF0SGludEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtaGludCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtdG9nZ2xlIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIuZXhwb3J0LWZvcm1hdC1idG4iKTsKICAgICAgaWYgKCFidG4pIHJldHVybjsKICAgICAgY3VycmVudEV4cG9ydEZvcm1hdCA9IGJ0bi5kYXRhc2V0LmZvcm1hdDsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLmV4cG9ydC1mb3JtYXQtYnRuIikuZm9yRWFjaCgoYikgPT4gewogICAgICAgIGIuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYiA9PT0gYnRuKTsKICAgICAgfSk7CiAgICAgIGV4cG9ydEZvcm1hdEhpbnRFbC50ZXh0Q29udGVudCA9IEVYUE9SVF9GT1JNQVRTW2N1cnJlbnRFeHBvcnRGb3JtYXRdLmhpbnQ7CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpOwogICAgICBjb25zdCBjb25maWcgPSBFWFBPUlRfRk9STUFUU1tjdXJyZW50RXhwb3J0Rm9ybWF0XTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiR8OpbsOpcmF0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChjb25maWcudXJsLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBjb25maWcuZmlsZW5hbWUoKTsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoY29uZmlnLnRvYXN0U3VjY2Vzcyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEltcG9ydCBkZSByZWxldsOpIGJhbmNhaXJlIChDU1YgQm91cnNvQmFuaykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIExlIGZpY2hpZXIgbidlc3QgamFtYWlzIGdhcmTDqSBhcHLDqHMgbCdhbmFseXNlIChuaSBpY2ksIG5pIGPDtHTDqQogICAgLy8gc2VydmV1cikgOiBzZXVsIGxlIHRhYmxlYXUgYGltcG9ydFByZXZpZXdSb3dzYCAoZMOpasOgIGRlcyB0cmFuc2FjdGlvbnMKICAgIC8vIGNhbmRpZGF0ZXMsIHBhcyBsZSBmaWNoaWVyIGJydXQpIHZpdCBlbiBtw6ltb2lyZSBsZSB0ZW1wcyBkZSBsYSByZXZ1ZS4KICAgIGxldCBpbXBvcnRQcmV2aWV3Um93cyA9IFtdOyAvLyBbeyAuLi5yb3csIHNlbGVjdGVkOiBib29sIH1dCiAgICBsZXQgaW1wb3J0Q2F0ZWdvcnlMYWJlbHMgPSB7IGV4cGVuc2U6IHt9LCBpbmNvbWU6IHt9IH07CgogICAgY29uc3QgaW1wb3J0RmlsZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1maWxlLWlucHV0Iik7CiAgICBjb25zdCBpbXBvcnRBbmFseXplQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1hbmFseXplLWJ0biIpOwogICAgY29uc3QgaW1wb3J0U3VtbWFyeUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1zdW1tYXJ5Iik7CiAgICBjb25zdCBpbXBvcnRQcmV2aWV3RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXByZXZpZXciKTsKICAgIGNvbnN0IGltcG9ydFJvd3NMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXJvd3MtbGlzdCIpOwogICAgY29uc3QgaW1wb3J0U2VsZWN0ZWRDb3VudEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1zZWxlY3RlZC1jb3VudCIpOwoKICAgIGZ1bmN0aW9uIHVwZGF0ZUltcG9ydFNlbGVjdGVkQ291bnQoKSB7CiAgICAgIGNvbnN0IG4gPSBpbXBvcnRQcmV2aWV3Um93cy5maWx0ZXIoKHIpID0+IHIuc2VsZWN0ZWQpLmxlbmd0aDsKICAgICAgaW1wb3J0U2VsZWN0ZWRDb3VudEVsLnRleHRDb250ZW50ID0gYCR7bn0gc8OpbGVjdGlvbm7DqWUke24gPiAxID8gInMiIDogIiJ9IHN1ciAke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aH1gOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWNvbW1pdC1idG4iKS5kaXNhYmxlZCA9IG4gPT09IDA7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVySW1wb3J0UHJldmlldygpIHsKICAgICAgaW1wb3J0Um93c0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCByb3cgb2YgaW1wb3J0UHJldmlld1Jvd3MpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93IiArIChyb3cuc2VsZWN0ZWQgPyAiIiA6ICIgZXhjbHVkZWQiKTsKCiAgICAgICAgY29uc3QgY2hlY2tib3ggPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGNoZWNrYm94LnR5cGUgPSAiY2hlY2tib3giOwogICAgICAgIGNoZWNrYm94LmNoZWNrZWQgPSByb3cuc2VsZWN0ZWQ7CiAgICAgICAgY2hlY2tib3guYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgcm93LnNlbGVjdGVkID0gY2hlY2tib3guY2hlY2tlZDsKICAgICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImV4Y2x1ZGVkIiwgIXJvdy5zZWxlY3RlZCk7CiAgICAgICAgICB1cGRhdGVJbXBvcnRTZWxlY3RlZENvdW50KCk7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LW1haW4iOwogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWRlc2MiOwogICAgICAgIGNvbnN0IGFtb3VudFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50U3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1hbW91bnQgIiArIHJvdy50eXBlOwogICAgICAgIGFtb3VudFNwYW4udGV4dENvbnRlbnQgPSAocm93LnR5cGUgPT09ICJleHBlbnNlIiA/ICItIiA6ICIrIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocm93LmFtb3VudCk7CiAgICAgICAgZGVzYy5hcHBlbmQoKHJvdy5kZXNjcmlwdGlvbiB8fCAiIikgKyAiIOKAlCAiKTsKICAgICAgICBkZXNjLmFwcGVuZENoaWxkKGFtb3VudFNwYW4pOwoKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWV0YS5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tZXRhIjsKICAgICAgICBsZXQgbWV0YVRleHQgPSBgJHtyb3cuZXhwZW5zZV9kYXRlfSDCtyAke3Jvdy5iYW5rX2xhYmVsfWA7CiAgICAgICAgaWYgKHJvdy5pc19pbnRlcm5hbF90cmFuc2ZlcikgbWV0YVRleHQgKz0gIiDCtyB2aXJlbWVudCBpbnRlcm5lIjsKICAgICAgICBtZXRhLnRleHRDb250ZW50ID0gbWV0YVRleHQ7CiAgICAgICAgaWYgKHJvdy5saWtlbHlfZHVwbGljYXRlKSB7CiAgICAgICAgICBjb25zdCBkdXBTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZHVwU3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kdXAiOwogICAgICAgICAgZHVwU3Bhbi50ZXh0Q29udGVudCA9ICIgwrcgZMOpasOgIHByw6lzZW50ZSA/IjsKICAgICAgICAgIG1ldGEuYXBwZW5kQ2hpbGQoZHVwU3Bhbik7CiAgICAgICAgfQoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobWV0YSk7CgogICAgICAgIGNvbnN0IGNhdFNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGNvbnN0IGxhYmVscyA9IHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyBpbXBvcnRDYXRlZ29yeUxhYmVscy5leHBlbnNlIDogaW1wb3J0Q2F0ZWdvcnlMYWJlbHMuaW5jb21lOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgT2JqZWN0LmVudHJpZXMobGFiZWxzKSkgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgaWYgKHZhbHVlID09PSByb3cuY2F0ZWdvcnkpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgICBjYXRTZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgY2F0U2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsgcm93LmNhdGVnb3J5ID0gY2F0U2VsZWN0LnZhbHVlOyB9KTsKCiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2hlY2tib3gpOwogICAgICAgIGVsLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGVsLmFwcGVuZENoaWxkKGNhdFNlbGVjdCk7CiAgICAgICAgaW1wb3J0Um93c0xpc3RFbC5hcHBlbmRDaGlsZChlbCk7CiAgICAgIH0KICAgICAgdXBkYXRlSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgfQoKICAgIGltcG9ydEFuYWx5emVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSBpbXBvcnRGaWxlSW5wdXQuZmlsZXMgJiYgaW1wb3J0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHsgc2hvd1RvYXN0KCJDaG9pc2lzIGQnYWJvcmQgdW4gZmljaGllciAuY3N2IiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gaW1wb3J0QW5hbHl6ZUJ0bi50ZXh0Q29udGVudDsKICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGltcG9ydEFuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3Vyc+KApiI7CiAgICAgIGltcG9ydFN1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBpbXBvcnRQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGVyci5kZXRhaWwgfHwgYMOJY2hlYyBkZSBsJ2FuYWx5c2UgKCR7cmVzLnN0YXR1c30pYCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgIGltcG9ydENhdGVnb3J5TGFiZWxzID0gewogICAgICAgICAgZXhwZW5zZTogZGF0YS5leHBlbnNlX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgICBpbmNvbWU6IGRhdGEuaW5jb21lX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgfTsKICAgICAgICBpbXBvcnRQcmV2aWV3Um93cyA9IGRhdGEucm93cy5tYXAoKHJvdykgPT4gKHsKICAgICAgICAgIC4uLnJvdywKICAgICAgICAgIHNlbGVjdGVkOiAhcm93LmlzX2ludGVybmFsX3RyYW5zZmVyICYmICFyb3cubGlrZWx5X2R1cGxpY2F0ZSwKICAgICAgICB9KSk7CgogICAgICAgIGxldCBzdW1tYXJ5ID0gYDxzdHJvbmc+JHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGh9PC9zdHJvbmc+IG9ww6lyYXRpb24ke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aCA+IDEgPyAicyIgOiAiIn0gZMOpdGVjdMOpZSR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RoID4gMSA/ICJzIiA6ICIifWA7CiAgICAgICAgaWYgKGRhdGEuYWNjb3VudF9iYWxhbmNlICE9IG51bGwpIHsKICAgICAgICAgIHN1bW1hcnkgKz0gYCDigJQgc29sZGUgZHUgY29tcHRlIGF1ICR7ZGF0YS5hY2NvdW50X2JhbGFuY2VfZGF0ZX0gOiA8c3Ryb25nPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGRhdGEuYWNjb3VudF9iYWxhbmNlKX08L3N0cm9uZz5gOwogICAgICAgIH0KICAgICAgICBpZiAoZGF0YS5za2lwcGVkX3Jvd3MpIHN1bW1hcnkgKz0gYCAoJHtkYXRhLnNraXBwZWRfcm93c30gbGlnbmUke2RhdGEuc2tpcHBlZF9yb3dzID4gMSA/ICJzIiA6ICIifSBpZ25vcsOpZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9LCBpbGxpc2libGUke2RhdGEuc2tpcHBlZF9yb3dzID4gMSA/ICJzIiA6ICIifSlgOwogICAgICAgIHN1bW1hcnkgKz0gIi4gTGVzIHZpcmVtZW50cyBpbnRlcm5lcyBldCBkb3VibG9ucyBwcm9iYWJsZXMgc29udCBkw6ljb2Now6lzIHBhciBkw6lmYXV0IOKAlCB2w6lyaWZpZSBhdmFudCBkJ2ltcG9ydGVyLiI7CiAgICAgICAgaW1wb3J0U3VtbWFyeUVsLmlubmVySFRNTCA9IHN1bW1hcnk7CiAgICAgICAgaW1wb3J0U3VtbWFyeUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGltcG9ydFByZXZpZXdFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICByZW5kZXJJbXBvcnRQcmV2aWV3KCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBpbXBvcnRBbmFseXplQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi50ZXh0Q29udGVudCA9IG9yaWdpbmFsVGV4dDsKICAgICAgfQogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC10b2dnbGUtYWxsLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBjb25zdCBhbnlTZWxlY3RlZCA9IGltcG9ydFByZXZpZXdSb3dzLnNvbWUoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBmb3IgKGNvbnN0IHJvdyBvZiBpbXBvcnRQcmV2aWV3Um93cykgcm93LnNlbGVjdGVkID0gIWFueVNlbGVjdGVkOwogICAgICByZW5kZXJJbXBvcnRQcmV2aWV3KCk7CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWNvbW1pdC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgc2VsZWN0ZWQgPSBpbXBvcnRQcmV2aWV3Um93cy5maWx0ZXIoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBpZiAoc2VsZWN0ZWQubGVuZ3RoID09PSAwKSByZXR1cm47CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgYEltcG9ydGVyICR7c2VsZWN0ZWQubGVuZ3RofSB0cmFuc2FjdGlvbiR7c2VsZWN0ZWQubGVuZ3RoID4gMSA/ICJzIiA6ICIifSA/IFbDqXJpZmllIGJpZW4gbGVzIGNhdMOpZ29yaWVzIGF2YW50IGRlIGNvbmZpcm1lci5gCiAgICAgICk7CiAgICAgIGlmICghb2spIHJldHVybjsKCiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpOwogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJJbXBvcnQgZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgICByb3dzOiBzZWxlY3RlZC5tYXAoKHIpID0+ICh7CiAgICAgICAgICAgIGV4cGVuc2VfZGF0ZTogci5leHBlbnNlX2RhdGUsCiAgICAgICAgICAgIHR5cGU6IHIudHlwZSwKICAgICAgICAgICAgYW1vdW50OiByLmFtb3VudCwKICAgICAgICAgICAgY2F0ZWdvcnk6IHIuY2F0ZWdvcnksCiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiByLmRlc2NyaXB0aW9uLAogICAgICAgICAgfSkpLAogICAgICAgIH07CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvaW1wb3J0L2JhbmstY3N2L2NvbW1pdCIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KGAke3Jlc3VsdC5pbnNlcnRlZH0gdHJhbnNhY3Rpb24ke3Jlc3VsdC5pbnNlcnRlZCA+IDEgPyAicyIgOiAiIn0gaW1wb3J0w6llJHtyZXN1bHQuaW5zZXJ0ZWQgPiAxID8gInMiIDogIiJ9YCk7CiAgICAgICAgaW1wb3J0UHJldmlld1Jvd3MgPSBbXTsKICAgICAgICBpbXBvcnRQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgaW1wb3J0U3VtbWFyeUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaW1wb3J0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBvayA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgICJTdXBwcmltZXIgRMOJRklOSVRJVkVNRU5UIHRvdXRlcyBsZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMpID8gQ2V0dGUgYWN0aW9uIGVzdCBpcnLDqXZlcnNpYmxlLiIKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwogICAgICAvLyBEb3VibGUgY29uZmlybWF0aW9uIHZ1IGxlIGNhcmFjdMOocmUgaXJyw6l2ZXJzaWJsZSBldCBjb21wbGV0IGRlIGwnYWN0aW9uLgogICAgICBjb25zdCBvazIgPSBhd2FpdCBzaG93Q29uZmlybSgiRGVybmnDqHJlIGNvbmZpcm1hdGlvbiA6IHZyYWltZW50IHRvdXQgcsOpaW5pdGlhbGlzZXIgPyIpOwogICAgICBpZiAoIW9rMikgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZXNldC1hbGwiKTsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIlLDqWluaXRpYWxpc2F0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZXNldC1hbGwiLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJBcHBsaWNhdGlvbiByw6lpbml0aWFsaXPDqWUiKTsKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgNjAwKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzZXIgdG91dGUgbCdhcHBsaWNhdGlvbiI7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBXQSA6IGluc3RhbGxhdGlvbiBzdXIgbCfDqWNyYW4gZCdhY2N1ZWlsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBpZiAoInNlcnZpY2VXb3JrZXIiIGluIG5hdmlnYXRvcikgewogICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigibG9hZCIsICgpID0+IHsKICAgICAgICBuYXZpZ2F0b3Iuc2VydmljZVdvcmtlci5yZWdpc3RlcigiL3N3LmpzIikuY2F0Y2goKCkgPT4ge30pOwogICAgICB9KTsKICAgIH0KCiAgICBsZXQgZGVmZXJyZWRJbnN0YWxsUHJvbXB0ID0gbnVsbDsKICAgIGNvbnN0IHB3YUluc3RhbGxSb3cgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicHdhLWluc3RhbGwtcm93Iik7CiAgICBjb25zdCBwd2FJbnN0YWxsQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInB3YS1pbnN0YWxsLWJ0biIpOwogICAgY29uc3QgcHdhSW9zSGludFJvdyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwd2EtaW9zLWhpbnQtcm93Iik7CgogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImJlZm9yZWluc3RhbGxwcm9tcHQiLCAoZSkgPT4gewogICAgICAvLyBFbXDDqmNoZSBsYSBtaW5pLWluZm9iYXIgYXV0b21hdGlxdWUgZHUgbmF2aWdhdGV1ciA6IG9uIGFmZmljaGUKICAgICAgLy8gcGx1dMO0dCBub3RyZSBwcm9wcmUgYm91dG9uLCBkYW5zIGwnb25nbGV0IEV4cG9ydCwgY29ow6lyZW50IGF2ZWMKICAgICAgLy8gbGUgcmVzdGUgZHUgc2l0ZS4KICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBlOwogICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIiI7CiAgICB9KTsKCiAgICBpZiAocHdhSW5zdGFsbEJ0bikgewogICAgICBwd2FJbnN0YWxsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgIGlmICghZGVmZXJyZWRJbnN0YWxsUHJvbXB0KSByZXR1cm47CiAgICAgICAgZGVmZXJyZWRJbnN0YWxsUHJvbXB0LnByb21wdCgpOwogICAgICAgIGNvbnN0IHsgb3V0Y29tZSB9ID0gYXdhaXQgZGVmZXJyZWRJbnN0YWxsUHJvbXB0LnVzZXJDaG9pY2U7CiAgICAgICAgZGVmZXJyZWRJbnN0YWxsUHJvbXB0ID0gbnVsbDsKICAgICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGlmIChvdXRjb21lID09PSAiYWNjZXB0ZWQiKSBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIGluc3RhbGzDqWUiKTsKICAgICAgfSk7CiAgICB9CgogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImFwcGluc3RhbGxlZCIsICgpID0+IHsKICAgICAgaWYgKHB3YUluc3RhbGxSb3cpIHB3YUluc3RhbGxSb3cuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgIH0pOwoKICAgIC8vIFNhZmFyaSBpT1MgbmUgZMOpY2xlbmNoZSBqYW1haXMgImJlZm9yZWluc3RhbGxwcm9tcHQiIDogb24gYWZmaWNoZSDDoCBsYQogICAgLy8gcGxhY2UgdW4gcGV0aXQgbW9kZSBkJ2VtcGxvaSAoUGFydGFnZXIgPiBTdXIgbCfDqWNyYW4gZCdhY2N1ZWlsKSwgc2F1ZgogICAgLy8gc2kgbCdhcHAgZXN0IGTDqWrDoCBpbnN0YWxsw6llIChtb2RlIHN0YW5kYWxvbmUpLgogICAgY29uc3QgaXNJb3MgPSAvaXBob25lfGlwYWR8aXBvZC9pLnRlc3QobmF2aWdhdG9yLnVzZXJBZ2VudCk7CiAgICBjb25zdCBpc1N0YW5kYWxvbmUgPQogICAgICB3aW5kb3cubWF0Y2hNZWRpYSgiKGRpc3BsYXktbW9kZTogc3RhbmRhbG9uZSkiKS5tYXRjaGVzIHx8IHdpbmRvdy5uYXZpZ2F0b3Iuc3RhbmRhbG9uZSA9PT0gdHJ1ZTsKICAgIGlmIChpc0lvcyAmJiAhaXNTdGFuZGFsb25lICYmIHB3YUlvc0hpbnRSb3cpIHsKICAgICAgcHdhSW9zSGludFJvdy5zdHlsZS5kaXNwbGF5ID0gIiI7CiAgICB9CgogICAgcG9wdWxhdGVDYXRlZ29yaWVzKCJleHBlbnNlIik7CiAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwoKICAgIC8vIFJpZW4gZGUgdG91dCDDp2EgKGNoYXJnZW1lbnQgZGVzIGRvbm7DqWVzLCByYWNjb3VyY2lzIFBXQS4uLikgbmUgZG9pdAogICAgLy8gZMOpbWFycmVyIGF2YW50IGQnYXZvaXIgdW4gamV0b24gZGUgc2Vzc2lvbiB2YWxpZGUg4oCUIHNpbm9uIGxhIHByZW1pw6hyZQogICAgLy8gcmVxdcOqdGUgw6ljaG91ZXJhaXQganVzdGUgYXZlYyB1bmUgNDAxIMOgIGxhIHBsYWNlIGRlIG1vbnRyZXIgbGUgdmVycm91LgogICAgaWYgKEFQSV9LRVkpIHsKICAgICAgc2hvd0FwcCgpOwogICAgICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgICAgICAvLyBDYXTDqWdvcmllcyBwZXJzbyArIHN1Z2dlc3Rpb25zIGlnbm9yw6llcyBkJ2Fib3JkLCBwb3VyIHF1ZSBsZXMKICAgICAgICAvLyBsaXN0ZXMgZMOpcm91bGFudGVzIGV0IGxlIGJhbmRlYXUgc29pZW50IGNvcnJlY3RzIGTDqHMgbGUgcHJlbWllcgogICAgICAgIC8vIHJlbmR1IHBsdXTDtHQgcXVlIGRlICJzYXV0ZXIiIHVuZSBmb2lzIGxlIHNlcnZldXIgcsOpcG9uZHUuCiAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoW2xvYWRDdXN0b21DYXRlZ29yaWVzKCksIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpLCBsb2FkQnVkZ2V0cygpLCBsb2FkU2F2aW5nc0dvYWwoKV0pOwogICAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIGxvYWRSZWN1cnJpbmcoKTsKCiAgICAgICAgLy8gUmFjY291cmNpcyBQV0EgKGFwcHVpIGxvbmcgc3VyIGwnaWPDtG5lIGRlIGwnYXBwIHVuZSBmb2lzIGluc3RhbGzDqWUpIDoKICAgICAgICAvLyAvP3Nob3J0Y3V0PWFkZCBvdXZyZSBkaXJlY3RlbWVudCBsZSBmb3JtdWxhaXJlIGQnYWpvdXQsIC8/c2hvcnRjdXQ9dm9pY2UKICAgICAgICAvLyBsYW5jZSBkaXJlY3RlbWVudCBsYSBkaWN0w6llIHZvY2FsZS4KICAgICAgICBjb25zdCBzaG9ydGN1dFBhcmFtID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoInNob3J0Y3V0Iik7CiAgICAgICAgaWYgKHNob3J0Y3V0UGFyYW0pIHsKICAgICAgICAgIC8vIE5ldHRvaWUgbCdVUkwgdG91dCBkZSBzdWl0ZSA6IHVuIHJlY2hhcmdlbWVudCBkZSBsYSBwYWdlIChvdSB1bgogICAgICAgICAgLy8gcGFydGFnZSBkdSBsaWVuKSBuZSBkb2l0IHBhcyByZWTDqWNsZW5jaGVyIGxlIHJhY2NvdXJjaS4KICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gImFkZCIpIHsKICAgICAgICAgICAgb3Blbk1vZGFsKCk7CiAgICAgICAgICB9IGVsc2UgaWYgKHNob3J0Y3V0UGFyYW0gPT09ICJ2b2ljZSIgJiYgIW1pY0J0bi5kaXNhYmxlZCkgewogICAgICAgICAgICBtaWNCdG4uY2xpY2soKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0pKCk7CiAgICB9IGVsc2UgewogICAgICBzaG93TG9ja1NjcmVlbigpOwogICAgfQogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
ICON_192_B64 = "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"
# END_ICON_192_B64
# BEGIN_ICON_512_B64
ICON_512_B64 = "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAjz0lEQVR4nO3deZScdZ3v8c9TVV3VW3pfknTSHbJhJAExsioBhQCCwh0GQQdBnBlwu27IyLjO9epxYXS4I+64wDiiIooKqBBQBMy9AUyCIUDIvnS6k053p9N7d1U99w8MNpCll6r6Ps/ze7/O6cM5Hkl/6tekv5/6Pk9VeUIgVVbX+9YZACAXero7POsMeDl+KEYY8ADwPAqCDQ69ABj2ADAxlIL844DzgIEPALlFIcg9DjQHGPgAUFgUgqnjACeJoQ8AwUAZmBwObQIY+gAQbJSB8eOgjoKhDwDhRBk4Mg7nMBj8ABANFIFD41DGYOgDQLRRBv6GgxCDHwBcQxFwvAAw+AHAbS4XAScfOIMfADCWi0XAqQfM4AcAHIlLRcCJB8rgBwBMhAtFIGYdIN8Y/gCAiXJhdkS24bjwwwMA5F9UtwGRe1AMfgBAPkStCETqEgDDHwCQL1GbMZFoM1H7oQAAgi0K24DQbwAY/gCAQovC7Al1AYjCDwAAEE5hn0GhXGGE/dABANESxksCodsAMPwBAEETxtkUqgIQxgMGALghbDMqFCuLsB0qAMBtYbgkEPgNAMMfABA2YZhdgS4AYThAAAAOJegzLLAFIOgHBwDA0QR5lgWyAAT5wAAAmIigzrTAFYCgHhQAAJMVxNkWqAIQxAMCACAXgjbjAlMAgnYwAADkWpBmXSAKQJAOBACAfArKzDMvAEE5CAAACiUIs8+0AAThAAAAsGA9A80KgPUDBwDAmuUsNCkADH8AAJ5nNRMLXgAY/gAAvJjFbCxoAWD4AwBwaIWekQUrAAx/AACOrJCzsiAFgOEPAMD4FGpmmr8PAAAAKLy8FwCe/QMAMDGFmJ15LQAMfwAAJiffMzRvBYDhDwDA1ORzlnIPAAAADspLAeDZPwAAuZGvmZrzAsDwBwAgt/IxW3NaABj+AADkR65nLPcAAADgoJwVAJ79AwCQX7mctTkpAAx/AAAKI1czl0sAAAA4aMoFgGf/AAAUVi5mLxsAAAAcNKUCwLN/AABsTHUGT7oAMPwBALA1lVnMJQAAABw0qQLAs38AAIJhsjOZDQAAAA6acAHg2T8AAMEymdnMBgAAAAdNqADw7B8AgGCa6IxmAwAAgIPGXQB49g8AQLBNZFazAQAAwEHjKgA8+wcAIBzGO7PZAAAA4CAKAAAADjpqAWD9DwBAuIxndrMBAADAQUcsADz7BwAgnI42w9kAAADgIAoAAAAOOmwBYP0PAEC4HWmWswEAAMBBFAAAABx0yALA+h8AgGg43ExnAwAAgIMoAAAAOOhlBYD1PwAA0XKo2c4GAAAAB1EAAABwEAUAAAAHvagAcP0fAIBoeumMZwMAAICDKAAAADiIAgAAgINeKABc/wcAINrGzno2AAAAOIgCAACAgygAAAA4iAIAAICDYhI3AAIA4IqDM58NAAAADqIAAADgIAoAAAAOogAAAOAgCgAAAA6iAAAA4CAKAAAADvJ4DwAAANzDBgAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcBAFAAAAB1EAAABwEAUAAAAHUQAAAHAQBQAAAAdRAAAAcFDCOgCAwogVlamooknJillKlDcqUVqnREmtEqW1ihdXKZYsVyxZpnhRuWLJUnmxIikWlxcrkheLy/ezUiYt30/Lz6TlZ0aUHe1TZqRf2ZE+ZUf6lB7sUnpgn9IDncoMdGi0t10jB3Yq3bdHvp+xPgIAY1AAgEjxlKxqVqp2oYprFihVM1+p2vlKVjYrXlw9tT/Zi0uJuDylpKKD/2v9uP5dP5vWaF+7Rrq3arhro4Y7N2qoa6OG921QZvjAlHIBmByvsrretw4BYHISpbUqbTpZpdNfpeKGJSppXKJ4qsI61gT4Gtm/XYN7ntTgnnUaaFutwfYn5WfT1sGAyKMAACESL65Wecsylc8+TaWzTlGqeq51pJzLpgc1sHu1BlpXqW/HnzTYtobLB0AeUACAgCtuOE4Vc5erfM5ZKp1+guS5de9uZmi/+rY/rN5tD6l3y4PKDO23jgREAgUACKCSxuNVufBCVcx/o5JVLdZxAsPPptW/80/q2XCPDmy+T5mhHutIQGhRAICAKCqfrqpFl6jquLdEcrWfa342rd4tD6h7/R3q2/oQlwmACaIAAJa8mKYd83rVnnCVyluWObfez5V0/151P32nup78oUZ7d1vHAUKBAgAYiKcqVL34rao54SolK2dbx4kM38+od9P96lzzffW3PmYdBwg0CgBQQImyetW9+p9Vc/yViiXLrONE2mD7Wu197Gvq3fyAJH7NAS9FAQAKoKh8hupP+Z+qPu4yefGkdRynDO17Rh2rvqae5+4VRQD4GwoAkEfxkhrVn/Re1Z5wlbxEyjqO04b2rlf7o19U3/aHraMAgUABAPLAS6RUt/Ra1b/mPaz6A6Zvx5/U/vDnNNTxtHUUwBQFAMixivnna/qyT3JzX4D5fkbdf/mR9qz8Mu8lAGdRAIAcSVbN0cyzP6/y5tdaR8E4ZQa71P7IF9S9/g7rKEDBUQCAKfJiCdUtvVYNp36I6/wh1bfjUe1+4F810rPTOgpQMBQAYAqK6xdp1nk3qbh+kXUUTFF2dEB7Hv2SOtfeJl4tABdQAIDJ8GKqW3qtGk+/Xl68yDoNcqhv+yPadd91SvfvtY4C5BUFAJigomkzNeuN/6myppOtoyBPMoNd2rXio+rdvMI6CpA3FABgAspmn6bZF35diZJa6ygogM7V31X7I1+Qn01bRwFyjgIAjFPd0mvUeMbH5Hlx6ygooP7WVdp57/uU7u+wjgLkFAUAOIpYUamalt+oymPfbB0FRtL9e7Xj7ms10LbGOgqQMxQA4AiSVXPUfNF3VFx7rHUUGPPTw9p1/0fUs+Fu6yhATlAAgMMobzlDsy/8huKpCusoCAxfe1Z+RR2rbrYOAkwZBQA4hIoFb9TsN97MS/xwSN3rfqzWBz8u+VnrKMCkxawDAEFTvfhyzb7w6wx/HFb1krdp9gUURIQbBQAYo27pNWpafiN3+uOoKhe+SS0Xf0+xRLF1FGBSKADAXzWefr2mL/ukdQyESHnLmWq++Pt8BgRCiQIAyNPMN3xW9ae83zoIQqi8+bVquei7lACEDgUAzpt+xsdUc8JV1jEQYuUty9T85u/IiyWsowDjRgGA02pf/c+qe827rGMgAqbNOUtN535ZkmcdBRgXCgCcVfWKizXjTK75I3eqFv2dpi/7hHUMYFwoAHBSecsyNZ33H+LZGnKtbuk1qj3xH61jAEdFAYBzShqPV/Obv8X1WuTN9DM/qfKWZdYxgCOiAMApRRVNavm7WxUrKrOOggjzvLhmX/h1parnWkcBDosCAGd48SI1X/gNJUpqraPAAfFUhZov/p5iScomgokCAGdMX/YplUx/lXUMOCRVPVdN53zROgZwSBQAOKFy4ZtU+6p3WMeAgyqPvUg1J1xpHQN4GQoAIi9VPVdNy2+0jgGHzTjz0yquW2QdA3gRCgAiLZYo1uw3fZPrsDDlxZOa9cab+PRABAoFAJE24/WfUXHdK6xjACquW6TG06+3jgG8gAKAyCpvfq2qF7/VOgbwgrql16p05lLrGIAkCgAiKpYo1syzP28dA3gxL6amc77Em1AhECgAiKT6Uz+kZNUc6xjAy6RqF6juNe+2jgFQABA9xfWLVLf0GusYwGHVn/J+JatarGPAceyhEC1eTE3LWbGOj6/h7q0a6d6i4e4tGuneqtGBDqX79ykz0KHM6ID8zLD89LDk+/ISKXnxpLxESomSGiVKG5Qoq1eyokmpmvlK1SxQqnquvETK+oEFXixRrOnLPqkdv6aowg6/JREptSe+UyWNJ1jHCCQ/m9ZA25/Vt/0RDbav1UDbGmVH+sb/748OSKMDkqR03x5Jz7zs/+PFEipuWKKypteotOkklTefoVhRaa4eQqRUzDtXZbNPU//O/2sdBY7yKqvrfesQQC7Ei6t17D89qliy3DpKYPjpYfVufVD7N9yt/h2PKDPcW9Dv78WTKm9+rSrmn6/KhW/iZ/MSQx3PaNOPLpD8rHUUOIgCgMiYvuyTXPv/q6GOp9X55H/pwHP3FHzoH04sUaKKhReoZvHbVNp0knWcwGi9/3p1r/+ZdQw4iAKASCgqn66F73zY+evPvVse1L7VtwR+rVw649WqP/l9mjb3bEmedRxTIz07tfHWs+Rn09ZR4BgKACJh5jlfUM2Sf7COYaZ/50q1P/olDbavtY4yIcX1r9SMMz+lstmnW0cxtfuBj6lr3e3WMeAYCgBCL1k1Rwve8aCTd/6P7N+u3X/4tPq2PWQdZUqmzVuuGWd+WsnKZusoJkZ7d+u5HyyTnxm1jgKH8D4ACL3G069zbvj7mVF1rLpZG3+4PPTDX5J6N6/Qph+ep861t0ly7zlJ0bSZqlp0iXUMOIYNAEKtuG6R5l/5W7l0HXm4a7N2/vb9Gtq73jpKXpQ1naJZF3xVReXTraMU1HDXZm287Wy5WIBggw0AQq3upPfIpeHf/dRPtflHF0Z2+EtSf+sqbf7RBYG/kTHXUjXzVDFvuXUMOIQCgNBKlNWrcsEF1jEKws+mtfv3n1Lrio8qmx60jpN36YFObfv5Fepc8wPrKAVVt/Ra6whwCAUAoVWz5Ap58SLrGHmXGe7Vtl9cqa4n/8s6SkH5fkZtD/0v7Xn0i9ZRCqa06SQV173COgYcQQFAKHmxhGqOv8I6Rt5lBru09c7L1b9zpXUUMx2Pf1Ot9/+LM++WV3P8260jwBEUAIRSxYILlShrsI6RV+n+vdpyx1sifb1/vLrX36HdD37COkZBVC26RLFkmXUMOIACgFCqPfFq6wh5lRnq0dafX6Hhrk3WUQKja93tavvjZ61j5F0sWabKYy+yjgEHUAAQOiWNS1Q649XWMfImmx7U9l9ereHO56yjBE7n6u+qc+2t1jHyjvcEQCFQABA6NUuifO3f167fflADbautgwRW+0P/W33bH7GOkVdlTScpWTnbOgYijgKAUPFiCVUsON86Rt7sXXWzDmy6zzpGoPl+Rjt/8z6NHmi1jpJHHlsA5B0FAKFS1vw6xYurrWPkRe/WP2jvyv+wjhEKmaEe7fzdB+X7GesoecN9AMg3CgBCpXLhm6wj5EV6oFOt939EvA3s+A20Pq6OVV+zjpE3qZr5StXMs46BCKMAIDS8eJEq5p9nHSMvWld8VOmBTusYodOx6qsa2veMdYy8qXDknS5hgwKA0ChvWaZ4qsI6Rs7tf/pO9W55wDpGKPnZtHY/8HFFdXNSMT+697vAHgUAoRHF9X9maL/aH/68dYxQG2hbra6/3G4dIy9KGhY796mIKBwKAELBiydVMe9c6xg5t+fRLyk9yOp/qvas/LKyI33WMfKivGWZdQRElFdZXR/N3RlMLP7wdusIKKCnbmqxjvCC+lPer8bTr7eOkXM9z92rnfe+1zoGIogNAIBI6Fz9PaX7O6xj5Fx58+vkeXHrGIighHUAAMiF7OiAnr3lZHle9J7XRPn9DmCHAgAgOvysfEc+NhiYquhVZQAAcFQUAAAAHEQBAADAQRQAAAAcRAEAAMBBFAAAABxEAQAAwEEUAAAAHEQBAADAQRQAAAAcRAEAAMBBFAAAABxEAQAAwEEUAAAAHEQBAADAQRQAAAAcRAEAAMBBFAAAABxEAQAAwEEUAAAAHEQBAADAQRQAAAAc5FVW1/vWIYCXmnvZnSptOsk6xtT4Wa3/z/ny/Yx1EgB4GTYACKR4cZV1hCnLDPcw/AEEFgUAgRRLlVtHmLLMSL91BAA4LAoAAimWKLGOMGX+6KB1BAA4LAoAAslLpKwjTJmfGbGOAACHRQFAIHmxIusIU+ZnKQAAgosCgEDyvPD/p+n7vMAGQHCF/7csoikCBUB+1joBABxWBH7LAgCAiaIAIKCisD73rAMAwGFRABBIfhTW51G4jAEgsvgNhWDKpK0TTJkXD/8rGQBEFwUAgZSNwGvoKQAAgowCgEDyRwesI0xZLFFqHQEADosCgEDKjPRZR5iyeAQ+zwBAdFEAEEiZwS7rCFMWT1XK8+LWMQDgkLzK6voovN4KAbH4w9utI6CAnrqpxToCgEliAwAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4KGEdAAByJVFaq1iixDpGzo307pb8rHUMRAwFAEAkJEpqteDqPyqemmYdJafSA5169ttLrWMggigAyKmnbmrJy59bNvs0HXPpT/LyZ1sZ2rtem29/s3w/Yx0lEhpO+3Dkhr8k9W17SJJvHQMRxD0ACIX+XauUHthnHSOnihuOU82rrrKOEQmpmvmqXvI26xh50bvtj9YREFEUAISDn9WBjb+xTpFzjadfr0RZg3WMkPM085wvyItFcKHpZ9W3/WHrFIgoCgBCo2fDPdYRci6WLFfT8hutY4RazQlXqqzpZOsYedG/+3FlhrqtYyCiKAAIjf7djyvdt8c6Rs5NO+b1qjnhSusYoVRU0aTpr/tX6xh5c2Djb60jIMIoAAgPP6ueCF4GkKTpyz6hVO1C6xih4sUSmn3B1xVLlllHyRNfBzb+zjoEIowCgFDpee5u6wh5EUuUqOWiWxQvrrSOEhqNr7tBpTNOtI6RNwNtazXa12YdAxFGAUCoDOxerdHe3dYx8iJZNUezL7hZ8vhreTSVCy9U3dJrrGPkVc+zv7SOgIjjNw1CxlfXututQ+RNecuZajr789YxAq10xomadd5NkjzrKHnjZ9Pav+HX1jEQcRQAhE73utvlZ0asY+RN9ZK3qfF1N1jHCKRk1Rw1X/w9eYmUdZS86t36e2UGu6xjIOIoAAid9ECnep6L3ksCx6o/6b1qOPWD1jECJVnVomPe8hMlSmqto+Td/vV3WkeAAygACKXONbdaR8i7htOu0/Rln7COEQjJymYdc+lPVFQ+wzpK3o32tat364PWMeAACgBCaXDPkxpsX2MdI+/qll6rpnP/PZrvcjdOJY3Ha+5b71LRtJnWUQqie93t8rNp6xhwAAUAodW55gfWEQqi+rjLNOfSHzux+n6paXPP0TGX3aFEaZ11lILws2l1rfuxdQw4ggKA0Op57l6l+zusYxREWdPJmnfFPSqd8WrrKAXheXE1nP4RtVx0i2KJEus4BXNg471K9++1jgFHUAAQWn42rX2rb7GOUTBF02bqmMvvVMNpH470JYFEWYPmXHq7Gk75gHPvidDxxLetI8Ahbv3tQuR0rb0tkp8PcDieF1fDqR/S3LfepZLGJdZxcq568eVa8I4HVTbrVOsoBde3/WEN7V1vHQMOoQAg1LLpIe197GbrGAVX0ni85r3t15r5hs9G4u2DU7ULdcylP1bT8hsVT1VYxzHR8fg3rSPAMV5ldb1vHQKYCi+W0IKr/6BkZbN1FBOZ4V7t+/O31bn6+8qO9lvHmZBEWYMaT7tOVYsvk+fFreOYGdj9hLb89O+tY8AxFABEQtWiSzTr/JusY5jKDHapc+1t6vrLfys9sM86zhElK5tVt/QaVR13mWKJYus45rb+7HL17/p/1jHgGAoAosGLacGV9/GRupL8zIh6Ntyt7vV3qH/XKknB+CvueXGVtZyhmsWXa9r885x+xj9W345Hte3nV1jHgIMoAIiMinnnqfmi71jHCJTR3t3q2fBrHdh8vwbb1sr3MwX9/p4XV8mME1Ux71xVveJ/KFHeWNDvH3y+Nt9+sQb3PGkdBA6iACBS5lzy3ypvOcM6RiBlhnrUt+NRDbSu0kDbWg3te1p+ZjS338SLqbjuWJXOWKrSppM0bc6ZihdX5/Z7RMj+Z+7Srt99yDoGHEUBQKQkK5s1/6oVXFceBz8zouGuTRru3qKR7q0a6dmudH+H0oOdSg90Kjs6ID8z8vyXn1UsnpSXSMmLp5QorlairF6J0joVVcxSqmbeX7/mK1ZUZv3QQiGbHtTGH5yl0b526yhwFAUAkVP3mndr+hkfs44BHNHelV/R3lVftY4Bh/E+AIicztXf1VDH09YxgMMa7t6ijie+ZR0DjqMAIHL8bFqtKz5a8BvegPHxtfuBj8nPjFgHgeMoAIikwT3r1OXIpwUiXLqfuoPX/CMQKACIrD0rv6KR/dusYwAvGO1rU/vDn7OOAUiiACDCsqMD2nHPe+Snh62jAJJ87frddcoMH7AOAkiiACDihjqe1u6H/s06BqDO1d9X/86V1jGAF1AAEHnd636s/c/8wjoGHDbU8bTa//Ql6xjAi1AA4ITdD35Cw50brWPAQZnhXu24591cikLgUADghOfvB3i3sqMD1lHgmNb7P6KR/dutYwAvQwGAM4a7Nql1xQ0KyqfjIfo6Hv+GDmy6zzoGcEgUADilZ8Ov1f7IF61jwAEHNt+vPY/eaB0DOCwKAJyz74lvqXP1d61jIMKGOp7Rrt9+UGybEGQUADip7Y+f0/5nf2UdAxE02rtb23/5Tu43QeBRAOAoX633Xae+7Y9YB0GEZIa6te0Xb9doX5t1FOCoKABwlp9Na8fd79Lgnr9YR0EEZEf7te2uqzXctdk6CjAuFAA4LTvar+13Xc3HB2NKsulBbf/lP2qwfa11FGDcKABwXnqwU1t/dpkGdj9hHQUhlE0PavtdV/MJfwgdCgCg59+tbdvP366+bQ9ZR0GIZEcHGP4ILQoA8FfZ9KC2/+qf1PPcPdZREAKZoW5tvfMfGP4ILQoAMIafTWvnb96v7qd+Yh0FATba16YtP71Ug+1rrKMAk0YBAF7Kz6p1xQ3qeOzr1kkQQEP7ntWWn1yi4a5N1lGAKfEqq+t5qyrgMCoXXqimc/9dsaIy6ygIgN4tD2jnbz6g7Gi/dRRgyigAwFGkaheq+c3fVqp6rnUUGNr351vU/sjnJT9rHQXICQoAMA7x1DTNOv//aNrcc6yjoMCyo/1qXXGDejbcbR0FyCkKADBunhpO/YAaTv2Q5HH7jAuGOzdqxz3v4t39EEkUAGCCyuecpVnnfUWJ0jrrKMij7vV3qO0P/8aH+iCyKADAJCRKajVz+RdUMe886yjIscxQt1pX3KADm+6zjgLkFQUAmILq4y7T9DM/rXhqmnUU5EDv1t+rdcUNSvfvtY4C5B0FAJiiRFmDZr7hs6qYf751FExSerBT7Q99Rvuf/ZV1FKBgKABAjlTMO1czXv8ZFU2baR0F4+Zr/9O/UNsfP6vMULd1GKCgKABADsUSJao7+b2qW3qtYoli6zg4gsE969T2h09roG21dRTABAUAyIOiiiZNP+Pjqlx4oSTPOg7GSPd3aM/KL6t7/R28qQ+cRgEA8qikYbEaX/svKp9zlnUU52WGerTviW+pc80PlE0PWscBzFEAgAIoazpZDad9WGWzT7eO4pzMcK+61t6qfX/+jjLDB6zjAIFBAQAKqKTxBNWf/D5VzD9XXBrIr/RApzrXfE+da29TdqTPOg4QOBQAwECqZp5qX3W1qhb9vWJJPmkwl4Y6nlHn2lu1/9m75KeHreMAgUUBAAzFkmWqfuWlqj7+ChXXHmsdJ7T8zIgObPqdup78ofpbH7OOA4QCBQAIiJLG41X1yktV9YqLFC+uto4TCoN7nlT3+jvVs+FXygz1WMcBQoUCAASMFy9SefMZqlhwgSrmLVe8uMo6UqAMdTyjno336sBz92q4e4t1HCC0KABAgHmxhMpmn6Zpx5yt8jlnKlU91zpSwfmZEfW3Pqa+bQ/pwOb7NbJ/u3UkIBIoAECIJCubVT7nTJXNOlVlTScrUdZgHSnnfD+joY5nNLBrlfp2rlT/zpV8JC+QBxQAIMSSVXNU1nSSShqPV3HDEhXXLwrdWxCn+/ZocO86De5Zp4G2NRpoe0LZkX7rWEDkUQCACPG8uFI185WqXTDmn/OUrGi2fbmhn9Vo/16N7N+m4a5NL3wN7XtW6f4Ou1yAwygAgCPixZUqqpil5LQmJcoblSipVaK0VonSOsVSlYonyxRLliuWLFMsUSovnpDnJaRYXF4sLvm+/GxGvp+WshllM8PKjvT/9atPmZE+ZQa7lB7sVHpg3/Nffe0aObBLo7275WdGrY8AwBgUAAAAHBSzDgAAAAqPAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOIgCAACAgygAAAA4iAIAAICDKAAAADiIAgAAgIMoAAAAOCjW093hWYcAAACF09Pd4bEBAADAQRQAAAAcRAEAAMBBFAAAABxEAQAAwEEUAAAAHEQBAADAQTHp+dcDWgcBAAD5d3DmswEAAMBBFAAAABxEAQAAwEEUAAAAHPRCAeBGQAAAom3srGcDAACAgygAAAA4iAIAAICDXlQAuA8AAIBoeumMZwMAAICDKAAAADiIAgAAgINeVgC4DwAAgGg51GxnAwAAgIMoAAAAOOiQBYDLAAAARMPhZjobAAAAHEQBAADAQYctAFwGAAAg3I40y9kAAADgIAoAAAAOOmIB4DIAAADhdLQZzgYAAAAHHbUAsAUAACBcxjO72QAAAOAgCgAAAA4aVwHgMgAAAOEw3pnNBgAAAAeNuwCwBQAAINgmMqvZAAAA4KAJFQC2AAAABNNEZzQbAAAAHDThAsAWAACAYJnMbGYDAACAgyZVANgCAAAQDJOdyWwAAABw0KQLAFsAAABsTWUWT2kDQAkAAMDGVGcwlwAAAHDQlAsAWwAAAAorF7OXDQAAAA7KSQFgCwAAQGHkaubmbANACQAAIL9yOWu5BAAAgINyWgDYAgAAkB+5nrE53wBQAgAAyK18zNa8XAKgBAAAkBv5mqncAwAAgIPyVgDYAgAAMDX5nKV53QBQAgAAmJx8z9C8XwKgBAAAMDGFmJ3cAwAAgIMKUgDYAgAAMD6FmpkF2wBQAgAAOLJCzsqCXgKgBAAAcGiFnpEFvweAEgAAwItZzEaTmwApAQAAPM9qJpq9CoASAABwneUsNH0ZICUAAOAq6xlo/j4A1gcAAEChBWH2mRcAKRgHAQBAIQRl5gWiAEjBORAAAPIlSLMuMAVACtbBAACQS0GbcYEqAFLwDggAgKkK4mwLXAGQgnlQAABMRlBnWiALgBTcAwMAYLyCPMsCWwCkYB8cAABHEvQZFugCIAX/AAEAeKkwzK7ABxyrsrret84AAMDhhGHwHxT4DcBYYTpYAIBbwjajQlUApPAdMAAg+sI4m0IXeCwuCQAALIVx8B8Uug3AWGE+eABAuIV9BoW6AEjh/wEAAMInCrMn9A9gLC4JAADyKQqD/6DQbwDGitIPBgAQLFGbMZF6MGOxDQAA5ELUBv9BkXxQY1EEAACTEdXBf1CkLgEcStR/gACA3HNhdkT+AY7FNgAAcCQuDP6DnHmgY1EEAABjuTT4D3LuAY9FEQAAt7k4+A9y9oGPRREAALe4PPgPcv4AxqIIAEC0Mfj/hoM4DMoAAEQDQ//QOJSjoAgAQDgx+I+Mw5kAygAABBtDf/w4qEmiDABAMDD0J4dDywHKAAAUFkN/6jjAPKAQAEBuMfBzjwMtAAoBAEwMAz//OGAjlAIAeB7D3gaHHlAUBABRwYAPpv8P/gFoLy5OhgoAAAAASUVORK5CYII="
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
