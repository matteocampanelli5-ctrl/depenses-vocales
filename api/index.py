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
import hashlib
import hmac
import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Header, HTTPException, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI()

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
_VOICE_SYSTEM_PROMPT = """Tu analyses une phrase dictée à l'oral en français, qui concerne les finances personnelles de l'utilisateur. Elle est de l'une de ces deux natures :

1. Une dépense ou un revenu à enregistrer, ou une correction d'une transaction déjà enregistrée.
2. Une question sur ses finances (combien il a dépensé, où il en est sur un budget, son solde, son épargne...).

Si la phrase est interrogative — ou commence par des mots comme "combien", "quel", "quelle", "est-ce que", "comment", "où en est", "ai-je", "suis-je", "me reste-t-il", "qu'est-ce que" — c'est TOUJOURS une question (intent="question"), jamais une transaction, même si elle mentionne un montant ou une catégorie.

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon l'un de ces deux schémas :

### Si intent = "transaction"
{
  "intent": "transaction",
  "type": "expense" ou "income",
  "amount": nombre (toujours positif),
  "category": une chaîne parmi restaurant, courses, transport, logement, loisirs, santé, autre (si type=expense) ou salaire, freelance, remboursement, cadeau, autre (si type=income),
  "raw_date_expression": l'expression de date EXACTEMENT telle que prononcée (ex: "hier", "lundi dernier", "le 3 septembre"), ou null si aucune date n'est mentionnée,
  "description": une description courte et nettoyée (sans le montant ni la date), ou null si rien de pertinent à part la catégorie,
  "is_correction": true seulement si la phrase exprime explicitement une intention de corriger une transaction déjà enregistrée (ex: "corrige", "en fait c'était plutôt", "change le montant de..."), false dans tous les autres cas, y compris si la phrase ressemble à une dépense déjà saisie,
  "is_recurring": true si la phrase indique explicitement qu'il s'agit d'une charge qui se répète chaque mois (mots comme "récurrent", "récurrence", "abonnement", "tous les mois", "chaque mois", "mensuel"), false sinon
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
  "category": une chaîne parmi restaurant, courses, transport, logement, loisirs, santé, autre, salaire, freelance, remboursement, cadeau (celle qui est pertinente pour la question), ou null si la question ne porte pas sur une catégorie précise,
  "raw_period_expression": l'expression de période EXACTEMENT telle que prononcée (ex: "ce mois-ci", "le mois dernier", "cette année", "l'année dernière", "en septembre", "depuis le début"), ou null si aucune période n'est mentionnée (le mois en cours sera utilisé par défaut)
}

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même un montant, une date calendaire ou une période à partir d'une expression relative. Tu ne connais ni le solde de l'utilisateur ni la date du jour. Recopie les expressions telles quelles ; un système déterministe s'occupe de tous les calculs à partir des vraies données.
- Si la phrase ne mentionne aucune date (transaction) ou aucune période (question), le champ correspondant doit être null.
- is_correction doit rester false par défaut : en cas de doute, considère qu'il s'agit d'une nouvelle transaction plutôt que d'une correction.
- is_recurring doit rester false par défaut : ne le mets à true que si la récurrence est clairement exprimée à l'oral, jamais par déduction (ex: "le loyer" seul ne suffit pas, il faut un mot indiquant explicitement la répétition)."""


def call_claude_extraction(text: str) -> dict:
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
            system=_VOICE_SYSTEM_PROMPT,
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


@app.post("/api/voice/parse", response_model=None)
def parse_voice_text(req: VoiceParseRequest, _: None = Depends(require_api_key)):
    data = call_claude_extraction(req.text)

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
            if category not in INCOME_CATEGORIES:
                category = None
        elif metric in ("spent", "budget_remaining"):
            if category not in EXPENSE_CATEGORIES:
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

        client = get_supabase_client()
        result = compute_voice_answer(metric, category, period, client)

        return VoiceQuestionResult(
            answer=result["answer"],
            metric=metric,
            category=category,
            period_label=period["label"],
            amount=result.get("amount"),
        )

    tx_type: TransactionType = "income" if data.get("type") == "income" else "expense"

    try:
        amount = float(data.get("amount"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")

    category = str(data.get("category") or "autre").strip().lower()
    allowed = INCOME_CATEGORIES if tx_type == "income" else EXPENSE_CATEGORIES
    if category not in allowed:
        category = "autre"

    description = data.get("description")
    description = description.strip() if isinstance(description, str) and description.strip() else None

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
    )


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdCB7CiAgICBjb2xvci1zY2hlbWU6IGRhcms7CiAgICAtLWJnOiAjMGYxMTE1OwogICAgLS1zdXJmYWNlOiAjMWExZDI0OwogICAgLS1zdXJmYWNlLTI6ICMyMjI2MmY7CiAgICAtLWJvcmRlcjogIzJhMmUzODsKICAgIC0tdGV4dDogI2U2ZTZlNjsKICAgIC0tdGV4dC1kaW06ICM5YWEwYWM7CiAgICAtLWFjY2VudDogIzNiODJmNjsKICAgIC0tYWNjZW50LWRpbTogIzFkNGVkODsKICAgIC0tZGFuZ2VyOiAjZWY0NDQ0OwogICAgLS1zdWNjZXNzOiAjMjJjNTVlOwogICAgLS1yYWRpdXM6IDE0cHg7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgYm9keSB7CiAgICBtYXJnaW46IDA7CiAgICBtaW4taGVpZ2h0OiAxMDB2aDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKICAgIHBhZGRpbmctYm90dG9tOiA2cmVtOwogIH0KICBoZWFkZXIgewogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gMXJlbTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICB9CiAgaDEgeyBmb250LXNpemU6IDEuM3JlbTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC45cmVtOyBtYXJnaW46IDA7IH0KCiAgLnRhYnMgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgfQogIC50YWItYnRuIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDExMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnRhYi1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KCiAgLnN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTAwcHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC45cmVtIDFyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAwLjI1cmVtOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUucG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b29sdGlwLWhvc3QgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGN1cnNvcjogaGVscDsgfQogIC5jdXN0b20tdG9vbHRpcCB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiA1MCU7CiAgICBib3R0b206IGNhbGMoMTAwJSArIDAuNnJlbSk7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg0cHgpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41NXJlbSAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB0ZXh0LWFsaWduOiBsZWZ0OwogICAgYm94LXNoYWRvdzogMCA4cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMzUpOwogICAgb3BhY2l0eTogMDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwogICAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjEycyBlYXNlLCB0cmFuc2Zvcm0gMC4xMnMgZWFzZTsKICAgIHotaW5kZXg6IDIwOwogIH0KICAuY3VzdG9tLXRvb2x0aXA6OmFmdGVyIHsKICAgIGNvbnRlbnQ6ICIiOwogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxMDAlOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYm9yZGVyOiA2cHggc29saWQgdHJhbnNwYXJlbnQ7CiAgICBib3JkZXItdG9wLWNvbG9yOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KICAuY3VzdG9tLXRvb2x0aXAudmlzaWJsZSB7CiAgICBvcGFjaXR5OiAxOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoMCk7CiAgICBwb2ludGVyLWV2ZW50czogYXV0bzsKICB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLndlZWstc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAtMC40cmVtIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQoKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxLjFyZW07CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudC1kaW0pOwogIH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gcCB7IG1hcmdpbjogMCAwIDAuN3JlbTsgZm9udC1zaXplOiAwLjg4cmVtOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBzZWxlY3QsCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idG4tcHJpbWFyeS1zbSwgLmJ0bi1zZWNvbmRhcnktc20gewogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuOHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KICAuYnRuLXNlY29uZGFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1yZWN1cnJpbmctYmFkZ2UgeyBmb250LXNpemU6IDAuNzVyZW07IG9wYWNpdHk6IDAuNzsgY3Vyc29yOiBoZWxwOyB9CiAgLnR4LXJlY2VpcHQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjc1cmVtOwogICAgb3BhY2l0eTogMC44NTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBwYWRkaW5nOiAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CgogIC55ZWFybHktc3VtbWFyeSB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgfQogIC55ZWFybHktc3RhdCB7CiAgICBmbGV4OiAxOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC43cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuMnJlbTsKICB9CiAgLnllYXJseS1zdGF0LWxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlIHsgZm9udC1zaXplOiAxLjA1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlLmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC55ZWFybHktc3RhdC12YWx1ZS5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudXBjb21pbmctbm90ZSB7CiAgICB3aWR0aDogOTZweDsKICAgIGZsZXgtc2hyaW5rOiAwOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjRyZW07CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjcycmVtOwogICAgbGluZS1oZWlnaHQ6IDEuMjU7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KICAudXBjb21pbmctbm90ZS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXN3YXRjaCB7CiAgICB3aWR0aDogMjhweDsKICAgIGhlaWdodDogMTRweDsKICAgIGJvcmRlcjogMS41cHggZGFzaGVkIHZhcigtLWRhbmdlcik7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLXJhZGl1czogNHB4OwogIH0KICAudXBjb21pbmctbm90ZS5wb3NpdGl2ZSAudXBjb21pbmctc3dhdGNoIHsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjIpOwogIH0KCiAgLnJlY3VycmluZy1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5yZWN1cnJpbmctc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KICAuZXhwb3J0LXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmV4cG9ydC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5zYXZpbmdzLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KCiAgLmJ1ZGdldHMtc2F2ZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5zYXZpbmdzLWdvYWwtcm93IGlucHV0IHsgZmxleDogMTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1hcmdpbjogMC44cmVtIDAgMC4zNXJlbTsKICB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5hZHZpY2UtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuYWR2aWNlLWNhcmQgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjg1cmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBsaW5lLWhlaWdodDogMS40OwogIH0KICAuYWR2aWNlLWNhcmQgLmFkdmljZS1pY29uIHsgZm9udC1zaXplOiAxLjFyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmFkdmljZS1jYXJkLnBvc2l0aXZlIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1zdWNjZXNzKTsgfQogIC5hZHZpY2UtY2FyZC53YXJuaW5nIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCAjZjU5ZTBiOyB9CiAgLmFkdmljZS1jYXJkLmluZm8geyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CgogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOHJlbSAxcmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbC5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoNCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgZm9udC1zaXplOiAwLjlyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGJhc2VsaW5lOwogICAgcGFkZGluZzogMC4zNXJlbSAwOwogICAgZm9udC1zaXplOiAwLjg4cmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyArIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAubmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5kdWUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuNzhyZW07IG1hcmdpbi1sZWZ0OiAwLjRyZW07IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC5jb21wYXJlLXNlbGVjdHMgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzZWxlY3QgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjQ1cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzcGFuIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CgogIC5zaW1wbGUtdGFibGUgeyB3aWR0aDogMTAwJTsgYm9yZGVyLWNvbGxhcHNlOiBjb2xsYXBzZTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CiAgLnNpbXBsZS10YWJsZSB0aCwgLnNpbXBsZS10YWJsZSB0ZCB7IHBhZGRpbmc6IDAuNXJlbSAwLjZyZW07IHRleHQtYWxpZ246IHJpZ2h0OyB9CiAgLnNpbXBsZS10YWJsZSB0aDpmaXJzdC1jaGlsZCwgLnNpbXBsZS10YWJsZSB0ZDpmaXJzdC1jaGlsZCB7IHRleHQtYWxpZ246IGxlZnQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoZWFkIHRoIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC13ZWlnaHQ6IDUwMDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyICsgdHIgdGQgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIudG90YWwtcm93IHRkIHsgZm9udC13ZWlnaHQ6IDYwMDsgYm9yZGVyLXRvcDogMnB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLXBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLXVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtZG93biB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50cmVuZC1mbGF0IHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQoKICAuYnVkZ2V0LXJvdyB7IG1hcmdpbi1ib3R0b206IDAuOXJlbTsgfQogIC5idWRnZXQtcm93LWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuMzVyZW07CiAgfQogIC5idWRnZXQtY2F0LW5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWFtb3VudHMgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuM3JlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtaW5wdXQgewogICAgd2lkdGg6IDY0cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDZweDsKICAgIHBhZGRpbmc6IDAuMjVyZW0gMC40cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnVkZ2V0LWJhci10cmFjayB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBoZWlnaHQ6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogIC5idWRnZXQtYmFyLWZpbGwgeyBoZWlnaHQ6IDEwMCU7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyB0cmFuc2l0aW9uOiB3aWR0aCAwLjJzIGVhc2U7IH0KICAuYnVkZ2V0LWJhci1maWxsLm9rIHsgYmFja2dyb3VuZDogdmFyKC0tc3VjY2Vzcyk7IH0KICAuYnVkZ2V0LWJhci1maWxsLndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5idWRnZXQtaGlzdG9yeS1zdHJpcCB7IGRpc3BsYXk6IGZsZXg7IGdhcDogNHB4OyBtYXJnaW4tdG9wOiAwLjRyZW07IH0KICAuaGlzdG9yeS1kb3QgewogICAgZmxleDogMTsKICAgIGhlaWdodDogNnB4OwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuaGlzdG9yeS1kb3Qub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5oaXN0b3J5LWRvdC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5oaXN0b3J5LWRvdC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5oaXN0b3J5LWRvdC5lbXB0eSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IG9wYWNpdHk6IDAuNTsgfQogIC5yZWMtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjZyZW07CiAgfQogIC5yZWMtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnN0YXJ0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjE1KTsKICAgIGNvbG9yOiAjOTNjNWZkOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnJlYy1hbW91bnQgeyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IDEuMDVyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5mYWItbWljIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiA1LjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS41cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoMCwgMCwgMCwgMC4zKTsKICAgIHRyYW5zaXRpb246IGJhY2tncm91bmQgMC4ycywgYm9yZGVyLWNvbG9yIDAuMnM7CiAgfQogIC5mYWItbWljOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KICAuZmFiLW1pYy5saXN0ZW5pbmcgewogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsKICAgIGFuaW1hdGlvbjogcHVsc2UgMS4ycyBpbmZpbml0ZTsKICB9CiAgLmZhYi1taWMucHJvY2Vzc2luZyB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmZhYi1taWM6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjM1OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgQGtleWZyYW1lcyBwdWxzZSB7CiAgICAwJSwgMTAwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDAgcmdiYSgyMzksIDY4LCA2OCwgMC40KTsgfQogICAgNTAlIHsgYm94LXNoYWRvdzogMCAwIDAgMTBweCByZ2JhKDIzOSwgNjgsIDY4LCAwKTsgfQogIH0KCiAgLnZvaWNlLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNTsKICB9CiAgLnZvaWNlLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnZvaWNlLWJhbm5lci5hbnN3ZXIgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtd2VpZ2h0OiA2MDA7IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KCiAgLm1vZGFsLW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LWVuZDsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTA7CiAgfQogIC5tb2RhbC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubW9kYWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXItcmFkaXVzOiAxOHB4IDE4cHggMCAwOwogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gY2FsYygxLjVyZW0gKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpOwogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuOXJlbTsKICB9CiAgLm1vZGFsIGgyIHsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC1zaXplOiAxLjFyZW07IH0KCiAgbGFiZWwgeyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuM3JlbTsgfQogIGlucHV0LCBzZWxlY3QgewogICAgd2lkdGg6IDEwMCU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjY1cmVtIDAuNzVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIGlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IH0KCiAgLnR5cGUtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IH0KICAudHlwZS1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNjVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImV4cGVuc2UiXSB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImluY29tZSJdIHsgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQoKICAubW9kYWwtYWN0aW9ucyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuY29uZmlybS1tb2RhbCB7IG1heC13aWR0aDogNDAwcHg7IH0KICAuY29uZmlybS1tb2RhbC1tZXNzYWdlIHsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LXNpemU6IDAuOTVyZW07IG1hcmdpbjogMDsgbGluZS1oZWlnaHQ6IDEuNDsgfQoKICAuaGlkZGVuLWZpbGUtaW5wdXQgeyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY2VpcHQtcHJldmlldy13cmFwIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjVyZW07CiAgICBhbGlnbi1pdGVtczogZmxleC1zdGFydDsKICAgIG1hcmdpbi1ib3R0b206IDAuNXJlbTsKICB9CiAgLnJlY2VpcHQtcHJldmlldy1pbWcgewogICAgbWF4LXdpZHRoOiAxMDAlOwogICAgbWF4LWhlaWdodDogMTYwcHg7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIG9iamVjdC1maXQ6IGNvbnRhaW47CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KCiAgLmxpZ2h0Ym94LW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuODUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDIwOwogICAgcGFkZGluZzogMS41cmVtOwogIH0KICAubGlnaHRib3gtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxpZ2h0Ym94LWltZyB7IG1heC13aWR0aDogMTAwJTsgbWF4LWhlaWdodDogODB2aDsgYm9yZGVyLXJhZGl1czogMTBweDsgfQogIC5saWdodGJveC1jbG9zZSB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDFyZW07CiAgICByaWdodDogMXJlbTsKICAgIHdpZHRoOiA0MHB4OwogICAgaGVpZ2h0OiA0MHB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS4xcmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSwgYnV0dG9uLnNlY29uZGFyeSB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC43NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIGJ1dHRvbi5wcmltYXJ5OmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CiAgYnV0dG9uLnNlY29uZGFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIGJ1dHRvbi5kYW5nZXIgeyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgY29sb3I6IHZhcigtLWRhbmdlcik7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWRhbmdlcik7IH0KICBidXR0b24uZGFuZ2VyOmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CgogIC5kYW5nZXItem9uZSB7CiAgICBib3JkZXItY29sb3I6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMzUpICFpbXBvcnRhbnQ7CiAgfQogIC5kYW5nZXItem9uZSBoMyB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b2FzdCB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHotaW5kZXg6IDIwOwogICAgbWF4LXdpZHRoOiA5MHZ3OwogIH0KICAudG9hc3QuZXJyb3IgeyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmNhNWE1OyB9CgogIC5sb2NrLXNjcmVlbiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5sb2NrLXNjcmVlbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxvY2stY2FyZCB7IG1heC13aWR0aDogMzIwcHg7IHdpZHRoOiAxMDAlOyB0ZXh0LWFsaWduOiBjZW50ZXI7IH0KICAubG9jay1lbW9qaSB7IGZvbnQtc2l6ZTogM3JlbTsgbWFyZ2luLWJvdHRvbTogMC41cmVtOyB9CiAgLmxvY2stY2FyZCBoMSB7IG1hcmdpbjogMCAwIDAuNXJlbTsgfQogIC5sb2NrLWNhcmQgcCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDEuMjVyZW07IGZvbnQtc2l6ZTogMC45cmVtOyB9CiAgLmxvY2stY2FyZCBpbnB1dCB7CiAgICB3aWR0aDogMTAwJTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLmxvY2stZXJyb3IgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgZm9udC1zaXplOiAwLjg1cmVtOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmxvY2stZXJyb3IuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogIDxkaXYgY2xhc3M9ImxvY2stc2NyZWVuIGhpZGRlbiIgaWQ9ImxvY2stc2NyZWVuIj4KICAgIDxkaXYgY2xhc3M9ImxvY2stY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImxvY2stZW1vamkiPvCfkrA8L2Rpdj4KICAgICAgPGgxPkthY2hpbmc8L2gxPgogICAgICA8cD5FbnRyZSBsZSBtb3QgZGUgcGFzc2UgcG91ciBhY2PDqWRlciDDoCB0ZXMgZG9ubsOpZXMuPC9wPgogICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJsb2NrLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlIiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiPgogICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InByaW1hcnkiIGlkPSJsb2NrLXVubG9jay1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+RMOpdmVycm91aWxsZXI8L2J1dHRvbj4KICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ibG9jay1lcnJvciI+PC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgaWQ9ImFwcC1yb290IiBoaWRkZW4+CiAgPGhlYWRlcj4KICAgIDxoMT7wn5KwIEthY2hpbmc8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1zYXZpbmdzIiBkYXRhLXZpZXc9InNhdmluZ3MiPsOJcGFyZ25lPC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIHJldmVudXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW4gcmV2ZW51IGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5CdWRnZXRzIG1lbnN1ZWxzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgSW5kaXF1ZSB1biBtb250YW50IHBvdXIgdW5lIGNhdMOpZ29yaWUgZXQgZW5yZWdpc3RyZSBhdmVjIPCfkr4g4oCUIGxhIGJhcnJlCiAgICAgICAgICBjb21wYXJlIGVuc3VpdGUgdGVzIGTDqXBlbnNlcyBkdSBtb2lzIGVuIGNvdXJzIMOgIGNlIHBsYWZvbmQgKHZlcnQsCiAgICAgICAgICBvcmFuZ2UgYXUtZGVsw6AgZGUgNzAlLCByb3VnZSBhdS1kZWzDoCBkZSAxMDAlKS4gTGEgcGV0aXRlIHJhbmfDqWUgZGUKICAgICAgICAgIGJhcnJlcyBlbiBkZXNzb3VzIG1vbnRyZSBsJ2hpc3RvcmlxdWUgZGVzIDYgZGVybmllcnMgbW9pcyAoc3Vydm9sZQogICAgICAgICAgb3UgdG91Y2hlIHVuZSBiYXJyZSBwb3VyIHZvaXIgbGUgZMOpdGFpbCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9ImJ1ZGdldHMtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0cy1zYXZlLXJvdyI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9ImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIiBhcmlhLWxhYmVsPSJFbnJlZ2lzdHJlciB0b3VzIGxlcyBidWRnZXRzIj7wn5K+PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPsOJdm9sdXRpb24gbWVuc3VlbGxlIChkw6lwZW5zZXMgdnMgcmV2ZW51cyk8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtZXZvbHV0aW9uIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Db21wYXJlciBkZXV4IG1vaXM8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNvbXBhcmUtc2VsZWN0cyI+CiAgICAgICAgICA8c2VsZWN0IGlkPSJjb21wYXJlLW1vbnRoLWEiPjwvc2VsZWN0PgogICAgICAgICAgPHNwYW4+dnM8L3NwYW4+CiAgICAgICAgICA8c2VsZWN0IGlkPSJjb21wYXJlLW1vbnRoLWIiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImNvbXBhcmUtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGFzc2V6IGRlIG1vaXMgZGlmZsOpcmVudHMgcG91ciBjb21wYXJlci4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+TW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLWhlYWQiPgogICAgICAgICAgPGgzPkJpbGFuIGFubnVlbDwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJ5ZWFybHkteWVhci1zZWxlY3QiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdW1tYXJ5Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5Ew6lwZW5zZXM8L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJ5ZWFybHktdG90YWwtZXhwZW5zZXMiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBleHBlbnNlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5SZXZlbnVzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWluY29tZSIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIGluY29tZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+U29sZGUgbmV0PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LW5ldCIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXllYXJseSI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZGUgZG9ubsOpZXMgcG91ciBjZXR0ZSBhbm7DqWUuCiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWNhdGVnb3J5LXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1yZWN1cnJpbmciIGNsYXNzPSJyZWN1cnJpbmctc2VjdGlvbiI+CiAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgQ2hhcmdlcyBmaXhlcyAoYWJvbm5lbWVudHMsIGxveWVyLCBzYWxhaXJl4oCmKSBjb21wdMOpZXMgYXV0b21hdGlxdWVtZW50CiAgICAgICAgY2hhcXVlIG1vaXMgZGFucyBsZSB0YWJsZWF1IGRlIGJvcmQg4oCUIHBhcyBiZXNvaW4gZGUgbGVzIHJlZGljdGVyLgogICAgICAgIE1ldHMgdW5lIGRhdGUgZGUgZMOpYnV0IHNpIHVuZSBjaGFyZ2UgbmUgZG9pdCBkw6ltYXJyZXIgcXVlIHBsdXMgdGFyZCwKICAgICAgICB1bmUgZGF0ZSBkZSBmaW4gc2kgZWxsZSBkb2l0IHMnYXJyw6p0ZXIgdW4gam91ci4KICAgICAgPC9wPgogICAgICA8ZGl2IGlkPSJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwiIGNsYXNzPSJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgaGlkZGVuIj4KICAgICAgICA8aDQ+UHJvY2hhaW5lcyDDqWNow6lhbmNlczwvaDQ+CiAgICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLWxpc3QiPjwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBBdWN1bmUgZMOpcGVuc2UgcsOpY3VycmVudGUgcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgKyBwb3VyIGVuIGFqb3V0ZXIgdW5lLgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1leHBvcnQiIGNsYXNzPSJleHBvcnQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5FeHBvcnRlciB0ZXMgZG9ubsOpZXM8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBUw6lsw6ljaGFyZ2UgdW4gZmljaGllciBFeGNlbCAoLnhsc3gpIGF2ZWMgdG91dGVzIHRlcyB0cmFuc2FjdGlvbnMKICAgICAgICAgIChkw6lwZW5zZXMgZXQgcmV2ZW51cykgZXQgdGVzIGNoYXJnZXMgcsOpY3VycmVudGVzIChkw6lwZW5zZXMgZXQKICAgICAgICAgIHJldmVudXMgcsOpY3VycmVudHMpLCBjaGFjdW5lIGRhbnMgc29uIHByb3ByZSBvbmdsZXQuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tZXhwb3J0LXhsc3giIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlciBsZSBmaWNoaWVyIEV4Y2VsPC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPlNhdXZlZ2FyZGUgY29tcGzDqHRlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgVMOpbMOpY2hhcmdlIHVuIGZpY2hpZXIgSlNPTiBhdmVjIGFic29sdW1lbnQgdG91dGVzIHRlcyBkb25uw6llcwogICAgICAgICAgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLAogICAgICAgICAgb2JqZWN0aWYgZCfDqXBhcmduZSkuIMOAIGdhcmRlciBkZSBjw7R0w6kgOiBTdXBhYmFzZSBuZSBmYWl0IHBhcyBkZQogICAgICAgICAgc2F1dmVnYXJkZSBhdXRvbWF0aXF1ZSBlbiBvZmZyZSBncmF0dWl0ZSwgY2UgZmljaGllciBlc3QgdG9uIGZpbGV0CiAgICAgICAgICBkZSBzw6ljdXJpdMOpIGVuIGNhcyBkZSBww6lwaW4uCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tZXhwb3J0LWpzb24iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlciBsYSBzYXV2ZWdhcmRlIChKU09OKTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJwd2EtaW5zdGFsbC1yb3ciIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICA8aDM+SW5zdGFsbGVyIGwnYXBwbGljYXRpb248L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBBam91dGUgbCdhcHAgc3VyIHRvbiDDqWNyYW4gZCdhY2N1ZWlsICh0w6lsw6lwaG9uZSwgdGFibGV0dGUgb3UKICAgICAgICAgIG9yZGluYXRldXIpIHBvdXIgbCdvdXZyaXIgZW4gdW4gZ2VzdGUsIGNvbW1lIHVuZSBhcHAgbmF0aXZlLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icHdhLWluc3RhbGwtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPvCfk7IgSW5zdGFsbGVyIGwnYXBwbGljYXRpb248L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0icHdhLWlvcy1oaW50LXJvdyIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIDxoMz5JbnN0YWxsZXIgbCdhcHBsaWNhdGlvbjwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFN1ciBpUGhvbmUvaVBhZCA6IGFwcHVpZSBzdXIgbCdpY8O0bmUgUGFydGFnZXIgZGUgU2FmYXJpLCBwdWlzCiAgICAgICAgICDCqyBTdXIgbCfDqWNyYW4gZCdhY2N1ZWlsIMK7LgogICAgICAgIDwvcD4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IGRhbmdlci16b25lIj4KICAgICAgICA8aDM+4pqg77iPIFpvbmUgZGFuZ2VyZXVzZTwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFN1cHByaW1lIGTDqWZpbml0aXZlbWVudCBUT1VURVMgbGVzIGRvbm7DqWVzIDogdHJhbnNhY3Rpb25zLCBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvbm5hbGlzw6llcywgc3VnZ2VzdGlvbnMgaWdub3LDqWVzLAogICAgICAgICAgYnVkZ2V0cywgcGhvdG9zIGRlIHJlw6d1cyBldCBvYmplY3RpZiBkJ8OpcGFyZ25lLiBQZW5zZSDDoCBleHBvcnRlciBlbgogICAgICAgICAgRXhjZWwgYXZhbnQgc2kgYmVzb2luIOKAlCBpbXBvc3NpYmxlIMOgIGFubnVsZXIuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9ImRhbmdlciIgaWQ9ImJ0bi1yZXNldC1hbGwiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+UsOpaW5pdGlhbGlzZXIgdG91dGUgbCdhcHBsaWNhdGlvbjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1zYXZpbmdzIiBjbGFzcz0ic2F2aW5ncy1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPk9iamVjdGlmIGQnw6lwYXJnbmUgbWVuc3VlbDwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIExlIG1vbnRhbnQgcXVlIHR1IHZldXggZ2FyZGVyIGRlIGPDtHTDqSBjaGFxdWUgbW9pcyAocmV2ZW51cyBtb2lucwogICAgICAgICAgZMOpcGVuc2VzKS4gQ29tcGFyw6kgw6AgdG9uIHNvbGRlIHLDqWVsIGR1IG1vaXMgZW4gY291cnMuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9InNhdmluZ3MtZ29hbC1yb3ciPgogICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InNhdmluZ3MtZ29hbC1pbnB1dCIgbWluPSIwIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iRXggOiAxMDAiPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iaWNvbi1idG4iIGlkPSJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iIGFyaWEtbGFiZWw9IkVucmVnaXN0cmVyIGwnb2JqZWN0aWYiPvCfkr48L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iIGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzIGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzLWxhYmVsIj4KICAgICAgICAgICAgPHNwYW4+U29sZGUgZHUgbW9pcyBlbiBjb3Vyczwvc3Bhbj4KICAgICAgICAgICAgPHN0cm9uZyBpZD0ic2F2aW5ncy1wcm9ncmVzcy10ZXh0Ij48L3N0cm9uZz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0LWJhci10cmFjayI+CiAgICAgICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3MtYmFyIiBjbGFzcz0iYnVkZ2V0LWJhci1maWxsIG9rIj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Db25zZWlsczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEJhc8OpcyBzdXIgdGVzIGJ1ZGdldHMgcGFyIGNhdMOpZ29yaWUgZXQgdGVzIHRlbmRhbmNlcyBkZSBkw6lwZW5zZXMKICAgICAgICAgICh2b2lyIGwnb25nbGV0IFRhYmxlYXUgZGUgYm9yZCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtYWR2aWNlLWxpc3QiIGNsYXNzPSJhZHZpY2UtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMgY2UgbW9pcy1jaSBwb3VyIHRlIGRvbm5lciBkZXMgY29uc2VpbHMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiLW1pYyIgaWQ9ImZhYi1taWMiIGFyaWEtbGFiZWw9IkRpY3RlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LCBvdSBwb3NlciB1bmUgcXVlc3Rpb24iIHRpdGxlPSJEaWN0ZSB1bmUgZMOpcGVuc2UvdW4gcmV2ZW51LCBvdSBwb3NlIHVuZSBxdWVzdGlvbiAoZXggOiDCqyBjb21iaWVuIGonYWkgZMOpcGVuc8OpIGVuIHJlc3RhdXJhbnQgY2UgbW9pcy1jaSA/IMK7KSI+8J+OpDwvYnV0dG9uPgogIDxidXR0b24gY2xhc3M9ImZhYiIgaWQ9ImZhYi1hZGQiIGFyaWEtbGFiZWw9IkFqb3V0ZXIiPis8L2J1dHRvbj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJtb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJtb2RhbC10aXRsZSI+Tm91dmVsbGUgdHJhbnNhY3Rpb248L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJ0eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9ImlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGVzY3JpcHRpb24iPkRlc2NyaXB0aW9uIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImlucHV0LWRlc2NyaXB0aW9uIiBwbGFjZWhvbGRlcj0iRXggOiBkw6lqZXVuZXIgYXZlYyBQYXVsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGF0ZSI+RGF0ZTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJpbnB1dC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsPlJlw6d1IChwaG90bywgb3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbnB1dC1yZWNlaXB0LWZpbGUiIGNsYXNzPSJoaWRkZW4tZmlsZS1pbnB1dCIgYWNjZXB0PSJpbWFnZS8qIiBjYXB0dXJlPSJlbnZpcm9ubWVudCI+CiAgICAgICAgPGRpdiBpZD0icmVjZWlwdC1wcmV2aWV3LXdyYXAiIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctd3JhcCBoaWRkZW4iPgogICAgICAgICAgPGltZyBpZD0icmVjZWlwdC1wcmV2aWV3LWltZyIgY2xhc3M9InJlY2VpcHQtcHJldmlldy1pbWciIGFsdD0iUmXDp3UiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tcmVjZWlwdC1yZW1vdmUiPlN1cHByaW1lciBsYSBwaG90bzwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcGljayIgc3R5bGU9IndpZHRoOjEwMCU7Ij7wn5O3IEFqb3V0ZXIgdW5lIHBob3RvIGRlIHJlw6d1PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9InJlYy1tb2RhbC10aXRsZSI+Tm91dmVsbGUgZMOpcGVuc2UgcsOpY3VycmVudGU8L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJyZWMtdHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1uYW1lIj5Ob208L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0icmVjLWlucHV0LW5hbWUiIHBsYWNlaG9sZGVyPSJFeCA6IE5ldGZsaXgsIExveWVyLCBTYWxhaXJlLi4uIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InJlYy1pbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1kYXkiPkpvdXIgZHUgbW9pczwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1kYXkiIG1pbj0iMSIgbWF4PSIzMSIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IjEgw6AgMzEiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+RGF0ZSBkZSBkw6lidXQgKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZW5kLWRhdGUiPkRhdGUgZGUgZmluIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1lbmQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJyZWMtYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJyZWMtYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJjb25maXJtLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwgY29uZmlybS1tb2RhbCI+CiAgICAgIDxoMiBpZD0iY29uZmlybS1tb2RhbC10aXRsZSI+Q29uZmlybWVyPC9oMj4KICAgICAgPHAgaWQ9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSIgY2xhc3M9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSI+PC9wPgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJjb25maXJtLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iY29uZmlybS1idG4tb2siPkNvbmZpcm1lcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJsaWdodGJveC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImxpZ2h0Ym94LWNsb3NlIiBpZD0icmVjZWlwdC1saWdodGJveC1jbG9zZSIgYXJpYS1sYWJlbD0iRmVybWVyIj7inJU8L2J1dHRvbj4KICAgIDxpbWcgY2xhc3M9ImxpZ2h0Ym94LWltZyIgaWQ9InJlY2VpcHQtbGlnaHRib3gtaW1nIiBhbHQ9IlJlw6d1IGVuIHBsZWluIMOpY3JhbiI+CiAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBMZSBqZXRvbiBkZSBzZXNzaW9uIChvYnRlbnUgYXByw6hzIGF2b2lyIHRhcMOpIGxlIG1vdCBkZSBwYXNzZSBzdXIgbCfDqWNyYW4KICAgIC8vIGRlIHZlcnJvdWlsbGFnZSkgcmVtcGxhY2UgbCdhbmNpZW5uZSBjbMOpIEFQSSBjb2TDqWUgZW4gZHVyIGljaSDigJQgY2VsbGUtY2kKICAgIC8vIMOpdGFpdCB2aXNpYmxlIHBhciBuJ2ltcG9ydGUgcXVpIHZpYSAiQWZmaWNoZXIgbGUgY29kZSBzb3VyY2UiLCBzYW5zCiAgICAvLyBhdWN1biBtb3QgZGUgcGFzc2UuIExlIGpldG9uIGVzdCBzaWduw6kgY8O0dMOpIHNlcnZldXIgZXQgZXhwaXJlIGFwcsOocyA5MAogICAgLy8gam91cnMgOyBpbCBuZSByw6l2w6hsZSByaWVuIGRlIHNlY3JldCBlbiBsdWktbcOqbWUuCiAgICBjb25zdCBUT0tFTl9TVE9SQUdFX0tFWSA9ICJrYWNoaW5nX3Nlc3Npb25fdG9rZW4iOwogICAgbGV0IEFQSV9LRVkgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSkgfHwgIiI7CgogICAgY29uc3QgbG9ja1NjcmVlbkVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stc2NyZWVuIik7CiAgICBjb25zdCBhcHBSb290RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXBwLXJvb3QiKTsKICAgIGNvbnN0IGxvY2tQYXNzd29yZElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IGxvY2tVbmxvY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9jay11bmxvY2stYnRuIik7CiAgICBjb25zdCBsb2NrRXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLWVycm9yIik7CgogICAgZnVuY3Rpb24gc2hvd0xvY2tTY3JlZW4oKSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKFRPS0VOX1NUT1JBR0VfS0VZKTsKICAgICAgQVBJX0tFWSA9ICIiOwogICAgICBhcHBSb290RWwuaGlkZGVuID0gdHJ1ZTsKICAgICAgbG9ja1NjcmVlbkVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBsb2NrUGFzc3dvcmRJbnB1dC52YWx1ZSA9ICIiOwogICAgICBsb2NrUGFzc3dvcmRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dBcHAoKSB7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRVbmxvY2soKSB7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gbG9ja1Bhc3N3b3JkSW5wdXQudmFsdWU7CiAgICAgIGlmICghcGFzc3dvcmQpIHJldHVybjsKICAgICAgbG9ja0Vycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGxvY2tVbmxvY2tCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBsb2NrVW5sb2NrQnRuLnRleHRDb250ZW50ID0gIlbDqXJpZmljYXRpb27igKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2xvZ2luIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBoZWFkZXJzOiB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcGFzc3dvcmQgfSksCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8ICJNb3QgZGUgcGFzc2UgaW5jb3JyZWN0Iik7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRPS0VOX1NUT1JBR0VfS0VZLCBkYXRhLnRva2VuKTsKICAgICAgICAvLyBSZWNoYXJnZW1lbnQgY29tcGxldCBwbHV0w7R0IHF1ZSBkZSByw6ktZW5jaGHDrm5lciBsJ2luaXQgbWFudWVsbGVtZW50IDoKICAgICAgICAvLyBwbHVzIHNpbXBsZSBldCBwbHVzIHPDu3IgKG9uIHJlcGFydCBhdmVjIHVuIMOpdGF0IHByb3ByZSwgQVBJX0tFWSBsdQogICAgICAgIC8vIGRlcHVpcyBsZSBsb2NhbFN0b3JhZ2UgY29tbWUgYXUgdG91dCBwcmVtaWVyIGNoYXJnZW1lbnQpLgogICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgbG9ja0Vycm9yRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZSB8fCAiTW90IGRlIHBhc3NlIGluY29ycmVjdCI7CiAgICAgICAgbG9ja0Vycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgbG9ja1VubG9ja0J0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGxvY2tVbmxvY2tCdG4udGV4dENvbnRlbnQgPSAiRMOpdmVycm91aWxsZXIiOwogICAgICB9CiAgICB9CgogICAgbG9ja1VubG9ja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGF0dGVtcHRVbmxvY2spOwogICAgbG9ja1Bhc3N3b3JkSW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigia2V5ZG93biIsIChlKSA9PiB7CiAgICAgIGlmIChlLmtleSA9PT0gIkVudGVyIikgYXR0ZW1wdFVubG9jaygpOwogICAgfSk7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBkZXNjcmlwdGlvbklucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRlc2NyaXB0aW9uIik7CiAgICBjb25zdCBkYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGF0ZSIpOwogICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tc2F2ZSIpOwoKICAgIGxldCBlZGl0aW5nSWQgPSBudWxsOyAvLyBudWxsID0gY3LDqWF0aW9uLCBzaW5vbiBpZCBkZSBsYSB0cmFuc2FjdGlvbiDDqWRpdMOpZQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBob3RvIGRlIHJlw6d1IGVuIHBpw6hjZSBqb2ludGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IHJlY2VpcHRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtcmVjZWlwdC1maWxlIik7CiAgICBjb25zdCByZWNlaXB0UHJldmlld1dyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LXdyYXAiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtcHJldmlldy1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRQaWNrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZWNlaXB0LXBpY2siKTsKICAgIGNvbnN0IHJlY2VpcHRSZW1vdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcmVtb3ZlIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hPdmVybGF5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjZWlwdExpZ2h0Ym94SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtaW1nIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hDbG9zZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIik7CgogICAgLy8gRmljaGllciBjaG9pc2kgbWFpcyBwYXMgZW5jb3JlIGVudm95w6kgKHVuaXF1ZW1lbnQgZW4gY3LDqWF0aW9uLCB0YW50IHF1ZQogICAgLy8gbGEgdHJhbnNhY3Rpb24gbidhIHBhcyBlbmNvcmUgZCdpZCkgOyBlbiDDqWRpdGlvbiwgbCdlbnZvaSBlc3QgaW1tw6lkaWF0LgogICAgbGV0IHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICBsZXQgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgbGV0IGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNldFJlY2VpcHRQcmV2aWV3RnJvbUJsb2IoYmxvYikgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpOwogICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9IHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgUmVtcGxhY2VyIGxhIHBob3RvIjsKICAgIH0KCiAgICBmdW5jdGlvbiByZXNldFJlY2VpcHRVaSgpIHsKICAgICAgaWYgKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKSB7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgICAgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgICB9CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9ICIiOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3UiOwogICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgIHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgewogICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSByZXR1cm47CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKTsKICAgICAgICBoYXNFeGlzdGluZ1JlY2VpcHQgPSB0cnVlOwogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgLy8gUGFzIGdyYXZlIDogbCd1dGlsaXNhdGV1ciBwZXV0IGp1c3RlIHLDqWVzc2F5ZXIgZCdvdXZyaXIgbGEgZmljaGUuCiAgICAgIH0KICAgIH0KCiAgICByZWNlaXB0UGlja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHJlY2VpcHRGaWxlSW5wdXQuY2xpY2soKSk7CgogICAgcmVjZWlwdEZpbGVJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSByZWNlaXB0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHJldHVybjsKICAgICAgaWYgKCFmaWxlLnR5cGUuc3RhcnRzV2l0aCgiaW1hZ2UvIikpIHsKICAgICAgICBzaG93VG9hc3QoIkNob2lzaXMgdW5lIGltYWdlIChKUEVHLCBQTkcsIFdFQlAgb3UgSEVJQykiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiA4ICogMTAyNCAqIDEwMjQpIHsKICAgICAgICBzaG93VG9hc3QoIkltYWdlIHRyb3AgbG91cmRlICg4IE1vIG1heGltdW0pIiwgdHJ1ZSk7CiAgICAgICAgcmVjZWlwdEZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihmaWxlKTsKCiAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAvLyBUcmFuc2FjdGlvbiBkw6lqw6AgZXhpc3RhbnRlIDogb24gZW52b2llIHRvdXQgZGUgc3VpdGUsIGluZMOpcGVuZGFtbWVudAogICAgICAgIC8vIGR1IGJvdXRvbiAiRW5yZWdpc3RyZXIiIGR1IGZvcm11bGFpcmUuCiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgIH0pLnRoZW4oYXN5bmMgKHJlcykgPT4gewogICAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLmRldGFpbCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWApOwogICAgICAgICAgICB9CiAgICAgICAgICB9KTsKICAgICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgICAgICBzaG93VG9hc3QoIlBob3RvIGR1IHJlw6d1IGVucmVnaXN0csOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICAvLyBOb3V2ZWxsZSB0cmFuc2FjdGlvbiBwYXMgZW5jb3JlIGNyw6nDqWUgOiBvbiBnYXJkZSBsZSBmaWNoaWVyIGRlIGPDtHTDqSwKICAgICAgICAvLyBpbCBzZXJhIGVudm95w6kganVzdGUgYXByw6hzIGxhIGNyw6lhdGlvbiAodm9pciBidG4tc2F2ZSkuCiAgICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gZmlsZTsKICAgICAgfQogICAgfSk7CgogICAgcmVjZWlwdFJlbW92ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgaWYgKGVkaXRpbmdJZCAmJiBoYXNFeGlzdGluZ1JlY2VpcHQpIHsKICAgICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGxhIHBob3RvIGRlIGNlIHJlw6d1ID8iKSkpIHJldHVybjsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gc3VwcHJpbcOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICB9CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjZWlwdExpZ2h0Ym94KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7dHJhbnNhY3Rpb25JZH0vcmVjZWlwdGAsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pCiAgICAgICAgLnRoZW4oKHJlcykgPT4gewogICAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiSW1wb3NzaWJsZSBkZSBjaGFyZ2VyIGxhIHBob3RvIik7CiAgICAgICAgICByZXR1cm4gcmVzLmJsb2IoKTsKICAgICAgICB9KQogICAgICAgIC50aGVuKChibG9iKSA9PiB7CiAgICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9IHVybDsKICAgICAgICAgIHJlY2VpcHRMaWdodGJveE92ZXJsYXkuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgfSkKICAgICAgICAuY2F0Y2goKGVycikgPT4gc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY2VpcHRMaWdodGJveCgpIHsKICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgaWYgKHJlY2VpcHRMaWdodGJveEltZy5zcmMpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRMaWdodGJveEltZy5zcmMpOwogICAgICAgIHJlY2VpcHRMaWdodGJveEltZy5zcmMgPSAiIjsKICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRMaWdodGJveENsb3NlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWNlaXB0TGlnaHRib3gpOwogICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gcmVjZWlwdExpZ2h0Ym94T3ZlcmxheSkgY2xvc2VSZWNlaXB0TGlnaHRib3goKTsKICAgIH0pOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIC8vIENhdMOpZ29yaWVzIGNyw6nDqWVzIHBhciBsJ3V0aWxpc2F0ZXVyIGRlcHVpcyBsZSBiYW5kZWF1IGRlIHN1Z2dlc3Rpb24KICAgIC8vICh2b2lyIHBsdXMgYmFzKSwgZXQgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIDogc3RvY2vDqWVzIGPDtHTDqSBzZXJ2ZXVyCiAgICAvLyAodGFibGVzIGN1c3RvbV9jYXRlZ29yaWVzIC8gZGlzbWlzc2VkX2NhdGVnb3J5X3N1Z2dlc3Rpb25zKSBwbHV0w7R0CiAgICAvLyBxdWUgZGFucyBsZSBuYXZpZ2F0ZXVyLCBwb3VyIHN1aXZyZSBzdXIgdG91cyBsZXMgYXBwYXJlaWxzICh0w6lsw6lwaG9uZSwKICAgIC8vIHRhYmxldHRlLCBvcmRpbmF0ZXVyKSBwbHV0w7R0IHF1ZSBkZSBuZSBtYXJjaGVyIHF1ZSBsw6Agb8O5IGMnw6l0YWl0IGNyw6nDqS4KICAgIGxldCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoKTsKICAgIGxldCBhbGxCdWRnZXRzID0gW107CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEJ1ZGdldHMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgYWxsQnVkZ2V0cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgYnVkZ2V0cyA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9iamVjdGlmIGQnw6lwYXJnbmUgbWVuc3VlbCArIGNvbnNlaWxzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBsZXQgc2F2aW5nc0dvYWwgPSBudWxsOyAvLyB7IG1vbnRobHlfdGFyZ2V0IH0gb3UgbnVsbCBzaSBqYW1haXMgY29uZmlndXLDqQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRTYXZpbmdzR29hbCgpIHsKICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlIGwnb2JqZWN0aWYgZCfDqXBhcmduZSA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGVudHJpZXMgPSBPYmplY3QuZW50cmllcyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KTsKICAgICAgbGV0IHNhdmVkQ291bnQgPSAwOwogICAgICBsZXQgaGFkRXJyb3IgPSBmYWxzZTsKICAgICAgZm9yIChjb25zdCBbY2F0ZWdvcnksIGlucHV0XSBvZiBlbnRyaWVzKSB7CiAgICAgICAgY29uc3QgcmF3ID0gaW5wdXQudmFsdWU7CiAgICAgICAgaWYgKHJhdyA9PT0gIiIgfHwgcmF3ID09PSBudWxsKSBjb250aW51ZTsKICAgICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIocmF3KTsKICAgICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgY29udGludWU7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGF3YWl0IHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCk7CiAgICAgICAgICBzYXZlZENvdW50ICs9IDE7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBoYWRFcnJvciA9IHRydWU7CiAgICAgICAgfQogICAgICB9CiAgICAgIGlmIChoYWRFcnJvcikgewogICAgICAgIHNob3dUb2FzdCgiQ2VydGFpbnMgYnVkZ2V0cyBuJ29udCBwYXMgcHUgw6p0cmUgZW5yZWdpc3Ryw6lzIiwgdHJ1ZSk7CiAgICAgIH0gZWxzZSBpZiAoc2F2ZWRDb3VudCA9PT0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSBhdSBtb2lucyB1biBtb250YW50IGRlIGJ1ZGdldCB2YWxpZGUiLCB0cnVlKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBzaG93VG9hc3QoIkJ1ZGdldHMgZW5yZWdpc3Ryw6lzIik7CiAgICAgIH0KICAgICAgcmVuZGVyQnVkZ2V0cyhhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgY29uc3Qgc2F2aW5nc0dvYWxJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtaW5wdXQiKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gTnVtYmVyKHNhdmluZ3NHb2FsSW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSB1biBtb250YW50IGQnb2JqZWN0aWYgdmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgc2F2aW5nc0dvYWwgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9zYXZpbmdzLWdvYWwiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb250aGx5X3RhcmdldDogYW1vdW50IH0pLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdCgiT2JqZWN0aWYgZW5yZWdpc3Ryw6kiKTsKICAgICAgICByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3ModHJhbnNhY3Rpb25zKSB7CiAgICAgIGlmIChzYXZpbmdzR29hbCkgc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwoKICAgICAgLy8gU29sZGUgZHUgbW9pcyBlbiBjb3VycyAocmV2ZW51cyAtIGTDqXBlbnNlcyksIHRvdXQgY29uZm9uZHUuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGxldCBtb250aEluY29tZSA9IDA7CiAgICAgIGxldCBtb250aEV4cGVuc2VzID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBjdXJyZW50TW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgbW9udGhJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSBtb250aEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRoTmV0ID0gbW9udGhJbmNvbWUgLSBtb250aEV4cGVuc2VzOwoKICAgICAgY29uc3QgcHJvZ3Jlc3NTZWN0aW9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIpOwogICAgICBjb25zdCBwcm9ncmVzc1RleHQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy10ZXh0Iik7CiAgICAgIGNvbnN0IHByb2dyZXNzQmFyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtYmFyIik7CiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgY29uc3QgdGFyZ2V0ID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CiAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5tYXgoMCwgTWF0aC5taW4oKG1vbnRoTmV0IC8gdGFyZ2V0KSAqIDEwMCwgMTAwKSk7CiAgICAgICAgcHJvZ3Jlc3NUZXh0LnRleHRDb250ZW50ID0gYCR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0YXJnZXQpfWA7CiAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgaWYgKG1vbnRoTmV0IDwgMCkgY2xzID0gIm92ZXIiOwogICAgICAgIGVsc2UgaWYgKG1vbnRoTmV0IDwgdGFyZ2V0KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgcHJvZ3Jlc3NCYXIuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgIHByb2dyZXNzQmFyLnN0eWxlLndpZHRoID0gcGN0ICsgIiUiOwogICAgICB9IGVsc2UgewogICAgICAgIHByb2dyZXNzU2VjdGlvbi5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KTsKICAgIH0KCiAgICAvLyBDb25zZWlscyA6IGNyb2lzZSBkw6lwYXNzZW1lbnRzIGRlIGJ1ZGdldCAob25nbGV0IFRhYmxlYXUgZGUgYm9yZCkgZXQKICAgIC8vIHRlbmRhbmNlcyBwYXIgY2F0w6lnb3JpZSBwb3VyIHBvaW50ZXIgdmVycyBjZSBxdWkgYWlkZSBsZSBwbHVzIMOgCiAgICAvLyBhdHRlaW5kcmUgbCdvYmplY3RpZiDigJQgcGFzIHVuZSBJQSwganVzdGUgZGVzIHLDqGdsZXMgc2ltcGxlcyBzdXIgZGVzCiAgICAvLyBkb25uw6llcyBkw6lqw6AgY2FsY3Vsw6llcyBhaWxsZXVycyBkYW5zIGwnYXBwLgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KSB7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWFkdmljZS1saXN0Iik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtZW1wdHkiKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBjb25zdCBhZHZpY2UgPSBbXTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiBtb250aFRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBjb25zdCB0cmVuZEJ5Q2F0ZWdvcnkgPSBPYmplY3QuZnJvbUVudHJpZXModHJlbmRzLm1hcCgodCkgPT4gW3QuY2F0ZWdvcnksIHRdKSk7CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0LCB0cmnDqWVzIHBhciBtb250YW50IGRlCiAgICAgIC8vIGTDqXBhc3NlbWVudCBkw6ljcm9pc3NhbnQg4oCUIGNlIHNvbnQgbGVzIGxldmllcnMgbGVzIHBsdXMgdXRpbGVzLgogICAgICBjb25zdCBvdmVyQnVkZ2V0ID0gW107CiAgICAgIGZvciAoY29uc3QgYnVkZ2V0IG9mIGFsbEJ1ZGdldHMpIHsKICAgICAgICBjb25zdCBzcGVudCA9IG1vbnRoVG90YWxzW2J1ZGdldC5jYXRlZ29yeV0gfHwgMDsKICAgICAgICBpZiAoc3BlbnQgPiBidWRnZXQuYW1vdW50KSB7CiAgICAgICAgICBvdmVyQnVkZ2V0LnB1c2goeyBjYXRlZ29yeTogYnVkZ2V0LmNhdGVnb3J5LCBzcGVudCwgYnVkZ2V0OiBidWRnZXQuYW1vdW50LCBvdmVyOiBzcGVudCAtIGJ1ZGdldC5hbW91bnQgfSk7CiAgICAgICAgfQogICAgICB9CiAgICAgIG92ZXJCdWRnZXQuc29ydCgoYSwgYikgPT4gYi5vdmVyIC0gYS5vdmVyKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBvdmVyQnVkZ2V0LnNsaWNlKDAsIDMpKSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tpdGVtLmNhdGVnb3J5XSB8fCBpdGVtLmNhdGVnb3J5OwogICAgICAgIGNvbnN0IHRyZW5kID0gdHJlbmRCeUNhdGVnb3J5W2l0ZW0uY2F0ZWdvcnldOwogICAgICAgIGxldCB0ZXh0ID0gYFR1IGFzIGTDqXBhc3PDqSB0b24gYnVkZ2V0IDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5vdmVyKX0gY2UgbW9pcy1jaS5gOwogICAgICAgIGlmICh0cmVuZCAmJiB0cmVuZC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRleHQgKz0gYCBMYSB0ZW5kYW5jZSBlc3Qgw6AgbGEgaGF1c3NlICgrJHtNYXRoLnJvdW5kKHRyZW5kLnJhdGlvICogMTAwKX0lIHZzIHRhIG1veWVubmUpIOKAlCByw6lkdWlyZSBjZXMgZMOpcGVuc2VzIHQnYWlkZXJhaXQgbGUgcGx1cyDDoCBhdHRlaW5kcmUgdG9uIG9iamVjdGlmLmA7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHRleHQgKz0gYCBFc3NhaWUgZGUgcmFtZW5lciDDp2Egc291cyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmJ1ZGdldCl9IGxlIG1vaXMgcHJvY2hhaW4uYDsKICAgICAgICB9CiAgICAgICAgYWR2aWNlLnB1c2goeyB0eXBlOiAid2FybmluZyIsIGljb246ICLimqDvuI8iLCB0ZXh0IH0pOwogICAgICB9CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBuZXR0ZSBoYXVzc2UgbcOqbWUgc2FucyBidWRnZXQgZMOpcGFzc8OpIChvdSBzYW5zIGJ1ZGdldAogICAgICAvLyBkw6lmaW5pIGR1IHRvdXQpIDogdW4gc2lnbmFsIHV0aWxlIGVuIHNvaS4KICAgICAgY29uc3QgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0ID0gdHJlbmRzCiAgICAgICAgLmZpbHRlcigodCkgPT4gdC5kaXJlY3Rpb24gPT09ICJ1cCIgJiYgdC5hdmVyYWdlID4gMCAmJiAhb3ZlckJ1ZGdldC5zb21lKChvKSA9PiBvLmNhdGVnb3J5ID09PSB0LmNhdGVnb3J5KSkKICAgICAgICAuc29ydCgoYSwgYikgPT4gYi5yYXRpbyAtIGEucmF0aW8pCiAgICAgICAgLnNsaWNlKDAsIDIpOwogICAgICBmb3IgKGNvbnN0IHQgb2YgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0KSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5OwogICAgICAgIGFkdmljZS5wdXNoKHsKICAgICAgICAgIHR5cGU6ICJpbmZvIiwKICAgICAgICAgIGljb246ICLwn5OIIiwKICAgICAgICAgIHRleHQ6IGBUZXMgZMOpcGVuc2VzIGVuIDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gc29udCBlbiBoYXVzc2UgZGUgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSUgcGFyIHJhcHBvcnQgw6AgdGEgbW95ZW5uZSDigJQgw6Agc3VydmVpbGxlciBzaSB0dSB2ZXV4IMOpcGFyZ25lciBwbHVzLmAsCiAgICAgICAgfSk7CiAgICAgIH0KCiAgICAgIC8vIE9iamVjdGlmIGF0dGVpbnQgLyBlbiBib25uZSB2b2llIGNlIG1vaXMtY2kuCiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBpZiAobW9udGhOZXQgPj0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogInBvc2l0aXZlIiwKICAgICAgICAgICAgaWNvbjogIvCfjokiLAogICAgICAgICAgICB0ZXh0OiBgT2JqZWN0aWYgYXR0ZWludCAhIFR1IGFzIGTDqWrDoCBtaXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobW9udGhOZXQpfSBkZSBjw7R0w6kgY2UgbW9pcy1jaSwgYXUtZGVsw6AgZGUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0gZWxzZSBpZiAob3ZlckJ1ZGdldC5sZW5ndGggPT09IDAgJiYgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0Lmxlbmd0aCA9PT0gMCkgewogICAgICAgICAgYWR2aWNlLnVuc2hpZnQoewogICAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICAgIGljb246ICLwn5GNIiwKICAgICAgICAgICAgdGV4dDogYFBhcyBkZSBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0IGNlIG1vaXMtY2kuIElsIHRlIHJlc3RlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0IC0gbW9udGhOZXQpfSDDoCDDqWNvbm9taXNlciBwb3VyIGF0dGVpbmRyZSB0b24gb2JqZWN0aWYgZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpfS5gLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBpZiAoYWR2aWNlLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhZHZpY2UpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAiYWR2aWNlLWNhcmQgIiArIGl0ZW0udHlwZTsKICAgICAgICBjb25zdCBpY29uID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGljb24uY2xhc3NOYW1lID0gImFkdmljZS1pY29uIjsKICAgICAgICBpY29uLnRleHRDb250ZW50ID0gaXRlbS5pY29uOwogICAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgdGV4dC5pbm5lckhUTUwgPSBpdGVtLnRleHQ7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChpY29uKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKHRleHQpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCkgewogICAgICBjb25zdCB1cGRhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIsIHsKICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnksIGFtb3VudCB9KSwKICAgICAgfSk7CiAgICAgIGNvbnN0IGlkeCA9IGFsbEJ1ZGdldHMuZmluZEluZGV4KChiKSA9PiBiLmNhdGVnb3J5ID09PSBjYXRlZ29yeSk7CiAgICAgIGlmIChpZHggPj0gMCkgYWxsQnVkZ2V0c1tpZHhdID0gdXBkYXRlZDsKICAgICAgZWxzZSBhbGxCdWRnZXRzLnB1c2godXBkYXRlZCk7CiAgICB9CgogICAgY29uc3QgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeSA9IHt9OwogICAgY29uc3QgQlVER0VUX0hJU1RPUllfTU9OVEhTID0gNjsKCiAgICAvLyBMZXMgTiBkZXJuaWVycyBtb2lzIChjbMOpcyAiWVlZWS1NTSIpLCBkdSBwbHVzIGFuY2llbiBhdSBwbHVzIHLDqWNlbnQsCiAgICAvLyBlbiBmaW5pc3NhbnQgcGFyIGVuZE1vbnRoS2V5IGluY2x1cy4KICAgIGZ1bmN0aW9uIGxhc3ROTW9udGhLZXlzKG4sIGVuZE1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IFt5LCBtXSA9IGVuZE1vbnRoS2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGtleXMgPSBbXTsKICAgICAgZm9yIChsZXQgaSA9IG4gLSAxOyBpID49IDA7IGktLSkgewogICAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSh5LCBtIC0gMSAtIGksIDEpOwogICAgICAgIGtleXMucHVzaChkLmdldEZ1bGxZZWFyKCkgKyAiLSIgKyBTdHJpbmcoZC5nZXRNb250aCgpICsgMSkucGFkU3RhcnQoMiwgIjAiKSk7CiAgICAgIH0KICAgICAgcmV0dXJuIGtleXM7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidWRnZXRzLWxpc3QiKTsKICAgICAgaWYgKCF3cmFwKSByZXR1cm47CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgY3VycmVudE1vbnRoS2V5KTsKCiAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpKSBkZWxldGUgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVtrZXldOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSkgewogICAgICAgIGNvbnN0IGJ1ZGdldCA9IGFsbEJ1ZGdldHMuZmluZCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gdmFsdWUpOwogICAgICAgIGNvbnN0IHNwZW50ID0gdG90YWxzW3ZhbHVlXSB8fCAwOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ciOwoKICAgICAgICBjb25zdCBoZWFkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZC5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdy1oZWFkIjsKCiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4uY2xhc3NOYW1lID0gImJ1ZGdldC1jYXQtbmFtZSI7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBsYWJlbDsKCiAgICAgICAgY29uc3QgYW1vdW50cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRzLmNsYXNzTmFtZSA9ICJidWRnZXQtYW1vdW50cyI7CiAgICAgICAgY29uc3Qgc3BlbnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHNwZW50U3Bhbi50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzcGVudCkgKyAiIC8gIjsKICAgICAgICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgaW5wdXQudHlwZSA9ICJudW1iZXIiOwogICAgICAgIGlucHV0LmNsYXNzTmFtZSA9ICJidWRnZXQtaW5wdXQiOwogICAgICAgIGlucHV0Lm1pbiA9ICIwIjsKICAgICAgICBpbnB1dC5zdGVwID0gIjEiOwogICAgICAgIGlucHV0LnBsYWNlaG9sZGVyID0gIuKAlCI7CiAgICAgICAgaWYgKGJ1ZGdldCkgaW5wdXQudmFsdWUgPSBidWRnZXQuYW1vdW50OwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoc3BlbnRTcGFuKTsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKGlucHV0KTsKICAgICAgICBidWRnZXRJbnB1dHNCeUNhdGVnb3J5W3ZhbHVlXSA9IGlucHV0OwoKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKG5hbWVTcGFuKTsKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKGFtb3VudHMpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChoZWFkKTsKCiAgICAgICAgaWYgKGJ1ZGdldCkgewogICAgICAgICAgY29uc3QgdHJhY2sgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHRyYWNrLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLXRyYWNrIjsKICAgICAgICAgIGNvbnN0IGZpbGwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIGNvbnN0IHJhdGlvID0gc3BlbnQgLyBidWRnZXQuYW1vdW50OwogICAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5taW4ocmF0aW8gKiAxMDAsIDEwMCk7CiAgICAgICAgICBsZXQgY2xzID0gIm9rIjsKICAgICAgICAgIGlmIChyYXRpbyA+PSAxKSBjbHMgPSAib3ZlciI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA+PSAwLjcpIGNscyA9ICJ3YXJuaW5nIjsKICAgICAgICAgIGZpbGwuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgICAgZmlsbC5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgICAgIHRyYWNrLmFwcGVuZENoaWxkKGZpbGwpOwogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHRyYWNrKTsKCiAgICAgICAgICBjb25zdCBzdHJpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgc3RyaXAuY2xhc3NOYW1lID0gImJ1ZGdldC1oaXN0b3J5LXN0cmlwIjsKICAgICAgICAgIGZvciAoY29uc3QgaGlzdEtleSBvZiBsYXN0Tk1vbnRoS2V5cyhCVURHRVRfSElTVE9SWV9NT05USFMsIGN1cnJlbnRNb250aEtleSkpIHsKICAgICAgICAgICAgY29uc3QgeyB0b3RhbHM6IGhpc3RUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBoaXN0S2V5KTsKICAgICAgICAgICAgY29uc3QgaGlzdFNwZW50ID0gaGlzdFRvdGFsc1t2YWx1ZV0gfHwgMDsKICAgICAgICAgICAgY29uc3QgZG90ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgICBpZiAoaGlzdFNwZW50ID09PSAwKSB7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCBlbXB0eSI7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgY29uc3QgaGlzdFJhdGlvID0gaGlzdFNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgICAgICBsZXQgaGlzdENscyA9ICJvayI7CiAgICAgICAgICAgICAgaWYgKGhpc3RSYXRpbyA+PSAxKSBoaXN0Q2xzID0gIm92ZXIiOwogICAgICAgICAgICAgIGVsc2UgaWYgKGhpc3RSYXRpbyA+PSAwLjcpIGhpc3RDbHMgPSAid2FybmluZyI7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCAiICsgaGlzdENsczsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBbaHksIGhtXSA9IGhpc3RLZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgICAgY29uc3QgbW9udGhMYWJlbCA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGh5LCBobSAtIDEsIDEpKTsKICAgICAgICAgICAgY29uc3QgZGV0YWlsVGV4dCA9IGAke21vbnRoTGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaGlzdFNwZW50KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChidWRnZXQuYW1vdW50KX1gOwogICAgICAgICAgICBkb3QudGl0bGUgPSBkZXRhaWxUZXh0OyAvLyBhZmZpY2jDqSBhdSBzdXJ2b2wgc3VyIG9yZGluYXRldXIKICAgICAgICAgICAgLy8gU3VyIG1vYmlsZSBpbCBuJ3kgYSBwYXMgZGUgc3Vydm9sIDogdW4gdGFwIHN1ciBsYSBiYXJyZSBtb250cmUKICAgICAgICAgICAgLy8gbGUgbcOqbWUgZMOpdGFpbCBkYW5zIHVuIHRvYXN0LgogICAgICAgICAgICBkb3QuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93VG9hc3QoZGV0YWlsVGV4dCkpOwogICAgICAgICAgICBzdHJpcC5hcHBlbmRDaGlsZChkb3QpOwogICAgICAgICAgfQogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHN0cmlwKTsKICAgICAgICB9CgogICAgICAgIHdyYXAuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRDdXN0b21DYXRlZ29yaWVzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiKTsKICAgICAgICBmb3IgKGNvbnN0IHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0gb2YgaXRlbXMpIHsKICAgICAgICAgIGlmIChjYXRlZ29yaWVzQnlUeXBlW3R5cGVdICYmICFjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdmFsdWUpKSB7CiAgICAgICAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgICAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgY2F0w6lnb3JpZXMgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGtleXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiKTsKICAgICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoa2V5cyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgdW5lIHN1Z2dlc3Rpb24gZMOpasOgIHZ1ZSByw6lhcHBhcmHDrnQgdW5lIGZvaXMuCiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzbHVnaWZ5Q2F0ZWdvcnkobGFiZWwpIHsKICAgICAgcmV0dXJuICgKICAgICAgICBsYWJlbAogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gZW5sw6h2ZSBsZXMgYWNjZW50cwogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC50cmltKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0rL2csICJfIikKICAgICAgICAgIC5yZXBsYWNlKC9eXyt8XyskL2csICIiKSB8fCAiYXV0cmUiCiAgICAgICk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc2F2ZUN1c3RvbUNhdGVnb3J5KHR5cGUsIHZhbHVlLCBsYWJlbCkgewogICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiQ2F0w6lnb3JpZSBjcsOpw6llIGljaSwgbWFpcyBwYXMgc2F1dmVnYXJkw6llIHN1ciBsZSBzZXJ2ZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gNDAxKSB7CiAgICAgICAgLy8gSmV0b24gYWJzZW50LCBpbnZhbGlkZSBvdSBleHBpcsOpIDogcmV0b3VyIMOgIGwnw6ljcmFuIGRlIHZlcnJvdWlsbGFnZQogICAgICAgIC8vIHBsdXTDtHQgcXVlIGQnYWZmaWNoZXIgdW5lIGVycmV1ciB0ZWNobmlxdWUgaW5jb21wcsOpaGVuc2libGUuCiAgICAgICAgc2hvd0xvY2tTY3JlZW4oKTsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoIlNlc3Npb24gZXhwaXLDqWUsIHJlY29ubmVjdGUtdG9pLiIpOwogICAgICB9CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgLy8gcmVzLnN0YXR1c1RleHQgZXN0IHNvdXZlbnQgdmlkZSAobmF2aWdhdGV1cnMgZW4gSFRUUC8yLCB1dGlsaXPDqSBwYXIKICAgICAgICAvLyBWZXJjZWwpLCBkb25jIG9uIG5lIHBldXQgcGFzIGNvbXB0ZXIgZGVzc3VzIGNvbW1lIG1lc3NhZ2UgcGFyCiAgICAgICAgLy8gZMOpZmF1dCA6IG9uIHJldG9tYmUgc3VyIGxlIGNvZGUgSFRUUCBwb3VyIG5lIGphbWFpcyBhZmZpY2hlciB1bgogICAgICAgIC8vIG1lc3NhZ2UgZCdlcnJldXIgdmlkZS4KICAgICAgICBsZXQgZGV0YWlsID0gcmVzLnN0YXR1c1RleHQgfHwgYEVycmV1ciBIVFRQICR7cmVzLnN0YXR1c31gOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGRhdGEuZGV0YWlsIHx8IGRldGFpbDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIHRocm93IG5ldyBFcnJvcihkZXRhaWwpOwogICAgICB9CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSAyMDQpIHJldHVybiBudWxsOwogICAgICByZXR1cm4gcmVzLmpzb24oKTsKICAgIH0KCiAgICBmdW5jdGlvbiB0b2RheUlzbygpIHsKICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IHR6ID0gZC5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKGQuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgc2VsZWN0ZWRWYWx1ZSA9IG51bGwpIHsKICAgICAgY2F0ZWdvcnlJbnB1dC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgaWYgKHZhbHVlID09PSAoc2VsZWN0ZWRWYWx1ZSB8fCAiYXV0cmUiKSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBjYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBtb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiTW9kaWZpZXIgbGEgdHJhbnNhY3Rpb24iIDogIk5vdXZlbGxlIHRyYW5zYWN0aW9uIjsKICAgICAgc2F2ZUJ0bi50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFR5cGUodHggPyB0eC50eXBlIDogImV4cGVuc2UiKTsKICAgICAgYW1vdW50SW5wdXQudmFsdWUgPSB0eCA/IHR4LmFtb3VudCA6ICIiOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoY3VycmVudFR5cGUsIHR4ID8gdHguY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgZGVzY3JpcHRpb25JbnB1dC52YWx1ZSA9IHR4ID8gKHR4LmRlc2NyaXB0aW9uIHx8ICIiKSA6ICIiOwogICAgICBkYXRlSW5wdXQudmFsdWUgPSB0eCA/IHR4LmV4cGVuc2VfZGF0ZSA6IHRvZGF5SXNvKCk7CgogICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICBpZiAoaXNFZGl0ICYmIHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHR4LmlkKTsKICAgICAgfQoKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBhbW91bnRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSB7CiAgICAgIC8vIE3Dqm1lIG1vbnRhbnQvY2F0w6lnb3JpZS9kZXNjcmlwdGlvbiwgbWFpcyBkYXTDqSBkJ2F1am91cmQnaHVpIGV0IHNhbnMKICAgICAgLy8gaWQgOiBsYSBzYXV2ZWdhcmRlIGNyw6llcmEgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uICh2b2lyIG9wZW5Nb2RhbCkuCiAgICAgIG9wZW5Nb2RhbCh7IC4uLnR4LCBpZDogbnVsbCwgZXhwZW5zZV9kYXRlOiB0b2RheUlzbygpIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWRpdGluZ0lkID0gbnVsbDsKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogY3VycmVudFR5cGUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbklucHV0LnZhbHVlLnRyaW0oKSB8fCBudWxsLAogICAgICAgIGV4cGVuc2VfZGF0ZTogZGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgIH07CgogICAgICBzYXZlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoZWRpdGluZ0lkKSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgICBpZiAocGVuZGluZ1JlY2VpcHRGaWxlKSB7CiAgICAgICAgICAgIC8vIExhIHBob3RvIGEgw6l0w6kgY2hvaXNpZSBhdmFudCBxdWUgbGEgdHJhbnNhY3Rpb24gbidleGlzdGUgOiBvbgogICAgICAgICAgICAvLyBsJ2Vudm9pZSBtYWludGVuYW50IHF1J29uIGEgdW4gaWQuCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBwZW5kaW5nUmVjZWlwdEZpbGUpOwogICAgICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2NyZWF0ZWQuaWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICAgICAgYm9keTogZm9ybURhdGEsCiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIGNyw6nDqWUsIG1haXMgbCdlbnZvaSBkZSBsYSBwaG90byBhIMOpY2hvdcOpIiwgdHJ1ZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YXV4IGdsb2JhdXggKFNvbGRlL0TDqXBlbnNlcy9SZXZlbnVzKSA6IGNhbGN1bMOpcyBzdXIgVE9VVEVTIGxlcwogICAgLy8gdHJhbnNhY3Rpb25zLCBpbmTDqXBlbmRhbW1lbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlIOKAlCB1biBmaWx0cmUKICAgIC8vIHNlcnQgw6AgY2hlcmNoZXIgZGFucyBsYSBsaXN0ZSwgcGFzIMOgIHJlY2FsY3VsZXIgbGUgc29sZGUgcsOpZWwuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKSB7CiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgLy8gQ29uc3RydWN0aW9uIGRlIGxhIGxpc3RlIGRlIGNhcnRlcyBhZmZpY2jDqWUgZGFucyBsJ29uZ2xldCBIaXN0b3JpcXVlIOKAlAogICAgLy8gcmXDp29pdCBkw6lqw6AgbGEgbGlzdGUgZmlsdHLDqWUgKHZvaXIgYXBwbHlIaXN0b3J5RmlsdGVycykuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbkxpc3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgaWYgKHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnRleHRDb250ZW50ID0gYWxsVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMAogICAgICAgICAgPyAiUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4iCiAgICAgICAgICA6ICJBdWN1biByw6lzdWx0YXQgcG91ciBjZXMgZmlsdHJlcy4iOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJ0eC1jYXJkICIgKyB0eC50eXBlOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAidHgtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAidHgtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRhdGVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGRhdGVTcGFuLmNsYXNzTmFtZSA9ICJ0eC1kYXRlIjsKICAgICAgICBkYXRlU3Bhbi50ZXh0Q29udGVudCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHR4LmV4cGVuc2VfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZGF0ZVNwYW4pOwogICAgICAgIGlmICh0eC5yZWN1cnJpbmdfZXhwZW5zZV9pZCkgewogICAgICAgICAgY29uc3QgcmVjQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICByZWNCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjdXJyaW5nLWJhZGdlIjsKICAgICAgICAgIHJlY0JhZGdlLnRleHRDb250ZW50ID0gIvCflIEiOwogICAgICAgICAgcmVjQmFkZ2UudGl0bGUgPSAiQ3LDqcOpZSBhdXRvbWF0aXF1ZW1lbnQgZGVwdWlzIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY0JhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgICAgY29uc3QgcmVjZWlwdEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudHlwZSA9ICJidXR0b24iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWNlaXB0LWJhZGdlIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50ZXh0Q29udGVudCA9ICLwn6e+IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50aXRsZSA9ICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiVm9pciBsYSBwaG90byBkdSByZcOndSIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY2VpcHRMaWdodGJveCh0eC5pZCkpOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY2VpcHRCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWhpc3RvcnkiKS5zdHlsZS5kaXNwbGF5ID0gdmlldyA9PT0gImhpc3RvcnkiID8gImJsb2NrIiA6ICJub25lIjsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBpZiAodmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICBpZiAodmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJzYXZpbmdzIikpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwogICAgbGV0IHllYXJseUNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgLy8gVW5lIGNoYXJnZSByw6ljdXJyZW50ZSBjb21wdGUgcG91ciB1biBtb2lzIGRvbm7DqSBzaSBjZSBtb2lzIGVzdCBkYW5zIHNhCiAgICAvLyBww6lyaW9kZSBkJ2FjdGl2aXTDqSA6IHBhcyBhdmFudCBzYSBkYXRlIGRlIGTDqWJ1dCAoc2kgcG9zw6llKSwgcGFzIGFwcsOocwogICAgLy8gbGUgbW9pcyBkZSBzYSBkYXRlIGRlIGZpbiAoc2kgcG9zw6llKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSB7CiAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUgJiYgbW9udGhLZXkgPCBpdGVtLnN0YXJ0X2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUgJiYgbW9udGhLZXkgPiBpdGVtLmVuZF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIHJldHVybiB0cnVlOwogICAgfQoKICAgIC8vIEpvdXIgZHUgbW9pcyBqdXNxdSdhdXF1ZWwgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBlc3QgY29uc2lkw6lyw6llIGNvbW1lCiAgICAvLyAiZMOpasOgIHByw6lsZXbDqWUiIHBvdXIgbGUgbW9pcyBgbW9udGhLZXlgIDogdG91cyBsZXMgam91cnMgcG91ciB1biBtb2lzCiAgICAvLyBkw6lqw6AgcGFzc8OpLCBhdWN1biBwb3VyIHVuIG1vaXMgZnV0dXIsIGV0IGxlIGpvdXIgZHUgam91ciBwb3VyIGxlIG1vaXMKICAgIC8vIGVuIGNvdXJzLiBQZXJtZXQgZGUgZGlzdGluZ3VlciBjZSBxdWkgZXN0IGTDqWrDoCBhcnJpdsOpIGRlIGNlIHF1aSBlc3QKICAgIC8vIHNldWxlbWVudCBwcsOpdnUgKGV4IDogdW4gYWJvbm5lbWVudCBwcsOpbGV2w6kgbGUgMjUsIG9uIGVzdCBsZSAyKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSkgewogICAgICBpZiAobW9udGhLZXkgPCBjdXJyZW50TW9udGhLZXkpIHJldHVybiAzMTsKICAgICAgaWYgKG1vbnRoS2V5ID4gY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMDsKICAgICAgcmV0dXJuIHRvZGF5RGF5OwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCkgbW9udGhTZXQuYWRkKG1vbnRoS2V5T2YodG9kYXlJc28oKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gIiI7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gIkF1Y3VuZSBkb25uw6llIjsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgc2VsZWN0LnZhbHVlID0gbW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IG1vbnRoc1swXTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCB1cGNvbWluZ05vdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIpOwogICAgICBjb25zdCB1cGNvbWluZ1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCIpOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBjb25zdCBjdXRvZmYgPSByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBVbiBzZXVsIHNvbGRlIG5ldCAiw6AgdmVuaXIiIChyZXZlbnVzIHLDqWN1cnJlbnRzIMOgIHZlbmlyIG1vaW5zIGTDqXBlbnNlcwogICAgICAvLyByw6ljdXJyZW50ZXMgw6AgdmVuaXIpLCBwbHV0w7R0IHF1ZSBkZXV4IGNoaWZmcmVzIHPDqXBhcsOpcyA6IHBsdXMgc2ltcGxlCiAgICAgIC8vIMOgIGxpcmUgZCd1biBjb3VwIGQnxZNpbC4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUgc29udCBQQVMKICAgICAgLy8gYWpvdXTDqWVzIGljaSA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUgdnJhaWVzIHRyYW5zYWN0aW9ucwogICAgICAvLyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzIGRhbnMgYHRvdGFsc2AKICAgICAgLy8gY2ktZGVzc3VzIOKAlCBsZXMgYWpvdXRlciDDoCBub3V2ZWF1IGxlcyBjb21wdGVyYWl0IGVuIGRvdWJsZS4KICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IGN1dG9mZikgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIE3Dqm1lIHByaW5jaXBlIHF1ZSByZW5kZXJDYXRlZ29yeUNoYXJ0LCBjw7R0w6kgcmV2ZW51cyDigJQgcGFzIGRlIG5vdGUgIsOgCiAgICAvLyB2ZW5pciIgaWNpLCBlbGxlIHJlc3RlIHVuaXF1ZW1lbnQgc3VyIGxlIGNhbWVtYmVydCBkZXMgZMOpcGVuc2VzIHBvdXIKICAgIC8vIG5lIHBhcyBhZmZpY2hlciBsZSBtw6ptZSBjaGlmZnJlIG5ldCDDoCBkZXV4IGVuZHJvaXRzLgogICAgZnVuY3Rpb24gcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJpbmNvbWUiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGlmIChpbmNvbWVDYXRlZ29yeUNoYXJ0KSB7IGluY29tZUNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgICAgbW9udGhseVtrZXldW3R4LnR5cGVdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFRvdWpvdXJzIGluY2x1cmUgbGUgbW9pcyBlbiBjb3VycyAobcOqbWUgc2FucyB0cmFuc2FjdGlvbikgcydpbCBleGlzdGUKICAgICAgLy8gZGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBwb3VyIHF1J2lsIGFwcGFyYWlzc2Ugc2FucyBhdHRlbmRyZSBsYQogICAgICAvLyBwcmVtacOocmUgdHJhbnNhY3Rpb24gZHUgbW9pcy4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUKICAgICAgLy8gc29udCBwbHVzIGFqb3V0w6llcyBpY2kgw6AgbGEgbWFpbiA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUKICAgICAgLy8gdnJhaWVzIHRyYW5zYWN0aW9ucyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzCiAgICAgIC8vIGRhbnMgYG1vbnRobHlgIHZpYSBsYSBib3VjbGUgc3VyIGB0cmFuc2FjdGlvbnNgIGNpLWRlc3N1cyDigJQgY2UgcXVpCiAgICAgIC8vIG4nZXN0IHBhcyBlbmNvcmUgYXJyaXbDqSBlc3QgcsOpc3Vtw6kgYWlsbGV1cnMgKHNvbGRlIG5ldCAiw6AgdmVuaXIiKS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29tcGFyZXIgZGV1eCBtb2lzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3Qgc2VsZWN0QSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKTsKICAgICAgY29uc3Qgc2VsZWN0QiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKTsKCiAgICAgIGZvciAoY29uc3Qgc2VsZWN0IG9mIFtzZWxlY3RBLCBzZWxlY3RCXSkgewogICAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGlmIChtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkpIHNlbGVjdC52YWx1ZSA9IHByZXZpb3VzVmFsdWU7CiAgICAgIH0KICAgICAgLy8gUGFyIGTDqWZhdXQgOiBtb2lzIGVuIGNvdXJzIHZzIG1vaXMgcHLDqWPDqWRlbnQsIHNpIGxlcyBkZXV4IGV4aXN0ZW50LgogICAgICBpZiAoIXNlbGVjdEEudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDApIHNlbGVjdEEudmFsdWUgPSBtb250aHNbMF07CiAgICAgIGlmICghc2VsZWN0Qi52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMSkgc2VsZWN0Qi52YWx1ZSA9IG1vbnRoc1sxXTsKICAgIH0KCiAgICBmdW5jdGlvbiBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgbW9udGhLZXkpIHsKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICByZXR1cm4geyB0b3RhbHMsIHRvdGFsIH07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyTW9udGhDb21wYXJpc29uKCkgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtdGFibGUtd3JhcCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtZW1wdHkiKTsKICAgICAgY29uc3QgbW9udGhBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLnZhbHVlOwogICAgICBjb25zdCBtb250aEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikudmFsdWU7CgogICAgICBpZiAoIW1vbnRoQSB8fCAhbW9udGhCKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQSwgdG90YWw6IGdyYW5kQSB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNCLCB0b3RhbDogZ3JhbmRCIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhCKTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KFsuLi5PYmplY3Qua2V5cyh0b3RhbHNBKSwgLi4uT2JqZWN0LmtleXModG90YWxzQildKV0uc29ydCgKICAgICAgICAoYSwgYikgPT4gKHRvdGFsc0JbYl0gfHwgMCkgLSAodG90YWxzQVthXSB8fCAwKQogICAgICApOwoKICAgICAgY29uc3QgW3lhLCBtYV0gPSBtb250aEEuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgW3liLCBtYl0gPSBtb250aEIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgbGFiZWxBID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWEsIG1hIC0gMSwgMSkpOwogICAgICBjb25zdCBsYWJlbEIgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YiwgbWIgLSAxLCAxKSk7CgogICAgICAvLyBEaWZmID0gbW9udGFudCBkdSBtb2lzIEIgbW9pbnMgY2VsdWkgZHUgbW9pcyBBLiBQb3VyIGRlcyBkw6lwZW5zZXMsCiAgICAgIC8vIGTDqXBlbnNlciBQTFVTIChkaWZmIHBvc2l0aWYpIGVzdCBsYSBtYXV2YWlzZSBub3V2ZWxsZSDihpIgcm91Z2UgOyBlbgogICAgICAvLyBkw6lwZW5zZXIgTU9JTlMgKGRpZmYgbsOpZ2F0aWYpIOKGkiB2ZXJ0LgogICAgICBmdW5jdGlvbiBkaWZmQ2VsbChhLCBiKSB7CiAgICAgICAgY29uc3QgZGlmZiA9IGIgLSBhOwogICAgICAgIGlmIChNYXRoLmFicyhkaWZmKSA8IDAuMDEpIHJldHVybiBgPHRkPuKAlDwvdGQ+YDsKICAgICAgICBjb25zdCBjbHMgPSBkaWZmID4gMCA/ICJkaWZmLW5lZ2F0aXZlIiA6ICJkaWZmLXBvc2l0aXZlIjsKICAgICAgICByZXR1cm4gYDx0ZCBjbGFzcz0iJHtjbHN9Ij4ke2RpZmYgPiAwID8gIisiIDogIiJ9JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGlmZil9PC90ZD5gOwogICAgICB9CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPiR7bGFiZWxBfTwvdGg+PHRoPiR7bGFiZWxCfTwvdGg+PHRoPkRpZmbDqXJlbmNlPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgY2F0IG9mIGNhdGVnb3JpZXMpIHsKICAgICAgICBjb25zdCBhID0gdG90YWxzQVtjYXRdIHx8IDA7CiAgICAgICAgY29uc3QgYiA9IHRvdGFsc0JbY2F0XSB8fCAwOwogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHthbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdH08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiKX08L3RkPiR7ZGlmZkNlbGwoYSwgYil9PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDx0ciBjbGFzcz0idG90YWwtcm93Ij48dGQ+VG90YWwgZMOpcGVuc2VzPC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRBKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEIpfTwvdGQ+JHtkaWZmQ2VsbChncmFuZEEsIGdyYW5kQil9PC90cj5gOwogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ2FsY3VsZSwgcG91ciBjaGFxdWUgY2F0w6lnb3JpZSBkZSBkw6lwZW5zZSwgbGEgbW95ZW5uZSBtZW5zdWVsbGUsIGxlCiAgICAvLyBtb250YW50IGR1IG1vaXMgZW4gY291cnMsIGV0IGxhIHRlbmRhbmNlIChkaXJlY3Rpb24gKyByYXRpbyB2cwogICAgLy8gbW95ZW5uZSkuIFBhcnRhZ8OpIGVudHJlIGxlIHRhYmxlYXUgIk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUiCiAgICAvLyBldCBsZXMgY29uc2VpbHMgZCfDqXBhcmduZSwgcG91ciBuZSBwYXMgZHVwbGlxdWVyIGNldHRlIGxvZ2lxdWUuCiAgICBmdW5jdGlvbiBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoS2V5cyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKV0uc29ydCgpOwogICAgICBpZiAobW9udGhLZXlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIFtdOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleXNbbW9udGhLZXlzLmxlbmd0aCAtIDFdOwogICAgICBjb25zdCBuYk1vbnRocyA9IG1vbnRoS2V5cy5sZW5ndGg7CgogICAgICAvLyB0b3RhbCBwYXIgY2F0w6lnb3JpZSwgZXQgcGFyIGNhdMOpZ29yaWUrbW9pcyAocG91ciBpc29sZXIgbGUgbW9pcyBlbiBjb3VycykKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBjb25zdCBjdXJyZW50TW9udGhCeUNhdGVnb3J5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIikgY29udGludWU7CiAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpID09PSBjdXJyZW50TW9udGhLZXkpIHsKICAgICAgICAgIGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICByZXR1cm4gY2F0ZWdvcmllcy5tYXAoKGNhdCkgPT4gewogICAgICAgIGNvbnN0IGF2ZXJhZ2UgPSB0b3RhbHNCeUNhdGVnb3J5W2NhdF0gLyBuYk1vbnRoczsKICAgICAgICBjb25zdCBjdXJyZW50ID0gY3VycmVudE1vbnRoQnlDYXRlZ29yeVtjYXRdIHx8IDA7CiAgICAgICAgbGV0IGRpcmVjdGlvbiA9ICJzdGFibGUiOwogICAgICAgIGxldCByYXRpbyA9IDA7CiAgICAgICAgaWYgKGF2ZXJhZ2UgPiAwKSB7CiAgICAgICAgICByYXRpbyA9IChjdXJyZW50IC0gYXZlcmFnZSkgLyBhdmVyYWdlOwogICAgICAgICAgaWYgKHJhdGlvID4gMC4xNSkgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvIDwgLTAuMTUpIGRpcmVjdGlvbiA9ICJkb3duIjsKICAgICAgICB9IGVsc2UgaWYgKGN1cnJlbnQgPiAwKSB7CiAgICAgICAgICBkaXJlY3Rpb24gPSAidXAiOwogICAgICAgIH0KICAgICAgICByZXR1cm4geyBjYXRlZ29yeTogY2F0LCBhdmVyYWdlLCBjdXJyZW50LCByYXRpbywgZGlyZWN0aW9uIH07CiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRyZW5kLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC1lbXB0eSIpOwoKICAgICAgY29uc3QgdHJlbmRzID0gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh0cmVuZHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPk1veWVubmUvbW9pczwvdGg+PHRoPkNlIG1vaXMtY2k8L3RoPjx0aD5UZW5kYW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IHQgb2YgdHJlbmRzKSB7CiAgICAgICAgbGV0IHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZmxhdCI+4oaSIHN0YWJsZTwvc3Bhbj5gOwogICAgICAgIGlmICh0LmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdHJlbmRIdG1sID0gdC5hdmVyYWdlID4gMAogICAgICAgICAgICA/IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSArJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YAogICAgICAgICAgICA6IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSBub3V2ZWF1PC9zcGFuPmA7CiAgICAgICAgfSBlbHNlIGlmICh0LmRpcmVjdGlvbiA9PT0gImRvd24iKSB7CiAgICAgICAgICB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWRvd24iPuKGkyAke01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JTwvc3Bhbj5gOwogICAgICAgIH0KICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7YWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmF2ZXJhZ2UpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuY3VycmVudCl9PC90ZD48dGQ+JHt0cmVuZEh0bWx9PC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBCaWxhbiBhbm51ZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IE1PTlRIX1NIT1JUX0xBQkVMUyA9IFsKICAgICAgIkphbiIsICJGw6l2IiwgIk1hciIsICJBdnIiLCAiTWFpIiwgIkp1aW4iLCAiSnVpbCIsICJBb8O7dCIsICJTZXAiLCAiT2N0IiwgIk5vdiIsICJEw6ljIiwKICAgIF07CgogICAgZnVuY3Rpb24gcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0Iik7CiAgICAgIGNvbnN0IHllYXJzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSkpXS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBjdXJyZW50WWVhciA9IFN0cmluZyhuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCkpOwogICAgICBpZiAoIXllYXJzLmluY2x1ZGVzKGN1cnJlbnRZZWFyKSkgeWVhcnMudW5zaGlmdChjdXJyZW50WWVhcik7CgogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0geWVhcnMubWFwKCh5KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt5fSI+JHt5fTwvb3B0aW9uPmApLmpvaW4oIiIpOwogICAgICBzZWxlY3QudmFsdWUgPSB5ZWFycy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBjdXJyZW50WWVhcjsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFyID0gc2VsZWN0LnZhbHVlOwogICAgICBpZiAoIXllYXIpIHJldHVybjsKCiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC15ZWFybHkiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktZW1wdHkiKTsKICAgICAgY29uc3QgdGFibGVXcmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIik7CgogICAgICBjb25zdCB5ZWFyVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSA9PT0geWVhcik7CgogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGNvbnN0IGV4cGVuc2VCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IGluY29tZUJ5TW9udGggPSBBcnJheSgxMikuZmlsbCgwKTsKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHllYXJUcmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBtb250aEluZGV4ID0gTnVtYmVyKHR4LmV4cGVuc2VfZGF0ZS5zbGljZSg1LCA3KSkgLSAxOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgewogICAgICAgICAgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICBpbmNvbWVCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgZXhwZW5zZUJ5TW9udGhbbW9udGhJbmRleF0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICB0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBuZXQgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CgogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWV4cGVuc2VzIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktdG90YWwtaW5jb21lIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgICBjb25zdCBuZXRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktbmV0Iik7CiAgICAgIG5ldEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG5ldCk7CiAgICAgIG5ldEVsLmNsYXNzTmFtZSA9ICJ5ZWFybHktc3RhdC12YWx1ZSAiICsgKG5ldCA+PSAwID8gImluY29tZSIgOiAiZXhwZW5zZSIpOwoKICAgICAgaWYgKHllYXJseUNoYXJ0KSB7IHllYXJseUNoYXJ0LmRlc3Ryb3koKTsgeWVhcmx5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoeWVhclRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICB5ZWFybHlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHM6IE1PTlRIX1NIT1JUX0xBQkVMUywKICAgICAgICAgIGRhdGFzZXRzOiBbCiAgICAgICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBleHBlbnNlQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBpbmNvbWVCeU1vbnRoLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICAgICAgXSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogeyBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9IH0sCiAgICAgICAgfSwKICAgICAgfSk7CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPlRvdGFsPC90aD48dGg+JSBkZSBsJ2FubsOpZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYW1vdW50ID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdOwogICAgICAgIGNvbnN0IHBjdCA9IHRvdGFsRXhwZW5zZXMgPiAwID8gTWF0aC5yb3VuZCgoYW1vdW50IC8gdG90YWxFeHBlbnNlcykgKiAxMDApIDogMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7YWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXR9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYW1vdW50KX08L3RkPjx0ZD4ke3BjdH0lPC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiByZW5kZXJZZWFybHlPdmVydmlldyhhbGxUcmFuc2FjdGlvbnMpKTsKCiAgICBmdW5jdGlvbiByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKSB7CiAgICAgIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpOwogICAgICByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZVllYXJTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyWWVhcmx5T3ZlcnZpZXcodHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEaWN0w6llIHZvY2FsZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbWljQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1taWMiKTsKICAgIGNvbnN0IHZvaWNlQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtYmFubmVyIik7CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIHRyYW5zYWN0aW9uIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZSBzZXNzaW9uIGRlCiAgICAvLyBuYXZpZ2F0aW9uIChyZW1pcyDDoCB6w6lybyBzaSBvbiByZWNoYXJnZSBsYSBwYWdlKS4gU2VydCB1bmlxdWVtZW50IMOgCiAgICAvLyBhcHBsaXF1ZXIgdW5lIGNvcnJlY3Rpb24gKCJlbiBmYWl0IGMnw6l0YWl0IHBsdXTDtHQuLi4iKSBzdXIgbGEgYm9ubmUKICAgIC8vIHRyYW5zYWN0aW9uLiBTYW5zIMOnYSwgb3Ugc2kgbGEgcGhyYXNlIG4nZXN0IHBhcyB1bmUgY29ycmVjdGlvbiwgb24KICAgIC8vIGNyw6llIHRvdWpvdXJzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiDigJQgbWlldXggdmF1dCB1biBkb3VibG9uIHF1J3VuZQogICAgLy8gZMOpcGVuc2UgY29ycm9tcHVlIHBhciBlcnJldXIuCiAgICBsZXQgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IG51bGw7CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VCYW5uZXIodGV4dCkgewogICAgICBpZiAoIXRleHQpIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiYW5zd2VyIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9ICIiOwogICAgICB9IGVsc2UgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRWb2ljZUFuc3dlckJhbm5lcih0ZXh0KSB7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiYW5zd2VyIik7CiAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgfQoKICAgIC8vIFByb25vbmNlIGxhIHLDqXBvbnNlIMOgIHVuZSBxdWVzdGlvbiB2b2NhbGUgKCJBc3Npc3RhbnQgdm9jYWwgcXVlc3Rpb24iKS4KICAgIC8vIFB1ciBib251cyA6IHNpIGxhIHN5bnRow6hzZSB2b2NhbGUgbidlc3QgcGFzIGRpc3BvIG91IMOpY2hvdWUsIGxhIHLDqXBvbnNlCiAgICAvLyByZXN0ZSBhZmZpY2jDqWUgZGFucyBsZSBiYW5kZWF1LCBkb25jIG9uIGF2YWxlIGwnZXJyZXVyIHNhbnMgYmxvcXVlci4KICAgIGZ1bmN0aW9uIHNwZWFrVm9pY2VBbnN3ZXIodGV4dCkgewogICAgICBpZiAoISgic3BlZWNoU3ludGhlc2lzIiBpbiB3aW5kb3cpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5jYW5jZWwoKTsKICAgICAgICBjb25zdCB1dHRlcmFuY2UgPSBuZXcgU3BlZWNoU3ludGhlc2lzVXR0ZXJhbmNlKHRleHQpOwogICAgICAgIHV0dGVyYW5jZS5sYW5nID0gImZyLUZSIjsKICAgICAgICB3aW5kb3cuc3BlZWNoU3ludGhlc2lzLnNwZWFrKHV0dGVyYW5jZSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudC4KICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIGxldCBiYW5uZXJEZWxheSA9IDE1MDA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL3BhcnNlIiwgewogICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0ZXh0OiB0cmFuc2NyaXB0IH0pLAogICAgICAgICAgfSk7CiAgICAgICAgICBpZiAocGFyc2VkLmludGVudCA9PT0gInF1ZXN0aW9uIikgewogICAgICAgICAgICAvLyBRdWVzdGlvbiBzdXIgbGVzIGZpbmFuY2VzICgiY29tYmllbiBqJ2FpIGTDqXBlbnPDqSBlbgogICAgICAgICAgICAvLyByZXN0YXVyYW50IGNlIG1vaXMtY2kgPyIpIDogcmllbiBuJ2VzdCBlbnJlZ2lzdHLDqSwgb24gYWZmaWNoZQogICAgICAgICAgICAvLyAoZXQgb24gcHJvbm9uY2UpIGp1c3RlIGxhIHLDqXBvbnNlIGNhbGN1bMOpZSBjw7R0w6kgc2VydmV1ci4KICAgICAgICAgICAgc2V0Vm9pY2VBbnN3ZXJCYW5uZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgICAgIHNwZWFrVm9pY2VBbnN3ZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNjAwMDsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGF3YWl0IGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIGJhbm5lckRlbGF5KTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgbWljQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGlmIChpc0xpc3RlbmluZykgewogICAgICAgICAgcmVjb2duaXRpb24uc3RvcCgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICB0cnkgewogICAgICAgICAgcmVjb2duaXRpb24uc3RhcnQoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIC8vIHN0YXJ0KCkgamV0dGUgc2kgZMOpasOgIGTDqW1hcnLDqSA7IG9uIGlnbm9yZS4KICAgICAgICB9CiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFN1Z2dlc3Rpb25zIGRlIGNhdMOpZ29yaWUg4oCUIHVuaXF1ZW1lbnQgYXByw6hzIHVuZSBzYWlzaWUgcGFyIGRpY3TDqWUKICAgIC8vIHZvY2FsZSAodW5lIGZhdXRlIGRlIGZyYXBwZSBlbiBzYWlzaWUgbWFudWVsbGUsIGMnZXN0IHVuZSBlcnJldXIgZGUKICAgIC8vIGwndXRpbGlzYXRldXIsIHBhcyBsYSBwZWluZSBkZSBsZSByZWxhbmNlciBkZXNzdXMpLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQgPSAzOwoKICAgIGZ1bmN0aW9uIG5vcm1hbGl6ZURlc2NyaXB0aW9uKGRlc2MpIHsKICAgICAgcmV0dXJuIChkZXNjIHx8ICIiKS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBkaXNtaXNzU3VnZ2VzdGlvbihrZXkpIHsKICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuYWRkKGtleSk7IC8vIGltbcOpZGlhdCBjw7R0w6kgVUksIHBhcyBiZXNvaW4gZCdhdHRlbmRyZSBsZSBzZXJ2ZXVyCiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGtleSB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSBsYSBzdWdnZXN0aW9uIHLDqWFwcGFyYcOudCB1bmUgZm9pcyBzdXIgdW4KICAgICAgICAvLyBhdXRyZSBhcHBhcmVpbCBzaSBsYSBzYXV2ZWdhcmRlIHNlcnZldXIgYSDDqWNob3XDqS4KICAgICAgfQogICAgfQoKICAgIC8vIFJlZ2FyZGUgc2kgbGEgZGVzY3JpcHRpb24gZGUgbGEgdHJhbnNhY3Rpb24gcXVpIHZpZW50IGQnw6p0cmUgYWpvdXTDqWUKICAgIC8vIChvdSBjb3JyaWfDqWUpIMOgIGxhIHZvaXggcmV2aWVudCBzb3V2ZW50LCBldCBzaSBvdWkgOgogICAgLy8gLSBzb2l0IGVsbGUgYSB0b3Vqb3VycyDDqXTDqSByYW5nw6llIGRhbnMgIkF1dHJlIiDihpIgb24gcHJvcG9zZSBkZSBjcsOpZXIKICAgIC8vICAgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGRlIGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpIDsKICAgIC8vIC0gc29pdCBlbGxlIGEgY2V0dGUgZm9pcyB1bmUgY2F0w6lnb3JpZSBkaWZmw6lyZW50ZSBkZSBkJ2hhYml0dWRlIOKGkiBvbgogICAgLy8gICBkZW1hbmRlIHNpIGNlIG4nZXN0IHBhcyB1bmUgZXJyZXVyLgogICAgZnVuY3Rpb24gY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24oZGVzY3JpcHRpb24sIHR5cGUpIHsKICAgICAgY29uc3Qgbm9ybSA9IG5vcm1hbGl6ZURlc2NyaXB0aW9uKGRlc2NyaXB0aW9uKTsKICAgICAgaWYgKCFub3JtKSByZXR1cm47CgogICAgICBjb25zdCBzYW1lRGVzY3JpcHRpb24gPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICh0eCkgPT4gdHgudHlwZSA9PT0gdHlwZSAmJiBub3JtYWxpemVEZXNjcmlwdGlvbih0eC5kZXNjcmlwdGlvbikgPT09IG5vcm0KICAgICAgKTsKICAgICAgaWYgKHNhbWVEZXNjcmlwdGlvbi5sZW5ndGggPCBDQVRFR09SWV9TVUdHRVNUSU9OX1RIUkVTSE9MRCkgcmV0dXJuOwoKICAgICAgY29uc3QgY291bnRzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2Ygc2FtZURlc2NyaXB0aW9uKSBjb3VudHNbdHguY2F0ZWdvcnldID0gKGNvdW50c1t0eC5jYXRlZ29yeV0gfHwgMCkgKyAxOwogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXMoY291bnRzKTsKICAgICAgY29uc3QgZG9taW5hbnQgPSBjYXRlZ29yaWVzLnJlZHVjZSgoYSwgYikgPT4gKGNvdW50c1thXSA+PSBjb3VudHNbYl0gPyBhIDogYikpOwogICAgICBjb25zdCBsYXRlc3QgPSBzYW1lRGVzY3JpcHRpb25bMF07IC8vIGFsbFRyYW5zYWN0aW9ucyBlc3QgdHJpw6kgcGFyIGRhdGUgZMOpY3JvaXNzYW50ZQoKICAgICAgbGV0IHN1Z2dlc3Rpb24gPSBudWxsOwogICAgICBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgbWlzbWF0Y2g6JHt0eXBlfToke25vcm19OiR7bGF0ZXN0LmNhdGVnb3J5fWAsCiAgICAgICAgICBraW5kOiAibWlzbWF0Y2giLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICBkb21pbmFudCwKICAgICAgICAgIGN1cnJlbnQ6IGxhdGVzdC5jYXRlZ29yeSwKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgPT09IGxhdGVzdC5jYXRlZ29yeSkubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPT09IDEgJiYgZG9taW5hbnQgPT09ICJhdXRyZSIpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgZ2VuZXJpYzoke3R5cGV9OiR7bm9ybX1gLAogICAgICAgICAga2luZDogImdlbmVyaWMiLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9CgogICAgICBpZiAoIXN1Z2dlc3Rpb24gfHwgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuaGFzKHN1Z2dlc3Rpb24ua2V5KSkgcmV0dXJuOwogICAgICBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pOwogICAgfQoKICAgIGZ1bmN0aW9uIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIik7CiAgICAgIGVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpIHsKICAgICAgY29uc3QgW2xhdGVzdElkLCAuLi5vdGhlcnNdID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgY29uc3QgaWRzVG9GaXggPSBbbGF0ZXN0SWRdOwogICAgICBpZiAoCiAgICAgICAgb3RoZXJzLmxlbmd0aCA+IDAgJiYKICAgICAgICAoYXdhaXQgc2hvd0NvbmZpcm0oYENvcnJpZ2VyIGF1c3NpIGxlcyAke290aGVycy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHByw6ljw6lkZW50ZShzKSBhdmVjIGxhIG3Dqm1lIGRlc2NyaXB0aW9uID9gKSkKICAgICAgKSB7CiAgICAgICAgaWRzVG9GaXgucHVzaCguLi5vdGhlcnMpOwogICAgICB9CgogICAgICB0cnkgewogICAgICAgIGZvciAoY29uc3QgaWQgb2YgaWRzVG9GaXgpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBjYXRlZ29yeTogdGFyZ2V0VmFsdWUgfSksCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgc2hvd1RvYXN0KGBDYXTDqWdvcmllIG1pc2Ugw6Agam91ciA6ICR7dGFyZ2V0TGFiZWx9YCk7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbikgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCBkZXNjTGFiZWwgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIoc2FucyBkZXNjcmlwdGlvbikiOwogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGBUdSBhcyB1dGlsaXPDqSAiJHtkZXNjTGFiZWx9IiAke3N1Z2dlc3Rpb24udHhJZHMubGVuZ3RofSBmb2lzLCB0b3Vqb3VycyBjbGFzc8OpIGVuIGAgKwogICAgICAgICAgYCJBdXRyZSIuIENyw6llciB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgY3VycmVudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5jdXJyZW50XSB8fCBzdWdnZXN0aW9uLmN1cnJlbnQ7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgIiR7ZGVzY0xhYmVsfSIgZXN0IGhhYml0dWVsbGVtZW50IGNsYXNzw6kgZW4gIiR7ZG9taW5hbnRMYWJlbH0iLCBtYWlzIGNldHRlIGZvaXMgYCArCiAgICAgICAgICBgYydlc3QgIiR7Y3VycmVudExhYmVsfSIuIFBhcyBkJ2VycmV1ciBvdSB1biBvdWJsaSA/YDsKICAgICAgfQogICAgICBlbC5hcHBlbmRDaGlsZCh0ZXh0KTsKCiAgICAgIGNvbnN0IGNvbnRyb2xzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGNvbnRyb2xzLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIjsKCiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdKSB7CiAgICAgICAgICBpZiAodmFsdWUgPT09ICJhdXRyZSIpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IG5ld09wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG5ld09wdC52YWx1ZSA9ICJfX25ld19fIjsKICAgICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgICBuZXdPcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgICBjb25zdCBuZXdOYW1lSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIG5ld05hbWVJbnB1dC50eXBlID0gInRleHQiOwogICAgICAgIG5ld05hbWVJbnB1dC5wbGFjZWhvbGRlciA9ICJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSI7CiAgICAgICAgbmV3TmFtZUlucHV0LnZhbHVlID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiIjsKCiAgICAgICAgc2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgICAgIG5ld05hbWVJbnB1dC5zdHlsZS5kaXNwbGF5ID0gc2VsZWN0LnZhbHVlID09PSAiX19uZXdfXyIgPyAiaW5saW5lLWJsb2NrIiA6ICJub25lIjsKICAgICAgICB9KTsKCiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoc2VsZWN0KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChuZXdOYW1lSW5wdXQpOwoKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gIkFwcGxpcXVlciI7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGxldCB0YXJnZXRWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICAgIGxldCB0YXJnZXRMYWJlbDsKICAgICAgICAgIGlmICh0YXJnZXRWYWx1ZSA9PT0gIl9fbmV3X18iKSB7CiAgICAgICAgICAgIGNvbnN0IG5hbWUgPSBuZXdOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgY2F0w6lnb3JpZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgICAgICAgdGFyZ2V0VmFsdWUgPSBzbHVnaWZ5Q2F0ZWdvcnkobmFtZSk7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gbmFtZTsKICAgICAgICAgICAgaWYgKCFjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB0YXJnZXRWYWx1ZSkpIHsKICAgICAgICAgICAgICBzYXZlQ3VzdG9tQ2F0ZWdvcnkoc3VnZ2VzdGlvbi50eXBlLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgICAgICB9CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3RhcmdldFZhbHVlXSB8fCB0YXJnZXRWYWx1ZTsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSBgQ29ycmlnZXIgZW4gIiR7ZG9taW5hbnRMYWJlbH0iYDsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgc3VnZ2VzdGlvbi5kb21pbmFudCwgZG9taW5hbnRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9CgogICAgICBjb25zdCBkaXNtaXNzQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGRpc21pc3NCdG4udGV4dENvbnRlbnQgPSAiSWdub3JlciI7CiAgICAgIGRpc21pc3NCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBkaXNtaXNzQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgIH0pOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChkaXNtaXNzQnRuKTsKCiAgICAgIGVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKICAgIH0KCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZQogICAgLy8gc2Vzc2lvbiAobcOqbWUgcHJpbmNpcGUgcXVlIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQsIG1haXMgcG91ciB1bmUKICAgIC8vIGNvcnJlY3Rpb24gcXVpIHN1aXQgbGEgY3LDqWF0aW9uIGQndW5lIHLDqWN1cnJlbnRlIHBhciBsYSB2b2l4KS4KICAgIGxldCBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IG51bGw7CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpIHsKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICAvLyAicsOpY3VycmVudCIsICJhYm9ubmVtZW50IiwgInRvdXMgbGVzIG1vaXMiLi4uIGTDqXRlY3TDqSBwYXIgbCdJQSA6IG9uCiAgICAgIC8vIGNyw6llL2NvcnJpZ2UgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBhdSBsaWV1IGQndW5lIHRyYW5zYWN0aW9uCiAgICAgIC8vIHBvbmN0dWVsbGUsIHF1ZWwgcXVlIHNvaXQgbCdvbmdsZXQgYWN0dWVsbGVtZW50IGFmZmljaMOpIOKAlCBsZSBtaWNybwogICAgICAvLyBlc3QgZ2xvYmFsLCBwYXMgbGnDqSDDoCBsJ29uZ2xldCBSw6ljdXJyZW50ZXMuCiAgICAgIGlmIChwYXJzZWQuaXNfcmVjdXJyaW5nKSB7CiAgICAgICAgY29uc3QgcmVjUGF5bG9hZCA9IHsKICAgICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgICAgbmFtZTogcGFyc2VkLmRlc2NyaXB0aW9uIHx8IChwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IHLDqWN1cnJlbnQiIDogIkTDqXBlbnNlIHLDqWN1cnJlbnRlIiksCiAgICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgICAgZGF5X29mX21vbnRoOiBOdW1iZXIocGFyc2VkLmV4cGVuc2VfZGF0ZS5zbGljZSg4LCAxMCkpLAogICAgICAgIH07CgogICAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7bGFzdFZvaWNlUmVjdXJyaW5nSWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgY29ycmlnw6llIDogJHtyZWNQYXlsb2FkLm5hbWV9ICgke2Ftb3VudExhYmVsfSlgKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHJlY1BheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgICBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgICBzaG93VG9hc3QoYENoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfQogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKHBhcnNlZC5kZXNjcmlwdGlvbiwgcGFyc2VkLnR5cGUpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiBzdHlsw6llIChyZW1wbGFjZSB3aW5kb3cuY29uZmlybSwgcXVpIGFmZmljaGUgdW5lIHBvcHVwCiAgICAvLyBuYXRpdmUgZHUgbmF2aWdhdGV1ciBob3JzIGNoYXJ0ZSBncmFwaGlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBjb25maXJtT3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgY29uZmlybU1lc3NhZ2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW1lc3NhZ2UiKTsKICAgIGNvbnN0IGNvbmZpcm1Pa0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1vayIpOwogICAgY29uc3QgY29uZmlybUNhbmNlbEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1jYW5jZWwiKTsKICAgIGxldCBjb25maXJtUmVzb2x2ZSA9IG51bGw7CgogICAgZnVuY3Rpb24gc2hvd0NvbmZpcm0obWVzc2FnZSkgewogICAgICBjb25maXJtTWVzc2FnZUVsLnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgY29uZmlybU92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSByZXNvbHZlOwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZUNvbmZpcm0ocmVzdWx0KSB7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGlmIChjb25maXJtUmVzb2x2ZSkgewogICAgICAgIGNvbmZpcm1SZXNvbHZlKHJlc3VsdCk7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSBudWxsOwogICAgICB9CiAgICB9CgogICAgY29uZmlybU9rQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKHRydWUpKTsKICAgIGNvbmZpcm1DYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBjbG9zZUNvbmZpcm0oZmFsc2UpKTsKICAgIGNvbmZpcm1PdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IGNvbmZpcm1PdmVybGF5RWwpIGNsb3NlQ29uZmlybShmYWxzZSk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEw6lwZW5zZXMgcsOpY3VycmVudGVzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCByZWNMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWxpc3QiKTsKICAgIGNvbnN0IHJlY0VtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWN1cnJpbmctZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHJlY092ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjTW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1tb2RhbC10aXRsZSIpOwogICAgY29uc3QgcmVjVHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy10eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgcmVjTmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1uYW1lIik7CiAgICBjb25zdCByZWNBbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCByZWNDYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgcmVjRGF5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWRheSIpOwogICAgY29uc3QgcmVjU3RhcnREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LXN0YXJ0LWRhdGUiKTsKICAgIGNvbnN0IHJlY0VuZERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZW5kLWRhdGUiKTsKICAgIGNvbnN0IHJlY1NhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1zYXZlIik7CgogICAgbGV0IGFsbFJlY3VycmluZyA9IFtdOwogICAgbGV0IGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICBsZXQgcmVjQ3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgZnVuY3Rpb24gcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIHJlY0NhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0UmVjdXJyaW5nVHlwZSh0eXBlKSB7CiAgICAgIHJlY0N1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgcmVjVHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCByZWNDYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICByZWNUeXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0UmVjdXJyaW5nVHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtID0gbnVsbCkgewogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBpdGVtID8gaXRlbS5pZCA6IG51bGw7CiAgICAgIHJlY01vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGl0ZW0gPyAiTW9kaWZpZXIgbGEgY2hhcmdlIHLDqWN1cnJlbnRlIiA6ICJOb3V2ZWxsZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICByZWNTYXZlQnRuLnRleHRDb250ZW50ID0gaXRlbSA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFJlY3VycmluZ1R5cGUoaXRlbSA/IGl0ZW0udHlwZSA6ICJleHBlbnNlIik7CiAgICAgIHJlY05hbWVJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLm5hbWUgOiAiIjsKICAgICAgcmVjQW1vdW50SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHJlY0N1cnJlbnRUeXBlLCBpdGVtID8gaXRlbS5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICByZWNEYXlJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLmRheV9vZl9tb250aCA6ICIiOwogICAgICByZWNTdGFydERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5zdGFydF9kYXRlID8gaXRlbS5zdGFydF9kYXRlIDogIiI7CiAgICAgIHJlY0VuZERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5lbmRfZGF0ZSA/IGl0ZW0uZW5kX2RhdGUgOiAiIjsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZWNOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY3VycmluZ01vZGFsKCkgewogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY3VycmluZ01vZGFsKTsKICAgIHJlY092ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gcmVjT3ZlcmxheUVsKSBjbG9zZVJlY3VycmluZ01vZGFsKCk7IH0pOwoKICAgIHJlY1NhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG5hbWUgPSByZWNOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KHJlY0Ftb3VudElucHV0LnZhbHVlKTsKICAgICAgY29uc3QgZGF5ID0gcGFyc2VJbnQocmVjRGF5SW5wdXQudmFsdWUsIDEwKTsKCiAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkxlIG5vbSBlc3Qgb2JsaWdhdG9pcmUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7IHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFkYXkgfHwgZGF5IDwgMSB8fCBkYXkgPiAzMSkgeyBzaG93VG9hc3QoIkpvdXIgZHUgbW9pcyBpbnZhbGlkZSAoMSDDoCAzMSkiLCB0cnVlKTsgcmV0dXJuOyB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHJlY0N1cnJlbnRUeXBlLAogICAgICAgIG5hbWUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiByZWNDYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRheV9vZl9tb250aDogZGF5LAogICAgICAgIHN0YXJ0X2RhdGU6IHJlY1N0YXJ0RGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgICAgZW5kX2RhdGU6IHJlY0VuZERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7ZWRpdGluZ1JlY3VycmluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZVJlY3VycmluZ01vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVSZWN1cnJpbmcoaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSByw6ljdXJyZW50ZSA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiRMOpcGVuc2UgcsOpY3VycmVudGUgc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKSB7CiAgICAgIHJlY0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgcmVjRW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSBpdGVtcy5sZW5ndGggPT09IDAgPyAiYmxvY2siIDogIm5vbmUiOwoKICAgICAgY29uc3QgdG9kYXlLZXkgPSB0b2RheUlzbygpOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGl0ZW1zKSB7CiAgICAgICAgY29uc3QgdHlwZSA9IGl0ZW0udHlwZSB8fCAiZXhwZW5zZSI7CiAgICAgICAgY29uc3QgZW5kZWQgPSBpdGVtLmVuZF9kYXRlICYmIGl0ZW0uZW5kX2RhdGUgPCB0b2RheUtleTsKICAgICAgICBjb25zdCBub3RTdGFydGVkID0gaXRlbS5zdGFydF9kYXRlICYmIGl0ZW0uc3RhcnRfZGF0ZSA+IHRvZGF5S2V5OwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAicmVjLWNhcmQgIiArIHR5cGUgKyAoZW5kZWQgPyAiIGVuZGVkIiA6ICIiKTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInJlYy1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJyZWMtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUpIHsKICAgICAgICAgIGNvbnN0IHN0YXJ0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBzdGFydEJhZGdlLmNsYXNzTmFtZSA9ICJzdGFydC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBzdGFydExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5zdGFydF9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICAgIHN0YXJ0QmFkZ2UudGV4dENvbnRlbnQgPSBub3RTdGFydGVkID8gYETDqHMgbGUgJHtzdGFydExhYmVsfWAgOiBgRGVwdWlzIGxlICR7c3RhcnRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHN0YXJ0QmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAoaXRlbS5lbmRfZGF0ZSkgewogICAgICAgICAgY29uc3QgZW5kQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBlbmRCYWRnZS5jbGFzc05hbWUgPSAiZW5kLWJhZGdlIjsKICAgICAgICAgIGNvbnN0IGVuZExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5lbmRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBlbmRCYWRnZS50ZXh0Q29udGVudCA9IGVuZGVkID8gYFRlcm1pbsOpIGxlICR7ZW5kTGFiZWx9YCA6IGBKdXNxdSdhdSAke2VuZExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZW5kQmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG5hbWUuY2xhc3NOYW1lID0gInJlYy1uYW1lIjsKICAgICAgICBuYW1lLnRleHRDb250ZW50ID0gaXRlbS5uYW1lOwoKICAgICAgICBjb25zdCBzdWIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBzdWIuY2xhc3NOYW1lID0gInJlYy1zdWIiOwogICAgICAgIHN1Yi50ZXh0Q29udGVudCA9IGBMZSAke2l0ZW0uZGF5X29mX21vbnRofSBkZSBjaGFxdWUgbW9pc2A7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKG5hbWUpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoc3ViKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAicmVjLWFtb3VudCAiICsgdHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtKSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVJlY3VycmluZyhpdGVtLmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICByZWNMaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhbCBkZXMgZMOpcGVuc2VzIHLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzIGNlIG1vaXMtY2kgKGNlbGxlcwogICAgLy8gZG9udCBsZSBqb3VyIGR1IG1vaXMgbidlc3QgcGFzIGVuY29yZSBwYXNzw6kpLCBhZmZpY2jDqSDDoCBjw7R0w6kgZGVzIDMKICAgIC8vIGNhcnRlcyBkdSBoYXV0IOKAlCBpbmTDqXBlbmRhbnQgZHUgbW9pcyBjaG9pc2kgZGFucyBsZSB0YWJsZWF1IGRlIGJvcmQsCiAgICAvLyB0b3Vqb3VycyAibGUgbW9pcyByw6llbCwgbWFpbnRlbmFudCIuCiAgICBmdW5jdGlvbiB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKSB7CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIGN1cnJlbnRNb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSB0b2RheURheSkgY29udGludWU7CiAgICAgICAgaWYgKChpdGVtLnR5cGUgfHwgImV4cGVuc2UiKSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBuZXQgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZyIpOwogICAgICBjb25zdCBjYXJkRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy1jYXJkIik7CiAgICAgIGNvbnN0IHRvb2x0aXBFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLXRvb2x0aXAiKTsKCiAgICAgIGlmIChuZXQgPT09IDApIHsKICAgICAgICBlbC50ZXh0Q29udGVudCA9ICLigJQiOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSI7CiAgICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9ICIiOwogICAgICAgIGNhcmRFbC5jbGFzc0xpc3QucmVtb3ZlKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHNpZ24gPSBuZXQgPiAwID8gIisiIDogIuKIkiI7CiAgICAgIGVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0KSl9YDsKICAgICAgZWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAobmV0ID4gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgY2FyZEVsLmNsYXNzTGlzdC5hZGQoInRvb2x0aXAtaG9zdCIpOwogICAgICB0b29sdGlwRWwuaW5uZXJIVE1MID0KICAgICAgICBgRMOpcGVuc2VzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdFeHBlbnNlKX08YnI+YCArCiAgICAgICAgYFJldmVudXMgw6AgdmVuaXIgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh1cGNvbWluZ0luY29tZSl9YDsKICAgIH0KCiAgICAvLyBQZXRpdGUgYnVsbGUgZGUgZMOpdGFpbCBmYcOnb24gInRvb2x0aXAiIGhhYmlsbMOpZSBhdXggY291bGV1cnMgZHUgc2l0ZSwKICAgIC8vIGF1IGxpZXUgZHUgdGl0bGUgbmF0aWYgZHUgbmF2aWdhdGV1ciAoZ3Jpcy9ibGFuYywgaG9ycyBjaGFydGUsIGV0CiAgICAvLyBpbnZpc2libGUgYXUgdGFjdGlsZSkuIEFmZmljaMOpZSBhdSBzdXJ2b2wgKG9yZGluYXRldXIpIGV0IGF1CiAgICAvLyB0YXAvdGFwLWVuLWRlaG9ycyAodMOpbMOpcGhvbmUvdGFibGV0dGUpLgogICAgKGZ1bmN0aW9uIHNldHVwU3VtbWFyeVVwY29taW5nVG9vbHRpcCgpIHsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBmdW5jdGlvbiBzaG93KCkgewogICAgICAgIGlmICh0b29sdGlwRWwuaW5uZXJIVE1MKSB0b29sdGlwRWwuY2xhc3NMaXN0LmFkZCgidmlzaWJsZSIpOwogICAgICB9CiAgICAgIGZ1bmN0aW9uIGhpZGUoKSB7CiAgICAgICAgdG9vbHRpcEVsLmNsYXNzTGlzdC5yZW1vdmUoInZpc2libGUiKTsKICAgICAgfQoKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlZW50ZXIiLCBzaG93KTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlbGVhdmUiLCBoaWRlKTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgICBlLnN0b3BQcm9wYWdhdGlvbigpOwogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIik7CiAgICAgIH0pOwogICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGhpZGUpOwogICAgfSkoKTsKCiAgICAvLyBSYW3DqG5lIHVuIGpvdXIgZHUgbW9pcyAoMS0zMSkgYXUgZGVybmllciBqb3VyIHLDqWVsIGR1IG1vaXMgdmlzw6kg4oCUCiAgICAvLyDDqXF1aXZhbGVudCBKUyBkZSBfY2xhbXBfZGF5IGPDtHTDqSBzZXJ2ZXVyLCBwb3VyIGNhbGN1bGVyIGRlIHZyYWllcwogICAgLy8gZGF0ZXMgKG5ldyBEYXRlKC4uLikpIHBsdXTDtHQgcXVlIGRlIGNvbXBhcmVyIGRlcyBqb3VycyB0b3V0IHNldWxzLgogICAgZnVuY3Rpb24gY2xhbXBEYXlKcyh5ZWFyLCBtb250aEluZGV4LCBkYXkpIHsKICAgICAgY29uc3QgbGFzdERheSA9IG5ldyBEYXRlKHllYXIsIG1vbnRoSW5kZXggKyAxLCAwKS5nZXREYXRlKCk7CiAgICAgIHJldHVybiBNYXRoLm1pbihkYXksIGxhc3REYXkpOwogICAgfQoKICAgIC8vIFByb2NoYWluZSBvY2N1cnJlbmNlIGQndW5lIGNoYXJnZSByw6ljdXJyZW50ZSDDoCBwYXJ0aXIgZCdhdWpvdXJkJ2h1aQogICAgLy8gKHN0cmljdGVtZW50IGFwcsOocyBhdWpvdXJkJ2h1aSkgOiByZWdhcmRlIGNlIG1vaXMtY2kgcHVpcywgc2kgYmVzb2luLAogICAgLy8gbGVzIGRldXggbW9pcyBzdWl2YW50cyDigJQgdXRpbGUgZW4gZmluIGRlIG1vaXMgcXVhbmQgcGx1cyByaWVuIG4nZXN0CiAgICAvLyDDoCB2ZW5pciBkYW5zIGxlIG1vaXMgY291cmFudC4KICAgIGZ1bmN0aW9uIG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheVN0cikgewogICAgICBjb25zdCBbdHksIHRtLCB0ZF0gPSB0b2RheVN0ci5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCB0b2RheURhdGUgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxLCB0ZCk7CiAgICAgIGZvciAobGV0IG9mZnNldCA9IDA7IG9mZnNldCA8PSAyOyBvZmZzZXQrKykgewogICAgICAgIGNvbnN0IGJhc2UgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxICsgb2Zmc2V0LCAxKTsKICAgICAgICBjb25zdCB5ID0gYmFzZS5nZXRGdWxsWWVhcigpOwogICAgICAgIGNvbnN0IG1JZHggPSBiYXNlLmdldE1vbnRoKCk7CiAgICAgICAgY29uc3QgbW9udGhLZXkgPSBgJHt5fS0ke1N0cmluZyhtSWR4ICsgMSkucGFkU3RhcnQoMiwgIjAiKX1gOwogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBjb25zdCBkYXkgPSBjbGFtcERheUpzKHksIG1JZHgsIGl0ZW0uZGF5X29mX21vbnRoKTsKICAgICAgICBjb25zdCBvY2NEYXRlID0gbmV3IERhdGUoeSwgbUlkeCwgZGF5KTsKICAgICAgICBpZiAob2NjRGF0ZSA+IHRvZGF5RGF0ZSkgcmV0dXJuIG9jY0RhdGU7CiAgICAgIH0KICAgICAgcmV0dXJuIG51bGw7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyVXBjb21pbmdSZWN1cnJpbmdMaXN0KCkgewogICAgICBjb25zdCBwYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwiKTsKICAgICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInVwY29taW5nLXJlY3VycmluZy1saXN0Iik7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKCiAgICAgIGNvbnN0IHVwY29taW5nID0gYWxsUmVjdXJyaW5nCiAgICAgICAgLm1hcCgoaXRlbSkgPT4gKHsgaXRlbSwgZGF0ZTogbmV4dE9jY3VycmVuY2VGb3JJdGVtKGl0ZW0sIHRvZGF5KSB9KSkKICAgICAgICAuZmlsdGVyKCh4KSA9PiB4LmRhdGUpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGEuZGF0ZSAtIGIuZGF0ZSkKICAgICAgICAuc2xpY2UoMCwgMyk7CgogICAgICBpZiAodXBjb21pbmcubGVuZ3RoID09PSAwKSB7CiAgICAgICAgcGFuZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHBhbmVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CgogICAgICBmb3IgKGNvbnN0IHsgaXRlbSwgZGF0ZSB9IG9mIHVwY29taW5nKSB7CiAgICAgICAgY29uc3QgZGF5cyA9IE1hdGgucm91bmQoKGRhdGUgLSBuZXcgRGF0ZShuZXcgRGF0ZSgpLnNldEhvdXJzKDAsIDAsIDAsIDApKSkgLyA4NjQwMDAwMCk7CiAgICAgICAgY29uc3QgZHVlTGFiZWwgPSBkYXlzIDw9IDEgPyAiZGVtYWluIiA6IGBkYW5zICR7ZGF5c30gam91cnNgOwogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gInVwY29taW5nLXJlY3VycmluZy1yb3ciOwogICAgICAgIGNvbnN0IGxlZnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbGVmdC5jbGFzc05hbWUgPSAibmFtZSI7CiAgICAgICAgbGVmdC50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKICAgICAgICBjb25zdCBkdWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGR1ZVNwYW4uY2xhc3NOYW1lID0gImR1ZSI7CiAgICAgICAgZHVlU3Bhbi50ZXh0Q29udGVudCA9IGAke2RhdGVGb3JtYXR0ZXIuZm9ybWF0KGRhdGUpfSDCtyAke2R1ZUxhYmVsfWA7CiAgICAgICAgbGVmdC5hcHBlbmRDaGlsZChkdWVTcGFuKTsKICAgICAgICBjb25zdCBhbW91bnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50LmNsYXNzTmFtZSA9ICJhbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50LnRleHRDb250ZW50ID0gKHR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5hbW91bnQpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChsZWZ0KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoYW1vdW50KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRSZWN1cnJpbmcoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciKTsKICAgICAgICBhbGxSZWN1cnJpbmcgPSBpdGVtczsKICAgICAgICByZW5kZXJSZWN1cnJpbmcoaXRlbXMpOwogICAgICAgIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpOwogICAgICAgIHVwZGF0ZVVwY29taW5nU3VtbWFyeSgpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEV4cG9ydCBFeGNlbAogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQteGxzeCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC14bHN4Iik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkfDqW7DqXJhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvZXhwb3J0L3hsc3giLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBgZGVwZW5zZXNfJHt0b2RheUlzbygpfS54bHN4YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFNhdXZlZ2FyZGUgY29tcGzDqHRlIChKU09OKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQtanNvbiIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1qc29uIik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkfDqW7DqXJhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvZXhwb3J0L2pzb24iLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBga2FjaGluZy1zYXV2ZWdhcmRlLSR7dG9kYXlJc28oKX0uanNvbmA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChsaW5rKTsKICAgICAgICBsaW5rLmNsaWNrKCk7CiAgICAgICAgbGluay5yZW1vdmUoKTsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICAgICAgc2hvd1RvYXN0KCJTYXV2ZWdhcmRlIHTDqWzDqWNoYXJnw6llIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVzZXQtYWxsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgIlN1cHByaW1lciBEw4lGSU5JVElWRU1FTlQgdG91dGVzIGxlcyBkb25uw6llcyAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcykgPyBDZXR0ZSBhY3Rpb24gZXN0IGlycsOpdmVyc2libGUuIgogICAgICApOwogICAgICBpZiAoIW9rKSByZXR1cm47CiAgICAgIC8vIERvdWJsZSBjb25maXJtYXRpb24gdnUgbGUgY2FyYWN0w6hyZSBpcnLDqXZlcnNpYmxlIGV0IGNvbXBsZXQgZGUgbCdhY3Rpb24uCiAgICAgIGNvbnN0IG9rMiA9IGF3YWl0IHNob3dDb25maXJtKCJEZXJuacOocmUgY29uZmlybWF0aW9uIDogdnJhaW1lbnQgdG91dCByw6lpbml0aWFsaXNlciA/Iik7CiAgICAgIGlmICghb2syKSByZXR1cm47CgogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpOwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3Jlc2V0LWFsbCIsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIHLDqWluaXRpYWxpc8OpZSIpOwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4gd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpLCA2MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJSw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uIjsKICAgICAgfQogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUFdBIDogaW5zdGFsbGF0aW9uIHN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGlmICgic2VydmljZVdvcmtlciIgaW4gbmF2aWdhdG9yKSB7CiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJsb2FkIiwgKCkgPT4gewogICAgICAgIG5hdmlnYXRvci5zZXJ2aWNlV29ya2VyLnJlZ2lzdGVyKCIvc3cuanMiKS5jYXRjaCgoKSA9PiB7fSk7CiAgICAgIH0pOwogICAgfQoKICAgIGxldCBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBudWxsOwogICAgY29uc3QgcHdhSW5zdGFsbFJvdyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwd2EtaW5zdGFsbC1yb3ciKTsKICAgIGNvbnN0IHB3YUluc3RhbGxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicHdhLWluc3RhbGwtYnRuIik7CiAgICBjb25zdCBwd2FJb3NIaW50Um93ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInB3YS1pb3MtaGludC1yb3ciKTsKCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiYmVmb3JlaW5zdGFsbHByb21wdCIsIChlKSA9PiB7CiAgICAgIC8vIEVtcMOqY2hlIGxhIG1pbmktaW5mb2JhciBhdXRvbWF0aXF1ZSBkdSBuYXZpZ2F0ZXVyIDogb24gYWZmaWNoZQogICAgICAvLyBwbHV0w7R0IG5vdHJlIHByb3ByZSBib3V0b24sIGRhbnMgbCdvbmdsZXQgRXhwb3J0LCBjb2jDqXJlbnQgYXZlYwogICAgICAvLyBsZSByZXN0ZSBkdSBzaXRlLgogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGRlZmVycmVkSW5zdGFsbFByb21wdCA9IGU7CiAgICAgIGlmIChwd2FJbnN0YWxsUm93KSBwd2FJbnN0YWxsUm93LnN0eWxlLmRpc3BsYXkgPSAiIjsKICAgIH0pOwoKICAgIGlmIChwd2FJbnN0YWxsQnRuKSB7CiAgICAgIHB3YUluc3RhbGxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgaWYgKCFkZWZlcnJlZEluc3RhbGxQcm9tcHQpIHJldHVybjsKICAgICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQucHJvbXB0KCk7CiAgICAgICAgY29uc3QgeyBvdXRjb21lIH0gPSBhd2FpdCBkZWZlcnJlZEluc3RhbGxQcm9tcHQudXNlckNob2ljZTsKICAgICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBudWxsOwogICAgICAgIGlmIChwd2FJbnN0YWxsUm93KSBwd2FJbnN0YWxsUm93LnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaWYgKG91dGNvbWUgPT09ICJhY2NlcHRlZCIpIHNob3dUb2FzdCgiQXBwbGljYXRpb24gaW5zdGFsbMOpZSIpOwogICAgICB9KTsKICAgIH0KCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiYXBwaW5zdGFsbGVkIiwgKCkgPT4gewogICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgfSk7CgogICAgLy8gU2FmYXJpIGlPUyBuZSBkw6ljbGVuY2hlIGphbWFpcyAiYmVmb3JlaW5zdGFsbHByb21wdCIgOiBvbiBhZmZpY2hlIMOgIGxhCiAgICAvLyBwbGFjZSB1biBwZXRpdCBtb2RlIGQnZW1wbG9pIChQYXJ0YWdlciA+IFN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwpLCBzYXVmCiAgICAvLyBzaSBsJ2FwcCBlc3QgZMOpasOgIGluc3RhbGzDqWUgKG1vZGUgc3RhbmRhbG9uZSkuCiAgICBjb25zdCBpc0lvcyA9IC9pcGhvbmV8aXBhZHxpcG9kL2kudGVzdChuYXZpZ2F0b3IudXNlckFnZW50KTsKICAgIGNvbnN0IGlzU3RhbmRhbG9uZSA9CiAgICAgIHdpbmRvdy5tYXRjaE1lZGlhKCIoZGlzcGxheS1tb2RlOiBzdGFuZGFsb25lKSIpLm1hdGNoZXMgfHwgd2luZG93Lm5hdmlnYXRvci5zdGFuZGFsb25lID09PSB0cnVlOwogICAgaWYgKGlzSW9zICYmICFpc1N0YW5kYWxvbmUgJiYgcHdhSW9zSGludFJvdykgewogICAgICBwd2FJb3NIaW50Um93LnN0eWxlLmRpc3BsYXkgPSAiIjsKICAgIH0KCiAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoImV4cGVuc2UiKTsKICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CgogICAgLy8gUmllbiBkZSB0b3V0IMOnYSAoY2hhcmdlbWVudCBkZXMgZG9ubsOpZXMsIHJhY2NvdXJjaXMgUFdBLi4uKSBuZSBkb2l0CiAgICAvLyBkw6ltYXJyZXIgYXZhbnQgZCdhdm9pciB1biBqZXRvbiBkZSBzZXNzaW9uIHZhbGlkZSDigJQgc2lub24gbGEgcHJlbWnDqHJlCiAgICAvLyByZXF1w6p0ZSDDqWNob3VlcmFpdCBqdXN0ZSBhdmVjIHVuZSA0MDEgw6AgbGEgcGxhY2UgZGUgbW9udHJlciBsZSB2ZXJyb3UuCiAgICBpZiAoQVBJX0tFWSkgewogICAgICBzaG93QXBwKCk7CiAgICAgIChhc3luYyBmdW5jdGlvbiBpbml0KCkgewogICAgICAgIC8vIENhdMOpZ29yaWVzIHBlcnNvICsgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIGQnYWJvcmQsIHBvdXIgcXVlIGxlcwogICAgICAgIC8vIGxpc3RlcyBkw6lyb3VsYW50ZXMgZXQgbGUgYmFuZGVhdSBzb2llbnQgY29ycmVjdHMgZMOocyBsZSBwcmVtaWVyCiAgICAgICAgLy8gcmVuZHUgcGx1dMO0dCBxdWUgZGUgInNhdXRlciIgdW5lIGZvaXMgbGUgc2VydmV1ciByw6lwb25kdS4KICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChbbG9hZEN1c3RvbUNhdGVnb3JpZXMoKSwgbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCksIGxvYWRCdWRnZXRzKCksIGxvYWRTYXZpbmdzR29hbCgpXSk7CiAgICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgbG9hZFJlY3VycmluZygpOwoKICAgICAgICAvLyBSYWNjb3VyY2lzIFBXQSAoYXBwdWkgbG9uZyBzdXIgbCdpY8O0bmUgZGUgbCdhcHAgdW5lIGZvaXMgaW5zdGFsbMOpZSkgOgogICAgICAgIC8vIC8/c2hvcnRjdXQ9YWRkIG91dnJlIGRpcmVjdGVtZW50IGxlIGZvcm11bGFpcmUgZCdham91dCwgLz9zaG9ydGN1dD12b2ljZQogICAgICAgIC8vIGxhbmNlIGRpcmVjdGVtZW50IGxhIGRpY3TDqWUgdm9jYWxlLgogICAgICAgIGNvbnN0IHNob3J0Y3V0UGFyYW0gPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgic2hvcnRjdXQiKTsKICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSkgewogICAgICAgICAgLy8gTmV0dG9pZSBsJ1VSTCB0b3V0IGRlIHN1aXRlIDogdW4gcmVjaGFyZ2VtZW50IGRlIGxhIHBhZ2UgKG91IHVuCiAgICAgICAgICAvLyBwYXJ0YWdlIGR1IGxpZW4pIG5lIGRvaXQgcGFzIHJlZMOpY2xlbmNoZXIgbGUgcmFjY291cmNpLgogICAgICAgICAgd2luZG93Lmhpc3RvcnkucmVwbGFjZVN0YXRlKHt9LCAiIiwgd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lKTsKICAgICAgICAgIGlmIChzaG9ydGN1dFBhcmFtID09PSAiYWRkIikgewogICAgICAgICAgICBvcGVuTW9kYWwoKTsKICAgICAgICAgIH0gZWxzZSBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gInZvaWNlIiAmJiAhbWljQnRuLmRpc2FibGVkKSB7CiAgICAgICAgICAgIG1pY0J0bi5jbGljaygpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSkoKTsKICAgIH0gZWxzZSB7CiAgICAgIHNob3dMb2NrU2NyZWVuKCk7CiAgICB9CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
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
