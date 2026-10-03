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


_VOICE_SYSTEM_PROMPT_TEMPLATE = """Tu analyses une phrase dictée à l'oral en français, qui concerne les finances personnelles de l'utilisateur. Elle est de l'une de ces deux natures :

1. Une dépense ou un revenu à enregistrer, ou une correction d'une transaction déjà enregistrée.
2. Une question sur ses finances (combien il a dépensé, où il en est sur un budget, son solde, son épargne...).

Si la phrase est interrogative — ou commence par des mots comme "combien", "quel", "quelle", "est-ce que", "comment", "où en est", "ai-je", "suis-je", "me reste-t-il", "qu'est-ce que" — c'est TOUJOURS une question (intent="question"), jamais une transaction, même si elle mentionne un montant ou une catégorie.

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon l'un de ces deux schémas :

### Si intent = "transaction"
{
  "intent": "transaction",
  "type": "expense" ou "income",
  "amount": nombre (toujours positif),
  "category": une chaîne parmi __EXPENSE_CATEGORIES__ (si type=expense) ou __INCOME_CATEGORIES__ (si type=income) — cette liste inclut les catégories par défaut ET les catégories personnalisées déjà créées par l'utilisateur ; si une catégorie personnalisée correspond clairement au sujet de la phrase (ex: une catégorie "casino" existe et la phrase parle du casino), utilise-la plutôt que "autre",
  "raw_date_expression": l'expression de date EXACTEMENT telle que prononcée (ex: "hier", "lundi dernier", "le 3 septembre"), ou null si aucune date n'est mentionnée,
  "description": une description courte (sans le montant ni la date), construite UNIQUEMENT à partir des mots-clés réellement prononcés (ex: "j'ai perdu 40 euros au casino" -> "casino", PAS "perte casino" : n'invente pas un nom comme "perte" ou "gain" à partir d'un verbe ("j'ai perdu", "j'ai gagné") s'il n'a pas été prononcé tel quel), ou null si rien de pertinent à part la catégorie,
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
  "category": une chaîne parmi __ALL_CATEGORIES__ (celle qui est pertinente pour la question, catégories personnalisées incluses), ou null si la question ne porte pas sur une catégorie précise,
  "raw_period_expression": l'expression de période EXACTEMENT telle que prononcée (ex: "ce mois-ci", "le mois dernier", "cette année", "l'année dernière", "en septembre", "depuis le début"), ou null si aucune période n'est mentionnée (le mois en cours sera utilisé par défaut)
}

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même un montant, une date calendaire ou une période à partir d'une expression relative. Tu ne connais ni le solde de l'utilisateur ni la date du jour. Recopie les expressions telles quelles ; un système déterministe s'occupe de tous les calculs à partir des vraies données.
- Si la phrase ne mentionne aucune date (transaction) ou aucune période (question), le champ correspondant doit être null.
- is_correction doit rester false par défaut : en cas de doute, considère qu'il s'agit d'une nouvelle transaction plutôt que d'une correction.
- is_recurring doit rester false par défaut : ne le mets à true que si la récurrence est clairement exprimée à l'oral, jamais par déduction (ex: "le loyer" seul ne suffit pas, il faut un mot indiquant explicitement la répétition)."""


def _fetch_custom_categories(client) -> dict[str, list[str]]:
    """Catégories personnalisées créées par l'utilisateur (bandeau de
    suggestion ou formulaire manuel), par type. Nécessaires pour que l'IA
    vocale puisse les proposer elle-même au lieu de toujours retomber sur
    "autre" pour une catégorie qu'elle ne connaît pas."""
    rows = client.table("custom_categories").select("type, value").execute().data
    result: dict[str, list[str]] = {"expense": [], "income": []}
    for row in rows:
        t = row.get("type")
        if t in result:
            result[t].append(row["value"])
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


@app.post("/api/voice/parse", response_model=None)
def parse_voice_text(req: VoiceParseRequest, _: None = Depends(require_api_key)):
    client = get_supabase_client()
    custom = _fetch_custom_categories(client)
    expense_categories = EXPENSE_CATEGORIES | set(custom["expense"])
    income_categories = INCOME_CATEGORIES | set(custom["income"])

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
    )


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdCB7CiAgICBjb2xvci1zY2hlbWU6IGRhcms7CiAgICAtLWJnOiAjMGYxMTE1OwogICAgLS1zdXJmYWNlOiAjMWExZDI0OwogICAgLS1zdXJmYWNlLTI6ICMyMjI2MmY7CiAgICAtLWJvcmRlcjogIzJhMmUzODsKICAgIC0tdGV4dDogI2U2ZTZlNjsKICAgIC0tdGV4dC1kaW06ICM5YWEwYWM7CiAgICAtLWFjY2VudDogIzNiODJmNjsKICAgIC0tYWNjZW50LWRpbTogIzFkNGVkODsKICAgIC0tZGFuZ2VyOiAjZWY0NDQ0OwogICAgLS1zdWNjZXNzOiAjMjJjNTVlOwogICAgLS1yYWRpdXM6IDE0cHg7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgYm9keSB7CiAgICBtYXJnaW46IDA7CiAgICBtaW4taGVpZ2h0OiAxMDB2aDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKICAgIHBhZGRpbmctYm90dG9tOiA2cmVtOwogIH0KICBoZWFkZXIgewogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gMXJlbTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICB9CiAgaDEgeyBmb250LXNpemU6IDEuM3JlbTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC45cmVtOyBtYXJnaW46IDA7IH0KCiAgLnRhYnMgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgfQogIC50YWItYnRuIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDExMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnRhYi1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KCiAgLnN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTAwcHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC45cmVtIDFyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAwLjI1cmVtOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUucG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b29sdGlwLWhvc3QgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGN1cnNvcjogaGVscDsgfQogIC5jdXN0b20tdG9vbHRpcCB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiA1MCU7CiAgICBib3R0b206IGNhbGMoMTAwJSArIDAuNnJlbSk7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg0cHgpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41NXJlbSAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB0ZXh0LWFsaWduOiBsZWZ0OwogICAgYm94LXNoYWRvdzogMCA4cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMzUpOwogICAgb3BhY2l0eTogMDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwogICAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjEycyBlYXNlLCB0cmFuc2Zvcm0gMC4xMnMgZWFzZTsKICAgIHotaW5kZXg6IDIwOwogIH0KICAuY3VzdG9tLXRvb2x0aXA6OmFmdGVyIHsKICAgIGNvbnRlbnQ6ICIiOwogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxMDAlOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYm9yZGVyOiA2cHggc29saWQgdHJhbnNwYXJlbnQ7CiAgICBib3JkZXItdG9wLWNvbG9yOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KICAuY3VzdG9tLXRvb2x0aXAudmlzaWJsZSB7CiAgICBvcGFjaXR5OiAxOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoMCk7CiAgICBwb2ludGVyLWV2ZW50czogYXV0bzsKICB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLndlZWstc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAtMC40cmVtIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQoKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxLjFyZW07CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudC1kaW0pOwogIH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gcCB7IG1hcmdpbjogMCAwIDAuN3JlbTsgZm9udC1zaXplOiAwLjg4cmVtOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBzZWxlY3QsCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idG4tcHJpbWFyeS1zbSwgLmJ0bi1zZWNvbmRhcnktc20gewogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuOHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KICAuYnRuLXNlY29uZGFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1yZWN1cnJpbmctYmFkZ2UgeyBmb250LXNpemU6IDAuNzVyZW07IG9wYWNpdHk6IDAuNzsgY3Vyc29yOiBoZWxwOyB9CiAgLnR4LXJlY2VpcHQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjc1cmVtOwogICAgb3BhY2l0eTogMC44NTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBwYWRkaW5nOiAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CgogIC55ZWFybHktc3VtbWFyeSB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgfQogIC55ZWFybHktc3RhdCB7CiAgICBmbGV4OiAxOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC43cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuMnJlbTsKICB9CiAgLnllYXJseS1zdGF0LWxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlIHsgZm9udC1zaXplOiAxLjA1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlLmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC55ZWFybHktc3RhdC12YWx1ZS5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudXBjb21pbmctbm90ZSB7CiAgICB3aWR0aDogOTZweDsKICAgIGZsZXgtc2hyaW5rOiAwOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjRyZW07CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjcycmVtOwogICAgbGluZS1oZWlnaHQ6IDEuMjU7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KICAudXBjb21pbmctbm90ZS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXN3YXRjaCB7CiAgICB3aWR0aDogMjhweDsKICAgIGhlaWdodDogMTRweDsKICAgIGJvcmRlcjogMS41cHggZGFzaGVkIHZhcigtLWRhbmdlcik7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLXJhZGl1czogNHB4OwogIH0KICAudXBjb21pbmctbm90ZS5wb3NpdGl2ZSAudXBjb21pbmctc3dhdGNoIHsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjIpOwogIH0KCiAgLnJlY3VycmluZy1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5yZWN1cnJpbmctc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KICAuZXhwb3J0LXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmV4cG9ydC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5zYXZpbmdzLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KCiAgLmJ1ZGdldHMtc2F2ZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5zYXZpbmdzLWdvYWwtcm93IGlucHV0IHsgZmxleDogMTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1hcmdpbjogMC44cmVtIDAgMC4zNXJlbTsKICB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5hZHZpY2UtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuYWR2aWNlLWNhcmQgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjg1cmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBsaW5lLWhlaWdodDogMS40OwogIH0KICAuYWR2aWNlLWNhcmQgLmFkdmljZS1pY29uIHsgZm9udC1zaXplOiAxLjFyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmFkdmljZS1jYXJkLnBvc2l0aXZlIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1zdWNjZXNzKTsgfQogIC5hZHZpY2UtY2FyZC53YXJuaW5nIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCAjZjU5ZTBiOyB9CiAgLmFkdmljZS1jYXJkLmluZm8geyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CgogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOHJlbSAxcmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbC5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoNCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgZm9udC1zaXplOiAwLjlyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGJhc2VsaW5lOwogICAgcGFkZGluZzogMC4zNXJlbSAwOwogICAgZm9udC1zaXplOiAwLjg4cmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyArIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAubmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5kdWUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuNzhyZW07IG1hcmdpbi1sZWZ0OiAwLjRyZW07IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC5jb21wYXJlLXNlbGVjdHMgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzZWxlY3QgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjQ1cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzcGFuIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CgogIC5zaW1wbGUtdGFibGUgeyB3aWR0aDogMTAwJTsgYm9yZGVyLWNvbGxhcHNlOiBjb2xsYXBzZTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CiAgLnNpbXBsZS10YWJsZSB0aCwgLnNpbXBsZS10YWJsZSB0ZCB7IHBhZGRpbmc6IDAuNXJlbSAwLjZyZW07IHRleHQtYWxpZ246IHJpZ2h0OyB9CiAgLnNpbXBsZS10YWJsZSB0aDpmaXJzdC1jaGlsZCwgLnNpbXBsZS10YWJsZSB0ZDpmaXJzdC1jaGlsZCB7IHRleHQtYWxpZ246IGxlZnQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoZWFkIHRoIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC13ZWlnaHQ6IDUwMDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyICsgdHIgdGQgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIudG90YWwtcm93IHRkIHsgZm9udC13ZWlnaHQ6IDYwMDsgYm9yZGVyLXRvcDogMnB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLXBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLXVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtZG93biB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50cmVuZC1mbGF0IHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQoKICAuYnVkZ2V0LXJvdyB7IG1hcmdpbi1ib3R0b206IDAuOXJlbTsgfQogIC5idWRnZXQtcm93LWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuMzVyZW07CiAgfQogIC5idWRnZXQtY2F0LW5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWFtb3VudHMgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuM3JlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtaW5wdXQgewogICAgd2lkdGg6IDY0cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDZweDsKICAgIHBhZGRpbmc6IDAuMjVyZW0gMC40cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnVkZ2V0LWJhci10cmFjayB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBoZWlnaHQ6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogIC5idWRnZXQtYmFyLWZpbGwgeyBoZWlnaHQ6IDEwMCU7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyB0cmFuc2l0aW9uOiB3aWR0aCAwLjJzIGVhc2U7IH0KICAuYnVkZ2V0LWJhci1maWxsLm9rIHsgYmFja2dyb3VuZDogdmFyKC0tc3VjY2Vzcyk7IH0KICAuYnVkZ2V0LWJhci1maWxsLndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5idWRnZXQtaGlzdG9yeS1zdHJpcCB7IGRpc3BsYXk6IGZsZXg7IGdhcDogNHB4OyBtYXJnaW4tdG9wOiAwLjRyZW07IH0KICAuaGlzdG9yeS1kb3QgewogICAgZmxleDogMTsKICAgIGhlaWdodDogNnB4OwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuaGlzdG9yeS1kb3Qub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5oaXN0b3J5LWRvdC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5oaXN0b3J5LWRvdC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5oaXN0b3J5LWRvdC5lbXB0eSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IG9wYWNpdHk6IDAuNTsgfQogIC5yZWMtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjZyZW07CiAgfQogIC5yZWMtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnN0YXJ0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjE1KTsKICAgIGNvbG9yOiAjOTNjNWZkOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnJlYy1hbW91bnQgeyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IDEuMDVyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5mYWItbWljIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiA1LjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS41cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoMCwgMCwgMCwgMC4zKTsKICAgIHRyYW5zaXRpb246IGJhY2tncm91bmQgMC4ycywgYm9yZGVyLWNvbG9yIDAuMnM7CiAgfQogIC5mYWItbWljOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KICAuZmFiLW1pYy5saXN0ZW5pbmcgewogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsKICAgIGFuaW1hdGlvbjogcHVsc2UgMS4ycyBpbmZpbml0ZTsKICB9CiAgLmZhYi1taWMucHJvY2Vzc2luZyB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmZhYi1taWM6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjM1OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgQGtleWZyYW1lcyBwdWxzZSB7CiAgICAwJSwgMTAwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDAgcmdiYSgyMzksIDY4LCA2OCwgMC40KTsgfQogICAgNTAlIHsgYm94LXNoYWRvdzogMCAwIDAgMTBweCByZ2JhKDIzOSwgNjgsIDY4LCAwKTsgfQogIH0KCiAgLnZvaWNlLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNTsKICB9CiAgLnZvaWNlLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnZvaWNlLWJhbm5lci5hbnN3ZXIgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtd2VpZ2h0OiA2MDA7IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KCiAgLm1vZGFsLW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LWVuZDsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTA7CiAgfQogIC5tb2RhbC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAjaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5tb2RhbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlci1yYWRpdXM6IDE4cHggMThweCAwIDA7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSBjYWxjKDEuNXJlbSArIGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKSk7CiAgICB3aWR0aDogMTAwJTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC45cmVtOwogIH0KICAubW9kYWwgaDIgeyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXNpemU6IDEuMXJlbTsgfQoKICBsYWJlbCB7IGZvbnQtc2l6ZTogMC44cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4zcmVtOyB9CiAgaW5wdXQsIHNlbGVjdCB7CiAgICB3aWR0aDogMTAwJTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNjVyZW0gMC43NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgaW5wdXQ6Zm9jdXMsIHNlbGVjdDpmb2N1cyB7IG91dGxpbmU6IG5vbmU7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQoKICAudHlwZS10b2dnbGUgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgfQogIC50eXBlLWJ0biB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC42NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iZXhwZW5zZSJdIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iaW5jb21lIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5jb25maXJtLW1vZGFsIHsgbWF4LXdpZHRoOiA0MDBweDsgfQogIC5jb25maXJtLW1vZGFsLW1lc3NhZ2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtc2l6ZTogMC45NXJlbTsgbWFyZ2luOiAwOyBsaW5lLWhlaWdodDogMS40OyB9CgogIC5oaWRkZW4tZmlsZS1pbnB1dCB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjZWlwdC1wcmV2aWV3LXdyYXAgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuNXJlbTsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OwogICAgbWFyZ2luLWJvdHRvbTogMC41cmVtOwogIH0KICAucmVjZWlwdC1wcmV2aWV3LWltZyB7CiAgICBtYXgtd2lkdGg6IDEwMCU7CiAgICBtYXgtaGVpZ2h0OiAxNjBweDsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgb2JqZWN0LWZpdDogY29udGFpbjsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgfQoKICAubGlnaHRib3gtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC44NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMjA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5saWdodGJveC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubGlnaHRib3gtaW1nIHsgbWF4LXdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiA4MHZoOyBib3JkZXItcmFkaXVzOiAxMHB4OyB9CiAgLmxpZ2h0Ym94LWNsb3NlIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMXJlbTsKICAgIHJpZ2h0OiAxcmVtOwogICAgd2lkdGg6IDQwcHg7CiAgICBoZWlnaHQ6IDQwcHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjFyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5LCBidXR0b24uc2Vjb25kYXJ5IHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjc1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogbm9uZTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CiAgYnV0dG9uLnByaW1hcnk6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KICBidXR0b24uc2Vjb25kYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgYnV0dG9uLmRhbmdlciB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tZGFuZ2VyKTsgfQogIGJ1dHRvbi5kYW5nZXI6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KCiAgLmRhbmdlci16b25lIHsKICAgIGJvcmRlci1jb2xvcjogcmdiYSgyMzksIDY4LCA2OCwgMC4zNSkgIWltcG9ydGFudDsKICB9CiAgLmRhbmdlci16b25lIGgzIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KCiAgLmxvY2stc2NyZWVuIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwMDsKICAgIHBhZGRpbmc6IDEuNXJlbTsKICB9CiAgLmxvY2stc2NyZWVuLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubG9jay1jYXJkIHsgbWF4LXdpZHRoOiAzMjBweDsgd2lkdGg6IDEwMCU7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogIC5sb2NrLWVtb2ppIHsgZm9udC1zaXplOiAzcmVtOyBtYXJnaW4tYm90dG9tOiAwLjVyZW07IH0KICAubG9jay1jYXJkIGgxIHsgbWFyZ2luOiAwIDAgMC41cmVtOyB9CiAgLmxvY2stY2FyZCBwIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luOiAwIDAgMS4yNXJlbTsgZm9udC1zaXplOiAwLjlyZW07IH0KICAubG9jay1jYXJkIGlucHV0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgbWFyZ2luLWJvdHRvbTogMC43NXJlbTsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjlyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICAubG9jay1lcnJvciB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyBmb250LXNpemU6IDAuODVyZW07IG1hcmdpbi10b3A6IDAuNzVyZW07IH0KICAubG9jay1lcnJvci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGRpdiBjbGFzcz0ibG9jay1zY3JlZW4gaGlkZGVuIiBpZD0ibG9jay1zY3JlZW4iPgogICAgPGRpdiBjbGFzcz0ibG9jay1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibG9jay1lbW9qaSI+8J+SsDwvZGl2PgogICAgICA8aDE+S2FjaGluZzwvaDE+CiAgICAgIDxwPkVudHJlIGxlIG1vdCBkZSBwYXNzZSBwb3VyIGFjY8OpZGVyIMOgIHRlcyBkb25uw6llcy48L3A+CiAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9ImxvY2stcGFzc3dvcmQtaW5wdXQiIHBsYWNlaG9sZGVyPSJNb3QgZGUgcGFzc2UiIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCI+CiAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9ImxvY2stdW5sb2NrLWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Ew6l2ZXJyb3VpbGxlcjwvYnV0dG9uPgogICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJsb2NrLWVycm9yIj48L3A+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBpZD0iYXBwLXJvb3QiIGhpZGRlbj4KICA8aGVhZGVyPgogICAgPGgxPvCfkrAgS2FjaGluZzwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgZXQgcmV2ZW51cywgYWpvdXTDqXMgb3Ugw6lkaXTDqXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4gYWN0aXZlIiBpZD0idGFiLWhpc3RvcnkiIGRhdGEtdmlldz0iaGlzdG9yeSI+SGlzdG9yaXF1ZTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWRhc2hib2FyZCIgZGF0YS12aWV3PSJkYXNoYm9hcmQiPlRhYmxlYXUgZGUgYm9yZDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXJlY3VycmluZyIgZGF0YS12aWV3PSJyZWN1cnJpbmciPlLDqWN1cnJlbnRlczwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWV4cG9ydCIgZGF0YS12aWV3PSJleHBvcnQiPkV4cG9ydDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXNhdmluZ3MiIGRhdGEtdmlldz0ic2F2aW5ncyI+w4lwYXJnbmU8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQgdG9vbHRpcC1ob3N0IiBpZD0ic3VtbWFyeS11cGNvbWluZy1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj7DgCB2ZW5pciBjZSBtb2lzLWNpPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LXVwY29taW5nIj7igJQ8L3A+CiAgICAgIDxkaXYgY2xhc3M9ImN1c3RvbS10b29sdGlwIiBpZD0ic3VtbWFyeS11cGNvbWluZy10b29sdGlwIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8cCBjbGFzcz0id2Vlay1zdW1tYXJ5IiBpZD0id2Vlay1zdW1tYXJ5Ij48L3A+CgogIDxkaXYgaWQ9ImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIiBjbGFzcz0iY2F0ZWdvcnktc3VnZ2VzdGlvbiBoaWRkZW4iPjwvZGl2PgoKICA8bWFpbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpc3RvcnkiPgogICAgICA8ZGl2IGNsYXNzPSJmaWx0ZXItYmFyIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImZpbHRlci1zZWFyY2giIHBsYWNlaG9sZGVyPSJSZWNoZXJjaGVyLi4uIj4KICAgICAgICA8c2VsZWN0IGlkPSJmaWx0ZXItY2F0ZWdvcnkiPjxvcHRpb24gdmFsdWU9IiI+VG91dGVzIGNhdMOpZ29yaWVzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmaWx0ZXItZGF0ZS1zdGFydCIgYXJpYS1sYWJlbD0iRHUiPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtZW5kIiBhcmlhLWxhYmVsPSJBdSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGlkPSJ0eC1saXN0IiBjbGFzcz0idHgtbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1kYXNoYm9hcmQiIGNsYXNzPSJkYXNoYm9hcmQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIGTDqXBlbnNlcyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXRlZ29yeS1jaGFydC1yb3ciPgogICAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIgY2xhc3M9InVwY29taW5nLW5vdGUgaGlkZGVuIj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InVwY29taW5nLXN3YXRjaCI+PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLXRleHQiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1bmUgZMOpcGVuc2UgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPlLDqXBhcnRpdGlvbiBkZXMgcmV2ZW51cyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1biByZXZlbnUgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkJ1ZGdldHMgbWVuc3VlbHMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBJbmRpcXVlIHVuIG1vbnRhbnQgcG91ciB1bmUgY2F0w6lnb3JpZSBldCBlbnJlZ2lzdHJlIGF2ZWMg8J+SviDigJQgbGEgYmFycmUKICAgICAgICAgIGNvbXBhcmUgZW5zdWl0ZSB0ZXMgZMOpcGVuc2VzIGR1IG1vaXMgZW4gY291cnMgw6AgY2UgcGxhZm9uZCAodmVydCwKICAgICAgICAgIG9yYW5nZSBhdS1kZWzDoCBkZSA3MCUsIHJvdWdlIGF1LWRlbMOgIGRlIDEwMCUpLiBMYSBwZXRpdGUgcmFuZ8OpZSBkZQogICAgICAgICAgYmFycmVzIGVuIGRlc3NvdXMgbW9udHJlIGwnaGlzdG9yaXF1ZSBkZXMgNiBkZXJuaWVycyBtb2lzIChzdXJ2b2xlCiAgICAgICAgICBvdSB0b3VjaGUgdW5lIGJhcnJlIHBvdXIgdm9pciBsZSBkw6l0YWlsKS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBpZD0iYnVkZ2V0cy1saXN0Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJidWRnZXRzLXNhdmUtcm93Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9Imljb24tYnRuIiBpZD0iYnVkZ2V0cy1zYXZlLWFsbC1idG4iIGFyaWEtbGFiZWw9IkVucmVnaXN0cmVyIHRvdXMgbGVzIGJ1ZGdldHMiPvCfkr48L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+w4l2b2x1dGlvbiBtZW5zdWVsbGUgKGTDqXBlbnNlcyB2cyByZXZlbnVzKTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1ldm9sdXRpb24iPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkNvbXBhcmVyIGRldXggbW9pczwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY29tcGFyZS1zZWxlY3RzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYSI+PC9zZWxlY3Q+CiAgICAgICAgICA8c3Bhbj52czwvc3Bhbj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYiI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgYXNzZXogZGUgbW9pcyBkaWZmw6lyZW50cyBwb3VyIGNvbXBhcmVyLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Nb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8ZGl2IGlkPSJ0cmVuZC10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJ0cmVuZC1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+QmlsYW4gYW5udWVsPC9oMz4KICAgICAgICAgIDxzZWxlY3QgaWQ9InllYXJseS15ZWFyLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN1bW1hcnkiPgogICAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN0YXQiPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ieWVhcmx5LXN0YXQtbGFiZWwiPkTDqXBlbnNlczwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS10b3RhbC1leHBlbnNlcyIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIGV4cGVuc2UiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN0YXQiPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ieWVhcmx5LXN0YXQtbGFiZWwiPlJldmVudXM8L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJ5ZWFybHktdG90YWwtaW5jb21lIiBjbGFzcz0ieWVhcmx5LXN0YXQtdmFsdWUgaW5jb21lIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5Tb2xkZSBuZXQ8L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJ5ZWFybHktbmV0IiBjbGFzcz0ieWVhcmx5LXN0YXQtdmFsdWUiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQteWVhcmx5Ij48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJ5ZWFybHktZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBkZSBkb25uw6llcyBwb3VyIGNldHRlIGFubsOpZS4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJ5ZWFybHktY2F0ZWdvcnktdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXJlY3VycmluZyIgY2xhc3M9InJlY3VycmluZy1zZWN0aW9uIj4KICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICBDaGFyZ2VzIGZpeGVzIChhYm9ubmVtZW50cywgbG95ZXIsIHNhbGFpcmXigKYpIGNvbXB0w6llcyBhdXRvbWF0aXF1ZW1lbnQKICAgICAgICBjaGFxdWUgbW9pcyBkYW5zIGxlIHRhYmxlYXUgZGUgYm9yZCDigJQgcGFzIGJlc29pbiBkZSBsZXMgcmVkaWN0ZXIuCiAgICAgICAgTWV0cyB1bmUgZGF0ZSBkZSBkw6lidXQgc2kgdW5lIGNoYXJnZSBuZSBkb2l0IGTDqW1hcnJlciBxdWUgcGx1cyB0YXJkLAogICAgICAgIHVuZSBkYXRlIGRlIGZpbiBzaSBlbGxlIGRvaXQgcydhcnLDqnRlciB1biBqb3VyLgogICAgICA8L3A+CiAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1wYW5lbCIgY2xhc3M9InVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoaWRkZW4iPgogICAgICAgIDxoND5Qcm9jaGFpbmVzIMOpY2jDqWFuY2VzPC9oND4KICAgICAgICA8ZGl2IGlkPSJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIEF1Y3VuZSBkw6lwZW5zZSByw6ljdXJyZW50ZSBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciArIHBvdXIgZW4gYWpvdXRlciB1bmUuCiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWV4cG9ydCIgY2xhc3M9ImV4cG9ydC1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkV4cG9ydGVyIHRlcyBkb25uw6llczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFTDqWzDqWNoYXJnZSB1biBmaWNoaWVyIEV4Y2VsICgueGxzeCkgYXZlYyB0b3V0ZXMgdGVzIHRyYW5zYWN0aW9ucwogICAgICAgICAgKGTDqXBlbnNlcyBldCByZXZlbnVzKSBldCB0ZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMgKGTDqXBlbnNlcyBldAogICAgICAgICAgcmV2ZW51cyByw6ljdXJyZW50cyksIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQteGxzeCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Uw6lsw6ljaGFyZ2VyIGxlIGZpY2hpZXIgRXhjZWw8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+U2F1dmVnYXJkZSBjb21wbMOodGU8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBUw6lsw6ljaGFyZ2UgdW4gZmljaGllciBKU09OIGF2ZWMgYWJzb2x1bWVudCB0b3V0ZXMgdGVzIGRvbm7DqWVzCiAgICAgICAgICAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsCiAgICAgICAgICBvYmplY3RpZiBkJ8OpcGFyZ25lKS4gw4AgZ2FyZGVyIGRlIGPDtHTDqSA6IFN1cGFiYXNlIG5lIGZhaXQgcGFzIGRlCiAgICAgICAgICBzYXV2ZWdhcmRlIGF1dG9tYXRpcXVlIGVuIG9mZnJlIGdyYXR1aXRlLCBjZSBmaWNoaWVyIGVzdCB0b24gZmlsZXQKICAgICAgICAgIGRlIHPDqWN1cml0w6kgZW4gY2FzIGRlIHDDqXBpbi4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQtanNvbiIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Uw6lsw6ljaGFyZ2VyIGxhIHNhdXZlZ2FyZGUgKEpTT04pPC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9InB3YS1pbnN0YWxsLXJvdyIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIDxoMz5JbnN0YWxsZXIgbCdhcHBsaWNhdGlvbjwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEFqb3V0ZSBsJ2FwcCBzdXIgdG9uIMOpY3JhbiBkJ2FjY3VlaWwgKHTDqWzDqXBob25lLCB0YWJsZXR0ZSBvdQogICAgICAgICAgb3JkaW5hdGV1cikgcG91ciBsJ291dnJpciBlbiB1biBnZXN0ZSwgY29tbWUgdW5lIGFwcCBuYXRpdmUuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJwd2EtaW5zdGFsbC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+8J+TsiBJbnN0YWxsZXIgbCdhcHBsaWNhdGlvbjwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJwd2EtaW9zLWhpbnQtcm93IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgPGgzPkluc3RhbGxlciBsJ2FwcGxpY2F0aW9uPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgU3VyIGlQaG9uZS9pUGFkIDogYXBwdWllIHN1ciBsJ2ljw7RuZSBQYXJ0YWdlciBkZSBTYWZhcmksIHB1aXMKICAgICAgICAgIMKrIFN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwgwrsuCiAgICAgICAgPC9wPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3cgZGFuZ2VyLXpvbmUiPgogICAgICAgIDxoMz7imqDvuI8gWm9uZSBkYW5nZXJldXNlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgU3VwcHJpbWUgZMOpZmluaXRpdmVtZW50IFRPVVRFUyBsZXMgZG9ubsOpZXMgOiB0cmFuc2FjdGlvbnMsIGNoYXJnZXMKICAgICAgICAgIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc29ubmFsaXPDqWVzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMsCiAgICAgICAgICBidWRnZXRzLCBwaG90b3MgZGUgcmXDp3VzIGV0IG9iamVjdGlmIGQnw6lwYXJnbmUuIFBlbnNlIMOgIGV4cG9ydGVyIGVuCiAgICAgICAgICBFeGNlbCBhdmFudCBzaSBiZXNvaW4g4oCUIGltcG9zc2libGUgw6AgYW5udWxlci4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZGFuZ2VyIiBpZD0iYnRuLXJlc2V0LWFsbCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Sw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXNhdmluZ3MiIGNsYXNzPSJzYXZpbmdzLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+T2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgTGUgbW9udGFudCBxdWUgdHUgdmV1eCBnYXJkZXIgZGUgY8O0dMOpIGNoYXF1ZSBtb2lzIChyZXZlbnVzIG1vaW5zCiAgICAgICAgICBkw6lwZW5zZXMpLiBDb21wYXLDqSDDoCB0b24gc29sZGUgcsOpZWwgZHUgbW9pcyBlbiBjb3Vycy4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0ic2F2aW5ncy1nb2FsLXJvdyI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ic2F2aW5ncy1nb2FsLWlucHV0IiBtaW49IjAiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSJFeCA6IDEwMCI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9InNhdmluZ3MtZ29hbC1zYXZlLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgbCdvYmplY3RpZiI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwiPgogICAgICAgICAgICA8c3Bhbj5Tb2xkZSBkdSBtb2lzIGVuIGNvdXJzPC9zcGFuPgogICAgICAgICAgICA8c3Ryb25nIGlkPSJzYXZpbmdzLXByb2dyZXNzLXRleHQiPjwvc3Ryb25nPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJidWRnZXQtYmFyLXRyYWNrIj4KICAgICAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wcm9ncmVzcy1iYXIiIGNsYXNzPSJidWRnZXQtYmFyLWZpbGwgb2siPjwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkNvbnNlaWxzPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgQmFzw6lzIHN1ciB0ZXMgYnVkZ2V0cyBwYXIgY2F0w6lnb3JpZSBldCB0ZXMgdGVuZGFuY2VzIGRlIGTDqXBlbnNlcwogICAgICAgICAgKHZvaXIgbCdvbmdsZXQgVGFibGVhdSBkZSBib3JkKS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtbGlzdCIgY2xhc3M9ImFkdmljZS1saXN0Ij48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLWFkdmljZS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcyBjZSBtb2lzLWNpIHBvdXIgdGUgZG9ubmVyIGRlcyBjb25zZWlscy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgPC9tYWluPgoKICA8ZGl2IGNsYXNzPSJ2b2ljZS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtYmFubmVyIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJmYWItbWljIiBpZD0iZmFiLW1pYyIgYXJpYS1sYWJlbD0iRGljdGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUsIG91IHBvc2VyIHVuZSBxdWVzdGlvbiIgdGl0bGU9IkRpY3RlIHVuZSBkw6lwZW5zZS91biByZXZlbnUsIG91IHBvc2UgdW5lIHF1ZXN0aW9uIChleCA6IMKrIGNvbWJpZW4gaidhaSBkw6lwZW5zw6kgZW4gcmVzdGF1cmFudCBjZSBtb2lzLWNpID8gwrspIj7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dAogICAgICAgICAgdHlwZT0idGV4dCIKICAgICAgICAgIGlkPSJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIKICAgICAgICAgIHBsYWNlaG9sZGVyPSJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIKICAgICAgICAgIGNsYXNzPSJoaWRkZW4iCiAgICAgICAgICBzdHlsZT0ibWFyZ2luLXRvcDogOHB4OyIKICAgICAgICA+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbD5SZcOndSAocGhvdG8sIG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iaW5wdXQtcmVjZWlwdC1maWxlIiBjbGFzcz0iaGlkZGVuLWZpbGUtaW5wdXQiIGFjY2VwdD0iaW1hZ2UvKiIgY2FwdHVyZT0iZW52aXJvbm1lbnQiPgogICAgICAgIDxkaXYgaWQ9InJlY2VpcHQtcHJldmlldy13cmFwIiBjbGFzcz0icmVjZWlwdC1wcmV2aWV3LXdyYXAgaGlkZGVuIj4KICAgICAgICAgIDxpbWcgaWQ9InJlY2VpcHQtcHJldmlldy1pbWciIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctaW1nIiBhbHQ9IlJlw6d1Ij4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcmVtb3ZlIj5TdXBwcmltZXIgbGEgcGhvdG88L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1yZWNlaXB0LXBpY2siIHN0eWxlPSJ3aWR0aDoxMDAlOyI+8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlYy1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJyZWMtbW9kYWwtdGl0bGUiPk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0icmVjLXR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtbmFtZSI+Tm9tPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InJlYy1pbnB1dC1uYW1lIiBwbGFjZWhvbGRlcj0iRXggOiBOZXRmbGl4LCBMb3llciwgU2FsYWlyZS4uLiI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZGF5Ij5Kb3VyIGR1IG1vaXM8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtZGF5IiBtaW49IjEiIG1heD0iMzEiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSIxIMOgIDMxIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPkRhdGUgZGUgZMOpYnV0IChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1zdGFydC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWVuZC1kYXRlIj5EYXRlIGRlIGZpbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtZW5kLWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0icmVjLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVjLWJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0iY29uZmlybS1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIGNvbmZpcm0tbW9kYWwiPgogICAgICA8aDIgaWQ9ImNvbmZpcm0tbW9kYWwtdGl0bGUiPkNvbmZpcm1lcjwvaDI+CiAgICAgIDxwIGlkPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiIGNsYXNzPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiPjwvcD4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iY29uZmlybS1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImNvbmZpcm0tYnRuLW9rIj5Db25maXJtZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibGlnaHRib3gtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LW92ZXJsYXkiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJsaWdodGJveC1jbG9zZSIgaWQ9InJlY2VpcHQtbGlnaHRib3gtY2xvc2UiIGFyaWEtbGFiZWw9IkZlcm1lciI+4pyVPC9idXR0b24+CiAgICA8aW1nIGNsYXNzPSJsaWdodGJveC1pbWciIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LWltZyIgYWx0PSJSZcOndSBlbiBwbGVpbiDDqWNyYW4iPgogIDwvZGl2PgogIDwvZGl2PgoKICA8c2NyaXB0PgogICAgLy8gTGUgamV0b24gZGUgc2Vzc2lvbiAob2J0ZW51IGFwcsOocyBhdm9pciB0YXDDqSBsZSBtb3QgZGUgcGFzc2Ugc3VyIGwnw6ljcmFuCiAgICAvLyBkZSB2ZXJyb3VpbGxhZ2UpIHJlbXBsYWNlIGwnYW5jaWVubmUgY2zDqSBBUEkgY29kw6llIGVuIGR1ciBpY2kg4oCUIGNlbGxlLWNpCiAgICAvLyDDqXRhaXQgdmlzaWJsZSBwYXIgbidpbXBvcnRlIHF1aSB2aWEgIkFmZmljaGVyIGxlIGNvZGUgc291cmNlIiwgc2FucwogICAgLy8gYXVjdW4gbW90IGRlIHBhc3NlLiBMZSBqZXRvbiBlc3Qgc2lnbsOpIGPDtHTDqSBzZXJ2ZXVyIGV0IGV4cGlyZSBhcHLDqHMgOTAKICAgIC8vIGpvdXJzIDsgaWwgbmUgcsOpdsOobGUgcmllbiBkZSBzZWNyZXQgZW4gbHVpLW3Dqm1lLgogICAgY29uc3QgVE9LRU5fU1RPUkFHRV9LRVkgPSAia2FjaGluZ19zZXNzaW9uX3Rva2VuIjsKICAgIGxldCBBUElfS0VZID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oVE9LRU5fU1RPUkFHRV9LRVkpIHx8ICIiOwoKICAgIGNvbnN0IGxvY2tTY3JlZW5FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLXNjcmVlbiIpOwogICAgY29uc3QgYXBwUm9vdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImFwcC1yb290Iik7CiAgICBjb25zdCBsb2NrUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLXBhc3N3b3JkLWlucHV0Iik7CiAgICBjb25zdCBsb2NrVW5sb2NrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stdW5sb2NrLWJ0biIpOwogICAgY29uc3QgbG9ja0Vycm9yRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9jay1lcnJvciIpOwoKICAgIGZ1bmN0aW9uIHNob3dMb2NrU2NyZWVuKCkgewogICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShUT0tFTl9TVE9SQUdFX0tFWSk7CiAgICAgIEFQSV9LRVkgPSAiIjsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IHRydWU7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbG9ja1Bhc3N3b3JkSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbG9ja1Bhc3N3b3JkSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93QXBwKCkgewogICAgICBsb2NrU2NyZWVuRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGFwcFJvb3RFbC5oaWRkZW4gPSBmYWxzZTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhdHRlbXB0VW5sb2NrKCkgewogICAgICBjb25zdCBwYXNzd29yZCA9IGxvY2tQYXNzd29yZElucHV0LnZhbHVlOwogICAgICBpZiAoIXBhc3N3b3JkKSByZXR1cm47CiAgICAgIGxvY2tFcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBsb2NrVW5sb2NrQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbG9ja1VubG9ja0J0bi50ZXh0Q29udGVudCA9ICJWw6lyaWZpY2F0aW9u4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9sb2dpbiIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgaGVhZGVyczogeyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0sCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBhc3N3b3JkIH0pLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKS5jYXRjaCgoKSA9PiAoe30pKTsKICAgICAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLmRldGFpbCB8fCAiTW90IGRlIHBhc3NlIGluY29ycmVjdCIpOwogICAgICAgIH0KICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSwgZGF0YS50b2tlbik7CiAgICAgICAgLy8gUmVjaGFyZ2VtZW50IGNvbXBsZXQgcGx1dMO0dCBxdWUgZGUgcsOpLWVuY2hhw65uZXIgbCdpbml0IG1hbnVlbGxlbWVudCA6CiAgICAgICAgLy8gcGx1cyBzaW1wbGUgZXQgcGx1cyBzw7tyIChvbiByZXBhcnQgYXZlYyB1biDDqXRhdCBwcm9wcmUsIEFQSV9LRVkgbHUKICAgICAgICAvLyBkZXB1aXMgbGUgbG9jYWxTdG9yYWdlIGNvbW1lIGF1IHRvdXQgcHJlbWllciBjaGFyZ2VtZW50KS4KICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIGxvY2tFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2UgfHwgIk1vdCBkZSBwYXNzZSBpbmNvcnJlY3QiOwogICAgICAgIGxvY2tFcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIGxvY2tVbmxvY2tCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBsb2NrVW5sb2NrQnRuLnRleHRDb250ZW50ID0gIkTDqXZlcnJvdWlsbGVyIjsKICAgICAgfQogICAgfQoKICAgIGxvY2tVbmxvY2tCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhdHRlbXB0VW5sb2NrKTsKICAgIGxvY2tQYXNzd29yZElucHV0LmFkZEV2ZW50TGlzdGVuZXIoImtleWRvd24iLCAoZSkgPT4gewogICAgICBpZiAoZS5rZXkgPT09ICJFbnRlciIpIGF0dGVtcHRVbmxvY2soKTsKICAgIH0pOwoKICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eC1saXN0Iik7CiAgICBjb25zdCBlbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHN1bW1hcnlCYWxhbmNlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1iYWxhbmNlIik7CiAgICBjb25zdCBzdW1tYXJ5RXhwZW5zZXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWV4cGVuc2VzIik7CiAgICBjb25zdCBzdW1tYXJ5SW5jb21lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1pbmNvbWUiKTsKCiAgICBjb25zdCBvdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgbW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLXRpdGxlIik7CiAgICBjb25zdCB0eXBlVG9nZ2xlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IGFtb3VudElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWFtb3VudCIpOwogICAgY29uc3QgY2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnkgPSBudWxsOyAvLyBjYXTDqWdvcmllIGRlIGxhIHRyYW5zYWN0aW9uIGF2YW50IMOpZGl0aW9uIChwb3VyIGTDqXRlY3RlciB1biBjaGFuZ2VtZW50KQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBob3RvIGRlIHJlw6d1IGVuIHBpw6hjZSBqb2ludGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IHJlY2VpcHRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtcmVjZWlwdC1maWxlIik7CiAgICBjb25zdCByZWNlaXB0UHJldmlld1dyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LXdyYXAiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtcHJldmlldy1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRQaWNrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZWNlaXB0LXBpY2siKTsKICAgIGNvbnN0IHJlY2VpcHRSZW1vdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcmVtb3ZlIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hPdmVybGF5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjZWlwdExpZ2h0Ym94SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtaW1nIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hDbG9zZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIik7CgogICAgLy8gRmljaGllciBjaG9pc2kgbWFpcyBwYXMgZW5jb3JlIGVudm95w6kgKHVuaXF1ZW1lbnQgZW4gY3LDqWF0aW9uLCB0YW50IHF1ZQogICAgLy8gbGEgdHJhbnNhY3Rpb24gbidhIHBhcyBlbmNvcmUgZCdpZCkgOyBlbiDDqWRpdGlvbiwgbCdlbnZvaSBlc3QgaW1tw6lkaWF0LgogICAgbGV0IHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICBsZXQgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgbGV0IGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNldFJlY2VpcHRQcmV2aWV3RnJvbUJsb2IoYmxvYikgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpOwogICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9IHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgUmVtcGxhY2VyIGxhIHBob3RvIjsKICAgIH0KCiAgICBmdW5jdGlvbiByZXNldFJlY2VpcHRVaSgpIHsKICAgICAgaWYgKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKSB7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgICAgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgICB9CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9ICIiOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3UiOwogICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgIHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgewogICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSByZXR1cm47CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKTsKICAgICAgICBoYXNFeGlzdGluZ1JlY2VpcHQgPSB0cnVlOwogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgLy8gUGFzIGdyYXZlIDogbCd1dGlsaXNhdGV1ciBwZXV0IGp1c3RlIHLDqWVzc2F5ZXIgZCdvdXZyaXIgbGEgZmljaGUuCiAgICAgIH0KICAgIH0KCiAgICByZWNlaXB0UGlja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHJlY2VpcHRGaWxlSW5wdXQuY2xpY2soKSk7CgogICAgcmVjZWlwdEZpbGVJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSByZWNlaXB0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHJldHVybjsKICAgICAgaWYgKCFmaWxlLnR5cGUuc3RhcnRzV2l0aCgiaW1hZ2UvIikpIHsKICAgICAgICBzaG93VG9hc3QoIkNob2lzaXMgdW5lIGltYWdlIChKUEVHLCBQTkcsIFdFQlAgb3UgSEVJQykiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiA4ICogMTAyNCAqIDEwMjQpIHsKICAgICAgICBzaG93VG9hc3QoIkltYWdlIHRyb3AgbG91cmRlICg4IE1vIG1heGltdW0pIiwgdHJ1ZSk7CiAgICAgICAgcmVjZWlwdEZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihmaWxlKTsKCiAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAvLyBUcmFuc2FjdGlvbiBkw6lqw6AgZXhpc3RhbnRlIDogb24gZW52b2llIHRvdXQgZGUgc3VpdGUsIGluZMOpcGVuZGFtbWVudAogICAgICAgIC8vIGR1IGJvdXRvbiAiRW5yZWdpc3RyZXIiIGR1IGZvcm11bGFpcmUuCiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgIH0pLnRoZW4oYXN5bmMgKHJlcykgPT4gewogICAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLmRldGFpbCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWApOwogICAgICAgICAgICB9CiAgICAgICAgICB9KTsKICAgICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgICAgICBzaG93VG9hc3QoIlBob3RvIGR1IHJlw6d1IGVucmVnaXN0csOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICAvLyBOb3V2ZWxsZSB0cmFuc2FjdGlvbiBwYXMgZW5jb3JlIGNyw6nDqWUgOiBvbiBnYXJkZSBsZSBmaWNoaWVyIGRlIGPDtHTDqSwKICAgICAgICAvLyBpbCBzZXJhIGVudm95w6kganVzdGUgYXByw6hzIGxhIGNyw6lhdGlvbiAodm9pciBidG4tc2F2ZSkuCiAgICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gZmlsZTsKICAgICAgfQogICAgfSk7CgogICAgcmVjZWlwdFJlbW92ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgaWYgKGVkaXRpbmdJZCAmJiBoYXNFeGlzdGluZ1JlY2VpcHQpIHsKICAgICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGxhIHBob3RvIGRlIGNlIHJlw6d1ID8iKSkpIHJldHVybjsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gc3VwcHJpbcOpZSIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0KICAgICAgfSBlbHNlIHsKICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICB9CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjZWlwdExpZ2h0Ym94KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7dHJhbnNhY3Rpb25JZH0vcmVjZWlwdGAsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pCiAgICAgICAgLnRoZW4oKHJlcykgPT4gewogICAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiSW1wb3NzaWJsZSBkZSBjaGFyZ2VyIGxhIHBob3RvIik7CiAgICAgICAgICByZXR1cm4gcmVzLmJsb2IoKTsKICAgICAgICB9KQogICAgICAgIC50aGVuKChibG9iKSA9PiB7CiAgICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9IHVybDsKICAgICAgICAgIHJlY2VpcHRMaWdodGJveE92ZXJsYXkuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgfSkKICAgICAgICAuY2F0Y2goKGVycikgPT4gc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY2VpcHRMaWdodGJveCgpIHsKICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgaWYgKHJlY2VpcHRMaWdodGJveEltZy5zcmMpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRMaWdodGJveEltZy5zcmMpOwogICAgICAgIHJlY2VpcHRMaWdodGJveEltZy5zcmMgPSAiIjsKICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRMaWdodGJveENsb3NlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWNlaXB0TGlnaHRib3gpOwogICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGlmIChlLnRhcmdldCA9PT0gcmVjZWlwdExpZ2h0Ym94T3ZlcmxheSkgY2xvc2VSZWNlaXB0TGlnaHRib3goKTsKICAgIH0pOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIC8vIENhdMOpZ29yaWVzIGNyw6nDqWVzIHBhciBsJ3V0aWxpc2F0ZXVyIGRlcHVpcyBsZSBiYW5kZWF1IGRlIHN1Z2dlc3Rpb24KICAgIC8vICh2b2lyIHBsdXMgYmFzKSwgZXQgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIDogc3RvY2vDqWVzIGPDtHTDqSBzZXJ2ZXVyCiAgICAvLyAodGFibGVzIGN1c3RvbV9jYXRlZ29yaWVzIC8gZGlzbWlzc2VkX2NhdGVnb3J5X3N1Z2dlc3Rpb25zKSBwbHV0w7R0CiAgICAvLyBxdWUgZGFucyBsZSBuYXZpZ2F0ZXVyLCBwb3VyIHN1aXZyZSBzdXIgdG91cyBsZXMgYXBwYXJlaWxzICh0w6lsw6lwaG9uZSwKICAgIC8vIHRhYmxldHRlLCBvcmRpbmF0ZXVyKSBwbHV0w7R0IHF1ZSBkZSBuZSBtYXJjaGVyIHF1ZSBsw6Agb8O5IGMnw6l0YWl0IGNyw6nDqS4KICAgIGxldCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoKTsKICAgIGxldCBhbGxCdWRnZXRzID0gW107CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEJ1ZGdldHMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgYWxsQnVkZ2V0cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgYnVkZ2V0cyA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9iamVjdGlmIGQnw6lwYXJnbmUgbWVuc3VlbCArIGNvbnNlaWxzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBsZXQgc2F2aW5nc0dvYWwgPSBudWxsOyAvLyB7IG1vbnRobHlfdGFyZ2V0IH0gb3UgbnVsbCBzaSBqYW1haXMgY29uZmlndXLDqQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRTYXZpbmdzR29hbCgpIHsKICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlIGwnb2JqZWN0aWYgZCfDqXBhcmduZSA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGVudHJpZXMgPSBPYmplY3QuZW50cmllcyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KTsKICAgICAgbGV0IHNhdmVkQ291bnQgPSAwOwogICAgICBsZXQgaGFkRXJyb3IgPSBmYWxzZTsKICAgICAgZm9yIChjb25zdCBbY2F0ZWdvcnksIGlucHV0XSBvZiBlbnRyaWVzKSB7CiAgICAgICAgY29uc3QgcmF3ID0gaW5wdXQudmFsdWU7CiAgICAgICAgaWYgKHJhdyA9PT0gIiIgfHwgcmF3ID09PSBudWxsKSBjb250aW51ZTsKICAgICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIocmF3KTsKICAgICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgY29udGludWU7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGF3YWl0IHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCk7CiAgICAgICAgICBzYXZlZENvdW50ICs9IDE7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBoYWRFcnJvciA9IHRydWU7CiAgICAgICAgfQogICAgICB9CiAgICAgIGlmIChoYWRFcnJvcikgewogICAgICAgIHNob3dUb2FzdCgiQ2VydGFpbnMgYnVkZ2V0cyBuJ29udCBwYXMgcHUgw6p0cmUgZW5yZWdpc3Ryw6lzIiwgdHJ1ZSk7CiAgICAgIH0gZWxzZSBpZiAoc2F2ZWRDb3VudCA9PT0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSBhdSBtb2lucyB1biBtb250YW50IGRlIGJ1ZGdldCB2YWxpZGUiLCB0cnVlKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBzaG93VG9hc3QoIkJ1ZGdldHMgZW5yZWdpc3Ryw6lzIik7CiAgICAgIH0KICAgICAgcmVuZGVyQnVkZ2V0cyhhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgY29uc3Qgc2F2aW5nc0dvYWxJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtaW5wdXQiKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gTnVtYmVyKHNhdmluZ3NHb2FsSW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSB1biBtb250YW50IGQnb2JqZWN0aWYgdmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgc2F2aW5nc0dvYWwgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9zYXZpbmdzLWdvYWwiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBtb250aGx5X3RhcmdldDogYW1vdW50IH0pLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdCgiT2JqZWN0aWYgZW5yZWdpc3Ryw6kiKTsKICAgICAgICByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3ModHJhbnNhY3Rpb25zKSB7CiAgICAgIGlmIChzYXZpbmdzR29hbCkgc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwoKICAgICAgLy8gU29sZGUgZHUgbW9pcyBlbiBjb3VycyAocmV2ZW51cyAtIGTDqXBlbnNlcyksIHRvdXQgY29uZm9uZHUuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGxldCBtb250aEluY29tZSA9IDA7CiAgICAgIGxldCBtb250aEV4cGVuc2VzID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBjdXJyZW50TW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgbW9udGhJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSBtb250aEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRoTmV0ID0gbW9udGhJbmNvbWUgLSBtb250aEV4cGVuc2VzOwoKICAgICAgY29uc3QgcHJvZ3Jlc3NTZWN0aW9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIpOwogICAgICBjb25zdCBwcm9ncmVzc1RleHQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy10ZXh0Iik7CiAgICAgIGNvbnN0IHByb2dyZXNzQmFyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtYmFyIik7CiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgY29uc3QgdGFyZ2V0ID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CiAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5tYXgoMCwgTWF0aC5taW4oKG1vbnRoTmV0IC8gdGFyZ2V0KSAqIDEwMCwgMTAwKSk7CiAgICAgICAgcHJvZ3Jlc3NUZXh0LnRleHRDb250ZW50ID0gYCR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0YXJnZXQpfWA7CiAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgaWYgKG1vbnRoTmV0IDwgMCkgY2xzID0gIm92ZXIiOwogICAgICAgIGVsc2UgaWYgKG1vbnRoTmV0IDwgdGFyZ2V0KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgcHJvZ3Jlc3NCYXIuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgIHByb2dyZXNzQmFyLnN0eWxlLndpZHRoID0gcGN0ICsgIiUiOwogICAgICB9IGVsc2UgewogICAgICAgIHByb2dyZXNzU2VjdGlvbi5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KTsKICAgIH0KCiAgICAvLyBDb25zZWlscyA6IGNyb2lzZSBkw6lwYXNzZW1lbnRzIGRlIGJ1ZGdldCAob25nbGV0IFRhYmxlYXUgZGUgYm9yZCkgZXQKICAgIC8vIHRlbmRhbmNlcyBwYXIgY2F0w6lnb3JpZSBwb3VyIHBvaW50ZXIgdmVycyBjZSBxdWkgYWlkZSBsZSBwbHVzIMOgCiAgICAvLyBhdHRlaW5kcmUgbCdvYmplY3RpZiDigJQgcGFzIHVuZSBJQSwganVzdGUgZGVzIHLDqGdsZXMgc2ltcGxlcyBzdXIgZGVzCiAgICAvLyBkb25uw6llcyBkw6lqw6AgY2FsY3Vsw6llcyBhaWxsZXVycyBkYW5zIGwnYXBwLgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5nc0FkdmljZSh0cmFuc2FjdGlvbnMsIG1vbnRoTmV0KSB7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWFkdmljZS1saXN0Iik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtZW1wdHkiKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBjb25zdCBhZHZpY2UgPSBbXTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiBtb250aFRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBjb25zdCB0cmVuZEJ5Q2F0ZWdvcnkgPSBPYmplY3QuZnJvbUVudHJpZXModHJlbmRzLm1hcCgodCkgPT4gW3QuY2F0ZWdvcnksIHRdKSk7CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0LCB0cmnDqWVzIHBhciBtb250YW50IGRlCiAgICAgIC8vIGTDqXBhc3NlbWVudCBkw6ljcm9pc3NhbnQg4oCUIGNlIHNvbnQgbGVzIGxldmllcnMgbGVzIHBsdXMgdXRpbGVzLgogICAgICBjb25zdCBvdmVyQnVkZ2V0ID0gW107CiAgICAgIGZvciAoY29uc3QgYnVkZ2V0IG9mIGFsbEJ1ZGdldHMpIHsKICAgICAgICBjb25zdCBzcGVudCA9IG1vbnRoVG90YWxzW2J1ZGdldC5jYXRlZ29yeV0gfHwgMDsKICAgICAgICBpZiAoc3BlbnQgPiBidWRnZXQuYW1vdW50KSB7CiAgICAgICAgICBvdmVyQnVkZ2V0LnB1c2goeyBjYXRlZ29yeTogYnVkZ2V0LmNhdGVnb3J5LCBzcGVudCwgYnVkZ2V0OiBidWRnZXQuYW1vdW50LCBvdmVyOiBzcGVudCAtIGJ1ZGdldC5hbW91bnQgfSk7CiAgICAgICAgfQogICAgICB9CiAgICAgIG92ZXJCdWRnZXQuc29ydCgoYSwgYikgPT4gYi5vdmVyIC0gYS5vdmVyKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBvdmVyQnVkZ2V0LnNsaWNlKDAsIDMpKSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnkpOwogICAgICAgIGNvbnN0IHRyZW5kID0gdHJlbmRCeUNhdGVnb3J5W2l0ZW0uY2F0ZWdvcnldOwogICAgICAgIGxldCB0ZXh0ID0gYFR1IGFzIGTDqXBhc3PDqSB0b24gYnVkZ2V0IDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5vdmVyKX0gY2UgbW9pcy1jaS5gOwogICAgICAgIGlmICh0cmVuZCAmJiB0cmVuZC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRleHQgKz0gYCBMYSB0ZW5kYW5jZSBlc3Qgw6AgbGEgaGF1c3NlICgrJHtNYXRoLnJvdW5kKHRyZW5kLnJhdGlvICogMTAwKX0lIHZzIHRhIG1veWVubmUpIOKAlCByw6lkdWlyZSBjZXMgZMOpcGVuc2VzIHQnYWlkZXJhaXQgbGUgcGx1cyDDoCBhdHRlaW5kcmUgdG9uIG9iamVjdGlmLmA7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHRleHQgKz0gYCBFc3NhaWUgZGUgcmFtZW5lciDDp2Egc291cyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmJ1ZGdldCl9IGxlIG1vaXMgcHJvY2hhaW4uYDsKICAgICAgICB9CiAgICAgICAgYWR2aWNlLnB1c2goeyB0eXBlOiAid2FybmluZyIsIGljb246ICLimqDvuI8iLCB0ZXh0IH0pOwogICAgICB9CgogICAgICAvLyBDYXTDqWdvcmllcyBlbiBuZXR0ZSBoYXVzc2UgbcOqbWUgc2FucyBidWRnZXQgZMOpcGFzc8OpIChvdSBzYW5zIGJ1ZGdldAogICAgICAvLyBkw6lmaW5pIGR1IHRvdXQpIDogdW4gc2lnbmFsIHV0aWxlIGVuIHNvaS4KICAgICAgY29uc3QgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0ID0gdHJlbmRzCiAgICAgICAgLmZpbHRlcigodCkgPT4gdC5kaXJlY3Rpb24gPT09ICJ1cCIgJiYgdC5hdmVyYWdlID4gMCAmJiAhb3ZlckJ1ZGdldC5zb21lKChvKSA9PiBvLmNhdGVnb3J5ID09PSB0LmNhdGVnb3J5KSkKICAgICAgICAuc29ydCgoYSwgYikgPT4gYi5yYXRpbyAtIGEucmF0aW8pCiAgICAgICAgLnNsaWNlKDAsIDIpOwogICAgICBmb3IgKGNvbnN0IHQgb2YgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0KSB7CiAgICAgICAgY29uc3QgbGFiZWwgPSBlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW3QuY2F0ZWdvcnldIHx8IHQuY2F0ZWdvcnkpOwogICAgICAgIGFkdmljZS5wdXNoKHsKICAgICAgICAgIHR5cGU6ICJpbmZvIiwKICAgICAgICAgIGljb246ICLwn5OIIiwKICAgICAgICAgIHRleHQ6IGBUZXMgZMOpcGVuc2VzIGVuIDxzdHJvbmc+JHtsYWJlbH08L3N0cm9uZz4gc29udCBlbiBoYXVzc2UgZGUgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSUgcGFyIHJhcHBvcnQgw6AgdGEgbW95ZW5uZSDigJQgw6Agc3VydmVpbGxlciBzaSB0dSB2ZXV4IMOpcGFyZ25lciBwbHVzLmAsCiAgICAgICAgfSk7CiAgICAgIH0KCiAgICAgIC8vIE9iamVjdGlmIGF0dGVpbnQgLyBlbiBib25uZSB2b2llIGNlIG1vaXMtY2kuCiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCA+IDApIHsKICAgICAgICBpZiAobW9udGhOZXQgPj0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogInBvc2l0aXZlIiwKICAgICAgICAgICAgaWNvbjogIvCfjokiLAogICAgICAgICAgICB0ZXh0OiBgT2JqZWN0aWYgYXR0ZWludCAhIFR1IGFzIGTDqWrDoCBtaXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobW9udGhOZXQpfSBkZSBjw7R0w6kgY2UgbW9pcy1jaSwgYXUtZGVsw6AgZGUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0gZWxzZSBpZiAob3ZlckJ1ZGdldC5sZW5ndGggPT09IDAgJiYgcmlzaW5nV2l0aG91dEJ1ZGdldEFsZXJ0Lmxlbmd0aCA9PT0gMCkgewogICAgICAgICAgYWR2aWNlLnVuc2hpZnQoewogICAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICAgIGljb246ICLwn5GNIiwKICAgICAgICAgICAgdGV4dDogYFBhcyBkZSBkw6lwYXNzZW1lbnQgZGUgYnVkZ2V0IGNlIG1vaXMtY2kuIElsIHRlIHJlc3RlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0IC0gbW9udGhOZXQpfSDDoCDDqWNvbm9taXNlciBwb3VyIGF0dGVpbmRyZSB0b24gb2JqZWN0aWYgZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpfS5gLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBpZiAoYWR2aWNlLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhZHZpY2UpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAiYWR2aWNlLWNhcmQgIiArIGl0ZW0udHlwZTsKICAgICAgICBjb25zdCBpY29uID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGljb24uY2xhc3NOYW1lID0gImFkdmljZS1pY29uIjsKICAgICAgICBpY29uLnRleHRDb250ZW50ID0gaXRlbS5pY29uOwogICAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgdGV4dC5pbm5lckhUTUwgPSBpdGVtLnRleHQ7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChpY29uKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKHRleHQpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCkgewogICAgICBjb25zdCB1cGRhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIsIHsKICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnksIGFtb3VudCB9KSwKICAgICAgfSk7CiAgICAgIGNvbnN0IGlkeCA9IGFsbEJ1ZGdldHMuZmluZEluZGV4KChiKSA9PiBiLmNhdGVnb3J5ID09PSBjYXRlZ29yeSk7CiAgICAgIGlmIChpZHggPj0gMCkgYWxsQnVkZ2V0c1tpZHhdID0gdXBkYXRlZDsKICAgICAgZWxzZSBhbGxCdWRnZXRzLnB1c2godXBkYXRlZCk7CiAgICB9CgogICAgY29uc3QgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeSA9IHt9OwogICAgY29uc3QgQlVER0VUX0hJU1RPUllfTU9OVEhTID0gNjsKCiAgICAvLyBMZXMgTiBkZXJuaWVycyBtb2lzIChjbMOpcyAiWVlZWS1NTSIpLCBkdSBwbHVzIGFuY2llbiBhdSBwbHVzIHLDqWNlbnQsCiAgICAvLyBlbiBmaW5pc3NhbnQgcGFyIGVuZE1vbnRoS2V5IGluY2x1cy4KICAgIGZ1bmN0aW9uIGxhc3ROTW9udGhLZXlzKG4sIGVuZE1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IFt5LCBtXSA9IGVuZE1vbnRoS2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGtleXMgPSBbXTsKICAgICAgZm9yIChsZXQgaSA9IG4gLSAxOyBpID49IDA7IGktLSkgewogICAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSh5LCBtIC0gMSAtIGksIDEpOwogICAgICAgIGtleXMucHVzaChkLmdldEZ1bGxZZWFyKCkgKyAiLSIgKyBTdHJpbmcoZC5nZXRNb250aCgpICsgMSkucGFkU3RhcnQoMiwgIjAiKSk7CiAgICAgIH0KICAgICAgcmV0dXJuIGtleXM7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidWRnZXRzLWxpc3QiKTsKICAgICAgaWYgKCF3cmFwKSByZXR1cm47CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgY3VycmVudE1vbnRoS2V5KTsKCiAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpKSBkZWxldGUgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVtrZXldOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSkgewogICAgICAgIGNvbnN0IGJ1ZGdldCA9IGFsbEJ1ZGdldHMuZmluZCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gdmFsdWUpOwogICAgICAgIGNvbnN0IHNwZW50ID0gdG90YWxzW3ZhbHVlXSB8fCAwOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ciOwoKICAgICAgICBjb25zdCBoZWFkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZC5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdy1oZWFkIjsKCiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4uY2xhc3NOYW1lID0gImJ1ZGdldC1jYXQtbmFtZSI7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBsYWJlbDsKCiAgICAgICAgY29uc3QgYW1vdW50cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRzLmNsYXNzTmFtZSA9ICJidWRnZXQtYW1vdW50cyI7CiAgICAgICAgY29uc3Qgc3BlbnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHNwZW50U3Bhbi50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzcGVudCkgKyAiIC8gIjsKICAgICAgICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgaW5wdXQudHlwZSA9ICJudW1iZXIiOwogICAgICAgIGlucHV0LmNsYXNzTmFtZSA9ICJidWRnZXQtaW5wdXQiOwogICAgICAgIGlucHV0Lm1pbiA9ICIwIjsKICAgICAgICBpbnB1dC5zdGVwID0gIjEiOwogICAgICAgIGlucHV0LnBsYWNlaG9sZGVyID0gIuKAlCI7CiAgICAgICAgaWYgKGJ1ZGdldCkgaW5wdXQudmFsdWUgPSBidWRnZXQuYW1vdW50OwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoc3BlbnRTcGFuKTsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKGlucHV0KTsKICAgICAgICBidWRnZXRJbnB1dHNCeUNhdGVnb3J5W3ZhbHVlXSA9IGlucHV0OwoKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKG5hbWVTcGFuKTsKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKGFtb3VudHMpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChoZWFkKTsKCiAgICAgICAgaWYgKGJ1ZGdldCkgewogICAgICAgICAgY29uc3QgdHJhY2sgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHRyYWNrLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLXRyYWNrIjsKICAgICAgICAgIGNvbnN0IGZpbGwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIGNvbnN0IHJhdGlvID0gc3BlbnQgLyBidWRnZXQuYW1vdW50OwogICAgICAgICAgY29uc3QgcGN0ID0gTWF0aC5taW4ocmF0aW8gKiAxMDAsIDEwMCk7CiAgICAgICAgICBsZXQgY2xzID0gIm9rIjsKICAgICAgICAgIGlmIChyYXRpbyA+PSAxKSBjbHMgPSAib3ZlciI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA+PSAwLjcpIGNscyA9ICJ3YXJuaW5nIjsKICAgICAgICAgIGZpbGwuY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItZmlsbCAiICsgY2xzOwogICAgICAgICAgZmlsbC5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgICAgIHRyYWNrLmFwcGVuZENoaWxkKGZpbGwpOwogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHRyYWNrKTsKCiAgICAgICAgICBjb25zdCBzdHJpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgc3RyaXAuY2xhc3NOYW1lID0gImJ1ZGdldC1oaXN0b3J5LXN0cmlwIjsKICAgICAgICAgIGZvciAoY29uc3QgaGlzdEtleSBvZiBsYXN0Tk1vbnRoS2V5cyhCVURHRVRfSElTVE9SWV9NT05USFMsIGN1cnJlbnRNb250aEtleSkpIHsKICAgICAgICAgICAgY29uc3QgeyB0b3RhbHM6IGhpc3RUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBoaXN0S2V5KTsKICAgICAgICAgICAgY29uc3QgaGlzdFNwZW50ID0gaGlzdFRvdGFsc1t2YWx1ZV0gfHwgMDsKICAgICAgICAgICAgY29uc3QgZG90ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgICBpZiAoaGlzdFNwZW50ID09PSAwKSB7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCBlbXB0eSI7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgY29uc3QgaGlzdFJhdGlvID0gaGlzdFNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgICAgICBsZXQgaGlzdENscyA9ICJvayI7CiAgICAgICAgICAgICAgaWYgKGhpc3RSYXRpbyA+PSAxKSBoaXN0Q2xzID0gIm92ZXIiOwogICAgICAgICAgICAgIGVsc2UgaWYgKGhpc3RSYXRpbyA+PSAwLjcpIGhpc3RDbHMgPSAid2FybmluZyI7CiAgICAgICAgICAgICAgZG90LmNsYXNzTmFtZSA9ICJoaXN0b3J5LWRvdCAiICsgaGlzdENsczsKICAgICAgICAgICAgfQogICAgICAgICAgICBjb25zdCBbaHksIGhtXSA9IGhpc3RLZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgICAgY29uc3QgbW9udGhMYWJlbCA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGh5LCBobSAtIDEsIDEpKTsKICAgICAgICAgICAgY29uc3QgZGV0YWlsVGV4dCA9IGAke21vbnRoTGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaGlzdFNwZW50KX0gLyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChidWRnZXQuYW1vdW50KX1gOwogICAgICAgICAgICBkb3QudGl0bGUgPSBkZXRhaWxUZXh0OyAvLyBhZmZpY2jDqSBhdSBzdXJ2b2wgc3VyIG9yZGluYXRldXIKICAgICAgICAgICAgLy8gU3VyIG1vYmlsZSBpbCBuJ3kgYSBwYXMgZGUgc3Vydm9sIDogdW4gdGFwIHN1ciBsYSBiYXJyZSBtb250cmUKICAgICAgICAgICAgLy8gbGUgbcOqbWUgZMOpdGFpbCBkYW5zIHVuIHRvYXN0LgogICAgICAgICAgICBkb3QuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93VG9hc3QoZGV0YWlsVGV4dCkpOwogICAgICAgICAgICBzdHJpcC5hcHBlbmRDaGlsZChkb3QpOwogICAgICAgICAgfQogICAgICAgICAgcm93LmFwcGVuZENoaWxkKHN0cmlwKTsKICAgICAgICB9CgogICAgICAgIHdyYXAuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRDdXN0b21DYXRlZ29yaWVzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiKTsKICAgICAgICBmb3IgKGNvbnN0IHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0gb2YgaXRlbXMpIHsKICAgICAgICAgIGlmIChjYXRlZ29yaWVzQnlUeXBlW3R5cGVdICYmICFjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdmFsdWUpKSB7CiAgICAgICAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgICAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgY2F0w6lnb3JpZXMgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGtleXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiKTsKICAgICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoa2V5cyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgdW5lIHN1Z2dlc3Rpb24gZMOpasOgIHZ1ZSByw6lhcHBhcmHDrnQgdW5lIGZvaXMuCiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzbHVnaWZ5Q2F0ZWdvcnkobGFiZWwpIHsKICAgICAgcmV0dXJuICgKICAgICAgICBsYWJlbAogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gZW5sw6h2ZSBsZXMgYWNjZW50cwogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC50cmltKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0rL2csICJfIikKICAgICAgICAgIC5yZXBsYWNlKC9eXyt8XyskL2csICIiKSB8fCAiYXV0cmUiCiAgICAgICk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc2F2ZUN1c3RvbUNhdGVnb3J5KHR5cGUsIHZhbHVlLCBsYWJlbCkgewogICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiQ2F0w6lnb3JpZSBjcsOpw6llIGljaSwgbWFpcyBwYXMgc2F1dmVnYXJkw6llIHN1ciBsZSBzZXJ2ZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIC8vIMOJY2hhcHBlIHVuZSB2YWxldXIgYXZhbnQgZGUgbCdpbnPDqXJlciBkYW5zIHVuIHRlbXBsYXRlIEhUTUwgY29uc3RydWl0CiAgICAvLyDDoCBsYSBtYWluIChpbm5lckhUTUwpIDogbsOpY2Vzc2FpcmUgcGFydG91dCBvw7kgdW5lIGRvbm7DqWUgc2Fpc2llIHBhcgogICAgLy8gbCd1dGlsaXNhdGV1ciBwZXV0IHMneSByZXRyb3V2ZXIg4oCUIGVuIHBhcnRpY3VsaWVyIGxlIGxpYmVsbMOpIGQndW5lCiAgICAvLyBjYXTDqWdvcmllIHBlcnNvbm5hbGlzw6llICh0ZXh0ZSBsaWJyZSwgZW5yZWdpc3Ryw6kgZW4gYmFzZSksIHBvdXIgw6l2aXRlcgogICAgLy8gcXUndW4gbGliZWxsw6kgZHUgZ2VucmUgPGltZyBzcmM9eCBvbmVycm9yPS4uLj4gbmUgcydleMOpY3V0ZSBjb21tZSBkdQogICAgLy8gSFRNTC9KUyBhdSBsaWV1IGRlIHMnYWZmaWNoZXIgY29tbWUgZHUgdGV4dGUgKGluamVjdGlvbiBYU1Mgc3RvY2vDqWUpLgogICAgZnVuY3Rpb24gZXNjYXBlSHRtbChzdHIpIHsKICAgICAgcmV0dXJuIFN0cmluZyhzdHIpLnJlcGxhY2UoL1smPD4iJ10vZywgKGNoKSA9PiAoewogICAgICAgICImIjogIiZhbXA7IiwgIjwiOiAiJmx0OyIsICI+IjogIiZndDsiLCAnIic6ICImcXVvdDsiLCAiJyI6ICImIzM5OyIsCiAgICAgIH1bY2hdKSk7CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd1RvYXN0KG1lc3NhZ2UsIGlzRXJyb3IgPSBmYWxzZSkgewogICAgICBjb25zdCB0b2FzdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICB0b2FzdC5jbGFzc05hbWUgPSAidG9hc3QiICsgKGlzRXJyb3IgPyAiIGVycm9yIiA6ICIiKTsKICAgICAgdG9hc3QudGV4dENvbnRlbnQgPSBtZXNzYWdlOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRvYXN0KTsKICAgICAgc2V0VGltZW91dCgoKSA9PiB0b2FzdC5yZW1vdmUoKSwgMzAwMCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCwgb3B0aW9ucyA9IHt9KSB7CiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKHBhdGgsIHsKICAgICAgICAuLi5vcHRpb25zLAogICAgICAgIGhlYWRlcnM6IHsKICAgICAgICAgICJYLUFQSS1LZXkiOiBBUElfS0VZLAogICAgICAgICAgLi4uKG9wdGlvbnMuYm9keSA/IHsgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiB9IDoge30pLAogICAgICAgICAgLi4uKG9wdGlvbnMuaGVhZGVycyB8fCB7fSksCiAgICAgICAgfSwKICAgICAgfSk7CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSA0MDEpIHsKICAgICAgICAvLyBKZXRvbiBhYnNlbnQsIGludmFsaWRlIG91IGV4cGlyw6kgOiByZXRvdXIgw6AgbCfDqWNyYW4gZGUgdmVycm91aWxsYWdlCiAgICAgICAgLy8gcGx1dMO0dCBxdWUgZCdhZmZpY2hlciB1bmUgZXJyZXVyIHRlY2huaXF1ZSBpbmNvbXByw6loZW5zaWJsZS4KICAgICAgICBzaG93TG9ja1NjcmVlbigpOwogICAgICAgIHRocm93IG5ldyBFcnJvcigiU2Vzc2lvbiBleHBpcsOpZSwgcmVjb25uZWN0ZS10b2kuIik7CiAgICAgIH0KICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAvLyByZXMuc3RhdHVzVGV4dCBlc3Qgc291dmVudCB2aWRlIChuYXZpZ2F0ZXVycyBlbiBIVFRQLzIsIHV0aWxpc8OpIHBhcgogICAgICAgIC8vIFZlcmNlbCksIGRvbmMgb24gbmUgcGV1dCBwYXMgY29tcHRlciBkZXNzdXMgY29tbWUgbWVzc2FnZSBwYXIKICAgICAgICAvLyBkw6lmYXV0IDogb24gcmV0b21iZSBzdXIgbGUgY29kZSBIVFRQIHBvdXIgbmUgamFtYWlzIGFmZmljaGVyIHVuCiAgICAgICAgLy8gbWVzc2FnZSBkJ2VycmV1ciB2aWRlLgogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgZGV0YWlsID0gZGF0YS5kZXRhaWwgfHwgZGV0YWlsOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICB9CgogICAgY2F0ZWdvcnlJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LmNsYXNzTGlzdC50b2dnbGUoImhpZGRlbiIsIGNhdGVnb3J5SW5wdXQudmFsdWUgIT09ICJfX25ld19fIik7CiAgICAgIGlmIChjYXRlZ29yeUlucHV0LnZhbHVlID09PSAiX19uZXdfXyIpIG5ld0NhdGVnb3J5TmFtZUlucHV0LmZvY3VzKCk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IGlzRWRpdCA/IHR4LmNhdGVnb3J5IDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwoKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgaWYgKGlzRWRpdCAmJiB0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICBsb2FkRXhpc3RpbmdSZWNlaXB0UHJldmlldyh0eC5pZCk7CiAgICAgIH0KCiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkgewogICAgICAvLyBNw6ptZSBtb250YW50L2NhdMOpZ29yaWUvZGVzY3JpcHRpb24sIG1haXMgZGF0w6kgZCdhdWpvdXJkJ2h1aSBldCBzYW5zCiAgICAgIC8vIGlkIDogbGEgc2F1dmVnYXJkZSBjcsOpZXJhIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiAodm9pciBvcGVuTW9kYWwpLgogICAgICBvcGVuTW9kYWwoeyAuLi50eCwgaWQ6IG51bGwsIGV4cGVuc2VfZGF0ZTogdG9kYXlJc28oKSB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICAgIGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5ID0gbnVsbDsKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICAvLyAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIiBzw6lsZWN0aW9ubsOpIDogb24gbGEgY3LDqWUgKHNpIGVsbGUgbidleGlzdGUKICAgICAgLy8gcGFzIGTDqWrDoCBzb3VzIGNlIG5vbSkgYXZhbnQgZCdlbnJlZ2lzdHJlciBsYSB0cmFuc2FjdGlvbiBhdmVjLgogICAgICBsZXQgY2F0ZWdvcnlWYWx1ZSA9IGNhdGVnb3J5SW5wdXQudmFsdWU7CiAgICAgIGlmIChjYXRlZ29yeVZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICBjb25zdCBuYW1lID0gbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgIGlmICghbmFtZSkgewogICAgICAgICAgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIsIHRydWUpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBjYXRlZ29yeVZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtjdXJyZW50VHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSBjYXRlZ29yeVZhbHVlKSkgewogICAgICAgICAgYXdhaXQgc2F2ZUN1c3RvbUNhdGVnb3J5KGN1cnJlbnRUeXBlLCBjYXRlZ29yeVZhbHVlLCBuYW1lKTsKICAgICAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgY2F0ZWdvcnlWYWx1ZSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlWYWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgY29uc3QgcHJldmlvdXNDYXRlZ29yeSA9IGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5OwogICAgICAgICAgY29uc3QgZWRpdGVkSWQgPSBlZGl0aW5nSWQ7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CgogICAgICAgICAgLy8gU2kgbGEgY2F0w6lnb3JpZSB2aWVudCBkZSBjaGFuZ2VyIG1hbnVlbGxlbWVudCwgb24gcHJvcG9zZSBkZQogICAgICAgICAgLy8gcmVwb3J0ZXIgbGUgbcOqbWUgY2hhbmdlbWVudCBzdXIgbGVzIGF1dHJlcyB0cmFuc2FjdGlvbnMgZG9udCBsYQogICAgICAgICAgLy8gZGVzY3JpcHRpb24gcGFydGFnZSB1biBtb3QtY2zDqSBzaWduaWZpY2F0aWYgKGV4LiAiY2FzaW5vIiAvCiAgICAgICAgICAvLyAiYXUgY2FzaW5vIiAvICJwZXJ0ZSBhdSBjYXNpbm8iKSBldCBxdWkgw6l0YWllbnQgZGFucyBsJ2FuY2llbm5lCiAgICAgICAgICAvLyBjYXTDqWdvcmllIOKAlCBqYW1haXMgYXV0b21hdGlxdWUsIHRvdWpvdXJzIHN1ciBjb25maXJtYXRpb24uCiAgICAgICAgICBpZiAocHJldmlvdXNDYXRlZ29yeSAmJiBwYXlsb2FkLmNhdGVnb3J5ICE9PSBwcmV2aW91c0NhdGVnb3J5ICYmIHBheWxvYWQuZGVzY3JpcHRpb24pIHsKICAgICAgICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhwYXlsb2FkLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgaWYgKGtleXdvcmRzLnNpemUgPiAwKSB7CiAgICAgICAgICAgICAgY29uc3Qgc2ltaWxhciA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgICAgICAgICAodCkgPT4KICAgICAgICAgICAgICAgICAgdC5pZCAhPT0gZWRpdGVkSWQgJiYKICAgICAgICAgICAgICAgICAgdC50eXBlID09PSBwYXlsb2FkLnR5cGUgJiYKICAgICAgICAgICAgICAgICAgdC5jYXRlZ29yeSA9PT0gcHJldmlvdXNDYXRlZ29yeSAmJgogICAgICAgICAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModC5kZXNjcmlwdGlvbikpCiAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgICBpZiAoc2ltaWxhci5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICBjb25zdCBuZXdMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BheWxvYWQuY2F0ZWdvcnldIHx8IHBheWxvYWQuY2F0ZWdvcnk7CiAgICAgICAgICAgICAgICBjb25zdCBleGFtcGxlRGVzYyA9IHNpbWlsYXJbMF0uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICAgICAgICAgICAgYEFwcGxpcXVlciBhdXNzaSBsYSBjYXTDqWdvcmllICIke25ld0xhYmVsfSIgYXV4ICR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIGAgKwogICAgICAgICAgICAgICAgICBgc2ltaWxhaXJlKHMpIChleC4gIiR7ZXhhbXBsZURlc2N9IikgP2AKICAgICAgICAgICAgICAgICk7CiAgICAgICAgICAgICAgICBpZiAoY29uZmlybWVkKSB7CiAgICAgICAgICAgICAgICAgIGZvciAoY29uc3QgdCBvZiBzaW1pbGFyKSB7CiAgICAgICAgICAgICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7dC5pZH1gLCB7CiAgICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBjYXRlZ29yeTogcGF5bG9hZC5jYXRlZ29yeSB9KSwKICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICBzaG93VG9hc3QoYCR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIG1pc2Uocykgw6Agam91cmApOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoY3VycmVudFR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSBham91dMOpIiA6ICJEw6lwZW5zZSBham91dMOpZSIpOwogICAgICAgICAgaWYgKHBlbmRpbmdSZWNlaXB0RmlsZSkgewogICAgICAgICAgICAvLyBMYSBwaG90byBhIMOpdMOpIGNob2lzaWUgYXZhbnQgcXVlIGxhIHRyYW5zYWN0aW9uIG4nZXhpc3RlIDogb24KICAgICAgICAgICAgLy8gbCdlbnZvaWUgbWFpbnRlbmFudCBxdSdvbiBhIHVuIGlkLgogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgcGVuZGluZ1JlY2VpcHRGaWxlKTsKICAgICAgICAgICAgICBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtjcmVhdGVkLmlkfS9yZWNlaXB0YCwgewogICAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBjcsOpw6llLCBtYWlzIGwnZW52b2kgZGUgbGEgcGhvdG8gYSDDqWNob3XDqSIsIHRydWUpOwogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRyYW5zYWN0aW9uKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgdHJhbnNhY3Rpb24gPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIFRvdGF1eCBnbG9iYXV4IChTb2xkZS9Ew6lwZW5zZXMvUmV2ZW51cykgOiBjYWxjdWzDqXMgc3VyIFRPVVRFUyBsZXMKICAgIC8vIHRyYW5zYWN0aW9ucywgaW5kw6lwZW5kYW1tZW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSDigJQgdW4gZmlsdHJlCiAgICAvLyBzZXJ0IMOgIGNoZXJjaGVyIGRhbnMgbGEgbGlzdGUsIHBhcyDDoCByZWNhbGN1bGVyIGxlIHNvbGRlIHLDqWVsLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucykgewogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSB0b3RhbEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBlbHNlIHRvdGFsRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgYmFsYW5jZSA9IHRvdGFsSW5jb21lIC0gdG90YWxFeHBlbnNlczsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiYWxhbmNlKTsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC5jbGFzc05hbWUgPSAidmFsdWUgIiArIChiYWxhbmNlID49IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIHN1bW1hcnlFeHBlbnNlc0VsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsRXhwZW5zZXMpOwogICAgICBzdW1tYXJ5SW5jb21lRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgfQoKICAgIC8vIENvbnN0cnVjdGlvbiBkZSBsYSBsaXN0ZSBkZSBjYXJ0ZXMgYWZmaWNow6llIGRhbnMgbCdvbmdsZXQgSGlzdG9yaXF1ZSDigJQKICAgIC8vIHJlw6dvaXQgZMOpasOgIGxhIGxpc3RlIGZpbHRyw6llICh2b2lyIGFwcGx5SGlzdG9yeUZpbHRlcnMpLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25MaXN0KHRyYW5zYWN0aW9ucykgewogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGlmICh0cmFuc2FjdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGVtcHR5U3RhdGVFbC50ZXh0Q29udGVudCA9IGFsbFRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDAKICAgICAgICAgID8gIlJpZW4gcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgbGUgYm91dG9uICsgcG91ciBham91dGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUuIgogICAgICAgICAgOiAiQXVjdW4gcsOpc3VsdGF0IHBvdXIgY2VzIGZpbHRyZXMuIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAidHgtY2FyZCAiICsgdHgudHlwZTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInR4LW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gInR4LXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkYXRlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkYXRlU3Bhbi5jbGFzc05hbWUgPSAidHgtZGF0ZSI7CiAgICAgICAgZGF0ZVNwYW4udGV4dENvbnRlbnQgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh0eC5leHBlbnNlX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChiYWRnZSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGRhdGVTcGFuKTsKICAgICAgICBpZiAodHgucmVjdXJyaW5nX2V4cGVuc2VfaWQpIHsKICAgICAgICAgIGNvbnN0IHJlY0JhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgcmVjQmFkZ2UuY2xhc3NOYW1lID0gInR4LXJlY3VycmluZy1iYWRnZSI7CiAgICAgICAgICByZWNCYWRnZS50ZXh0Q29udGVudCA9ICLwn5SBIjsKICAgICAgICAgIHJlY0JhZGdlLnRpdGxlID0gIkNyw6nDqWUgYXV0b21hdGlxdWVtZW50IGRlcHVpcyB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChyZWNCYWRnZSk7CiAgICAgICAgfQogICAgICAgIGlmICh0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICAgIGNvbnN0IHJlY2VpcHRCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnR5cGUgPSAiYnV0dG9uIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjZWlwdC1iYWRnZSI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudGV4dENvbnRlbnQgPSAi8J+nviI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudGl0bGUgPSAiVm9pciBsYSBwaG90byBkdSByZcOndSI7CiAgICAgICAgICByZWNlaXB0QmFkZ2Uuc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlZvaXIgbGEgcGhvdG8gZHUgcmXDp3UiKTsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5SZWNlaXB0TGlnaHRib3godHguaWQpKTsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChyZWNlaXB0QmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gInR4LWRlc2NyaXB0aW9uIjsKICAgICAgICBkZXNjLnRleHRDb250ZW50ID0gdHguZGVzY3JpcHRpb24gfHwgIuKAlCI7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwoKICAgICAgICBjb25zdCBhbW91bnRFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudEVsLmNsYXNzTmFtZSA9ICJ0eC1hbW91bnQgIiArIHR4LnR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHgudHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0eC5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3Blbk1vZGFsKHR4KSk7CiAgICAgICAgY29uc3QgZHVwbGljYXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZHVwbGljYXRlQnRuLnRleHRDb250ZW50ID0gIvCfk4siOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiRHVwbGlxdWVyIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpKTsKICAgICAgICBjb25zdCBkZWxldGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkZWxldGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIGRhbmdlciI7CiAgICAgICAgZGVsZXRlQnRuLnRleHRDb250ZW50ID0gIvCfl5HvuI8iOwogICAgICAgIGRlbGV0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiU3VwcHJpbWVyIik7CiAgICAgICAgZGVsZXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZGVsZXRlVHJhbnNhY3Rpb24odHguaWQpKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGVkaXRCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZHVwbGljYXRlQnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSw6lzdW3DqSAiY2V0dGUgc2VtYWluZSIgKGluZMOpcGVuZGFudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzdGFydE9mV2Vla0lzbygpIHsKICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgZGF5ID0gbm93LmdldERheSgpOyAvLyAwID0gZGltYW5jaGUsIDEgPSBsdW5kaSwgLi4uCiAgICAgIGNvbnN0IGRpZmZUb01vbmRheSA9IGRheSA9PT0gMCA/IDYgOiBkYXkgLSAxOwogICAgICBjb25zdCBtb25kYXkgPSBuZXcgRGF0ZShub3cpOwogICAgICBtb25kYXkuc2V0RGF0ZShub3cuZ2V0RGF0ZSgpIC0gZGlmZlRvTW9uZGF5KTsKICAgICAgY29uc3QgdHogPSBtb25kYXkuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShtb25kYXkuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc3RhcnQgPSBzdGFydE9mV2Vla0lzbygpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJleHBlbnNlIiAmJiB0eC5leHBlbnNlX2RhdGUgPj0gc3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDw9IHRvZGF5KSB7CiAgICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIndlZWstc3VtbWFyeSIpLnRleHRDb250ZW50ID0KICAgICAgICBgQ2V0dGUgc2VtYWluZSAoZGVwdWlzIGx1bmRpKSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsKX0gZMOpcGVuc8Opc2A7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUmVjaGVyY2hlIGV0IGZpbHRyZXMgZGFucyBsJ2hpc3RvcmlxdWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCkgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5Iik7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgT2JqZWN0LmVudHJpZXMoYWxsQ2F0ZWdvcnlMYWJlbHMpKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBhcHBseUhpc3RvcnlGaWx0ZXJzKCkgewogICAgICBjb25zdCBzZWFyY2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLXNlYXJjaCIpLnZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCBjYXRlZ29yeSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZVN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLXN0YXJ0IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVFbmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtZW5kIikudmFsdWU7CgogICAgICBjb25zdCBmaWx0ZXJlZCA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoKHR4KSA9PiB7CiAgICAgICAgaWYgKGNhdGVnb3J5ICYmIHR4LmNhdGVnb3J5ICE9PSBjYXRlZ29yeSkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlU3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDwgZGF0ZVN0YXJ0KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVFbmQgJiYgdHguZXhwZW5zZV9kYXRlID4gZGF0ZUVuZCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChzZWFyY2gpIHsKICAgICAgICAgIGNvbnN0IGhheXN0YWNrID0gYCR7dHguZGVzY3JpcHRpb24gfHwgIiJ9ICR7YWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5fWAudG9Mb3dlckNhc2UoKTsKICAgICAgICAgIGlmICghaGF5c3RhY2suaW5jbHVkZXMoc2VhcmNoKSkgcmV0dXJuIGZhbHNlOwogICAgICAgIH0KICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgfSk7CiAgICAgIHJlbmRlclRyYW5zYWN0aW9uTGlzdChmaWx0ZXJlZCk7CiAgICB9CgogICAgWyJmaWx0ZXItc2VhcmNoIiwgImZpbHRlci1jYXRlZ29yeSIsICJmaWx0ZXItZGF0ZS1zdGFydCIsICJmaWx0ZXItZGF0ZS1lbmQiXS5mb3JFYWNoKChpZCkgPT4gewogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuYWRkRXZlbnRMaXN0ZW5lcigiaW5wdXQiLCBhcHBseUhpc3RvcnlGaWx0ZXJzKTsKICAgIH0pOwoKICAgIGxldCBhbGxUcmFuc2FjdGlvbnMgPSBbXTsKICAgIGxldCBjdXJyZW50VmlldyA9ICJoaXN0b3J5IjsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkVHJhbnNhY3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHRyYW5zYWN0aW9ucyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIpOwogICAgICAgIGFsbFRyYW5zYWN0aW9ucyA9IHRyYW5zYWN0aW9uczsKICAgICAgICByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKTsKICAgICAgICB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpOwogICAgICAgIGFwcGx5SGlzdG9yeUZpbHRlcnMoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5ncyh0cmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9uZ2xldHMgKEhpc3RvcmlxdWUgLyBUYWJsZWF1IGRlIGJvcmQpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzd2l0Y2hWaWV3KHZpZXcpIHsKICAgICAgY3VycmVudFZpZXcgPSB2aWV3OwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiaGlzdG9yeSIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXNhdmluZ3MiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1oaXN0b3J5Iikuc3R5bGUuZGlzcGxheSA9IHZpZXcgPT09ICJoaXN0b3J5IiA/ICJibG9jayIgOiAibm9uZSI7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXNhdmluZ3MiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gInNhdmluZ3MiKTsKICAgICAgaWYgKHZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgaWYgKHZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5ncyhhbGxUcmFuc2FjdGlvbnMpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiaGlzdG9yeSIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJkYXNoYm9hcmQiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygicmVjdXJyaW5nIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImV4cG9ydCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygic2F2aW5ncyIpKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBUYWJsZWF1IGRlIGJvcmQgKGdyYXBoaXF1ZXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtb250aEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJsb25nIiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgbW9udGhTaG9ydEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IENIQVJUX0NPTE9SUyA9IFsiIzNiODJmNiIsICIjMjJjNTVlIiwgIiNlZjQ0NDQiLCAiI2Y1OWUwYiIsICIjYTg1NWY3IiwgIiMxNGI4YTYiLCAiI2VjNDg5OSIsICIjNjQ3NDhiIl07CgogICAgbGV0IGNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGluY29tZUNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsKICAgIGxldCB5ZWFybHlDaGFydCA9IG51bGw7CgogICAgZnVuY3Rpb24gbW9udGhLZXlPZihleHBlbnNlRGF0ZSkgewogICAgICByZXR1cm4gZXhwZW5zZURhdGUuc2xpY2UoMCwgNyk7IC8vICJZWVlZLU1NIgogICAgfQoKICAgIC8vIFVuZSBjaGFyZ2UgcsOpY3VycmVudGUgY29tcHRlIHBvdXIgdW4gbW9pcyBkb25uw6kgc2kgY2UgbW9pcyBlc3QgZGFucyBzYQogICAgLy8gcMOpcmlvZGUgZCdhY3Rpdml0w6kgOiBwYXMgYXZhbnQgc2EgZGF0ZSBkZSBkw6lidXQgKHNpIHBvc8OpZSksIHBhcyBhcHLDqHMKICAgIC8vIGxlIG1vaXMgZGUgc2EgZGF0ZSBkZSBmaW4gKHNpIHBvc8OpZSkuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkgewogICAgICBpZiAoaXRlbS5zdGFydF9kYXRlICYmIG1vbnRoS2V5IDwgaXRlbS5zdGFydF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChpdGVtLmVuZF9kYXRlICYmIG1vbnRoS2V5ID4gaXRlbS5lbmRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICAvLyBKb3VyIGR1IG1vaXMganVzcXUnYXVxdWVsIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgZXN0IGNvbnNpZMOpcsOpZSBjb21tZQogICAgLy8gImTDqWrDoCBwcsOpbGV2w6llIiBwb3VyIGxlIG1vaXMgYG1vbnRoS2V5YCA6IHRvdXMgbGVzIGpvdXJzIHBvdXIgdW4gbW9pcwogICAgLy8gZMOpasOgIHBhc3PDqSwgYXVjdW4gcG91ciB1biBtb2lzIGZ1dHVyLCBldCBsZSBqb3VyIGR1IGpvdXIgcG91ciBsZSBtb2lzCiAgICAvLyBlbiBjb3Vycy4gUGVybWV0IGRlIGRpc3Rpbmd1ZXIgY2UgcXVpIGVzdCBkw6lqw6AgYXJyaXbDqSBkZSBjZSBxdWkgZXN0CiAgICAvLyBzZXVsZW1lbnQgcHLDqXZ1IChleCA6IHVuIGFib25uZW1lbnQgcHLDqWxldsOpIGxlIDI1LCBvbiBlc3QgbGUgMikuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpIHsKICAgICAgaWYgKG1vbnRoS2V5IDwgY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMzE7CiAgICAgIGlmIChtb250aEtleSA+IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDA7CiAgICAgIHJldHVybiB0b2RheURheTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDApIG1vbnRoU2V0LmFkZChtb250aEtleU9mKHRvZGF5SXNvKCkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9ICIiOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9ICJBdWN1bmUgZG9ubsOpZSI7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIHNlbGVjdC52YWx1ZSA9IG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBtb250aHNbMF07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiKTsKICAgICAgY29uc3QgdXBjb21pbmdOb3RlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiKTsKICAgICAgY29uc3QgdXBjb21pbmdUZXh0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLXRleHQiKTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVW4gc2V1bCBzb2xkZSBuZXQgIsOgIHZlbmlyIiAocmV2ZW51cyByw6ljdXJyZW50cyDDoCB2ZW5pciBtb2lucyBkw6lwZW5zZXMKICAgICAgLy8gcsOpY3VycmVudGVzIMOgIHZlbmlyKSwgcGx1dMO0dCBxdWUgZGV1eCBjaGlmZnJlcyBzw6lwYXLDqXMgOiBwbHVzIHNpbXBsZQogICAgICAvLyDDoCBsaXJlIGQndW4gY291cCBkJ8WTaWwuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lIHNvbnQgUEFTCiAgICAgIC8vIGFqb3V0w6llcyBpY2kgOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlIHZyYWllcyB0cmFuc2FjdGlvbnMKICAgICAgLy8gKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcyBkYW5zIGB0b3RhbHNgCiAgICAgIC8vIGNpLWRlc3N1cyDigJQgbGVzIGFqb3V0ZXIgw6Agbm91dmVhdSBsZXMgY29tcHRlcmFpdCBlbiBkb3VibGUuCiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSBjdXRvZmYpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLnR5cGUgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgY29uc3QgbmV0VXBjb21pbmcgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgaWYgKG5ldFVwY29taW5nICE9PSAwKSB7CiAgICAgICAgY29uc3Qgc2lnbiA9IG5ldFVwY29taW5nID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICAgIHVwY29taW5nVGV4dEVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0VXBjb21pbmcpKX0gw6AgdmVuaXJgOwogICAgICAgIHVwY29taW5nTm90ZUVsLnRpdGxlID0gIlLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzL3Jlw6d1ZXMgY2UgbW9pcy1jaSAocmV2ZW51cyBtb2lucyBkw6lwZW5zZXMpIjsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QudG9nZ2xlKCJwb3NpdGl2ZSIsIG5ldFVwY29taW5nID4gMCk7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIGlmIChjYXRlZ29yeUNoYXJ0KSB7IGNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICAvLyBNw6ptZSBwcmluY2lwZSBxdWUgcmVuZGVyQ2F0ZWdvcnlDaGFydCwgY8O0dMOpIHJldmVudXMg4oCUIHBhcyBkZSBub3RlICLDoAogICAgLy8gdmVuaXIiIGljaSwgZWxsZSByZXN0ZSB1bmlxdWVtZW50IHN1ciBsZSBjYW1lbWJlcnQgZGVzIGTDqXBlbnNlcyBwb3VyCiAgICAvLyBuZSBwYXMgYWZmaWNoZXIgbGUgbcOqbWUgY2hpZmZyZSBuZXQgw6AgZGV1eCBlbmRyb2l0cy4KICAgIGZ1bmN0aW9uIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtaW5jb21lLWNhdGVnb3JpZXMtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiaW5jb21lIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBpZiAoaW5jb21lQ2F0ZWdvcnlDaGFydCkgeyBpbmNvbWVDYXRlZ29yeUNoYXJ0LmRlc3Ryb3koKTsgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiZG91Z2hudXQiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBkYXRhLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGxhYmVscy5tYXAoKF8sIGkpID0+IENIQVJUX0NPTE9SU1tpICUgQ0hBUlRfQ09MT1JTLmxlbmd0aF0pLAogICAgICAgICAgICBib3JkZXJDb2xvcjogIiMxYTFkMjQiLAogICAgICAgICAgICBib3JkZXJXaWR0aDogMiwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgcG9zaXRpb246ICJib3R0b20iLCBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiwgYm94V2lkdGg6IDEyLCBwYWRkaW5nOiAxMiwgZm9udDogeyBzaXplOiAxMSB9IH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkKX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1ldm9sdXRpb24iKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5Iik7CgogICAgICBjb25zdCBtb250aGx5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3Qga2V5ID0gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpOwogICAgICAgIGlmICghbW9udGhseVtrZXldKSBtb250aGx5W2tleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICAgIG1vbnRobHlba2V5XVt0eC50eXBlXSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBUb3Vqb3VycyBpbmNsdXJlIGxlIG1vaXMgZW4gY291cnMgKG3Dqm1lIHNhbnMgdHJhbnNhY3Rpb24pIHMnaWwgZXhpc3RlCiAgICAgIC8vIGRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgcG91ciBxdSdpbCBhcHBhcmFpc3NlIHNhbnMgYXR0ZW5kcmUgbGEKICAgICAgLy8gcHJlbWnDqHJlIHRyYW5zYWN0aW9uIGR1IG1vaXMuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lCiAgICAgIC8vIHNvbnQgcGx1cyBham91dMOpZXMgaWNpIMOgIGxhIG1haW4gOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlCiAgICAgIC8vIHZyYWllcyB0cmFuc2FjdGlvbnMgKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcwogICAgICAvLyBkYW5zIGBtb250aGx5YCB2aWEgbGEgYm91Y2xlIHN1ciBgdHJhbnNhY3Rpb25zYCBjaS1kZXNzdXMg4oCUIGNlIHF1aQogICAgICAvLyBuJ2VzdCBwYXMgZW5jb3JlIGFycml2w6kgZXN0IHLDqXN1bcOpIGFpbGxldXJzIChzb2xkZSBuZXQgIsOgIHZlbmlyIikuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCAmJiAhbW9udGhseVtjdXJyZW50TW9udGhLZXldKSB7CiAgICAgICAgbW9udGhseVtjdXJyZW50TW9udGhLZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgfQogICAgICBjb25zdCBtb250aHMgPSBPYmplY3Qua2V5cyhtb250aGx5KS5zb3J0KCk7CgogICAgICBpZiAoZXZvbHV0aW9uQ2hhcnQpIHsgZXZvbHV0aW9uQ2hhcnQuZGVzdHJveSgpOyBldm9sdXRpb25DaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjb25zdCBsYWJlbHMgPSBtb250aHMubWFwKChrZXkpID0+IHsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICByZXR1cm4gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgfSk7CgogICAgICBjb25zdCBkYXRhc2V0cyA9IFsKICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5leHBlbnNlKSwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICB7IGxhYmVsOiAiUmV2ZW51cyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uaW5jb21lKSwgYmFja2dyb3VuZENvbG9yOiAiIzIyYzU1ZSIgfSwKICAgICAgXTsKCiAgICAgIGV2b2x1dGlvbkNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJiYXIiLAogICAgICAgIGRhdGE6IHsgbGFiZWxzLCBkYXRhc2V0cyB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9LCBiZWdpbkF0WmVybzogdHJ1ZSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5kYXRhc2V0LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQueSl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbXBhcmVyIGRldXggbW9pcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHNlbGVjdEEgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIik7CiAgICAgIGNvbnN0IHNlbGVjdEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIik7CgogICAgICBmb3IgKGNvbnN0IHNlbGVjdCBvZiBbc2VsZWN0QSwgc2VsZWN0Ql0pIHsKICAgICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBpZiAobW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpKSBzZWxlY3QudmFsdWUgPSBwcmV2aW91c1ZhbHVlOwogICAgICB9CiAgICAgIC8vIFBhciBkw6lmYXV0IDogbW9pcyBlbiBjb3VycyB2cyBtb2lzIHByw6ljw6lkZW50LCBzaSBsZXMgZGV1eCBleGlzdGVudC4KICAgICAgaWYgKCFzZWxlY3RBLnZhbHVlICYmIG1vbnRocy5sZW5ndGggPiAwKSBzZWxlY3RBLnZhbHVlID0gbW9udGhzWzBdOwogICAgICBpZiAoIXNlbGVjdEIudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDEpIHNlbGVjdEIudmFsdWUgPSBtb250aHNbMV07CiAgICB9CgogICAgZnVuY3Rpb24gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIG1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgcmV0dXJuIHsgdG90YWxzLCB0b3RhbCB9OwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLWVtcHR5Iik7CiAgICAgIGNvbnN0IG1vbnRoQSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS52YWx1ZTsKICAgICAgY29uc3QgbW9udGhCID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLnZhbHVlOwoKICAgICAgaWYgKCFtb250aEEgfHwgIW1vbnRoQikgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgY29uc3QgeyB0b3RhbHM6IHRvdGFsc0EsIHRvdGFsOiBncmFuZEEgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHMoYWxsVHJhbnNhY3Rpb25zLCBtb250aEEpOwogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQiwgdG90YWw6IGdyYW5kQiB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQik7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBbLi4ubmV3IFNldChbLi4uT2JqZWN0LmtleXModG90YWxzQSksIC4uLk9iamVjdC5rZXlzKHRvdGFsc0IpXSldLnNvcnQoCiAgICAgICAgKGEsIGIpID0+ICh0b3RhbHNCW2JdIHx8IDApIC0gKHRvdGFsc0FbYV0gfHwgMCkKICAgICAgKTsKCiAgICAgIGNvbnN0IFt5YSwgbWFdID0gbW9udGhBLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IFt5YiwgbWJdID0gbW9udGhCLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGxhYmVsQSA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHlhLCBtYSAtIDEsIDEpKTsKICAgICAgY29uc3QgbGFiZWxCID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWIsIG1iIC0gMSwgMSkpOwoKICAgICAgLy8gRGlmZiA9IG1vbnRhbnQgZHUgbW9pcyBCIG1vaW5zIGNlbHVpIGR1IG1vaXMgQS4gUG91ciBkZXMgZMOpcGVuc2VzLAogICAgICAvLyBkw6lwZW5zZXIgUExVUyAoZGlmZiBwb3NpdGlmKSBlc3QgbGEgbWF1dmFpc2Ugbm91dmVsbGUg4oaSIHJvdWdlIDsgZW4KICAgICAgLy8gZMOpcGVuc2VyIE1PSU5TIChkaWZmIG7DqWdhdGlmKSDihpIgdmVydC4KICAgICAgZnVuY3Rpb24gZGlmZkNlbGwoYSwgYikgewogICAgICAgIGNvbnN0IGRpZmYgPSBiIC0gYTsKICAgICAgICBpZiAoTWF0aC5hYnMoZGlmZikgPCAwLjAxKSByZXR1cm4gYDx0ZD7igJQ8L3RkPmA7CiAgICAgICAgY29uc3QgY2xzID0gZGlmZiA+IDAgPyAiZGlmZi1uZWdhdGl2ZSIgOiAiZGlmZi1wb3NpdGl2ZSI7CiAgICAgICAgcmV0dXJuIGA8dGQgY2xhc3M9IiR7Y2xzfSI+JHtkaWZmID4gMCA/ICIrIiA6ICIifSR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGRpZmYpfTwvdGQ+YDsKICAgICAgfQoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD4ke2xhYmVsQX08L3RoPjx0aD4ke2xhYmVsQn08L3RoPjx0aD5EaWZmw6lyZW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYSA9IHRvdGFsc0FbY2F0XSB8fCAwOwogICAgICAgIGNvbnN0IGIgPSB0b3RhbHNCW2NhdF0gfHwgMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYil9PC90ZD4ke2RpZmZDZWxsKGEsIGIpfTwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8dHIgY2xhc3M9InRvdGFsLXJvdyI+PHRkPlRvdGFsIGTDqXBlbnNlczwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGdyYW5kQSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRCKX08L3RkPiR7ZGlmZkNlbGwoZ3JhbmRBLCBncmFuZEIpfTwvdHI+YDsKICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgcmVuZGVyTW9udGhDb21wYXJpc29uKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENhbGN1bGUsIHBvdXIgY2hhcXVlIGNhdMOpZ29yaWUgZGUgZMOpcGVuc2UsIGxhIG1veWVubmUgbWVuc3VlbGxlLCBsZQogICAgLy8gbW9udGFudCBkdSBtb2lzIGVuIGNvdXJzLCBldCBsYSB0ZW5kYW5jZSAoZGlyZWN0aW9uICsgcmF0aW8gdnMKICAgIC8vIG1veWVubmUpLiBQYXJ0YWfDqSBlbnRyZSBsZSB0YWJsZWF1ICJNb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllIgogICAgLy8gZXQgbGVzIGNvbnNlaWxzIGQnw6lwYXJnbmUsIHBvdXIgbmUgcGFzIGR1cGxpcXVlciBjZXR0ZSBsb2dpcXVlLgogICAgZnVuY3Rpb24gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aEtleXMgPSBbLi4ubmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSldLnNvcnQoKTsKICAgICAgaWYgKG1vbnRoS2V5cy5sZW5ndGggPT09IDApIHJldHVybiBbXTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlzW21vbnRoS2V5cy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgbmJNb250aHMgPSBtb250aEtleXMubGVuZ3RoOwoKICAgICAgLy8gdG90YWwgcGFyIGNhdMOpZ29yaWUsIGV0IHBhciBjYXTDqWdvcmllK21vaXMgKHBvdXIgaXNvbGVyIGxlIG1vaXMgZW4gY291cnMpCiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSA9PT0gY3VycmVudE1vbnRoS2V5KSB7CiAgICAgICAgICBjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9IChjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgcmV0dXJuIGNhdGVnb3JpZXMubWFwKChjYXQpID0+IHsKICAgICAgICBjb25zdCBhdmVyYWdlID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdIC8gbmJNb250aHM7CiAgICAgICAgY29uc3QgY3VycmVudCA9IGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbY2F0XSB8fCAwOwogICAgICAgIGxldCBkaXJlY3Rpb24gPSAic3RhYmxlIjsKICAgICAgICBsZXQgcmF0aW8gPSAwOwogICAgICAgIGlmIChhdmVyYWdlID4gMCkgewogICAgICAgICAgcmF0aW8gPSAoY3VycmVudCAtIGF2ZXJhZ2UpIC8gYXZlcmFnZTsKICAgICAgICAgIGlmIChyYXRpbyA+IDAuMTUpIGRpcmVjdGlvbiA9ICJ1cCI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA8IC0wLjE1KSBkaXJlY3Rpb24gPSAiZG93biI7CiAgICAgICAgfSBlbHNlIGlmIChjdXJyZW50ID4gMCkgewogICAgICAgICAgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHsgY2F0ZWdvcnk6IGNhdCwgYXZlcmFnZSwgY3VycmVudCwgcmF0aW8sIGRpcmVjdGlvbiB9OwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHJlbmQtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBpZiAodHJlbmRzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD5Nb3llbm5lL21vaXM8L3RoPjx0aD5DZSBtb2lzLWNpPC90aD48dGg+VGVuZGFuY2U8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCB0IG9mIHRyZW5kcykgewogICAgICAgIGxldCB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWZsYXQiPuKGkiBzdGFibGU8L3NwYW4+YDsKICAgICAgICBpZiAodC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRyZW5kSHRtbCA9IHQuYXZlcmFnZSA+IDAKICAgICAgICAgICAgPyBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgKyR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lPC9zcGFuPmAKICAgICAgICAgICAgOiBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgbm91dmVhdTwvc3Bhbj5gOwogICAgICAgIH0gZWxzZSBpZiAodC5kaXJlY3Rpb24gPT09ICJkb3duIikgewogICAgICAgICAgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC1kb3duIj7ihpMgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YDsKICAgICAgICB9CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2VzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodC5hdmVyYWdlKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmN1cnJlbnQpfTwvdGQ+PHRkPiR7dHJlbmRIdG1sfTwvdGQ+PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB3cmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQmlsYW4gYW5udWVsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBNT05USF9TSE9SVF9MQUJFTFMgPSBbCiAgICAgICJKYW4iLCAiRsOpdiIsICJNYXIiLCAiQXZyIiwgIk1haSIsICJKdWluIiwgIkp1aWwiLCAiQW/Du3QiLCAiU2VwIiwgIk9jdCIsICJOb3YiLCAiRMOpYyIsCiAgICBdOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlWWVhclNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFycyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiB0eC5leHBlbnNlX2RhdGUuc2xpY2UoMCwgNCkpKV0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3QgY3VycmVudFllYXIgPSBTdHJpbmcobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTsKICAgICAgaWYgKCF5ZWFycy5pbmNsdWRlcyhjdXJyZW50WWVhcikpIHllYXJzLnVuc2hpZnQoY3VycmVudFllYXIpOwoKICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgc2VsZWN0LmlubmVySFRNTCA9IHllYXJzLm1hcCgoeSkgPT4gYDxvcHRpb24gdmFsdWU9IiR7eX0iPiR7eX08L29wdGlvbj5gKS5qb2luKCIiKTsKICAgICAgc2VsZWN0LnZhbHVlID0geWVhcnMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkgPyBwcmV2aW91c1ZhbHVlIDogY3VycmVudFllYXI7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyWWVhcmx5T3ZlcnZpZXcodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKTsKICAgICAgY29uc3QgeWVhciA9IHNlbGVjdC52YWx1ZTsKICAgICAgaWYgKCF5ZWFyKSByZXR1cm47CgogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQteWVhcmx5Iik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LWVtcHR5Iik7CiAgICAgIGNvbnN0IHRhYmxlV3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktY2F0ZWdvcnktdGFibGUtd3JhcCIpOwoKICAgICAgY29uc3QgeWVhclRyYW5zYWN0aW9ucyA9IHRyYW5zYWN0aW9ucy5maWx0ZXIoKHR4KSA9PiB0eC5leHBlbnNlX2RhdGUuc2xpY2UoMCwgNCkgPT09IHllYXIpOwoKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBjb25zdCBleHBlbnNlQnlNb250aCA9IEFycmF5KDEyKS5maWxsKDApOwogICAgICBjb25zdCBpbmNvbWVCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB5ZWFyVHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgbW9udGhJbmRleCA9IE51bWJlcih0eC5leHBlbnNlX2RhdGUuc2xpY2UoNSwgNykpIC0gMTsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHsKICAgICAgICAgIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgaW5jb21lQnlNb250aFttb250aEluZGV4XSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICAgIGV4cGVuc2VCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwoKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS10b3RhbC1leHBlbnNlcyIpLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsRXhwZW5zZXMpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWluY29tZSIpLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgICAgY29uc3QgbmV0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LW5ldCIpOwogICAgICBuZXRFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChuZXQpOwogICAgICBuZXRFbC5jbGFzc05hbWUgPSAieWVhcmx5LXN0YXQtdmFsdWUgIiArIChuZXQgPj0gMCA/ICJpbmNvbWUiIDogImV4cGVuc2UiKTsKCiAgICAgIGlmICh5ZWFybHlDaGFydCkgeyB5ZWFybHlDaGFydC5kZXN0cm95KCk7IHllYXJseUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKHllYXJUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICB0YWJsZVdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgeWVhcmx5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzOiBNT05USF9TSE9SVF9MQUJFTFMsCiAgICAgICAgICBkYXRhc2V0czogWwogICAgICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogZXhwZW5zZUJ5TW9udGgsIGJhY2tncm91bmRDb2xvcjogIiNlZjQ0NDQiIH0sCiAgICAgICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogaW5jb21lQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiIzIyYzU1ZSIgfSwKICAgICAgICAgIF0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeDogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICAgIHk6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSB9LAogICAgICAgIH0sCiAgICAgIH0pOwoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD5Ub3RhbDwvdGg+PHRoPiUgZGUgbCdhbm7DqWU8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCBjYXQgb2YgY2F0ZWdvcmllcykgewogICAgICAgIGNvbnN0IGFtb3VudCA9IHRvdGFsc0J5Q2F0ZWdvcnlbY2F0XTsKICAgICAgICBjb25zdCBwY3QgPSB0b3RhbEV4cGVuc2VzID4gMCA/IE1hdGgucm91bmQoKGFtb3VudCAvIHRvdGFsRXhwZW5zZXMpICogMTAwKSA6IDA7CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2VzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGFtb3VudCl9PC90ZD48dGQ+JHtwY3R9JTwvdGQ+PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB0YWJsZVdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gcmVuZGVyWWVhcmx5T3ZlcnZpZXcoYWxsVHJhbnNhY3Rpb25zKSk7CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJCdWRnZXRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHBvcHVsYXRlQ29tcGFyZU1vbnRoU2VsZWN0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJNb250aENvbXBhcmlzb24oKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlclllYXJseU92ZXJ2aWV3KHRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImFuc3dlciIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSAiIjsKICAgICAgfSBlbHNlIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VBbnN3ZXJCYW5uZXIodGV4dCkgewogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImFuc3dlciIpOwogICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgIH0KCiAgICAvLyBQcm9ub25jZSBsYSByw6lwb25zZSDDoCB1bmUgcXVlc3Rpb24gdm9jYWxlICgiQXNzaXN0YW50IHZvY2FsIHF1ZXN0aW9uIikuCiAgICAvLyBQdXIgYm9udXMgOiBzaSBsYSBzeW50aMOoc2Ugdm9jYWxlIG4nZXN0IHBhcyBkaXNwbyBvdSDDqWNob3VlLCBsYSByw6lwb25zZQogICAgLy8gcmVzdGUgYWZmaWNow6llIGRhbnMgbGUgYmFuZGVhdSwgZG9uYyBvbiBhdmFsZSBsJ2VycmV1ciBzYW5zIGJsb3F1ZXIuCiAgICBmdW5jdGlvbiBzcGVha1ZvaWNlQW5zd2VyKHRleHQpIHsKICAgICAgaWYgKCEoInNwZWVjaFN5bnRoZXNpcyIgaW4gd2luZG93KSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuY2FuY2VsKCk7CiAgICAgICAgY29uc3QgdXR0ZXJhbmNlID0gbmV3IFNwZWVjaFN5bnRoZXNpc1V0dGVyYW5jZSh0ZXh0KTsKICAgICAgICB1dHRlcmFuY2UubGFuZyA9ICJmci1GUiI7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5zcGVhayh1dHRlcmFuY2UpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQuCiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBTcGVlY2hSZWNvZ25pdGlvbkN0b3IgPSB3aW5kb3cuU3BlZWNoUmVjb2duaXRpb24gfHwgd2luZG93LndlYmtpdFNwZWVjaFJlY29nbml0aW9uOwoKICAgIGlmICghU3BlZWNoUmVjb2duaXRpb25DdG9yKSB7CiAgICAgIG1pY0J0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIG1pY0J0bi50aXRsZSA9ICJEaWN0w6llIHZvY2FsZSBub24gZGlzcG9uaWJsZSBzdXIgY2UgbmF2aWdhdGV1ciAodXRpbGlzZSBDaHJvbWUgb3UgRWRnZSkiOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgcmVjb2duaXRpb24gPSBuZXcgU3BlZWNoUmVjb2duaXRpb25DdG9yKCk7CiAgICAgIHJlY29nbml0aW9uLmxhbmcgPSAiZnItRlIiOwogICAgICByZWNvZ25pdGlvbi5jb250aW51b3VzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLmludGVyaW1SZXN1bHRzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLm1heEFsdGVybmF0aXZlcyA9IDE7CgogICAgICBsZXQgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInN0YXJ0IiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gdHJ1ZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgibGlzdGVuaW5nIik7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIkplIHQnw6ljb3V0ZeKApiIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVuZCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlcnJvciIsIChldmVudCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgaWYgKGV2ZW50LmVycm9yID09PSAibm8tc3BlZWNoIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIlJpZW4gZW50ZW5kdSwgcsOpZXNzYWllLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMjAwMCk7CiAgICAgICAgfSBlbHNlIGlmIChldmVudC5lcnJvciA9PT0gIm5vdC1hbGxvd2VkIiB8fCBldmVudC5lcnJvciA9PT0gInNlcnZpY2Utbm90LWFsbG93ZWQiKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiTWljcm8gcmVmdXPDqSDigJQgYXV0b3Jpc2UgbCdhY2PDqHMgYXUgbWljcm8gZGFucyB0b24gbmF2aWdhdGV1ci4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDQwMDApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcihudWxsKTsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIG1pY3JvIDogIiArIGV2ZW50LmVycm9yLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigicmVzdWx0IiwgYXN5bmMgKGV2ZW50KSA9PiB7CiAgICAgICAgY29uc3QgdHJhbnNjcmlwdCA9IGV2ZW50LnJlc3VsdHNbMF1bMF0udHJhbnNjcmlwdDsKICAgICAgICBzZXRWb2ljZUJhbm5lcihgIiR7dHJhbnNjcmlwdH0iYCk7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoInByb2Nlc3NpbmciKTsKICAgICAgICBsZXQgYmFubmVyRGVsYXkgPSAxNTAwOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgIH0pOwogICAgICAgICAgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJxdWVzdGlvbiIpIHsKICAgICAgICAgICAgLy8gUXVlc3Rpb24gc3VyIGxlcyBmaW5hbmNlcyAoImNvbWJpZW4gaidhaSBkw6lwZW5zw6kgZW4KICAgICAgICAgICAgLy8gcmVzdGF1cmFudCBjZSBtb2lzLWNpID8iKSA6IHJpZW4gbidlc3QgZW5yZWdpc3Ryw6ksIG9uIGFmZmljaGUKICAgICAgICAgICAgLy8gKGV0IG9uIHByb25vbmNlKSBqdXN0ZSBsYSByw6lwb25zZSBjYWxjdWzDqWUgY8O0dMOpIHNlcnZldXIuCiAgICAgICAgICAgIHNldFZvaWNlQW5zd2VyQmFubmVyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgICBzcGVha1ZvaWNlQW5zd2VyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgICBiYW5uZXJEZWxheSA9IDYwMDA7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBhd2FpdCBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCk7CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfSBmaW5hbGx5IHsKICAgICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCBiYW5uZXJEZWxheSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTdWdnZXN0aW9ucyBkZSBjYXTDqWdvcmllIOKAlCB1bmlxdWVtZW50IGFwcsOocyB1bmUgc2Fpc2llIHBhciBkaWN0w6llCiAgICAvLyB2b2NhbGUgKHVuZSBmYXV0ZSBkZSBmcmFwcGUgZW4gc2Fpc2llIG1hbnVlbGxlLCBjJ2VzdCB1bmUgZXJyZXVyIGRlCiAgICAvLyBsJ3V0aWxpc2F0ZXVyLCBwYXMgbGEgcGVpbmUgZGUgbGUgcmVsYW5jZXIgZGVzc3VzKS4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEID0gMzsKCiAgICAvLyBNb3RzIGRlIGxpYWlzb24gZnJhbsOnYWlzIMOgIGlnbm9yZXIgOiAiY2FzaW5vIiwgImF1IGNhc2lubyIgZXQgInBlcnRlIGF1CiAgICAvLyBjYXNpbm8iIGRvaXZlbnQgw6p0cmUgcmVjb25udXMgY29tbWUgbGEgbcOqbWUgaWTDqWUgbWFsZ3LDqSBsZXMgbW90cwogICAgLy8gZGlmZsOpcmVudHMgYXV0b3VyLCBkb25jIG9uIGNvbXBhcmUgZGVzIG1vdHMtY2zDqXMgc2lnbmlmaWNhdGlmcyBwbHV0w7R0CiAgICAvLyBxdWUgbGEgZGVzY3JpcHRpb24gY29tcGzDqHRlIHRlbGxlIHF1ZWxsZS4KICAgIGNvbnN0IERFU0NSSVBUSU9OX1NUT1BXT1JEUyA9IG5ldyBTZXQoWwogICAgICAiYSIsICJhdSIsICJhdXgiLCAiZGUiLCAiZHUiLCAiZGVzIiwgImQiLCAibGUiLCAibGEiLCAibGVzIiwgImwiLAogICAgICAidW4iLCAidW5lIiwgImNlIiwgImNldCIsICJjZXR0ZSIsICJjZXMiLCAibW9uIiwgIm1hIiwgIm1lcyIsCiAgICAgICJ0b24iLCAidGEiLCAidGVzIiwgInNvbiIsICJzYSIsICJzZXMiLCAibm90cmUiLCAibm9zIiwgInZvdHJlIiwKICAgICAgInZvcyIsICJsZXVyIiwgImxldXJzIiwgImNoZXoiLCAic3VyIiwgImRhbnMiLCAicG91ciIsICJhdmVjIiwKICAgICAgImV0IiwgIm91IiwgImVuIiwgInBhciIsCiAgICBdKTsKCiAgICAvLyBFeHRyYWl0IGxlcyBtb3RzLWNsw6lzIHNpZ25pZmljYXRpZnMgZCd1bmUgZGVzY3JpcHRpb24gKGFjY2VudHMgZXQKICAgIC8vIGNhc3NlIGlnbm9yw6lzLCBtb3RzIGRlIGxpYWlzb24gZXQgbW90cyB0cm9wIGNvdXJ0cyDDqWNhcnTDqXMpLgogICAgZnVuY3Rpb24gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMoZGVzYykgewogICAgICBjb25zdCBub3JtYWxpemVkID0gKGRlc2MgfHwgIiIpCiAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikKICAgICAgICAucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gcmV0aXJlIGxlcyBhY2NlbnRzICjDqSAtPiBlLCBldGMuKQogICAgICAgIC50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCB0b2tlbnMgPSBub3JtYWxpemVkLnNwbGl0KC9bXmEtejAtOV0rLykuZmlsdGVyKEJvb2xlYW4pOwogICAgICByZXR1cm4gbmV3IFNldCgKICAgICAgICB0b2tlbnMuZmlsdGVyKCh0KSA9PiB0Lmxlbmd0aCA+PSAzICYmICFERVNDUklQVElPTl9TVE9QV09SRFMuaGFzKHQpKQogICAgICApOwogICAgfQoKICAgIGZ1bmN0aW9uIGtleXdvcmRzSW50ZXJzZWN0KGEsIGIpIHsKICAgICAgZm9yIChjb25zdCB0b2tlbiBvZiBhKSB7CiAgICAgICAgaWYgKGIuaGFzKHRva2VuKSkgcmV0dXJuIHRydWU7CiAgICAgIH0KICAgICAgcmV0dXJuIGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGRpc21pc3NTdWdnZXN0aW9uKGtleSkgewogICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5hZGQoa2V5KTsgLy8gaW1tw6lkaWF0IGPDtHTDqSBVSSwgcGFzIGJlc29pbiBkJ2F0dGVuZHJlIGxlIHNlcnZldXIKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsga2V5IH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIGxhIHN1Z2dlc3Rpb24gcsOpYXBwYXJhw650IHVuZSBmb2lzIHN1ciB1bgogICAgICAgIC8vIGF1dHJlIGFwcGFyZWlsIHNpIGxhIHNhdXZlZ2FyZGUgc2VydmV1ciBhIMOpY2hvdcOpLgogICAgICB9CiAgICB9CgogICAgLy8gUmVnYXJkZSBzaSBsYSBkZXNjcmlwdGlvbiBkZSBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZQogICAgLy8gKG91IGNvcnJpZ8OpZSkgw6AgbGEgdm9peCByZXZpZW50IHNvdXZlbnQsIGV0IHNpIG91aSA6CiAgICAvLyAtIHNvaXQgZWxsZSBhIHRvdWpvdXJzIMOpdMOpIHJhbmfDqWUgZGFucyAiQXV0cmUiIOKGkiBvbiBwcm9wb3NlIGRlIGNyw6llcgogICAgLy8gICB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgZGUgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgOwogICAgLy8gLSBzb2l0IGVsbGUgYSBjZXR0ZSBmb2lzIHVuZSBjYXTDqWdvcmllIGRpZmbDqXJlbnRlIGRlIGQnaGFiaXR1ZGUg4oaSIG9uCiAgICAvLyAgIGRlbWFuZGUgc2kgY2Ugbidlc3QgcGFzIHVuZSBlcnJldXIgOwogICAgLy8gLSBzb2l0IGxhIHRyYW5zYWN0aW9uIHF1aSB2aWVudCBkJ8OqdHJlIGFqb3V0w6llIGVzdCBkw6lqw6AgYmllbiBjbGFzc8OpZSwKICAgIC8vICAgbWFpcyBkJ2FuY2llbm5lcyB0cmFuc2FjdGlvbnMgc2ltaWxhaXJlcyB0cmHDrm5lbnQgZGFucyB1bmUgYXV0cmUKICAgIC8vICAgY2F0w6lnb3JpZSAoZXguICJwZXJ0ZSBhdSBjYXNpbm8iIGNsYXNzw6llIGVuICJMb2lzaXJzIiBhdmFudCBxdWUKICAgIC8vICAgImNhc2lubyIgZXhpc3RlIGNvbW1lIGNhdMOpZ29yaWUpIOKGkiBvbiBwcm9wb3NlIGRlIGxlcyBhbGlnbmVyLgogICAgZnVuY3Rpb24gY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24oZGVzY3JpcHRpb24sIHR5cGUpIHsKICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhkZXNjcmlwdGlvbik7CiAgICAgIGlmIChrZXl3b3Jkcy5zaXplID09PSAwKSByZXR1cm47CgogICAgICBjb25zdCBzYW1lRGVzY3JpcHRpb24gPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICh0eCkgPT4KICAgICAgICAgIHR4LnR5cGUgPT09IHR5cGUgJiYKICAgICAgICAgIGtleXdvcmRzSW50ZXJzZWN0KGtleXdvcmRzLCBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3Jkcyh0eC5kZXNjcmlwdGlvbikpCiAgICAgICk7CiAgICAgIGlmIChzYW1lRGVzY3JpcHRpb24ubGVuZ3RoIDwgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQpIHJldHVybjsKCiAgICAgIGNvbnN0IGNvdW50cyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHNhbWVEZXNjcmlwdGlvbikgY291bnRzW3R4LmNhdGVnb3J5XSA9IChjb3VudHNbdHguY2F0ZWdvcnldIHx8IDApICsgMTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKGNvdW50cyk7CiAgICAgIGNvbnN0IGRvbWluYW50ID0gY2F0ZWdvcmllcy5yZWR1Y2UoKGEsIGIpID0+IChjb3VudHNbYV0gPj0gY291bnRzW2JdID8gYSA6IGIpKTsKICAgICAgY29uc3QgbGF0ZXN0ID0gc2FtZURlc2NyaXB0aW9uWzBdOyAvLyBhbGxUcmFuc2FjdGlvbnMgZXN0IHRyacOpIHBhciBkYXRlIGTDqWNyb2lzc2FudGUKCiAgICAgIC8vIENsw6kgc3RhYmxlIGJhc8OpZSBzdXIgbGVzIG1vdHMtY2zDqXMgKHRyacOpcykgcGx1dMO0dCBxdWUgbGEgZGVzY3JpcHRpb24KICAgICAgLy8gZXhhY3RlLCBwb3VyIHF1ZSBsZSAiSWdub3JlciIgcmVzdGUgdmFsYWJsZSBtw6ptZSBzaSBsYSBmb3JtdWxhdGlvbgogICAgICAvLyB2YXJpZSB1biBwZXUgZCd1bmUgZm9pcyDDoCBsJ2F1dHJlLgogICAgICBjb25zdCBzaWduYXR1cmUgPSBbLi4ua2V5d29yZHNdLnNvcnQoKS5qb2luKCIrIik7CgogICAgICBsZXQgc3VnZ2VzdGlvbiA9IG51bGw7CiAgICAgIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ICE9PSBkb21pbmFudCkgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBtaXNtYXRjaDoke3R5cGV9OiR7c2lnbmF0dXJlfToke2xhdGVzdC5jYXRlZ29yeX1gLAogICAgICAgICAga2luZDogIm1pc21hdGNoIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICBjdXJyZW50OiBsYXRlc3QuY2F0ZWdvcnksCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ID09PSBsYXRlc3QuY2F0ZWdvcnkpLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID09PSAxICYmIGRvbWluYW50ID09PSAiYXV0cmUiKSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYGdlbmVyaWM6JHt0eXBlfToke3NpZ25hdHVyZX1gLAogICAgICAgICAga2luZDogImdlbmVyaWMiLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID4gMSAmJiBsYXRlc3QuY2F0ZWdvcnkgPT09IGRvbWluYW50KSB7CiAgICAgICAgLy8gTGEgdHJhbnNhY3Rpb24gbGEgcGx1cyByw6ljZW50ZSBlc3QgZMOpasOgIGJpZW4gY2xhc3PDqWUsIG1haXMKICAgICAgICAvLyBkJ2F1dHJlcyB0cmFuc2FjdGlvbnMgc2ltaWxhaXJlcyBzb250IHJlc3TDqWVzIGRhbnMgdW5lIGNhdMOpZ29yaWUKICAgICAgICAvLyBtaW5vcml0YWlyZSAodHlwaXF1ZW1lbnQgcGx1cyBhbmNpZW5uZXMsIGNsYXNzw6llcyBhdmFudCBxdWUgbGEKICAgICAgICAvLyBjYXTDqWdvcmllIGRvbWluYW50ZSBhY3R1ZWxsZSBuJ2V4aXN0ZSkgOiBvbiBwcm9wb3NlIGRlIGxlcyBhbGlnbmVyLgogICAgICAgIGNvbnN0IG91dGxpZXJzID0gc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ICE9PSBkb21pbmFudCk7CiAgICAgICAgaWYgKG91dGxpZXJzLmxlbmd0aCA+IDApIHsKICAgICAgICAgIGNvbnN0IG91dGxpZXJDYXRlZ29yaWVzID0gWy4uLm5ldyBTZXQob3V0bGllcnMubWFwKCh0eCkgPT4gdHguY2F0ZWdvcnkpKV07CiAgICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAgICBrZXk6IGByZWNvbmNpbGU6JHt0eXBlfToke3NpZ25hdHVyZX06JHtkb21pbmFudH1gLAogICAgICAgICAgICBraW5kOiAicmVjb25jaWxlIiwKICAgICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgICAgdHlwZSwKICAgICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICAgIG91dGxpZXJDYXRlZ29yaWVzLAogICAgICAgICAgICB0eElkczogb3V0bGllcnMubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgICAgfTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGlmICghc3VnZ2VzdGlvbiB8fCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5oYXMoc3VnZ2VzdGlvbi5rZXkpKSByZXR1cm47CiAgICAgIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbik7CiAgICB9CgogICAgZnVuY3Rpb24gaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCkgewogICAgICBsZXQgaWRzVG9GaXg7CiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJyZWNvbmNpbGUiKSB7CiAgICAgICAgLy8gSWNpIHN1Z2dlc3Rpb24udHhJZHMgZXN0IGTDqWrDoCBleGFjdGVtZW50IGwnZW5zZW1ibGUgZGVzIGFuY2llbm5lcwogICAgICAgIC8vIHRyYW5zYWN0aW9ucyDDoCBhbGlnbmVyIChwYXMgZGUgImRlcm5pw6hyZSB0cmFuc2FjdGlvbiIgw6AgcGFydCkgOiBsZQogICAgICAgIC8vIHRleHRlIGRlIGxhIGJhbm5pw6hyZSBsJ2Fubm9uY2UgZMOpasOgLCBwYXMgYmVzb2luIGQndW5lIGNvbmZpcm1hdGlvbgogICAgICAgIC8vIHN1cHBsw6ltZW50YWlyZS4KICAgICAgICBpZHNUb0ZpeCA9IHN1Z2dlc3Rpb24udHhJZHM7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgW2xhdGVzdElkLCAuLi5vdGhlcnNdID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgICBpZHNUb0ZpeCA9IFtsYXRlc3RJZF07CiAgICAgICAgaWYgKAogICAgICAgICAgb3RoZXJzLmxlbmd0aCA+IDAgJiYKICAgICAgICAgIChhd2FpdCBzaG93Q29uZmlybShgQ29ycmlnZXIgYXVzc2kgbGVzICR7b3RoZXJzLmxlbmd0aH0gdHJhbnNhY3Rpb24ocykgcHLDqWPDqWRlbnRlKHMpIGF2ZWMgbGEgbcOqbWUgZGVzY3JpcHRpb24gP2ApKQogICAgICAgICkgewogICAgICAgICAgaWRzVG9GaXgucHVzaCguLi5vdGhlcnMpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgdHJ5IHsKICAgICAgICBmb3IgKGNvbnN0IGlkIG9mIGlkc1RvRml4KSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnk6IHRhcmdldFZhbHVlIH0pLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIHNob3dUb2FzdChgQ2F0w6lnb3JpZSBtaXNlIMOgIGpvdXIgOiAke3RhcmdldExhYmVsfWApOwogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwoKICAgICAgY29uc3QgZGVzY0xhYmVsID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiKHNhbnMgZGVzY3JpcHRpb24pIjsKICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgVHUgYXMgdXRpbGlzw6kgIiR7ZGVzY0xhYmVsfSIgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gZm9pcywgdG91am91cnMgY2xhc3PDqSBlbiBgICsKICAgICAgICAgIGAiQXV0cmUiLiBDcsOpZXIgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpID9gOwogICAgICB9IGVsc2UgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gInJlY29uY2lsZSIpIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBvdXRsaWVyTGFiZWxzID0gc3VnZ2VzdGlvbi5vdXRsaWVyQ2F0ZWdvcmllcwogICAgICAgICAgLm1hcCgoYykgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY10gfHwgYykKICAgICAgICAgIC5qb2luKCIsICIpOwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCR7c3VnZ2VzdGlvbi50eElkcy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHNpbWlsYWlyZShzKSDDoCAiJHtkZXNjTGFiZWx9IiBzb250IGNsYXNzw6llcyBlbiBgICsKICAgICAgICAgIGAiJHtvdXRsaWVyTGFiZWxzfSIsIGFsb3JzIHF1ZSAiJHtkb21pbmFudExhYmVsfSIgZXN0IG1haW50ZW5hbnQgbGEgY2F0w6lnb3JpZSBoYWJpdHVlbGxlLiBgICsKICAgICAgICAgIGBMZXMgYWxpZ25lciBzdXIgIiR7ZG9taW5hbnRMYWJlbH0iID9gOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGN1cnJlbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uY3VycmVudF0gfHwgc3VnZ2VzdGlvbi5jdXJyZW50OwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCIke2Rlc2NMYWJlbH0iIGVzdCBoYWJpdHVlbGxlbWVudCBjbGFzc8OpIGVuICIke2RvbWluYW50TGFiZWx9IiwgbWFpcyBjZXR0ZSBmb2lzIGAgKwogICAgICAgICAgYGMnZXN0ICIke2N1cnJlbnRMYWJlbH0iLiBQYXMgZCdlcnJldXIgb3UgdW4gb3VibGkgP2A7CiAgICAgIH0KICAgICAgZWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAiY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyI7CgogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzZWxlY3QiKTsKICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXSkgewogICAgICAgICAgaWYgKHZhbHVlID09PSAiYXV0cmUiKSBjb250aW51ZTsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBuZXdPcHQudmFsdWUgPSAiX19uZXdfXyI7CiAgICAgICAgbmV3T3B0LnRleHRDb250ZW50ID0gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiI7CiAgICAgICAgbmV3T3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQobmV3T3B0KTsKCiAgICAgICAgY29uc3QgbmV3TmFtZUlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBuZXdOYW1lSW5wdXQudHlwZSA9ICJ0ZXh0IjsKICAgICAgICBuZXdOYW1lSW5wdXQucGxhY2Vob2xkZXIgPSAiTm9tIGRlIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiOwogICAgICAgIG5ld05hbWVJbnB1dC52YWx1ZSA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIiI7CgogICAgICAgIHNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICBuZXdOYW1lSW5wdXQuc3R5bGUuZGlzcGxheSA9IHNlbGVjdC52YWx1ZSA9PT0gIl9fbmV3X18iID8gImlubGluZS1ibG9jayIgOiAibm9uZSI7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKHNlbGVjdCk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQobmV3TmFtZUlucHV0KTsKCiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9ICJBcHBsaXF1ZXIiOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBsZXQgdGFyZ2V0VmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgICBsZXQgdGFyZ2V0TGFiZWw7CiAgICAgICAgICBpZiAodGFyZ2V0VmFsdWUgPT09ICJfX25ld19fIikgewogICAgICAgICAgICBjb25zdCBuYW1lID0gbmV3TmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgaWYgKCFuYW1lKSB7IHNob3dUb2FzdCgiRG9ubmUgdW4gbm9tIMOgIGxhIGNhdMOpZ29yaWUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgICAgICAgIHRhcmdldFZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IG5hbWU7CiAgICAgICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdGFyZ2V0VmFsdWUpKSB7CiAgICAgICAgICAgICAgc2F2ZUN1c3RvbUNhdGVnb3J5KHN1Z2dlc3Rpb24udHlwZSwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1t0YXJnZXRWYWx1ZV0gfHwgdGFyZ2V0VmFsdWU7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gYENvcnJpZ2VyIGVuICIke2RvbWluYW50TGFiZWx9ImA7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHN1Z2dlc3Rpb24uZG9taW5hbnQsIGRvbWluYW50TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfQoKICAgICAgY29uc3QgZGlzbWlzc0J0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBkaXNtaXNzQnRuLnRleHRDb250ZW50ID0gIklnbm9yZXIiOwogICAgICBkaXNtaXNzQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgZGlzbWlzc0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICB9KTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoZGlzbWlzc0J0bik7CgogICAgICBlbC5hcHBlbmRDaGlsZChjb250cm9scyk7CiAgICB9CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIGNoYXJnZSByw6ljdXJyZW50ZSBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUKICAgIC8vIHNlc3Npb24gKG3Dqm1lIHByaW5jaXBlIHF1ZSBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkLCBtYWlzIHBvdXIgdW5lCiAgICAvLyBjb3JyZWN0aW9uIHF1aSBzdWl0IGxhIGNyw6lhdGlvbiBkJ3VuZSByw6ljdXJyZW50ZSBwYXIgbGEgdm9peCkuCiAgICBsZXQgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgIGNvbnN0IGFtb3VudExhYmVsID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpOwoKICAgICAgLy8gInLDqWN1cnJlbnQiLCAiYWJvbm5lbWVudCIsICJ0b3VzIGxlcyBtb2lzIi4uLiBkw6l0ZWN0w6kgcGFyIGwnSUEgOiBvbgogICAgICAvLyBjcsOpZS9jb3JyaWdlIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgYXUgbGlldSBkJ3VuZSB0cmFuc2FjdGlvbgogICAgICAvLyBwb25jdHVlbGxlLCBxdWVsIHF1ZSBzb2l0IGwnb25nbGV0IGFjdHVlbGxlbWVudCBhZmZpY2jDqSDigJQgbGUgbWljcm8KICAgICAgLy8gZXN0IGdsb2JhbCwgcGFzIGxpw6kgw6AgbCdvbmdsZXQgUsOpY3VycmVudGVzLgogICAgICBpZiAocGFyc2VkLmlzX3JlY3VycmluZykgewogICAgICAgIGNvbnN0IHJlY1BheWxvYWQgPSB7CiAgICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICAgIG5hbWU6IHBhcnNlZC5kZXNjcmlwdGlvbiB8fCAocGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSByw6ljdXJyZW50IiA6ICJEw6lwZW5zZSByw6ljdXJyZW50ZSIpLAogICAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICAgIGRheV9vZl9tb250aDogTnVtYmVyKHBhcnNlZC5leHBlbnNlX2RhdGUuc2xpY2UoOCwgMTApKSwKICAgICAgICB9OwoKICAgICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2xhc3RWb2ljZVJlY3VycmluZ0lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVjUGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICAgIHNob3dUb2FzdChgQ2hhcmdlIHLDqWN1cnJlbnRlIGNvcnJpZ8OpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBjcmVhdGVkLmlkOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUgOiAke3JlY1BheWxvYWQubmFtZX0gKCR7YW1vdW50TGFiZWx9KWApOwogICAgICAgIH0KICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQpIHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtsYXN0Vm9pY2VUcmFuc2FjdGlvbklkfWAsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYENvcnJpZ8OpIDogJHt2ZXJiLnRvTG93ZXJDYXNlKCl9IGRlICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgc2hvd1RvYXN0KGAke3ZlcmJ9IGFqb3V0w6kke3BhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICIiIDogImUifSA6ICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0KICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihwYXJzZWQuZGVzY3JpcHRpb24sIHBhcnNlZC50eXBlKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb25maXJtYXRpb24gc3R5bMOpZSAocmVtcGxhY2Ugd2luZG93LmNvbmZpcm0sIHF1aSBhZmZpY2hlIHVuZSBwb3B1cAogICAgLy8gbmF0aXZlIGR1IG5hdmlnYXRldXIgaG9ycyBjaGFydGUgZ3JhcGhpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgY29uZmlybU92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IGNvbmZpcm1NZXNzYWdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1tb2RhbC1tZXNzYWdlIik7CiAgICBjb25zdCBjb25maXJtT2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tb2siKTsKICAgIGNvbnN0IGNvbmZpcm1DYW5jZWxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tY2FuY2VsIik7CiAgICBsZXQgY29uZmlybVJlc29sdmUgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNob3dDb25maXJtKG1lc3NhZ2UpIHsKICAgICAgY29uZmlybU1lc3NhZ2VFbC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4gewogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gcmVzb2x2ZTsKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VDb25maXJtKHJlc3VsdCkgewogICAgICBjb25maXJtT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAoY29uZmlybVJlc29sdmUpIHsKICAgICAgICBjb25maXJtUmVzb2x2ZShyZXN1bHQpOwogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gbnVsbDsKICAgICAgfQogICAgfQoKICAgIGNvbmZpcm1Pa0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGNsb3NlQ29uZmlybSh0cnVlKSk7CiAgICBjb25maXJtQ2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKGZhbHNlKSk7CiAgICBjb25maXJtT3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBjb25maXJtT3ZlcmxheUVsKSBjbG9zZUNvbmZpcm0oZmFsc2UpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgZMOpcGVuc2UgcsOpY3VycmVudGUgPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgLy8gUmFtw6huZSB1biBqb3VyIGR1IG1vaXMgKDEtMzEpIGF1IGRlcm5pZXIgam91ciByw6llbCBkdSBtb2lzIHZpc8OpIOKAlAogICAgLy8gw6lxdWl2YWxlbnQgSlMgZGUgX2NsYW1wX2RheSBjw7R0w6kgc2VydmV1ciwgcG91ciBjYWxjdWxlciBkZSB2cmFpZXMKICAgIC8vIGRhdGVzIChuZXcgRGF0ZSguLi4pKSBwbHV0w7R0IHF1ZSBkZSBjb21wYXJlciBkZXMgam91cnMgdG91dCBzZXVscy4KICAgIGZ1bmN0aW9uIGNsYW1wRGF5SnMoeWVhciwgbW9udGhJbmRleCwgZGF5KSB7CiAgICAgIGNvbnN0IGxhc3REYXkgPSBuZXcgRGF0ZSh5ZWFyLCBtb250aEluZGV4ICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgICByZXR1cm4gTWF0aC5taW4oZGF5LCBsYXN0RGF5KTsKICAgIH0KCiAgICAvLyBQcm9jaGFpbmUgb2NjdXJyZW5jZSBkJ3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgw6AgcGFydGlyIGQnYXVqb3VyZCdodWkKICAgIC8vIChzdHJpY3RlbWVudCBhcHLDqHMgYXVqb3VyZCdodWkpIDogcmVnYXJkZSBjZSBtb2lzLWNpIHB1aXMsIHNpIGJlc29pbiwKICAgIC8vIGxlcyBkZXV4IG1vaXMgc3VpdmFudHMg4oCUIHV0aWxlIGVuIGZpbiBkZSBtb2lzIHF1YW5kIHBsdXMgcmllbiBuJ2VzdAogICAgLy8gw6AgdmVuaXIgZGFucyBsZSBtb2lzIGNvdXJhbnQuCiAgICBmdW5jdGlvbiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXlTdHIpIHsKICAgICAgY29uc3QgW3R5LCB0bSwgdGRdID0gdG9kYXlTdHIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdG9kYXlEYXRlID0gbmV3IERhdGUodHksIHRtIC0gMSwgdGQpOwogICAgICBmb3IgKGxldCBvZmZzZXQgPSAwOyBvZmZzZXQgPD0gMjsgb2Zmc2V0KyspIHsKICAgICAgICBjb25zdCBiYXNlID0gbmV3IERhdGUodHksIHRtIC0gMSArIG9mZnNldCwgMSk7CiAgICAgICAgY29uc3QgeSA9IGJhc2UuZ2V0RnVsbFllYXIoKTsKICAgICAgICBjb25zdCBtSWR4ID0gYmFzZS5nZXRNb250aCgpOwogICAgICAgIGNvbnN0IG1vbnRoS2V5ID0gYCR7eX0tJHtTdHJpbmcobUlkeCArIDEpLnBhZFN0YXJ0KDIsICIwIil9YDsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgY29uc3QgZGF5ID0gY2xhbXBEYXlKcyh5LCBtSWR4LCBpdGVtLmRheV9vZl9tb250aCk7CiAgICAgICAgY29uc3Qgb2NjRGF0ZSA9IG5ldyBEYXRlKHksIG1JZHgsIGRheSk7CiAgICAgICAgaWYgKG9jY0RhdGUgPiB0b2RheURhdGUpIHJldHVybiBvY2NEYXRlOwogICAgICB9CiAgICAgIHJldHVybiBudWxsOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpIHsKICAgICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIik7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CgogICAgICBjb25zdCB1cGNvbWluZyA9IGFsbFJlY3VycmluZwogICAgICAgIC5tYXAoKGl0ZW0pID0+ICh7IGl0ZW0sIGRhdGU6IG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheSkgfSkpCiAgICAgICAgLmZpbHRlcigoeCkgPT4geC5kYXRlKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBhLmRhdGUgLSBiLmRhdGUpCiAgICAgICAgLnNsaWNlKDAsIDMpOwoKICAgICAgaWYgKHVwY29taW5nLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwYW5lbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwoKICAgICAgZm9yIChjb25zdCB7IGl0ZW0sIGRhdGUgfSBvZiB1cGNvbWluZykgewogICAgICAgIGNvbnN0IGRheXMgPSBNYXRoLnJvdW5kKChkYXRlIC0gbmV3IERhdGUobmV3IERhdGUoKS5zZXRIb3VycygwLCAwLCAwLCAwKSkpIC8gODY0MDAwMDApOwogICAgICAgIGNvbnN0IGR1ZUxhYmVsID0gZGF5cyA8PSAxID8gImRlbWFpbiIgOiBgZGFucyAke2RheXN9IGpvdXJzYDsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJ1cGNvbWluZy1yZWN1cnJpbmctcm93IjsKICAgICAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGxlZnQuY2xhc3NOYW1lID0gIm5hbWUiOwogICAgICAgIGxlZnQudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CiAgICAgICAgY29uc3QgZHVlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkdWVTcGFuLmNsYXNzTmFtZSA9ICJkdWUiOwogICAgICAgIGR1ZVNwYW4udGV4dENvbnRlbnQgPSBgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChkYXRlKX0gwrcgJHtkdWVMYWJlbH1gOwogICAgICAgIGxlZnQuYXBwZW5kQ2hpbGQoZHVlU3Bhbik7CiAgICAgICAgY29uc3QgYW1vdW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAiYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQobGVmdCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGFtb3VudCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkUmVjdXJyaW5nKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIik7CiAgICAgICAgYWxsUmVjdXJyaW5nID0gaXRlbXM7CiAgICAgICAgcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKTsKICAgICAgICByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKTsKICAgICAgICB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBFeHBvcnQgRXhjZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LXhsc3giKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQteGxzeCIpOwogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJHw6luw6lyYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2V4cG9ydC94bHN4IiwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiw4ljaGVjIGRlIGwnZXhwb3J0ICgiICsgcmVzLnN0YXR1cyArICIpIik7CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgICBjb25zdCBsaW5rID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYSIpOwogICAgICAgIGxpbmsuaHJlZiA9IHVybDsKICAgICAgICBsaW5rLmRvd25sb2FkID0gYGRlcGVuc2VzXyR7dG9kYXlJc28oKX0ueGxzeGA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChsaW5rKTsKICAgICAgICBsaW5rLmNsaWNrKCk7CiAgICAgICAgbGluay5yZW1vdmUoKTsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICAgICAgc2hvd1RvYXN0KCJFeHBvcnQgdMOpbMOpY2hhcmfDqSIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTYXV2ZWdhcmRlIGNvbXBsw6h0ZSAoSlNPTikKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LWpzb24iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQtanNvbiIpOwogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJHw6luw6lyYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2V4cG9ydC9qc29uIiwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiw4ljaGVjIGRlIGwnZXhwb3J0ICgiICsgcmVzLnN0YXR1cyArICIpIik7CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgICBjb25zdCBsaW5rID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYSIpOwogICAgICAgIGxpbmsuaHJlZiA9IHVybDsKICAgICAgICBsaW5rLmRvd25sb2FkID0gYGthY2hpbmctc2F1dmVnYXJkZS0ke3RvZGF5SXNvKCl9Lmpzb25gOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobGluayk7CiAgICAgICAgbGluay5jbGljaygpOwogICAgICAgIGxpbmsucmVtb3ZlKCk7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogICAgICAgIHNob3dUb2FzdCgiU2F1dmVnYXJkZSB0w6lsw6ljaGFyZ8OpZSIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBvayA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgICJTdXBwcmltZXIgRMOJRklOSVRJVkVNRU5UIHRvdXRlcyBsZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMpID8gQ2V0dGUgYWN0aW9uIGVzdCBpcnLDqXZlcnNpYmxlLiIKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwogICAgICAvLyBEb3VibGUgY29uZmlybWF0aW9uIHZ1IGxlIGNhcmFjdMOocmUgaXJyw6l2ZXJzaWJsZSBldCBjb21wbGV0IGRlIGwnYWN0aW9uLgogICAgICBjb25zdCBvazIgPSBhd2FpdCBzaG93Q29uZmlybSgiRGVybmnDqHJlIGNvbmZpcm1hdGlvbiA6IHZyYWltZW50IHRvdXQgcsOpaW5pdGlhbGlzZXIgPyIpOwogICAgICBpZiAoIW9rMikgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZXNldC1hbGwiKTsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIlLDqWluaXRpYWxpc2F0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZXNldC1hbGwiLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJBcHBsaWNhdGlvbiByw6lpbml0aWFsaXPDqWUiKTsKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgNjAwKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzZXIgdG91dGUgbCdhcHBsaWNhdGlvbiI7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBXQSA6IGluc3RhbGxhdGlvbiBzdXIgbCfDqWNyYW4gZCdhY2N1ZWlsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBpZiAoInNlcnZpY2VXb3JrZXIiIGluIG5hdmlnYXRvcikgewogICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigibG9hZCIsICgpID0+IHsKICAgICAgICBuYXZpZ2F0b3Iuc2VydmljZVdvcmtlci5yZWdpc3RlcigiL3N3LmpzIikuY2F0Y2goKCkgPT4ge30pOwogICAgICB9KTsKICAgIH0KCiAgICBsZXQgZGVmZXJyZWRJbnN0YWxsUHJvbXB0ID0gbnVsbDsKICAgIGNvbnN0IHB3YUluc3RhbGxSb3cgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicHdhLWluc3RhbGwtcm93Iik7CiAgICBjb25zdCBwd2FJbnN0YWxsQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInB3YS1pbnN0YWxsLWJ0biIpOwogICAgY29uc3QgcHdhSW9zSGludFJvdyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwd2EtaW9zLWhpbnQtcm93Iik7CgogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImJlZm9yZWluc3RhbGxwcm9tcHQiLCAoZSkgPT4gewogICAgICAvLyBFbXDDqmNoZSBsYSBtaW5pLWluZm9iYXIgYXV0b21hdGlxdWUgZHUgbmF2aWdhdGV1ciA6IG9uIGFmZmljaGUKICAgICAgLy8gcGx1dMO0dCBub3RyZSBwcm9wcmUgYm91dG9uLCBkYW5zIGwnb25nbGV0IEV4cG9ydCwgY29ow6lyZW50IGF2ZWMKICAgICAgLy8gbGUgcmVzdGUgZHUgc2l0ZS4KICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBlOwogICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIiI7CiAgICB9KTsKCiAgICBpZiAocHdhSW5zdGFsbEJ0bikgewogICAgICBwd2FJbnN0YWxsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgIGlmICghZGVmZXJyZWRJbnN0YWxsUHJvbXB0KSByZXR1cm47CiAgICAgICAgZGVmZXJyZWRJbnN0YWxsUHJvbXB0LnByb21wdCgpOwogICAgICAgIGNvbnN0IHsgb3V0Y29tZSB9ID0gYXdhaXQgZGVmZXJyZWRJbnN0YWxsUHJvbXB0LnVzZXJDaG9pY2U7CiAgICAgICAgZGVmZXJyZWRJbnN0YWxsUHJvbXB0ID0gbnVsbDsKICAgICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGlmIChvdXRjb21lID09PSAiYWNjZXB0ZWQiKSBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIGluc3RhbGzDqWUiKTsKICAgICAgfSk7CiAgICB9CgogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImFwcGluc3RhbGxlZCIsICgpID0+IHsKICAgICAgaWYgKHB3YUluc3RhbGxSb3cpIHB3YUluc3RhbGxSb3cuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgIH0pOwoKICAgIC8vIFNhZmFyaSBpT1MgbmUgZMOpY2xlbmNoZSBqYW1haXMgImJlZm9yZWluc3RhbGxwcm9tcHQiIDogb24gYWZmaWNoZSDDoCBsYQogICAgLy8gcGxhY2UgdW4gcGV0aXQgbW9kZSBkJ2VtcGxvaSAoUGFydGFnZXIgPiBTdXIgbCfDqWNyYW4gZCdhY2N1ZWlsKSwgc2F1ZgogICAgLy8gc2kgbCdhcHAgZXN0IGTDqWrDoCBpbnN0YWxsw6llIChtb2RlIHN0YW5kYWxvbmUpLgogICAgY29uc3QgaXNJb3MgPSAvaXBob25lfGlwYWR8aXBvZC9pLnRlc3QobmF2aWdhdG9yLnVzZXJBZ2VudCk7CiAgICBjb25zdCBpc1N0YW5kYWxvbmUgPQogICAgICB3aW5kb3cubWF0Y2hNZWRpYSgiKGRpc3BsYXktbW9kZTogc3RhbmRhbG9uZSkiKS5tYXRjaGVzIHx8IHdpbmRvdy5uYXZpZ2F0b3Iuc3RhbmRhbG9uZSA9PT0gdHJ1ZTsKICAgIGlmIChpc0lvcyAmJiAhaXNTdGFuZGFsb25lICYmIHB3YUlvc0hpbnRSb3cpIHsKICAgICAgcHdhSW9zSGludFJvdy5zdHlsZS5kaXNwbGF5ID0gIiI7CiAgICB9CgogICAgcG9wdWxhdGVDYXRlZ29yaWVzKCJleHBlbnNlIik7CiAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwoKICAgIC8vIFJpZW4gZGUgdG91dCDDp2EgKGNoYXJnZW1lbnQgZGVzIGRvbm7DqWVzLCByYWNjb3VyY2lzIFBXQS4uLikgbmUgZG9pdAogICAgLy8gZMOpbWFycmVyIGF2YW50IGQnYXZvaXIgdW4gamV0b24gZGUgc2Vzc2lvbiB2YWxpZGUg4oCUIHNpbm9uIGxhIHByZW1pw6hyZQogICAgLy8gcmVxdcOqdGUgw6ljaG91ZXJhaXQganVzdGUgYXZlYyB1bmUgNDAxIMOgIGxhIHBsYWNlIGRlIG1vbnRyZXIgbGUgdmVycm91LgogICAgaWYgKEFQSV9LRVkpIHsKICAgICAgc2hvd0FwcCgpOwogICAgICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgICAgICAvLyBDYXTDqWdvcmllcyBwZXJzbyArIHN1Z2dlc3Rpb25zIGlnbm9yw6llcyBkJ2Fib3JkLCBwb3VyIHF1ZSBsZXMKICAgICAgICAvLyBsaXN0ZXMgZMOpcm91bGFudGVzIGV0IGxlIGJhbmRlYXUgc29pZW50IGNvcnJlY3RzIGTDqHMgbGUgcHJlbWllcgogICAgICAgIC8vIHJlbmR1IHBsdXTDtHQgcXVlIGRlICJzYXV0ZXIiIHVuZSBmb2lzIGxlIHNlcnZldXIgcsOpcG9uZHUuCiAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoW2xvYWRDdXN0b21DYXRlZ29yaWVzKCksIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpLCBsb2FkQnVkZ2V0cygpLCBsb2FkU2F2aW5nc0dvYWwoKV0pOwogICAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIGxvYWRSZWN1cnJpbmcoKTsKCiAgICAgICAgLy8gUmFjY291cmNpcyBQV0EgKGFwcHVpIGxvbmcgc3VyIGwnaWPDtG5lIGRlIGwnYXBwIHVuZSBmb2lzIGluc3RhbGzDqWUpIDoKICAgICAgICAvLyAvP3Nob3J0Y3V0PWFkZCBvdXZyZSBkaXJlY3RlbWVudCBsZSBmb3JtdWxhaXJlIGQnYWpvdXQsIC8/c2hvcnRjdXQ9dm9pY2UKICAgICAgICAvLyBsYW5jZSBkaXJlY3RlbWVudCBsYSBkaWN0w6llIHZvY2FsZS4KICAgICAgICBjb25zdCBzaG9ydGN1dFBhcmFtID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoInNob3J0Y3V0Iik7CiAgICAgICAgaWYgKHNob3J0Y3V0UGFyYW0pIHsKICAgICAgICAgIC8vIE5ldHRvaWUgbCdVUkwgdG91dCBkZSBzdWl0ZSA6IHVuIHJlY2hhcmdlbWVudCBkZSBsYSBwYWdlIChvdSB1bgogICAgICAgICAgLy8gcGFydGFnZSBkdSBsaWVuKSBuZSBkb2l0IHBhcyByZWTDqWNsZW5jaGVyIGxlIHJhY2NvdXJjaS4KICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gImFkZCIpIHsKICAgICAgICAgICAgb3Blbk1vZGFsKCk7CiAgICAgICAgICB9IGVsc2UgaWYgKHNob3J0Y3V0UGFyYW0gPT09ICJ2b2ljZSIgJiYgIW1pY0J0bi5kaXNhYmxlZCkgewogICAgICAgICAgICBtaWNCdG4uY2xpY2soKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0pKCk7CiAgICB9IGVsc2UgewogICAgICBzaG93TG9ja1NjcmVlbigpOwogICAgfQogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
