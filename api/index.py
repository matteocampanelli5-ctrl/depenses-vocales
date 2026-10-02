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
import json
import os
import re
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
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
# Clé service_role (secrète) et non la clé anon (publique) : le RLS est
# activé sans aucune policy pour anon/public, donc seule service_role peut
# lire/écrire. Cette clé ne doit JAMAIS être envoyée au frontend — elle vit
# uniquement ici, côté serveur, comme variable d'environnement Vercel.
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    """Protection basique : sans cette clé dans le header, on refuse.

    Ce n'est pas une vraie authentification (la clé est visible côté
    client, dans le JS de la page), juste un obstacle contre les accès
    accidentels ou les bots qui scannent les endpoints publics.
    """
    if not API_SECRET_KEY or x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Clé API invalide ou manquante")


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
    type: TransactionType
    amount: float
    category: str
    description: str | None
    expense_date: date
    is_correction: bool
    is_recurring: bool
    raw_date_expression: str | None


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
# Extraction IA (API Anthropic) — transforme une phrase dictée en brouillon
# structuré. Ne touche jamais la base : c'est le frontend qui décide ensuite
# d'appeler POST ou PUT sur /api/transactions avec le résultat.
# ---------------------------------------------------------------------------
_VOICE_SYSTEM_PROMPT = """Tu extrais des informations structurées à partir d'une phrase dictée à l'oral en français, qui décrit une dépense ou un revenu personnel.

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon exactement ce schéma :
{
  "type": "expense" ou "income",
  "amount": nombre (toujours positif),
  "category": une chaîne parmi restaurant, courses, transport, logement, loisirs, santé, autre (si type=expense) ou salaire, freelance, remboursement, cadeau, autre (si type=income),
  "raw_date_expression": l'expression de date EXACTEMENT telle que prononcée (ex: "hier", "lundi dernier", "le 3 septembre"), ou null si aucune date n'est mentionnée,
  "description": une description courte et nettoyée (sans le montant ni la date), ou null si rien de pertinent à part la catégorie,
  "is_correction": true seulement si la phrase exprime explicitement une intention de corriger une transaction déjà enregistrée (ex: "corrige", "en fait c'était plutôt", "change le montant de..."), false dans tous les autres cas, y compris si la phrase ressemble à une dépense déjà saisie,
  "is_recurring": true si la phrase indique explicitement qu'il s'agit d'une charge qui se répète chaque mois (mots comme "récurrent", "récurrence", "abonnement", "tous les mois", "chaque mois", "mensuel"), false sinon
}

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même une date calendaire (comme "2026-09-30") à partir d'une expression relative. Tu ne connais pas la date du jour. Recopie l'expression de date telle quelle dans raw_date_expression ; un autre système déterministe s'occupera de la convertir.
- Si la phrase ne mentionne aucune date, raw_date_expression doit être null (la date du jour sera utilisée par défaut).
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


@app.post("/api/voice/parse", response_model=VoiceParseResult)
def parse_voice_text(req: VoiceParseRequest, _: None = Depends(require_api_key)) -> VoiceParseResult:
    data = call_claude_extraction(req.text)

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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdCB7CiAgICBjb2xvci1zY2hlbWU6IGRhcms7CiAgICAtLWJnOiAjMGYxMTE1OwogICAgLS1zdXJmYWNlOiAjMWExZDI0OwogICAgLS1zdXJmYWNlLTI6ICMyMjI2MmY7CiAgICAtLWJvcmRlcjogIzJhMmUzODsKICAgIC0tdGV4dDogI2U2ZTZlNjsKICAgIC0tdGV4dC1kaW06ICM5YWEwYWM7CiAgICAtLWFjY2VudDogIzNiODJmNjsKICAgIC0tYWNjZW50LWRpbTogIzFkNGVkODsKICAgIC0tZGFuZ2VyOiAjZWY0NDQ0OwogICAgLS1zdWNjZXNzOiAjMjJjNTVlOwogICAgLS1yYWRpdXM6IDE0cHg7CiAgfQogICogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgYm9keSB7CiAgICBtYXJnaW46IDA7CiAgICBtaW4taGVpZ2h0OiAxMDB2aDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKICAgIHBhZGRpbmctYm90dG9tOiA2cmVtOwogIH0KICBoZWFkZXIgewogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gMXJlbTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICB9CiAgaDEgeyBmb250LXNpemU6IDEuM3JlbTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgfQogIC5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC45cmVtOyBtYXJnaW46IDA7IH0KCiAgLnRhYnMgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgfQogIC50YWItYnRuIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDExMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnRhYi1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KCiAgLnN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTAwcHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC45cmVtIDFyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgLmxhYmVsIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAwLjI1cmVtOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUucG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b29sdGlwLWhvc3QgeyBwb3NpdGlvbjogcmVsYXRpdmU7IGN1cnNvcjogaGVscDsgfQogIC5jdXN0b20tdG9vbHRpcCB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICBsZWZ0OiA1MCU7CiAgICBib3R0b206IGNhbGMoMTAwJSArIDAuNnJlbSk7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSg0cHgpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC41NXJlbSAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgICB0ZXh0LWFsaWduOiBsZWZ0OwogICAgYm94LXNoYWRvdzogMCA4cHggMjBweCByZ2JhKDAsIDAsIDAsIDAuMzUpOwogICAgb3BhY2l0eTogMDsKICAgIHBvaW50ZXItZXZlbnRzOiBub25lOwogICAgdHJhbnNpdGlvbjogb3BhY2l0eSAwLjEycyBlYXNlLCB0cmFuc2Zvcm0gMC4xMnMgZWFzZTsKICAgIHotaW5kZXg6IDIwOwogIH0KICAuY3VzdG9tLXRvb2x0aXA6OmFmdGVyIHsKICAgIGNvbnRlbnQ6ICIiOwogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxMDAlOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYm9yZGVyOiA2cHggc29saWQgdHJhbnNwYXJlbnQ7CiAgICBib3JkZXItdG9wLWNvbG9yOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KICAuY3VzdG9tLXRvb2x0aXAudmlzaWJsZSB7CiAgICBvcGFjaXR5OiAxOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoMCk7CiAgICBwb2ludGVyLWV2ZW50czogYXV0bzsKICB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLndlZWstc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAtMC40cmVtIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQoKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxLjFyZW07CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudC1kaW0pOwogIH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gcCB7IG1hcmdpbjogMCAwIDAuN3JlbTsgZm9udC1zaXplOiAwLjg4cmVtOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBzZWxlY3QsCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idG4tcHJpbWFyeS1zbSwgLmJ0bi1zZWNvbmRhcnktc20gewogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuOHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6ICNmZmY7IH0KICAuYnRuLXNlY29uZGFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1yZWN1cnJpbmctYmFkZ2UgeyBmb250LXNpemU6IDAuNzVyZW07IG9wYWNpdHk6IDAuNzsgY3Vyc29yOiBoZWxwOyB9CiAgLnR4LXJlY2VpcHQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjc1cmVtOwogICAgb3BhY2l0eTogMC44NTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBwYWRkaW5nOiAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnVwY29taW5nLW5vdGUgewogICAgd2lkdGg6IDk2cHg7CiAgICBmbGV4LXNocmluazogMDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC40cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjI1OwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CiAgLnVwY29taW5nLW5vdGUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1zd2F0Y2ggewogICAgd2lkdGg6IDI4cHg7CiAgICBoZWlnaHQ6IDE0cHg7CiAgICBib3JkZXI6IDEuNXB4IGRhc2hlZCB2YXIoLS1kYW5nZXIpOwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICB9CiAgLnVwY29taW5nLW5vdGUucG9zaXRpdmUgLnVwY29taW5nLXN3YXRjaCB7CiAgICBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOwogICAgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4yKTsKICB9CgogIC5yZWN1cnJpbmctc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjdXJyaW5nLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLmV4cG9ydC1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5leHBvcnQtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KICAuc2F2aW5ncy1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5zYXZpbmdzLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5zYXZpbmdzLWdvYWwtcm93IHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KICAuc2F2aW5ncy1nb2FsLXJvdyBpbnB1dCB7IGZsZXg6IDE7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXJnaW46IDAuOHJlbSAwIDAuMzVyZW07CiAgfQogIC5zYXZpbmdzLXByb2dyZXNzLWxhYmVsIHN0cm9uZyB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuYWR2aWNlLWxpc3QgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgLmFkdmljZS1jYXJkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjdyZW0gMC44NXJlbTsKICAgIGZvbnQtc2l6ZTogMC45cmVtOwogICAgbGluZS1oZWlnaHQ6IDEuNDsKICB9CiAgLmFkdmljZS1jYXJkIC5hZHZpY2UtaWNvbiB7IGZvbnQtc2l6ZTogMS4xcmVtOyBmbGV4LXNocmluazogMDsgfQogIC5hZHZpY2UtY2FyZC5wb3NpdGl2ZSB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tc3VjY2Vzcyk7IH0KICAuYWR2aWNlLWNhcmQud2FybmluZyB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgI2Y1OWUwYjsgfQogIC5hZHZpY2UtY2FyZC5pbmZvIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1hY2NlbnQpOyB9CiAgLnJlY3VycmluZy1oaW50IHsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW46IDAgMCAwLjlyZW07CiAgfQoKICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjhyZW0gMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgaDQgeyBtYXJnaW46IDAgMCAwLjZyZW07IGZvbnQtc2l6ZTogMC45cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBiYXNlbGluZTsKICAgIHBhZGRpbmc6IDAuMzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgKyAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLm5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuZHVlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjc4cmVtOyBtYXJnaW4tbGVmdDogMC40cmVtOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuY29tcGFyZS1zZWxlY3RzIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjZyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc2VsZWN0IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40NXJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc3BhbiB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQoKICAuc2ltcGxlLXRhYmxlIHsgd2lkdGg6IDEwMCU7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQogIC5zaW1wbGUtdGFibGUgdGgsIC5zaW1wbGUtdGFibGUgdGQgeyBwYWRkaW5nOiAwLjVyZW0gMC42cmVtOyB0ZXh0LWFsaWduOiByaWdodDsgfQogIC5zaW1wbGUtdGFibGUgdGg6Zmlyc3QtY2hpbGQsIC5zaW1wbGUtdGFibGUgdGQ6Zmlyc3QtY2hpbGQgeyB0ZXh0LWFsaWduOiBsZWZ0OyB9CiAgLnNpbXBsZS10YWJsZSB0aGVhZCB0aCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtd2VpZ2h0OiA1MDA7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSB0Ym9keSB0ciArIHRyIHRkIHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyLnRvdGFsLXJvdyB0ZCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGJvcmRlci10b3A6IDJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zaW1wbGUtdGFibGUgLmRpZmYtbmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50cmVuZC11cCB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLWRvd24geyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHJlbmQtZmxhdCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KCiAgLmJ1ZGdldC1yb3cgeyBtYXJnaW4tYm90dG9tOiAwLjlyZW07IH0KICAuYnVkZ2V0LXJvdy1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjVyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjM1cmVtOwogIH0KICAuYnVkZ2V0LWNhdC1uYW1lIHsgY29sb3I6IHZhcigtLXRleHQpOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLmJ1ZGdldC1hbW91bnRzIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWlucHV0IHsKICAgIHdpZHRoOiA2NHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA2cHg7CiAgICBwYWRkaW5nOiAwLjI1cmVtIDAuNHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmJ1ZGdldC1iYXItdHJhY2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgaGVpZ2h0OiA4cHg7IG92ZXJmbG93OiBoaWRkZW47IH0KICAuYnVkZ2V0LWJhci1maWxsIHsgaGVpZ2h0OiAxMDAlOyBib3JkZXItcmFkaXVzOiA5OTlweDsgdHJhbnNpdGlvbjogd2lkdGggMC4ycyBlYXNlOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vayB7IGJhY2tncm91bmQ6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5idWRnZXQtYmFyLWZpbGwub3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IH0KICAuYnVkZ2V0cy1zYXZlLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7IG1hcmdpbi10b3A6IDAuNnJlbTsgfQogIC5idWRnZXRzLXNhdmUtcm93IGJ1dHRvbi5wcmltYXJ5IHsgZmxleDogbm9uZTsgcGFkZGluZzogMC42NXJlbSAxLjFyZW07IH0KICAucmVjLWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1hY2NlbnQpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC42cmVtOwogIH0KICAucmVjLWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnJlYy1jYXJkLmluY29tZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtY2FyZC5lbmRlZCB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG9wYWNpdHk6IDAuNjsgfQogIC5yZWMtbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC5yZWMtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IGZsZXgtd3JhcDogd3JhcDsgfQogIC5yZWMtbmFtZSB7IGZvbnQtc2l6ZTogMC45NXJlbTsgb3ZlcmZsb3c6IGhpZGRlbjsgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLXN1YiB7IGZvbnQtc2l6ZTogMC43OHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5lbmQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7CiAgICBjb2xvcjogI2ZjYTVhNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5zdGFydC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4xNSk7CiAgICBjb2xvcjogIzkzYzVmZDsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5yZWMtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuZmFiIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiAxLjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogICAgY29sb3I6IHdoaXRlOwogICAgZm9udC1zaXplOiAxLjhyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSg1OSwgMTMwLCAyNDYsIDAuNCk7CiAgfQogIC5mYWI6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQoKICAuZmFiLW1pYyB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogNS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDAsIDAsIDAsIDAuMyk7CiAgICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAuMnMsIGJvcmRlci1jb2xvciAwLjJzOwogIH0KICAuZmFiLW1pYzphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CiAgLmZhYi1taWMubGlzdGVuaW5nIHsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7CiAgICBhbmltYXRpb246IHB1bHNlIDEuMnMgaW5maW5pdGU7CiAgfQogIC5mYWItbWljLnByb2Nlc3NpbmcgeyBvcGFjaXR5OiAwLjY7IGN1cnNvcjogZGVmYXVsdDsgfQogIC5mYWItbWljOmRpc2FibGVkIHsgb3BhY2l0eTogMC4zNTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQogIEBrZXlmcmFtZXMgcHVsc2UgewogICAgMCUsIDEwMCUgeyBib3gtc2hhZG93OiAwIDAgMCAwIHJnYmEoMjM5LCA2OCwgNjgsIDAuNCk7IH0KICAgIDUwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDEwcHggcmdiYSgyMzksIDY4LCA2OCwgMCk7IH0KICB9CgogIC52b2ljZS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTU7CiAgfQogIC52b2ljZS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQoKICAubW9kYWwtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC41NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGZsZXgtZW5kOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDsKICB9CiAgLm1vZGFsLW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5tb2RhbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlci1yYWRpdXM6IDE4cHggMThweCAwIDA7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSBjYWxjKDEuNXJlbSArIGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKSk7CiAgICB3aWR0aDogMTAwJTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC45cmVtOwogIH0KICAubW9kYWwgaDIgeyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXNpemU6IDEuMXJlbTsgfQoKICBsYWJlbCB7IGZvbnQtc2l6ZTogMC44cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4zcmVtOyB9CiAgaW5wdXQsIHNlbGVjdCB7CiAgICB3aWR0aDogMTAwJTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNjVyZW0gMC43NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgaW5wdXQ6Zm9jdXMsIHNlbGVjdDpmb2N1cyB7IG91dGxpbmU6IG5vbmU7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQoKICAudHlwZS10b2dnbGUgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgfQogIC50eXBlLWJ0biB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC42NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iZXhwZW5zZSJdIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iaW5jb21lIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5jb25maXJtLW1vZGFsIHsgbWF4LXdpZHRoOiA0MDBweDsgfQogIC5jb25maXJtLW1vZGFsLW1lc3NhZ2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtc2l6ZTogMC45NXJlbTsgbWFyZ2luOiAwOyBsaW5lLWhlaWdodDogMS40OyB9CgogIC5oaWRkZW4tZmlsZS1pbnB1dCB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjZWlwdC1wcmV2aWV3LXdyYXAgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuNXJlbTsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OwogICAgbWFyZ2luLWJvdHRvbTogMC41cmVtOwogIH0KICAucmVjZWlwdC1wcmV2aWV3LWltZyB7CiAgICBtYXgtd2lkdGg6IDEwMCU7CiAgICBtYXgtaGVpZ2h0OiAxNjBweDsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgb2JqZWN0LWZpdDogY29udGFpbjsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgfQoKICAubGlnaHRib3gtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC44NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMjA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5saWdodGJveC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubGlnaHRib3gtaW1nIHsgbWF4LXdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiA4MHZoOyBib3JkZXItcmFkaXVzOiAxMHB4OyB9CiAgLmxpZ2h0Ym94LWNsb3NlIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMXJlbTsKICAgIHJpZ2h0OiAxcmVtOwogICAgd2lkdGg6IDQwcHg7CiAgICBoZWlnaHQ6IDQwcHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjFyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5LCBidXR0b24uc2Vjb25kYXJ5IHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjc1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogbm9uZTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CiAgYnV0dG9uLnByaW1hcnk6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KICBidXR0b24uc2Vjb25kYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgYnV0dG9uLmRhbmdlciB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tZGFuZ2VyKTsgfQogIGJ1dHRvbi5kYW5nZXI6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KCiAgLmRhbmdlci16b25lIHsKICAgIGJvcmRlci1jb2xvcjogcmdiYSgyMzksIDY4LCA2OCwgMC4zNSkgIWltcG9ydGFudDsKICB9CiAgLmRhbmdlci16b25lIGgzIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICA8aGVhZGVyPgogICAgPGgxPvCfkrAgS2FjaGluZzwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgZXQgcmV2ZW51cywgYWpvdXTDqXMgb3Ugw6lkaXTDqXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4gYWN0aXZlIiBpZD0idGFiLWhpc3RvcnkiIGRhdGEtdmlldz0iaGlzdG9yeSI+SGlzdG9yaXF1ZTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWRhc2hib2FyZCIgZGF0YS12aWV3PSJkYXNoYm9hcmQiPlRhYmxlYXUgZGUgYm9yZDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXJlY3VycmluZyIgZGF0YS12aWV3PSJyZWN1cnJpbmciPlLDqWN1cnJlbnRlczwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWV4cG9ydCIgZGF0YS12aWV3PSJleHBvcnQiPkV4cG9ydDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXNhdmluZ3MiIGRhdGEtdmlldz0ic2F2aW5ncyI+w4lwYXJnbmU8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQgdG9vbHRpcC1ob3N0IiBpZD0ic3VtbWFyeS11cGNvbWluZy1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj7DgCB2ZW5pciBjZSBtb2lzLWNpPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LXVwY29taW5nIj7igJQ8L3A+CiAgICAgIDxkaXYgY2xhc3M9ImN1c3RvbS10b29sdGlwIiBpZD0ic3VtbWFyeS11cGNvbWluZy10b29sdGlwIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8cCBjbGFzcz0id2Vlay1zdW1tYXJ5IiBpZD0id2Vlay1zdW1tYXJ5Ij48L3A+CgogIDxkaXYgaWQ9ImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIiBjbGFzcz0iY2F0ZWdvcnktc3VnZ2VzdGlvbiBoaWRkZW4iPjwvZGl2PgoKICA8bWFpbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpc3RvcnkiPgogICAgICA8ZGl2IGNsYXNzPSJmaWx0ZXItYmFyIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImZpbHRlci1zZWFyY2giIHBsYWNlaG9sZGVyPSJSZWNoZXJjaGVyLi4uIj4KICAgICAgICA8c2VsZWN0IGlkPSJmaWx0ZXItY2F0ZWdvcnkiPjxvcHRpb24gdmFsdWU9IiI+VG91dGVzIGNhdMOpZ29yaWVzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmaWx0ZXItZGF0ZS1zdGFydCIgYXJpYS1sYWJlbD0iRHUiPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtZW5kIiBhcmlhLWxhYmVsPSJBdSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGlkPSJ0eC1saXN0IiBjbGFzcz0idHgtbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1kYXNoYm9hcmQiIGNsYXNzPSJkYXNoYm9hcmQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIGTDqXBlbnNlcyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXRlZ29yeS1jaGFydC1yb3ciPgogICAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIgY2xhc3M9InVwY29taW5nLW5vdGUgaGlkZGVuIj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InVwY29taW5nLXN3YXRjaCI+PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLXRleHQiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1bmUgZMOpcGVuc2UgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPlLDqXBhcnRpdGlvbiBkZXMgcmV2ZW51cyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1biByZXZlbnUgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkJ1ZGdldHMgbWVuc3VlbHMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBJbmRpcXVlIHVuIG1vbnRhbnQgcG91ciBjaGFxdWUgY2F0w6lnb3JpZSDigJQgbGEgYmFycmUgY29tcGFyZSBlbnN1aXRlCiAgICAgICAgICB0ZXMgZMOpcGVuc2VzIGR1IG1vaXMgZW4gY291cnMgw6AgY2UgcGxhZm9uZCAodmVydCwgb3JhbmdlIGF1LWRlbMOgIGRlCiAgICAgICAgICA3MCUsIHJvdWdlIGF1LWRlbMOgIGRlIDEwMCUpLiBFbnJlZ2lzdHJlIHRvdXQgYXZlYyBsZSBib3V0b24gZW4gYmFzLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJidWRnZXRzLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldHMtc2F2ZS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIj7wn5K+IEVucmVnaXN0cmVyIGxlcyBidWRnZXRzPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPsOJdm9sdXRpb24gbWVuc3VlbGxlIChkw6lwZW5zZXMgdnMgcmV2ZW51cyk8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtZXZvbHV0aW9uIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Db21wYXJlciBkZXV4IG1vaXM8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNvbXBhcmUtc2VsZWN0cyI+CiAgICAgICAgICA8c2VsZWN0IGlkPSJjb21wYXJlLW1vbnRoLWEiPjwvc2VsZWN0PgogICAgICAgICAgPHNwYW4+dnM8L3NwYW4+CiAgICAgICAgICA8c2VsZWN0IGlkPSJjb21wYXJlLW1vbnRoLWIiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImNvbXBhcmUtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGFzc2V6IGRlIG1vaXMgZGlmZsOpcmVudHMgcG91ciBjb21wYXJlci4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+TW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXJlY3VycmluZyIgY2xhc3M9InJlY3VycmluZy1zZWN0aW9uIj4KICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICBDaGFyZ2VzIGZpeGVzIChhYm9ubmVtZW50cywgbG95ZXIsIHNhbGFpcmXigKYpIGNvbXB0w6llcyBhdXRvbWF0aXF1ZW1lbnQKICAgICAgICBjaGFxdWUgbW9pcyBkYW5zIGxlIHRhYmxlYXUgZGUgYm9yZCDigJQgcGFzIGJlc29pbiBkZSBsZXMgcmVkaWN0ZXIuCiAgICAgICAgTWV0cyB1bmUgZGF0ZSBkZSBkw6lidXQgc2kgdW5lIGNoYXJnZSBuZSBkb2l0IGTDqW1hcnJlciBxdWUgcGx1cyB0YXJkLAogICAgICAgIHVuZSBkYXRlIGRlIGZpbiBzaSBlbGxlIGRvaXQgcydhcnLDqnRlciB1biBqb3VyLgogICAgICA8L3A+CiAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1wYW5lbCIgY2xhc3M9InVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoaWRkZW4iPgogICAgICAgIDxoND5Qcm9jaGFpbmVzIMOpY2jDqWFuY2VzPC9oND4KICAgICAgICA8ZGl2IGlkPSJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIEF1Y3VuZSBkw6lwZW5zZSByw6ljdXJyZW50ZSBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciArIHBvdXIgZW4gYWpvdXRlciB1bmUuCiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWV4cG9ydCIgY2xhc3M9ImV4cG9ydC1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkV4cG9ydGVyIHRlcyBkb25uw6llczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFTDqWzDqWNoYXJnZSB1biBmaWNoaWVyIEV4Y2VsICgueGxzeCkgYXZlYyB0b3V0ZXMgdGVzIHRyYW5zYWN0aW9ucwogICAgICAgICAgKGTDqXBlbnNlcyBldCByZXZlbnVzKSBldCB0ZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMgKGTDqXBlbnNlcyBldAogICAgICAgICAgcmV2ZW51cyByw6ljdXJyZW50cyksIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQteGxzeCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Uw6lsw6ljaGFyZ2VyIGxlIGZpY2hpZXIgRXhjZWw8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0icHdhLWluc3RhbGwtcm93IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgPGgzPkluc3RhbGxlciBsJ2FwcGxpY2F0aW9uPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgQWpvdXRlIGwnYXBwIHN1ciB0b24gw6ljcmFuIGQnYWNjdWVpbCAodMOpbMOpcGhvbmUsIHRhYmxldHRlIG91CiAgICAgICAgICBvcmRpbmF0ZXVyKSBwb3VyIGwnb3V2cmlyIGVuIHVuIGdlc3RlLCBjb21tZSB1bmUgYXBwIG5hdGl2ZS4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9InB3YS1pbnN0YWxsLWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij7wn5OyIEluc3RhbGxlciBsJ2FwcGxpY2F0aW9uPC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9InB3YS1pb3MtaGludC1yb3ciIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICA8aDM+SW5zdGFsbGVyIGwnYXBwbGljYXRpb248L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBTdXIgaVBob25lL2lQYWQgOiBhcHB1aWUgc3VyIGwnaWPDtG5lIFBhcnRhZ2VyIGRlIFNhZmFyaSwgcHVpcwogICAgICAgICAgwqsgU3VyIGwnw6ljcmFuIGQnYWNjdWVpbCDCuy4KICAgICAgICA8L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyBkYW5nZXItem9uZSI+CiAgICAgICAgPGgzPuKaoO+4jyBab25lIGRhbmdlcmV1c2U8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBTdXBwcmltZSBkw6lmaW5pdGl2ZW1lbnQgVE9VVEVTIGxlcyBkb25uw6llcyA6IHRyYW5zYWN0aW9ucywgY2hhcmdlcwogICAgICAgICAgcsOpY3VycmVudGVzLCBjYXTDqWdvcmllcyBwZXJzb25uYWxpc8OpZXMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcywKICAgICAgICAgIGJ1ZGdldHMsIHBob3RvcyBkZSByZcOndXMgZXQgb2JqZWN0aWYgZCfDqXBhcmduZS4gUGVuc2Ugw6AgZXhwb3J0ZXIgZW4KICAgICAgICAgIEV4Y2VsIGF2YW50IHNpIGJlc29pbiDigJQgaW1wb3NzaWJsZSDDoCBhbm51bGVyLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJkYW5nZXIiIGlkPSJidG4tcmVzZXQtYWxsIiBzdHlsZT0id2lkdGg6MTAwJTsiPlLDqWluaXRpYWxpc2VyIHRvdXRlIGwnYXBwbGljYXRpb248L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctc2F2aW5ncyIgY2xhc3M9InNhdmluZ3Mtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5PYmplY3RpZiBkJ8OpcGFyZ25lIG1lbnN1ZWw8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBMZSBtb250YW50IHF1ZSB0dSB2ZXV4IGdhcmRlciBkZSBjw7R0w6kgY2hhcXVlIG1vaXMgKHJldmVudXMgbW9pbnMKICAgICAgICAgIGTDqXBlbnNlcykuIENvbXBhcsOpIMOgIHRvbiBzb2xkZSByw6llbCBkdSBtb2lzIGVuIGNvdXJzLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLWdvYWwtcm93Ij4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJzYXZpbmdzLWdvYWwtaW5wdXQiIG1pbj0iMCIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IkV4IDogMTAwIj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJzYXZpbmdzLWdvYWwtc2F2ZS1idG4iPvCfkr4gRW5yZWdpc3RyZXI8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iIGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzIGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLXByb2dyZXNzLWxhYmVsIj4KICAgICAgICAgICAgPHNwYW4+U29sZGUgZHUgbW9pcyBlbiBjb3Vyczwvc3Bhbj4KICAgICAgICAgICAgPHN0cm9uZyBpZD0ic2F2aW5ncy1wcm9ncmVzcy10ZXh0Ij48L3N0cm9uZz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0LWJhci10cmFjayI+CiAgICAgICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3MtYmFyIiBjbGFzcz0iYnVkZ2V0LWJhci1maWxsIG9rIj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Db25zZWlsczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEJhc8OpcyBzdXIgdGVzIGJ1ZGdldHMgcGFyIGNhdMOpZ29yaWUgZXQgdGVzIHRlbmRhbmNlcyBkZSBkw6lwZW5zZXMKICAgICAgICAgICh2b2lyIGwnb25nbGV0IFRhYmxlYXUgZGUgYm9yZCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtYWR2aWNlLWxpc3QiIGNsYXNzPSJhZHZpY2UtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMgY2UgbW9pcy1jaSBwb3VyIHRlIGRvbm5lciBkZXMgY29uc2VpbHMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiLW1pYyIgaWQ9ImZhYi1taWMiIGFyaWEtbGFiZWw9IkRpY3RlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51Ij7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kZXNjcmlwdGlvbiI+RGVzY3JpcHRpb24gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW5wdXQtZGVzY3JpcHRpb24iIHBsYWNlaG9sZGVyPSJFeCA6IGTDqWpldW5lciBhdmVjIFBhdWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kYXRlIj5EYXRlPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImlucHV0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWw+UmXDp3UgKHBob3RvLCBvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImlucHV0LXJlY2VpcHQtZmlsZSIgY2xhc3M9ImhpZGRlbi1maWxlLWlucHV0IiBhY2NlcHQ9ImltYWdlLyoiIGNhcHR1cmU9ImVudmlyb25tZW50Ij4KICAgICAgICA8ZGl2IGlkPSJyZWNlaXB0LXByZXZpZXctd3JhcCIgY2xhc3M9InJlY2VpcHQtcHJldmlldy13cmFwIGhpZGRlbiI+CiAgICAgICAgICA8aW1nIGlkPSJyZWNlaXB0LXByZXZpZXctaW1nIiBjbGFzcz0icmVjZWlwdC1wcmV2aWV3LWltZyIgYWx0PSJSZcOndSI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1yZWNlaXB0LXJlbW92ZSI+U3VwcHJpbWVyIGxhIHBob3RvPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tcmVjZWlwdC1waWNrIiBzdHlsZT0id2lkdGg6MTAwJTsiPvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3U8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWMtbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0icmVjLW1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSBkw6lwZW5zZSByw6ljdXJyZW50ZTwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InJlYy10eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LW5hbWUiPk5vbTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJyZWMtaW5wdXQtbmFtZSIgcGxhY2Vob2xkZXI9IkV4IDogTmV0ZmxpeCwgTG95ZXIsIFNhbGFpcmUuLi4iPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0icmVjLWlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWRheSI+Sm91ciBkdSBtb2lzPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWRheSIgbWluPSIxIiBtYXg9IjMxIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iMSDDoCAzMSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1zdGFydC1kYXRlIj5EYXRlIGRlIGTDqWJ1dCAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1lbmQtZGF0ZSI+RGF0ZSBkZSBmaW4gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LWVuZC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9InJlYy1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9InJlYy1idG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9ImNvbmZpcm0tbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCBjb25maXJtLW1vZGFsIj4KICAgICAgPGgyIGlkPSJjb25maXJtLW1vZGFsLXRpdGxlIj5Db25maXJtZXI8L2gyPgogICAgICA8cCBpZD0iY29uZmlybS1tb2RhbC1tZXNzYWdlIiBjbGFzcz0iY29uZmlybS1tb2RhbC1tZXNzYWdlIj48L3A+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImNvbmZpcm0tYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJjb25maXJtLWJ0bi1vayI+Q29uZmlybWVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImxpZ2h0Ym94LW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjZWlwdC1saWdodGJveC1vdmVybGF5Ij4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ibGlnaHRib3gtY2xvc2UiIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIiBhcmlhLWxhYmVsPSJGZXJtZXIiPuKclTwvYnV0dG9uPgogICAgPGltZyBjbGFzcz0ibGlnaHRib3gtaW1nIiBpZD0icmVjZWlwdC1saWdodGJveC1pbWciIGFsdD0iUmXDp3UgZW4gcGxlaW4gw6ljcmFuIj4KICA8L2Rpdj4KCiAgPHNjcmlwdD4KICAgIC8vIERvaXQgY29ycmVzcG9uZHJlIGV4YWN0ZW1lbnQgw6AgbGEgdmFyaWFibGUgZCdlbnZpcm9ubmVtZW50IEFQSV9TRUNSRVRfS0VZIHN1ciBWZXJjZWwuCiAgICBjb25zdCBBUElfS0VZID0gIjNJUFFzeUVRRm1jQkxsbVRmVGsxSUF5MUNuazlGMGVWIjsKCiAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHgtbGlzdCIpOwogICAgY29uc3QgZW1wdHlTdGF0ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImVtcHR5LXN0YXRlIik7CiAgICBjb25zdCBzdW1tYXJ5QmFsYW5jZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktYmFsYW5jZSIpOwogICAgY29uc3Qgc3VtbWFyeUV4cGVuc2VzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1leHBlbnNlcyIpOwogICAgY29uc3Qgc3VtbWFyeUluY29tZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktaW5jb21lIik7CgogICAgY29uc3Qgb3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IG1vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC10aXRsZSIpOwogICAgY29uc3QgdHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR5cGUtdG9nZ2xlIik7CiAgICBjb25zdCBhbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1hbW91bnQiKTsKICAgIGNvbnN0IGNhdGVnb3J5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUGhvdG8gZGUgcmXDp3UgZW4gcGnDqGNlIGpvaW50ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjZWlwdEZpbGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1yZWNlaXB0LWZpbGUiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3V3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LXByZXZpZXctd3JhcCIpOwogICAgY29uc3QgcmVjZWlwdFByZXZpZXdJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LWltZyIpOwogICAgY29uc3QgcmVjZWlwdFBpY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcGljayIpOwogICAgY29uc3QgcmVjZWlwdFJlbW92ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVjZWlwdC1yZW1vdmUiKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveE92ZXJsYXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1vdmVybGF5Iik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveENsb3NlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtY2xvc2UiKTsKCiAgICAvLyBGaWNoaWVyIGNob2lzaSBtYWlzIHBhcyBlbmNvcmUgZW52b3nDqSAodW5pcXVlbWVudCBlbiBjcsOpYXRpb24sIHRhbnQgcXVlCiAgICAvLyBsYSB0cmFuc2FjdGlvbiBuJ2EgcGFzIGVuY29yZSBkJ2lkKSA7IGVuIMOpZGl0aW9uLCBsJ2Vudm9pIGVzdCBpbW3DqWRpYXQuCiAgICBsZXQgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgIGxldCByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICBsZXQgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKSB7CiAgICAgIGlmIChyZWNlaXB0UHJldmlld09iamVjdFVybCkgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgIHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gcmVjZWlwdFByZXZpZXdPYmplY3RVcmw7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBSZW1wbGFjZXIgbGEgcGhvdG8iOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlc2V0UmVjZWlwdFVpKCkgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKTsKICAgICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICAgIH0KICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gIiI7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndSI7CiAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHJhbnNhY3Rpb25JZCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3RyYW5zYWN0aW9uSWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHJldHVybjsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGJsb2IpOwogICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAvLyBQYXMgZ3JhdmUgOiBsJ3V0aWxpc2F0ZXVyIHBldXQganVzdGUgcsOpZXNzYXllciBkJ291dnJpciBsYSBmaWNoZS4KICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRQaWNrQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gcmVjZWlwdEZpbGVJbnB1dC5jbGljaygpKTsKCiAgICByZWNlaXB0RmlsZUlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IHJlY2VpcHRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBpZiAoIWZpbGUudHlwZS5zdGFydHNXaXRoKCJpbWFnZS8iKSkgewogICAgICAgIHNob3dUb2FzdCgiQ2hvaXNpcyB1bmUgaW1hZ2UgKEpQRUcsIFBORywgV0VCUCBvdSBIRUlDKSIsIHRydWUpOwogICAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IDggKiAxMDI0ICogMTAyNCkgewogICAgICAgIHNob3dUb2FzdCgiSW1hZ2UgdHJvcCBsb3VyZGUgKDggTW8gbWF4aW11bSkiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGZpbGUpOwoKICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgIC8vIFRyYW5zYWN0aW9uIGTDqWrDoCBleGlzdGFudGUgOiBvbiBlbnZvaWUgdG91dCBkZSBzdWl0ZSwgaW5kw6lwZW5kYW1tZW50CiAgICAgICAgLy8gZHUgYm91dG9uICJFbnJlZ2lzdHJlciIgZHUgZm9ybXVsYWlyZS4KICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIGZpbGUpOwogICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgfSkudGhlbihhc3luYyAocmVzKSA9PiB7CiAgICAgICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8IGBFcnJldXIgSFRUUCAke3Jlcy5zdGF0dXN9YCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gdHJ1ZTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gZHUgcmXDp3UgZW5yZWdpc3Ryw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIC8vIE5vdXZlbGxlIHRyYW5zYWN0aW9uIHBhcyBlbmNvcmUgY3LDqcOpZSA6IG9uIGdhcmRlIGxlIGZpY2hpZXIgZGUgY8O0dMOpLAogICAgICAgIC8vIGlsIHNlcmEgZW52b3nDqSBqdXN0ZSBhcHLDqHMgbGEgY3LDqWF0aW9uICh2b2lyIGJ0bi1zYXZlKS4KICAgICAgICBwZW5kaW5nUmVjZWlwdEZpbGUgPSBmaWxlOwogICAgICB9CiAgICB9KTsKCiAgICByZWNlaXB0UmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBpZiAoZWRpdGluZ0lkICYmIGhhc0V4aXN0aW5nUmVjZWlwdCkgewogICAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgbGEgcGhvdG8gZGUgY2UgcmXDp3UgPyIpKSkgcmV0dXJuOwogICAgICAgIHRyeSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9L3JlY2VpcHRgLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICAgICAgc2hvd1RvYXN0KCJQaG90byBzdXBwcmltw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWNlaXB0TGlnaHRib3godHJhbnNhY3Rpb25JZCkgewogICAgICBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSkKICAgICAgICAudGhlbigocmVzKSA9PiB7CiAgICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCJJbXBvc3NpYmxlIGRlIGNoYXJnZXIgbGEgcGhvdG8iKTsKICAgICAgICAgIHJldHVybiByZXMuYmxvYigpOwogICAgICAgIH0pCiAgICAgICAgLnRoZW4oKGJsb2IpID0+IHsKICAgICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgICByZWNlaXB0TGlnaHRib3hJbWcuc3JjID0gdXJsOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB9KQogICAgICAgIC5jYXRjaCgoZXJyKSA9PiBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlUmVjZWlwdExpZ2h0Ym94KCkgewogICAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAocmVjZWlwdExpZ2h0Ym94SW1nLnNyYykgewogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdExpZ2h0Ym94SW1nLnNyYyk7CiAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9ICIiOwogICAgICB9CiAgICB9CgogICAgcmVjZWlwdExpZ2h0Ym94Q2xvc2VCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY2VpcHRMaWdodGJveCk7CiAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSByZWNlaXB0TGlnaHRib3hPdmVybGF5KSBjbG9zZVJlY2VpcHRMaWdodGJveCgpOwogICAgfSk7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgLy8gQ2F0w6lnb3JpZXMgY3LDqcOpZXMgcGFyIGwndXRpbGlzYXRldXIgZGVwdWlzIGxlIGJhbmRlYXUgZGUgc3VnZ2VzdGlvbgogICAgLy8gKHZvaXIgcGx1cyBiYXMpLCBldCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgOiBzdG9ja8OpZXMgY8O0dMOpIHNlcnZldXIKICAgIC8vICh0YWJsZXMgY3VzdG9tX2NhdGVnb3JpZXMgLyBkaXNtaXNzZWRfY2F0ZWdvcnlfc3VnZ2VzdGlvbnMpIHBsdXTDtHQKICAgIC8vIHF1ZSBkYW5zIGxlIG5hdmlnYXRldXIsIHBvdXIgc3VpdnJlIHN1ciB0b3VzIGxlcyBhcHBhcmVpbHMgKHTDqWzDqXBob25lLAogICAgLy8gdGFibGV0dGUsIG9yZGluYXRldXIpIHBsdXTDtHQgcXVlIGRlIG5lIG1hcmNoZXIgcXVlIGzDoCBvw7kgYyfDqXRhaXQgY3LDqcOpLgogICAgbGV0IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldCgpOwogICAgbGV0IGFsbEJ1ZGdldHMgPSBbXTsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQnVkZ2V0cygpIHsKICAgICAgdHJ5IHsKICAgICAgICBhbGxCdWRnZXRzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBidWRnZXRzIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1zYXZlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIHNhdmVBbGxCdWRnZXRzKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBPYmplY3RpZiBkJ8OpcGFyZ25lIG1lbnN1ZWwgKyBjb25zZWlscwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgbGV0IHNhdmluZ3NHb2FsID0gbnVsbDsgLy8geyBtb250aGx5X3RhcmdldCB9IG91IG51bGwgc2kgamFtYWlzIGNvbmZpZ3Vyw6kKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkU2F2aW5nc0dvYWwoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgc2F2aW5nc0dvYWwgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9zYXZpbmdzLWdvYWwiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZSBsJ29iamVjdGlmIGQnw6lwYXJnbmUgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IHNhdmluZ3NHb2FsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1nb2FsLWlucHV0Iik7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1nb2FsLXNhdmUtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IE51bWJlcihzYXZpbmdzR29hbElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIkluZGlxdWUgdW4gbW9udGFudCBkJ29iamVjdGlmIHZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICB0cnkgewogICAgICAgIHNhdmluZ3NHb2FsID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvc2F2aW5ncy1nb2FsIiwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgbW9udGhseV90YXJnZXQ6IGFtb3VudCB9KSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoIk9iamVjdGlmIGVucmVnaXN0csOpIik7CiAgICAgICAgcmVuZGVyU2F2aW5ncyhhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9KTsKCiAgICBmdW5jdGlvbiByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucykgewogICAgICBpZiAoc2F2aW5nc0dvYWwpIHNhdmluZ3NHb2FsSW5wdXQudmFsdWUgPSBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldDsKCiAgICAgIC8vIFNvbGRlIGR1IG1vaXMgZW4gY291cnMgKHJldmVudXMgLSBkw6lwZW5zZXMpLCB0b3V0IGNvbmZvbmR1LgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBsZXQgbW9udGhJbmNvbWUgPSAwOwogICAgICBsZXQgbW9udGhFeHBlbnNlcyA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gY3VycmVudE1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIG1vbnRoSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgbW9udGhFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBtb250aE5ldCA9IG1vbnRoSW5jb21lIC0gbW9udGhFeHBlbnNlczsKCiAgICAgIGNvbnN0IHByb2dyZXNzU2VjdGlvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iKTsKICAgICAgY29uc3QgcHJvZ3Jlc3NUZXh0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtdGV4dCIpOwogICAgICBjb25zdCBwcm9ncmVzc0JhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLWJhciIpOwogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgcHJvZ3Jlc3NTZWN0aW9uLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIGNvbnN0IHRhcmdldCA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwogICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWF4KDAsIE1hdGgubWluKChtb250aE5ldCAvIHRhcmdldCkgKiAxMDAsIDEwMCkpOwogICAgICAgIHByb2dyZXNzVGV4dC50ZXh0Q29udGVudCA9IGAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChtb250aE5ldCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0KX1gOwogICAgICAgIGxldCBjbHMgPSAib2siOwogICAgICAgIGlmIChtb250aE5ldCA8IDApIGNscyA9ICJvdmVyIjsKICAgICAgICBlbHNlIGlmIChtb250aE5ldCA8IHRhcmdldCkgY2xzID0gIndhcm5pbmciOwogICAgICAgIHByb2dyZXNzQmFyLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICBwcm9ncmVzc0Jhci5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCk7CiAgICB9CgogICAgLy8gQ29uc2VpbHMgOiBjcm9pc2UgZMOpcGFzc2VtZW50cyBkZSBidWRnZXQgKG9uZ2xldCBUYWJsZWF1IGRlIGJvcmQpIGV0CiAgICAvLyB0ZW5kYW5jZXMgcGFyIGNhdMOpZ29yaWUgcG91ciBwb2ludGVyIHZlcnMgY2UgcXVpIGFpZGUgbGUgcGx1cyDDoAogICAgLy8gYXR0ZWluZHJlIGwnb2JqZWN0aWYg4oCUIHBhcyB1bmUgSUEsIGp1c3RlIGRlcyByw6hnbGVzIHNpbXBsZXMgc3VyIGRlcwogICAgLy8gZG9ubsOpZXMgZMOpasOgIGNhbGN1bMOpZXMgYWlsbGV1cnMgZGFucyBsJ2FwcC4KICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCkgewogICAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtbGlzdCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtYWR2aWNlLWVtcHR5Iik7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgY29uc3QgYWR2aWNlID0gW107CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFsczogbW9udGhUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBjdXJyZW50TW9udGhLZXkpOwogICAgICBjb25zdCB0cmVuZHMgPSBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgY29uc3QgdHJlbmRCeUNhdGVnb3J5ID0gT2JqZWN0LmZyb21FbnRyaWVzKHRyZW5kcy5tYXAoKHQpID0+IFt0LmNhdGVnb3J5LCB0XSkpOwoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCwgdHJpw6llcyBwYXIgbW9udGFudCBkZQogICAgICAvLyBkw6lwYXNzZW1lbnQgZMOpY3JvaXNzYW50IOKAlCBjZSBzb250IGxlcyBsZXZpZXJzIGxlcyBwbHVzIHV0aWxlcy4KICAgICAgY29uc3Qgb3ZlckJ1ZGdldCA9IFtdOwogICAgICBmb3IgKGNvbnN0IGJ1ZGdldCBvZiBhbGxCdWRnZXRzKSB7CiAgICAgICAgY29uc3Qgc3BlbnQgPSBtb250aFRvdGFsc1tidWRnZXQuY2F0ZWdvcnldIHx8IDA7CiAgICAgICAgaWYgKHNwZW50ID4gYnVkZ2V0LmFtb3VudCkgewogICAgICAgICAgb3ZlckJ1ZGdldC5wdXNoKHsgY2F0ZWdvcnk6IGJ1ZGdldC5jYXRlZ29yeSwgc3BlbnQsIGJ1ZGdldDogYnVkZ2V0LmFtb3VudCwgb3Zlcjogc3BlbnQgLSBidWRnZXQuYW1vdW50IH0pOwogICAgICAgIH0KICAgICAgfQogICAgICBvdmVyQnVkZ2V0LnNvcnQoKGEsIGIpID0+IGIub3ZlciAtIGEub3Zlcik7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2Ygb3ZlckJ1ZGdldC5zbGljZSgwLCAzKSkgewogICAgICAgIGNvbnN0IGxhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeTsKICAgICAgICBjb25zdCB0cmVuZCA9IHRyZW5kQnlDYXRlZ29yeVtpdGVtLmNhdGVnb3J5XTsKICAgICAgICBsZXQgdGV4dCA9IGBUdSBhcyBkw6lwYXNzw6kgdG9uIGJ1ZGdldCA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0ub3Zlcil9IGNlIG1vaXMtY2kuYDsKICAgICAgICBpZiAodHJlbmQgJiYgdHJlbmQuZGlyZWN0aW9uID09PSAidXAiKSB7CiAgICAgICAgICB0ZXh0ICs9IGAgTGEgdGVuZGFuY2UgZXN0IMOgIGxhIGhhdXNzZSAoKyR7TWF0aC5yb3VuZCh0cmVuZC5yYXRpbyAqIDEwMCl9JSB2cyB0YSBtb3llbm5lKSDigJQgcsOpZHVpcmUgY2VzIGTDqXBlbnNlcyB0J2FpZGVyYWl0IGxlIHBsdXMgw6AgYXR0ZWluZHJlIHRvbiBvYmplY3RpZi5gOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0ZXh0ICs9IGAgRXNzYWllIGRlIHJhbWVuZXIgw6dhIHNvdXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5idWRnZXQpfSBsZSBtb2lzIHByb2NoYWluLmA7CiAgICAgICAgfQogICAgICAgIGFkdmljZS5wdXNoKHsgdHlwZTogIndhcm5pbmciLCBpY29uOiAi4pqg77iPIiwgdGV4dCB9KTsKICAgICAgfQoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gbmV0dGUgaGF1c3NlIG3Dqm1lIHNhbnMgYnVkZ2V0IGTDqXBhc3PDqSAob3Ugc2FucyBidWRnZXQKICAgICAgLy8gZMOpZmluaSBkdSB0b3V0KSA6IHVuIHNpZ25hbCB1dGlsZSBlbiBzb2kuCiAgICAgIGNvbnN0IHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCA9IHRyZW5kcwogICAgICAgIC5maWx0ZXIoKHQpID0+IHQuZGlyZWN0aW9uID09PSAidXAiICYmIHQuYXZlcmFnZSA+IDAgJiYgIW92ZXJCdWRnZXQuc29tZSgobykgPT4gby5jYXRlZ29yeSA9PT0gdC5jYXRlZ29yeSkpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGIucmF0aW8gLSBhLnJhdGlvKQogICAgICAgIC5zbGljZSgwLCAyKTsKICAgICAgZm9yIChjb25zdCB0IG9mIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCkgewogICAgICAgIGNvbnN0IGxhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeTsKICAgICAgICBhZHZpY2UucHVzaCh7CiAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICBpY29uOiAi8J+TiCIsCiAgICAgICAgICB0ZXh0OiBgVGVzIGTDqXBlbnNlcyBlbiA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IHNvbnQgZW4gaGF1c3NlIGRlICR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lIHBhciByYXBwb3J0IMOgIHRhIG1veWVubmUg4oCUIMOgIHN1cnZlaWxsZXIgc2kgdHUgdmV1eCDDqXBhcmduZXIgcGx1cy5gLAogICAgICAgIH0pOwogICAgICB9CgogICAgICAvLyBPYmplY3RpZiBhdHRlaW50IC8gZW4gYm9ubmUgdm9pZSBjZSBtb2lzLWNpLgogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgaWYgKG1vbnRoTmV0ID49IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KSB7CiAgICAgICAgICBhZHZpY2UudW5zaGlmdCh7CiAgICAgICAgICAgIHR5cGU6ICJwb3NpdGl2ZSIsCiAgICAgICAgICAgIGljb246ICLwn46JIiwKICAgICAgICAgICAgdGV4dDogYE9iamVjdGlmIGF0dGVpbnQgISBUdSBhcyBkw6lqw6AgbWlzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gZGUgY8O0dMOpIGNlIG1vaXMtY2ksIGF1LWRlbMOgIGRlIHRvbiBvYmplY3RpZiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCl9LmAsCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgaWYgKG92ZXJCdWRnZXQubGVuZ3RoID09PSAwICYmIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydC5sZW5ndGggPT09IDApIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogImluZm8iLAogICAgICAgICAgICBpY29uOiAi8J+RjSIsCiAgICAgICAgICAgIHRleHQ6IGBQYXMgZGUgZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCBjZSBtb2lzLWNpLiBJbCB0ZSByZXN0ZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCAtIG1vbnRoTmV0KX0gw6Agw6ljb25vbWlzZXIgcG91ciBhdHRlaW5kcmUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKGFkdmljZS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWR2aWNlKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gImFkdmljZS1jYXJkICIgKyBpdGVtLnR5cGU7CiAgICAgICAgY29uc3QgaWNvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBpY29uLmNsYXNzTmFtZSA9ICJhZHZpY2UtaWNvbiI7CiAgICAgICAgaWNvbi50ZXh0Q29udGVudCA9IGl0ZW0uaWNvbjsKICAgICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHRleHQuaW5uZXJIVE1MID0gaXRlbS50ZXh0OwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoaWNvbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZCh0ZXh0KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpIHsKICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiLCB7CiAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5LCBhbW91bnQgfSksCiAgICAgIH0pOwogICAgICBjb25zdCBpZHggPSBhbGxCdWRnZXRzLmZpbmRJbmRleCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gY2F0ZWdvcnkpOwogICAgICBpZiAoaWR4ID49IDApIGFsbEJ1ZGdldHNbaWR4XSA9IHVwZGF0ZWQ7CiAgICAgIGVsc2UgYWxsQnVkZ2V0cy5wdXNoKHVwZGF0ZWQpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVBbGxCdWRnZXRzKCkgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ1ZGdldHMtbGlzdCIpOwogICAgICBpZiAoIXdyYXApIHJldHVybjsKICAgICAgY29uc3QgaW5wdXRzID0gd3JhcC5xdWVyeVNlbGVjdG9yQWxsKCIuYnVkZ2V0LWlucHV0Iik7CiAgICAgIGNvbnN0IHRvU2F2ZSA9IFtdOwogICAgICBmb3IgKGNvbnN0IGlucHV0IG9mIGlucHV0cykgewogICAgICAgIGNvbnN0IHJhdyA9IGlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICBpZiAocmF3ID09PSAiIikgY29udGludWU7CiAgICAgICAgY29uc3QgYW1vdW50ID0gTnVtYmVyKHJhdyk7CiAgICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICAgIHNob3dUb2FzdCgiSW5kaXF1ZSB1biBtb250YW50IGRlIGJ1ZGdldCB2YWxpZGUgcG91ciAiICsgaW5wdXQuZGF0YXNldC5jYXRlZ29yeUxhYmVsLCB0cnVlKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdG9TYXZlLnB1c2goeyBjYXRlZ29yeTogaW5wdXQuZGF0YXNldC5jYXRlZ29yeSwgYW1vdW50IH0pOwogICAgICB9CiAgICAgIGlmICh0b1NhdmUubGVuZ3RoID09PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJBdWN1biBtb250YW50IMOgIGVucmVnaXN0cmVyIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IHNhdmVBbGxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1zYXZlLWFsbC1idG4iKTsKICAgICAgc2F2ZUFsbEJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgZm9yIChjb25zdCB7IGNhdGVnb3J5LCBhbW91bnQgfSBvZiB0b1NhdmUpIHsKICAgICAgICAgIGF3YWl0IHNhdmVCdWRnZXQoY2F0ZWdvcnksIGFtb3VudCk7CiAgICAgICAgfQogICAgICAgIHNob3dUb2FzdCgiQnVkZ2V0cyBlbnJlZ2lzdHLDqXMiKTsKICAgICAgICByZW5kZXJCdWRnZXRzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgc2F2ZUFsbEJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidWRnZXRzLWxpc3QiKTsKICAgICAgaWYgKCF3cmFwKSByZXR1cm47CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHsgdG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgY3VycmVudE1vbnRoS2V5KTsKCiAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlKSB7CiAgICAgICAgY29uc3QgYnVkZ2V0ID0gYWxsQnVkZ2V0cy5maW5kKChiKSA9PiBiLmNhdGVnb3J5ID09PSB2YWx1ZSk7CiAgICAgICAgY29uc3Qgc3BlbnQgPSB0b3RhbHNbdmFsdWVdIHx8IDA7CgogICAgICAgIGNvbnN0IHJvdyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHJvdy5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdyI7CgogICAgICAgIGNvbnN0IGhlYWQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBoZWFkLmNsYXNzTmFtZSA9ICJidWRnZXQtcm93LWhlYWQiOwoKICAgICAgICBjb25zdCBuYW1lU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBuYW1lU3Bhbi5jbGFzc05hbWUgPSAiYnVkZ2V0LWNhdC1uYW1lIjsKICAgICAgICBuYW1lU3Bhbi50ZXh0Q29udGVudCA9IGxhYmVsOwoKICAgICAgICBjb25zdCBhbW91bnRzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudHMuY2xhc3NOYW1lID0gImJ1ZGdldC1hbW91bnRzIjsKICAgICAgICBjb25zdCBzcGVudFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgc3BlbnRTcGFuLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNwZW50KSArICIgLyAiOwogICAgICAgIGNvbnN0IGlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBpbnB1dC50eXBlID0gIm51bWJlciI7CiAgICAgICAgaW5wdXQuY2xhc3NOYW1lID0gImJ1ZGdldC1pbnB1dCI7CiAgICAgICAgaW5wdXQubWluID0gIjAiOwogICAgICAgIGlucHV0LnN0ZXAgPSAiMSI7CiAgICAgICAgaW5wdXQucGxhY2Vob2xkZXIgPSAi4oCUIjsKICAgICAgICBpbnB1dC5kYXRhc2V0LmNhdGVnb3J5ID0gdmFsdWU7CiAgICAgICAgaW5wdXQuZGF0YXNldC5jYXRlZ29yeUxhYmVsID0gbGFiZWw7CiAgICAgICAgaWYgKGJ1ZGdldCkgaW5wdXQudmFsdWUgPSBidWRnZXQuYW1vdW50OwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoc3BlbnRTcGFuKTsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKGlucHV0KTsKCiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChhbW91bnRzKTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaGVhZCk7CgogICAgICAgIGlmIChidWRnZXQpIHsKICAgICAgICAgIGNvbnN0IHRyYWNrID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICB0cmFjay5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci10cmFjayI7CiAgICAgICAgICBjb25zdCBmaWxsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjb25zdCByYXRpbyA9IHNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWluKHJhdGlvICogMTAwLCAxMDApOwogICAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgICBpZiAocmF0aW8gPj0gMSkgY2xzID0gIm92ZXIiOwogICAgICAgICAgZWxzZSBpZiAocmF0aW8gPj0gMC43KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgICBmaWxsLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICAgIGZpbGwuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgICAgICB0cmFjay5hcHBlbmRDaGlsZChmaWxsKTsKICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZCh0cmFjayk7CiAgICAgICAgfQoKICAgICAgICB3cmFwLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIik7CiAgICAgICAgZm9yIChjb25zdCB7IHR5cGUsIHZhbHVlLCBsYWJlbCB9IG9mIGl0ZW1zKSB7CiAgICAgICAgICBpZiAoY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSAmJiAhY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHZhbHVlKSkgewogICAgICAgICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICAgICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGVzIGNhdMOpZ29yaWVzIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBrZXlzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIik7CiAgICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMgPSBuZXcgU2V0KGtleXMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIHVuZSBzdWdnZXN0aW9uIGTDqWrDoCB2dWUgcsOpYXBwYXJhw650IHVuZSBmb2lzLgogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2x1Z2lmeUNhdGVnb3J5KGxhYmVsKSB7CiAgICAgIHJldHVybiAoCiAgICAgICAgbGFiZWwKICAgICAgICAgIC5ub3JtYWxpemUoIk5GRCIpLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpIC8vIGVubMOodmUgbGVzIGFjY2VudHMKICAgICAgICAgIC50b0xvd2VyQ2FzZSgpCiAgICAgICAgICAudHJpbSgpCiAgICAgICAgICAucmVwbGFjZSgvW15hLXowLTldKy9nLCAiXyIpCiAgICAgICAgICAucmVwbGFjZSgvXl8rfF8rJC9nLCAiIikgfHwgImF1dHJlIgogICAgICApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVDdXN0b21DYXRlZ29yeSh0eXBlLCB2YWx1ZSwgbGFiZWwpIHsKICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkNhdMOpZ29yaWUgY3LDqcOpZSBpY2ksIG1haXMgcGFzIHNhdXZlZ2FyZMOpZSBzdXIgbGUgc2VydmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBjdXJyZW5jeUZvcm1hdHRlciA9IG5ldyBJbnRsLk51bWJlckZvcm1hdCgiZnItRlIiLCB7IHN0eWxlOiAiY3VycmVuY3kiLCBjdXJyZW5jeTogIkVVUiIgfSk7CiAgICBjb25zdCBkYXRlRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBkYXk6ICJudW1lcmljIiwgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKCiAgICBmdW5jdGlvbiBzaG93VG9hc3QobWVzc2FnZSwgaXNFcnJvciA9IGZhbHNlKSB7CiAgICAgIGNvbnN0IHRvYXN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIHRvYXN0LmNsYXNzTmFtZSA9ICJ0b2FzdCIgKyAoaXNFcnJvciA/ICIgZXJyb3IiIDogIiIpOwogICAgICB0b2FzdC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQodG9hc3QpOwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRvYXN0LnJlbW92ZSgpLCAzMDAwKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcGlGZXRjaChwYXRoLCBvcHRpb25zID0ge30pIHsKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gocGF0aCwgewogICAgICAgIC4uLm9wdGlvbnMsCiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgIlgtQVBJLUtleSI6IEFQSV9LRVksCiAgICAgICAgICAuLi4ob3B0aW9ucy5ib2R5ID8geyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0gOiB7fSksCiAgICAgICAgICAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KSwKICAgICAgICB9LAogICAgICB9KTsKICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAvLyByZXMuc3RhdHVzVGV4dCBlc3Qgc291dmVudCB2aWRlIChuYXZpZ2F0ZXVycyBlbiBIVFRQLzIsIHV0aWxpc8OpIHBhcgogICAgICAgIC8vIFZlcmNlbCksIGRvbmMgb24gbmUgcGV1dCBwYXMgY29tcHRlciBkZXNzdXMgY29tbWUgbWVzc2FnZSBwYXIKICAgICAgICAvLyBkw6lmYXV0IDogb24gcmV0b21iZSBzdXIgbGUgY29kZSBIVFRQIHBvdXIgbmUgamFtYWlzIGFmZmljaGVyIHVuCiAgICAgICAgLy8gbWVzc2FnZSBkJ2VycmV1ciB2aWRlLgogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dCB8fCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgZGV0YWlsID0gZGF0YS5kZXRhaWwgfHwgZGV0YWlsOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFR5cGUodHlwZSkgewogICAgICBjdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHR5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgY2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgdHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFR5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuTW9kYWwodHggPSBudWxsKSB7CiAgICAgIC8vIE9uIGRpc3Rpbmd1ZSAibW9kaWZpZXIiICh0eCBhIHVuIGlkLCB2cmFpZSDDqWRpdGlvbiBlbiBiYXNlKSBkZQogICAgICAvLyAicHLDqS1yZW1wbGlyIMOgIHBhcnRpciBkJ3VuIG1vZMOobGUiIChkdXBsaWNhdGlvbiA6IHR4IGZvdXJuaSBtYWlzIHNhbnMKICAgICAgLy8gaWQgPT4gb24gY3LDqWUgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIGF1IGxpZXUgZCfDqWNyYXNlciBsJ29yaWdpbmFsZSkuCiAgICAgIGNvbnN0IGlzRWRpdCA9IEJvb2xlYW4odHggJiYgdHguaWQpOwogICAgICBlZGl0aW5nSWQgPSBpc0VkaXQgPyB0eC5pZCA6IG51bGw7CiAgICAgIG1vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJNb2RpZmllciBsYSB0cmFuc2FjdGlvbiIgOiAiTm91dmVsbGUgdHJhbnNhY3Rpb24iOwogICAgICBzYXZlQnRuLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIkVucmVnaXN0cmVyIiA6ICJBam91dGVyIjsKICAgICAgc2V0VHlwZSh0eCA/IHR4LnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICBhbW91bnRJbnB1dC52YWx1ZSA9IHR4ID8gdHguYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgdHggPyB0eC5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICBkZXNjcmlwdGlvbklucHV0LnZhbHVlID0gdHggPyAodHguZGVzY3JpcHRpb24gfHwgIiIpIDogIiI7CiAgICAgIGRhdGVJbnB1dC52YWx1ZSA9IHR4ID8gdHguZXhwZW5zZV9kYXRlIDogdG9kYXlJc28oKTsKCiAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIGlmIChpc0VkaXQgJiYgdHgucmVjZWlwdF9wYXRoKSB7CiAgICAgICAgbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHguaWQpOwogICAgICB9CgogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIGFtb3VudElucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpIHsKICAgICAgLy8gTcOqbWUgbW9udGFudC9jYXTDqWdvcmllL2Rlc2NyaXB0aW9uLCBtYWlzIGRhdMOpIGQnYXVqb3VyZCdodWkgZXQgc2FucwogICAgICAvLyBpZCA6IGxhIHNhdXZlZ2FyZGUgY3LDqWVyYSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gKHZvaXIgb3Blbk1vZGFsKS4KICAgICAgb3Blbk1vZGFsKHsgLi4udHgsIGlkOiBudWxsLCBleHBlbnNlX2RhdGU6IHRvZGF5SXNvKCkgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VNb2RhbCgpIHsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nSWQgPSBudWxsOwogICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItYWRkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInJlY3VycmluZyIpIG9wZW5SZWN1cnJpbmdNb2RhbCgpOwogICAgICBlbHNlIG9wZW5Nb2RhbCgpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VNb2RhbCk7CiAgICBvdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXlFbCkgY2xvc2VNb2RhbCgpOyB9KTsKCiAgICBzYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KGFtb3VudElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBjdXJyZW50VHlwZSwKICAgICAgICBhbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5SW5wdXQudmFsdWUsCiAgICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uSW5wdXQudmFsdWUudHJpbSgpIHx8IG51bGwsCiAgICAgICAgZXhwZW5zZV9kYXRlOiBkYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGN1cnJlbnRUeXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUgYWpvdXTDqSIgOiAiRMOpcGVuc2UgYWpvdXTDqWUiKTsKICAgICAgICAgIGlmIChwZW5kaW5nUmVjZWlwdEZpbGUpIHsKICAgICAgICAgICAgLy8gTGEgcGhvdG8gYSDDqXTDqSBjaG9pc2llIGF2YW50IHF1ZSBsYSB0cmFuc2FjdGlvbiBuJ2V4aXN0ZSA6IG9uCiAgICAgICAgICAgIC8vIGwnZW52b2llIG1haW50ZW5hbnQgcXUnb24gYSB1biBpZC4KICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YSgpOwogICAgICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIHBlbmRpbmdSZWNlaXB0RmlsZSk7CiAgICAgICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7Y3JlYXRlZC5pZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gY3LDqcOpZSwgbWFpcyBsJ2Vudm9pIGRlIGxhIHBob3RvIGEgw6ljaG91w6kiLCB0cnVlKTsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBjbG9zZU1vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVUcmFuc2FjdGlvbihpZCkgewogICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGNldHRlIHRyYW5zYWN0aW9uID8iKSkpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhdXggZ2xvYmF1eCAoU29sZGUvRMOpcGVuc2VzL1JldmVudXMpIDogY2FsY3Vsw6lzIHN1ciBUT1VURVMgbGVzCiAgICAvLyB0cmFuc2FjdGlvbnMsIGluZMOpcGVuZGFtbWVudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUg4oCUIHVuIGZpbHRyZQogICAgLy8gc2VydCDDoCBjaGVyY2hlciBkYW5zIGxhIGxpc3RlLCBwYXMgw6AgcmVjYWxjdWxlciBsZSBzb2xkZSByw6llbC4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGJhbGFuY2UgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYmFsYW5jZSk7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAoYmFsYW5jZSA+PSAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBzdW1tYXJ5RXhwZW5zZXNFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgc3VtbWFyeUluY29tZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgIH0KCiAgICAvLyBDb25zdHJ1Y3Rpb24gZGUgbGEgbGlzdGUgZGUgY2FydGVzIGFmZmljaMOpZSBkYW5zIGwnb25nbGV0IEhpc3RvcmlxdWUg4oCUCiAgICAvLyByZcOnb2l0IGTDqWrDoCBsYSBsaXN0ZSBmaWx0csOpZSAodm9pciBhcHBseUhpc3RvcnlGaWx0ZXJzKS4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9uTGlzdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBpZiAodHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBlbXB0eVN0YXRlRWwudGV4dENvbnRlbnQgPSBhbGxUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwCiAgICAgICAgICA/ICJSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LiIKICAgICAgICAgIDogIkF1Y3VuIHLDqXN1bHRhdCBwb3VyIGNlcyBmaWx0cmVzLiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInR4LWNhcmQgIiArIHR4LnR5cGU7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJ0eC1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJ0eC10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gInR4LWRhdGUiOwogICAgICAgIGRhdGVTcGFuLnRleHRDb250ZW50ID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUodHguZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CiAgICAgICAgaWYgKHR4LnJlY3VycmluZ19leHBlbnNlX2lkKSB7CiAgICAgICAgICBjb25zdCByZWNCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIHJlY0JhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWN1cnJpbmctYmFkZ2UiOwogICAgICAgICAgcmVjQmFkZ2UudGV4dENvbnRlbnQgPSAi8J+UgSI7CiAgICAgICAgICByZWNCYWRnZS50aXRsZSA9ICJDcsOpw6llIGF1dG9tYXRpcXVlbWVudCBkZXB1aXMgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSI7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQocmVjQmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAodHgucmVjZWlwdF9wYXRoKSB7CiAgICAgICAgICBjb25zdCByZWNlaXB0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UuY2xhc3NOYW1lID0gInR4LXJlY2VpcHQtYmFkZ2UiOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnRleHRDb250ZW50ID0gIvCfp74iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnRpdGxlID0gIlZvaXIgbGEgcGhvdG8gZHUgcmXDp3UiOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1Iik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjZWlwdExpZ2h0Ym94KHR4LmlkKSk7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQocmVjZWlwdEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJ0eC1kZXNjcmlwdGlvbiI7CiAgICAgICAgZGVzYy50ZXh0Q29udGVudCA9IHR4LmRlc2NyaXB0aW9uIHx8ICLigJQiOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAidHgtYW1vdW50ICIgKyB0eC50eXBlOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gKHR4LnR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodHguYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCh0eCkpOwogICAgICAgIGNvbnN0IGR1cGxpY2F0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGR1cGxpY2F0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5OLIjsKICAgICAgICBkdXBsaWNhdGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIkR1cGxpcXVlciIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVRyYW5zYWN0aW9uKHR4LmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGR1cGxpY2F0ZUJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUsOpc3Vtw6kgImNldHRlIHNlbWFpbmUiIChpbmTDqXBlbmRhbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3RhcnRPZldlZWtJc28oKSB7CiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IGRheSA9IG5vdy5nZXREYXkoKTsgLy8gMCA9IGRpbWFuY2hlLCAxID0gbHVuZGksIC4uLgogICAgICBjb25zdCBkaWZmVG9Nb25kYXkgPSBkYXkgPT09IDAgPyA2IDogZGF5IC0gMTsKICAgICAgY29uc3QgbW9uZGF5ID0gbmV3IERhdGUobm93KTsKICAgICAgbW9uZGF5LnNldERhdGUobm93LmdldERhdGUoKSAtIGRpZmZUb01vbmRheSk7CiAgICAgIGNvbnN0IHR6ID0gbW9uZGF5LmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUobW9uZGF5LmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHN0YXJ0ID0gc3RhcnRPZldlZWtJc28oKTsKICAgICAgY29uc3QgdG9kYXkgPSB0b2RheUlzbygpOwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiZXhwZW5zZSIgJiYgdHguZXhwZW5zZV9kYXRlID49IHN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8PSB0b2RheSkgewogICAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ3ZWVrLXN1bW1hcnkiKS50ZXh0Q29udGVudCA9CiAgICAgICAgYENldHRlIHNlbWFpbmUgKGRlcHVpcyBsdW5kaSkgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbCl9IGTDqXBlbnPDqXNgOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFJlY2hlcmNoZSBldCBmaWx0cmVzIGRhbnMgbCdoaXN0b3JpcXVlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIE9iamVjdC5lbnRyaWVzKGFsbENhdGVnb3J5TGFiZWxzKSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gYXBwbHlIaXN0b3J5RmlsdGVycygpIHsKICAgICAgY29uc3Qgc2VhcmNoID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1zZWFyY2giKS52YWx1ZS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgY2F0ZWdvcnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVTdGFydCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1zdGFydCIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlRW5kID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLWVuZCIpLnZhbHVlOwoKICAgICAgY29uc3QgZmlsdGVyZWQgPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKCh0eCkgPT4gewogICAgICAgIGlmIChjYXRlZ29yeSAmJiB0eC5jYXRlZ29yeSAhPT0gY2F0ZWdvcnkpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZVN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8IGRhdGVTdGFydCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlRW5kICYmIHR4LmV4cGVuc2VfZGF0ZSA+IGRhdGVFbmQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoc2VhcmNoKSB7CiAgICAgICAgICBjb25zdCBoYXlzdGFjayA9IGAke3R4LmRlc2NyaXB0aW9uIHx8ICIifSAke2FsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeX1gLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgICBpZiAoIWhheXN0YWNrLmluY2x1ZGVzKHNlYXJjaCkpIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHRydWU7CiAgICAgIH0pOwogICAgICByZW5kZXJUcmFuc2FjdGlvbkxpc3QoZmlsdGVyZWQpOwogICAgfQoKICAgIFsiZmlsdGVyLXNlYXJjaCIsICJmaWx0ZXItY2F0ZWdvcnkiLCAiZmlsdGVyLWRhdGUtc3RhcnQiLCAiZmlsdGVyLWRhdGUtZW5kIl0uZm9yRWFjaCgoaWQpID0+IHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgYXBwbHlIaXN0b3J5RmlsdGVycyk7CiAgICB9KTsKCiAgICBsZXQgYWxsVHJhbnNhY3Rpb25zID0gW107CiAgICBsZXQgY3VycmVudFZpZXcgPSAiaGlzdG9yeSI7CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFRyYW5zYWN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB0cmFuc2FjdGlvbnMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiKTsKICAgICAgICBhbGxUcmFuc2FjdGlvbnMgPSB0cmFuc2FjdGlvbnM7CiAgICAgICAgcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKTsKICAgICAgICBhcHBseUhpc3RvcnlGaWx0ZXJzKCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3ModHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBPbmdsZXRzIChIaXN0b3JpcXVlIC8gVGFibGVhdSBkZSBib3JkKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3dpdGNoVmlldyh2aWV3KSB7CiAgICAgIGN1cnJlbnRWaWV3ID0gdmlldzsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImhpc3RvcnkiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gInNhdmluZ3MiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctaGlzdG9yeSIpLnN0eWxlLmRpc3BsYXkgPSB2aWV3ID09PSAiaGlzdG9yeSIgPyAiYmxvY2siIDogIm5vbmUiOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1zYXZpbmdzIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGlmICh2aWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh2aWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImhpc3RvcnkiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZGFzaGJvYXJkIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoInJlY3VycmluZyIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJleHBvcnQiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXNhdmluZ3MiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoInNhdmluZ3MiKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gVGFibGVhdSBkZSBib3JkIChncmFwaGlxdWVzKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbW9udGhGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAibG9uZyIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IG1vbnRoU2hvcnRGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBDSEFSVF9DT0xPUlMgPSBbIiMzYjgyZjYiLCAiIzIyYzU1ZSIsICIjZWY0NDQ0IiwgIiNmNTllMGIiLCAiI2E4NTVmNyIsICIjMTRiOGE2IiwgIiNlYzQ4OTkiLCAiIzY0NzQ4YiJdOwoKICAgIGxldCBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsKICAgIGxldCBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsKICAgIGxldCBldm9sdXRpb25DaGFydCA9IG51bGw7CgogICAgZnVuY3Rpb24gbW9udGhLZXlPZihleHBlbnNlRGF0ZSkgewogICAgICByZXR1cm4gZXhwZW5zZURhdGUuc2xpY2UoMCwgNyk7IC8vICJZWVlZLU1NIgogICAgfQoKICAgIC8vIFVuZSBjaGFyZ2UgcsOpY3VycmVudGUgY29tcHRlIHBvdXIgdW4gbW9pcyBkb25uw6kgc2kgY2UgbW9pcyBlc3QgZGFucyBzYQogICAgLy8gcMOpcmlvZGUgZCdhY3Rpdml0w6kgOiBwYXMgYXZhbnQgc2EgZGF0ZSBkZSBkw6lidXQgKHNpIHBvc8OpZSksIHBhcyBhcHLDqHMKICAgIC8vIGxlIG1vaXMgZGUgc2EgZGF0ZSBkZSBmaW4gKHNpIHBvc8OpZSkuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkgewogICAgICBpZiAoaXRlbS5zdGFydF9kYXRlICYmIG1vbnRoS2V5IDwgaXRlbS5zdGFydF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChpdGVtLmVuZF9kYXRlICYmIG1vbnRoS2V5ID4gaXRlbS5lbmRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICAvLyBKb3VyIGR1IG1vaXMganVzcXUnYXVxdWVsIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgZXN0IGNvbnNpZMOpcsOpZSBjb21tZQogICAgLy8gImTDqWrDoCBwcsOpbGV2w6llIiBwb3VyIGxlIG1vaXMgYG1vbnRoS2V5YCA6IHRvdXMgbGVzIGpvdXJzIHBvdXIgdW4gbW9pcwogICAgLy8gZMOpasOgIHBhc3PDqSwgYXVjdW4gcG91ciB1biBtb2lzIGZ1dHVyLCBldCBsZSBqb3VyIGR1IGpvdXIgcG91ciBsZSBtb2lzCiAgICAvLyBlbiBjb3Vycy4gUGVybWV0IGRlIGRpc3Rpbmd1ZXIgY2UgcXVpIGVzdCBkw6lqw6AgYXJyaXbDqSBkZSBjZSBxdWkgZXN0CiAgICAvLyBzZXVsZW1lbnQgcHLDqXZ1IChleCA6IHVuIGFib25uZW1lbnQgcHLDqWxldsOpIGxlIDI1LCBvbiBlc3QgbGUgMikuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpIHsKICAgICAgaWYgKG1vbnRoS2V5IDwgY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMzE7CiAgICAgIGlmIChtb250aEtleSA+IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDA7CiAgICAgIHJldHVybiB0b2RheURheTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDApIG1vbnRoU2V0LmFkZChtb250aEtleU9mKHRvZGF5SXNvKCkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9ICIiOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9ICJBdWN1bmUgZG9ubsOpZSI7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIHNlbGVjdC52YWx1ZSA9IG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBtb250aHNbMF07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiKTsKICAgICAgY29uc3QgdXBjb21pbmdOb3RlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiKTsKICAgICAgY29uc3QgdXBjb21pbmdUZXh0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLXRleHQiKTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVW4gc2V1bCBzb2xkZSBuZXQgIsOgIHZlbmlyIiAocmV2ZW51cyByw6ljdXJyZW50cyDDoCB2ZW5pciBtb2lucyBkw6lwZW5zZXMKICAgICAgLy8gcsOpY3VycmVudGVzIMOgIHZlbmlyKSwgcGx1dMO0dCBxdWUgZGV1eCBjaGlmZnJlcyBzw6lwYXLDqXMgOiBwbHVzIHNpbXBsZQogICAgICAvLyDDoCBsaXJlIGQndW4gY291cCBkJ8WTaWwuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lIHNvbnQgUEFTCiAgICAgIC8vIGFqb3V0w6llcyBpY2kgOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlIHZyYWllcyB0cmFuc2FjdGlvbnMKICAgICAgLy8gKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcyBkYW5zIGB0b3RhbHNgCiAgICAgIC8vIGNpLWRlc3N1cyDigJQgbGVzIGFqb3V0ZXIgw6Agbm91dmVhdSBsZXMgY29tcHRlcmFpdCBlbiBkb3VibGUuCiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSBjdXRvZmYpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLnR5cGUgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgY29uc3QgbmV0VXBjb21pbmcgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgaWYgKG5ldFVwY29taW5nICE9PSAwKSB7CiAgICAgICAgY29uc3Qgc2lnbiA9IG5ldFVwY29taW5nID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICAgIHVwY29taW5nVGV4dEVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0VXBjb21pbmcpKX0gw6AgdmVuaXJgOwogICAgICAgIHVwY29taW5nTm90ZUVsLnRpdGxlID0gIlLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzL3Jlw6d1ZXMgY2UgbW9pcy1jaSAocmV2ZW51cyBtb2lucyBkw6lwZW5zZXMpIjsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QudG9nZ2xlKCJwb3NpdGl2ZSIsIG5ldFVwY29taW5nID4gMCk7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIGlmIChjYXRlZ29yeUNoYXJ0KSB7IGNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICAvLyBNw6ptZSBwcmluY2lwZSBxdWUgcmVuZGVyQ2F0ZWdvcnlDaGFydCwgY8O0dMOpIHJldmVudXMg4oCUIHBhcyBkZSBub3RlICLDoAogICAgLy8gdmVuaXIiIGljaSwgZWxsZSByZXN0ZSB1bmlxdWVtZW50IHN1ciBsZSBjYW1lbWJlcnQgZGVzIGTDqXBlbnNlcyBwb3VyCiAgICAvLyBuZSBwYXMgYWZmaWNoZXIgbGUgbcOqbWUgY2hpZmZyZSBuZXQgw6AgZGV1eCBlbmRyb2l0cy4KICAgIGZ1bmN0aW9uIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtaW5jb21lLWNhdGVnb3JpZXMtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiaW5jb21lIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBpZiAoaW5jb21lQ2F0ZWdvcnlDaGFydCkgeyBpbmNvbWVDYXRlZ29yeUNoYXJ0LmRlc3Ryb3koKTsgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiZG91Z2hudXQiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBkYXRhLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGxhYmVscy5tYXAoKF8sIGkpID0+IENIQVJUX0NPTE9SU1tpICUgQ0hBUlRfQ09MT1JTLmxlbmd0aF0pLAogICAgICAgICAgICBib3JkZXJDb2xvcjogIiMxYTFkMjQiLAogICAgICAgICAgICBib3JkZXJXaWR0aDogMiwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgcG9zaXRpb246ICJib3R0b20iLCBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiwgYm94V2lkdGg6IDEyLCBwYWRkaW5nOiAxMiwgZm9udDogeyBzaXplOiAxMSB9IH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkKX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1ldm9sdXRpb24iKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5Iik7CgogICAgICBjb25zdCBtb250aGx5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3Qga2V5ID0gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpOwogICAgICAgIGlmICghbW9udGhseVtrZXldKSBtb250aGx5W2tleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICAgIG1vbnRobHlba2V5XVt0eC50eXBlXSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBUb3Vqb3VycyBpbmNsdXJlIGxlIG1vaXMgZW4gY291cnMgKG3Dqm1lIHNhbnMgdHJhbnNhY3Rpb24pIHMnaWwgZXhpc3RlCiAgICAgIC8vIGRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgcG91ciBxdSdpbCBhcHBhcmFpc3NlIHNhbnMgYXR0ZW5kcmUgbGEKICAgICAgLy8gcHJlbWnDqHJlIHRyYW5zYWN0aW9uIGR1IG1vaXMuIExlcyBjaGFyZ2VzIGTDqWrDoCBwcsOpbGV2w6llcy9yZcOndWVzIG5lCiAgICAgIC8vIHNvbnQgcGx1cyBham91dMOpZXMgaWNpIMOgIGxhIG1haW4gOiBlbGxlcyBleGlzdGVudCBkw6lzb3JtYWlzIGNvbW1lIGRlCiAgICAgIC8vIHZyYWllcyB0cmFuc2FjdGlvbnMgKGNyw6nDqWVzIGPDtHTDqSBzZXJ2ZXVyKSBldCBzb250IGRvbmMgZMOpasOgIGNvbXB0w6llcwogICAgICAvLyBkYW5zIGBtb250aGx5YCB2aWEgbGEgYm91Y2xlIHN1ciBgdHJhbnNhY3Rpb25zYCBjaS1kZXNzdXMg4oCUIGNlIHF1aQogICAgICAvLyBuJ2VzdCBwYXMgZW5jb3JlIGFycml2w6kgZXN0IHLDqXN1bcOpIGFpbGxldXJzIChzb2xkZSBuZXQgIsOgIHZlbmlyIikuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCAmJiAhbW9udGhseVtjdXJyZW50TW9udGhLZXldKSB7CiAgICAgICAgbW9udGhseVtjdXJyZW50TW9udGhLZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgfQogICAgICBjb25zdCBtb250aHMgPSBPYmplY3Qua2V5cyhtb250aGx5KS5zb3J0KCk7CgogICAgICBpZiAoZXZvbHV0aW9uQ2hhcnQpIHsgZXZvbHV0aW9uQ2hhcnQuZGVzdHJveSgpOyBldm9sdXRpb25DaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjb25zdCBsYWJlbHMgPSBtb250aHMubWFwKChrZXkpID0+IHsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICByZXR1cm4gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgfSk7CgogICAgICBjb25zdCBkYXRhc2V0cyA9IFsKICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5leHBlbnNlKSwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICB7IGxhYmVsOiAiUmV2ZW51cyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uaW5jb21lKSwgYmFja2dyb3VuZENvbG9yOiAiIzIyYzU1ZSIgfSwKICAgICAgXTsKCiAgICAgIGV2b2x1dGlvbkNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJiYXIiLAogICAgICAgIGRhdGE6IHsgbGFiZWxzLCBkYXRhc2V0cyB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9LCBiZWdpbkF0WmVybzogdHJ1ZSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5kYXRhc2V0LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQueSl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbXBhcmVyIGRldXggbW9pcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHNlbGVjdEEgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIik7CiAgICAgIGNvbnN0IHNlbGVjdEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIik7CgogICAgICBmb3IgKGNvbnN0IHNlbGVjdCBvZiBbc2VsZWN0QSwgc2VsZWN0Ql0pIHsKICAgICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBpZiAobW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpKSBzZWxlY3QudmFsdWUgPSBwcmV2aW91c1ZhbHVlOwogICAgICB9CiAgICAgIC8vIFBhciBkw6lmYXV0IDogbW9pcyBlbiBjb3VycyB2cyBtb2lzIHByw6ljw6lkZW50LCBzaSBsZXMgZGV1eCBleGlzdGVudC4KICAgICAgaWYgKCFzZWxlY3RBLnZhbHVlICYmIG1vbnRocy5sZW5ndGggPiAwKSBzZWxlY3RBLnZhbHVlID0gbW9udGhzWzBdOwogICAgICBpZiAoIXNlbGVjdEIudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDEpIHNlbGVjdEIudmFsdWUgPSBtb250aHNbMV07CiAgICB9CgogICAgZnVuY3Rpb24gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIG1vbnRoS2V5KSB7CiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgcmV0dXJuIHsgdG90YWxzLCB0b3RhbCB9OwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLWVtcHR5Iik7CiAgICAgIGNvbnN0IG1vbnRoQSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS52YWx1ZTsKICAgICAgY29uc3QgbW9udGhCID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLnZhbHVlOwoKICAgICAgaWYgKCFtb250aEEgfHwgIW1vbnRoQikgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgY29uc3QgeyB0b3RhbHM6IHRvdGFsc0EsIHRvdGFsOiBncmFuZEEgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHMoYWxsVHJhbnNhY3Rpb25zLCBtb250aEEpOwogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQiwgdG90YWw6IGdyYW5kQiB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQik7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBbLi4ubmV3IFNldChbLi4uT2JqZWN0LmtleXModG90YWxzQSksIC4uLk9iamVjdC5rZXlzKHRvdGFsc0IpXSldLnNvcnQoCiAgICAgICAgKGEsIGIpID0+ICh0b3RhbHNCW2JdIHx8IDApIC0gKHRvdGFsc0FbYV0gfHwgMCkKICAgICAgKTsKCiAgICAgIGNvbnN0IFt5YSwgbWFdID0gbW9udGhBLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IFt5YiwgbWJdID0gbW9udGhCLnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgIGNvbnN0IGxhYmVsQSA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHlhLCBtYSAtIDEsIDEpKTsKICAgICAgY29uc3QgbGFiZWxCID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWIsIG1iIC0gMSwgMSkpOwoKICAgICAgLy8gRGlmZiA9IG1vbnRhbnQgZHUgbW9pcyBCIG1vaW5zIGNlbHVpIGR1IG1vaXMgQS4gUG91ciBkZXMgZMOpcGVuc2VzLAogICAgICAvLyBkw6lwZW5zZXIgUExVUyAoZGlmZiBwb3NpdGlmKSBlc3QgbGEgbWF1dmFpc2Ugbm91dmVsbGUg4oaSIHJvdWdlIDsgZW4KICAgICAgLy8gZMOpcGVuc2VyIE1PSU5TIChkaWZmIG7DqWdhdGlmKSDihpIgdmVydC4KICAgICAgZnVuY3Rpb24gZGlmZkNlbGwoYSwgYikgewogICAgICAgIGNvbnN0IGRpZmYgPSBiIC0gYTsKICAgICAgICBpZiAoTWF0aC5hYnMoZGlmZikgPCAwLjAxKSByZXR1cm4gYDx0ZD7igJQ8L3RkPmA7CiAgICAgICAgY29uc3QgY2xzID0gZGlmZiA+IDAgPyAiZGlmZi1uZWdhdGl2ZSIgOiAiZGlmZi1wb3NpdGl2ZSI7CiAgICAgICAgcmV0dXJuIGA8dGQgY2xhc3M9IiR7Y2xzfSI+JHtkaWZmID4gMCA/ICIrIiA6ICIifSR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGRpZmYpfTwvdGQ+YDsKICAgICAgfQoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD4ke2xhYmVsQX08L3RoPjx0aD4ke2xhYmVsQn08L3RoPjx0aD5EaWZmw6lyZW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYSA9IHRvdGFsc0FbY2F0XSB8fCAwOwogICAgICAgIGNvbnN0IGIgPSB0b3RhbHNCW2NhdF0gfHwgMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7YWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXR9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYil9PC90ZD4ke2RpZmZDZWxsKGEsIGIpfTwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8dHIgY2xhc3M9InRvdGFsLXJvdyI+PHRkPlRvdGFsIGTDqXBlbnNlczwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGdyYW5kQSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRCKX08L3RkPiR7ZGlmZkNlbGwoZ3JhbmRBLCBncmFuZEIpfTwvdHI+YDsKICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgcmVuZGVyTW9udGhDb21wYXJpc29uKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENhbGN1bGUsIHBvdXIgY2hhcXVlIGNhdMOpZ29yaWUgZGUgZMOpcGVuc2UsIGxhIG1veWVubmUgbWVuc3VlbGxlLCBsZQogICAgLy8gbW9udGFudCBkdSBtb2lzIGVuIGNvdXJzLCBldCBsYSB0ZW5kYW5jZSAoZGlyZWN0aW9uICsgcmF0aW8gdnMKICAgIC8vIG1veWVubmUpLiBQYXJ0YWfDqSBlbnRyZSBsZSB0YWJsZWF1ICJNb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllIgogICAgLy8gZXQgbGVzIGNvbnNlaWxzIGQnw6lwYXJnbmUsIHBvdXIgbmUgcGFzIGR1cGxpcXVlciBjZXR0ZSBsb2dpcXVlLgogICAgZnVuY3Rpb24gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBtb250aEtleXMgPSBbLi4ubmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSldLnNvcnQoKTsKICAgICAgaWYgKG1vbnRoS2V5cy5sZW5ndGggPT09IDApIHJldHVybiBbXTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlzW21vbnRoS2V5cy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgbmJNb250aHMgPSBtb250aEtleXMubGVuZ3RoOwoKICAgICAgLy8gdG90YWwgcGFyIGNhdMOpZ29yaWUsIGV0IHBhciBjYXTDqWdvcmllK21vaXMgKHBvdXIgaXNvbGVyIGxlIG1vaXMgZW4gY291cnMpCiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSA9PT0gY3VycmVudE1vbnRoS2V5KSB7CiAgICAgICAgICBjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9IChjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgcmV0dXJuIGNhdGVnb3JpZXMubWFwKChjYXQpID0+IHsKICAgICAgICBjb25zdCBhdmVyYWdlID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdIC8gbmJNb250aHM7CiAgICAgICAgY29uc3QgY3VycmVudCA9IGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbY2F0XSB8fCAwOwogICAgICAgIGxldCBkaXJlY3Rpb24gPSAic3RhYmxlIjsKICAgICAgICBsZXQgcmF0aW8gPSAwOwogICAgICAgIGlmIChhdmVyYWdlID4gMCkgewogICAgICAgICAgcmF0aW8gPSAoY3VycmVudCAtIGF2ZXJhZ2UpIC8gYXZlcmFnZTsKICAgICAgICAgIGlmIChyYXRpbyA+IDAuMTUpIGRpcmVjdGlvbiA9ICJ1cCI7CiAgICAgICAgICBlbHNlIGlmIChyYXRpbyA8IC0wLjE1KSBkaXJlY3Rpb24gPSAiZG93biI7CiAgICAgICAgfSBlbHNlIGlmIChjdXJyZW50ID4gMCkgewogICAgICAgICAgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHsgY2F0ZWdvcnk6IGNhdCwgYXZlcmFnZSwgY3VycmVudCwgcmF0aW8sIGRpcmVjdGlvbiB9OwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHJlbmQtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBpZiAodHJlbmRzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgbGV0IGh0bWwgPSBgPHRhYmxlIGNsYXNzPSJzaW1wbGUtdGFibGUiPjx0aGVhZD48dHI+PHRoPkNhdMOpZ29yaWU8L3RoPjx0aD5Nb3llbm5lL21vaXM8L3RoPjx0aD5DZSBtb2lzLWNpPC90aD48dGg+VGVuZGFuY2U8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCB0IG9mIHRyZW5kcykgewogICAgICAgIGxldCB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWZsYXQiPuKGkiBzdGFibGU8L3NwYW4+YDsKICAgICAgICBpZiAodC5kaXJlY3Rpb24gPT09ICJ1cCIpIHsKICAgICAgICAgIHRyZW5kSHRtbCA9IHQuYXZlcmFnZSA+IDAKICAgICAgICAgICAgPyBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgKyR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lPC9zcGFuPmAKICAgICAgICAgICAgOiBgPHNwYW4gY2xhc3M9InRyZW5kLXVwIj7ihpEgbm91dmVhdTwvc3Bhbj5gOwogICAgICAgIH0gZWxzZSBpZiAodC5kaXJlY3Rpb24gPT09ICJkb3duIikgewogICAgICAgICAgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC1kb3duIj7ihpMgJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YDsKICAgICAgICB9CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2FsbENhdGVnb3J5TGFiZWxzW3QuY2F0ZWdvcnldIHx8IHQuY2F0ZWdvcnl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodC5hdmVyYWdlKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmN1cnJlbnQpfTwvdGQ+PHRkPiR7dHJlbmRIdG1sfTwvdGQ+PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB3cmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJCdWRnZXRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHBvcHVsYXRlQ29tcGFyZU1vbnRoU2VsZWN0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJNb250aENvbXBhcmlzb24oKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEaWN0w6llIHZvY2FsZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbWljQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1taWMiKTsKICAgIGNvbnN0IHZvaWNlQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtYmFubmVyIik7CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIHRyYW5zYWN0aW9uIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZSBzZXNzaW9uIGRlCiAgICAvLyBuYXZpZ2F0aW9uIChyZW1pcyDDoCB6w6lybyBzaSBvbiByZWNoYXJnZSBsYSBwYWdlKS4gU2VydCB1bmlxdWVtZW50IMOgCiAgICAvLyBhcHBsaXF1ZXIgdW5lIGNvcnJlY3Rpb24gKCJlbiBmYWl0IGMnw6l0YWl0IHBsdXTDtHQuLi4iKSBzdXIgbGEgYm9ubmUKICAgIC8vIHRyYW5zYWN0aW9uLiBTYW5zIMOnYSwgb3Ugc2kgbGEgcGhyYXNlIG4nZXN0IHBhcyB1bmUgY29ycmVjdGlvbiwgb24KICAgIC8vIGNyw6llIHRvdWpvdXJzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiDigJQgbWlldXggdmF1dCB1biBkb3VibG9uIHF1J3VuZQogICAgLy8gZMOpcGVuc2UgY29ycm9tcHVlIHBhciBlcnJldXIuCiAgICBsZXQgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IG51bGw7CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VCYW5uZXIodGV4dCkgewogICAgICBpZiAoIXRleHQpIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSAiIjsKICAgICAgfSBlbHNlIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgICB9CiAgICB9CgogICAgY29uc3QgU3BlZWNoUmVjb2duaXRpb25DdG9yID0gd2luZG93LlNwZWVjaFJlY29nbml0aW9uIHx8IHdpbmRvdy53ZWJraXRTcGVlY2hSZWNvZ25pdGlvbjsKCiAgICBpZiAoIVNwZWVjaFJlY29nbml0aW9uQ3RvcikgewogICAgICBtaWNCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBtaWNCdG4udGl0bGUgPSAiRGljdMOpZSB2b2NhbGUgbm9uIGRpc3BvbmlibGUgc3VyIGNlIG5hdmlnYXRldXIgKHV0aWxpc2UgQ2hyb21lIG91IEVkZ2UpIjsKICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHJlY29nbml0aW9uID0gbmV3IFNwZWVjaFJlY29nbml0aW9uQ3RvcigpOwogICAgICByZWNvZ25pdGlvbi5sYW5nID0gImZyLUZSIjsKICAgICAgcmVjb2duaXRpb24uY29udGludW91cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5pbnRlcmltUmVzdWx0cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5tYXhBbHRlcm5hdGl2ZXMgPSAxOwoKICAgICAgbGV0IGlzTGlzdGVuaW5nID0gZmFsc2U7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJzdGFydCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IHRydWU7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoImxpc3RlbmluZyIpOwogICAgICAgIHNldFZvaWNlQmFubmVyKCJKZSB0J8OpY291dGXigKYiKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlbmQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZXJyb3IiLCAoZXZlbnQpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgIGlmIChldmVudC5lcnJvciA9PT0gIm5vLXNwZWVjaCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJSaWVuIGVudGVuZHUsIHLDqWVzc2FpZS4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDIwMDApOwogICAgICAgIH0gZWxzZSBpZiAoZXZlbnQuZXJyb3IgPT09ICJub3QtYWxsb3dlZCIgfHwgZXZlbnQuZXJyb3IgPT09ICJzZXJ2aWNlLW5vdC1hbGxvd2VkIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIk1pY3JvIHJlZnVzw6kg4oCUIGF1dG9yaXNlIGwnYWNjw6hzIGF1IG1pY3JvIGRhbnMgdG9uIG5hdmlnYXRldXIuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCA0MDAwKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIobnVsbCk7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBtaWNybyA6ICIgKyBldmVudC5lcnJvciwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInJlc3VsdCIsIGFzeW5jIChldmVudCkgPT4gewogICAgICAgIGNvbnN0IHRyYW5zY3JpcHQgPSBldmVudC5yZXN1bHRzWzBdWzBdLnRyYW5zY3JpcHQ7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoYCIke3RyYW5zY3JpcHR9ImApOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJwcm9jZXNzaW5nIik7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL3BhcnNlIiwgewogICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0ZXh0OiB0cmFuc2NyaXB0IH0pLAogICAgICAgICAgfSk7CiAgICAgICAgICBhd2FpdCBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfSBmaW5hbGx5IHsKICAgICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAxNTAwKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgbWljQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGlmIChpc0xpc3RlbmluZykgewogICAgICAgICAgcmVjb2duaXRpb24uc3RvcCgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICB0cnkgewogICAgICAgICAgcmVjb2duaXRpb24uc3RhcnQoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIC8vIHN0YXJ0KCkgamV0dGUgc2kgZMOpasOgIGTDqW1hcnLDqSA7IG9uIGlnbm9yZS4KICAgICAgICB9CiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFN1Z2dlc3Rpb25zIGRlIGNhdMOpZ29yaWUg4oCUIHVuaXF1ZW1lbnQgYXByw6hzIHVuZSBzYWlzaWUgcGFyIGRpY3TDqWUKICAgIC8vIHZvY2FsZSAodW5lIGZhdXRlIGRlIGZyYXBwZSBlbiBzYWlzaWUgbWFudWVsbGUsIGMnZXN0IHVuZSBlcnJldXIgZGUKICAgIC8vIGwndXRpbGlzYXRldXIsIHBhcyBsYSBwZWluZSBkZSBsZSByZWxhbmNlciBkZXNzdXMpLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQgPSAzOwoKICAgIGZ1bmN0aW9uIG5vcm1hbGl6ZURlc2NyaXB0aW9uKGRlc2MpIHsKICAgICAgcmV0dXJuIChkZXNjIHx8ICIiKS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBkaXNtaXNzU3VnZ2VzdGlvbihrZXkpIHsKICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuYWRkKGtleSk7IC8vIGltbcOpZGlhdCBjw7R0w6kgVUksIHBhcyBiZXNvaW4gZCdhdHRlbmRyZSBsZSBzZXJ2ZXVyCiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGtleSB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSBsYSBzdWdnZXN0aW9uIHLDqWFwcGFyYcOudCB1bmUgZm9pcyBzdXIgdW4KICAgICAgICAvLyBhdXRyZSBhcHBhcmVpbCBzaSBsYSBzYXV2ZWdhcmRlIHNlcnZldXIgYSDDqWNob3XDqS4KICAgICAgfQogICAgfQoKICAgIC8vIFJlZ2FyZGUgc2kgbGEgZGVzY3JpcHRpb24gZGUgbGEgdHJhbnNhY3Rpb24gcXVpIHZpZW50IGQnw6p0cmUgYWpvdXTDqWUKICAgIC8vIChvdSBjb3JyaWfDqWUpIMOgIGxhIHZvaXggcmV2aWVudCBzb3V2ZW50LCBldCBzaSBvdWkgOgogICAgLy8gLSBzb2l0IGVsbGUgYSB0b3Vqb3VycyDDqXTDqSByYW5nw6llIGRhbnMgIkF1dHJlIiDihpIgb24gcHJvcG9zZSBkZSBjcsOpZXIKICAgIC8vICAgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGRlIGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpIDsKICAgIC8vIC0gc29pdCBlbGxlIGEgY2V0dGUgZm9pcyB1bmUgY2F0w6lnb3JpZSBkaWZmw6lyZW50ZSBkZSBkJ2hhYml0dWRlIOKGkiBvbgogICAgLy8gICBkZW1hbmRlIHNpIGNlIG4nZXN0IHBhcyB1bmUgZXJyZXVyLgogICAgZnVuY3Rpb24gY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24oZGVzY3JpcHRpb24sIHR5cGUpIHsKICAgICAgY29uc3Qgbm9ybSA9IG5vcm1hbGl6ZURlc2NyaXB0aW9uKGRlc2NyaXB0aW9uKTsKICAgICAgaWYgKCFub3JtKSByZXR1cm47CgogICAgICBjb25zdCBzYW1lRGVzY3JpcHRpb24gPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICh0eCkgPT4gdHgudHlwZSA9PT0gdHlwZSAmJiBub3JtYWxpemVEZXNjcmlwdGlvbih0eC5kZXNjcmlwdGlvbikgPT09IG5vcm0KICAgICAgKTsKICAgICAgaWYgKHNhbWVEZXNjcmlwdGlvbi5sZW5ndGggPCBDQVRFR09SWV9TVUdHRVNUSU9OX1RIUkVTSE9MRCkgcmV0dXJuOwoKICAgICAgY29uc3QgY291bnRzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2Ygc2FtZURlc2NyaXB0aW9uKSBjb3VudHNbdHguY2F0ZWdvcnldID0gKGNvdW50c1t0eC5jYXRlZ29yeV0gfHwgMCkgKyAxOwogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXMoY291bnRzKTsKICAgICAgY29uc3QgZG9taW5hbnQgPSBjYXRlZ29yaWVzLnJlZHVjZSgoYSwgYikgPT4gKGNvdW50c1thXSA+PSBjb3VudHNbYl0gPyBhIDogYikpOwogICAgICBjb25zdCBsYXRlc3QgPSBzYW1lRGVzY3JpcHRpb25bMF07IC8vIGFsbFRyYW5zYWN0aW9ucyBlc3QgdHJpw6kgcGFyIGRhdGUgZMOpY3JvaXNzYW50ZQoKICAgICAgbGV0IHN1Z2dlc3Rpb24gPSBudWxsOwogICAgICBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgbWlzbWF0Y2g6JHt0eXBlfToke25vcm19OiR7bGF0ZXN0LmNhdGVnb3J5fWAsCiAgICAgICAgICBraW5kOiAibWlzbWF0Y2giLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICBkb21pbmFudCwKICAgICAgICAgIGN1cnJlbnQ6IGxhdGVzdC5jYXRlZ29yeSwKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgPT09IGxhdGVzdC5jYXRlZ29yeSkubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPT09IDEgJiYgZG9taW5hbnQgPT09ICJhdXRyZSIpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgZ2VuZXJpYzoke3R5cGV9OiR7bm9ybX1gLAogICAgICAgICAga2luZDogImdlbmVyaWMiLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9CgogICAgICBpZiAoIXN1Z2dlc3Rpb24gfHwgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuaGFzKHN1Z2dlc3Rpb24ua2V5KSkgcmV0dXJuOwogICAgICBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pOwogICAgfQoKICAgIGZ1bmN0aW9uIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIik7CiAgICAgIGVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpIHsKICAgICAgY29uc3QgW2xhdGVzdElkLCAuLi5vdGhlcnNdID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgY29uc3QgaWRzVG9GaXggPSBbbGF0ZXN0SWRdOwogICAgICBpZiAoCiAgICAgICAgb3RoZXJzLmxlbmd0aCA+IDAgJiYKICAgICAgICAoYXdhaXQgc2hvd0NvbmZpcm0oYENvcnJpZ2VyIGF1c3NpIGxlcyAke290aGVycy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHByw6ljw6lkZW50ZShzKSBhdmVjIGxhIG3Dqm1lIGRlc2NyaXB0aW9uID9gKSkKICAgICAgKSB7CiAgICAgICAgaWRzVG9GaXgucHVzaCguLi5vdGhlcnMpOwogICAgICB9CgogICAgICB0cnkgewogICAgICAgIGZvciAoY29uc3QgaWQgb2YgaWRzVG9GaXgpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBjYXRlZ29yeTogdGFyZ2V0VmFsdWUgfSksCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgc2hvd1RvYXN0KGBDYXTDqWdvcmllIG1pc2Ugw6Agam91ciA6ICR7dGFyZ2V0TGFiZWx9YCk7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbikgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCBkZXNjTGFiZWwgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIoc2FucyBkZXNjcmlwdGlvbikiOwogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGBUdSBhcyB1dGlsaXPDqSAiJHtkZXNjTGFiZWx9IiAke3N1Z2dlc3Rpb24udHhJZHMubGVuZ3RofSBmb2lzLCB0b3Vqb3VycyBjbGFzc8OpIGVuIGAgKwogICAgICAgICAgYCJBdXRyZSIuIENyw6llciB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgY3VycmVudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5jdXJyZW50XSB8fCBzdWdnZXN0aW9uLmN1cnJlbnQ7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgIiR7ZGVzY0xhYmVsfSIgZXN0IGhhYml0dWVsbGVtZW50IGNsYXNzw6kgZW4gIiR7ZG9taW5hbnRMYWJlbH0iLCBtYWlzIGNldHRlIGZvaXMgYCArCiAgICAgICAgICBgYydlc3QgIiR7Y3VycmVudExhYmVsfSIuIFBhcyBkJ2VycmV1ciBvdSB1biBvdWJsaSA/YDsKICAgICAgfQogICAgICBlbC5hcHBlbmRDaGlsZCh0ZXh0KTsKCiAgICAgIGNvbnN0IGNvbnRyb2xzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGNvbnRyb2xzLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIjsKCiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdKSB7CiAgICAgICAgICBpZiAodmFsdWUgPT09ICJhdXRyZSIpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IG5ld09wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG5ld09wdC52YWx1ZSA9ICJfX25ld19fIjsKICAgICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgICBuZXdPcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgICBjb25zdCBuZXdOYW1lSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIG5ld05hbWVJbnB1dC50eXBlID0gInRleHQiOwogICAgICAgIG5ld05hbWVJbnB1dC5wbGFjZWhvbGRlciA9ICJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSI7CiAgICAgICAgbmV3TmFtZUlucHV0LnZhbHVlID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiIjsKCiAgICAgICAgc2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgICAgIG5ld05hbWVJbnB1dC5zdHlsZS5kaXNwbGF5ID0gc2VsZWN0LnZhbHVlID09PSAiX19uZXdfXyIgPyAiaW5saW5lLWJsb2NrIiA6ICJub25lIjsKICAgICAgICB9KTsKCiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoc2VsZWN0KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChuZXdOYW1lSW5wdXQpOwoKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gIkFwcGxpcXVlciI7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGxldCB0YXJnZXRWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICAgIGxldCB0YXJnZXRMYWJlbDsKICAgICAgICAgIGlmICh0YXJnZXRWYWx1ZSA9PT0gIl9fbmV3X18iKSB7CiAgICAgICAgICAgIGNvbnN0IG5hbWUgPSBuZXdOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgY2F0w6lnb3JpZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgICAgICAgdGFyZ2V0VmFsdWUgPSBzbHVnaWZ5Q2F0ZWdvcnkobmFtZSk7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gbmFtZTsKICAgICAgICAgICAgaWYgKCFjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB0YXJnZXRWYWx1ZSkpIHsKICAgICAgICAgICAgICBzYXZlQ3VzdG9tQ2F0ZWdvcnkoc3VnZ2VzdGlvbi50eXBlLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgICAgICB9CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3RhcmdldFZhbHVlXSB8fCB0YXJnZXRWYWx1ZTsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSBgQ29ycmlnZXIgZW4gIiR7ZG9taW5hbnRMYWJlbH0iYDsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgc3VnZ2VzdGlvbi5kb21pbmFudCwgZG9taW5hbnRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9CgogICAgICBjb25zdCBkaXNtaXNzQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGRpc21pc3NCdG4udGV4dENvbnRlbnQgPSAiSWdub3JlciI7CiAgICAgIGRpc21pc3NCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBkaXNtaXNzQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgIH0pOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChkaXNtaXNzQnRuKTsKCiAgICAgIGVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKICAgIH0KCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZQogICAgLy8gc2Vzc2lvbiAobcOqbWUgcHJpbmNpcGUgcXVlIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQsIG1haXMgcG91ciB1bmUKICAgIC8vIGNvcnJlY3Rpb24gcXVpIHN1aXQgbGEgY3LDqWF0aW9uIGQndW5lIHLDqWN1cnJlbnRlIHBhciBsYSB2b2l4KS4KICAgIGxldCBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IG51bGw7CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpIHsKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICAvLyAicsOpY3VycmVudCIsICJhYm9ubmVtZW50IiwgInRvdXMgbGVzIG1vaXMiLi4uIGTDqXRlY3TDqSBwYXIgbCdJQSA6IG9uCiAgICAgIC8vIGNyw6llL2NvcnJpZ2UgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBhdSBsaWV1IGQndW5lIHRyYW5zYWN0aW9uCiAgICAgIC8vIHBvbmN0dWVsbGUsIHF1ZWwgcXVlIHNvaXQgbCdvbmdsZXQgYWN0dWVsbGVtZW50IGFmZmljaMOpIOKAlCBsZSBtaWNybwogICAgICAvLyBlc3QgZ2xvYmFsLCBwYXMgbGnDqSDDoCBsJ29uZ2xldCBSw6ljdXJyZW50ZXMuCiAgICAgIGlmIChwYXJzZWQuaXNfcmVjdXJyaW5nKSB7CiAgICAgICAgY29uc3QgcmVjUGF5bG9hZCA9IHsKICAgICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgICAgbmFtZTogcGFyc2VkLmRlc2NyaXB0aW9uIHx8IChwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IHLDqWN1cnJlbnQiIDogIkTDqXBlbnNlIHLDqWN1cnJlbnRlIiksCiAgICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgICAgZGF5X29mX21vbnRoOiBOdW1iZXIocGFyc2VkLmV4cGVuc2VfZGF0ZS5zbGljZSg4LCAxMCkpLAogICAgICAgIH07CgogICAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7bGFzdFZvaWNlUmVjdXJyaW5nSWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgY29ycmlnw6llIDogJHtyZWNQYXlsb2FkLm5hbWV9ICgke2Ftb3VudExhYmVsfSlgKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHJlY1BheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgICBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgICBzaG93VG9hc3QoYENoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfQogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKHBhcnNlZC5kZXNjcmlwdGlvbiwgcGFyc2VkLnR5cGUpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiBzdHlsw6llIChyZW1wbGFjZSB3aW5kb3cuY29uZmlybSwgcXVpIGFmZmljaGUgdW5lIHBvcHVwCiAgICAvLyBuYXRpdmUgZHUgbmF2aWdhdGV1ciBob3JzIGNoYXJ0ZSBncmFwaGlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBjb25maXJtT3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgY29uZmlybU1lc3NhZ2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW1lc3NhZ2UiKTsKICAgIGNvbnN0IGNvbmZpcm1Pa0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1vayIpOwogICAgY29uc3QgY29uZmlybUNhbmNlbEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1jYW5jZWwiKTsKICAgIGxldCBjb25maXJtUmVzb2x2ZSA9IG51bGw7CgogICAgZnVuY3Rpb24gc2hvd0NvbmZpcm0obWVzc2FnZSkgewogICAgICBjb25maXJtTWVzc2FnZUVsLnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgY29uZmlybU92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSByZXNvbHZlOwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZUNvbmZpcm0ocmVzdWx0KSB7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGlmIChjb25maXJtUmVzb2x2ZSkgewogICAgICAgIGNvbmZpcm1SZXNvbHZlKHJlc3VsdCk7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSBudWxsOwogICAgICB9CiAgICB9CgogICAgY29uZmlybU9rQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKHRydWUpKTsKICAgIGNvbmZpcm1DYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBjbG9zZUNvbmZpcm0oZmFsc2UpKTsKICAgIGNvbmZpcm1PdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IGNvbmZpcm1PdmVybGF5RWwpIGNsb3NlQ29uZmlybShmYWxzZSk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEw6lwZW5zZXMgcsOpY3VycmVudGVzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCByZWNMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWxpc3QiKTsKICAgIGNvbnN0IHJlY0VtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWN1cnJpbmctZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHJlY092ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjTW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1tb2RhbC10aXRsZSIpOwogICAgY29uc3QgcmVjVHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy10eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgcmVjTmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1uYW1lIik7CiAgICBjb25zdCByZWNBbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCByZWNDYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgcmVjRGF5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWRheSIpOwogICAgY29uc3QgcmVjU3RhcnREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LXN0YXJ0LWRhdGUiKTsKICAgIGNvbnN0IHJlY0VuZERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZW5kLWRhdGUiKTsKICAgIGNvbnN0IHJlY1NhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1zYXZlIik7CgogICAgbGV0IGFsbFJlY3VycmluZyA9IFtdOwogICAgbGV0IGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICBsZXQgcmVjQ3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgZnVuY3Rpb24gcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIHJlY0NhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0UmVjdXJyaW5nVHlwZSh0eXBlKSB7CiAgICAgIHJlY0N1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgcmVjVHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCByZWNDYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICByZWNUeXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0UmVjdXJyaW5nVHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtID0gbnVsbCkgewogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBpdGVtID8gaXRlbS5pZCA6IG51bGw7CiAgICAgIHJlY01vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGl0ZW0gPyAiTW9kaWZpZXIgbGEgY2hhcmdlIHLDqWN1cnJlbnRlIiA6ICJOb3V2ZWxsZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICByZWNTYXZlQnRuLnRleHRDb250ZW50ID0gaXRlbSA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFJlY3VycmluZ1R5cGUoaXRlbSA/IGl0ZW0udHlwZSA6ICJleHBlbnNlIik7CiAgICAgIHJlY05hbWVJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLm5hbWUgOiAiIjsKICAgICAgcmVjQW1vdW50SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHJlY0N1cnJlbnRUeXBlLCBpdGVtID8gaXRlbS5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICByZWNEYXlJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLmRheV9vZl9tb250aCA6ICIiOwogICAgICByZWNTdGFydERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5zdGFydF9kYXRlID8gaXRlbS5zdGFydF9kYXRlIDogIiI7CiAgICAgIHJlY0VuZERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5lbmRfZGF0ZSA/IGl0ZW0uZW5kX2RhdGUgOiAiIjsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZWNOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY3VycmluZ01vZGFsKCkgewogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY3VycmluZ01vZGFsKTsKICAgIHJlY092ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gcmVjT3ZlcmxheUVsKSBjbG9zZVJlY3VycmluZ01vZGFsKCk7IH0pOwoKICAgIHJlY1NhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG5hbWUgPSByZWNOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KHJlY0Ftb3VudElucHV0LnZhbHVlKTsKICAgICAgY29uc3QgZGF5ID0gcGFyc2VJbnQocmVjRGF5SW5wdXQudmFsdWUsIDEwKTsKCiAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkxlIG5vbSBlc3Qgb2JsaWdhdG9pcmUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7IHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFkYXkgfHwgZGF5IDwgMSB8fCBkYXkgPiAzMSkgeyBzaG93VG9hc3QoIkpvdXIgZHUgbW9pcyBpbnZhbGlkZSAoMSDDoCAzMSkiLCB0cnVlKTsgcmV0dXJuOyB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHJlY0N1cnJlbnRUeXBlLAogICAgICAgIG5hbWUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiByZWNDYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRheV9vZl9tb250aDogZGF5LAogICAgICAgIHN0YXJ0X2RhdGU6IHJlY1N0YXJ0RGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgICAgZW5kX2RhdGU6IHJlY0VuZERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7ZWRpdGluZ1JlY3VycmluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZVJlY3VycmluZ01vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVSZWN1cnJpbmcoaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSByw6ljdXJyZW50ZSA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiRMOpcGVuc2UgcsOpY3VycmVudGUgc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKSB7CiAgICAgIHJlY0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgcmVjRW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSBpdGVtcy5sZW5ndGggPT09IDAgPyAiYmxvY2siIDogIm5vbmUiOwoKICAgICAgY29uc3QgdG9kYXlLZXkgPSB0b2RheUlzbygpOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGl0ZW1zKSB7CiAgICAgICAgY29uc3QgdHlwZSA9IGl0ZW0udHlwZSB8fCAiZXhwZW5zZSI7CiAgICAgICAgY29uc3QgZW5kZWQgPSBpdGVtLmVuZF9kYXRlICYmIGl0ZW0uZW5kX2RhdGUgPCB0b2RheUtleTsKICAgICAgICBjb25zdCBub3RTdGFydGVkID0gaXRlbS5zdGFydF9kYXRlICYmIGl0ZW0uc3RhcnRfZGF0ZSA+IHRvZGF5S2V5OwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAicmVjLWNhcmQgIiArIHR5cGUgKyAoZW5kZWQgPyAiIGVuZGVkIiA6ICIiKTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInJlYy1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJyZWMtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUpIHsKICAgICAgICAgIGNvbnN0IHN0YXJ0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBzdGFydEJhZGdlLmNsYXNzTmFtZSA9ICJzdGFydC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBzdGFydExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5zdGFydF9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICAgIHN0YXJ0QmFkZ2UudGV4dENvbnRlbnQgPSBub3RTdGFydGVkID8gYETDqHMgbGUgJHtzdGFydExhYmVsfWAgOiBgRGVwdWlzIGxlICR7c3RhcnRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHN0YXJ0QmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAoaXRlbS5lbmRfZGF0ZSkgewogICAgICAgICAgY29uc3QgZW5kQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBlbmRCYWRnZS5jbGFzc05hbWUgPSAiZW5kLWJhZGdlIjsKICAgICAgICAgIGNvbnN0IGVuZExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5lbmRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBlbmRCYWRnZS50ZXh0Q29udGVudCA9IGVuZGVkID8gYFRlcm1pbsOpIGxlICR7ZW5kTGFiZWx9YCA6IGBKdXNxdSdhdSAke2VuZExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZW5kQmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG5hbWUuY2xhc3NOYW1lID0gInJlYy1uYW1lIjsKICAgICAgICBuYW1lLnRleHRDb250ZW50ID0gaXRlbS5uYW1lOwoKICAgICAgICBjb25zdCBzdWIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBzdWIuY2xhc3NOYW1lID0gInJlYy1zdWIiOwogICAgICAgIHN1Yi50ZXh0Q29udGVudCA9IGBMZSAke2l0ZW0uZGF5X29mX21vbnRofSBkZSBjaGFxdWUgbW9pc2A7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKG5hbWUpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoc3ViKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAicmVjLWFtb3VudCAiICsgdHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtKSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVJlY3VycmluZyhpdGVtLmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICByZWNMaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhbCBkZXMgZMOpcGVuc2VzIHLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzIGNlIG1vaXMtY2kgKGNlbGxlcwogICAgLy8gZG9udCBsZSBqb3VyIGR1IG1vaXMgbidlc3QgcGFzIGVuY29yZSBwYXNzw6kpLCBhZmZpY2jDqSDDoCBjw7R0w6kgZGVzIDMKICAgIC8vIGNhcnRlcyBkdSBoYXV0IOKAlCBpbmTDqXBlbmRhbnQgZHUgbW9pcyBjaG9pc2kgZGFucyBsZSB0YWJsZWF1IGRlIGJvcmQsCiAgICAvLyB0b3Vqb3VycyAibGUgbW9pcyByw6llbCwgbWFpbnRlbmFudCIuCiAgICBmdW5jdGlvbiB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKSB7CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIGN1cnJlbnRNb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSB0b2RheURheSkgY29udGludWU7CiAgICAgICAgaWYgKChpdGVtLnR5cGUgfHwgImV4cGVuc2UiKSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBuZXQgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZyIpOwogICAgICBjb25zdCBjYXJkRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy1jYXJkIik7CiAgICAgIGNvbnN0IHRvb2x0aXBFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLXRvb2x0aXAiKTsKCiAgICAgIGlmIChuZXQgPT09IDApIHsKICAgICAgICBlbC50ZXh0Q29udGVudCA9ICLigJQiOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSI7CiAgICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9ICIiOwogICAgICAgIGNhcmRFbC5jbGFzc0xpc3QucmVtb3ZlKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHNpZ24gPSBuZXQgPiAwID8gIisiIDogIuKIkiI7CiAgICAgIGVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0KSl9YDsKICAgICAgZWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAobmV0ID4gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgY2FyZEVsLmNsYXNzTGlzdC5hZGQoInRvb2x0aXAtaG9zdCIpOwogICAgICB0b29sdGlwRWwuaW5uZXJIVE1MID0KICAgICAgICBgRMOpcGVuc2VzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdFeHBlbnNlKX08YnI+YCArCiAgICAgICAgYFJldmVudXMgw6AgdmVuaXIgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh1cGNvbWluZ0luY29tZSl9YDsKICAgIH0KCiAgICAvLyBQZXRpdGUgYnVsbGUgZGUgZMOpdGFpbCBmYcOnb24gInRvb2x0aXAiIGhhYmlsbMOpZSBhdXggY291bGV1cnMgZHUgc2l0ZSwKICAgIC8vIGF1IGxpZXUgZHUgdGl0bGUgbmF0aWYgZHUgbmF2aWdhdGV1ciAoZ3Jpcy9ibGFuYywgaG9ycyBjaGFydGUsIGV0CiAgICAvLyBpbnZpc2libGUgYXUgdGFjdGlsZSkuIEFmZmljaMOpZSBhdSBzdXJ2b2wgKG9yZGluYXRldXIpIGV0IGF1CiAgICAvLyB0YXAvdGFwLWVuLWRlaG9ycyAodMOpbMOpcGhvbmUvdGFibGV0dGUpLgogICAgKGZ1bmN0aW9uIHNldHVwU3VtbWFyeVVwY29taW5nVG9vbHRpcCgpIHsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBmdW5jdGlvbiBzaG93KCkgewogICAgICAgIGlmICh0b29sdGlwRWwuaW5uZXJIVE1MKSB0b29sdGlwRWwuY2xhc3NMaXN0LmFkZCgidmlzaWJsZSIpOwogICAgICB9CiAgICAgIGZ1bmN0aW9uIGhpZGUoKSB7CiAgICAgICAgdG9vbHRpcEVsLmNsYXNzTGlzdC5yZW1vdmUoInZpc2libGUiKTsKICAgICAgfQoKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlZW50ZXIiLCBzaG93KTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlbGVhdmUiLCBoaWRlKTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgICBlLnN0b3BQcm9wYWdhdGlvbigpOwogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIik7CiAgICAgIH0pOwogICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGhpZGUpOwogICAgfSkoKTsKCiAgICAvLyBSYW3DqG5lIHVuIGpvdXIgZHUgbW9pcyAoMS0zMSkgYXUgZGVybmllciBqb3VyIHLDqWVsIGR1IG1vaXMgdmlzw6kg4oCUCiAgICAvLyDDqXF1aXZhbGVudCBKUyBkZSBfY2xhbXBfZGF5IGPDtHTDqSBzZXJ2ZXVyLCBwb3VyIGNhbGN1bGVyIGRlIHZyYWllcwogICAgLy8gZGF0ZXMgKG5ldyBEYXRlKC4uLikpIHBsdXTDtHQgcXVlIGRlIGNvbXBhcmVyIGRlcyBqb3VycyB0b3V0IHNldWxzLgogICAgZnVuY3Rpb24gY2xhbXBEYXlKcyh5ZWFyLCBtb250aEluZGV4LCBkYXkpIHsKICAgICAgY29uc3QgbGFzdERheSA9IG5ldyBEYXRlKHllYXIsIG1vbnRoSW5kZXggKyAxLCAwKS5nZXREYXRlKCk7CiAgICAgIHJldHVybiBNYXRoLm1pbihkYXksIGxhc3REYXkpOwogICAgfQoKICAgIC8vIFByb2NoYWluZSBvY2N1cnJlbmNlIGQndW5lIGNoYXJnZSByw6ljdXJyZW50ZSDDoCBwYXJ0aXIgZCdhdWpvdXJkJ2h1aQogICAgLy8gKHN0cmljdGVtZW50IGFwcsOocyBhdWpvdXJkJ2h1aSkgOiByZWdhcmRlIGNlIG1vaXMtY2kgcHVpcywgc2kgYmVzb2luLAogICAgLy8gbGVzIGRldXggbW9pcyBzdWl2YW50cyDigJQgdXRpbGUgZW4gZmluIGRlIG1vaXMgcXVhbmQgcGx1cyByaWVuIG4nZXN0CiAgICAvLyDDoCB2ZW5pciBkYW5zIGxlIG1vaXMgY291cmFudC4KICAgIGZ1bmN0aW9uIG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheVN0cikgewogICAgICBjb25zdCBbdHksIHRtLCB0ZF0gPSB0b2RheVN0ci5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCB0b2RheURhdGUgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxLCB0ZCk7CiAgICAgIGZvciAobGV0IG9mZnNldCA9IDA7IG9mZnNldCA8PSAyOyBvZmZzZXQrKykgewogICAgICAgIGNvbnN0IGJhc2UgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxICsgb2Zmc2V0LCAxKTsKICAgICAgICBjb25zdCB5ID0gYmFzZS5nZXRGdWxsWWVhcigpOwogICAgICAgIGNvbnN0IG1JZHggPSBiYXNlLmdldE1vbnRoKCk7CiAgICAgICAgY29uc3QgbW9udGhLZXkgPSBgJHt5fS0ke1N0cmluZyhtSWR4ICsgMSkucGFkU3RhcnQoMiwgIjAiKX1gOwogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBjb25zdCBkYXkgPSBjbGFtcERheUpzKHksIG1JZHgsIGl0ZW0uZGF5X29mX21vbnRoKTsKICAgICAgICBjb25zdCBvY2NEYXRlID0gbmV3IERhdGUoeSwgbUlkeCwgZGF5KTsKICAgICAgICBpZiAob2NjRGF0ZSA+IHRvZGF5RGF0ZSkgcmV0dXJuIG9jY0RhdGU7CiAgICAgIH0KICAgICAgcmV0dXJuIG51bGw7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyVXBjb21pbmdSZWN1cnJpbmdMaXN0KCkgewogICAgICBjb25zdCBwYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwiKTsKICAgICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInVwY29taW5nLXJlY3VycmluZy1saXN0Iik7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKCiAgICAgIGNvbnN0IHVwY29taW5nID0gYWxsUmVjdXJyaW5nCiAgICAgICAgLm1hcCgoaXRlbSkgPT4gKHsgaXRlbSwgZGF0ZTogbmV4dE9jY3VycmVuY2VGb3JJdGVtKGl0ZW0sIHRvZGF5KSB9KSkKICAgICAgICAuZmlsdGVyKCh4KSA9PiB4LmRhdGUpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGEuZGF0ZSAtIGIuZGF0ZSkKICAgICAgICAuc2xpY2UoMCwgMyk7CgogICAgICBpZiAodXBjb21pbmcubGVuZ3RoID09PSAwKSB7CiAgICAgICAgcGFuZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHBhbmVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CgogICAgICBmb3IgKGNvbnN0IHsgaXRlbSwgZGF0ZSB9IG9mIHVwY29taW5nKSB7CiAgICAgICAgY29uc3QgZGF5cyA9IE1hdGgucm91bmQoKGRhdGUgLSBuZXcgRGF0ZShuZXcgRGF0ZSgpLnNldEhvdXJzKDAsIDAsIDAsIDApKSkgLyA4NjQwMDAwMCk7CiAgICAgICAgY29uc3QgZHVlTGFiZWwgPSBkYXlzIDw9IDEgPyAiZGVtYWluIiA6IGBkYW5zICR7ZGF5c30gam91cnNgOwogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gInVwY29taW5nLXJlY3VycmluZy1yb3ciOwogICAgICAgIGNvbnN0IGxlZnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbGVmdC5jbGFzc05hbWUgPSAibmFtZSI7CiAgICAgICAgbGVmdC50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKICAgICAgICBjb25zdCBkdWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGR1ZVNwYW4uY2xhc3NOYW1lID0gImR1ZSI7CiAgICAgICAgZHVlU3Bhbi50ZXh0Q29udGVudCA9IGAke2RhdGVGb3JtYXR0ZXIuZm9ybWF0KGRhdGUpfSDCtyAke2R1ZUxhYmVsfWA7CiAgICAgICAgbGVmdC5hcHBlbmRDaGlsZChkdWVTcGFuKTsKICAgICAgICBjb25zdCBhbW91bnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50LmNsYXNzTmFtZSA9ICJhbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50LnRleHRDb250ZW50ID0gKHR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5hbW91bnQpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChsZWZ0KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoYW1vdW50KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRSZWN1cnJpbmcoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciKTsKICAgICAgICBhbGxSZWN1cnJpbmcgPSBpdGVtczsKICAgICAgICByZW5kZXJSZWN1cnJpbmcoaXRlbXMpOwogICAgICAgIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpOwogICAgICAgIHVwZGF0ZVVwY29taW5nU3VtbWFyeSgpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEV4cG9ydCBFeGNlbAogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQteGxzeCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC14bHN4Iik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkfDqW7DqXJhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvZXhwb3J0L3hsc3giLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBgZGVwZW5zZXNfJHt0b2RheUlzbygpfS54bHN4YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVzZXQtYWxsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgIlN1cHByaW1lciBEw4lGSU5JVElWRU1FTlQgdG91dGVzIGxlcyBkb25uw6llcyAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcykgPyBDZXR0ZSBhY3Rpb24gZXN0IGlycsOpdmVyc2libGUuIgogICAgICApOwogICAgICBpZiAoIW9rKSByZXR1cm47CiAgICAgIC8vIERvdWJsZSBjb25maXJtYXRpb24gdnUgbGUgY2FyYWN0w6hyZSBpcnLDqXZlcnNpYmxlIGV0IGNvbXBsZXQgZGUgbCdhY3Rpb24uCiAgICAgIGNvbnN0IG9rMiA9IGF3YWl0IHNob3dDb25maXJtKCJEZXJuacOocmUgY29uZmlybWF0aW9uIDogdnJhaW1lbnQgdG91dCByw6lpbml0aWFsaXNlciA/Iik7CiAgICAgIGlmICghb2syKSByZXR1cm47CgogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpOwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3Jlc2V0LWFsbCIsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIHLDqWluaXRpYWxpc8OpZSIpOwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4gd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpLCA2MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJSw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uIjsKICAgICAgfQogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUFdBIDogaW5zdGFsbGF0aW9uIHN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGlmICgic2VydmljZVdvcmtlciIgaW4gbmF2aWdhdG9yKSB7CiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJsb2FkIiwgKCkgPT4gewogICAgICAgIG5hdmlnYXRvci5zZXJ2aWNlV29ya2VyLnJlZ2lzdGVyKCIvc3cuanMiKS5jYXRjaCgoKSA9PiB7fSk7CiAgICAgIH0pOwogICAgfQoKICAgIGxldCBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBudWxsOwogICAgY29uc3QgcHdhSW5zdGFsbFJvdyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwd2EtaW5zdGFsbC1yb3ciKTsKICAgIGNvbnN0IHB3YUluc3RhbGxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicHdhLWluc3RhbGwtYnRuIik7CiAgICBjb25zdCBwd2FJb3NIaW50Um93ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInB3YS1pb3MtaGludC1yb3ciKTsKCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiYmVmb3JlaW5zdGFsbHByb21wdCIsIChlKSA9PiB7CiAgICAgIC8vIEVtcMOqY2hlIGxhIG1pbmktaW5mb2JhciBhdXRvbWF0aXF1ZSBkdSBuYXZpZ2F0ZXVyIDogb24gYWZmaWNoZQogICAgICAvLyBwbHV0w7R0IG5vdHJlIHByb3ByZSBib3V0b24sIGRhbnMgbCdvbmdsZXQgRXhwb3J0LCBjb2jDqXJlbnQgYXZlYwogICAgICAvLyBsZSByZXN0ZSBkdSBzaXRlLgogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGRlZmVycmVkSW5zdGFsbFByb21wdCA9IGU7CiAgICAgIGlmIChwd2FJbnN0YWxsUm93KSBwd2FJbnN0YWxsUm93LnN0eWxlLmRpc3BsYXkgPSAiIjsKICAgIH0pOwoKICAgIGlmIChwd2FJbnN0YWxsQnRuKSB7CiAgICAgIHB3YUluc3RhbGxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgaWYgKCFkZWZlcnJlZEluc3RhbGxQcm9tcHQpIHJldHVybjsKICAgICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQucHJvbXB0KCk7CiAgICAgICAgY29uc3QgeyBvdXRjb21lIH0gPSBhd2FpdCBkZWZlcnJlZEluc3RhbGxQcm9tcHQudXNlckNob2ljZTsKICAgICAgICBkZWZlcnJlZEluc3RhbGxQcm9tcHQgPSBudWxsOwogICAgICAgIGlmIChwd2FJbnN0YWxsUm93KSBwd2FJbnN0YWxsUm93LnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaWYgKG91dGNvbWUgPT09ICJhY2NlcHRlZCIpIHNob3dUb2FzdCgiQXBwbGljYXRpb24gaW5zdGFsbMOpZSIpOwogICAgICB9KTsKICAgIH0KCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiYXBwaW5zdGFsbGVkIiwgKCkgPT4gewogICAgICBpZiAocHdhSW5zdGFsbFJvdykgcHdhSW5zdGFsbFJvdy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgfSk7CgogICAgLy8gU2FmYXJpIGlPUyBuZSBkw6ljbGVuY2hlIGphbWFpcyAiYmVmb3JlaW5zdGFsbHByb21wdCIgOiBvbiBhZmZpY2hlIMOgIGxhCiAgICAvLyBwbGFjZSB1biBwZXRpdCBtb2RlIGQnZW1wbG9pIChQYXJ0YWdlciA+IFN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwpLCBzYXVmCiAgICAvLyBzaSBsJ2FwcCBlc3QgZMOpasOgIGluc3RhbGzDqWUgKG1vZGUgc3RhbmRhbG9uZSkuCiAgICBjb25zdCBpc0lvcyA9IC9pcGhvbmV8aXBhZHxpcG9kL2kudGVzdChuYXZpZ2F0b3IudXNlckFnZW50KTsKICAgIGNvbnN0IGlzU3RhbmRhbG9uZSA9CiAgICAgIHdpbmRvdy5tYXRjaE1lZGlhKCIoZGlzcGxheS1tb2RlOiBzdGFuZGFsb25lKSIpLm1hdGNoZXMgfHwgd2luZG93Lm5hdmlnYXRvci5zdGFuZGFsb25lID09PSB0cnVlOwogICAgaWYgKGlzSW9zICYmICFpc1N0YW5kYWxvbmUgJiYgcHdhSW9zSGludFJvdykgewogICAgICBwd2FJb3NIaW50Um93LnN0eWxlLmRpc3BsYXkgPSAiIjsKICAgIH0KCiAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoImV4cGVuc2UiKTsKICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgICAgLy8gQ2F0w6lnb3JpZXMgcGVyc28gKyBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgZCdhYm9yZCwgcG91ciBxdWUgbGVzCiAgICAgIC8vIGxpc3RlcyBkw6lyb3VsYW50ZXMgZXQgbGUgYmFuZGVhdSBzb2llbnQgY29ycmVjdHMgZMOocyBsZSBwcmVtaWVyCiAgICAgIC8vIHJlbmR1IHBsdXTDtHQgcXVlIGRlICJzYXV0ZXIiIHVuZSBmb2lzIGxlIHNlcnZldXIgcsOpcG9uZHUuCiAgICAgIGF3YWl0IFByb21pc2UuYWxsKFtsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpLCBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSwgbG9hZEJ1ZGdldHMoKSwgbG9hZFNhdmluZ3NHb2FsKCldKTsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBsb2FkUmVjdXJyaW5nKCk7CiAgICB9KSgpOwogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
}

# Service worker minimal : pas de cache hors-ligne pour l'instant (les
# données viennent de toute façon de l'API), juste ce qu'il faut pour que
# Chrome/Android considère le site comme installable (manifest + SW avec un
# gestionnaire fetch). Un passthrough simple, sans mise en cache, pour ne
# jamais servir de données périmées.
PWA_SERVICE_WORKER = """
self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  event.respondWith(fetch(event.request));
});
"""


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
