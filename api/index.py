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

from fastapi import Depends, FastAPI, Header, HTTPException, Response
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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vY2hhcnQuanNANC40LjQvZGlzdC9jaGFydC51bWQubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAudGFicyB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICB9CiAgLnRhYi1idG4gewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudGFiLWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnRvb2x0aXAtaG9zdCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgY3Vyc29yOiBoZWxwOyB9CiAgLmN1c3RvbS10b29sdGlwIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIGxlZnQ6IDUwJTsKICAgIGJvdHRvbTogY2FsYygxMDAlICsgMC42cmVtKTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDRweCk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjU1cmVtIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuNzhyZW07CiAgICBsaW5lLWhlaWdodDogMS41OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICAgIHRleHQtYWxpZ246IGxlZnQ7CiAgICBib3gtc2hhZG93OiAwIDhweCAyMHB4IHJnYmEoMCwgMCwgMCwgMC4zNSk7CiAgICBvcGFjaXR5OiAwOwogICAgcG9pbnRlci1ldmVudHM6IG5vbmU7CiAgICB0cmFuc2l0aW9uOiBvcGFjaXR5IDAuMTJzIGVhc2UsIHRyYW5zZm9ybSAwLjEycyBlYXNlOwogICAgei1pbmRleDogMjA7CiAgfQogIC5jdXN0b20tdG9vbHRpcDo6YWZ0ZXIgewogICAgY29udGVudDogIiI7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDEwMCU7CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBib3JkZXI6IDZweCBzb2xpZCB0cmFuc3BhcmVudDsKICAgIGJvcmRlci10b3AtY29sb3I6IHZhcigtLXN1cmZhY2UtMik7CiAgfQogIC5jdXN0b20tdG9vbHRpcC52aXNpYmxlIHsKICAgIG9wYWNpdHk6IDE7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSgwKTsKICAgIHBvaW50ZXItZXZlbnRzOiBhdXRvOwogIH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAud2Vlay1zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IC0wLjRyZW0gYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CgogIC5jYXRlZ29yeS1zdWdnZXN0aW9uIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMC45cmVtIDEuMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYWNjZW50LWRpbSk7CiAgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiBwIHsgbWFyZ2luOiAwIDAgMC43cmVtOyBmb250LXNpemU6IDAuODhyZW07IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIHsgZGlzcGxheTogZmxleDsgZmxleC13cmFwOiB3cmFwOyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIHNlbGVjdCwKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBpbnB1dFt0eXBlPSJ0ZXh0Il0gewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtLCAuYnRuLXNlY29uZGFyeS1zbSB7CiAgICBib3JkZXI6IG5vbmU7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjRyZW0gMC44cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuYnRuLXByaW1hcnktc20geyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogI2ZmZjsgfQogIC5idG4tc2Vjb25kYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KCiAgLmZpbHRlci1iYXIgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtd3JhcDogd3JhcDsKICAgIGdhcDogMC41cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogIH0KICAuZmlsdGVyLWJhciBpbnB1dCwKICAuZmlsdGVyLWJhciBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBmbGV4OiAxIDEgMTMwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogICNmaWx0ZXItc2VhcmNoIHsgZmxleDogMSAxIDEwMCU7IH0KCiAgLnR4LWxpc3QgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDAuNnJlbTsgfQoKICAudHgtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgfQogIC50eC1jYXJkLmluY29tZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50eC1jYXJkLmV4cGVuc2UgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudHgtbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC50eC10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgfQogIC5jYXRlZ29yeS1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC50eC1kYXRlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnR4LXJlY3VycmluZy1iYWRnZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgb3BhY2l0eTogMC43OyBjdXJzb3I6IGhlbHA7IH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyAuY2hhcnQtd3JhcCB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC51cGNvbWluZy1ub3RlIHsKICAgIHdpZHRoOiA5NnB4OwogICAgZmxleC1zaHJpbms6IDA7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNHJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXI6IDFweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuNzJyZW07CiAgICBsaW5lLWhlaWdodDogMS4yNTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQogIC51cGNvbWluZy1ub3RlLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctc3dhdGNoIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAxNHB4OwogICAgYm9yZGVyOiAxLjVweCBkYXNoZWQgdmFyKC0tZGFuZ2VyKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC51cGNvbWluZy1ub3RlLnBvc2l0aXZlIC51cGNvbWluZy1zd2F0Y2ggewogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMik7CiAgfQoKICAucmVjdXJyaW5nLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY3VycmluZy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5leHBvcnQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZXhwb3J0LXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLnJlY3VycmluZy1oaW50IHsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW46IDAgMCAwLjlyZW07CiAgfQoKICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjhyZW0gMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgaDQgeyBtYXJnaW46IDAgMCAwLjZyZW07IGZvbnQtc2l6ZTogMC45cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBiYXNlbGluZTsKICAgIHBhZGRpbmc6IDAuMzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgKyAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLm5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuZHVlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjc4cmVtOyBtYXJnaW4tbGVmdDogMC40cmVtOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuY29tcGFyZS1zZWxlY3RzIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjZyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc2VsZWN0IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40NXJlbSAwLjZyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5jb21wYXJlLXNlbGVjdHMgc3BhbiB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQoKICAuc2ltcGxlLXRhYmxlIHsgd2lkdGg6IDEwMCU7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IGZvbnQtc2l6ZTogMC44NXJlbTsgfQogIC5zaW1wbGUtdGFibGUgdGgsIC5zaW1wbGUtdGFibGUgdGQgeyBwYWRkaW5nOiAwLjVyZW0gMC42cmVtOyB0ZXh0LWFsaWduOiByaWdodDsgfQogIC5zaW1wbGUtdGFibGUgdGg6Zmlyc3QtY2hpbGQsIC5zaW1wbGUtdGFibGUgdGQ6Zmlyc3QtY2hpbGQgeyB0ZXh0LWFsaWduOiBsZWZ0OyB9CiAgLnNpbXBsZS10YWJsZSB0aGVhZCB0aCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtd2VpZ2h0OiA1MDA7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSB0Ym9keSB0ciArIHRyIHRkIHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyLnRvdGFsLXJvdyB0ZCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGJvcmRlci10b3A6IDJweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zaW1wbGUtdGFibGUgLmRpZmYtbmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50cmVuZC11cCB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLWRvd24geyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHJlbmQtZmxhdCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KCiAgLmJ1ZGdldC1yb3cgeyBtYXJnaW4tYm90dG9tOiAwLjlyZW07IH0KICAuYnVkZ2V0LXJvdy1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjVyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjM1cmVtOwogIH0KICAuYnVkZ2V0LWNhdC1uYW1lIHsgY29sb3I6IHZhcigtLXRleHQpOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLmJ1ZGdldC1hbW91bnRzIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWlucHV0IHsKICAgIHdpZHRoOiA2NHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA2cHg7CiAgICBwYWRkaW5nOiAwLjI1cmVtIDAuNHJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmJ1ZGdldC1iYXItdHJhY2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgaGVpZ2h0OiA4cHg7IG92ZXJmbG93OiBoaWRkZW47IH0KICAuYnVkZ2V0LWJhci1maWxsIHsgaGVpZ2h0OiAxMDAlOyBib3JkZXItcmFkaXVzOiA5OTlweDsgdHJhbnNpdGlvbjogd2lkdGggMC4ycyBlYXNlOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vayB7IGJhY2tncm91bmQ6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5idWRnZXQtYmFyLWZpbGwub3ZlciB7IGJhY2tncm91bmQ6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1hY2NlbnQpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC42cmVtOwogIH0KICAucmVjLWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnJlYy1jYXJkLmluY29tZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtY2FyZC5lbmRlZCB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG9wYWNpdHk6IDAuNjsgfQogIC5yZWMtbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC5yZWMtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IGZsZXgtd3JhcDogd3JhcDsgfQogIC5yZWMtbmFtZSB7IGZvbnQtc2l6ZTogMC45NXJlbTsgb3ZlcmZsb3c6IGhpZGRlbjsgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLXN1YiB7IGZvbnQtc2l6ZTogMC43OHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5lbmQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7CiAgICBjb2xvcjogI2ZjYTVhNTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5zdGFydC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4xNSk7CiAgICBjb2xvcjogIzkzYzVmZDsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC5yZWMtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuZmFiIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiAxLjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogICAgY29sb3I6IHdoaXRlOwogICAgZm9udC1zaXplOiAxLjhyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSg1OSwgMTMwLCAyNDYsIDAuNCk7CiAgfQogIC5mYWI6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQoKICAuZmFiLW1pYyB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogNS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDAsIDAsIDAsIDAuMyk7CiAgICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAuMnMsIGJvcmRlci1jb2xvciAwLjJzOwogIH0KICAuZmFiLW1pYzphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CiAgLmZhYi1taWMubGlzdGVuaW5nIHsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7CiAgICBhbmltYXRpb246IHB1bHNlIDEuMnMgaW5maW5pdGU7CiAgfQogIC5mYWItbWljLnByb2Nlc3NpbmcgeyBvcGFjaXR5OiAwLjY7IGN1cnNvcjogZGVmYXVsdDsgfQogIC5mYWItbWljOmRpc2FibGVkIHsgb3BhY2l0eTogMC4zNTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQogIEBrZXlmcmFtZXMgcHVsc2UgewogICAgMCUsIDEwMCUgeyBib3gtc2hhZG93OiAwIDAgMCAwIHJnYmEoMjM5LCA2OCwgNjgsIDAuNCk7IH0KICAgIDUwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDEwcHggcmdiYSgyMzksIDY4LCA2OCwgMCk7IH0KICB9CgogIC52b2ljZS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTU7CiAgfQogIC52b2ljZS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQoKICAubW9kYWwtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC41NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGZsZXgtZW5kOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDsKICB9CiAgLm1vZGFsLW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5tb2RhbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlci1yYWRpdXM6IDE4cHggMThweCAwIDA7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSBjYWxjKDEuNXJlbSArIGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKSk7CiAgICB3aWR0aDogMTAwJTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC45cmVtOwogIH0KICAubW9kYWwgaDIgeyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXNpemU6IDEuMXJlbTsgfQoKICBsYWJlbCB7IGZvbnQtc2l6ZTogMC44cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4zcmVtOyB9CiAgaW5wdXQsIHNlbGVjdCB7CiAgICB3aWR0aDogMTAwJTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNjVyZW0gMC43NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgaW5wdXQ6Zm9jdXMsIHNlbGVjdDpmb2N1cyB7IG91dGxpbmU6IG5vbmU7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQoKICAudHlwZS10b2dnbGUgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgfQogIC50eXBlLWJ0biB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC42NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iZXhwZW5zZSJdIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iaW5jb21lIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5jb25maXJtLW1vZGFsIHsgbWF4LXdpZHRoOiA0MDBweDsgfQogIC5jb25maXJtLW1vZGFsLW1lc3NhZ2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IGZvbnQtc2l6ZTogMC45NXJlbTsgbWFyZ2luOiAwOyBsaW5lLWhlaWdodDogMS40OyB9CiAgYnV0dG9uLnByaW1hcnksIGJ1dHRvbi5zZWNvbmRhcnkgewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNzVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiBub25lOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICBidXR0b24ucHJpbWFyeTpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQogIGJ1dHRvbi5zZWNvbmRhcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICA8aGVhZGVyPgogICAgPGgxPvCfkrMgU3VpdmkgZGUgZMOpcGVuc2VzPC9oMT4KICAgIDxwIGNsYXNzPSJzdWJ0aXRsZSI+VGVzIGTDqXBlbnNlcyBldCByZXZlbnVzLCBham91dMOpcyBvdSDDqWRpdMOpcyBtYW51ZWxsZW1lbnQuPC9wPgogIDwvaGVhZGVyPgoKICA8ZGl2IGNsYXNzPSJ0YWJzIj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biBhY3RpdmUiIGlkPSJ0YWItaGlzdG9yeSIgZGF0YS12aWV3PSJoaXN0b3J5Ij5IaXN0b3JpcXVlPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItZGFzaGJvYXJkIiBkYXRhLXZpZXc9ImRhc2hib2FyZCI+VGFibGVhdSBkZSBib3JkPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItcmVjdXJyaW5nIiBkYXRhLXZpZXc9InJlY3VycmluZyI+UsOpY3VycmVudGVzPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItZXhwb3J0IiBkYXRhLXZpZXc9ImV4cG9ydCI+RXhwb3J0PC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5CdWRnZXRzIG1lbnN1ZWxzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgSW5kaXF1ZSB1biBtb250YW50IHBvdXIgdW5lIGNhdMOpZ29yaWUgZXQgZW5yZWdpc3RyZSBhdmVjIPCfkr4g4oCUIGxhIGJhcnJlCiAgICAgICAgICBjb21wYXJlIGVuc3VpdGUgdGVzIGTDqXBlbnNlcyBkdSBtb2lzIGVuIGNvdXJzIMOgIGNlIHBsYWZvbmQgKHZlcnQsCiAgICAgICAgICBvcmFuZ2UgYXUtZGVsw6AgZGUgNzAlLCByb3VnZSBhdS1kZWzDoCBkZSAxMDAlKS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBpZD0iYnVkZ2V0cy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyByZXZlbnVzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWluY29tZS1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtaW5jb21lLWNhdGVnb3JpZXMtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIEF1Y3VuIHJldmVudSBjZSBtb2lzLWzDoC4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+w4l2b2x1dGlvbiBtZW5zdWVsbGUgKGTDqXBlbnNlcyB2cyByZXZlbnVzKTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1ldm9sdXRpb24iPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkNvbXBhcmVyIGRldXggbW9pczwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY29tcGFyZS1zZWxlY3RzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYSI+PC9zZWxlY3Q+CiAgICAgICAgICA8c3Bhbj52czwvc3Bhbj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYiI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgYXNzZXogZGUgbW9pcyBkaWZmw6lyZW50cyBwb3VyIGNvbXBhcmVyLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Nb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8ZGl2IGlkPSJ0cmVuZC10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJ0cmVuZC1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIiBjbGFzcz0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGhpZGRlbiI+CiAgICAgICAgPGg0PlByb2NoYWluZXMgw6ljaMOpYW5jZXM8L2g0PgogICAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1lbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgQXVjdW5lIGTDqXBlbnNlIHLDqWN1cnJlbnRlIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZXhwb3J0IiBjbGFzcz0iZXhwb3J0LXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+RXhwb3J0ZXIgdGVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgVMOpbMOpY2hhcmdlIHVuIGZpY2hpZXIgRXhjZWwgKC54bHN4KSBhdmVjIHRvdXRlcyB0ZXMgdHJhbnNhY3Rpb25zCiAgICAgICAgICAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcyAoZMOpcGVuc2VzIGV0CiAgICAgICAgICByZXZlbnVzIHLDqWN1cnJlbnRzKSwgY2hhY3VuZSBkYW5zIHNvbiBwcm9wcmUgb25nbGV0LgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLWV4cG9ydC14bHN4IiBzdHlsZT0id2lkdGg6MTAwJTsiPlTDqWzDqWNoYXJnZXIgbGUgZmljaGllciBFeGNlbDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICA8L21haW4+CgogIDxkaXYgY2xhc3M9InZvaWNlLWJhbm5lciBoaWRkZW4iIGlkPSJ2b2ljZS1iYW5uZXIiPjwvZGl2PgogIDxidXR0b24gY2xhc3M9ImZhYi1taWMiIGlkPSJmYWItbWljIiBhcmlhLWxhYmVsPSJEaWN0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudSI+8J+OpDwvYnV0dG9uPgogIDxidXR0b24gY2xhc3M9ImZhYiIgaWQ9ImZhYi1hZGQiIGFyaWEtbGFiZWw9IkFqb3V0ZXIiPis8L2J1dHRvbj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJtb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJtb2RhbC10aXRsZSI+Tm91dmVsbGUgdHJhbnNhY3Rpb248L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJ0eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9ImlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGVzY3JpcHRpb24iPkRlc2NyaXB0aW9uIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImlucHV0LWRlc2NyaXB0aW9uIiBwbGFjZWhvbGRlcj0iRXggOiBkw6lqZXVuZXIgYXZlYyBQYXVsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGF0ZSI+RGF0ZTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJpbnB1dC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWMtbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0icmVjLW1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSBkw6lwZW5zZSByw6ljdXJyZW50ZTwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InJlYy10eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LW5hbWUiPk5vbTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJyZWMtaW5wdXQtbmFtZSIgcGxhY2Vob2xkZXI9IkV4IDogTmV0ZmxpeCwgTG95ZXIsIFNhbGFpcmUuLi4iPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0icmVjLWlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWRheSI+Sm91ciBkdSBtb2lzPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWRheSIgbWluPSIxIiBtYXg9IjMxIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iMSDDoCAzMSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1zdGFydC1kYXRlIj5EYXRlIGRlIGTDqWJ1dCAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1lbmQtZGF0ZSI+RGF0ZSBkZSBmaW4gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LWVuZC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9InJlYy1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9InJlYy1idG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9ImNvbmZpcm0tbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCBjb25maXJtLW1vZGFsIj4KICAgICAgPGgyIGlkPSJjb25maXJtLW1vZGFsLXRpdGxlIj5Db25maXJtZXI8L2gyPgogICAgICA8cCBpZD0iY29uZmlybS1tb2RhbC1tZXNzYWdlIiBjbGFzcz0iY29uZmlybS1tb2RhbC1tZXNzYWdlIj48L3A+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImNvbmZpcm0tYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJjb25maXJtLWJ0bi1vayI+Q29uZmlybWVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBEb2l0IGNvcnJlc3BvbmRyZSBleGFjdGVtZW50IMOgIGxhIHZhcmlhYmxlIGQnZW52aXJvbm5lbWVudCBBUElfU0VDUkVUX0tFWSBzdXIgVmVyY2VsLgogICAgY29uc3QgQVBJX0tFWSA9ICIzSVBRc3lFUUZtY0JMbG1UZlRrMUlBeTFDbms5RjBlViI7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBkZXNjcmlwdGlvbklucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRlc2NyaXB0aW9uIik7CiAgICBjb25zdCBkYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGF0ZSIpOwogICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tc2F2ZSIpOwoKICAgIGxldCBlZGl0aW5nSWQgPSBudWxsOyAvLyBudWxsID0gY3LDqWF0aW9uLCBzaW5vbiBpZCBkZSBsYSB0cmFuc2FjdGlvbiDDqWRpdMOpZQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIC8vIENhdMOpZ29yaWVzIGNyw6nDqWVzIHBhciBsJ3V0aWxpc2F0ZXVyIGRlcHVpcyBsZSBiYW5kZWF1IGRlIHN1Z2dlc3Rpb24KICAgIC8vICh2b2lyIHBsdXMgYmFzKSwgZXQgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIDogc3RvY2vDqWVzIGPDtHTDqSBzZXJ2ZXVyCiAgICAvLyAodGFibGVzIGN1c3RvbV9jYXRlZ29yaWVzIC8gZGlzbWlzc2VkX2NhdGVnb3J5X3N1Z2dlc3Rpb25zKSBwbHV0w7R0CiAgICAvLyBxdWUgZGFucyBsZSBuYXZpZ2F0ZXVyLCBwb3VyIHN1aXZyZSBzdXIgdG91cyBsZXMgYXBwYXJlaWxzICh0w6lsw6lwaG9uZSwKICAgIC8vIHRhYmxldHRlLCBvcmRpbmF0ZXVyKSBwbHV0w7R0IHF1ZSBkZSBuZSBtYXJjaGVyIHF1ZSBsw6Agb8O5IGMnw6l0YWl0IGNyw6nDqS4KICAgIGxldCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoKTsKICAgIGxldCBhbGxCdWRnZXRzID0gW107CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEJ1ZGdldHMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgYWxsQnVkZ2V0cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgYnVkZ2V0cyA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB1cGRhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5LCBhbW91bnQgfSksCiAgICAgICAgfSk7CiAgICAgICAgY29uc3QgaWR4ID0gYWxsQnVkZ2V0cy5maW5kSW5kZXgoKGIpID0+IGIuY2F0ZWdvcnkgPT09IGNhdGVnb3J5KTsKICAgICAgICBpZiAoaWR4ID49IDApIGFsbEJ1ZGdldHNbaWR4XSA9IHVwZGF0ZWQ7CiAgICAgICAgZWxzZSBhbGxCdWRnZXRzLnB1c2godXBkYXRlZCk7CiAgICAgICAgc2hvd1RvYXN0KCJCdWRnZXQgZW5yZWdpc3Ryw6kiKTsKICAgICAgICByZW5kZXJCdWRnZXRzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1saXN0Iik7CiAgICAgIGlmICghd3JhcCkgcmV0dXJuOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CgogICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSkgewogICAgICAgIGNvbnN0IGJ1ZGdldCA9IGFsbEJ1ZGdldHMuZmluZCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gdmFsdWUpOwogICAgICAgIGNvbnN0IHNwZW50ID0gdG90YWxzW3ZhbHVlXSB8fCAwOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ciOwoKICAgICAgICBjb25zdCBoZWFkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZC5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdy1oZWFkIjsKCiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4uY2xhc3NOYW1lID0gImJ1ZGdldC1jYXQtbmFtZSI7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBsYWJlbDsKCiAgICAgICAgY29uc3QgYW1vdW50cyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRzLmNsYXNzTmFtZSA9ICJidWRnZXQtYW1vdW50cyI7CiAgICAgICAgY29uc3Qgc3BlbnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHNwZW50U3Bhbi50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzcGVudCkgKyAiIC8gIjsKICAgICAgICBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgaW5wdXQudHlwZSA9ICJudW1iZXIiOwogICAgICAgIGlucHV0LmNsYXNzTmFtZSA9ICJidWRnZXQtaW5wdXQiOwogICAgICAgIGlucHV0Lm1pbiA9ICIwIjsKICAgICAgICBpbnB1dC5zdGVwID0gIjEiOwogICAgICAgIGlucHV0LnBsYWNlaG9sZGVyID0gIuKAlCI7CiAgICAgICAgaWYgKGJ1ZGdldCkgaW5wdXQudmFsdWUgPSBidWRnZXQuYW1vdW50OwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoc3BlbnRTcGFuKTsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKGlucHV0KTsKCiAgICAgICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIHNhdmVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBzYXZlQnRuLnRleHRDb250ZW50ID0gIvCfkr4iOwogICAgICAgIHNhdmVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIkVucmVnaXN0cmVyIGxlIGJ1ZGdldCIpOwogICAgICAgIHNhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIoaW5wdXQudmFsdWUpOwogICAgICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIHVuIG1vbnRhbnQgZGUgYnVkZ2V0IHZhbGlkZSIsIHRydWUpOwogICAgICAgICAgICByZXR1cm47CiAgICAgICAgICB9CiAgICAgICAgICBzYXZlQnVkZ2V0KHZhbHVlLCBhbW91bnQpOwogICAgICAgIH0pOwoKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKG5hbWVTcGFuKTsKICAgICAgICBoZWFkLmFwcGVuZENoaWxkKGFtb3VudHMpOwogICAgICAgIGhlYWQuYXBwZW5kQ2hpbGQoc2F2ZUJ0bik7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGhlYWQpOwoKICAgICAgICBpZiAoYnVkZ2V0KSB7CiAgICAgICAgICBjb25zdCB0cmFjayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgdHJhY2suY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItdHJhY2siOwogICAgICAgICAgY29uc3QgZmlsbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgY29uc3QgcmF0aW8gPSBzcGVudCAvIGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgICBjb25zdCBwY3QgPSBNYXRoLm1pbihyYXRpbyAqIDEwMCwgMTAwKTsKICAgICAgICAgIGxldCBjbHMgPSAib2siOwogICAgICAgICAgaWYgKHJhdGlvID49IDEpIGNscyA9ICJvdmVyIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvID49IDAuNykgY2xzID0gIndhcm5pbmciOwogICAgICAgICAgZmlsbC5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci1maWxsICIgKyBjbHM7CiAgICAgICAgICBmaWxsLnN0eWxlLndpZHRoID0gcGN0ICsgIiUiOwogICAgICAgICAgdHJhY2suYXBwZW5kQ2hpbGQoZmlsbCk7CiAgICAgICAgICByb3cuYXBwZW5kQ2hpbGQodHJhY2spOwogICAgICAgIH0KCiAgICAgICAgd3JhcC5hcHBlbmRDaGlsZChyb3cpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEN1c3RvbUNhdGVnb3JpZXMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIpOwogICAgICAgIGZvciAoY29uc3QgeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSBvZiBpdGVtcykgewogICAgICAgICAgaWYgKGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0gJiYgIWNhdGVnb3JpZXNCeVR5cGVbdHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB2YWx1ZSkpIHsKICAgICAgICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBjYXTDqWdvcmllcyA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3Qga2V5cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2Rpc21pc3NlZC1zdWdnZXN0aW9ucyIpOwogICAgICAgIGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldChrZXlzKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSB1bmUgc3VnZ2VzdGlvbiBkw6lqw6AgdnVlIHLDqWFwcGFyYcOudCB1bmUgZm9pcy4KICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNsdWdpZnlDYXRlZ29yeShsYWJlbCkgewogICAgICByZXR1cm4gKAogICAgICAgIGxhYmVsCiAgICAgICAgICAubm9ybWFsaXplKCJORkQiKS5yZXBsYWNlKC9bzIAtza9dL2csICIiKSAvLyBlbmzDqHZlIGxlcyBhY2NlbnRzCiAgICAgICAgICAudG9Mb3dlckNhc2UoKQogICAgICAgICAgLnRyaW0oKQogICAgICAgICAgLnJlcGxhY2UoL1teYS16MC05XSsvZywgIl8iKQogICAgICAgICAgLnJlcGxhY2UoL15fK3xfKyQvZywgIiIpIHx8ICJhdXRyZSIKICAgICAgKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQ3VzdG9tQ2F0ZWdvcnkodHlwZSwgdmFsdWUsIGxhYmVsKSB7CiAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHR5cGUsIHZhbHVlLCBsYWJlbCB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJDYXTDqWdvcmllIGNyw6nDqWUgaWNpLCBtYWlzIHBhcyBzYXV2ZWdhcmTDqWUgc3VyIGxlIHNlcnZldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgY29uc3QgY3VycmVuY3lGb3JtYXR0ZXIgPSBuZXcgSW50bC5OdW1iZXJGb3JtYXQoImZyLUZSIiwgeyBzdHlsZTogImN1cnJlbmN5IiwgY3VycmVuY3k6ICJFVVIiIH0pOwogICAgY29uc3QgZGF0ZUZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgZGF5OiAibnVtZXJpYyIsIG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CgogICAgZnVuY3Rpb24gc2hvd1RvYXN0KG1lc3NhZ2UsIGlzRXJyb3IgPSBmYWxzZSkgewogICAgICBjb25zdCB0b2FzdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICB0b2FzdC5jbGFzc05hbWUgPSAidG9hc3QiICsgKGlzRXJyb3IgPyAiIGVycm9yIiA6ICIiKTsKICAgICAgdG9hc3QudGV4dENvbnRlbnQgPSBtZXNzYWdlOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRvYXN0KTsKICAgICAgc2V0VGltZW91dCgoKSA9PiB0b2FzdC5yZW1vdmUoKSwgMzAwMCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCwgb3B0aW9ucyA9IHt9KSB7CiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKHBhdGgsIHsKICAgICAgICAuLi5vcHRpb25zLAogICAgICAgIGhlYWRlcnM6IHsKICAgICAgICAgICJYLUFQSS1LZXkiOiBBUElfS0VZLAogICAgICAgICAgLi4uKG9wdGlvbnMuYm9keSA/IHsgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiB9IDoge30pLAogICAgICAgICAgLi4uKG9wdGlvbnMuaGVhZGVycyB8fCB7fSksCiAgICAgICAgfSwKICAgICAgfSk7CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgbGV0IGRldGFpbCA9IHJlcy5zdGF0dXNUZXh0OwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGRhdGEuZGV0YWlsIHx8IGRldGFpbDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIHRocm93IG5ldyBFcnJvcihkZXRhaWwpOwogICAgICB9CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSAyMDQpIHJldHVybiBudWxsOwogICAgICByZXR1cm4gcmVzLmpzb24oKTsKICAgIH0KCiAgICBmdW5jdGlvbiB0b2RheUlzbygpIHsKICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IHR6ID0gZC5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKGQuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgc2VsZWN0ZWRWYWx1ZSA9IG51bGwpIHsKICAgICAgY2F0ZWdvcnlJbnB1dC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgaWYgKHZhbHVlID09PSAoc2VsZWN0ZWRWYWx1ZSB8fCAiYXV0cmUiKSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBjYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBtb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiTW9kaWZpZXIgbGEgdHJhbnNhY3Rpb24iIDogIk5vdXZlbGxlIHRyYW5zYWN0aW9uIjsKICAgICAgc2F2ZUJ0bi50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFR5cGUodHggPyB0eC50eXBlIDogImV4cGVuc2UiKTsKICAgICAgYW1vdW50SW5wdXQudmFsdWUgPSB0eCA/IHR4LmFtb3VudCA6ICIiOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoY3VycmVudFR5cGUsIHR4ID8gdHguY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgZGVzY3JpcHRpb25JbnB1dC52YWx1ZSA9IHR4ID8gKHR4LmRlc2NyaXB0aW9uIHx8ICIiKSA6ICIiOwogICAgICBkYXRlSW5wdXQudmFsdWUgPSB0eCA/IHR4LmV4cGVuc2VfZGF0ZSA6IHRvZGF5SXNvKCk7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkgewogICAgICAvLyBNw6ptZSBtb250YW50L2NhdMOpZ29yaWUvZGVzY3JpcHRpb24sIG1haXMgZGF0w6kgZCdhdWpvdXJkJ2h1aSBldCBzYW5zCiAgICAgIC8vIGlkIDogbGEgc2F1dmVnYXJkZSBjcsOpZXJhIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiAodm9pciBvcGVuTW9kYWwpLgogICAgICBvcGVuTW9kYWwoeyAuLi50eCwgaWQ6IG51bGwsIGV4cGVuc2VfZGF0ZTogdG9kYXlJc28oKSB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1hZGQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAicmVjdXJyaW5nIikgb3BlblJlY3VycmluZ01vZGFsKCk7CiAgICAgIGVsc2Ugb3Blbk1vZGFsKCk7CiAgICB9KTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZU1vZGFsKTsKICAgIG92ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheUVsKSBjbG9zZU1vZGFsKCk7IH0pOwoKICAgIHNhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQoYW1vdW50SW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIG1vZGlmacOpZSIpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgfQogICAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRyYW5zYWN0aW9uKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgdHJhbnNhY3Rpb24gPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIFRvdGF1eCBnbG9iYXV4IChTb2xkZS9Ew6lwZW5zZXMvUmV2ZW51cykgOiBjYWxjdWzDqXMgc3VyIFRPVVRFUyBsZXMKICAgIC8vIHRyYW5zYWN0aW9ucywgaW5kw6lwZW5kYW1tZW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSDigJQgdW4gZmlsdHJlCiAgICAvLyBzZXJ0IMOgIGNoZXJjaGVyIGRhbnMgbGEgbGlzdGUsIHBhcyDDoCByZWNhbGN1bGVyIGxlIHNvbGRlIHLDqWVsLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucykgewogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSB0b3RhbEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBlbHNlIHRvdGFsRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgYmFsYW5jZSA9IHRvdGFsSW5jb21lIC0gdG90YWxFeHBlbnNlczsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiYWxhbmNlKTsKICAgICAgc3VtbWFyeUJhbGFuY2VFbC5jbGFzc05hbWUgPSAidmFsdWUgIiArIChiYWxhbmNlID49IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIHN1bW1hcnlFeHBlbnNlc0VsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsRXhwZW5zZXMpOwogICAgICBzdW1tYXJ5SW5jb21lRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgfQoKICAgIC8vIENvbnN0cnVjdGlvbiBkZSBsYSBsaXN0ZSBkZSBjYXJ0ZXMgYWZmaWNow6llIGRhbnMgbCdvbmdsZXQgSGlzdG9yaXF1ZSDigJQKICAgIC8vIHJlw6dvaXQgZMOpasOgIGxhIGxpc3RlIGZpbHRyw6llICh2b2lyIGFwcGx5SGlzdG9yeUZpbHRlcnMpLgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25MaXN0KHRyYW5zYWN0aW9ucykgewogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGlmICh0cmFuc2FjdGlvbnMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGVtcHR5U3RhdGVFbC50ZXh0Q29udGVudCA9IGFsbFRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDAKICAgICAgICAgID8gIlJpZW4gcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgbGUgYm91dG9uICsgcG91ciBham91dGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUuIgogICAgICAgICAgOiAiQXVjdW4gcsOpc3VsdGF0IHBvdXIgY2VzIGZpbHRyZXMuIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAidHgtY2FyZCAiICsgdHgudHlwZTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInR4LW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gInR4LXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkYXRlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkYXRlU3Bhbi5jbGFzc05hbWUgPSAidHgtZGF0ZSI7CiAgICAgICAgZGF0ZVNwYW4udGV4dENvbnRlbnQgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh0eC5leHBlbnNlX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChiYWRnZSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGRhdGVTcGFuKTsKICAgICAgICBpZiAodHgucmVjdXJyaW5nX2V4cGVuc2VfaWQpIHsKICAgICAgICAgIGNvbnN0IHJlY0JhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgcmVjQmFkZ2UuY2xhc3NOYW1lID0gInR4LXJlY3VycmluZy1iYWRnZSI7CiAgICAgICAgICByZWNCYWRnZS50ZXh0Q29udGVudCA9ICLwn5SBIjsKICAgICAgICAgIHJlY0JhZGdlLnRpdGxlID0gIkNyw6nDqWUgYXV0b21hdGlxdWVtZW50IGRlcHVpcyB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChyZWNCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9uZ2xldHMgKEhpc3RvcmlxdWUgLyBUYWJsZWF1IGRlIGJvcmQpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzd2l0Y2hWaWV3KHZpZXcpIHsKICAgICAgY3VycmVudFZpZXcgPSB2aWV3OwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiaGlzdG9yeSIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1oaXN0b3J5Iikuc3R5bGUuZGlzcGxheSA9IHZpZXcgPT09ICJoaXN0b3J5IiA/ICJibG9jayIgOiAibm9uZSI7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGlmICh2aWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIG1vbnRoS2V5T2YoZXhwZW5zZURhdGUpIHsKICAgICAgcmV0dXJuIGV4cGVuc2VEYXRlLnNsaWNlKDAsIDcpOyAvLyAiWVlZWS1NTSIKICAgIH0KCiAgICAvLyBVbmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNvbXB0ZSBwb3VyIHVuIG1vaXMgZG9ubsOpIHNpIGNlIG1vaXMgZXN0IGRhbnMgc2EKICAgIC8vIHDDqXJpb2RlIGQnYWN0aXZpdMOpIDogcGFzIGF2YW50IHNhIGRhdGUgZGUgZMOpYnV0IChzaSBwb3PDqWUpLCBwYXMgYXByw6hzCiAgICAvLyBsZSBtb2lzIGRlIHNhIGRhdGUgZGUgZmluIChzaSBwb3PDqWUpLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpIHsKICAgICAgaWYgKGl0ZW0uc3RhcnRfZGF0ZSAmJiBtb250aEtleSA8IGl0ZW0uc3RhcnRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICBpZiAoaXRlbS5lbmRfZGF0ZSAmJiBtb250aEtleSA+IGl0ZW0uZW5kX2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgcmV0dXJuIHRydWU7CiAgICB9CgogICAgLy8gSm91ciBkdSBtb2lzIGp1c3F1J2F1cXVlbCB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGVzdCBjb25zaWTDqXLDqWUgY29tbWUKICAgIC8vICJkw6lqw6AgcHLDqWxldsOpZSIgcG91ciBsZSBtb2lzIGBtb250aEtleWAgOiB0b3VzIGxlcyBqb3VycyBwb3VyIHVuIG1vaXMKICAgIC8vIGTDqWrDoCBwYXNzw6ksIGF1Y3VuIHBvdXIgdW4gbW9pcyBmdXR1ciwgZXQgbGUgam91ciBkdSBqb3VyIHBvdXIgbGUgbW9pcwogICAgLy8gZW4gY291cnMuIFBlcm1ldCBkZSBkaXN0aW5ndWVyIGNlIHF1aSBlc3QgZMOpasOgIGFycml2w6kgZGUgY2UgcXVpIGVzdAogICAgLy8gc2V1bGVtZW50IHByw6l2dSAoZXggOiB1biBhYm9ubmVtZW50IHByw6lsZXbDqSBsZSAyNSwgb24gZXN0IGxlIDIpLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KSB7CiAgICAgIGlmIChtb250aEtleSA8IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDMxOwogICAgICBpZiAobW9udGhLZXkgPiBjdXJyZW50TW9udGhLZXkpIHJldHVybiAwOwogICAgICByZXR1cm4gdG9kYXlEYXk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhTZXQgPSBuZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwKSBtb250aFNldC5hZGQobW9udGhLZXlPZih0b2RheUlzbygpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSAiIjsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSAiQXVjdW5lIGRvbm7DqWUiOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCBrZXkgb2YgbW9udGhzKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBzZWxlY3QudmFsdWUgPSBtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkgPyBwcmV2aW91c1ZhbHVlIDogbW9udGhzWzBdOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5Iik7CiAgICAgIGNvbnN0IHVwY29taW5nTm90ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy1ub3RlIik7CiAgICAgIGNvbnN0IHVwY29taW5nVGV4dEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy10ZXh0Iik7CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGNvbnN0IGN1dG9mZiA9IHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSk7CgogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFVuIHNldWwgc29sZGUgbmV0ICLDoCB2ZW5pciIgKHJldmVudXMgcsOpY3VycmVudHMgw6AgdmVuaXIgbW9pbnMgZMOpcGVuc2VzCiAgICAgIC8vIHLDqWN1cnJlbnRlcyDDoCB2ZW5pciksIHBsdXTDtHQgcXVlIGRldXggY2hpZmZyZXMgc8OpcGFyw6lzIDogcGx1cyBzaW1wbGUKICAgICAgLy8gw6AgbGlyZSBkJ3VuIGNvdXAgZCfFk2lsLiBMZXMgY2hhcmdlcyBkw6lqw6AgcHLDqWxldsOpZXMvcmXDp3VlcyBuZSBzb250IFBBUwogICAgICAvLyBham91dMOpZXMgaWNpIDogZWxsZXMgZXhpc3RlbnQgZMOpc29ybWFpcyBjb21tZSBkZSB2cmFpZXMgdHJhbnNhY3Rpb25zCiAgICAgIC8vIChjcsOpw6llcyBjw7R0w6kgc2VydmV1cikgZXQgc29udCBkb25jIGTDqWrDoCBjb21wdMOpZXMgZGFucyBgdG90YWxzYAogICAgICAvLyBjaS1kZXNzdXMg4oCUIGxlcyBham91dGVyIMOgIG5vdXZlYXUgbGVzIGNvbXB0ZXJhaXQgZW4gZG91YmxlLgogICAgICBsZXQgdXBjb21pbmdFeHBlbnNlID0gMDsKICAgICAgbGV0IHVwY29taW5nSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gY3V0b2ZmKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS50eXBlID09PSAiaW5jb21lIikgdXBjb21pbmdJbmNvbWUgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICBlbHNlIHVwY29taW5nRXhwZW5zZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGNvbnN0IG5ldFVwY29taW5nID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGlmIChuZXRVcGNvbWluZyAhPT0gMCkgewogICAgICAgIGNvbnN0IHNpZ24gPSBuZXRVcGNvbWluZyA+IDAgPyAiKyIgOiAi4oiSIjsKICAgICAgICB1cGNvbWluZ1RleHRFbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldFVwY29taW5nKSl9IMOgIHZlbmlyYDsKICAgICAgICB1cGNvbWluZ05vdGVFbC50aXRsZSA9ICJSw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcy9yZcOndWVzIGNlIG1vaXMtY2kgKHJldmVudXMgbW9pbnMgZMOpcGVuc2VzKSI7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnRvZ2dsZSgicG9zaXRpdmUiLCBuZXRVcGNvbWluZyA+IDApOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICB9IGVsc2UgewogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB9CgogICAgICBpZiAoY2F0ZWdvcnlDaGFydCkgeyBjYXRlZ29yeUNoYXJ0LmRlc3Ryb3koKTsgY2F0ZWdvcnlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgY2F0ZWdvcnlDaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiZG91Z2hudXQiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBkYXRhLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGxhYmVscy5tYXAoKF8sIGkpID0+IENIQVJUX0NPTE9SU1tpICUgQ0hBUlRfQ09MT1JTLmxlbmd0aF0pLAogICAgICAgICAgICBib3JkZXJDb2xvcjogIiMxYTFkMjQiLAogICAgICAgICAgICBib3JkZXJXaWR0aDogMiwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgcG9zaXRpb246ICJib3R0b20iLCBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiwgYm94V2lkdGg6IDEyLCBwYWRkaW5nOiAxMiwgZm9udDogeyBzaXplOiAxMSB9IH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkKX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgLy8gTcOqbWUgcHJpbmNpcGUgcXVlIHJlbmRlckNhdGVnb3J5Q2hhcnQsIGPDtHTDqSByZXZlbnVzIOKAlCBwYXMgZGUgbm90ZSAiw6AKICAgIC8vIHZlbmlyIiBpY2ksIGVsbGUgcmVzdGUgdW5pcXVlbWVudCBzdXIgbGUgY2FtZW1iZXJ0IGRlcyBkw6lwZW5zZXMgcG91cgogICAgLy8gbmUgcGFzIGFmZmljaGVyIGxlIG3Dqm1lIGNoaWZmcmUgbmV0IMOgIGRldXggZW5kcm9pdHMuCiAgICBmdW5jdGlvbiByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWluY29tZS1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5Iik7CgogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImluY29tZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgaWYgKGluY29tZUNhdGVnb3J5Q2hhcnQpIHsgaW5jb21lQ2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGluY29tZUNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGluY29tZUNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtZXZvbHV0aW9uIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIpOwoKICAgICAgY29uc3QgbW9udGhseSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGtleSA9IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKTsKICAgICAgICBpZiAoIW1vbnRobHlba2V5XSkgbW9udGhseVtrZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgICBtb250aGx5W2tleV1bdHgudHlwZV0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVG91am91cnMgaW5jbHVyZSBsZSBtb2lzIGVuIGNvdXJzIChtw6ptZSBzYW5zIHRyYW5zYWN0aW9uKSBzJ2lsIGV4aXN0ZQogICAgICAvLyBkZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMsIHBvdXIgcXUnaWwgYXBwYXJhaXNzZSBzYW5zIGF0dGVuZHJlIGxhCiAgICAgIC8vIHByZW1pw6hyZSB0cmFuc2FjdGlvbiBkdSBtb2lzLiBMZXMgY2hhcmdlcyBkw6lqw6AgcHLDqWxldsOpZXMvcmXDp3VlcyBuZQogICAgICAvLyBzb250IHBsdXMgYWpvdXTDqWVzIGljaSDDoCBsYSBtYWluIDogZWxsZXMgZXhpc3RlbnQgZMOpc29ybWFpcyBjb21tZSBkZQogICAgICAvLyB2cmFpZXMgdHJhbnNhY3Rpb25zIChjcsOpw6llcyBjw7R0w6kgc2VydmV1cikgZXQgc29udCBkb25jIGTDqWrDoCBjb21wdMOpZXMKICAgICAgLy8gZGFucyBgbW9udGhseWAgdmlhIGxhIGJvdWNsZSBzdXIgYHRyYW5zYWN0aW9uc2AgY2ktZGVzc3VzIOKAlCBjZSBxdWkKICAgICAgLy8gbidlc3QgcGFzIGVuY29yZSBhcnJpdsOpIGVzdCByw6lzdW3DqSBhaWxsZXVycyAoc29sZGUgbmV0ICLDoCB2ZW5pciIpLgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDAgJiYgIW1vbnRobHlbY3VycmVudE1vbnRoS2V5XSkgewogICAgICAgIG1vbnRobHlbY3VycmVudE1vbnRoS2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgIH0KICAgICAgY29uc3QgbW9udGhzID0gT2JqZWN0LmtleXMobW9udGhseSkuc29ydCgpOwoKICAgICAgaWYgKGV2b2x1dGlvbkNoYXJ0KSB7IGV2b2x1dGlvbkNoYXJ0LmRlc3Ryb3koKTsgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgY29uc3QgbGFiZWxzID0gbW9udGhzLm1hcCgoa2V5KSA9PiB7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgcmV0dXJuIG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgIH0pOwoKICAgICAgY29uc3QgZGF0YXNldHMgPSBbCiAgICAgICAgeyBsYWJlbDogIkTDqXBlbnNlcyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uZXhwZW5zZSksIGJhY2tncm91bmRDb2xvcjogIiNlZjQ0NDQiIH0sCiAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmluY29tZSksIGJhY2tncm91bmRDb2xvcjogIiMyMmM1NWUiIH0sCiAgICAgIF07CgogICAgICBldm9sdXRpb25DaGFydCA9IG5ldyBDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7IGxhYmVscywgZGF0YXNldHMgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeDogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICAgIHk6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSwgYmVnaW5BdFplcm86IHRydWUgfSwKICAgICAgICAgIH0sCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHguZGF0YXNldC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkLnkpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb21wYXJlciBkZXV4IG1vaXMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ29tcGFyZU1vbnRoU2VsZWN0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgbW9udGhTZXQgPSBuZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBzZWxlY3RBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpOwogICAgICBjb25zdCBzZWxlY3RCID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpOwoKICAgICAgZm9yIChjb25zdCBzZWxlY3Qgb2YgW3NlbGVjdEEsIHNlbGVjdEJdKSB7CiAgICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgbW9udGhzKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgaWYgKG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSkgc2VsZWN0LnZhbHVlID0gcHJldmlvdXNWYWx1ZTsKICAgICAgfQogICAgICAvLyBQYXIgZMOpZmF1dCA6IG1vaXMgZW4gY291cnMgdnMgbW9pcyBwcsOpY8OpZGVudCwgc2kgbGVzIGRldXggZXhpc3RlbnQuCiAgICAgIGlmICghc2VsZWN0QS52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMCkgc2VsZWN0QS52YWx1ZSA9IG1vbnRoc1swXTsKICAgICAgaWYgKCFzZWxlY3RCLnZhbHVlICYmIG1vbnRocy5sZW5ndGggPiAxKSBzZWxlY3RCLnZhbHVlID0gbW9udGhzWzFdOwogICAgfQoKICAgIGZ1bmN0aW9uIG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBtb250aEtleSkgewogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIHJldHVybiB7IHRvdGFscywgdG90YWwgfTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJNb250aENvbXBhcmlzb24oKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1lbXB0eSIpOwogICAgICBjb25zdCBtb250aEEgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIikudmFsdWU7CiAgICAgIGNvbnN0IG1vbnRoQiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKS52YWx1ZTsKCiAgICAgIGlmICghbW9udGhBIHx8ICFtb250aEIpIHsKICAgICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNBLCB0b3RhbDogZ3JhbmRBIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhBKTsKICAgICAgY29uc3QgeyB0b3RhbHM6IHRvdGFsc0IsIHRvdGFsOiBncmFuZEIgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHMoYWxsVHJhbnNhY3Rpb25zLCBtb250aEIpOwogICAgICBjb25zdCBjYXRlZ29yaWVzID0gWy4uLm5ldyBTZXQoWy4uLk9iamVjdC5rZXlzKHRvdGFsc0EpLCAuLi5PYmplY3Qua2V5cyh0b3RhbHNCKV0pXS5zb3J0KAogICAgICAgIChhLCBiKSA9PiAodG90YWxzQltiXSB8fCAwKSAtICh0b3RhbHNBW2FdIHx8IDApCiAgICAgICk7CgogICAgICBjb25zdCBbeWEsIG1hXSA9IG1vbnRoQS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBbeWIsIG1iXSA9IG1vbnRoQi5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBsYWJlbEEgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YSwgbWEgLSAxLCAxKSk7CiAgICAgIGNvbnN0IGxhYmVsQiA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHliLCBtYiAtIDEsIDEpKTsKCiAgICAgIC8vIERpZmYgPSBtb250YW50IGR1IG1vaXMgQiBtb2lucyBjZWx1aSBkdSBtb2lzIEEuIFBvdXIgZGVzIGTDqXBlbnNlcywKICAgICAgLy8gZMOpcGVuc2VyIFBMVVMgKGRpZmYgcG9zaXRpZikgZXN0IGxhIG1hdXZhaXNlIG5vdXZlbGxlIOKGkiByb3VnZSA7IGVuCiAgICAgIC8vIGTDqXBlbnNlciBNT0lOUyAoZGlmZiBuw6lnYXRpZikg4oaSIHZlcnQuCiAgICAgIGZ1bmN0aW9uIGRpZmZDZWxsKGEsIGIpIHsKICAgICAgICBjb25zdCBkaWZmID0gYiAtIGE7CiAgICAgICAgaWYgKE1hdGguYWJzKGRpZmYpIDwgMC4wMSkgcmV0dXJuIGA8dGQ+4oCUPC90ZD5gOwogICAgICAgIGNvbnN0IGNscyA9IGRpZmYgPiAwID8gImRpZmYtbmVnYXRpdmUiIDogImRpZmYtcG9zaXRpdmUiOwogICAgICAgIHJldHVybiBgPHRkIGNsYXNzPSIke2Nsc30iPiR7ZGlmZiA+IDAgPyAiKyIgOiAiIn0ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChkaWZmKX08L3RkPmA7CiAgICAgIH0KCiAgICAgIGxldCBodG1sID0gYDx0YWJsZSBjbGFzcz0ic2ltcGxlLXRhYmxlIj48dGhlYWQ+PHRyPjx0aD5DYXTDqWdvcmllPC90aD48dGg+JHtsYWJlbEF9PC90aD48dGg+JHtsYWJlbEJ9PC90aD48dGg+RGlmZsOpcmVuY2U8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCBjYXQgb2YgY2F0ZWdvcmllcykgewogICAgICAgIGNvbnN0IGEgPSB0b3RhbHNBW2NhdF0gfHwgMDsKICAgICAgICBjb25zdCBiID0gdG90YWxzQltjYXRdIHx8IDA7CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2FsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0fTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGEpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGIpfTwvdGQ+JHtkaWZmQ2VsbChhLCBiKX08L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPHRyIGNsYXNzPSJ0b3RhbC1yb3ciPjx0ZD5Ub3RhbCBkw6lwZW5zZXM8L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEEpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGdyYW5kQil9PC90ZD4ke2RpZmZDZWxsKGdyYW5kQSwgZ3JhbmRCKX08L3RyPmA7CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB3cmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgcmVuZGVyTW9udGhDb21wYXJpc29uKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBNb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHJlbmQtZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRoS2V5cyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKV0uc29ydCgpOwogICAgICBpZiAobW9udGhLZXlzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHdyYXAuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlzW21vbnRoS2V5cy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgbmJNb250aHMgPSBtb250aEtleXMubGVuZ3RoOwoKICAgICAgLy8gdG90YWwgcGFyIGNhdMOpZ29yaWUsIGV0IHBhciBjYXTDqWdvcmllK21vaXMgKHBvdXIgaXNvbGVyIGxlIG1vaXMgZW4gY291cnMpCiAgICAgIGNvbnN0IHRvdGFsc0J5Q2F0ZWdvcnkgPSB7fTsKICAgICAgY29uc3QgY3VycmVudE1vbnRoQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSA9PT0gY3VycmVudE1vbnRoS2V5KSB7CiAgICAgICAgICBjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9IChjdXJyZW50TW9udGhCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKHRvdGFsc0J5Q2F0ZWdvcnkpLnNvcnQoKGEsIGIpID0+IHRvdGFsc0J5Q2F0ZWdvcnlbYl0gLSB0b3RhbHNCeUNhdGVnb3J5W2FdKTsKICAgICAgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPk1veWVubmUvbW9pczwvdGg+PHRoPkNlIG1vaXMtY2k8L3RoPjx0aD5UZW5kYW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYXZlcmFnZSA9IHRvdGFsc0J5Q2F0ZWdvcnlbY2F0XSAvIG5iTW9udGhzOwogICAgICAgIGNvbnN0IGN1cnJlbnQgPSBjdXJyZW50TW9udGhCeUNhdGVnb3J5W2NhdF0gfHwgMDsKICAgICAgICBsZXQgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC1mbGF0Ij7ihpIgc3RhYmxlPC9zcGFuPmA7CiAgICAgICAgaWYgKGF2ZXJhZ2UgPiAwKSB7CiAgICAgICAgICBjb25zdCByYXRpbyA9IChjdXJyZW50IC0gYXZlcmFnZSkgLyBhdmVyYWdlOwogICAgICAgICAgaWYgKHJhdGlvID4gMC4xNSkgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC11cCI+4oaRICske01hdGgucm91bmQocmF0aW8gKiAxMDApfSU8L3NwYW4+YDsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvIDwgLTAuMTUpIHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZG93biI+4oaTICR7TWF0aC5yb3VuZChyYXRpbyAqIDEwMCl9JTwvc3Bhbj5gOwogICAgICAgIH0gZWxzZSBpZiAoY3VycmVudCA+IDApIHsKICAgICAgICAgIHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSBub3V2ZWF1PC9zcGFuPmA7CiAgICAgICAgfQogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHthbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdH08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhdmVyYWdlKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdXJyZW50KX08L3RkPjx0ZD4ke3RyZW5kSHRtbH08L3RkPjwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpIHsKICAgICAgcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyTW9udGhDb21wYXJpc29uKCk7CiAgICAgIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gIiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgIH0pOwogICAgICAgICAgYXdhaXQgYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMTUwMCk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTdWdnZXN0aW9ucyBkZSBjYXTDqWdvcmllIOKAlCB1bmlxdWVtZW50IGFwcsOocyB1bmUgc2Fpc2llIHBhciBkaWN0w6llCiAgICAvLyB2b2NhbGUgKHVuZSBmYXV0ZSBkZSBmcmFwcGUgZW4gc2Fpc2llIG1hbnVlbGxlLCBjJ2VzdCB1bmUgZXJyZXVyIGRlCiAgICAvLyBsJ3V0aWxpc2F0ZXVyLCBwYXMgbGEgcGVpbmUgZGUgbGUgcmVsYW5jZXIgZGVzc3VzKS4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEID0gMzsKCiAgICBmdW5jdGlvbiBub3JtYWxpemVEZXNjcmlwdGlvbihkZXNjKSB7CiAgICAgIHJldHVybiAoZGVzYyB8fCAiIikudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gZGlzbWlzc1N1Z2dlc3Rpb24oa2V5KSB7CiAgICAgIGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzLmFkZChrZXkpOyAvLyBpbW3DqWRpYXQgY8O0dMOpIFVJLCBwYXMgYmVzb2luIGQnYXR0ZW5kcmUgbGUgc2VydmV1cgogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL2Rpc21pc3NlZC1zdWdnZXN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBrZXkgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgbGEgc3VnZ2VzdGlvbiByw6lhcHBhcmHDrnQgdW5lIGZvaXMgc3VyIHVuCiAgICAgICAgLy8gYXV0cmUgYXBwYXJlaWwgc2kgbGEgc2F1dmVnYXJkZSBzZXJ2ZXVyIGEgw6ljaG91w6kuCiAgICAgIH0KICAgIH0KCiAgICAvLyBSZWdhcmRlIHNpIGxhIGRlc2NyaXB0aW9uIGRlIGxhIHRyYW5zYWN0aW9uIHF1aSB2aWVudCBkJ8OqdHJlIGFqb3V0w6llCiAgICAvLyAob3UgY29ycmlnw6llKSDDoCBsYSB2b2l4IHJldmllbnQgc291dmVudCwgZXQgc2kgb3VpIDoKICAgIC8vIC0gc29pdCBlbGxlIGEgdG91am91cnMgw6l0w6kgcmFuZ8OpZSBkYW5zICJBdXRyZSIg4oaSIG9uIHByb3Bvc2UgZGUgY3LDqWVyCiAgICAvLyAgIHVuZSBjYXTDqWdvcmllIGTDqWRpw6llIChvdSBkZSBsYSByYXR0YWNoZXIgw6AgdW5lIGNhdMOpZ29yaWUgZXhpc3RhbnRlKSA7CiAgICAvLyAtIHNvaXQgZWxsZSBhIGNldHRlIGZvaXMgdW5lIGNhdMOpZ29yaWUgZGlmZsOpcmVudGUgZGUgZCdoYWJpdHVkZSDihpIgb24KICAgIC8vICAgZGVtYW5kZSBzaSBjZSBuJ2VzdCBwYXMgdW5lIGVycmV1ci4KICAgIGZ1bmN0aW9uIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKGRlc2NyaXB0aW9uLCB0eXBlKSB7CiAgICAgIGNvbnN0IG5vcm0gPSBub3JtYWxpemVEZXNjcmlwdGlvbihkZXNjcmlwdGlvbik7CiAgICAgIGlmICghbm9ybSkgcmV0dXJuOwoKICAgICAgY29uc3Qgc2FtZURlc2NyaXB0aW9uID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigKICAgICAgICAodHgpID0+IHR4LnR5cGUgPT09IHR5cGUgJiYgbm9ybWFsaXplRGVzY3JpcHRpb24odHguZGVzY3JpcHRpb24pID09PSBub3JtCiAgICAgICk7CiAgICAgIGlmIChzYW1lRGVzY3JpcHRpb24ubGVuZ3RoIDwgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQpIHJldHVybjsKCiAgICAgIGNvbnN0IGNvdW50cyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHNhbWVEZXNjcmlwdGlvbikgY291bnRzW3R4LmNhdGVnb3J5XSA9IChjb3VudHNbdHguY2F0ZWdvcnldIHx8IDApICsgMTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKGNvdW50cyk7CiAgICAgIGNvbnN0IGRvbWluYW50ID0gY2F0ZWdvcmllcy5yZWR1Y2UoKGEsIGIpID0+IChjb3VudHNbYV0gPj0gY291bnRzW2JdID8gYSA6IGIpKTsKICAgICAgY29uc3QgbGF0ZXN0ID0gc2FtZURlc2NyaXB0aW9uWzBdOyAvLyBhbGxUcmFuc2FjdGlvbnMgZXN0IHRyacOpIHBhciBkYXRlIGTDqWNyb2lzc2FudGUKCiAgICAgIGxldCBzdWdnZXN0aW9uID0gbnVsbDsKICAgICAgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID4gMSAmJiBsYXRlc3QuY2F0ZWdvcnkgIT09IGRvbWluYW50KSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYG1pc21hdGNoOiR7dHlwZX06JHtub3JtfToke2xhdGVzdC5jYXRlZ29yeX1gLAogICAgICAgICAga2luZDogIm1pc21hdGNoIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICBjdXJyZW50OiBsYXRlc3QuY2F0ZWdvcnksCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ID09PSBsYXRlc3QuY2F0ZWdvcnkpLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID09PSAxICYmIGRvbWluYW50ID09PSAiYXV0cmUiKSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYGdlbmVyaWM6JHt0eXBlfToke25vcm19YCwKICAgICAgICAgIGtpbmQ6ICJnZW5lcmljIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAgdHhJZHM6IHNhbWVEZXNjcmlwdGlvbi5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgfTsKICAgICAgfQoKICAgICAgaWYgKCFzdWdnZXN0aW9uIHx8IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzLmhhcyhzdWdnZXN0aW9uLmtleSkpIHJldHVybjsKICAgICAgc2hvd0NhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcihzdWdnZXN0aW9uKTsKICAgIH0KCiAgICBmdW5jdGlvbiBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKSB7CiAgICAgIGNvbnN0IFtsYXRlc3RJZCwgLi4ub3RoZXJzXSA9IHN1Z2dlc3Rpb24udHhJZHM7CiAgICAgIGNvbnN0IGlkc1RvRml4ID0gW2xhdGVzdElkXTsKICAgICAgaWYgKAogICAgICAgIG90aGVycy5sZW5ndGggPiAwICYmCiAgICAgICAgKGF3YWl0IHNob3dDb25maXJtKGBDb3JyaWdlciBhdXNzaSBsZXMgJHtvdGhlcnMubGVuZ3RofSB0cmFuc2FjdGlvbihzKSBwcsOpY8OpZGVudGUocykgYXZlYyBsYSBtw6ptZSBkZXNjcmlwdGlvbiA/YCkpCiAgICAgICkgewogICAgICAgIGlkc1RvRml4LnB1c2goLi4ub3RoZXJzKTsKICAgICAgfQoKICAgICAgdHJ5IHsKICAgICAgICBmb3IgKGNvbnN0IGlkIG9mIGlkc1RvRml4KSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnk6IHRhcmdldFZhbHVlIH0pLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIHNob3dUb2FzdChgQ2F0w6lnb3JpZSBtaXNlIMOgIGpvdXIgOiAke3RhcmdldExhYmVsfWApOwogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwoKICAgICAgY29uc3QgZGVzY0xhYmVsID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiKHNhbnMgZGVzY3JpcHRpb24pIjsKICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgVHUgYXMgdXRpbGlzw6kgIiR7ZGVzY0xhYmVsfSIgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gZm9pcywgdG91am91cnMgY2xhc3PDqSBlbiBgICsKICAgICAgICAgIGAiQXV0cmUiLiBDcsOpZXIgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpID9gOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGN1cnJlbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uY3VycmVudF0gfHwgc3VnZ2VzdGlvbi5jdXJyZW50OwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCIke2Rlc2NMYWJlbH0iIGVzdCBoYWJpdHVlbGxlbWVudCBjbGFzc8OpIGVuICIke2RvbWluYW50TGFiZWx9IiwgbWFpcyBjZXR0ZSBmb2lzIGAgKwogICAgICAgICAgYGMnZXN0ICIke2N1cnJlbnRMYWJlbH0iLiBQYXMgZCdlcnJldXIgb3UgdW4gb3VibGkgP2A7CiAgICAgIH0KICAgICAgZWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAiY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyI7CgogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzZWxlY3QiKTsKICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXSkgewogICAgICAgICAgaWYgKHZhbHVlID09PSAiYXV0cmUiKSBjb250aW51ZTsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBuZXdPcHQudmFsdWUgPSAiX19uZXdfXyI7CiAgICAgICAgbmV3T3B0LnRleHRDb250ZW50ID0gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiI7CiAgICAgICAgbmV3T3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQobmV3T3B0KTsKCiAgICAgICAgY29uc3QgbmV3TmFtZUlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBuZXdOYW1lSW5wdXQudHlwZSA9ICJ0ZXh0IjsKICAgICAgICBuZXdOYW1lSW5wdXQucGxhY2Vob2xkZXIgPSAiTm9tIGRlIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiOwogICAgICAgIG5ld05hbWVJbnB1dC52YWx1ZSA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIiI7CgogICAgICAgIHNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICBuZXdOYW1lSW5wdXQuc3R5bGUuZGlzcGxheSA9IHNlbGVjdC52YWx1ZSA9PT0gIl9fbmV3X18iID8gImlubGluZS1ibG9jayIgOiAibm9uZSI7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKHNlbGVjdCk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQobmV3TmFtZUlucHV0KTsKCiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9ICJBcHBsaXF1ZXIiOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBsZXQgdGFyZ2V0VmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgICBsZXQgdGFyZ2V0TGFiZWw7CiAgICAgICAgICBpZiAodGFyZ2V0VmFsdWUgPT09ICJfX25ld19fIikgewogICAgICAgICAgICBjb25zdCBuYW1lID0gbmV3TmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgaWYgKCFuYW1lKSB7IHNob3dUb2FzdCgiRG9ubmUgdW4gbm9tIMOgIGxhIGNhdMOpZ29yaWUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgICAgICAgIHRhcmdldFZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IG5hbWU7CiAgICAgICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdGFyZ2V0VmFsdWUpKSB7CiAgICAgICAgICAgICAgc2F2ZUN1c3RvbUNhdGVnb3J5KHN1Z2dlc3Rpb24udHlwZSwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1t0YXJnZXRWYWx1ZV0gfHwgdGFyZ2V0VmFsdWU7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gYENvcnJpZ2VyIGVuICIke2RvbWluYW50TGFiZWx9ImA7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHN1Z2dlc3Rpb24uZG9taW5hbnQsIGRvbWluYW50TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfQoKICAgICAgY29uc3QgZGlzbWlzc0J0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBkaXNtaXNzQnRuLnRleHRDb250ZW50ID0gIklnbm9yZXIiOwogICAgICBkaXNtaXNzQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgZGlzbWlzc0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICB9KTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoZGlzbWlzc0J0bik7CgogICAgICBlbC5hcHBlbmRDaGlsZChjb250cm9scyk7CiAgICB9CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIGNoYXJnZSByw6ljdXJyZW50ZSBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUKICAgIC8vIHNlc3Npb24gKG3Dqm1lIHByaW5jaXBlIHF1ZSBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkLCBtYWlzIHBvdXIgdW5lCiAgICAvLyBjb3JyZWN0aW9uIHF1aSBzdWl0IGxhIGNyw6lhdGlvbiBkJ3VuZSByw6ljdXJyZW50ZSBwYXIgbGEgdm9peCkuCiAgICBsZXQgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgIGNvbnN0IGFtb3VudExhYmVsID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpOwoKICAgICAgLy8gInLDqWN1cnJlbnQiLCAiYWJvbm5lbWVudCIsICJ0b3VzIGxlcyBtb2lzIi4uLiBkw6l0ZWN0w6kgcGFyIGwnSUEgOiBvbgogICAgICAvLyBjcsOpZS9jb3JyaWdlIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgYXUgbGlldSBkJ3VuZSB0cmFuc2FjdGlvbgogICAgICAvLyBwb25jdHVlbGxlLCBxdWVsIHF1ZSBzb2l0IGwnb25nbGV0IGFjdHVlbGxlbWVudCBhZmZpY2jDqSDigJQgbGUgbWljcm8KICAgICAgLy8gZXN0IGdsb2JhbCwgcGFzIGxpw6kgw6AgbCdvbmdsZXQgUsOpY3VycmVudGVzLgogICAgICBpZiAocGFyc2VkLmlzX3JlY3VycmluZykgewogICAgICAgIGNvbnN0IHJlY1BheWxvYWQgPSB7CiAgICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICAgIG5hbWU6IHBhcnNlZC5kZXNjcmlwdGlvbiB8fCAocGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSByw6ljdXJyZW50IiA6ICJEw6lwZW5zZSByw6ljdXJyZW50ZSIpLAogICAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICAgIGRheV9vZl9tb250aDogTnVtYmVyKHBhcnNlZC5leHBlbnNlX2RhdGUuc2xpY2UoOCwgMTApKSwKICAgICAgICB9OwoKICAgICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2xhc3RWb2ljZVJlY3VycmluZ0lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVjUGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICAgIHNob3dUb2FzdChgQ2hhcmdlIHLDqWN1cnJlbnRlIGNvcnJpZ8OpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBjcmVhdGVkLmlkOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUgOiAke3JlY1BheWxvYWQubmFtZX0gKCR7YW1vdW50TGFiZWx9KWApOwogICAgICAgIH0KICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQpIHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtsYXN0Vm9pY2VUcmFuc2FjdGlvbklkfWAsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYENvcnJpZ8OpIDogJHt2ZXJiLnRvTG93ZXJDYXNlKCl9IGRlICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgc2hvd1RvYXN0KGAke3ZlcmJ9IGFqb3V0w6kke3BhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICIiIDogImUifSA6ICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0KICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihwYXJzZWQuZGVzY3JpcHRpb24sIHBhcnNlZC50eXBlKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb25maXJtYXRpb24gc3R5bMOpZSAocmVtcGxhY2Ugd2luZG93LmNvbmZpcm0sIHF1aSBhZmZpY2hlIHVuZSBwb3B1cAogICAgLy8gbmF0aXZlIGR1IG5hdmlnYXRldXIgaG9ycyBjaGFydGUgZ3JhcGhpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgY29uZmlybU92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IGNvbmZpcm1NZXNzYWdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1tb2RhbC1tZXNzYWdlIik7CiAgICBjb25zdCBjb25maXJtT2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tb2siKTsKICAgIGNvbnN0IGNvbmZpcm1DYW5jZWxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tY2FuY2VsIik7CiAgICBsZXQgY29uZmlybVJlc29sdmUgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNob3dDb25maXJtKG1lc3NhZ2UpIHsKICAgICAgY29uZmlybU1lc3NhZ2VFbC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4gewogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gcmVzb2x2ZTsKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VDb25maXJtKHJlc3VsdCkgewogICAgICBjb25maXJtT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAoY29uZmlybVJlc29sdmUpIHsKICAgICAgICBjb25maXJtUmVzb2x2ZShyZXN1bHQpOwogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gbnVsbDsKICAgICAgfQogICAgfQoKICAgIGNvbmZpcm1Pa0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGNsb3NlQ29uZmlybSh0cnVlKSk7CiAgICBjb25maXJtQ2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKGZhbHNlKSk7CiAgICBjb25maXJtT3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBjb25maXJtT3ZlcmxheUVsKSBjbG9zZUNvbmZpcm0oZmFsc2UpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgZMOpcGVuc2UgcsOpY3VycmVudGUgPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgLy8gUmFtw6huZSB1biBqb3VyIGR1IG1vaXMgKDEtMzEpIGF1IGRlcm5pZXIgam91ciByw6llbCBkdSBtb2lzIHZpc8OpIOKAlAogICAgLy8gw6lxdWl2YWxlbnQgSlMgZGUgX2NsYW1wX2RheSBjw7R0w6kgc2VydmV1ciwgcG91ciBjYWxjdWxlciBkZSB2cmFpZXMKICAgIC8vIGRhdGVzIChuZXcgRGF0ZSguLi4pKSBwbHV0w7R0IHF1ZSBkZSBjb21wYXJlciBkZXMgam91cnMgdG91dCBzZXVscy4KICAgIGZ1bmN0aW9uIGNsYW1wRGF5SnMoeWVhciwgbW9udGhJbmRleCwgZGF5KSB7CiAgICAgIGNvbnN0IGxhc3REYXkgPSBuZXcgRGF0ZSh5ZWFyLCBtb250aEluZGV4ICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgICByZXR1cm4gTWF0aC5taW4oZGF5LCBsYXN0RGF5KTsKICAgIH0KCiAgICAvLyBQcm9jaGFpbmUgb2NjdXJyZW5jZSBkJ3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgw6AgcGFydGlyIGQnYXVqb3VyZCdodWkKICAgIC8vIChzdHJpY3RlbWVudCBhcHLDqHMgYXVqb3VyZCdodWkpIDogcmVnYXJkZSBjZSBtb2lzLWNpIHB1aXMsIHNpIGJlc29pbiwKICAgIC8vIGxlcyBkZXV4IG1vaXMgc3VpdmFudHMg4oCUIHV0aWxlIGVuIGZpbiBkZSBtb2lzIHF1YW5kIHBsdXMgcmllbiBuJ2VzdAogICAgLy8gw6AgdmVuaXIgZGFucyBsZSBtb2lzIGNvdXJhbnQuCiAgICBmdW5jdGlvbiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXlTdHIpIHsKICAgICAgY29uc3QgW3R5LCB0bSwgdGRdID0gdG9kYXlTdHIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdG9kYXlEYXRlID0gbmV3IERhdGUodHksIHRtIC0gMSwgdGQpOwogICAgICBmb3IgKGxldCBvZmZzZXQgPSAwOyBvZmZzZXQgPD0gMjsgb2Zmc2V0KyspIHsKICAgICAgICBjb25zdCBiYXNlID0gbmV3IERhdGUodHksIHRtIC0gMSArIG9mZnNldCwgMSk7CiAgICAgICAgY29uc3QgeSA9IGJhc2UuZ2V0RnVsbFllYXIoKTsKICAgICAgICBjb25zdCBtSWR4ID0gYmFzZS5nZXRNb250aCgpOwogICAgICAgIGNvbnN0IG1vbnRoS2V5ID0gYCR7eX0tJHtTdHJpbmcobUlkeCArIDEpLnBhZFN0YXJ0KDIsICIwIil9YDsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgY29uc3QgZGF5ID0gY2xhbXBEYXlKcyh5LCBtSWR4LCBpdGVtLmRheV9vZl9tb250aCk7CiAgICAgICAgY29uc3Qgb2NjRGF0ZSA9IG5ldyBEYXRlKHksIG1JZHgsIGRheSk7CiAgICAgICAgaWYgKG9jY0RhdGUgPiB0b2RheURhdGUpIHJldHVybiBvY2NEYXRlOwogICAgICB9CiAgICAgIHJldHVybiBudWxsOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpIHsKICAgICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIik7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CgogICAgICBjb25zdCB1cGNvbWluZyA9IGFsbFJlY3VycmluZwogICAgICAgIC5tYXAoKGl0ZW0pID0+ICh7IGl0ZW0sIGRhdGU6IG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheSkgfSkpCiAgICAgICAgLmZpbHRlcigoeCkgPT4geC5kYXRlKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBhLmRhdGUgLSBiLmRhdGUpCiAgICAgICAgLnNsaWNlKDAsIDMpOwoKICAgICAgaWYgKHVwY29taW5nLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwYW5lbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwoKICAgICAgZm9yIChjb25zdCB7IGl0ZW0sIGRhdGUgfSBvZiB1cGNvbWluZykgewogICAgICAgIGNvbnN0IGRheXMgPSBNYXRoLnJvdW5kKChkYXRlIC0gbmV3IERhdGUobmV3IERhdGUoKS5zZXRIb3VycygwLCAwLCAwLCAwKSkpIC8gODY0MDAwMDApOwogICAgICAgIGNvbnN0IGR1ZUxhYmVsID0gZGF5cyA8PSAxID8gImRlbWFpbiIgOiBgZGFucyAke2RheXN9IGpvdXJzYDsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJ1cGNvbWluZy1yZWN1cnJpbmctcm93IjsKICAgICAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGxlZnQuY2xhc3NOYW1lID0gIm5hbWUiOwogICAgICAgIGxlZnQudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CiAgICAgICAgY29uc3QgZHVlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkdWVTcGFuLmNsYXNzTmFtZSA9ICJkdWUiOwogICAgICAgIGR1ZVNwYW4udGV4dENvbnRlbnQgPSBgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChkYXRlKX0gwrcgJHtkdWVMYWJlbH1gOwogICAgICAgIGxlZnQuYXBwZW5kQ2hpbGQoZHVlU3Bhbik7CiAgICAgICAgY29uc3QgYW1vdW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAiYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQobGVmdCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGFtb3VudCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkUmVjdXJyaW5nKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIik7CiAgICAgICAgYWxsUmVjdXJyaW5nID0gaXRlbXM7CiAgICAgICAgcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKTsKICAgICAgICByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKTsKICAgICAgICB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBFeHBvcnQgRXhjZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LXhsc3giKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQteGxzeCIpOwogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJHw6luw6lyYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2V4cG9ydC94bHN4IiwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHRocm93IG5ldyBFcnJvcigiw4ljaGVjIGRlIGwnZXhwb3J0ICgiICsgcmVzLnN0YXR1cyArICIpIik7CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgICBjb25zdCBsaW5rID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYSIpOwogICAgICAgIGxpbmsuaHJlZiA9IHVybDsKICAgICAgICBsaW5rLmRvd25sb2FkID0gYGRlcGVuc2VzXyR7dG9kYXlJc28oKX0ueGxzeGA7CiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChsaW5rKTsKICAgICAgICBsaW5rLmNsaWNrKCk7CiAgICAgICAgbGluay5yZW1vdmUoKTsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICAgICAgc2hvd1RvYXN0KCJFeHBvcnQgdMOpbMOpY2hhcmfDqSIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoImV4cGVuc2UiKTsKICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgICAgLy8gQ2F0w6lnb3JpZXMgcGVyc28gKyBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgZCdhYm9yZCwgcG91ciBxdWUgbGVzCiAgICAgIC8vIGxpc3RlcyBkw6lyb3VsYW50ZXMgZXQgbGUgYmFuZGVhdSBzb2llbnQgY29ycmVjdHMgZMOocyBsZSBwcmVtaWVyCiAgICAgIC8vIHJlbmR1IHBsdXTDtHQgcXVlIGRlICJzYXV0ZXIiIHVuZSBmb2lzIGxlIHNlcnZldXIgcsOpcG9uZHUuCiAgICAgIGF3YWl0IFByb21pc2UuYWxsKFtsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpLCBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSwgbG9hZEJ1ZGdldHMoKV0pOwogICAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIGxvYWRSZWN1cnJpbmcoKTsKICAgIH0pKCk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
# END_FRONTEND_B64


@app.get("/", response_class=HTMLResponse)
def serve_frontend() -> HTMLResponse:
    if not FRONTEND_HTML_B64:
        return HTMLResponse(
            content="<h1>Frontend non généré</h1><p>Lance build.py.</p>",
            status_code=500,
        )
    html = base64.b64decode(FRONTEND_HTML_B64).decode("utf-8")
    return HTMLResponse(content=html)


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
