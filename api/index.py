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


class VoiceParseRequest(BaseModel):
    text: str = Field(min_length=1)


class VoiceParseResult(BaseModel):
    type: TransactionType
    amount: float
    category: str
    description: str | None
    expense_date: date
    is_correction: bool
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
  "is_correction": true seulement si la phrase exprime explicitement une intention de corriger une transaction déjà enregistrée (ex: "corrige", "en fait c'était plutôt", "change le montant de..."), false dans tous les autres cas, y compris si la phrase ressemble à une dépense déjà saisie
}

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même une date calendaire (comme "2026-09-30") à partir d'une expression relative. Tu ne connais pas la date du jour. Recopie l'expression de date telle quelle dans raw_date_expression ; un autre système déterministe s'occupera de la convertir.
- Si la phrase ne mentionne aucune date, raw_date_expression doit être null (la date du jour sera utilisée par défaut).
- is_correction doit rester false par défaut : en cas de doute, considère qu'il s'agit d'une nouvelle transaction plutôt que d'une correction."""


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

    return VoiceParseResult(
        type=tx_type,
        amount=amount,
        category=category,
        description=description,
        expense_date=expense_date,
        is_correction=is_correction,
        raw_date_expression=raw_date_expression,
    )


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vY2hhcnQuanNANC40LjQvZGlzdC9jaGFydC51bWQubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAudGFicyB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICB9CiAgLnRhYi1idG4gewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudGFiLWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnRvb2x0aXAtaG9zdCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgY3Vyc29yOiBoZWxwOyB9CiAgLmN1c3RvbS10b29sdGlwIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIGxlZnQ6IDUwJTsKICAgIGJvdHRvbTogY2FsYygxMDAlICsgMC42cmVtKTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDRweCk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjU1cmVtIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuNzhyZW07CiAgICBsaW5lLWhlaWdodDogMS41OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICAgIHRleHQtYWxpZ246IGxlZnQ7CiAgICBib3gtc2hhZG93OiAwIDhweCAyMHB4IHJnYmEoMCwgMCwgMCwgMC4zNSk7CiAgICBvcGFjaXR5OiAwOwogICAgcG9pbnRlci1ldmVudHM6IG5vbmU7CiAgICB0cmFuc2l0aW9uOiBvcGFjaXR5IDAuMTJzIGVhc2UsIHRyYW5zZm9ybSAwLjEycyBlYXNlOwogICAgei1pbmRleDogMjA7CiAgfQogIC5jdXN0b20tdG9vbHRpcDo6YWZ0ZXIgewogICAgY29udGVudDogIiI7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDEwMCU7CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBib3JkZXI6IDZweCBzb2xpZCB0cmFuc3BhcmVudDsKICAgIGJvcmRlci10b3AtY29sb3I6IHZhcigtLXN1cmZhY2UtMik7CiAgfQogIC5jdXN0b20tdG9vbHRpcC52aXNpYmxlIHsKICAgIG9wYWNpdHk6IDE7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSgwKTsKICAgIHBvaW50ZXItZXZlbnRzOiBhdXRvOwogIH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAud2Vlay1zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IC0wLjRyZW0gYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CgogIC5jYXRlZ29yeS1zdWdnZXN0aW9uIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMC45cmVtIDEuMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYWNjZW50LWRpbSk7CiAgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuY2F0ZWdvcnktc3VnZ2VzdGlvbiBwIHsgbWFyZ2luOiAwIDAgMC43cmVtOyBmb250LXNpemU6IDAuODhyZW07IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIHsgZGlzcGxheTogZmxleDsgZmxleC13cmFwOiB3cmFwOyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIHNlbGVjdCwKICAuY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyBpbnB1dFt0eXBlPSJ0ZXh0Il0gewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgcGFkZGluZzogMC40cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmJ0bi1wcmltYXJ5LXNtLCAuYnRuLXNlY29uZGFyeS1zbSB7CiAgICBib3JkZXI6IG5vbmU7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjRyZW0gMC44cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuYnRuLXByaW1hcnktc20geyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogI2ZmZjsgfQogIC5idG4tc2Vjb25kYXJ5LXNtIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KCiAgLmZpbHRlci1iYXIgewogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtd3JhcDogd3JhcDsKICAgIGdhcDogMC41cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogIH0KICAuZmlsdGVyLWJhciBpbnB1dCwKICAuZmlsdGVyLWJhciBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBmbGV4OiAxIDEgMTMwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogICNmaWx0ZXItc2VhcmNoIHsgZmxleDogMSAxIDEwMCU7IH0KCiAgLnR4LWxpc3QgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDAuNnJlbTsgfQoKICAudHgtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgfQogIC50eC1jYXJkLmluY29tZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50eC1jYXJkLmV4cGVuc2UgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudHgtbWFpbiB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC50eC10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgfQogIC5jYXRlZ29yeS1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHdoaXRlLXNwYWNlOiBub3dyYXA7CiAgfQogIC50eC1kYXRlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnR4LXJlY3VycmluZy1iYWRnZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgb3BhY2l0eTogMC43OyBjdXJzb3I6IGhlbHA7IH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyAuY2hhcnQtd3JhcCB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQogIC51cGNvbWluZy1ub3RlIHsKICAgIHdpZHRoOiA5NnB4OwogICAgZmxleC1zaHJpbms6IDA7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNHJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXI6IDFweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuNzJyZW07CiAgICBsaW5lLWhlaWdodDogMS4yNTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQogIC51cGNvbWluZy1ub3RlLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctc3dhdGNoIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAxNHB4OwogICAgYm9yZGVyOiAxLjVweCBkYXNoZWQgdmFyKC0tZGFuZ2VyKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC51cGNvbWluZy1ub3RlLnBvc2l0aXZlIC51cGNvbWluZy1zd2F0Y2ggewogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMik7CiAgfQoKICAucmVjdXJyaW5nLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY3VycmluZy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5leHBvcnQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZXhwb3J0LXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLnJlY3VycmluZy1oaW50IHsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBtYXJnaW46IDAgMCAwLjlyZW07CiAgfQogIC5yZWMtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjZyZW07CiAgfQogIC5yZWMtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnN0YXJ0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjE1KTsKICAgIGNvbG9yOiAjOTNjNWZkOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnJlYy1hbW91bnQgeyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IDEuMDVyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAucmVjLWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5mYWItbWljIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiA1LjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS41cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoMCwgMCwgMCwgMC4zKTsKICAgIHRyYW5zaXRpb246IGJhY2tncm91bmQgMC4ycywgYm9yZGVyLWNvbG9yIDAuMnM7CiAgfQogIC5mYWItbWljOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KICAuZmFiLW1pYy5saXN0ZW5pbmcgewogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsKICAgIGFuaW1hdGlvbjogcHVsc2UgMS4ycyBpbmZpbml0ZTsKICB9CiAgLmZhYi1taWMucHJvY2Vzc2luZyB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmZhYi1taWM6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjM1OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgQGtleWZyYW1lcyBwdWxzZSB7CiAgICAwJSwgMTAwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDAgcmdiYSgyMzksIDY4LCA2OCwgMC40KTsgfQogICAgNTAlIHsgYm94LXNoYWRvdzogMCAwIDAgMTBweCByZ2JhKDIzOSwgNjgsIDY4LCAwKTsgfQogIH0KCiAgLnZvaWNlLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNTsKICB9CiAgLnZvaWNlLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CgogIC5tb2RhbC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogZmxleC1lbmQ7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwOwogIH0KICAubW9kYWwtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLm1vZGFsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyLXJhZGl1czogMThweCAxOHB4IDAgMDsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIGNhbGMoMS41cmVtICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsKICAgIHdpZHRoOiAxMDAlOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjlyZW07CiAgfQogIC5tb2RhbCBoMiB7IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtc2l6ZTogMS4xcmVtOyB9CgogIGxhYmVsIHsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjNyZW07IH0KICBpbnB1dCwgc2VsZWN0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42NXJlbSAwLjc1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CgogIC50eXBlLXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyB9CiAgLnR5cGUtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjY1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJleHBlbnNlIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJpbmNvbWUiXSB7IGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KCiAgLm1vZGFsLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgYnV0dG9uLnByaW1hcnksIGJ1dHRvbi5zZWNvbmRhcnkgewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNzVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiBub25lOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICBidXR0b24ucHJpbWFyeTpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQogIGJ1dHRvbi5zZWNvbmRhcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICA8aGVhZGVyPgogICAgPGgxPvCfkrMgU3VpdmkgZGUgZMOpcGVuc2VzPC9oMT4KICAgIDxwIGNsYXNzPSJzdWJ0aXRsZSI+VGVzIGTDqXBlbnNlcyBldCByZXZlbnVzLCBham91dMOpcyBvdSDDqWRpdMOpcyBtYW51ZWxsZW1lbnQuPC9wPgogIDwvaGVhZGVyPgoKICA8ZGl2IGNsYXNzPSJ0YWJzIj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biBhY3RpdmUiIGlkPSJ0YWItaGlzdG9yeSIgZGF0YS12aWV3PSJoaXN0b3J5Ij5IaXN0b3JpcXVlPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItZGFzaGJvYXJkIiBkYXRhLXZpZXc9ImRhc2hib2FyZCI+VGFibGVhdSBkZSBib3JkPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItcmVjdXJyaW5nIiBkYXRhLXZpZXc9InJlY3VycmluZyI+UsOpY3VycmVudGVzPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItZXhwb3J0IiBkYXRhLXZpZXc9ImV4cG9ydCI+RXhwb3J0PC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIHJldmVudXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW4gcmV2ZW51IGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz7DiXZvbHV0aW9uIG1lbnN1ZWxsZSAoZMOpcGVuc2VzIHZzIHJldmVudXMpPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWV2b2x1dGlvbiI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIEF1Y3VuZSBkw6lwZW5zZSByw6ljdXJyZW50ZSBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciArIHBvdXIgZW4gYWpvdXRlciB1bmUuCiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWV4cG9ydCIgY2xhc3M9ImV4cG9ydC1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkV4cG9ydGVyIHRlcyBkb25uw6llczwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFTDqWzDqWNoYXJnZSB1biBmaWNoaWVyIEV4Y2VsICgueGxzeCkgYXZlYyB0b3V0ZXMgdGVzIHRyYW5zYWN0aW9ucwogICAgICAgICAgKGTDqXBlbnNlcyBldCByZXZlbnVzKSBldCB0ZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMgKGTDqXBlbnNlcyBldAogICAgICAgICAgcmV2ZW51cyByw6ljdXJyZW50cyksIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQteGxzeCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Uw6lsw6ljaGFyZ2VyIGxlIGZpY2hpZXIgRXhjZWw8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgPC9tYWluPgoKICA8ZGl2IGNsYXNzPSJ2b2ljZS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtYmFubmVyIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJmYWItbWljIiBpZD0iZmFiLW1pYyIgYXJpYS1sYWJlbD0iRGljdGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUiPvCfjqQ8L2J1dHRvbj4KICA8YnV0dG9uIGNsYXNzPSJmYWIiIGlkPSJmYWItYWRkIiBhcmlhLWxhYmVsPSJBam91dGVyIj4rPC9idXR0b24+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0ibW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0ibW9kYWwtdGl0bGUiPk5vdXZlbGxlIHRyYW5zYWN0aW9uPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0idHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJpbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9InJlYy1tb2RhbC10aXRsZSI+Tm91dmVsbGUgZMOpcGVuc2UgcsOpY3VycmVudGU8L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJyZWMtdHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1uYW1lIj5Ob208L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0icmVjLWlucHV0LW5hbWUiIHBsYWNlaG9sZGVyPSJFeCA6IE5ldGZsaXgsIExveWVyLCBTYWxhaXJlLi4uIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InJlYy1pbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1kYXkiPkpvdXIgZHUgbW9pczwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1kYXkiIG1pbj0iMSIgbWF4PSIzMSIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IjEgw6AgMzEiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+RGF0ZSBkZSBkw6lidXQgKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZW5kLWRhdGUiPkRhdGUgZGUgZmluIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1lbmQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJyZWMtYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJyZWMtYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHNjcmlwdD4KICAgIC8vIERvaXQgY29ycmVzcG9uZHJlIGV4YWN0ZW1lbnQgw6AgbGEgdmFyaWFibGUgZCdlbnZpcm9ubmVtZW50IEFQSV9TRUNSRVRfS0VZIHN1ciBWZXJjZWwuCiAgICBjb25zdCBBUElfS0VZID0gIjNJUFFzeUVRRm1jQkxsbVRmVGsxSUF5MUNuazlGMGVWIjsKCiAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHgtbGlzdCIpOwogICAgY29uc3QgZW1wdHlTdGF0ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImVtcHR5LXN0YXRlIik7CiAgICBjb25zdCBzdW1tYXJ5QmFsYW5jZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktYmFsYW5jZSIpOwogICAgY29uc3Qgc3VtbWFyeUV4cGVuc2VzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1leHBlbnNlcyIpOwogICAgY29uc3Qgc3VtbWFyeUluY29tZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktaW5jb21lIik7CgogICAgY29uc3Qgb3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IG1vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC10aXRsZSIpOwogICAgY29uc3QgdHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR5cGUtdG9nZ2xlIik7CiAgICBjb25zdCBhbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1hbW91bnQiKTsKICAgIGNvbnN0IGNhdGVnb3J5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgLy8gQ2F0w6lnb3JpZXMgY3LDqcOpZXMgcGFyIGwndXRpbGlzYXRldXIgZGVwdWlzIGxlIGJhbmRlYXUgZGUgc3VnZ2VzdGlvbgogICAgLy8gKHZvaXIgcGx1cyBiYXMpLCBldCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgOiBzdG9ja8OpZXMgY8O0dMOpIHNlcnZldXIKICAgIC8vICh0YWJsZXMgY3VzdG9tX2NhdGVnb3JpZXMgLyBkaXNtaXNzZWRfY2F0ZWdvcnlfc3VnZ2VzdGlvbnMpIHBsdXTDtHQKICAgIC8vIHF1ZSBkYW5zIGxlIG5hdmlnYXRldXIsIHBvdXIgc3VpdnJlIHN1ciB0b3VzIGxlcyBhcHBhcmVpbHMgKHTDqWzDqXBob25lLAogICAgLy8gdGFibGV0dGUsIG9yZGluYXRldXIpIHBsdXTDtHQgcXVlIGRlIG5lIG1hcmNoZXIgcXVlIGzDoCBvw7kgYyfDqXRhaXQgY3LDqcOpLgogICAgbGV0IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldCgpOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRDdXN0b21DYXRlZ29yaWVzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiKTsKICAgICAgICBmb3IgKGNvbnN0IHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0gb2YgaXRlbXMpIHsKICAgICAgICAgIGlmIChjYXRlZ29yaWVzQnlUeXBlW3R5cGVdICYmICFjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdmFsdWUpKSB7CiAgICAgICAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgICAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZXMgY2F0w6lnb3JpZXMgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGtleXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiKTsKICAgICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cyA9IG5ldyBTZXQoa2V5cyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudCA6IGF1IHBpcmUgdW5lIHN1Z2dlc3Rpb24gZMOpasOgIHZ1ZSByw6lhcHBhcmHDrnQgdW5lIGZvaXMuCiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzbHVnaWZ5Q2F0ZWdvcnkobGFiZWwpIHsKICAgICAgcmV0dXJuICgKICAgICAgICBsYWJlbAogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gZW5sw6h2ZSBsZXMgYWNjZW50cwogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC50cmltKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0rL2csICJfIikKICAgICAgICAgIC5yZXBsYWNlKC9eXyt8XyskL2csICIiKSB8fCAiYXV0cmUiCiAgICAgICk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc2F2ZUN1c3RvbUNhdGVnb3J5KHR5cGUsIHZhbHVlLCBsYWJlbCkgewogICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSksCiAgICAgICAgfSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiQ2F0w6lnb3JpZSBjcsOpw6llIGljaSwgbWFpcyBwYXMgc2F1dmVnYXJkw6llIHN1ciBsZSBzZXJ2ZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dDsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgICBkZXRhaWwgPSBkYXRhLmRldGFpbCB8fCBkZXRhaWw7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZGV0YWlsKTsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gMjA0KSByZXR1cm4gbnVsbDsKICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICB9CgogICAgZnVuY3Rpb24gdG9kYXlJc28oKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCB0eiA9IGQuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShkLmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIGNhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0VHlwZSh0eXBlKSB7CiAgICAgIGN1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgdHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBjYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICB0eXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0VHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5Nb2RhbCh0eCA9IG51bGwpIHsKICAgICAgLy8gT24gZGlzdGluZ3VlICJtb2RpZmllciIgKHR4IGEgdW4gaWQsIHZyYWllIMOpZGl0aW9uIGVuIGJhc2UpIGRlCiAgICAgIC8vICJwcsOpLXJlbXBsaXIgw6AgcGFydGlyIGQndW4gbW9kw6hsZSIgKGR1cGxpY2F0aW9uIDogdHggZm91cm5pIG1haXMgc2FucwogICAgICAvLyBpZCA9PiBvbiBjcsOpZSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gYXUgbGlldSBkJ8OpY3Jhc2VyIGwnb3JpZ2luYWxlKS4KICAgICAgY29uc3QgaXNFZGl0ID0gQm9vbGVhbih0eCAmJiB0eC5pZCk7CiAgICAgIGVkaXRpbmdJZCA9IGlzRWRpdCA/IHR4LmlkIDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIGFtb3VudElucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpIHsKICAgICAgLy8gTcOqbWUgbW9udGFudC9jYXTDqWdvcmllL2Rlc2NyaXB0aW9uLCBtYWlzIGRhdMOpIGQnYXVqb3VyZCdodWkgZXQgc2FucwogICAgICAvLyBpZCA6IGxhIHNhdXZlZ2FyZGUgY3LDqWVyYSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gKHZvaXIgb3Blbk1vZGFsKS4KICAgICAgb3Blbk1vZGFsKHsgLi4udHgsIGlkOiBudWxsLCBleHBlbnNlX2RhdGU6IHRvZGF5SXNvKCkgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VNb2RhbCgpIHsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItYWRkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInJlY3VycmluZyIpIG9wZW5SZWN1cnJpbmdNb2RhbCgpOwogICAgICBlbHNlIG9wZW5Nb2RhbCgpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VNb2RhbCk7CiAgICBvdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXlFbCkgY2xvc2VNb2RhbCgpOyB9KTsKCiAgICBzYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KGFtb3VudElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBjdXJyZW50VHlwZSwKICAgICAgICBhbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5SW5wdXQudmFsdWUsCiAgICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uSW5wdXQudmFsdWUudHJpbSgpIHx8IG51bGwsCiAgICAgICAgZXhwZW5zZV9kYXRlOiBkYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoY3VycmVudFR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSBham91dMOpIiA6ICJEw6lwZW5zZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZU1vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVUcmFuc2FjdGlvbihpZCkgewogICAgICBpZiAoIWNvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhdXggZ2xvYmF1eCAoU29sZGUvRMOpcGVuc2VzL1JldmVudXMpIDogY2FsY3Vsw6lzIHN1ciBUT1VURVMgbGVzCiAgICAvLyB0cmFuc2FjdGlvbnMsIGluZMOpcGVuZGFtbWVudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUg4oCUIHVuIGZpbHRyZQogICAgLy8gc2VydCDDoCBjaGVyY2hlciBkYW5zIGxhIGxpc3RlLCBwYXMgw6AgcmVjYWxjdWxlciBsZSBzb2xkZSByw6llbC4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGJhbGFuY2UgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYmFsYW5jZSk7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAoYmFsYW5jZSA+PSAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBzdW1tYXJ5RXhwZW5zZXNFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgc3VtbWFyeUluY29tZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgIH0KCiAgICAvLyBDb25zdHJ1Y3Rpb24gZGUgbGEgbGlzdGUgZGUgY2FydGVzIGFmZmljaMOpZSBkYW5zIGwnb25nbGV0IEhpc3RvcmlxdWUg4oCUCiAgICAvLyByZcOnb2l0IGTDqWrDoCBsYSBsaXN0ZSBmaWx0csOpZSAodm9pciBhcHBseUhpc3RvcnlGaWx0ZXJzKS4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9uTGlzdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBpZiAodHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBlbXB0eVN0YXRlRWwudGV4dENvbnRlbnQgPSBhbGxUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwCiAgICAgICAgICA/ICJSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LiIKICAgICAgICAgIDogIkF1Y3VuIHLDqXN1bHRhdCBwb3VyIGNlcyBmaWx0cmVzLiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInR4LWNhcmQgIiArIHR4LnR5cGU7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJ0eC1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJ0eC10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gInR4LWRhdGUiOwogICAgICAgIGRhdGVTcGFuLnRleHRDb250ZW50ID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUodHguZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CiAgICAgICAgaWYgKHR4LnJlY3VycmluZ19leHBlbnNlX2lkKSB7CiAgICAgICAgICBjb25zdCByZWNCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIHJlY0JhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWN1cnJpbmctYmFkZ2UiOwogICAgICAgICAgcmVjQmFkZ2UudGV4dENvbnRlbnQgPSAi8J+UgSI7CiAgICAgICAgICByZWNCYWRnZS50aXRsZSA9ICJDcsOpw6llIGF1dG9tYXRpcXVlbWVudCBkZXB1aXMgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSI7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQocmVjQmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gInR4LWRlc2NyaXB0aW9uIjsKICAgICAgICBkZXNjLnRleHRDb250ZW50ID0gdHguZGVzY3JpcHRpb24gfHwgIuKAlCI7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwoKICAgICAgICBjb25zdCBhbW91bnRFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudEVsLmNsYXNzTmFtZSA9ICJ0eC1hbW91bnQgIiArIHR4LnR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHgudHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0eC5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3Blbk1vZGFsKHR4KSk7CiAgICAgICAgY29uc3QgZHVwbGljYXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZHVwbGljYXRlQnRuLnRleHRDb250ZW50ID0gIvCfk4siOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiRHVwbGlxdWVyIik7CiAgICAgICAgZHVwbGljYXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpKTsKICAgICAgICBjb25zdCBkZWxldGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkZWxldGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIGRhbmdlciI7CiAgICAgICAgZGVsZXRlQnRuLnRleHRDb250ZW50ID0gIvCfl5HvuI8iOwogICAgICAgIGRlbGV0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiU3VwcHJpbWVyIik7CiAgICAgICAgZGVsZXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZGVsZXRlVHJhbnNhY3Rpb24odHguaWQpKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGVkaXRCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZHVwbGljYXRlQnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSw6lzdW3DqSAiY2V0dGUgc2VtYWluZSIgKGluZMOpcGVuZGFudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzdGFydE9mV2Vla0lzbygpIHsKICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgZGF5ID0gbm93LmdldERheSgpOyAvLyAwID0gZGltYW5jaGUsIDEgPSBsdW5kaSwgLi4uCiAgICAgIGNvbnN0IGRpZmZUb01vbmRheSA9IGRheSA9PT0gMCA/IDYgOiBkYXkgLSAxOwogICAgICBjb25zdCBtb25kYXkgPSBuZXcgRGF0ZShub3cpOwogICAgICBtb25kYXkuc2V0RGF0ZShub3cuZ2V0RGF0ZSgpIC0gZGlmZlRvTW9uZGF5KTsKICAgICAgY29uc3QgdHogPSBtb25kYXkuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShtb25kYXkuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc3RhcnQgPSBzdGFydE9mV2Vla0lzbygpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJleHBlbnNlIiAmJiB0eC5leHBlbnNlX2RhdGUgPj0gc3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDw9IHRvZGF5KSB7CiAgICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIndlZWstc3VtbWFyeSIpLnRleHRDb250ZW50ID0KICAgICAgICBgQ2V0dGUgc2VtYWluZSAoZGVwdWlzIGx1bmRpKSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsKX0gZMOpcGVuc8Opc2A7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUmVjaGVyY2hlIGV0IGZpbHRyZXMgZGFucyBsJ2hpc3RvcmlxdWUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCkgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5Iik7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgT2JqZWN0LmVudHJpZXMoYWxsQ2F0ZWdvcnlMYWJlbHMpKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBhcHBseUhpc3RvcnlGaWx0ZXJzKCkgewogICAgICBjb25zdCBzZWFyY2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLXNlYXJjaCIpLnZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCBjYXRlZ29yeSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZVN0YXJ0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLXN0YXJ0IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVFbmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtZW5kIikudmFsdWU7CgogICAgICBjb25zdCBmaWx0ZXJlZCA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoKHR4KSA9PiB7CiAgICAgICAgaWYgKGNhdGVnb3J5ICYmIHR4LmNhdGVnb3J5ICE9PSBjYXRlZ29yeSkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlU3RhcnQgJiYgdHguZXhwZW5zZV9kYXRlIDwgZGF0ZVN0YXJ0KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVFbmQgJiYgdHguZXhwZW5zZV9kYXRlID4gZGF0ZUVuZCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChzZWFyY2gpIHsKICAgICAgICAgIGNvbnN0IGhheXN0YWNrID0gYCR7dHguZGVzY3JpcHRpb24gfHwgIiJ9ICR7YWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5fWAudG9Mb3dlckNhc2UoKTsKICAgICAgICAgIGlmICghaGF5c3RhY2suaW5jbHVkZXMoc2VhcmNoKSkgcmV0dXJuIGZhbHNlOwogICAgICAgIH0KICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgfSk7CiAgICAgIHJlbmRlclRyYW5zYWN0aW9uTGlzdChmaWx0ZXJlZCk7CiAgICB9CgogICAgWyJmaWx0ZXItc2VhcmNoIiwgImZpbHRlci1jYXRlZ29yeSIsICJmaWx0ZXItZGF0ZS1zdGFydCIsICJmaWx0ZXItZGF0ZS1lbmQiXS5mb3JFYWNoKChpZCkgPT4gewogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuYWRkRXZlbnRMaXN0ZW5lcigiaW5wdXQiLCBhcHBseUhpc3RvcnlGaWx0ZXJzKTsKICAgIH0pOwoKICAgIGxldCBhbGxUcmFuc2FjdGlvbnMgPSBbXTsKICAgIGxldCBjdXJyZW50VmlldyA9ICJoaXN0b3J5IjsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkVHJhbnNhY3Rpb25zKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHRyYW5zYWN0aW9ucyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIpOwogICAgICAgIGFsbFRyYW5zYWN0aW9ucyA9IHRyYW5zYWN0aW9uczsKICAgICAgICByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKTsKICAgICAgICB1cGRhdGVXZWVrU3VtbWFyeSh0cmFuc2FjdGlvbnMpOwogICAgICAgIGFwcGx5SGlzdG9yeUZpbHRlcnMoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBPbmdsZXRzIChIaXN0b3JpcXVlIC8gVGFibGVhdSBkZSBib3JkKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3dpdGNoVmlldyh2aWV3KSB7CiAgICAgIGN1cnJlbnRWaWV3ID0gdmlldzsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImhpc3RvcnkiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctaGlzdG9yeSIpLnN0eWxlLmRpc3BsYXkgPSB2aWV3ID09PSAiaGlzdG9yeSIgPyAiYmxvY2siIDogIm5vbmUiOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBpZiAodmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiaGlzdG9yeSIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJkYXNoYm9hcmQiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygicmVjdXJyaW5nIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImV4cG9ydCIpKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBUYWJsZWF1IGRlIGJvcmQgKGdyYXBoaXF1ZXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtb250aEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJsb25nIiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgbW9udGhTaG9ydEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IENIQVJUX0NPTE9SUyA9IFsiIzNiODJmNiIsICIjMjJjNTVlIiwgIiNlZjQ0NDQiLCAiI2Y1OWUwYiIsICIjYTg1NWY3IiwgIiMxNGI4YTYiLCAiI2VjNDg5OSIsICIjNjQ3NDhiIl07CgogICAgbGV0IGNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGluY29tZUNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgLy8gVW5lIGNoYXJnZSByw6ljdXJyZW50ZSBjb21wdGUgcG91ciB1biBtb2lzIGRvbm7DqSBzaSBjZSBtb2lzIGVzdCBkYW5zIHNhCiAgICAvLyBww6lyaW9kZSBkJ2FjdGl2aXTDqSA6IHBhcyBhdmFudCBzYSBkYXRlIGRlIGTDqWJ1dCAoc2kgcG9zw6llKSwgcGFzIGFwcsOocwogICAgLy8gbGUgbW9pcyBkZSBzYSBkYXRlIGRlIGZpbiAoc2kgcG9zw6llKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSB7CiAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUgJiYgbW9udGhLZXkgPCBpdGVtLnN0YXJ0X2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUgJiYgbW9udGhLZXkgPiBpdGVtLmVuZF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIHJldHVybiB0cnVlOwogICAgfQoKICAgIC8vIEpvdXIgZHUgbW9pcyBqdXNxdSdhdXF1ZWwgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBlc3QgY29uc2lkw6lyw6llIGNvbW1lCiAgICAvLyAiZMOpasOgIHByw6lsZXbDqWUiIHBvdXIgbGUgbW9pcyBgbW9udGhLZXlgIDogdG91cyBsZXMgam91cnMgcG91ciB1biBtb2lzCiAgICAvLyBkw6lqw6AgcGFzc8OpLCBhdWN1biBwb3VyIHVuIG1vaXMgZnV0dXIsIGV0IGxlIGpvdXIgZHUgam91ciBwb3VyIGxlIG1vaXMKICAgIC8vIGVuIGNvdXJzLiBQZXJtZXQgZGUgZGlzdGluZ3VlciBjZSBxdWkgZXN0IGTDqWrDoCBhcnJpdsOpIGRlIGNlIHF1aSBlc3QKICAgIC8vIHNldWxlbWVudCBwcsOpdnUgKGV4IDogdW4gYWJvbm5lbWVudCBwcsOpbGV2w6kgbGUgMjUsIG9uIGVzdCBsZSAyKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSkgewogICAgICBpZiAobW9udGhLZXkgPCBjdXJyZW50TW9udGhLZXkpIHJldHVybiAzMTsKICAgICAgaWYgKG1vbnRoS2V5ID4gY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMDsKICAgICAgcmV0dXJuIHRvZGF5RGF5OwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCkgbW9udGhTZXQuYWRkKG1vbnRoS2V5T2YodG9kYXlJc28oKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gIiI7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gIkF1Y3VuZSBkb25uw6llIjsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgc2VsZWN0LnZhbHVlID0gbW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IG1vbnRoc1swXTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCB1cGNvbWluZ05vdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIpOwogICAgICBjb25zdCB1cGNvbWluZ1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCIpOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBjb25zdCBjdXRvZmYgPSByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBVbiBzZXVsIHNvbGRlIG5ldCAiw6AgdmVuaXIiIChyZXZlbnVzIHLDqWN1cnJlbnRzIMOgIHZlbmlyIG1vaW5zIGTDqXBlbnNlcwogICAgICAvLyByw6ljdXJyZW50ZXMgw6AgdmVuaXIpLCBwbHV0w7R0IHF1ZSBkZXV4IGNoaWZmcmVzIHPDqXBhcsOpcyA6IHBsdXMgc2ltcGxlCiAgICAgIC8vIMOgIGxpcmUgZCd1biBjb3VwIGQnxZNpbC4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUgc29udCBQQVMKICAgICAgLy8gYWpvdXTDqWVzIGljaSA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUgdnJhaWVzIHRyYW5zYWN0aW9ucwogICAgICAvLyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzIGRhbnMgYHRvdGFsc2AKICAgICAgLy8gY2ktZGVzc3VzIOKAlCBsZXMgYWpvdXRlciDDoCBub3V2ZWF1IGxlcyBjb21wdGVyYWl0IGVuIGRvdWJsZS4KICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IGN1dG9mZikgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIC8vIE3Dqm1lIHByaW5jaXBlIHF1ZSByZW5kZXJDYXRlZ29yeUNoYXJ0LCBjw7R0w6kgcmV2ZW51cyDigJQgcGFzIGRlIG5vdGUgIsOgCiAgICAvLyB2ZW5pciIgaWNpLCBlbGxlIHJlc3RlIHVuaXF1ZW1lbnQgc3VyIGxlIGNhbWVtYmVydCBkZXMgZMOpcGVuc2VzIHBvdXIKICAgIC8vIG5lIHBhcyBhZmZpY2hlciBsZSBtw6ptZSBjaGlmZnJlIG5ldCDDoCBkZXV4IGVuZHJvaXRzLgogICAgZnVuY3Rpb24gcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJpbmNvbWUiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGlmIChpbmNvbWVDYXRlZ29yeUNoYXJ0KSB7IGluY29tZUNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgICAgbW9udGhseVtrZXldW3R4LnR5cGVdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFRvdWpvdXJzIGluY2x1cmUgbGUgbW9pcyBlbiBjb3VycyAobcOqbWUgc2FucyB0cmFuc2FjdGlvbikgcydpbCBleGlzdGUKICAgICAgLy8gZGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBwb3VyIHF1J2lsIGFwcGFyYWlzc2Ugc2FucyBhdHRlbmRyZSBsYQogICAgICAvLyBwcmVtacOocmUgdHJhbnNhY3Rpb24gZHUgbW9pcy4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUKICAgICAgLy8gc29udCBwbHVzIGFqb3V0w6llcyBpY2kgw6AgbGEgbWFpbiA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUKICAgICAgLy8gdnJhaWVzIHRyYW5zYWN0aW9ucyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzCiAgICAgIC8vIGRhbnMgYG1vbnRobHlgIHZpYSBsYSBib3VjbGUgc3VyIGB0cmFuc2FjdGlvbnNgIGNpLWRlc3N1cyDigJQgY2UgcXVpCiAgICAgIC8vIG4nZXN0IHBhcyBlbmNvcmUgYXJyaXbDqSBlc3QgcsOpc3Vtw6kgYWlsbGV1cnMgKHNvbGRlIG5ldCAiw6AgdmVuaXIiKS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIERpY3TDqWUgdm9jYWxlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtaWNCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLW1pYyIpOwogICAgY29uc3Qgdm9pY2VCYW5uZXJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2b2ljZS1iYW5uZXIiKTsKCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgdHJhbnNhY3Rpb24gY3LDqcOpZSBQQVIgTEEgVk9JWCBkYW5zIGNldHRlIHNlc3Npb24gZGUKICAgIC8vIG5hdmlnYXRpb24gKHJlbWlzIMOgIHrDqXJvIHNpIG9uIHJlY2hhcmdlIGxhIHBhZ2UpLiBTZXJ0IHVuaXF1ZW1lbnQgw6AKICAgIC8vIGFwcGxpcXVlciB1bmUgY29ycmVjdGlvbiAoImVuIGZhaXQgYyfDqXRhaXQgcGx1dMO0dC4uLiIpIHN1ciBsYSBib25uZQogICAgLy8gdHJhbnNhY3Rpb24uIFNhbnMgw6dhLCBvdSBzaSBsYSBwaHJhc2Ugbidlc3QgcGFzIHVuZSBjb3JyZWN0aW9uLCBvbgogICAgLy8gY3LDqWUgdG91am91cnMgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIOKAlCBtaWV1eCB2YXV0IHVuIGRvdWJsb24gcXUndW5lCiAgICAvLyBkw6lwZW5zZSBjb3Jyb21wdWUgcGFyIGVycmV1ci4KICAgIGxldCBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gbnVsbDsKCiAgICBmdW5jdGlvbiBzZXRWb2ljZUJhbm5lcih0ZXh0KSB7CiAgICAgIGlmICghdGV4dCkgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9ICIiOwogICAgICB9IGVsc2UgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBTcGVlY2hSZWNvZ25pdGlvbkN0b3IgPSB3aW5kb3cuU3BlZWNoUmVjb2duaXRpb24gfHwgd2luZG93LndlYmtpdFNwZWVjaFJlY29nbml0aW9uOwoKICAgIGlmICghU3BlZWNoUmVjb2duaXRpb25DdG9yKSB7CiAgICAgIG1pY0J0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIG1pY0J0bi50aXRsZSA9ICJEaWN0w6llIHZvY2FsZSBub24gZGlzcG9uaWJsZSBzdXIgY2UgbmF2aWdhdGV1ciAodXRpbGlzZSBDaHJvbWUgb3UgRWRnZSkiOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgcmVjb2duaXRpb24gPSBuZXcgU3BlZWNoUmVjb2duaXRpb25DdG9yKCk7CiAgICAgIHJlY29nbml0aW9uLmxhbmcgPSAiZnItRlIiOwogICAgICByZWNvZ25pdGlvbi5jb250aW51b3VzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLmludGVyaW1SZXN1bHRzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLm1heEFsdGVybmF0aXZlcyA9IDE7CgogICAgICBsZXQgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInN0YXJ0IiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gdHJ1ZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgibGlzdGVuaW5nIik7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIkplIHQnw6ljb3V0ZeKApiIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVuZCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlcnJvciIsIChldmVudCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgaWYgKGV2ZW50LmVycm9yID09PSAibm8tc3BlZWNoIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIlJpZW4gZW50ZW5kdSwgcsOpZXNzYWllLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMjAwMCk7CiAgICAgICAgfSBlbHNlIGlmIChldmVudC5lcnJvciA9PT0gIm5vdC1hbGxvd2VkIiB8fCBldmVudC5lcnJvciA9PT0gInNlcnZpY2Utbm90LWFsbG93ZWQiKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiTWljcm8gcmVmdXPDqSDigJQgYXV0b3Jpc2UgbCdhY2PDqHMgYXUgbWljcm8gZGFucyB0b24gbmF2aWdhdGV1ci4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDQwMDApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcihudWxsKTsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIG1pY3JvIDogIiArIGV2ZW50LmVycm9yLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigicmVzdWx0IiwgYXN5bmMgKGV2ZW50KSA9PiB7CiAgICAgICAgY29uc3QgdHJhbnNjcmlwdCA9IGV2ZW50LnJlc3VsdHNbMF1bMF0udHJhbnNjcmlwdDsKICAgICAgICBzZXRWb2ljZUJhbm5lcihgIiR7dHJhbnNjcmlwdH0iYCk7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoInByb2Nlc3NpbmciKTsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgcGFyc2VkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvcGFyc2UiLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRleHQ6IHRyYW5zY3JpcHQgfSksCiAgICAgICAgICB9KTsKICAgICAgICAgIGF3YWl0IGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDE1MDApOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICBtaWNCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgaWYgKGlzTGlzdGVuaW5nKSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdG9wKCk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIHRyeSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdGFydCgpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgLy8gc3RhcnQoKSBqZXR0ZSBzaSBkw6lqw6AgZMOpbWFycsOpIDsgb24gaWdub3JlLgogICAgICAgIH0KICAgICAgfSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU3VnZ2VzdGlvbnMgZGUgY2F0w6lnb3JpZSDigJQgdW5pcXVlbWVudCBhcHLDqHMgdW5lIHNhaXNpZSBwYXIgZGljdMOpZQogICAgLy8gdm9jYWxlICh1bmUgZmF1dGUgZGUgZnJhcHBlIGVuIHNhaXNpZSBtYW51ZWxsZSwgYydlc3QgdW5lIGVycmV1ciBkZQogICAgLy8gbCd1dGlsaXNhdGV1ciwgcGFzIGxhIHBlaW5lIGRlIGxlIHJlbGFuY2VyIGRlc3N1cykuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBDQVRFR09SWV9TVUdHRVNUSU9OX1RIUkVTSE9MRCA9IDM7CgogICAgZnVuY3Rpb24gbm9ybWFsaXplRGVzY3JpcHRpb24oZGVzYykgewogICAgICByZXR1cm4gKGRlc2MgfHwgIiIpLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGRpc21pc3NTdWdnZXN0aW9uKGtleSkgewogICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5hZGQoa2V5KTsgLy8gaW1tw6lkaWF0IGPDtHTDqSBVSSwgcGFzIGJlc29pbiBkJ2F0dGVuZHJlIGxlIHNlcnZldXIKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsga2V5IH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIGxhIHN1Z2dlc3Rpb24gcsOpYXBwYXJhw650IHVuZSBmb2lzIHN1ciB1bgogICAgICAgIC8vIGF1dHJlIGFwcGFyZWlsIHNpIGxhIHNhdXZlZ2FyZGUgc2VydmV1ciBhIMOpY2hvdcOpLgogICAgICB9CiAgICB9CgogICAgLy8gUmVnYXJkZSBzaSBsYSBkZXNjcmlwdGlvbiBkZSBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZQogICAgLy8gKG91IGNvcnJpZ8OpZSkgw6AgbGEgdm9peCByZXZpZW50IHNvdXZlbnQsIGV0IHNpIG91aSA6CiAgICAvLyAtIHNvaXQgZWxsZSBhIHRvdWpvdXJzIMOpdMOpIHJhbmfDqWUgZGFucyAiQXV0cmUiIOKGkiBvbiBwcm9wb3NlIGRlIGNyw6llcgogICAgLy8gICB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgZGUgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgOwogICAgLy8gLSBzb2l0IGVsbGUgYSBjZXR0ZSBmb2lzIHVuZSBjYXTDqWdvcmllIGRpZmbDqXJlbnRlIGRlIGQnaGFiaXR1ZGUg4oaSIG9uCiAgICAvLyAgIGRlbWFuZGUgc2kgY2Ugbidlc3QgcGFzIHVuZSBlcnJldXIuCiAgICBmdW5jdGlvbiBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihkZXNjcmlwdGlvbiwgdHlwZSkgewogICAgICBjb25zdCBub3JtID0gbm9ybWFsaXplRGVzY3JpcHRpb24oZGVzY3JpcHRpb24pOwogICAgICBpZiAoIW5vcm0pIHJldHVybjsKCiAgICAgIGNvbnN0IHNhbWVEZXNjcmlwdGlvbiA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgKHR4KSA9PiB0eC50eXBlID09PSB0eXBlICYmIG5vcm1hbGl6ZURlc2NyaXB0aW9uKHR4LmRlc2NyaXB0aW9uKSA9PT0gbm9ybQogICAgICApOwogICAgICBpZiAoc2FtZURlc2NyaXB0aW9uLmxlbmd0aCA8IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEKSByZXR1cm47CgogICAgICBjb25zdCBjb3VudHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiBzYW1lRGVzY3JpcHRpb24pIGNvdW50c1t0eC5jYXRlZ29yeV0gPSAoY291bnRzW3R4LmNhdGVnb3J5XSB8fCAwKSArIDE7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBPYmplY3Qua2V5cyhjb3VudHMpOwogICAgICBjb25zdCBkb21pbmFudCA9IGNhdGVnb3JpZXMucmVkdWNlKChhLCBiKSA9PiAoY291bnRzW2FdID49IGNvdW50c1tiXSA/IGEgOiBiKSk7CiAgICAgIGNvbnN0IGxhdGVzdCA9IHNhbWVEZXNjcmlwdGlvblswXTsgLy8gYWxsVHJhbnNhY3Rpb25zIGVzdCB0cmnDqSBwYXIgZGF0ZSBkw6ljcm9pc3NhbnRlCgogICAgICBsZXQgc3VnZ2VzdGlvbiA9IG51bGw7CiAgICAgIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ICE9PSBkb21pbmFudCkgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBtaXNtYXRjaDoke3R5cGV9OiR7bm9ybX06JHtsYXRlc3QuY2F0ZWdvcnl9YCwKICAgICAgICAgIGtpbmQ6ICJtaXNtYXRjaCIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIGRvbWluYW50LAogICAgICAgICAgY3VycmVudDogbGF0ZXN0LmNhdGVnb3J5LAogICAgICAgICAgdHhJZHM6IHNhbWVEZXNjcmlwdGlvbi5maWx0ZXIoKHR4KSA9PiB0eC5jYXRlZ29yeSA9PT0gbGF0ZXN0LmNhdGVnb3J5KS5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgfTsKICAgICAgfSBlbHNlIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA9PT0gMSAmJiBkb21pbmFudCA9PT0gImF1dHJlIikgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBnZW5lcmljOiR7dHlwZX06JHtub3JtfWAsCiAgICAgICAgICBraW5kOiAiZ2VuZXJpYyIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24ubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0KCiAgICAgIGlmICghc3VnZ2VzdGlvbiB8fCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5oYXMoc3VnZ2VzdGlvbi5rZXkpKSByZXR1cm47CiAgICAgIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbik7CiAgICB9CgogICAgZnVuY3Rpb24gaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCkgewogICAgICBjb25zdCBbbGF0ZXN0SWQsIC4uLm90aGVyc10gPSBzdWdnZXN0aW9uLnR4SWRzOwogICAgICBjb25zdCBpZHNUb0ZpeCA9IFtsYXRlc3RJZF07CiAgICAgIGlmICgKICAgICAgICBvdGhlcnMubGVuZ3RoID4gMCAmJgogICAgICAgIGNvbmZpcm0oYENvcnJpZ2VyIGF1c3NpIGxlcyAke290aGVycy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHByw6ljw6lkZW50ZShzKSBhdmVjIGxhIG3Dqm1lIGRlc2NyaXB0aW9uID9gKQogICAgICApIHsKICAgICAgICBpZHNUb0ZpeC5wdXNoKC4uLm90aGVycyk7CiAgICAgIH0KCiAgICAgIHRyeSB7CiAgICAgICAgZm9yIChjb25zdCBpZCBvZiBpZHNUb0ZpeCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5OiB0YXJnZXRWYWx1ZSB9KSwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgICBzaG93VG9hc3QoYENhdMOpZ29yaWUgbWlzZSDDoCBqb3VyIDogJHt0YXJnZXRMYWJlbH1gKTsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd0NhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcihzdWdnZXN0aW9uKSB7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgICBlbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKCiAgICAgIGNvbnN0IGRlc2NMYWJlbCA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYFR1IGFzIHV0aWxpc8OpICIke2Rlc2NMYWJlbH0iICR7c3VnZ2VzdGlvbi50eElkcy5sZW5ndGh9IGZvaXMsIHRvdWpvdXJzIGNsYXNzw6kgZW4gYCArCiAgICAgICAgICBgIkF1dHJlIi4gQ3LDqWVyIHVuZSBjYXTDqWdvcmllIGTDqWRpw6llIChvdSBsYSByYXR0YWNoZXIgw6AgdW5lIGNhdMOpZ29yaWUgZXhpc3RhbnRlKSA/YDsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBjdXJyZW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmN1cnJlbnRdIHx8IHN1Z2dlc3Rpb24uY3VycmVudDsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGAiJHtkZXNjTGFiZWx9IiBlc3QgaGFiaXR1ZWxsZW1lbnQgY2xhc3PDqSBlbiAiJHtkb21pbmFudExhYmVsfSIsIG1haXMgY2V0dGUgZm9pcyBgICsKICAgICAgICAgIGBjJ2VzdCAiJHtjdXJyZW50TGFiZWx9Ii4gUGFzIGQnZXJyZXVyIG91IHVuIG91YmxpID9gOwogICAgICB9CiAgICAgIGVsLmFwcGVuZENoaWxkKHRleHQpOwoKICAgICAgY29uc3QgY29udHJvbHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgY29udHJvbHMuY2xhc3NOYW1lID0gImNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMiOwoKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2VsZWN0Iik7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0pIHsKICAgICAgICAgIGlmICh2YWx1ZSA9PT0gImF1dHJlIikgY29udGludWU7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgY29uc3QgbmV3T3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICAgIG5ld09wdC50ZXh0Q29udGVudCA9ICIrIE5vdXZlbGxlIGNhdMOpZ29yaWXigKYiOwogICAgICAgIG5ld09wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG5ld09wdCk7CgogICAgICAgIGNvbnN0IG5ld05hbWVJbnB1dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgbmV3TmFtZUlucHV0LnR5cGUgPSAidGV4dCI7CiAgICAgICAgbmV3TmFtZUlucHV0LnBsYWNlaG9sZGVyID0gIk5vbSBkZSBsYSBub3V2ZWxsZSBjYXTDqWdvcmllIjsKICAgICAgICBuZXdOYW1lSW5wdXQudmFsdWUgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIiOwoKICAgICAgICBzZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgbmV3TmFtZUlucHV0LnN0eWxlLmRpc3BsYXkgPSBzZWxlY3QudmFsdWUgPT09ICJfX25ld19fIiA/ICJpbmxpbmUtYmxvY2siIDogIm5vbmUiOwogICAgICAgIH0pOwoKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChzZWxlY3QpOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKG5ld05hbWVJbnB1dCk7CgogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSAiQXBwbGlxdWVyIjsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgbGV0IHRhcmdldFZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICAgICAgbGV0IHRhcmdldExhYmVsOwogICAgICAgICAgaWYgKHRhcmdldFZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICAgICAgY29uc3QgbmFtZSA9IG5ld05hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgICAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkRvbm5lIHVuIG5vbSDDoCBsYSBjYXTDqWdvcmllIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICAgICAgICB0YXJnZXRWYWx1ZSA9IHNsdWdpZnlDYXRlZ29yeShuYW1lKTsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBuYW1lOwogICAgICAgICAgICBpZiAoIWNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHRhcmdldFZhbHVlKSkgewogICAgICAgICAgICAgIHNhdmVDdXN0b21DYXRlZ29yeShzdWdnZXN0aW9uLnR5cGUsIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdGFyZ2V0VmFsdWVdIHx8IHRhcmdldFZhbHVlOwogICAgICAgICAgfQogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICB9KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChhcHBseUJ0bik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9IGBDb3JyaWdlciBlbiAiJHtkb21pbmFudExhYmVsfSJgOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCBzdWdnZXN0aW9uLmRvbWluYW50LCBkb21pbmFudExhYmVsKTsKICAgICAgICB9KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChhcHBseUJ0bik7CiAgICAgIH0KCiAgICAgIGNvbnN0IGRpc21pc3NCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgZGlzbWlzc0J0bi50ZXh0Q29udGVudCA9ICJJZ25vcmVyIjsKICAgICAgZGlzbWlzc0J0bi5jbGFzc05hbWUgPSAiYnRuLXNlY29uZGFyeS1zbSI7CiAgICAgIGRpc21pc3NCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgfSk7CiAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGRpc21pc3NCdG4pOwoKICAgICAgZWwuYXBwZW5kQ2hpbGQoY29udHJvbHMpOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBjb25zdCB2ZXJiID0gcGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSIgOiAiRMOpcGVuc2UiOwogICAgICBjb25zdCBhbW91bnRMYWJlbCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChwYXJzZWQuYW1vdW50KTsKCiAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkKSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7bGFzdFZvaWNlVHJhbnNhY3Rpb25JZH1gLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KGBDb3JyaWfDqSA6ICR7dmVyYi50b0xvd2VyQ2FzZSgpfSBkZSAke2Ftb3VudExhYmVsfWApOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBjcmVhdGVkLmlkOwogICAgICAgIHNob3dUb2FzdChgJHt2ZXJifSBham91dMOpJHtwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiIiA6ICJlIn0gOiAke2Ftb3VudExhYmVsfWApOwogICAgICB9CiAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24ocGFyc2VkLmRlc2NyaXB0aW9uLCBwYXJzZWQudHlwZSk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghY29uZmlybSgiU3VwcHJpbWVyIGNldHRlIGTDqXBlbnNlIHLDqWN1cnJlbnRlID8iKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFJlY3VycmluZygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIpOwogICAgICAgIGFsbFJlY3VycmluZyA9IGl0ZW1zOwogICAgICAgIHJlbmRlclJlY3VycmluZyhpdGVtcyk7CiAgICAgICAgdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRXhwb3J0IEV4Y2VsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC14bHN4IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LXhsc3giKTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiR8OpbsOpcmF0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9leHBvcnQveGxzeCIsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pOwogICAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoIsOJY2hlYyBkZSBsJ2V4cG9ydCAoIiArIHJlcy5zdGF0dXMgKyAiKSIpOwogICAgICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByZXMuYmxvYigpOwogICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgY29uc3QgbGluayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImEiKTsKICAgICAgICBsaW5rLmhyZWYgPSB1cmw7CiAgICAgICAgbGluay5kb3dubG9hZCA9IGBkZXBlbnNlc18ke3RvZGF5SXNvKCl9Lnhsc3hgOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobGluayk7CiAgICAgICAgbGluay5jbGljaygpOwogICAgICAgIGxpbmsucmVtb3ZlKCk7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogICAgICAgIHNob3dUb2FzdCgiRXhwb3J0IHTDqWzDqWNoYXJnw6kiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IG9yaWdpbmFsVGV4dDsKICAgICAgfQogICAgfSk7CgogICAgcG9wdWxhdGVDYXRlZ29yaWVzKCJleHBlbnNlIik7CiAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgKGFzeW5jIGZ1bmN0aW9uIGluaXQoKSB7CiAgICAgIC8vIENhdMOpZ29yaWVzIHBlcnNvICsgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIGQnYWJvcmQsIHBvdXIgcXVlIGxlcwogICAgICAvLyBsaXN0ZXMgZMOpcm91bGFudGVzIGV0IGxlIGJhbmRlYXUgc29pZW50IGNvcnJlY3RzIGTDqHMgbGUgcHJlbWllcgogICAgICAvLyByZW5kdSBwbHV0w7R0IHF1ZSBkZSAic2F1dGVyIiB1bmUgZm9pcyBsZSBzZXJ2ZXVyIHLDqXBvbmR1LgogICAgICBhd2FpdCBQcm9taXNlLmFsbChbbG9hZEN1c3RvbUNhdGVnb3JpZXMoKSwgbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCldKTsKICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBsb2FkUmVjdXJyaW5nKCk7CiAgICB9KSgpOwogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
