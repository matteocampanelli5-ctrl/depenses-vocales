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
    name: str = Field(min_length=1)
    amount: float = Field(gt=0)
    category: str = "autre"
    day_of_month: int = Field(ge=1, le=31)
    end_date: date | None = None  # None => pas de date de fin, se répète indéfiniment


class RecurringExpenseUpdate(BaseModel):
    name: str | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    day_of_month: int | None = Field(default=None, ge=1, le=31)
    end_date: date | None = None


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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vY2hhcnQuanNANC40LjQvZGlzdC9jaGFydC51bWQubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAudGFicyB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICB9CiAgLnRhYi1idG4gewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudGFiLWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAud2Vlay1zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IC0wLjRyZW0gYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnVwY29taW5nLW5vdGUgewogICAgd2lkdGg6IDk2cHg7CiAgICBmbGV4LXNocmluazogMDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC40cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjI1OwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CiAgLnVwY29taW5nLW5vdGUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1zd2F0Y2ggewogICAgd2lkdGg6IDI4cHg7CiAgICBoZWlnaHQ6IDE0cHg7CiAgICBib3JkZXI6IDEuNXB4IGRhc2hlZCB2YXIoLS1kYW5nZXIpOwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICB9CgogIC5yZWN1cnJpbmctc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjdXJyaW5nLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLmV4cG9ydC1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5leHBvcnQtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CiAgLnJlYy1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNnJlbTsKICB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnJlYy1hbW91bnQgeyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IDEuMDVyZW07IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KCiAgLmZhYiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogMS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsKICAgIGNvbG9yOiB3aGl0ZTsKICAgIGZvbnQtc2l6ZTogMS44cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjQpOwogIH0KICAuZmFiOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KCiAgLmZhYi1taWMgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDUuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSgwLCAwLCAwLCAwLjMpOwogICAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzLCBib3JkZXItY29sb3IgMC4yczsKICB9CiAgLmZhYi1taWM6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQogIC5mYWItbWljLmxpc3RlbmluZyB7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOwogICAgYW5pbWF0aW9uOiBwdWxzZSAxLjJzIGluZmluaXRlOwogIH0KICAuZmFiLW1pYy5wcm9jZXNzaW5nIHsgb3BhY2l0eTogMC42OyBjdXJzb3I6IGRlZmF1bHQ7IH0KICAuZmFiLW1pYzpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuMzU7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KICBAa2V5ZnJhbWVzIHB1bHNlIHsKICAgIDAlLCAxMDAlIHsgYm94LXNoYWRvdzogMCAwIDAgMCByZ2JhKDIzOSwgNjgsIDY4LCAwLjQpOyB9CiAgICA1MCUgeyBib3gtc2hhZG93OiAwIDAgMCAxMHB4IHJnYmEoMjM5LCA2OCwgNjgsIDApOyB9CiAgfQoKICAudm9pY2UtYmFubmVyIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGJvdHRvbTogOS41cmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTJweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE1OwogIH0KICAudm9pY2UtYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KCiAgLm1vZGFsLW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LWVuZDsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTA7CiAgfQogIC5tb2RhbC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubW9kYWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXItcmFkaXVzOiAxOHB4IDE4cHggMCAwOwogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gY2FsYygxLjVyZW0gKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpOwogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuOXJlbTsKICB9CiAgLm1vZGFsIGgyIHsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC1zaXplOiAxLjFyZW07IH0KCiAgbGFiZWwgeyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuM3JlbTsgfQogIGlucHV0LCBzZWxlY3QgewogICAgd2lkdGg6IDEwMCU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjY1cmVtIDAuNzVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIGlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IH0KCiAgLnR5cGUtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IH0KICAudHlwZS1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNjVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImV4cGVuc2UiXSB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImluY29tZSJdIHsgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQoKICAubW9kYWwtYWN0aW9ucyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICBidXR0b24ucHJpbWFyeSwgYnV0dG9uLnNlY29uZGFyeSB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC43NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIGJ1dHRvbi5wcmltYXJ5OmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CiAgYnV0dG9uLnNlY29uZGFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAudG9hc3QgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgdG9wOiAxcmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICB6LWluZGV4OiAyMDsKICAgIG1heC13aWR0aDogOTB2dzsKICB9CiAgLnRvYXN0LmVycm9yIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogI2ZjYTVhNTsgfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogIDxoZWFkZXI+CiAgICA8aDE+8J+SsyBTdWl2aSBkZSBkw6lwZW5zZXM8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxwIGNsYXNzPSJ3ZWVrLXN1bW1hcnkiIGlkPSJ3ZWVrLXN1bW1hcnkiPjwvcD4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz7DiXZvbHV0aW9uIG1lbnN1ZWxsZSAoZMOpcGVuc2VzIHZzIHJldmVudXMpPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWV2b2x1dGlvbiI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llcuKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudCBjaGFxdWUgbW9pcwogICAgICAgIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4gTWV0cyB1bmUgZGF0ZSBkZQogICAgICAgIGZpbiBzaSB1bmUgY2hhcmdlIGRvaXQgcydhcnLDqnRlciB1biBqb3VyLgogICAgICA8L3A+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBBdWN1bmUgZMOpcGVuc2UgcsOpY3VycmVudGUgcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgKyBwb3VyIGVuIGFqb3V0ZXIgdW5lLgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1leHBvcnQiIGNsYXNzPSJleHBvcnQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5FeHBvcnRlciB0ZXMgZG9ubsOpZXM8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBUw6lsw6ljaGFyZ2UgdW4gZmljaGllciBFeGNlbCAoLnhsc3gpIGF2ZWMgdG91dGVzIHRlcyB0cmFuc2FjdGlvbnMKICAgICAgICAgIChkw6lwZW5zZXMgZXQgcmV2ZW51cykgZXQgdGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24KICAgICAgICAgIHByb3ByZSBvbmdsZXQuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tZXhwb3J0LXhsc3giIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlciBsZSBmaWNoaWVyIEV4Y2VsPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiLW1pYyIgaWQ9ImZhYi1taWMiIGFyaWEtbGFiZWw9IkRpY3RlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51Ij7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kZXNjcmlwdGlvbiI+RGVzY3JpcHRpb24gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW5wdXQtZGVzY3JpcHRpb24iIHBsYWNlaG9sZGVyPSJFeCA6IGTDqWpldW5lciBhdmVjIFBhdWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kYXRlIj5EYXRlPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImlucHV0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlYy1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJyZWMtbW9kYWwtdGl0bGUiPk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlPC9oMj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LW5hbWUiPk5vbTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJyZWMtaW5wdXQtbmFtZSIgcGxhY2Vob2xkZXI9IkV4IDogTmV0ZmxpeCwgTG95ZXIuLi4iPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0icmVjLWlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWRheSI+Sm91ciBkdSBtb2lzPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWRheSIgbWluPSIxIiBtYXg9IjMxIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iMSDDoCAzMSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1lbmQtZGF0ZSI+RGF0ZSBkZSBmaW4gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LWVuZC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9InJlYy1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9InJlYy1idG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8c2NyaXB0PgogICAgLy8gRG9pdCBjb3JyZXNwb25kcmUgZXhhY3RlbWVudCDDoCBsYSB2YXJpYWJsZSBkJ2Vudmlyb25uZW1lbnQgQVBJX1NFQ1JFVF9LRVkgc3VyIFZlcmNlbC4KICAgIGNvbnN0IEFQSV9LRVkgPSAiM0lQUXN5RVFGbWNCTGxtVGZUazFJQXkxQ25rOUYwZVYiOwoKICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eC1saXN0Iik7CiAgICBjb25zdCBlbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHN1bW1hcnlCYWxhbmNlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1iYWxhbmNlIik7CiAgICBjb25zdCBzdW1tYXJ5RXhwZW5zZXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWV4cGVuc2VzIik7CiAgICBjb25zdCBzdW1tYXJ5SW5jb21lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1pbmNvbWUiKTsKCiAgICBjb25zdCBvdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgbW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLXRpdGxlIik7CiAgICBjb25zdCB0eXBlVG9nZ2xlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IGFtb3VudElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWFtb3VudCIpOwogICAgY29uc3QgY2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgZGVzY3JpcHRpb25JbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kZXNjcmlwdGlvbiIpOwogICAgY29uc3QgZGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRhdGUiKTsKICAgIGNvbnN0IHNhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXNhdmUiKTsKCiAgICBsZXQgZWRpdGluZ0lkID0gbnVsbDsgLy8gbnVsbCA9IGNyw6lhdGlvbiwgc2lub24gaWQgZGUgbGEgdHJhbnNhY3Rpb24gw6lkaXTDqWUKICAgIGxldCBjdXJyZW50VHlwZSA9ICJleHBlbnNlIjsKCiAgICBjb25zdCBjYXRlZ29yaWVzQnlUeXBlID0gewogICAgICBleHBlbnNlOiBbCiAgICAgICAgWyJyZXN0YXVyYW50IiwgIlJlc3RhdXJhbnQiXSwKICAgICAgICBbImNvdXJzZXMiLCAiQ291cnNlcyJdLAogICAgICAgIFsidHJhbnNwb3J0IiwgIlRyYW5zcG9ydCJdLAogICAgICAgIFsibG9nZW1lbnQiLCAiTG9nZW1lbnQiXSwKICAgICAgICBbImxvaXNpcnMiLCAiTG9pc2lycyJdLAogICAgICAgIFsic2FudMOpIiwgIlNhbnTDqSJdLAogICAgICAgIFsiYXV0cmUiLCAiQXV0cmUiXSwKICAgICAgXSwKICAgICAgaW5jb21lOiBbCiAgICAgICAgWyJzYWxhaXJlIiwgIlNhbGFpcmUiXSwKICAgICAgICBbImZyZWVsYW5jZSIsICJGcmVlbGFuY2UiXSwKICAgICAgICBbInJlbWJvdXJzZW1lbnQiLCAiUmVtYm91cnNlbWVudCJdLAogICAgICAgIFsiY2FkZWF1IiwgIkNhZGVhdSJdLAogICAgICAgIFsiYXV0cmUiLCAiQXV0cmUiXSwKICAgICAgXSwKICAgIH07CgogICAgY29uc3QgYWxsQ2F0ZWdvcnlMYWJlbHMgPSBPYmplY3QuZnJvbUVudHJpZXMoCiAgICAgIFsuLi5jYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UsIC4uLmNhdGVnb3JpZXNCeVR5cGUuaW5jb21lXQogICAgKTsKCiAgICBjb25zdCBjdXJyZW5jeUZvcm1hdHRlciA9IG5ldyBJbnRsLk51bWJlckZvcm1hdCgiZnItRlIiLCB7IHN0eWxlOiAiY3VycmVuY3kiLCBjdXJyZW5jeTogIkVVUiIgfSk7CiAgICBjb25zdCBkYXRlRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBkYXk6ICJudW1lcmljIiwgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKCiAgICBmdW5jdGlvbiBzaG93VG9hc3QobWVzc2FnZSwgaXNFcnJvciA9IGZhbHNlKSB7CiAgICAgIGNvbnN0IHRvYXN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIHRvYXN0LmNsYXNzTmFtZSA9ICJ0b2FzdCIgKyAoaXNFcnJvciA/ICIgZXJyb3IiIDogIiIpOwogICAgICB0b2FzdC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQodG9hc3QpOwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRvYXN0LnJlbW92ZSgpLCAzMDAwKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcGlGZXRjaChwYXRoLCBvcHRpb25zID0ge30pIHsKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gocGF0aCwgewogICAgICAgIC4uLm9wdGlvbnMsCiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgIlgtQVBJLUtleSI6IEFQSV9LRVksCiAgICAgICAgICAuLi4ob3B0aW9ucy5ib2R5ID8geyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0gOiB7fSksCiAgICAgICAgICAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KSwKICAgICAgICB9LAogICAgICB9KTsKICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICBsZXQgZGV0YWlsID0gcmVzLnN0YXR1c1RleHQ7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgZGV0YWlsID0gZGF0YS5kZXRhaWwgfHwgZGV0YWlsOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFR5cGUodHlwZSkgewogICAgICBjdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHR5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgY2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgdHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFR5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuTW9kYWwodHggPSBudWxsKSB7CiAgICAgIC8vIE9uIGRpc3Rpbmd1ZSAibW9kaWZpZXIiICh0eCBhIHVuIGlkLCB2cmFpZSDDqWRpdGlvbiBlbiBiYXNlKSBkZQogICAgICAvLyAicHLDqS1yZW1wbGlyIMOgIHBhcnRpciBkJ3VuIG1vZMOobGUiIChkdXBsaWNhdGlvbiA6IHR4IGZvdXJuaSBtYWlzIHNhbnMKICAgICAgLy8gaWQgPT4gb24gY3LDqWUgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIGF1IGxpZXUgZCfDqWNyYXNlciBsJ29yaWdpbmFsZSkuCiAgICAgIGNvbnN0IGlzRWRpdCA9IEJvb2xlYW4odHggJiYgdHguaWQpOwogICAgICBlZGl0aW5nSWQgPSBpc0VkaXQgPyB0eC5pZCA6IG51bGw7CiAgICAgIG1vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJNb2RpZmllciBsYSB0cmFuc2FjdGlvbiIgOiAiTm91dmVsbGUgdHJhbnNhY3Rpb24iOwogICAgICBzYXZlQnRuLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIkVucmVnaXN0cmVyIiA6ICJBam91dGVyIjsKICAgICAgc2V0VHlwZSh0eCA/IHR4LnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICBhbW91bnRJbnB1dC52YWx1ZSA9IHR4ID8gdHguYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgdHggPyB0eC5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICBkZXNjcmlwdGlvbklucHV0LnZhbHVlID0gdHggPyAodHguZGVzY3JpcHRpb24gfHwgIiIpIDogIiI7CiAgICAgIGRhdGVJbnB1dC52YWx1ZSA9IHR4ID8gdHguZXhwZW5zZV9kYXRlIDogdG9kYXlJc28oKTsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBhbW91bnRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSB7CiAgICAgIC8vIE3Dqm1lIG1vbnRhbnQvY2F0w6lnb3JpZS9kZXNjcmlwdGlvbiwgbWFpcyBkYXTDqSBkJ2F1am91cmQnaHVpIGV0IHNhbnMKICAgICAgLy8gaWQgOiBsYSBzYXV2ZWdhcmRlIGNyw6llcmEgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uICh2b2lyIG9wZW5Nb2RhbCkuCiAgICAgIG9wZW5Nb2RhbCh7IC4uLnR4LCBpZDogbnVsbCwgZXhwZW5zZV9kYXRlOiB0b2RheUlzbygpIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWRpdGluZ0lkID0gbnVsbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogY3VycmVudFR5cGUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbklucHV0LnZhbHVlLnRyaW0oKSB8fCBudWxsLAogICAgICAgIGV4cGVuc2VfZGF0ZTogZGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgIH07CgogICAgICBzYXZlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoZWRpdGluZ0lkKSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGN1cnJlbnRUeXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUgYWpvdXTDqSIgOiAiRMOpcGVuc2UgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCFjb25maXJtKCJTdXBwcmltZXIgY2V0dGUgdHJhbnNhY3Rpb24gPyIpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YXV4IGdsb2JhdXggKFNvbGRlL0TDqXBlbnNlcy9SZXZlbnVzKSA6IGNhbGN1bMOpcyBzdXIgVE9VVEVTIGxlcwogICAgLy8gdHJhbnNhY3Rpb25zLCBpbmTDqXBlbmRhbW1lbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlIOKAlCB1biBmaWx0cmUKICAgIC8vIHNlcnQgw6AgY2hlcmNoZXIgZGFucyBsYSBsaXN0ZSwgcGFzIMOgIHJlY2FsY3VsZXIgbGUgc29sZGUgcsOpZWwuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKSB7CiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgLy8gQ29uc3RydWN0aW9uIGRlIGxhIGxpc3RlIGRlIGNhcnRlcyBhZmZpY2jDqWUgZGFucyBsJ29uZ2xldCBIaXN0b3JpcXVlIOKAlAogICAgLy8gcmXDp29pdCBkw6lqw6AgbGEgbGlzdGUgZmlsdHLDqWUgKHZvaXIgYXBwbHlIaXN0b3J5RmlsdGVycykuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbkxpc3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgaWYgKHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnRleHRDb250ZW50ID0gYWxsVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMAogICAgICAgICAgPyAiUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4iCiAgICAgICAgICA6ICJBdWN1biByw6lzdWx0YXQgcG91ciBjZXMgZmlsdHJlcy4iOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJ0eC1jYXJkICIgKyB0eC50eXBlOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAidHgtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAidHgtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRhdGVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGRhdGVTcGFuLmNsYXNzTmFtZSA9ICJ0eC1kYXRlIjsKICAgICAgICBkYXRlU3Bhbi50ZXh0Q29udGVudCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHR4LmV4cGVuc2VfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZGF0ZVNwYW4pOwoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIE9uZ2xldHMgKEhpc3RvcmlxdWUgLyBUYWJsZWF1IGRlIGJvcmQpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBzd2l0Y2hWaWV3KHZpZXcpIHsKICAgICAgY3VycmVudFZpZXcgPSB2aWV3OwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiaGlzdG9yeSIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1oaXN0b3J5Iikuc3R5bGUuZGlzcGxheSA9IHZpZXcgPT09ICJoaXN0b3J5IiA/ICJibG9jayIgOiAibm9uZSI7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAicmVjdXJyaW5nIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGlmICh2aWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIG1vbnRoS2V5T2YoZXhwZW5zZURhdGUpIHsKICAgICAgcmV0dXJuIGV4cGVuc2VEYXRlLnNsaWNlKDAsIDcpOyAvLyAiWVlZWS1NTSIKICAgIH0KCiAgICAvLyBVbmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNvbXB0ZSBwb3VyIHVuIG1vaXMgZG9ubsOpIHNpIGVsbGUgbidhIHBhcyBkZSBkYXRlCiAgICAvLyBkZSBmaW4sIG91IHNpIGNlIG1vaXMgZXN0IGVuY29yZSBhdmFudCAob3Ugw6lnYWwgw6ApIGxlIG1vaXMgZGUgc2EgZGF0ZQogICAgLy8gZGUgZmluLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpIHsKICAgICAgaWYgKCFpdGVtLmVuZF9kYXRlKSByZXR1cm4gdHJ1ZTsKICAgICAgcmV0dXJuIG1vbnRoS2V5IDw9IGl0ZW0uZW5kX2RhdGUuc2xpY2UoMCwgNyk7CiAgICB9CgogICAgLy8gSm91ciBkdSBtb2lzIGp1c3F1J2F1cXVlbCB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGVzdCBjb25zaWTDqXLDqWUgY29tbWUKICAgIC8vICJkw6lqw6AgcHLDqWxldsOpZSIgcG91ciBsZSBtb2lzIGBtb250aEtleWAgOiB0b3VzIGxlcyBqb3VycyBwb3VyIHVuIG1vaXMKICAgIC8vIGTDqWrDoCBwYXNzw6ksIGF1Y3VuIHBvdXIgdW4gbW9pcyBmdXR1ciwgZXQgbGUgam91ciBkdSBqb3VyIHBvdXIgbGUgbW9pcwogICAgLy8gZW4gY291cnMuIFBlcm1ldCBkZSBkaXN0aW5ndWVyIGNlIHF1aSBlc3QgZMOpasOgIGFycml2w6kgZGUgY2UgcXVpIGVzdAogICAgLy8gc2V1bGVtZW50IHByw6l2dSAoZXggOiB1biBhYm9ubmVtZW50IHByw6lsZXbDqSBsZSAyNSwgb24gZXN0IGxlIDIpLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KSB7CiAgICAgIGlmIChtb250aEtleSA8IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDMxOwogICAgICBpZiAobW9udGhLZXkgPiBjdXJyZW50TW9udGhLZXkpIHJldHVybiAwOwogICAgICByZXR1cm4gdG9kYXlEYXk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhTZXQgPSBuZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwKSBtb250aFNldC5hZGQobW9udGhLZXlPZih0b2RheUlzbygpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSAiIjsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSAiQXVjdW5lIGRvbm7DqWUiOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCBrZXkgb2YgbW9udGhzKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBzZWxlY3QudmFsdWUgPSBtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkgPyBwcmV2aW91c1ZhbHVlIDogbW9udGhzWzBdOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5Iik7CiAgICAgIGNvbnN0IHVwY29taW5nTm90ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy1ub3RlIik7CiAgICAgIGNvbnN0IHVwY29taW5nVGV4dEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy10ZXh0Iik7CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGNvbnN0IGN1dG9mZiA9IHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSk7CgogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGxldCB1cGNvbWluZ1RvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gY3V0b2ZmKSB7CiAgICAgICAgICB0b3RhbHNbaXRlbS5jYXRlZ29yeV0gPSAodG90YWxzW2l0ZW0uY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgdXBjb21pbmdUb3RhbCArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBpZiAodXBjb21pbmdUb3RhbCA+IDApIHsKICAgICAgICB1cGNvbWluZ1RleHRFbC50ZXh0Q29udGVudCA9IGArICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nVG90YWwpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMgY2UgbW9pcy1jaSwgbm9uIGNvbXB0w6llcyBkYW5zIGxlIGdyYXBoaXF1ZSI7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIGlmIChjYXRlZ29yeUNoYXJ0KSB7IGNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjYXRlZ29yeUNoYXJ0ID0gbmV3IENoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwLCB1cGNvbWluZzogMCB9OwogICAgICAgIG1vbnRobHlba2V5XVt0eC50eXBlXSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBUb3Vqb3VycyBpbmNsdXJlIGxlIG1vaXMgZW4gY291cnMgKG3Dqm1lIHNhbnMgdHJhbnNhY3Rpb24pIHMnaWwgZXhpc3RlCiAgICAgIC8vIGRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgcG91ciBxdSdlbGxlcyBhcHBhcmFpc3NlbnQgc2FucyByZWRpY3TDqWUuCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCwgdXBjb21pbmc6IDAgfTsKICAgICAgfQogICAgICBsZXQgaGFzVXBjb21pbmcgPSBmYWxzZTsKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKG1vbnRobHkpKSB7CiAgICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIGtleSkpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KGtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSk7CiAgICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gY3V0b2ZmKSB7CiAgICAgICAgICAgIG1vbnRobHlba2V5XS5leHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBtb250aGx5W2tleV0udXBjb21pbmcgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICAgICAgaGFzVXBjb21pbmcgPSB0cnVlOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBtb250aHMgPSBPYmplY3Qua2V5cyhtb250aGx5KS5zb3J0KCk7CgogICAgICBpZiAoZXZvbHV0aW9uQ2hhcnQpIHsgZXZvbHV0aW9uQ2hhcnQuZGVzdHJveSgpOyBldm9sdXRpb25DaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBjb25zdCBsYWJlbHMgPSBtb250aHMubWFwKChrZXkpID0+IHsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICByZXR1cm4gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgfSk7CgogICAgICBjb25zdCBkYXRhc2V0cyA9IFsKICAgICAgICB7IGxhYmVsOiAiRMOpcGVuc2VzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5leHBlbnNlKSwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIsIHN0YWNrOiAiZXhwZW5zZXMiIH0sCiAgICAgIF07CiAgICAgIGlmIChoYXNVcGNvbWluZykgewogICAgICAgIGRhdGFzZXRzLnB1c2goewogICAgICAgICAgbGFiZWw6ICJSw6ljdXJyZW50ZXMgw6AgdmVuaXIiLAogICAgICAgICAgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS51cGNvbWluZyksCiAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6ICJyZ2JhKDIzOSwgNjgsIDY4LCAwLjI1KSIsCiAgICAgICAgICBib3JkZXJDb2xvcjogIiNlZjQ0NDQiLAogICAgICAgICAgYm9yZGVyV2lkdGg6IDEuNSwKICAgICAgICAgIGJvcmRlckRhc2g6IFs1LCA0XSwKICAgICAgICAgIHN0YWNrOiAiZXhwZW5zZXMiLAogICAgICAgIH0pOwogICAgICB9CiAgICAgIGRhdGFzZXRzLnB1c2goeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmluY29tZSksIGJhY2tncm91bmRDb2xvcjogIiMyMmM1NWUiLCBzdGFjazogInJldmVudXMiIH0pOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgc3RhY2tlZDogdHJ1ZSwgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHN0YWNrZWQ6IHRydWUsIHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gIiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgIH0pOwogICAgICAgICAgYXdhaXQgYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMTUwMCk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCkgewogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY0VuZERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZW5kLWRhdGUiKTsKICAgIGNvbnN0IHJlY1NhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1zYXZlIik7CgogICAgbGV0IGFsbFJlY3VycmluZyA9IFtdOwogICAgbGV0IGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CgogICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UpIHsKICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgfQoKICAgIGZ1bmN0aW9uIG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtID0gbnVsbCkgewogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBpdGVtID8gaXRlbS5pZCA6IG51bGw7CiAgICAgIHJlY01vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGl0ZW0gPyAiTW9kaWZpZXIgbGEgZMOpcGVuc2UgcsOpY3VycmVudGUiIDogIk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHJlY0NhdGVnb3J5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5jYXRlZ29yeSA6ICJhdXRyZSI7CiAgICAgIHJlY0RheUlucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uZGF5X29mX21vbnRoIDogIiI7CiAgICAgIHJlY0VuZERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5lbmRfZGF0ZSA/IGl0ZW0uZW5kX2RhdGUgOiAiIjsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZWNOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY3VycmluZ01vZGFsKCkgewogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY3VycmluZ01vZGFsKTsKICAgIHJlY092ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gcmVjT3ZlcmxheUVsKSBjbG9zZVJlY3VycmluZ01vZGFsKCk7IH0pOwoKICAgIHJlY1NhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG5hbWUgPSByZWNOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KHJlY0Ftb3VudElucHV0LnZhbHVlKTsKICAgICAgY29uc3QgZGF5ID0gcGFyc2VJbnQocmVjRGF5SW5wdXQudmFsdWUsIDEwKTsKCiAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkxlIG5vbSBlc3Qgb2JsaWdhdG9pcmUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7IHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFkYXkgfHwgZGF5IDwgMSB8fCBkYXkgPiAzMSkgeyBzaG93VG9hc3QoIkpvdXIgZHUgbW9pcyBpbnZhbGlkZSAoMSDDoCAzMSkiLCB0cnVlKTsgcmV0dXJuOyB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIG5hbWUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiByZWNDYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRheV9vZl9tb250aDogZGF5LAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJEw6lwZW5zZSByw6ljdXJyZW50ZSBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIGFqb3V0w6llIik7CiAgICAgICAgfQogICAgICAgIGNsb3NlUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICByZWNTYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVJlY3VycmluZyhpZCkgewogICAgICBpZiAoIWNvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSByw6ljdXJyZW50ZSA/IikpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS9yZWN1cnJpbmcvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJEw6lwZW5zZSByw6ljdXJyZW50ZSBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJSZWN1cnJpbmcoaXRlbXMpIHsKICAgICAgcmVjTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICByZWNFbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9IGl0ZW1zLmxlbmd0aCA9PT0gMCA/ICJibG9jayIgOiAibm9uZSI7CgogICAgICBjb25zdCB0b2RheUtleSA9IHRvZGF5SXNvKCk7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgaXRlbXMpIHsKICAgICAgICBjb25zdCBlbmRlZCA9IGl0ZW0uZW5kX2RhdGUgJiYgaXRlbS5lbmRfZGF0ZSA8IHRvZGF5S2V5OwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAicmVjLWNhcmQiICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5lbmRfZGF0ZSkgewogICAgICAgICAgY29uc3QgZW5kQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBlbmRCYWRnZS5jbGFzc05hbWUgPSAiZW5kLWJhZGdlIjsKICAgICAgICAgIGNvbnN0IGVuZExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5lbmRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBlbmRCYWRnZS50ZXh0Q29udGVudCA9IGVuZGVkID8gYFRlcm1pbsOpIGxlICR7ZW5kTGFiZWx9YCA6IGBKdXNxdSdhdSAke2VuZExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZW5kQmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG5hbWUuY2xhc3NOYW1lID0gInJlYy1uYW1lIjsKICAgICAgICBuYW1lLnRleHRDb250ZW50ID0gaXRlbS5uYW1lOwoKICAgICAgICBjb25zdCBzdWIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBzdWIuY2xhc3NOYW1lID0gInJlYy1zdWIiOwogICAgICAgIHN1Yi50ZXh0Q29udGVudCA9IGBMZSAke2l0ZW0uZGF5X29mX21vbnRofSBkZSBjaGFxdWUgbW9pc2A7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKG5hbWUpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoc3ViKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAicmVjLWFtb3VudCI7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAi4oiSICIgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY3VycmluZ01vZGFsKGl0ZW0pKTsKICAgICAgICBjb25zdCBkZWxldGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkZWxldGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIGRhbmdlciI7CiAgICAgICAgZGVsZXRlQnRuLnRleHRDb250ZW50ID0gIvCfl5HvuI8iOwogICAgICAgIGRlbGV0ZUJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiU3VwcHJpbWVyIik7CiAgICAgICAgZGVsZXRlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gZGVsZXRlUmVjdXJyaW5nKGl0ZW0uaWQpKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGVkaXRCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIHJlY0xpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRSZWN1cnJpbmcoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciKTsKICAgICAgICBhbGxSZWN1cnJpbmcgPSBpdGVtczsKICAgICAgICByZW5kZXJSZWN1cnJpbmcoaXRlbXMpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEV4cG9ydCBFeGNlbAogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1leHBvcnQteGxzeCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC14bHN4Iik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkfDqW7DqXJhdGlvbiBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvZXhwb3J0L3hsc3giLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBgZGVwZW5zZXNfJHt0b2RheUlzbygpfS54bHN4YDsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIHBvcHVsYXRlQ2F0ZWdvcmllcygiZXhwZW5zZSIpOwogICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgIGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgIGxvYWRSZWN1cnJpbmcoKTsKICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg=="
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
# Pas de transaction créée chaque mois : le frontend reçoit la liste brute
# (nom, montant, catégorie, jour du mois, date de fin optionnelle) et c'est
# lui qui les intègre au tableau de bord mois par mois. `end_date` (optionnelle)
# permet d'arrêter automatiquement la prise en compte après une certaine date,
# sans avoir à revenir supprimer/désactiver la ligne à la main.
@app.get("/api/recurring")
def list_recurring(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    result = client.table("recurring_expenses").select("*").order("day_of_month").execute()
    return result.data


@app.post("/api/recurring", status_code=201)
def create_recurring(item: RecurringExpenseIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    payload = {
        "name": item.name.strip(),
        "amount": item.amount,
        "category": (item.category or "autre").strip() or "autre",
        "day_of_month": item.day_of_month,
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
# Export Excel
# ---------------------------------------------------------------------------
@app.get("/api/export/xlsx")
def export_xlsx(_: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
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
    from openpyxl.styles import Font

    type_labels = {"expense": "Dépense", "income": "Revenu"}

    wb = Workbook()
    ws_tx = wb.active
    ws_tx.title = "Transactions"
    ws_tx.append(["Date", "Type", "Catégorie", "Montant (€)", "Description"])
    for cell in ws_tx[1]:
        cell.font = Font(bold=True)
    for tx in transactions:
        ws_tx.append([
            tx["expense_date"],
            type_labels.get(tx["type"], tx["type"]),
            category_label(tx["category"], tx["type"]),
            float(tx["amount"]),
            tx.get("description") or "",
        ])
    for col_letter, width in zip("ABCDE", [12, 10, 14, 12, 42]):
        ws_tx.column_dimensions[col_letter].width = width

    ws_rec = wb.create_sheet("Dépenses récurrentes")
    ws_rec.append(["Nom", "Montant (€)", "Catégorie", "Jour du mois", "Date de fin"])
    for cell in ws_rec[1]:
        cell.font = Font(bold=True)
    for item in recurring:
        ws_rec.append([
            item["name"],
            float(item["amount"]),
            category_label(item["category"], "expense"),
            item["day_of_month"],
            item.get("end_date") or "",
        ])
    for col_letter, width in zip("ABCDE", [24, 12, 14, 12, 14]):
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
