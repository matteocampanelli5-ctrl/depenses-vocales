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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vY2hhcnQuanNANC40LjQvZGlzdC9jaGFydC51bWQubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAudGFicyB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICB9CiAgLnRhYi1idG4gewogICAgZmxleDogMTsKICAgIG1pbi13aWR0aDogMTEwcHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudGFiLWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAud2Vlay1zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IC0wLjRyZW0gYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZm9udC1zaXplOiAwLjgycmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CgogIC5maWx0ZXItYmFyIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LXdyYXA6IHdyYXA7CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLmZpbHRlci1iYXIgaW5wdXQsCiAgLmZpbHRlci1iYXIgc2VsZWN0IHsKICAgIHdpZHRoOiBhdXRvOwogICAgZmxleDogMSAxIDEzMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAjZmlsdGVyLXNlYXJjaCB7IGZsZXg6IDEgMSAxMDAlOyB9CgogIC50eC1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IH0KCiAgLnR4LWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAudHgtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLnR4LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAudHgtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtZGF0ZSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC50eC1kZXNjcmlwdGlvbiB7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBvdmVyZmxvdzogaGlkZGVuOwogICAgdGV4dC1vdmVyZmxvdzogZWxsaXBzaXM7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAudHgtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnR4LWFtb3VudC5pbmNvbWUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAudHgtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnR4LWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5kYXNoYm9hcmQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZGFzaGJvYXJkLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5kYXNoYm9hcmQtcm93IHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAxcmVtIDEuMXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDFyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IGgzIHsKICAgIG1hcmdpbjogMCAwIDAuNzVyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNjAwOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBnYXA6IDAuNXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgfQogIC5kYXNoYm9hcmQtcm93IC5kYXNoYm9hcmQtaGVhZCBoMyB7IG1hcmdpbjogMDsgfQogIC5kYXNoYm9hcmQtcm93IHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIG1pbi13aWR0aDogMTQwcHg7CiAgfQogIC5jaGFydC13cmFwIHsgcG9zaXRpb246IHJlbGF0aXZlOyBoZWlnaHQ6IDI0MHB4OyB9CiAgLmRhc2hib2FyZC1lbXB0eSB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgcGFkZGluZzogMnJlbSAwOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuY2F0ZWdvcnktY2hhcnQtcm93IC5jaGFydC13cmFwIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnVwY29taW5nLW5vdGUgewogICAgd2lkdGg6IDk2cHg7CiAgICBmbGV4LXNocmluazogMDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC40cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuNHJlbTsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjI1OwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICB9CiAgLnVwY29taW5nLW5vdGUuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC51cGNvbWluZy1zd2F0Y2ggewogICAgd2lkdGg6IDI4cHg7CiAgICBoZWlnaHQ6IDE0cHg7CiAgICBib3JkZXI6IDEuNXB4IGRhc2hlZCB2YXIoLS1kYW5nZXIpOwogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1yYWRpdXM6IDRweDsKICB9CiAgLnVwY29taW5nLW5vdGUucG9zaXRpdmUgLnVwY29taW5nLXN3YXRjaCB7CiAgICBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOwogICAgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4yKTsKICB9CgogIC5yZWN1cnJpbmctc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAucmVjdXJyaW5nLXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgLmV4cG9ydC1zZWN0aW9uIHsgZGlzcGxheTogbm9uZTsgfQogIC5leHBvcnQtc2VjdGlvbi52aXNpYmxlIHsgZGlzcGxheTogYmxvY2s7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CiAgLnJlYy1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNnJlbTsKICB9CiAgLnJlYy1jYXJkLmV4cGVuc2UgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWMtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWNhcmQuZW5kZWQgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBvcGFjaXR5OiAwLjY7IH0KICAucmVjLW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAucmVjLXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IH0KICAucmVjLW5hbWUgeyBmb250LXNpemU6IDAuOTVyZW07IG92ZXJmbG93OiBoaWRkZW47IHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1zdWIgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuZW5kLWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOwogICAgY29sb3I6ICNmY2E1YTU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuc3RhcnQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMTUpOwogICAgY29sb3I6ICM5M2M1ZmQ7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAucmVjLWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLmZhYiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogMS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsKICAgIGNvbG9yOiB3aGl0ZTsKICAgIGZvbnQtc2l6ZTogMS44cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjQpOwogIH0KICAuZmFiOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KCiAgLmZhYi1taWMgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDUuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSgwLCAwLCAwLCAwLjMpOwogICAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzLCBib3JkZXItY29sb3IgMC4yczsKICB9CiAgLmZhYi1taWM6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQogIC5mYWItbWljLmxpc3RlbmluZyB7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOwogICAgYW5pbWF0aW9uOiBwdWxzZSAxLjJzIGluZmluaXRlOwogIH0KICAuZmFiLW1pYy5wcm9jZXNzaW5nIHsgb3BhY2l0eTogMC42OyBjdXJzb3I6IGRlZmF1bHQ7IH0KICAuZmFiLW1pYzpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuMzU7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KICBAa2V5ZnJhbWVzIHB1bHNlIHsKICAgIDAlLCAxMDAlIHsgYm94LXNoYWRvdzogMCAwIDAgMCByZ2JhKDIzOSwgNjgsIDY4LCAwLjQpOyB9CiAgICA1MCUgeyBib3gtc2hhZG93OiAwIDAgMCAxMHB4IHJnYmEoMjM5LCA2OCwgNjgsIDApOyB9CiAgfQoKICAudm9pY2UtYmFubmVyIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGJvdHRvbTogOS41cmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTJweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE1OwogIH0KICAudm9pY2UtYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KCiAgLm1vZGFsLW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuNTUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBmbGV4LWVuZDsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTA7CiAgfQogIC5tb2RhbC1vdmVybGF5LmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubW9kYWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXItcmFkaXVzOiAxOHB4IDE4cHggMCAwOwogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gY2FsYygxLjVyZW0gKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpOwogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuOXJlbTsKICB9CiAgLm1vZGFsIGgyIHsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC1zaXplOiAxLjFyZW07IH0KCiAgbGFiZWwgeyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuM3JlbTsgfQogIGlucHV0LCBzZWxlY3QgewogICAgd2lkdGg6IDEwMCU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjY1cmVtIDAuNzVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIGlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IH0KCiAgLnR5cGUtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IH0KICAudHlwZS1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNjVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImV4cGVuc2UiXSB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImluY29tZSJdIHsgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQoKICAubW9kYWwtYWN0aW9ucyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICBidXR0b24ucHJpbWFyeSwgYnV0dG9uLnNlY29uZGFyeSB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC43NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIGJ1dHRvbi5wcmltYXJ5OmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CiAgYnV0dG9uLnNlY29uZGFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAudG9hc3QgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgdG9wOiAxcmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICB6LWluZGV4OiAyMDsKICAgIG1heC13aWR0aDogOTB2dzsKICB9CiAgLnRvYXN0LmVycm9yIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogI2ZjYTVhNTsgfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogIDxoZWFkZXI+CiAgICA8aDE+8J+SsyBTdWl2aSBkZSBkw6lwZW5zZXM8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPsOAIHZlbmlyIGNlIG1vaXMtY2k8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktdXBjb21pbmciPuKAlDwvcD4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8cCBjbGFzcz0id2Vlay1zdW1tYXJ5IiBpZD0id2Vlay1zdW1tYXJ5Ij48L3A+CgogIDxtYWluPgogICAgPHNlY3Rpb24gaWQ9InZpZXctaGlzdG9yeSI+CiAgICAgIDxkaXYgY2xhc3M9ImZpbHRlci1iYXIiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iZmlsdGVyLXNlYXJjaCIgcGxhY2Vob2xkZXI9IlJlY2hlcmNoZXIuLi4iPgogICAgICAgIDxzZWxlY3QgaWQ9ImZpbHRlci1jYXRlZ29yeSI+PG9wdGlvbiB2YWx1ZT0iIj5Ub3V0ZXMgY2F0w6lnb3JpZXM8L29wdGlvbj48L3NlbGVjdD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLXN0YXJ0IiBhcmlhLWxhYmVsPSJEdSI+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmaWx0ZXItZGF0ZS1lbmQiIGFyaWEtbGFiZWw9IkF1Ij4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgaWQ9InR4LWxpc3QiIGNsYXNzPSJ0eC1saXN0Ij48L2Rpdj4KICAgICAgPGRpdiBpZD0iZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgIFJpZW4gcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgbGUgYm91dG9uICsgcG91ciBham91dGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUuCiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWRhc2hib2FyZCIgY2xhc3M9ImRhc2hib2FyZC1zZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLWhlYWQiPgogICAgICAgICAgPGgzPlLDqXBhcnRpdGlvbiBkZXMgZMOpcGVuc2VzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImRhc2hib2FyZC1tb250aC1zZWxlY3QiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNhdGVnb3J5LWNoYXJ0LXJvdyI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtY2F0ZWdvcmllcyI+PC9jYW52YXM+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC11cGNvbWluZy1ub3RlIiBjbGFzcz0idXBjb21pbmctbm90ZSBoaWRkZW4iPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0idXBjb21pbmctc3dhdGNoIj48L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIEF1Y3VuZSBkw6lwZW5zZSBjZSBtb2lzLWzDoC4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+w4l2b2x1dGlvbiBtZW5zdWVsbGUgKGTDqXBlbnNlcyB2cyByZXZlbnVzKTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1ldm9sdXRpb24iPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXJlY3VycmluZyIgY2xhc3M9InJlY3VycmluZy1zZWN0aW9uIj4KICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICBDaGFyZ2VzIGZpeGVzIChhYm9ubmVtZW50cywgbG95ZXIsIHNhbGFpcmXigKYpIGNvbXB0w6llcyBhdXRvbWF0aXF1ZW1lbnQKICAgICAgICBjaGFxdWUgbW9pcyBkYW5zIGxlIHRhYmxlYXUgZGUgYm9yZCDigJQgcGFzIGJlc29pbiBkZSBsZXMgcmVkaWN0ZXIuCiAgICAgICAgTWV0cyB1bmUgZGF0ZSBkZSBkw6lidXQgc2kgdW5lIGNoYXJnZSBuZSBkb2l0IGTDqW1hcnJlciBxdWUgcGx1cyB0YXJkLAogICAgICAgIHVuZSBkYXRlIGRlIGZpbiBzaSBlbGxlIGRvaXQgcydhcnLDqnRlciB1biBqb3VyLgogICAgICA8L3A+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPGRpdiBpZD0icmVjdXJyaW5nLWVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBBdWN1bmUgZMOpcGVuc2UgcsOpY3VycmVudGUgcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgKyBwb3VyIGVuIGFqb3V0ZXIgdW5lLgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1leHBvcnQiIGNsYXNzPSJleHBvcnQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5FeHBvcnRlciB0ZXMgZG9ubsOpZXM8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBUw6lsw6ljaGFyZ2UgdW4gZmljaGllciBFeGNlbCAoLnhsc3gpIGF2ZWMgdG91dGVzIHRlcyB0cmFuc2FjdGlvbnMKICAgICAgICAgIChkw6lwZW5zZXMgZXQgcmV2ZW51cykgZXQgdGVzIGNoYXJnZXMgcsOpY3VycmVudGVzIChkw6lwZW5zZXMgZXQKICAgICAgICAgIHJldmVudXMgcsOpY3VycmVudHMpLCBjaGFjdW5lIGRhbnMgc29uIHByb3ByZSBvbmdsZXQuCiAgICAgICAgPC9wPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tZXhwb3J0LXhsc3giIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlciBsZSBmaWNoaWVyIEV4Y2VsPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiLW1pYyIgaWQ9ImZhYi1taWMiIGFyaWEtbGFiZWw9IkRpY3RlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51Ij7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kZXNjcmlwdGlvbiI+RGVzY3JpcHRpb24gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW5wdXQtZGVzY3JpcHRpb24iIHBsYWNlaG9sZGVyPSJFeCA6IGTDqWpldW5lciBhdmVjIFBhdWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kYXRlIj5EYXRlPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImlucHV0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlYy1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJyZWMtbW9kYWwtdGl0bGUiPk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0icmVjLXR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtbmFtZSI+Tm9tPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InJlYy1pbnB1dC1uYW1lIiBwbGFjZWhvbGRlcj0iRXggOiBOZXRmbGl4LCBMb3llciwgU2FsYWlyZS4uLiI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZGF5Ij5Kb3VyIGR1IG1vaXM8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtZGF5IiBtaW49IjEiIG1heD0iMzEiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSIxIMOgIDMxIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPkRhdGUgZGUgZMOpYnV0IChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1zdGFydC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWVuZC1kYXRlIj5EYXRlIGRlIGZpbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtZW5kLWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0icmVjLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVjLWJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBEb2l0IGNvcnJlc3BvbmRyZSBleGFjdGVtZW50IMOgIGxhIHZhcmlhYmxlIGQnZW52aXJvbm5lbWVudCBBUElfU0VDUkVUX0tFWSBzdXIgVmVyY2VsLgogICAgY29uc3QgQVBJX0tFWSA9ICIzSVBRc3lFUUZtY0JMbG1UZlRrMUlBeTFDbms5RjBlViI7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBkZXNjcmlwdGlvbklucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRlc2NyaXB0aW9uIik7CiAgICBjb25zdCBkYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGF0ZSIpOwogICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tc2F2ZSIpOwoKICAgIGxldCBlZGl0aW5nSWQgPSBudWxsOyAvLyBudWxsID0gY3LDqWF0aW9uLCBzaW5vbiBpZCBkZSBsYSB0cmFuc2FjdGlvbiDDqWRpdMOpZQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dDsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgICBkZXRhaWwgPSBkYXRhLmRldGFpbCB8fCBkZXRhaWw7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZGV0YWlsKTsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gMjA0KSByZXR1cm4gbnVsbDsKICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICB9CgogICAgZnVuY3Rpb24gdG9kYXlJc28oKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCB0eiA9IGQuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShkLmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIGNhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0VHlwZSh0eXBlKSB7CiAgICAgIGN1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgdHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBjYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICB0eXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0VHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5Nb2RhbCh0eCA9IG51bGwpIHsKICAgICAgLy8gT24gZGlzdGluZ3VlICJtb2RpZmllciIgKHR4IGEgdW4gaWQsIHZyYWllIMOpZGl0aW9uIGVuIGJhc2UpIGRlCiAgICAgIC8vICJwcsOpLXJlbXBsaXIgw6AgcGFydGlyIGQndW4gbW9kw6hsZSIgKGR1cGxpY2F0aW9uIDogdHggZm91cm5pIG1haXMgc2FucwogICAgICAvLyBpZCA9PiBvbiBjcsOpZSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gYXUgbGlldSBkJ8OpY3Jhc2VyIGwnb3JpZ2luYWxlKS4KICAgICAgY29uc3QgaXNFZGl0ID0gQm9vbGVhbih0eCAmJiB0eC5pZCk7CiAgICAgIGVkaXRpbmdJZCA9IGlzRWRpdCA/IHR4LmlkIDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIGFtb3VudElucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gZHVwbGljYXRlVHJhbnNhY3Rpb24odHgpIHsKICAgICAgLy8gTcOqbWUgbW9udGFudC9jYXTDqWdvcmllL2Rlc2NyaXB0aW9uLCBtYWlzIGRhdMOpIGQnYXVqb3VyZCdodWkgZXQgc2FucwogICAgICAvLyBpZCA6IGxhIHNhdXZlZ2FyZGUgY3LDqWVyYSB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24gKHZvaXIgb3Blbk1vZGFsKS4KICAgICAgb3Blbk1vZGFsKHsgLi4udHgsIGlkOiBudWxsLCBleHBlbnNlX2RhdGU6IHRvZGF5SXNvKCkgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VNb2RhbCgpIHsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItYWRkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInJlY3VycmluZyIpIG9wZW5SZWN1cnJpbmdNb2RhbCgpOwogICAgICBlbHNlIG9wZW5Nb2RhbCgpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VNb2RhbCk7CiAgICBvdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXlFbCkgY2xvc2VNb2RhbCgpOyB9KTsKCiAgICBzYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KGFtb3VudElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBjdXJyZW50VHlwZSwKICAgICAgICBhbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5SW5wdXQudmFsdWUsCiAgICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uSW5wdXQudmFsdWUudHJpbSgpIHx8IG51bGwsCiAgICAgICAgZXhwZW5zZV9kYXRlOiBkYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoY3VycmVudFR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSBham91dMOpIiA6ICJEw6lwZW5zZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZU1vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVUcmFuc2FjdGlvbihpZCkgewogICAgICBpZiAoIWNvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhdXggZ2xvYmF1eCAoU29sZGUvRMOpcGVuc2VzL1JldmVudXMpIDogY2FsY3Vsw6lzIHN1ciBUT1VURVMgbGVzCiAgICAvLyB0cmFuc2FjdGlvbnMsIGluZMOpcGVuZGFtbWVudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUg4oCUIHVuIGZpbHRyZQogICAgLy8gc2VydCDDoCBjaGVyY2hlciBkYW5zIGxhIGxpc3RlLCBwYXMgw6AgcmVjYWxjdWxlciBsZSBzb2xkZSByw6llbC4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGJhbGFuY2UgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYmFsYW5jZSk7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAoYmFsYW5jZSA+PSAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBzdW1tYXJ5RXhwZW5zZXNFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgc3VtbWFyeUluY29tZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgIH0KCiAgICAvLyBDb25zdHJ1Y3Rpb24gZGUgbGEgbGlzdGUgZGUgY2FydGVzIGFmZmljaMOpZSBkYW5zIGwnb25nbGV0IEhpc3RvcmlxdWUg4oCUCiAgICAvLyByZcOnb2l0IGTDqWrDoCBsYSBsaXN0ZSBmaWx0csOpZSAodm9pciBhcHBseUhpc3RvcnlGaWx0ZXJzKS4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9uTGlzdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBpZiAodHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBlbXB0eVN0YXRlRWwudGV4dENvbnRlbnQgPSBhbGxUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwCiAgICAgICAgICA/ICJSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LiIKICAgICAgICAgIDogIkF1Y3VuIHLDqXN1bHRhdCBwb3VyIGNlcyBmaWx0cmVzLiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInR4LWNhcmQgIiArIHR4LnR5cGU7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJ0eC1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJ0eC10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gInR4LWRhdGUiOwogICAgICAgIGRhdGVTcGFuLnRleHRDb250ZW50ID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUodHguZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CgogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJ0eC1kZXNjcmlwdGlvbiI7CiAgICAgICAgZGVzYy50ZXh0Q29udGVudCA9IHR4LmRlc2NyaXB0aW9uIHx8ICLigJQiOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAidHgtYW1vdW50ICIgKyB0eC50eXBlOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gKHR4LnR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodHguYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCh0eCkpOwogICAgICAgIGNvbnN0IGR1cGxpY2F0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGR1cGxpY2F0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5OLIjsKICAgICAgICBkdXBsaWNhdGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIkR1cGxpcXVlciIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVRyYW5zYWN0aW9uKHR4LmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGR1cGxpY2F0ZUJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUsOpc3Vtw6kgImNldHRlIHNlbWFpbmUiIChpbmTDqXBlbmRhbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3RhcnRPZldlZWtJc28oKSB7CiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IGRheSA9IG5vdy5nZXREYXkoKTsgLy8gMCA9IGRpbWFuY2hlLCAxID0gbHVuZGksIC4uLgogICAgICBjb25zdCBkaWZmVG9Nb25kYXkgPSBkYXkgPT09IDAgPyA2IDogZGF5IC0gMTsKICAgICAgY29uc3QgbW9uZGF5ID0gbmV3IERhdGUobm93KTsKICAgICAgbW9uZGF5LnNldERhdGUobm93LmdldERhdGUoKSAtIGRpZmZUb01vbmRheSk7CiAgICAgIGNvbnN0IHR6ID0gbW9uZGF5LmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUobW9uZGF5LmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHN0YXJ0ID0gc3RhcnRPZldlZWtJc28oKTsKICAgICAgY29uc3QgdG9kYXkgPSB0b2RheUlzbygpOwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiZXhwZW5zZSIgJiYgdHguZXhwZW5zZV9kYXRlID49IHN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8PSB0b2RheSkgewogICAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ3ZWVrLXN1bW1hcnkiKS50ZXh0Q29udGVudCA9CiAgICAgICAgYENldHRlIHNlbWFpbmUgKGRlcHVpcyBsdW5kaSkgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbCl9IGTDqXBlbnPDqXNgOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFJlY2hlcmNoZSBldCBmaWx0cmVzIGRhbnMgbCdoaXN0b3JpcXVlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIE9iamVjdC5lbnRyaWVzKGFsbENhdGVnb3J5TGFiZWxzKSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gYXBwbHlIaXN0b3J5RmlsdGVycygpIHsKICAgICAgY29uc3Qgc2VhcmNoID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1zZWFyY2giKS52YWx1ZS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgY2F0ZWdvcnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVTdGFydCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1zdGFydCIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlRW5kID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLWVuZCIpLnZhbHVlOwoKICAgICAgY29uc3QgZmlsdGVyZWQgPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKCh0eCkgPT4gewogICAgICAgIGlmIChjYXRlZ29yeSAmJiB0eC5jYXRlZ29yeSAhPT0gY2F0ZWdvcnkpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZVN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8IGRhdGVTdGFydCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlRW5kICYmIHR4LmV4cGVuc2VfZGF0ZSA+IGRhdGVFbmQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoc2VhcmNoKSB7CiAgICAgICAgICBjb25zdCBoYXlzdGFjayA9IGAke3R4LmRlc2NyaXB0aW9uIHx8ICIifSAke2FsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeX1gLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgICBpZiAoIWhheXN0YWNrLmluY2x1ZGVzKHNlYXJjaCkpIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHRydWU7CiAgICAgIH0pOwogICAgICByZW5kZXJUcmFuc2FjdGlvbkxpc3QoZmlsdGVyZWQpOwogICAgfQoKICAgIFsiZmlsdGVyLXNlYXJjaCIsICJmaWx0ZXItY2F0ZWdvcnkiLCAiZmlsdGVyLWRhdGUtc3RhcnQiLCAiZmlsdGVyLWRhdGUtZW5kIl0uZm9yRWFjaCgoaWQpID0+IHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgYXBwbHlIaXN0b3J5RmlsdGVycyk7CiAgICB9KTsKCiAgICBsZXQgYWxsVHJhbnNhY3Rpb25zID0gW107CiAgICBsZXQgY3VycmVudFZpZXcgPSAiaGlzdG9yeSI7CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFRyYW5zYWN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB0cmFuc2FjdGlvbnMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiKTsKICAgICAgICBhbGxUcmFuc2FjdGlvbnMgPSB0cmFuc2FjdGlvbnM7CiAgICAgICAgcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKTsKICAgICAgICBhcHBseUhpc3RvcnlGaWx0ZXJzKCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWhpc3RvcnkiKS5zdHlsZS5kaXNwbGF5ID0gdmlldyA9PT0gImhpc3RvcnkiID8gImJsb2NrIiA6ICJub25lIjsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgaWYgKHZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImhpc3RvcnkiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZGFzaGJvYXJkIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoInJlY3VycmluZyIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJleHBvcnQiKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gVGFibGVhdSBkZSBib3JkIChncmFwaGlxdWVzKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbW9udGhGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAibG9uZyIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IG1vbnRoU2hvcnRGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBDSEFSVF9DT0xPUlMgPSBbIiMzYjgyZjYiLCAiIzIyYzU1ZSIsICIjZWY0NDQ0IiwgIiNmNTllMGIiLCAiI2E4NTVmNyIsICIjMTRiOGE2IiwgIiNlYzQ4OTkiLCAiIzY0NzQ4YiJdOwoKICAgIGxldCBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsKICAgIGxldCBldm9sdXRpb25DaGFydCA9IG51bGw7CgogICAgZnVuY3Rpb24gbW9udGhLZXlPZihleHBlbnNlRGF0ZSkgewogICAgICByZXR1cm4gZXhwZW5zZURhdGUuc2xpY2UoMCwgNyk7IC8vICJZWVlZLU1NIgogICAgfQoKICAgIC8vIFVuZSBjaGFyZ2UgcsOpY3VycmVudGUgY29tcHRlIHBvdXIgdW4gbW9pcyBkb25uw6kgc2kgY2UgbW9pcyBlc3QgZGFucyBzYQogICAgLy8gcMOpcmlvZGUgZCdhY3Rpdml0w6kgOiBwYXMgYXZhbnQgc2EgZGF0ZSBkZSBkw6lidXQgKHNpIHBvc8OpZSksIHBhcyBhcHLDqHMKICAgIC8vIGxlIG1vaXMgZGUgc2EgZGF0ZSBkZSBmaW4gKHNpIHBvc8OpZSkuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkgewogICAgICBpZiAoaXRlbS5zdGFydF9kYXRlICYmIG1vbnRoS2V5IDwgaXRlbS5zdGFydF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIGlmIChpdGVtLmVuZF9kYXRlICYmIG1vbnRoS2V5ID4gaXRlbS5lbmRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICAvLyBKb3VyIGR1IG1vaXMganVzcXUnYXVxdWVsIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgZXN0IGNvbnNpZMOpcsOpZSBjb21tZQogICAgLy8gImTDqWrDoCBwcsOpbGV2w6llIiBwb3VyIGxlIG1vaXMgYG1vbnRoS2V5YCA6IHRvdXMgbGVzIGpvdXJzIHBvdXIgdW4gbW9pcwogICAgLy8gZMOpasOgIHBhc3PDqSwgYXVjdW4gcG91ciB1biBtb2lzIGZ1dHVyLCBldCBsZSBqb3VyIGR1IGpvdXIgcG91ciBsZSBtb2lzCiAgICAvLyBlbiBjb3Vycy4gUGVybWV0IGRlIGRpc3Rpbmd1ZXIgY2UgcXVpIGVzdCBkw6lqw6AgYXJyaXbDqSBkZSBjZSBxdWkgZXN0CiAgICAvLyBzZXVsZW1lbnQgcHLDqXZ1IChleCA6IHVuIGFib25uZW1lbnQgcHLDqWxldsOpIGxlIDI1LCBvbiBlc3QgbGUgMikuCiAgICBmdW5jdGlvbiByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpIHsKICAgICAgaWYgKG1vbnRoS2V5IDwgY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMzE7CiAgICAgIGlmIChtb250aEtleSA+IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDA7CiAgICAgIHJldHVybiB0b2RheURheTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aFNldCA9IG5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDApIG1vbnRoU2V0LmFkZChtb250aEtleU9mKHRvZGF5SXNvKCkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9ICIiOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9ICJBdWN1bmUgZG9ubsOpZSI7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIHNlbGVjdC52YWx1ZSA9IG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBtb250aHNbMF07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiKTsKICAgICAgY29uc3QgdXBjb21pbmdOb3RlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiKTsKICAgICAgY29uc3QgdXBjb21pbmdUZXh0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLXVwY29taW5nLXRleHQiKTsKCiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVW4gc2V1bCBzb2xkZSBuZXQgIsOgIHZlbmlyIiAocmV2ZW51cyByw6ljdXJyZW50cyDDoCB2ZW5pciBtb2lucyBkw6lwZW5zZXMKICAgICAgLy8gcsOpY3VycmVudGVzIMOgIHZlbmlyKSwgcGx1dMO0dCBxdWUgZGV1eCBjaGlmZnJlcyBzw6lwYXLDqXMgOiBwbHVzIHNpbXBsZQogICAgICAvLyDDoCBsaXJlIGQndW4gY291cCBkJ8WTaWwuCiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBtb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSBjdXRvZmYpIHsKICAgICAgICAgIGlmIChpdGVtLnR5cGUgPT09ICJleHBlbnNlIikgewogICAgICAgICAgICB0b3RhbHNbaXRlbS5jYXRlZ29yeV0gPSAodG90YWxzW2l0ZW0uY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHsKICAgICAgICAgIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHVwY29taW5nRXhwZW5zZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtZXZvbHV0aW9uIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIpOwoKICAgICAgY29uc3QgbW9udGhseSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGtleSA9IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKTsKICAgICAgICBpZiAoIW1vbnRobHlba2V5XSkgbW9udGhseVtrZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgICBtb250aGx5W2tleV1bdHgudHlwZV0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVG91am91cnMgaW5jbHVyZSBsZSBtb2lzIGVuIGNvdXJzIChtw6ptZSBzYW5zIHRyYW5zYWN0aW9uKSBzJ2lsIGV4aXN0ZQogICAgICAvLyBkZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMsIHBvdXIgcXUnZWxsZXMgYXBwYXJhaXNzZW50IHNhbnMgcmVkaWN0w6llLgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCAmJiAhbW9udGhseVtjdXJyZW50TW9udGhLZXldKSB7CiAgICAgICAgbW9udGhseVtjdXJyZW50TW9udGhLZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgfQogICAgICAvLyBTZXVsZXMgbGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgY29tcHRlbnQgZGFucyBsZXMgYmFycmVzIOKAlAogICAgICAvLyBjZSBxdWkgbidlc3QgcGFzIGVuY29yZSBhcnJpdsOpIGVzdCByw6lzdW3DqSBhaWxsZXVycyAoc29sZGUgbmV0ICLDoAogICAgICAvLyB2ZW5pciIpLCBwYXMgZMOpdGFpbGzDqSBtb2lzIHBhciBtb2lzIGljaS4KICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKG1vbnRobHkpKSB7CiAgICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIGtleSkpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3QgY3V0b2ZmID0gcmVjdXJyaW5nQ3V0b2ZmRGF5KGtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSk7CiAgICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gY3V0b2ZmKSB7CiAgICAgICAgICAgIG1vbnRobHlba2V5XVtpdGVtLnR5cGVdICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucykgewogICAgICBwb3B1bGF0ZU1vbnRoU2VsZWN0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gIiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgIH0pOwogICAgICAgICAgYXdhaXQgYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMTUwMCk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCkgewogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghY29uZmlybSgiU3VwcHJpbWVyIGNldHRlIGTDqXBlbnNlIHLDqWN1cnJlbnRlID8iKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoKGl0ZW0udHlwZSB8fCAiZXhwZW5zZSIpICE9PSAiZXhwZW5zZSIpIGNvbnRpbnVlOwogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgY3VycmVudE1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoID4gdG9kYXlEYXkpIHRvdGFsICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZyIpOwogICAgICBpZiAodG90YWwgPiAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSBg4oiSICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsKX1gOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSBuZWdhdGl2ZSI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFJlY3VycmluZygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIpOwogICAgICAgIGFsbFJlY3VycmluZyA9IGl0ZW1zOwogICAgICAgIHJlbmRlclJlY3VycmluZyhpdGVtcyk7CiAgICAgICAgdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRXhwb3J0IEV4Y2VsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC14bHN4IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LXhsc3giKTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiR8OpbsOpcmF0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9leHBvcnQveGxzeCIsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pOwogICAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoIsOJY2hlYyBkZSBsJ2V4cG9ydCAoIiArIHJlcy5zdGF0dXMgKyAiKSIpOwogICAgICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByZXMuYmxvYigpOwogICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgY29uc3QgbGluayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImEiKTsKICAgICAgICBsaW5rLmhyZWYgPSB1cmw7CiAgICAgICAgbGluay5kb3dubG9hZCA9IGBkZXBlbnNlc18ke3RvZGF5SXNvKCl9Lnhsc3hgOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobGluayk7CiAgICAgICAgbGluay5jbGljaygpOwogICAgICAgIGxpbmsucmVtb3ZlKCk7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogICAgICAgIHNob3dUb2FzdCgiRXhwb3J0IHTDqWzDqWNoYXJnw6kiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IG9yaWdpbmFsVGV4dDsKICAgICAgfQogICAgfSk7CgogICAgcG9wdWxhdGVDYXRlZ29yaWVzKCJleHBlbnNlIik7CiAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgbG9hZFJlY3VycmluZygpOwogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
# (type dépense/revenu, nom, montant, catégorie, jour du mois, dates de
# début/fin optionnelles) et c'est lui qui les intègre au tableau de bord
# mois par mois. `start_date`/`end_date` (optionnelles) bornent la période où
# la charge compte, sans avoir à revenir supprimer/désactiver la ligne à la
# main (ex : un abonnement qui ne démarre qu'en novembre).
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

    ws_rec = wb.create_sheet("Récurrentes")
    ws_rec.append(["Type", "Nom", "Montant (€)", "Catégorie", "Jour du mois", "Date de début", "Date de fin"])
    for cell in ws_rec[1]:
        cell.font = Font(bold=True)
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
