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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vY2hhcnQuanNANC40LjQvZGlzdC9jaGFydC51bWQubWluLmpzIj48L3NjcmlwdD4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAudGFicyB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNXJlbTsKICB9CiAgLnRhYi1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNnJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudGFiLWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAudHgtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC50eC1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLnR4LWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50eC1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnR4LXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyB9CiAgLmNhdGVnb3J5LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWRhdGUgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5mYWItbWljIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiA1LjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS41cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoMCwgMCwgMCwgMC4zKTsKICAgIHRyYW5zaXRpb246IGJhY2tncm91bmQgMC4ycywgYm9yZGVyLWNvbG9yIDAuMnM7CiAgfQogIC5mYWItbWljOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KICAuZmFiLW1pYy5saXN0ZW5pbmcgewogICAgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4yKTsKICAgIGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsKICAgIGFuaW1hdGlvbjogcHVsc2UgMS4ycyBpbmZpbml0ZTsKICB9CiAgLmZhYi1taWMucHJvY2Vzc2luZyB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgLmZhYi1taWM6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjM1OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB9CiAgQGtleWZyYW1lcyBwdWxzZSB7CiAgICAwJSwgMTAwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDAgcmdiYSgyMzksIDY4LCA2OCwgMC40KTsgfQogICAgNTAlIHsgYm94LXNoYWRvdzogMCAwIDAgMTBweCByZ2JhKDIzOSwgNjgsIDY4LCAwKTsgfQogIH0KCiAgLnZvaWNlLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNTsKICB9CiAgLnZvaWNlLWJhbm5lci5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CgogIC5tb2RhbC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogZmxleC1lbmQ7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwOwogIH0KICAubW9kYWwtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLm1vZGFsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyLXJhZGl1czogMThweCAxOHB4IDAgMDsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIGNhbGMoMS41cmVtICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsKICAgIHdpZHRoOiAxMDAlOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjlyZW07CiAgfQogIC5tb2RhbCBoMiB7IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtc2l6ZTogMS4xcmVtOyB9CgogIGxhYmVsIHsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjNyZW07IH0KICBpbnB1dCwgc2VsZWN0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42NXJlbSAwLjc1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CgogIC50eXBlLXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyB9CiAgLnR5cGUtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjY1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJleHBlbnNlIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJpbmNvbWUiXSB7IGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KCiAgLm1vZGFsLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgYnV0dG9uLnByaW1hcnksIGJ1dHRvbi5zZWNvbmRhcnkgewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNzVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiBub25lOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICBidXR0b24ucHJpbWFyeTpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQogIGJ1dHRvbi5zZWNvbmRhcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLnRvYXN0IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHRvcDogMXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgei1pbmRleDogMjA7CiAgICBtYXgtd2lkdGg6IDkwdnc7CiAgfQogIC50b2FzdC5lcnJvciB7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6ICNmY2E1YTU7IH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICA8aGVhZGVyPgogICAgPGgxPvCfkrMgU3VpdmkgZGUgZMOpcGVuc2VzPC9oMT4KICAgIDxwIGNsYXNzPSJzdWJ0aXRsZSI+VGVzIGTDqXBlbnNlcyBldCByZXZlbnVzLCBham91dMOpcyBvdSDDqWRpdMOpcyBtYW51ZWxsZW1lbnQuPC9wPgogIDwvaGVhZGVyPgoKICA8ZGl2IGNsYXNzPSJ0YWJzIj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biBhY3RpdmUiIGlkPSJ0YWItaGlzdG9yeSIgZGF0YS12aWV3PSJoaXN0b3J5Ij5IaXN0b3JpcXVlPC9idXR0b24+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4iIGlkPSJ0YWItZGFzaGJvYXJkIiBkYXRhLXZpZXc9ImRhc2hib2FyZCI+VGFibGVhdSBkZSBib3JkPC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8bWFpbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpc3RvcnkiPgogICAgICA8ZGl2IGlkPSJ0eC1saXN0IiBjbGFzcz0idHgtbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1kYXNoYm9hcmQiIGNsYXNzPSJkYXNoYm9hcmQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIGTDqXBlbnNlcyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1bmUgZMOpcGVuc2UgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPsOJdm9sdXRpb24gbWVuc3VlbGxlIChkw6lwZW5zZXMgdnMgcmV2ZW51cyk8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtZXZvbHV0aW9uIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICA8L21haW4+CgogIDxkaXYgY2xhc3M9InZvaWNlLWJhbm5lciBoaWRkZW4iIGlkPSJ2b2ljZS1iYW5uZXIiPjwvZGl2PgogIDxidXR0b24gY2xhc3M9ImZhYi1taWMiIGlkPSJmYWItbWljIiBhcmlhLWxhYmVsPSJEaWN0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudSI+8J+OpDwvYnV0dG9uPgogIDxidXR0b24gY2xhc3M9ImZhYiIgaWQ9ImZhYi1hZGQiIGFyaWEtbGFiZWw9IkFqb3V0ZXIiPis8L2J1dHRvbj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJtb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJtb2RhbC10aXRsZSI+Tm91dmVsbGUgdHJhbnNhY3Rpb248L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJ0eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9ImlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGVzY3JpcHRpb24iPkRlc2NyaXB0aW9uIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImlucHV0LWRlc2NyaXB0aW9uIiBwbGFjZWhvbGRlcj0iRXggOiBkw6lqZXVuZXIgYXZlYyBQYXVsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGF0ZSI+RGF0ZTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJpbnB1dC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHNjcmlwdD4KICAgIC8vIERvaXQgY29ycmVzcG9uZHJlIGV4YWN0ZW1lbnQgw6AgbGEgdmFyaWFibGUgZCdlbnZpcm9ubmVtZW50IEFQSV9TRUNSRVRfS0VZIHN1ciBWZXJjZWwuCiAgICBjb25zdCBBUElfS0VZID0gIjNJUFFzeUVRRm1jQkxsbVRmVGsxSUF5MUNuazlGMGVWIjsKCiAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHgtbGlzdCIpOwogICAgY29uc3QgZW1wdHlTdGF0ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImVtcHR5LXN0YXRlIik7CiAgICBjb25zdCBzdW1tYXJ5QmFsYW5jZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktYmFsYW5jZSIpOwogICAgY29uc3Qgc3VtbWFyeUV4cGVuc2VzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1leHBlbnNlcyIpOwogICAgY29uc3Qgc3VtbWFyeUluY29tZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktaW5jb21lIik7CgogICAgY29uc3Qgb3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IG1vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC10aXRsZSIpOwogICAgY29uc3QgdHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR5cGUtdG9nZ2xlIik7CiAgICBjb25zdCBhbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1hbW91bnQiKTsKICAgIGNvbnN0IGNhdGVnb3J5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgY29uc3QgY3VycmVuY3lGb3JtYXR0ZXIgPSBuZXcgSW50bC5OdW1iZXJGb3JtYXQoImZyLUZSIiwgeyBzdHlsZTogImN1cnJlbmN5IiwgY3VycmVuY3k6ICJFVVIiIH0pOwogICAgY29uc3QgZGF0ZUZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgZGF5OiAibnVtZXJpYyIsIG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CgogICAgZnVuY3Rpb24gc2hvd1RvYXN0KG1lc3NhZ2UsIGlzRXJyb3IgPSBmYWxzZSkgewogICAgICBjb25zdCB0b2FzdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICB0b2FzdC5jbGFzc05hbWUgPSAidG9hc3QiICsgKGlzRXJyb3IgPyAiIGVycm9yIiA6ICIiKTsKICAgICAgdG9hc3QudGV4dENvbnRlbnQgPSBtZXNzYWdlOwogICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRvYXN0KTsKICAgICAgc2V0VGltZW91dCgoKSA9PiB0b2FzdC5yZW1vdmUoKSwgMzAwMCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBpRmV0Y2gocGF0aCwgb3B0aW9ucyA9IHt9KSB7CiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKHBhdGgsIHsKICAgICAgICAuLi5vcHRpb25zLAogICAgICAgIGhlYWRlcnM6IHsKICAgICAgICAgICJYLUFQSS1LZXkiOiBBUElfS0VZLAogICAgICAgICAgLi4uKG9wdGlvbnMuYm9keSA/IHsgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiB9IDoge30pLAogICAgICAgICAgLi4uKG9wdGlvbnMuaGVhZGVycyB8fCB7fSksCiAgICAgICAgfSwKICAgICAgfSk7CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgbGV0IGRldGFpbCA9IHJlcy5zdGF0dXNUZXh0OwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGRhdGEuZGV0YWlsIHx8IGRldGFpbDsKICAgICAgICB9IGNhdGNoIChfKSB7fQogICAgICAgIHRocm93IG5ldyBFcnJvcihkZXRhaWwpOwogICAgICB9CiAgICAgIGlmIChyZXMuc3RhdHVzID09PSAyMDQpIHJldHVybiBudWxsOwogICAgICByZXR1cm4gcmVzLmpzb24oKTsKICAgIH0KCiAgICBmdW5jdGlvbiB0b2RheUlzbygpIHsKICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IHR6ID0gZC5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKGQuZ2V0VGltZSgpIC0gdHogKiA2MDAwMCk7CiAgICAgIHJldHVybiBsb2NhbC50b0lTT1N0cmluZygpLnNsaWNlKDAsIDEwKTsKICAgIH0KCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgc2VsZWN0ZWRWYWx1ZSA9IG51bGwpIHsKICAgICAgY2F0ZWdvcnlJbnB1dC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgaWYgKHZhbHVlID09PSAoc2VsZWN0ZWRWYWx1ZSB8fCAiYXV0cmUiKSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBjYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICBlZGl0aW5nSWQgPSB0eCA/IHR4LmlkIDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gdHggPyAiTW9kaWZpZXIgbGEgdHJhbnNhY3Rpb24iIDogIk5vdXZlbGxlIHRyYW5zYWN0aW9uIjsKICAgICAgc2F2ZUJ0bi50ZXh0Q29udGVudCA9IHR4ID8gIkVucmVnaXN0cmVyIiA6ICJBam91dGVyIjsKICAgICAgc2V0VHlwZSh0eCA/IHR4LnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICBhbW91bnRJbnB1dC52YWx1ZSA9IHR4ID8gdHguYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgdHggPyB0eC5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICBkZXNjcmlwdGlvbklucHV0LnZhbHVlID0gdHggPyAodHguZGVzY3JpcHRpb24gfHwgIiIpIDogIiI7CiAgICAgIGRhdGVJbnB1dC52YWx1ZSA9IHR4ID8gdHguZXhwZW5zZV9kYXRlIDogdG9kYXlJc28oKTsKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBhbW91bnRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWRpdGluZ0lkID0gbnVsbDsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3Blbk1vZGFsKCkpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogY3VycmVudFR5cGUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbklucHV0LnZhbHVlLnRyaW0oKSB8fCBudWxsLAogICAgICAgIGV4cGVuc2VfZGF0ZTogZGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgIH07CgogICAgICBzYXZlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoZWRpdGluZ0lkKSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGN1cnJlbnRUeXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUgYWpvdXTDqSIgOiAiRMOpcGVuc2UgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCFjb25maXJtKCJTdXBwcmltZXIgY2V0dGUgdHJhbnNhY3Rpb24gPyIpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucykgewogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gdHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCA/ICJibG9jayIgOiAibm9uZSI7CgogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAidHgtY2FyZCAiICsgdHgudHlwZTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInR4LW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gInR4LXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkYXRlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkYXRlU3Bhbi5jbGFzc05hbWUgPSAidHgtZGF0ZSI7CiAgICAgICAgZGF0ZVNwYW4udGV4dENvbnRlbnQgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh0eC5leHBlbnNlX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChiYWRnZSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGRhdGVTcGFuKTsKCiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gInR4LWRlc2NyaXB0aW9uIjsKICAgICAgICBkZXNjLnRleHRDb250ZW50ID0gdHguZGVzY3JpcHRpb24gfHwgIuKAlCI7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwoKICAgICAgICBjb25zdCBhbW91bnRFbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudEVsLmNsYXNzTmFtZSA9ICJ0eC1hbW91bnQgIiArIHR4LnR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHgudHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0eC5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAidHgtYWN0aW9ucyI7CiAgICAgICAgY29uc3QgZWRpdEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGVkaXRCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBlZGl0QnRuLnRleHRDb250ZW50ID0gIuKcj++4jyI7CiAgICAgICAgZWRpdEJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiTW9kaWZpZXIiKTsKICAgICAgICBlZGl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3Blbk1vZGFsKHR4KSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVRyYW5zYWN0aW9uKHR4LmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KCiAgICAgIGNvbnN0IGJhbGFuY2UgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYmFsYW5jZSk7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAoYmFsYW5jZSA+PSAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBzdW1tYXJ5RXhwZW5zZXNFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgc3VtbWFyeUluY29tZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgIH0KCiAgICBsZXQgYWxsVHJhbnNhY3Rpb25zID0gW107CiAgICBsZXQgY3VycmVudFZpZXcgPSAiaGlzdG9yeSI7CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFRyYW5zYWN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB0cmFuc2FjdGlvbnMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiKTsKICAgICAgICBhbGxUcmFuc2FjdGlvbnMgPSB0cmFuc2FjdGlvbnM7CiAgICAgICAgcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1oaXN0b3J5Iikuc3R5bGUuZGlzcGxheSA9IHZpZXcgPT09ICJoaXN0b3J5IiA/ICJibG9jayIgOiAibm9uZSI7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWRhc2hib2FyZCIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGlmICh2aWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBUYWJsZWF1IGRlIGJvcmQgKGdyYXBoaXF1ZXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtb250aEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJsb25nIiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgbW9udGhTaG9ydEZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IENIQVJUX0NPTE9SUyA9IFsiIzNiODJmNiIsICIjMjJjNTVlIiwgIiNlZjQ0NDQiLCAiI2Y1OWUwYiIsICIjYTg1NWY3IiwgIiMxNGI4YTYiLCAiI2VjNDg5OSIsICIjNjQ3NDhiIl07CgogICAgbGV0IGNhdGVnb3J5Q2hhcnQgPSBudWxsOwogICAgbGV0IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpXS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9ICIiOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9ICJBdWN1bmUgZG9ubsOpZSI7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IGtleSBvZiBtb250aHMpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIHNlbGVjdC52YWx1ZSA9IG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBtb250aHNbMF07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNhdGVnb3JpZXMtZW1wdHkiKTsKCiAgICAgIGNvbnN0IHRvdGFscyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlICE9PSAiZXhwZW5zZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtZXZvbHV0aW9uIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIpOwoKICAgICAgY29uc3QgbW9udGhseSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGtleSA9IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKTsKICAgICAgICBpZiAoIW1vbnRobHlba2V5XSkgbW9udGhseVtrZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgICBtb250aGx5W2tleV1bdHgudHlwZV0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbW9udGhzID0gT2JqZWN0LmtleXMobW9udGhseSkuc29ydCgpOwoKICAgICAgaWYgKGV2b2x1dGlvbkNoYXJ0KSB7IGV2b2x1dGlvbkNoYXJ0LmRlc3Ryb3koKTsgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgY29uc3QgbGFiZWxzID0gbW9udGhzLm1hcCgoa2V5KSA9PiB7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgcmV0dXJuIG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgIH0pOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBuZXcgQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFsKICAgICAgICAgICAgeyBsYWJlbDogIkTDqXBlbnNlcyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uZXhwZW5zZSksIGJhY2tncm91bmRDb2xvcjogIiNlZjQ0NDQiIH0sCiAgICAgICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICAgICAgXSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9LCBiZWdpbkF0WmVybzogdHJ1ZSB9LAogICAgICAgICAgfSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiIH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5kYXRhc2V0LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQueSl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpIHsKICAgICAgcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiByZW5kZXJDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucykpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIERpY3TDqWUgdm9jYWxlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBtaWNCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLW1pYyIpOwogICAgY29uc3Qgdm9pY2VCYW5uZXJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2b2ljZS1iYW5uZXIiKTsKCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgdHJhbnNhY3Rpb24gY3LDqcOpZSBQQVIgTEEgVk9JWCBkYW5zIGNldHRlIHNlc3Npb24gZGUKICAgIC8vIG5hdmlnYXRpb24gKHJlbWlzIMOgIHrDqXJvIHNpIG9uIHJlY2hhcmdlIGxhIHBhZ2UpLiBTZXJ0IHVuaXF1ZW1lbnQgw6AKICAgIC8vIGFwcGxpcXVlciB1bmUgY29ycmVjdGlvbiAoImVuIGZhaXQgYyfDqXRhaXQgcGx1dMO0dC4uLiIpIHN1ciBsYSBib25uZQogICAgLy8gdHJhbnNhY3Rpb24uIFNhbnMgw6dhLCBvdSBzaSBsYSBwaHJhc2Ugbidlc3QgcGFzIHVuZSBjb3JyZWN0aW9uLCBvbgogICAgLy8gY3LDqWUgdG91am91cnMgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIOKAlCBtaWV1eCB2YXV0IHVuIGRvdWJsb24gcXUndW5lCiAgICAvLyBkw6lwZW5zZSBjb3Jyb21wdWUgcGFyIGVycmV1ci4KICAgIGxldCBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gbnVsbDsKCiAgICBmdW5jdGlvbiBzZXRWb2ljZUJhbm5lcih0ZXh0KSB7CiAgICAgIGlmICghdGV4dCkgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9ICIiOwogICAgICB9IGVsc2UgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBTcGVlY2hSZWNvZ25pdGlvbkN0b3IgPSB3aW5kb3cuU3BlZWNoUmVjb2duaXRpb24gfHwgd2luZG93LndlYmtpdFNwZWVjaFJlY29nbml0aW9uOwoKICAgIGlmICghU3BlZWNoUmVjb2duaXRpb25DdG9yKSB7CiAgICAgIG1pY0J0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIG1pY0J0bi50aXRsZSA9ICJEaWN0w6llIHZvY2FsZSBub24gZGlzcG9uaWJsZSBzdXIgY2UgbmF2aWdhdGV1ciAodXRpbGlzZSBDaHJvbWUgb3UgRWRnZSkiOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgcmVjb2duaXRpb24gPSBuZXcgU3BlZWNoUmVjb2duaXRpb25DdG9yKCk7CiAgICAgIHJlY29nbml0aW9uLmxhbmcgPSAiZnItRlIiOwogICAgICByZWNvZ25pdGlvbi5jb250aW51b3VzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLmludGVyaW1SZXN1bHRzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLm1heEFsdGVybmF0aXZlcyA9IDE7CgogICAgICBsZXQgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInN0YXJ0IiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gdHJ1ZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgibGlzdGVuaW5nIik7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIkplIHQnw6ljb3V0ZeKApiIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVuZCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlcnJvciIsIChldmVudCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgaWYgKGV2ZW50LmVycm9yID09PSAibm8tc3BlZWNoIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIlJpZW4gZW50ZW5kdSwgcsOpZXNzYWllLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMjAwMCk7CiAgICAgICAgfSBlbHNlIGlmIChldmVudC5lcnJvciA9PT0gIm5vdC1hbGxvd2VkIiB8fCBldmVudC5lcnJvciA9PT0gInNlcnZpY2Utbm90LWFsbG93ZWQiKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiTWljcm8gcmVmdXPDqSDigJQgYXV0b3Jpc2UgbCdhY2PDqHMgYXUgbWljcm8gZGFucyB0b24gbmF2aWdhdGV1ci4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDQwMDApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcihudWxsKTsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIG1pY3JvIDogIiArIGV2ZW50LmVycm9yLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigicmVzdWx0IiwgYXN5bmMgKGV2ZW50KSA9PiB7CiAgICAgICAgY29uc3QgdHJhbnNjcmlwdCA9IGV2ZW50LnJlc3VsdHNbMF1bMF0udHJhbnNjcmlwdDsKICAgICAgICBzZXRWb2ljZUJhbm5lcihgIiR7dHJhbnNjcmlwdH0iYCk7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoInByb2Nlc3NpbmciKTsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgcGFyc2VkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvcGFyc2UiLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRleHQ6IHRyYW5zY3JpcHQgfSksCiAgICAgICAgICB9KTsKICAgICAgICAgIGF3YWl0IGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDE1MDApOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICBtaWNCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgaWYgKGlzTGlzdGVuaW5nKSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdG9wKCk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIHRyeSB7CiAgICAgICAgICByZWNvZ25pdGlvbi5zdGFydCgpOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgLy8gc3RhcnQoKSBqZXR0ZSBzaSBkw6lqw6AgZMOpbWFycsOpIDsgb24gaWdub3JlLgogICAgICAgIH0KICAgICAgfSk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpIHsKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICBkZXNjcmlwdGlvbjogcGFyc2VkLmRlc2NyaXB0aW9uLAogICAgICAgIGV4cGVuc2VfZGF0ZTogcGFyc2VkLmV4cGVuc2VfZGF0ZSwKICAgICAgfTsKCiAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgIGNvbnN0IGFtb3VudExhYmVsID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpOwoKICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQpIHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtsYXN0Vm9pY2VUcmFuc2FjdGlvbklkfWAsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYENvcnJpZ8OpIDogJHt2ZXJiLnRvTG93ZXJDYXNlKCl9IGRlICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgc2hvd1RvYXN0KGAke3ZlcmJ9IGFqb3V0w6kke3BhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICIiIDogImUifSA6ICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0KICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgfQoKICAgIHBvcHVsYXRlQ2F0ZWdvcmllcygiZXhwZW5zZSIpOwogICAgbG9hZFRyYW5zYWN0aW9ucygpOwogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
