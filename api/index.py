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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXN1Y2Nlc3M6ICMyMmM1NWU7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnN1bW1hcnktY2FyZCB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMDBweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4ycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW46IDA7IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZS5wb3NpdGl2ZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLm5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgbWFpbiB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgfQoKICAudHgtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC50eC1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLnR4LWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50eC1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnR4LXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyB9CiAgLmNhdGVnb3J5LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWRhdGUgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZmFiIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiAxLjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogICAgY29sb3I6IHdoaXRlOwogICAgZm9udC1zaXplOiAxLjhyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSg1OSwgMTMwLCAyNDYsIDAuNCk7CiAgfQogIC5mYWI6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQoKICAuZmFiLW1pYyB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogNS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDAsIDAsIDAsIDAuMyk7CiAgICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAuMnMsIGJvcmRlci1jb2xvciAwLjJzOwogIH0KICAuZmFiLW1pYzphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CiAgLmZhYi1taWMubGlzdGVuaW5nIHsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7CiAgICBhbmltYXRpb246IHB1bHNlIDEuMnMgaW5maW5pdGU7CiAgfQogIC5mYWItbWljLnByb2Nlc3NpbmcgeyBvcGFjaXR5OiAwLjY7IGN1cnNvcjogZGVmYXVsdDsgfQogIC5mYWItbWljOmRpc2FibGVkIHsgb3BhY2l0eTogMC4zNTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQogIEBrZXlmcmFtZXMgcHVsc2UgewogICAgMCUsIDEwMCUgeyBib3gtc2hhZG93OiAwIDAgMCAwIHJnYmEoMjM5LCA2OCwgNjgsIDAuNCk7IH0KICAgIDUwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDEwcHggcmdiYSgyMzksIDY4LCA2OCwgMCk7IH0KICB9CgogIC52b2ljZS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTU7CiAgfQogIC52b2ljZS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQoKICAubW9kYWwtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC41NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGZsZXgtZW5kOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDsKICB9CiAgLm1vZGFsLW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5tb2RhbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlci1yYWRpdXM6IDE4cHggMThweCAwIDA7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSBjYWxjKDEuNXJlbSArIGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKSk7CiAgICB3aWR0aDogMTAwJTsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC45cmVtOwogIH0KICAubW9kYWwgaDIgeyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXNpemU6IDEuMXJlbTsgfQoKICBsYWJlbCB7IGZvbnQtc2l6ZTogMC44cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4zcmVtOyB9CiAgaW5wdXQsIHNlbGVjdCB7CiAgICB3aWR0aDogMTAwJTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNjVyZW0gMC43NXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgaW5wdXQ6Zm9jdXMsIHNlbGVjdDpmb2N1cyB7IG91dGxpbmU6IG5vbmU7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgfQoKICAudHlwZS10b2dnbGUgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgfQogIC50eXBlLWJ0biB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC42NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iZXhwZW5zZSJdIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHlwZS1idG4uYWN0aXZlW2RhdGEtdHlwZT0iaW5jb21lIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDM0LCAxOTcsIDk0LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIGJ1dHRvbi5wcmltYXJ5LCBidXR0b24uc2Vjb25kYXJ5IHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjc1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogbm9uZTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CiAgYnV0dG9uLnByaW1hcnk6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KICBidXR0b24uc2Vjb25kYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50b2FzdCB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHotaW5kZXg6IDIwOwogICAgbWF4LXdpZHRoOiA5MHZ3OwogIH0KICAudG9hc3QuZXJyb3IgeyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmNhNWE1OyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGhlYWRlcj4KICAgIDxoMT7wn5KzIFN1aXZpIGRlIGTDqXBlbnNlczwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgZXQgcmV2ZW51cywgYWpvdXTDqXMgb3Ugw6lkaXTDqXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxtYWluPgogICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgPGRpdiBpZD0iZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgPC9kaXY+CiAgPC9tYWluPgoKICA8ZGl2IGNsYXNzPSJ2b2ljZS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtYmFubmVyIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJmYWItbWljIiBpZD0iZmFiLW1pYyIgYXJpYS1sYWJlbD0iRGljdGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUiPvCfjqQ8L2J1dHRvbj4KICA8YnV0dG9uIGNsYXNzPSJmYWIiIGlkPSJmYWItYWRkIiBhcmlhLWxhYmVsPSJBam91dGVyIj4rPC9idXR0b24+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0ibW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0ibW9kYWwtdGl0bGUiPk5vdXZlbGxlIHRyYW5zYWN0aW9uPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0idHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJpbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBEb2l0IGNvcnJlc3BvbmRyZSBleGFjdGVtZW50IMOgIGxhIHZhcmlhYmxlIGQnZW52aXJvbm5lbWVudCBBUElfU0VDUkVUX0tFWSBzdXIgVmVyY2VsLgogICAgY29uc3QgQVBJX0tFWSA9ICIzSVBRc3lFUUZtY0JMbG1UZlRrMUlBeTFDbms5RjBlViI7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBkZXNjcmlwdGlvbklucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRlc2NyaXB0aW9uIik7CiAgICBjb25zdCBkYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGF0ZSIpOwogICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tc2F2ZSIpOwoKICAgIGxldCBlZGl0aW5nSWQgPSBudWxsOyAvLyBudWxsID0gY3LDqWF0aW9uLCBzaW5vbiBpZCBkZSBsYSB0cmFuc2FjdGlvbiDDqWRpdMOpZQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGNvbnN0IGNhdGVnb3JpZXNCeVR5cGUgPSB7CiAgICAgIGV4cGVuc2U6IFsKICAgICAgICBbInJlc3RhdXJhbnQiLCAiUmVzdGF1cmFudCJdLAogICAgICAgIFsiY291cnNlcyIsICJDb3Vyc2VzIl0sCiAgICAgICAgWyJ0cmFuc3BvcnQiLCAiVHJhbnNwb3J0Il0sCiAgICAgICAgWyJsb2dlbWVudCIsICJMb2dlbWVudCJdLAogICAgICAgIFsibG9pc2lycyIsICJMb2lzaXJzIl0sCiAgICAgICAgWyJzYW50w6kiLCAiU2FudMOpIl0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgICBpbmNvbWU6IFsKICAgICAgICBbInNhbGFpcmUiLCAiU2FsYWlyZSJdLAogICAgICAgIFsiZnJlZWxhbmNlIiwgIkZyZWVsYW5jZSJdLAogICAgICAgIFsicmVtYm91cnNlbWVudCIsICJSZW1ib3Vyc2VtZW50Il0sCiAgICAgICAgWyJjYWRlYXUiLCAiQ2FkZWF1Il0sCiAgICAgICAgWyJhdXRyZSIsICJBdXRyZSJdLAogICAgICBdLAogICAgfTsKCiAgICBjb25zdCBhbGxDYXRlZ29yeUxhYmVscyA9IE9iamVjdC5mcm9tRW50cmllcygKICAgICAgWy4uLmNhdGVnb3JpZXNCeVR5cGUuZXhwZW5zZSwgLi4uY2F0ZWdvcmllc0J5VHlwZS5pbmNvbWVdCiAgICApOwoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dDsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgICBkZXRhaWwgPSBkYXRhLmRldGFpbCB8fCBkZXRhaWw7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZGV0YWlsKTsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gMjA0KSByZXR1cm4gbnVsbDsKICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICB9CgogICAgZnVuY3Rpb24gdG9kYXlJc28oKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCB0eiA9IGQuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShkLmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIGNhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0VHlwZSh0eXBlKSB7CiAgICAgIGN1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgdHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBjYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICB0eXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0VHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5Nb2RhbCh0eCA9IG51bGwpIHsKICAgICAgZWRpdGluZ0lkID0gdHggPyB0eC5pZCA6IG51bGw7CiAgICAgIG1vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IHR4ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSB0eCA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFR5cGUodHggPyB0eC50eXBlIDogImV4cGVuc2UiKTsKICAgICAgYW1vdW50SW5wdXQudmFsdWUgPSB0eCA/IHR4LmFtb3VudCA6ICIiOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoY3VycmVudFR5cGUsIHR4ID8gdHguY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgZGVzY3JpcHRpb25JbnB1dC52YWx1ZSA9IHR4ID8gKHR4LmRlc2NyaXB0aW9uIHx8ICIiKSA6ICIiOwogICAgICBkYXRlSW5wdXQudmFsdWUgPSB0eCA/IHR4LmV4cGVuc2VfZGF0ZSA6IHRvZGF5SXNvKCk7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1hZGQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCgpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZU1vZGFsKTsKICAgIG92ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheUVsKSBjbG9zZU1vZGFsKCk7IH0pOwoKICAgIHNhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQoYW1vdW50SW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIG1vZGlmacOpZSIpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgfQogICAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBzYXZlQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRyYW5zYWN0aW9uKGlkKSB7CiAgICAgIGlmICghY29uZmlybSgiU3VwcHJpbWVyIGNldHRlIHRyYW5zYWN0aW9uID8iKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9IHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDAgPyAiYmxvY2siIDogIm5vbmUiOwoKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwoKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInR4LWNhcmQgIiArIHR4LnR5cGU7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJ0eC1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJ0eC10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gInR4LWRhdGUiOwogICAgICAgIGRhdGVTcGFuLnRleHRDb250ZW50ID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUodHguZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CgogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJ0eC1kZXNjcmlwdGlvbiI7CiAgICAgICAgZGVzYy50ZXh0Q29udGVudCA9IHR4LmRlc2NyaXB0aW9uIHx8ICLigJQiOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAidHgtYW1vdW50ICIgKyB0eC50eXBlOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gKHR4LnR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodHguYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCh0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CgogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFRyYW5zYWN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB0cmFuc2FjdGlvbnMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiKTsKICAgICAgICByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEaWN0w6llIHZvY2FsZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbWljQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1taWMiKTsKICAgIGNvbnN0IHZvaWNlQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtYmFubmVyIik7CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIHRyYW5zYWN0aW9uIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZSBzZXNzaW9uIGRlCiAgICAvLyBuYXZpZ2F0aW9uIChyZW1pcyDDoCB6w6lybyBzaSBvbiByZWNoYXJnZSBsYSBwYWdlKS4gU2VydCB1bmlxdWVtZW50IMOgCiAgICAvLyBhcHBsaXF1ZXIgdW5lIGNvcnJlY3Rpb24gKCJlbiBmYWl0IGMnw6l0YWl0IHBsdXTDtHQuLi4iKSBzdXIgbGEgYm9ubmUKICAgIC8vIHRyYW5zYWN0aW9uLiBTYW5zIMOnYSwgb3Ugc2kgbGEgcGhyYXNlIG4nZXN0IHBhcyB1bmUgY29ycmVjdGlvbiwgb24KICAgIC8vIGNyw6llIHRvdWpvdXJzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiDigJQgbWlldXggdmF1dCB1biBkb3VibG9uIHF1J3VuZQogICAgLy8gZMOpcGVuc2UgY29ycm9tcHVlIHBhciBlcnJldXIuCiAgICBsZXQgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IG51bGw7CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VCYW5uZXIodGV4dCkgewogICAgICBpZiAoIXRleHQpIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSAiIjsKICAgICAgfSBlbHNlIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgICB9CiAgICB9CgogICAgY29uc3QgU3BlZWNoUmVjb2duaXRpb25DdG9yID0gd2luZG93LlNwZWVjaFJlY29nbml0aW9uIHx8IHdpbmRvdy53ZWJraXRTcGVlY2hSZWNvZ25pdGlvbjsKCiAgICBpZiAoIVNwZWVjaFJlY29nbml0aW9uQ3RvcikgewogICAgICBtaWNCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBtaWNCdG4udGl0bGUgPSAiRGljdMOpZSB2b2NhbGUgbm9uIGRpc3BvbmlibGUgc3VyIGNlIG5hdmlnYXRldXIgKHV0aWxpc2UgQ2hyb21lIG91IEVkZ2UpIjsKICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHJlY29nbml0aW9uID0gbmV3IFNwZWVjaFJlY29nbml0aW9uQ3RvcigpOwogICAgICByZWNvZ25pdGlvbi5sYW5nID0gImZyLUZSIjsKICAgICAgcmVjb2duaXRpb24uY29udGludW91cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5pbnRlcmltUmVzdWx0cyA9IGZhbHNlOwogICAgICByZWNvZ25pdGlvbi5tYXhBbHRlcm5hdGl2ZXMgPSAxOwoKICAgICAgbGV0IGlzTGlzdGVuaW5nID0gZmFsc2U7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJzdGFydCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IHRydWU7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoImxpc3RlbmluZyIpOwogICAgICAgIHNldFZvaWNlQmFubmVyKCJKZSB0J8OpY291dGXigKYiKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlbmQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZXJyb3IiLCAoZXZlbnQpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgicHJvY2Vzc2luZyIpOwogICAgICAgIGlmIChldmVudC5lcnJvciA9PT0gIm5vLXNwZWVjaCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJSaWVuIGVudGVuZHUsIHLDqWVzc2FpZS4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDIwMDApOwogICAgICAgIH0gZWxzZSBpZiAoZXZlbnQuZXJyb3IgPT09ICJub3QtYWxsb3dlZCIgfHwgZXZlbnQuZXJyb3IgPT09ICJzZXJ2aWNlLW5vdC1hbGxvd2VkIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIk1pY3JvIHJlZnVzw6kg4oCUIGF1dG9yaXNlIGwnYWNjw6hzIGF1IG1pY3JvIGRhbnMgdG9uIG5hdmlnYXRldXIuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCA0MDAwKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIobnVsbCk7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBtaWNybyA6ICIgKyBldmVudC5lcnJvciwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInJlc3VsdCIsIGFzeW5jIChldmVudCkgPT4gewogICAgICAgIGNvbnN0IHRyYW5zY3JpcHQgPSBldmVudC5yZXN1bHRzWzBdWzBdLnRyYW5zY3JpcHQ7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoYCIke3RyYW5zY3JpcHR9ImApOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJwcm9jZXNzaW5nIik7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL3BhcnNlIiwgewogICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB0ZXh0OiB0cmFuc2NyaXB0IH0pLAogICAgICAgICAgfSk7CiAgICAgICAgICBhd2FpdCBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfSBmaW5hbGx5IHsKICAgICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAxNTAwKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgbWljQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGlmIChpc0xpc3RlbmluZykgewogICAgICAgICAgcmVjb2duaXRpb24uc3RvcCgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICB0cnkgewogICAgICAgICAgcmVjb2duaXRpb24uc3RhcnQoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIC8vIHN0YXJ0KCkgamV0dGUgc2kgZMOpasOgIGTDqW1hcnLDqSA7IG9uIGlnbm9yZS4KICAgICAgICB9CiAgICAgIH0pOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBjb25zdCB2ZXJiID0gcGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSIgOiAiRMOpcGVuc2UiOwogICAgICBjb25zdCBhbW91bnRMYWJlbCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChwYXJzZWQuYW1vdW50KTsKCiAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkKSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7bGFzdFZvaWNlVHJhbnNhY3Rpb25JZH1gLCB7CiAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KGBDb3JyaWfDqSA6ICR7dmVyYi50b0xvd2VyQ2FzZSgpfSBkZSAke2Ftb3VudExhYmVsfWApOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBjcmVhdGVkLmlkOwogICAgICAgIHNob3dUb2FzdChgJHt2ZXJifSBham91dMOpJHtwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiIiA6ICJlIn0gOiAke2Ftb3VudExhYmVsfWApOwogICAgICB9CiAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgIH0KCiAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoImV4cGVuc2UiKTsKICAgIGxvYWRUcmFuc2FjdGlvbnMoKTsKICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg=="
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
