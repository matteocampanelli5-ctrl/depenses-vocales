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
import os
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI()

PARIS_TZ = ZoneInfo("Europe/Paris")


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
class ExpenseIn(BaseModel):
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None
    expense_date: date | None = None  # None => aujourd'hui (Europe/Paris)


class ExpenseUpdate(BaseModel):
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    description: str | None = None
    expense_date: date | None = None


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHN0eWxlPgogIDpyb290IHsKICAgIGNvbG9yLXNjaGVtZTogZGFyazsKICAgIC0tYmc6ICMwZjExMTU7CiAgICAtLXN1cmZhY2U6ICMxYTFkMjQ7CiAgICAtLXN1cmZhY2UtMjogIzIyMjYyZjsKICAgIC0tYm9yZGVyOiAjMmEyZTM4OwogICAgLS10ZXh0OiAjZTZlNmU2OwogICAgLS10ZXh0LWRpbTogIzlhYTBhYzsKICAgIC0tYWNjZW50OiAjM2I4MmY2OwogICAgLS1hY2NlbnQtZGltOiAjMWQ0ZWQ4OwogICAgLS1kYW5nZXI6ICNlZjQ0NDQ7CiAgICAtLXJhZGl1czogMTRweDsKICB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgIlNlZ29lIFVJIiwgUm9ib3RvLCBzYW5zLXNlcmlmOwogICAgcGFkZGluZy1ib3R0b206IDZyZW07CiAgfQogIGhlYWRlciB7CiAgICBwYWRkaW5nOiAxLjVyZW0gMS4yNXJlbSAxcmVtOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCAwLjI1cmVtOyBmb250LXdlaWdodDogNjAwOyB9CiAgLnN1YnRpdGxlIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjlyZW07IG1hcmdpbjogMDsgfQoKICAuc3VtbWFyeSB7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG8gMXJlbTsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNzVyZW07CiAgfQogIC5zdW1tYXJ5LWNhcmQgewogICAgZmxleDogMTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjlyZW0gMXJlbTsKICB9CiAgLnN1bW1hcnktY2FyZCAubGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDAuMjVyZW07IH0KICAuc3VtbWFyeS1jYXJkIC52YWx1ZSB7IGZvbnQtc2l6ZTogMS4yNXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAwOyB9CgogIG1haW4gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogIH0KCiAgLmV4cGVuc2UtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC5leHBlbnNlLWNhcmQgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuODVyZW0gMXJlbTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAgZ2FwOiAwLjc1cmVtOwogIH0KICAuZXhwZW5zZS1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLmV4cGVuc2UtdG9wIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuMTVyZW07IH0KICAuY2F0ZWdvcnktYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuZXhwZW5zZS1kYXRlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmV4cGVuc2UtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLmV4cGVuc2UtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CgogIC5leHBlbnNlLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuM3JlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuaWNvbi1idG4gewogICAgd2lkdGg6IDMycHg7CiAgICBoZWlnaHQ6IDMycHg7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQogIC5pY29uLWJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICMyZDMyM2Q7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC5pY29uLWJ0bi5kYW5nZXI6aG92ZXIgeyBiYWNrZ3JvdW5kOiAjM2ExZDFkOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAuZW1wdHktc3RhdGUgewogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIHBhZGRpbmc6IDNyZW0gMXJlbTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICB9CgogIC5mYWIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDEuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7CiAgICBjb2xvcjogd2hpdGU7CiAgICBmb250LXNpemU6IDEuOHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDU5LCAxMzAsIDI0NiwgMC40KTsKICB9CiAgLmZhYjphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CgogIC5tb2RhbC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogZmxleC1lbmQ7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwOwogIH0KICAubW9kYWwtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLm1vZGFsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyLXJhZGl1czogMThweCAxOHB4IDAgMDsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIGNhbGMoMS41cmVtICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsKICAgIHdpZHRoOiAxMDAlOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjlyZW07CiAgfQogIC5tb2RhbCBoMiB7IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtc2l6ZTogMS4xcmVtOyB9CgogIGxhYmVsIHsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjNyZW07IH0KICBpbnB1dCwgc2VsZWN0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42NXJlbSAwLjc1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CgogIC5tb2RhbC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIGJ1dHRvbi5wcmltYXJ5LCBidXR0b24uc2Vjb25kYXJ5IHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjc1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogbm9uZTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIGJ1dHRvbi5wcmltYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CiAgYnV0dG9uLnByaW1hcnk6ZGlzYWJsZWQgeyBvcGFjaXR5OiAwLjY7IH0KICBidXR0b24uc2Vjb25kYXJ5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50b2FzdCB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHotaW5kZXg6IDIwOwogICAgbWF4LXdpZHRoOiA5MHZ3OwogIH0KICAudG9hc3QuZXJyb3IgeyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmNhNWE1OyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGhlYWRlcj4KICAgIDxoMT7wn5KzIFN1aXZpIGRlIGTDqXBlbnNlczwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgcG9uY3R1ZWxsZXMsIGFqb3V0w6llcyBvdSDDqWRpdMOpZXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlRvdGFsPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LXRvdGFsIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWNvdW50Ij7igJQ8L3A+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPG1haW4+CiAgICA8ZGl2IGlkPSJleHBlbnNlLWxpc3QiIGNsYXNzPSJleHBlbnNlLWxpc3QiPjwvZGl2PgogICAgPGRpdiBpZD0iZW1wdHktc3RhdGUiIGNsYXNzPSJlbXB0eS1zdGF0ZSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICBBdWN1bmUgZMOpcGVuc2UgcG91ciBsJ2luc3RhbnQg4oCUIGFwcHVpZSBzdXIgbGUgYm91dG9uICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgIDwvZGl2PgogIDwvbWFpbj4KCiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciB1bmUgZMOpcGVuc2UiPis8L2J1dHRvbj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJtb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJtb2RhbC10aXRsZSI+Tm91dmVsbGUgZMOpcGVuc2U8L2gyPgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJpbnB1dC1jYXRlZ29yeSI+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJyZXN0YXVyYW50Ij5SZXN0YXVyYW50PC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJjb3Vyc2VzIj5Db3Vyc2VzPC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ0cmFuc3BvcnQiPlRyYW5zcG9ydDwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ibG9nZW1lbnQiPkxvZ2VtZW50PC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJsb2lzaXJzIj5Mb2lzaXJzPC9vcHRpb24+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJzYW50w6kiPlNhbnTDqTwvb3B0aW9uPgogICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYXV0cmUiIHNlbGVjdGVkPkF1dHJlPC9vcHRpb24+CiAgICAgICAgPC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBEb2l0IGNvcnJlc3BvbmRyZSBleGFjdGVtZW50IMOgIGxhIHZhcmlhYmxlIGQnZW52aXJvbm5lbWVudCBBUElfU0VDUkVUX0tFWSBzdXIgVmVyY2VsLgogICAgY29uc3QgQVBJX0tFWSA9ICIzSVBRc3lFUUZtY0JMbG1UZlRrMUlBeTFDbms5RjBlViI7CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cGVuc2UtbGlzdCIpOwogICAgY29uc3QgZW1wdHlTdGF0ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImVtcHR5LXN0YXRlIik7CiAgICBjb25zdCBzdW1tYXJ5VG90YWxFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXRvdGFsIik7CiAgICBjb25zdCBzdW1tYXJ5Q291bnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWNvdW50Iik7CgogICAgY29uc3Qgb3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IG1vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC10aXRsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBkZXNjcmlwdGlvbklucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRlc2NyaXB0aW9uIik7CiAgICBjb25zdCBkYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGF0ZSIpOwogICAgY29uc3Qgc2F2ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tc2F2ZSIpOwoKICAgIGxldCBlZGl0aW5nSWQgPSBudWxsOyAvLyBudWxsID0gY3LDqWF0aW9uLCBzaW5vbiBpZCBkZSBsYSBkw6lwZW5zZSDDqWRpdMOpZQoKICAgIGNvbnN0IGNhdGVnb3J5TGFiZWxzID0gewogICAgICByZXN0YXVyYW50OiAiUmVzdGF1cmFudCIsCiAgICAgIGNvdXJzZXM6ICJDb3Vyc2VzIiwKICAgICAgdHJhbnNwb3J0OiAiVHJhbnNwb3J0IiwKICAgICAgbG9nZW1lbnQ6ICJMb2dlbWVudCIsCiAgICAgIGxvaXNpcnM6ICJMb2lzaXJzIiwKICAgICAgc2FudMOpOiAiU2FudMOpIiwKICAgICAgYXV0cmU6ICJBdXRyZSIsCiAgICB9OwoKICAgIGNvbnN0IGN1cnJlbmN5Rm9ybWF0dGVyID0gbmV3IEludGwuTnVtYmVyRm9ybWF0KCJmci1GUiIsIHsgc3R5bGU6ICJjdXJyZW5jeSIsIGN1cnJlbmN5OiAiRVVSIiB9KTsKICAgIGNvbnN0IGRhdGVGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IGRheTogIm51bWVyaWMiLCBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIGxldCBkZXRhaWwgPSByZXMuc3RhdHVzVGV4dDsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgICBkZXRhaWwgPSBkYXRhLmRldGFpbCB8fCBkZXRhaWw7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZGV0YWlsKTsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gMjA0KSByZXR1cm4gbnVsbDsKICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICB9CgogICAgZnVuY3Rpb24gdG9kYXlJc28oKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCB0eiA9IGQuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShkLmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKGV4cGVuc2UgPSBudWxsKSB7CiAgICAgIGVkaXRpbmdJZCA9IGV4cGVuc2UgPyBleHBlbnNlLmlkIDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gZXhwZW5zZSA/ICJNb2RpZmllciBsYSBkw6lwZW5zZSIgOiAiTm91dmVsbGUgZMOpcGVuc2UiOwogICAgICBzYXZlQnRuLnRleHRDb250ZW50ID0gZXhwZW5zZSA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gZXhwZW5zZSA/IGV4cGVuc2UuYW1vdW50IDogIiI7CiAgICAgIGNhdGVnb3J5SW5wdXQudmFsdWUgPSBleHBlbnNlID8gZXhwZW5zZS5jYXRlZ29yeSA6ICJhdXRyZSI7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSBleHBlbnNlID8gKGV4cGVuc2UuZGVzY3JpcHRpb24gfHwgIiIpIDogIiI7CiAgICAgIGRhdGVJbnB1dC52YWx1ZSA9IGV4cGVuc2UgPyBleHBlbnNlLmV4cGVuc2VfZGF0ZSA6IHRvZGF5SXNvKCk7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1hZGQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCgpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZU1vZGFsKTsKICAgIG92ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gb3ZlcmxheUVsKSBjbG9zZU1vZGFsKCk7IH0pOwoKICAgIHNhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQoYW1vdW50SW5wdXQudmFsdWUpOwogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgewogICAgICAgIHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvZXhwZW5zZXMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiRMOpcGVuc2UgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL2V4cGVuc2VzIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgfQogICAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgICBhd2FpdCBsb2FkRXhwZW5zZXMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlRXhwZW5zZShpZCkgewogICAgICBpZiAoIWNvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSA/IikpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS9leHBlbnNlcy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkRXhwZW5zZXMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyRXhwZW5zZXMoZXhwZW5zZXMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBpZiAoZXhwZW5zZXMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IGV4cCBvZiBleHBlbnNlcykgewogICAgICAgIHRvdGFsICs9IE51bWJlcihleHAuYW1vdW50KTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gImV4cGVuc2UtY2FyZCI7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJleHBlbnNlLW1haW4iOwoKICAgICAgICBjb25zdCB0b3AgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICB0b3AuY2xhc3NOYW1lID0gImV4cGVuc2UtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gY2F0ZWdvcnlMYWJlbHNbZXhwLmNhdGVnb3J5XSB8fCBleHAuY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gImV4cGVuc2UtZGF0ZSI7CiAgICAgICAgZGF0ZVNwYW4udGV4dENvbnRlbnQgPSBkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShleHAuZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CgogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJleHBlbnNlLWRlc2NyaXB0aW9uIjsKICAgICAgICBkZXNjLnRleHRDb250ZW50ID0gZXhwLmRlc2NyaXB0aW9uIHx8ICLigJQiOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAiZXhwZW5zZS1hbW91bnQiOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGV4cC5hbW91bnQpOwoKICAgICAgICBjb25zdCBhY3Rpb25zID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYWN0aW9ucy5jbGFzc05hbWUgPSAiZXhwZW5zZS1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwoZXhwKSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZUV4cGVuc2UoZXhwLmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KCiAgICAgIHN1bW1hcnlUb3RhbEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsKTsKICAgICAgc3VtbWFyeUNvdW50RWwudGV4dENvbnRlbnQgPSBleHBlbnNlcy5sZW5ndGg7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEV4cGVuc2VzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGV4cGVuc2VzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvZXhwZW5zZXMiKTsKICAgICAgICByZW5kZXJFeHBlbnNlcyhleHBlbnNlcyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgbG9hZEV4cGVuc2VzKCk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
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
    corrects et que la table `expenses` est lisible via la clé service_role
    (qui contourne le RLS, activé sans policy pour anon/public)."""
    client = get_supabase_client()
    try:
        result = client.table("expenses").select("id", count="exact").limit(1).execute()
    except Exception as exc:  # noqa: BLE001 - on veut un message clair, pas une 500 opaque
        raise HTTPException(status_code=500, detail=f"Erreur Supabase : {exc}") from exc
    return {"status": "ok", "expenses_table_reachable": True, "row_count": result.count}


# ---------------------------------------------------------------------------
# Dépenses ponctuelles — CRUD
# ---------------------------------------------------------------------------
@app.get("/api/expenses")
def list_expenses(_: None = Depends(require_api_key)) -> list[dict]:
    client = get_supabase_client()
    result = (
        client.table("expenses")
        .select("*")
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


@app.post("/api/expenses", status_code=201)
def create_expense(expense: ExpenseIn, _: None = Depends(require_api_key)) -> dict:
    client = get_supabase_client()
    payload = {
        "amount": expense.amount,
        "category": (expense.category or "autre").strip() or "autre",
        "description": expense.description,
        "expense_date": (expense.expense_date or today_paris()).isoformat(),
    }
    result = client.table("expenses").insert(payload).execute()
    return result.data[0]


@app.put("/api/expenses/{expense_id}")
def update_expense(
    expense_id: str, expense: ExpenseUpdate, _: None = Depends(require_api_key)
) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    data = expense.model_dump(exclude_unset=True)
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, date):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = client.table("expenses").update(payload).eq("id", expense_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense introuvable")
    return result.data[0]


@app.delete("/api/expenses/{expense_id}", status_code=204)
def delete_expense(expense_id: str, _: None = Depends(require_api_key)) -> Response:
    client = get_supabase_client()
    result = client.table("expenses").delete().eq("id", expense_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense introuvable")
    return Response(status_code=204)
