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

import os
from datetime import datetime, timezone
import base64

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI()

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
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+U3VpdmkgZGUgZMOpcGVuc2VzPC90aXRsZT4KPHN0eWxlPgogIDpyb290IHsgY29sb3Itc2NoZW1lOiBkYXJrOyB9CiAgKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICBib2R5IHsKICAgIG1hcmdpbjogMDsKICAgIG1pbi1oZWlnaHQ6IDEwMHZoOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICBiYWNrZ3JvdW5kOiAjMGYxMTE1OwogICAgY29sb3I6ICNlNmU2ZTY7CiAgICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIHNhbnMtc2VyaWY7CiAgICBnYXA6IDEuMjVyZW07CiAgICBwYWRkaW5nOiAycmVtOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KICBoMSB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDA7IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICBwIHsgbWFyZ2luOiAwOyBjb2xvcjogIzlhYTBhYzsgbWF4LXdpZHRoOiAzMnJlbTsgfQogIGJ1dHRvbiB7CiAgICBiYWNrZ3JvdW5kOiAjM2I4MmY2OwogICAgY29sb3I6IHdoaXRlOwogICAgYm9yZGVyOiBub25lOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuOHJlbSAxLjZyZW07CiAgICBmb250LXNpemU6IDFyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBmb250LXdlaWdodDogNTAwOwogIH0KICBidXR0b246YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk4KTsgfQogIGJ1dHRvbjpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgY3Vyc29yOiBkZWZhdWx0OyB9CiAgcHJlIHsKICAgIGJhY2tncm91bmQ6ICMxYTFkMjQ7CiAgICBib3JkZXI6IDFweCBzb2xpZCAjMjYyYTMzOwogICAgcGFkZGluZzogMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBtYXgtd2lkdGg6IG1pbig5MHZ3LCAzMnJlbSk7CiAgICB3aWR0aDogMzJyZW07CiAgICBvdmVyZmxvdy14OiBhdXRvOwogICAgdGV4dC1hbGlnbjogbGVmdDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMDsKICB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGgxPvCfp6ogU3VpdmkgZGUgZMOpcGVuc2VzIOKAlCBzcXVlbGV0dGUgZGUgZMOpcGxvaWVtZW50PC9oMT4KICA8cD5TaSB0dSB2b2lzIGNldHRlIHBhZ2UsIFZlcmNlbCBzZXJ0IGJpZW4gbCdhcHBsaWNhdGlvbi4gTGUgYm91dG9uIGNpLWRlc3NvdXMgdGVzdGUgbGEgY29ubmV4aW9uIMOgIFN1cGFiYXNlLjwvcD4KICA8YnV0dG9uIGlkPSJjaGVjay1kYiI+VGVzdGVyIGxhIGNvbm5leGlvbiDDoCBTdXBhYmFzZTwvYnV0dG9uPgogIDxwcmUgaWQ9InJlc3VsdCI+RW4gYXR0ZW50ZeKApjwvcHJlPgoKICA8c2NyaXB0PgogICAgLy8gRG9pdCBjb3JyZXNwb25kcmUgZXhhY3RlbWVudCDDoCBsYSB2YXJpYWJsZSBkJ2Vudmlyb25uZW1lbnQgQVBJX1NFQ1JFVF9LRVkgc3VyIFZlcmNlbC4KICAgIGNvbnN0IEFQSV9LRVkgPSAiM0lQUXN5RVFGbWNCTGxtVGZUazFJQXkxQ25rOUYwZVYiOwoKICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGVjay1kYiIpOwogICAgY29uc3QgcmVzdWx0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVzdWx0Iik7CgogICAgYnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICByZXN1bHRFbC50ZXh0Q29udGVudCA9ICJWw6lyaWZpY2F0aW9u4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9kYi1jaGVjayIsIHsKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfQogICAgICAgIH0pOwogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgIHJlc3VsdEVsLnRleHRDb250ZW50ID0gYEhUVFAgJHtyZXMuc3RhdHVzfVxuYCArIEpTT04uc3RyaW5naWZ5KGRhdGEsIG51bGwsIDIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICByZXN1bHRFbC50ZXh0Q29udGVudCA9ICJFcnJldXIgcsOpc2VhdSA6ICIgKyBlcnI7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0KICAgIH0pOwogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
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
# Endpoints de test du squelette (étape 1)
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
