"""Tâche quotidienne (Vercel Cron) et préférences de l'utilisateur.

La tâche quotidienne sert à deux choses :
1. garder le projet Supabase éveillé (les projets gratuits sont mis en pause
   après une semaine sans activité) ;
2. le 1er du mois, envoyer le résumé du mois écoulé à ceux qui l'ont activé.
"""

import hmac
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from app.config import CRON_SECRET
from app.db import get_supabase_client
from app.models import PreferencesIn
from app.security import require_user
from app.summary import send_monthly_summary

router = APIRouter()


@router.get("/api/cron/daily")
def cron_daily(authorization: str = Header(default="")) -> dict:
    expected = f"Bearer {CRON_SECRET}"
    if not CRON_SECRET or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Non autorisé")
    client = get_supabase_client()
    # Simple lecture : suffit à compter comme activité pour Supabase.
    client.table("app_users").select("id").limit(1).execute()
    sent = 0
    today = datetime.now(timezone.utc).date()
    if today.day == 1:
        month = today.strftime("%Y-%m")
        users = (
            client.table("app_users")
            .select("id, email, last_summary_month")
            .eq("monthly_summary", True)
            .execute()
            .data
        )
        for user in users:
            if user.get("last_summary_month") == month:
                continue
            try:
                if send_monthly_summary(client, user, today):
                    sent += 1
                client.table("app_users").update({"last_summary_month": month}).eq("id", user["id"]).execute()
            except Exception:  # noqa: BLE001 - un échec ne doit pas bloquer les autres
                continue
    return {"ok": True, "summaries_sent": sent}


@router.get("/api/preferences")
def get_preferences(user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    rows = client.table("app_users").select("monthly_summary").eq("id", user_id).limit(1).execute().data
    return {"monthly_summary": bool(rows and rows[0].get("monthly_summary"))}


@router.put("/api/preferences")
def set_preferences(item: PreferencesIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    client.table("app_users").update({"monthly_summary": item.monthly_summary}).eq("id", user_id).execute()
    return {"monthly_summary": item.monthly_summary}
