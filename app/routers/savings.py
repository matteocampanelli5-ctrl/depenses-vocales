"""Objectif d'épargne mensuel (une seule ligne globale, pas par catégorie)."""

from fastapi import APIRouter, Depends

from app.db import get_supabase_client
from app.models import SavingsGoalIn
from app.security import require_user

router = APIRouter()


@router.get("/api/savings-goal")
def get_savings_goal(user_id: str = Depends(require_user)) -> dict | None:
    client = get_supabase_client()
    rows = (
        client.table("savings_goal")
        .select("*")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    return rows[0] if rows else None


@router.put("/api/savings-goal")
def upsert_savings_goal(item: SavingsGoalIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    existing = (
        client.table("savings_goal")
        .select("id")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    if existing:
        result = (
            client.table("savings_goal")
            .update({"monthly_target": item.monthly_target})
            .eq("id", existing[0]["id"])
            .eq("user_id", user_id)
            .execute()
        )
        return result.data[0]

    result = client.table("savings_goal").insert(
        {"monthly_target": item.monthly_target, "user_id": user_id}
    ).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Coach IA (récompense du niveau Or) : à partir d'un résumé chiffré du mois
# préparé par l'appli (totaux par catégorie, moyennes, abonnements), l'IA
# propose 3 actions concrètes. Aucune donnée n'est stockée.
# ---------------------------------------------------------------------------
import json as _json
import re as _re

from fastapi import HTTPException
from pydantic import BaseModel, Field

from app.config import ANTHROPIC_API_KEY


class CoachIn(BaseModel):
    summary: str = Field(min_length=10, max_length=6000)


_COACH_PROMPT = (
    "Tu es un coach budgétaire bienveillant pour un étudiant français. On te donne un résumé "
    "chiffré de son mois et de ses habitudes. Propose exactement 3 actions concrètes, "
    "chiffrées et réalistes pour le mois prochain, basées uniquement sur ces chiffres "
    "(pas de conseil d'investissement sur des titres précis). Réponds UNIQUEMENT en JSON : "
    '{"tips": [{"title": "phrase courte", "detail": "1 à 2 phrases avec un chiffre", "saving": nombre_euros_par_mois_ou_0}]}'
)


@router.post("/api/coach")
def coach(item: CoachIn, user_id: str = Depends(require_user)) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : ANTHROPIC_API_KEY")
    from anthropic import Anthropic

    try:
        message = Anthropic(api_key=ANTHROPIC_API_KEY).messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=700,
            system=_COACH_PROMPT,
            messages=[{"role": "user", "content": item.summary}],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail="Le coach IA est indisponible pour le moment, réessaie plus tard.") from exc
    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    raw = _re.sub(r"^```(json)?|```$", "", raw, flags=_re.MULTILINE).strip()
    try:
        data = _json.loads(raw)
        tips = [
            {
                "title": str(t.get("title", ""))[:120],
                "detail": str(t.get("detail", ""))[:400],
                "saving": float(t.get("saving") or 0),
            }
            for t in data.get("tips", [])[:3]
            if isinstance(t, dict)
        ]
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="Réponse du coach illisible, réessaie.") from exc
    return {"tips": tips}
