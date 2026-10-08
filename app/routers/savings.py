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
