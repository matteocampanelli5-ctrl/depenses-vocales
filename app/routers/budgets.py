"""Budgets mensuels par catégorie.

Un seul budget par catégorie (pas par mois) : c'est un plafond reconduit
automatiquement chaque mois, comparé aux dépenses réelles du mois en cours
côté frontend.
"""

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import BudgetIn
from app.security import require_user

router = APIRouter()


@router.get("/api/budgets")
def list_budgets(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return client.table("budgets").select("*").eq("user_id", user_id).execute().data


@router.put("/api/budgets")
def upsert_budget(item: BudgetIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    category = item.category.strip().lower()

    existing = (
        client.table("budgets")
        .select("*")
        .eq("user_id", user_id)
        .eq("category", category)
        .execute()
        .data
    )
    if existing:
        result = (
            client.table("budgets")
            .update({"amount": item.amount})
            .eq("user_id", user_id)
            .eq("category", category)
            .execute()
        )
        return result.data[0]

    result = client.table("budgets").insert(
        {"category": category, "amount": item.amount, "user_id": user_id}
    ).execute()
    return result.data[0]


@router.delete("/api/budgets/{category}", status_code=204)
def delete_budget(category: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("budgets")
        .delete()
        .eq("user_id", user_id)
        .eq("category", category)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Budget introuvable")
    return Response(status_code=204)
