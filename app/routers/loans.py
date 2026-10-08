"""Prêts immobiliers (premier bloc du suivi de patrimoine) — CRUD simple, le
calcul d'amortissement (intérêts, capital restant dû, date de fin estimée)
est entièrement fait côté frontend à partir des 4 champs stockés ici,
jamais ici : pas de table de mensualités mois par mois à tenir à jour.
"""

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import PropertyLoanIn, PropertyLoanUpdate
from app.security import require_user

router = APIRouter()


@router.get("/api/property-loans")
def list_property_loans(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("property_loans")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at")
        .execute()
        .data
    )


@router.post("/api/property-loans", status_code=201)
def create_property_loan(item: PropertyLoanIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
        "user_id": user_id,
        "property_name": item.property_name.strip(),
        "principal_amount": item.principal_amount,
        "annual_rate_pct": item.annual_rate_pct,
        "monthly_payment": item.monthly_payment,
        "start_date": item.start_date.isoformat(),
        "active": True,
    }
    result = client.table("property_loans").insert(payload).execute()
    return result.data[0]


@router.put("/api/property-loans/{loan_id}")
def update_property_loan(
    loan_id: str, item: PropertyLoanUpdate, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
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

    result = (
        client.table("property_loans")
        .update(payload)
        .eq("id", loan_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Prêt introuvable")
    return result.data[0]


@router.delete("/api/property-loans/{loan_id}", status_code=204)
def delete_property_loan(loan_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("property_loans")
        .delete()
        .eq("id", loan_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Prêt introuvable")
    return Response(status_code=204)
