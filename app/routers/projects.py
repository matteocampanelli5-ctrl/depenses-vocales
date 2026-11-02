"""Projets de placement (ex : les projets Bricks) : plusieurs projets par
compte, chacun avec son montant investi, son rendement, sa durée.

Ce module ne stocke que les données ; les intérêts courus, la progression et
les échéances sont calculés côté frontend (comme pour les prêts).
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import InvestmentProjectIn, InvestmentProjectUpdate
from app.routers.accounts import ensure_own_accounts
from app.security import require_user

router = APIRouter()


def _clean_name(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned:
        raise HTTPException(status_code=400, detail="Le nom du projet est obligatoire")
    return cleaned


@router.get("/api/investment-projects")
def list_projects(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("investment_projects")
        .select("*")
        .eq("user_id", user_id)
        .order("start_date")
        .execute()
        .data
    )


@router.post("/api/investment-projects", status_code=201)
def create_project(item: InvestmentProjectIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    ensure_own_accounts(client, user_id, item.account_id)
    payload = {
        "user_id": user_id,
        "account_id": str(item.account_id) if item.account_id else None,
        "name": _clean_name(item.name),
        "invested_amount": round(item.invested_amount, 2),
        "annual_rate_pct": item.annual_rate_pct,
        "start_date": item.start_date.isoformat(),
        "duration_months": item.duration_months,
        "received_amount": round(item.received_amount, 2),
        "status": item.status,
    }
    return client.table("investment_projects").insert(payload).execute().data[0]


@router.put("/api/investment-projects/{project_id}")
def update_project(project_id: UUID, item: InvestmentProjectUpdate, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    for key, value in item.model_dump(exclude_unset=True).items():
        if key == "account_id":
            if value is not None:
                ensure_own_accounts(client, user_id, value)
            payload[key] = str(value) if value else None  # null autorisé : détache le projet du compte
        elif value is None:
            continue
        elif key == "name":
            payload[key] = _clean_name(value)
        elif key == "start_date":
            payload[key] = value.isoformat()
        elif key in ("invested_amount", "received_amount"):
            payload[key] = round(value, 2)
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")
    result = (
        client.table("investment_projects")
        .update(payload)
        .eq("id", str(project_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Projet introuvable")
    return result.data[0]


@router.delete("/api/investment-projects/{project_id}", status_code=204)
def delete_project(project_id: UUID, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("investment_projects")
        .delete()
        .eq("id", str(project_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Projet introuvable")
    return Response(status_code=204)
