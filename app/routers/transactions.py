"""Transactions ponctuelles (dépenses, revenus et virements entre comptes de
l'utilisateur) — CRUD."""

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response

from app.config import LOAN_CATEGORY, TRANSFER_CATEGORY, today_paris
from app.db import get_supabase_client
from app.models import TransactionIn, TransactionUpdate
from app.routers.accounts import ensure_own_accounts
from app.routers.loans import active_loans, ensure_own_loan, match_loan_for_payment
from app.routers.recurring import sync_recurring_occurrences
from app.security import require_user

router = APIRouter()


@router.get("/api/health")
def health() -> dict:
    """Public, sans dépendance à Supabase : confirme juste que le déploiement
    Vercel + le routing FastAPI fonctionnent."""
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@router.get("/api/transactions")
def list_transactions(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    sync_recurring_occurrences(client, user_id)
    result = (
        client.table("transactions")
        .select("*")
        .eq("user_id", user_id)
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


@router.post("/api/transactions", status_code=201)
def create_transaction(tx: TransactionIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    if tx.transfer_account_id and tx.transfer_account_id == tx.account_id:
        raise HTTPException(status_code=400, detail="Un virement doit relier deux comptes différents")
    ensure_own_accounts(client, user_id, tx.account_id, tx.transfer_account_id)
    ensure_own_loan(client, user_id, tx.loan_id)
    category = (tx.category or "autre").strip() or "autre"
    loan_id = str(tx.loan_id) if tx.loan_id else None
    if tx.transfer_account_id:
        category = TRANSFER_CATEGORY
        loan_id = None
    elif loan_id:
        category = LOAN_CATEGORY
    elif category == LOAN_CATEGORY and tx.type == "expense":
        # Mensualité saisie à la main ou dictée ("j'ai payé ma mensualité de
        # prêt") : rattachée au prêt dont la mensualité correspond.
        loan_id = match_loan_for_payment(active_loans(client, user_id), tx.amount, tx.description, hinted=True)
    payload = {
        "type": tx.type,
        "amount": tx.amount,
        "category": category,
        "description": tx.description,
        "expense_date": (tx.expense_date or today_paris()).isoformat(),
        "user_id": user_id,
        "account_id": str(tx.account_id) if tx.account_id else None,
        "transfer_account_id": str(tx.transfer_account_id) if tx.transfer_account_id else None,
    }
    if loan_id:
        payload["loan_id"] = loan_id
    result = client.table("transactions").insert(payload).execute()
    return result.data[0]


@router.put("/api/transactions/{transaction_id}")
def update_transaction(
    transaction_id: str, tx: TransactionUpdate, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    data = tx.model_dump(exclude_unset=True)
    for key, value in data.items():
        if key in ("description", "account_id", "transfer_account_id", "loan_id"):
            # Champs explicitement nullables : un null envoyé par le client
            # efface la valeur (ex: description devenue redondante avec la
            # catégorie, opération qui n'est plus un virement), contrairement
            # aux autres champs ci-dessous où null signifie "pas touché".
            payload[key] = str(value) if key != "description" and value else value
            continue
        if value is None:
            continue
        if isinstance(value, date):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")
    if payload.get("transfer_account_id"):
        if "account_id" in payload:
            own_account = payload["account_id"]
        else:
            current = (
                client.table("transactions")
                .select("account_id")
                .eq("id", transaction_id)
                .eq("user_id", user_id)
                .execute()
                .data
            )
            own_account = current[0]["account_id"] if current else None
        if payload["transfer_account_id"] == own_account:
            raise HTTPException(status_code=400, detail="Un virement doit relier deux comptes différents")
    ensure_own_accounts(client, user_id, payload.get("account_id"), payload.get("transfer_account_id"))
    ensure_own_loan(client, user_id, payload.get("loan_id"))
    if payload.get("transfer_account_id"):
        payload["category"] = TRANSFER_CATEGORY
        payload["loan_id"] = None
    elif payload.get("loan_id"):
        payload["category"] = LOAN_CATEGORY
    elif "category" in payload and payload["category"] != LOAN_CATEGORY and "loan_id" not in payload:
        # Une opération qui quitte la catégorie "Crédit / prêt" n'est plus
        # une mensualité.
        payload["loan_id"] = None

    result = (
        client.table("transactions")
        .update(payload)
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return result.data[0]


@router.delete("/api/transactions/{transaction_id}", status_code=204)
def delete_transaction(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("transactions")
        .delete()
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return Response(status_code=204)
