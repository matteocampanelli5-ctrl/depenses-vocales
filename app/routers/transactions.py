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


# ---------------------------------------------------------------------------
# Suppression d'un mois entier (rattrapage d'une erreur d'import)
# ---------------------------------------------------------------------------
def _month_bounds(month: str) -> tuple[str, str]:
    try:
        year, mon = (int(part) for part in month.split("-"))
        first = date(year, mon, 1)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Mois invalide (attendu : AAAA-MM)") from exc
    nxt = date(year + (mon == 12), 1 if mon == 12 else mon + 1, 1)
    return first.isoformat(), nxt.isoformat()


def _month_query(client, user_id: str, month: str, account_id: str | None):
    start, end = _month_bounds(month)
    query = (
        client.table("transactions")
        .select("id, recurring_expense_id")
        .eq("user_id", user_id)
        .gte("expense_date", start)
        .lt("expense_date", end)
    )
    if account_id:
        ensure_own_accounts(client, user_id, account_id)
        query = query.eq("account_id", account_id)
    return query.execute().data


@router.get("/api/transaction-months")
def list_transaction_months(account_id: str | None = None, user_id: str = Depends(require_user)) -> list[dict]:
    """Mois qui contiennent des opérations (avec leur nombre), pour le choix
    du mois à supprimer. `account_id` restreint à un compte."""
    client = get_supabase_client()
    query = client.table("transactions").select("expense_date, recurring_expense_id").eq("user_id", user_id)
    if account_id:
        ensure_own_accounts(client, user_id, account_id)
        query = query.eq("account_id", account_id)
    counts: dict[str, int] = {}
    for row in query.execute().data:
        key = str(row["expense_date"])[:7]
        counts[key] = counts.get(key, 0) + 1
    return [{"month": m, "count": c} for m, c in sorted(counts.items(), reverse=True)]


@router.delete("/api/transaction-months/{month}")
def delete_transaction_month(month: str, account_id: str | None = None, user_id: str = Depends(require_user)) -> dict:
    """Supprime les opérations d'un mois (et d'un compte si `account_id`).
    Les occurrences de charges récurrentes sont gardées : elles seraient
    recréées automatiquement au prochain chargement ; pour les faire
    disparaître, il faut modifier ou supprimer la charge récurrente."""
    client = get_supabase_client()
    rows = _month_query(client, user_id, month, account_id)
    to_delete = [row["id"] for row in rows if not row.get("recurring_expense_id")]
    kept = len(rows) - len(to_delete)
    for start in range(0, len(to_delete), 200):
        chunk = to_delete[start:start + 200]
        client.table("transactions").delete().eq("user_id", user_id).in_("id", chunk).execute()
    return {"deleted": len(to_delete), "kept_recurring": kept}
