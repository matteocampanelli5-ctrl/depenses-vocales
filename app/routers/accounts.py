"""Comptes de l'utilisateur (banques, livrets, placements), soldes relevés à
la main et historique de patrimoine déclaré.

Le solde affiché d'un livret ou d'un placement est calculé côté frontend :
dernier solde relevé (table account_balances) + virements arrivés depuis −
virements repartis depuis. Ce module ne stocke que les données brutes ; il
ne fait aucun calcul de solde.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import AccountBalanceIn, AccountIn, AccountUpdate, NetWorthSnapshotIn
from app.security import require_user

router = APIRouter()


def ensure_own_accounts(client, user_id: str, *account_ids: UUID | str | None) -> None:
    """Vérifie que chaque id de compte fourni (les None sont ignorés)
    appartient bien à l'utilisateur connecté. Sans ce contrôle, un client
    pourrait rattacher ses opérations au compte de quelqu'un d'autre en
    devinant son identifiant."""
    wanted = {str(a) for a in account_ids if a}
    if not wanted:
        return
    rows = (
        client.table("accounts")
        .select("id")
        .eq("user_id", user_id)
        .in_("id", list(wanted))
        .execute()
        .data
    )
    if {row["id"] for row in rows} != wanted:
        raise HTTPException(status_code=400, detail="Compte introuvable")


# ---------------------------------------------------------------------------
# Comptes
# ---------------------------------------------------------------------------
@router.get("/api/accounts")
def list_accounts(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("accounts")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at")
        .execute()
        .data
    )


def _clean_name(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned:
        raise HTTPException(status_code=400, detail="Le nom du compte est obligatoire")
    return cleaned


@router.post("/api/accounts", status_code=201)
def create_account(item: AccountIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
        "user_id": user_id,
        "name": _clean_name(item.name),
        "kind": item.kind,
        "annual_rate_pct": item.annual_rate_pct,
        "active": True,
    }
    return client.table("accounts").insert(payload).execute().data[0]


@router.put("/api/accounts/{account_id}")
def update_account(account_id: UUID, item: AccountUpdate, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    for key, value in item.model_dump(exclude_unset=True).items():
        if key == "annual_rate_pct":
            payload[key] = value  # null autorisé : retire le taux
        elif value is None:
            continue
        elif key == "name":
            payload[key] = _clean_name(value)
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")
    result = (
        client.table("accounts")
        .update(payload)
        .eq("id", str(account_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Compte introuvable")
    return result.data[0]


@router.delete("/api/accounts/{account_id}", status_code=204)
def delete_account(account_id: UUID, user_id: str = Depends(require_user)) -> Response:
    # Les dépenses et revenus rattachés à ce compte sont gardés : leur compte
    # repasse simplement à vide (on delete set null côté base). Les virements
    # vers ou depuis ce compte, eux, sont supprimés avec lui : sans leur
    # compte, ils redeviendraient de fausses dépenses ou de faux revenus et
    # fausseraient tous les totaux. Les soldes relevés disparaissent aussi
    # (on delete cascade). Pour garder l'historique, l'utilisateur peut
    # plutôt marquer le compte comme fermé (active = false).
    client = get_supabase_client()
    account = str(account_id)
    owned = client.table("accounts").select("id").eq("id", account).eq("user_id", user_id).execute().data
    if not owned:
        raise HTTPException(status_code=404, detail="Compte introuvable")
    client.table("transactions").delete().eq("user_id", user_id).eq("transfer_account_id", account).execute()
    own_transfer_ids = [
        row["id"]
        for row in client.table("transactions")
        .select("id, transfer_account_id")
        .eq("user_id", user_id)
        .eq("account_id", account)
        .execute()
        .data
        if row.get("transfer_account_id")
    ]
    if own_transfer_ids:
        client.table("transactions").delete().eq("user_id", user_id).in_("id", own_transfer_ids).execute()
    result = (
        client.table("accounts")
        .delete()
        .eq("id", str(account_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Compte introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Soldes relevés à la main ("je tape le vrai solde")
# ---------------------------------------------------------------------------
@router.get("/api/account-balances")
def list_account_balances(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("account_balances")
        .select("*")
        .eq("user_id", user_id)
        .order("balance_date")
        .order("created_at")
        .execute()
        .data
    )


@router.post("/api/accounts/{account_id}/balances", status_code=201)
def add_account_balance(
    account_id: UUID, item: AccountBalanceIn, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    ensure_own_accounts(client, user_id, account_id)
    payload = {
        "user_id": user_id,
        "account_id": str(account_id),
        "balance_date": item.balance_date.isoformat(),
        "balance": round(item.balance, 2),
    }
    return client.table("account_balances").insert(payload).execute().data[0]


@router.delete("/api/account-balances/{balance_id}", status_code=204)
def delete_account_balance(balance_id: UUID, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("account_balances")
        .delete()
        .eq("id", str(balance_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Solde introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Historique de patrimoine déclaré (ex: relevés Endettement / Patrimoine)
# ---------------------------------------------------------------------------
@router.get("/api/net-worth-snapshots")
def list_net_worth_snapshots(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("net_worth_snapshots")
        .select("*")
        .eq("user_id", user_id)
        .order("snapshot_date")
        .execute()
        .data
    )


@router.post("/api/net-worth-snapshots", status_code=201)
def add_net_worth_snapshot(item: NetWorthSnapshotIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
        "user_id": user_id,
        "snapshot_date": item.snapshot_date.isoformat(),
        "assets": round(item.assets, 2),
        "debts": round(item.debts, 2),
        "label": (item.label or "").strip() or None,
    }
    return client.table("net_worth_snapshots").insert(payload).execute().data[0]


@router.delete("/api/net-worth-snapshots/{snapshot_id}", status_code=204)
def delete_net_worth_snapshot(snapshot_id: UUID, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("net_worth_snapshots")
        .delete()
        .eq("id", str(snapshot_id))
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Point d'historique introuvable")
    return Response(status_code=204)
