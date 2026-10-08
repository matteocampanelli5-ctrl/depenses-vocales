"""Transactions ponctuelles (dépenses + revenus) — CRUD, et photo de reçu en
pièce jointe."""

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile

from app.config import RECEIPTS_BUCKET, today_paris
from app.db import get_supabase_client
from app.models import TransactionIn, TransactionUpdate
from app.routers.recurring import sync_recurring_occurrences
from app.security import require_user

router = APIRouter()


@router.get("/api/health")
def health() -> dict:
    """Public, sans dépendance à Supabase : confirme juste que le déploiement
    Vercel + le routing FastAPI fonctionnent."""
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@router.get("/api/db-check")
def db_check(user_id: str = Depends(require_user)) -> dict:
    """Protégé par session valide : confirme que les identifiants Supabase
    sont corrects et que la table `transactions` est lisible via la clé
    service_role (qui contourne le RLS, activé sans policy pour anon/public)."""
    client = get_supabase_client()
    try:
        result = (
            client.table("transactions")
            .select("id", count="exact")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:  # noqa: BLE001 - on veut un message clair, pas une 500 opaque
        raise HTTPException(status_code=500, detail=f"Erreur Supabase : {exc}") from exc
    return {"status": "ok", "transactions_table_reachable": True, "row_count": result.count}


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
    payload = {
        "type": tx.type,
        "amount": tx.amount,
        "category": (tx.category or "autre").strip() or "autre",
        "description": tx.description,
        "expense_date": (tx.expense_date or today_paris()).isoformat(),
        "user_id": user_id,
    }
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
        if key == "description":
            # Champ explicitement nullable : un description=null envoyé par
            # le client doit effacer la description (ex: nettoyage auto d'un
            # mot-clé devenu redondant avec la catégorie), contrairement aux
            # autres champs ci-dessous où null signifie juste "pas touché".
            payload["description"] = value
            continue
        if value is None:
            continue
        if isinstance(value, date):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

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
# Photo de reçu en pièce jointe
# ---------------------------------------------------------------------------
# Stockée dans un bucket Supabase Storage privé ("receipts"), jamais exposée
# en public : comme pour les tables, seul ce backend (clé service_role)
# peut y lire/écrire. Le chemin de stockage est simplement l'id de la
# transaction (un seul reçu par transaction ; en réattacher un nouveau
# remplace l'ancien). Le type MIME d'origine est gardé en base pour pouvoir
# resservir l'image avec le bon Content-Type.
ALLOWED_RECEIPT_TYPES = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
MAX_RECEIPT_SIZE_BYTES = 8 * 1024 * 1024  # 8 Mo, large pour une photo de reçu au téléphone


@router.put("/api/transactions/{transaction_id}/receipt")
async def upload_receipt(
    transaction_id: str, file: UploadFile = File(...), user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    existing = (
        client.table("transactions")
        .select("id")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Transaction introuvable")

    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_RECEIPT_TYPES:
        raise HTTPException(status_code=400, detail="Format d'image non supporté (JPEG, PNG, WEBP ou HEIC uniquement)")

    data = await file.read()
    if len(data) > MAX_RECEIPT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Image trop lourde (8 Mo maximum)")

    try:
        client.storage.from_(RECEIPTS_BUCKET).upload(
            transaction_id,
            data,
            file_options={"content-type": content_type, "upsert": "true"},
        )
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(
            status_code=500,
            detail="Échec de l'envoi vers le stockage (le bucket 'receipts' existe-t-il bien dans Supabase ?)",
        ) from exc
    result = (
        client.table("transactions")
        .update({"receipt_path": transaction_id, "receipt_content_type": content_type})
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    return result.data[0]


@router.get("/api/transactions/{transaction_id}/receipt")
def get_receipt(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions")
        .select("receipt_path, receipt_content_type")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    content_type = rows[0].get("receipt_content_type") or "application/octet-stream"
    try:
        image_bytes = client.storage.from_(RECEIPTS_BUCKET).download(rows[0]["receipt_path"])
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(status_code=404, detail="Photo introuvable dans le stockage") from exc
    return Response(
        content=image_bytes,
        media_type=content_type,
        headers={"Cache-Control": "private, no-cache"},
    )


@router.delete("/api/transactions/{transaction_id}/receipt", status_code=204)
def delete_receipt(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions")
        .select("receipt_path")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    try:
        client.storage.from_(RECEIPTS_BUCKET).remove([rows[0]["receipt_path"]])
    except Exception:  # noqa: BLE001 - le fichier est peut-être déjà absent du bucket
        pass
    client.table("transactions").update(
        {"receipt_path": None, "receipt_content_type": None}
    ).eq("id", transaction_id).eq("user_id", user_id).execute()
    return Response(status_code=204)
