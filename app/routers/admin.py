"""Réinitialisation complète des données de l'utilisateur connecté
(/api/reset-all) — opère uniquement sur ses propres lignes, jamais sur
celles des autres comptes (voir _RESET_TABLES dans app/config.py).
"""

from fastapi import APIRouter, Depends, Response

from app.config import _RESET_TABLES
from app.db import get_supabase_client
from app.security import require_user

router = APIRouter()

# Ancien bucket des photos de reçus, gardé uniquement pour le nettoyage.
_LEGACY_RECEIPTS_BUCKET = "receipts"


# Supprime TOUT : transactions, charges récurrentes, catégories perso,
# suggestions ignorées, budgets, objectif d'épargne, prêts, comptes et
# soldes. Irréversible, protégé par la session comme le reste, avec une
# confirmation forte côté frontend.
@router.delete("/api/reset-all", status_code=204)
def reset_all(user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()

    # Les photos de reçus (fonctionnalité retirée en octobre 2026) peuvent
    # encore exister dans le stockage Supabase : nommées d'après l'id de leur
    # opération, elles sont effacées avec le reste. On relève donc les ids
    # des opérations de l'utilisateur AVANT de les supprimer — le bucket est
    # partagé entre tous les comptes, on ne touche qu'à ses propres fichiers.
    try:
        own_tx_ids = {
            row["id"]
            for row in client.table("transactions").select("id").eq("user_id", user_id).execute().data
        }
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas bloquer la réinitialisation
        own_tx_ids = set()

    for table_name in _RESET_TABLES:
        client.table(table_name).delete().eq("user_id", user_id).execute()

    try:
        if own_tx_ids:
            files = client.storage.from_(_LEGACY_RECEIPTS_BUCKET).list(options={"limit": 1000})
            paths = [f["name"] for f in files if f.get("name") in own_tx_ids]
            if paths:
                client.storage.from_(_LEGACY_RECEIPTS_BUCKET).remove(paths)
    except Exception:  # noqa: BLE001 - bucket absent ou déjà vide : rien à nettoyer
        pass
    return Response(status_code=204)
