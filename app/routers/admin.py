"""Opérations d'administration/gestion de compte sans meilleur home dédié :
  - /api/admin/claim-orphan-data : réservée à un compte administrateur
  - /api/reset-all : réservée à l'utilisateur connecté sur ses propres
    données (PAS restreinte à un admin dans le code d'origine — gardée ici
    par choix éditorial car elle opère sur le même _RESET_TABLES cross-
    table que claim-orphan-data, voir app/config.py)
"""

from fastapi import APIRouter, Depends, HTTPException, Response

from app.config import RECEIPTS_BUCKET, _RESET_TABLES
from app.db import get_supabase_client
from app.security import require_user

router = APIRouter()


# ---------------------------------------------------------------------------
# Migration des données créées avant le multi-profil
# ---------------------------------------------------------------------------
# Toutes les lignes créées avant ce passage au multi-profil ont un `user_id`
# NULL (la colonne vient d'être ajoutée). Cette route les rattache en bloc
# au compte appelant, pour que l'historique existant (transactions,
# budgets, etc.) ne soit pas perdu de vue après la migration — réservée à un
# admin, et pensée pour n'être utilisée qu'une seule fois (par le premier
# compte créé, juste après son inscription). Rejouer cette route plus tard
# ne fait rien de dangereux : une fois les lignes orphelines réclamées, il
# n'en reste plus aucune à réclamer, donc un second appel est un no-op.
@router.post("/api/admin/claim-orphan-data")
def claim_orphan_data(user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    caller = client.table("app_users").select("is_admin").eq("id", user_id).limit(1).execute().data
    if not caller or not caller[0].get("is_admin"):
        raise HTTPException(status_code=403, detail="Seul un compte administrateur peut réclamer ces données")

    claimed: dict[str, int] = {}
    for table_name in _RESET_TABLES:
        result = (
            client.table(table_name)
            .update({"user_id": user_id})
            .is_("user_id", "null")
            .execute()
        )
        claimed[table_name] = len(result.data)
    return {"claimed": claimed}


# ---------------------------------------------------------------------------
# Réinitialisation complète (données de test)
# ---------------------------------------------------------------------------
# Supprime TOUT : transactions, charges récurrentes, catégories perso,
# suggestions ignorées et budgets. Irréversible, protégé par la clé API
# comme le reste, avec une confirmation forte côté frontend.
@router.delete("/api/reset-all", status_code=204)
def reset_all(user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()

    # On récupère la liste des propres transactions de l'utilisateur AVANT
    # de supprimer quoi que ce soit, pour pouvoir nettoyer ses reçus dans le
    # Storage ensuite (le bucket est partagé entre tous les comptes, donc on
    # ne doit toucher qu'aux fichiers qui lui appartiennent).
    try:
        own_tx_ids = {
            row["id"]
            for row in client.table("transactions").select("id").eq("user_id", user_id).execute().data
        }
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas faire échouer le reset des tables
        own_tx_ids = set()

    for table_name in _RESET_TABLES:
        client.table(table_name).delete().eq("user_id", user_id).execute()

    # Les photos de reçus vivent dans le Storage, pas dans une table : les
    # effacer séparément, sinon "tout réinitialiser" laisserait les anciennes
    # photos orphelines dans le bucket (non listées nulle part, mais toujours
    # stockées et comptant dans le quota Supabase).
    try:
        if own_tx_ids:
            receipt_files = client.storage.from_(RECEIPTS_BUCKET).list(options={"limit": 1000})
            paths = [f["name"] for f in receipt_files if f.get("name") in own_tx_ids]
            if paths:
                client.storage.from_(RECEIPTS_BUCKET).remove(paths)
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas faire échouer le reset des tables
        pass

    return Response(status_code=204)
