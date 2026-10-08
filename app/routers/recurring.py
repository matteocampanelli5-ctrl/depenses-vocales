"""Dépenses récurrentes — CRUD, et matérialisation des occurrences déjà
arrivées en vraies transactions.

En plus de la définition (type, nom, montant, catégorie, jour du mois,
dates de début/fin optionnelles), chaque occurrence déjà arrivée (jour du
mois <= aujourd'hui) est matérialisée en vraie ligne dans `transactions`
par `sync_recurring_occurrences` ci-dessous — c'est ce qui la fait
apparaître dans l'historique, les filtres, l'export Excel, etc. comme
n'importe quelle transaction. `start_date`/`end_date` (optionnelles)
bornent la période où la charge compte, sans avoir à revenir
supprimer/désactiver la ligne à la main (ex : un abonnement qui ne démarre
qu'en novembre).
"""

import calendar
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.config import today_paris
from app.models import RecurringExpenseIn, RecurringExpenseUpdate
from app.security import require_user

router = APIRouter()


def _clamp_day(year: int, month: int, day: int) -> int:
    """Ramène un jour du mois (1-31) au dernier jour réel du mois visé, pour
    les charges récurrentes posées sur un jour qui n'existe pas partout
    (ex : le 31 d'un mois à 30 jours, ou le 30 février)."""
    last_day = calendar.monthrange(year, month)[1]
    return min(day, last_day)


def _month_add(year: int, month: int, delta: int) -> tuple[int, int]:
    total = (year * 12 + (month - 1)) + delta
    return total // 12, total % 12 + 1


def sync_recurring_occurrences(client, user_id: str) -> None:
    """Crée, dans `transactions`, les occurrences de charges récurrentes déjà
    arrivées qui n'ont pas encore de ligne correspondante.

    Chaque occurrence (une charge récurrente pour un mois donné) est
    identifiée de façon unique par la paire (recurring_expense_id,
    occurrence_month), ce qui évite de la créer deux fois même si cette
    fonction est appelée à chaque chargement de page. On part de la date de
    début (si posée) ou du mois de création de la charge (sinon) — jamais
    plus tôt —, pour ne pas générer rétroactivement des mois antérieurs à
    l'existence de la charge récurrente.

    Important : on ne modifie ni ne supprime jamais une transaction déjà
    créée ici, même si la charge récurrente est ensuite éditée ou supprimée.
    Une fois matérialisée, une occurrence est un fait passé (de l'argent
    réellement dépensé/reçu ce mois-là), pas une projection à recalculer.
    """
    recurring_items = client.table("recurring_expenses").select("*").eq("user_id", user_id).execute().data
    if not recurring_items:
        return

    today = today_paris()
    existing = (
        client.table("transactions")
        .select("recurring_expense_id, occurrence_month")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    existing_keys = {
        (row["recurring_expense_id"], row["occurrence_month"])
        for row in existing
        if row.get("recurring_expense_id")
    }

    new_rows: list[dict] = []
    for item in recurring_items:
        start_date = date.fromisoformat(item["start_date"]) if item.get("start_date") else None
        end_date = date.fromisoformat(item["end_date"]) if item.get("end_date") else None
        created_at = datetime.fromisoformat(item["created_at"]).date()
        year, month = (start_date.year, start_date.month) if start_date else (created_at.year, created_at.month)
        # On ne remonte jamais plus loin que le mois dernier, même si la
        # charge a été créée il y a longtemps : ça évite, au premier appel
        # après cette mise à jour, de faire apparaître d'un coup des mois et
        # des mois de transactions "fantômes" pour une charge ancienne.
        earliest = _month_add(today.year, today.month, -1)
        if (year, month) < earliest:
            year, month = earliest

        while (year, month) <= (today.year, today.month):
            day = _clamp_day(year, month, item["day_of_month"])
            occurrence_date = date(year, month, day)

            if occurrence_date > today:
                break  # les mois suivants seront encore plus loin dans le futur
            if end_date and occurrence_date > end_date:
                break  # charge terminée, rien au-delà
            if start_date and occurrence_date < start_date:
                year, month = _month_add(year, month, 1)
                continue

            occurrence_month = date(year, month, 1).isoformat()
            key = (item["id"], occurrence_month)
            if key not in existing_keys:
                new_rows.append({
                    "type": item["type"],
                    "amount": item["amount"],
                    "category": item["category"],
                    "description": item["name"],
                    "expense_date": occurrence_date.isoformat(),
                    "recurring_expense_id": item["id"],
                    "occurrence_month": occurrence_month,
                    "user_id": user_id,
                })
            year, month = _month_add(year, month, 1)

    if new_rows:
        client.table("transactions").insert(new_rows).execute()


@router.get("/api/recurring")
def list_recurring(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    result = (
        client.table("recurring_expenses")
        .select("*")
        .eq("user_id", user_id)
        .order("day_of_month")
        .execute()
    )
    return result.data


@router.post("/api/recurring", status_code=201)
def create_recurring(item: RecurringExpenseIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
        "type": item.type,
        "name": item.name.strip(),
        "amount": item.amount,
        "category": (item.category or "autre").strip() or "autre",
        "day_of_month": item.day_of_month,
        "start_date": item.start_date.isoformat() if item.start_date else None,
        "end_date": item.end_date.isoformat() if item.end_date else None,
        "user_id": user_id,
        "active": True,
    }
    result = client.table("recurring_expenses").insert(payload).execute()
    return result.data[0]


@router.put("/api/recurring/{recurring_id}")
def update_recurring(
    recurring_id: str, item: RecurringExpenseUpdate, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    # Contrairement à update_transaction, on NE saute PAS les valeurs None :
    # c'est ce qui permet d'effacer une date de fin déjà posée (renvoyer
    # end_date: null doit bien la retirer, pas être ignoré).
    payload: dict = {}
    data = item.model_dump(exclude_unset=True)
    for key, value in data.items():
        if isinstance(value, date):
            payload[key] = value.isoformat()
        elif isinstance(value, str):
            payload[key] = value.strip()
        else:
            payload[key] = value
    if "essentiality_rating" in payload:
        # Horodate la note (comme rating_updated_at sur category_essentiality_ratings)
        # pour pouvoir afficher "noté il y a X mois" dans le Plan d'épargne.
        payload["essentiality_rated_at"] = datetime.now(timezone.utc).isoformat()
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = (
        client.table("recurring_expenses")
        .update(payload)
        .eq("id", recurring_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return result.data[0]


@router.delete("/api/recurring/{recurring_id}", status_code=204)
def delete_recurring(recurring_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("recurring_expenses")
        .delete()
        .eq("id", recurring_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return Response(status_code=204)
