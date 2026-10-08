"""Catégories personnalisées + suggestions ignorées + notes d'essentialité
par catégorie (Plan d'épargne).

En base (pas dans le navigateur) pour suivre l'utilisateur d'un appareil à
l'autre (téléphone, tablette, ordinateur) : une catégorie créée depuis le
bandeau de suggestion, ou une suggestion ignorée, doit se retrouver
partout, pas seulement sur l'appareil où l'action a été faite.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import CategoryRatingIn, CustomCategoryIn, DismissedSuggestionIn
from app.security import require_user

router = APIRouter()


@router.get("/api/custom-categories")
def list_custom_categories(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("custom_categories")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at")
        .execute()
        .data
    )


@router.post("/api/custom-categories", status_code=201)
def create_custom_category(item: CustomCategoryIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    value = item.value.strip()
    label = item.label.strip()
    if not value or not label:
        raise HTTPException(status_code=400, detail="Valeur et libellé requis")

    # Idempotent : si la catégorie existe déjà (même type + valeur) pour CET
    # utilisateur, on la renvoie telle quelle plutôt que de planter sur la
    # contrainte unique — ça évite un souci si le bandeau est validé deux
    # fois par erreur, ou sur deux appareils en même temps.
    existing = (
        client.table("custom_categories")
        .select("*")
        .eq("user_id", user_id)
        .eq("type", item.type)
        .eq("value", value)
        .execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("custom_categories").insert(
        {"type": item.type, "value": value, "label": label, "user_id": user_id}
    ).execute()
    return result.data[0]


@router.get("/api/dismissed-suggestions")
def list_dismissed_suggestions(user_id: str = Depends(require_user)) -> list[str]:
    client = get_supabase_client()
    rows = (
        client.table("dismissed_category_suggestions")
        .select("suggestion_key")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    return [row["suggestion_key"] for row in rows]


@router.post("/api/dismissed-suggestions", status_code=201)
def create_dismissed_suggestion(item: DismissedSuggestionIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    key = item.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="Clé requise")

    existing = (
        client.table("dismissed_category_suggestions")
        .select("*")
        .eq("user_id", user_id)
        .eq("suggestion_key", key)
        .execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("dismissed_category_suggestions").insert(
        {"suggestion_key": key, "user_id": user_id}
    ).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Plan d'épargne — note d'essentialité (1 à 5) par catégorie de dépense,
# donnée par la PERSONNE elle-même (jamais déduite ni jugée par l'IA), pour
# calculer une économie potentielle si cet argent était redirigé vers
# l'épargne. Même principe pour les charges récurrentes, mais via
# `essentiality_rating` directement sur /api/recurring (PUT, voir
# app/routers/recurring.py), chaque charge ayant déjà un montant propre —
# pas besoin d'une moyenne comme ici.
# ---------------------------------------------------------------------------
@router.get("/api/category-ratings")
def list_category_ratings(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("category_essentiality_ratings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
        .data
    )


@router.put("/api/category-ratings")
def upsert_category_rating(item: CategoryRatingIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    category = item.category.strip().lower()
    existing = (
        client.table("category_essentiality_ratings")
        .select("id")
        .eq("user_id", user_id)
        .eq("category", category)
        .limit(1)
        .execute()
        .data
    )
    now = datetime.now(timezone.utc).isoformat()
    if existing:
        result = (
            client.table("category_essentiality_ratings")
            .update({"rating": item.rating, "rating_updated_at": now})
            .eq("id", existing[0]["id"])
            .eq("user_id", user_id)
            .execute()
        )
        return result.data[0]

    result = client.table("category_essentiality_ratings").insert(
        {"user_id": user_id, "category": category, "rating": item.rating, "rating_updated_at": now}
    ).execute()
    return result.data[0]
