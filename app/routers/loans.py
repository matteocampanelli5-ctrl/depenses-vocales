"""Prêts (immobilier ou tout autre crédit) — CRUD simple, le calcul
d'amortissement (intérêts, capital restant dû, date de fin estimée)
est entièrement fait côté frontend à partir des 4 champs stockés ici,
jamais ici : pas de table de mensualités mois par mois à tenir à jour.
"""

import re
import unicodedata
from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response

from app.db import get_supabase_client
from app.models import PropertyLoanIn, PropertyLoanUpdate
from app.security import require_user

router = APIRouter()

# Mots qui, dans un libellé bancaire, désignent une mensualité de prêt.
_LOAN_LABEL_PATTERN = re.compile(r"\b(pret|prets|credit|credits|emprunt|echeance|ech|immo|mensualite)\b")


def _plain(text: str | None) -> str:
    text = unicodedata.normalize("NFD", text or "")
    return "".join(c for c in text if unicodedata.category(c) != "Mn").lower()


def ensure_own_loan(client, user_id: str, loan_id: UUID | str | None) -> None:
    """Refuse de rattacher une opération au prêt de quelqu'un d'autre."""
    if not loan_id:
        return
    rows = (
        client.table("property_loans")
        .select("id")
        .eq("user_id", user_id)
        .eq("id", str(loan_id))
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(status_code=400, detail="Prêt introuvable")


def active_loans(client, user_id: str) -> list[dict]:
    return [
        loan
        for loan in client.table("property_loans")
        .select("id, property_name, monthly_payment, active")
        .eq("user_id", user_id)
        .execute()
        .data
        if loan.get("active", True)
    ]


# Catégories de consommation courante : une dépense ainsi classée n'est
# jamais rattachée à un prêt sur la seule base de son montant (un plein de
# courses de 350 € ne doit pas devenir la mensualité d'un prêt de 350 €).
_SPENDING_CATEGORIES = {"restaurant", "courses", "transport", "loisirs", "santé"}


def match_loan_for_payment(
    loans: list[dict], amount: float, label: str | None, hinted: bool = False, category: str | None = None
) -> str | None:
    """Prêt dont cette dépense est très probablement la mensualité, ou None.

    - Montant quasi identique à une mensualité (à 0,5 % près, 50 € minimum) :
      une coïncidence est très improbable, le rattachement est fait.
    - Sinon, si le libellé parle de prêt/crédit/échéance (ou si `hinted`,
      ex : catégorie "Crédit / prêt" choisie), une tolérance de 2 % suffit
      (assurance emprunteur, arrondis...).
    S'il reste plusieurs prêts possibles, on garde celui dont le nom apparaît
    dans le libellé ; sinon on ne rattache rien plutôt que de deviner."""
    if not loans or amount <= 0:
        return None
    plain_label = _plain(label)
    hinted = hinted or bool(_LOAN_LABEL_PATTERN.search(plain_label))
    amount_only_ok = category not in _SPENDING_CATEGORIES and not re.match(r"\s*(cb|carte)\b", plain_label)
    candidates = []
    for loan in loans:
        payment = float(loan["monthly_payment"])
        gap = abs(amount - payment)
        if (amount_only_ok and payment >= 50 and gap <= 0.005 * payment) or (hinted and gap <= 0.02 * payment):
            candidates.append(loan)
    if len(candidates) == 1:
        return candidates[0]["id"]
    def name_score(loan: dict) -> int:
        return sum(1 for word in _plain(loan["property_name"]).split() if len(word) >= 4 and word in plain_label)

    scored = sorted(((name_score(loan), loan) for loan in candidates), key=lambda pair: pair[0], reverse=True)
    if scored and scored[0][0] > 0 and (len(scored) == 1 or scored[0][0] > scored[1][0]):
        return scored[0][1]["id"]
    return None


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
    if not item.property_name.strip():
        raise HTTPException(status_code=400, detail="Le nom du prêt est obligatoire")
    payload = {
        "user_id": user_id,
        "property_name": item.property_name.strip(),
        "principal_amount": item.principal_amount,
        "annual_rate_pct": item.annual_rate_pct,
        "monthly_payment": item.monthly_payment,
        "start_date": item.start_date.isoformat(),
        "monthly_rent": item.monthly_rent,
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
        if value is None and key != "monthly_rent":
            continue  # null = pas touché (sauf le loyer, qu'on peut retirer)
        if isinstance(value, date):
            payload[key] = value.isoformat()
        elif isinstance(value, str):
            if not value.strip():
                raise HTTPException(status_code=400, detail="Le nom du prêt est obligatoire")
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
