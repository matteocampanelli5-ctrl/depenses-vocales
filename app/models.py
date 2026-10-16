"""Tous les modèles Pydantic de l'API, regroupés dans un seul module pour
éviter les imports circulaires entre routeurs (plusieurs routeurs partagent
parfois le même modèle, ex: TransactionType)."""

from datetime import date
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.config import MAX_GENERIC_IMPORT_ENTRIES, TransactionType

AccountKind = Literal["bank", "savings", "investment", "other"]

# ---------------------------------------------------------------------------
# Comptes — inscription (sur invitation uniquement), connexion, mot de passe
# oublié, vérification d'email, génération d'invitations
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    invite_token: str = Field(min_length=1)
    email: str = Field(min_length=3)
    username: str = Field(min_length=2, max_length=40)
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=1)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class InviteRequest(BaseModel):
    email: str | None = None


# ---------------------------------------------------------------------------
# Modèles de données
# ---------------------------------------------------------------------------
# `account_id` : le compte d'où part l'argent (dépense) ou où il arrive
# (revenu). `transfer_account_id` : renseigné uniquement pour un virement
# entre deux comptes de l'utilisateur — c'est l'autre compte (destination
# pour une sortie, provenance pour une entrée). Un virement n'est ni une
# dépense ni un revenu : il est exclu de tous les totaux.
class TransactionIn(BaseModel):
    type: TransactionType = "expense"
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None
    expense_date: date | None = None  # None => aujourd'hui (Europe/Paris)
    account_id: UUID | None = None
    transfer_account_id: UUID | None = None
    # Prêt de l'onglet Prêts que cette opération rembourse (mensualité).
    loan_id: UUID | None = None


class TransactionUpdate(BaseModel):
    type: TransactionType | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    description: str | None = None
    expense_date: date | None = None
    # Nullables explicitement : envoyer null retire le compte / annule le
    # statut de virement (contrairement aux champs ci-dessus où null veut
    # juste dire "pas touché").
    account_id: UUID | None = None
    transfer_account_id: UUID | None = None
    loan_id: UUID | None = None


# ---------------------------------------------------------------------------
# Comptes (banques, livrets, placements) et soldes relevés
# ---------------------------------------------------------------------------
class AccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    kind: AccountKind = "bank"
    # Taux annuel attendu, utile pour la projection d'un livret ou d'un
    # placement (ex: Livret A). Facultatif.
    annual_rate_pct: float | None = Field(default=None, ge=0, le=100)


class AccountUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=60)
    kind: AccountKind | None = None
    annual_rate_pct: float | None = Field(default=None, ge=0, le=100)
    active: bool | None = None


class AccountBalanceIn(BaseModel):
    balance_date: date
    balance: float = Field(ge=-100_000_000, le=100_000_000)


# Historique de patrimoine "déclaré" (ex: les relevés Endettement /
# Patrimoine de Boursorama) : une série à part, indépendante des comptes,
# pour ne jamais compter deux fois une dette déjà suivie dans Prêts.
class NetWorthSnapshotIn(BaseModel):
    snapshot_date: date
    assets: float = Field(ge=0, le=1_000_000_000)
    debts: float = Field(ge=0, le=1_000_000_000)
    label: str | None = Field(default=None, max_length=60)


class RecurringExpenseIn(BaseModel):
    type: TransactionType = "expense"
    name: str = Field(min_length=1)
    amount: float = Field(gt=0)
    category: str = "autre"
    day_of_month: int = Field(ge=1, le=31)
    start_date: date | None = None  # None => pas de date de début, compte dès maintenant
    end_date: date | None = None  # None => pas de date de fin, se répète indéfiniment


class RecurringExpenseUpdate(BaseModel):
    type: TransactionType | None = None
    name: str | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    day_of_month: int | None = Field(default=None, ge=1, le=31)
    start_date: date | None = None
    end_date: date | None = None
    essentiality_rating: int | None = Field(default=None, ge=1, le=5)


class CustomCategoryIn(BaseModel):
    type: TransactionType = "expense"
    value: str = Field(min_length=1)
    label: str = Field(min_length=1)


class DismissedSuggestionIn(BaseModel):
    key: str = Field(min_length=1)


class BudgetIn(BaseModel):
    category: str = Field(min_length=1)
    amount: float = Field(gt=0)


class SavingsGoalIn(BaseModel):
    monthly_target: float = Field(gt=0)


class CategoryRatingIn(BaseModel):
    category: str = Field(min_length=1)
    rating: int = Field(ge=1, le=5)


# Prêts (immobilier ou tout autre crédit) : seules 4 valeurs sont stockées
# (capital emprunté, taux, mensualité, date de départ) — l'amortissement
# (intérêts, capital restant dû...) est recalculé à la volée côté frontend à
# partir de ces 4 valeurs, exactement comme la simulation de placement.
# `property_name` garde son nom historique mais contient le nom du prêt (un
# bien immobilier, "Prêt étudiant", "Crédit auto"...). `monthly_rent` :
# loyer mensuel perçu quand le prêt finance un bien loué, facultatif.
class PropertyLoanIn(BaseModel):
    property_name: str = Field(min_length=1, max_length=80)
    principal_amount: float = Field(gt=0)
    annual_rate_pct: float = Field(ge=0, le=100)
    monthly_payment: float = Field(gt=0)
    start_date: date
    monthly_rent: float | None = Field(default=None, ge=0)


class PropertyLoanUpdate(BaseModel):
    property_name: str | None = Field(default=None, min_length=1, max_length=80)
    principal_amount: float | None = Field(default=None, gt=0)
    annual_rate_pct: float | None = Field(default=None, ge=0, le=100)
    monthly_payment: float | None = Field(default=None, gt=0)
    start_date: date | None = None
    active: bool | None = None
    monthly_rent: float | None = Field(default=None, ge=0)


class VoiceParseRequest(BaseModel):
    text: str = Field(min_length=1)


class VoiceParseResult(BaseModel):
    intent: str = "transaction"
    type: TransactionType
    amount: float
    category: str
    description: str | None
    expense_date: date
    is_correction: bool
    is_recurring: bool
    raw_date_expression: str | None
    # Virement dicté entre deux comptes de l'utilisateur ("j'ai mis 200 € sur
    # mon Livret A") : ni dépense ni revenu. account_id = compte de départ
    # (ou d'arrivée pour un type "income"), transfer_account_id = l'autre.
    is_transfer: bool = False
    account_id: str | None = None
    transfer_account_id: str | None = None
    transfer_label: str | None = None
    # True si l'IA a un doute réel sur l'interprétation (montant approximatif,
    # catégorie incertaine, phrase ambiguë...) : le frontend doit alors
    # demander confirmation au lieu d'enregistrer directement.
    needs_confirmation: bool = False


class VoiceQuestionResult(BaseModel):
    """Réponse à une question posée à l'oral sur ses finances (ex: "combien
    j'ai dépensé en restaurant ce mois-ci ?"). `answer` est la phrase à
    afficher/prononcer ; `amount` est le nombre brut correspondant quand il a
    un sens (None pour budget_status, par exemple, qui liste des catégories)."""

    intent: str = "question"
    answer: str
    metric: str
    category: str | None = None
    period_label: str
    amount: float | None = None


class VoiceEditResult(BaseModel):
    """Résultat d'une modification vocale d'une transaction déjà enregistrée,
    désignée par position ("la dernière dépense", "le dernier revenu"), sans
    redicter son montant. `answer` est la phrase de confirmation à
    afficher/prononcer. Les champs de la transaction mise à jour sont inclus
    pour que le frontend puisse rafraîchir l'affichage sans requête de plus."""

    intent: str = "edit_last"
    answer: str
    # True si la modification n'a PAS encore été appliquée (doute de l'IA) :
    # le frontend doit alors afficher une bannière de confirmation plutôt que
    # de considérer que c'est déjà fait. Dans ce cas, transaction_id/type/
    # category/amount ci-dessous ne sont pas renseignés — seuls target/
    # requested_new_type/requested_new_category le sont (ce que l'IA a
    # compris vouloir changer, pas encore validé).
    pending: bool = False
    target: str | None = None
    requested_new_type: str | None = None
    requested_new_category: str | None = None
    transaction_id: str | None = None
    type: TransactionType | None = None
    category: str | None = None
    amount: float | None = None


class VoiceConfirmRequest(BaseModel):
    """Réponse (vocale ou par bouton) à une bannière de confirmation affichée
    côté frontend. `pending` est repris tel quel depuis ce que /api/voice/parse
    avait renvoyé (ou une version simplifiée pour edit_last — voir le
    frontend). `reply_text` est rempli pour une réponse vocale (interprétée
    par l'IA) ; `decision` est rempli directement pour un bouton Confirmer/
    Annuler (aucun appel IA nécessaire dans ce cas, c'est explicite)."""

    kind: str
    pending: dict
    reply_text: str | None = None
    decision: str | None = None  # "confirm" ou "cancel", si rempli directement par un bouton


# ---------------------------------------------------------------------------
# Import générique par IA (tout fichier .csv/.xlsx, structure quelconque)
# ---------------------------------------------------------------------------
class GenericImportCommitTransaction(BaseModel):
    expense_date: date
    type: TransactionType
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None
    transfer_account_id: UUID | None = None
    loan_id: UUID | None = None


class GenericImportCommitRecurring(BaseModel):
    type: TransactionType = "expense"
    name: str = Field(min_length=1)
    amount: float = Field(gt=0)
    category: str = "autre"
    day_of_month: int = Field(default=1, ge=1, le=31)
    start_date: date | None = None
    end_date: date | None = None


class GenericImportCommitRequest(BaseModel):
    # Compte auquel appartient le relevé importé (toutes les lignes) —
    # facultatif.
    account_id: UUID | None = None
    transactions: list[GenericImportCommitTransaction] = Field(
        default_factory=list, max_length=MAX_GENERIC_IMPORT_ENTRIES
    )
    recurring: list[GenericImportCommitRecurring] = Field(default_factory=list, max_length=50)


# ---------------------------------------------------------------------------
# Import d'un classeur onglet par onglet (prêts et historique de patrimoine,
# lus en code — les onglets mensuels passent par l'import générique)
# ---------------------------------------------------------------------------
class WorkbookLoanIn(PropertyLoanIn):
    active: bool = True


class WorkbookCommitRequest(BaseModel):
    loans: list[WorkbookLoanIn] = Field(default_factory=list, max_length=50)
    snapshots: list[NetWorthSnapshotIn] = Field(default_factory=list, max_length=2000)

