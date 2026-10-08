"""Assistant vocal : analyse d'une phrase dictée (transaction, question, ou
modification d'une transaction déjà enregistrée) et confirmation d'une
action restée en doute."""

from fastapi import APIRouter, Depends, HTTPException

from app.config import EXPENSE_CATEGORIES, INCOME_CATEGORIES, today_paris
from app.db import get_supabase_client
from app.models import VoiceConfirmRequest, VoiceParseRequest, VoiceQuestionResult
from app.security import require_user
from app.voice_nlp import (
    _fetch_custom_categories,
    _finalize_edit_last,
    _finalize_transaction,
    _preview_edit_last,
    _VOICE_QUESTION_METRICS,
    call_claude_confirm,
    call_claude_extraction,
    compute_voice_answer,
    parse_french_period_expression,
)

router = APIRouter()


@router.post("/api/voice/parse", response_model=None)
def parse_voice_text(req: VoiceParseRequest, user_id: str = Depends(require_user)):
    client = get_supabase_client()
    custom = _fetch_custom_categories(client, user_id)
    expense_categories = EXPENSE_CATEGORIES | set(custom["expense"].keys())
    income_categories = INCOME_CATEGORIES | set(custom["income"].keys())

    data = call_claude_extraction(req.text, expense_categories, income_categories)

    if data.get("intent") == "question":
        metric = str(data.get("metric") or "").strip()
        if metric not in _VOICE_QUESTION_METRICS:
            return VoiceQuestionResult(
                answer="Je n'ai pas compris ta question, tu peux réessayer ?",
                metric="unknown",
                period_label="",
            )

        category = data.get("category")
        category = category.strip().lower() if isinstance(category, str) and category.strip() else None
        if metric == "earned":
            if category not in income_categories:
                category = None
        elif metric in ("spent", "budget_remaining"):
            if category not in expense_categories:
                category = None
        else:
            category = None

        raw_period_expression = data.get("raw_period_expression")
        raw_period_expression = raw_period_expression if isinstance(raw_period_expression, str) else None

        period = parse_french_period_expression(raw_period_expression, today_paris())

        # Les budgets et l'objectif d'épargne sont des notions "mensuelles"
        # sans historique propre (un seul montant, reconduit chaque mois) :
        # une question sur "cette année" ou "au total" n'a pas de sens pour
        # ces métriques, on retombe donc sur le mois en cours.
        if metric in ("budget_remaining", "budget_status", "savings_progress") and period["kind"] != "month":
            reference = today_paris()
            period = {
                "kind": "month",
                "month_key": f"{reference.year:04d}-{reference.month:02d}",
                "label": "ce mois-ci",
            }

        result = compute_voice_answer(metric, category, period, client, user_id)

        return VoiceQuestionResult(
            answer=result["answer"],
            metric=metric,
            category=category,
            period_label=period["label"],
            amount=result.get("amount"),
        )

    if data.get("intent") == "edit_last":
        if data.get("needs_confirmation"):
            return _preview_edit_last(data)
        return _finalize_edit_last(data, client, expense_categories, income_categories, custom, user_id)

    return _finalize_transaction(data, expense_categories, income_categories)


@router.post("/api/voice/confirm", response_model=None)
def confirm_voice_action(req: VoiceConfirmRequest, user_id: str = Depends(require_user)):
    client = get_supabase_client()
    custom = _fetch_custom_categories(client, user_id)
    expense_categories = EXPENSE_CATEGORIES | set(custom["expense"].keys())
    income_categories = INCOME_CATEGORIES | set(custom["income"].keys())

    if req.decision in ("confirm", "cancel"):
        # Bouton "Confirmer"/"Annuler" tapé directement : pas d'ambiguïté à
        # lever, pas besoin d'appeler l'IA.
        decision = req.decision
        updated = req.pending
    else:
        if not req.reply_text:
            raise HTTPException(status_code=422, detail="reply_text requis en l'absence de decision")
        decision_data = call_claude_confirm(req.reply_text, req.pending, expense_categories, income_categories)
        decision = decision_data.get("decision")
        updated = decision_data.get("updated") or req.pending

    if decision == "cancel":
        return {"decision": "cancel"}

    # Qu'il s'agisse d'une simple confirmation ou d'une correction, cette
    # réponse est la résolution du doute : on ne redemande jamais une
    # deuxième confirmation sur la foi de cette réponse-là.
    updated = dict(updated)
    updated["needs_confirmation"] = False

    if req.kind == "edit_last":
        return _finalize_edit_last(updated, client, expense_categories, income_categories, custom, user_id)
    return _finalize_transaction(updated, expense_categories, income_categories)
