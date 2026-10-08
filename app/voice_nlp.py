"""Assistant vocal : analyse déterministe des dates/périodes en français,
calcul des réponses aux questions sur les finances (toujours à partir des
vraies données, jamais inventé par l'IA), et extraction IA (API Anthropic)
qui transforme une phrase dictée en brouillon structuré.
"""

import json
import re
from datetime import date, timedelta

from fastapi import HTTPException

from app.config import ANTHROPIC_API_KEY, TransactionType, category_label, today_paris
from app.emails import _notify_admin_once
from app.models import VoiceEditResult, VoiceParseResult

# ---------------------------------------------------------------------------
# Analyse déterministe des expressions de date en français
# ---------------------------------------------------------------------------
# Important : l'IA ne doit JAMAIS calculer elle-même une date calendaire à
# partir d'une expression relative ("hier", "lundi prochain") — elle ne
# connaît pas la date du jour et se trompe. Elle se contente d'extraire
# l'expression telle quelle ; c'est cette fonction, déterministe, qui la
# convertit en vraie date, à partir de `today_paris()`.
_WEEKDAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]

_MONTHS = {
    "janvier": 1, "février": 2, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5,
    "juin": 6, "juillet": 7, "août": 8, "aout": 8, "septembre": 9,
    "octobre": 10, "novembre": 11, "décembre": 12, "decembre": 12,
}


def parse_french_date_expression(expr: str | None, reference: date) -> date | None:
    """Convertit une expression de date en français (dite à l'oral) en date
    réelle, de façon déterministe, par rapport à `reference` (= aujourd'hui).
    Retourne None si l'expression n'est pas reconnue (le code appelant doit
    alors utiliser `reference` par défaut plutôt que de deviner)."""
    if not expr:
        return None
    text = expr.strip().lower()
    text = text.replace("’", "'")

    if text in ("aujourd'hui", "aujourdhui", "ce jour"):
        return reference
    if text == "hier":
        return reference - timedelta(days=1)
    if text in ("avant-hier", "avant hier"):
        return reference - timedelta(days=2)
    if text == "demain":
        return reference + timedelta(days=1)
    if text in ("après-demain", "apres-demain", "après demain", "apres demain"):
        return reference + timedelta(days=2)

    m = re.match(r"^il y a (\d+) jours?$", text)
    if m:
        return reference - timedelta(days=int(m.group(1)))
    m = re.match(r"^il y a (\d+) semaines?$", text)
    if m:
        return reference - timedelta(weeks=int(m.group(1)))

    m = re.match(
        r"^(lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche)"
        r"(?:\s+(dernier|derni[eè]re|prochain|prochaine))?$",
        text,
    )
    if m:
        weekday_name, qualifier = m.group(1), m.group(2)
        target_weekday = _WEEKDAYS.index(weekday_name)
        delta = target_weekday - reference.weekday()
        if qualifier in ("prochain", "prochaine"):
            if delta <= 0:
                delta += 7
        else:
            # bare weekday ou "dernier" : occurrence la plus récente, aujourd'hui
            # inclus seulement pour un nom de jour sans qualificatif.
            if qualifier in ("dernier", "dernière", "derniere"):
                if delta >= 0:
                    delta -= 7
            else:
                if delta > 0:
                    delta -= 7
        return reference + timedelta(days=delta)

    # Date explicite "15 septembre" ou "15 septembre 2026"
    m = re.match(r"^(\d{1,2})(?:er)?\s+([a-zéû]+)(?:\s+(\d{4}))?$", text)
    if m and m.group(2) in _MONTHS:
        day = int(m.group(1))
        month = _MONTHS[m.group(2)]
        year = int(m.group(3)) if m.group(3) else reference.year
        try:
            candidate = date(year, month, day)
        except ValueError:
            return None
        if not m.group(3) and candidate > reference + timedelta(days=1):
            # Pas d'année précisée et la date tombe dans le futur : on suppose
            # qu'il s'agissait de l'année précédente (contexte : saisie de
            # dépenses passées, pas de planification future).
            try:
                candidate = date(year - 1, month, day)
            except ValueError:
                return None
        return candidate

    # Date numérique "15/09" ou "15/09/2026" (format français JJ/MM[/AAAA])
    m = re.match(r"^(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?$", text)
    if m:
        day, month = int(m.group(1)), int(m.group(2))
        if m.group(3):
            year = int(m.group(3))
            if year < 100:
                year += 2000
        else:
            year = reference.year
        try:
            candidate = date(year, month, day)
        except ValueError:
            return None
        if not m.group(3) and candidate > reference + timedelta(days=1):
            try:
                candidate = date(year - 1, month, day)
            except ValueError:
                return None
        return candidate

    return None


# ---------------------------------------------------------------------------
# Analyse déterministe des expressions de période (pour l'assistant vocal
# "question" — même principe que parse_french_date_expression ci-dessus :
# l'IA ne calcule JAMAIS elle-même une période, elle recopie l'expression
# telle quelle ; c'est cette fonction qui la convertit en bornes concrètes.
# ---------------------------------------------------------------------------
_MONTH_NAMES_FR = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
]


def parse_french_period_expression(expr: str | None, reference: date) -> dict:
    """Retourne {"kind": "month"|"year"|"all", "month_key"?, "year"?, "label"}.
    `label` est une expression française prête à insérer dans une phrase de
    réponse ("ce mois-ci", "le mois dernier", "cette année"...). Par défaut
    (expression absente ou non reconnue) : le mois en cours."""
    current_month_key = f"{reference.year:04d}-{reference.month:02d}"

    if not expr:
        return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}

    text = expr.strip().lower()
    text = text.replace("’", "'")
    text = re.sub(r"^(en|pour|sur|durant|pendant)\s+", "", text)

    if text in ("ce mois", "ce mois-ci", "ce mois ci"):
        return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}

    if text in (
        "le mois dernier", "mois dernier", "le mois précédent", "mois précédent",
        "le mois precedent", "mois precedent",
    ):
        prev_month = reference.month - 1 if reference.month > 1 else 12
        prev_year = reference.year if reference.month > 1 else reference.year - 1
        return {
            "kind": "month",
            "month_key": f"{prev_year:04d}-{prev_month:02d}",
            "label": "le mois dernier",
        }

    if text in ("cette année", "cette année-ci", "cette annee", "cette annee-ci"):
        return {"kind": "year", "year": str(reference.year), "label": "cette année"}

    if text in (
        "l'année dernière", "année dernière", "l'an dernier", "an dernier",
        "l'annee derniere", "annee derniere",
    ):
        return {"kind": "year", "year": str(reference.year - 1), "label": "l'année dernière"}

    if text in ("depuis le début", "depuis toujours", "au total", "depuis le debut", "toujours"):
        return {"kind": "all", "label": "au total"}

    # Mois explicite, avec ou sans année : "mars", "en mars 2026"
    m = re.match(r"^([a-zéû]+)(?:\s+(\d{4}))?$", text)
    if m and m.group(1) in _MONTHS:
        month = _MONTHS[m.group(1)]
        if m.group(2):
            year = int(m.group(2))
        else:
            year = reference.year
            if date(year, month, 1) > reference.replace(day=1):
                year -= 1
        month_name = _MONTH_NAMES_FR[month - 1]
        return {
            "kind": "month",
            "month_key": f"{year:04d}-{month:02d}",
            "label": f"en {month_name} {year}",
        }

    return {"kind": "month", "month_key": current_month_key, "label": "ce mois-ci"}


def filter_transactions_by_period(transactions: list[dict], period: dict) -> list[dict]:
    if period["kind"] == "all":
        return transactions
    if period["kind"] == "year":
        return [tx for tx in transactions if tx["expense_date"][:4] == period["year"]]
    return [tx for tx in transactions if tx["expense_date"][:7] == period["month_key"]]


def format_eur(amount: float) -> str:
    sign = "-" if amount < 0 else ""
    formatted = f"{abs(amount):,.2f}".replace(",", " ").replace(".", ",")
    return f"{sign}{formatted} €"


def compute_voice_answer(metric: str, category: str | None, period: dict, client, user_id: str) -> dict:
    """Calcule la réponse à une question vocale à partir des vraies données
    (jamais inventée par l'IA). Retourne {"answer": str, "amount": float|None}."""
    period_label = period["label"]
    transactions = (
        client.table("transactions")
        .select("type, amount, category, expense_date")
        .eq("user_id", user_id)
        .execute()
        .data
    )

    if metric == "spent":
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "expense"
        ]
        if category:
            filtered = [tx for tx in filtered if tx["category"] == category]
        total = sum(float(tx["amount"]) for tx in filtered)
        if category:
            cat_label = category_label(category, "expense")
            answer = f"Tu as dépensé {format_eur(total)} en {cat_label.lower()} {period_label}."
        else:
            answer = f"Tu as dépensé {format_eur(total)} {period_label}."
        return {"answer": answer, "amount": total}

    if metric == "earned":
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "income"
        ]
        if category:
            filtered = [tx for tx in filtered if tx["category"] == category]
        total = sum(float(tx["amount"]) for tx in filtered)
        if category:
            cat_label = category_label(category, "income")
            answer = f"Tu as gagné {format_eur(total)} en {cat_label.lower()} {period_label}."
        else:
            answer = f"Tu as gagné {format_eur(total)} {period_label}."
        return {"answer": answer, "amount": total}

    if metric == "balance":
        filtered = filter_transactions_by_period(transactions, period)
        spent = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "expense")
        earned = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "income")
        balance = earned - spent
        detail = f"{format_eur(earned)} de revenus pour {format_eur(spent)} de dépenses"
        if balance >= 0:
            answer = f"Ton solde est positif de {format_eur(balance)} {period_label} ({detail})."
        else:
            answer = f"Ton solde est négatif de {format_eur(abs(balance))} {period_label} ({detail})."
        return {"answer": answer, "amount": balance}

    if metric == "budget_remaining":
        if not category:
            return {
                "answer": "Précise une catégorie pour que je te dise où tu en es sur son budget.",
                "amount": None,
            }
        budgets = (
            client.table("budgets")
            .select("*")
            .eq("user_id", user_id)
            .eq("category", category)
            .execute()
            .data
        )
        cat_label = category_label(category, "expense")
        if not budgets:
            return {"answer": f"Tu n'as pas encore défini de budget pour {cat_label.lower()}.", "amount": None}
        budget_amount = float(budgets[0]["amount"])
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period)
            if tx["type"] == "expense" and tx["category"] == category
        ]
        spent = sum(float(tx["amount"]) for tx in filtered)
        remaining = budget_amount - spent
        if remaining >= 0:
            answer = (
                f"Il te reste {format_eur(remaining)} sur ton budget {cat_label.lower()} {period_label} "
                f"(sur {format_eur(budget_amount)})."
            )
        else:
            answer = (
                f"Tu as dépassé ton budget {cat_label.lower()} de {format_eur(abs(remaining))} "
                f"{period_label} (budget de {format_eur(budget_amount)})."
            )
        return {"answer": answer, "amount": remaining}

    if metric == "budget_status":
        budgets = client.table("budgets").select("*").eq("user_id", user_id).execute().data
        if not budgets:
            return {"answer": "Tu n'as pas encore défini de budget pour tes catégories.", "amount": None}
        filtered = [
            tx for tx in filter_transactions_by_period(transactions, period) if tx["type"] == "expense"
        ]
        totals: dict[str, float] = {}
        for tx in filtered:
            totals[tx["category"]] = totals.get(tx["category"], 0.0) + float(tx["amount"])
        over = []
        for b in budgets:
            spent = totals.get(b["category"], 0.0)
            over_amount = spent - float(b["amount"])
            if over_amount > 0:
                over.append((category_label(b["category"], "expense"), over_amount))
        if not over:
            answer = f"Aucun dépassement de budget {period_label} — bien joué !"
        else:
            over.sort(key=lambda pair: pair[1], reverse=True)
            parts = [f"{label} (+{format_eur(amt)})" for label, amt in over]
            answer = f"Tu dépasses ton budget {period_label} sur : {', '.join(parts)}."
        return {"answer": answer, "amount": None}

    if metric == "savings_progress":
        goal_rows = (
            client.table("savings_goal")
            .select("*")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if not goal_rows:
            return {"answer": "Tu n'as pas encore défini d'objectif d'épargne mensuel.", "amount": None}
        target = float(goal_rows[0]["monthly_target"])
        filtered = filter_transactions_by_period(transactions, period)
        spent = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "expense")
        earned = sum(float(tx["amount"]) for tx in filtered if tx["type"] == "income")
        net = earned - spent
        if net >= target:
            answer = (
                f"Objectif atteint ! Tu as économisé {format_eur(net)} {period_label}, "
                f"pour un objectif de {format_eur(target)}."
            )
        elif net > 0:
            answer = (
                f"Tu as économisé {format_eur(net)} {period_label}, il te manque "
                f"{format_eur(target - net)} pour atteindre ton objectif de {format_eur(target)}."
            )
        else:
            answer = (
                f"Tu es en négatif de {format_eur(abs(net))} {period_label} : impossible d'épargner "
                f"pour l'instant (objectif : {format_eur(target)})."
            )
        return {"answer": answer, "amount": net}

    return {"answer": "Je n'ai pas compris ta question, tu peux réessayer ?", "amount": None}


# ---------------------------------------------------------------------------
# Extraction IA (API Anthropic) — transforme une phrase dictée en brouillon
# structuré, soit une transaction à enregistrer, soit une question sur ses
# finances. Ne touche jamais la base pour une transaction : c'est le frontend
# qui décide ensuite d'appeler POST ou PUT sur /api/transactions avec le
# résultat. Pour une question, en revanche, le calcul se fait ici même,
# côté serveur, à partir des vraies données — jamais inventé par l'IA.
# ---------------------------------------------------------------------------

# Mots de liaison français à retirer d'une description dictée à la voix (ex:
# "au casino" -> "casino", "gains au casino" -> "gains casino"), pour que les
# descriptions restent courtes et cohérentes avec le regroupement par
# mots-clés fait côté frontend (voir extractDescriptionKeywords dans
# frontend/index.html, qui ignore la même liste). On ne touche jamais une
# description saisie manuellement : uniquement celle que l'IA vocale extrait
# ci-dessous, une description tapée au clavier reflète un choix délibéré de
# l'utilisateur.
_DESCRIPTION_STOPWORDS = {
    "a", "à", "au", "aux", "de", "du", "des", "d", "le", "la", "les", "l",
    "un", "une", "ce", "cet", "cette", "ces", "mon", "ma", "mes",
    "ton", "ta", "tes", "son", "sa", "ses", "notre", "nos", "votre",
    "vos", "leur", "leurs", "chez", "sur", "dans", "pour", "avec",
    "et", "ou", "en", "par",
}


def _strip_description_stopwords(description: str) -> str:
    words = description.split()
    kept = [w for w in words if w.lower().strip(".,!?;:'\"-") not in _DESCRIPTION_STOPWORDS]
    cleaned = " ".join(kept)
    return cleaned or description  # si tout a été retiré (rare), on garde l'original


_VOICE_SYSTEM_PROMPT_TEMPLATE = """Tu analyses une phrase dictée à l'oral en français, qui concerne les finances personnelles de l'utilisateur. Elle est de l'une de ces trois natures :

1. Une dépense ou un revenu à enregistrer, ou une correction d'une transaction qui vient tout juste d'être dictée (la phrase précédente).
2. Une question sur ses finances (combien il a dépensé, où il en est sur un budget, son solde, son épargne...).
3. Une demande de modifier le TYPE et/ou la CATÉGORIE d'une transaction déjà enregistrée, désignée par position plutôt que redictée en entier (ex: "change la dernière dépense en revenu", "mets la dernière dépense dans la catégorie restaurant", "le dernier revenu, c'est en fait des freelance").

Si la phrase est interrogative — ou commence par des mots comme "combien", "quel", "quelle", "est-ce que", "comment", "où en est", "ai-je", "suis-je", "me reste-t-il", "qu'est-ce que" — c'est TOUJOURS une question (intent="question"), jamais une transaction, même si elle mentionne un montant ou une catégorie.

Si la phrase désigne une transaction déjà enregistrée par sa position ("la dernière dépense", "le dernier revenu", "la dernière transaction") SANS redicter de montant, c'est TOUJOURS intent="edit_last", jamais "transaction" — même si elle contient un mot comme "change" ou "corrige".

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon l'un de ces trois schémas :

### Si intent = "transaction"
{
  "intent": "transaction",
  "type": "expense" ou "income" — détermine-le UNIQUEMENT à partir du verbe qui décrit l'argent qui bouge (gagné/reçu/touché = income ; dépensé/payé/perdu = expense). Une phrase dictée à l'oral contient parfois, en plus, une instruction du type "mets-la/classe-la/range-la dans la catégorie X" pour préciser la catégorie : ignore cette partie pour le type, elle ne sert qu'à choisir "category", jamais à décider "expense" ou "income". Attention aussi aux approximations de reconnaissance vocale : "mets"/"met"/"mettez" (verbe mettre, utilisé dans cette instruction de catégorie) peuvent être mal transcrits en un mot proche phonétiquement comme "mais" — ne les confonds jamais avec une dépense,
  "amount": nombre (toujours positif),
  "category": une chaîne parmi __EXPENSE_CATEGORIES__ (si type=expense) ou __INCOME_CATEGORIES__ (si type=income) — cette liste inclut les catégories par défaut ET les catégories personnalisées déjà créées par l'utilisateur. Si la phrase contient une instruction explicite du genre "mets-la/classe-la/range-la dans la catégorie X", utilise X en priorité (en la faisant correspondre à la liste). Sinon, si une catégorie personnalisée correspond clairement au sujet de la phrase (ex: une catégorie "casino" existe et la phrase parle du casino), utilise-la plutôt que "autre",
  "raw_date_expression": l'expression de date EXACTEMENT telle que prononcée (ex: "hier", "lundi dernier", "le 3 septembre"), ou null si aucune date n'est mentionnée,
  "description": une description courte (sans le montant ni la date), construite UNIQUEMENT à partir des mots-clés réellement prononcés (ex: "j'ai perdu 40 euros au casino" -> "casino", PAS "perte casino" : n'invente pas un nom comme "perte" ou "gain" à partir d'un verbe ("j'ai perdu", "j'ai gagné") s'il n'a pas été prononcé tel quel), ou null si rien de pertinent à part la catégorie,
  "is_correction": true seulement si la phrase exprime explicitement une intention de corriger une transaction déjà enregistrée (ex: "corrige", "en fait c'était plutôt", "change le montant de..."), false dans tous les autres cas, y compris si la phrase ressemble à une dépense déjà saisie,
  "is_recurring": true si la phrase indique explicitement qu'il s'agit d'une charge qui se répète chaque mois (mots comme "récurrent", "récurrence", "abonnement", "tous les mois", "chaque mois", "mensuel"), false sinon,
  "needs_confirmation": true UNIQUEMENT si tu as un doute réel sur l'interprétation (montant approximatif ou peu clair, catégorie devinée sans élément solide, structure de phrase bizarre ou ambiguë, plusieurs lectures possibles) ; false si l'interprétation est claire et directe — ne mets pas true par excès de prudence, seulement en cas de doute véritable
}

### Si intent = "question"
{
  "intent": "question",
  "metric": une chaîne parmi :
    - "spent" : combien a été dépensé (au total, ou dans une catégorie précise) sur une période,
    - "earned" : combien a été gagné/reçu (au total, ou dans une catégorie précise) sur une période,
    - "balance" : le solde (revenus moins dépenses) sur une période,
    - "budget_remaining" : combien il reste sur le budget d'une catégorie précise, ce mois-ci,
    - "budget_status" : quelles catégories dépassent leur budget, ce mois-ci,
    - "savings_progress" : où en est l'utilisateur par rapport à son objectif d'épargne mensuel,
  "category": une chaîne parmi __ALL_CATEGORIES__ (celle qui est pertinente pour la question, catégories personnalisées incluses), ou null si la question ne porte pas sur une catégorie précise,
  "raw_period_expression": l'expression de période EXACTEMENT telle que prononcée (ex: "ce mois-ci", "le mois dernier", "cette année", "l'année dernière", "en septembre", "depuis le début"), ou null si aucune période n'est mentionnée (le mois en cours sera utilisé par défaut)
}

### Si intent = "edit_last"
{
  "intent": "edit_last",
  "target": "last_expense" (la dernière dépense) ou "last_income" (le dernier revenu) ou "last_transaction" (la dernière transaction tout court, sans préciser dépense ou revenu),
  "new_type": "expense" ou "income" si la phrase demande explicitement de changer le type (ex: "change cette dépense en revenu"), sinon null,
  "new_category": une chaîne parmi __ALL_CATEGORIES__ si la phrase demande explicitement de changer la catégorie (ex: "mets-la dans la catégorie restaurant", "c'est en fait du freelance"), sinon null,
  "needs_confirmation": true UNIQUEMENT si tu as un doute réel (la cible "last_expense"/"last_income"/"last_transaction" n'est pas claire, la nouvelle catégorie demandée ne correspond à rien de connu, phrase ambiguë) ; false si c'est clair
}
Si la phrase ne précise ni nouveau type ni nouvelle catégorie de façon exploitable, laisse les deux à null plutôt que d'inventer une valeur — un système déterministe gère ce cas côté serveur.

RÈGLES IMPORTANTES :
- N'essaie JAMAIS de calculer toi-même un montant, une date calendaire ou une période à partir d'une expression relative. Tu ne connais ni le solde de l'utilisateur ni la date du jour. Recopie les expressions telles quelles ; un système déterministe s'occupe de tous les calculs à partir des vraies données.
- Si la phrase ne mentionne aucune date (transaction) ou aucune période (question), le champ correspondant doit être null.
- is_correction doit rester false par défaut : en cas de doute, considère qu'il s'agit d'une nouvelle transaction plutôt que d'une correction.
- is_recurring doit rester false par défaut : ne le mets à true que si la récurrence est clairement exprimée à l'oral, jamais par déduction (ex: "le loyer" seul ne suffit pas, il faut un mot indiquant explicitement la répétition)."""


def _fetch_custom_categories(client, user_id: str) -> dict[str, dict[str, str]]:
    """Catégories personnalisées créées par l'utilisateur (bandeau de
    suggestion ou formulaire manuel), par type, sous forme {value: label}.
    Nécessaires pour que l'IA vocale puisse les proposer elle-même au lieu de
    toujours retomber sur "autre" pour une catégorie qu'elle ne connaît pas,
    et pour afficher un libellé lisible (pas juste le slug) dans les
    confirmations vocales."""
    rows = (
        client.table("custom_categories")
        .select("type, value, label")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    result: dict[str, dict[str, str]] = {"expense": {}, "income": {}}
    for row in rows:
        t = row.get("type")
        if t in result:
            result[t][row["value"]] = row["label"]
    return result


def _build_voice_system_prompt(expense_categories: set[str], income_categories: set[str]) -> str:
    all_categories = sorted(expense_categories | income_categories)
    return (
        _VOICE_SYSTEM_PROMPT_TEMPLATE
        .replace("__EXPENSE_CATEGORIES__", ", ".join(sorted(expense_categories)))
        .replace("__INCOME_CATEGORIES__", ", ".join(sorted(income_categories)))
        .replace("__ALL_CATEGORIES__", ", ".join(all_categories))
    )


def call_claude_extraction(text: str, expense_categories: set[str], income_categories: set[str]) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Configuration manquante : ANTHROPIC_API_KEY",
        )
    from anthropic import Anthropic

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            system=_build_voice_system_prompt(expense_categories, income_categories),
            messages=[{"role": "user", "content": text}],
        )
    except Exception as exc:  # noqa: BLE001
        _notify_admin_once(
            "anthropic_api_failure",
            "⚠️ Kaching — l'IA ne répond plus",
            f"<p>L'appel à l'API Anthropic a échoué (plus de crédit, clé invalide, panne du "
            f"service...). Détail technique :</p><pre>{exc}</pre>",
        )
        raise HTTPException(
            status_code=502,
            detail="Le service de reconnaissance vocale est temporairement indisponible, réessaie plus tard.",
        ) from exc

    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    # Au cas où le modèle entoure sa réponse de ```json ... ``` malgré la consigne.
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}"
        ) from exc
    return data


_VOICE_QUESTION_METRICS = {
    "spent", "earned", "balance", "budget_remaining", "budget_status", "savings_progress",
}


def _finalize_transaction(data: dict, expense_categories: set[str], income_categories: set[str]) -> VoiceParseResult:
    """Valide et finalise un objet "transaction" (venant soit directement de
    l'IA, soit d'une correction après une bannière de confirmation) en un
    VoiceParseResult prêt à être renvoyé au frontend — qui se charge ensuite
    lui-même de l'enregistrer (POST/PUT /api/transactions)."""
    tx_type: TransactionType = "income" if data.get("type") == "income" else "expense"

    try:
        amount = float(data.get("amount"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Montant non reconnu dans la phrase")

    category = str(data.get("category") or "autre").strip().lower()
    allowed = income_categories if tx_type == "income" else expense_categories
    if category not in allowed:
        category = "autre"

    description = data.get("description")
    description = description.strip() if isinstance(description, str) and description.strip() else None
    if description:
        description = _strip_description_stopwords(description)

    raw_date_expression = data.get("raw_date_expression")
    raw_date_expression = raw_date_expression if isinstance(raw_date_expression, str) else None

    reference = today_paris()
    parsed_date = parse_french_date_expression(raw_date_expression, reference)
    expense_date = parsed_date or reference

    is_correction = bool(data.get("is_correction", False))
    is_recurring = bool(data.get("is_recurring", False))

    return VoiceParseResult(
        type=tx_type,
        amount=amount,
        category=category,
        description=description,
        expense_date=expense_date,
        is_correction=is_correction,
        is_recurring=is_recurring,
        raw_date_expression=raw_date_expression,
        needs_confirmation=bool(data.get("needs_confirmation", False)),
    )


def _preview_edit_last(data: dict) -> VoiceEditResult:
    """Aucune écriture en base : juste de quoi afficher une bannière de
    confirmation côté frontend (qui retrouve lui-même la transaction ciblée
    dans sa liste déjà chargée pour donner du contexte)."""
    return VoiceEditResult(
        answer="",
        pending=True,
        target=data.get("target"),
        requested_new_type=data.get("new_type"),
        requested_new_category=data.get("new_category"),
    )


def _finalize_edit_last(
    data: dict, client, expense_categories: set[str], income_categories: set[str], custom: dict, user_id: str
) -> VoiceEditResult:
    target = data.get("target")
    if target not in ("last_expense", "last_income", "last_transaction"):
        return VoiceEditResult(answer="Je n'ai pas compris quelle transaction modifier, tu peux réessayer ?")

    query = (
        client.table("transactions")
        .select("*")
        .eq("user_id", user_id)
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
    )
    if target == "last_expense":
        query = query.eq("type", "expense")
    elif target == "last_income":
        query = query.eq("type", "income")
    rows = query.limit(1).execute().data
    if not rows:
        return VoiceEditResult(answer="Je n'ai trouvé aucune transaction correspondante à modifier.")
    tx = rows[0]

    new_type = data.get("new_type")
    new_type = new_type if new_type in ("expense", "income") else None
    final_type: TransactionType = new_type or tx["type"]

    new_category = data.get("new_category")
    new_category = new_category.strip().lower() if isinstance(new_category, str) and new_category.strip() else None
    final_allowed = income_categories if final_type == "income" else expense_categories
    if new_category and new_category not in final_allowed:
        # Catégorie non reconnue (mal transcrite, inventée...) : on
        # l'ignore plutôt que de planter ou d'enregistrer n'importe quoi.
        new_category = None

    update_payload: dict = {}
    if new_type and new_type != tx["type"]:
        update_payload["type"] = new_type
        # Une catégorie de dépense n'a généralement aucun sens côté
        # revenu (et inversement) : si le type change sans nouvelle
        # catégorie valide donnée, on retombe sur "autre" plutôt que de
        # garder une catégorie qui n'existe pas pour ce type.
        if not new_category and tx["category"] not in final_allowed:
            update_payload["category"] = "autre"
    if new_category:
        update_payload["category"] = new_category

    if not update_payload:
        return VoiceEditResult(
            answer="Je n'ai rien trouvé de concret à changer (ni nouveau type, ni nouvelle catégorie reconnue).",
            transaction_id=tx["id"],
            type=tx["type"],
            category=tx["category"],
            amount=tx["amount"],
        )

    result = (
        client.table("transactions")
        .update(update_payload)
        .eq("id", tx["id"])
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    updated = result.data[0]

    label = category_label(updated["category"], updated["type"]) if updated["category"] not in custom.get(updated["type"], {}) else custom[updated["type"]][updated["category"]]
    type_label = "revenu" if updated["type"] == "income" else "dépense"
    answer = f"C'est fait : {format_eur(updated['amount'])} classé en {type_label} / {label}."

    return VoiceEditResult(
        answer=answer,
        transaction_id=updated["id"],
        type=updated["type"],
        category=updated["category"],
        amount=updated["amount"],
    )


_VOICE_CONFIRM_SYSTEM_PROMPT_TEMPLATE = """L'application de finances de l'utilisateur avait compris l'action suivante, mais avait un doute et lui a demandé confirmation à l'oral :

__PENDING_JSON__

L'utilisateur vient de répondre à l'oral pour confirmer, annuler, ou corriger cette action. Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour :

{
  "decision": "confirm" si la réponse confirme que c'est bien ça (ex: "oui", "oui c'est ça", "c'est bon", "exact", "vas-y"),
             "cancel" si la réponse annule/refuse sans donner de correction exploitable (ex: "non", "annule", "laisse tomber", "non rien"),
             "correction" si la réponse indique explicitement ce qui doit changer,
  "updated": uniquement si decision="correction" — une copie EXACTE de l'objet ci-dessus (mêmes clés, mêmes types) avec UNIQUEMENT les champs mentionnés par la correction modifiés, tous les autres recopiés à l'identique. Absent sinon.
}

Catégories de dépense valables : __EXPENSE_CATEGORIES__
Catégories de revenu valables : __INCOME_CATEGORIES__"""


def call_claude_confirm(reply_text: str, pending: dict, expense_categories: set[str], income_categories: set[str]) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : ANTHROPIC_API_KEY")
    from anthropic import Anthropic

    system = (
        _VOICE_CONFIRM_SYSTEM_PROMPT_TEMPLATE
        .replace("__PENDING_JSON__", json.dumps(pending, ensure_ascii=False, default=str))
        .replace("__EXPENSE_CATEGORIES__", ", ".join(sorted(expense_categories)))
        .replace("__INCOME_CATEGORIES__", ", ".join(sorted(income_categories)))
    )

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            system=system,
            messages=[{"role": "user", "content": reply_text}],
        )
    except Exception as exc:  # noqa: BLE001
        _notify_admin_once(
            "anthropic_api_failure",
            "⚠️ Kaching — l'IA ne répond plus",
            f"<p>L'appel à l'API Anthropic a échoué (plus de crédit, clé invalide, panne du "
            f"service...). Détail technique :</p><pre>{exc}</pre>",
        )
        raise HTTPException(
            status_code=502,
            detail="Le service de reconnaissance vocale est temporairement indisponible, réessaie plus tard.",
        ) from exc

    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}") from exc
