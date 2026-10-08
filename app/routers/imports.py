"""Import de relevés — un routeur dédié (déviation mineure par rapport au
plan de découpage initial, qui ne listait pas de routeur "imports" à part :
jugé plus clair de séparer ce bloc de ~750 lignes de transactions.py/
recurring.py plutôt que de l'y noyer).

Deux mécanismes distincts :
  1. Import de relevé bancaire (CSV export BoursoBank) — colonnes fixes
     connues à l'avance, parsées déterministement (sans IA).
  2. Import générique par IA (tout fichier .csv/.xlsx, structure quelconque)
     — contrairement à (1), ici le contenu brut du fichier est envoyé à
     l'IA qui le réinterprète elle-même. La détection récurrent / crédit /
     déjà-terminé, elle, reste déterministe côté serveur (voir
     _detect_recurring_patterns).
"""

import calendar
import csv
import json
import re
import unicodedata
from datetime import date
from io import BytesIO, StringIO

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.config import (
    ANTHROPIC_API_KEY,
    EXPENSE_CATEGORIES,
    INCOME_CATEGORIES,
    MAX_GENERIC_IMPORT_ENTRIES,
    TransactionType,
    category_label,
    today_paris,
)
from app.db import get_supabase_client
from app.emails import _notify_admin_once
from app.models import BankImportCommitRequest, GenericImportCommitRequest
from app.routers.recurring import _clamp_day, _month_add
from app.security import require_user
from app.voice_nlp import _fetch_custom_categories

router = APIRouter()


# ---------------------------------------------------------------------------
# Import de relevé bancaire (CSV export BoursoBank)
# ---------------------------------------------------------------------------
# Format ciblé pour l'instant : export "export-operations-....CSV" de
# BoursoBank — ";" comme séparateur, BOM UTF-8, et une bizarrerie de cet
# export : DEUX colonnes s'appellent toutes les deux "Solde" dans l'en-tête.
# La première est en réalité le MONTANT signé de l'opération (négatif =
# dépense, positif = revenu, décimale à la française avec une virgule) ; la
# dernière est le vrai solde du compte après l'opération (décimale avec un
# point). On ne lit jamais le numéro de compte (IBAN/RIB) : il n'est utile à
# rien ici et n'est jamais recopié dans la réponse. Le fichier n'est ni
# stocké sur disque ni envoyé à Supabase Storage — uniquement analysé en
# mémoire le temps de la requête, puis oublié.
_BOURSO_EXPECTED_HEADER_PREFIX = ["Date Opération", "Date Valeur", "Libellé"]
MAX_BANK_IMPORT_FILE_SIZE = 3 * 1024 * 1024  # 3 Mo : largement assez pour un relevé annuel

# Catégorie BoursoBank ("Catégorie" fine, ou "Catégorie Parente" en repli),
# normalisée (accents/majuscules retirés) -> catégorie de dépense de l'appli.
# Uniquement pour les dépenses : les catégories bancaires côté revenus
# ("Virements reçus"...) ne correspondent à rien d'assez fiable chez nous,
# donc un revenu importé reste toujours en "autre" (à reclasser à la main —
# le système de suggestion par mot-clé prend ensuite le relais comme pour
# une saisie vocale ou manuelle).
_BOURSO_CATEGORY_MAP = {
    "peages": "transport",
    "carburant": "transport",
    "auto & moto": "transport",
    "alimentation": "courses",
    "vie quotidienne": "loisirs",
    "vie quotidienne - autres": "loisirs",
    "livres, cd/dvd, bijoux, jouets...": "loisirs",
    "mobilier, electromenager, decoration...": "loisirs",
    "electronique et informatique": "loisirs",
    "equipements sportifs et artistiques": "loisirs",
    "bricolage et jardinage": "loisirs",
}


def _normalize_bourso_key(text: str) -> str:
    stripped = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")
    return stripped.strip().lower()


def _is_bourso_internal_transfer(parent_category: str) -> bool:
    """Virement entre deux comptes de l'utilisateur lui-même (ex: vers son
    épargne) : ne doit pas compter comme une vraie dépense/un vrai revenu,
    donc décoché par défaut dans l'aperçu plutôt qu'importé directement."""
    return "mouvements internes" in _normalize_bourso_key(parent_category)


def _guess_category_from_bourso(
    category: str, parent_category: str, custom_expense: dict[str, str]
) -> str:
    guess = _BOURSO_CATEGORY_MAP.get(_normalize_bourso_key(category))
    if not guess:
        guess = _BOURSO_CATEGORY_MAP.get(_normalize_bourso_key(parent_category))
    if not guess:
        return "autre"
    valid = EXPENSE_CATEGORIES | set(custom_expense.keys())
    return guess if guess in valid else "autre"


def _parse_french_amount(raw: str) -> float | None:
    cleaned = raw.strip().replace("\xa0", "").replace(" ", "").replace(",", ".")
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


@router.post("/api/import/bank-csv", response_model=None)
async def preview_bank_import(file: UploadFile = File(...), user_id: str = Depends(require_user)) -> dict:
    filename = (file.filename or "").lower()
    if not filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Seuls les fichiers .csv sont acceptés pour l'instant (export BoursoBank)")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Fichier vide")
    if len(raw_bytes) > MAX_BANK_IMPORT_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (3 Mo maximum)")

    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw_bytes.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Encodage du fichier non reconnu") from exc

    reader = csv.reader(StringIO(text), delimiter=";")
    try:
        header = next(reader)
    except StopIteration:
        raise HTTPException(status_code=400, detail="Fichier vide") from None

    header_clean = [h.strip().strip('"') for h in header]
    if header_clean[:3] != _BOURSO_EXPECTED_HEADER_PREFIX:
        raise HTTPException(
            status_code=422,
            detail=(
                "Format non reconnu : seul l'export CSV BoursoBank "
                '("export-operations...") est supporté pour l\'instant'
            ),
        )

    solde_indices = [i for i, h in enumerate(header_clean) if h == "Solde"]
    try:
        idx_date = header_clean.index("Date Opération")
        idx_libelle = header_clean.index("Libellé")
        idx_libelle_suggere = header_clean.index("Libellé Suggéré")
        idx_categorie = header_clean.index("Catégorie")
        idx_categorie_parente = header_clean.index("Catégorie Parente")
        idx_libelle_compte = header_clean.index("Libellé Compte")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Colonnes attendues manquantes dans le fichier") from exc
    if len(solde_indices) < 2:
        raise HTTPException(status_code=422, detail="Colonnes attendues manquantes dans le fichier")
    idx_montant, idx_solde_reel = solde_indices[0], solde_indices[-1]

    client = get_supabase_client()
    custom = _fetch_custom_categories(client, user_id)

    rows_out: list[dict] = []
    skipped = 0
    account_label: str | None = None
    account_balance: float | None = None
    account_balance_date: date | None = None
    parsed_dates: list[date] = []

    for i, row in enumerate(reader):
        if len(row) <= max(idx_date, idx_libelle, idx_montant, idx_solde_reel):
            skipped += 1
            continue
        try:
            op_date = date.fromisoformat(row[idx_date].strip())
        except ValueError:
            skipped += 1
            continue
        amount_raw = _parse_french_amount(row[idx_montant])
        if amount_raw is None or amount_raw == 0:
            skipped += 1
            continue

        tx_type: TransactionType = "expense" if amount_raw < 0 else "income"
        amount = round(abs(amount_raw), 2)

        suggere = row[idx_libelle_suggere].strip() if idx_libelle_suggere < len(row) else ""
        brut = row[idx_libelle].strip() if idx_libelle < len(row) else ""
        description = suggere or brut or "Opération bancaire"
        category_raw = row[idx_categorie].strip() if idx_categorie < len(row) else ""
        parent_raw = row[idx_categorie_parente].strip() if idx_categorie_parente < len(row) else ""
        is_transfer = _is_bourso_internal_transfer(parent_raw)
        category = (
            _guess_category_from_bourso(category_raw, parent_raw, custom.get("expense", {}))
            if tx_type == "expense"
            else "autre"
        )

        parsed_dates.append(op_date)
        if account_balance_date is None or op_date >= account_balance_date:
            solde_raw = row[idx_solde_reel].strip() if idx_solde_reel < len(row) else ""
            try:
                account_balance = float(solde_raw.replace(",", "."))
                account_balance_date = op_date
            except ValueError:
                pass
        if account_label is None and idx_libelle_compte < len(row):
            account_label = row[idx_libelle_compte].strip() or None

        rows_out.append({
            "row_index": i,
            "expense_date": op_date,
            "type": tx_type,
            "amount": amount,
            "description": description,
            "category": category,
            "bank_label": parent_raw or category_raw or "Non catégorisé",
            "is_internal_transfer": is_transfer,
        })

    if not rows_out:
        raise HTTPException(status_code=422, detail="Aucune opération exploitable trouvée dans ce fichier")

    # Détection de doublons probables (même date + montant + type + libellé
    # déjà en base) : évite de réimporter deux fois le même relevé sans s'en
    # rendre compte. Les lignes repérées restent importables (ce n'est qu'une
    # alerte, pas un blocage) mais sont décochées par défaut côté frontend.
    min_date, max_date = min(parsed_dates), max(parsed_dates)
    existing = (
        client.table("transactions")
        .select("expense_date, amount, type, description")
        .eq("user_id", user_id)
        .gte("expense_date", min_date.isoformat())
        .lte("expense_date", max_date.isoformat())
        .execute()
    ).data
    existing_signatures = {
        (
            row["expense_date"],
            round(float(row["amount"]), 2),
            row["type"],
            (row.get("description") or "").strip().lower(),
        )
        for row in existing
    }
    for row in rows_out:
        sig = (row["expense_date"].isoformat(), row["amount"], row["type"], row["description"].strip().lower())
        row["likely_duplicate"] = sig in existing_signatures

    return {
        "rows": rows_out,
        "account_label": account_label,
        "account_balance": account_balance,
        "account_balance_date": account_balance_date,
        "skipped_rows": skipped,
        "expense_categories": {
            **{c: category_label(c, "expense") for c in EXPENSE_CATEGORIES},
            **custom.get("expense", {}),
        },
        "income_categories": {
            **{c: category_label(c, "income") for c in INCOME_CATEGORIES},
            **custom.get("income", {}),
        },
    }


@router.post("/api/import/bank-csv/commit", status_code=201)
def commit_bank_import(req: BankImportCommitRequest, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = [
        {
            "type": row.type,
            "amount": row.amount,
            "category": (row.category or "autre").strip() or "autre",
            "description": row.description,
            "expense_date": row.expense_date.isoformat(),
            "user_id": user_id,
        }
        for row in req.rows
    ]
    result = client.table("transactions").insert(payload).execute()
    return {"inserted": len(result.data)}


# ---------------------------------------------------------------------------
# Import générique par IA (tout fichier .csv/.xlsx, structure quelconque) —
# contrairement à /api/import/bank-csv (colonnes BoursoBank fixes connues à
# l'avance), ici le contenu brut du fichier est envoyé à l'IA qui le
# réinterprète elle-même. Utile par ex. pour un fichier personnel organisé en
# un tableau par mois, sans date précise par opération ni catégorie.
#
# La détection récurrent / crédit / déjà-terminé, elle, reste déterministe
# côté serveur (une comparaison de libellés/montants sur plusieurs mois est
# plus fiable en code qu'en laissant l'IA "se souvenir" d'un mois à l'autre) :
# voir _detect_recurring_patterns. Règles, dans l'ordre de priorité :
#   1. Libellé contenant un numéro d'échéance ("3/12", "échéance 4/18") :
#      quasi certain que c'est un crédit/financement fini, jamais une
#      dépense récurrente classique — le numéro permet même de calculer le
#      nombre d'échéances restantes et une date de fin.
#   2. Libellé contenant un nom d'organisme/abonnement connu (Netflix,
#      loyer, assurance...) : poids fort vers "récurrent", pas de
#      confirmation demandée.
#   3. Le motif a cessé d'apparaître dans les derniers mois disponibles du
#      fichier : considéré comme déjà terminé tout seul, pas de charge
#      récurrente créée (les occurrences passées sont importées telles
#      quelles).
#   4. Sinon (motif répété, ni mot-clé ni numéro d'échéance, toujours
#      présent récemment) : cas ambigu, l'IA ne tranche pas seule — bandeau
#      de confirmation côté frontend (même logique que l'assistant vocal).
# ---------------------------------------------------------------------------

MAX_GENERIC_IMPORT_FILE_SIZE = 3 * 1024 * 1024  # aligné avec /api/import/bank-csv
MAX_GENERIC_IMPORT_TEXT_CHARS = 60_000  # ~15k tokens, large marge pour un relevé annuel

_KNOWN_RECURRING_KEYWORDS = {
    "netflix", "spotify", "disney", "canal+", "canal plus", "amazon prime",
    "deezer", "apple music", "apple one", "icloud", "appstore", "app store",
    "youtube premium", "loyer", "assurance", "mutuelle", "edf", "engie",
    "free mobile", "orange", "sfr", "bouygues", "box internet", "salle de sport",
    "abonnement", "creche", "cantine", "loa", "leasing",
}

# "3/12", "échéance 4/18", "mensualité 2 sur 10"...
_INSTALLMENT_PATTERN = re.compile(
    r"(?:(?:echeance|mensualite|prelevement)\s*)?(\d{1,2})\s*(?:/|sur)\s*(\d{1,2})\b",
    re.IGNORECASE,
)


def _strip_installment_counter(label: str) -> tuple[str, tuple[int, int] | None]:
    """Repère un numéro d'échéance dans un libellé brut et le retire pour ne
    garder que le nom (utilisé ensuite comme clé de regroupement commune à
    toutes les échéances d'un même crédit, ex: "iPad 3/12" et "iPad 4/12")."""
    match = _INSTALLMENT_PATTERN.search(_normalize_bourso_key(label))
    if not match:
        return label, None
    try:
        seen, total = int(match.group(1)), int(match.group(2))
    except ValueError:
        return label, None
    if seen < 1 or total < seen or total > 60:
        return label, None
    cleaned = (label[: match.start()] + label[match.end():]).strip(" -/:·|")
    return (cleaned or label), (seen, total)


def _yyyymm_to_tuple(value: str) -> tuple[int, int]:
    return int(value[:4]), int(value[5:7])


def _months_between(earlier: str, later: str) -> int:
    ey, em = _yyyymm_to_tuple(earlier)
    ly, lm = _yyyymm_to_tuple(later)
    return (ly * 12 + lm) - (ey * 12 + em)


def _add_months_to_date(d: date, months: int) -> date:
    year, month = _month_add(d.year, d.month, months)
    return date(year, month, _clamp_day(year, month, d.day))


def _extract_generic_import_text(filename: str, raw_bytes: bytes) -> str:
    """Convertit le fichier (structure quelconque) en texte brut lisible par
    l'IA : un simple dump ligne par ligne, cellules séparées par " | ". Les
    lignes vides sont conservées (elles marquent souvent, dans ce genre de
    fichier personnel, la rupture entre deux tableaux mensuels)."""
    if filename.endswith(".xlsx"):
        from openpyxl import load_workbook

        try:
            wb = load_workbook(BytesIO(raw_bytes), data_only=True, read_only=True)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="Fichier .xlsx illisible") from exc
        lines: list[str] = []
        try:
            for sheet in wb.worksheets:
                if len(wb.worksheets) > 1:
                    lines.append(f"### Feuille : {sheet.title}")
                for row in sheet.iter_rows(values_only=True):
                    cells = [str(c).strip() if c is not None else "" for c in row]
                    if not any(cells):
                        lines.append("")
                        continue
                    lines.append(" | ".join(cells))
        finally:
            wb.close()
        return "\n".join(lines)

    if filename.endswith(".csv"):
        try:
            return raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                return raw_bytes.decode("latin-1")
            except UnicodeDecodeError as exc:
                raise HTTPException(status_code=400, detail="Encodage du fichier non reconnu") from exc

    raise HTTPException(status_code=400, detail="Formats acceptés : .csv ou .xlsx")


_GENERIC_IMPORT_SYSTEM_PROMPT_TEMPLATE = """Tu reçois le contenu brut d'un fichier de suivi de finances personnelles (export Excel ou CSV), dont la structure n'est PAS standardisée — ce n'est pas forcément un relevé bancaire classique avec une colonne par champ. Il peut par exemple s'agir d'un tableau par mois (avec un titre de section indiquant le mois), sans date précise par opération, sans catégorie, juste un nom de dépense et un montant.

Ta tâche : repérer TOUTES les opérations (dépenses et revenus) présentes dans ce texte et les restituer sous forme d'une liste structurée.

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, selon ce schéma :
{
  "entries": [
    {
      "description": "libellé court et lisible de la dépense/du revenu (nettoyé, sans le montant)",
      "source_label": "le texte brut EXACT tel qu'il apparaît dans le fichier pour cette ligne (important : ne le modifie pas, il sert à détecter des motifs comme un numéro d'échéance)",
      "amount": nombre positif,
      "type": "expense" ou "income",
      "category_guess": une chaîne parmi __ALL_CATEGORIES__ — ta meilleure estimation à partir du libellé, "autre" si aucune ne correspond clairement,
      "month": "YYYY-MM" — le mois auquel se rattache cette opération, déduit du contexte (titre de section, en-tête de tableau, etc.),
      "day": nombre entier (jour du mois) UNIQUEMENT si une date précise est réellement indiquée pour CETTE opération dans le fichier, sinon null — n'invente JAMAIS un jour si le fichier ne donne qu'un mois
    }
  ],
  "warnings": ["tout ce qui t'a semblé ambigu ou incertain lors de la lecture, en français" (liste vide si rien à signaler)]
}

RÈGLES IMPORTANTES :
- N'invente aucune opération : seulement celles réellement présentes dans le texte.
- Si l'année n'est pas explicitement indiquée, utilise __DEFAULT_YEAR__ par défaut et signale-le dans "warnings".
- Ignore les lignes de total, sous-total, solde, ou en-tête de colonnes.
- "source_label" doit rester le texte brut non modifié (utile pour une détection de motifs faite ensuite par un autre programme) ; "description" peut en revanche être nettoyé/raccourci.
- Conserve TOUTES les opérations, y compris celles qui se répètent d'un mois à l'autre (ne les regroupe pas toi-même) : un autre programme s'occupe ensuite de détecter les récurrences."""


def _build_generic_import_prompt(all_categories: set[str]) -> str:
    return (
        _GENERIC_IMPORT_SYSTEM_PROMPT_TEMPLATE
        .replace("__ALL_CATEGORIES__", ", ".join(sorted(all_categories)))
        .replace("__DEFAULT_YEAR__", str(today_paris().year))
    )


def _call_claude_generic_import(raw_text: str, all_categories: set[str]) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : ANTHROPIC_API_KEY")
    from anthropic import Anthropic

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=8000,
            system=_build_generic_import_prompt(all_categories),
            messages=[{"role": "user", "content": raw_text}],
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
            detail="Le service d'import par IA est temporairement indisponible, réessaie plus tard.",
        ) from exc

    raw = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}"
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Réponse IA invalide (objet JSON attendu)")
    return data


def _detect_recurring_patterns(parsed: list[dict]) -> tuple[list[dict], dict[int, str]]:
    overall_last_month = max(row["expense_date"].strftime("%Y-%m") for row in parsed)

    groups: dict[tuple[str, str], list[int]] = {}
    group_counters: dict[tuple[str, str], list[tuple[int, int]]] = {}
    group_clean_label: dict[tuple[str, str], str] = {}

    for idx, row in enumerate(parsed):
        cleaned_label, counter = _strip_installment_counter(row["source_label"])
        key = (row["type"], _normalize_bourso_key(cleaned_label))
        groups.setdefault(key, []).append(idx)
        group_clean_label.setdefault(key, (cleaned_label or row["description"]).strip())
        if counter:
            group_counters.setdefault(key, []).append(counter)

    candidates: list[dict] = []
    group_by_index: dict[int, str] = {}
    group_num = 0

    for key, indices in groups.items():
        months_seen = sorted({parsed[i]["expense_date"].strftime("%Y-%m") for i in indices})
        has_counter = key in group_counters
        if len(months_seen) < 2 and not has_counter:
            continue  # occurrence isolée : pas assez de signal pour parler de récurrence

        group_num += 1
        group_id = f"g{group_num}"
        for i in indices:
            group_by_index[i] = group_id

        tx_type = key[0]
        amounts = sorted(parsed[i]["amount"] for i in indices)
        representative_amount = amounts[len(amounts) // 2]  # médiane : robuste aux variations ponctuelles
        categories = [parsed[i]["category"] for i in indices]
        category = max(set(categories), key=categories.count)
        first_month, last_month = months_seen[0], months_seen[-1]
        start_date = date(*_yyyymm_to_tuple(first_month), 1)

        installment_info: dict | None = None
        end_date: date | None = None

        if has_counter:
            seen_max, total_guess = max(group_counters[key], key=lambda c: c[0])
            remaining = max(total_guess - seen_max, 0)
            installment_info = {"last_seen": seen_max, "total": total_guess, "remaining": remaining}
            classification = "credit"
            needs_confirmation = False
            last_month_date = date(*_yyyymm_to_tuple(last_month), 1)
            end_date = _add_months_to_date(last_month_date, remaining) if remaining > 0 else last_month_date
        elif any(kw in _normalize_bourso_key(group_clean_label[key]) for kw in _KNOWN_RECURRING_KEYWORDS):
            classification = "recurring"
            needs_confirmation = False
        elif last_month != overall_last_month and _months_between(last_month, overall_last_month) >= 2:
            classification = "ended"
            needs_confirmation = False
            end_date = date(*_yyyymm_to_tuple(last_month), 1)
        else:
            classification = "uncertain"
            needs_confirmation = True

        candidates.append({
            "group_id": group_id,
            "name": group_clean_label[key][:80].strip().capitalize() or "Dépense récurrente",
            "type": tx_type,
            "amount": representative_amount,
            "category": category,
            "months_seen": months_seen,
            "classification": classification,
            "needs_confirmation": needs_confirmation,
            "installment_info": installment_info,
            "suggested_start_date": start_date,
            "suggested_end_date": end_date,
        })

    return candidates, group_by_index


@router.post("/api/import/generic", response_model=None)
async def preview_generic_import(file: UploadFile = File(...), user_id: str = Depends(require_user)) -> dict:
    filename = (file.filename or "").lower()
    if not (filename.endswith(".csv") or filename.endswith(".xlsx")):
        raise HTTPException(status_code=400, detail="Formats acceptés : .csv ou .xlsx")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Fichier vide")
    if len(raw_bytes) > MAX_GENERIC_IMPORT_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (3 Mo maximum)")

    raw_text = _extract_generic_import_text(filename, raw_bytes)
    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="Fichier vide ou illisible")
    if len(raw_text) > MAX_GENERIC_IMPORT_TEXT_CHARS:
        raise HTTPException(
            status_code=422,
            detail=(
                "Fichier trop volumineux/complexe pour l'import IA pour l'instant "
                "(essaie un export sur une période plus courte)"
            ),
        )

    client = get_supabase_client()
    custom = _fetch_custom_categories(client, user_id)
    expense_cats = EXPENSE_CATEGORIES | set(custom.get("expense", {}).keys())
    income_cats = INCOME_CATEGORIES | set(custom.get("income", {}).keys())
    all_categories = expense_cats | income_cats

    ai_data = _call_claude_generic_import(raw_text, all_categories)
    raw_entries = ai_data.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise HTTPException(status_code=422, detail="Aucune opération exploitable détectée par l'IA dans ce fichier")
    truncated = len(raw_entries) > MAX_GENERIC_IMPORT_ENTRIES
    raw_entries = raw_entries[:MAX_GENERIC_IMPORT_ENTRIES]

    parsed: list[dict] = []
    skipped = 0
    for i, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            skipped += 1
            continue
        amount_val = raw.get("amount")
        amount = _parse_french_amount(amount_val) if isinstance(amount_val, str) else None
        if amount is None and not isinstance(amount_val, str):
            try:
                amount = float(amount_val)
            except (TypeError, ValueError):
                amount = None
        if not amount:
            skipped += 1
            continue
        amount = round(abs(amount), 2)

        tx_type: TransactionType = "income" if raw.get("type") == "income" else "expense"

        month_str = str(raw.get("month") or "").strip()
        parts = month_str.split("-")
        try:
            if len(parts) < 2:
                raise ValueError
            year, month = int(parts[0]), int(parts[1])
            if not (1 <= month <= 12):
                raise ValueError
        except ValueError:
            skipped += 1
            continue

        day_raw = raw.get("day")
        day = None
        if isinstance(day_raw, (int, float)) and day_raw:
            candidate = int(day_raw)
            if 1 <= candidate <= calendar.monthrange(year, month)[1]:
                day = candidate
        expense_date = date(year, month, day or 1)

        description = str(raw.get("description") or "").strip() or "Opération importée"
        source_label = str(raw.get("source_label") or description).strip()
        category_guess = str(raw.get("category_guess") or "autre").strip().lower()
        valid_cats = income_cats if tx_type == "income" else expense_cats
        category = category_guess if category_guess in valid_cats else "autre"

        parsed.append({
            "row_index": i,
            "expense_date": expense_date,
            "date_precision": "day" if day else "month",
            "type": tx_type,
            "amount": amount,
            "description": description,
            "category": category,
            "source_label": source_label,
        })

    if not parsed:
        raise HTTPException(status_code=422, detail="Aucune opération exploitable détectée par l'IA dans ce fichier")

    recurring_candidates, group_by_index = _detect_recurring_patterns(parsed)
    for idx, row in enumerate(parsed):
        row["recurring_group_id"] = group_by_index.get(idx)

    dates = [row["expense_date"] for row in parsed]
    min_date, max_date = min(dates), max(dates)
    existing = (
        client.table("transactions")
        .select("expense_date, amount, type, description")
        .eq("user_id", user_id)
        .gte("expense_date", min_date.isoformat())
        .lte("expense_date", max_date.isoformat())
        .execute()
    ).data
    existing_signatures = {
        (
            row["expense_date"],
            round(float(row["amount"]), 2),
            row["type"],
            (row.get("description") or "").strip().lower(),
        )
        for row in existing
    }
    for row in parsed:
        sig = (row["expense_date"].isoformat(), row["amount"], row["type"], row["description"].strip().lower())
        row["likely_duplicate"] = sig in existing_signatures

    warnings = [w for w in (ai_data.get("warnings") or []) if isinstance(w, str)]
    if skipped:
        warnings.append(f"{skipped} ligne(s) ignorée(s) par l'IA car illisibles")
    if truncated:
        warnings.append(f"Fichier très volumineux : seules les {MAX_GENERIC_IMPORT_ENTRIES} premières opérations détectées ont été gardées")

    return {
        "rows": parsed,
        "recurring_candidates": recurring_candidates,
        "warnings": warnings,
        "expense_categories": {
            **{c: category_label(c, "expense") for c in EXPENSE_CATEGORIES},
            **custom.get("expense", {}),
        },
        "income_categories": {
            **{c: category_label(c, "income") for c in INCOME_CATEGORIES},
            **custom.get("income", {}),
        },
    }


@router.post("/api/import/generic/commit", status_code=201)
def commit_generic_import(req: GenericImportCommitRequest, user_id: str = Depends(require_user)) -> dict:
    if not req.transactions and not req.recurring:
        raise HTTPException(status_code=400, detail="Rien à importer")

    client = get_supabase_client()
    inserted_transactions = 0
    inserted_recurring = 0

    if req.transactions:
        payload = [
            {
                "type": row.type,
                "amount": row.amount,
                "category": (row.category or "autre").strip() or "autre",
                "description": row.description,
                "expense_date": row.expense_date.isoformat(),
                "user_id": user_id,
            }
            for row in req.transactions
        ]
        result = client.table("transactions").insert(payload).execute()
        inserted_transactions = len(result.data)

    if req.recurring:
        payload = [
            {
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
            for item in req.recurring
        ]
        result = client.table("recurring_expenses").insert(payload).execute()
        inserted_recurring = len(result.data)

    return {"inserted_transactions": inserted_transactions, "inserted_recurring": inserted_recurring}
