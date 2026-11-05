"""Import de relevés — un routeur dédié (déviation mineure par rapport au
plan de découpage initial, qui ne listait pas de routeur "imports" à part :
jugé plus clair de séparer ce bloc dans son propre fichier plutôt que de le
noyer dans transactions.py/recurring.py).

Deux mécanismes complémentaires, valables pour n'importe quelle banque (pas
de format propriétaire codé en dur) :
  - import générique par IA : le contenu brut du fichier (.csv, .xlsx,
    .xlsm ou relevé .pdf) est envoyé à l'IA, qui le réinterprète elle-même
    et propose des transactions à valider. La détection récurrent / crédit /
    déjà-terminé, elle, reste déterministe côté serveur (voir
    _detect_recurring_patterns) ;
  - classeur onglet par onglet (/api/import/workbook/...) : pour un fichier
    Excel non standard, chaque onglet est reconnu (mensuel, prêt,
    endettement) et l'utilisateur confirme ce qu'il importe. Les prêts et
    l'historique de patrimoine sont lus en code (app/workbook_parsing.py) ;
    les onglets mensuels repassent par l'import générique, limité aux
    onglets choisis.
"""

import base64
import calendar
import io
import json
import re
import unicodedata
from datetime import date, timedelta
from io import BytesIO
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.config import (
    ANTHROPIC_API_KEY,
    EXPENSE_CATEGORIES,
    INCOME_CATEGORIES,
    LOAN_CATEGORY,
    MAX_GENERIC_IMPORT_ENTRIES,
    TRANSFER_CATEGORY,
    TransactionType,
    category_label,
    today_paris,
)
from app.db import get_supabase_client
from app.emails import _notify_admin_once
from app.models import GenericImportCommitRequest, WorkbookCommitRequest
from app.routers.accounts import ensure_own_accounts
from app.routers.loans import active_loans, match_loan_for_payment
from app.routers.recurring import _clamp_day, _month_add
from app.rules import learn_rule, load_rules, match_rule, rule_key
from app.security import require_user
from app.voice_nlp import _fetch_custom_categories
from app.workbook_parsing import analyze_workbook, property_key

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers partagés par l'import générique ci-dessous (_normalize_key sert
# aussi à la détection de récurrence : regrouper "iPad 3/12" et "iPad 4/12"
# malgré l'accentuation/la casse qui peut varier d'une banque à l'autre).
# ---------------------------------------------------------------------------
def _normalize_key(text: str) -> str:
    stripped = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")
    return re.sub(r"\s+", " ", stripped).strip().lower()


def _parse_french_amount(raw: str) -> float | None:
    cleaned = raw.strip().replace("\xa0", "").replace(" ", "").replace(",", ".")
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None



# ---------------------------------------------------------------------------
# Import générique par IA (tout fichier .csv/.xlsx, structure quelconque,
# n'importe quelle banque) — le contenu brut du fichier est envoyé à l'IA qui
# le réinterprète elle-même. Utile par ex. pour un fichier personnel organisé
# en un tableau par mois, sans date précise par opération ni catégorie.
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

MAX_GENERIC_IMPORT_FILE_SIZE = 3 * 1024 * 1024  # 3 Mo : largement assez pour un relevé annuel
# Relevé PDF : un peu plus large (mise en page, logos), mais sous la limite de
# 4,5 Mo par requête imposée par Vercel.
MAX_PDF_IMPORT_FILE_SIZE = 4 * 1024 * 1024
# Classeur onglet par onglet : un fichier Excel avec macros et beaucoup
# d'onglets est vite plus lourd ; même plafond Vercel.
MAX_WORKBOOK_FILE_SIZE = 4 * 1024 * 1024
MAX_GENERIC_IMPORT_TEXT_CHARS = 60_000  # ~15k tokens, large marge pour un relevé annuel

_SPREADSHEET_EXTENSIONS = (".xlsx", ".xlsm")
_ACCEPTED_EXTENSIONS = (".csv", ".pdf", *_SPREADSHEET_EXTENSIONS)

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
    normalized = _normalize_key(label)
    match = _INSTALLMENT_PATTERN.search(normalized)
    if not match:
        return label, None
    try:
        seen, total = int(match.group(1)), int(match.group(2))
    except ValueError:
        return label, None
    if seen < 1 or total < seen or total > 60:
        return label, None
    # Sur un relevé bancaire, "CB CARREFOUR 04/09" est la DATE du paiement
    # par carte, pas une échéance 4 sur 9 : sans mot-clé explicite
    # (échéance, mensualité...), un paiement par carte ou un "jj/mm" écrit
    # avec des zéros devant n'est jamais pris pour un numéro d'échéance.
    has_keyword = bool(re.search(r"echeance|mensualite|prelevement|\bsur\b", match.group(0)))
    compact = match.group(0).replace(" ", "")
    looks_like_date = bool(re.fullmatch(r"\d{2}/\d{2}", compact)) and 1 <= seen <= 31 and 1 <= total <= 12
    is_card_payment = bool(re.match(r"(cb|carte|paiement par carte)\b", normalized))
    if not has_keyword and (looks_like_date or is_card_payment):
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


def _extract_generic_import_text(filename: str, raw_bytes: bytes, only_sheets: list[str] | None = None) -> str:
    """Convertit le fichier (structure quelconque) en texte brut lisible par
    l'IA : un simple dump ligne par ligne, cellules séparées par " | ". Les
    lignes vides sont conservées (elles marquent souvent, dans ce genre de
    fichier personnel, la rupture entre deux tableaux mensuels).
    `only_sheets` : pour un classeur, ne garder que ces onglets (choisis par
    l'utilisateur à l'étape "onglet par onglet")."""
    if filename.endswith(_SPREADSHEET_EXTENSIONS):
        from openpyxl import load_workbook

        try:
            wb = load_workbook(BytesIO(raw_bytes), data_only=True, read_only=True)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="Fichier Excel illisible") from exc
        lines: list[str] = []
        try:
            selected = [
                sheet for sheet in wb.worksheets
                if only_sheets is None or sheet.title in only_sheets
            ]
            if not selected:
                raise HTTPException(status_code=400, detail="Aucun des onglets choisis n'existe dans ce fichier")
            for sheet in selected:
                if len(wb.worksheets) > 1:
                    lines.append(f"### Feuille : {sheet.title}")
                if hasattr(sheet, "reset_dimensions"):
                    sheet.reset_dimensions()
                for row in sheet.iter_rows(max_row=3000, max_col=40, values_only=True):
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

    raise HTTPException(status_code=400, detail="Formats acceptés : .csv, .xlsx, .xlsm ou .pdf")


# Numéros de compte, IBAN, références bancaires : inutiles à l'IA pour
# reconnaître une opération, et sensibles. Masqués dans le texte envoyé
# (CSV / Excel) : IBAN, puis toute suite d'au moins 10 chiffres (éventuellement
# séparés par des espaces) — un montant ou une date n'en a jamais autant.
_IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ \u00a0]?[A-Z0-9]){11,30}\b")
_LONG_NUMBER_PATTERN = re.compile(r"(?<![\d.,])\d(?:[ \u00a0]?\d){9,}(?![\d])")


def _mask_sensitive_numbers(text: str) -> str:
    text = _IBAN_PATTERN.sub("[IBAN masqué]", text)
    return _LONG_NUMBER_PATTERN.sub("[n° masqué]", text)


_PDF_DATE_WORD = re.compile(r"^\d{2}/\d{2}(?:/\d{4})?$")  # jj/mm/aaaa ou jj/mm (La Banque Postale)
_PDF_AMOUNT_WORD = re.compile(r"^\d{1,3}(?:[ \u00a0.]\d{3})*,\d{2}$|^\d+,\d{2}$")


def _annotate_pdf_columns(raw_bytes: bytes) -> str | None:
    """Lit un relevé PDF avec la position de chaque mot et marque chaque
    opération [DÉBIT] ou [CRÉDIT] selon la colonne où se trouve son montant.
    L'IA lit mal ces deux colonnes sur l'image du PDF (elle prend des crédits
    pour des dépenses) ; ici la décision est mécanique, donc fiable.
    Renvoie None si le PDF n'a pas de colonnes Débit/Crédit identifiables
    (l'ancien envoi du PDF tel quel sert alors de repli)."""
    try:
        import pdfplumber

        lines_out: list[str] = []
        tagged = 0
        deb_x = cred_x = None
        with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
            for page in pdf.pages[:40]:
                words = page.extract_words(x_tolerance=1.2, use_text_flow=False, keep_blank_chars=False)
                # En-têtes de colonnes de la page (répétés à chaque page).
                for w in words:
                    low = w["text"].lower()
                    # Le « é » sort parfois mal décodé du PDF (« DØbit ») :
                    # n'importe quel caractère au milieu convient.
                    if re.fullmatch(r"d.bit", low):
                        deb_x = w["x1"]
                    elif re.fullmatch(r"cr.dit", low):
                        cred_x = w["x1"]
                rows: list[list[dict]] = []
                for w in sorted(words, key=lambda w: (round(w["top"]), w["x0"])):
                    if rows and abs(rows[-1][0]["top"] - w["top"]) <= 3:
                        rows[-1].append(w)
                    else:
                        rows.append([w])
                for row in rows:
                    row.sort(key=lambda w: w["x0"])
                    text = " ".join(w["text"] for w in row).replace("Ø", "é").replace("(cid:128)", "€")
                    if deb_x is not None and cred_x is not None and _PDF_DATE_WORD.match(row[0]["text"]):
                        amounts = [w for w in row[1:] if _PDF_AMOUNT_WORD.match(w["text"])]
                        if amounts:
                            amount_word = amounts[-1]
                            d_deb = abs(amount_word["x1"] - deb_x)
                            d_cred = abs(amount_word["x1"] - cred_x)
                            # Le montant doit être aligné sur une des deux
                            # colonnes (sinon c'est une ligne d'en-tête ou
                            # autre chose qu'une opération).
                            if min(d_deb, d_cred) <= 40:
                                text += "  [CRÉDIT]" if d_cred < d_deb else "  [DÉBIT]"
                                tagged += 1
                    lines_out.append(text)
        if not tagged:
            return None
        return "\n".join(lines_out)
    except Exception:  # noqa: BLE001 - repli sur l'envoi du PDF brut
        return None



_SAVINGS_SECTION = re.compile(r"Comptes\s+d.{1,12}pargne", re.IGNORECASE)


def _split_statement_sections(annotated: str) -> tuple[str, str | None]:
    """Certains relevés (La Banque Postale) regroupent le compte courant ET les
    livrets du même titulaire. Renvoie (partie compte courant, partie épargne) ;
    la seconde vaut None quand le relevé n'a qu'une section."""
    match = _SAVINGS_SECTION.search(annotated)
    if not match:
        return annotated, None
    return annotated[: match.start()], annotated[match.start():]


def _fr_amount(text: str) -> float | None:
    """« 1.216,10 », « -678,30 », « 1 216,10 » -> float."""
    cleaned = text.replace("\u00a0", "").replace(" ", "")
    negative = cleaned.startswith("-")
    cleaned = cleaned.lstrip("-").replace(".", "").replace(",", ".")
    try:
        value = float(cleaned)
    except ValueError:
        return None
    return -value if negative else value


def _read_statement_balances(annotated: str) -> dict | None:
    """Soldes d'un relevé PDF lisible en colonnes : solde de départ, solde de
    fin, fin de période, et totaux des colonnes. Sert à vérifier mécaniquement
    que les opérations lues tombent juste (départ + crédits − débits = fin).
    None si le relevé n'affiche pas ces deux soldes."""
    opening = re.search(r"SOLDE\s*AU\s*:\s*(\d{2}/\d{2}/\d{4})\s*(-?\s*[\d.]+,\d{2})", annotated, re.IGNORECASE)
    closing = re.search(r"Nouveau\s*solde\s*(?:en\s*EUR)?\s*:\s*(-?\s*[\d.]+,\d{2})", annotated, re.IGNORECASE)
    closing_date = None
    if not opening or not closing:
        # Modèle La Banque Postale : « Ancien solde au jj/mm/aaaa 77,76 » …
        # « Nouveau solde au jj/mm/aaaa 0,15 ».
        opening = re.search(r"Ancien\s*solde\s*au\s*(\d{2}/\d{2}/\d{4})\s*(-?\s*[\d.\s]*\d,\d{2})", annotated, re.IGNORECASE)
        closing = re.search(r"Nouveau\s*solde\s*au\s*(\d{2}/\d{2}/\d{4})\s*(-?\s*[\d.\s]*\d,\d{2})", annotated, re.IGNORECASE)
        if not opening or not closing:
            return None
        closing_date = closing.group(1)
        opening_amount, closing_amount = _fr_amount(opening.group(2)), _fr_amount(closing.group(2))
    else:
        opening_amount, closing_amount = _fr_amount(opening.group(2)), _fr_amount(closing.group(1))
    if opening_amount is None or closing_amount is None:
        return None
    period = re.search(r"du\s*(\d{2}/\d{2}/\d{4})\s*au\s*(\d{2}/\d{2}/\d{4})", annotated)
    period_end = None
    if closing_date:
        d, m, y = closing_date.split("/")
        period_end = f"{y}-{m}-{d}"
    elif period:
        d, m, y = period.group(2).split("/")
        period_end = f"{y}-{m}-{d}"
    debits = credits = 0.0
    for line in annotated.split("\n"):
        tag = "[CRÉDIT]" if line.endswith("[CRÉDIT]") else "[DÉBIT]" if line.endswith("[DÉBIT]") else None
        if not tag:
            continue
        tokens = [t for t in line[: -len(tag)].split() if re.fullmatch(r"-?\d[\d.]*,\d{2}", t)]
        value = _fr_amount(tokens[-1]) if tokens else None
        if value is None:
            continue
        if tag == "[CRÉDIT]":
            credits += abs(value)
        else:
            debits += abs(value)
    return {
        "opening": round(opening_amount, 2),
        "closing": round(closing_amount, 2),
        "period_end": period_end,
        "credits": round(credits, 2),
        "debits": round(debits, 2),
    }


_GENERIC_IMPORT_SYSTEM_PROMPT_TEMPLATE = """Tu reçois le contenu brut d'un fichier de suivi de finances personnelles (export Excel ou CSV), dont la structure n'est PAS standardisée — ce n'est pas forcément un relevé bancaire classique avec une colonne par champ. Il peut par exemple s'agir d'un tableau par mois (avec un titre de section indiquant le mois), sans date précise par opération, sans catégorie, juste un nom de dépense et un montant.

Ta tâche : repérer TOUTES les opérations (dépenses et revenus) présentes dans ce texte et les restituer sous forme d'une liste structurée.

Réponds UNIQUEMENT avec un objet JSON valide, sans aucun texte autour, SUR UNE SEULE LIGNE (aucune indentation ni retour à la ligne), selon ce schéma. Les clés sont volontairement courtes : respecte-les exactement.
{"e":[{"d":"libellé court et lisible (nettoyé, sans le montant)","s":"texte brut EXACT de la ligne tel qu'il apparaît dans le fichier (sert à détecter des motifs comme un numéro d'échéance ; ne le modifie pas)","a":nombre positif,"t":"expense" ou "income","c":une chaîne parmi __ALL_CATEGORIES__ — ta meilleure estimation, "autre" si aucune ne correspond clairement,"m":"YYYY-MM" (mois de l'opération, déduit du contexte),"y":jour du mois en nombre entier UNIQUEMENT si une date précise est indiquée pour CETTE opération, sinon null (n'invente JAMAIS un jour),"x":nom EXACT d'un autre compte de l'utilisateur si l'opération est un virement entre ses propres comptes (liste plus bas), sinon null}],"w":["avertissement court"]}
"w" : 3 avertissements au maximum, une courte phrase chacun, uniquement pour un vrai problème de lecture (liste vide sinon). Ne commente JAMAIS les virements (ni vers le titulaire lui-même, ni vers un tiers) ni les soldes.

RÈGLES IMPORTANTES :
- N'invente aucune opération : seulement celles réellement présentes dans le texte.
- La catégorie "avance" est réservée aux achats faits pour quelqu'un qui les rembourse et à ces remboursements : ne la choisis que si le libellé le dit clairement (les règles apprises de l'utilisateur s'en chargent sinon).
- CATÉGORIES : n'invente pas. Si tu ne reconnais pas clairement l'enseigne ou la nature de la dépense (sigle, nom propre inconnu, libellé bancaire opaque), mets "autre" — c'est préférable à une catégorie précise devinée. L'utilisateur corrige ensuite et l'appli retient ses choix. Ne choisis une catégorie que si le libellé est sans ambiguïté (ex : supermarché connu, SNCF, Netflix, restaurant explicite).
- Si l'année n'est pas explicitement indiquée, utilise __DEFAULT_YEAR__ par défaut et signale-le dans "warnings".
- Ignore les lignes de total, sous-total, solde, ou en-tête de colonnes.
- "source_label" doit rester le texte brut non modifié (utile pour une détection de motifs faite ensuite par un autre programme) ; "description" peut en revanche être nettoyé/raccourci.
- Conserve TOUTES les opérations, y compris celles qui se répètent d'un mois à l'autre (ne les regroupe pas toi-même) : un autre programme s'occupe ensuite de détecter les récurrences.
- Pour un relevé bancaire, une ligne au débit est une dépense ("expense") et une ligne au crédit un revenu ("income"), même pour un virement.
- Si une ligne se termine par [DÉBIT] ou [CRÉDIT] (marqueur ajouté automatiquement d'après la colonne du montant dans le relevé), ce marqueur est FIABLE et prioritaire : [DÉBIT] = "expense", [CRÉDIT] = "income", quel que soit le libellé (un « VIR » peut être l'un ou l'autre).
- Pour un paiement par carte dont le libellé contient « CARTE jj/mm/aa », la date de l'opération est celle du libellé (le jour réel de l'achat), pas la date d'écriture en début de ligne.

COMPTES DE L'UTILISATEUR (pour repérer les virements entre ses propres comptes, par exemple "VIR LIVRET A", "virement vers Bricks", "placement") : __ACCOUNTS__
Ne remplis "transfer_account" que si le libellé désigne clairement un de ces comptes ; dans le doute, null. Un virement vers ou depuis une autre personne n'est PAS un virement entre comptes de l'utilisateur."""


def _build_generic_import_prompt(all_categories: set[str], account_names: list[str]) -> str:
    accounts_text = (
        ", ".join(f'"{name}"' for name in account_names)
        if account_names
        else "aucun compte enregistré (mets toujours null pour transfer_account)"
    )
    return (
        _GENERIC_IMPORT_SYSTEM_PROMPT_TEMPLATE
        .replace("__ALL_CATEGORIES__", ", ".join(sorted(all_categories)))
        .replace("__DEFAULT_YEAR__", str(today_paris().year))
        .replace("__ACCOUNTS__", accounts_text)
    )


def _call_claude_generic_import(
    content: str | list[dict], all_categories: set[str], account_names: list[str]
) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : ANTHROPIC_API_KEY")
    from anthropic import Anthropic

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=16000,
            system=_build_generic_import_prompt(all_categories, account_names),
            messages=[{"role": "user", "content": content}],
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
    truncated = getattr(message, "stop_reason", None) == "max_tokens"
    data = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        if truncated:
            data = _salvage_truncated_entries(raw)
        if data is None:
            if truncated:
                raise HTTPException(
                    status_code=422,
                    detail="Relevé trop long pour être lu en une fois : importe-le en plusieurs morceaux (un ou deux mois à la fois).",
                ) from exc
            raise HTTPException(
                status_code=502, detail=f"Réponse IA invalide (JSON attendu) : {raw[:200]}"
            ) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Réponse IA invalide (objet JSON attendu)")
    return _expand_compact_keys(data, truncated)


_COMPACT_KEYS = {"d": "description", "s": "source_label", "a": "amount", "t": "type", "c": "category_guess", "m": "month", "y": "day", "x": "transfer_account"}


def _expand_compact_keys(data: dict, truncated: bool) -> dict:
    """Remet les clés longues attendues par le reste du code (le prompt demande
    des clés courtes pour réduire la taille de la réponse de l'IA)."""
    entries = data.get("entries", data.get("e"))
    out_entries = []
    for item in entries if isinstance(entries, list) else []:
        if isinstance(item, dict):
            out_entries.append({_COMPACT_KEYS.get(k, k): v for k, v in item.items()})
    warnings = data.get("warnings", data.get("w")) or []
    warnings = [w for w in warnings if isinstance(w, str)]
    if truncated:
        warnings.insert(0, "Relevé très long : la fin n'a pas pu être lue. Vérifie la dernière date importée et réimporte la suite séparément.")
    return {"entries": out_entries, "warnings": warnings}


def _salvage_truncated_entries(raw: str) -> dict | None:
    """Réponse coupée en plein milieu : récupère les opérations complètes déjà
    écrites (objets JSON entiers dans la liste), ignore le dernier objet coupé."""
    start = raw.find("[")
    if start < 0:
        return None
    decoder = json.JSONDecoder()
    pos = start + 1
    entries = []
    while True:
        while pos < len(raw) and raw[pos] in " ,\n\r\t":
            pos += 1
        if pos >= len(raw) or raw[pos] != "{":
            break
        try:
            obj, pos = decoder.raw_decode(raw, pos)
        except json.JSONDecodeError:
            break
        entries.append(obj)
    return {"e": entries} if entries else None


def _detect_recurring_patterns(parsed: list[dict]) -> tuple[list[dict], dict[int, str]]:
    overall_last_month = max(row["expense_date"].strftime("%Y-%m") for row in parsed)

    groups: dict[tuple[str, str], list[int]] = {}
    group_counters: dict[tuple[str, str], list[tuple[int, int]]] = {}
    group_clean_label: dict[tuple[str, str], str] = {}

    for idx, row in enumerate(parsed):
        cleaned_label, counter = _strip_installment_counter(row["source_label"])
        # La date collée au libellé ("PRLV COFIDIS 05/10", "05/11"...) change
        # chaque mois : retirée de la clé de regroupement, sinon un même
        # prélèvement mensuel ne serait jamais reconnu comme récurrent.
        group_label = re.sub(r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b", " ", _normalize_key(cleaned_label))
        key = (row["type"], re.sub(r"\s+", " ", group_label).strip())
        groups.setdefault(key, []).append(idx)
        display_label = re.sub(r"\s+", " ", re.sub(r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b", " ", cleaned_label or "")).strip()
        group_clean_label.setdefault(key, (display_label or row["description"]).strip())
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
        elif any(kw in _normalize_key(group_clean_label[key]) for kw in _KNOWN_RECURRING_KEYWORDS):
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


def _parse_optional_uuid(raw: str | None) -> UUID | None:
    if not raw:
        return None
    try:
        return UUID(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Compte invalide") from exc


def _parse_sheet_list(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    try:
        sheets = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Liste d'onglets invalide") from exc
    if not isinstance(sheets, list) or not all(isinstance(x, str) for x in sheets) or len(sheets) > 40:
        raise HTTPException(status_code=400, detail="Liste d'onglets invalide")
    return sheets


@router.post("/api/import/generic", response_model=None)
async def preview_generic_import(
    file: UploadFile = File(...),
    account_id: str | None = Form(None),
    sheets: str | None = Form(None),
    user_id: str = Depends(require_user),
) -> dict:
    filename = (file.filename or "").lower()
    if not filename.endswith(_ACCEPTED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Formats acceptés : .csv, .xlsx, .xlsm ou .pdf")
    is_pdf = filename.endswith(".pdf")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Fichier vide")
    max_size = MAX_PDF_IMPORT_FILE_SIZE if is_pdf else (
        MAX_WORKBOOK_FILE_SIZE if filename.endswith(_SPREADSHEET_EXTENSIONS) else MAX_GENERIC_IMPORT_FILE_SIZE
    )
    if len(raw_bytes) > max_size:
        raise HTTPException(status_code=400, detail=f"Fichier trop volumineux ({max_size // (1024 * 1024)} Mo maximum)")

    statement_balances = None
    if is_pdf:
        if not raw_bytes.startswith(b"%PDF"):
            raise HTTPException(status_code=400, detail="Ce fichier n'est pas un PDF valide")
        annotated = _annotate_pdf_columns(raw_bytes)
        if annotated and ("Situation de vos comptes" in annotated or _SAVINGS_SECTION.search(annotated)):
            # Relevé multi-comptes (compte courant + livrets, ex. La Banque
            # Postale) : on ne garde que la partie du compte choisi, sinon les
            # opérations du livret se mélangeraient à celles du compte courant.
            current_part, savings_part = _split_statement_sections(annotated)
            chosen_kind = None
            chosen_id = _parse_optional_uuid(account_id)
            if chosen_id:
                rows_kind = (
                    get_supabase_client().table("accounts").select("kind, name")
                    .eq("user_id", user_id).eq("id", str(chosen_id)).execute().data
                )
                if rows_kind:
                    # Un livret = type « épargne » ET un nom de livret (un compte
                    # courant peut avoir été rangé en « épargne » par erreur).
                    plain_name = _plain_label(rows_kind[0]["name"])
                    is_livret = rows_kind[0]["kind"] == "savings" and bool(
                        re.search(r"livret|epargne|ldds|\blep\b|\bpel\b|\bcel\b", plain_name)
                    )
                    chosen_kind = "savings" if is_livret else "bank"
            if chosen_kind == "savings":
                if savings_part is None:
                    raise HTTPException(
                        status_code=400,
                        detail="Ce relevé ne contient aucune opération sur ce livret (seul son solde y apparaît) : rien à importer.",
                    )
                annotated = savings_part
            else:
                annotated = current_part
        statement_balances = _read_statement_balances(annotated) if annotated else None
        ai_content: str | list[dict] = _mask_sensitive_numbers(annotated) if annotated else [
            {
                "type": "document",
                "source": {
                    "type": "base64",
                    "media_type": "application/pdf",
                    "data": base64.b64encode(raw_bytes).decode("ascii"),
                },
            },
            {"type": "text", "text": "Voici le relevé à analyser."},
        ]
    else:
        raw_text = _mask_sensitive_numbers(_extract_generic_import_text(filename, raw_bytes, _parse_sheet_list(sheets)))
        if not raw_text.strip():
            raise HTTPException(status_code=400, detail="Fichier vide ou illisible")
        if len(raw_text) > MAX_GENERIC_IMPORT_TEXT_CHARS:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Fichier trop volumineux/complexe pour l'import IA pour l'instant "
                    "(essaie un export sur une période plus courte, ou moins d'onglets à la fois)"
                ),
            )
        ai_content = raw_text

    client = get_supabase_client()
    statement_account = _parse_optional_uuid(account_id)
    ensure_own_accounts(client, user_id, statement_account)
    # Comptes vers/depuis lesquels un virement peut être reconnu : tous les
    # comptes actifs de l'utilisateur, sauf celui d'où vient le relevé.
    accounts = (
        client.table("accounts")
        .select("id, name, active")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    transfer_targets = {
        _normalize_key(acc["name"]): acc["id"]
        for acc in accounts
        if acc.get("active", True) and acc["id"] != (str(statement_account) if statement_account else None)
    }
    target_names = [acc["name"] for acc in accounts if _normalize_key(acc["name"]) in transfer_targets]

    custom = _fetch_custom_categories(client, user_id)
    expense_cats = EXPENSE_CATEGORIES | set(custom.get("expense", {}).keys())
    income_cats = INCOME_CATEGORIES | set(custom.get("income", {}).keys())
    all_categories = expense_cats | income_cats
    loans = active_loans(client, user_id)
    learned_rules = load_rules(client, user_id)

    ai_data = _call_claude_generic_import(ai_content, all_categories, target_names)
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
        # Paiement par carte : « CARTE 05/11/25 ... » donne le vrai jour de
        # l'achat (la date en début de ligne est celle de l'écriture, 1 à 3
        # jours plus tard). Décidé ici, pas par l'IA, pour être fiable.
        card_match = re.search(r"\bCARTE\s+(\d{2})/(\d{2})/(\d{2}|\d{4})\b", str(raw.get("source_label") or ""), re.IGNORECASE)
        if card_match:
            try:
                c_day, c_month, c_year = int(card_match.group(1)), int(card_match.group(2)), int(card_match.group(3))
                if c_year < 100:
                    c_year += 2000
                card_date = date(c_year, c_month, c_day)
                year, month, day = card_date.year, card_date.month, card_date.day
            except ValueError:
                pass
        expense_date = date(year, month, day or 1)

        description = str(raw.get("description") or "").strip() or "Opération importée"
        source_label = str(raw.get("source_label") or description).strip()
        category_guess = str(raw.get("category_guess") or "autre").strip().lower()
        valid_cats = income_cats if tx_type == "income" else expense_cats
        category = category_guess if category_guess in valid_cats else "autre"
        # Une correspondance apprise (l'utilisateur a déjà corrigé cette
        # enseigne) l'emporte sur la proposition de l'IA.
        rule_applied = False
        learned = match_rule(learned_rules, tx_type, rule_key(source_label))
        if learned and learned in valid_cats:
            category = learned
            rule_applied = True
        transfer_name = raw.get("transfer_account")
        transfer_account_id = (
            transfer_targets.get(_normalize_key(transfer_name)) if isinstance(transfer_name, str) else None
        )
        loan_id = None
        if transfer_account_id:
            category = TRANSFER_CATEGORY
        elif tx_type == "expense":
            # Mensualité d'un prêt de l'onglet Prêts (même montant, ou
            # libellé de prêt avec un montant proche) : rattachée à ce prêt.
            loan_id = match_loan_for_payment(
                loans, amount, f"{source_label} {description}", hinted=category == LOAN_CATEGORY, category=category
            )
            if loan_id:
                category = LOAN_CATEGORY

        parsed.append({
            "row_index": i,
            "expense_date": expense_date,
            "date_precision": "day" if day else "month",
            "type": tx_type,
            "amount": amount,
            "description": description,
            "category": category,
            "source_label": source_label,
            "transfer_account_id": transfer_account_id,
            "loan_id": loan_id,
            "rule_applied": rule_applied and not transfer_account_id and category != LOAN_CATEGORY,
        })

    if not parsed:
        raise HTTPException(status_code=422, detail="Aucune opération exploitable détectée par l'IA dans ce fichier")

    # Les virements entre comptes de l'utilisateur (ex: tous les mois vers le
    # Livret A) ne sont pas des charges récurrentes, et une mensualité de prêt
    # est déjà suivie dans l'onglet Prêts : exclus de la détection.
    flows = [row for row in parsed if not row["transfer_account_id"] and not row["loan_id"]]
    recurring_candidates, group_by_index = _detect_recurring_patterns(flows) if flows else ([], {})
    for row in parsed:
        row["recurring_group_id"] = None
    for idx, row in enumerate(flows):
        row["recurring_group_id"] = group_by_index.get(idx)

    dates = [row["expense_date"] for row in parsed]
    min_date, max_date = min(dates), max(dates)
    existing_query = (
        client.table("transactions")
        .select("expense_date, amount, type, account_id")
        .eq("user_id", user_id)
        .gte("expense_date", (min_date - timedelta(days=31)).isoformat())
        .lte("expense_date", (max_date + timedelta(days=31)).isoformat())
    )
    if statement_account:
        existing_query = existing_query.eq("account_id", str(statement_account))
    existing = existing_query.execute().data
    # Doublon = même compte, même jour, même montant, même sens. Le libellé
    # n'entre PAS dans la comparaison : l'IA reformule le libellé à chaque
    # lecture (« Virement Melody » / « Virement WERO Melody »), donc comparer
    # le texte laissait passer les doublons. On compte : s'il y a déjà 2
    # opérations identiques en base, les 2 premières du relevé sont des
    # doublons, la 3e est une vraie nouvelle opération.
    remaining: dict[tuple, int] = {}
    for row in existing:
        key = (row["expense_date"], round(float(row["amount"]), 2), row["type"])
        remaining[key] = remaining.get(key, 0) + 1
    pending = []
    for row in parsed:
        key = (row["expense_date"].isoformat(), row["amount"], row["type"])
        if remaining.get(key, 0) > 0:
            remaining[key] -= 1
            row["likely_duplicate"] = True
        else:
            row["likely_duplicate"] = False
            pending.append(row)
    # Lignes dont le jour est incertain (le relevé donne la date de valeur, le
    # libellé une autre date, ou seul le mois est lu) : on les rapproche d'une
    # opération identique restante à 1 jour près, ou du même mois si le jour
    # n'est pas précisé.
    for row in pending:
        month_only = row.get("date_precision") != "day"
        best = None
        for (d, amount, kind), left in remaining.items():
            if left <= 0 or kind != row["type"] or abs(amount - row["amount"]) >= 0.01:
                continue
            gap = abs((date.fromisoformat(d) - row["expense_date"]).days)
            same_month = d[:7] == row["expense_date"].isoformat()[:7]
            if month_only and (gap <= 1 or same_month):
                if best is None or gap < best[0]:
                    best = (gap, (d, amount, kind))
        if best:
            remaining[best[1]] -= 1
            row["likely_duplicate"] = True

    warnings = [w for w in (ai_data.get("warnings") or []) if isinstance(w, str)]
    if skipped:
        warnings.append(f"{skipped} ligne(s) ignorée(s) par l'IA car illisibles")
    if truncated:
        warnings.append(f"Fichier très volumineux : seules les {MAX_GENERIC_IMPORT_ENTRIES} premières opérations détectées ont été gardées")
    try:
        links = _find_transfer_links(client, user_id, str(statement_account) if statement_account else None, parsed)
    except Exception:  # noqa: BLE001 - simple information, ne doit jamais bloquer l'analyse
        links = {}
    for idx, other in links.items():
        # Affichage : la ligne apparaît déjà comme virement avec l'autre compte.
        parsed[idx]["transfer_account_id"] = other["account_id"]
        parsed[idx]["category"] = TRANSFER_CATEGORY
        parsed[idx]["already_recorded"] = True
    if links:
        warnings.append(
            f"{len(links)} virement(s) déjà enregistré(s) depuis l'autre compte : ils seront reliés à l'import, sans doublon (garde-les cochés)."
        )

    statement_check = None
    if statement_balances:
        expected_net = round(statement_balances["closing"] - statement_balances["opening"], 2)
        rows_net = round(
            sum(r["amount"] if r["type"] == "income" else -r["amount"] for r in parsed), 2
        )
        columns_net = round(statement_balances["credits"] - statement_balances["debits"], 2)
        statement_check = {
            **statement_balances,
            "expected_net": expected_net,
            "rows_net": rows_net,
            "rows_diff": round(rows_net - expected_net, 2),
            "columns_diff": round(columns_net - expected_net, 2),
            "ok": abs(rows_net - expected_net) < 0.01,
        }

    return {
        "rows": parsed,
        "statement_check": statement_check,
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


_TRANSFER_WORDS = re.compile(r"\b(vir|virt|vrt|virement|virements)\b")


def _plain_label(text: str | None) -> str:
    text = unicodedata.normalize("NFD", text or "")
    return "".join(c for c in text if unicodedata.category(c) != "Mn").lower()


_GENERIC_LABEL_WORDS = {
    "vir", "virt", "vrt", "virement", "virements", "inst", "instantane", "instantanee", "pour", "de", "du", "des", "le", "la",
    "a", "au", "vers", "recu", "emis", "sepa", "compte", "mr", "m", "mme", "mlle", "default", "reference", "ref", "debit",
    "credit", "date", "valeur", "iban", "masque", "personnel", "propre", "perso", "et", "en", "sur",
}


def _label_words(text: str | None) -> set[str]:
    return {w for w in re.findall(r"[a-z]{3,}", _plain_label(text)) if w not in _GENERIC_LABEL_WORDS}


def _foreign_label(candidate_text: str | None, row_text: str) -> bool:
    """Vrai si le libellé de l'opération existante parle de quelqu'un/quelque
    chose d'autre que le libellé du relevé (ex : « argent de poche … JEAN-MARC »
    face à « virement pour MATTEO CAMPANELLI ») : ce n'est pas la même opération.
    Un libellé court (« Clé voiture », « Essence ») reste accepté."""
    own = _label_words(row_text)
    extra = _label_words(candidate_text) - own
    return len(extra) > 2


def _find_transfer_links(client, user_id: str, account_id: str | None, rows: list[dict]) -> dict[int, dict]:
    """Pour chaque ligne du relevé de `account_id` qui est en fait un virement
    déjà enregistré depuis l'autre compte, renvoie {position: opération
    existante}. `rows` : dicts avec expense_date (date), type, amount,
    description, source_label, transfer_account_id, loan_id.

    Une ligne « virement » qui correspond à UNE SEULE opération déjà
    enregistrée sur un autre compte (sens inverse, même montant, dates
    identiques ou à 3 jours près, libellés de virement des deux côtés) est le
    même mouvement d'argent vu des deux relevés. L'opération existante est soit
    à relier (`needs_link`), soit déjà un virement vers ce compte. Au moindre
    doute (plusieurs correspondances possibles), rien n'est lié."""
    if not account_id or not rows:
        return {}
    from datetime import timedelta
    dates = [row["expense_date"] for row in rows]
    existing = (
        client.table("transactions")
        .select("id, type, amount, description, expense_date, account_id, transfer_account_id, loan_id, recurring_expense_id")
        .eq("user_id", user_id)
        .gte("expense_date", (min(dates) - timedelta(days=3)).isoformat())
        .lte("expense_date", (max(dates) + timedelta(days=3)).isoformat())
        .execute()
        .data
    )
    candidates = []
    for e in existing:
        if not e.get("account_id") or e["account_id"] == account_id or e.get("loan_id") or e.get("recurring_expense_id"):
            continue
        if not _TRANSFER_WORDS.search(_plain_label(e.get("description"))):
            continue
        if not e.get("transfer_account_id"):
            candidates.append({**e, "needs_link": True})
        elif e["transfer_account_id"] == account_id:
            candidates.append({**e, "needs_link": False})  # déjà relié à ce compte
    matches: dict[int, list[dict]] = {}
    for idx, row in enumerate(rows):
        if row.get("loan_id"):
            continue
        wanted = str(row["transfer_account_id"]) if row.get("transfer_account_id") else None
        if not _TRANSFER_WORDS.search(_plain_label(f"{row.get('source_label') or ''} {row.get('description') or ''}")):
            continue
        matches[idx] = [
            e for e in candidates
            if (not wanted or e["account_id"] == wanted)
            and (not e["needs_link"] or not _foreign_label(e.get("description"), f"{row.get('source_label') or ''} {row.get('description') or ''}"))
            and e["type"] != row["type"]
            and abs(float(e["amount"]) - float(row["amount"])) < 0.01
            and abs((date.fromisoformat(e["expense_date"]) - row["expense_date"]).days) <= 3
        ]
    found: dict[int, dict] = {}
    used: set[str] = set()
    for idx, cands in matches.items():
        if len(cands) != 1 or cands[0]["id"] in used:
            continue
        other = cands[0]
        # Réciproque : cette opération existante ne doit correspondre qu'à une
        # seule ligne du relevé.
        if sum(1 for c in matches.values() if any(x["id"] == other["id"] for x in c)) != 1:
            continue
        used.add(other["id"])
        found[idx] = other
    # Plusieurs virements identiques (même montant, quelques jours d'écart, même
    # compte d'en face) : impossible de dire lequel est lequel, mais ça n'a pas
    # d'importance, ils sont interchangeables. On les apparie au plus proche.
    pairs = []
    for idx, cands in matches.items():
        if idx in found:
            continue
        # Une opération déjà reliée à CE compte est forcément la contrepartie
        # (un autre virement de même montant d'un tiers ne doit pas gêner).
        linked_here = [c for c in cands if not c["needs_link"]]
        if linked_here:
            cands = linked_here
        accounts = {c["account_id"] for c in cands}
        if len(accounts) != 1:
            continue  # contreparties sur des comptes différents : on ne devine pas
        for c in cands:
            if c["id"] in used:
                continue
            gap = abs((date.fromisoformat(c["expense_date"]) - rows[idx]["expense_date"]).days)
            pairs.append((gap, idx, c["id"], c))
    pairs.sort(key=lambda x: (x[0], x[1], x[2]))
    for gap, idx, cid, c in pairs:
        if idx in found or cid in used:
            continue
        used.add(cid)
        found[idx] = c
    return found


def _link_existing_transfers(client, user_id: str, account_id: str | None, rows: list) -> set[int]:
    """Applique `_find_transfer_links` à l'import : relie l'opération existante
    si besoin, et renvoie les positions des lignes absorbées (à ne pas
    ajouter, sinon le virement compterait deux fois)."""
    plain = [
        {
            "expense_date": r.expense_date, "type": r.type, "amount": r.amount,
            "description": r.description, "source_label": r.source_label,
            "transfer_account_id": r.transfer_account_id, "loan_id": r.loan_id,
        }
        for r in rows
    ]
    found = _find_transfer_links(client, user_id, account_id, plain)
    for other in found.values():
        if other["needs_link"]:
            client.table("transactions").update(
                {"transfer_account_id": account_id, "category": TRANSFER_CATEGORY}
            ).eq("id", other["id"]).eq("user_id", user_id).execute()
    return set(found)


@router.post("/api/import/generic/commit", status_code=201)
def commit_generic_import(req: GenericImportCommitRequest, user_id: str = Depends(require_user)) -> dict:
    if not req.transactions and not req.recurring:
        raise HTTPException(status_code=400, detail="Rien à importer")

    client = get_supabase_client()
    ensure_own_accounts(
        client, user_id, req.account_id, *(row.transfer_account_id for row in req.transactions)
    )
    account_id = str(req.account_id) if req.account_id else None
    inserted_transactions = 0
    inserted_recurring = 0
    loans = active_loans(client, user_id) if req.transactions else []
    own_loan_ids = {
        row["id"]
        for row in client.table("property_loans").select("id").eq("user_id", user_id).execute().data
    } if any(row.loan_id for row in req.transactions) else set()
    if any(row.loan_id and str(row.loan_id) not in own_loan_ids for row in req.transactions):
        raise HTTPException(status_code=400, detail="Prêt introuvable")

    linked_transfers = 0
    if req.transactions:
        absorbed = _link_existing_transfers(client, user_id, account_id, req.transactions)
        linked_transfers = len(absorbed)
        payload = []
        for position, row in enumerate(req.transactions):
            if position in absorbed:
                continue
            # Un "virement" vers le compte du relevé lui-même n'en est pas un :
            # la ligne redevient une dépense/un revenu normal ("autre").
            transfer_id = (
                str(row.transfer_account_id)
                if row.transfer_account_id and str(row.transfer_account_id) != account_id
                else None
            )
            category = (row.category or "autre").strip() or "autre"
            loan_id = str(row.loan_id) if row.loan_id and not transfer_id else None
            if transfer_id:
                category = TRANSFER_CATEGORY
            elif category == TRANSFER_CATEGORY:
                category = "autre"
            if (
                not transfer_id
                and not loan_id
                and "loan_id" not in row.model_fields_set
                and row.type == "expense"
            ):
                # Ligne dont l'utilisateur n'a pas touché la catégorie : on
                # tente le rattachement à un prêt maintenant, ce qui couvre les
                # prêts créés juste avant par le même import de classeur.
                loan_id = match_loan_for_payment(
                    loans, row.amount, row.description, hinted=category == LOAN_CATEGORY, category=category
                )
            if loan_id:
                category = LOAN_CATEGORY
            payload.append({
                "type": row.type,
                "amount": row.amount,
                "category": category,
                "description": row.description,
                "expense_date": row.expense_date.isoformat(),
                "user_id": user_id,
                "account_id": account_id,
                "transfer_account_id": transfer_id,
                "loan_id": loan_id,
            })
            if row.learn_rule and not transfer_id and not loan_id and category not in (TRANSFER_CATEGORY, LOAN_CATEGORY):
                learn_rule(client, user_id, row.type, row.source_label or row.description, category)
        if payload:
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

    return {
        "inserted_transactions": inserted_transactions,
        "inserted_recurring": inserted_recurring,
        "linked_transfers": linked_transfers,
    }


# ---------------------------------------------------------------------------
# Classeur onglet par onglet
# ---------------------------------------------------------------------------
@router.post("/api/import/workbook/analyze", response_model=None)
async def analyze_workbook_import(file: UploadFile = File(...), user_id: str = Depends(require_user)) -> dict:
    """Reconnaît le type de chaque onglet sans rien écrire en base ni appeler
    l'IA : l'utilisateur confirme ensuite onglet par onglet."""
    filename = (file.filename or "").lower()
    if not filename.endswith(_SPREADSHEET_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Formats acceptés : .xlsx ou .xlsm")
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Fichier vide")
    if len(raw_bytes) > MAX_WORKBOOK_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (4 Mo maximum)")
    try:
        sheets = analyze_workbook(raw_bytes, today_paris())
    except Exception as exc:  # noqa: BLE001 - fichier corrompu, protégé par mot de passe...
        raise HTTPException(status_code=400, detail="Fichier Excel illisible") from exc

    # Prêts déjà présents (même bien, même date de départ) : proposés
    # décochés, pour ne pas créer de doublon en réimportant le même fichier.
    client = get_supabase_client()
    existing = (
        client.table("property_loans")
        .select("property_name, start_date")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    existing_keys = {(property_key(row["property_name"]), str(row["start_date"])[:10]) for row in existing}
    existing_names = {property_key(row["property_name"]) for row in existing}
    for sheet in sheets:
        loan = sheet.get("loan")
        if not loan:
            continue
        key = property_key(loan["property_name"])
        if (key, loan["start_date"]) in existing_keys:
            loan["already_imported"] = True
            sheet["selected"] = False
            sheet["note"] = "Déjà importé"
        else:
            loan["already_imported"] = False
            loan["same_name_exists"] = key in existing_names
    return {"sheets": sheets}


@router.post("/api/import/workbook/commit", status_code=201)
def commit_workbook_import(req: WorkbookCommitRequest, user_id: str = Depends(require_user)) -> dict:
    if not req.loans and not req.snapshots:
        raise HTTPException(status_code=400, detail="Rien à importer")
    client = get_supabase_client()
    inserted_loans = 0
    updated_rents = 0
    inserted_snapshots = 0

    if req.loans:
        existing = (
            client.table("property_loans")
            .select("id, property_name, start_date")
            .eq("user_id", user_id)
            .execute()
            .data
        )
        existing_by_key = {
            (property_key(row["property_name"]), str(row["start_date"])[:10]): row["id"] for row in existing
        }
        to_insert = []
        for loan in req.loans:
            key = (property_key(loan.property_name), loan.start_date.isoformat())
            if key in existing_by_key:
                # Même prêt déjà importé : on met juste le loyer à jour.
                if loan.monthly_rent is not None:
                    client.table("property_loans").update({"monthly_rent": loan.monthly_rent}).eq(
                        "id", existing_by_key[key]
                    ).eq("user_id", user_id).execute()
                    updated_rents += 1
                continue
            to_insert.append({
                "user_id": user_id,
                "property_name": loan.property_name.strip(),
                "principal_amount": loan.principal_amount,
                "annual_rate_pct": loan.annual_rate_pct,
                "monthly_payment": loan.monthly_payment,
                "start_date": loan.start_date.isoformat(),
                "monthly_rent": loan.monthly_rent,
                "active": loan.active,
            })
        if to_insert:
            inserted_loans = len(client.table("property_loans").insert(to_insert).execute().data)

    if req.snapshots:
        existing_dates = {
            str(row["snapshot_date"])[:10]
            for row in client.table("net_worth_snapshots")
            .select("snapshot_date")
            .eq("user_id", user_id)
            .execute()
            .data
        }
        rows = []
        for snap in req.snapshots:
            day = snap.snapshot_date.isoformat()
            if day in existing_dates:
                continue
            existing_dates.add(day)
            rows.append({
                "user_id": user_id,
                "snapshot_date": day,
                "assets": round(snap.assets, 2),
                "debts": round(snap.debts, 2),
                "label": (snap.label or "").strip() or None,
            })
        if rows:
            inserted_snapshots = len(client.table("net_worth_snapshots").insert(rows).execute().data)

    return {
        "inserted_loans": inserted_loans,
        "updated_rents": updated_rents,
        "inserted_snapshots": inserted_snapshots,
    }
