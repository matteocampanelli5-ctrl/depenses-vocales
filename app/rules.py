"""Règles apprises à l'import : libellé de relevé -> catégorie.

Quand l'utilisateur corrige la catégorie proposée pour une ligne de relevé
(ex : « CARREFOUR MARKET » classé « Autre » -> « Courses »), on mémorise la
correspondance. Aux imports suivants, la même enseigne reçoit directement la
bonne catégorie, avant même que l'IA ne propose la sienne.
"""

import re
import unicodedata

# Mots de bruit que les banques ajoutent devant ou derrière l'enseigne.
_NOISE_WORDS = {
    "cb", "carte", "paiement", "prlv", "prelevement", "vir", "virement", "sepa", "achat",
    "retrait", "dab", "facture", "fact", "pos", "contactless", "sans", "contact", "de", "du", "la", "le", "des",
}
MAX_RULES_PER_USER = 500


def rule_key(label: str | None) -> str:
    """Clé stable d'un libellé : sans accents ni dates ni chiffres ni bruit
    bancaire, limitée aux trois premiers mots. Vide si rien d'exploitable."""
    if not label:
        return ""
    text = "".join(c for c in unicodedata.normalize("NFD", str(label)) if unicodedata.category(c) != "Mn").lower()
    text = re.sub(r"\b\d{1,2}[/.-]\d{1,2}(?:[/.-]\d{2,4})?\b", " ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    words = [w for w in text.split() if len(w) > 1 and w not in _NOISE_WORDS and not re.fullmatch(r"x+", w)]
    return " ".join(words[:3])[:60]


def load_rules(client, user_id: str) -> dict[tuple[str, str], str]:
    """{(type, clé): catégorie} pour tout ce que l'utilisateur a appris."""
    rows = client.table("category_rules").select("tx_type, rule_key, category").eq("user_id", user_id).execute().data
    return {(row["tx_type"], row["rule_key"]): row["category"] for row in rows}


def learn_rule(client, user_id: str, tx_type: str, label: str | None, category: str) -> bool:
    key = rule_key(label)
    if not key or not category:
        return False
    existing = (
        client.table("category_rules")
        .select("id")
        .eq("user_id", user_id)
        .eq("tx_type", tx_type)
        .eq("rule_key", key)
        .limit(1)
        .execute()
        .data
    )
    if existing:
        client.table("category_rules").update({"category": category}).eq("id", existing[0]["id"]).eq("user_id", user_id).execute()
        return True
    total = client.table("category_rules").select("id").eq("user_id", user_id).execute().data
    if len(total) >= MAX_RULES_PER_USER:
        return False
    client.table("category_rules").insert(
        {"user_id": user_id, "tx_type": tx_type, "rule_key": key, "category": category}
    ).execute()
    return True


def match_rule(rules: dict[tuple[str, str], str], tx_type: str, key: str) -> str | None:
    """Catégorie apprise pour ce libellé : correspondance exacte, sinon la règle
    la plus longue dont la clé est le début du libellé (une règle apprise sur
    « escota » s'applique aussi à « escota vinci »)."""
    if not key:
        return None
    if (tx_type, key) in rules:
        return rules[(tx_type, key)]
    best = None
    for (rtype, rkey), category in rules.items():
        if rtype == tx_type and key.startswith(rkey + " ") and (best is None or len(rkey) > len(best[0])):
            best = (rkey, category)
    return best[1] if best else None
