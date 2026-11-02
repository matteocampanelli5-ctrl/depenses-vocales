"""Résumé mensuel envoyé par email (facultatif, activé dans Aide > Préférences)."""

from datetime import date
from html import escape

from app.emails import _send_email

TRANSFER_CATEGORY = "virement"


def previous_month_bounds(today: date) -> tuple[date, date, str]:
    first_this = today.replace(day=1)
    last_prev = date.fromordinal(first_this.toordinal() - 1)
    first_prev = last_prev.replace(day=1)
    return first_prev, first_this, first_prev.strftime("%Y-%m")


def _eur(value: float) -> str:
    return f"{value:,.2f} €".replace(",", " ").replace(".", ",")


def build_summary(rows: list[dict]) -> dict:
    expenses = incomes = 0.0
    by_cat: dict[str, float] = {}
    for row in rows:
        if row.get("category") == TRANSFER_CATEGORY or row.get("transfer_account_id"):
            continue
        amount = float(row.get("amount") or 0)
        if row.get("type") == "income":
            incomes += amount
        else:
            expenses += amount
            by_cat[row.get("category") or "autre"] = by_cat.get(row.get("category") or "autre", 0) + amount
    top = sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)[:3]
    return {"expenses": round(expenses, 2), "incomes": round(incomes, 2), "top": top}


def send_monthly_summary(client, user: dict, today: date) -> bool:
    start, end, label = previous_month_bounds(today)
    rows = (
        client.table("transactions")
        .select("amount, type, category, transfer_account_id, expense_date")
        .eq("user_id", user["id"])
        .gte("expense_date", start.isoformat())
        .lt("expense_date", end.isoformat())
        .execute()
        .data
    )
    if not rows:
        return False
    s = build_summary(rows)
    net = s["incomes"] - s["expenses"]
    top_html = "".join(f"<li>{escape(str(c))} : {_eur(v)}</li>" for c, v in s["top"])
    html = (
        f"<p>Voici ton bilan de <strong>{label}</strong> sur Kaching :</p>"
        f"<ul><li>Dépenses : {_eur(s['expenses'])}</li><li>Revenus : {_eur(s['incomes'])}</li>"
        f"<li>Solde du mois : {_eur(net)}</li></ul>"
        f"<p>Tes plus grosses catégories :</p><ul>{top_html}</ul>"
        "<p>Tu peux désactiver cet email dans Aide &gt; Préférences.</p>"
    )
    return _send_email(user["email"], f"Kaching — ton bilan de {label}", html)
