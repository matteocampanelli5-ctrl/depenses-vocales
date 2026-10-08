"""Emails transactionnels (vérification d'adresse, mot de passe oublié,
invitations) via Resend, et alertes techniques à l'admin.

Best-effort de bout en bout : si RESEND_API_KEY n'est pas configurée, ou si
l'envoi échoue pour une raison quelconque (clé invalide, Resend
indisponible...), on ne bloque JAMAIS l'opération elle-même — le lien reste
valide et utilisable, simplement l'email ne part pas. Mieux vaut un compte
créé sans email de bienvenue qu'une inscription qui plante.
"""

from datetime import datetime, timezone

from app.config import ADMIN_ALERT_EMAIL, APP_PUBLIC_URL, RESEND_API_KEY, RESEND_FROM_EMAIL
from app.db import get_supabase_client


def _send_email(to: str, subject: str, html: str) -> bool:
    if not RESEND_API_KEY:
        return False
    import httpx

    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={"from": RESEND_FROM_EMAIL, "to": [to], "subject": subject, "html": html},
            timeout=10,
        )
        return response.status_code < 300
    except Exception:  # noqa: BLE001 - un email qui ne part pas ne doit jamais faire planter l'opération
        return False


def _build_link(path: str, token: str, query_key: str = "token") -> str:
    base = APP_PUBLIC_URL.rstrip("/") if APP_PUBLIC_URL else ""
    return f"{base}{path}?{query_key}={token}"


# ---------------------------------------------------------------------------
# Alertes techniques à l'admin (ex: panne de l'API Anthropic — plus de
# crédit, clé invalide...), envoyées à ADMIN_ALERT_EMAIL. Contrairement aux
# invitations/resets envoyés à un tiers, celle-ci part vers la propre
# adresse du compte Resend : donc PAS concernée par la restriction sandbox
# qui bloque les destinataires tiers sans domaine vérifié — ça marche tel
# quel. Un cooldown (table admin_alerts) évite de spammer l'admin si la
# panne dure : une seule alerte par clé et par fenêtre de temps, best-effort
# de bout en bout (une alerte qui échoue ne doit jamais faire planter
# l'opération qui l'a déclenchée).
# ---------------------------------------------------------------------------
ADMIN_ALERT_COOLDOWN_SECONDS = 60 * 60  # 1 heure


def _notify_admin_once(key: str, subject: str, html: str) -> None:
    if not ADMIN_ALERT_EMAIL:
        return
    try:
        client = get_supabase_client()
        rows = client.table("admin_alerts").select("*").eq("key", key).limit(1).execute().data
        now = datetime.now(timezone.utc)
        if rows:
            last_sent_at = datetime.fromisoformat(str(rows[0]["last_sent_at"]).replace("Z", "+00:00"))
            if (now - last_sent_at).total_seconds() < ADMIN_ALERT_COOLDOWN_SECONDS:
                return
            client.table("admin_alerts").update({"last_sent_at": now.isoformat()}).eq("key", key).execute()
        else:
            client.table("admin_alerts").insert({"key": key, "last_sent_at": now.isoformat()}).execute()
        _send_email(ADMIN_ALERT_EMAIL, subject, html)
    except Exception:  # noqa: BLE001
        pass
