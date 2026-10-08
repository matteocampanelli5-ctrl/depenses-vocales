"""Mots de passe, jetons de session signés, et anti-brute-force sur la
connexion / la réinitialisation de mot de passe.

---------------------------------------------------------------------------
Mots de passe : hachage PBKDF2-HMAC-SHA256 (bibliothèque standard Python
uniquement, pas de dépendance externe type bcrypt à installer sur Vercel).
310 000 itérations = recommandation OWASP 2023 pour PBKDF2-SHA256. Format
stocké : "pbkdf2$<itérations>$<sel hex>$<hash hex>" — le nombre
d'itérations fait partie du hash stocké, pour pouvoir le relever plus tard
sans invalider les mots de passe déjà enregistrés.
---------------------------------------------------------------------------
"""

import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta, timezone

from fastapi import Header, HTTPException

from app.config import API_SECRET_KEY
from app.db import get_supabase_client
from app.emails import _notify_admin_once

_PBKDF2_ITERATIONS = 310_000


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations_str, salt_hex, digest_hex = stored_hash.split("$")
        if scheme != "pbkdf2":
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_token() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()


# ---------------------------------------------------------------------------
# Authentification par compte + jeton de session signé
# ---------------------------------------------------------------------------
# Principe inchangé par rapport à l'ancien système mono-mot de passe : un
# jeton "<payload>.<signature>" signé avec API_SECRET_KEY, sans aucun état
# gardé en mémoire (Vercel est sans état entre les invocations) — n'importe
# quelle invocation peut le revalider elle-même en recalculant la signature.
# Nouveau : le payload contient maintenant l'identifiant du compte (user_id),
# pas seulement une date d'expiration — c'est ce qui permet à chacun de ne
# voir que ses propres données (toutes les routes ci-dessous filtrent par ce
# user_id). Un jeton ne peut pas être forgé sans connaître API_SECRET_KEY, et
# ne peut pas non plus être réattribué à un autre compte sans le casser (la
# signature couvre le user_id lui-même).
#
# Le payload embarque aussi un "security_stamp" (app_users.security_stamp,
# une chaîne aléatoire tirée à la création du compte) : c'est ce qui permet
# de révoquer tous les jetons déjà émis pour un compte sans tenir d'état côté
# serveur — _record_password_change() en tire un nouveau après une
# réinitialisation de mot de passe, et require_user() compare le stamp du
# jeton à celui actuellement en base. Sans ça, un jeton volé avant un "mot de
# passe oublié" resterait valable jusqu'à ses 90 jours même après le reset.
SESSION_DURATION_SECONDS = 90 * 24 * 3600  # 90 jours


def _sign_session_payload(payload: str) -> str:
    return hmac.new(API_SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _create_session_token(user_id: str, security_stamp: str) -> str:
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    payload = f"{user_id}:{expires_at}:{security_stamp}"
    return f"{payload}.{_sign_session_payload(payload)}"


def _verify_session_token(token: str) -> tuple[str, str] | None:
    """Renvoie (user_id, security_stamp) si le jeton est valide (signature et
    expiration), sinon None. Ne vérifie PAS encore que le security_stamp
    correspond toujours à celui en base (voir require_user, qui fait cette
    dernière vérification avec un appel à la base)."""
    if not token or not API_SECRET_KEY or "." not in token:
        return None
    payload, _, signature = token.rpartition(".")
    if not payload:
        return None
    expected_signature = _sign_session_payload(payload)
    if not hmac.compare_digest(signature, expected_signature):
        return None
    user_id, _, rest = payload.partition(":")
    expires_part, _, security_stamp = rest.partition(":")
    try:
        expires_at = int(expires_part)
    except ValueError:
        return None
    if time.time() >= expires_at or not user_id or not security_stamp:
        return None
    return user_id, security_stamp


def require_user(x_api_key: str = Header(default="", alias="X-API-Key")) -> str:
    """Exige un jeton de session valide (obtenu via /api/auth/login ou
    /api/auth/signup) et renvoie l'identifiant du compte associé — c'est ce
    user_id qui scope chaque lecture/écriture pour que personne ne voie les
    données d'un autre compte. Vérifie aussi que le security_stamp du jeton
    correspond à celui actuellement en base : un jeton émis avant un
    changement de mot de passe (donc potentiellement volé) est ainsi rejeté
    même s'il n'a pas encore expiré."""
    parsed = _verify_session_token(x_api_key)
    if not parsed:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée, reconnecte-toi")
    user_id, security_stamp = parsed
    client = get_supabase_client()
    rows = client.table("app_users").select("security_stamp").eq("id", user_id).limit(1).execute().data
    if not rows or rows[0].get("security_stamp") != security_stamp:
        raise HTTPException(status_code=401, detail="Session invalide ou expirée, reconnecte-toi")
    return user_id


# ---------------------------------------------------------------------------
# Anti-brute-force sur /api/auth/login — PAR COMPTE (plus globale comme
# avant) : un verrouillage ne bloque que le compte ciblé par les échecs,
# jamais les autres. Limite connue et acceptée à ce stade : quelqu'un qui
# connaît l'email d'un proche peut encore le verrouiller temporairement (15
# minutes) en multipliant volontairement les échecs — à revoir (ex : limite
# par IP en plus) si l'appli s'ouvre un jour largement au-delà d'un cercle de
# confiance.
# ---------------------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60  # 15 minutes


def _get_login_attempts_row(client, email: str) -> dict:
    rows = client.table("login_attempts").select("*").eq("email", email).limit(1).execute().data
    if rows:
        return rows[0]
    result = client.table("login_attempts").insert({"email": email, "failed_count": 0}).execute()
    return result.data[0]


def _enforce_login_lockout(row: dict) -> None:
    locked_until = row.get("locked_until")
    if not locked_until:
        return
    locked_until_dt = datetime.fromisoformat(str(locked_until).replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if now < locked_until_dt:
        remaining_minutes = int((locked_until_dt - now).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives incorrectes. Réessaie dans {remaining_minutes} minute(s).",
        )


def _record_login_result(client, row: dict, success: bool) -> None:
    if success:
        client.table("login_attempts").update(
            {"failed_count": 0, "locked_until": None}
        ).eq("id", row["id"]).execute()
        return

    new_count = row.get("failed_count", 0) + 1
    payload: dict = {"failed_count": new_count}
    if new_count >= LOGIN_MAX_ATTEMPTS:
        payload["failed_count"] = 0
        payload["locked_until"] = (
            datetime.now(timezone.utc) + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        ).isoformat()
    client.table("login_attempts").update(payload).eq("id", row["id"]).execute()


# ---------------------------------------------------------------------------
# Anti-spam sur /api/auth/forgot-password — même principe que le
# verrouillage de /api/auth/login ci-dessus (une ligne par email, limite
# connue et acceptée : par email et non par IP). Sans ça, n'importe qui
# pouvait déclencher l'envoi de l'email de réinitialisation en boucle sur une
# adresse donnée. Compte à part de login_attempts car la sémantique diffère
# (ici on compte des DEMANDES, pas des échecs — chaque appel compte, que le
# compte existe ou non, pour ne jamais révéler par ce biais si un email est
# enregistré).
# ---------------------------------------------------------------------------
PASSWORD_RESET_MAX_REQUESTS = 3
PASSWORD_RESET_LOCKOUT_SECONDS = 60 * 60  # 1 heure


def _get_password_reset_attempts_row(client, email: str) -> dict:
    rows = client.table("password_reset_requests").select("*").eq("email", email).limit(1).execute().data
    if rows:
        return rows[0]
    result = client.table("password_reset_requests").insert({"email": email, "request_count": 0}).execute()
    return result.data[0]


def _enforce_password_reset_lockout(row: dict) -> None:
    locked_until = row.get("locked_until")
    if not locked_until:
        return
    locked_until_dt = datetime.fromisoformat(str(locked_until).replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if now < locked_until_dt:
        remaining_minutes = int((locked_until_dt - now).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Trop de demandes pour cette adresse. Réessaie dans {remaining_minutes} minute(s).",
        )


def _record_password_reset_request(client, row: dict) -> None:
    new_count = row.get("request_count", 0) + 1
    payload: dict = {"request_count": new_count}
    if new_count >= PASSWORD_RESET_MAX_REQUESTS:
        payload["request_count"] = 0
        payload["locked_until"] = (
            datetime.now(timezone.utc) + timedelta(seconds=PASSWORD_RESET_LOCKOUT_SECONDS)
        ).isoformat()
        # Verrouillage déclenché : signe possible d'un tiers qui essaie de
        # déclencher des réinitialisations sur cette adresse. Même mécanique
        # d'alerte (avec cooldown) que la panne de l'API Anthropic ci-dessus,
        # réutilisée ici pour la sécurité du compte plutôt que pour l'IA.
        _notify_admin_once(
            f"password_reset_lockout:{row.get('email', '')}",
            "🔒 Kaching — verrouillage mot de passe oublié",
            (
                f"<p>L'adresse <strong>{row.get('email', '')}</strong> a dépassé le nombre de demandes "
                f"autorisées pour « mot de passe oublié » ({PASSWORD_RESET_MAX_REQUESTS}) et est "
                f"verrouillée pendant 1 heure. Si ce n'est pas toi, quelqu'un essaie peut-être "
                f"d'accéder à ce compte.</p>"
            ),
        )
    client.table("password_reset_requests").update(payload).eq("id", row["id"]).execute()
