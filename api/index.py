"""
Point d'entrée unique de l'API (et du frontend) pour Vercel.

Tout est regroupé dans ce seul fichier .py : c'est volontaire. Vercel ne
garantit pas d'embarquer les fichiers non-Python présents à côté du point
d'entrée (ex: frontend/index.html) dans le paquet de la fonction serverless.
Le HTML du frontend est donc encodé en base64 et copié directement dans ce
fichier par build.py, qui régénère la section entre les marqueurs
BEGIN_FRONTEND_B64 / END_FRONTEND_B64 ci-dessous. Ne jamais éditer cette
section à la main — éditer frontend/index.html puis relancer build.py.
"""

import base64
import calendar
import csv
import hashlib
import hmac
import json
import os
import re
import time
import unicodedata
from datetime import date, datetime, timedelta, timezone
from io import BytesIO, StringIO
from typing import Literal
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI()


# En-têtes de sécurité appliqués à TOUTES les réponses :
# - X-Content-Type-Options: empêche un navigateur de deviner ("sniffer") un
#   autre type de contenu que celui déclaré — utile en particulier pour les
#   photos de reçus (uploadées par l'utilisateur) : sans ça, un fichier dont
#   le contenu ressemble à du HTML pourrait, sur certains navigateurs plus
#   anciens, être exécuté comme tel malgré son Content-Type image/*.
# - X-Frame-Options: interdit d'afficher le site dans une <iframe> sur un
#   autre site (protection contre le "clickjacking", notamment sur l'écran de
#   mot de passe).
# - Referrer-Policy: n'envoie pas l'URL complète de la page (potentiellement
#   avec des paramètres) comme referrer vers d'autres sites.
# - Strict-Transport-Security (HSTS) : dit au navigateur de ne plus jamais
#   essayer la version http:// de ce site, même si quelqu'un tape l'URL sans
#   le "s". En pratique *.vercel.app est déjà sur la liste de préchargement
#   HSTS des navigateurs (donc déjà forcé en HTTPS avant même la première
#   requête), ce header est une couche de robustesse en plus, utile surtout
#   si un domaine personnalisé est branché un jour dessus.
# - Content-Security-Policy : limite les origines dont le navigateur accepte
#   de charger du script/style/image/etc. Même avec 'unsafe-inline' (requis
#   ici car toute la page est un seul fichier HTML avec son JS/CSS en ligne,
#   pas de fichiers séparés), ça bloque un script qui tenterait de charger
#   une ressource depuis un domaine extérieur non listé — utile si jamais
#   une faille XSS passait malgré l'échappement déjà en place côté JS.
# - Permissions-Policy : désactive les API sensibles du navigateur non
#   utilisées (caméra, géolocalisation, paiement...) ; le micro reste
#   autorisé en 'self' car l'assistant vocal en a besoin.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), payment=(), usb=(), microphone=(self)"
    )
    return response


PARIS_TZ = ZoneInfo("Europe/Paris")

TransactionType = Literal["expense", "income"]

EXPENSE_CATEGORIES = {"restaurant", "courses", "transport", "logement", "loisirs", "santé", "autre"}
INCOME_CATEGORIES = {"salaire", "freelance", "remboursement", "cadeau", "autre"}

# Libellés lisibles pour l'export Excel (les catégories sont stockées en base
# sous forme de slugs courts — "restaurant", "salaire"... — mais on veut un
# fichier lisible par un humain, pas les codes internes).
EXPENSE_CATEGORY_LABELS = {
    "restaurant": "Restaurant", "courses": "Courses", "transport": "Transport",
    "logement": "Logement", "loisirs": "Loisirs", "santé": "Santé", "autre": "Autre",
}
INCOME_CATEGORY_LABELS = {
    "salaire": "Salaire", "freelance": "Freelance", "remboursement": "Remboursement",
    "cadeau": "Cadeau", "autre": "Autre",
}


def category_label(category: str, tx_type: str) -> str:
    labels = INCOME_CATEGORY_LABELS if tx_type == "income" else EXPENSE_CATEGORY_LABELS
    return labels.get(category, category)


def today_paris() -> date:
    """Date du jour en heure locale Europe/Paris (pas UTC) — important près de
    minuit, où le jour calendaire à Paris peut différer du jour UTC."""
    return datetime.now(PARIS_TZ).date()


# ---------------------------------------------------------------------------
# Configuration (variables d'environnement à définir sur Vercel)
# ---------------------------------------------------------------------------
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
# Clé service_role (secrète) et non la clé anon (publique) : le RLS est
# activé sans aucune policy pour anon/public, donc seule service_role peut
# lire/écrire. Cette clé ne doit JAMAIS être envoyée au frontend — elle vit
# uniquement ici, côté serveur, comme variable d'environnement Vercel.
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Service d'envoi d'emails (vérification d'adresse, mot de passe oublié,
# invitations). Sans clé configurée, les emails ne partent simplement pas —
# l'opération elle-même n'est jamais bloquée (le lien utile est toujours
# renvoyé dans la réponse de l'API en secours).
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "Kaching <onboarding@resend.dev>")
# URL publique de l'appli (ex: https://kaching.vercel.app, SANS slash final),
# utilisée pour construire les liens envoyés par email.
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "")
# Adresse où envoyer les alertes techniques (ex: panne de l'API Anthropic) —
# doit être la même adresse que le compte Resend lui-même, seule autorisée
# en mode sandbox (sans nom de domaine vérifié). Optionnelle : sans elle, les
# alertes sont simplement désactivées (aucune erreur, juste pas d'email).
ADMIN_ALERT_EMAIL = os.environ.get("ADMIN_ALERT_EMAIL", "")


# ---------------------------------------------------------------------------
# Mots de passe : hachage PBKDF2-HMAC-SHA256 (bibliothèque standard Python
# uniquement, pas de dépendance externe type bcrypt à installer sur Vercel).
# 310 000 itérations = recommandation OWASP 2023 pour PBKDF2-SHA256. Format
# stocké : "pbkdf2$<itérations>$<sel hex>$<hash hex>" — le nombre
# d'itérations fait partie du hash stocké, pour pouvoir le relever plus tard
# sans invalider les mots de passe déjà enregistrés.
# ---------------------------------------------------------------------------
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


def get_supabase_client():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(
            status_code=500,
            detail="Configuration Supabase manquante (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)",
        )
    from supabase import create_client

    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


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


# ---------------------------------------------------------------------------
# Emails transactionnels (vérification d'adresse, mot de passe oublié,
# invitations) via Resend. Best-effort : si RESEND_API_KEY n'est pas
# configurée, ou si l'envoi échoue pour une raison quelconque (clé invalide,
# Resend indisponible...), on ne bloque JAMAIS l'opération elle-même — le
# lien reste valide et utilisable, simplement l'email ne part pas. Mieux vaut
# un compte créé sans email de bienvenue qu'une inscription qui plante.
# ---------------------------------------------------------------------------
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


@app.post("/api/auth/signup", status_code=201)
def signup(req: SignupRequest) -> dict:
    client = get_supabase_client()
    email = req.email.strip().lower()
    username = req.username.strip()

    invites = (
        client.table("invite_tokens")
        .select("*")
        .eq("token", req.invite_token)
        .is_("used_by", "null")
        .execute()
        .data
    )
    if not invites:
        raise HTTPException(status_code=400, detail="Lien d'invitation invalide ou déjà utilisé")
    invite = invites[0]
    invite_expires_at = datetime.fromisoformat(str(invite["expires_at"]).replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= invite_expires_at:
        raise HTTPException(status_code=400, detail="Ce lien d'invitation a expiré")
    if invite.get("email") and invite["email"].strip().lower() != email:
        raise HTTPException(status_code=400, detail="Cette invitation est destinée à une autre adresse email")

    existing = (
        client.table("app_users")
        .select("id")
        .or_(f"email.eq.{email},username.eq.{username}")
        .execute()
        .data
    )
    if existing:
        raise HTTPException(status_code=409, detail="Cet email ou ce nom d'utilisateur est déjà pris")

    # Le tout premier compte créé (base vierge, avant toute invitation) devient
    # automatiquement administrateur : lui seul pourra ensuite générer des
    # invitations pour les suivants, et réclamer les données créées avant le
    # multi-profil (voir /api/admin/claim-orphan-data, plus bas).
    is_first_account = not client.table("app_users").select("id").limit(1).execute().data

    user = client.table("app_users").insert({
        "email": email,
        "username": username,
        "password_hash": _hash_password(req.password),
        "email_verified": False,
        "is_admin": is_first_account,
    }).execute().data[0]

    # Le filtre .is_("used_by", "null") sur l'UPDATE (et pas seulement sur le
    # SELECT fait plus haut) ferme la fenêtre entre "lu comme non utilisé" et
    # "marqué utilisé" : si deux inscriptions concurrentes arrivaient ici
    # avec le même jeton, une seule des deux updates toucherait réellement
    # une ligne (l'autre mettrait à jour 0 ligne) — on vérifie ça ci-dessous
    # pour refuser la seconde inscription plutôt que de laisser un jeton à
    # usage unique créer deux comptes.
    claim_result = (
        client.table("invite_tokens")
        .update({"used_by": user["id"], "used_at": datetime.now(timezone.utc).isoformat()})
        .eq("id", invite["id"])
        .is_("used_by", "null")
        .execute()
    )
    if not claim_result.data:
        # Le compte vient d'être créé mais l'invitation a été raflée par une
        # autre requête concurrente entre-temps : on annule la création
        # plutôt que de laisser un compte orphelin sans invitation valide.
        client.table("app_users").delete().eq("id", user["id"]).execute()
        raise HTTPException(status_code=400, detail="Lien d'invitation invalide ou déjà utilisé")

    verify_token = _new_token()
    client.table("email_verification_tokens").insert({
        "user_id": user["id"],
        "token_hash": _hash_token(verify_token),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
    }).execute()
    verify_link = _build_link("/api/auth/verify-email", verify_token)
    _send_email(
        email,
        "Confirme ton adresse Kaching",
        f"<p>Bienvenue sur Kaching ! Confirme ton adresse en cliquant ici : "
        f"<a href=\"{verify_link}\">{verify_link}</a></p>",
    )

    return {
        "token": _create_session_token(user["id"], user["security_stamp"]),
        "is_admin": user["is_admin"],
    }


@app.post("/api/auth/login")
def login(req: LoginRequest) -> dict:
    if not API_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Configuration manquante : API_SECRET_KEY")
    client = get_supabase_client()
    email = req.email.strip().lower()

    attempts_row = _get_login_attempts_row(client, email)
    _enforce_login_lockout(attempts_row)

    users = client.table("app_users").select("*").eq("email", email).limit(1).execute().data
    # Un hash factice (jamais valide) est comparé même si le compte n'existe
    # pas, pour qu'une adresse inconnue prenne sensiblement le même temps de
    # réponse qu'une adresse connue avec un mauvais mot de passe — et pour
    # que _record_login_result compte quand même l'échec dans tous les cas.
    stored_hash = users[0]["password_hash"] if users else _hash_password(os.urandom(16).hex())
    is_correct = bool(users) and _verify_password(req.password, stored_hash)

    _record_login_result(client, attempts_row, success=is_correct)
    if not is_correct:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    user = users[0]
    return {
        "token": _create_session_token(user["id"], user["security_stamp"]),
        "is_admin": user.get("is_admin", False),
    }


@app.post("/api/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest) -> dict:
    client = get_supabase_client()
    email = req.email.strip().lower()

    attempts_row = _get_password_reset_attempts_row(client, email)
    _enforce_password_reset_lockout(attempts_row)
    _record_password_reset_request(client, attempts_row)

    users = client.table("app_users").select("id").eq("email", email).limit(1).execute().data
    # Réponse volontairement identique que le compte existe ou non : ne
    # jamais confirmer par ce biais qu'un email donné est enregistré ou pas.
    if users:
        reset_token = _new_token()
        client.table("password_reset_tokens").insert({
            "user_id": users[0]["id"],
            "token_hash": _hash_token(reset_token),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }).execute()
        # "/" et non "/reset-password" : l'app est une seule page qui lit
        # elle-même le paramètre ?reset=... au chargement pour afficher
        # directement l'écran de réinitialisation (il n'existe pas de route
        # serveur dédiée pour /reset-password).
        reset_link = _build_link("/", reset_token, "reset")
        _send_email(
            email,
            "Réinitialise ton mot de passe Kaching",
            f"<p>Clique ici pour choisir un nouveau mot de passe (valable 1 heure) : "
            f"<a href=\"{reset_link}\">{reset_link}</a></p>",
        )
    return {"status": "ok"}


@app.post("/api/auth/reset-password")
def reset_password(req: ResetPasswordRequest) -> dict:
    client = get_supabase_client()
    rows = (
        client.table("password_reset_tokens")
        .select("*")
        .eq("token_hash", _hash_token(req.token))
        .is_("used_at", "null")
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(status_code=400, detail="Lien de réinitialisation invalide ou déjà utilisé")
    reset_row = rows[0]
    reset_expires_at = datetime.fromisoformat(str(reset_row["expires_at"]).replace("Z", "+00:00"))
    if datetime.now(timezone.utc) >= reset_expires_at:
        raise HTTPException(status_code=400, detail="Ce lien de réinitialisation a expiré")

    # On tire aussi un nouveau security_stamp : ça invalide immédiatement
    # tous les jetons de session déjà émis pour ce compte (voir require_user
    # plus haut), au cas où le mot de passe était réinitialisé précisément
    # parce qu'un jeton avait pu fuiter.
    client.table("app_users").update(
        {"password_hash": _hash_password(req.new_password), "security_stamp": _new_token()}
    ).eq("id", reset_row["user_id"]).execute()
    client.table("password_reset_tokens").update(
        {"used_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", reset_row["id"]).execute()
    return {"status": "ok"}


@app.get("/api/auth/verify-email")
def verify_email(token: str) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("email_verification_tokens")
        .select("*")
        .eq("token_hash", _hash_token(token))
        .is_("used_at", "null")
        .execute()
        .data
    )
    if rows:
        row = rows[0]
        verify_expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if datetime.now(timezone.utc) < verify_expires_at:
            client.table("app_users").update({"email_verified": True}).eq("id", row["user_id"]).execute()
            client.table("email_verification_tokens").update(
                {"used_at": datetime.now(timezone.utc).isoformat()}
            ).eq("id", row["id"]).execute()
    # Lien cliqué depuis un email : on redirige vers l'appli plutôt que de
    # renvoyer du JSON brut. La vérification n'est pas bloquante pour
    # l'instant (pas besoin d'écran dédié côté frontend).
    return Response(status_code=302, headers={"Location": "/"})


@app.post("/api/auth/invite", status_code=201)
def create_invite(req: InviteRequest, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    caller = client.table("app_users").select("is_admin").eq("id", user_id).limit(1).execute().data
    if not caller or not caller[0].get("is_admin"):
        raise HTTPException(status_code=403, detail="Seul un compte administrateur peut inviter quelqu'un")

    token = _new_token()
    invite_email = req.email.strip().lower() if req.email else None
    client.table("invite_tokens").insert({
        "token": token,
        "email": invite_email,
        "created_by": user_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }).execute()
    # "/" et non "/signup" : même raison que pour le lien de réinitialisation
    # ci-dessus — l'app lit ?invite=... elle-même au chargement.
    invite_link = _build_link("/", token, "invite")
    if invite_email:
        _send_email(
            invite_email,
            "Invitation à rejoindre Kaching",
            f"<p>Tu es invité(e) à rejoindre Kaching : "
            f"<a href=\"{invite_link}\">{invite_link}</a> (valable 7 jours).</p>",
        )
    return {"invite_link": invite_link}


# ---------------------------------------------------------------------------
# Migration des données créées avant le multi-profil
# ---------------------------------------------------------------------------
# Toutes les lignes créées avant ce passage au multi-profil ont un `user_id`
# NULL (la colonne vient d'être ajoutée). Cette route les rattache en bloc
# au compte appelant, pour que l'historique existant (transactions,
# budgets, etc.) ne soit pas perdu de vue après la migration — réservée à un
# admin, et pensée pour n'être utilisée qu'une seule fois (par le premier
# compte créé, juste après son inscription). Rejouer cette route plus tard
# ne fait rien de dangereux : une fois les lignes orphelines réclamées, il
# n'en reste plus aucune à réclamer, donc un second appel est un no-op.
@app.post("/api/admin/claim-orphan-data")
def claim_orphan_data(user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    caller = client.table("app_users").select("is_admin").eq("id", user_id).limit(1).execute().data
    if not caller or not caller[0].get("is_admin"):
        raise HTTPException(status_code=403, detail="Seul un compte administrateur peut réclamer ces données")

    claimed: dict[str, int] = {}
    for table_name in _RESET_TABLES:
        result = (
            client.table(table_name)
            .update({"user_id": user_id})
            .is_("user_id", "null")
            .execute()
        )
        claimed[table_name] = len(result.data)
    return {"claimed": claimed}


# ---------------------------------------------------------------------------
# Modèles de données
# ---------------------------------------------------------------------------
class TransactionIn(BaseModel):
    type: TransactionType = "expense"
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None
    expense_date: date | None = None  # None => aujourd'hui (Europe/Paris)


class TransactionUpdate(BaseModel):
    type: TransactionType | None = None
    amount: float | None = Field(default=None, gt=0)
    category: str | None = None
    description: str | None = None
    expense_date: date | None = None


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


@app.post("/api/voice/parse", response_model=None)
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


@app.post("/api/voice/confirm", response_model=None)
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


# ---------------------------------------------------------------------------
# Frontend embarqué (régénéré par build.py — ne pas éditer à la main)
# ---------------------------------------------------------------------------
# BEGIN_FRONTEND_B64
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyIgb25lcnJvcj0iY29uc29sZS5lcnJvcignQ2hhcnQuanMgOiDDqWNoZWMgZHUgcHJlbWllciBjaGFyZ2VtZW50IGRlcHVpcyBsZSBDRE4uJykiPjwvc2NyaXB0Pgo8c3R5bGU+CiAgOnJvb3QgewogICAgY29sb3Itc2NoZW1lOiBkYXJrOwogICAgLS1iZzogIzBmMTExNTsKICAgIC0tc3VyZmFjZTogIzFhMWQyNDsKICAgIC0tc3VyZmFjZS0yOiAjMjIyNjJmOwogICAgLS1ib3JkZXI6ICMyYTJlMzg7CiAgICAtLXRleHQ6ICNlNmU2ZTY7CiAgICAtLXRleHQtZGltOiAjOWFhMGFjOwogICAgLS1hY2NlbnQ6ICMzYjgyZjY7CiAgICAtLWFjY2VudC1kaW06ICMxZDRlZDg7CiAgICAtLWRhbmdlcjogI2VmNDQ0NDsKICAgIC0tc3VjY2VzczogIzIyYzU1ZTsKICAgIC0tcmFkaXVzOiAxNHB4OwogIH0KICAqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogIGJvZHkgewogICAgbWFyZ2luOiAwOwogICAgbWluLWhlaWdodDogMTAwdmg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIHNhbnMtc2VyaWY7CiAgICBwYWRkaW5nLWJvdHRvbTogNnJlbTsKICB9CiAgaGVhZGVyIHsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIDFyZW07CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgfQogIGgxIHsgZm9udC1zaXplOiAxLjNyZW07IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAuc3VidGl0bGUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuOXJlbTsgbWFyZ2luOiAwOyB9CgogIC50YWJzIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtd3JhcDogd3JhcDsKICAgIGdhcDogMC41cmVtOwogIH0KICAudGFiLWJ0biB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50YWItYnRuLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CgogIC8qIFN1ciBwZXRpdCDDqWNyYW4sIGxhIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciAobWVudSAiYnVyZ2VyIikKICAgICBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIGVuIHBsdXNpZXVycyBsaWduZXMgOiBwbHVzIGRlIHBsYWNlIHBvdXIgbGUKICAgICBjb250ZW51LCBldCBkZXMgbGliZWxsw6lzIHRvdWpvdXJzIGxpc2libGVzIGVuIGVudGllci4gKi8KICAubWVudS10b2dnbGUtYnRuIHsKICAgIGRpc3BsYXk6IG5vbmU7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiAxcmVtOwogICAgei1pbmRleDogMzA7CiAgICB3aWR0aDogNDJweDsKICAgIGhlaWdodDogNDJweDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuMnJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLm5hdi1kcmF3ZXItYmFja2Ryb3AgewogICAgZGlzcGxheTogbm9uZTsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIHotaW5kZXg6IDI1OwogIH0KICBAbWVkaWEgKG1heC13aWR0aDogNjQwcHgpIHsKICAgIC5tZW51LXRvZ2dsZS1idG4geyBkaXNwbGF5OiBmbGV4OyB9CiAgICBoZWFkZXIgeyBwYWRkaW5nLWxlZnQ6IDMuNzVyZW07IH0KICAgIC50YWJzIHsKICAgICAgcG9zaXRpb246IGZpeGVkOwogICAgICB0b3A6IDA7CiAgICAgIGxlZnQ6IDA7CiAgICAgIGJvdHRvbTogMDsKICAgICAgZmxleC13cmFwOiBub3dyYXA7CiAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICAgIHdpZHRoOiAyNDBweDsKICAgICAgbWF4LXdpZHRoOiA4MHZ3OwogICAgICBtYXJnaW46IDA7CiAgICAgIHBhZGRpbmc6IDQuNXJlbSAxcmVtIDEuNXJlbTsKICAgICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICAgIGJvcmRlci1yaWdodDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICAgIHotaW5kZXg6IDI2OwogICAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTEwMCUpOwogICAgICB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMC4ycyBlYXNlOwogICAgICBvdmVyZmxvdy15OiBhdXRvOwogICAgfQogICAgLnRhYi1idG4geyBmbGV4OiBub25lOyB3aWR0aDogMTAwJTsgdGV4dC1hbGlnbjogbGVmdDsgfQogICAgYm9keS5uYXYtZHJhd2VyLW9wZW4gLnRhYnMgeyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMCk7IH0KICAgIGJvZHkubmF2LWRyYXdlci1vcGVuIC5uYXYtZHJhd2VyLWJhY2tkcm9wIHsgZGlzcGxheTogYmxvY2s7IH0KICB9CgogIC5zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgZmxleC13cmFwOiB3cmFwOwogIH0KICAuc3VtbWFyeS1jYXJkIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDEwMHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxcmVtOwogIH0KICAuc3VtbWFyeS1jYXJkIC5sYWJlbCB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlIHsgZm9udC1zaXplOiAxLjJyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbjogMDsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLnBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUubmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudG9vbHRpcC1ob3N0IHsgcG9zaXRpb246IHJlbGF0aXZlOyBjdXJzb3I6IGhlbHA7IH0KICAuY3VzdG9tLXRvb2x0aXAgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgbGVmdDogNTAlOwogICAgYm90dG9tOiBjYWxjKDEwMCUgKyAwLjZyZW0pOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoNHB4KTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNTVyZW0gMC43NXJlbTsKICAgIGZvbnQtc2l6ZTogMC43OHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogICAgdGV4dC1hbGlnbjogbGVmdDsKICAgIGJveC1zaGFkb3c6IDAgOHB4IDIwcHggcmdiYSgwLCAwLCAwLCAwLjM1KTsKICAgIG9wYWNpdHk6IDA7CiAgICBwb2ludGVyLWV2ZW50czogbm9uZTsKICAgIHRyYW5zaXRpb246IG9wYWNpdHkgMC4xMnMgZWFzZSwgdHJhbnNmb3JtIDAuMTJzIGVhc2U7CiAgICB6LWluZGV4OiAyMDsKICB9CiAgLmN1c3RvbS10b29sdGlwOjphZnRlciB7CiAgICBjb250ZW50OiAiIjsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMTAwJTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJvcmRlcjogNnB4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgYm9yZGVyLXRvcC1jb2xvcjogdmFyKC0tc3VyZmFjZS0yKTsKICB9CiAgLmN1c3RvbS10b29sdGlwLnZpc2libGUgewogICAgb3BhY2l0eTogMTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDApOwogICAgcG9pbnRlci1ldmVudHM6IGF1dG87CiAgfQoKICBtYWluIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICB9CgogIC53ZWVrLXN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogLTAuNHJlbSBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBmb250LXNpemU6IDAuODJyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwLjlyZW0gMS4xcmVtOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1hY2NlbnQtZGltKTsKICB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24uaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uIHAgeyBtYXJnaW46IDAgMCAwLjdyZW07IGZvbnQtc2l6ZTogMC44OHJlbTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LXdyYXA6IHdyYXA7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgc2VsZWN0LAogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIGlucHV0W3R5cGU9InRleHQiXSB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjRyZW0gMC42cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnRuLXByaW1hcnktc20sIC5idG4tc2Vjb25kYXJ5LXNtIHsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjhyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5idG4tcHJpbWFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiAjZmZmOyB9CiAgLmJ0bi1zZWNvbmRhcnktc20geyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoKICAuZmlsdGVyLWJhciB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgfQogIC5maWx0ZXItYmFyIGlucHV0LAogIC5maWx0ZXItYmFyIHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIGZsZXg6IDEgMSAxMzBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgI2ZpbHRlci1zZWFyY2ggeyBmbGV4OiAxIDEgMTAwJTsgfQoKICAudHgtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC50eC1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLnR4LWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50eC1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnR4LXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyB9CiAgLmNhdGVnb3J5LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWRhdGUgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudHgtcmVjdXJyaW5nLWJhZGdlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBvcGFjaXR5OiAwLjc7IGN1cnNvcjogaGVscDsgfQogIC50eC1yZWNlaXB0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43NXJlbTsKICAgIG9wYWNpdHk6IDAuODU7CiAgICBiYWNrZ3JvdW5kOiBub25lOwogICAgYm9yZGVyOiBub25lOwogICAgcGFkZGluZzogMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGxpbmUtaGVpZ2h0OiAxOwogIH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyAuY2hhcnQtd3JhcCB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQoKICAvKiBTw6lsZWN0ZXVyIGR1IHRhYmxlYXUgZGUgYm9yZCA6IHVuIHNldWwgZ3JhcGhpcXVlL2Jsb2MgYWZmaWNow6kgw6AgbGEgZm9pcwogICAgIChhdSBsaWV1IGRlcyA3IGVtcGlsw6lzKSwgY2hvaXNpIHZpYSB1bmUgcmFuZ8OpZSBkZSBwdWNlcyBkw6lmaWxhbnRlLiAqLwogIC5kYXNoYm9hcmQtY2hpcC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC41cmVtOwogICAgb3ZlcmZsb3cteDogYXV0bzsKICAgIHBhZGRpbmctYm90dG9tOiAwLjI1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICAgIC13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOiB0b3VjaDsKICB9CiAgLmRhc2hib2FyZC1jaGlwLXJvdzo6LXdlYmtpdC1zY3JvbGxiYXIgeyBoZWlnaHQ6IDRweDsgfQogIC5kYXNoYm9hcmQtY2hpcCB7CiAgICBmbGV4OiBub25lOwogICAgcGFkZGluZzogMC41cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuZGFzaGJvYXJkLWNoaXAuYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICAuZGFzaGJvYXJkLXJvdy5kYXNoLWhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KCiAgLnllYXJseS1zdW1tYXJ5IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLnllYXJseS1zdGF0IHsKICAgIGZsZXg6IDE7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjdyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC4ycmVtOwogIH0KICAueWVhcmx5LXN0YXQtbGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUgeyBmb250LXNpemU6IDEuMDVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlLmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1ub3RlIHsKICAgIHdpZHRoOiA5NnB4OwogICAgZmxleC1zaHJpbms6IDA7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNHJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXI6IDFweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuNzJyZW07CiAgICBsaW5lLWhlaWdodDogMS4yNTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQogIC51cGNvbWluZy1ub3RlLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctc3dhdGNoIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAxNHB4OwogICAgYm9yZGVyOiAxLjVweCBkYXNoZWQgdmFyKC0tZGFuZ2VyKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC51cGNvbWluZy1ub3RlLnBvc2l0aXZlIC51cGNvbWluZy1zd2F0Y2ggewogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMik7CiAgfQoKICAucmVjdXJyaW5nLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY3VycmluZy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5leHBvcnQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZXhwb3J0LXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5leHBvcnQtZm9ybWF0LXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOyB9CiAgLmV4cG9ydC1mb3JtYXQtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5leHBvcnQtZm9ybWF0LWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAvKiBJbXBvcnQgZGUgcmVsZXbDqSBiYW5jYWlyZSAqLwogIC5pbXBvcnQtZmlsZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtZmlsZS1yb3cgaW5wdXRbdHlwZT0iZmlsZSJdIHsgZmxleDogMTsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuaW1wb3J0LWRyb3B6b25lIHsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNXJlbSAwLjc1cmVtIDAuNzVyZW07CiAgfQogIC5pbXBvcnQtZHJvcHpvbmUuZHJhZy1vdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4wOCk7IH0KICAuaW1wb3J0LWRyb3B6b25lLWhpbnQgeyBtYXJnaW46IDAuNHJlbSAwIDA7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgLmltcG9ydC1zdW1tYXJ5IHsKICAgIG1hcmdpbjogMC45cmVtIDA7CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogIH0KICAuaW1wb3J0LXN1bW1hcnkgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmltcG9ydC1wcmV2aWV3IHsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtcHJldmlldy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmltcG9ydC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwOwogICAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgfQogIC5pbXBvcnQtcm93LmV4Y2x1ZGVkIHsgb3BhY2l0eTogMC40NTsgfQogIC5pbXBvcnQtcm93LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAuaW1wb3J0LXJvdy1kZXNjIHsgZm9udC1zaXplOiAwLjg4cmVtOyBmb250LXdlaWdodDogNTAwOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmltcG9ydC1yb3ctbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xcmVtOyB9CiAgLmltcG9ydC1yb3ctZHVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAuaW1wb3J0LXJvdyBzZWxlY3QgeyBmb250LXNpemU6IDAuOHJlbTsgbWF4LXdpZHRoOiAxMzBweDsgfQogIC5pbXBvcnQtYWN0aW9ucy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBtYXJnaW46IDAuNzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICB9CiAgLmltcG9ydC1hY3Rpb25zLXJvdyBidXR0b24geyBiYWNrZ3JvdW5kOiBub25lOyBib3JkZXI6IG5vbmU7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjdXJzb3I6IHBvaW50ZXI7IGZvbnQtc2l6ZTogMC44MnJlbTsgcGFkZGluZzogMDsgfQoKICAvKiBJbXBvcnQgZ8OpbsOpcmlxdWUgSUEg4oCUIGJhbmRlYXUgZGUgcsOpY3VycmVuY2VzIGTDqXRlY3TDqWVzICovCiAgLnJlY3VycmluZy1jYW5kaWRhdGVzLWxpc3QgeyBtYXJnaW46IDAuNzVyZW0gMDsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlIHsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjVyZW07CiAgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLm5lZWRzLWNvbmZpcm1hdGlvbiB7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMDcpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtaGVhZGVyIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogYmFzZWxpbmU7IGdhcDogMC41cmVtOyBmb250LXNpemU6IDAuODhyZW07IGZvbnQtd2VpZ2h0OiA1MDA7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcgeyBmb250LXNpemU6IDAuN3JlbTsgZm9udC13ZWlnaHQ6IDYwMDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuMDNlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5jcmVkaXQgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5yZWN1cnJpbmcgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcuZW5kZWQgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtdGFnLnVuY2VydGFpbiB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xNXJlbTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWNob2ljZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC45cmVtOyBtYXJnaW4tdG9wOiAwLjU1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IGZvbnQtc2l6ZTogMC44cmVtOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIGxhYmVsIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IGN1cnNvcjogcG9pbnRlcjsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWVuZGRhdGUgeyBtYXJnaW4tdG9wOiAwLjQ1cmVtOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNHJlbTsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtZW5kZGF0ZSBpbnB1dFt0eXBlPSJkYXRlIl0geyBmb250LXNpemU6IDAuOHJlbTsgfQoKICAvKiBTaW11bGF0aW9uIGRlIHBsYWNlbWVudCAow6lwYXJnbmUpICovCiAgLnBsYWNlbWVudC1wcmVzZXRzIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IG1hcmdpbi1ib3R0b206IDAuNzVyZW07IGZsZXgtd3JhcDogd3JhcDsgfQogIC5wbGFjZW1lbnQtcHJlc2V0LWJ0biB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxNDBweDsKICAgIHBhZGRpbmc6IDAuNDVyZW0gMC42cmVtOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDAuOHJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnBsYWNlbWVudC1wcmVzZXQtYnRuOmhvdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgLnBsYWNlbWVudC1pbnB1dHMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogMC43NXJlbTsgbWFyZ2luLWJvdHRvbTogMXJlbTsgfQogIC5wbGFjZW1lbnQtaW5wdXRzIGxhYmVsIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4yNXJlbTsgfQogIC5wbGFjZW1lbnQtcmVzdWx0IHsKICAgIG1hcmdpbi10b3A6IDAuOXJlbTsKICAgIHBhZGRpbmc6IDAuOHJlbSAwLjlyZW07CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnBsYWNlbWVudC1yZXN1bHQgc3Ryb25nIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAvKiBQbGFuIGQnw6lwYXJnbmUg4oCUIG5vdGF0aW9uIGQnZXNzZW50aWFsaXTDqSBwYXIgbGEgcGVyc29ubmUgZWxsZS1tw6ptZSAqLwogIC5zYXZpbmdzLXBsYW4tcGFuZWwgeyBtYXJnaW4tdG9wOiAwLjlyZW07IH0KICAuc2F2aW5ncy1wbGFuLXBhbmVsLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1wbGFuLXBhbmVsIGg0IHsgbWFyZ2luOiAxLjFyZW0gMCAwLjJyZW07IGZvbnQtc2l6ZTogMC45cmVtOyB9CiAgLnNhdmluZ3MtcGxhbi1saXN0IHsgbWFyZ2luLXRvcDogMC40cmVtOyB9CiAgLnNhdmluZ3MtcGxhbi1pdGVtIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjZyZW07CiAgICBwYWRkaW5nOiAwLjU1cmVtIDA7CiAgICBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLnNhdmluZ3MtcGxhbi1pdGVtLWluZm8geyBmbGV4OiAxOyBtaW4td2lkdGg6IDE0MHB4OyB9CiAgLnNhdmluZ3MtcGxhbi1pdGVtLW5hbWUgeyBmb250LXNpemU6IDAuODZyZW07IGZvbnQtd2VpZ2h0OiA1MDA7IH0KICAuc2F2aW5ncy1wbGFuLWl0ZW0tYW1vdW50IHsgZm9udC1zaXplOiAwLjc1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW4tdG9wOiAwLjFyZW07IH0KICAuc2F2aW5ncy1wbGFuLXJhdGluZyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC4zcmVtOyB9CiAgLnNhdmluZ3MtcGxhbi1yYXRpbmctYnRuIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAyOHB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjc4cmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuc2F2aW5ncy1wbGFuLXJhdGluZy1idG4uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICAuc2F2aW5ncy1wbGFuLWl0ZW0tc3RhbGVuZXNzIHsKICAgIGZvbnQtc2l6ZTogMC43MnJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBvcGFjaXR5OiAwLjc1OwogICAgbWFyZ2luLXRvcDogMC4xcmVtOwogIH0KICAuc2F2aW5ncy1wbGFuLWJ1ZGdldC1zdWdnZXN0aW9uIHsgbWFyZ2luOiAtMC4zcmVtIDAgMC42cmVtOyB9CiAgLmxpbmstYnRuIHsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBjb2xvcjogdmFyKC0tYWNjZW50KTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIHBhZGRpbmc6IDAuMnJlbSAwOwogICAgdGV4dC1hbGlnbjogbGVmdDsKICB9CiAgLmxpbmstYnRuOmhvdmVyIHsgdGV4dC1kZWNvcmF0aW9uOiB1bmRlcmxpbmU7IH0KICAuc2F2aW5ncy1wbGFuLWNvcnJlbGF0aW9uLW5vdGUgewogICAgbWFyZ2luOiAtMC4zcmVtIDAgMC42cmVtOwogICAgcGFkZGluZzogMC42cmVtIDAuOHJlbTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogIH0KICAuc2F2aW5ncy1wbGFuLXN1bW1hcnkgewogICAgbWFyZ2luLXRvcDogMXJlbTsKICAgIHBhZGRpbmc6IDAuOHJlbSAwLjlyZW07CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnNhdmluZ3MtcGxhbi1zdW1tYXJ5IHN0cm9uZyB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5zYXZpbmdzLXBsYW4tc3VtbWFyeSBidXR0b24geyBtYXJnaW4tdG9wOiAwLjZyZW07IH0KCiAgLmJ1ZGdldHMtc2F2ZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IGZsZXgtZW5kOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQogIC5zYXZpbmdzLWdvYWwtcm93IGlucHV0IHsgZmxleDogMTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1hcmdpbjogMC44cmVtIDAgMC4zNXJlbTsKICB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC5hZHZpY2UtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuYWR2aWNlLWNhcmQgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjg1cmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBsaW5lLWhlaWdodDogMS40OwogIH0KICAuYWR2aWNlLWNhcmQgLmFkdmljZS1pY29uIHsgZm9udC1zaXplOiAxLjFyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmFkdmljZS1jYXJkLnBvc2l0aXZlIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCB2YXIoLS1zdWNjZXNzKTsgfQogIC5hZHZpY2UtY2FyZC53YXJuaW5nIHsgYm9yZGVyLWxlZnQ6IDNweCBzb2xpZCAjZjU5ZTBiOyB9CiAgLmFkdmljZS1jYXJkLmluZm8geyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7IH0KICAucmVjdXJyaW5nLWhpbnQgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbjogMCAwIDAuOXJlbTsKICB9CgogIC51cGNvbWluZy1yZWN1cnJpbmctcGFuZWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOHJlbSAxcmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbC5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCBoNCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgZm9udC1zaXplOiAwLjlyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGJhc2VsaW5lOwogICAgcGFkZGluZzogMC4zNXJlbSAwOwogICAgZm9udC1zaXplOiAwLjg4cmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyArIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsgYm9yZGVyLXRvcDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAubmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5kdWUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuNzhyZW07IG1hcmdpbi1sZWZ0OiAwLjRyZW07IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXJvdyAuYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC5jb21wYXJlLXNlbGVjdHMgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICAgIGZsZXgtd3JhcDogd3JhcDsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzZWxlY3QgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjQ1cmVtIDAuNnJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgLmNvbXBhcmUtc2VsZWN0cyBzcGFuIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CgogIC5zaW1wbGUtdGFibGUgeyB3aWR0aDogMTAwJTsgYm9yZGVyLWNvbGxhcHNlOiBjb2xsYXBzZTsgZm9udC1zaXplOiAwLjg1cmVtOyB9CiAgLnNpbXBsZS10YWJsZSB0aCwgLnNpbXBsZS10YWJsZSB0ZCB7IHBhZGRpbmc6IDAuNXJlbSAwLjZyZW07IHRleHQtYWxpZ246IHJpZ2h0OyB9CiAgLnNpbXBsZS10YWJsZSB0aDpmaXJzdC1jaGlsZCwgLnNpbXBsZS10YWJsZSB0ZDpmaXJzdC1jaGlsZCB7IHRleHQtYWxpZ246IGxlZnQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoZWFkIHRoIHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZm9udC13ZWlnaHQ6IDUwMDsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIHRib2R5IHRyICsgdHIgdGQgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIudG90YWwtcm93IHRkIHsgZm9udC13ZWlnaHQ6IDYwMDsgYm9yZGVyLXRvcDogMnB4IHNvbGlkIHZhcigtLWJvcmRlcik7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLXBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNpbXBsZS10YWJsZSAuZGlmZi1uZWdhdGl2ZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnRyZW5kLXVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtZG93biB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC50cmVuZC1mbGF0IHsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQoKICAuYnVkZ2V0LXJvdyB7IG1hcmdpbi1ib3R0b206IDAuOXJlbTsgfQogIC5idWRnZXQtcm93LWhlYWQgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNXJlbTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuMzVyZW07CiAgfQogIC5idWRnZXQtY2F0LW5hbWUgeyBjb2xvcjogdmFyKC0tdGV4dCk7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KICAuYnVkZ2V0LWFtb3VudHMgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuM3JlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtaW5wdXQgewogICAgd2lkdGg6IDY0cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDZweDsKICAgIHBhZGRpbmc6IDAuMjVyZW0gMC40cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnVkZ2V0LWJhci10cmFjayB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBoZWlnaHQ6IDhweDsgb3ZlcmZsb3c6IGhpZGRlbjsgfQogIC5idWRnZXQtYmFyLWZpbGwgeyBoZWlnaHQ6IDEwMCU7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyB0cmFuc2l0aW9uOiB3aWR0aCAwLjJzIGVhc2U7IH0KICAuYnVkZ2V0LWJhci1maWxsLm9rIHsgYmFja2dyb3VuZDogdmFyKC0tc3VjY2Vzcyk7IH0KICAuYnVkZ2V0LWJhci1maWxsLndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmJ1ZGdldC1iYXItZmlsbC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5idWRnZXQtaGlzdG9yeS1zdHJpcCB7IGRpc3BsYXk6IGZsZXg7IGdhcDogNHB4OyBtYXJnaW4tdG9wOiAwLjRyZW07IH0KICAuaGlzdG9yeS1kb3QgewogICAgZmxleDogMTsKICAgIGhlaWdodDogNnB4OwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAuaGlzdG9yeS1kb3Qub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5oaXN0b3J5LWRvdC53YXJuaW5nIHsgYmFja2dyb3VuZDogI2Y1OWUwYjsgfQogIC5oaXN0b3J5LWRvdC5vdmVyIHsgYmFja2dyb3VuZDogdmFyKC0tZGFuZ2VyKTsgfQogIC5oaXN0b3J5LWRvdC5lbXB0eSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IG9wYWNpdHk6IDAuNTsgfQogIC5yZWMtY2FyZCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLWFjY2VudCk7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44NXJlbSAxcmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjZyZW07CiAgfQogIC5yZWMtY2FyZC5leHBlbnNlIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAucmVjLWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1jYXJkLmVuZGVkIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXRleHQtZGltKTsgb3BhY2l0eTogMC42OyB9CiAgLnJlYy1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnJlYy10b3AgeyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNXJlbTsgbWFyZ2luLWJvdHRvbTogMC4xNXJlbTsgZmxleC13cmFwOiB3cmFwOyB9CiAgLnJlYy1uYW1lIHsgZm9udC1zaXplOiAwLjk1cmVtOyBvdmVyZmxvdzogaGlkZGVuOyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtc3ViIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmVuZC1iYWRnZSB7CiAgICBmb250LXNpemU6IDAuN3JlbTsKICAgIHBhZGRpbmc6IDAuMTVyZW0gMC41cmVtOwogICAgYm9yZGVyLXJhZGl1czogOTk5cHg7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsKICAgIGNvbG9yOiAjZmNhNWE1OwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnN0YXJ0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjE1KTsKICAgIGNvbG9yOiAjOTNjNWZkOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnRvLW5vdGUtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSgyNDUsIDE1OCwgMTEsIDAuMTUpOwogICAgY29sb3I6ICNmYmJmMjQ7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICAudG8tbm90ZS1iYWRnZTpob3ZlciB7IGJhY2tncm91bmQ6IHJnYmEoMjQ1LCAxNTgsIDExLCAwLjI4KTsgfQogIC5yZWMtYW1vdW50IHsgZm9udC13ZWlnaHQ6IDYwMDsgZm9udC1zaXplOiAxLjA1cmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnJlYy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQoKICAuZmFiIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIHJpZ2h0OiAxLjI1cmVtOwogICAgYm90dG9tOiAxLjI1cmVtOwogICAgd2lkdGg6IDU2cHg7CiAgICBoZWlnaHQ6IDU2cHg7CiAgICBib3JkZXItcmFkaXVzOiA1MCU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogICAgY29sb3I6IHdoaXRlOwogICAgZm9udC1zaXplOiAxLjhyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSg1OSwgMTMwLCAyNDYsIDAuNCk7CiAgfQogIC5mYWI6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQoKICAuZmFiLW1pYyB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogNS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY3Vyc29yOiBwb2ludGVyOwogICAgYm94LXNoYWRvdzogMCA0cHggMTZweCByZ2JhKDAsIDAsIDAsIDAuMyk7CiAgICB0cmFuc2l0aW9uOiBiYWNrZ3JvdW5kIDAuMnMsIGJvcmRlci1jb2xvciAwLjJzOwogIH0KICAuZmFiLW1pYzphY3RpdmUgeyB0cmFuc2Zvcm06IHNjYWxlKDAuOTUpOyB9CiAgLmZhYi1taWMubGlzdGVuaW5nIHsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7CiAgICBhbmltYXRpb246IHB1bHNlIDEuMnMgaW5maW5pdGU7CiAgfQogIC5mYWItbWljLnByb2Nlc3NpbmcgeyBvcGFjaXR5OiAwLjY7IGN1cnNvcjogZGVmYXVsdDsgfQogIC5mYWItbWljOmRpc2FibGVkIHsgb3BhY2l0eTogMC4zNTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQogIEBrZXlmcmFtZXMgcHVsc2UgewogICAgMCUsIDEwMCUgeyBib3gtc2hhZG93OiAwIDAgMCAwIHJnYmEoMjM5LCA2OCwgNjgsIDAuNCk7IH0KICAgIDUwJSB7IGJveC1zaGFkb3c6IDAgMCAwIDEwcHggcmdiYSgyMzksIDY4LCA2OCwgMCk7IH0KICB9CgogIC52b2ljZS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC42cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWF4LXdpZHRoOiA4NXZ3OwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogICAgei1pbmRleDogMTU7CiAgfQogIC52b2ljZS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC52b2ljZS1iYW5uZXIuYW5zd2VyIHsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LXdlaWdodDogNjAwOyBsaW5lLWhlaWdodDogMS40OyB9CgogIC52b2ljZS1jb25maXJtLWJhbm5lciB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBib3R0b206IDkuNXJlbTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYWNjZW50LCAjNGE3ZGZmKTsKICAgIGJvcmRlci1yYWRpdXM6IDEycHg7CiAgICBwYWRkaW5nOiAwLjc1cmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOXJlbTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE2OwogIH0KICAudm9pY2UtY29uZmlybS1iYW5uZXIuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC52b2ljZS1jb25maXJtLWJhbm5lciBwIHsgbWFyZ2luOiAwIDAgMC42cmVtOyBsaW5lLWhlaWdodDogMS40OyB9CiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyIC52b2ljZS1jb25maXJtLWhpbnQgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC52b2ljZS1jb25maXJtLWNvbnRyb2xzIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IGp1c3RpZnktY29udGVudDogY2VudGVyOyB9CgogIC5tb2RhbC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogZmxleC1lbmQ7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDEwOwogIH0KICAubW9kYWwtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgI2lucHV0LW5ldy1jYXRlZ29yeS1uYW1lLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubW9kYWwgewogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXItcmFkaXVzOiAxOHB4IDE4cHggMCAwOwogICAgcGFkZGluZzogMS41cmVtIDEuMjVyZW0gY2FsYygxLjVyZW0gKyBlbnYoc2FmZS1hcmVhLWluc2V0LWJvdHRvbSkpOwogICAgd2lkdGg6IDEwMCU7CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICBnYXA6IDAuOXJlbTsKICB9CiAgLm1vZGFsIGgyIHsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgZm9udC1zaXplOiAxLjFyZW07IH0KCiAgbGFiZWwgeyBmb250LXNpemU6IDAuOHJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgZGlzcGxheTogYmxvY2s7IG1hcmdpbi1ib3R0b206IDAuM3JlbTsgfQogIGlucHV0LCBzZWxlY3QgewogICAgd2lkdGg6IDEwMCU7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBwYWRkaW5nOiAwLjY1cmVtIDAuNzVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIGlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IH0KCiAgLnR5cGUtdG9nZ2xlIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjVyZW07IH0KICAudHlwZS1idG4gewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNjVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImV4cGVuc2UiXSB7IGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnR5cGUtYnRuLmFjdGl2ZVtkYXRhLXR5cGU9ImluY29tZSJdIHsgYmFja2dyb3VuZDogcmdiYSgzNCwgMTk3LCA5NCwgMC4xNSk7IGJvcmRlci1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQoKICAubW9kYWwtYWN0aW9ucyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC42cmVtOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAuY29uZmlybS1tb2RhbCB7IG1heC13aWR0aDogNDAwcHg7IH0KICAuY29uZmlybS1tb2RhbC1tZXNzYWdlIHsgY29sb3I6IHZhcigtLXRleHQpOyBmb250LXNpemU6IDAuOTVyZW07IG1hcmdpbjogMDsgbGluZS1oZWlnaHQ6IDEuNDsgfQoKICAuaGlkZGVuLWZpbGUtaW5wdXQgeyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY2VpcHQtcHJldmlldy13cmFwIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjVyZW07CiAgICBhbGlnbi1pdGVtczogZmxleC1zdGFydDsKICAgIG1hcmdpbi1ib3R0b206IDAuNXJlbTsKICB9CiAgLnJlY2VpcHQtcHJldmlldy1pbWcgewogICAgbWF4LXdpZHRoOiAxMDAlOwogICAgbWF4LWhlaWdodDogMTYwcHg7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIG9iamVjdC1maXQ6IGNvbnRhaW47CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogIH0KCiAgLmxpZ2h0Ym94LW92ZXJsYXkgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDAsIDAsIDAsIDAuODUpOwogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIHotaW5kZXg6IDIwOwogICAgcGFkZGluZzogMS41cmVtOwogIH0KICAubGlnaHRib3gtb3ZlcmxheS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxpZ2h0Ym94LWltZyB7IG1heC13aWR0aDogMTAwJTsgbWF4LWhlaWdodDogODB2aDsgYm9yZGVyLXJhZGl1czogMTBweDsgfQogIC5saWdodGJveC1jbG9zZSB7CiAgICBwb3NpdGlvbjogYWJzb2x1dGU7CiAgICB0b3A6IDFyZW07CiAgICByaWdodDogMXJlbTsKICAgIHdpZHRoOiA0MHB4OwogICAgaGVpZ2h0OiA0MHB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMS4xcmVtOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSwgYnV0dG9uLnNlY29uZGFyeSB7CiAgICBmbGV4OiAxOwogICAgcGFkZGluZzogMC43NXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IG5vbmU7CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICBmb250LXdlaWdodDogNTAwOwogICAgY3Vyc29yOiBwb2ludGVyOwogIH0KICBidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQogIGJ1dHRvbi5wcmltYXJ5OmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CiAgYnV0dG9uLnNlY29uZGFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7IGNvbG9yOiB2YXIoLS10ZXh0KTsgfQogIGJ1dHRvbi5kYW5nZXIgeyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgY29sb3I6IHZhcigtLWRhbmdlcik7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWRhbmdlcik7IH0KICBidXR0b24uZGFuZ2VyOmRpc2FibGVkIHsgb3BhY2l0eTogMC42OyB9CgogIC5kYW5nZXItem9uZSB7CiAgICBib3JkZXItY29sb3I6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMzUpICFpbXBvcnRhbnQ7CiAgfQogIC5kYW5nZXItem9uZSBoMyB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50b2FzdCB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHotaW5kZXg6IDIwOwogICAgbWF4LXdpZHRoOiA5MHZ3OwogIH0KICAudG9hc3QuZXJyb3IgeyBib3JkZXItY29sb3I6IHZhcigtLWRhbmdlcik7IGNvbG9yOiAjZmNhNWE1OyB9CgogIC5sb2NrLXNjcmVlbiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDA7CiAgICBwYWRkaW5nOiAxLjVyZW07CiAgfQogIC5sb2NrLXNjcmVlbi5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmxvY2stY2FyZCB7IG1heC13aWR0aDogMzIwcHg7IHdpZHRoOiAxMDAlOyB0ZXh0LWFsaWduOiBjZW50ZXI7IH0KICAubG9jay1lbW9qaSB7IGZvbnQtc2l6ZTogM3JlbTsgbWFyZ2luLWJvdHRvbTogMC41cmVtOyB9CiAgLmxvY2stY2FyZCBoMSB7IG1hcmdpbjogMCAwIDAuNXJlbTsgfQogIC5sb2NrLWNhcmQgcCB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IG1hcmdpbjogMCAwIDEuMjVyZW07IGZvbnQtc2l6ZTogMC45cmVtOyB9CiAgLmxvY2stY2FyZCBpbnB1dCB7CiAgICB3aWR0aDogMTAwJTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLmxvY2stZXJyb3IgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgZm9udC1zaXplOiAwLjg1cmVtOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmxvY2stZXJyb3IuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5sb2NrLXN1Y2Nlc3MgeyBjb2xvcjogIzRhZGU4MDsgZm9udC1zaXplOiAwLjg1cmVtOyBtYXJnaW4tdG9wOiAwLjc1cmVtOyB9CiAgLmxvY2stc3VjY2Vzcy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmF1dGgtdmlldy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmF1dGgtc3dpdGNoIHsgbWFyZ2luLXRvcDogMS4xcmVtOyBmb250LXNpemU6IDAuODVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuYXV0aC1zd2l0Y2ggYSB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjdXJzb3I6IHBvaW50ZXI7IHRleHQtZGVjb3JhdGlvbjogdW5kZXJsaW5lOyB9CiAgLmxvY2stY2FyZCBpbnB1dFt0eXBlPSJlbWFpbCJdLAogIC5sb2NrLWNhcmQgaW5wdXRbdHlwZT0idGV4dCJdIHsKICAgIHdpZHRoOiAxMDAlOwogICAgbWFyZ2luLWJvdHRvbTogMC43NXJlbTsKICAgIHBhZGRpbmc6IDAuN3JlbSAwLjlyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICAucGFzc3dvcmQtZmllbGQgeyBwb3NpdGlvbjogcmVsYXRpdmU7IG1hcmdpbi1ib3R0b206IDAuNzVyZW07IH0KICAucGFzc3dvcmQtZmllbGQgaW5wdXQgewogICAgd2lkdGg6IDEwMCU7CiAgICBtYXJnaW4tYm90dG9tOiAwOwogICAgcGFkZGluZzogMC43cmVtIDIuNnJlbSAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLnBhc3N3b3JkLXRvZ2dsZS1idG4gewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgcmlnaHQ6IDAuNHJlbTsKICAgIHRvcDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC01MCUpOwogICAgYmFja2dyb3VuZDogbm9uZTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGZvbnQtc2l6ZTogMS4xcmVtOwogICAgcGFkZGluZzogMC4zcmVtIDAuNXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG9wYWNpdHk6IDAuNzsKICB9CiAgLnBhc3N3b3JkLXRvZ2dsZS1idG46aG92ZXIgeyBvcGFjaXR5OiAxOyB9CiAgLnBhc3N3b3JkLXRvZ2dsZS1idG4uYWN0aXZlIHsgb3BhY2l0eTogMTsgY29sb3I6IHZhcigtLWFjY2VudCk7IH0KPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICA8ZGl2IGNsYXNzPSJsb2NrLXNjcmVlbiBoaWRkZW4iIGlkPSJsb2NrLXNjcmVlbiI+CiAgICA8ZGl2IGNsYXNzPSJsb2NrLWNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJsb2NrLWVtb2ppIj7wn5KwPC9kaXY+CiAgICAgIDxoMT5LYWNoaW5nPC9oMT4KCiAgICAgIDwhLS0gQ29ubmV4aW9uIC0tPgogICAgICA8ZGl2IGNsYXNzPSJhdXRoLXZpZXciIGlkPSJhdXRoLXZpZXctbG9naW4iPgogICAgICAgIDxwPkNvbm5lY3RlLXRvaSBwb3VyIGFjY8OpZGVyIMOgIHRlcyBkb25uw6llcy48L3A+CiAgICAgICAgPGlucHV0IHR5cGU9ImVtYWlsIiBpZD0ibG9naW4tZW1haWwtaW5wdXQiIHBsYWNlaG9sZGVyPSJFbWFpbCIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGFzc3dvcmQtZmllbGQiPgogICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0ibG9naW4tcGFzc3dvcmQtaW5wdXQiIHBsYWNlaG9sZGVyPSJNb3QgZGUgcGFzc2UiIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InBhc3N3b3JkLXRvZ2dsZS1idG4iIGRhdGEtdGFyZ2V0PSJsb2dpbi1wYXNzd29yZC1pbnB1dCIgYXJpYS1sYWJlbD0iQWZmaWNoZXIgbGUgbW90IGRlIHBhc3NlIj7wn5GBPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwcmltYXJ5IiBpZD0ibG9naW4tc3VibWl0LWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5TZSBjb25uZWN0ZXI8L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJsb2dpbi1lcnJvciI+PC9wPgogICAgICAgIDxwIGNsYXNzPSJhdXRoLXN3aXRjaCI+CiAgICAgICAgICA8YSBpZD0ibG9naW4tZ290by1mb3Jnb3QiPk1vdCBkZSBwYXNzZSBvdWJsacOpID88L2E+PGJyPgogICAgICAgICAgPGEgaWQ9ImxvZ2luLWdvdG8tc2lnbnVwIj5KJ2FpIHVuIGxpZW4gZCdpbnZpdGF0aW9uPC9hPgogICAgICAgIDwvcD4KICAgICAgPC9kaXY+CgogICAgICA8IS0tIEluc2NyaXB0aW9uIChzdXIgaW52aXRhdGlvbiB1bmlxdWVtZW50KSAtLT4KICAgICAgPGRpdiBjbGFzcz0iYXV0aC12aWV3IGhpZGRlbiIgaWQ9ImF1dGgtdmlldy1zaWdudXAiPgogICAgICAgIDxwPkNyw6llIHRvbiBjb21wdGUgw6AgcGFydGlyIGRlIHRvbiBsaWVuIGQnaW52aXRhdGlvbi48L3A+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJzaWdudXAtaW52aXRlLWlucHV0IiBwbGFjZWhvbGRlcj0iQ29kZSBkJ2ludml0YXRpb24iPgogICAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9InNpZ251cC1lbWFpbC1pbnB1dCIgcGxhY2Vob2xkZXI9IkVtYWlsIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InNpZ251cC11c2VybmFtZS1pbnB1dCIgcGxhY2Vob2xkZXI9Ik5vbSBkJ3V0aWxpc2F0ZXVyIiBhdXRvY29tcGxldGU9Im5pY2tuYW1lIj4KICAgICAgICA8ZGl2IGNsYXNzPSJwYXNzd29yZC1maWVsZCI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJzaWdudXAtcGFzc3dvcmQtaW5wdXQiIHBsYWNlaG9sZGVyPSJNb3QgZGUgcGFzc2UgKDggY2FyYWN0w6hyZXMgbWluLikiIGF1dG9jb21wbGV0ZT0ibmV3LXBhc3N3b3JkIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icGFzc3dvcmQtdG9nZ2xlLWJ0biIgZGF0YS10YXJnZXQ9InNpZ251cC1wYXNzd29yZC1pbnB1dCIgYXJpYS1sYWJlbD0iQWZmaWNoZXIgbGUgbW90IGRlIHBhc3NlIj7wn5GBPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwcmltYXJ5IiBpZD0ic2lnbnVwLXN1Ym1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+Q3LDqWVyIG1vbiBjb21wdGU8L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJzaWdudXAtZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPjxhIGlkPSJzaWdudXAtZ290by1sb2dpbiI+SidhaSBkw6lqw6AgdW4gY29tcHRlPC9hPjwvcD4KICAgICAgPC9kaXY+CgogICAgICA8IS0tIE1vdCBkZSBwYXNzZSBvdWJsacOpIC0tPgogICAgICA8ZGl2IGNsYXNzPSJhdXRoLXZpZXcgaGlkZGVuIiBpZD0iYXV0aC12aWV3LWZvcmdvdCI+CiAgICAgICAgPHA+RW50cmUgdG9uIGVtYWlsIDogc2kgdW4gY29tcHRlIGV4aXN0ZSwgdHUgcmVjZXZyYXMgdW4gbGllbiBkZSByw6lpbml0aWFsaXNhdGlvbi48L3A+CiAgICAgICAgPGlucHV0IHR5cGU9ImVtYWlsIiBpZD0iZm9yZ290LWVtYWlsLWlucHV0IiBwbGFjZWhvbGRlcj0iRW1haWwiIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9ImZvcmdvdC1zdWJtaXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPkVudm95ZXIgbGUgbGllbjwvYnV0dG9uPgogICAgICAgIDxwIGNsYXNzPSJsb2NrLWVycm9yIGhpZGRlbiIgaWQ9ImZvcmdvdC1lcnJvciI+PC9wPgogICAgICAgIDxwIGNsYXNzPSJsb2NrLXN1Y2Nlc3MgaGlkZGVuIiBpZD0iZm9yZ290LXN1Y2Nlc3MiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPjxhIGlkPSJmb3Jnb3QtZ290by1sb2dpbiI+UmV0b3VyIMOgIGxhIGNvbm5leGlvbjwvYT48L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSBSw6lpbml0aWFsaXNhdGlvbiBkdSBtb3QgZGUgcGFzc2UgKGRlcHVpcyBsZSBsaWVuIHJlw6d1IHBhciBlbWFpbCkgLS0+CiAgICAgIDxkaXYgY2xhc3M9ImF1dGgtdmlldyBoaWRkZW4iIGlkPSJhdXRoLXZpZXctcmVzZXQiPgogICAgICAgIDxwPkNob2lzaXMgdW4gbm91dmVhdSBtb3QgZGUgcGFzc2UuPC9wPgogICAgICAgIDxkaXYgY2xhc3M9InBhc3N3b3JkLWZpZWxkIj4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InJlc2V0LXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTm91dmVhdSBtb3QgZGUgcGFzc2UgKDggY2FyYWN0w6hyZXMgbWluLikiIGF1dG9jb21wbGV0ZT0ibmV3LXBhc3N3b3JkIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icGFzc3dvcmQtdG9nZ2xlLWJ0biIgZGF0YS10YXJnZXQ9InJlc2V0LXBhc3N3b3JkLWlucHV0IiBhcmlhLWxhYmVsPSJBZmZpY2hlciBsZSBtb3QgZGUgcGFzc2UiPvCfkYE8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InByaW1hcnkiIGlkPSJyZXNldC1zdWJtaXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPlZhbGlkZXI8L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJyZXNldC1lcnJvciI+PC9wPgogICAgICAgIDxwIGNsYXNzPSJsb2NrLXN1Y2Nlc3MgaGlkZGVuIiBpZD0icmVzZXQtc3VjY2VzcyI+PC9wPgogICAgICAgIDxwIGNsYXNzPSJhdXRoLXN3aXRjaCI+PGEgaWQ9InJlc2V0LWdvdG8tbG9naW4iPlJldG91ciDDoCBsYSBjb25uZXhpb248L2E+PC9wPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGlkPSJhcHAtcm9vdCIgaGlkZGVuPgogIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ibWVudS10b2dnbGUtYnRuIiBpZD0ibWVudS10b2dnbGUtYnRuIiBhcmlhLWxhYmVsPSJPdXZyaXIgbGUgbWVudSI+4piwPC9idXR0b24+CiAgPGRpdiBjbGFzcz0ibmF2LWRyYXdlci1iYWNrZHJvcCIgaWQ9Im5hdi1kcmF3ZXItYmFja2Ryb3AiPjwvZGl2PgogIDxoZWFkZXI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Imljb24tYnRuIGRhbmdlciIgaWQ9ImxvZ291dC1idG4iIHRpdGxlPSJTZSBkw6ljb25uZWN0ZXIiIGFyaWEtbGFiZWw9IlNlIGTDqWNvbm5lY3RlciIgc3R5bGU9InBvc2l0aW9uOmFic29sdXRlOyB0b3A6MXJlbTsgcmlnaHQ6MXJlbTsiPuKPuzwvYnV0dG9uPgogICAgPGgxPvCfkrAgS2FjaGluZzwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPlRlcyBkw6lwZW5zZXMgZXQgcmV2ZW51cywgYWpvdXTDqXMgb3Ugw6lkaXTDqXMgbWFudWVsbGVtZW50LjwvcD4KICA8L2hlYWRlcj4KCiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InRhYi1idG4gYWN0aXZlIiBpZD0idGFiLWhpc3RvcnkiIGRhdGEtdmlldz0iaGlzdG9yeSI+SGlzdG9yaXF1ZTwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWRhc2hib2FyZCIgZGF0YS12aWV3PSJkYXNoYm9hcmQiPlRhYmxlYXUgZGUgYm9yZDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXJlY3VycmluZyIgZGF0YS12aWV3PSJyZWN1cnJpbmciPlLDqWN1cnJlbnRlczwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLWV4cG9ydCIgZGF0YS12aWV3PSJleHBvcnQiPkV4cG9ydDwvYnV0dG9uPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIiBpZD0idGFiLXNhdmluZ3MiIGRhdGEtdmlldz0ic2F2aW5ncyI+w4lwYXJnbmU8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ic3VtbWFyeSI+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQiPgogICAgICA8cCBjbGFzcz0ibGFiZWwiPlNvbGRlPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWJhbGFuY2UiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Ew6lwZW5zZXM8L3A+CiAgICAgIDxwIGNsYXNzPSJ2YWx1ZSIgaWQ9InN1bW1hcnktZXhwZW5zZXMiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5SZXZlbnVzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWluY29tZSI+4oCUPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzdW1tYXJ5LWNhcmQgdG9vbHRpcC1ob3N0IiBpZD0ic3VtbWFyeS11cGNvbWluZy1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj7DgCB2ZW5pciBjZSBtb2lzLWNpPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LXVwY29taW5nIj7igJQ8L3A+CiAgICAgIDxkaXYgY2xhc3M9ImN1c3RvbS10b29sdGlwIiBpZD0ic3VtbWFyeS11cGNvbWluZy10b29sdGlwIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8cCBjbGFzcz0id2Vlay1zdW1tYXJ5IiBpZD0id2Vlay1zdW1tYXJ5Ij48L3A+CgogIDxkaXYgaWQ9ImNhdGVnb3J5LXN1Z2dlc3Rpb24tYmFubmVyIiBjbGFzcz0iY2F0ZWdvcnktc3VnZ2VzdGlvbiBoaWRkZW4iPjwvZGl2PgoKICA8bWFpbj4KICAgIDxzZWN0aW9uIGlkPSJ2aWV3LWhpc3RvcnkiPgogICAgICA8ZGl2IGNsYXNzPSJmaWx0ZXItYmFyIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImZpbHRlci1zZWFyY2giIHBsYWNlaG9sZGVyPSJSZWNoZXJjaGVyLi4uIj4KICAgICAgICA8c2VsZWN0IGlkPSJmaWx0ZXItY2F0ZWdvcnkiPjxvcHRpb24gdmFsdWU9IiI+VG91dGVzIGNhdMOpZ29yaWVzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmaWx0ZXItZGF0ZS1zdGFydCIgYXJpYS1sYWJlbD0iRHUiPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtZW5kIiBhcmlhLWxhYmVsPSJBdSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGlkPSJ0eC1saXN0IiBjbGFzcz0idHgtbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVtcHR5LXN0YXRlIiBjbGFzcz0iZW1wdHktc3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICBSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8c2VjdGlvbiBpZD0idmlldy1kYXNoYm9hcmQiIGNsYXNzPSJkYXNoYm9hcmQtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1jaGlwLXJvdyIgaWQ9ImRhc2hib2FyZC1jaGlwLXJvdyI+PC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0iZGFzaC1yb3ctZXhwZW5zZXMiPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIGTDqXBlbnNlcyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXRlZ29yeS1jaGFydC1yb3ciPgogICAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIgY2xhc3M9InVwY29taW5nLW5vdGUgaGlkZGVuIj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InVwY29taW5nLXN3YXRjaCI+PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLXRleHQiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1bmUgZMOpcGVuc2UgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWluY29tZSI+CiAgICAgICAgPGgzPlLDqXBhcnRpdGlvbiBkZXMgcmV2ZW51cyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBBdWN1biByZXZlbnUgY2UgbW9pcy1sw6AuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWJ1ZGdldHMiPgogICAgICAgIDxoMz5CdWRnZXRzIG1lbnN1ZWxzIHBhciBjYXTDqWdvcmllPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgSW5kaXF1ZSB1biBtb250YW50IHBvdXIgdW5lIGNhdMOpZ29yaWUgZXQgZW5yZWdpc3RyZSBhdmVjIPCfkr4g4oCUIGxhIGJhcnJlCiAgICAgICAgICBjb21wYXJlIGVuc3VpdGUgdGVzIGTDqXBlbnNlcyBkdSBtb2lzIGVuIGNvdXJzIMOgIGNlIHBsYWZvbmQgKHZlcnQsCiAgICAgICAgICBvcmFuZ2UgYXUtZGVsw6AgZGUgNzAlLCByb3VnZSBhdS1kZWzDoCBkZSAxMDAlKS4gTGEgcGV0aXRlIHJhbmfDqWUgZGUKICAgICAgICAgIGJhcnJlcyBlbiBkZXNzb3VzIG1vbnRyZSBsJ2hpc3RvcmlxdWUgZGVzIDYgZGVybmllcnMgbW9pcyAoc3Vydm9sZQogICAgICAgICAgb3UgdG91Y2hlIHVuZSBiYXJyZSBwb3VyIHZvaXIgbGUgZMOpdGFpbCkuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgaWQ9ImJ1ZGdldHMtbGlzdCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iYnVkZ2V0cy1zYXZlLXJvdyI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9ImJ1ZGdldHMtc2F2ZS1hbGwtYnRuIiBhcmlhLWxhYmVsPSJFbnJlZ2lzdHJlciB0b3VzIGxlcyBidWRnZXRzIj7wn5K+PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWV2b2x1dGlvbiI+CiAgICAgICAgPGgzPsOJdm9sdXRpb24gbWVuc3VlbGxlIChkw6lwZW5zZXMgdnMgcmV2ZW51cyk8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtZXZvbHV0aW9uIj48L2NhbnZhcz4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtZXZvbHV0aW9uLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1jb21wYXJlIj4KICAgICAgICA8aDM+Q29tcGFyZXIgZGV1eCBtb2lzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjb21wYXJlLXNlbGVjdHMiPgogICAgICAgICAgPHNlbGVjdCBpZD0iY29tcGFyZS1tb250aC1hIj48L3NlbGVjdD4KICAgICAgICAgIDxzcGFuPnZzPC9zcGFuPgogICAgICAgICAgPHNlbGVjdCBpZD0iY29tcGFyZS1tb250aC1iIj48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImNvbXBhcmUtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBhc3NleiBkZSBtb2lzIGRpZmbDqXJlbnRzIHBvdXIgY29tcGFyZXIuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LXRyZW5kIj4KICAgICAgICA8aDM+TW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtdGFibGUtd3JhcCI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idHJlbmQtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgIFBhcyBlbmNvcmUgYXNzZXogZGUgZG9ubsOpZXMuCiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LXllYXJseSI+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLWhlYWQiPgogICAgICAgICAgPGgzPkJpbGFuIGFubnVlbDwvaDM+CiAgICAgICAgICA8c2VsZWN0IGlkPSJ5ZWFybHkteWVhci1zZWxlY3QiPjwvc2VsZWN0PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdW1tYXJ5Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5Ew6lwZW5zZXM8L3NwYW4+CiAgICAgICAgICAgIDxzcGFuIGlkPSJ5ZWFybHktdG90YWwtZXhwZW5zZXMiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBleHBlbnNlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InllYXJseS1zdGF0Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9InllYXJseS1zdGF0LWxhYmVsIj5SZXZlbnVzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWluY29tZSIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIGluY29tZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+U29sZGUgbmV0PC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LW5ldCIgY2xhc3M9InllYXJseS1zdGF0LXZhbHVlIj48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXllYXJseSI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZGUgZG9ubsOpZXMgcG91ciBjZXR0ZSBhbm7DqWUuCiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ieWVhcmx5LWNhdGVnb3J5LXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1yZXRyby1zYXZpbmdzIiBjbGFzcz0iYWR2aWNlLWNhcmQgcG9zaXRpdmUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7IG1hcmdpbi10b3A6IDAuOHJlbTsiPgogICAgICAgICAgPHNwYW4gY2xhc3M9ImFkdmljZS1pY29uIj7wn5KhPC9zcGFuPgogICAgICAgICAgPHNwYW4gaWQ9InllYXJseS1yZXRyby1zYXZpbmdzLXRleHQiPjwvc3Bhbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIiBjbGFzcz0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGhpZGRlbiI+CiAgICAgICAgPGg0PlByb2NoYWluZXMgw6ljaMOpYW5jZXM8L2g0PgogICAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1lbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgQXVjdW5lIGTDqXBlbnNlIHLDqWN1cnJlbnRlIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZXhwb3J0IiBjbGFzcz0iZXhwb3J0LXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+RXhwb3J0ZXIgdGVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJleHBvcnQtZm9ybWF0LXRvZ2dsZSIgaWQ9ImV4cG9ydC1mb3JtYXQtdG9nZ2xlIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZXhwb3J0LWZvcm1hdC1idG4gYWN0aXZlIiBkYXRhLWZvcm1hdD0ieGxzeCI+RXhjZWwgKC54bHN4KTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJleHBvcnQtZm9ybWF0LWJ0biIgZGF0YS1mb3JtYXQ9Impzb24iPlNhdXZlZ2FyZGUgY29tcGzDqHRlIChKU09OKTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCIgaWQ9ImV4cG9ydC1mb3JtYXQtaGludCI+CiAgICAgICAgICBUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQtZG93bmxvYWQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnRlciB1biByZWxldsOpIGJhbmNhaXJlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciBsJ2V4cG9ydCBDU1YgwqsgZXhwb3J0LW9wZXJhdGlvbnMuLi4gwrsgZGUgQm91cnNvQmFuawogICAgICAgICAgdW5pcXVlbWVudC4gTGVzIG1vbnRhbnRzLCBkYXRlcyBldCBkZXNjcmlwdGlvbnMgc29udCBhbmFseXPDqXMgaWNpCiAgICAgICAgICBtw6ptZSAocmllbiBuJ2VzdCBlbnZvecOpIGFpbGxldXJzKSA7IHR1IGNob2lzaXMgZW5zdWl0ZSBsaWduZSBwYXIKICAgICAgICAgIGxpZ25lIHF1b2kgaW1wb3J0ZXIgYXZhbnQgdG91dGUgw6ljcml0dXJlIGVuIGJhc2UuIExlIG51bcOpcm8gZGUKICAgICAgICAgIGNvbXB0ZSBuJ2VzdCBqYW1haXMgbHUuIFBvdXIgdW4gYXV0cmUgZm9ybWF0IChvdSB1biBmaWNoaWVyIHNhbnMKICAgICAgICAgIEJvdXJzb0JhbmspLCB1dGlsaXNlIGwnaW1wb3J0IGfDqW7DqXJpcXVlIHBhciBJQSB1biBwZXUgcGx1cyBiYXMuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1kcm9wem9uZSIgaWQ9ImltcG9ydC1kcm9wem9uZSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJpbXBvcnQtZmlsZS1yb3ciPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImltcG9ydC1maWxlLWlucHV0IiBhY2NlcHQ9Ii5jc3YsdGV4dC9jc3YiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iaW1wb3J0LWFuYWx5emUtYnRuIj5BbmFseXNlcjwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0iaW1wb3J0LWRyb3B6b25lLWhpbnQiPm91IGdsaXNzZS1kw6lwb3NlIGxlIGZpY2hpZXIgLmNzdiBpY2k8L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXN1bW1hcnkiIGNsYXNzPSJpbXBvcnQtc3VtbWFyeSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImltcG9ydC1wcmV2aWV3IiBjbGFzcz0iaW1wb3J0LXByZXZpZXcgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1hY3Rpb25zLXJvdyI+CiAgICAgICAgICAgIDxzcGFuIGlkPSJpbXBvcnQtc2VsZWN0ZWQtY291bnQiPjwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJpbXBvcnQtdG9nZ2xlLWFsbC1idG4iPlRvdXQgY29jaGVyIC8gZMOpY29jaGVyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgaWQ9ImltcG9ydC1yb3dzLWxpc3QiPjwvZGl2PgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImltcG9ydC1jb21taXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsgbWFyZ2luLXRvcDowLjc1cmVtOyI+SW1wb3J0ZXIgbGEgc8OpbGVjdGlvbjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnQgZ8OpbsOpcmlxdWUgcGFyIElBICh0b3V0IGZpY2hpZXIpPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciB1biBmaWNoaWVyIHF1aSBuZSB2aWVudCBwYXMgZGUgQm91cnNvQmFuaywgb3UgcXVpIG4nYSBwYXMgdW5lCiAgICAgICAgICBzdHJ1Y3R1cmUgY2xhc3NpcXVlIChleCA6IHVuIHRhYmxlYXUgcGFyIG1vaXMsIHNhbnMgZGF0ZSBwcsOpY2lzZSBuaQogICAgICAgICAgY2F0w6lnb3JpZSkuIEwnSUEgbGl0IGxlIGZpY2hpZXIgZXQgcHJvcG9zZSBkZXMgdHJhbnNhY3Rpb25zIMOgCiAgICAgICAgICB2YWxpZGVyIDsgc2kgdW5lIGTDqXBlbnNlIHNlbWJsZSBzZSByw6lww6l0ZXIgY2hhcXVlIG1vaXMsIGVsbGUgZXN0CiAgICAgICAgICBtaXNlIGRlIGPDtHTDqSBwb3VyIHF1ZSB0dSBjb25maXJtZXMgdG9pLW3Dqm1lIHMnaWwgcydhZ2l0IGQndW5lCiAgICAgICAgICBjaGFyZ2UgcsOpY3VycmVudGUgb3UgZCd1biBjcsOpZGl0IGVuIGNvdXJzIGRlIHJlbWJvdXJzZW1lbnQuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1kcm9wem9uZSIgaWQ9ImdlbmVyaWMtaW1wb3J0LWRyb3B6b25lIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1maWxlLXJvdyI+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iZ2VuZXJpYy1pbXBvcnQtZmlsZS1pbnB1dCIgYWNjZXB0PSIuY3N2LC54bHN4LHRleHQvY3N2Ij4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImdlbmVyaWMtaW1wb3J0LWFuYWx5emUtYnRuIj5BbmFseXNlcjwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0iaW1wb3J0LWRyb3B6b25lLWhpbnQiPm91IGdsaXNzZS1kw6lwb3NlIHVuIGZpY2hpZXIgLmNzdiAvIC54bHN4IGljaTwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1zdW1tYXJ5IiBjbGFzcz0iaW1wb3J0LXN1bW1hcnkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctc2VjdGlvbiIgY2xhc3M9ImhpZGRlbiI+CiAgICAgICAgICA8aDQgc3R5bGU9Im1hcmdpbi1ib3R0b206MC4yNXJlbTsiPkTDqXBlbnNlcyBxdWkgc2VtYmxlbnQgc2UgcsOpcMOpdGVyPC9oND4KICAgICAgICAgIDxkaXYgaWQ9ImdlbmVyaWMtaW1wb3J0LXJlY3VycmluZy1saXN0IiBjbGFzcz0icmVjdXJyaW5nLWNhbmRpZGF0ZXMtbGlzdCI+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZ2VuZXJpYy1pbXBvcnQtcHJldmlldyIgY2xhc3M9ImltcG9ydC1wcmV2aWV3IGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJpbXBvcnQtYWN0aW9ucy1yb3ciPgogICAgICAgICAgICA8c3BhbiBpZD0iZ2VuZXJpYy1pbXBvcnQtc2VsZWN0ZWQtY291bnQiPjwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJnZW5lcmljLWltcG9ydC10b2dnbGUtYWxsLWJ0biI+VG91dCBjb2NoZXIgLyBkw6ljb2NoZXI8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZ2VuZXJpYy1pbXBvcnQtcm93cy1saXN0Ij48L2Rpdj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsgbWFyZ2luLXRvcDowLjc1cmVtOyI+SW1wb3J0ZXIgbGEgc8OpbGVjdGlvbjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3cgZGFuZ2VyLXpvbmUiPgogICAgICAgIDxoMz7imqDvuI8gWm9uZSBkYW5nZXJldXNlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgU3VwcHJpbWUgZMOpZmluaXRpdmVtZW50IFRPVVRFUyBsZXMgZG9ubsOpZXMgOiB0cmFuc2FjdGlvbnMsIGNoYXJnZXMKICAgICAgICAgIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc29ubmFsaXPDqWVzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMsCiAgICAgICAgICBidWRnZXRzLCBwaG90b3MgZGUgcmXDp3VzIGV0IG9iamVjdGlmIGQnw6lwYXJnbmUuIFBlbnNlIMOgIGV4cG9ydGVyIGVuCiAgICAgICAgICBFeGNlbCBhdmFudCBzaSBiZXNvaW4g4oCUIGltcG9zc2libGUgw6AgYW5udWxlci4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZGFuZ2VyIiBpZD0iYnRuLXJlc2V0LWFsbCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Sw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXNhdmluZ3MiIGNsYXNzPSJzYXZpbmdzLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+T2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgTGUgbW9udGFudCBxdWUgdHUgdmV1eCBnYXJkZXIgZGUgY8O0dMOpIGNoYXF1ZSBtb2lzIChyZXZlbnVzIG1vaW5zCiAgICAgICAgICBkw6lwZW5zZXMpLiBDb21wYXLDqSDDoCB0b24gc29sZGUgcsOpZWwgZHUgbW9pcyBlbiBjb3Vycy4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0ic2F2aW5ncy1nb2FsLXJvdyI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ic2F2aW5ncy1nb2FsLWlucHV0IiBtaW49IjAiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSJFeCA6IDEwMCI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9InNhdmluZ3MtZ29hbC1zYXZlLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgbCdvYmplY3RpZiI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwiPgogICAgICAgICAgICA8c3Bhbj5Tb2xkZSBkdSBtb2lzIGVuIGNvdXJzPC9zcGFuPgogICAgICAgICAgICA8c3Ryb25nIGlkPSJzYXZpbmdzLXByb2dyZXNzLXRleHQiPjwvc3Ryb25nPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJidWRnZXQtYmFyLXRyYWNrIj4KICAgICAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wcm9ncmVzcy1iYXIiIGNsYXNzPSJidWRnZXQtYmFyLWZpbGwgb2siPjwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkNvbnNlaWxzPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgQmFzw6lzIHN1ciB0ZXMgYnVkZ2V0cyBwYXIgY2F0w6lnb3JpZSBldCB0ZXMgdGVuZGFuY2VzIGRlIGTDqXBlbnNlcwogICAgICAgICAgKHZvaXIgbCdvbmdsZXQgVGFibGVhdSBkZSBib3JkKS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtbGlzdCIgY2xhc3M9ImFkdmljZS1saXN0Ij48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLWFkdmljZS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcyBjZSBtb2lzLWNpIHBvdXIgdGUgZG9ubmVyIGRlcyBjb25zZWlscy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+U2ltdWxhdGlvbiBkZSBwbGFjZW1lbnQ8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBQcm9qZWN0aW9uIHNpIHR1IHBsYWNlcyB1bmUgc29tbWUgc3VyIHVuIGxpdnJldCBvdSB1biBwbGFjZW1lbnQgw6AKICAgICAgICAgIHRhdXggZml4ZSAoaW50w6lyw6p0cyBjb21wb3PDqXMsIGNhbGN1bMOpcyBtZW5zdWVsbGVtZW50KS4gU2ltdWxhdGlvbiDDoAogICAgICAgICAgdGl0cmUgaW5mb3JtYXRpZiDigJQgbGVzIHBlcmZvcm1hbmNlcyBwYXNzw6llcyBuZSBnYXJhbnRpc3NlbnQgcGFzIGxlcwogICAgICAgICAgcGVyZm9ybWFuY2VzIGZ1dHVyZXMsIGNlIG4nZXN0IHBhcyB1biBjb25zZWlsIGZpbmFuY2llci4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LXByZXNldHMiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwbGFjZW1lbnQtcHJlc2V0LWJ0biIgZGF0YS1yYXRlPSIzIj5MaXZyZXQgQSAofjMlKTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwbGFjZW1lbnQtcHJlc2V0LWJ0biIgZGF0YS1yYXRlPSI3Ij5BY3Rpb25zIC8gRVRGIG1vbmRlICh+NyUpPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LWlucHV0cyI+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtaW5pdGlhbCI+TW9udGFudCBpbml0aWFsICjigqwpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC1pbml0aWFsIiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSI1MDAiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtbW9udGhseSI+VmVyc2VtZW50IG1lbnN1ZWwgKOKCrCk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LW1vbnRobHkiIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IjUwIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXJhdGUiPlRhdXggYW5udWVsICglKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQtcmF0ZSIgbWluPSIwIiBzdGVwPSIwLjEiIHZhbHVlPSIzIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXllYXJzIj5EdXLDqWUgKGFubsOpZXMpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC15ZWFycyIgbWluPSIxIiBzdGVwPSIxIiB2YWx1ZT0iNSI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXBsYWNlbWVudCI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0icGxhY2VtZW50LWNoYXJ0LWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LXJlc3VsdCIgaWQ9InBsYWNlbWVudC1yZXN1bHQiPjwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5QbGFuIGQnw6lwYXJnbmU8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBOb3RlIGNoYWN1bmUgZGUgdGVzIGTDqXBlbnNlcyBkZSAxIChwYXMgZXNzZW50aWVsKSDDoCA1IChlc3NlbnRpZWwpIOKAlAogICAgICAgICAgYydlc3QgdG9pIHF1aSBqdWdlcywgamFtYWlzIGwnSUEuIE9uIGNhbGN1bGUgZW5zdWl0ZSBjZSBxdWUgdHUKICAgICAgICAgIHBvdXJyYWlzIMOpY29ub21pc2VyIGVuIHBsdXMgc2kgY2V0IGFyZ2VudCBhbGxhaXQgc3VyIGRlIGwnw6lwYXJnbmUKICAgICAgICAgIHBsdXTDtHQgcXVlIGQnw6p0cmUgZMOpcGVuc8OpLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0ic2F2aW5ncy1wbGFuLXRvZ2dsZS1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+T3V2cmlyIGxlIHBsYW4gZCfDqXBhcmduZTwvYnV0dG9uPgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcGxhbi1wYW5lbCIgY2xhc3M9InNhdmluZ3MtcGxhbi1wYW5lbCBoaWRkZW4iPgogICAgICAgICAgPGg0PkNhdMOpZ29yaWVzIGRlIGTDqXBlbnNlczwvaDQ+CiAgICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPk1vbnRhbnQgbW95ZW4gcGFyIG1vaXMsIGNhbGN1bMOpIHN1ciB0b24gaGlzdG9yaXF1ZS48L3A+CiAgICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXBsYW4tY2F0ZWdvcmllcy1saXN0IiBjbGFzcz0ic2F2aW5ncy1wbGFuLWxpc3QiPjwvZGl2PgogICAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wbGFuLWNhdGVnb3JpZXMtZW1wdHkiIGNsYXNzPSJkYXNoYm9hcmQtZW1wdHkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkw6lwZW5zZXMgZW5yZWdpc3Ryw6llcyBwb3VyIG5vdGVyIGRlcyBjYXTDqWdvcmllcy4KICAgICAgICAgIDwvZGl2PgoKICAgICAgICAgIDxoND5DaGFyZ2VzIHLDqWN1cnJlbnRlczwvaDQ+CiAgICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXBsYW4tcmVjdXJyaW5nLWxpc3QiIGNsYXNzPSJzYXZpbmdzLXBsYW4tbGlzdCI+PC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXBsYW4tcmVjdXJyaW5nLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICAgIEF1Y3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgYWN0aXZlIMOgIG5vdGVyLgogICAgICAgICAgPC9kaXY+CgogICAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wbGFuLXN1bW1hcnkiIGNsYXNzPSJzYXZpbmdzLXBsYW4tc3VtbWFyeSI+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgogIDwvbWFpbj4KCiAgPGRpdiBjbGFzcz0idm9pY2UtYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWJhbm5lciI+PC9kaXY+CiAgPGRpdiBjbGFzcz0idm9pY2UtY29uZmlybS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtY29uZmlybS1iYW5uZXIiPjwvZGl2PgogIDxidXR0b24gY2xhc3M9ImZhYi1taWMiIGlkPSJmYWItbWljIiBhcmlhLWxhYmVsPSJEaWN0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudSwgb3UgcG9zZXIgdW5lIHF1ZXN0aW9uIiB0aXRsZT0iRGljdGUgdW5lIGTDqXBlbnNlL3VuIHJldmVudSwgb3UgcG9zZSB1bmUgcXVlc3Rpb24gKGV4IDogwqsgY29tYmllbiBqJ2FpIGTDqXBlbnPDqSBlbiByZXN0YXVyYW50IGNlIG1vaXMtY2kgPyDCuykiPvCfjqQ8L2J1dHRvbj4KICA8YnV0dG9uIGNsYXNzPSJmYWIiIGlkPSJmYWItYWRkIiBhcmlhLWxhYmVsPSJBam91dGVyIj4rPC9idXR0b24+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0ibW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0ibW9kYWwtdGl0bGUiPk5vdXZlbGxlIHRyYW5zYWN0aW9uPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0idHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJpbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgICAgPGlucHV0CiAgICAgICAgICB0eXBlPSJ0ZXh0IgogICAgICAgICAgaWQ9ImlucHV0LW5ldy1jYXRlZ29yeS1uYW1lIgogICAgICAgICAgcGxhY2Vob2xkZXI9Ik5vbSBkZSBsYSBub3V2ZWxsZSBjYXTDqWdvcmllIgogICAgICAgICAgY2xhc3M9ImhpZGRlbiIKICAgICAgICAgIHN0eWxlPSJtYXJnaW4tdG9wOiA4cHg7IgogICAgICAgID4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGVzY3JpcHRpb24iPkRlc2NyaXB0aW9uIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImlucHV0LWRlc2NyaXB0aW9uIiBwbGFjZWhvbGRlcj0iRXggOiBkw6lqZXVuZXIgYXZlYyBQYXVsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtZGF0ZSI+RGF0ZTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJpbnB1dC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsPlJlw6d1IChwaG90bywgb3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbnB1dC1yZWNlaXB0LWZpbGUiIGNsYXNzPSJoaWRkZW4tZmlsZS1pbnB1dCIgYWNjZXB0PSJpbWFnZS8qIiBjYXB0dXJlPSJlbnZpcm9ubWVudCI+CiAgICAgICAgPGRpdiBpZD0icmVjZWlwdC1wcmV2aWV3LXdyYXAiIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctd3JhcCBoaWRkZW4iPgogICAgICAgICAgPGltZyBpZD0icmVjZWlwdC1wcmV2aWV3LWltZyIgY2xhc3M9InJlY2VpcHQtcHJldmlldy1pbWciIGFsdD0iUmXDp3UiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tcmVjZWlwdC1yZW1vdmUiPlN1cHByaW1lciBsYSBwaG90bzwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcGljayIgc3R5bGU9IndpZHRoOjEwMCU7Ij7wn5O3IEFqb3V0ZXIgdW5lIHBob3RvIGRlIHJlw6d1PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9InJlYy1tb2RhbC10aXRsZSI+Tm91dmVsbGUgZMOpcGVuc2UgcsOpY3VycmVudGU8L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJyZWMtdHlwZS10b2dnbGUiPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4gYWN0aXZlIiBkYXRhLXR5cGU9ImV4cGVuc2UiPvCfkrggRMOpcGVuc2U8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIiBkYXRhLXR5cGU9ImluY29tZSI+8J+SsCBSZXZlbnU8L2J1dHRvbj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1uYW1lIj5Ob208L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0icmVjLWlucHV0LW5hbWUiIHBsYWNlaG9sZGVyPSJFeCA6IE5ldGZsaXgsIExveWVyLCBTYWxhaXJlLi4uIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWFtb3VudCI+TW9udGFudCAo4oKsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9InJlYy1pbnB1dC1jYXRlZ29yeSI+PC9zZWxlY3Q+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1kYXkiPkpvdXIgZHUgbW9pczwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InJlYy1pbnB1dC1kYXkiIG1pbj0iMSIgbWF4PSIzMSIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IjEgw6AgMzEiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+RGF0ZSBkZSBkw6lidXQgKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZW5kLWRhdGUiPkRhdGUgZGUgZmluIChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1lbmQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJyZWMtYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJyZWMtYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJjb25maXJtLW1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwgY29uZmlybS1tb2RhbCI+CiAgICAgIDxoMiBpZD0iY29uZmlybS1tb2RhbC10aXRsZSI+Q29uZmlybWVyPC9oMj4KICAgICAgPHAgaWQ9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSIgY2xhc3M9ImNvbmZpcm0tbW9kYWwtbWVzc2FnZSI+PC9wPgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJjb25maXJtLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iY29uZmlybS1idG4tb2siPkNvbmZpcm1lcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJsaWdodGJveC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSI+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImxpZ2h0Ym94LWNsb3NlIiBpZD0icmVjZWlwdC1saWdodGJveC1jbG9zZSIgYXJpYS1sYWJlbD0iRmVybWVyIj7inJU8L2J1dHRvbj4KICAgIDxpbWcgY2xhc3M9ImxpZ2h0Ym94LWltZyIgaWQ9InJlY2VpcHQtbGlnaHRib3gtaW1nIiBhbHQ9IlJlw6d1IGVuIHBsZWluIMOpY3JhbiI+CiAgPC9kaXY+CiAgPC9kaXY+CgogIDxzY3JpcHQ+CiAgICAvLyBMZSBqZXRvbiBkZSBzZXNzaW9uIChvYnRlbnUgYXByw6hzIGF2b2lyIHRhcMOpIGxlIG1vdCBkZSBwYXNzZSBzdXIgbCfDqWNyYW4KICAgIC8vIGRlIHZlcnJvdWlsbGFnZSkgcmVtcGxhY2UgbCdhbmNpZW5uZSBjbMOpIEFQSSBjb2TDqWUgZW4gZHVyIGljaSDigJQgY2VsbGUtY2kKICAgIC8vIMOpdGFpdCB2aXNpYmxlIHBhciBuJ2ltcG9ydGUgcXVpIHZpYSAiQWZmaWNoZXIgbGUgY29kZSBzb3VyY2UiLCBzYW5zCiAgICAvLyBhdWN1biBtb3QgZGUgcGFzc2UuIExlIGpldG9uIGVzdCBzaWduw6kgY8O0dMOpIHNlcnZldXIgZXQgZXhwaXJlIGFwcsOocyA5MAogICAgLy8gam91cnMgOyBpbCBuZSByw6l2w6hsZSByaWVuIGRlIHNlY3JldCBlbiBsdWktbcOqbWUuCiAgICBjb25zdCBUT0tFTl9TVE9SQUdFX0tFWSA9ICJrYWNoaW5nX3Nlc3Npb25fdG9rZW4iOwogICAgbGV0IEFQSV9LRVkgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSkgfHwgIiI7CgogICAgY29uc3QgbG9ja1NjcmVlbkVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvY2stc2NyZWVuIik7CiAgICBjb25zdCBhcHBSb290RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXBwLXJvb3QiKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIMOJY3JhbiBkZSBjb25uZXhpb24gOiBwbHVzaWV1cnMgdnVlcyAoY29ubmV4aW9uIC8gaW5zY3JpcHRpb24gc3VyCiAgICAvLyBpbnZpdGF0aW9uIC8gbW90IGRlIHBhc3NlIG91Ymxpw6kgLyByw6lpbml0aWFsaXNhdGlvbikgZGFucyBsYSBtw6ptZQogICAgLy8gY2FydGUsIHVuZSBzZXVsZSBhZmZpY2jDqWUgw6AgbGEgZm9pcy4gP2ludml0ZT0uLi4gZXQgP3Jlc2V0PS4uLiBkYW5zCiAgICAvLyBsJ1VSTCAobGllbnMgcmXDp3VzIHBhciBlbWFpbCkgb3V2cmVudCBkaXJlY3RlbWVudCBsYSB2dWUgY29ycmVzcG9uZGFudGUKICAgIC8vIGF2ZWMgbGUgamV0b24gcHLDqS1yZW1wbGkg4oCUIGlsIG4nZXhpc3RlIHBhcyBkZSByb3V0ZSBzZXJ2ZXVyIGTDqWRpw6llCiAgICAvLyBwb3VyIC9zaWdudXAgb3UgL3Jlc2V0LXBhc3N3b3JkLCB0b3V0IHNlIHBhc3NlIGljaSBjw7R0w6kgZnJvbnRlbmQuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IGF1dGhWaWV3cyA9IHsKICAgICAgbG9naW46IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhdXRoLXZpZXctbG9naW4iKSwKICAgICAgc2lnbnVwOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXV0aC12aWV3LXNpZ251cCIpLAogICAgICBmb3Jnb3Q6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhdXRoLXZpZXctZm9yZ290IiksCiAgICAgIHJlc2V0OiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXV0aC12aWV3LXJlc2V0IiksCiAgICB9OwoKICAgIGZ1bmN0aW9uIHNob3dBdXRoVmlldyhuYW1lKSB7CiAgICAgIGZvciAoY29uc3QgW2tleSwgZWxdIG9mIE9iamVjdC5lbnRyaWVzKGF1dGhWaWV3cykpIHsKICAgICAgICBlbC5jbGFzc0xpc3QudG9nZ2xlKCJoaWRkZW4iLCBrZXkgIT09IG5hbWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd0xvY2tTY3JlZW4oaW5pdGlhbFZpZXcgPSAibG9naW4iKSB7CiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKFRPS0VOX1NUT1JBR0VfS0VZKTsKICAgICAgQVBJX0tFWSA9ICIiOwogICAgICBhcHBSb290RWwuaGlkZGVuID0gdHJ1ZTsKICAgICAgbG9ja1NjcmVlbkVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBzaG93QXV0aFZpZXcoaW5pdGlhbFZpZXcpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dBcHAoKSB7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IGZhbHNlOwogICAgfQoKICAgIGZ1bmN0aW9uIHNldEF1dGhCdXN5KGJ0biwgYnVzeUxhYmVsLCBpZGxlTGFiZWwpIHsKICAgICAgYnRuLmRpc2FibGVkID0gISFidXN5TGFiZWw7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9IGJ1c3lMYWJlbCB8fCBpZGxlTGFiZWw7CiAgICB9CgogICAgLy8gTGUgYmFja2VuZCAoRmFzdEFQSS9weWRhbnRpYykgcmVudm9pZSBlbiB0ZW1wcyBub3JtYWwgYGRldGFpbGAgY29tbWUKICAgIC8vIHVuZSBzaW1wbGUgY2hhw65uZSwgbWFpcyBxdWFuZCBsYSByZXF1w6p0ZSBuZSByZXNwZWN0ZSBwYXMgbGUgc2Now6ltYQogICAgLy8gYXR0ZW5kdSAoZXg6IG1vdCBkZSBwYXNzZSB0cm9wIGNvdXJ0IGF2YW50IG3Dqm1lIGQnYXR0ZWluZHJlIG5vdHJlCiAgICAvLyBwcm9wcmUgY29kZSksIGBkZXRhaWxgIGVzdCB1bmUgTElTVEUgZCdvYmpldHMgZCdlcnJldXIgZGUgdmFsaWRhdGlvbi4KICAgIC8vIFNhbnMgw6dhLCBgbmV3IEVycm9yKGRldGFpbClgIGFmZmljaGUgbGl0dMOpcmFsZW1lbnQgIltvYmplY3QgT2JqZWN0XSIKICAgIC8vIMOgIGwnw6ljcmFuIChjZSBxdWUgYGRldGFpbGAgZGV2aWVudCB1bmUgZm9pcyBjb252ZXJ0aSBlbiB0ZXh0ZSkgYXUgbGlldQogICAgLy8gZCd1biBtZXNzYWdlIGNvbXByw6loZW5zaWJsZSDigJQgY2V0dGUgZm9uY3Rpb24gdHJhbnNmb3JtZSBjZXR0ZSBsaXN0ZSBlbgogICAgLy8gcGhyYXNlIGxpc2libGUgZW4gZnJhbsOnYWlzLgogICAgY29uc3QgX1ZBTElEQVRJT05fRklFTERfTEFCRUxTX0ZSID0gewogICAgICBwYXNzd29yZDogIm1vdCBkZSBwYXNzZSIsCiAgICAgIG5ld19wYXNzd29yZDogIm5vdXZlYXUgbW90IGRlIHBhc3NlIiwKICAgICAgZW1haWw6ICJlbWFpbCIsCiAgICAgIHVzZXJuYW1lOiAibm9tIGQndXRpbGlzYXRldXIiLAogICAgICBpbnZpdGVfdG9rZW46ICJjb2RlIGQnaW52aXRhdGlvbiIsCiAgICAgIHRva2VuOiAiamV0b24iLAogICAgICBhbW91bnQ6ICJtb250YW50IiwKICAgICAgbmFtZTogIm5vbSIsCiAgICAgIGNhdGVnb3J5OiAiY2F0w6lnb3JpZSIsCiAgICAgIGRlc2NyaXB0aW9uOiAiZGVzY3JpcHRpb24iLAogICAgfTsKCiAgICBmdW5jdGlvbiBfZnJpZW5kbHlWYWxpZGF0aW9uRXJyb3IoZXJyKSB7CiAgICAgIGNvbnN0IGxvYyA9IEFycmF5LmlzQXJyYXkoZXJyLmxvYykgPyBlcnIubG9jLmZpbHRlcigocCkgPT4gcCAhPT0gImJvZHkiKSA6IFtdOwogICAgICBjb25zdCBmaWVsZCA9IGxvYy5sZW5ndGggPyBTdHJpbmcobG9jW2xvYy5sZW5ndGggLSAxXSkgOiBudWxsOwogICAgICBjb25zdCBsYWJlbCA9IChmaWVsZCAmJiBfVkFMSURBVElPTl9GSUVMRF9MQUJFTFNfRlJbZmllbGRdKSB8fCBmaWVsZCB8fCAiY2hhbXAiOwogICAgICBjb25zdCBjdHggPSBlcnIuY3R4IHx8IHt9OwogICAgICBpZiAoZXJyLnR5cGUgPT09ICJzdHJpbmdfdG9vX3Nob3J0IiAmJiBjdHgubWluX2xlbmd0aCAhPSBudWxsKSB7CiAgICAgICAgcmV0dXJuIGBMZSAke2xhYmVsfSBkb2l0IGNvbnRlbmlyIGF1IG1vaW5zICR7Y3R4Lm1pbl9sZW5ndGh9IGNhcmFjdMOocmUke2N0eC5taW5fbGVuZ3RoID4gMSA/ICJzIiA6ICIifS5gOwogICAgICB9CiAgICAgIGlmIChlcnIudHlwZSA9PT0gInN0cmluZ190b29fbG9uZyIgJiYgY3R4Lm1heF9sZW5ndGggIT0gbnVsbCkgewogICAgICAgIHJldHVybiBgTGUgJHtsYWJlbH0gbmUgZG9pdCBwYXMgZMOpcGFzc2VyICR7Y3R4Lm1heF9sZW5ndGh9IGNhcmFjdMOocmUke2N0eC5tYXhfbGVuZ3RoID4gMSA/ICJzIiA6ICIifS5gOwogICAgICB9CiAgICAgIGlmIChlcnIudHlwZSA9PT0gIm1pc3NpbmciKSB7CiAgICAgICAgcmV0dXJuIGBMZSBjaGFtcCDCqyAke2xhYmVsfSDCuyBlc3QgcmVxdWlzLmA7CiAgICAgIH0KICAgICAgcmV0dXJuIGBWw6lyaWZpZSBsZSBjaGFtcCDCqyAke2xhYmVsfSDCuy5gOwogICAgfQoKICAgIGZ1bmN0aW9uIGV4dHJhY3RFcnJvckRldGFpbChkYXRhLCBmYWxsYmFjaykgewogICAgICBjb25zdCBkZXRhaWwgPSBkYXRhICYmIGRhdGEuZGV0YWlsOwogICAgICBpZiAodHlwZW9mIGRldGFpbCA9PT0gInN0cmluZyIgJiYgZGV0YWlsKSByZXR1cm4gZGV0YWlsOwogICAgICBpZiAoQXJyYXkuaXNBcnJheShkZXRhaWwpICYmIGRldGFpbC5sZW5ndGgpIHsKICAgICAgICByZXR1cm4gZGV0YWlsCiAgICAgICAgICAubWFwKChlKSA9PiAoZSAmJiB0eXBlb2YgZSA9PT0gIm9iamVjdCIgPyBfZnJpZW5kbHlWYWxpZGF0aW9uRXJyb3IoZSkgOiBTdHJpbmcoZSkpKQogICAgICAgICAgLmpvaW4oIiAiKTsKICAgICAgfQogICAgICByZXR1cm4gZmFsbGJhY2s7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gcG9zdEF1dGgocGF0aCwgcGF5bG9hZCkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgaGVhZGVyczogeyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0sCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgIH0pOwogICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKS5jYXRjaCgoKSA9PiAoe30pKTsKICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZXh0cmFjdEVycm9yRGV0YWlsKGRhdGEsICJVbmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSwgcsOpZXNzYWllLiIpKTsKICAgICAgfQogICAgICByZXR1cm4gZGF0YTsKICAgIH0KCiAgICBmdW5jdGlvbiBvblNlc3Npb25PYnRhaW5lZCh0b2tlbikgewogICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShUT0tFTl9TVE9SQUdFX0tFWSwgdG9rZW4pOwogICAgICAvLyBSZWNoYXJnZW1lbnQgY29tcGxldCBwbHV0w7R0IHF1ZSBkZSByw6ktZW5jaGHDrm5lciBsJ2luaXQgbWFudWVsbGVtZW50IDoKICAgICAgLy8gcGx1cyBzaW1wbGUgZXQgcGx1cyBzw7tyIChvbiByZXBhcnQgYXZlYyB1biDDqXRhdCBwcm9wcmUsIEFQSV9LRVkgbHUKICAgICAgLy8gZGVwdWlzIGxlIGxvY2FsU3RvcmFnZSBjb21tZSBhdSB0b3V0IHByZW1pZXIgY2hhcmdlbWVudCkuCiAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTsKICAgIH0KCiAgICAvLyAtLS0gQ29ubmV4aW9uIC0tLQogICAgY29uc3QgbG9naW5FbWFpbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWVtYWlsLWlucHV0Iik7CiAgICBjb25zdCBsb2dpblBhc3N3b3JkSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IGxvZ2luU3VibWl0QnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLXN1Ym1pdC1idG4iKTsKICAgIGNvbnN0IGxvZ2luRXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dpbi1lcnJvciIpOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRMb2dpbigpIHsKICAgICAgY29uc3QgZW1haWwgPSBsb2dpbkVtYWlsSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBwYXNzd29yZCA9IGxvZ2luUGFzc3dvcmRJbnB1dC52YWx1ZTsKICAgICAgaWYgKCFlbWFpbCB8fCAhcGFzc3dvcmQpIHJldHVybjsKICAgICAgbG9naW5FcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBzZXRBdXRoQnVzeShsb2dpblN1Ym1pdEJ0biwgIkNvbm5leGlvbuKApiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL2xvZ2luIiwgeyBlbWFpbCwgcGFzc3dvcmQgfSk7CiAgICAgICAgb25TZXNzaW9uT2J0YWluZWQoZGF0YS50b2tlbik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIGxvZ2luRXJyb3JFbC50ZXh0Q29udGVudCA9IGVyci5tZXNzYWdlOwogICAgICAgIGxvZ2luRXJyb3JFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShsb2dpblN1Ym1pdEJ0biwgbnVsbCwgIlNlIGNvbm5lY3RlciIpOwogICAgICB9CiAgICB9CiAgICBsb2dpblN1Ym1pdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGF0dGVtcHRMb2dpbik7CiAgICBbbG9naW5FbWFpbElucHV0LCBsb2dpblBhc3N3b3JkSW5wdXRdLmZvckVhY2goKGlucHV0KSA9PiB7CiAgICAgIGlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImtleWRvd24iLCAoZSkgPT4geyBpZiAoZS5rZXkgPT09ICJFbnRlciIpIGF0dGVtcHRMb2dpbigpOyB9KTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWdvdG8tZm9yZ290IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93QXV0aFZpZXcoImZvcmdvdCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dpbi1nb3RvLXNpZ251cCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0F1dGhWaWV3KCJzaWdudXAiKSk7CgogICAgLy8gLS0tIEluc2NyaXB0aW9uIChzdXIgaW52aXRhdGlvbikgLS0tCiAgICBjb25zdCBzaWdudXBJbnZpdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtaW52aXRlLWlucHV0Iik7CiAgICBjb25zdCBzaWdudXBFbWFpbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNpZ251cC1lbWFpbC1pbnB1dCIpOwogICAgY29uc3Qgc2lnbnVwVXNlcm5hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtdXNlcm5hbWUtaW5wdXQiKTsKICAgIGNvbnN0IHNpZ251cFBhc3N3b3JkSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLXBhc3N3b3JkLWlucHV0Iik7CiAgICBjb25zdCBzaWdudXBTdWJtaXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLXN1Ym1pdC1idG4iKTsKICAgIGNvbnN0IHNpZ251cEVycm9yRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLWVycm9yIik7CgogICAgYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdFNpZ251cCgpIHsKICAgICAgY29uc3QgaW52aXRlX3Rva2VuID0gc2lnbnVwSW52aXRlSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBlbWFpbCA9IHNpZ251cEVtYWlsSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCB1c2VybmFtZSA9IHNpZ251cFVzZXJuYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBwYXNzd29yZCA9IHNpZ251cFBhc3N3b3JkSW5wdXQudmFsdWU7CiAgICAgIGlmICghaW52aXRlX3Rva2VuIHx8ICFlbWFpbCB8fCAhdXNlcm5hbWUgfHwgIXBhc3N3b3JkKSB7CiAgICAgICAgc2lnbnVwRXJyb3JFbC50ZXh0Q29udGVudCA9ICJUb3VzIGxlcyBjaGFtcHMgc29udCByZXF1aXMuIjsKICAgICAgICBzaWdudXBFcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBzaWdudXBFcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBzZXRBdXRoQnVzeShzaWdudXBTdWJtaXRCdG4sICJDcsOpYXRpb27igKYiKTsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcG9zdEF1dGgoIi9hcGkvYXV0aC9zaWdudXAiLCB7IGludml0ZV90b2tlbiwgZW1haWwsIHVzZXJuYW1lLCBwYXNzd29yZCB9KTsKICAgICAgICBvblNlc3Npb25PYnRhaW5lZChkYXRhLnRva2VuKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2lnbnVwRXJyb3JFbC50ZXh0Q29udGVudCA9IGVyci5tZXNzYWdlOwogICAgICAgIHNpZ251cEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3koc2lnbnVwU3VibWl0QnRuLCBudWxsLCAiQ3LDqWVyIG1vbiBjb21wdGUiKTsKICAgICAgfQogICAgfQogICAgc2lnbnVwU3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdFNpZ251cCk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLWdvdG8tbG9naW4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygibG9naW4iKSk7CgogICAgLy8gLS0tIE1vdCBkZSBwYXNzZSBvdWJsacOpIC0tLQogICAgY29uc3QgZm9yZ290RW1haWxJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3QtZW1haWwtaW5wdXQiKTsKICAgIGNvbnN0IGZvcmdvdFN1Ym1pdEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3Qtc3VibWl0LWJ0biIpOwogICAgY29uc3QgZm9yZ290RXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3QtZXJyb3IiKTsKICAgIGNvbnN0IGZvcmdvdFN1Y2Nlc3NFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3Qtc3VjY2VzcyIpOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRGb3Jnb3RQYXNzd29yZCgpIHsKICAgICAgY29uc3QgZW1haWwgPSBmb3Jnb3RFbWFpbElucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgaWYgKCFlbWFpbCkgcmV0dXJuOwogICAgICBmb3Jnb3RFcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBmb3Jnb3RTdWNjZXNzRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHNldEF1dGhCdXN5KGZvcmdvdFN1Ym1pdEJ0biwgIkVudm9p4oCmIik7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgcG9zdEF1dGgoIi9hcGkvYXV0aC9mb3Jnb3QtcGFzc3dvcmQiLCB7IGVtYWlsIH0pOwogICAgICAgIGZvcmdvdFN1Y2Nlc3NFbC50ZXh0Q29udGVudCA9ICJTaSB1biBjb21wdGUgZXhpc3RlIGF2ZWMgY2V0IGVtYWlsLCB1biBsaWVuIGRlIHLDqWluaXRpYWxpc2F0aW9uIHZpZW50IGQnw6p0cmUgZW52b3nDqS4iOwogICAgICAgIGZvcmdvdFN1Y2Nlc3NFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShmb3Jnb3RTdWJtaXRCdG4sIG51bGwsICJFbnZveWVyIGxlIGxpZW4iKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgZm9yZ290RXJyb3JFbC50ZXh0Q29udGVudCA9IGVyci5tZXNzYWdlOwogICAgICAgIGZvcmdvdEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3koZm9yZ290U3VibWl0QnRuLCBudWxsLCAiRW52b3llciBsZSBsaWVuIik7CiAgICAgIH0KICAgIH0KICAgIGZvcmdvdFN1Ym1pdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGF0dGVtcHRGb3Jnb3RQYXNzd29yZCk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZm9yZ290LWdvdG8tbG9naW4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygibG9naW4iKSk7CgogICAgLy8gLS0tIFLDqWluaXRpYWxpc2F0aW9uIChkZXB1aXMgbGUgbGllbiByZcOndSBwYXIgZW1haWwsID9yZXNldD1UT0tFTikgLS0tCiAgICBjb25zdCByZXNldFBhc3N3b3JkSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVzZXQtcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IHJlc2V0U3VibWl0QnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlc2V0LXN1Ym1pdC1idG4iKTsKICAgIGNvbnN0IHJlc2V0RXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1lcnJvciIpOwogICAgY29uc3QgcmVzZXRTdWNjZXNzRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVzZXQtc3VjY2VzcyIpOwogICAgbGV0IHBlbmRpbmdSZXNldFRva2VuID0gbnVsbDsKCiAgICBhc3luYyBmdW5jdGlvbiBhdHRlbXB0UmVzZXRQYXNzd29yZCgpIHsKICAgICAgY29uc3QgbmV3X3Bhc3N3b3JkID0gcmVzZXRQYXNzd29yZElucHV0LnZhbHVlOwogICAgICBpZiAoIW5ld19wYXNzd29yZCB8fCAhcGVuZGluZ1Jlc2V0VG9rZW4pIHJldHVybjsKICAgICAgcmVzZXRFcnJvckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICByZXNldFN1Y2Nlc3NFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgc2V0QXV0aEJ1c3kocmVzZXRTdWJtaXRCdG4sICJWYWxpZGF0aW9u4oCmIik7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgcG9zdEF1dGgoIi9hcGkvYXV0aC9yZXNldC1wYXNzd29yZCIsIHsgdG9rZW46IHBlbmRpbmdSZXNldFRva2VuLCBuZXdfcGFzc3dvcmQgfSk7CiAgICAgICAgcmVzZXRTdWNjZXNzRWwudGV4dENvbnRlbnQgPSAiTW90IGRlIHBhc3NlIG1pcyDDoCBqb3VyLCB0dSBwZXV4IHRlIGNvbm5lY3Rlci4iOwogICAgICAgIHJlc2V0U3VjY2Vzc0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KHJlc2V0U3VibWl0QnRuLCBudWxsLCAiVmFsaWRlciIpOwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2hvd0F1dGhWaWV3KCJsb2dpbiIpLCAxNTAwKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgcmVzZXRFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgcmVzZXRFcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KHJlc2V0U3VibWl0QnRuLCBudWxsLCAiVmFsaWRlciIpOwogICAgICB9CiAgICB9CiAgICByZXNldFN1Ym1pdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGF0dGVtcHRSZXNldFBhc3N3b3JkKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1nb3RvLWxvZ2luIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93QXV0aFZpZXcoImxvZ2luIikpOwoKICAgIC8vIC0tLSBBZmZpY2hlci9tYXNxdWVyIGxlIG1vdCBkZSBwYXNzZSAoaWPDtG5lIMWTaWwpIC0tLQogICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLnBhc3N3b3JkLXRvZ2dsZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgY29uc3QgdGFyZ2V0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoYnRuLmRhdGFzZXQudGFyZ2V0KTsKICAgICAgYnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGNvbnN0IHNob3dpbmcgPSB0YXJnZXQudHlwZSA9PT0gInRleHQiOwogICAgICAgIHRhcmdldC50eXBlID0gc2hvd2luZyA/ICJwYXNzd29yZCIgOiAidGV4dCI7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsICFzaG93aW5nKTsKICAgICAgICBidG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgc2hvd2luZyA/ICJBZmZpY2hlciBsZSBtb3QgZGUgcGFzc2UiIDogIk1hc3F1ZXIgbGUgbW90IGRlIHBhc3NlIik7CiAgICAgIH0pOwogICAgfSk7CgogICAgLy8gLS0tIETDqWNvbm5leGlvbiAtLS0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dvdXQtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oIlNlIGTDqWNvbm5lY3RlciA/IFR1IGRldnJhcyByZXNzYWlzaXIgdG9uIG1vdCBkZSBwYXNzZSBwb3VyIHJldmVuaXIuIik7CiAgICAgIGlmIChvaykgc2hvd0xvY2tTY3JlZW4oImxvZ2luIik7CiAgICB9KTsKCiAgICAvLyAtLS0gTGllbnMgcmXDp3VzIHBhciBlbWFpbCAoP2ludml0ZT0uLi4gb3UgP3Jlc2V0PS4uLikgLS0tCiAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpOwogICAgY29uc3QgaW52aXRlVG9rZW5Gcm9tVXJsID0gdXJsUGFyYW1zLmdldCgiaW52aXRlIik7CiAgICBjb25zdCByZXNldFRva2VuRnJvbVVybCA9IHVybFBhcmFtcy5nZXQoInJlc2V0Iik7CiAgICBsZXQgaW5pdGlhbEF1dGhWaWV3ID0gImxvZ2luIjsKICAgIGlmIChpbnZpdGVUb2tlbkZyb21VcmwpIHsKICAgICAgc2lnbnVwSW52aXRlSW5wdXQudmFsdWUgPSBpbnZpdGVUb2tlbkZyb21Vcmw7CiAgICAgIGluaXRpYWxBdXRoVmlldyA9ICJzaWdudXAiOwogICAgICB3aW5kb3cuaGlzdG9yeS5yZXBsYWNlU3RhdGUoe30sICIiLCB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUpOwogICAgfSBlbHNlIGlmIChyZXNldFRva2VuRnJvbVVybCkgewogICAgICBwZW5kaW5nUmVzZXRUb2tlbiA9IHJlc2V0VG9rZW5Gcm9tVXJsOwogICAgICBpbml0aWFsQXV0aFZpZXcgPSAicmVzZXQiOwogICAgICB3aW5kb3cuaGlzdG9yeS5yZXBsYWNlU3RhdGUoe30sICIiLCB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUpOwogICAgfQoKICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eC1saXN0Iik7CiAgICBjb25zdCBlbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHN1bW1hcnlCYWxhbmNlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1iYWxhbmNlIik7CiAgICBjb25zdCBzdW1tYXJ5RXhwZW5zZXNFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWV4cGVuc2VzIik7CiAgICBjb25zdCBzdW1tYXJ5SW5jb21lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS1pbmNvbWUiKTsKCiAgICBjb25zdCBvdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgbW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1vZGFsLXRpdGxlIik7CiAgICBjb25zdCB0eXBlVG9nZ2xlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IGFtb3VudElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWFtb3VudCIpOwogICAgY29uc3QgY2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUiKTsKICAgIGNvbnN0IGRlc2NyaXB0aW9uSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtZGVzY3JpcHRpb24iKTsKICAgIGNvbnN0IGRhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kYXRlIik7CiAgICBjb25zdCBzYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1zYXZlIik7CgogICAgbGV0IGVkaXRpbmdJZCA9IG51bGw7IC8vIG51bGwgPSBjcsOpYXRpb24sIHNpbm9uIGlkIGRlIGxhIHRyYW5zYWN0aW9uIMOpZGl0w6llCiAgICBsZXQgZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnkgPSBudWxsOyAvLyBjYXTDqWdvcmllIGRlIGxhIHRyYW5zYWN0aW9uIGF2YW50IMOpZGl0aW9uIChwb3VyIGTDqXRlY3RlciB1biBjaGFuZ2VtZW50KQogICAgbGV0IGN1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBob3RvIGRlIHJlw6d1IGVuIHBpw6hjZSBqb2ludGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IHJlY2VpcHRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtcmVjZWlwdC1maWxlIik7CiAgICBjb25zdCByZWNlaXB0UHJldmlld1dyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LXdyYXAiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtcHJldmlldy1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRQaWNrQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZWNlaXB0LXBpY2siKTsKICAgIGNvbnN0IHJlY2VpcHRSZW1vdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcmVtb3ZlIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hPdmVybGF5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjZWlwdExpZ2h0Ym94SW1nID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtaW1nIik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hDbG9zZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIik7CgogICAgLy8gRmljaGllciBjaG9pc2kgbWFpcyBwYXMgZW5jb3JlIGVudm95w6kgKHVuaXF1ZW1lbnQgZW4gY3LDqWF0aW9uLCB0YW50IHF1ZQogICAgLy8gbGEgdHJhbnNhY3Rpb24gbidhIHBhcyBlbmNvcmUgZCdpZCkgOyBlbiDDqWRpdGlvbiwgbCdlbnZvaSBlc3QgaW1tw6lkaWF0LgogICAgbGV0IHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICBsZXQgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgbGV0IGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNldFJlY2VpcHRQcmV2aWV3RnJvbUJsb2IoYmxvYikgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpOwogICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9IHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgUmVtcGxhY2VyIGxhIHBob3RvIjsKICAgIH0KCiAgICBmdW5jdGlvbiByZXNldFJlY2VpcHRVaSgpIHsKICAgICAgaWYgKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKSB7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgICAgcmVjZWlwdFByZXZpZXdPYmplY3RVcmwgPSBudWxsOwogICAgICB9CiAgICAgIHJlY2VpcHRQcmV2aWV3SW1nLnNyYyA9ICIiOwogICAgICByZWNlaXB0UHJldmlld1dyYXAuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlY2VpcHRQaWNrQnRuLnRleHRDb250ZW50ID0gIvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3UiOwogICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgIHBlbmRpbmdSZWNlaXB0RmlsZSA9IG51bGw7CiAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IGZhbHNlOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHRyYW5zYWN0aW9uSWQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgewogICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSByZXR1cm47CiAgICAgICAgY29uc3QgYmxvYiA9IGF3YWl0IHJlcy5ibG9iKCk7CiAgICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKTsKICAgICAgICBoYXNFeGlzdGluZ1JlY2VpcHQgPSB0cnVlOwogICAgICB9IGNhdGNoIChfKSB7CiAgICAgICAgLy8gUGFzIGdyYXZlIDogbCd1dGlsaXNhdGV1ciBwZXV0IGp1c3RlIHLDqWVzc2F5ZXIgZCdvdXZyaXIgbGEgZmljaGUuCiAgICAgIH0KICAgIH0KCiAgICByZWNlaXB0UGlja0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHJlY2VpcHRGaWxlSW5wdXQuY2xpY2soKSk7CgogICAgcmVjZWlwdEZpbGVJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGZpbGUgPSByZWNlaXB0RmlsZUlucHV0LmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHJldHVybjsKICAgICAgaWYgKCFmaWxlLnR5cGUuc3RhcnRzV2l0aCgiaW1hZ2UvIikpIHsKICAgICAgICBzaG93VG9hc3QoIkNob2lzaXMgdW5lIGltYWdlIChKUEVHLCBQTkcsIFdFQlAgb3UgSEVJQykiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiA4ICogMTAyNCAqIDEwMjQpIHsKICAgICAgICBzaG93VG9hc3QoIkltYWdlIHRyb3AgbG91cmRlICg4IE1vIG1heGltdW0pIiwgdHJ1ZSk7CiAgICAgICAgcmVjZWlwdEZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihmaWxlKTsKCiAgICAgIGlmIChlZGl0aW5nSWQpIHsKICAgICAgICAvLyBUcmFuc2FjdGlvbiBkw6lqw6AgZXhpc3RhbnRlIDogb24gZW52b2llIHRvdXQgZGUgc3VpdGUsIGluZMOpcGVuZGFtbWVudAogICAgICAgIC8vIGR1IGJvdXRvbiAiRW5yZWdpc3RyZXIiIGR1IGZvcm11bGFpcmUuCiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgIH0pLnRoZW4oYXN5bmMgKHJlcykgPT4gewogICAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihleHRyYWN0RXJyb3JEZXRhaWwoZGF0YSwgYEVycmV1ciBIVFRQICR7cmVzLnN0YXR1c31gKSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gdHJ1ZTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gZHUgcmXDp3UgZW5yZWdpc3Ryw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIC8vIE5vdXZlbGxlIHRyYW5zYWN0aW9uIHBhcyBlbmNvcmUgY3LDqcOpZSA6IG9uIGdhcmRlIGxlIGZpY2hpZXIgZGUgY8O0dMOpLAogICAgICAgIC8vIGlsIHNlcmEgZW52b3nDqSBqdXN0ZSBhcHLDqHMgbGEgY3LDqWF0aW9uICh2b2lyIGJ0bi1zYXZlKS4KICAgICAgICBwZW5kaW5nUmVjZWlwdEZpbGUgPSBmaWxlOwogICAgICB9CiAgICB9KTsKCiAgICByZWNlaXB0UmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBpZiAoZWRpdGluZ0lkICYmIGhhc0V4aXN0aW5nUmVjZWlwdCkgewogICAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgbGEgcGhvdG8gZGUgY2UgcmXDp3UgPyIpKSkgcmV0dXJuOwogICAgICAgIHRyeSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9L3JlY2VpcHRgLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICAgICAgc2hvd1RvYXN0KCJQaG90byBzdXBwcmltw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWNlaXB0TGlnaHRib3godHJhbnNhY3Rpb25JZCkgewogICAgICBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSkKICAgICAgICAudGhlbigocmVzKSA9PiB7CiAgICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCJJbXBvc3NpYmxlIGRlIGNoYXJnZXIgbGEgcGhvdG8iKTsKICAgICAgICAgIHJldHVybiByZXMuYmxvYigpOwogICAgICAgIH0pCiAgICAgICAgLnRoZW4oKGJsb2IpID0+IHsKICAgICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgICByZWNlaXB0TGlnaHRib3hJbWcuc3JjID0gdXJsOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB9KQogICAgICAgIC5jYXRjaCgoZXJyKSA9PiBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlUmVjZWlwdExpZ2h0Ym94KCkgewogICAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAocmVjZWlwdExpZ2h0Ym94SW1nLnNyYykgewogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdExpZ2h0Ym94SW1nLnNyYyk7CiAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9ICIiOwogICAgICB9CiAgICB9CgogICAgcmVjZWlwdExpZ2h0Ym94Q2xvc2VCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY2VpcHRMaWdodGJveCk7CiAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSByZWNlaXB0TGlnaHRib3hPdmVybGF5KSBjbG9zZVJlY2VpcHRMaWdodGJveCgpOwogICAgfSk7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgLy8gQ2F0w6lnb3JpZXMgY3LDqcOpZXMgcGFyIGwndXRpbGlzYXRldXIgZGVwdWlzIGxlIGJhbmRlYXUgZGUgc3VnZ2VzdGlvbgogICAgLy8gKHZvaXIgcGx1cyBiYXMpLCBldCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgOiBzdG9ja8OpZXMgY8O0dMOpIHNlcnZldXIKICAgIC8vICh0YWJsZXMgY3VzdG9tX2NhdGVnb3JpZXMgLyBkaXNtaXNzZWRfY2F0ZWdvcnlfc3VnZ2VzdGlvbnMpIHBsdXTDtHQKICAgIC8vIHF1ZSBkYW5zIGxlIG5hdmlnYXRldXIsIHBvdXIgc3VpdnJlIHN1ciB0b3VzIGxlcyBhcHBhcmVpbHMgKHTDqWzDqXBob25lLAogICAgLy8gdGFibGV0dGUsIG9yZGluYXRldXIpIHBsdXTDtHQgcXVlIGRlIG5lIG1hcmNoZXIgcXVlIGzDoCBvw7kgYyfDqXRhaXQgY3LDqcOpLgogICAgbGV0IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldCgpOwogICAgbGV0IGFsbEJ1ZGdldHMgPSBbXTsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQnVkZ2V0cygpIHsKICAgICAgdHJ5IHsKICAgICAgICBhbGxCdWRnZXRzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBidWRnZXRzIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsICsgY29uc2VpbHMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGxldCBzYXZpbmdzR29hbCA9IG51bGw7IC8vIHsgbW9udGhseV90YXJnZXQgfSBvdSBudWxsIHNpIGphbWFpcyBjb25maWd1csOpCgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFNhdmluZ3NHb2FsKCkgewogICAgICB0cnkgewogICAgICAgIHNhdmluZ3NHb2FsID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvc2F2aW5ncy1nb2FsIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGUgbCdvYmplY3RpZiBkJ8OpcGFyZ25lIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1zYXZlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZW50cmllcyA9IE9iamVjdC5lbnRyaWVzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpOwogICAgICBsZXQgc2F2ZWRDb3VudCA9IDA7CiAgICAgIGxldCBoYWRFcnJvciA9IGZhbHNlOwogICAgICBmb3IgKGNvbnN0IFtjYXRlZ29yeSwgaW5wdXRdIG9mIGVudHJpZXMpIHsKICAgICAgICBjb25zdCByYXcgPSBpbnB1dC52YWx1ZTsKICAgICAgICBpZiAocmF3ID09PSAiIiB8fCByYXcgPT09IG51bGwpIGNvbnRpbnVlOwogICAgICAgIGNvbnN0IGFtb3VudCA9IE51bWJlcihyYXcpOwogICAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSBjb250aW51ZTsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgc2F2ZUJ1ZGdldChjYXRlZ29yeSwgYW1vdW50KTsKICAgICAgICAgIHNhdmVkQ291bnQgKz0gMTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIGhhZEVycm9yID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KICAgICAgaWYgKGhhZEVycm9yKSB7CiAgICAgICAgc2hvd1RvYXN0KCJDZXJ0YWlucyBidWRnZXRzIG4nb250IHBhcyBwdSDDqnRyZSBlbnJlZ2lzdHLDqXMiLCB0cnVlKTsKICAgICAgfSBlbHNlIGlmIChzYXZlZENvdW50ID09PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIGF1IG1vaW5zIHVuIG1vbnRhbnQgZGUgYnVkZ2V0IHZhbGlkZSIsIHRydWUpOwogICAgICB9IGVsc2UgewogICAgICAgIHNob3dUb2FzdCgiQnVkZ2V0cyBlbnJlZ2lzdHLDqXMiKTsKICAgICAgfQogICAgICByZW5kZXJCdWRnZXRzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICBjb25zdCBzYXZpbmdzR29hbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1pbnB1dCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1zYXZlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIoc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIHVuIG1vbnRhbnQgZCdvYmplY3RpZiB2YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IG1vbnRobHlfdGFyZ2V0OiBhbW91bnQgfSksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJPYmplY3RpZiBlbnJlZ2lzdHLDqSIpOwogICAgICAgIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfSk7CgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5ncyh0cmFuc2FjdGlvbnMpIHsKICAgICAgaWYgKHNhdmluZ3NHb2FsKSBzYXZpbmdzR29hbElucHV0LnZhbHVlID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CiAgICAgIGlmIChzYXZpbmdzR29hbCAmJiBwbGFjZW1lbnRNb250aGx5QXV0b0ZpbGxlZCkgewogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtbW9udGhseSIpLnZhbHVlID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CiAgICAgIH0KCiAgICAgIC8vIFNvbGRlIGR1IG1vaXMgZW4gY291cnMgKHJldmVudXMgLSBkw6lwZW5zZXMpLCB0b3V0IGNvbmZvbmR1LgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBsZXQgbW9udGhJbmNvbWUgPSAwOwogICAgICBsZXQgbW9udGhFeHBlbnNlcyA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gY3VycmVudE1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIG1vbnRoSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgbW9udGhFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBtb250aE5ldCA9IG1vbnRoSW5jb21lIC0gbW9udGhFeHBlbnNlczsKCiAgICAgIGNvbnN0IHByb2dyZXNzU2VjdGlvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iKTsKICAgICAgY29uc3QgcHJvZ3Jlc3NUZXh0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtdGV4dCIpOwogICAgICBjb25zdCBwcm9ncmVzc0JhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLWJhciIpOwogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgcHJvZ3Jlc3NTZWN0aW9uLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIGNvbnN0IHRhcmdldCA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwogICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWF4KDAsIE1hdGgubWluKChtb250aE5ldCAvIHRhcmdldCkgKiAxMDAsIDEwMCkpOwogICAgICAgIHByb2dyZXNzVGV4dC50ZXh0Q29udGVudCA9IGAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChtb250aE5ldCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0KX1gOwogICAgICAgIGxldCBjbHMgPSAib2siOwogICAgICAgIGlmIChtb250aE5ldCA8IDApIGNscyA9ICJvdmVyIjsKICAgICAgICBlbHNlIGlmIChtb250aE5ldCA8IHRhcmdldCkgY2xzID0gIndhcm5pbmciOwogICAgICAgIHByb2dyZXNzQmFyLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICBwcm9ncmVzc0Jhci5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCk7CiAgICAgIHJlbmRlclBsYWNlbWVudFNpbXVsYXRpb24oKTsKICAgICAgcmVuZGVyU2F2aW5nc1BsYW4oKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTaW11bGF0aW9uIGRlIHBsYWNlbWVudCAoaW50w6lyw6p0cyBjb21wb3PDqXMsIGNhbGN1bMOpcyBtZW5zdWVsbGVtZW50KSDigJQKICAgIC8vIHB1cmVtZW50IGPDtHTDqSBjbGllbnQgOiBhdWN1bmUgZG9ubsOpZSByw6llbGxlIGRlIGwndXRpbGlzYXRldXIgbidlbnRyZQogICAgLy8gZW4gamV1LCBzZXVsZW1lbnQgbGVzIDQgY2hhbXBzIGR1IGZvcm11bGFpcmUuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBsZXQgcGxhY2VtZW50Q2hhcnQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIGNvbXB1dGVQbGFjZW1lbnRTZXJpZXMoaW5pdGlhbCwgbW9udGhseUNvbnRyaWJ1dGlvbiwgYW5udWFsUmF0ZVBlcmNlbnQsIHllYXJzKSB7CiAgICAgIGNvbnN0IG1vbnRocyA9IE1hdGgubWF4KDEsIE1hdGgucm91bmQoeWVhcnMgKiAxMikpOwogICAgICBjb25zdCBtb250aGx5UmF0ZSA9IE1hdGgucG93KDEgKyBhbm51YWxSYXRlUGVyY2VudCAvIDEwMCwgMSAvIDEyKSAtIDE7CiAgICAgIGxldCBiYWxhbmNlID0gaW5pdGlhbDsKICAgICAgY29uc3Qgc2VyaWVzID0gW2JhbGFuY2VdOwogICAgICBmb3IgKGxldCBtID0gMTsgbSA8PSBtb250aHM7IG0rKykgewogICAgICAgIGJhbGFuY2UgPSBiYWxhbmNlICogKDEgKyBtb250aGx5UmF0ZSkgKyBtb250aGx5Q29udHJpYnV0aW9uOwogICAgICAgIHNlcmllcy5wdXNoKGJhbGFuY2UpOwogICAgICB9CiAgICAgIHJldHVybiBzZXJpZXM7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbigpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LXBsYWNlbWVudCIpOwogICAgICBpZiAoIWNhbnZhcykgcmV0dXJuOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1jaGFydC1lbXB0eSIpOwogICAgICBjb25zdCBpbml0aWFsID0gTWF0aC5tYXgoMCwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtaW5pdGlhbCIpLnZhbHVlKSB8fCAwKTsKICAgICAgY29uc3QgbW9udGhseSA9IE1hdGgubWF4KDAsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LW1vbnRobHkiKS52YWx1ZSkgfHwgMCk7CiAgICAgIGNvbnN0IHJhdGUgPSBNYXRoLm1heCgwLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1yYXRlIikudmFsdWUpIHx8IDApOwogICAgICBjb25zdCB5ZWFycyA9IE1hdGgubWF4KDEsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LXllYXJzIikudmFsdWUpIHx8IDEpOwoKICAgICAgY29uc3Qgc2VyaWVzID0gY29tcHV0ZVBsYWNlbWVudFNlcmllcyhpbml0aWFsLCBtb250aGx5LCByYXRlLCB5ZWFycyk7CiAgICAgIGNvbnN0IG1vbnRocyA9IHNlcmllcy5sZW5ndGggLSAxOwogICAgICBjb25zdCBsYWJlbHMgPSBzZXJpZXMubWFwKChfLCBpKSA9PiAoCiAgICAgICAgaSAlIDEyID09PSAwID8gYEFuICR7aSAvIDEyfWAgOiAiIgogICAgICApKTsKCiAgICAgIGlmIChwbGFjZW1lbnRDaGFydCkgeyBwbGFjZW1lbnRDaGFydC5kZXN0cm95KCk7IHBsYWNlbWVudENoYXJ0ID0gbnVsbDsgfQogICAgICBpZiAoZW1wdHlFbCkgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgIHBsYWNlbWVudENoYXJ0ID0gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJsaW5lIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgbGFiZWw6ICJTb2xkZSBwcm9qZXTDqSIsCiAgICAgICAgICAgIGRhdGE6IHNlcmllcywKICAgICAgICAgICAgYm9yZGVyQ29sb3I6IENIQVJUX0NPTE9SU1sxXSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAicmdiYSgzNCwgMTk3LCA5NCwgMC4xNSkiLAogICAgICAgICAgICBmaWxsOiB0cnVlLAogICAgICAgICAgICB0ZW5zaW9uOiAwLjIsCiAgICAgICAgICAgIHBvaW50UmFkaXVzOiAwLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7IGxlZ2VuZDogeyBkaXNwbGF5OiBmYWxzZSB9IH0sCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjYWxsYmFjazogKHYpID0+IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh2KSB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0sIGVtcHR5RWwpOwoKICAgICAgY29uc3QgZmluYWxCYWxhbmNlID0gc2VyaWVzW3Nlcmllcy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgdG90YWxDb250cmlidXRlZCA9IGluaXRpYWwgKyBtb250aGx5ICogbW9udGhzOwogICAgICBjb25zdCBpbnRlcmVzdEVhcm5lZCA9IGZpbmFsQmFsYW5jZSAtIHRvdGFsQ29udHJpYnV0ZWQ7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtcmVzdWx0IikuaW5uZXJIVE1MID0KICAgICAgICBgQXByw6hzICR7eWVhcnN9IGFuJHt5ZWFycyA+IDEgPyAicyIgOiAiIn0gOiA8c3Ryb25nPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGZpbmFsQmFsYW5jZSl9PC9zdHJvbmc+IGAgKwogICAgICAgIGAoZG9udCAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpbnRlcmVzdEVhcm5lZCl9IGQnaW50w6lyw6p0cywgcG91ciAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbENvbnRyaWJ1dGVkKX0gdmVyc8OpcykuYDsKICAgIH0KCiAgICBmb3IgKGNvbnN0IGlkIG9mIFsicGxhY2VtZW50LWluaXRpYWwiLCAicGxhY2VtZW50LW1vbnRobHkiLCAicGxhY2VtZW50LXJhdGUiLCAicGxhY2VtZW50LXllYXJzIl0pIHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbik7CiAgICB9CgogICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLnBsYWNlbWVudC1wcmVzZXQtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgIGJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LXJhdGUiKS52YWx1ZSA9IGJ0bi5kYXRhc2V0LnJhdGU7CiAgICAgICAgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbigpOwogICAgICB9KTsKICAgIH0pOwoKICAgIC8vIFRhbnQgcXVlIGwndXRpbGlzYXRldXIgbidhIHBhcyB0YXDDqSBsdWktbcOqbWUgZGFucyAidmVyc2VtZW50IG1lbnN1ZWwiLAogICAgLy8gb24gbGUgZ2FyZGUgc3luY2hyb25pc8OpIGF2ZWMgc29uIG9iamVjdGlmIGQnw6lwYXJnbmUgY29uZmlndXLDqSAoZXQsCiAgICAvLyBwbHVzIGJhcywgYXZlYyBsZSBwbGFuIGQnw6lwYXJnbmUpIOKAlCBkw6hzIHF1J2lsIHkgdG91Y2hlLCBvbiBhcnLDqnRlIGRlCiAgICAvLyBsJ8OpY3Jhc2VyIGF1dG9tYXRpcXVlbWVudC4KICAgIGxldCBwbGFjZW1lbnRNb250aGx5QXV0b0ZpbGxlZCA9IHRydWU7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LW1vbnRobHkiKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsICgpID0+IHsKICAgICAgcGxhY2VtZW50TW9udGhseUF1dG9GaWxsZWQgPSBmYWxzZTsKICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBsYW4gZCfDqXBhcmduZSDigJQgbm90ZSBkJ2Vzc2VudGlhbGl0w6kgKDEgw6AgNSkgZG9ubsOpZSBwYXIgbGEgUEVSU09OTkUKICAgIC8vIGVsbGUtbcOqbWUgKGphbWFpcyBkw6lkdWl0ZSBuaSBqdWfDqWUgcGFyIGwnSUEpIHBvdXIgY2hhcXVlIGNhdMOpZ29yaWUgZGUKICAgIC8vIGTDqXBlbnNlIGV0IGNoYXF1ZSBjaGFyZ2UgcsOpY3VycmVudGUsIHBvdXIgZXN0aW1lciBjZSBxdSdlbGxlIHBvdXJyYWl0CiAgICAvLyDDqWNvbm9taXNlciBlbiBwbHVzIHNpIGNldCBhcmdlbnQgw6l0YWl0IHJlZGlyaWfDqSB2ZXJzIGwnw6lwYXJnbmUuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBCYXLDqG1lIGRlIGTDqXBhcnQgOiAxIChwYXMgZXNzZW50aWVsKSAtPiBvbiBjb25zaWTDqHJlIHF1J29uIHBvdXJyYWl0IGVuCiAgICAvLyByw6ljdXDDqXJlciBsYSBtb2l0acOpIDsgNCBldCA1IChlc3NlbnRpZWwpIC0+IDAlLCBvbiBuJ3kgdG91Y2hlIHBhcy4KICAgIC8vIEFqdXN0YWJsZSBmYWNpbGVtZW50IGljaSBzaSBiZXNvaW4gYXByw6hzIHVzYWdlIHLDqWVsLgogICAgY29uc3QgRVNTRU5USUFMSVRZX1JFRFVDVElPTl9QQ1QgPSB7IDE6IDAuNTAsIDI6IDAuMjUsIDM6IDAuMTAsIDQ6IDAsIDU6IDAgfTsKCiAgICBsZXQgY2F0ZWdvcnlSYXRpbmdzID0ge307IC8vIHsgW2NhdGVnb3J5XTogcmF0aW5nIH0KICAgIGxldCBjYXRlZ29yeVJhdGluZ1VwZGF0ZWRBdCA9IHt9OyAvLyB7IFtjYXRlZ29yeV06IHJhdGluZ191cGRhdGVkX2F0IChJU08pIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ2F0ZWdvcnlSYXRpbmdzKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJvd3MgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jYXRlZ29yeS1yYXRpbmdzIik7CiAgICAgICAgY2F0ZWdvcnlSYXRpbmdzID0gT2JqZWN0LmZyb21FbnRyaWVzKHJvd3MubWFwKChyKSA9PiBbci5jYXRlZ29yeSwgci5yYXRpbmddKSk7CiAgICAgICAgY2F0ZWdvcnlSYXRpbmdVcGRhdGVkQXQgPSBPYmplY3QuZnJvbUVudHJpZXMocm93cy5tYXAoKHIpID0+IFtyLmNhdGVnb3J5LCByLnJhdGluZ191cGRhdGVkX2F0XSkpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBub3RlcyBkZSBjYXTDqWdvcmllcyA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gTm9tYnJlIGRlIG1vaXMgKGFycm9uZGkpIGVudHJlIHVuZSBkYXRlIElTTyBldCBhdWpvdXJkJ2h1aSDigJQgcG91cgogICAgLy8gYWZmaWNoZXIgIm5vdMOpIGlsIHkgYSBYIG1vaXMiIGRhbnMgbGUgUGxhbiBkJ8OpcGFyZ25lLCBzYW5zIGZvcmNlciBkZQogICAgLy8gcmVtaXNlIMOgIGpvdXIgKGp1c3RlIHVuZSBpbmZvLCB2b2lyIGlkw6llIGNvbmZpcm3DqWUgcGFyIGwndXRpbGlzYXRldXIpLgogICAgZnVuY3Rpb24gbW9udGhzU2luY2UoaXNvRGF0ZSkgewogICAgICBpZiAoIWlzb0RhdGUpIHJldHVybiBudWxsOwogICAgICBjb25zdCB0aGVuID0gbmV3IERhdGUoaXNvRGF0ZSk7CiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IG1vbnRocyA9IChub3cuZ2V0RnVsbFllYXIoKSAtIHRoZW4uZ2V0RnVsbFllYXIoKSkgKiAxMiArIChub3cuZ2V0TW9udGgoKSAtIHRoZW4uZ2V0TW9udGgoKSk7CiAgICAgIHJldHVybiBNYXRoLm1heCgwLCBtb250aHMpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNhdmluZ3NQbGFuUmF0aW5nQnV0dG9ucyhjdXJyZW50UmF0aW5nLCBvblBpY2spIHsKICAgICAgY29uc3Qgd3JhcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICB3cmFwLmNsYXNzTmFtZSA9ICJzYXZpbmdzLXBsYW4tcmF0aW5nIjsKICAgICAgZm9yIChsZXQgbiA9IDE7IG4gPD0gNTsgbisrKSB7CiAgICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYnRuLnR5cGUgPSAiYnV0dG9uIjsKICAgICAgICBidG4uY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1yYXRpbmctYnRuIiArIChjdXJyZW50UmF0aW5nID09PSBuID8gIiBhY3RpdmUiIDogIiIpOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IFN0cmluZyhuKTsKICAgICAgICBidG4udGl0bGUgPSBuIDw9IDIgPyAiUGV1L3BhcyBlc3NlbnRpZWwiIDogbiA9PT0gMyA/ICJOZXV0cmUiIDogIkVzc2VudGllbCI7CiAgICAgICAgYnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb25QaWNrKG4pKTsKICAgICAgICB3cmFwLmFwcGVuZENoaWxkKGJ0bik7CiAgICAgIH0KICAgICAgcmV0dXJuIHdyYXA7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5nc1BsYW4oKSB7CiAgICAgIGNvbnN0IHBhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi1wYW5lbCIpOwogICAgICBpZiAoIXBhbmVsIHx8IHBhbmVsLmNsYXNzTGlzdC5jb250YWlucygiaGlkZGVuIikpIHJldHVybjsgLy8gcGFzIG91dmVydCA6IHBhcyBsYSBwZWluZSBkZSByZWNhbGN1bGVyCgogICAgICAvLyAtLS0gQ2F0w6lnb3JpZXMgZGUgZMOpcGVuc2VzIChtb3llbm5lIG1lbnN1ZWxsZSBzdXIgbCdoaXN0b3JpcXVlKSAtLS0KICAgICAgY29uc3QgY2F0TGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi1jYXRlZ29yaWVzLWxpc3QiKTsKICAgICAgY29uc3QgY2F0RW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXBsYW4tY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCBjYXRlZ29yeVRyZW5kcyA9IGNvbXB1dGVDYXRlZ29yeVRyZW5kcyhhbGxUcmFuc2FjdGlvbnMpLmZpbHRlcigodCkgPT4gdC5hdmVyYWdlID4gMC41KTsKICAgICAgY2F0TGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBjYXRFbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSBjYXRlZ29yeVRyZW5kcy5sZW5ndGggPyAibm9uZSIgOiAiYmxvY2siOwoKICAgICAgbGV0IHBvdGVudGlhbFNhdmluZ3MgPSAwOwoKICAgICAgZm9yIChjb25zdCB0IG9mIGNhdGVnb3J5VHJlbmRzKSB7CiAgICAgICAgY29uc3QgcmF0aW5nID0gY2F0ZWdvcnlSYXRpbmdzW3QuY2F0ZWdvcnldIHx8IG51bGw7CiAgICAgICAgY29uc3QgcmVkdWN0aW9uID0gcmF0aW5nID8gdC5hdmVyYWdlICogKEVTU0VOVElBTElUWV9SRURVQ1RJT05fUENUW3JhdGluZ10gfHwgMCkgOiAwOwogICAgICAgIGlmIChyYXRpbmcpIHBvdGVudGlhbFNhdmluZ3MgKz0gcmVkdWN0aW9uOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1pdGVtIjsKICAgICAgICBjb25zdCBpbmZvID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaW5mby5jbGFzc05hbWUgPSAic2F2aW5ncy1wbGFuLWl0ZW0taW5mbyI7CiAgICAgICAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG5hbWUuY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1pdGVtLW5hbWUiOwogICAgICAgIG5hbWUudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGFtb3VudCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAic2F2aW5ncy1wbGFuLWl0ZW0tYW1vdW50IjsKICAgICAgICBhbW91bnQudGV4dENvbnRlbnQgPSBgfiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuYXZlcmFnZSl9L21vaXNgOwogICAgICAgIGluZm8uYXBwZW5kQ2hpbGQobmFtZSk7CiAgICAgICAgaW5mby5hcHBlbmRDaGlsZChhbW91bnQpOwoKICAgICAgICAvLyBTaW1wbGUgaW5mbywgcGFzIHVuZSByZWxhbmNlIDogZGVwdWlzIGNvbWJpZW4gZGUgdGVtcHMgY2V0dGUgbm90ZQogICAgICAgIC8vIG4nYSBwYXMgYm91Z8OpIChjb25maXJtw6kgcGFyIGwndXRpbGlzYXRldXIgOiDDp2EgcGV1dCByZXN0ZXIgc3RhYmxlCiAgICAgICAgLy8gZGVzIG1vaXMsIGNlIG4nZXN0IHF1J3VuIHJlcMOocmUsIGphbWFpcyB1bmUgbm90aWZpY2F0aW9uIGZvcmPDqWUpLgogICAgICAgIGNvbnN0IG1vbnRocyA9IHJhdGluZyA/IG1vbnRoc1NpbmNlKGNhdGVnb3J5UmF0aW5nVXBkYXRlZEF0W3QuY2F0ZWdvcnldKSA6IG51bGw7CiAgICAgICAgaWYgKG1vbnRocyAhPT0gbnVsbCAmJiBtb250aHMgPj0gMSkgewogICAgICAgICAgY29uc3Qgc3RhbGVuZXNzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBzdGFsZW5lc3MuY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1pdGVtLXN0YWxlbmVzcyI7CiAgICAgICAgICBzdGFsZW5lc3MudGV4dENvbnRlbnQgPSBgTm90w6kgaWwgeSBhICR7bW9udGhzfSBtb2lzYDsKICAgICAgICAgIGluZm8uYXBwZW5kQ2hpbGQoc3RhbGVuZXNzKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IHJhdGluZ0J1dHRvbnMgPSBzYXZpbmdzUGxhblJhdGluZ0J1dHRvbnMocmF0aW5nLCBhc3luYyAobikgPT4gewogICAgICAgICAgY29uc3QgcHJldmlvdXMgPSBjYXRlZ29yeVJhdGluZ3NbdC5jYXRlZ29yeV0gfHwgbnVsbDsKICAgICAgICAgIGNhdGVnb3J5UmF0aW5nc1t0LmNhdGVnb3J5XSA9IG47IC8vIG9wdGltaXN0ZQogICAgICAgICAgY2F0ZWdvcnlSYXRpbmdVcGRhdGVkQXRbdC5jYXRlZ29yeV0gPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7CiAgICAgICAgICByZW5kZXJTYXZpbmdzUGxhbigpOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvY2F0ZWdvcnktcmF0aW5ncyIsIHsKICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgY2F0ZWdvcnk6IHQuY2F0ZWdvcnksIHJhdGluZzogbiB9KSwKICAgICAgICAgICAgfSk7CiAgICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgICAgY2F0ZWdvcnlSYXRpbmdzW3QuY2F0ZWdvcnldID0gcHJldmlvdXM7IC8vIGFubnVsZSBzaSDDp2Egw6ljaG91ZQogICAgICAgICAgICByZW5kZXJTYXZpbmdzUGxhbigpOwogICAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgICAgfQogICAgICAgIH0pOwoKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaW5mbyk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKHJhdGluZ0J1dHRvbnMpOwogICAgICAgIGNhdExpc3RFbC5hcHBlbmRDaGlsZChyb3cpOwoKICAgICAgICAvLyBTdWdnZXN0aW9uIChqYW1haXMgYXV0b21hdGlxdWUpIGQnYWp1c3RlciBsZSBidWRnZXQgZGUgY2V0dGUKICAgICAgICAvLyBjYXTDqWdvcmllIGF1IG1vbnRhbnQgcsOpZHVpdCwgcXVhbmQgdW4gYnVkZ2V0IHBsdXMgw6lsZXbDqSBleGlzdGUKICAgICAgICAvLyBkw6lqw6Ag4oCUIHJlbGllIGxhIG5vdGUgZCdlc3NlbnRpYWxpdMOpIMOgIGwnb3V0aWwgZGUgYnVkZ2V0IGV4aXN0YW50LgogICAgICAgIGlmIChyYXRpbmcgJiYgcmVkdWN0aW9uID4gMC41KSB7CiAgICAgICAgICBjb25zdCBleGlzdGluZ0J1ZGdldCA9IGFsbEJ1ZGdldHMuZmluZCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gdC5jYXRlZ29yeSk7CiAgICAgICAgICBjb25zdCB0YXJnZXRBbW91bnQgPSBNYXRoLm1heCgwLCBNYXRoLnJvdW5kKHQuYXZlcmFnZSAtIHJlZHVjdGlvbikpOwogICAgICAgICAgaWYgKGV4aXN0aW5nQnVkZ2V0ICYmIGV4aXN0aW5nQnVkZ2V0LmFtb3VudCA+IHRhcmdldEFtb3VudCkgewogICAgICAgICAgICBjb25zdCBzdWdnZXN0Um93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICAgIHN1Z2dlc3RSb3cuY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1idWRnZXQtc3VnZ2VzdGlvbiI7CiAgICAgICAgICAgIGNvbnN0IHN1Z2dlc3RCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICAgICAgc3VnZ2VzdEJ0bi50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgICAgIHN1Z2dlc3RCdG4uY2xhc3NOYW1lID0gImxpbmstYnRuIjsKICAgICAgICAgICAgc3VnZ2VzdEJ0bi50ZXh0Q29udGVudCA9CiAgICAgICAgICAgICAgYEFqdXN0ZXIgbGUgYnVkZ2V0IMKrICR7YWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeX0gwrsgw6AgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0QW1vdW50KX0vbW9pc2A7CiAgICAgICAgICAgIHN1Z2dlc3RCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIGF3YWl0IHNhdmVCdWRnZXQodC5jYXRlZ29yeSwgdGFyZ2V0QW1vdW50KTsKICAgICAgICAgICAgICAgIHNob3dUb2FzdCgiQnVkZ2V0IGFqdXN0w6kiKTsKICAgICAgICAgICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckJ1ZGdldHMoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgc3VnZ2VzdFJvdy5hcHBlbmRDaGlsZChzdWdnZXN0QnRuKTsKICAgICAgICAgICAgY2F0TGlzdEVsLmFwcGVuZENoaWxkKHN1Z2dlc3RSb3cpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfQoKICAgICAgLy8gLS0tIENoYXJnZXMgcsOpY3VycmVudGVzIGFjdGl2ZXMgKGTDqXBlbnNlcyB1bmlxdWVtZW50KSAtLS0KICAgICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCByZWNFbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi1yZWN1cnJpbmctZW1wdHkiKTsKICAgICAgY29uc3QgYWN0aXZlUmVjdXJyaW5nRXhwZW5zZXMgPSBhbGxSZWN1cnJpbmcuZmlsdGVyKChyKSA9PiByLnR5cGUgPT09ICJleHBlbnNlIiAmJiByLmFjdGl2ZSAhPT0gZmFsc2UpOwogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5RWwuc3R5bGUuZGlzcGxheSA9IGFjdGl2ZVJlY3VycmluZ0V4cGVuc2VzLmxlbmd0aCA/ICJub25lIiA6ICJibG9jayI7CgogICAgICBmb3IgKGNvbnN0IHIgb2YgYWN0aXZlUmVjdXJyaW5nRXhwZW5zZXMpIHsKICAgICAgICBjb25zdCByYXRpbmcgPSByLmVzc2VudGlhbGl0eV9yYXRpbmcgfHwgbnVsbDsKICAgICAgICBpZiAocmF0aW5nKSBwb3RlbnRpYWxTYXZpbmdzICs9IE51bWJlcihyLmFtb3VudCkgKiAoRVNTRU5USUFMSVRZX1JFRFVDVElPTl9QQ1RbcmF0aW5nXSB8fCAwKTsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJzYXZpbmdzLXBsYW4taXRlbSI7CiAgICAgICAgY29uc3QgaW5mbyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGluZm8uY2xhc3NOYW1lID0gInNhdmluZ3MtcGxhbi1pdGVtLWluZm8iOwogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJzYXZpbmdzLXBsYW4taXRlbS1uYW1lIjsKICAgICAgICBuYW1lLnRleHRDb250ZW50ID0gci5uYW1lOwogICAgICAgIGNvbnN0IGFtb3VudCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAic2F2aW5ncy1wbGFuLWl0ZW0tYW1vdW50IjsKICAgICAgICBhbW91bnQudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoci5hbW91bnQpfS9tb2lzYDsKICAgICAgICBpbmZvLmFwcGVuZENoaWxkKG5hbWUpOwogICAgICAgIGluZm8uYXBwZW5kQ2hpbGQoYW1vdW50KTsKCiAgICAgICAgY29uc3QgcmF0aW5nQnV0dG9ucyA9IHNhdmluZ3NQbGFuUmF0aW5nQnV0dG9ucyhyYXRpbmcsIGFzeW5jIChuKSA9PiB7CiAgICAgICAgICBjb25zdCBwcmV2aW91cyA9IHIuZXNzZW50aWFsaXR5X3JhdGluZyB8fCBudWxsOwogICAgICAgICAgci5lc3NlbnRpYWxpdHlfcmF0aW5nID0gbjsgLy8gb3B0aW1pc3RlCiAgICAgICAgICByZW5kZXJTYXZpbmdzUGxhbigpOwogICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7ci5pZH1gLCB7CiAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGVzc2VudGlhbGl0eV9yYXRpbmc6IG4gfSksCiAgICAgICAgICAgIH0pOwogICAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAgIHIuZXNzZW50aWFsaXR5X3JhdGluZyA9IHByZXZpb3VzOwogICAgICAgICAgICByZW5kZXJTYXZpbmdzUGxhbigpOwogICAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgICAgfQogICAgICAgIH0pOwoKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaW5mbyk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKHJhdGluZ0J1dHRvbnMpOwogICAgICAgIHJlY0xpc3RFbC5hcHBlbmRDaGlsZChyb3cpOwoKICAgICAgICAvLyBDb3Jyw6lsYXRpb24gZmFjdHVlbGxlIDogbGEgY2hhcmdlIEVUIHNhIGNhdMOpZ29yaWUgc29udCB0b3V0ZXMgbGVzCiAgICAgICAgLy8gZGV1eCBub3TDqWVzIHBldSBlc3NlbnRpZWxsZXMgcGFyIGwndXRpbGlzYXRldXIgbHVpLW3Dqm1lLiBPbiBuZSBmYWl0CiAgICAgICAgLy8gcXVlIHJhcHBlbGVyIGNlIHF1J2lsIGEgZGl0LCBzYW5zIMOpbWV0dHJlIGRlIGp1Z2VtZW50IG5pIGRlIGNvbnNlaWwuCiAgICAgICAgY29uc3QgY2F0ZWdvcnlSYXRpbmcgPSByLmNhdGVnb3J5ID8gY2F0ZWdvcnlSYXRpbmdzW3IuY2F0ZWdvcnldIHx8IG51bGwgOiBudWxsOwogICAgICAgIGlmIChyYXRpbmcgJiYgcmF0aW5nIDw9IDIgJiYgY2F0ZWdvcnlSYXRpbmcgJiYgY2F0ZWdvcnlSYXRpbmcgPD0gMikgewogICAgICAgICAgY29uc3QgY2F0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tyLmNhdGVnb3J5XSB8fCByLmNhdGVnb3J5OwogICAgICAgICAgY29uc3Qgbm90ZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgbm90ZS5jbGFzc05hbWUgPSAic2F2aW5ncy1wbGFuLWNvcnJlbGF0aW9uLW5vdGUiOwogICAgICAgICAgbm90ZS50ZXh0Q29udGVudCA9CiAgICAgICAgICAgIGDwn5KhIFR1IGFzIG5vdMOpIMKrICR7Y2F0TGFiZWx9IMK7IHBldSBlc3NlbnRpZWxsZSwgZXQgwqsgJHtyLm5hbWV9IMK7IGF1c3NpIOKAlCBgICsKICAgICAgICAgICAgYGFycsOqdGVyIGNldHRlIGNoYXJnZSBsaWLDqXJlcmFpdCAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChyLmFtb3VudCl9L21vaXMuYDsKICAgICAgICAgIHJlY0xpc3RFbC5hcHBlbmRDaGlsZChub3RlKTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIC8vIC0tLSBSw6lzdW3DqSA6IMOpY29ub21pZSBwb3RlbnRpZWxsZSArIGxpZW4gdmVycyBsZSBzaW11bGF0ZXVyIC0tLQogICAgICBjb25zdCBjdXJyZW50R29hbCA9IHNhdmluZ3NHb2FsID8gTnVtYmVyKHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KSA6IDA7CiAgICAgIGNvbnN0IGNvbWJpbmVkVG90YWwgPSBjdXJyZW50R29hbCArIHBvdGVudGlhbFNhdmluZ3M7CiAgICAgIGNvbnN0IHN1bW1hcnlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXBsYW4tc3VtbWFyeSIpOwogICAgICBzdW1tYXJ5RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGNvbnN0IHN1bW1hcnlUZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGlmIChwb3RlbnRpYWxTYXZpbmdzID4gMC41KSB7CiAgICAgICAgc3VtbWFyeVRleHQuaW5uZXJIVE1MID0KICAgICAgICAgIGDDiWNvbm9taWUgcG90ZW50aWVsbGUgZXN0aW3DqWUgOiA8c3Ryb25nPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBvdGVudGlhbFNhdmluZ3MpfS9tb2lzPC9zdHJvbmc+IGAgKwogICAgICAgICAgYGVuIHBsdXMgZGUgdG9uIMOpcGFyZ25lIGFjdHVlbGxlICgke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdXJyZW50R29hbCl9L21vaXMpID0gYCArCiAgICAgICAgICBgPHN0cm9uZz4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjb21iaW5lZFRvdGFsKX0vbW9pczwvc3Ryb25nPiBhdSB0b3RhbC5gOwogICAgICB9IGVsc2UgewogICAgICAgIHN1bW1hcnlUZXh0LnRleHRDb250ZW50ID0gIk5vdGUgdGVzIGTDqXBlbnNlcyBjaS1kZXNzdXMgcG91ciB2b2lyIGwnw6ljb25vbWllIHBvdGVudGllbGxlIGVzdGltw6llLiI7CiAgICAgIH0KICAgICAgc3VtbWFyeUVsLmFwcGVuZENoaWxkKHN1bW1hcnlUZXh0KTsKCiAgICAgIGlmIChwb3RlbnRpYWxTYXZpbmdzID4gMC41KSB7CiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gInByaW1hcnkiOwogICAgICAgIGFwcGx5QnRuLnN0eWxlLndpZHRoID0gIjEwMCUiOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gIlV0aWxpc2VyIGNlIG1vbnRhbnQgZGFucyBsYSBzaW11bGF0aW9uIGRlIHBsYWNlbWVudCI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LW1vbnRobHkiKS52YWx1ZSA9IE1hdGgucm91bmQoY29tYmluZWRUb3RhbCk7CiAgICAgICAgICBwbGFjZW1lbnRNb250aGx5QXV0b0ZpbGxlZCA9IGZhbHNlOwogICAgICAgICAgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbigpOwogICAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LXBsYWNlbWVudCIpLnNjcm9sbEludG9WaWV3KHsgYmVoYXZpb3I6ICJzbW9vdGgiLCBibG9jazogImNlbnRlciIgfSk7CiAgICAgICAgfSk7CiAgICAgICAgc3VtbWFyeUVsLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfQogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXBsYW4tdG9nZ2xlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBjb25zdCBwYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXBsYW4tcGFuZWwiKTsKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi10b2dnbGUtYnRuIik7CiAgICAgIGNvbnN0IG5vd0hpZGRlbiA9ICFwYW5lbC5jbGFzc0xpc3QuY29udGFpbnMoImhpZGRlbiIpOwogICAgICBwYW5lbC5jbGFzc0xpc3QudG9nZ2xlKCJoaWRkZW4iLCBub3dIaWRkZW4pOwogICAgICBidG4udGV4dENvbnRlbnQgPSBub3dIaWRkZW4gPyAiT3V2cmlyIGxlIHBsYW4gZCfDqXBhcmduZSIgOiAiRmVybWVyIGxlIHBsYW4gZCfDqXBhcmduZSI7CiAgICAgIGlmICghbm93SGlkZGVuKSByZW5kZXJTYXZpbmdzUGxhbigpOwogICAgfSk7CgogICAgLy8gQ29uc2VpbHMgOiBjcm9pc2UgZMOpcGFzc2VtZW50cyBkZSBidWRnZXQgKG9uZ2xldCBUYWJsZWF1IGRlIGJvcmQpIGV0CiAgICAvLyB0ZW5kYW5jZXMgcGFyIGNhdMOpZ29yaWUgcG91ciBwb2ludGVyIHZlcnMgY2UgcXVpIGFpZGUgbGUgcGx1cyDDoAogICAgLy8gYXR0ZWluZHJlIGwnb2JqZWN0aWYg4oCUIHBhcyB1bmUgSUEsIGp1c3RlIGRlcyByw6hnbGVzIHNpbXBsZXMgc3VyIGRlcwogICAgLy8gZG9ubsOpZXMgZMOpasOgIGNhbGN1bMOpZXMgYWlsbGV1cnMgZGFucyBsJ2FwcC4KICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCkgewogICAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtbGlzdCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtYWR2aWNlLWVtcHR5Iik7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgY29uc3QgYWR2aWNlID0gW107CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFsczogbW9udGhUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBjdXJyZW50TW9udGhLZXkpOwogICAgICBjb25zdCB0cmVuZHMgPSBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgY29uc3QgdHJlbmRCeUNhdGVnb3J5ID0gT2JqZWN0LmZyb21FbnRyaWVzKHRyZW5kcy5tYXAoKHQpID0+IFt0LmNhdGVnb3J5LCB0XSkpOwoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCwgdHJpw6llcyBwYXIgbW9udGFudCBkZQogICAgICAvLyBkw6lwYXNzZW1lbnQgZMOpY3JvaXNzYW50IOKAlCBjZSBzb250IGxlcyBsZXZpZXJzIGxlcyBwbHVzIHV0aWxlcy4gQ2VsbGVzCiAgICAgIC8vIHF1ZSBsJ3V0aWxpc2F0ZXVyIGEgTFVJLU3Dik1FIG5vdMOpZXMgcGV1IGVzc2VudGllbGxlcyBkYW5zIGxlIFBsYW4KICAgICAgLy8gZCfDqXBhcmduZSBwYXNzZW50IGVuIHByZW1pZXIgOiBjJ2VzdCBsZSBsZXZpZXIgbGUgcGx1cyBwZXJ0aW5lbnQKICAgICAgLy8gKGTDqXBhc3NlbWVudCArIHNhIHByb3ByZSBub3RlKSwgcGFzIHVuIGp1Z2VtZW50IGRlIGwnSUEg4oCUIGp1c3RlIHVuZQogICAgICAvLyBjb3Jyw6lsYXRpb24gZW50cmUgZGV1eCBjaG9zZXMgcXUnb24gc2FpdCBkw6lqw6Agc3VyIHNlcyBkb25uw6llcy4KICAgICAgY29uc3Qgb3ZlckJ1ZGdldCA9IFtdOwogICAgICBmb3IgKGNvbnN0IGJ1ZGdldCBvZiBhbGxCdWRnZXRzKSB7CiAgICAgICAgY29uc3Qgc3BlbnQgPSBtb250aFRvdGFsc1tidWRnZXQuY2F0ZWdvcnldIHx8IDA7CiAgICAgICAgaWYgKHNwZW50ID4gYnVkZ2V0LmFtb3VudCkgewogICAgICAgICAgY29uc3QgcmF0aW5nID0gY2F0ZWdvcnlSYXRpbmdzW2J1ZGdldC5jYXRlZ29yeV0gfHwgbnVsbDsKICAgICAgICAgIG92ZXJCdWRnZXQucHVzaCh7CiAgICAgICAgICAgIGNhdGVnb3J5OiBidWRnZXQuY2F0ZWdvcnksCiAgICAgICAgICAgIHNwZW50LAogICAgICAgICAgICBidWRnZXQ6IGJ1ZGdldC5hbW91bnQsCiAgICAgICAgICAgIG92ZXI6IHNwZW50IC0gYnVkZ2V0LmFtb3VudCwKICAgICAgICAgICAgbG93RXNzZW50aWFsaXR5OiByYXRpbmcgIT09IG51bGwgJiYgcmF0aW5nIDw9IDIsCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgb3ZlckJ1ZGdldC5zb3J0KChhLCBiKSA9PiB7CiAgICAgICAgaWYgKGEubG93RXNzZW50aWFsaXR5ICE9PSBiLmxvd0Vzc2VudGlhbGl0eSkgcmV0dXJuIGEubG93RXNzZW50aWFsaXR5ID8gLTEgOiAxOwogICAgICAgIHJldHVybiBiLm92ZXIgLSBhLm92ZXI7CiAgICAgIH0pOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIG92ZXJCdWRnZXQuc2xpY2UoMCwgMykpIHsKICAgICAgICBjb25zdCBsYWJlbCA9IGVzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeSk7CiAgICAgICAgY29uc3QgdHJlbmQgPSB0cmVuZEJ5Q2F0ZWdvcnlbaXRlbS5jYXRlZ29yeV07CiAgICAgICAgbGV0IHRleHQgPSBgVHUgYXMgZMOpcGFzc8OpIHRvbiBidWRnZXQgPHN0cm9uZz4ke2xhYmVsfTwvc3Ryb25nPiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLm92ZXIpfSBjZSBtb2lzLWNpLmA7CiAgICAgICAgaWYgKGl0ZW0ubG93RXNzZW50aWFsaXR5KSB7CiAgICAgICAgICB0ZXh0ICs9IGAgVHUgYXMgdG9pLW3Dqm1lIG5vdMOpIGNldHRlIGNhdMOpZ29yaWUgcGV1IGVzc2VudGllbGxlIGRhbnMgdG9uIFBsYW4gZCfDqXBhcmduZSDigJQgYydlc3Qgc2FucyBkb3V0ZSBsZSBkw6lwYXNzZW1lbnQgbGUgcGx1cyBpbnTDqXJlc3NhbnQgw6AgY29ycmlnZXIuYDsKICAgICAgICB9IGVsc2UgaWYgKHRyZW5kICYmIHRyZW5kLmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdGV4dCArPSBgIExhIHRlbmRhbmNlIGVzdCDDoCBsYSBoYXVzc2UgKCske01hdGgucm91bmQodHJlbmQucmF0aW8gKiAxMDApfSUgdnMgdGEgbW95ZW5uZSkg4oCUIHLDqWR1aXJlIGNlcyBkw6lwZW5zZXMgdCdhaWRlcmFpdCBsZSBwbHVzIMOgIGF0dGVpbmRyZSB0b24gb2JqZWN0aWYuYDsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgdGV4dCArPSBgIEVzc2FpZSBkZSByYW1lbmVyIMOnYSBzb3VzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYnVkZ2V0KX0gbGUgbW9pcyBwcm9jaGFpbi5gOwogICAgICAgIH0KICAgICAgICBhZHZpY2UucHVzaCh7IHR5cGU6ICJ3YXJuaW5nIiwgaWNvbjogaXRlbS5sb3dFc3NlbnRpYWxpdHkgPyAi8J+OryIgOiAi4pqg77iPIiwgdGV4dCB9KTsKICAgICAgfQoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gbmV0dGUgaGF1c3NlIG3Dqm1lIHNhbnMgYnVkZ2V0IGTDqXBhc3PDqSAob3Ugc2FucyBidWRnZXQKICAgICAgLy8gZMOpZmluaSBkdSB0b3V0KSA6IHVuIHNpZ25hbCB1dGlsZSBlbiBzb2kuCiAgICAgIGNvbnN0IHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCA9IHRyZW5kcwogICAgICAgIC5maWx0ZXIoKHQpID0+IHQuZGlyZWN0aW9uID09PSAidXAiICYmIHQuYXZlcmFnZSA+IDAgJiYgIW92ZXJCdWRnZXQuc29tZSgobykgPT4gby5jYXRlZ29yeSA9PT0gdC5jYXRlZ29yeSkpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGIucmF0aW8gLSBhLnJhdGlvKQogICAgICAgIC5zbGljZSgwLCAyKTsKICAgICAgZm9yIChjb25zdCB0IG9mIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCkgewogICAgICAgIGNvbnN0IGxhYmVsID0gZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KTsKICAgICAgICBhZHZpY2UucHVzaCh7CiAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICBpY29uOiAi8J+TiCIsCiAgICAgICAgICB0ZXh0OiBgVGVzIGTDqXBlbnNlcyBlbiA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IHNvbnQgZW4gaGF1c3NlIGRlICR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lIHBhciByYXBwb3J0IMOgIHRhIG1veWVubmUg4oCUIMOgIHN1cnZlaWxsZXIgc2kgdHUgdmV1eCDDqXBhcmduZXIgcGx1cy5gLAogICAgICAgIH0pOwogICAgICB9CgogICAgICAvLyBPYmplY3RpZiBhdHRlaW50IC8gZW4gYm9ubmUgdm9pZSBjZSBtb2lzLWNpLgogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgaWYgKG1vbnRoTmV0ID49IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KSB7CiAgICAgICAgICBhZHZpY2UudW5zaGlmdCh7CiAgICAgICAgICAgIHR5cGU6ICJwb3NpdGl2ZSIsCiAgICAgICAgICAgIGljb246ICLwn46JIiwKICAgICAgICAgICAgdGV4dDogYE9iamVjdGlmIGF0dGVpbnQgISBUdSBhcyBkw6lqw6AgbWlzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gZGUgY8O0dMOpIGNlIG1vaXMtY2ksIGF1LWRlbMOgIGRlIHRvbiBvYmplY3RpZiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCl9LmAsCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgaWYgKG92ZXJCdWRnZXQubGVuZ3RoID09PSAwICYmIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydC5sZW5ndGggPT09IDApIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogImluZm8iLAogICAgICAgICAgICBpY29uOiAi8J+RjSIsCiAgICAgICAgICAgIHRleHQ6IGBQYXMgZGUgZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCBjZSBtb2lzLWNpLiBJbCB0ZSByZXN0ZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCAtIG1vbnRoTmV0KX0gw6Agw6ljb25vbWlzZXIgcG91ciBhdHRlaW5kcmUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKGFkdmljZS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWR2aWNlKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gImFkdmljZS1jYXJkICIgKyBpdGVtLnR5cGU7CiAgICAgICAgY29uc3QgaWNvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBpY29uLmNsYXNzTmFtZSA9ICJhZHZpY2UtaWNvbiI7CiAgICAgICAgaWNvbi50ZXh0Q29udGVudCA9IGl0ZW0uaWNvbjsKICAgICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHRleHQuaW5uZXJIVE1MID0gaXRlbS50ZXh0OwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoaWNvbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZCh0ZXh0KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpIHsKICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiLCB7CiAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5LCBhbW91bnQgfSksCiAgICAgIH0pOwogICAgICBjb25zdCBpZHggPSBhbGxCdWRnZXRzLmZpbmRJbmRleCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gY2F0ZWdvcnkpOwogICAgICBpZiAoaWR4ID49IDApIGFsbEJ1ZGdldHNbaWR4XSA9IHVwZGF0ZWQ7CiAgICAgIGVsc2UgYWxsQnVkZ2V0cy5wdXNoKHVwZGF0ZWQpOwogICAgfQoKICAgIGNvbnN0IGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkgPSB7fTsKICAgIGNvbnN0IEJVREdFVF9ISVNUT1JZX01PTlRIUyA9IDY7CgogICAgLy8gTGVzIE4gZGVybmllcnMgbW9pcyAoY2zDqXMgIllZWVktTU0iKSwgZHUgcGx1cyBhbmNpZW4gYXUgcGx1cyByw6ljZW50LAogICAgLy8gZW4gZmluaXNzYW50IHBhciBlbmRNb250aEtleSBpbmNsdXMuCiAgICBmdW5jdGlvbiBsYXN0Tk1vbnRoS2V5cyhuLCBlbmRNb250aEtleSkgewogICAgICBjb25zdCBbeSwgbV0gPSBlbmRNb250aEtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBrZXlzID0gW107CiAgICAgIGZvciAobGV0IGkgPSBuIC0gMTsgaSA+PSAwOyBpLS0pIHsKICAgICAgICBjb25zdCBkID0gbmV3IERhdGUoeSwgbSAtIDEgLSBpLCAxKTsKICAgICAgICBrZXlzLnB1c2goZC5nZXRGdWxsWWVhcigpICsgIi0iICsgU3RyaW5nKGQuZ2V0TW9udGgoKSArIDEpLnBhZFN0YXJ0KDIsICIwIikpOwogICAgICB9CiAgICAgIHJldHVybiBrZXlzOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1saXN0Iik7CiAgICAgIGlmICghd3JhcCkgcmV0dXJuOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CgogICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KSkgZGVsZXRlIGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnlba2V5XTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UpIHsKICAgICAgICBjb25zdCBidWRnZXQgPSBhbGxCdWRnZXRzLmZpbmQoKGIpID0+IGIuY2F0ZWdvcnkgPT09IHZhbHVlKTsKICAgICAgICBjb25zdCBzcGVudCA9IHRvdGFsc1t2YWx1ZV0gfHwgMDsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJidWRnZXQtcm93IjsKCiAgICAgICAgY29uc3QgaGVhZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGhlYWQuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ctaGVhZCI7CgogICAgICAgIGNvbnN0IG5hbWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIG5hbWVTcGFuLmNsYXNzTmFtZSA9ICJidWRnZXQtY2F0LW5hbWUiOwogICAgICAgIG5hbWVTcGFuLnRleHRDb250ZW50ID0gbGFiZWw7CgogICAgICAgIGNvbnN0IGFtb3VudHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50cy5jbGFzc05hbWUgPSAiYnVkZ2V0LWFtb3VudHMiOwogICAgICAgIGNvbnN0IHNwZW50U3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBzcGVudFNwYW4udGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc3BlbnQpICsgIiAvICI7CiAgICAgICAgY29uc3QgaW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGlucHV0LnR5cGUgPSAibnVtYmVyIjsKICAgICAgICBpbnB1dC5jbGFzc05hbWUgPSAiYnVkZ2V0LWlucHV0IjsKICAgICAgICBpbnB1dC5taW4gPSAiMCI7CiAgICAgICAgaW5wdXQuc3RlcCA9ICIxIjsKICAgICAgICBpbnB1dC5wbGFjZWhvbGRlciA9ICLigJQiOwogICAgICAgIGlmIChidWRnZXQpIGlucHV0LnZhbHVlID0gYnVkZ2V0LmFtb3VudDsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKHNwZW50U3Bhbik7CiAgICAgICAgYW1vdW50cy5hcHBlbmRDaGlsZChpbnB1dCk7CiAgICAgICAgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVt2YWx1ZV0gPSBpbnB1dDsKCiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChhbW91bnRzKTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaGVhZCk7CgogICAgICAgIGlmIChidWRnZXQpIHsKICAgICAgICAgIGNvbnN0IHRyYWNrID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICB0cmFjay5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci10cmFjayI7CiAgICAgICAgICBjb25zdCBmaWxsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjb25zdCByYXRpbyA9IHNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWluKHJhdGlvICogMTAwLCAxMDApOwogICAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgICBpZiAocmF0aW8gPj0gMSkgY2xzID0gIm92ZXIiOwogICAgICAgICAgZWxzZSBpZiAocmF0aW8gPj0gMC43KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgICBmaWxsLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICAgIGZpbGwuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgICAgICB0cmFjay5hcHBlbmRDaGlsZChmaWxsKTsKICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZCh0cmFjayk7CgogICAgICAgICAgY29uc3Qgc3RyaXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHN0cmlwLmNsYXNzTmFtZSA9ICJidWRnZXQtaGlzdG9yeS1zdHJpcCI7CiAgICAgICAgICBmb3IgKGNvbnN0IGhpc3RLZXkgb2YgbGFzdE5Nb250aEtleXMoQlVER0VUX0hJU1RPUllfTU9OVEhTLCBjdXJyZW50TW9udGhLZXkpKSB7CiAgICAgICAgICAgIGNvbnN0IHsgdG90YWxzOiBoaXN0VG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgaGlzdEtleSk7CiAgICAgICAgICAgIGNvbnN0IGhpc3RTcGVudCA9IGhpc3RUb3RhbHNbdmFsdWVdIHx8IDA7CiAgICAgICAgICAgIGNvbnN0IGRvdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgICAgaWYgKGhpc3RTcGVudCA9PT0gMCkgewogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgZW1wdHkiOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgIGNvbnN0IGhpc3RSYXRpbyA9IGhpc3RTcGVudCAvIGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgICAgICAgbGV0IGhpc3RDbHMgPSAib2siOwogICAgICAgICAgICAgIGlmIChoaXN0UmF0aW8gPj0gMSkgaGlzdENscyA9ICJvdmVyIjsKICAgICAgICAgICAgICBlbHNlIGlmIChoaXN0UmF0aW8gPj0gMC43KSBoaXN0Q2xzID0gIndhcm5pbmciOwogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgIiArIGhpc3RDbHM7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgW2h5LCBobV0gPSBoaXN0S2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICAgIGNvbnN0IG1vbnRoTGFiZWwgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShoeSwgaG0gLSAxLCAxKSk7CiAgICAgICAgICAgIGNvbnN0IGRldGFpbFRleHQgPSBgJHttb250aExhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGhpc3RTcGVudCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYnVkZ2V0LmFtb3VudCl9YDsKICAgICAgICAgICAgZG90LnRpdGxlID0gZGV0YWlsVGV4dDsgLy8gYWZmaWNow6kgYXUgc3Vydm9sIHN1ciBvcmRpbmF0ZXVyCiAgICAgICAgICAgIC8vIFN1ciBtb2JpbGUgaWwgbid5IGEgcGFzIGRlIHN1cnZvbCA6IHVuIHRhcCBzdXIgbGEgYmFycmUgbW9udHJlCiAgICAgICAgICAgIC8vIGxlIG3Dqm1lIGTDqXRhaWwgZGFucyB1biB0b2FzdC4KICAgICAgICAgICAgZG90LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd1RvYXN0KGRldGFpbFRleHQpKTsKICAgICAgICAgICAgc3RyaXAuYXBwZW5kQ2hpbGQoZG90KTsKICAgICAgICAgIH0KICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZChzdHJpcCk7CiAgICAgICAgfQoKICAgICAgICB3cmFwLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIik7CiAgICAgICAgZm9yIChjb25zdCB7IHR5cGUsIHZhbHVlLCBsYWJlbCB9IG9mIGl0ZW1zKSB7CiAgICAgICAgICBpZiAoY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSAmJiAhY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHZhbHVlKSkgewogICAgICAgICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICAgICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGVzIGNhdMOpZ29yaWVzIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBrZXlzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIik7CiAgICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMgPSBuZXcgU2V0KGtleXMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIHVuZSBzdWdnZXN0aW9uIGTDqWrDoCB2dWUgcsOpYXBwYXJhw650IHVuZSBmb2lzLgogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2x1Z2lmeUNhdGVnb3J5KGxhYmVsKSB7CiAgICAgIHJldHVybiAoCiAgICAgICAgbGFiZWwKICAgICAgICAgIC5ub3JtYWxpemUoIk5GRCIpLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpIC8vIGVubMOodmUgbGVzIGFjY2VudHMKICAgICAgICAgIC50b0xvd2VyQ2FzZSgpCiAgICAgICAgICAudHJpbSgpCiAgICAgICAgICAucmVwbGFjZSgvW15hLXowLTldKy9nLCAiXyIpCiAgICAgICAgICAucmVwbGFjZSgvXl8rfF8rJC9nLCAiIikgfHwgImF1dHJlIgogICAgICApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVDdXN0b21DYXRlZ29yeSh0eXBlLCB2YWx1ZSwgbGFiZWwpIHsKICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkNhdMOpZ29yaWUgY3LDqcOpZSBpY2ksIG1haXMgcGFzIHNhdXZlZ2FyZMOpZSBzdXIgbGUgc2VydmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBjdXJyZW5jeUZvcm1hdHRlciA9IG5ldyBJbnRsLk51bWJlckZvcm1hdCgiZnItRlIiLCB7IHN0eWxlOiAiY3VycmVuY3kiLCBjdXJyZW5jeTogIkVVUiIgfSk7CiAgICBjb25zdCBkYXRlRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBkYXk6ICJudW1lcmljIiwgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKCiAgICAvLyDDiWNoYXBwZSB1bmUgdmFsZXVyIGF2YW50IGRlIGwnaW5zw6lyZXIgZGFucyB1biB0ZW1wbGF0ZSBIVE1MIGNvbnN0cnVpdAogICAgLy8gw6AgbGEgbWFpbiAoaW5uZXJIVE1MKSA6IG7DqWNlc3NhaXJlIHBhcnRvdXQgb8O5IHVuZSBkb25uw6llIHNhaXNpZSBwYXIKICAgIC8vIGwndXRpbGlzYXRldXIgcGV1dCBzJ3kgcmV0cm91dmVyIOKAlCBlbiBwYXJ0aWN1bGllciBsZSBsaWJlbGzDqSBkJ3VuZQogICAgLy8gY2F0w6lnb3JpZSBwZXJzb25uYWxpc8OpZSAodGV4dGUgbGlicmUsIGVucmVnaXN0csOpIGVuIGJhc2UpLCBwb3VyIMOpdml0ZXIKICAgIC8vIHF1J3VuIGxpYmVsbMOpIGR1IGdlbnJlIDxpbWcgc3JjPXggb25lcnJvcj0uLi4+IG5lIHMnZXjDqWN1dGUgY29tbWUgZHUKICAgIC8vIEhUTUwvSlMgYXUgbGlldSBkZSBzJ2FmZmljaGVyIGNvbW1lIGR1IHRleHRlIChpbmplY3Rpb24gWFNTIHN0b2Nrw6llKS4KICAgIGZ1bmN0aW9uIGVzY2FwZUh0bWwoc3RyKSB7CiAgICAgIHJldHVybiBTdHJpbmcoc3RyKS5yZXBsYWNlKC9bJjw+IiddL2csIChjaCkgPT4gKHsKICAgICAgICAiJiI6ICImYW1wOyIsICI8IjogIiZsdDsiLCAiPiI6ICImZ3Q7IiwgJyInOiAiJnF1b3Q7IiwgIiciOiAiJiMzOTsiLAogICAgICB9W2NoXSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gNDAxKSB7CiAgICAgICAgLy8gSmV0b24gYWJzZW50LCBpbnZhbGlkZSBvdSBleHBpcsOpIDogcmV0b3VyIMOgIGwnw6ljcmFuIGRlIHZlcnJvdWlsbGFnZQogICAgICAgIC8vIHBsdXTDtHQgcXVlIGQnYWZmaWNoZXIgdW5lIGVycmV1ciB0ZWNobmlxdWUgaW5jb21wcsOpaGVuc2libGUuCiAgICAgICAgc2hvd0xvY2tTY3JlZW4oKTsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoIlNlc3Npb24gZXhwaXLDqWUsIHJlY29ubmVjdGUtdG9pLiIpOwogICAgICB9CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgLy8gcmVzLnN0YXR1c1RleHQgZXN0IHNvdXZlbnQgdmlkZSAobmF2aWdhdGV1cnMgZW4gSFRUUC8yLCB1dGlsaXPDqSBwYXIKICAgICAgICAvLyBWZXJjZWwpLCBkb25jIG9uIG5lIHBldXQgcGFzIGNvbXB0ZXIgZGVzc3VzIGNvbW1lIG1lc3NhZ2UgcGFyCiAgICAgICAgLy8gZMOpZmF1dCA6IG9uIHJldG9tYmUgc3VyIGxlIGNvZGUgSFRUUCBwb3VyIG5lIGphbWFpcyBhZmZpY2hlciB1bgogICAgICAgIC8vIG1lc3NhZ2UgZCdlcnJldXIgdmlkZS4KICAgICAgICBsZXQgZGV0YWlsID0gcmVzLnN0YXR1c1RleHQgfHwgYEVycmV1ciBIVFRQICR7cmVzLnN0YXR1c31gOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGV4dHJhY3RFcnJvckRldGFpbChkYXRhLCBkZXRhaWwpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICB9CgogICAgY2F0ZWdvcnlJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LmNsYXNzTGlzdC50b2dnbGUoImhpZGRlbiIsIGNhdGVnb3J5SW5wdXQudmFsdWUgIT09ICJfX25ld19fIik7CiAgICAgIGlmIChjYXRlZ29yeUlucHV0LnZhbHVlID09PSAiX19uZXdfXyIpIG5ld0NhdGVnb3J5TmFtZUlucHV0LmZvY3VzKCk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IGlzRWRpdCA/IHR4LmNhdGVnb3J5IDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwoKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgaWYgKGlzRWRpdCAmJiB0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICBsb2FkRXhpc3RpbmdSZWNlaXB0UHJldmlldyh0eC5pZCk7CiAgICAgIH0KCiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkgewogICAgICAvLyBNw6ptZSBtb250YW50L2NhdMOpZ29yaWUvZGVzY3JpcHRpb24sIG1haXMgZGF0w6kgZCdhdWpvdXJkJ2h1aSBldCBzYW5zCiAgICAgIC8vIGlkIDogbGEgc2F1dmVnYXJkZSBjcsOpZXJhIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiAodm9pciBvcGVuTW9kYWwpLgogICAgICBvcGVuTW9kYWwoeyAuLi50eCwgaWQ6IG51bGwsIGV4cGVuc2VfZGF0ZTogdG9kYXlJc28oKSB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICAgIGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5ID0gbnVsbDsKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICAvLyAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIiBzw6lsZWN0aW9ubsOpIDogb24gbGEgY3LDqWUgKHNpIGVsbGUgbidleGlzdGUKICAgICAgLy8gcGFzIGTDqWrDoCBzb3VzIGNlIG5vbSkgYXZhbnQgZCdlbnJlZ2lzdHJlciBsYSB0cmFuc2FjdGlvbiBhdmVjLgogICAgICBsZXQgY2F0ZWdvcnlWYWx1ZSA9IGNhdGVnb3J5SW5wdXQudmFsdWU7CiAgICAgIGlmIChjYXRlZ29yeVZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICBjb25zdCBuYW1lID0gbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgIGlmICghbmFtZSkgewogICAgICAgICAgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIsIHRydWUpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBjYXRlZ29yeVZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtjdXJyZW50VHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSBjYXRlZ29yeVZhbHVlKSkgewogICAgICAgICAgYXdhaXQgc2F2ZUN1c3RvbUNhdGVnb3J5KGN1cnJlbnRUeXBlLCBjYXRlZ29yeVZhbHVlLCBuYW1lKTsKICAgICAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgY2F0ZWdvcnlWYWx1ZSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlWYWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgY29uc3QgcHJldmlvdXNDYXRlZ29yeSA9IGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5OwogICAgICAgICAgY29uc3QgZWRpdGVkSWQgPSBlZGl0aW5nSWQ7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CgogICAgICAgICAgLy8gU2kgbGEgY2F0w6lnb3JpZSB2aWVudCBkZSBjaGFuZ2VyIG1hbnVlbGxlbWVudCwgb24gcHJvcG9zZSBkZQogICAgICAgICAgLy8gcmVwb3J0ZXIgbGUgbcOqbWUgY2hhbmdlbWVudCBzdXIgbGVzIGF1dHJlcyB0cmFuc2FjdGlvbnMgZG9udCBsYQogICAgICAgICAgLy8gZGVzY3JpcHRpb24gcGFydGFnZSB1biBtb3QtY2zDqSBzaWduaWZpY2F0aWYgKGV4LiAiY2FzaW5vIiAvCiAgICAgICAgICAvLyAiYXUgY2FzaW5vIiAvICJwZXJ0ZSBhdSBjYXNpbm8iKSBldCBxdWkgw6l0YWllbnQgZGFucyBsJ2FuY2llbm5lCiAgICAgICAgICAvLyBjYXTDqWdvcmllIOKAlCBqYW1haXMgYXV0b21hdGlxdWUsIHRvdWpvdXJzIHN1ciBjb25maXJtYXRpb24uCiAgICAgICAgICBpZiAocHJldmlvdXNDYXRlZ29yeSAmJiBwYXlsb2FkLmNhdGVnb3J5ICE9PSBwcmV2aW91c0NhdGVnb3J5ICYmIHBheWxvYWQuZGVzY3JpcHRpb24pIHsKICAgICAgICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhwYXlsb2FkLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgaWYgKGtleXdvcmRzLnNpemUgPiAwKSB7CiAgICAgICAgICAgICAgY29uc3Qgc2ltaWxhciA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgICAgICAgICAodCkgPT4KICAgICAgICAgICAgICAgICAgdC5pZCAhPT0gZWRpdGVkSWQgJiYKICAgICAgICAgICAgICAgICAgdC50eXBlID09PSBwYXlsb2FkLnR5cGUgJiYKICAgICAgICAgICAgICAgICAgdC5jYXRlZ29yeSA9PT0gcHJldmlvdXNDYXRlZ29yeSAmJgogICAgICAgICAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModC5kZXNjcmlwdGlvbikpCiAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgICBpZiAoc2ltaWxhci5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICBjb25zdCBuZXdMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BheWxvYWQuY2F0ZWdvcnldIHx8IHBheWxvYWQuY2F0ZWdvcnk7CiAgICAgICAgICAgICAgICBjb25zdCBleGFtcGxlRGVzYyA9IHNpbWlsYXJbMF0uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICAgICAgICAgICAgYEFwcGxpcXVlciBhdXNzaSBsYSBjYXTDqWdvcmllICIke25ld0xhYmVsfSIgYXV4ICR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIGAgKwogICAgICAgICAgICAgICAgICBgc2ltaWxhaXJlKHMpIChleC4gIiR7ZXhhbXBsZURlc2N9IikgP2AKICAgICAgICAgICAgICAgICk7CiAgICAgICAgICAgICAgICBpZiAoY29uZmlybWVkKSB7CiAgICAgICAgICAgICAgICAgIGZvciAoY29uc3QgdCBvZiBzaW1pbGFyKSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgZml4UGF5bG9hZCA9IHsgY2F0ZWdvcnk6IHBheWxvYWQuY2F0ZWdvcnkgfTsKICAgICAgICAgICAgICAgICAgICAvLyBDb21tZSBwb3VyIGxhIGJhbm5pw6hyZSBkZSBzdWdnZXN0aW9uIDogbGEgY2F0w6lnb3JpZQogICAgICAgICAgICAgICAgICAgIC8vIHBvcnRlIG1haW50ZW5hbnQgbCdpbmZvLCBvbiByZXRpcmUgbGUgbW90LWNsw6kgZGV2ZW51CiAgICAgICAgICAgICAgICAgICAgLy8gcmVkb25kYW50IGRlIGxhIGRlc2NyaXB0aW9uIGRlIENFUyB0cmFuc2FjdGlvbnMtbMOgCiAgICAgICAgICAgICAgICAgICAgLy8gKHBhcyBjZWxsZSBxdSdvbiB2aWVudCBkJ8OpZGl0ZXIgw6AgbGEgbWFpbikuCiAgICAgICAgICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKHQuZGVzY3JpcHRpb24sIGtleXdvcmRzKTsKICAgICAgICAgICAgICAgICAgICBpZiAoY2xlYW5lZCAhPT0gKHQuZGVzY3JpcHRpb24gfHwgbnVsbCkpIGZpeFBheWxvYWQuZGVzY3JpcHRpb24gPSBjbGVhbmVkOwogICAgICAgICAgICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3QuaWR9YCwgewogICAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGZpeFBheWxvYWQpLAogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgIHNob3dUb2FzdChgJHtzaW1pbGFyLmxlbmd0aH0gYXV0cmUocykgdHJhbnNhY3Rpb24ocykgbWlzZShzKSDDoCBqb3VyYCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgICBpZiAocGVuZGluZ1JlY2VpcHRGaWxlKSB7CiAgICAgICAgICAgIC8vIExhIHBob3RvIGEgw6l0w6kgY2hvaXNpZSBhdmFudCBxdWUgbGEgdHJhbnNhY3Rpb24gbidleGlzdGUgOiBvbgogICAgICAgICAgICAvLyBsJ2Vudm9pZSBtYWludGVuYW50IHF1J29uIGEgdW4gaWQuCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBwZW5kaW5nUmVjZWlwdEZpbGUpOwogICAgICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2NyZWF0ZWQuaWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICAgICAgYm9keTogZm9ybURhdGEsCiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIGNyw6nDqWUsIG1haXMgbCdlbnZvaSBkZSBsYSBwaG90byBhIMOpY2hvdcOpIiwgdHJ1ZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YXV4IGdsb2JhdXggKFNvbGRlL0TDqXBlbnNlcy9SZXZlbnVzKSA6IGNhbGN1bMOpcyBzdXIgVE9VVEVTIGxlcwogICAgLy8gdHJhbnNhY3Rpb25zLCBpbmTDqXBlbmRhbW1lbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlIOKAlCB1biBmaWx0cmUKICAgIC8vIHNlcnQgw6AgY2hlcmNoZXIgZGFucyBsYSBsaXN0ZSwgcGFzIMOgIHJlY2FsY3VsZXIgbGUgc29sZGUgcsOpZWwuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKSB7CiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgLy8gQ29uc3RydWN0aW9uIGRlIGxhIGxpc3RlIGRlIGNhcnRlcyBhZmZpY2jDqWUgZGFucyBsJ29uZ2xldCBIaXN0b3JpcXVlIOKAlAogICAgLy8gcmXDp29pdCBkw6lqw6AgbGEgbGlzdGUgZmlsdHLDqWUgKHZvaXIgYXBwbHlIaXN0b3J5RmlsdGVycykuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbkxpc3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgaWYgKHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnRleHRDb250ZW50ID0gYWxsVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMAogICAgICAgICAgPyAiUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4iCiAgICAgICAgICA6ICJBdWN1biByw6lzdWx0YXQgcG91ciBjZXMgZmlsdHJlcy4iOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJ0eC1jYXJkICIgKyB0eC50eXBlOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAidHgtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAidHgtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRhdGVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGRhdGVTcGFuLmNsYXNzTmFtZSA9ICJ0eC1kYXRlIjsKICAgICAgICBkYXRlU3Bhbi50ZXh0Q29udGVudCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHR4LmV4cGVuc2VfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZGF0ZVNwYW4pOwogICAgICAgIGlmICh0eC5yZWN1cnJpbmdfZXhwZW5zZV9pZCkgewogICAgICAgICAgY29uc3QgcmVjQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICByZWNCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjdXJyaW5nLWJhZGdlIjsKICAgICAgICAgIHJlY0JhZGdlLnRleHRDb250ZW50ID0gIvCflIEiOwogICAgICAgICAgcmVjQmFkZ2UudGl0bGUgPSAiQ3LDqcOpZSBhdXRvbWF0aXF1ZW1lbnQgZGVwdWlzIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY0JhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgICAgY29uc3QgcmVjZWlwdEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudHlwZSA9ICJidXR0b24iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWNlaXB0LWJhZGdlIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50ZXh0Q29udGVudCA9ICLwn6e+IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50aXRsZSA9ICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiVm9pciBsYSBwaG90byBkdSByZcOndSIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY2VpcHRMaWdodGJveCh0eC5pZCkpOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY2VpcHRCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWhpc3RvcnkiKS5zdHlsZS5kaXNwbGF5ID0gdmlldyA9PT0gImhpc3RvcnkiID8gImJsb2NrIiA6ICJub25lIjsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBpZiAodmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICBpZiAodmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIGNsb3NlTmF2RHJhd2VyKCk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJzYXZpbmdzIikpOwoKICAgIC8vIE1lbnUgImJ1cmdlciIgKG1vYmlsZSB1bmlxdWVtZW50LCB2b2lyIGxlIENTUyBAbWVkaWEgYXNzb2Npw6kpIDogbGEKICAgIC8vIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIHN1cgogICAgLy8gcGx1c2lldXJzIGxpZ25lcy4gRmVybcOpIGF1dG9tYXRpcXVlbWVudCBkw6hzIHF1J3VuIG9uZ2xldCBlc3QgY2hvaXNpCiAgICAvLyAodm9pciBzd2l0Y2hWaWV3IGNpLWRlc3N1cykgb3UgZW4gdG91Y2hhbnQgbGUgZm9uZCBhc3NvbWJyaS4KICAgIGZ1bmN0aW9uIGNsb3NlTmF2RHJhd2VyKCkgewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC5yZW1vdmUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1lbnUtdG9nZ2xlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC50b2dnbGUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibmF2LWRyYXdlci1iYWNrZHJvcCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VOYXZEcmF3ZXIpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDaGFyZ2VtZW50IGRlIENoYXJ0LmpzIDogbGEgYmlibGlvdGjDqHF1ZSB2aWVudCBkJ3VuIENETiBleHRlcm5lICh2b2lyCiAgICAvLyBsYSBiYWxpc2UgPHNjcmlwdD4gZW4gaGF1dCBkZSBwYWdlKS4gU2kgY2UgY2hhcmdlbWVudCByYXRlIChjb3VwdXJlCiAgICAvLyByw6lzZWF1LCBDRE4gbW9tZW50YW7DqW1lbnQgaW5qb2lnbmFibGUuLi4pLCBgQ2hhcnRgIG4nZXhpc3RlIHBhcyBldCB1bgogICAgLy8gYG5ldyBDaGFydCguLi4pYCBsw6h2ZSB1bmUgZXJyZXVyIG5vbiBpbnRlcmNlcHTDqWUg4oCUIHF1aSwgYXZhbnQgY2UKICAgIC8vIGNvcnJlY3RpZiwgaW50ZXJyb21wYWl0IHRvdXQgbGUgcmVzdGUgZHUgcmVuZHUgZHUgdGFibGVhdSBkZSBib3JkIHNhbnMKICAgIC8vIGF1Y3VuIG1lc3NhZ2UsIGxhaXNzYW50IGxlcyBncmFwaGlxdWVzIChldCBwYXJmb2lzIGRlcyBzZWN0aW9ucwogICAgLy8gc3VpdmFudGVzKSB2aWRlcyBpbmTDqWZpbmltZW50LCBtw6ptZSBhcHLDqHMgdW4gcmVjaGFyZ2VtZW50IGRlIGxhIHBhZ2UKICAgIC8vIHNpIGxlIENETiByZXN0YWl0IGluam9pZ25hYmxlLiBgc2FmZUNyZWF0ZUNoYXJ0YCByZW1wbGFjZSBjaGFxdWUgYXBwZWwKICAgIC8vIGRpcmVjdCDDoCBgbmV3IENoYXJ0KC4uLilgIDogc2kgbGEgYmlibGlvdGjDqHF1ZSBtYW5xdWUsIG9uIGFmZmljaGUgdW4KICAgIC8vIG1lc3NhZ2UgY2xhaXIgw6AgbGEgcGxhY2UgZHUgZ3JhcGhpcXVlIGV0IG9uIHRlbnRlIGF1dG9tYXRpcXVlbWVudCB1bgogICAgLy8gc2Vjb25kIGNoYXJnZW1lbnQgZHUgc2NyaXB0LCBwdWlzIG9uIHJlZGVzc2luZSBsYSB2dWUgY291cmFudGUgZMOocwogICAgLy8gcXUnaWwgcsOpdXNzaXQg4oCUIHNhbnMgcXVlIGwndXRpbGlzYXRldXIgYWl0IHF1b2kgcXVlIGNlIHNvaXQgw6AgZmFpcmUuCiAgICBsZXQgY2hhcnRKc1JlbG9hZEF0dGVtcHRlZCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIGlzQ2hhcnRKc1JlYWR5KCkgewogICAgICByZXR1cm4gdHlwZW9mIENoYXJ0ICE9PSAidW5kZWZpbmVkIjsKICAgIH0KCiAgICBmdW5jdGlvbiB0cnlSZWxvYWRDaGFydEpzKCkgewogICAgICBpZiAoY2hhcnRKc1JlbG9hZEF0dGVtcHRlZCkgcmV0dXJuOwogICAgICBjaGFydEpzUmVsb2FkQXR0ZW1wdGVkID0gdHJ1ZTsKICAgICAgY29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7CiAgICAgIHNjcmlwdC5zcmMgPSAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9jaGFydC5qc0A0LjQuNC9kaXN0L2NoYXJ0LnVtZC5taW4uanM/cmV0cnk9IiArIERhdGUubm93KCk7CiAgICAgIHNjcmlwdC5vbmxvYWQgPSAoKSA9PiB7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfTsKICAgICAgc2NyaXB0Lm9uZXJyb3IgPSAoKSA9PiB7CiAgICAgICAgY29uc29sZS5lcnJvcigiQ2hhcnQuanMgOiBsZSBzZWNvbmQgZXNzYWkgZGUgY2hhcmdlbWVudCBhIGF1c3NpIMOpY2hvdcOpLiIpOwogICAgICB9OwogICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHNjcmlwdCk7CiAgICB9CgogICAgZnVuY3Rpb24gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgY29uZmlnLCBlbXB0eUVsLCB1bmF2YWlsYWJsZU1lc3NhZ2UpIHsKICAgICAgaWYgKCFpc0NoYXJ0SnNSZWFkeSgpKSB7CiAgICAgICAgY29uc29sZS5lcnJvcigiQ2hhcnQuanMgbidlc3QgcGFzIGNoYXJnw6kg4oCUIGdyYXBoaXF1ZSBub24gYWZmaWNow6kuIik7CiAgICAgICAgaWYgKGNhbnZhcykgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaWYgKGVtcHR5RWwpIHsKICAgICAgICAgIGVtcHR5RWwudGV4dENvbnRlbnQgPSB1bmF2YWlsYWJsZU1lc3NhZ2UKICAgICAgICAgICAgfHwgIkdyYXBoaXF1ZSBtb21lbnRhbsOpbWVudCBpbmRpc3BvbmlibGUg4oCUIG5vdXZlbGxlIHRlbnRhdGl2ZSBlbiBjb3VycywgcsOpZXNzYWllIGRhbnMgcXVlbHF1ZXMgc2Vjb25kZXMuIjsKICAgICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgfQogICAgICAgIHRyeVJlbG9hZENoYXJ0SnMoKTsKICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQogICAgICB0cnkgewogICAgICAgIHJldHVybiBuZXcgQ2hhcnQoY2FudmFzLCBjb25maWcpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCJFcnJldXIgbG9ycyBkZSBsYSBjcsOpYXRpb24gZHUgZ3JhcGhpcXVlIDoiLCBlcnIpOwogICAgICAgIGlmIChjYW52YXMpIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGlmIChlbXB0eUVsKSB7CiAgICAgICAgICBlbXB0eUVsLnRleHRDb250ZW50ID0gIkVycmV1ciBkJ2FmZmljaGFnZSBkdSBncmFwaGlxdWUg4oCUIGVzc2FpZSBkZSByZWNoYXJnZXIgbGEgcGFnZS4iOwogICAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgIH0KICAgIH0KCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwogICAgbGV0IHllYXJseUNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgLy8gVW5lIGNoYXJnZSByw6ljdXJyZW50ZSBjb21wdGUgcG91ciB1biBtb2lzIGRvbm7DqSBzaSBjZSBtb2lzIGVzdCBkYW5zIHNhCiAgICAvLyBww6lyaW9kZSBkJ2FjdGl2aXTDqSA6IHBhcyBhdmFudCBzYSBkYXRlIGRlIGTDqWJ1dCAoc2kgcG9zw6llKSwgcGFzIGFwcsOocwogICAgLy8gbGUgbW9pcyBkZSBzYSBkYXRlIGRlIGZpbiAoc2kgcG9zw6llKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSB7CiAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUgJiYgbW9udGhLZXkgPCBpdGVtLnN0YXJ0X2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUgJiYgbW9udGhLZXkgPiBpdGVtLmVuZF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIHJldHVybiB0cnVlOwogICAgfQoKICAgIC8vIEpvdXIgZHUgbW9pcyBqdXNxdSdhdXF1ZWwgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBlc3QgY29uc2lkw6lyw6llIGNvbW1lCiAgICAvLyAiZMOpasOgIHByw6lsZXbDqWUiIHBvdXIgbGUgbW9pcyBgbW9udGhLZXlgIDogdG91cyBsZXMgam91cnMgcG91ciB1biBtb2lzCiAgICAvLyBkw6lqw6AgcGFzc8OpLCBhdWN1biBwb3VyIHVuIG1vaXMgZnV0dXIsIGV0IGxlIGpvdXIgZHUgam91ciBwb3VyIGxlIG1vaXMKICAgIC8vIGVuIGNvdXJzLiBQZXJtZXQgZGUgZGlzdGluZ3VlciBjZSBxdWkgZXN0IGTDqWrDoCBhcnJpdsOpIGRlIGNlIHF1aSBlc3QKICAgIC8vIHNldWxlbWVudCBwcsOpdnUgKGV4IDogdW4gYWJvbm5lbWVudCBwcsOpbGV2w6kgbGUgMjUsIG9uIGVzdCBsZSAyKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSkgewogICAgICBpZiAobW9udGhLZXkgPCBjdXJyZW50TW9udGhLZXkpIHJldHVybiAzMTsKICAgICAgaWYgKG1vbnRoS2V5ID4gY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMDsKICAgICAgcmV0dXJuIHRvZGF5RGF5OwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCkgbW9udGhTZXQuYWRkKG1vbnRoS2V5T2YodG9kYXlJc28oKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gIiI7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gIkF1Y3VuZSBkb25uw6llIjsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgc2VsZWN0LnZhbHVlID0gbW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IG1vbnRoc1swXTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCB1cGNvbWluZ05vdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIpOwogICAgICBjb25zdCB1cGNvbWluZ1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCIpOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBjb25zdCBjdXRvZmYgPSByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBVbiBzZXVsIHNvbGRlIG5ldCAiw6AgdmVuaXIiIChyZXZlbnVzIHLDqWN1cnJlbnRzIMOgIHZlbmlyIG1vaW5zIGTDqXBlbnNlcwogICAgICAvLyByw6ljdXJyZW50ZXMgw6AgdmVuaXIpLCBwbHV0w7R0IHF1ZSBkZXV4IGNoaWZmcmVzIHPDqXBhcsOpcyA6IHBsdXMgc2ltcGxlCiAgICAgIC8vIMOgIGxpcmUgZCd1biBjb3VwIGQnxZNpbC4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUgc29udCBQQVMKICAgICAgLy8gYWpvdXTDqWVzIGljaSA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUgdnJhaWVzIHRyYW5zYWN0aW9ucwogICAgICAvLyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzIGRhbnMgYHRvdGFsc2AKICAgICAgLy8gY2ktZGVzc3VzIOKAlCBsZXMgYWpvdXRlciDDoCBub3V2ZWF1IGxlcyBjb21wdGVyYWl0IGVuIGRvdWJsZS4KICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IGN1dG9mZikgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0sIGVtcHR5RWwpOwogICAgfQoKICAgIC8vIE3Dqm1lIHByaW5jaXBlIHF1ZSByZW5kZXJDYXRlZ29yeUNoYXJ0LCBjw7R0w6kgcmV2ZW51cyDigJQgcGFzIGRlIG5vdGUgIsOgCiAgICAvLyB2ZW5pciIgaWNpLCBlbGxlIHJlc3RlIHVuaXF1ZW1lbnQgc3VyIGxlIGNhbWVtYmVydCBkZXMgZMOpcGVuc2VzIHBvdXIKICAgIC8vIG5lIHBhcyBhZmZpY2hlciBsZSBtw6ptZSBjaGlmZnJlIG5ldCDDoCBkZXV4IGVuZHJvaXRzLgogICAgZnVuY3Rpb24gcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJpbmNvbWUiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGlmIChpbmNvbWVDYXRlZ29yeUNoYXJ0KSB7IGluY29tZUNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9LCBlbXB0eUVsKTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgICAgbW9udGhseVtrZXldW3R4LnR5cGVdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFRvdWpvdXJzIGluY2x1cmUgbGUgbW9pcyBlbiBjb3VycyAobcOqbWUgc2FucyB0cmFuc2FjdGlvbikgcydpbCBleGlzdGUKICAgICAgLy8gZGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBwb3VyIHF1J2lsIGFwcGFyYWlzc2Ugc2FucyBhdHRlbmRyZSBsYQogICAgICAvLyBwcmVtacOocmUgdHJhbnNhY3Rpb24gZHUgbW9pcy4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUKICAgICAgLy8gc29udCBwbHVzIGFqb3V0w6llcyBpY2kgw6AgbGEgbWFpbiA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUKICAgICAgLy8gdnJhaWVzIHRyYW5zYWN0aW9ucyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzCiAgICAgIC8vIGRhbnMgYG1vbnRobHlgIHZpYSBsYSBib3VjbGUgc3VyIGB0cmFuc2FjdGlvbnNgIGNpLWRlc3N1cyDigJQgY2UgcXVpCiAgICAgIC8vIG4nZXN0IHBhcyBlbmNvcmUgYXJyaXbDqSBlc3QgcsOpc3Vtw6kgYWlsbGV1cnMgKHNvbGRlIG5ldCAiw6AgdmVuaXIiKS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSwgZW1wdHlFbCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29tcGFyZXIgZGV1eCBtb2lzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3Qgc2VsZWN0QSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKTsKICAgICAgY29uc3Qgc2VsZWN0QiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKTsKCiAgICAgIGZvciAoY29uc3Qgc2VsZWN0IG9mIFtzZWxlY3RBLCBzZWxlY3RCXSkgewogICAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGlmIChtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkpIHNlbGVjdC52YWx1ZSA9IHByZXZpb3VzVmFsdWU7CiAgICAgIH0KICAgICAgLy8gUGFyIGTDqWZhdXQgOiBtb2lzIGVuIGNvdXJzIHZzIG1vaXMgcHLDqWPDqWRlbnQsIHNpIGxlcyBkZXV4IGV4aXN0ZW50LgogICAgICBpZiAoIXNlbGVjdEEudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDApIHNlbGVjdEEudmFsdWUgPSBtb250aHNbMF07CiAgICAgIGlmICghc2VsZWN0Qi52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMSkgc2VsZWN0Qi52YWx1ZSA9IG1vbnRoc1sxXTsKICAgIH0KCiAgICBmdW5jdGlvbiBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgbW9udGhLZXkpIHsKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICByZXR1cm4geyB0b3RhbHMsIHRvdGFsIH07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyTW9udGhDb21wYXJpc29uKCkgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtdGFibGUtd3JhcCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtZW1wdHkiKTsKICAgICAgY29uc3QgbW9udGhBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLnZhbHVlOwogICAgICBjb25zdCBtb250aEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikudmFsdWU7CgogICAgICBpZiAoIW1vbnRoQSB8fCAhbW9udGhCKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQSwgdG90YWw6IGdyYW5kQSB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNCLCB0b3RhbDogZ3JhbmRCIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhCKTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KFsuLi5PYmplY3Qua2V5cyh0b3RhbHNBKSwgLi4uT2JqZWN0LmtleXModG90YWxzQildKV0uc29ydCgKICAgICAgICAoYSwgYikgPT4gKHRvdGFsc0JbYl0gfHwgMCkgLSAodG90YWxzQVthXSB8fCAwKQogICAgICApOwoKICAgICAgY29uc3QgW3lhLCBtYV0gPSBtb250aEEuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgW3liLCBtYl0gPSBtb250aEIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgbGFiZWxBID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWEsIG1hIC0gMSwgMSkpOwogICAgICBjb25zdCBsYWJlbEIgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YiwgbWIgLSAxLCAxKSk7CgogICAgICAvLyBEaWZmID0gbW9udGFudCBkdSBtb2lzIEIgbW9pbnMgY2VsdWkgZHUgbW9pcyBBLiBQb3VyIGRlcyBkw6lwZW5zZXMsCiAgICAgIC8vIGTDqXBlbnNlciBQTFVTIChkaWZmIHBvc2l0aWYpIGVzdCBsYSBtYXV2YWlzZSBub3V2ZWxsZSDihpIgcm91Z2UgOyBlbgogICAgICAvLyBkw6lwZW5zZXIgTU9JTlMgKGRpZmYgbsOpZ2F0aWYpIOKGkiB2ZXJ0LgogICAgICBmdW5jdGlvbiBkaWZmQ2VsbChhLCBiKSB7CiAgICAgICAgY29uc3QgZGlmZiA9IGIgLSBhOwogICAgICAgIGlmIChNYXRoLmFicyhkaWZmKSA8IDAuMDEpIHJldHVybiBgPHRkPuKAlDwvdGQ+YDsKICAgICAgICBjb25zdCBjbHMgPSBkaWZmID4gMCA/ICJkaWZmLW5lZ2F0aXZlIiA6ICJkaWZmLXBvc2l0aXZlIjsKICAgICAgICByZXR1cm4gYDx0ZCBjbGFzcz0iJHtjbHN9Ij4ke2RpZmYgPiAwID8gIisiIDogIiJ9JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGlmZil9PC90ZD5gOwogICAgICB9CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPiR7bGFiZWxBfTwvdGg+PHRoPiR7bGFiZWxCfTwvdGg+PHRoPkRpZmbDqXJlbmNlPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgY2F0IG9mIGNhdGVnb3JpZXMpIHsKICAgICAgICBjb25zdCBhID0gdG90YWxzQVtjYXRdIHx8IDA7CiAgICAgICAgY29uc3QgYiA9IHRvdGFsc0JbY2F0XSB8fCAwOwogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHtlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiKX08L3RkPiR7ZGlmZkNlbGwoYSwgYil9PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDx0ciBjbGFzcz0idG90YWwtcm93Ij48dGQ+VG90YWwgZMOpcGVuc2VzPC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRBKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEIpfTwvdGQ+JHtkaWZmQ2VsbChncmFuZEEsIGdyYW5kQil9PC90cj5gOwogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ2FsY3VsZSwgcG91ciBjaGFxdWUgY2F0w6lnb3JpZSBkZSBkw6lwZW5zZSwgbGEgbW95ZW5uZSBtZW5zdWVsbGUsIGxlCiAgICAvLyBtb250YW50IGR1IG1vaXMgZW4gY291cnMsIGV0IGxhIHRlbmRhbmNlIChkaXJlY3Rpb24gKyByYXRpbyB2cwogICAgLy8gbW95ZW5uZSkuIFBhcnRhZ8OpIGVudHJlIGxlIHRhYmxlYXUgIk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUiCiAgICAvLyBldCBsZXMgY29uc2VpbHMgZCfDqXBhcmduZSwgcG91ciBuZSBwYXMgZHVwbGlxdWVyIGNldHRlIGxvZ2lxdWUuCiAgICBmdW5jdGlvbiBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoS2V5cyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKV0uc29ydCgpOwogICAgICBpZiAobW9udGhLZXlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIFtdOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleXNbbW9udGhLZXlzLmxlbmd0aCAtIDFdOwogICAgICBjb25zdCBuYk1vbnRocyA9IG1vbnRoS2V5cy5sZW5ndGg7CgogICAgICAvLyB0b3RhbCBwYXIgY2F0w6lnb3JpZSwgZXQgcGFyIGNhdMOpZ29yaWUrbW9pcyAocG91ciBpc29sZXIgbGUgbW9pcyBlbiBjb3VycykKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBjb25zdCBjdXJyZW50TW9udGhCeUNhdGVnb3J5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIikgY29udGludWU7CiAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpID09PSBjdXJyZW50TW9udGhLZXkpIHsKICAgICAgICAgIGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICByZXR1cm4gY2F0ZWdvcmllcy5tYXAoKGNhdCkgPT4gewogICAgICAgIGNvbnN0IGF2ZXJhZ2UgPSB0b3RhbHNCeUNhdGVnb3J5W2NhdF0gLyBuYk1vbnRoczsKICAgICAgICBjb25zdCBjdXJyZW50ID0gY3VycmVudE1vbnRoQnlDYXRlZ29yeVtjYXRdIHx8IDA7CiAgICAgICAgbGV0IGRpcmVjdGlvbiA9ICJzdGFibGUiOwogICAgICAgIGxldCByYXRpbyA9IDA7CiAgICAgICAgaWYgKGF2ZXJhZ2UgPiAwKSB7CiAgICAgICAgICByYXRpbyA9IChjdXJyZW50IC0gYXZlcmFnZSkgLyBhdmVyYWdlOwogICAgICAgICAgaWYgKHJhdGlvID4gMC4xNSkgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvIDwgLTAuMTUpIGRpcmVjdGlvbiA9ICJkb3duIjsKICAgICAgICB9IGVsc2UgaWYgKGN1cnJlbnQgPiAwKSB7CiAgICAgICAgICBkaXJlY3Rpb24gPSAidXAiOwogICAgICAgIH0KICAgICAgICByZXR1cm4geyBjYXRlZ29yeTogY2F0LCBhdmVyYWdlLCBjdXJyZW50LCByYXRpbywgZGlyZWN0aW9uIH07CiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRyZW5kLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC1lbXB0eSIpOwoKICAgICAgY29uc3QgdHJlbmRzID0gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh0cmVuZHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPk1veWVubmUvbW9pczwvdGg+PHRoPkNlIG1vaXMtY2k8L3RoPjx0aD5UZW5kYW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IHQgb2YgdHJlbmRzKSB7CiAgICAgICAgbGV0IHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZmxhdCI+4oaSIHN0YWJsZTwvc3Bhbj5gOwogICAgICAgIGlmICh0LmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdHJlbmRIdG1sID0gdC5hdmVyYWdlID4gMAogICAgICAgICAgICA/IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSArJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YAogICAgICAgICAgICA6IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSBub3V2ZWF1PC9zcGFuPmA7CiAgICAgICAgfSBlbHNlIGlmICh0LmRpcmVjdGlvbiA9PT0gImRvd24iKSB7CiAgICAgICAgICB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWRvd24iPuKGkyAke01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JTwvc3Bhbj5gOwogICAgICAgIH0KICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmF2ZXJhZ2UpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuY3VycmVudCl9PC90ZD48dGQ+JHt0cmVuZEh0bWx9PC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBCaWxhbiBhbm51ZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IE1PTlRIX1NIT1JUX0xBQkVMUyA9IFsKICAgICAgIkphbiIsICJGw6l2IiwgIk1hciIsICJBdnIiLCAiTWFpIiwgIkp1aW4iLCAiSnVpbCIsICJBb8O7dCIsICJTZXAiLCAiT2N0IiwgIk5vdiIsICJEw6ljIiwKICAgIF07CgogICAgZnVuY3Rpb24gcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0Iik7CiAgICAgIGNvbnN0IHllYXJzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSkpXS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBjdXJyZW50WWVhciA9IFN0cmluZyhuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCkpOwogICAgICBpZiAoIXllYXJzLmluY2x1ZGVzKGN1cnJlbnRZZWFyKSkgeWVhcnMudW5zaGlmdChjdXJyZW50WWVhcik7CgogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0geWVhcnMubWFwKCh5KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt5fSI+JHt5fTwvb3B0aW9uPmApLmpvaW4oIiIpOwogICAgICBzZWxlY3QudmFsdWUgPSB5ZWFycy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBjdXJyZW50WWVhcjsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFyID0gc2VsZWN0LnZhbHVlOwogICAgICBpZiAoIXllYXIpIHJldHVybjsKCiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC15ZWFybHkiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktZW1wdHkiKTsKICAgICAgY29uc3QgdGFibGVXcmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIik7CgogICAgICBjb25zdCB5ZWFyVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSA9PT0geWVhcik7CgogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGNvbnN0IGV4cGVuc2VCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IGluY29tZUJ5TW9udGggPSBBcnJheSgxMikuZmlsbCgwKTsKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHllYXJUcmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBtb250aEluZGV4ID0gTnVtYmVyKHR4LmV4cGVuc2VfZGF0ZS5zbGljZSg1LCA3KSkgLSAxOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgewogICAgICAgICAgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICBpbmNvbWVCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgZXhwZW5zZUJ5TW9udGhbbW9udGhJbmRleF0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICB0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBuZXQgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CgogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWV4cGVuc2VzIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktdG90YWwtaW5jb21lIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgICBjb25zdCBuZXRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktbmV0Iik7CiAgICAgIG5ldEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG5ldCk7CiAgICAgIG5ldEVsLmNsYXNzTmFtZSA9ICJ5ZWFybHktc3RhdC12YWx1ZSAiICsgKG5ldCA+PSAwID8gImluY29tZSIgOiAiZXhwZW5zZSIpOwoKICAgICAgaWYgKHllYXJseUNoYXJ0KSB7IHllYXJseUNoYXJ0LmRlc3Ryb3koKTsgeWVhcmx5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoeWVhclRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICB5ZWFybHlDaGFydCA9IHNhZmVDcmVhdGVDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHM6IE1PTlRIX1NIT1JUX0xBQkVMUywKICAgICAgICAgIGRhdGFzZXRzOiBbCiAgICAgICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBleHBlbnNlQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBpbmNvbWVCeU1vbnRoLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICAgICAgXSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogeyBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9IH0sCiAgICAgICAgfSwKICAgICAgfSwgZW1wdHlFbCk7CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPlRvdGFsPC90aD48dGg+JSBkZSBsJ2FubsOpZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYW1vdW50ID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdOwogICAgICAgIGNvbnN0IHBjdCA9IHRvdGFsRXhwZW5zZXMgPiAwID8gTWF0aC5yb3VuZCgoYW1vdW50IC8gdG90YWxFeHBlbnNlcykgKiAxMDApIDogMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYW1vdW50KX08L3RkPjx0ZD4ke3BjdH0lPC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSBodG1sOwoKICAgICAgLy8gUsOpdHJvc3BlY3RpdmUgZHUgUGxhbiBkJ8OpcGFyZ25lIDogYXBwbGlxdWUgdGVzIG5vdGVzIGQnZXNzZW50aWFsaXTDqQogICAgICAvLyBBQ1RVRUxMRVMgKGNhdMOpZ29yaWVzICsgY2hhcmdlcyByw6ljdXJyZW50ZXMpIGF1eCBkw6lwZW5zZXMgUsOJRUxMRVMgZGUKICAgICAgLy8gY2V0dGUgYW5uw6llLWzDoCDigJQgbcOqbWUgY2FsY3VsIHF1ZSBsYSBzaW11bGF0aW9uIHRvdXJuw6llIHZlcnMgbCdhdmVuaXIKICAgICAgLy8gKHJlbmRlclNhdmluZ3NQbGFuKSwgbWFpcyBzdXIgZHUgY29uY3JldCBkw6lqw6AgYXJyaXbDqS4KICAgICAgY29uc3QgcmV0cm9FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktcmV0cm8tc2F2aW5ncyIpOwogICAgICBjb25zdCByZXRyb1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktcmV0cm8tc2F2aW5ncy10ZXh0Iik7CiAgICAgIGxldCByZXRyb1NhdmluZ3MgPSAwOwogICAgICBmb3IgKGNvbnN0IFtjYXQsIGFtb3VudF0gb2YgT2JqZWN0LmVudHJpZXModG90YWxzQnlDYXRlZ29yeSkpIHsKICAgICAgICBjb25zdCByYXRpbmcgPSBjYXRlZ29yeVJhdGluZ3NbY2F0XSB8fCBudWxsOwogICAgICAgIGlmIChyYXRpbmcpIHJldHJvU2F2aW5ncyArPSBhbW91bnQgKiAoRVNTRU5USUFMSVRZX1JFRFVDVElPTl9QQ1RbcmF0aW5nXSB8fCAwKTsKICAgICAgfQogICAgICBjb25zdCByZWN1cnJpbmdTcGVudFRoaXNZZWFyID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgeWVhclRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiZXhwZW5zZSIgJiYgdHgucmVjdXJyaW5nX2V4cGVuc2VfaWQpIHsKICAgICAgICAgIHJlY3VycmluZ1NwZW50VGhpc1llYXJbdHgucmVjdXJyaW5nX2V4cGVuc2VfaWRdID0KICAgICAgICAgICAgKHJlY3VycmluZ1NwZW50VGhpc1llYXJbdHgucmVjdXJyaW5nX2V4cGVuc2VfaWRdIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CiAgICAgIGZvciAoY29uc3QgciBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoKHIudHlwZSB8fCAiZXhwZW5zZSIpICE9PSAiZXhwZW5zZSIgfHwgIXIuZXNzZW50aWFsaXR5X3JhdGluZykgY29udGludWU7CiAgICAgICAgY29uc3Qgc3BlbnQgPSByZWN1cnJpbmdTcGVudFRoaXNZZWFyW3IuaWRdIHx8IDA7CiAgICAgICAgcmV0cm9TYXZpbmdzICs9IHNwZW50ICogKEVTU0VOVElBTElUWV9SRURVQ1RJT05fUENUW3IuZXNzZW50aWFsaXR5X3JhdGluZ10gfHwgMCk7CiAgICAgIH0KICAgICAgaWYgKHJldHJvU2F2aW5ncyA+IDAuNSkgewogICAgICAgIHJldHJvRWwuc3R5bGUuZGlzcGxheSA9ICJmbGV4IjsKICAgICAgICByZXRyb1RleHRFbC5pbm5lckhUTUwgPQogICAgICAgICAgYFNpIHR1IGF2YWlzIGFwcGxpcXXDqSB0ZXMgbm90ZXMgYWN0dWVsbGVzIGR1IFBsYW4gZCfDqXBhcmduZSB0b3V0IGF1IGxvbmcgZGUgJHt5ZWFyfSwgYCArCiAgICAgICAgICBgdHUgYXVyYWlzIMOpY29ub21pc8OpIGVudmlyb24gPHN0cm9uZz4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChyZXRyb1NhdmluZ3MpfTwvc3Ryb25nPiBlbiBwbHVzLmA7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgcmV0cm9FbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHJlbmRlclllYXJseU92ZXJ2aWV3KGFsbFRyYW5zYWN0aW9ucykpOwoKICAgIGZ1bmN0aW9uIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpIHsKICAgICAgcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyTW9udGhDb21wYXJpc29uKCk7CiAgICAgIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHBvcHVsYXRlWWVhclNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpOwogICAgICBzZXR1cERhc2hib2FyZENoaXBzKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU8OpbGVjdGV1ciBkdSB0YWJsZWF1IGRlIGJvcmQgOiB1biBzZXVsIGJsb2MgYWZmaWNow6kgw6AgbGEgZm9pcyAoc3VyIGxlcwogICAgLy8gNyBlbXBpbMOpcykgcG91ciBxdWUgw6dhIHRpZW5uZSBzdXIgdW4gw6ljcmFuIGRlIHTDqWzDqXBob25lIHNhbnMgZMOpZmlsZXIKICAgIC8vIHNhbnMgZmluLiBMZXMgY2FsY3Vscy9ncmFwaGlxdWVzIGV1eC1tw6ptZXMgbmUgY2hhbmdlbnQgcGFzIOKAlCBzZXVsZSBsYQogICAgLy8gdmlzaWJpbGl0w6kgZGVzIGJsb2NzIGVzdCBwaWxvdMOpZSBwYXIgbGEgcHVjZSBhY3RpdmUuCiAgICBjb25zdCBEQVNIQk9BUkRfU0VDVElPTlMgPSBbCiAgICAgIHsga2V5OiAiZXhwZW5zZXMiLCBsYWJlbDogIkTDqXBlbnNlcyIsIHJvd0lkOiAiZGFzaC1yb3ctZXhwZW5zZXMiIH0sCiAgICAgIHsga2V5OiAiaW5jb21lIiwgbGFiZWw6ICJSZXZlbnVzIiwgcm93SWQ6ICJkYXNoLXJvdy1pbmNvbWUiIH0sCiAgICAgIHsga2V5OiAiYnVkZ2V0cyIsIGxhYmVsOiAiQnVkZ2V0cyIsIHJvd0lkOiAiZGFzaC1yb3ctYnVkZ2V0cyIgfSwKICAgICAgeyBrZXk6ICJldm9sdXRpb24iLCBsYWJlbDogIsOJdm9sdXRpb24iLCByb3dJZDogImRhc2gtcm93LWV2b2x1dGlvbiIgfSwKICAgICAgeyBrZXk6ICJjb21wYXJlIiwgbGFiZWw6ICJDb21wYXJlciIsIHJvd0lkOiAiZGFzaC1yb3ctY29tcGFyZSIgfSwKICAgICAgeyBrZXk6ICJ0cmVuZCIsIGxhYmVsOiAiVGVuZGFuY2VzIiwgcm93SWQ6ICJkYXNoLXJvdy10cmVuZCIgfSwKICAgICAgeyBrZXk6ICJ5ZWFybHkiLCBsYWJlbDogIkFubsOpZSIsIHJvd0lkOiAiZGFzaC1yb3cteWVhcmx5IiB9LAogICAgXTsKICAgIGxldCBkYXNoYm9hcmRBY3RpdmVTZWN0aW9uID0gREFTSEJPQVJEX1NFQ1RJT05TWzBdLmtleTsKICAgIGxldCBkYXNoYm9hcmRDaGlwc0J1aWx0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2hvd0Rhc2hib2FyZFNlY3Rpb24oa2V5KSB7CiAgICAgIGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24gPSBrZXk7CiAgICAgIGZvciAoY29uc3Qgc2VjdGlvbiBvZiBEQVNIQk9BUkRfU0VDVElPTlMpIHsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChzZWN0aW9uLnJvd0lkKS5jbGFzc0xpc3QudG9nZ2xlKCJkYXNoLWhpZGRlbiIsIHNlY3Rpb24ua2V5ICE9PSBrZXkpOwogICAgICB9CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoIi5kYXNoYm9hcmQtY2hpcCIpLmZvckVhY2goKGNoaXApID0+IHsKICAgICAgICBjaGlwLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGNoaXAuZGF0YXNldC5zZWN0aW9uID09PSBrZXkpOwogICAgICB9KTsKICAgICAgLy8gVW4gZ3JhcGhpcXVlIENoYXJ0LmpzIHJlY3LDqcOpIHBlbmRhbnQgcXVlIHNvbiBibG9jIMOpdGFpdCBtYXNxdcOpCiAgICAgIC8vIChkaXNwbGF5Om5vbmUpIHNlIHJldHJvdXZlIGF2ZWMgdW4gY2FuZXZhcyBkZSB0YWlsbGUgbnVsbGUgZXQgbmUgc2UKICAgICAgLy8gY29ycmlnZSBwYXMgdG91dCBzZXVsIGVuIHJlZGV2ZW5hbnQgdmlzaWJsZSDigJQgb24gZm9yY2UgdW4gcmVzaXplCiAgICAgIC8vIGp1c3RlIGFwcsOocyBsJ2F2b2lyIGFmZmljaMOpLCBwb3VyIGxlcyA0IGdyYXBoaXF1ZXMgY29uY2VybsOpcy4KICAgICAgZm9yIChjb25zdCBjaGFydCBvZiBbY2F0ZWdvcnlDaGFydCwgaW5jb21lQ2F0ZWdvcnlDaGFydCwgZXZvbHV0aW9uQ2hhcnQsIHllYXJseUNoYXJ0XSkgewogICAgICAgIGlmIChjaGFydCkgY2hhcnQucmVzaXplKCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXR1cERhc2hib2FyZENoaXBzKCkgewogICAgICBpZiAoZGFzaGJvYXJkQ2hpcHNCdWlsdCkgewogICAgICAgIHNob3dEYXNoYm9hcmRTZWN0aW9uKGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24pOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNoaXAtcm93Iik7CiAgICAgIGZvciAoY29uc3Qgc2VjdGlvbiBvZiBEQVNIQk9BUkRfU0VDVElPTlMpIHsKICAgICAgICBjb25zdCBjaGlwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgY2hpcC50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgY2hpcC5jbGFzc05hbWUgPSAiZGFzaGJvYXJkLWNoaXAiOwogICAgICAgIGNoaXAuZGF0YXNldC5zZWN0aW9uID0gc2VjdGlvbi5rZXk7CiAgICAgICAgY2hpcC50ZXh0Q29udGVudCA9IHNlY3Rpb24ubGFiZWw7CiAgICAgICAgY2hpcC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dEYXNoYm9hcmRTZWN0aW9uKHNlY3Rpb24ua2V5KSk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGNoaXApOwogICAgICB9CiAgICAgIGRhc2hib2FyZENoaXBzQnVpbHQgPSB0cnVlOwogICAgICBzaG93RGFzaGJvYXJkU2VjdGlvbihkYXNoYm9hcmRBY3RpdmVTZWN0aW9uKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEaWN0w6llIHZvY2FsZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbWljQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1taWMiKTsKICAgIGNvbnN0IHZvaWNlQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtYmFubmVyIik7CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIHRyYW5zYWN0aW9uIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZSBzZXNzaW9uIGRlCiAgICAvLyBuYXZpZ2F0aW9uIChyZW1pcyDDoCB6w6lybyBzaSBvbiByZWNoYXJnZSBsYSBwYWdlKS4gU2VydCB1bmlxdWVtZW50IMOgCiAgICAvLyBhcHBsaXF1ZXIgdW5lIGNvcnJlY3Rpb24gKCJlbiBmYWl0IGMnw6l0YWl0IHBsdXTDtHQuLi4iKSBzdXIgbGEgYm9ubmUKICAgIC8vIHRyYW5zYWN0aW9uLiBTYW5zIMOnYSwgb3Ugc2kgbGEgcGhyYXNlIG4nZXN0IHBhcyB1bmUgY29ycmVjdGlvbiwgb24KICAgIC8vIGNyw6llIHRvdWpvdXJzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiDigJQgbWlldXggdmF1dCB1biBkb3VibG9uIHF1J3VuZQogICAgLy8gZMOpcGVuc2UgY29ycm9tcHVlIHBhciBlcnJldXIuCiAgICBsZXQgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IG51bGw7CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VCYW5uZXIodGV4dCkgewogICAgICBpZiAoIXRleHQpIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiYW5zd2VyIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9ICIiOwogICAgICB9IGVsc2UgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRWb2ljZUFuc3dlckJhbm5lcih0ZXh0KSB7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiYW5zd2VyIik7CiAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgfQoKICAgIC8vIFByb25vbmNlIGxhIHLDqXBvbnNlIMOgIHVuZSBxdWVzdGlvbiB2b2NhbGUgKCJBc3Npc3RhbnQgdm9jYWwgcXVlc3Rpb24iKS4KICAgIC8vIFB1ciBib251cyA6IHNpIGxhIHN5bnRow6hzZSB2b2NhbGUgbidlc3QgcGFzIGRpc3BvIG91IMOpY2hvdWUsIGxhIHLDqXBvbnNlCiAgICAvLyByZXN0ZSBhZmZpY2jDqWUgZGFucyBsZSBiYW5kZWF1LCBkb25jIG9uIGF2YWxlIGwnZXJyZXVyIHNhbnMgYmxvcXVlci4KICAgIGZ1bmN0aW9uIHNwZWFrVm9pY2VBbnN3ZXIodGV4dCkgewogICAgICBpZiAoISgic3BlZWNoU3ludGhlc2lzIiBpbiB3aW5kb3cpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5jYW5jZWwoKTsKICAgICAgICBjb25zdCB1dHRlcmFuY2UgPSBuZXcgU3BlZWNoU3ludGhlc2lzVXR0ZXJhbmNlKHRleHQpOwogICAgICAgIHV0dGVyYW5jZS5sYW5nID0gImZyLUZSIjsKICAgICAgICB3aW5kb3cuc3BlZWNoU3ludGhlc2lzLnNwZWFrKHV0dGVyYW5jZSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudC4KICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29uZmlybWF0aW9uIHZvY2FsZSDigJQgcXVhbmQgbCdJQSBhIHVuIGRvdXRlIHN1ciBsJ2ludGVycHLDqXRhdGlvbgogICAgLy8gKG1vbnRhbnQgYXBwcm94aW1hdGlmLCBjYXTDqWdvcmllIGluY2VydGFpbmUuLi4pLCBlbGxlIGRlbWFuZGUKICAgIC8vIGNvbmZpcm1hdGlvbiBhdSBsaWV1IGQnYXBwbGlxdWVyIGRpcmVjdGVtZW50LiBMJ3V0aWxpc2F0ZXVyIHBldXQKICAgIC8vIHLDqXBvbmRyZSBlbiBhcHB1eWFudCBzdXIgIkNvbmZpcm1lciIvIkFubnVsZXIiLCBPVSBlbiByw6ktYXBwdXlhbnQgc3VyCiAgICAvLyBsZSBtaWNybyBwb3VyIHLDqXBvbmRyZSBkZSB2aXZlIHZvaXggKCJvdWkgYydlc3Qgw6dhIiwgIm5vbiwgY2hhbmdlIMOnYQogICAgLy8gZW4gcmVzdGF1cmFudCIuLi4pIOKAlCBkYW5zIGNlIGNhcywgbGEgZGljdMOpZSBzdWl2YW50ZSBlc3QgaW50ZXJwcsOpdMOpZQogICAgLy8gY29tbWUgdW5lIHLDqXBvbnNlIMOgIENFVFRFIGNvbmZpcm1hdGlvbiBwbHV0w7R0IHF1ZSBjb21tZSB1bmUgbm91dmVsbGUKICAgIC8vIHRyYW5zYWN0aW9uICh2b2lyIHBlbmRpbmdWb2ljZUFjdGlvbiwgdsOpcmlmacOpIGRhbnMgbGUgbGlzdGVuZXIKICAgIC8vICJyZXN1bHQiIGRlIGxhIHJlY29ubmFpc3NhbmNlIHZvY2FsZSB1biBwZXUgcGx1cyBiYXMpLgogICAgbGV0IHBlbmRpbmdWb2ljZUFjdGlvbiA9IG51bGw7IC8vIHsga2luZDogInRyYW5zYWN0aW9uIiB8ICJlZGl0X2xhc3QiLCBkYXRhOiB7Li4ufSB9IG91IG51bGwKICAgIGNvbnN0IHZvaWNlQ29uZmlybUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWNvbmZpcm0tYmFubmVyIik7CgogICAgZnVuY3Rpb24gaGlkZVZvaWNlQ29uZmlybUJhbm5lcigpIHsKICAgICAgcGVuZGluZ1ZvaWNlQWN0aW9uID0gbnVsbDsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoa2luZCwgcGFyc2VkKSB7CiAgICAgIHBlbmRpbmdWb2ljZUFjdGlvbiA9IHsKICAgICAgICBraW5kLAogICAgICAgIGRhdGE6CiAgICAgICAgICBraW5kID09PSAidHJhbnNhY3Rpb24iCiAgICAgICAgICAgID8gcGFyc2VkCiAgICAgICAgICAgIDogewogICAgICAgICAgICAgICAgdGFyZ2V0OiBwYXJzZWQudGFyZ2V0LAogICAgICAgICAgICAgICAgbmV3X3R5cGU6IHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X3R5cGUsCiAgICAgICAgICAgICAgICBuZXdfY2F0ZWdvcnk6IHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5LAogICAgICAgICAgICAgIH0sCiAgICAgIH07CgogICAgICBsZXQgcXVlc3Rpb247CiAgICAgIGlmIChraW5kID09PSAidHJhbnNhY3Rpb24iKSB7CiAgICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgICBjb25zdCBjYXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BhcnNlZC5jYXRlZ29yeV0gfHwgcGFyc2VkLmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRlc2NQYXJ0ID0gcGFyc2VkLmRlc2NyaXB0aW9uID8gYCAoJHtwYXJzZWQuZGVzY3JpcHRpb259KWAgOiAiIjsKICAgICAgICBxdWVzdGlvbiA9CiAgICAgICAgICBgJHt2ZXJifSBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChwYXJzZWQuYW1vdW50KX0gZW4gJHtjYXRMYWJlbH0ke2Rlc2NQYXJ0fSwgYCArCiAgICAgICAgICBgbGUgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShwYXJzZWQuZXhwZW5zZV9kYXRlKSl9IOKAlCBjJ2VzdCBiaWVuIMOnYSA/YDsKICAgICAgfSBlbHNlIHsKICAgICAgICAvLyBlZGl0X2xhc3QgOiBvbiByZXRyb3V2ZSBsYSB0cmFuc2FjdGlvbiBjaWJsw6llIGRhbnMgYWxsVHJhbnNhY3Rpb25zCiAgICAgICAgLy8gKGTDqWrDoCB0cmnDqSBwYXIgZGF0ZSBkw6ljcm9pc3NhbnRlKSBwb3VyIGRvbm5lciB1biBjb250ZXh0ZSB1dGlsZS4KICAgICAgICBjb25zdCBjYW5kaWRhdGVzID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodCkgPT4gewogICAgICAgICAgaWYgKHBhcnNlZC50YXJnZXQgPT09ICJsYXN0X2V4cGVuc2UiKSByZXR1cm4gdC50eXBlID09PSAiZXhwZW5zZSI7CiAgICAgICAgICBpZiAocGFyc2VkLnRhcmdldCA9PT0gImxhc3RfaW5jb21lIikgcmV0dXJuIHQudHlwZSA9PT0gImluY29tZSI7CiAgICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgICB9KTsKICAgICAgICBjb25zdCB0YXJnZXQgPSBjYW5kaWRhdGVzWzBdOwogICAgICAgIGNvbnN0IHRhcmdldExhYmVsID0gdGFyZ2V0CiAgICAgICAgICA/IGAke3RhcmdldC50eXBlID09PSAiaW5jb21lIiA/ICJsZSByZXZlbnUiIDogImxhIGTDqXBlbnNlIn0gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0LmFtb3VudCl9YCArCiAgICAgICAgICAgICh0YXJnZXQuZGVzY3JpcHRpb24gPyBgICgke3RhcmdldC5kZXNjcmlwdGlvbn0pYCA6ICIiKQogICAgICAgICAgOiAibGEgdHJhbnNhY3Rpb24gY29ycmVzcG9uZGFudGUiOwogICAgICAgIGNvbnN0IGNoYW5nZXMgPSBbXTsKICAgICAgICBpZiAocGFyc2VkLnJlcXVlc3RlZF9uZXdfdHlwZSkgewogICAgICAgICAgY2hhbmdlcy5wdXNoKGB0eXBlIDogJHtwYXJzZWQucmVxdWVzdGVkX25ld190eXBlID09PSAiaW5jb21lIiA/ICJyZXZlbnUiIDogImTDqXBlbnNlIn1gKTsKICAgICAgICB9CiAgICAgICAgaWYgKHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5KSB7CiAgICAgICAgICBjaGFuZ2VzLnB1c2goYGNhdMOpZ29yaWUgOiAke2FsbENhdGVnb3J5TGFiZWxzW3BhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5XSB8fCBwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeX1gKTsKICAgICAgICB9CiAgICAgICAgcXVlc3Rpb24gPSBgTW9kaWZpZXIgJHt0YXJnZXRMYWJlbH0g4oCUICR7Y2hhbmdlcy5qb2luKCIsICIpIHx8ICJhdWN1biBjaGFuZ2VtZW50IHJlY29ubnUifSDigJQgYydlc3QgYmllbiDDp2EgP2A7CiAgICAgIH0KCiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmlubmVySFRNTCA9ICIiOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKCiAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIHRleHQudGV4dENvbnRlbnQgPSBxdWVzdGlvbjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAidm9pY2UtY29uZmlybS1jb250cm9scyI7CgogICAgICBjb25zdCBjb25maXJtQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGNvbmZpcm1CdG4udGV4dENvbnRlbnQgPSAi4pyFIENvbmZpcm1lciI7CiAgICAgIGNvbmZpcm1CdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgY29uZmlybUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN1Ym1pdFZvaWNlQ29uZmlybURlY2lzaW9uKCJjb25maXJtIikpOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChjb25maXJtQnRuKTsKCiAgICAgIGNvbnN0IGNhbmNlbEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBjYW5jZWxCdG4udGV4dENvbnRlbnQgPSAi4p2MIEFubnVsZXIiOwogICAgICBjYW5jZWxCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBjYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbigiY2FuY2VsIikpOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChjYW5jZWxCdG4pOwoKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQoY29udHJvbHMpOwoKICAgICAgY29uc3QgaGludCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaGludC5jbGFzc05hbWUgPSAidm9pY2UtY29uZmlybS1oaW50IjsKICAgICAgaGludC50ZXh0Q29udGVudCA9ICLwn46kIFR1IHBldXggYXVzc2kgcsOpcG9uZHJlIMOgIGxhIHZvaXggZW4gcsOpLWFwcHV5YW50IHN1ciBsZSBtaWNyby4iOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5hcHBlbmRDaGlsZChoaW50KTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbihkZWNpc2lvbikgewogICAgICBpZiAoIXBlbmRpbmdWb2ljZUFjdGlvbikgcmV0dXJuOwogICAgICBjb25zdCB7IGtpbmQsIGRhdGEgfSA9IHBlbmRpbmdWb2ljZUFjdGlvbjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9jb25maXJtIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRlY2lzaW9uLCBraW5kLCBwZW5kaW5nOiBkYXRhIH0pLAogICAgICAgIH0pOwogICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlQ29uZmlybVJlc3VsdChyZXN1bHQpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBoYW5kbGVWb2ljZUNvbmZpcm1SZXN1bHQocmVzdWx0KSB7CiAgICAgIGhpZGVWb2ljZUNvbmZpcm1CYW5uZXIoKTsKICAgICAgaWYgKHJlc3VsdC5kZWNpc2lvbiA9PT0gImNhbmNlbCIpIHsKICAgICAgICBzaG93VG9hc3QoIkFubnVsw6kiKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgLy8gU2lub24sIHJlc3VsdCBlc3QgdW4gcsOpc3VsdGF0IGTDqWrDoCBmaW5hbGlzw6kgKFZvaWNlUGFyc2VSZXN1bHQgcG91cgogICAgICAvLyB1bmUgdHJhbnNhY3Rpb24sIFZvaWNlRWRpdFJlc3VsdCBwb3VyIHVuIGVkaXRfbGFzdCkgOiBvbiBsZSB0cmFpdGUKICAgICAgLy8gZXhhY3RlbWVudCBjb21tZSB1biByw6lzdWx0YXQgZGUgZGljdMOpZSBub3JtYWwuCiAgICAgIGF3YWl0IGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocmVzdWx0KTsKICAgIH0KCiAgICAvLyBQb2ludCBkJ2VudHLDqWUgY29tbXVuIHBvdXIgbGUgcsOpc3VsdGF0IGQndW5lIGRpY3TDqWUgImZyYcOuY2hlIiAoZW52b3nDqWUKICAgIC8vIMOgIC9hcGkvdm9pY2UvcGFyc2UpIEVUIHBvdXIgbGUgcsOpc3VsdGF0IGTDqWrDoCBmaW5hbGlzw6kgZCd1bmUKICAgIC8vIGNvbmZpcm1hdGlvbiDigJQgbGVzIGRldXggY2hlbWlucyByZXRvbWJlbnQgc3VyIGxlIG3Dqm1lIHRyYWl0ZW1lbnQgdW5lCiAgICAvLyBmb2lzIHF1J29uIHNhaXQgcXUnaWwgbid5IGEgcGx1cyBkZSBkb3V0ZSDDoCBsZXZlci4KICAgIGFzeW5jIGZ1bmN0aW9uIGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGlmIChwYXJzZWQuaW50ZW50ID09PSAicXVlc3Rpb24iKSB7CiAgICAgICAgc2V0Vm9pY2VBbnN3ZXJCYW5uZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgc3BlYWtWb2ljZUFuc3dlcihwYXJzZWQuYW5zd2VyKTsKICAgICAgfSBlbHNlIGlmIChwYXJzZWQuaW50ZW50ID09PSAiZWRpdF9sYXN0IikgewogICAgICAgIGlmIChwYXJzZWQucGVuZGluZykgewogICAgICAgICAgc2hvd1ZvaWNlQ29uZmlybUJhbm5lcigiZWRpdF9sYXN0IiwgcGFyc2VkKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2V0Vm9pY2VBbnN3ZXJCYW5uZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgICBzcGVha1ZvaWNlQW5zd2VyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChwYXJzZWQubmVlZHNfY29uZmlybWF0aW9uKSB7CiAgICAgICAgc2hvd1ZvaWNlQ29uZmlybUJhbm5lcigidHJhbnNhY3Rpb24iLCBwYXJzZWQpOwogICAgICB9IGVsc2UgewogICAgICAgIGF3YWl0IGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIGxldCBiYW5uZXJEZWxheSA9IDE1MDA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGlmIChwZW5kaW5nVm9pY2VBY3Rpb24pIHsKICAgICAgICAgICAgLy8gVW5lIGJhbm5pw6hyZSBkZSBjb25maXJtYXRpb24gZXN0IGFmZmljaMOpZSA6IGNldHRlIGRpY3TDqWUgZXN0CiAgICAgICAgICAgIC8vIHVuZSByw6lwb25zZSAoIm91aSIsICJub24iLCAiY2hhbmdlIMOnYSBlbi4uLiIpIMOgIENFVFRFCiAgICAgICAgICAgIC8vIGNvbmZpcm1hdGlvbiwgcGFzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbi4KICAgICAgICAgICAgY29uc3QgeyBraW5kLCBkYXRhIH0gPSBwZW5kaW5nVm9pY2VBY3Rpb247CiAgICAgICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL2NvbmZpcm0iLCB7CiAgICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyByZXBseV90ZXh0OiB0cmFuc2NyaXB0LCBraW5kLCBwZW5kaW5nOiBkYXRhIH0pLAogICAgICAgICAgICB9KTsKICAgICAgICAgICAgYXdhaXQgaGFuZGxlVm9pY2VDb25maXJtUmVzdWx0KHJlc3VsdCk7CiAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNDAwMDsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL3BhcnNlIiwgewogICAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGlmIChwYXJzZWQuaW50ZW50ID09PSAicXVlc3Rpb24iKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSA2MDAwOwogICAgICAgICAgICB9IGVsc2UgaWYgKHBhcnNlZC5uZWVkc19jb25maXJtYXRpb24gfHwgcGFyc2VkLnBlbmRpbmcpIHsKICAgICAgICAgICAgICBiYW5uZXJEZWxheSA9IDE1MDA7IC8vIGxhIGJhbm5pw6hyZSBkZSBjb25maXJtYXRpb24gcHJlbmQgbGUgcmVsYWlzIHZpc3VlbGxlbWVudAogICAgICAgICAgICB9IGVsc2UgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJlZGl0X2xhc3QiKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSA0MDAwOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocGFyc2VkKTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIGJhbm5lckRlbGF5KTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgbWljQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGlmIChpc0xpc3RlbmluZykgewogICAgICAgICAgcmVjb2duaXRpb24uc3RvcCgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICB0cnkgewogICAgICAgICAgcmVjb2duaXRpb24uc3RhcnQoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIC8vIHN0YXJ0KCkgamV0dGUgc2kgZMOpasOgIGTDqW1hcnLDqSA7IG9uIGlnbm9yZS4KICAgICAgICB9CiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFN1Z2dlc3Rpb25zIGRlIGNhdMOpZ29yaWUg4oCUIHVuaXF1ZW1lbnQgYXByw6hzIHVuZSBzYWlzaWUgcGFyIGRpY3TDqWUKICAgIC8vIHZvY2FsZSAodW5lIGZhdXRlIGRlIGZyYXBwZSBlbiBzYWlzaWUgbWFudWVsbGUsIGMnZXN0IHVuZSBlcnJldXIgZGUKICAgIC8vIGwndXRpbGlzYXRldXIsIHBhcyBsYSBwZWluZSBkZSBsZSByZWxhbmNlciBkZXNzdXMpLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQgPSAzOwoKICAgIC8vIE1vdHMgZGUgbGlhaXNvbiBmcmFuw6dhaXMgw6AgaWdub3JlciA6ICJjYXNpbm8iLCAiYXUgY2FzaW5vIiBldCAicGVydGUgYXUKICAgIC8vIGNhc2lubyIgZG9pdmVudCDDqnRyZSByZWNvbm51cyBjb21tZSBsYSBtw6ptZSBpZMOpZSBtYWxncsOpIGxlcyBtb3RzCiAgICAvLyBkaWZmw6lyZW50cyBhdXRvdXIsIGRvbmMgb24gY29tcGFyZSBkZXMgbW90cy1jbMOpcyBzaWduaWZpY2F0aWZzIHBsdXTDtHQKICAgIC8vIHF1ZSBsYSBkZXNjcmlwdGlvbiBjb21wbMOodGUgdGVsbGUgcXVlbGxlLgogICAgY29uc3QgREVTQ1JJUFRJT05fU1RPUFdPUkRTID0gbmV3IFNldChbCiAgICAgICJhIiwgImF1IiwgImF1eCIsICJkZSIsICJkdSIsICJkZXMiLCAiZCIsICJsZSIsICJsYSIsICJsZXMiLCAibCIsCiAgICAgICJ1biIsICJ1bmUiLCAiY2UiLCAiY2V0IiwgImNldHRlIiwgImNlcyIsICJtb24iLCAibWEiLCAibWVzIiwKICAgICAgInRvbiIsICJ0YSIsICJ0ZXMiLCAic29uIiwgInNhIiwgInNlcyIsICJub3RyZSIsICJub3MiLCAidm90cmUiLAogICAgICAidm9zIiwgImxldXIiLCAibGV1cnMiLCAiY2hleiIsICJzdXIiLCAiZGFucyIsICJwb3VyIiwgImF2ZWMiLAogICAgICAiZXQiLCAib3UiLCAiZW4iLCAicGFyIiwKICAgIF0pOwoKICAgIC8vIEV4dHJhaXQgbGVzIG1vdHMtY2zDqXMgc2lnbmlmaWNhdGlmcyBkJ3VuZSBkZXNjcmlwdGlvbiAoYWNjZW50cyBldAogICAgLy8gY2Fzc2UgaWdub3LDqXMsIG1vdHMgZGUgbGlhaXNvbiBldCBtb3RzIHRyb3AgY291cnRzIMOpY2FydMOpcykuCiAgICBmdW5jdGlvbiBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhkZXNjKSB7CiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSAoZGVzYyB8fCAiIikKICAgICAgICAubm9ybWFsaXplKCJORkQiKQogICAgICAgIC5yZXBsYWNlKC9bzIAtza9dL2csICIiKSAvLyByZXRpcmUgbGVzIGFjY2VudHMgKMOpIC0+IGUsIGV0Yy4pCiAgICAgICAgLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IHRva2VucyA9IG5vcm1hbGl6ZWQuc3BsaXQoL1teYS16MC05XSsvKS5maWx0ZXIoQm9vbGVhbik7CiAgICAgIHJldHVybiBuZXcgU2V0KAogICAgICAgIHRva2Vucy5maWx0ZXIoKHQpID0+IHQubGVuZ3RoID49IDMgJiYgIURFU0NSSVBUSU9OX1NUT1BXT1JEUy5oYXModCkpCiAgICAgICk7CiAgICB9CgogICAgZnVuY3Rpb24ga2V5d29yZHNJbnRlcnNlY3QoYSwgYikgewogICAgICBmb3IgKGNvbnN0IHRva2VuIG9mIGEpIHsKICAgICAgICBpZiAoYi5oYXModG9rZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAgfQogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CgogICAgLy8gUmV0aXJlIGQndW5lIGRlc2NyaXB0aW9uIGxlcyBtb3RzIHF1aSBvbnQgc2Vydmkgw6AgZMOpdGVjdGVyIGxhCiAgICAvLyBjYXTDqWdvcmllIChleC4gImNhc2lubyIgdW5lIGZvaXMgcXVlIGxhIGNhdMOpZ29yaWUgImNhc2lubyIgZXhpc3RlKSA6CiAgICAvLyB1bmUgZm9pcyBxdWUgbGEgY2F0w6lnb3JpZSBwb3J0ZSBsJ2luZm9ybWF0aW9uLCBsYSByw6lww6l0ZXIgZGFucyBsYQogICAgLy8gZGVzY3JpcHRpb24gbidhcHBvcnRlIHBsdXMgcmllbi4gUmVudm9pZSBudWxsIHNpIGxhIGRlc2NyaXB0aW9uCiAgICAvLyBkZXZpZW50IHZpZGUgdW5lIGZvaXMgY2VzIG1vdHMgcmV0aXLDqXMuCiAgICBmdW5jdGlvbiBzdHJpcE1hdGNoZWRLZXl3b3Jkc0Zyb21EZXNjcmlwdGlvbihkZXNjcmlwdGlvbiwga2V5d29yZHMpIHsKICAgICAgaWYgKCFkZXNjcmlwdGlvbiB8fCAha2V5d29yZHMgfHwga2V5d29yZHMuc2l6ZSA9PT0gMCkgcmV0dXJuIGRlc2NyaXB0aW9uIHx8IG51bGw7CiAgICAgIGNvbnN0IHdvcmRzID0gZGVzY3JpcHRpb24uc3BsaXQoL1xzKy8pLmZpbHRlcihCb29sZWFuKTsKICAgICAgY29uc3Qga2VwdCA9IHdvcmRzLmZpbHRlcigodykgPT4gewogICAgICAgIGNvbnN0IG5vcm0gPSB3CiAgICAgICAgICAubm9ybWFsaXplKCJORkQiKQogICAgICAgICAgLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpCiAgICAgICAgICAudG9Mb3dlckNhc2UoKQogICAgICAgICAgLnJlcGxhY2UoL1teYS16MC05XS9nLCAiIik7CiAgICAgICAgcmV0dXJuICFrZXl3b3Jkcy5oYXMobm9ybSk7CiAgICAgIH0pOwogICAgICBjb25zdCBjbGVhbmVkID0ga2VwdC5qb2luKCIgIikudHJpbSgpOwogICAgICByZXR1cm4gY2xlYW5lZCB8fCBudWxsOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGRpc21pc3NTdWdnZXN0aW9uKGtleSkgewogICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5hZGQoa2V5KTsgLy8gaW1tw6lkaWF0IGPDtHTDqSBVSSwgcGFzIGJlc29pbiBkJ2F0dGVuZHJlIGxlIHNlcnZldXIKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsga2V5IH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIGxhIHN1Z2dlc3Rpb24gcsOpYXBwYXJhw650IHVuZSBmb2lzIHN1ciB1bgogICAgICAgIC8vIGF1dHJlIGFwcGFyZWlsIHNpIGxhIHNhdXZlZ2FyZGUgc2VydmV1ciBhIMOpY2hvdcOpLgogICAgICB9CiAgICB9CgogICAgLy8gUmVnYXJkZSBzaSBsYSBkZXNjcmlwdGlvbiBkZSBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZQogICAgLy8gKG91IGNvcnJpZ8OpZSkgw6AgbGEgdm9peCByZXZpZW50IHNvdXZlbnQsIGV0IHNpIG91aSA6CiAgICAvLyAtIHNvaXQgZWxsZSBhIHRvdWpvdXJzIMOpdMOpIHJhbmfDqWUgZGFucyAiQXV0cmUiIOKGkiBvbiBwcm9wb3NlIGRlIGNyw6llcgogICAgLy8gICB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgZGUgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgOwogICAgLy8gLSBzb2l0IGVsbGUgYSBjZXR0ZSBmb2lzIHVuZSBjYXTDqWdvcmllIGRpZmbDqXJlbnRlIGRlIGQnaGFiaXR1ZGUg4oaSIG9uCiAgICAvLyAgIGRlbWFuZGUgc2kgY2Ugbidlc3QgcGFzIHVuZSBlcnJldXIgOwogICAgLy8gLSBzb2l0IGxhIHRyYW5zYWN0aW9uIHF1aSB2aWVudCBkJ8OqdHJlIGFqb3V0w6llIGVzdCBkw6lqw6AgYmllbiBjbGFzc8OpZSwKICAgIC8vICAgbWFpcyBkJ2FuY2llbm5lcyB0cmFuc2FjdGlvbnMgc2ltaWxhaXJlcyB0cmHDrm5lbnQgZGFucyB1bmUgYXV0cmUKICAgIC8vICAgY2F0w6lnb3JpZSAoZXguICJwZXJ0ZSBhdSBjYXNpbm8iIGNsYXNzw6llIGVuICJMb2lzaXJzIiBhdmFudCBxdWUKICAgIC8vICAgImNhc2lubyIgZXhpc3RlIGNvbW1lIGNhdMOpZ29yaWUpIOKGkiBvbiBwcm9wb3NlIGRlIGxlcyBhbGlnbmVyLgogICAgZnVuY3Rpb24gY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24oZGVzY3JpcHRpb24sIHR5cGUpIHsKICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhkZXNjcmlwdGlvbik7CiAgICAgIGlmIChrZXl3b3Jkcy5zaXplID09PSAwKSByZXR1cm47CgogICAgICBjb25zdCBzYW1lRGVzY3JpcHRpb24gPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICh0eCkgPT4KICAgICAgICAgIHR4LnR5cGUgPT09IHR5cGUgJiYKICAgICAgICAgIGtleXdvcmRzSW50ZXJzZWN0KGtleXdvcmRzLCBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3Jkcyh0eC5kZXNjcmlwdGlvbikpCiAgICAgICk7CiAgICAgIGlmIChzYW1lRGVzY3JpcHRpb24ubGVuZ3RoIDwgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQpIHJldHVybjsKCiAgICAgIGNvbnN0IGNvdW50cyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHNhbWVEZXNjcmlwdGlvbikgY291bnRzW3R4LmNhdGVnb3J5XSA9IChjb3VudHNbdHguY2F0ZWdvcnldIHx8IDApICsgMTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKGNvdW50cyk7CiAgICAgIGNvbnN0IGRvbWluYW50ID0gY2F0ZWdvcmllcy5yZWR1Y2UoKGEsIGIpID0+IChjb3VudHNbYV0gPj0gY291bnRzW2JdID8gYSA6IGIpKTsKICAgICAgY29uc3QgbGF0ZXN0ID0gc2FtZURlc2NyaXB0aW9uWzBdOyAvLyBhbGxUcmFuc2FjdGlvbnMgZXN0IHRyacOpIHBhciBkYXRlIGTDqWNyb2lzc2FudGUKCiAgICAgIC8vIENsw6kgc3RhYmxlIGJhc8OpZSBzdXIgbGVzIG1vdHMtY2zDqXMgKHRyacOpcykgcGx1dMO0dCBxdWUgbGEgZGVzY3JpcHRpb24KICAgICAgLy8gZXhhY3RlLCBwb3VyIHF1ZSBsZSAiSWdub3JlciIgcmVzdGUgdmFsYWJsZSBtw6ptZSBzaSBsYSBmb3JtdWxhdGlvbgogICAgICAvLyB2YXJpZSB1biBwZXUgZCd1bmUgZm9pcyDDoCBsJ2F1dHJlLgogICAgICBjb25zdCBzaWduYXR1cmUgPSBbLi4ua2V5d29yZHNdLnNvcnQoKS5qb2luKCIrIik7CgogICAgICBsZXQgc3VnZ2VzdGlvbiA9IG51bGw7CiAgICAgIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ICE9PSBkb21pbmFudCkgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBtaXNtYXRjaDoke3R5cGV9OiR7c2lnbmF0dXJlfToke2xhdGVzdC5jYXRlZ29yeX1gLAogICAgICAgICAga2luZDogIm1pc21hdGNoIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICBjdXJyZW50OiBsYXRlc3QuY2F0ZWdvcnksCiAgICAgICAgICBrZXl3b3JkcywKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgPT09IGxhdGVzdC5jYXRlZ29yeSkubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPT09IDEgJiYgZG9taW5hbnQgPT09ICJhdXRyZSIpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgZ2VuZXJpYzoke3R5cGV9OiR7c2lnbmF0dXJlfWAsCiAgICAgICAgICBraW5kOiAiZ2VuZXJpYyIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIGtleXdvcmRzLAogICAgICAgICAgdHhJZHM6IHNhbWVEZXNjcmlwdGlvbi5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgfTsKICAgICAgfSBlbHNlIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ID09PSBkb21pbmFudCkgewogICAgICAgIC8vIExhIHRyYW5zYWN0aW9uIGxhIHBsdXMgcsOpY2VudGUgZXN0IGTDqWrDoCBiaWVuIGNsYXNzw6llLCBtYWlzCiAgICAgICAgLy8gZCdhdXRyZXMgdHJhbnNhY3Rpb25zIHNpbWlsYWlyZXMgc29udCByZXN0w6llcyBkYW5zIHVuZSBjYXTDqWdvcmllCiAgICAgICAgLy8gbWlub3JpdGFpcmUgKHR5cGlxdWVtZW50IHBsdXMgYW5jaWVubmVzLCBjbGFzc8OpZXMgYXZhbnQgcXVlIGxhCiAgICAgICAgLy8gY2F0w6lnb3JpZSBkb21pbmFudGUgYWN0dWVsbGUgbidleGlzdGUpIDogb24gcHJvcG9zZSBkZSBsZXMgYWxpZ25lci4KICAgICAgICBjb25zdCBvdXRsaWVycyA9IHNhbWVEZXNjcmlwdGlvbi5maWx0ZXIoKHR4KSA9PiB0eC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpOwogICAgICAgIGlmIChvdXRsaWVycy5sZW5ndGggPiAwKSB7CiAgICAgICAgICBjb25zdCBvdXRsaWVyQ2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KG91dGxpZXJzLm1hcCgodHgpID0+IHR4LmNhdGVnb3J5KSldOwogICAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgICAga2V5OiBgcmVjb25jaWxlOiR7dHlwZX06JHtzaWduYXR1cmV9OiR7ZG9taW5hbnR9YCwKICAgICAgICAgICAga2luZDogInJlY29uY2lsZSIsCiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICAgIHR5cGUsCiAgICAgICAgICAgIGRvbWluYW50LAogICAgICAgICAgICBvdXRsaWVyQ2F0ZWdvcmllcywKICAgICAgICAgICAga2V5d29yZHMsCiAgICAgICAgICAgIHR4SWRzOiBvdXRsaWVycy5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgICB9OwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKCFzdWdnZXN0aW9uIHx8IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzLmhhcyhzdWdnZXN0aW9uLmtleSkpIHJldHVybjsKICAgICAgc2hvd0NhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcihzdWdnZXN0aW9uKTsKICAgIH0KCiAgICBmdW5jdGlvbiBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKSB7CiAgICAgIGxldCBpZHNUb0ZpeDsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gInJlY29uY2lsZSIpIHsKICAgICAgICAvLyBJY2kgc3VnZ2VzdGlvbi50eElkcyBlc3QgZMOpasOgIGV4YWN0ZW1lbnQgbCdlbnNlbWJsZSBkZXMgYW5jaWVubmVzCiAgICAgICAgLy8gdHJhbnNhY3Rpb25zIMOgIGFsaWduZXIgKHBhcyBkZSAiZGVybmnDqHJlIHRyYW5zYWN0aW9uIiDDoCBwYXJ0KSA6IGxlCiAgICAgICAgLy8gdGV4dGUgZGUgbGEgYmFubmnDqHJlIGwnYW5ub25jZSBkw6lqw6AsIHBhcyBiZXNvaW4gZCd1bmUgY29uZmlybWF0aW9uCiAgICAgICAgLy8gc3VwcGzDqW1lbnRhaXJlLgogICAgICAgIGlkc1RvRml4ID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBbbGF0ZXN0SWQsIC4uLm90aGVyc10gPSBzdWdnZXN0aW9uLnR4SWRzOwogICAgICAgIGlkc1RvRml4ID0gW2xhdGVzdElkXTsKICAgICAgICBpZiAoCiAgICAgICAgICBvdGhlcnMubGVuZ3RoID4gMCAmJgogICAgICAgICAgKGF3YWl0IHNob3dDb25maXJtKGBDb3JyaWdlciBhdXNzaSBsZXMgJHtvdGhlcnMubGVuZ3RofSB0cmFuc2FjdGlvbihzKSBwcsOpY8OpZGVudGUocykgYXZlYyBsYSBtw6ptZSBkZXNjcmlwdGlvbiA/YCkpCiAgICAgICAgKSB7CiAgICAgICAgICBpZHNUb0ZpeC5wdXNoKC4uLm90aGVycyk7CiAgICAgICAgfQogICAgICB9CgogICAgICB0cnkgewogICAgICAgIGZvciAoY29uc3QgaWQgb2YgaWRzVG9GaXgpIHsKICAgICAgICAgIGNvbnN0IHBheWxvYWQgPSB7IGNhdGVnb3J5OiB0YXJnZXRWYWx1ZSB9OwogICAgICAgICAgLy8gTGEgY2F0w6lnb3JpZSBwb3J0ZSBtYWludGVuYW50IGwnaW5mb3JtYXRpb24gOiBvbiByZXRpcmUgZGVzCiAgICAgICAgICAvLyBkZXNjcmlwdGlvbnMgbGUocykgbW90KHMpLWNsw6kocykgcXVpIG9udCBzZXJ2aSDDoCBsYSBkw6l0ZWN0ZXIsCiAgICAgICAgICAvLyBwb3VyIMOpdml0ZXIgbGEgcmVkb25kYW5jZSAiY2FzaW5vIiBlbiBjYXTDqWdvcmllIEVUIGVuIG5vdGUuCiAgICAgICAgICBjb25zdCB0eCA9IGFsbFRyYW5zYWN0aW9ucy5maW5kKCh0KSA9PiB0LmlkID09PSBpZCk7CiAgICAgICAgICBpZiAodHggJiYgc3VnZ2VzdGlvbi5rZXl3b3JkcykgewogICAgICAgICAgICBjb25zdCBjbGVhbmVkID0gc3RyaXBNYXRjaGVkS2V5d29yZHNGcm9tRGVzY3JpcHRpb24odHguZGVzY3JpcHRpb24sIHN1Z2dlc3Rpb24ua2V5d29yZHMpOwogICAgICAgICAgICBpZiAoY2xlYW5lZCAhPT0gKHR4LmRlc2NyaXB0aW9uIHx8IG51bGwpKSBwYXlsb2FkLmRlc2NyaXB0aW9uID0gY2xlYW5lZDsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgc2hvd1RvYXN0KGBDYXTDqWdvcmllIG1pc2Ugw6Agam91ciA6ICR7dGFyZ2V0TGFiZWx9YCk7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbikgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCBkZXNjTGFiZWwgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIoc2FucyBkZXNjcmlwdGlvbikiOwogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGBUdSBhcyB1dGlsaXPDqSAiJHtkZXNjTGFiZWx9IiAke3N1Z2dlc3Rpb24udHhJZHMubGVuZ3RofSBmb2lzLCB0b3Vqb3VycyBjbGFzc8OpIGVuIGAgKwogICAgICAgICAgYCJBdXRyZSIuIENyw6llciB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgP2A7CiAgICAgIH0gZWxzZSBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAicmVjb25jaWxlIikgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IG91dGxpZXJMYWJlbHMgPSBzdWdnZXN0aW9uLm91dGxpZXJDYXRlZ29yaWVzCiAgICAgICAgICAubWFwKChjKSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjXSB8fCBjKQogICAgICAgICAgLmpvaW4oIiwgIik7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gdHJhbnNhY3Rpb24ocykgc2ltaWxhaXJlKHMpIMOgICIke2Rlc2NMYWJlbH0iIHNvbnQgY2xhc3PDqWVzIGVuIGAgKwogICAgICAgICAgYCIke291dGxpZXJMYWJlbHN9IiwgYWxvcnMgcXVlICIke2RvbWluYW50TGFiZWx9IiBlc3QgbWFpbnRlbmFudCBsYSBjYXTDqWdvcmllIGhhYml0dWVsbGUuIGAgKwogICAgICAgICAgYExlcyBhbGlnbmVyIHN1ciAiJHtkb21pbmFudExhYmVsfSIgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgY3VycmVudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5jdXJyZW50XSB8fCBzdWdnZXN0aW9uLmN1cnJlbnQ7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgIiR7ZGVzY0xhYmVsfSIgZXN0IGhhYml0dWVsbGVtZW50IGNsYXNzw6kgZW4gIiR7ZG9taW5hbnRMYWJlbH0iLCBtYWlzIGNldHRlIGZvaXMgYCArCiAgICAgICAgICBgYydlc3QgIiR7Y3VycmVudExhYmVsfSIuIFBhcyBkJ2VycmV1ciBvdSB1biBvdWJsaSA/YDsKICAgICAgfQogICAgICBlbC5hcHBlbmRDaGlsZCh0ZXh0KTsKCiAgICAgIGNvbnN0IGNvbnRyb2xzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGNvbnRyb2xzLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIjsKCiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdKSB7CiAgICAgICAgICBpZiAodmFsdWUgPT09ICJhdXRyZSIpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IG5ld09wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG5ld09wdC52YWx1ZSA9ICJfX25ld19fIjsKICAgICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgICBuZXdPcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgICBjb25zdCBuZXdOYW1lSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIG5ld05hbWVJbnB1dC50eXBlID0gInRleHQiOwogICAgICAgIG5ld05hbWVJbnB1dC5wbGFjZWhvbGRlciA9ICJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSI7CiAgICAgICAgbmV3TmFtZUlucHV0LnZhbHVlID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiIjsKCiAgICAgICAgc2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgICAgIG5ld05hbWVJbnB1dC5zdHlsZS5kaXNwbGF5ID0gc2VsZWN0LnZhbHVlID09PSAiX19uZXdfXyIgPyAiaW5saW5lLWJsb2NrIiA6ICJub25lIjsKICAgICAgICB9KTsKCiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoc2VsZWN0KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChuZXdOYW1lSW5wdXQpOwoKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gIkFwcGxpcXVlciI7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGxldCB0YXJnZXRWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICAgIGxldCB0YXJnZXRMYWJlbDsKICAgICAgICAgIGlmICh0YXJnZXRWYWx1ZSA9PT0gIl9fbmV3X18iKSB7CiAgICAgICAgICAgIGNvbnN0IG5hbWUgPSBuZXdOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgY2F0w6lnb3JpZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgICAgICAgdGFyZ2V0VmFsdWUgPSBzbHVnaWZ5Q2F0ZWdvcnkobmFtZSk7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gbmFtZTsKICAgICAgICAgICAgaWYgKCFjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB0YXJnZXRWYWx1ZSkpIHsKICAgICAgICAgICAgICBzYXZlQ3VzdG9tQ2F0ZWdvcnkoc3VnZ2VzdGlvbi50eXBlLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgICAgICB9CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3RhcmdldFZhbHVlXSB8fCB0YXJnZXRWYWx1ZTsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSBgQ29ycmlnZXIgZW4gIiR7ZG9taW5hbnRMYWJlbH0iYDsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgc3VnZ2VzdGlvbi5kb21pbmFudCwgZG9taW5hbnRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9CgogICAgICBjb25zdCBkaXNtaXNzQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGRpc21pc3NCdG4udGV4dENvbnRlbnQgPSAiSWdub3JlciI7CiAgICAgIGRpc21pc3NCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBkaXNtaXNzQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgIH0pOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChkaXNtaXNzQnRuKTsKCiAgICAgIGVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKICAgIH0KCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZQogICAgLy8gc2Vzc2lvbiAobcOqbWUgcHJpbmNpcGUgcXVlIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQsIG1haXMgcG91ciB1bmUKICAgIC8vIGNvcnJlY3Rpb24gcXVpIHN1aXQgbGEgY3LDqWF0aW9uIGQndW5lIHLDqWN1cnJlbnRlIHBhciBsYSB2b2l4KS4KICAgIGxldCBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IG51bGw7CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpIHsKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICAvLyAicsOpY3VycmVudCIsICJhYm9ubmVtZW50IiwgInRvdXMgbGVzIG1vaXMiLi4uIGTDqXRlY3TDqSBwYXIgbCdJQSA6IG9uCiAgICAgIC8vIGNyw6llL2NvcnJpZ2UgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBhdSBsaWV1IGQndW5lIHRyYW5zYWN0aW9uCiAgICAgIC8vIHBvbmN0dWVsbGUsIHF1ZWwgcXVlIHNvaXQgbCdvbmdsZXQgYWN0dWVsbGVtZW50IGFmZmljaMOpIOKAlCBsZSBtaWNybwogICAgICAvLyBlc3QgZ2xvYmFsLCBwYXMgbGnDqSDDoCBsJ29uZ2xldCBSw6ljdXJyZW50ZXMuCiAgICAgIGlmIChwYXJzZWQuaXNfcmVjdXJyaW5nKSB7CiAgICAgICAgY29uc3QgcmVjUGF5bG9hZCA9IHsKICAgICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgICAgbmFtZTogcGFyc2VkLmRlc2NyaXB0aW9uIHx8IChwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IHLDqWN1cnJlbnQiIDogIkTDqXBlbnNlIHLDqWN1cnJlbnRlIiksCiAgICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgICAgZGF5X29mX21vbnRoOiBOdW1iZXIocGFyc2VkLmV4cGVuc2VfZGF0ZS5zbGljZSg4LCAxMCkpLAogICAgICAgIH07CgogICAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7bGFzdFZvaWNlUmVjdXJyaW5nSWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgY29ycmlnw6llIDogJHtyZWNQYXlsb2FkLm5hbWV9ICgke2Ftb3VudExhYmVsfSlgKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHJlY1BheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgICBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgICBzaG93VG9hc3QoYENoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfQogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKHBhcnNlZC5kZXNjcmlwdGlvbiwgcGFyc2VkLnR5cGUpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiBzdHlsw6llIChyZW1wbGFjZSB3aW5kb3cuY29uZmlybSwgcXVpIGFmZmljaGUgdW5lIHBvcHVwCiAgICAvLyBuYXRpdmUgZHUgbmF2aWdhdGV1ciBob3JzIGNoYXJ0ZSBncmFwaGlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBjb25maXJtT3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgY29uZmlybU1lc3NhZ2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW1lc3NhZ2UiKTsKICAgIGNvbnN0IGNvbmZpcm1Pa0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1vayIpOwogICAgY29uc3QgY29uZmlybUNhbmNlbEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1jYW5jZWwiKTsKICAgIGxldCBjb25maXJtUmVzb2x2ZSA9IG51bGw7CgogICAgZnVuY3Rpb24gc2hvd0NvbmZpcm0obWVzc2FnZSkgewogICAgICBjb25maXJtTWVzc2FnZUVsLnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgY29uZmlybU92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSByZXNvbHZlOwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZUNvbmZpcm0ocmVzdWx0KSB7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGlmIChjb25maXJtUmVzb2x2ZSkgewogICAgICAgIGNvbmZpcm1SZXNvbHZlKHJlc3VsdCk7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSBudWxsOwogICAgICB9CiAgICB9CgogICAgY29uZmlybU9rQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKHRydWUpKTsKICAgIGNvbmZpcm1DYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBjbG9zZUNvbmZpcm0oZmFsc2UpKTsKICAgIGNvbmZpcm1PdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IGNvbmZpcm1PdmVybGF5RWwpIGNsb3NlQ29uZmlybShmYWxzZSk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEw6lwZW5zZXMgcsOpY3VycmVudGVzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCByZWNMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWxpc3QiKTsKICAgIGNvbnN0IHJlY0VtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWN1cnJpbmctZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHJlY092ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjTW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1tb2RhbC10aXRsZSIpOwogICAgY29uc3QgcmVjVHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy10eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgcmVjTmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1uYW1lIik7CiAgICBjb25zdCByZWNBbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCByZWNDYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgcmVjRGF5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWRheSIpOwogICAgY29uc3QgcmVjU3RhcnREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LXN0YXJ0LWRhdGUiKTsKICAgIGNvbnN0IHJlY0VuZERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZW5kLWRhdGUiKTsKICAgIGNvbnN0IHJlY1NhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1zYXZlIik7CgogICAgbGV0IGFsbFJlY3VycmluZyA9IFtdOwogICAgbGV0IGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICBsZXQgcmVjQ3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgZnVuY3Rpb24gcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIHJlY0NhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0UmVjdXJyaW5nVHlwZSh0eXBlKSB7CiAgICAgIHJlY0N1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgcmVjVHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCByZWNDYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICByZWNUeXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0UmVjdXJyaW5nVHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtID0gbnVsbCkgewogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBpdGVtID8gaXRlbS5pZCA6IG51bGw7CiAgICAgIHJlY01vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGl0ZW0gPyAiTW9kaWZpZXIgbGEgY2hhcmdlIHLDqWN1cnJlbnRlIiA6ICJOb3V2ZWxsZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICByZWNTYXZlQnRuLnRleHRDb250ZW50ID0gaXRlbSA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFJlY3VycmluZ1R5cGUoaXRlbSA/IGl0ZW0udHlwZSA6ICJleHBlbnNlIik7CiAgICAgIHJlY05hbWVJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLm5hbWUgOiAiIjsKICAgICAgcmVjQW1vdW50SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHJlY0N1cnJlbnRUeXBlLCBpdGVtID8gaXRlbS5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICByZWNEYXlJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLmRheV9vZl9tb250aCA6ICIiOwogICAgICByZWNTdGFydERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5zdGFydF9kYXRlID8gaXRlbS5zdGFydF9kYXRlIDogIiI7CiAgICAgIHJlY0VuZERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5lbmRfZGF0ZSA/IGl0ZW0uZW5kX2RhdGUgOiAiIjsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZWNOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY3VycmluZ01vZGFsKCkgewogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY3VycmluZ01vZGFsKTsKICAgIHJlY092ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gcmVjT3ZlcmxheUVsKSBjbG9zZVJlY3VycmluZ01vZGFsKCk7IH0pOwoKICAgIHJlY1NhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG5hbWUgPSByZWNOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KHJlY0Ftb3VudElucHV0LnZhbHVlKTsKICAgICAgY29uc3QgZGF5ID0gcGFyc2VJbnQocmVjRGF5SW5wdXQudmFsdWUsIDEwKTsKCiAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkxlIG5vbSBlc3Qgb2JsaWdhdG9pcmUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7IHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFkYXkgfHwgZGF5IDwgMSB8fCBkYXkgPiAzMSkgeyBzaG93VG9hc3QoIkpvdXIgZHUgbW9pcyBpbnZhbGlkZSAoMSDDoCAzMSkiLCB0cnVlKTsgcmV0dXJuOyB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHJlY0N1cnJlbnRUeXBlLAogICAgICAgIG5hbWUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiByZWNDYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRheV9vZl9tb250aDogZGF5LAogICAgICAgIHN0YXJ0X2RhdGU6IHJlY1N0YXJ0RGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgICAgZW5kX2RhdGU6IHJlY0VuZERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7ZWRpdGluZ1JlY3VycmluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZVJlY3VycmluZ01vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVSZWN1cnJpbmcoaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSByw6ljdXJyZW50ZSA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiRMOpcGVuc2UgcsOpY3VycmVudGUgc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKSB7CiAgICAgIHJlY0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgcmVjRW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSBpdGVtcy5sZW5ndGggPT09IDAgPyAiYmxvY2siIDogIm5vbmUiOwoKICAgICAgY29uc3QgdG9kYXlLZXkgPSB0b2RheUlzbygpOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGl0ZW1zKSB7CiAgICAgICAgY29uc3QgdHlwZSA9IGl0ZW0udHlwZSB8fCAiZXhwZW5zZSI7CiAgICAgICAgY29uc3QgZW5kZWQgPSBpdGVtLmVuZF9kYXRlICYmIGl0ZW0uZW5kX2RhdGUgPCB0b2RheUtleTsKICAgICAgICBjb25zdCBub3RTdGFydGVkID0gaXRlbS5zdGFydF9kYXRlICYmIGl0ZW0uc3RhcnRfZGF0ZSA+IHRvZGF5S2V5OwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAicmVjLWNhcmQgIiArIHR5cGUgKyAoZW5kZWQgPyAiIGVuZGVkIiA6ICIiKTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInJlYy1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJyZWMtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUpIHsKICAgICAgICAgIGNvbnN0IHN0YXJ0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBzdGFydEJhZGdlLmNsYXNzTmFtZSA9ICJzdGFydC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBzdGFydExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5zdGFydF9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICAgIHN0YXJ0QmFkZ2UudGV4dENvbnRlbnQgPSBub3RTdGFydGVkID8gYETDqHMgbGUgJHtzdGFydExhYmVsfWAgOiBgRGVwdWlzIGxlICR7c3RhcnRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHN0YXJ0QmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAoaXRlbS5lbmRfZGF0ZSkgewogICAgICAgICAgY29uc3QgZW5kQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBlbmRCYWRnZS5jbGFzc05hbWUgPSAiZW5kLWJhZGdlIjsKICAgICAgICAgIGNvbnN0IGVuZExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5lbmRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBlbmRCYWRnZS50ZXh0Q29udGVudCA9IGVuZGVkID8gYFRlcm1pbsOpIGxlICR7ZW5kTGFiZWx9YCA6IGBKdXNxdSdhdSAke2VuZExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZW5kQmFkZ2UpOwogICAgICAgIH0KICAgICAgICAvLyBQYXMgZW5jb3JlIG5vdMOpZSBkYW5zIGxlIFBsYW4gZCfDqXBhcmduZSA6IHNpbXBsZSByYXBwZWwgdmlzdWVsLAogICAgICAgIC8vIHBvdXIgcXVlIGxhIGNvcnLDqWxhdGlvbiAoaWTDqWUgMSkgZXQgbGUgY2FsY3VsIGQnw6ljb25vbWllIHJlc3RlbnQgw6AKICAgICAgICAvLyBqb3VyIG3Dqm1lIHBvdXIgbGVzIGNoYXJnZXMgY3LDqcOpZXMgYXByw6hzIGNvdXAgKHZvY2FsLCBpbXBvcnQuLi4pLgogICAgICAgIGlmICh0eXBlID09PSAiZXhwZW5zZSIgJiYgaXRlbS5hY3RpdmUgIT09IGZhbHNlICYmICFpdGVtLmVzc2VudGlhbGl0eV9yYXRpbmcpIHsKICAgICAgICAgIGNvbnN0IHRvTm90ZUJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgdG9Ob3RlQmFkZ2UuY2xhc3NOYW1lID0gInRvLW5vdGUtYmFkZ2UiOwogICAgICAgICAgdG9Ob3RlQmFkZ2UudGV4dENvbnRlbnQgPSAi4q2QIMOAIG5vdGVyIjsKICAgICAgICAgIHRvTm90ZUJhZGdlLnRpdGxlID0gIlBhcyBlbmNvcmUgbm90w6llIGRhbnMgbGUgUGxhbiBkJ8OpcGFyZ25lIjsKICAgICAgICAgIHRvTm90ZUJhZGdlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgICAgICBzd2l0Y2hWaWV3KCJzYXZpbmdzIik7CiAgICAgICAgICAgIGNvbnN0IHBhbmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcGxhbi1wYW5lbCIpOwogICAgICAgICAgICBpZiAocGFuZWwgJiYgcGFuZWwuY2xhc3NMaXN0LmNvbnRhaW5zKCJoaWRkZW4iKSkgewogICAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXBsYW4tdG9nZ2xlLWJ0biIpLmNsaWNrKCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHRvTm90ZUJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgLy8gUmFtw6huZSB1biBqb3VyIGR1IG1vaXMgKDEtMzEpIGF1IGRlcm5pZXIgam91ciByw6llbCBkdSBtb2lzIHZpc8OpIOKAlAogICAgLy8gw6lxdWl2YWxlbnQgSlMgZGUgX2NsYW1wX2RheSBjw7R0w6kgc2VydmV1ciwgcG91ciBjYWxjdWxlciBkZSB2cmFpZXMKICAgIC8vIGRhdGVzIChuZXcgRGF0ZSguLi4pKSBwbHV0w7R0IHF1ZSBkZSBjb21wYXJlciBkZXMgam91cnMgdG91dCBzZXVscy4KICAgIGZ1bmN0aW9uIGNsYW1wRGF5SnMoeWVhciwgbW9udGhJbmRleCwgZGF5KSB7CiAgICAgIGNvbnN0IGxhc3REYXkgPSBuZXcgRGF0ZSh5ZWFyLCBtb250aEluZGV4ICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgICByZXR1cm4gTWF0aC5taW4oZGF5LCBsYXN0RGF5KTsKICAgIH0KCiAgICAvLyBQcm9jaGFpbmUgb2NjdXJyZW5jZSBkJ3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgw6AgcGFydGlyIGQnYXVqb3VyZCdodWkKICAgIC8vIChzdHJpY3RlbWVudCBhcHLDqHMgYXVqb3VyZCdodWkpIDogcmVnYXJkZSBjZSBtb2lzLWNpIHB1aXMsIHNpIGJlc29pbiwKICAgIC8vIGxlcyBkZXV4IG1vaXMgc3VpdmFudHMg4oCUIHV0aWxlIGVuIGZpbiBkZSBtb2lzIHF1YW5kIHBsdXMgcmllbiBuJ2VzdAogICAgLy8gw6AgdmVuaXIgZGFucyBsZSBtb2lzIGNvdXJhbnQuCiAgICBmdW5jdGlvbiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXlTdHIpIHsKICAgICAgY29uc3QgW3R5LCB0bSwgdGRdID0gdG9kYXlTdHIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdG9kYXlEYXRlID0gbmV3IERhdGUodHksIHRtIC0gMSwgdGQpOwogICAgICBmb3IgKGxldCBvZmZzZXQgPSAwOyBvZmZzZXQgPD0gMjsgb2Zmc2V0KyspIHsKICAgICAgICBjb25zdCBiYXNlID0gbmV3IERhdGUodHksIHRtIC0gMSArIG9mZnNldCwgMSk7CiAgICAgICAgY29uc3QgeSA9IGJhc2UuZ2V0RnVsbFllYXIoKTsKICAgICAgICBjb25zdCBtSWR4ID0gYmFzZS5nZXRNb250aCgpOwogICAgICAgIGNvbnN0IG1vbnRoS2V5ID0gYCR7eX0tJHtTdHJpbmcobUlkeCArIDEpLnBhZFN0YXJ0KDIsICIwIil9YDsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgY29uc3QgZGF5ID0gY2xhbXBEYXlKcyh5LCBtSWR4LCBpdGVtLmRheV9vZl9tb250aCk7CiAgICAgICAgY29uc3Qgb2NjRGF0ZSA9IG5ldyBEYXRlKHksIG1JZHgsIGRheSk7CiAgICAgICAgaWYgKG9jY0RhdGUgPiB0b2RheURhdGUpIHJldHVybiBvY2NEYXRlOwogICAgICB9CiAgICAgIHJldHVybiBudWxsOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpIHsKICAgICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIik7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CgogICAgICBjb25zdCB1cGNvbWluZyA9IGFsbFJlY3VycmluZwogICAgICAgIC5tYXAoKGl0ZW0pID0+ICh7IGl0ZW0sIGRhdGU6IG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheSkgfSkpCiAgICAgICAgLmZpbHRlcigoeCkgPT4geC5kYXRlKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBhLmRhdGUgLSBiLmRhdGUpCiAgICAgICAgLnNsaWNlKDAsIDMpOwoKICAgICAgaWYgKHVwY29taW5nLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwYW5lbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwoKICAgICAgZm9yIChjb25zdCB7IGl0ZW0sIGRhdGUgfSBvZiB1cGNvbWluZykgewogICAgICAgIGNvbnN0IGRheXMgPSBNYXRoLnJvdW5kKChkYXRlIC0gbmV3IERhdGUobmV3IERhdGUoKS5zZXRIb3VycygwLCAwLCAwLCAwKSkpIC8gODY0MDAwMDApOwogICAgICAgIGNvbnN0IGR1ZUxhYmVsID0gZGF5cyA8PSAxID8gImRlbWFpbiIgOiBgZGFucyAke2RheXN9IGpvdXJzYDsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJ1cGNvbWluZy1yZWN1cnJpbmctcm93IjsKICAgICAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGxlZnQuY2xhc3NOYW1lID0gIm5hbWUiOwogICAgICAgIGxlZnQudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CiAgICAgICAgY29uc3QgZHVlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkdWVTcGFuLmNsYXNzTmFtZSA9ICJkdWUiOwogICAgICAgIGR1ZVNwYW4udGV4dENvbnRlbnQgPSBgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChkYXRlKX0gwrcgJHtkdWVMYWJlbH1gOwogICAgICAgIGxlZnQuYXBwZW5kQ2hpbGQoZHVlU3Bhbik7CiAgICAgICAgY29uc3QgYW1vdW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAiYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQobGVmdCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGFtb3VudCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkUmVjdXJyaW5nKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIik7CiAgICAgICAgYWxsUmVjdXJyaW5nID0gaXRlbXM7CiAgICAgICAgcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKTsKICAgICAgICByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKTsKICAgICAgICB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5nc1BsYW4oKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBFeHBvcnQgKEV4Y2VsIG91IHNhdXZlZ2FyZGUgSlNPTiBjb21wbMOodGUsIHVuIHNldWwgYm91dG9uIGF2ZWMgdW4KICAgIC8vIGNob2l4IGRlIGZvcm1hdCBwbHV0w7R0IHF1ZSBkZXV4IGdyb3MgYm91dG9ucyBzw6lwYXLDqXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBFWFBPUlRfRk9STUFUUyA9IHsKICAgICAgeGxzeDogewogICAgICAgIGhpbnQ6ICJUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2hhY3VuZSBkYW5zIHNvbiBwcm9wcmUgb25nbGV0LiIsCiAgICAgICAgdXJsOiAiL2FwaS9leHBvcnQveGxzeCIsCiAgICAgICAgZmlsZW5hbWU6ICgpID0+IGBkZXBlbnNlc18ke3RvZGF5SXNvKCl9Lnhsc3hgLAogICAgICAgIHRvYXN0U3VjY2VzczogIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIiwKICAgICAgfSwKICAgICAganNvbjogewogICAgICAgIGhpbnQ6ICJBYnNvbHVtZW50IHRvdXRlcyB0ZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBvYmplY3RpZiBkJ8OpcGFyZ25lKS4gw4AgZ2FyZGVyIGRlIGPDtHTDqSA6IFN1cGFiYXNlIG5lIGZhaXQgcGFzIGRlIHNhdXZlZ2FyZGUgYXV0b21hdGlxdWUgZW4gb2ZmcmUgZ3JhdHVpdGUsIGNlIGZpY2hpZXIgZXN0IHRvbiBmaWxldCBkZSBzw6ljdXJpdMOpIGVuIGNhcyBkZSBww6lwaW4uIiwKICAgICAgICB1cmw6ICIvYXBpL2V4cG9ydC9qc29uIiwKICAgICAgICBmaWxlbmFtZTogKCkgPT4gYGthY2hpbmctc2F1dmVnYXJkZS0ke3RvZGF5SXNvKCl9Lmpzb25gLAogICAgICAgIHRvYXN0U3VjY2VzczogIlNhdXZlZ2FyZGUgdMOpbMOpY2hhcmfDqWUiLAogICAgICB9LAogICAgfTsKICAgIGxldCBjdXJyZW50RXhwb3J0Rm9ybWF0ID0gInhsc3giOwogICAgY29uc3QgZXhwb3J0Rm9ybWF0SGludEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtaGludCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtdG9nZ2xlIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIuZXhwb3J0LWZvcm1hdC1idG4iKTsKICAgICAgaWYgKCFidG4pIHJldHVybjsKICAgICAgY3VycmVudEV4cG9ydEZvcm1hdCA9IGJ0bi5kYXRhc2V0LmZvcm1hdDsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLmV4cG9ydC1mb3JtYXQtYnRuIikuZm9yRWFjaCgoYikgPT4gewogICAgICAgIGIuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYiA9PT0gYnRuKTsKICAgICAgfSk7CiAgICAgIGV4cG9ydEZvcm1hdEhpbnRFbC50ZXh0Q29udGVudCA9IEVYUE9SVF9GT1JNQVRTW2N1cnJlbnRFeHBvcnRGb3JtYXRdLmhpbnQ7CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpOwogICAgICBjb25zdCBjb25maWcgPSBFWFBPUlRfRk9STUFUU1tjdXJyZW50RXhwb3J0Rm9ybWF0XTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiR8OpbsOpcmF0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChjb25maWcudXJsLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBjb25maWcuZmlsZW5hbWUoKTsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoY29uZmlnLnRvYXN0U3VjY2Vzcyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEdhcmRlLWZvdSBnbG9iYWwgY29udHJlIGxlIGNvbXBvcnRlbWVudCBwYXIgZMOpZmF1dCBkdSBuYXZpZ2F0ZXVyIDoKICAgIC8vIGTDqXBvc2VyIHVuIGZpY2hpZXIgTidJTVBPUlRFIE/DmSBzdXIgbGEgcGFnZSAoZW4gZGVob3JzIGQndW5lIHpvbmUKICAgIC8vIHByw6l2dWUgcG91ciDDp2EpIGZhaXQgbm9ybWFsZW1lbnQgTkFWSUdVRVIgbCdvbmdsZXQgdmVycyBjZSBmaWNoaWVyCiAgICAvLyBsb2NhbCAoZmlsZTovLy4uLiksIHF1aSB0ZW50ZSBkZSBsJ2FmZmljaGVyIGNvbW1lIHVuZSBwYWdlIOKAlCBhdmVjIHVuCiAgICAvLyBncm9zIGZpY2hpZXIgb3UgdW4gZm9ybWF0IGluYXR0ZW5kdSwgw6dhIHBldXQgcGxhbnRlciBsJ29uZ2xldAogICAgLy8gKCJBw69lIGHDr2UgYcOvZSIpLiBPbiBibG9xdWUgY2UgY29tcG9ydGVtZW50IHBhcnRvdXQsIGV0IGxhIHpvbmUgZGUKICAgIC8vIGTDqXDDtHQgZMOpZGnDqWUgKHBsdXMgYmFzKSByZXByZW5kIGxhIG1haW4gc3VyIGxlIGZpY2hpZXIgZMOpcG9zw6kuCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ292ZXIiLCAoZSkgPT4gZS5wcmV2ZW50RGVmYXVsdCgpKTsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJkcm9wIiwgKGUpID0+IGUucHJldmVudERlZmF1bHQoKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gSW1wb3J0IGRlIHJlbGV2w6kgYmFuY2FpcmUgKENTViBCb3Vyc29CYW5rKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTGUgZmljaGllciBuJ2VzdCBqYW1haXMgZ2FyZMOpIGFwcsOocyBsJ2FuYWx5c2UgKG5pIGljaSwgbmkgY8O0dMOpCiAgICAvLyBzZXJ2ZXVyKSA6IHNldWwgbGUgdGFibGVhdSBgaW1wb3J0UHJldmlld1Jvd3NgIChkw6lqw6AgZGVzIHRyYW5zYWN0aW9ucwogICAgLy8gY2FuZGlkYXRlcywgcGFzIGxlIGZpY2hpZXIgYnJ1dCkgdml0IGVuIG3DqW1vaXJlIGxlIHRlbXBzIGRlIGxhIHJldnVlLgogICAgbGV0IGltcG9ydFByZXZpZXdSb3dzID0gW107IC8vIFt7IC4uLnJvdywgc2VsZWN0ZWQ6IGJvb2wgfV0KICAgIGxldCBpbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsgZXhwZW5zZToge30sIGluY29tZToge30gfTsKICAgIGNvbnN0IE1BWF9JTVBPUlRfRklMRV9TSVpFX0JZVEVTID0gMyAqIDEwMjQgKiAxMDI0OyAvLyBkb2l0IHJlc3RlciBhbGlnbsOpIGF2ZWMgbGUgYmFja2VuZAoKICAgIGNvbnN0IGltcG9ydERyb3B6b25lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWRyb3B6b25lIik7CiAgICBjb25zdCBpbXBvcnRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWZpbGUtaW5wdXQiKTsKICAgIGNvbnN0IGltcG9ydEFuYWx5emVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWFuYWx5emUtYnRuIik7CiAgICBjb25zdCBpbXBvcnRTdW1tYXJ5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXN1bW1hcnkiKTsKICAgIGNvbnN0IGltcG9ydFByZXZpZXdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcHJldmlldyIpOwogICAgY29uc3QgaW1wb3J0Um93c0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcm93cy1saXN0Iik7CiAgICBjb25zdCBpbXBvcnRTZWxlY3RlZENvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXNlbGVjdGVkLWNvdW50Iik7CgogICAgZnVuY3Rpb24gdXBkYXRlSW1wb3J0U2VsZWN0ZWRDb3VudCgpIHsKICAgICAgY29uc3QgbiA9IGltcG9ydFByZXZpZXdSb3dzLmZpbHRlcigocikgPT4gci5zZWxlY3RlZCkubGVuZ3RoOwogICAgICBpbXBvcnRTZWxlY3RlZENvdW50RWwudGV4dENvbnRlbnQgPSBgJHtufSBzw6lsZWN0aW9ubsOpZSR7biA+IDEgPyAicyIgOiAiIn0gc3VyICR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RofWA7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpLmRpc2FibGVkID0gbiA9PT0gMDsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJJbXBvcnRQcmV2aWV3KCkgewogICAgICBpbXBvcnRSb3dzTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IHJvdyBvZiBpbXBvcnRQcmV2aWV3Um93cykgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZWwuY2xhc3NOYW1lID0gImltcG9ydC1yb3ciICsgKHJvdy5zZWxlY3RlZCA/ICIiIDogIiBleGNsdWRlZCIpOwoKICAgICAgICBjb25zdCBjaGVja2JveCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgY2hlY2tib3gudHlwZSA9ICJjaGVja2JveCI7CiAgICAgICAgY2hlY2tib3guY2hlY2tlZCA9IHJvdy5zZWxlY3RlZDsKICAgICAgICBjaGVja2JveC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICByb3cuc2VsZWN0ZWQgPSBjaGVja2JveC5jaGVja2VkOwogICAgICAgICAgZWwuY2xhc3NMaXN0LnRvZ2dsZSgiZXhjbHVkZWQiLCAhcm93LnNlbGVjdGVkKTsKICAgICAgICAgIHVwZGF0ZUltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgICAgICB9KTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWFpbiI7CiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctZGVzYyI7CiAgICAgICAgY29uc3QgYW1vdW50U3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRTcGFuLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWFtb3VudCAiICsgcm93LnR5cGU7CiAgICAgICAgYW1vdW50U3Bhbi50ZXh0Q29udGVudCA9IChyb3cudHlwZSA9PT0gImV4cGVuc2UiID8gIi0iIDogIisiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChyb3cuYW1vdW50KTsKICAgICAgICBkZXNjLmFwcGVuZCgocm93LmRlc2NyaXB0aW9uIHx8ICIiKSArICIg4oCUICIpOwogICAgICAgIGRlc2MuYXBwZW5kQ2hpbGQoYW1vdW50U3Bhbik7CgogICAgICAgIGNvbnN0IG1ldGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtZXRhLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LW1ldGEiOwogICAgICAgIGxldCBtZXRhVGV4dCA9IGAke3Jvdy5leHBlbnNlX2RhdGV9IMK3ICR7cm93LmJhbmtfbGFiZWx9YDsKICAgICAgICBpZiAocm93LmlzX2ludGVybmFsX3RyYW5zZmVyKSBtZXRhVGV4dCArPSAiIMK3IHZpcmVtZW50IGludGVybmUiOwogICAgICAgIG1ldGEudGV4dENvbnRlbnQgPSBtZXRhVGV4dDsKICAgICAgICBpZiAocm93Lmxpa2VseV9kdXBsaWNhdGUpIHsKICAgICAgICAgIGNvbnN0IGR1cFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBkdXBTcGFuLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWR1cCI7CiAgICAgICAgICBkdXBTcGFuLnRleHRDb250ZW50ID0gIiDCtyBkw6lqw6AgcHLDqXNlbnRlID8iOwogICAgICAgICAgbWV0YS5hcHBlbmRDaGlsZChkdXBTcGFuKTsKICAgICAgICB9CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChtZXRhKTsKCiAgICAgICAgY29uc3QgY2F0U2VsZWN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2VsZWN0Iik7CiAgICAgICAgY29uc3QgbGFiZWxzID0gcm93LnR5cGUgPT09ICJleHBlbnNlIiA/IGltcG9ydENhdGVnb3J5TGFiZWxzLmV4cGVuc2UgOiBpbXBvcnRDYXRlZ29yeUxhYmVscy5pbmNvbWU7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhsYWJlbHMpKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBpZiAodmFsdWUgPT09IHJvdy5jYXRlZ29yeSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICAgIGNhdFNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjYXRTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4geyByb3cuY2F0ZWdvcnkgPSBjYXRTZWxlY3QudmFsdWU7IH0pOwoKICAgICAgICBlbC5hcHBlbmRDaGlsZChjaGVja2JveCk7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2F0U2VsZWN0KTsKICAgICAgICBpbXBvcnRSb3dzTGlzdEVsLmFwcGVuZENoaWxkKGVsKTsKICAgICAgfQogICAgICB1cGRhdGVJbXBvcnRTZWxlY3RlZENvdW50KCk7CiAgICB9CgogICAgLy8gR2xpc3Nlci1kw6lwb3NlciBkaXJlY3RlbWVudCBzdXIgbGEgY2FydGUgKGVuIHBsdXMgZHUgc8OpbGVjdGV1cgogICAgLy8gY2xhc3NpcXVlKSA6IG9uIHJlbXBsYWNlIGxlcyBmaWNoaWVycyBkZSBsJ2lucHV0IHZpYSBEYXRhVHJhbnNmZXIsCiAgICAvLyBwb3VyIHF1ZSBsZSByZXN0ZSBkdSBmbHV4IChib3V0b24gQW5hbHlzZXIpIHJlc3RlIGluY2hhbmfDqS4KICAgIGltcG9ydERyb3B6b25lRWwuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ292ZXIiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGltcG9ydERyb3B6b25lRWwuY2xhc3NMaXN0LmFkZCgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGltcG9ydERyb3B6b25lRWwuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ2xlYXZlIiwgKCkgPT4gewogICAgICBpbXBvcnREcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgfSk7CiAgICBpbXBvcnREcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGltcG9ydERyb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICAgIGNvbnN0IGZpbGUgPSBlLmRhdGFUcmFuc2Zlci5maWxlcyAmJiBlLmRhdGFUcmFuc2Zlci5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSByZXR1cm47CiAgICAgIGNvbnN0IGR0ID0gbmV3IERhdGFUcmFuc2ZlcigpOwogICAgICBkdC5pdGVtcy5hZGQoZmlsZSk7CiAgICAgIGltcG9ydEZpbGVJbnB1dC5maWxlcyA9IGR0LmZpbGVzOwogICAgfSk7CgogICAgaW1wb3J0QW5hbHl6ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IGltcG9ydEZpbGVJbnB1dC5maWxlcyAmJiBpbXBvcnRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgeyBzaG93VG9hc3QoIkNob2lzaXMgZCdhYm9yZCB1biBmaWNoaWVyIC5jc3YiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZmlsZS5uYW1lLnRvTG93ZXJDYXNlKCkuZW5kc1dpdGgoIi5jc3YiKSkgewogICAgICAgIHNob3dUb2FzdCgiU2V1bHMgbGVzIGZpY2hpZXJzIC5jc3Ygc29udCBhY2NlcHTDqXMgcG91ciBsJ2luc3RhbnQiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IE1BWF9JTVBPUlRfRklMRV9TSVpFX0JZVEVTKSB7CiAgICAgICAgc2hvd1RvYXN0KCJGaWNoaWVyIHRyb3Agdm9sdW1pbmV1eCAoMyBNbyBtYXhpbXVtKSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gaW1wb3J0QW5hbHl6ZUJ0bi50ZXh0Q29udGVudDsKICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGltcG9ydEFuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3Vyc+KApiI7CiAgICAgIGltcG9ydFN1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBpbXBvcnRQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGV4dHJhY3RFcnJvckRldGFpbChlcnIsIGDDiWNoZWMgZGUgbCdhbmFseXNlICgke3Jlcy5zdGF0dXN9KWApKTsKICAgICAgICB9CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgaW1wb3J0Q2F0ZWdvcnlMYWJlbHMgPSB7CiAgICAgICAgICBleHBlbnNlOiBkYXRhLmV4cGVuc2VfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICAgIGluY29tZTogZGF0YS5pbmNvbWVfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICB9OwogICAgICAgIGltcG9ydFByZXZpZXdSb3dzID0gZGF0YS5yb3dzLm1hcCgocm93KSA9PiAoewogICAgICAgICAgLi4ucm93LAogICAgICAgICAgc2VsZWN0ZWQ6ICFyb3cuaXNfaW50ZXJuYWxfdHJhbnNmZXIgJiYgIXJvdy5saWtlbHlfZHVwbGljYXRlLAogICAgICAgIH0pKTsKCiAgICAgICAgbGV0IHN1bW1hcnkgPSBgPHN0cm9uZz4ke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aH08L3N0cm9uZz4gb3DDqXJhdGlvbiR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RoID4gMSA/ICJzIiA6ICIifSBkw6l0ZWN0w6llJHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9YDsKICAgICAgICBpZiAoZGF0YS5hY2NvdW50X2JhbGFuY2UgIT0gbnVsbCkgewogICAgICAgICAgc3VtbWFyeSArPSBgIOKAlCBzb2xkZSBkdSBjb21wdGUgYXUgJHtkYXRhLmFjY291bnRfYmFsYW5jZV9kYXRlfSA6IDxzdHJvbmc+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGF0YS5hY2NvdW50X2JhbGFuY2UpfTwvc3Ryb25nPmA7CiAgICAgICAgfQogICAgICAgIGlmIChkYXRhLnNraXBwZWRfcm93cykgc3VtbWFyeSArPSBgICgke2RhdGEuc2tpcHBlZF9yb3dzfSBsaWduZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9IGlnbm9yw6llJHtkYXRhLnNraXBwZWRfcm93cyA+IDEgPyAicyIgOiAiIn0sIGlsbGlzaWJsZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9KWA7CiAgICAgICAgc3VtbWFyeSArPSAiLiBMZXMgdmlyZW1lbnRzIGludGVybmVzIGV0IGRvdWJsb25zIHByb2JhYmxlcyBzb250IGTDqWNvY2jDqXMgcGFyIGTDqWZhdXQg4oCUIHbDqXJpZmllIGF2YW50IGQnaW1wb3J0ZXIuIjsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuaW5uZXJIVE1MID0gc3VtbWFyeTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgaW1wb3J0UHJldmlld0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGltcG9ydEFuYWx5emVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBpbXBvcnRBbmFseXplQnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXRvZ2dsZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGNvbnN0IGFueVNlbGVjdGVkID0gaW1wb3J0UHJldmlld1Jvd3Muc29tZSgocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGZvciAoY29uc3Qgcm93IG9mIGltcG9ydFByZXZpZXdSb3dzKSByb3cuc2VsZWN0ZWQgPSAhYW55U2VsZWN0ZWQ7CiAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBzZWxlY3RlZCA9IGltcG9ydFByZXZpZXdSb3dzLmZpbHRlcigocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGlmIChzZWxlY3RlZC5sZW5ndGggPT09IDApIHJldHVybjsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICBgSW1wb3J0ZXIgJHtzZWxlY3RlZC5sZW5ndGh9IHRyYW5zYWN0aW9uJHtzZWxlY3RlZC5sZW5ndGggPiAxID8gInMiIDogIiJ9ID8gVsOpcmlmaWUgYmllbiBsZXMgY2F0w6lnb3JpZXMgYXZhbnQgZGUgY29uZmlybWVyLmAKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1jb21taXQtYnRuIik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkltcG9ydCBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICAgIHJvd3M6IHNlbGVjdGVkLm1hcCgocikgPT4gKHsKICAgICAgICAgICAgZXhwZW5zZV9kYXRlOiByLmV4cGVuc2VfZGF0ZSwKICAgICAgICAgICAgdHlwZTogci50eXBlLAogICAgICAgICAgICBhbW91bnQ6IHIuYW1vdW50LAogICAgICAgICAgICBjYXRlZ29yeTogci5jYXRlZ29yeSwKICAgICAgICAgICAgZGVzY3JpcHRpb246IHIuZGVzY3JpcHRpb24sCiAgICAgICAgICB9KSksCiAgICAgICAgfTsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YvY29tbWl0IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYCR7cmVzdWx0Lmluc2VydGVkfSB0cmFuc2FjdGlvbiR7cmVzdWx0Lmluc2VydGVkID4gMSA/ICJzIiA6ICIifSBpbXBvcnTDqWUke3Jlc3VsdC5pbnNlcnRlZCA+IDEgPyAicyIgOiAiIn1gKTsKICAgICAgICBpbXBvcnRQcmV2aWV3Um93cyA9IFtdOwogICAgICAgIGltcG9ydFByZXZpZXdFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICBpbXBvcnRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEltcG9ydCBnw6luw6lyaXF1ZSBwYXIgSUEgKHRvdXQgZmljaGllciAuY3N2Ly54bHN4LCBzdHJ1Y3R1cmUgcXVlbGNvbnF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbW1lIHBvdXIgbCdpbXBvcnQgQm91cnNvQmFuaywgbGUgZmljaGllciBuJ2VzdCBqYW1haXMgZ2FyZMOpIGFwcsOocwogICAgLy8gbCdhbmFseXNlIDogc2V1bGVzIGxlcyB0cmFuc2FjdGlvbnMgY2FuZGlkYXRlcyBldCBsZXMgZ3JvdXBlcyBkZQogICAgLy8gcsOpY3VycmVuY2UgZMOpdGVjdMOpcyB2aXZlbnQgZW4gbcOpbW9pcmUgbGUgdGVtcHMgZGUgbGEgcmV2dWUuCiAgICBsZXQgZ2VuZXJpY0ltcG9ydFJvd3MgPSBbXTsgLy8gW3sgLi4ucm93LCBzZWxlY3RlZDogYm9vbCB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzID0gW107IC8vIFt7IC4uLmNhbmRpZGF0ZSwgZGVjaXNpb246ICJyZWN1cnJpbmcifCJjcmVkaXQifCJpZ25vcmUiLCBlbmRfZGF0ZSB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsgZXhwZW5zZToge30sIGluY29tZToge30gfTsKICAgIGNvbnN0IE1BWF9HRU5FUklDX0lNUE9SVF9GSUxFX1NJWkVfQllURVMgPSAzICogMTAyNCAqIDEwMjQ7IC8vIGFsaWduw6kgYXZlYyBsZSBiYWNrZW5kCgogICAgY29uc3QgZ2VuZXJpY0Ryb3B6b25lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZHJvcHpvbmUiKTsKICAgIGNvbnN0IGdlbmVyaWNGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZmlsZS1pbnB1dCIpOwogICAgY29uc3QgZ2VuZXJpY0FuYWx5emVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtYW5hbHl6ZS1idG4iKTsKICAgIGNvbnN0IGdlbmVyaWNTdW1tYXJ5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc3VtbWFyeSIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctc2VjdGlvbiIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctbGlzdCIpOwogICAgY29uc3QgZ2VuZXJpY1ByZXZpZXdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1wcmV2aWV3Iik7CiAgICBjb25zdCBnZW5lcmljUm93c0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yb3dzLWxpc3QiKTsKICAgIGNvbnN0IGdlbmVyaWNTZWxlY3RlZENvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc2VsZWN0ZWQtY291bnQiKTsKCiAgICBjb25zdCBSRUNVUlJJTkdfQ0xBU1NJRklDQVRJT05fTEFCRUxTID0gewogICAgICByZWN1cnJpbmc6ICJSw6ljdXJyZW50ZSIsCiAgICAgIGNyZWRpdDogIkNyw6lkaXQgZW4gY291cnMiLAogICAgICBlbmRlZDogIkFycsOqdMOpZSIsCiAgICAgIHVuY2VydGFpbjogIsOAIGNvbmZpcm1lciIsCiAgICB9OwoKICAgIGZ1bmN0aW9uIHVwZGF0ZUdlbmVyaWNJbXBvcnRTZWxlY3RlZENvdW50KCkgewogICAgICBjb25zdCBuID0gZ2VuZXJpY0ltcG9ydFJvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKS5sZW5ndGg7CiAgICAgIGdlbmVyaWNTZWxlY3RlZENvdW50RWwudGV4dENvbnRlbnQgPSBgJHtufSBzw6lsZWN0aW9ubsOpZSR7biA+IDEgPyAicyIgOiAiIn0gc3VyICR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RofWA7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIikuZGlzYWJsZWQgPSBuID09PSAwOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRSZWN1cnJpbmdMaXN0KCkgewogICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGNhbmQgb2YgZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlIiArIChjYW5kLm5lZWRzX2NvbmZpcm1hdGlvbiA/ICIgbmVlZHMtY29uZmlybWF0aW9uIiA6ICIiKTsKCiAgICAgICAgY29uc3QgaGVhZGVyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZGVyLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLWhlYWRlciI7CiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBjYW5kLm5hbWU7CiAgICAgICAgY29uc3QgdGFnU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICB0YWdTcGFuLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLXRhZyAiICsgY2FuZC5jbGFzc2lmaWNhdGlvbjsKICAgICAgICB0YWdTcGFuLnRleHRDb250ZW50ID0gUkVDVVJSSU5HX0NMQVNTSUZJQ0FUSU9OX0xBQkVMU1tjYW5kLmNsYXNzaWZpY2F0aW9uXSB8fCBjYW5kLmNsYXNzaWZpY2F0aW9uOwogICAgICAgIGhlYWRlci5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZGVyLmFwcGVuZENoaWxkKHRhZ1NwYW4pOwoKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWV0YS5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1tZXRhIjsKICAgICAgICBjb25zdCBsYWJlbHMgPSBjYW5kLnR5cGUgPT09ICJleHBlbnNlIiA/IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5leHBlbnNlIDogZ2VuZXJpY0ltcG9ydENhdGVnb3J5TGFiZWxzLmluY29tZTsKICAgICAgICBjb25zdCBjYXRMYWJlbCA9IGxhYmVsc1tjYW5kLmNhdGVnb3J5XSB8fCBjYW5kLmNhdGVnb3J5OwogICAgICAgIG1ldGEudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY2FuZC5hbW91bnQpfSBlbnZpcm9uIMK3ICR7Y2F0TGFiZWx9IMK3IHZ1ICR7Y2FuZC5tb250aHNfc2Vlbi5sZW5ndGh9IG1vaXMgKCR7Y2FuZC5tb250aHNfc2VlblswXX0g4oaSICR7Y2FuZC5tb250aHNfc2VlbltjYW5kLm1vbnRoc19zZWVuLmxlbmd0aCAtIDFdfSlgOwogICAgICAgIGlmIChjYW5kLmluc3RhbGxtZW50X2luZm8pIHsKICAgICAgICAgIG1ldGEudGV4dENvbnRlbnQgKz0gYCDCtyDDqWNow6lhbmNlICR7Y2FuZC5pbnN0YWxsbWVudF9pbmZvLmxhc3Rfc2Vlbn0vJHtjYW5kLmluc3RhbGxtZW50X2luZm8udG90YWx9LCAke2NhbmQuaW5zdGFsbG1lbnRfaW5mby5yZW1haW5pbmd9IHJlc3RhbnRlJHtjYW5kLmluc3RhbGxtZW50X2luZm8ucmVtYWluaW5nID4gMSA/ICJzIiA6ICIifWA7CiAgICAgICAgfQoKICAgICAgICBlbC5hcHBlbmRDaGlsZChoZWFkZXIpOwogICAgICAgIGVsLmFwcGVuZENoaWxkKG1ldGEpOwoKICAgICAgICBpZiAoY2FuZC5jbGFzc2lmaWNhdGlvbiAhPT0gImVuZGVkIikgewogICAgICAgICAgY29uc3QgY2hvaWNlUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjaG9pY2VSb3cuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIjsKICAgICAgICAgIGNvbnN0IG9wdGlvbnMgPSBbCiAgICAgICAgICAgIFsicmVjdXJyaW5nIiwgIlLDqWN1cnJlbnRlIChjb250aW51ZSkiXSwKICAgICAgICAgICAgWyJjcmVkaXQiLCAiQ3LDqWRpdCAoZGF0ZSBkZSBmaW4pIl0sCiAgICAgICAgICAgIFsiaWdub3JlIiwgIk5lIHBhcyByZW5kcmUgcsOpY3VycmVudGUiXSwKICAgICAgICAgIF07CiAgICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIG9wdGlvbnMpIHsKICAgICAgICAgICAgY29uc3QgbGJsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgibGFiZWwiKTsKICAgICAgICAgICAgY29uc3QgcmFkaW8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICByYWRpby50eXBlID0gInJhZGlvIjsKICAgICAgICAgICAgcmFkaW8ubmFtZSA9IGByZWN1cnJpbmctZGVjaXNpb24tJHtjYW5kLmdyb3VwX2lkfWA7CiAgICAgICAgICAgIHJhZGlvLnZhbHVlID0gdmFsdWU7CiAgICAgICAgICAgIHJhZGlvLmNoZWNrZWQgPSBjYW5kLmRlY2lzaW9uID09PSB2YWx1ZTsKICAgICAgICAgICAgcmFkaW8uYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgICAgIGNhbmQuZGVjaXNpb24gPSB2YWx1ZTsKICAgICAgICAgICAgICByZW5kZXJHZW5lcmljSW1wb3J0UmVjdXJyaW5nTGlzdCgpOwogICAgICAgICAgICB9KTsKICAgICAgICAgICAgbGJsLmFwcGVuZENoaWxkKHJhZGlvKTsKICAgICAgICAgICAgbGJsLmFwcGVuZChsYWJlbCk7CiAgICAgICAgICAgIGNob2ljZVJvdy5hcHBlbmRDaGlsZChsYmwpOwogICAgICAgICAgfQogICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2hvaWNlUm93KTsKCiAgICAgICAgICBpZiAoY2FuZC5kZWNpc2lvbiA9PT0gImNyZWRpdCIpIHsKICAgICAgICAgICAgY29uc3QgZW5kUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICAgIGVuZFJvdy5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1lbmRkYXRlIjsKICAgICAgICAgICAgY29uc3QgZW5kTGFiZWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICAgIGVuZExhYmVsLnRleHRDb250ZW50ID0gIkZpbiBlc3RpbcOpZSA6IjsKICAgICAgICAgICAgY29uc3QgZW5kSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICBlbmRJbnB1dC50eXBlID0gImRhdGUiOwogICAgICAgICAgICBlbmRJbnB1dC52YWx1ZSA9IGNhbmQuZW5kX2RhdGUgfHwgIiI7CiAgICAgICAgICAgIGVuZElucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsgY2FuZC5lbmRfZGF0ZSA9IGVuZElucHV0LnZhbHVlOyB9KTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZExhYmVsKTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZElucHV0KTsKICAgICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoZW5kUm93KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgZW5kZWROb3RlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBlbmRlZE5vdGUuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSI7CiAgICAgICAgICBlbmRlZE5vdGUudGV4dENvbnRlbnQgPSAiU2VtYmxlIHMnw6p0cmUgYXJyw6p0w6llIHRvdXRlIHNldWxlIOKAlCBpbXBvcnTDqWUgdGVsbGUgcXVlbGxlLCBhdWN1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUuIjsKICAgICAgICAgIGVsLmFwcGVuZENoaWxkKGVuZGVkTm90ZSk7CiAgICAgICAgfQoKICAgICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmFwcGVuZENoaWxkKGVsKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRQcmV2aWV3KCkgewogICAgICBnZW5lcmljUm93c0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCByb3cgb2YgZ2VuZXJpY0ltcG9ydFJvd3MpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93IiArIChyb3cuc2VsZWN0ZWQgPyAiIiA6ICIgZXhjbHVkZWQiKTsKCiAgICAgICAgY29uc3QgY2hlY2tib3ggPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGNoZWNrYm94LnR5cGUgPSAiY2hlY2tib3giOwogICAgICAgIGNoZWNrYm94LmNoZWNrZWQgPSByb3cuc2VsZWN0ZWQ7CiAgICAgICAgY2hlY2tib3guYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgcm93LnNlbGVjdGVkID0gY2hlY2tib3guY2hlY2tlZDsKICAgICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImV4Y2x1ZGVkIiwgIXJvdy5zZWxlY3RlZCk7CiAgICAgICAgICB1cGRhdGVHZW5lcmljSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgICAgIH0pOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tYWluIjsKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kZXNjIjsKICAgICAgICBjb25zdCBhbW91bnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudFNwYW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctYW1vdW50ICIgKyByb3cudHlwZTsKICAgICAgICBhbW91bnRTcGFuLnRleHRDb250ZW50ID0gKHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyAiLSIgOiAiKyIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHJvdy5hbW91bnQpOwogICAgICAgIGRlc2MuYXBwZW5kKChyb3cucmVjdXJyaW5nX2dyb3VwX2lkID8gIvCflIEgIiA6ICIiKSArIChyb3cuZGVzY3JpcHRpb24gfHwgIiIpICsgIiDigJQgIik7CiAgICAgICAgZGVzYy5hcHBlbmRDaGlsZChhbW91bnRTcGFuKTsKCiAgICAgICAgY29uc3QgbWV0YSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1ldGEuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWV0YSI7CiAgICAgICAgbWV0YS50ZXh0Q29udGVudCA9IHJvdy5kYXRlX3ByZWNpc2lvbiA9PT0gImRheSIKICAgICAgICAgID8gYCR7cm93LmV4cGVuc2VfZGF0ZX0gwrcgJHtyb3cuc291cmNlX2xhYmVsfWAKICAgICAgICAgIDogYCR7cm93LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA3KX0gKGpvdXIgbm9uIHByw6ljaXPDqSkgwrcgJHtyb3cuc291cmNlX2xhYmVsfWA7CiAgICAgICAgaWYgKHJvdy5saWtlbHlfZHVwbGljYXRlKSB7CiAgICAgICAgICBjb25zdCBkdXBTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZHVwU3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kdXAiOwogICAgICAgICAgZHVwU3Bhbi50ZXh0Q29udGVudCA9ICIgwrcgZMOpasOgIHByw6lzZW50ZSA/IjsKICAgICAgICAgIG1ldGEuYXBwZW5kQ2hpbGQoZHVwU3Bhbik7CiAgICAgICAgfQoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobWV0YSk7CgogICAgICAgIGNvbnN0IGNhdFNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGNvbnN0IGxhYmVscyA9IHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyBnZW5lcmljSW1wb3J0Q2F0ZWdvcnlMYWJlbHMuZXhwZW5zZSA6IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5pbmNvbWU7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhsYWJlbHMpKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBpZiAodmFsdWUgPT09IHJvdy5jYXRlZ29yeSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICAgIGNhdFNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjYXRTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4geyByb3cuY2F0ZWdvcnkgPSBjYXRTZWxlY3QudmFsdWU7IH0pOwoKICAgICAgICBlbC5hcHBlbmRDaGlsZChjaGVja2JveCk7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2F0U2VsZWN0KTsKICAgICAgICBnZW5lcmljUm93c0xpc3RFbC5hcHBlbmRDaGlsZChlbCk7CiAgICAgIH0KICAgICAgdXBkYXRlR2VuZXJpY0ltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgIH0KCiAgICBnZW5lcmljRHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcmFnb3ZlciIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LmFkZCgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyYWdsZWF2ZSIsICgpID0+IHsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGdlbmVyaWNEcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgICBjb25zdCBmaWxlID0gZS5kYXRhVHJhbnNmZXIuZmlsZXMgJiYgZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBjb25zdCBkdCA9IG5ldyBEYXRhVHJhbnNmZXIoKTsKICAgICAgZHQuaXRlbXMuYWRkKGZpbGUpOwogICAgICBnZW5lcmljRmlsZUlucHV0LmZpbGVzID0gZHQuZmlsZXM7CiAgICB9KTsKCiAgICBnZW5lcmljQW5hbHl6ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IGdlbmVyaWNGaWxlSW5wdXQuZmlsZXMgJiYgZ2VuZXJpY0ZpbGVJbnB1dC5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSB7IHNob3dUb2FzdCgiQ2hvaXNpcyBkJ2Fib3JkIHVuIGZpY2hpZXIgLmNzdiBvdSAueGxzeCIsIHRydWUpOyByZXR1cm47IH0KICAgICAgY29uc3QgbG93ZXJOYW1lID0gZmlsZS5uYW1lLnRvTG93ZXJDYXNlKCk7CiAgICAgIGlmICghbG93ZXJOYW1lLmVuZHNXaXRoKCIuY3N2IikgJiYgIWxvd2VyTmFtZS5lbmRzV2l0aCgiLnhsc3giKSkgewogICAgICAgIHNob3dUb2FzdCgiRm9ybWF0cyBhY2NlcHTDqXMgOiAuY3N2IG91IC54bHN4IiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiBNQVhfR0VORVJJQ19JTVBPUlRfRklMRV9TSVpFX0JZVEVTKSB7CiAgICAgICAgc2hvd1RvYXN0KCJGaWNoaWVyIHRyb3Agdm9sdW1pbmV1eCAoMyBNbyBtYXhpbXVtKSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQ7CiAgICAgIGdlbmVyaWNBbmFseXplQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3VycyAoSUEp4oCmIjsKICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBnZW5lcmljUmVjdXJyaW5nU2VjdGlvbkVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBnZW5lcmljUHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgZmlsZSk7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvaW1wb3J0L2dlbmVyaWMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGV4dHJhY3RFcnJvckRldGFpbChlcnIsIGDDiWNoZWMgZGUgbCdhbmFseXNlICgke3Jlcy5zdGF0dXN9KWApKTsKICAgICAgICB9CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgZ2VuZXJpY0ltcG9ydENhdGVnb3J5TGFiZWxzID0gewogICAgICAgICAgZXhwZW5zZTogZGF0YS5leHBlbnNlX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgICBpbmNvbWU6IGRhdGEuaW5jb21lX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgfTsKICAgICAgICBnZW5lcmljSW1wb3J0Um93cyA9IGRhdGEucm93cy5tYXAoKHJvdykgPT4gKHsKICAgICAgICAgIC4uLnJvdywKICAgICAgICAgIHNlbGVjdGVkOiAhcm93Lmxpa2VseV9kdXBsaWNhdGUsCiAgICAgICAgfSkpOwogICAgICAgIGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzID0gKGRhdGEucmVjdXJyaW5nX2NhbmRpZGF0ZXMgfHwgW10pLm1hcCgoY2FuZCkgPT4gKHsKICAgICAgICAgIC4uLmNhbmQsCiAgICAgICAgICBkZWNpc2lvbjogY2FuZC5jbGFzc2lmaWNhdGlvbiA9PT0gImNyZWRpdCIgPyAiY3JlZGl0IiA6IGNhbmQuY2xhc3NpZmljYXRpb24gPT09ICJlbmRlZCIgPyAiaWdub3JlIiA6ICJyZWN1cnJpbmciLAogICAgICAgICAgZW5kX2RhdGU6IGNhbmQuc3VnZ2VzdGVkX2VuZF9kYXRlIHx8IG51bGwsCiAgICAgICAgfSkpOwoKICAgICAgICBsZXQgc3VtbWFyeSA9IGA8c3Ryb25nPiR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RofTwvc3Ryb25nPiBvcMOpcmF0aW9uJHtnZW5lcmljSW1wb3J0Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9IGTDqXRlY3TDqWUke2dlbmVyaWNJbXBvcnRSb3dzLmxlbmd0aCA+IDEgPyAicyIgOiAiIn0gcGFyIGwnSUFgOwogICAgICAgIGNvbnN0IHRvQ29uZmlybSA9IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzLmZpbHRlcigoYykgPT4gYy5uZWVkc19jb25maXJtYXRpb24pLmxlbmd0aDsKICAgICAgICBpZiAodG9Db25maXJtKSBzdW1tYXJ5ICs9IGAg4oCUIDxzdHJvbmc+JHt0b0NvbmZpcm19PC9zdHJvbmc+IG1vdGlmJHt0b0NvbmZpcm0gPiAxID8gInMiIDogIiJ9IGRlIHLDqWN1cnJlbmNlIMOgIGNvbmZpcm1lciBjaS1kZXNzb3VzYDsKICAgICAgICBpZiAoZGF0YS53YXJuaW5ncyAmJiBkYXRhLndhcm5pbmdzLmxlbmd0aCkgewogICAgICAgICAgc3VtbWFyeSArPSAiPGJyPiIgKyBkYXRhLndhcm5pbmdzLm1hcCgodykgPT4gYOKaoO+4jyAke3d9YCkuam9pbigiPGJyPiIpOwogICAgICAgIH0KICAgICAgICBnZW5lcmljU3VtbWFyeUVsLmlubmVySFRNTCA9IHN1bW1hcnk7CiAgICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgICAgaWYgKGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzLmxlbmd0aCkgewogICAgICAgICAgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICAgIHJlbmRlckdlbmVyaWNJbXBvcnRSZWN1cnJpbmdMaXN0KCk7CiAgICAgICAgfQogICAgICAgIGdlbmVyaWNQcmV2aWV3RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgcmVuZGVyR2VuZXJpY0ltcG9ydFByZXZpZXcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGdlbmVyaWNBbmFseXplQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC10b2dnbGUtYWxsLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBjb25zdCBhbnlTZWxlY3RlZCA9IGdlbmVyaWNJbXBvcnRSb3dzLnNvbWUoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBmb3IgKGNvbnN0IHJvdyBvZiBnZW5lcmljSW1wb3J0Um93cykgcm93LnNlbGVjdGVkID0gIWFueVNlbGVjdGVkOwogICAgICByZW5kZXJHZW5lcmljSW1wb3J0UHJldmlldygpOwogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImdlbmVyaWMtaW1wb3J0LWNvbW1pdC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgc2VsZWN0ZWQgPSBnZW5lcmljSW1wb3J0Um93cy5maWx0ZXIoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBpZiAoc2VsZWN0ZWQubGVuZ3RoID09PSAwKSByZXR1cm47CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgYEltcG9ydGVyICR7c2VsZWN0ZWQubGVuZ3RofSB0cmFuc2FjdGlvbiR7c2VsZWN0ZWQubGVuZ3RoID4gMSA/ICJzIiA6ICIifSA/IFbDqXJpZmllIGJpZW4gbGVzIGNhdMOpZ29yaWVzIGV0IGxlcyByw6ljdXJyZW5jZXMgYXZhbnQgZGUgY29uZmlybWVyLmAKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImdlbmVyaWMtaW1wb3J0LWNvbW1pdC1idG4iKTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiSW1wb3J0IGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZWN1cnJpbmdQYXlsb2FkID0gZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMKICAgICAgICAgIC5maWx0ZXIoKGMpID0+IGMuZGVjaXNpb24gPT09ICJyZWN1cnJpbmciIHx8IGMuZGVjaXNpb24gPT09ICJjcmVkaXQiKQogICAgICAgICAgLm1hcCgoYykgPT4gKHsKICAgICAgICAgICAgdHlwZTogYy50eXBlLAogICAgICAgICAgICBuYW1lOiBjLm5hbWUsCiAgICAgICAgICAgIGFtb3VudDogYy5hbW91bnQsCiAgICAgICAgICAgIGNhdGVnb3J5OiBjLmNhdGVnb3J5LAogICAgICAgICAgICBkYXlfb2ZfbW9udGg6IDEsCiAgICAgICAgICAgIHN0YXJ0X2RhdGU6IGMuc3VnZ2VzdGVkX3N0YXJ0X2RhdGUsCiAgICAgICAgICAgIGVuZF9kYXRlOiBjLmRlY2lzaW9uID09PSAiY3JlZGl0IiA/IChjLmVuZF9kYXRlIHx8IG51bGwpIDogbnVsbCwKICAgICAgICAgIH0pKTsKICAgICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgICAgdHJhbnNhY3Rpb25zOiBzZWxlY3RlZC5tYXAoKHIpID0+ICh7CiAgICAgICAgICAgIGV4cGVuc2VfZGF0ZTogci5leHBlbnNlX2RhdGUsCiAgICAgICAgICAgIHR5cGU6IHIudHlwZSwKICAgICAgICAgICAgYW1vdW50OiByLmFtb3VudCwKICAgICAgICAgICAgY2F0ZWdvcnk6IHIuY2F0ZWdvcnksCiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiByLmRlc2NyaXB0aW9uLAogICAgICAgICAgfSkpLAogICAgICAgICAgcmVjdXJyaW5nOiByZWN1cnJpbmdQYXlsb2FkLAogICAgICAgIH07CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvaW1wb3J0L2dlbmVyaWMvY29tbWl0IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBjb25zdCBwYXJ0cyA9IFtdOwogICAgICAgIGlmIChyZXN1bHQuaW5zZXJ0ZWRfdHJhbnNhY3Rpb25zKSBwYXJ0cy5wdXNoKGAke3Jlc3VsdC5pbnNlcnRlZF90cmFuc2FjdGlvbnN9IHRyYW5zYWN0aW9uJHtyZXN1bHQuaW5zZXJ0ZWRfdHJhbnNhY3Rpb25zID4gMSA/ICJzIiA6ICIifWApOwogICAgICAgIGlmIChyZXN1bHQuaW5zZXJ0ZWRfcmVjdXJyaW5nKSBwYXJ0cy5wdXNoKGAke3Jlc3VsdC5pbnNlcnRlZF9yZWN1cnJpbmd9IGNoYXJnZSR7cmVzdWx0Lmluc2VydGVkX3JlY3VycmluZyA+IDEgPyAicyIgOiAiIn0gcsOpY3VycmVudGUke3Jlc3VsdC5pbnNlcnRlZF9yZWN1cnJpbmcgPiAxID8gInMiIDogIiJ9YCk7CiAgICAgICAgc2hvd1RvYXN0KHBhcnRzLmxlbmd0aCA/IGBJbXBvcnTDqSA6ICR7cGFydHMuam9pbigiIGV0ICIpfWAgOiAiSW1wb3J0IHRlcm1pbsOpIik7CiAgICAgICAgZ2VuZXJpY0ltcG9ydFJvd3MgPSBbXTsKICAgICAgICBnZW5lcmljSW1wb3J0Q2FuZGlkYXRlcyA9IFtdOwogICAgICAgIGdlbmVyaWNQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICBnZW5lcmljU3VtbWFyeUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgZ2VuZXJpY0ZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVzZXQtYWxsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgIlN1cHByaW1lciBEw4lGSU5JVElWRU1FTlQgdG91dGVzIGxlcyBkb25uw6llcyAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcykgPyBDZXR0ZSBhY3Rpb24gZXN0IGlycsOpdmVyc2libGUuIgogICAgICApOwogICAgICBpZiAoIW9rKSByZXR1cm47CiAgICAgIC8vIERvdWJsZSBjb25maXJtYXRpb24gdnUgbGUgY2FyYWN0w6hyZSBpcnLDqXZlcnNpYmxlIGV0IGNvbXBsZXQgZGUgbCdhY3Rpb24uCiAgICAgIGNvbnN0IG9rMiA9IGF3YWl0IHNob3dDb25maXJtKCJEZXJuacOocmUgY29uZmlybWF0aW9uIDogdnJhaW1lbnQgdG91dCByw6lpbml0aWFsaXNlciA/Iik7CiAgICAgIGlmICghb2syKSByZXR1cm47CgogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpOwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3Jlc2V0LWFsbCIsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIHLDqWluaXRpYWxpc8OpZSIpOwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4gd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpLCA2MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJSw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uIjsKICAgICAgfQogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUFdBIDogaW5zdGFsbGF0aW9uIHN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGlmICgic2VydmljZVdvcmtlciIgaW4gbmF2aWdhdG9yKSB7CiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJsb2FkIiwgKCkgPT4gewogICAgICAgIG5hdmlnYXRvci5zZXJ2aWNlV29ya2VyLnJlZ2lzdGVyKCIvc3cuanMiKS5jYXRjaCgoKSA9PiB7fSk7CiAgICAgIH0pOwogICAgfQoKICAgIHBvcHVsYXRlQ2F0ZWdvcmllcygiZXhwZW5zZSIpOwogICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKCiAgICAvLyBSaWVuIGRlIHRvdXQgw6dhIChjaGFyZ2VtZW50IGRlcyBkb25uw6llcywgcmFjY291cmNpcyBQV0EuLi4pIG5lIGRvaXQKICAgIC8vIGTDqW1hcnJlciBhdmFudCBkJ2F2b2lyIHVuIGpldG9uIGRlIHNlc3Npb24gdmFsaWRlIOKAlCBzaW5vbiBsYSBwcmVtacOocmUKICAgIC8vIHJlcXXDqnRlIMOpY2hvdWVyYWl0IGp1c3RlIGF2ZWMgdW5lIDQwMSDDoCBsYSBwbGFjZSBkZSBtb250cmVyIGxlIHZlcnJvdS4KICAgIGlmIChBUElfS0VZICYmICFpbnZpdGVUb2tlbkZyb21VcmwgJiYgIXJlc2V0VG9rZW5Gcm9tVXJsKSB7CiAgICAgIHNob3dBcHAoKTsKICAgICAgKGFzeW5jIGZ1bmN0aW9uIGluaXQoKSB7CiAgICAgICAgLy8gQ2F0w6lnb3JpZXMgcGVyc28gKyBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgZCdhYm9yZCwgcG91ciBxdWUgbGVzCiAgICAgICAgLy8gbGlzdGVzIGTDqXJvdWxhbnRlcyBldCBsZSBiYW5kZWF1IHNvaWVudCBjb3JyZWN0cyBkw6hzIGxlIHByZW1pZXIKICAgICAgICAvLyByZW5kdSBwbHV0w7R0IHF1ZSBkZSAic2F1dGVyIiB1bmUgZm9pcyBsZSBzZXJ2ZXVyIHLDqXBvbmR1LgogICAgICAgIGF3YWl0IFByb21pc2UuYWxsKFtsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpLCBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSwgbG9hZEJ1ZGdldHMoKSwgbG9hZFNhdmluZ3NHb2FsKCksIGxvYWRDYXRlZ29yeVJhdGluZ3MoKV0pOwogICAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIGxvYWRSZWN1cnJpbmcoKTsKCiAgICAgICAgLy8gUmFjY291cmNpcyBQV0EgKGFwcHVpIGxvbmcgc3VyIGwnaWPDtG5lIGRlIGwnYXBwIHVuZSBmb2lzIGluc3RhbGzDqWUpIDoKICAgICAgICAvLyAvP3Nob3J0Y3V0PWFkZCBvdXZyZSBkaXJlY3RlbWVudCBsZSBmb3JtdWxhaXJlIGQnYWpvdXQsIC8/c2hvcnRjdXQ9dm9pY2UKICAgICAgICAvLyBsYW5jZSBkaXJlY3RlbWVudCBsYSBkaWN0w6llIHZvY2FsZS4KICAgICAgICBjb25zdCBzaG9ydGN1dFBhcmFtID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKS5nZXQoInNob3J0Y3V0Iik7CiAgICAgICAgaWYgKHNob3J0Y3V0UGFyYW0pIHsKICAgICAgICAgIC8vIE5ldHRvaWUgbCdVUkwgdG91dCBkZSBzdWl0ZSA6IHVuIHJlY2hhcmdlbWVudCBkZSBsYSBwYWdlIChvdSB1bgogICAgICAgICAgLy8gcGFydGFnZSBkdSBsaWVuKSBuZSBkb2l0IHBhcyByZWTDqWNsZW5jaGVyIGxlIHJhY2NvdXJjaS4KICAgICAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gImFkZCIpIHsKICAgICAgICAgICAgb3Blbk1vZGFsKCk7CiAgICAgICAgICB9IGVsc2UgaWYgKHNob3J0Y3V0UGFyYW0gPT09ICJ2b2ljZSIgJiYgIW1pY0J0bi5kaXNhYmxlZCkgewogICAgICAgICAgICBtaWNCdG4uY2xpY2soKTsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0pKCk7CiAgICB9IGVsc2UgewogICAgICBzaG93TG9ja1NjcmVlbihpbml0aWFsQXV0aFZpZXcpOwogICAgfQogIDwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K"
# END_FRONTEND_B64


@app.get("/", response_class=HTMLResponse)
def serve_frontend() -> HTMLResponse:
    if not FRONTEND_HTML_B64:
        return HTMLResponse(
            content="<h1>Frontend non généré</h1><p>Lance build.py.</p>",
            status_code=500,
        )
    html = base64.b64decode(FRONTEND_HTML_B64).decode("utf-8")
    # No-cache explicite : même installée en PWA (mode standalone, sans barre
    # d'adresse), l'app doit toujours recharger la dernière version publiée
    # au lieu de rester bloquée sur une version mise en cache par le
    # navigateur ou par Vercel.
    return HTMLResponse(content=html, headers={"Cache-Control": "no-cache, must-revalidate"})


# ---------------------------------------------------------------------------
# PWA : manifest, service worker et icônes (installation sur l'écran d'accueil)
# ---------------------------------------------------------------------------
# Icônes embarquées en base64 pour la même raison que le HTML ci-dessus :
# Vercel ne garantit pas d'inclure les fichiers non-Python du dépôt dans le
# paquet de la fonction serverless. Régénérées par build.py à partir de
# frontend/icons/*.png — ne pas éditer ces blocs à la main.
# BEGIN_ICON_192_B64
ICON_192_B64 = "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"
# END_ICON_192_B64
# BEGIN_ICON_512_B64
ICON_512_B64 = "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"
# END_ICON_512_B64
# BEGIN_ICON_512_MASKABLE_B64
ICON_512_MASKABLE_B64 = "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAaaElEQVR4nO3deZSddZ3n8e+9dWtJVWWpVIqELCRECCAooIDiirjgQreICjOtuLQ62uqZo7b2Gbu1+4zLtNPtaI+249h2zyC0oy0ugCsjaKvg1qCgICCQpYCQPZWkqlLbrTt/QM/h2CGpJFX1q6rv63VOzs0/1P3UOUXqfZ/7PM+tLOzqaQQAkEq19AAAYPoJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACA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QgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAASEgAAkJAAAICEBAAAJCQAACAhAQAACQkAAEhIAABAQgIAABISAACQkAAAgIQEAAAkJAAAICEBAAAJCQAASEgAAEBCAgAAEhIAAJCQAACAhAQAACQkAAAgIQEAAAkJAABISAAAQEICAAAS+n/hQ40A9Qig2gAAAABJRU5ErkJggg=="
# END_ICON_512_MASKABLE_B64

PWA_MANIFEST = {
    "name": "Kaching",
    "short_name": "Kaching",
    "description": "Suivi de dépenses et revenus piloté à la voix.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#0f1115",
    "theme_color": "#0f1115",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
    # Raccourcis affichés par un appui long (ou clic droit) sur l'icône de
    # l'app une fois installée — ouvrent directement le formulaire d'ajout ou
    # la dictée vocale, sans repasser par le tableau de bord. Pris en charge
    # par Android/Chrome ; ignoré silencieusement là où ce n'est pas supporté
    # (notamment iOS/Safari), donc sans risque à ajouter.
    "shortcuts": [
        {
            "name": "Ajouter une dépense",
            "short_name": "Ajouter",
            "description": "Ouvrir directement le formulaire d'ajout",
            "url": "/?shortcut=add",
            "icons": [{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"}],
        },
        {
            "name": "Dicter",
            "short_name": "Dicter",
            "description": "Lancer directement la dictée vocale",
            "url": "/?shortcut=voice",
            "icons": [{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"}],
        },
    ],
}

# Service worker minimal : pas de cache hors-ligne pour l'instant (les
# données viennent de toute façon de l'API), juste ce qu'il faut pour que
# Chrome/Android considère le site comme installable (manifest + SW avec un
# gestionnaire fetch). Un passthrough simple, sans mise en cache, pour ne
# jamais servir de données périmées.
OFFLINE_HTML = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kaching — Pas de connexion</title>
<style>
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f1115;
    color: #e5e7eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    text-align: center;
    padding: 2rem;
    box-sizing: border-box;
  }
  .card { max-width: 360px; }
  .emoji { font-size: 3rem; margin-bottom: 1rem; }
  h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
  p { color: #9aa0ac; line-height: 1.5; margin: 0 0 1.5rem; }
  button {
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 0.75rem 1.5rem;
    font-size: 1rem;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="emoji">📡</div>
    <h1>Pas de connexion</h1>
    <p>Kaching a besoin d'internet pour accéder à tes données (elles sont stockées en ligne, pas sur ton téléphone). Vérifie ta connexion et réessaie.</p>
    <button onclick="location.reload()">Réessayer</button>
  </div>
</body>
</html>"""

# Cache minimal : juste de quoi afficher une page d'erreur propre si le
# téléphone n'a pas de réseau au lancement de l'app, plutôt que l'écran
# d'erreur générique du navigateur/système. Les données elles-mêmes ne sont
# JAMAIS mises en cache ici : seule la page /offline.html (statique) l'est,
# pour ne jamais risquer d'afficher des montants périmés.
PWA_SERVICE_WORKER = """
const OFFLINE_CACHE = "kaching-offline-v1";
const OFFLINE_URL = "/offline.html";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(OFFLINE_CACHE).then((cache) => cache.add(OFFLINE_URL))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  // Seules les navigations de page (ouverture/rechargement de l'app) ont un
  // filet de secours hors-ligne. Tout le reste (API, icônes...) reste un
  // passthrough pur, sans aucune mise en cache, pour ne jamais servir de
  // données périmées.
  if (event.request.mode === "navigate") {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }
  event.respondWith(fetch(event.request));
});
"""


@app.get("/offline.html", response_class=HTMLResponse)
def serve_offline_page() -> HTMLResponse:
    return HTMLResponse(content=OFFLINE_HTML, headers={"Cache-Control": "no-cache, must-revalidate"})


@app.get("/manifest.webmanifest")
def serve_manifest() -> Response:
    return Response(
        content=json.dumps(PWA_MANIFEST),
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/sw.js")
def serve_service_worker() -> Response:
    return Response(
        content=PWA_SERVICE_WORKER,
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


@app.get("/icon-192.png")
def serve_icon_192() -> Response:
    return Response(content=base64.b64decode(ICON_192_B64), media_type="image/png")


@app.get("/icon-512.png")
def serve_icon_512() -> Response:
    return Response(content=base64.b64decode(ICON_512_B64), media_type="image/png")


@app.get("/icon-512-maskable.png")
def serve_icon_512_maskable() -> Response:
    return Response(content=base64.b64decode(ICON_512_MASKABLE_B64), media_type="image/png")


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    """Public, sans dépendance à Supabase : confirme juste que le déploiement
    Vercel + le routing FastAPI fonctionnent."""
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/db-check")
def db_check(user_id: str = Depends(require_user)) -> dict:
    """Protégé par session valide : confirme que les identifiants Supabase
    sont corrects et que la table `transactions` est lisible via la clé
    service_role (qui contourne le RLS, activé sans policy pour anon/public)."""
    client = get_supabase_client()
    try:
        result = (
            client.table("transactions")
            .select("id", count="exact")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:  # noqa: BLE001 - on veut un message clair, pas une 500 opaque
        raise HTTPException(status_code=500, detail=f"Erreur Supabase : {exc}") from exc
    return {"status": "ok", "transactions_table_reachable": True, "row_count": result.count}


# ---------------------------------------------------------------------------
# Transactions ponctuelles (dépenses + revenus) — CRUD
# ---------------------------------------------------------------------------
@app.get("/api/transactions")
def list_transactions(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    sync_recurring_occurrences(client, user_id)
    result = (
        client.table("transactions")
        .select("*")
        .eq("user_id", user_id)
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


@app.post("/api/transactions", status_code=201)
def create_transaction(tx: TransactionIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
        "type": tx.type,
        "amount": tx.amount,
        "category": (tx.category or "autre").strip() or "autre",
        "description": tx.description,
        "expense_date": (tx.expense_date or today_paris()).isoformat(),
        "user_id": user_id,
    }
    result = client.table("transactions").insert(payload).execute()
    return result.data[0]


@app.put("/api/transactions/{transaction_id}")
def update_transaction(
    transaction_id: str, tx: TransactionUpdate, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    payload: dict = {}
    data = tx.model_dump(exclude_unset=True)
    for key, value in data.items():
        if key == "description":
            # Champ explicitement nullable : un description=null envoyé par
            # le client doit effacer la description (ex: nettoyage auto d'un
            # mot-clé devenu redondant avec la catégorie), contrairement aux
            # autres champs ci-dessous où null signifie juste "pas touché".
            payload["description"] = value
            continue
        if value is None:
            continue
        if isinstance(value, date):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = (
        client.table("transactions")
        .update(payload)
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return result.data[0]


@app.delete("/api/transactions/{transaction_id}", status_code=204)
def delete_transaction(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("transactions")
        .delete()
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Transaction introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Photo de reçu en pièce jointe
# ---------------------------------------------------------------------------
# Stockée dans un bucket Supabase Storage privé ("receipts"), jamais exposée
# en public : comme pour les tables, seul ce backend (clé service_role)
# peut y lire/écrire. Le chemin de stockage est simplement l'id de la
# transaction (un seul reçu par transaction ; en réattacher un nouveau
# remplace l'ancien). Le type MIME d'origine est gardé en base pour pouvoir
# resservir l'image avec le bon Content-Type.
RECEIPTS_BUCKET = "receipts"
ALLOWED_RECEIPT_TYPES = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
MAX_RECEIPT_SIZE_BYTES = 8 * 1024 * 1024  # 8 Mo, large pour une photo de reçu au téléphone


@app.put("/api/transactions/{transaction_id}/receipt")
async def upload_receipt(
    transaction_id: str, file: UploadFile = File(...), user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    existing = (
        client.table("transactions")
        .select("id")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Transaction introuvable")

    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_RECEIPT_TYPES:
        raise HTTPException(status_code=400, detail="Format d'image non supporté (JPEG, PNG, WEBP ou HEIC uniquement)")

    data = await file.read()
    if len(data) > MAX_RECEIPT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Image trop lourde (8 Mo maximum)")

    try:
        client.storage.from_(RECEIPTS_BUCKET).upload(
            transaction_id,
            data,
            file_options={"content-type": content_type, "upsert": "true"},
        )
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(
            status_code=500,
            detail="Échec de l'envoi vers le stockage (le bucket 'receipts' existe-t-il bien dans Supabase ?)",
        ) from exc
    result = (
        client.table("transactions")
        .update({"receipt_path": transaction_id, "receipt_content_type": content_type})
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
    )
    return result.data[0]


@app.get("/api/transactions/{transaction_id}/receipt")
def get_receipt(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions")
        .select("receipt_path, receipt_content_type")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    content_type = rows[0].get("receipt_content_type") or "application/octet-stream"
    try:
        image_bytes = client.storage.from_(RECEIPTS_BUCKET).download(rows[0]["receipt_path"])
    except Exception as exc:  # noqa: BLE001 - message clair plutôt qu'une 500 opaque
        raise HTTPException(status_code=404, detail="Photo introuvable dans le stockage") from exc
    return Response(
        content=image_bytes,
        media_type=content_type,
        headers={"Cache-Control": "private, no-cache"},
    )


@app.delete("/api/transactions/{transaction_id}/receipt", status_code=204)
def delete_receipt(transaction_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    rows = (
        client.table("transactions")
        .select("receipt_path")
        .eq("id", transaction_id)
        .eq("user_id", user_id)
        .execute()
        .data
    )
    if not rows or not rows[0].get("receipt_path"):
        raise HTTPException(status_code=404, detail="Aucun reçu pour cette transaction")

    try:
        client.storage.from_(RECEIPTS_BUCKET).remove([rows[0]["receipt_path"]])
    except Exception:  # noqa: BLE001 - le fichier est peut-être déjà absent du bucket
        pass
    client.table("transactions").update(
        {"receipt_path": None, "receipt_content_type": None}
    ).eq("id", transaction_id).eq("user_id", user_id).execute()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Dépenses récurrentes — CRUD
# ---------------------------------------------------------------------------
# En plus de la définition (type, nom, montant, catégorie, jour du mois,
# dates de début/fin optionnelles), chaque occurrence déjà arrivée (jour du
# mois <= aujourd'hui) est matérialisée en vraie ligne dans `transactions`
# par `sync_recurring_occurrences` ci-dessous — c'est ce qui la fait
# apparaître dans l'historique, les filtres, l'export Excel, etc. comme
# n'importe quelle transaction. `start_date`/`end_date` (optionnelles)
# bornent la période où la charge compte, sans avoir à revenir
# supprimer/désactiver la ligne à la main (ex : un abonnement qui ne démarre
# qu'en novembre).
def _clamp_day(year: int, month: int, day: int) -> int:
    """Ramène un jour du mois (1-31) au dernier jour réel du mois visé, pour
    les charges récurrentes posées sur un jour qui n'existe pas partout
    (ex : le 31 d'un mois à 30 jours, ou le 30 février)."""
    last_day = calendar.monthrange(year, month)[1]
    return min(day, last_day)


def _month_add(year: int, month: int, delta: int) -> tuple[int, int]:
    total = (year * 12 + (month - 1)) + delta
    return total // 12, total % 12 + 1


def sync_recurring_occurrences(client, user_id: str) -> None:
    """Crée, dans `transactions`, les occurrences de charges récurrentes déjà
    arrivées qui n'ont pas encore de ligne correspondante.

    Chaque occurrence (une charge récurrente pour un mois donné) est
    identifiée de façon unique par la paire (recurring_expense_id,
    occurrence_month), ce qui évite de la créer deux fois même si cette
    fonction est appelée à chaque chargement de page. On part de la date de
    début (si posée) ou du mois de création de la charge (sinon) — jamais
    plus tôt —, pour ne pas générer rétroactivement des mois antérieurs à
    l'existence de la charge récurrente.

    Important : on ne modifie ni ne supprime jamais une transaction déjà
    créée ici, même si la charge récurrente est ensuite éditée ou supprimée.
    Une fois matérialisée, une occurrence est un fait passé (de l'argent
    réellement dépensé/reçu ce mois-là), pas une projection à recalculer.
    """
    recurring_items = client.table("recurring_expenses").select("*").eq("user_id", user_id).execute().data
    if not recurring_items:
        return

    today = today_paris()
    existing = (
        client.table("transactions")
        .select("recurring_expense_id, occurrence_month")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    existing_keys = {
        (row["recurring_expense_id"], row["occurrence_month"])
        for row in existing
        if row.get("recurring_expense_id")
    }

    new_rows: list[dict] = []
    for item in recurring_items:
        start_date = date.fromisoformat(item["start_date"]) if item.get("start_date") else None
        end_date = date.fromisoformat(item["end_date"]) if item.get("end_date") else None
        created_at = datetime.fromisoformat(item["created_at"]).date()
        year, month = (start_date.year, start_date.month) if start_date else (created_at.year, created_at.month)
        # On ne remonte jamais plus loin que le mois dernier, même si la
        # charge a été créée il y a longtemps : ça évite, au premier appel
        # après cette mise à jour, de faire apparaître d'un coup des mois et
        # des mois de transactions "fantômes" pour une charge ancienne.
        earliest = _month_add(today.year, today.month, -1)
        if (year, month) < earliest:
            year, month = earliest

        while (year, month) <= (today.year, today.month):
            day = _clamp_day(year, month, item["day_of_month"])
            occurrence_date = date(year, month, day)

            if occurrence_date > today:
                break  # les mois suivants seront encore plus loin dans le futur
            if end_date and occurrence_date > end_date:
                break  # charge terminée, rien au-delà
            if start_date and occurrence_date < start_date:
                year, month = _month_add(year, month, 1)
                continue

            occurrence_month = date(year, month, 1).isoformat()
            key = (item["id"], occurrence_month)
            if key not in existing_keys:
                new_rows.append({
                    "type": item["type"],
                    "amount": item["amount"],
                    "category": item["category"],
                    "description": item["name"],
                    "expense_date": occurrence_date.isoformat(),
                    "recurring_expense_id": item["id"],
                    "occurrence_month": occurrence_month,
                    "user_id": user_id,
                })
            year, month = _month_add(year, month, 1)

    if new_rows:
        client.table("transactions").insert(new_rows).execute()


@app.get("/api/recurring")
def list_recurring(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    result = (
        client.table("recurring_expenses")
        .select("*")
        .eq("user_id", user_id)
        .order("day_of_month")
        .execute()
    )
    return result.data


@app.post("/api/recurring", status_code=201)
def create_recurring(item: RecurringExpenseIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    payload = {
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
    result = client.table("recurring_expenses").insert(payload).execute()
    return result.data[0]


@app.put("/api/recurring/{recurring_id}")
def update_recurring(
    recurring_id: str, item: RecurringExpenseUpdate, user_id: str = Depends(require_user)
) -> dict:
    client = get_supabase_client()
    # Contrairement à update_transaction, on NE saute PAS les valeurs None :
    # c'est ce qui permet d'effacer une date de fin déjà posée (renvoyer
    # end_date: null doit bien la retirer, pas être ignoré).
    payload: dict = {}
    data = item.model_dump(exclude_unset=True)
    for key, value in data.items():
        if isinstance(value, date):
            payload[key] = value.isoformat()
        elif isinstance(value, str):
            payload[key] = value.strip()
        else:
            payload[key] = value
    if "essentiality_rating" in payload:
        # Horodate la note (comme rating_updated_at sur category_essentiality_ratings)
        # pour pouvoir afficher "noté il y a X mois" dans le Plan d'épargne.
        payload["essentiality_rated_at"] = datetime.now(timezone.utc).isoformat()
    if not payload:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    result = (
        client.table("recurring_expenses")
        .update(payload)
        .eq("id", recurring_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return result.data[0]


@app.delete("/api/recurring/{recurring_id}", status_code=204)
def delete_recurring(recurring_id: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("recurring_expenses")
        .delete()
        .eq("id", recurring_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Dépense récurrente introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Catégories personnalisées + suggestions ignorées
# ---------------------------------------------------------------------------
# En base (pas dans le navigateur) pour suivre l'utilisateur d'un appareil à
# l'autre (téléphone, tablette, ordinateur) : une catégorie créée depuis le
# bandeau de suggestion, ou une suggestion ignorée, doit se retrouver
# partout, pas seulement sur l'appareil où l'action a été faite.
@app.get("/api/custom-categories")
def list_custom_categories(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("custom_categories")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at")
        .execute()
        .data
    )


@app.post("/api/custom-categories", status_code=201)
def create_custom_category(item: CustomCategoryIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    value = item.value.strip()
    label = item.label.strip()
    if not value or not label:
        raise HTTPException(status_code=400, detail="Valeur et libellé requis")

    # Idempotent : si la catégorie existe déjà (même type + valeur) pour CET
    # utilisateur, on la renvoie telle quelle plutôt que de planter sur la
    # contrainte unique — ça évite un souci si le bandeau est validé deux
    # fois par erreur, ou sur deux appareils en même temps.
    existing = (
        client.table("custom_categories")
        .select("*")
        .eq("user_id", user_id)
        .eq("type", item.type)
        .eq("value", value)
        .execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("custom_categories").insert(
        {"type": item.type, "value": value, "label": label, "user_id": user_id}
    ).execute()
    return result.data[0]


@app.get("/api/dismissed-suggestions")
def list_dismissed_suggestions(user_id: str = Depends(require_user)) -> list[str]:
    client = get_supabase_client()
    rows = (
        client.table("dismissed_category_suggestions")
        .select("suggestion_key")
        .eq("user_id", user_id)
        .execute()
        .data
    )
    return [row["suggestion_key"] for row in rows]


@app.post("/api/dismissed-suggestions", status_code=201)
def create_dismissed_suggestion(item: DismissedSuggestionIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    key = item.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="Clé requise")

    existing = (
        client.table("dismissed_category_suggestions")
        .select("*")
        .eq("user_id", user_id)
        .eq("suggestion_key", key)
        .execute()
    ).data
    if existing:
        return existing[0]

    result = client.table("dismissed_category_suggestions").insert(
        {"suggestion_key": key, "user_id": user_id}
    ).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Budgets mensuels par catégorie
# ---------------------------------------------------------------------------
# Un seul budget par catégorie (pas par mois) : c'est un plafond reconduit
# automatiquement chaque mois, comparé aux dépenses réelles du mois en cours
# côté frontend.
@app.get("/api/budgets")
def list_budgets(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return client.table("budgets").select("*").eq("user_id", user_id).execute().data


@app.put("/api/budgets")
def upsert_budget(item: BudgetIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    category = item.category.strip().lower()

    existing = (
        client.table("budgets")
        .select("*")
        .eq("user_id", user_id)
        .eq("category", category)
        .execute()
        .data
    )
    if existing:
        result = (
            client.table("budgets")
            .update({"amount": item.amount})
            .eq("user_id", user_id)
            .eq("category", category)
            .execute()
        )
        return result.data[0]

    result = client.table("budgets").insert(
        {"category": category, "amount": item.amount, "user_id": user_id}
    ).execute()
    return result.data[0]


@app.delete("/api/budgets/{category}", status_code=204)
def delete_budget(category: str, user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    result = (
        client.table("budgets")
        .delete()
        .eq("user_id", user_id)
        .eq("category", category)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Budget introuvable")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Objectif d'épargne mensuel (une seule ligne globale, pas par catégorie)
# ---------------------------------------------------------------------------
@app.get("/api/savings-goal")
def get_savings_goal(user_id: str = Depends(require_user)) -> dict | None:
    client = get_supabase_client()
    rows = (
        client.table("savings_goal")
        .select("*")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    return rows[0] if rows else None


@app.put("/api/savings-goal")
def upsert_savings_goal(item: SavingsGoalIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    existing = (
        client.table("savings_goal")
        .select("id")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    if existing:
        result = (
            client.table("savings_goal")
            .update({"monthly_target": item.monthly_target})
            .eq("id", existing[0]["id"])
            .eq("user_id", user_id)
            .execute()
        )
        return result.data[0]

    result = client.table("savings_goal").insert(
        {"monthly_target": item.monthly_target, "user_id": user_id}
    ).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Plan d'épargne — note d'essentialité (1 à 5) par catégorie de dépense,
# donnée par la PERSONNE elle-même (jamais déduite ni jugée par l'IA), pour
# calculer une économie potentielle si cet argent était redirigé vers
# l'épargne. Même principe pour les charges récurrentes, mais via
# `essentiality_rating` directement sur /api/recurring (PUT), chaque charge
# ayant déjà un montant propre — pas besoin d'une moyenne comme ici.
# ---------------------------------------------------------------------------
@app.get("/api/category-ratings")
def list_category_ratings(user_id: str = Depends(require_user)) -> list[dict]:
    client = get_supabase_client()
    return (
        client.table("category_essentiality_ratings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
        .data
    )


@app.put("/api/category-ratings")
def upsert_category_rating(item: CategoryRatingIn, user_id: str = Depends(require_user)) -> dict:
    client = get_supabase_client()
    category = item.category.strip().lower()
    existing = (
        client.table("category_essentiality_ratings")
        .select("id")
        .eq("user_id", user_id)
        .eq("category", category)
        .limit(1)
        .execute()
        .data
    )
    now = datetime.now(timezone.utc).isoformat()
    if existing:
        result = (
            client.table("category_essentiality_ratings")
            .update({"rating": item.rating, "rating_updated_at": now})
            .eq("id", existing[0]["id"])
            .eq("user_id", user_id)
            .execute()
        )
        return result.data[0]

    result = client.table("category_essentiality_ratings").insert(
        {"user_id": user_id, "category": category, "rating": item.rating, "rating_updated_at": now}
    ).execute()
    return result.data[0]


# ---------------------------------------------------------------------------
# Réinitialisation complète (données de test)
# ---------------------------------------------------------------------------
# Supprime TOUT : transactions, charges récurrentes, catégories perso,
# suggestions ignorées et budgets. Irréversible, protégé par la clé API
# comme le reste, avec une confirmation forte côté frontend.
_RESET_TABLES = [
    "transactions",
    "recurring_expenses",
    "custom_categories",
    "dismissed_category_suggestions",
    "budgets",
    "savings_goal",
    "category_essentiality_ratings",
]
# UUID nil : ne correspond jamais à une ligne réelle, donc ce filtre revient
# à "toutes les lignes" — l'API Supabase (postgrest) exige un filtre sur delete.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


@app.delete("/api/reset-all", status_code=204)
def reset_all(user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()

    # On récupère la liste des propres transactions de l'utilisateur AVANT
    # de supprimer quoi que ce soit, pour pouvoir nettoyer ses reçus dans le
    # Storage ensuite (le bucket est partagé entre tous les comptes, donc on
    # ne doit toucher qu'aux fichiers qui lui appartiennent).
    try:
        own_tx_ids = {
            row["id"]
            for row in client.table("transactions").select("id").eq("user_id", user_id).execute().data
        }
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas faire échouer le reset des tables
        own_tx_ids = set()

    for table_name in _RESET_TABLES:
        client.table(table_name).delete().eq("user_id", user_id).execute()

    # Les photos de reçus vivent dans le Storage, pas dans une table : les
    # effacer séparément, sinon "tout réinitialiser" laisserait les anciennes
    # photos orphelines dans le bucket (non listées nulle part, mais toujours
    # stockées et comptant dans le quota Supabase).
    try:
        if own_tx_ids:
            receipt_files = client.storage.from_(RECEIPTS_BUCKET).list(options={"limit": 1000})
            paths = [f["name"] for f in receipt_files if f.get("name") in own_tx_ids]
            if paths:
                client.storage.from_(RECEIPTS_BUCKET).remove(paths)
    except Exception:  # noqa: BLE001 - best-effort, ne doit pas faire échouer le reset des tables
        pass

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Sauvegarde complète (JSON brut de toutes les tables) — Supabase ne fait pas
# de sauvegarde automatique en offre gratuite ; ce fichier est le filet de
# sécurité en cas de suppression accidentelle ou de pépin côté Supabase. Ne
# couvre pas les photos de reçus elles-mêmes (binaires), seulement les
# chemins qui y pointent (receipt_path) — les fichiers restent dans le bucket
# Storage, qui a sa propre durabilité côté Supabase.
# ---------------------------------------------------------------------------
@app.get("/api/export/json")
def export_json(user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    sync_recurring_occurrences(client, user_id)

    backup: dict = {
        "app": "Kaching",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for table_name in _RESET_TABLES:
        backup[table_name] = client.table(table_name).select("*").eq("user_id", user_id).execute().data

    payload = json.dumps(backup, indent=2, ensure_ascii=False, default=str)
    filename = f"kaching-sauvegarde-{today_paris().isoformat()}.json"
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Export Excel
# ---------------------------------------------------------------------------
@app.get("/api/export/xlsx")
def export_xlsx(user_id: str = Depends(require_user)) -> Response:
    client = get_supabase_client()
    sync_recurring_occurrences(client, user_id)
    transactions = (
        client.table("transactions")
        .select("*")
        .eq("user_id", user_id)
        .order("expense_date", desc=True)
        .order("created_at", desc=True)
        .execute()
    ).data
    recurring = (
        client.table("recurring_expenses")
        .select("*")
        .eq("user_id", user_id)
        .order("day_of_month")
        .execute()
    ).data
    category_ratings = (
        client.table("category_essentiality_ratings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    ).data

    # Import différé : openpyxl n'est utile que pour cette seule route, pas
    # besoin de l'importer (et de ralentir le démarrage de la fonction) pour
    # le reste de l'API.
    from io import BytesIO

    from openpyxl import Workbook
    from openpyxl.chart import BarChart, PieChart, Reference
    from openpyxl.chart.series import DataPoint
    from openpyxl.chart.shapes import GraphicalProperties
    from openpyxl.styles import Font, PatternFill

    type_labels = {"expense": "Dépense", "income": "Revenu"}

    # Mêmes couleurs que le site (voir CHART_COLORS côté frontend) pour que
    # l'export ressemble au tableau de bord : rouge pour les dépenses, vert
    # pour les revenus, et la même palette cyclique pour les catégories.
    COLOR_EXPENSE = "EF4444"
    COLOR_INCOME = "22C55E"
    COLOR_ACCENT = "3B82F6"
    CHART_COLORS = ["3B82F6", "22C55E", "EF4444", "F59E0B", "A855F7", "14B8A6", "EC4899", "64748B"]
    HEADER_FILL = PatternFill(start_color="EEF2FF", end_color="EEF2FF", fill_type="solid")

    def category_colors(rows: list[tuple[str, float]]) -> list[DataPoint]:
        return [
            DataPoint(idx=i, spPr=GraphicalProperties(solidFill=CHART_COLORS[i % len(CHART_COLORS)]))
            for i in range(len(rows))
        ]

    # --- Agrégats pour le résumé (totaux, camemberts, évolution mensuelle) ---
    total_expenses = 0.0
    total_income = 0.0
    expense_category_totals: dict[str, float] = {}
    income_category_totals: dict[str, float] = {}
    monthly_totals: dict[str, dict[str, float]] = {}
    for tx in transactions:
        amount = float(tx["amount"])
        month_key = tx["expense_date"][:7]
        monthly_totals.setdefault(month_key, {"expense": 0.0, "income": 0.0})
        monthly_totals[month_key][tx["type"]] += amount
        if tx["type"] == "expense":
            total_expenses += amount
            expense_category_totals[tx["category"]] = expense_category_totals.get(tx["category"], 0.0) + amount
        else:
            total_income += amount
            income_category_totals[tx["category"]] = income_category_totals.get(tx["category"], 0.0) + amount
    expense_category_rows = sorted(expense_category_totals.items(), key=lambda kv: kv[1], reverse=True)
    income_category_rows = sorted(income_category_totals.items(), key=lambda kv: kv[1], reverse=True)
    month_keys = sorted(monthly_totals)
    solde = total_income - total_expenses

    wb = Workbook()
    ws_summary = wb.active
    ws_summary.title = "Résumé"
    ws_summary["A1"] = "Résumé financier"
    ws_summary["A1"].font = Font(bold=True, size=14, color=COLOR_ACCENT)

    ws_summary["A3"] = "Solde"
    ws_summary["B3"] = solde
    ws_summary["A4"] = "Total dépenses"
    ws_summary["B4"] = total_expenses
    ws_summary["A5"] = "Total revenus"
    ws_summary["B5"] = total_income
    ws_summary.cell(row=3, column=1).font = Font(bold=True)
    ws_summary.cell(row=3, column=2).font = Font(bold=True, color=COLOR_INCOME if solde >= 0 else COLOR_EXPENSE)
    ws_summary.cell(row=4, column=1).font = Font(bold=True, color=COLOR_EXPENSE)
    ws_summary.cell(row=4, column=2).font = Font(color=COLOR_EXPENSE)
    ws_summary.cell(row=5, column=1).font = Font(bold=True, color=COLOR_INCOME)
    ws_summary.cell(row=5, column=2).font = Font(color=COLOR_INCOME)

    def write_category_section(title: str, header_row: int, rows: list[tuple[str, float]], tx_type: str) -> int:
        """Écrit le titre de section + le tableau Catégorie/Montant à partir de
        `header_row`, et renvoie la dernière ligne utilisée (ou header_row si
        `rows` est vide, pour que l'appelant puisse quand même avancer)."""
        ws_summary.cell(row=header_row - 1, column=1, value=title).font = Font(bold=True, color=COLOR_ACCENT)
        ws_summary.cell(row=header_row, column=1, value="Catégorie")
        ws_summary.cell(row=header_row, column=2, value="Montant (€)")
        for col in (1, 2):
            cell = ws_summary.cell(row=header_row, column=col)
            cell.font = Font(bold=True)
            cell.fill = HEADER_FILL
        start_row = header_row + 1
        for i, (cat, amount) in enumerate(rows):
            row = start_row + i
            ws_summary.cell(row=row, column=1, value=category_label(cat, tx_type))
            ws_summary.cell(row=row, column=2, value=amount)
        return start_row + len(rows) - 1 if rows else header_row

    # Les deux camemberts sont anchorés à intervalle fixe en colonne D, assez
    # espacés (17 lignes) pour ne jamais se chevaucher quel que soit le
    # nombre de catégories listées en colonnes A/B à côté.
    cat_header_row = 7
    cat_end_row = write_category_section(
        "Dépenses par catégorie", cat_header_row, expense_category_rows, "expense"
    )
    if expense_category_rows:
        pie_expense = PieChart()
        pie_expense.title = "Répartition des dépenses par catégorie"
        data = Reference(ws_summary, min_col=2, min_row=cat_header_row + 1, max_row=cat_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=cat_header_row + 1, max_row=cat_end_row)
        pie_expense.add_data(data, titles_from_data=False)
        pie_expense.set_categories(cats)
        pie_expense.series[0].data_points = category_colors(expense_category_rows)
        pie_expense.height = 8
        pie_expense.width = 13
        ws_summary.add_chart(pie_expense, "D3")

    inc_header_row = cat_end_row + 3
    inc_end_row = write_category_section(
        "Revenus par catégorie", inc_header_row, income_category_rows, "income"
    )
    if income_category_rows:
        pie_income = PieChart()
        pie_income.title = "Répartition des revenus par catégorie"
        data = Reference(ws_summary, min_col=2, min_row=inc_header_row + 1, max_row=inc_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=inc_header_row + 1, max_row=inc_end_row)
        pie_income.add_data(data, titles_from_data=False)
        pie_income.set_categories(cats)
        pie_income.series[0].data_points = category_colors(income_category_rows)
        pie_income.height = 8
        pie_income.width = 13
        ws_summary.add_chart(pie_income, "D20")

    month_header_row = inc_end_row + 3
    ws_summary.cell(row=month_header_row - 1, column=1, value="Évolution mensuelle").font = Font(
        bold=True, color=COLOR_ACCENT
    )
    ws_summary.cell(row=month_header_row, column=1, value="Mois")
    ws_summary.cell(row=month_header_row, column=2, value="Dépenses")
    ws_summary.cell(row=month_header_row, column=3, value="Revenus")
    for col in (1, 2, 3):
        cell = ws_summary.cell(row=month_header_row, column=col)
        cell.font = Font(bold=True)
        cell.fill = HEADER_FILL
    month_start_row = month_header_row + 1
    for i, month_key in enumerate(month_keys):
        row = month_start_row + i
        ws_summary.cell(row=row, column=1, value=month_key)
        ws_summary.cell(row=row, column=2, value=monthly_totals[month_key]["expense"]).font = Font(color=COLOR_EXPENSE)
        ws_summary.cell(row=row, column=3, value=monthly_totals[month_key]["income"]).font = Font(color=COLOR_INCOME)
    month_end_row = month_start_row + len(month_keys) - 1

    if month_keys:
        bar = BarChart()
        bar.type = "col"
        bar.title = "Évolution mensuelle (dépenses vs revenus)"
        data = Reference(ws_summary, min_col=2, max_col=3, min_row=month_header_row, max_row=month_end_row)
        cats = Reference(ws_summary, min_col=1, min_row=month_start_row, max_row=month_end_row)
        bar.add_data(data, titles_from_data=True)
        bar.set_categories(cats)
        bar.series[0].graphicalProperties.solidFill = COLOR_EXPENSE
        bar.series[1].graphicalProperties.solidFill = COLOR_INCOME
        bar.height = 8
        bar.width = 15
        ws_summary.add_chart(bar, "D37")

    for col_letter, width in zip("ABC", [24, 14, 14]):
        ws_summary.column_dimensions[col_letter].width = width

    # --- Transactions : deux blocs de colonnes séparés (dépenses / revenus) ---
    # plutôt qu'une seule liste mélangée triée par date — plus lisible, en
    # particulier avec beaucoup de lignes des deux types.
    ws_tx = wb.create_sheet("Transactions")
    expense_txs = [tx for tx in transactions if tx["type"] == "expense"]
    income_txs = [tx for tx in transactions if tx["type"] == "income"]

    def write_tx_block(title: str, start_col: int, rows: list[dict], color: str) -> None:
        col_letters = [chr(ord("A") + start_col - 1 + i) for i in range(4)]
        ws_tx.cell(row=1, column=start_col, value=title).font = Font(bold=True, color=COLOR_ACCENT)
        headers = ["Date", "Catégorie", "Montant (€)", "Description"]
        for i, header in enumerate(headers):
            cell = ws_tx.cell(row=2, column=start_col + i, value=header)
            cell.font = Font(bold=True)
            cell.fill = HEADER_FILL
        for r, tx in enumerate(rows):
            row = 3 + r
            ws_tx.cell(row=row, column=start_col, value=tx["expense_date"])
            ws_tx.cell(row=row, column=start_col + 1, value=category_label(tx["category"], tx["type"]))
            ws_tx.cell(row=row, column=start_col + 2, value=float(tx["amount"])).font = Font(color=color)
            ws_tx.cell(row=row, column=start_col + 3, value=tx.get("description") or "")
        for col_letter, width in zip(col_letters, [12, 14, 12, 42]):
            ws_tx.column_dimensions[col_letter].width = width

    write_tx_block("Dépenses", 1, expense_txs, COLOR_EXPENSE)  # colonnes A-D
    write_tx_block("Revenus", 6, income_txs, COLOR_INCOME)  # colonnes F-I (E = séparateur)

    ws_rec = wb.create_sheet("Récurrentes")
    ws_rec.append([
        "Type", "Nom", "Montant (€)", "Catégorie", "Jour du mois", "Date de début", "Date de fin",
        "Essentialité (1-5)",
    ])
    for cell in ws_rec[1]:
        cell.font = Font(bold=True)
        cell.fill = HEADER_FILL
    for item in recurring:
        rec_type = item.get("type") or "expense"
        ws_rec.append([
            type_labels.get(rec_type, rec_type),
            item["name"],
            float(item["amount"]),
            category_label(item["category"], rec_type),
            item["day_of_month"],
            item.get("start_date") or "",
            item.get("end_date") or "",
            item.get("essentiality_rating") or "",
        ])
        ws_rec.cell(row=ws_rec.max_row, column=3).font = Font(
            color=COLOR_INCOME if rec_type == "income" else COLOR_EXPENSE
        )
    for col_letter, width in zip("ABCDEFGH", [10, 24, 12, 14, 12, 14, 14, 16]):
        ws_rec.column_dimensions[col_letter].width = width

    # Plan d'épargne : notes d'essentialité par catégorie (celles des charges
    # récurrentes sont déjà dans la colonne ci-dessus) — uniquement si
    # l'utilisateur en a renseigné au moins une.
    if category_ratings:
        ws_plan = wb.create_sheet("Plan d'épargne")
        ws_plan.append(["Catégorie", "Essentialité (1-5)"])
        for cell in ws_plan[1]:
            cell.font = Font(bold=True)
            cell.fill = HEADER_FILL
        for rating_row in sorted(category_ratings, key=lambda r: r["category"]):
            ws_plan.append([
                category_label(rating_row["category"], "expense"),
                rating_row["rating"],
            ])
        for col_letter, width in zip("AB", [24, 16]):
            ws_plan.column_dimensions[col_letter].width = width

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    filename = f"depenses_{today_paris().isoformat()}.xlsx"
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
MAX_BANK_IMPORT_COMMIT_ROWS = 2000

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


class BankImportRow(BaseModel):
    row_index: int
    expense_date: date
    type: TransactionType
    amount: float
    description: str
    category: str
    bank_label: str
    is_internal_transfer: bool
    likely_duplicate: bool


class BankImportCommitRow(BaseModel):
    expense_date: date
    type: TransactionType
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None


class BankImportCommitRequest(BaseModel):
    rows: list[BankImportCommitRow] = Field(min_length=1, max_length=MAX_BANK_IMPORT_COMMIT_ROWS)


@app.post("/api/import/bank-csv", response_model=None)
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


@app.post("/api/import/bank-csv/commit", status_code=201)
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
MAX_GENERIC_IMPORT_ENTRIES = 600

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


class GenericImportCommitTransaction(BaseModel):
    expense_date: date
    type: TransactionType
    amount: float = Field(gt=0)
    category: str = "autre"
    description: str | None = None


class GenericImportCommitRecurring(BaseModel):
    type: TransactionType = "expense"
    name: str = Field(min_length=1)
    amount: float = Field(gt=0)
    category: str = "autre"
    day_of_month: int = Field(default=1, ge=1, le=31)
    start_date: date | None = None
    end_date: date | None = None


class GenericImportCommitRequest(BaseModel):
    transactions: list[GenericImportCommitTransaction] = Field(
        default_factory=list, max_length=MAX_GENERIC_IMPORT_ENTRIES
    )
    recurring: list[GenericImportCommitRecurring] = Field(default_factory=list, max_length=50)


@app.post("/api/import/generic", response_model=None)
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


@app.post("/api/import/generic/commit", status_code=201)
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
