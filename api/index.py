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
        raise HTTPException(status_code=502, detail=f"Erreur API Anthropic : {exc}") from exc

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
        raise HTTPException(status_code=502, detail=f"Erreur API Anthropic : {exc}") from exc

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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyIgb25lcnJvcj0iY29uc29sZS5lcnJvcignQ2hhcnQuanMgOiDDqWNoZWMgZHUgcHJlbWllciBjaGFyZ2VtZW50IGRlcHVpcyBsZSBDRE4uJykiPjwvc2NyaXB0Pgo8c3R5bGU+CiAgOnJvb3QgewogICAgY29sb3Itc2NoZW1lOiBkYXJrOwogICAgLS1iZzogIzBmMTExNTsKICAgIC0tc3VyZmFjZTogIzFhMWQyNDsKICAgIC0tc3VyZmFjZS0yOiAjMjIyNjJmOwogICAgLS1ib3JkZXI6ICMyYTJlMzg7CiAgICAtLXRleHQ6ICNlNmU2ZTY7CiAgICAtLXRleHQtZGltOiAjOWFhMGFjOwogICAgLS1hY2NlbnQ6ICMzYjgyZjY7CiAgICAtLWFjY2VudC1kaW06ICMxZDRlZDg7CiAgICAtLWRhbmdlcjogI2VmNDQ0NDsKICAgIC0tc3VjY2VzczogIzIyYzU1ZTsKICAgIC0tcmFkaXVzOiAxNHB4OwogIH0KICAqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogIGJvZHkgewogICAgbWFyZ2luOiAwOwogICAgbWluLWhlaWdodDogMTAwdmg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIHNhbnMtc2VyaWY7CiAgICBwYWRkaW5nLWJvdHRvbTogNnJlbTsKICB9CiAgaGVhZGVyIHsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIDFyZW07CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgfQogIGgxIHsgZm9udC1zaXplOiAxLjNyZW07IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAuc3VidGl0bGUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuOXJlbTsgbWFyZ2luOiAwOyB9CgogIC50YWJzIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtd3JhcDogd3JhcDsKICAgIGdhcDogMC41cmVtOwogIH0KICAudGFiLWJ0biB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50YWItYnRuLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CgogIC8qIFN1ciBwZXRpdCDDqWNyYW4sIGxhIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciAobWVudSAiYnVyZ2VyIikKICAgICBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIGVuIHBsdXNpZXVycyBsaWduZXMgOiBwbHVzIGRlIHBsYWNlIHBvdXIgbGUKICAgICBjb250ZW51LCBldCBkZXMgbGliZWxsw6lzIHRvdWpvdXJzIGxpc2libGVzIGVuIGVudGllci4gKi8KICAubWVudS10b2dnbGUtYnRuIHsKICAgIGRpc3BsYXk6IG5vbmU7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiAxcmVtOwogICAgei1pbmRleDogMzA7CiAgICB3aWR0aDogNDJweDsKICAgIGhlaWdodDogNDJweDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuMnJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLm5hdi1kcmF3ZXItYmFja2Ryb3AgewogICAgZGlzcGxheTogbm9uZTsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIHotaW5kZXg6IDI1OwogIH0KICBAbWVkaWEgKG1heC13aWR0aDogNjQwcHgpIHsKICAgIC5tZW51LXRvZ2dsZS1idG4geyBkaXNwbGF5OiBmbGV4OyB9CiAgICBoZWFkZXIgeyBwYWRkaW5nLWxlZnQ6IDMuNzVyZW07IH0KICAgIC50YWJzIHsKICAgICAgcG9zaXRpb246IGZpeGVkOwogICAgICB0b3A6IDA7CiAgICAgIGxlZnQ6IDA7CiAgICAgIGJvdHRvbTogMDsKICAgICAgZmxleC13cmFwOiBub3dyYXA7CiAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICAgIHdpZHRoOiAyNDBweDsKICAgICAgbWF4LXdpZHRoOiA4MHZ3OwogICAgICBtYXJnaW46IDA7CiAgICAgIHBhZGRpbmc6IDQuNXJlbSAxcmVtIDEuNXJlbTsKICAgICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICAgIGJvcmRlci1yaWdodDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICAgIHotaW5kZXg6IDI2OwogICAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTEwMCUpOwogICAgICB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMC4ycyBlYXNlOwogICAgICBvdmVyZmxvdy15OiBhdXRvOwogICAgfQogICAgLnRhYi1idG4geyBmbGV4OiBub25lOyB3aWR0aDogMTAwJTsgdGV4dC1hbGlnbjogbGVmdDsgfQogICAgYm9keS5uYXYtZHJhd2VyLW9wZW4gLnRhYnMgeyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMCk7IH0KICAgIGJvZHkubmF2LWRyYXdlci1vcGVuIC5uYXYtZHJhd2VyLWJhY2tkcm9wIHsgZGlzcGxheTogYmxvY2s7IH0KICB9CgogIC5zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgZmxleC13cmFwOiB3cmFwOwogIH0KICAuc3VtbWFyeS1jYXJkIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDEwMHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxcmVtOwogIH0KICAuc3VtbWFyeS1jYXJkIC5sYWJlbCB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlIHsgZm9udC1zaXplOiAxLjJyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbjogMDsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLnBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUubmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudG9vbHRpcC1ob3N0IHsgcG9zaXRpb246IHJlbGF0aXZlOyBjdXJzb3I6IGhlbHA7IH0KICAuY3VzdG9tLXRvb2x0aXAgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgbGVmdDogNTAlOwogICAgYm90dG9tOiBjYWxjKDEwMCUgKyAwLjZyZW0pOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoNHB4KTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNTVyZW0gMC43NXJlbTsKICAgIGZvbnQtc2l6ZTogMC43OHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogICAgdGV4dC1hbGlnbjogbGVmdDsKICAgIGJveC1zaGFkb3c6IDAgOHB4IDIwcHggcmdiYSgwLCAwLCAwLCAwLjM1KTsKICAgIG9wYWNpdHk6IDA7CiAgICBwb2ludGVyLWV2ZW50czogbm9uZTsKICAgIHRyYW5zaXRpb246IG9wYWNpdHkgMC4xMnMgZWFzZSwgdHJhbnNmb3JtIDAuMTJzIGVhc2U7CiAgICB6LWluZGV4OiAyMDsKICB9CiAgLmN1c3RvbS10b29sdGlwOjphZnRlciB7CiAgICBjb250ZW50OiAiIjsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMTAwJTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJvcmRlcjogNnB4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgYm9yZGVyLXRvcC1jb2xvcjogdmFyKC0tc3VyZmFjZS0yKTsKICB9CiAgLmN1c3RvbS10b29sdGlwLnZpc2libGUgewogICAgb3BhY2l0eTogMTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDApOwogICAgcG9pbnRlci1ldmVudHM6IGF1dG87CiAgfQoKICBtYWluIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICB9CgogIC53ZWVrLXN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogLTAuNHJlbSBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBmb250LXNpemU6IDAuODJyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwLjlyZW0gMS4xcmVtOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1hY2NlbnQtZGltKTsKICB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24uaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uIHAgeyBtYXJnaW46IDAgMCAwLjdyZW07IGZvbnQtc2l6ZTogMC44OHJlbTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LXdyYXA6IHdyYXA7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgc2VsZWN0LAogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIGlucHV0W3R5cGU9InRleHQiXSB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjRyZW0gMC42cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnRuLXByaW1hcnktc20sIC5idG4tc2Vjb25kYXJ5LXNtIHsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjhyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5idG4tcHJpbWFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiAjZmZmOyB9CiAgLmJ0bi1zZWNvbmRhcnktc20geyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoKICAuZmlsdGVyLWJhciB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgfQogIC5maWx0ZXItYmFyIGlucHV0LAogIC5maWx0ZXItYmFyIHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIGZsZXg6IDEgMSAxMzBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgI2ZpbHRlci1zZWFyY2ggeyBmbGV4OiAxIDEgMTAwJTsgfQoKICAudHgtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC50eC1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLnR4LWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50eC1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnR4LXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyB9CiAgLmNhdGVnb3J5LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWRhdGUgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudHgtcmVjdXJyaW5nLWJhZGdlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBvcGFjaXR5OiAwLjc7IGN1cnNvcjogaGVscDsgfQogIC50eC1yZWNlaXB0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43NXJlbTsKICAgIG9wYWNpdHk6IDAuODU7CiAgICBiYWNrZ3JvdW5kOiBub25lOwogICAgYm9yZGVyOiBub25lOwogICAgcGFkZGluZzogMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGxpbmUtaGVpZ2h0OiAxOwogIH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyAuY2hhcnQtd3JhcCB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQoKICAvKiBTw6lsZWN0ZXVyIGR1IHRhYmxlYXUgZGUgYm9yZCA6IHVuIHNldWwgZ3JhcGhpcXVlL2Jsb2MgYWZmaWNow6kgw6AgbGEgZm9pcwogICAgIChhdSBsaWV1IGRlcyA3IGVtcGlsw6lzKSwgY2hvaXNpIHZpYSB1bmUgcmFuZ8OpZSBkZSBwdWNlcyBkw6lmaWxhbnRlLiAqLwogIC5kYXNoYm9hcmQtY2hpcC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC41cmVtOwogICAgb3ZlcmZsb3cteDogYXV0bzsKICAgIHBhZGRpbmctYm90dG9tOiAwLjI1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICAgIC13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOiB0b3VjaDsKICB9CiAgLmRhc2hib2FyZC1jaGlwLXJvdzo6LXdlYmtpdC1zY3JvbGxiYXIgeyBoZWlnaHQ6IDRweDsgfQogIC5kYXNoYm9hcmQtY2hpcCB7CiAgICBmbGV4OiBub25lOwogICAgcGFkZGluZzogMC41cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuZGFzaGJvYXJkLWNoaXAuYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICAuZGFzaGJvYXJkLXJvdy5kYXNoLWhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KCiAgLnllYXJseS1zdW1tYXJ5IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLnllYXJseS1zdGF0IHsKICAgIGZsZXg6IDE7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjdyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC4ycmVtOwogIH0KICAueWVhcmx5LXN0YXQtbGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUgeyBmb250LXNpemU6IDEuMDVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlLmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1ub3RlIHsKICAgIHdpZHRoOiA5NnB4OwogICAgZmxleC1zaHJpbms6IDA7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNHJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXI6IDFweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuNzJyZW07CiAgICBsaW5lLWhlaWdodDogMS4yNTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQogIC51cGNvbWluZy1ub3RlLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctc3dhdGNoIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAxNHB4OwogICAgYm9yZGVyOiAxLjVweCBkYXNoZWQgdmFyKC0tZGFuZ2VyKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC51cGNvbWluZy1ub3RlLnBvc2l0aXZlIC51cGNvbWluZy1zd2F0Y2ggewogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMik7CiAgfQoKICAucmVjdXJyaW5nLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY3VycmluZy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5leHBvcnQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZXhwb3J0LXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5leHBvcnQtZm9ybWF0LXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOyB9CiAgLmV4cG9ydC1mb3JtYXQtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5leHBvcnQtZm9ybWF0LWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAvKiBJbXBvcnQgZGUgcmVsZXbDqSBiYW5jYWlyZSAqLwogIC5pbXBvcnQtZmlsZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtZmlsZS1yb3cgaW5wdXRbdHlwZT0iZmlsZSJdIHsgZmxleDogMTsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuaW1wb3J0LWRyb3B6b25lIHsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNXJlbSAwLjc1cmVtIDAuNzVyZW07CiAgfQogIC5pbXBvcnQtZHJvcHpvbmUuZHJhZy1vdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4wOCk7IH0KICAuaW1wb3J0LWRyb3B6b25lLWhpbnQgeyBtYXJnaW46IDAuNHJlbSAwIDA7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgLmltcG9ydC1zdW1tYXJ5IHsKICAgIG1hcmdpbjogMC45cmVtIDA7CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogIH0KICAuaW1wb3J0LXN1bW1hcnkgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmltcG9ydC1wcmV2aWV3IHsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtcHJldmlldy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmltcG9ydC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwOwogICAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgfQogIC5pbXBvcnQtcm93LmV4Y2x1ZGVkIHsgb3BhY2l0eTogMC40NTsgfQogIC5pbXBvcnQtcm93LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAuaW1wb3J0LXJvdy1kZXNjIHsgZm9udC1zaXplOiAwLjg4cmVtOyBmb250LXdlaWdodDogNTAwOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmltcG9ydC1yb3ctbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xcmVtOyB9CiAgLmltcG9ydC1yb3ctZHVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAuaW1wb3J0LXJvdyBzZWxlY3QgeyBmb250LXNpemU6IDAuOHJlbTsgbWF4LXdpZHRoOiAxMzBweDsgfQogIC5pbXBvcnQtYWN0aW9ucy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBtYXJnaW46IDAuNzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICB9CiAgLmltcG9ydC1hY3Rpb25zLXJvdyBidXR0b24geyBiYWNrZ3JvdW5kOiBub25lOyBib3JkZXI6IG5vbmU7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjdXJzb3I6IHBvaW50ZXI7IGZvbnQtc2l6ZTogMC44MnJlbTsgcGFkZGluZzogMDsgfQoKICAvKiBJbXBvcnQgZ8OpbsOpcmlxdWUgSUEg4oCUIGJhbmRlYXUgZGUgcsOpY3VycmVuY2VzIGTDqXRlY3TDqWVzICovCiAgLnJlY3VycmluZy1jYW5kaWRhdGVzLWxpc3QgeyBtYXJnaW46IDAuNzVyZW0gMDsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlIHsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjVyZW07CiAgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLm5lZWRzLWNvbmZpcm1hdGlvbiB7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMDcpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtaGVhZGVyIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogYmFzZWxpbmU7IGdhcDogMC41cmVtOyBmb250LXNpemU6IDAuODhyZW07IGZvbnQtd2VpZ2h0OiA1MDA7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcgeyBmb250LXNpemU6IDAuN3JlbTsgZm9udC13ZWlnaHQ6IDYwMDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuMDNlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5jcmVkaXQgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5yZWN1cnJpbmcgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcuZW5kZWQgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtdGFnLnVuY2VydGFpbiB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xNXJlbTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWNob2ljZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC45cmVtOyBtYXJnaW4tdG9wOiAwLjU1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IGZvbnQtc2l6ZTogMC44cmVtOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIGxhYmVsIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IGN1cnNvcjogcG9pbnRlcjsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWVuZGRhdGUgeyBtYXJnaW4tdG9wOiAwLjQ1cmVtOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNHJlbTsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtZW5kZGF0ZSBpbnB1dFt0eXBlPSJkYXRlIl0geyBmb250LXNpemU6IDAuOHJlbTsgfQoKICAvKiBTaW11bGF0aW9uIGRlIHBsYWNlbWVudCAow6lwYXJnbmUpICovCiAgLnBsYWNlbWVudC1pbnB1dHMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogMC43NXJlbTsgbWFyZ2luLWJvdHRvbTogMXJlbTsgfQogIC5wbGFjZW1lbnQtaW5wdXRzIGxhYmVsIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4yNXJlbTsgfQogIC5wbGFjZW1lbnQtcmVzdWx0IHsKICAgIG1hcmdpbi10b3A6IDAuOXJlbTsKICAgIHBhZGRpbmc6IDAuOHJlbSAwLjlyZW07CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnBsYWNlbWVudC1yZXN1bHQgc3Ryb25nIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuYnVkZ2V0cy1zYXZlLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7IG1hcmdpbi10b3A6IDAuNzVyZW07IH0KICAuc2F2aW5ncy1nb2FsLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgaW5wdXQgeyBmbGV4OiAxOyB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLWxhYmVsIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWFyZ2luOiAwLjhyZW0gMCAwLjM1cmVtOwogIH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCBzdHJvbmcgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLmFkdmljZS1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5hZHZpY2UtY2FyZCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBhbGlnbi1pdGVtczogZmxleC1zdGFydDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC43cmVtIDAuODVyZW07CiAgICBmb250LXNpemU6IDAuOXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjQ7CiAgfQogIC5hZHZpY2UtY2FyZCAuYWR2aWNlLWljb24geyBmb250LXNpemU6IDEuMXJlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuYWR2aWNlLWNhcmQucG9zaXRpdmUgeyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmFkdmljZS1jYXJkLndhcm5pbmcgeyBib3JkZXItbGVmdDogM3B4IHNvbGlkICNmNTllMGI7IH0KICAuYWR2aWNlLWNhcmQuaW5mbyB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsgfQogIC5yZWN1cnJpbmctaGludCB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgbWFyZ2luOiAwIDAgMC45cmVtOwogIH0KCiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44cmVtIDFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGg0IHsgbWFyZ2luOiAwIDAgMC42cmVtOyBmb250LXNpemU6IDAuOXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogYmFzZWxpbmU7CiAgICBwYWRkaW5nOiAwLjM1cmVtIDA7CiAgICBmb250LXNpemU6IDAuODhyZW07CiAgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93ICsgLnVwY29taW5nLXJlY3VycmluZy1yb3cgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5uYW1lIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmR1ZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC43OHJlbTsgbWFyZ2luLWxlZnQ6IDAuNHJlbTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmNvbXBhcmUtc2VsZWN0cyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC42cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogICAgZmxleC13cmFwOiB3cmFwOwogIH0KICAuY29tcGFyZS1zZWxlY3RzIHNlbGVjdCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNDVyZW0gMC42cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuY29tcGFyZS1zZWxlY3RzIHNwYW4geyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuODVyZW07IH0KCiAgLnNpbXBsZS10YWJsZSB7IHdpZHRoOiAxMDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LXNpemU6IDAuODVyZW07IH0KICAuc2ltcGxlLXRhYmxlIHRoLCAuc2ltcGxlLXRhYmxlIHRkIHsgcGFkZGluZzogMC41cmVtIDAuNnJlbTsgdGV4dC1hbGlnbjogcmlnaHQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoOmZpcnN0LWNoaWxkLCAuc2ltcGxlLXRhYmxlIHRkOmZpcnN0LWNoaWxkIHsgdGV4dC1hbGlnbjogbGVmdDsgfQogIC5zaW1wbGUtdGFibGUgdGhlYWQgdGggeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXdlaWdodDogNTAwOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIgKyB0ciB0ZCB7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSB0Ym9keSB0ci50b3RhbC1yb3cgdGQgeyBmb250LXdlaWdodDogNjAwOyBib3JkZXItdG9wOiAycHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgLmRpZmYtcG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLW5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtdXAgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50cmVuZC1kb3duIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnRyZW5kLWZsYXQgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CgogIC5idWRnZXQtcm93IHsgbWFyZ2luLWJvdHRvbTogMC45cmVtOyB9CiAgLmJ1ZGdldC1yb3ctaGVhZCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC41cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC4zNXJlbTsKICB9CiAgLmJ1ZGdldC1jYXQtbmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtYW1vdW50cyB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC4zcmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLmJ1ZGdldC1pbnB1dCB7CiAgICB3aWR0aDogNjRweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogNnB4OwogICAgcGFkZGluZzogMC4yNXJlbSAwLjRyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idWRnZXQtYmFyLXRyYWNrIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgYm9yZGVyLXJhZGl1czogOTk5cHg7IGhlaWdodDogOHB4OyBvdmVyZmxvdzogaGlkZGVuOyB9CiAgLmJ1ZGdldC1iYXItZmlsbCB7IGhlaWdodDogMTAwJTsgYm9yZGVyLXJhZGl1czogOTk5cHg7IHRyYW5zaXRpb246IHdpZHRoIDAuMnMgZWFzZTsgfQogIC5idWRnZXQtYmFyLWZpbGwub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5idWRnZXQtYmFyLWZpbGwud2FybmluZyB7IGJhY2tncm91bmQ6ICNmNTllMGI7IH0KICAuYnVkZ2V0LWJhci1maWxsLm92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmJ1ZGdldC1oaXN0b3J5LXN0cmlwIHsgZGlzcGxheTogZmxleDsgZ2FwOiA0cHg7IG1hcmdpbi10b3A6IDAuNHJlbTsgfQogIC5oaXN0b3J5LWRvdCB7CiAgICBmbGV4OiAxOwogICAgaGVpZ2h0OiA2cHg7CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5oaXN0b3J5LWRvdC5vayB7IGJhY2tncm91bmQ6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmhpc3RvcnktZG90Lndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmhpc3RvcnktZG90Lm92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmhpc3RvcnktZG90LmVtcHR5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgb3BhY2l0eTogMC41OyB9CiAgLnJlYy1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNnJlbTsKICB9CiAgLnJlYy1jYXJkLmV4cGVuc2UgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWMtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWNhcmQuZW5kZWQgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBvcGFjaXR5OiAwLjY7IH0KICAucmVjLW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAucmVjLXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IH0KICAucmVjLW5hbWUgeyBmb250LXNpemU6IDAuOTVyZW07IG92ZXJmbG93OiBoaWRkZW47IHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1zdWIgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuZW5kLWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOwogICAgY29sb3I6ICNmY2E1YTU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuc3RhcnQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMTUpOwogICAgY29sb3I6ICM5M2M1ZmQ7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAucmVjLWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLmZhYiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogMS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsKICAgIGNvbG9yOiB3aGl0ZTsKICAgIGZvbnQtc2l6ZTogMS44cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjQpOwogIH0KICAuZmFiOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KCiAgLmZhYi1taWMgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDUuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSgwLCAwLCAwLCAwLjMpOwogICAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzLCBib3JkZXItY29sb3IgMC4yczsKICB9CiAgLmZhYi1taWM6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQogIC5mYWItbWljLmxpc3RlbmluZyB7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOwogICAgYW5pbWF0aW9uOiBwdWxzZSAxLjJzIGluZmluaXRlOwogIH0KICAuZmFiLW1pYy5wcm9jZXNzaW5nIHsgb3BhY2l0eTogMC42OyBjdXJzb3I6IGRlZmF1bHQ7IH0KICAuZmFiLW1pYzpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuMzU7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KICBAa2V5ZnJhbWVzIHB1bHNlIHsKICAgIDAlLCAxMDAlIHsgYm94LXNoYWRvdzogMCAwIDAgMCByZ2JhKDIzOSwgNjgsIDY4LCAwLjQpOyB9CiAgICA1MCUgeyBib3gtc2hhZG93OiAwIDAgMCAxMHB4IHJnYmEoMjM5LCA2OCwgNjgsIDApOyB9CiAgfQoKICAudm9pY2UtYmFubmVyIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGJvdHRvbTogOS41cmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTJweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE1OwogIH0KICAudm9pY2UtYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudm9pY2UtYmFubmVyLmFuc3dlciB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgZm9udC13ZWlnaHQ6IDYwMDsgbGluZS1oZWlnaHQ6IDEuNDsgfQoKICAudm9pY2UtY29uZmlybS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudCwgIzRhN2RmZik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC43NXJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNjsKICB9CiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudm9pY2UtY29uZmlybS1iYW5uZXIgcCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgbGluZS1oZWlnaHQ6IDEuNDsgfQogIC52b2ljZS1jb25maXJtLWJhbm5lciAudm9pY2UtY29uZmlybS1oaW50IHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAudm9pY2UtY29uZmlybS1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgfQoKICAubW9kYWwtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC41NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGZsZXgtZW5kOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDsKICB9CiAgLm1vZGFsLW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogICNpbnB1dC1uZXctY2F0ZWdvcnktbmFtZS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLm1vZGFsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyLXJhZGl1czogMThweCAxOHB4IDAgMDsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIGNhbGMoMS41cmVtICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsKICAgIHdpZHRoOiAxMDAlOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjlyZW07CiAgfQogIC5tb2RhbCBoMiB7IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtc2l6ZTogMS4xcmVtOyB9CgogIGxhYmVsIHsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjNyZW07IH0KICBpbnB1dCwgc2VsZWN0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42NXJlbSAwLjc1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CgogIC50eXBlLXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyB9CiAgLnR5cGUtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjY1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJleHBlbnNlIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJpbmNvbWUiXSB7IGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KCiAgLm1vZGFsLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgLmNvbmZpcm0tbW9kYWwgeyBtYXgtd2lkdGg6IDQwMHB4OyB9CiAgLmNvbmZpcm0tbW9kYWwtbWVzc2FnZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgZm9udC1zaXplOiAwLjk1cmVtOyBtYXJnaW46IDA7IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KCiAgLmhpZGRlbi1maWxlLWlucHV0IHsgZGlzcGxheTogbm9uZTsgfQogIC5yZWNlaXB0LXByZXZpZXctd3JhcCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC41cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBtYXJnaW4tYm90dG9tOiAwLjVyZW07CiAgfQogIC5yZWNlaXB0LXByZXZpZXctaW1nIHsKICAgIG1heC13aWR0aDogMTAwJTsKICAgIG1heC1oZWlnaHQ6IDE2MHB4OwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBvYmplY3QtZml0OiBjb250YWluOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICB9CgogIC5saWdodGJveC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjg1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAyMDsKICAgIHBhZGRpbmc6IDEuNXJlbTsKICB9CiAgLmxpZ2h0Ym94LW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5saWdodGJveC1pbWcgeyBtYXgtd2lkdGg6IDEwMCU7IG1heC1oZWlnaHQ6IDgwdmg7IGJvcmRlci1yYWRpdXM6IDEwcHg7IH0KICAubGlnaHRib3gtY2xvc2UgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxcmVtOwogICAgcmlnaHQ6IDFyZW07CiAgICB3aWR0aDogNDBweDsKICAgIGhlaWdodDogNDBweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuMXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnksIGJ1dHRvbi5zZWNvbmRhcnkgewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNzVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiBub25lOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICBidXR0b24ucHJpbWFyeTpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQogIGJ1dHRvbi5zZWNvbmRhcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICBidXR0b24uZGFuZ2VyIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1kYW5nZXIpOyB9CiAgYnV0dG9uLmRhbmdlcjpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQoKICAuZGFuZ2VyLXpvbmUgewogICAgYm9yZGVyLWNvbG9yOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjM1KSAhaW1wb3J0YW50OwogIH0KICAuZGFuZ2VyLXpvbmUgaDMgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudG9hc3QgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgdG9wOiAxcmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICB6LWluZGV4OiAyMDsKICAgIG1heC13aWR0aDogOTB2dzsKICB9CiAgLnRvYXN0LmVycm9yIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogI2ZjYTVhNTsgfQoKICAubG9jay1zY3JlZW4gewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTAwOwogICAgcGFkZGluZzogMS41cmVtOwogIH0KICAubG9jay1zY3JlZW4uaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5sb2NrLWNhcmQgeyBtYXgtd2lkdGg6IDMyMHB4OyB3aWR0aDogMTAwJTsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgLmxvY2stZW1vamkgeyBmb250LXNpemU6IDNyZW07IG1hcmdpbi1ib3R0b206IDAuNXJlbTsgfQogIC5sb2NrLWNhcmQgaDEgeyBtYXJnaW46IDAgMCAwLjVyZW07IH0KICAubG9jay1jYXJkIHAgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAxLjI1cmVtOyBmb250LXNpemU6IDAuOXJlbTsgfQogIC5sb2NrLWNhcmQgaW5wdXQgewogICAgd2lkdGg6IDEwMCU7CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogICAgcGFkZGluZzogMC43cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIC5sb2NrLWVycm9yIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IGZvbnQtc2l6ZTogMC44NXJlbTsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5sb2NrLWVycm9yLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubG9jay1zdWNjZXNzIHsgY29sb3I6ICM0YWRlODA7IGZvbnQtc2l6ZTogMC44NXJlbTsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5sb2NrLXN1Y2Nlc3MuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5hdXRoLXZpZXcuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5hdXRoLXN3aXRjaCB7IG1hcmdpbi10b3A6IDEuMXJlbTsgZm9udC1zaXplOiAwLjg1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmF1dGgtc3dpdGNoIGEgeyBjb2xvcjogdmFyKC0tYWNjZW50KTsgY3Vyc29yOiBwb2ludGVyOyB0ZXh0LWRlY29yYXRpb246IHVuZGVybGluZTsgfQogIC5sb2NrLWNhcmQgaW5wdXRbdHlwZT0iZW1haWwiXSwKICAubG9jay1jYXJkIGlucHV0W3R5cGU9InRleHQiXSB7CiAgICB3aWR0aDogMTAwJTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLnBhc3N3b3JkLWZpZWxkIHsgcG9zaXRpb246IHJlbGF0aXZlOyBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOyB9CiAgLnBhc3N3b3JkLWZpZWxkIGlucHV0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgbWFyZ2luLWJvdHRvbTogMDsKICAgIHBhZGRpbmc6IDAuN3JlbSAyLjZyZW0gMC43cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHJpZ2h0OiAwLjRyZW07CiAgICB0b3A6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWSgtNTAlKTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBmb250LXNpemU6IDEuMXJlbTsKICAgIHBhZGRpbmc6IDAuM3JlbSAwLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBvcGFjaXR5OiAwLjc7CiAgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuOmhvdmVyIHsgb3BhY2l0eTogMTsgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuLmFjdGl2ZSB7IG9wYWNpdHk6IDE7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGRpdiBjbGFzcz0ibG9jay1zY3JlZW4gaGlkZGVuIiBpZD0ibG9jay1zY3JlZW4iPgogICAgPGRpdiBjbGFzcz0ibG9jay1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibG9jay1lbW9qaSI+8J+SsDwvZGl2PgogICAgICA8aDE+S2FjaGluZzwvaDE+CgogICAgICA8IS0tIENvbm5leGlvbiAtLT4KICAgICAgPGRpdiBjbGFzcz0iYXV0aC12aWV3IiBpZD0iYXV0aC12aWV3LWxvZ2luIj4KICAgICAgICA8cD5Db25uZWN0ZS10b2kgcG91ciBhY2PDqWRlciDDoCB0ZXMgZG9ubsOpZXMuPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9ImxvZ2luLWVtYWlsLWlucHV0IiBwbGFjZWhvbGRlcj0iRW1haWwiIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiPgogICAgICAgIDxkaXYgY2xhc3M9InBhc3N3b3JkLWZpZWxkIj4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9ImxvZ2luLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlIiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwYXNzd29yZC10b2dnbGUtYnRuIiBkYXRhLXRhcmdldD0ibG9naW4tcGFzc3dvcmQtaW5wdXQiIGFyaWEtbGFiZWw9IkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSI+8J+RgTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9ImxvZ2luLXN1Ym1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+U2UgY29ubmVjdGVyPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ibG9naW4tZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPgogICAgICAgICAgPGEgaWQ9ImxvZ2luLWdvdG8tZm9yZ290Ij5Nb3QgZGUgcGFzc2Ugb3VibGnDqSA/PC9hPjxicj4KICAgICAgICAgIDxhIGlkPSJsb2dpbi1nb3RvLXNpZ251cCI+SidhaSB1biBsaWVuIGQnaW52aXRhdGlvbjwvYT4KICAgICAgICA8L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSBJbnNjcmlwdGlvbiAoc3VyIGludml0YXRpb24gdW5pcXVlbWVudCkgLS0+CiAgICAgIDxkaXYgY2xhc3M9ImF1dGgtdmlldyBoaWRkZW4iIGlkPSJhdXRoLXZpZXctc2lnbnVwIj4KICAgICAgICA8cD5DcsOpZSB0b24gY29tcHRlIMOgIHBhcnRpciBkZSB0b24gbGllbiBkJ2ludml0YXRpb24uPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0ic2lnbnVwLWludml0ZS1pbnB1dCIgcGxhY2Vob2xkZXI9IkNvZGUgZCdpbnZpdGF0aW9uIj4KICAgICAgICA8aW5wdXQgdHlwZT0iZW1haWwiIGlkPSJzaWdudXAtZW1haWwtaW5wdXQiIHBsYWNlaG9sZGVyPSJFbWFpbCIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJzaWdudXAtdXNlcm5hbWUtaW5wdXQiIHBsYWNlaG9sZGVyPSJOb20gZCd1dGlsaXNhdGV1ciIgYXV0b2NvbXBsZXRlPSJuaWNrbmFtZSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGFzc3dvcmQtZmllbGQiPgogICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0ic2lnbnVwLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlICg4IGNhcmFjdMOocmVzIG1pbi4pIiBhdXRvY29tcGxldGU9Im5ldy1wYXNzd29yZCI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InBhc3N3b3JkLXRvZ2dsZS1idG4iIGRhdGEtdGFyZ2V0PSJzaWdudXAtcGFzc3dvcmQtaW5wdXQiIGFyaWEtbGFiZWw9IkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSI+8J+RgTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9InNpZ251cC1zdWJtaXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPkNyw6llciBtb24gY29tcHRlPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ic2lnbnVwLWVycm9yIj48L3A+CiAgICAgICAgPHAgY2xhc3M9ImF1dGgtc3dpdGNoIj48YSBpZD0ic2lnbnVwLWdvdG8tbG9naW4iPkonYWkgZMOpasOgIHVuIGNvbXB0ZTwvYT48L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSBNb3QgZGUgcGFzc2Ugb3VibGnDqSAtLT4KICAgICAgPGRpdiBjbGFzcz0iYXV0aC12aWV3IGhpZGRlbiIgaWQ9ImF1dGgtdmlldy1mb3Jnb3QiPgogICAgICAgIDxwPkVudHJlIHRvbiBlbWFpbCA6IHNpIHVuIGNvbXB0ZSBleGlzdGUsIHR1IHJlY2V2cmFzIHVuIGxpZW4gZGUgcsOpaW5pdGlhbGlzYXRpb24uPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9ImZvcmdvdC1lbWFpbC1pbnB1dCIgcGxhY2Vob2xkZXI9IkVtYWlsIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InByaW1hcnkiIGlkPSJmb3Jnb3Qtc3VibWl0LWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5FbnZveWVyIGxlIGxpZW48L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJmb3Jnb3QtZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0ibG9jay1zdWNjZXNzIGhpZGRlbiIgaWQ9ImZvcmdvdC1zdWNjZXNzIj48L3A+CiAgICAgICAgPHAgY2xhc3M9ImF1dGgtc3dpdGNoIj48YSBpZD0iZm9yZ290LWdvdG8tbG9naW4iPlJldG91ciDDoCBsYSBjb25uZXhpb248L2E+PC9wPgogICAgICA8L2Rpdj4KCiAgICAgIDwhLS0gUsOpaW5pdGlhbGlzYXRpb24gZHUgbW90IGRlIHBhc3NlIChkZXB1aXMgbGUgbGllbiByZcOndSBwYXIgZW1haWwpIC0tPgogICAgICA8ZGl2IGNsYXNzPSJhdXRoLXZpZXcgaGlkZGVuIiBpZD0iYXV0aC12aWV3LXJlc2V0Ij4KICAgICAgICA8cD5DaG9pc2lzIHVuIG5vdXZlYXUgbW90IGRlIHBhc3NlLjwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJwYXNzd29yZC1maWVsZCI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJyZXNldC1wYXNzd29yZC1pbnB1dCIgcGxhY2Vob2xkZXI9Ik5vdXZlYXUgbW90IGRlIHBhc3NlICg4IGNhcmFjdMOocmVzIG1pbi4pIiBhdXRvY29tcGxldGU9Im5ldy1wYXNzd29yZCI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InBhc3N3b3JkLXRvZ2dsZS1idG4iIGRhdGEtdGFyZ2V0PSJyZXNldC1wYXNzd29yZC1pbnB1dCIgYXJpYS1sYWJlbD0iQWZmaWNoZXIgbGUgbW90IGRlIHBhc3NlIj7wn5GBPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVzZXQtc3VibWl0LWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5WYWxpZGVyPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0icmVzZXQtZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0ibG9jay1zdWNjZXNzIGhpZGRlbiIgaWQ9InJlc2V0LXN1Y2Nlc3MiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPjxhIGlkPSJyZXNldC1nb3RvLWxvZ2luIj5SZXRvdXIgw6AgbGEgY29ubmV4aW9uPC9hPjwvcD4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBpZD0iYXBwLXJvb3QiIGhpZGRlbj4KICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Im1lbnUtdG9nZ2xlLWJ0biIgaWQ9Im1lbnUtdG9nZ2xlLWJ0biIgYXJpYS1sYWJlbD0iT3V2cmlyIGxlIG1lbnUiPuKYsDwvYnV0dG9uPgogIDxkaXYgY2xhc3M9Im5hdi1kcmF3ZXItYmFja2Ryb3AiIGlkPSJuYXYtZHJhd2VyLWJhY2tkcm9wIj48L2Rpdj4KICA8aGVhZGVyPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJpY29uLWJ0biBkYW5nZXIiIGlkPSJsb2dvdXQtYnRuIiB0aXRsZT0iU2UgZMOpY29ubmVjdGVyIiBhcmlhLWxhYmVsPSJTZSBkw6ljb25uZWN0ZXIiIHN0eWxlPSJwb3NpdGlvbjphYnNvbHV0ZTsgdG9wOjFyZW07IHJpZ2h0OjFyZW07Ij7ij7s8L2J1dHRvbj4KICAgIDxoMT7wn5KwIEthY2hpbmc8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1zYXZpbmdzIiBkYXRhLXZpZXc9InNhdmluZ3MiPsOJcGFyZ25lPC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtY2hpcC1yb3ciIGlkPSJkYXNoYm9hcmQtY2hpcC1yb3ciPjwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWV4cGVuc2VzIj4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1pbmNvbWUiPgogICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIHJldmVudXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW4gcmV2ZW51IGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1idWRnZXRzIj4KICAgICAgICA8aDM+QnVkZ2V0cyBtZW5zdWVscyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEluZGlxdWUgdW4gbW9udGFudCBwb3VyIHVuZSBjYXTDqWdvcmllIGV0IGVucmVnaXN0cmUgYXZlYyDwn5K+IOKAlCBsYSBiYXJyZQogICAgICAgICAgY29tcGFyZSBlbnN1aXRlIHRlcyBkw6lwZW5zZXMgZHUgbW9pcyBlbiBjb3VycyDDoCBjZSBwbGFmb25kICh2ZXJ0LAogICAgICAgICAgb3JhbmdlIGF1LWRlbMOgIGRlIDcwJSwgcm91Z2UgYXUtZGVsw6AgZGUgMTAwJSkuIExhIHBldGl0ZSByYW5nw6llIGRlCiAgICAgICAgICBiYXJyZXMgZW4gZGVzc291cyBtb250cmUgbCdoaXN0b3JpcXVlIGRlcyA2IGRlcm5pZXJzIG1vaXMgKHN1cnZvbGUKICAgICAgICAgIG91IHRvdWNoZSB1bmUgYmFycmUgcG91ciB2b2lyIGxlIGTDqXRhaWwpLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJidWRnZXRzLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldHMtc2F2ZS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iaWNvbi1idG4iIGlkPSJidWRnZXRzLXNhdmUtYWxsLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgdG91cyBsZXMgYnVkZ2V0cyI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1ldm9sdXRpb24iPgogICAgICAgIDxoMz7DiXZvbHV0aW9uIG1lbnN1ZWxsZSAoZMOpcGVuc2VzIHZzIHJldmVudXMpPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWV2b2x1dGlvbiI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0iZGFzaC1yb3ctY29tcGFyZSI+CiAgICAgICAgPGgzPkNvbXBhcmVyIGRldXggbW9pczwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY29tcGFyZS1zZWxlY3RzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYSI+PC9zZWxlY3Q+CiAgICAgICAgICA8c3Bhbj52czwvc3Bhbj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYiI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgYXNzZXogZGUgbW9pcyBkaWZmw6lyZW50cyBwb3VyIGNvbXBhcmVyLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy10cmVuZCI+CiAgICAgICAgPGgzPk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgaWQ9InRyZW5kLXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InRyZW5kLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy15ZWFybHkiPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5CaWxhbiBhbm51ZWw8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0ieWVhcmx5LXllYXItc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3VtbWFyeSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+RMOpcGVuc2VzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWV4cGVuc2VzIiBjbGFzcz0ieWVhcmx5LXN0YXQtdmFsdWUgZXhwZW5zZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+UmV2ZW51czwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS10b3RhbC1pbmNvbWUiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBpbmNvbWUiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN0YXQiPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ieWVhcmx5LXN0YXQtbGFiZWwiPlNvbGRlIG5ldDwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS1uZXQiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC15ZWFybHkiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGRlIGRvbm7DqWVzIHBvdXIgY2V0dGUgYW5uw6llLgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIiBjbGFzcz0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGhpZGRlbiI+CiAgICAgICAgPGg0PlByb2NoYWluZXMgw6ljaMOpYW5jZXM8L2g0PgogICAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1lbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgQXVjdW5lIGTDqXBlbnNlIHLDqWN1cnJlbnRlIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZXhwb3J0IiBjbGFzcz0iZXhwb3J0LXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+RXhwb3J0ZXIgdGVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJleHBvcnQtZm9ybWF0LXRvZ2dsZSIgaWQ9ImV4cG9ydC1mb3JtYXQtdG9nZ2xlIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZXhwb3J0LWZvcm1hdC1idG4gYWN0aXZlIiBkYXRhLWZvcm1hdD0ieGxzeCI+RXhjZWwgKC54bHN4KTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJleHBvcnQtZm9ybWF0LWJ0biIgZGF0YS1mb3JtYXQ9Impzb24iPlNhdXZlZ2FyZGUgY29tcGzDqHRlIChKU09OKTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCIgaWQ9ImV4cG9ydC1mb3JtYXQtaGludCI+CiAgICAgICAgICBUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQtZG93bmxvYWQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnRlciB1biByZWxldsOpIGJhbmNhaXJlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciBsJ2V4cG9ydCBDU1YgwqsgZXhwb3J0LW9wZXJhdGlvbnMuLi4gwrsgZGUgQm91cnNvQmFuawogICAgICAgICAgdW5pcXVlbWVudC4gTGVzIG1vbnRhbnRzLCBkYXRlcyBldCBkZXNjcmlwdGlvbnMgc29udCBhbmFseXPDqXMgaWNpCiAgICAgICAgICBtw6ptZSAocmllbiBuJ2VzdCBlbnZvecOpIGFpbGxldXJzKSA7IHR1IGNob2lzaXMgZW5zdWl0ZSBsaWduZSBwYXIKICAgICAgICAgIGxpZ25lIHF1b2kgaW1wb3J0ZXIgYXZhbnQgdG91dGUgw6ljcml0dXJlIGVuIGJhc2UuIExlIG51bcOpcm8gZGUKICAgICAgICAgIGNvbXB0ZSBuJ2VzdCBqYW1haXMgbHUuIFBvdXIgdW4gYXV0cmUgZm9ybWF0IChvdSB1biBmaWNoaWVyIHNhbnMKICAgICAgICAgIEJvdXJzb0JhbmspLCB1dGlsaXNlIGwnaW1wb3J0IGfDqW7DqXJpcXVlIHBhciBJQSB1biBwZXUgcGx1cyBiYXMuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1kcm9wem9uZSIgaWQ9ImltcG9ydC1kcm9wem9uZSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJpbXBvcnQtZmlsZS1yb3ciPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImltcG9ydC1maWxlLWlucHV0IiBhY2NlcHQ9Ii5jc3YsdGV4dC9jc3YiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iaW1wb3J0LWFuYWx5emUtYnRuIj5BbmFseXNlcjwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0iaW1wb3J0LWRyb3B6b25lLWhpbnQiPm91IGdsaXNzZS1kw6lwb3NlIGxlIGZpY2hpZXIgLmNzdiBpY2k8L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXN1bW1hcnkiIGNsYXNzPSJpbXBvcnQtc3VtbWFyeSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImltcG9ydC1wcmV2aWV3IiBjbGFzcz0iaW1wb3J0LXByZXZpZXcgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1hY3Rpb25zLXJvdyI+CiAgICAgICAgICAgIDxzcGFuIGlkPSJpbXBvcnQtc2VsZWN0ZWQtY291bnQiPjwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJpbXBvcnQtdG9nZ2xlLWFsbC1idG4iPlRvdXQgY29jaGVyIC8gZMOpY29jaGVyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgaWQ9ImltcG9ydC1yb3dzLWxpc3QiPjwvZGl2PgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImltcG9ydC1jb21taXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsgbWFyZ2luLXRvcDowLjc1cmVtOyI+SW1wb3J0ZXIgbGEgc8OpbGVjdGlvbjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnQgZ8OpbsOpcmlxdWUgcGFyIElBICh0b3V0IGZpY2hpZXIpPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciB1biBmaWNoaWVyIHF1aSBuZSB2aWVudCBwYXMgZGUgQm91cnNvQmFuaywgb3UgcXVpIG4nYSBwYXMgdW5lCiAgICAgICAgICBzdHJ1Y3R1cmUgY2xhc3NpcXVlIChleCA6IHVuIHRhYmxlYXUgcGFyIG1vaXMsIHNhbnMgZGF0ZSBwcsOpY2lzZSBuaQogICAgICAgICAgY2F0w6lnb3JpZSkuIEwnSUEgbGl0IGxlIGZpY2hpZXIgZXQgcHJvcG9zZSBkZXMgdHJhbnNhY3Rpb25zIMOgCiAgICAgICAgICB2YWxpZGVyIDsgc2kgdW5lIGTDqXBlbnNlIHNlbWJsZSBzZSByw6lww6l0ZXIgY2hhcXVlIG1vaXMsIGVsbGUgZXN0CiAgICAgICAgICBtaXNlIGRlIGPDtHTDqSBwb3VyIHF1ZSB0dSBjb25maXJtZXMgdG9pLW3Dqm1lIHMnaWwgcydhZ2l0IGQndW5lCiAgICAgICAgICBjaGFyZ2UgcsOpY3VycmVudGUgb3UgZCd1biBjcsOpZGl0IGVuIGNvdXJzIGRlIHJlbWJvdXJzZW1lbnQuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1kcm9wem9uZSIgaWQ9ImdlbmVyaWMtaW1wb3J0LWRyb3B6b25lIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1maWxlLXJvdyI+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iZ2VuZXJpYy1pbXBvcnQtZmlsZS1pbnB1dCIgYWNjZXB0PSIuY3N2LC54bHN4LHRleHQvY3N2Ij4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImdlbmVyaWMtaW1wb3J0LWFuYWx5emUtYnRuIj5BbmFseXNlcjwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8cCBjbGFzcz0iaW1wb3J0LWRyb3B6b25lLWhpbnQiPm91IGdsaXNzZS1kw6lwb3NlIHVuIGZpY2hpZXIgLmNzdiAvIC54bHN4IGljaTwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1zdW1tYXJ5IiBjbGFzcz0iaW1wb3J0LXN1bW1hcnkiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctc2VjdGlvbiIgY2xhc3M9ImhpZGRlbiI+CiAgICAgICAgICA8aDQgc3R5bGU9Im1hcmdpbi1ib3R0b206MC4yNXJlbTsiPkTDqXBlbnNlcyBxdWkgc2VtYmxlbnQgc2UgcsOpcMOpdGVyPC9oND4KICAgICAgICAgIDxkaXYgaWQ9ImdlbmVyaWMtaW1wb3J0LXJlY3VycmluZy1saXN0IiBjbGFzcz0icmVjdXJyaW5nLWNhbmRpZGF0ZXMtbGlzdCI+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZ2VuZXJpYy1pbXBvcnQtcHJldmlldyIgY2xhc3M9ImltcG9ydC1wcmV2aWV3IGhpZGRlbiI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJpbXBvcnQtYWN0aW9ucy1yb3ciPgogICAgICAgICAgICA8c3BhbiBpZD0iZ2VuZXJpYy1pbXBvcnQtc2VsZWN0ZWQtY291bnQiPjwvc3Bhbj4KICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJnZW5lcmljLWltcG9ydC10b2dnbGUtYWxsLWJ0biI+VG91dCBjb2NoZXIgLyBkw6ljb2NoZXI8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZ2VuZXJpYy1pbXBvcnQtcm93cy1saXN0Ij48L2Rpdj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsgbWFyZ2luLXRvcDowLjc1cmVtOyI+SW1wb3J0ZXIgbGEgc8OpbGVjdGlvbjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3cgZGFuZ2VyLXpvbmUiPgogICAgICAgIDxoMz7imqDvuI8gWm9uZSBkYW5nZXJldXNlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgU3VwcHJpbWUgZMOpZmluaXRpdmVtZW50IFRPVVRFUyBsZXMgZG9ubsOpZXMgOiB0cmFuc2FjdGlvbnMsIGNoYXJnZXMKICAgICAgICAgIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc29ubmFsaXPDqWVzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMsCiAgICAgICAgICBidWRnZXRzLCBwaG90b3MgZGUgcmXDp3VzIGV0IG9iamVjdGlmIGQnw6lwYXJnbmUuIFBlbnNlIMOgIGV4cG9ydGVyIGVuCiAgICAgICAgICBFeGNlbCBhdmFudCBzaSBiZXNvaW4g4oCUIGltcG9zc2libGUgw6AgYW5udWxlci4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZGFuZ2VyIiBpZD0iYnRuLXJlc2V0LWFsbCIgc3R5bGU9IndpZHRoOjEwMCU7Ij5Sw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDxzZWN0aW9uIGlkPSJ2aWV3LXNhdmluZ3MiIGNsYXNzPSJzYXZpbmdzLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+T2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgTGUgbW9udGFudCBxdWUgdHUgdmV1eCBnYXJkZXIgZGUgY8O0dMOpIGNoYXF1ZSBtb2lzIChyZXZlbnVzIG1vaW5zCiAgICAgICAgICBkw6lwZW5zZXMpLiBDb21wYXLDqSDDoCB0b24gc29sZGUgcsOpZWwgZHUgbW9pcyBlbiBjb3Vycy4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0ic2F2aW5ncy1nb2FsLXJvdyI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ic2F2aW5ncy1nb2FsLWlucHV0IiBtaW49IjAiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSJFeCA6IDEwMCI+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJpY29uLWJ0biIgaWQ9InNhdmluZ3MtZ29hbC1zYXZlLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgbCdvYmplY3RpZiI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtcHJvZ3Jlc3Mtc2VjdGlvbiIgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9InNhdmluZ3MtcHJvZ3Jlc3MtbGFiZWwiPgogICAgICAgICAgICA8c3Bhbj5Tb2xkZSBkdSBtb2lzIGVuIGNvdXJzPC9zcGFuPgogICAgICAgICAgICA8c3Ryb25nIGlkPSJzYXZpbmdzLXByb2dyZXNzLXRleHQiPjwvc3Ryb25nPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJidWRnZXQtYmFyLXRyYWNrIj4KICAgICAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wcm9ncmVzcy1iYXIiIGNsYXNzPSJidWRnZXQtYmFyLWZpbGwgb2siPjwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkNvbnNlaWxzPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgQmFzw6lzIHN1ciB0ZXMgYnVkZ2V0cyBwYXIgY2F0w6lnb3JpZSBldCB0ZXMgdGVuZGFuY2VzIGRlIGTDqXBlbnNlcwogICAgICAgICAgKHZvaXIgbCdvbmdsZXQgVGFibGVhdSBkZSBib3JkKS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1hZHZpY2UtbGlzdCIgY2xhc3M9ImFkdmljZS1saXN0Ij48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLWFkdmljZS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcyBjZSBtb2lzLWNpIHBvdXIgdGUgZG9ubmVyIGRlcyBjb25zZWlscy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+U2ltdWxhdGlvbiBkZSBwbGFjZW1lbnQ8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBQcm9qZWN0aW9uIHNpIHR1IHBsYWNlcyB1bmUgc29tbWUgc3VyIHVuIGxpdnJldCBvdSB1biBwbGFjZW1lbnQgw6AKICAgICAgICAgIHRhdXggZml4ZSAoaW50w6lyw6p0cyBjb21wb3PDqXMsIGNhbGN1bMOpcyBtZW5zdWVsbGVtZW50KS4gTGUgdGF1eCBwYXIKICAgICAgICAgIGTDqWZhdXQgKDMlKSBjb3JyZXNwb25kIGF1IExpdnJldCBBIOKAlCBjaGFuZ2UtbGUgcG91ciBzaW11bGVyIHVuCiAgICAgICAgICBhdXRyZSBwbGFjZW1lbnQuCiAgICAgICAgPC9wPgogICAgICAgIDxkaXYgY2xhc3M9InBsYWNlbWVudC1pbnB1dHMiPgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LWluaXRpYWwiPk1vbnRhbnQgaW5pdGlhbCAo4oKsKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQtaW5pdGlhbCIgbWluPSIwIiBzdGVwPSIxIiB2YWx1ZT0iNTAwIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LW1vbnRobHkiPlZlcnNlbWVudCBtZW5zdWVsICjigqwpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC1tb250aGx5IiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSI1MCI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxsYWJlbCBmb3I9InBsYWNlbWVudC1yYXRlIj5UYXV4IGFubnVlbCAoJSk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LXJhdGUiIG1pbj0iMCIgc3RlcD0iMC4xIiB2YWx1ZT0iMyI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxsYWJlbCBmb3I9InBsYWNlbWVudC15ZWFycyI+RHVyw6llIChhbm7DqWVzKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQteWVhcnMiIG1pbj0iMSIgc3RlcD0iMSIgdmFsdWU9IjUiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1wbGFjZW1lbnQiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InBsYWNlbWVudC1jaGFydC1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InBsYWNlbWVudC1yZXN1bHQiIGlkPSJwbGFjZW1lbnQtcmVzdWx0Ij48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgPC9tYWluPgoKICA8ZGl2IGNsYXNzPSJ2b2ljZS1iYW5uZXIgaGlkZGVuIiBpZD0idm9pY2UtYmFubmVyIj48L2Rpdj4KICA8ZGl2IGNsYXNzPSJ2b2ljZS1jb25maXJtLWJhbm5lciBoaWRkZW4iIGlkPSJ2b2ljZS1jb25maXJtLWJhbm5lciI+PC9kaXY+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiLW1pYyIgaWQ9ImZhYi1taWMiIGFyaWEtbGFiZWw9IkRpY3RlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LCBvdSBwb3NlciB1bmUgcXVlc3Rpb24iIHRpdGxlPSJEaWN0ZSB1bmUgZMOpcGVuc2UvdW4gcmV2ZW51LCBvdSBwb3NlIHVuZSBxdWVzdGlvbiAoZXggOiDCqyBjb21iaWVuIGonYWkgZMOpcGVuc8OpIGVuIHJlc3RhdXJhbnQgY2UgbW9pcy1jaSA/IMK7KSI+8J+OpDwvYnV0dG9uPgogIDxidXR0b24gY2xhc3M9ImZhYiIgaWQ9ImZhYi1hZGQiIGFyaWEtbGFiZWw9IkFqb3V0ZXIiPis8L2J1dHRvbj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJtb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJtb2RhbC10aXRsZSI+Tm91dmVsbGUgdHJhbnNhY3Rpb248L2gyPgoKICAgICAgPGRpdiBjbGFzcz0idHlwZS10b2dnbGUiIGlkPSJ0eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0iaW5wdXQtY2F0ZWdvcnkiPkNhdMOpZ29yaWU8L2xhYmVsPgogICAgICAgIDxzZWxlY3QgaWQ9ImlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgICA8aW5wdXQKICAgICAgICAgIHR5cGU9InRleHQiCiAgICAgICAgICBpZD0iaW5wdXQtbmV3LWNhdGVnb3J5LW5hbWUiCiAgICAgICAgICBwbGFjZWhvbGRlcj0iTm9tIGRlIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiCiAgICAgICAgICBjbGFzcz0iaGlkZGVuIgogICAgICAgICAgc3R5bGU9Im1hcmdpbi10b3A6IDhweDsiCiAgICAgICAgPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kZXNjcmlwdGlvbiI+RGVzY3JpcHRpb24gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW5wdXQtZGVzY3JpcHRpb24iIHBsYWNlaG9sZGVyPSJFeCA6IGTDqWpldW5lciBhdmVjIFBhdWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1kYXRlIj5EYXRlPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImlucHV0LWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWw+UmXDp3UgKHBob3RvLCBvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImlucHV0LXJlY2VpcHQtZmlsZSIgY2xhc3M9ImhpZGRlbi1maWxlLWlucHV0IiBhY2NlcHQ9ImltYWdlLyoiIGNhcHR1cmU9ImVudmlyb25tZW50Ij4KICAgICAgICA8ZGl2IGlkPSJyZWNlaXB0LXByZXZpZXctd3JhcCIgY2xhc3M9InJlY2VpcHQtcHJldmlldy13cmFwIGhpZGRlbiI+CiAgICAgICAgICA8aW1nIGlkPSJyZWNlaXB0LXByZXZpZXctaW1nIiBjbGFzcz0icmVjZWlwdC1wcmV2aWV3LWltZyIgYWx0PSJSZcOndSI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1yZWNlaXB0LXJlbW92ZSI+U3VwcHJpbWVyIGxhIHBob3RvPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJzZWNvbmRhcnkiIGlkPSJidG4tcmVjZWlwdC1waWNrIiBzdHlsZT0id2lkdGg6MTAwJTsiPvCfk7cgQWpvdXRlciB1bmUgcGhvdG8gZGUgcmXDp3U8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iYnRuLXNhdmUiPkFqb3V0ZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibW9kYWwtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWMtbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICAgIDxoMiBpZD0icmVjLW1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSBkw6lwZW5zZSByw6ljdXJyZW50ZTwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InJlYy10eXBlLXRvZ2dsZSI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biBhY3RpdmUiIGRhdGEtdHlwZT0iZXhwZW5zZSI+8J+SuCBEw6lwZW5zZTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idHlwZS1idG4iIGRhdGEtdHlwZT0iaW5jb21lIj7wn5KwIFJldmVudTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LW5hbWUiPk5vbTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJyZWMtaW5wdXQtbmFtZSIgcGxhY2Vob2xkZXI9IkV4IDogTmV0ZmxpeCwgTG95ZXIsIFNhbGFpcmUuLi4iPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtYW1vdW50Ij5Nb250YW50ICjigqwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWFtb3VudCIgc3RlcD0iMC4wMSIgbWluPSIwLjAxIiBwbGFjZWhvbGRlcj0iMTIuNTAiIGlucHV0bW9kZT0iZGVjaW1hbCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0icmVjLWlucHV0LWNhdGVnb3J5Ij48L3NlbGVjdD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWRheSI+Sm91ciBkdSBtb2lzPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icmVjLWlucHV0LWRheSIgbWluPSIxIiBtYXg9IjMxIiBzdGVwPSIxIiBwbGFjZWhvbGRlcj0iMSDDoCAzMSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1zdGFydC1kYXRlIj5EYXRlIGRlIGTDqWJ1dCAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtc3RhcnQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1lbmQtZGF0ZSI+RGF0ZSBkZSBmaW4gKG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0icmVjLWlucHV0LWVuZC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9InJlYy1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9InJlYy1idG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9ImNvbmZpcm0tbW9kYWwtb3ZlcmxheSI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbCBjb25maXJtLW1vZGFsIj4KICAgICAgPGgyIGlkPSJjb25maXJtLW1vZGFsLXRpdGxlIj5Db25maXJtZXI8L2gyPgogICAgICA8cCBpZD0iY29uZmlybS1tb2RhbC1tZXNzYWdlIiBjbGFzcz0iY29uZmlybS1tb2RhbC1tZXNzYWdlIj48L3A+CiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAgIDxidXR0b24gY2xhc3M9InNlY29uZGFyeSIgaWQ9ImNvbmZpcm0tYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJjb25maXJtLWJ0bi1vayI+Q29uZmlybWVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImxpZ2h0Ym94LW92ZXJsYXkgaGlkZGVuIiBpZD0icmVjZWlwdC1saWdodGJveC1vdmVybGF5Ij4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ibGlnaHRib3gtY2xvc2UiIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LWNsb3NlIiBhcmlhLWxhYmVsPSJGZXJtZXIiPuKclTwvYnV0dG9uPgogICAgPGltZyBjbGFzcz0ibGlnaHRib3gtaW1nIiBpZD0icmVjZWlwdC1saWdodGJveC1pbWciIGFsdD0iUmXDp3UgZW4gcGxlaW4gw6ljcmFuIj4KICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHNjcmlwdD4KICAgIC8vIExlIGpldG9uIGRlIHNlc3Npb24gKG9idGVudSBhcHLDqHMgYXZvaXIgdGFww6kgbGUgbW90IGRlIHBhc3NlIHN1ciBsJ8OpY3JhbgogICAgLy8gZGUgdmVycm91aWxsYWdlKSByZW1wbGFjZSBsJ2FuY2llbm5lIGNsw6kgQVBJIGNvZMOpZSBlbiBkdXIgaWNpIOKAlCBjZWxsZS1jaQogICAgLy8gw6l0YWl0IHZpc2libGUgcGFyIG4naW1wb3J0ZSBxdWkgdmlhICJBZmZpY2hlciBsZSBjb2RlIHNvdXJjZSIsIHNhbnMKICAgIC8vIGF1Y3VuIG1vdCBkZSBwYXNzZS4gTGUgamV0b24gZXN0IHNpZ27DqSBjw7R0w6kgc2VydmV1ciBldCBleHBpcmUgYXByw6hzIDkwCiAgICAvLyBqb3VycyA7IGlsIG5lIHLDqXbDqGxlIHJpZW4gZGUgc2VjcmV0IGVuIGx1aS1tw6ptZS4KICAgIGNvbnN0IFRPS0VOX1NUT1JBR0VfS0VZID0gImthY2hpbmdfc2Vzc2lvbl90b2tlbiI7CiAgICBsZXQgQVBJX0tFWSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKFRPS0VOX1NUT1JBR0VfS0VZKSB8fCAiIjsKCiAgICBjb25zdCBsb2NrU2NyZWVuRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9jay1zY3JlZW4iKTsKICAgIGNvbnN0IGFwcFJvb3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhcHAtcm9vdCIpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gw4ljcmFuIGRlIGNvbm5leGlvbiA6IHBsdXNpZXVycyB2dWVzIChjb25uZXhpb24gLyBpbnNjcmlwdGlvbiBzdXIKICAgIC8vIGludml0YXRpb24gLyBtb3QgZGUgcGFzc2Ugb3VibGnDqSAvIHLDqWluaXRpYWxpc2F0aW9uKSBkYW5zIGxhIG3Dqm1lCiAgICAvLyBjYXJ0ZSwgdW5lIHNldWxlIGFmZmljaMOpZSDDoCBsYSBmb2lzLiA/aW52aXRlPS4uLiBldCA/cmVzZXQ9Li4uIGRhbnMKICAgIC8vIGwnVVJMIChsaWVucyByZcOndXMgcGFyIGVtYWlsKSBvdXZyZW50IGRpcmVjdGVtZW50IGxhIHZ1ZSBjb3JyZXNwb25kYW50ZQogICAgLy8gYXZlYyBsZSBqZXRvbiBwcsOpLXJlbXBsaSDigJQgaWwgbidleGlzdGUgcGFzIGRlIHJvdXRlIHNlcnZldXIgZMOpZGnDqWUKICAgIC8vIHBvdXIgL3NpZ251cCBvdSAvcmVzZXQtcGFzc3dvcmQsIHRvdXQgc2UgcGFzc2UgaWNpIGPDtHTDqSBmcm9udGVuZC4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgYXV0aFZpZXdzID0gewogICAgICBsb2dpbjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImF1dGgtdmlldy1sb2dpbiIpLAogICAgICBzaWdudXA6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhdXRoLXZpZXctc2lnbnVwIiksCiAgICAgIGZvcmdvdDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImF1dGgtdmlldy1mb3Jnb3QiKSwKICAgICAgcmVzZXQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhdXRoLXZpZXctcmVzZXQiKSwKICAgIH07CgogICAgZnVuY3Rpb24gc2hvd0F1dGhWaWV3KG5hbWUpIHsKICAgICAgZm9yIChjb25zdCBba2V5LCBlbF0gb2YgT2JqZWN0LmVudHJpZXMoYXV0aFZpZXdzKSkgewogICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImhpZGRlbiIsIGtleSAhPT0gbmFtZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzaG93TG9ja1NjcmVlbihpbml0aWFsVmlldyA9ICJsb2dpbiIpIHsKICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oVE9LRU5fU1RPUkFHRV9LRVkpOwogICAgICBBUElfS0VZID0gIiI7CiAgICAgIGFwcFJvb3RFbC5oaWRkZW4gPSB0cnVlOwogICAgICBsb2NrU2NyZWVuRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHNob3dBdXRoVmlldyhpbml0aWFsVmlldyk7CiAgICB9CgogICAgZnVuY3Rpb24gc2hvd0FwcCgpIHsKICAgICAgbG9ja1NjcmVlbkVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBhcHBSb290RWwuaGlkZGVuID0gZmFsc2U7CiAgICB9CgogICAgZnVuY3Rpb24gc2V0QXV0aEJ1c3koYnRuLCBidXN5TGFiZWwsIGlkbGVMYWJlbCkgewogICAgICBidG4uZGlzYWJsZWQgPSAhIWJ1c3lMYWJlbDsKICAgICAgYnRuLnRleHRDb250ZW50ID0gYnVzeUxhYmVsIHx8IGlkbGVMYWJlbDsKICAgIH0KCiAgICAvLyBMZSBiYWNrZW5kIChGYXN0QVBJL3B5ZGFudGljKSByZW52b2llIGVuIHRlbXBzIG5vcm1hbCBgZGV0YWlsYCBjb21tZQogICAgLy8gdW5lIHNpbXBsZSBjaGHDrm5lLCBtYWlzIHF1YW5kIGxhIHJlcXXDqnRlIG5lIHJlc3BlY3RlIHBhcyBsZSBzY2jDqW1hCiAgICAvLyBhdHRlbmR1IChleDogbW90IGRlIHBhc3NlIHRyb3AgY291cnQgYXZhbnQgbcOqbWUgZCdhdHRlaW5kcmUgbm90cmUKICAgIC8vIHByb3ByZSBjb2RlKSwgYGRldGFpbGAgZXN0IHVuZSBMSVNURSBkJ29iamV0cyBkJ2VycmV1ciBkZSB2YWxpZGF0aW9uLgogICAgLy8gU2FucyDDp2EsIGBuZXcgRXJyb3IoZGV0YWlsKWAgYWZmaWNoZSBsaXR0w6lyYWxlbWVudCAiW29iamVjdCBPYmplY3RdIgogICAgLy8gw6AgbCfDqWNyYW4gKGNlIHF1ZSBgZGV0YWlsYCBkZXZpZW50IHVuZSBmb2lzIGNvbnZlcnRpIGVuIHRleHRlKSBhdSBsaWV1CiAgICAvLyBkJ3VuIG1lc3NhZ2UgY29tcHLDqWhlbnNpYmxlIOKAlCBjZXR0ZSBmb25jdGlvbiB0cmFuc2Zvcm1lIGNldHRlIGxpc3RlIGVuCiAgICAvLyBwaHJhc2UgbGlzaWJsZSBlbiBmcmFuw6dhaXMuCiAgICBjb25zdCBfVkFMSURBVElPTl9GSUVMRF9MQUJFTFNfRlIgPSB7CiAgICAgIHBhc3N3b3JkOiAibW90IGRlIHBhc3NlIiwKICAgICAgbmV3X3Bhc3N3b3JkOiAibm91dmVhdSBtb3QgZGUgcGFzc2UiLAogICAgICBlbWFpbDogImVtYWlsIiwKICAgICAgdXNlcm5hbWU6ICJub20gZCd1dGlsaXNhdGV1ciIsCiAgICAgIGludml0ZV90b2tlbjogImNvZGUgZCdpbnZpdGF0aW9uIiwKICAgICAgdG9rZW46ICJqZXRvbiIsCiAgICAgIGFtb3VudDogIm1vbnRhbnQiLAogICAgICBuYW1lOiAibm9tIiwKICAgICAgY2F0ZWdvcnk6ICJjYXTDqWdvcmllIiwKICAgICAgZGVzY3JpcHRpb246ICJkZXNjcmlwdGlvbiIsCiAgICB9OwoKICAgIGZ1bmN0aW9uIF9mcmllbmRseVZhbGlkYXRpb25FcnJvcihlcnIpIHsKICAgICAgY29uc3QgbG9jID0gQXJyYXkuaXNBcnJheShlcnIubG9jKSA/IGVyci5sb2MuZmlsdGVyKChwKSA9PiBwICE9PSAiYm9keSIpIDogW107CiAgICAgIGNvbnN0IGZpZWxkID0gbG9jLmxlbmd0aCA/IFN0cmluZyhsb2NbbG9jLmxlbmd0aCAtIDFdKSA6IG51bGw7CiAgICAgIGNvbnN0IGxhYmVsID0gKGZpZWxkICYmIF9WQUxJREFUSU9OX0ZJRUxEX0xBQkVMU19GUltmaWVsZF0pIHx8IGZpZWxkIHx8ICJjaGFtcCI7CiAgICAgIGNvbnN0IGN0eCA9IGVyci5jdHggfHwge307CiAgICAgIGlmIChlcnIudHlwZSA9PT0gInN0cmluZ190b29fc2hvcnQiICYmIGN0eC5taW5fbGVuZ3RoICE9IG51bGwpIHsKICAgICAgICByZXR1cm4gYExlICR7bGFiZWx9IGRvaXQgY29udGVuaXIgYXUgbW9pbnMgJHtjdHgubWluX2xlbmd0aH0gY2FyYWN0w6hyZSR7Y3R4Lm1pbl9sZW5ndGggPiAxID8gInMiIDogIiJ9LmA7CiAgICAgIH0KICAgICAgaWYgKGVyci50eXBlID09PSAic3RyaW5nX3Rvb19sb25nIiAmJiBjdHgubWF4X2xlbmd0aCAhPSBudWxsKSB7CiAgICAgICAgcmV0dXJuIGBMZSAke2xhYmVsfSBuZSBkb2l0IHBhcyBkw6lwYXNzZXIgJHtjdHgubWF4X2xlbmd0aH0gY2FyYWN0w6hyZSR7Y3R4Lm1heF9sZW5ndGggPiAxID8gInMiIDogIiJ9LmA7CiAgICAgIH0KICAgICAgaWYgKGVyci50eXBlID09PSAibWlzc2luZyIpIHsKICAgICAgICByZXR1cm4gYExlIGNoYW1wIMKrICR7bGFiZWx9IMK7IGVzdCByZXF1aXMuYDsKICAgICAgfQogICAgICByZXR1cm4gYFbDqXJpZmllIGxlIGNoYW1wIMKrICR7bGFiZWx9IMK7LmA7CiAgICB9CgogICAgZnVuY3Rpb24gZXh0cmFjdEVycm9yRGV0YWlsKGRhdGEsIGZhbGxiYWNrKSB7CiAgICAgIGNvbnN0IGRldGFpbCA9IGRhdGEgJiYgZGF0YS5kZXRhaWw7CiAgICAgIGlmICh0eXBlb2YgZGV0YWlsID09PSAic3RyaW5nIiAmJiBkZXRhaWwpIHJldHVybiBkZXRhaWw7CiAgICAgIGlmIChBcnJheS5pc0FycmF5KGRldGFpbCkgJiYgZGV0YWlsLmxlbmd0aCkgewogICAgICAgIHJldHVybiBkZXRhaWwKICAgICAgICAgIC5tYXAoKGUpID0+IChlICYmIHR5cGVvZiBlID09PSAib2JqZWN0IiA/IF9mcmllbmRseVZhbGlkYXRpb25FcnJvcihlKSA6IFN0cmluZyhlKSkpCiAgICAgICAgICAuam9pbigiICIpOwogICAgICB9CiAgICAgIHJldHVybiBmYWxsYmFjazsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBwb3N0QXV0aChwYXRoLCBwYXlsb2FkKSB7CiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKHBhdGgsIHsKICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICBoZWFkZXJzOiB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgfSk7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIHRocm93IG5ldyBFcnJvcihleHRyYWN0RXJyb3JEZXRhaWwoZGF0YSwgIlVuZSBlcnJldXIgZXN0IHN1cnZlbnVlLCByw6llc3NhaWUuIikpOwogICAgICB9CiAgICAgIHJldHVybiBkYXRhOwogICAgfQoKICAgIGZ1bmN0aW9uIG9uU2Vzc2lvbk9idGFpbmVkKHRva2VuKSB7CiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRPS0VOX1NUT1JBR0VfS0VZLCB0b2tlbik7CiAgICAgIC8vIFJlY2hhcmdlbWVudCBjb21wbGV0IHBsdXTDtHQgcXVlIGRlIHLDqS1lbmNoYcOubmVyIGwnaW5pdCBtYW51ZWxsZW1lbnQgOgogICAgICAvLyBwbHVzIHNpbXBsZSBldCBwbHVzIHPDu3IgKG9uIHJlcGFydCBhdmVjIHVuIMOpdGF0IHByb3ByZSwgQVBJX0tFWSBsdQogICAgICAvLyBkZXB1aXMgbGUgbG9jYWxTdG9yYWdlIGNvbW1lIGF1IHRvdXQgcHJlbWllciBjaGFyZ2VtZW50KS4KICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOwogICAgfQoKICAgIC8vIC0tLSBDb25uZXhpb24gLS0tCiAgICBjb25zdCBsb2dpbkVtYWlsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tZW1haWwtaW5wdXQiKTsKICAgIGNvbnN0IGxvZ2luUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dpbi1wYXNzd29yZC1pbnB1dCIpOwogICAgY29uc3QgbG9naW5TdWJtaXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tc3VibWl0LWJ0biIpOwogICAgY29uc3QgbG9naW5FcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWVycm9yIik7CgogICAgYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdExvZ2luKCkgewogICAgICBjb25zdCBlbWFpbCA9IGxvZ2luRW1haWxJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gbG9naW5QYXNzd29yZElucHV0LnZhbHVlOwogICAgICBpZiAoIWVtYWlsIHx8ICFwYXNzd29yZCkgcmV0dXJuOwogICAgICBsb2dpbkVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHNldEF1dGhCdXN5KGxvZ2luU3VibWl0QnRuLCAiQ29ubmV4aW9u4oCmIik7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHBvc3RBdXRoKCIvYXBpL2F1dGgvbG9naW4iLCB7IGVtYWlsLCBwYXNzd29yZCB9KTsKICAgICAgICBvblNlc3Npb25PYnRhaW5lZChkYXRhLnRva2VuKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgbG9naW5FcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgbG9naW5FcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KGxvZ2luU3VibWl0QnRuLCBudWxsLCAiU2UgY29ubmVjdGVyIik7CiAgICAgIH0KICAgIH0KICAgIGxvZ2luU3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdExvZ2luKTsKICAgIFtsb2dpbkVtYWlsSW5wdXQsIGxvZ2luUGFzc3dvcmRJbnB1dF0uZm9yRWFjaCgoaW5wdXQpID0+IHsKICAgICAgaW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigia2V5ZG93biIsIChlKSA9PiB7IGlmIChlLmtleSA9PT0gIkVudGVyIikgYXR0ZW1wdExvZ2luKCk7IH0pOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tZ290by1mb3Jnb3QiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygiZm9yZ290IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWdvdG8tc2lnbnVwIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93QXV0aFZpZXcoInNpZ251cCIpKTsKCiAgICAvLyAtLS0gSW5zY3JpcHRpb24gKHN1ciBpbnZpdGF0aW9uKSAtLS0KICAgIGNvbnN0IHNpZ251cEludml0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNpZ251cC1pbnZpdGUtaW5wdXQiKTsKICAgIGNvbnN0IHNpZ251cEVtYWlsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLWVtYWlsLWlucHV0Iik7CiAgICBjb25zdCBzaWdudXBVc2VybmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNpZ251cC11c2VybmFtZS1pbnB1dCIpOwogICAgY29uc3Qgc2lnbnVwUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IHNpZ251cFN1Ym1pdEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtc3VibWl0LWJ0biIpOwogICAgY29uc3Qgc2lnbnVwRXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtZXJyb3IiKTsKCiAgICBhc3luYyBmdW5jdGlvbiBhdHRlbXB0U2lnbnVwKCkgewogICAgICBjb25zdCBpbnZpdGVfdG9rZW4gPSBzaWdudXBJbnZpdGVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IGVtYWlsID0gc2lnbnVwRW1haWxJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHVzZXJuYW1lID0gc2lnbnVwVXNlcm5hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gc2lnbnVwUGFzc3dvcmRJbnB1dC52YWx1ZTsKICAgICAgaWYgKCFpbnZpdGVfdG9rZW4gfHwgIWVtYWlsIHx8ICF1c2VybmFtZSB8fCAhcGFzc3dvcmQpIHsKICAgICAgICBzaWdudXBFcnJvckVsLnRleHRDb250ZW50ID0gIlRvdXMgbGVzIGNoYW1wcyBzb250IHJlcXVpcy4iOwogICAgICAgIHNpZ251cEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHNpZ251cEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHNldEF1dGhCdXN5KHNpZ251cFN1Ym1pdEJ0biwgIkNyw6lhdGlvbuKApiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL3NpZ251cCIsIHsgaW52aXRlX3Rva2VuLCBlbWFpbCwgdXNlcm5hbWUsIHBhc3N3b3JkIH0pOwogICAgICAgIG9uU2Vzc2lvbk9idGFpbmVkKGRhdGEudG9rZW4pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaWdudXBFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgc2lnbnVwRXJyb3JFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShzaWdudXBTdWJtaXRCdG4sIG51bGwsICJDcsOpZXIgbW9uIGNvbXB0ZSIpOwogICAgICB9CiAgICB9CiAgICBzaWdudXBTdWJtaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhdHRlbXB0U2lnbnVwKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtZ290by1sb2dpbiIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0F1dGhWaWV3KCJsb2dpbiIpKTsKCiAgICAvLyAtLS0gTW90IGRlIHBhc3NlIG91Ymxpw6kgLS0tCiAgICBjb25zdCBmb3Jnb3RFbWFpbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1lbWFpbC1pbnB1dCIpOwogICAgY29uc3QgZm9yZ290U3VibWl0QnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1zdWJtaXQtYnRuIik7CiAgICBjb25zdCBmb3Jnb3RFcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1lcnJvciIpOwogICAgY29uc3QgZm9yZ290U3VjY2Vzc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1zdWNjZXNzIik7CgogICAgYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdEZvcmdvdFBhc3N3b3JkKCkgewogICAgICBjb25zdCBlbWFpbCA9IGZvcmdvdEVtYWlsSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBpZiAoIWVtYWlsKSByZXR1cm47CiAgICAgIGZvcmdvdEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGZvcmdvdFN1Y2Nlc3NFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgc2V0QXV0aEJ1c3koZm9yZ290U3VibWl0QnRuLCAiRW52b2nigKYiKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL2ZvcmdvdC1wYXNzd29yZCIsIHsgZW1haWwgfSk7CiAgICAgICAgZm9yZ290U3VjY2Vzc0VsLnRleHRDb250ZW50ID0gIlNpIHVuIGNvbXB0ZSBleGlzdGUgYXZlYyBjZXQgZW1haWwsIHVuIGxpZW4gZGUgcsOpaW5pdGlhbGlzYXRpb24gdmllbnQgZCfDqnRyZSBlbnZvecOpLiI7CiAgICAgICAgZm9yZ290U3VjY2Vzc0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KGZvcmdvdFN1Ym1pdEJ0biwgbnVsbCwgIkVudm95ZXIgbGUgbGllbiIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBmb3Jnb3RFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgZm9yZ290RXJyb3JFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShmb3Jnb3RTdWJtaXRCdG4sIG51bGwsICJFbnZveWVyIGxlIGxpZW4iKTsKICAgICAgfQogICAgfQogICAgZm9yZ290U3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdEZvcmdvdFBhc3N3b3JkKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3QtZ290by1sb2dpbiIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0F1dGhWaWV3KCJsb2dpbiIpKTsKCiAgICAvLyAtLS0gUsOpaW5pdGlhbGlzYXRpb24gKGRlcHVpcyBsZSBsaWVuIHJlw6d1IHBhciBlbWFpbCwgP3Jlc2V0PVRPS0VOKSAtLS0KICAgIGNvbnN0IHJlc2V0UGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1wYXNzd29yZC1pbnB1dCIpOwogICAgY29uc3QgcmVzZXRTdWJtaXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVzZXQtc3VibWl0LWJ0biIpOwogICAgY29uc3QgcmVzZXRFcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlc2V0LWVycm9yIik7CiAgICBjb25zdCByZXNldFN1Y2Nlc3NFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1zdWNjZXNzIik7CiAgICBsZXQgcGVuZGluZ1Jlc2V0VG9rZW4gPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRSZXNldFBhc3N3b3JkKCkgewogICAgICBjb25zdCBuZXdfcGFzc3dvcmQgPSByZXNldFBhc3N3b3JkSW5wdXQudmFsdWU7CiAgICAgIGlmICghbmV3X3Bhc3N3b3JkIHx8ICFwZW5kaW5nUmVzZXRUb2tlbikgcmV0dXJuOwogICAgICByZXNldEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlc2V0U3VjY2Vzc0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBzZXRBdXRoQnVzeShyZXNldFN1Ym1pdEJ0biwgIlZhbGlkYXRpb27igKYiKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL3Jlc2V0LXBhc3N3b3JkIiwgeyB0b2tlbjogcGVuZGluZ1Jlc2V0VG9rZW4sIG5ld19wYXNzd29yZCB9KTsKICAgICAgICByZXNldFN1Y2Nlc3NFbC50ZXh0Q29udGVudCA9ICJNb3QgZGUgcGFzc2UgbWlzIMOgIGpvdXIsIHR1IHBldXggdGUgY29ubmVjdGVyLiI7CiAgICAgICAgcmVzZXRTdWNjZXNzRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3kocmVzZXRTdWJtaXRCdG4sIG51bGwsICJWYWxpZGVyIik7CiAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzaG93QXV0aFZpZXcoImxvZ2luIiksIDE1MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICByZXNldEVycm9yRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZTsKICAgICAgICByZXNldEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3kocmVzZXRTdWJtaXRCdG4sIG51bGwsICJWYWxpZGVyIik7CiAgICAgIH0KICAgIH0KICAgIHJlc2V0U3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdFJlc2V0UGFzc3dvcmQpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlc2V0LWdvdG8tbG9naW4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygibG9naW4iKSk7CgogICAgLy8gLS0tIEFmZmljaGVyL21hc3F1ZXIgbGUgbW90IGRlIHBhc3NlIChpY8O0bmUgxZNpbCkgLS0tCiAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIucGFzc3dvcmQtdG9nZ2xlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICBjb25zdCB0YXJnZXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChidG4uZGF0YXNldC50YXJnZXQpOwogICAgICBidG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgY29uc3Qgc2hvd2luZyA9IHRhcmdldC50eXBlID09PSAidGV4dCI7CiAgICAgICAgdGFyZ2V0LnR5cGUgPSBzaG93aW5nID8gInBhc3N3b3JkIiA6ICJ0ZXh0IjsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgIXNob3dpbmcpOwogICAgICAgIGJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCBzaG93aW5nID8gIkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSIgOiAiTWFzcXVlciBsZSBtb3QgZGUgcGFzc2UiKTsKICAgICAgfSk7CiAgICB9KTsKCiAgICAvLyAtLS0gRMOpY29ubmV4aW9uIC0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ291dC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgiU2UgZMOpY29ubmVjdGVyID8gVHUgZGV2cmFzIHJlc3NhaXNpciB0b24gbW90IGRlIHBhc3NlIHBvdXIgcmV2ZW5pci4iKTsKICAgICAgaWYgKG9rKSBzaG93TG9ja1NjcmVlbigibG9naW4iKTsKICAgIH0pOwoKICAgIC8vIC0tLSBMaWVucyByZcOndXMgcGFyIGVtYWlsICg/aW52aXRlPS4uLiBvdSA/cmVzZXQ9Li4uKSAtLS0KICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7CiAgICBjb25zdCBpbnZpdGVUb2tlbkZyb21VcmwgPSB1cmxQYXJhbXMuZ2V0KCJpbnZpdGUiKTsKICAgIGNvbnN0IHJlc2V0VG9rZW5Gcm9tVXJsID0gdXJsUGFyYW1zLmdldCgicmVzZXQiKTsKICAgIGxldCBpbml0aWFsQXV0aFZpZXcgPSAibG9naW4iOwogICAgaWYgKGludml0ZVRva2VuRnJvbVVybCkgewogICAgICBzaWdudXBJbnZpdGVJbnB1dC52YWx1ZSA9IGludml0ZVRva2VuRnJvbVVybDsKICAgICAgaW5pdGlhbEF1dGhWaWV3ID0gInNpZ251cCI7CiAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICB9IGVsc2UgaWYgKHJlc2V0VG9rZW5Gcm9tVXJsKSB7CiAgICAgIHBlbmRpbmdSZXNldFRva2VuID0gcmVzZXRUb2tlbkZyb21Vcmw7CiAgICAgIGluaXRpYWxBdXRoVmlldyA9ICJyZXNldCI7CiAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICB9CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBuZXdDYXRlZ29yeU5hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIpOwogICAgY29uc3QgZGVzY3JpcHRpb25JbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kZXNjcmlwdGlvbiIpOwogICAgY29uc3QgZGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRhdGUiKTsKICAgIGNvbnN0IHNhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXNhdmUiKTsKCiAgICBsZXQgZWRpdGluZ0lkID0gbnVsbDsgLy8gbnVsbCA9IGNyw6lhdGlvbiwgc2lub24gaWQgZGUgbGEgdHJhbnNhY3Rpb24gw6lkaXTDqWUKICAgIGxldCBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IG51bGw7IC8vIGNhdMOpZ29yaWUgZGUgbGEgdHJhbnNhY3Rpb24gYXZhbnQgw6lkaXRpb24gKHBvdXIgZMOpdGVjdGVyIHVuIGNoYW5nZW1lbnQpCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUGhvdG8gZGUgcmXDp3UgZW4gcGnDqGNlIGpvaW50ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjZWlwdEZpbGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1yZWNlaXB0LWZpbGUiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3V3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LXByZXZpZXctd3JhcCIpOwogICAgY29uc3QgcmVjZWlwdFByZXZpZXdJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LWltZyIpOwogICAgY29uc3QgcmVjZWlwdFBpY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcGljayIpOwogICAgY29uc3QgcmVjZWlwdFJlbW92ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVjZWlwdC1yZW1vdmUiKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveE92ZXJsYXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1vdmVybGF5Iik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveENsb3NlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtY2xvc2UiKTsKCiAgICAvLyBGaWNoaWVyIGNob2lzaSBtYWlzIHBhcyBlbmNvcmUgZW52b3nDqSAodW5pcXVlbWVudCBlbiBjcsOpYXRpb24sIHRhbnQgcXVlCiAgICAvLyBsYSB0cmFuc2FjdGlvbiBuJ2EgcGFzIGVuY29yZSBkJ2lkKSA7IGVuIMOpZGl0aW9uLCBsJ2Vudm9pIGVzdCBpbW3DqWRpYXQuCiAgICBsZXQgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgIGxldCByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICBsZXQgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKSB7CiAgICAgIGlmIChyZWNlaXB0UHJldmlld09iamVjdFVybCkgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgIHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gcmVjZWlwdFByZXZpZXdPYmplY3RVcmw7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBSZW1wbGFjZXIgbGEgcGhvdG8iOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlc2V0UmVjZWlwdFVpKCkgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKTsKICAgICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICAgIH0KICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gIiI7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndSI7CiAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHJhbnNhY3Rpb25JZCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3RyYW5zYWN0aW9uSWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHJldHVybjsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGJsb2IpOwogICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAvLyBQYXMgZ3JhdmUgOiBsJ3V0aWxpc2F0ZXVyIHBldXQganVzdGUgcsOpZXNzYXllciBkJ291dnJpciBsYSBmaWNoZS4KICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRQaWNrQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gcmVjZWlwdEZpbGVJbnB1dC5jbGljaygpKTsKCiAgICByZWNlaXB0RmlsZUlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IHJlY2VpcHRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBpZiAoIWZpbGUudHlwZS5zdGFydHNXaXRoKCJpbWFnZS8iKSkgewogICAgICAgIHNob3dUb2FzdCgiQ2hvaXNpcyB1bmUgaW1hZ2UgKEpQRUcsIFBORywgV0VCUCBvdSBIRUlDKSIsIHRydWUpOwogICAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IDggKiAxMDI0ICogMTAyNCkgewogICAgICAgIHNob3dUb2FzdCgiSW1hZ2UgdHJvcCBsb3VyZGUgKDggTW8gbWF4aW11bSkiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGZpbGUpOwoKICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgIC8vIFRyYW5zYWN0aW9uIGTDqWrDoCBleGlzdGFudGUgOiBvbiBlbnZvaWUgdG91dCBkZSBzdWl0ZSwgaW5kw6lwZW5kYW1tZW50CiAgICAgICAgLy8gZHUgYm91dG9uICJFbnJlZ2lzdHJlciIgZHUgZm9ybXVsYWlyZS4KICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIGZpbGUpOwogICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgfSkudGhlbihhc3luYyAocmVzKSA9PiB7CiAgICAgICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGV4dHJhY3RFcnJvckRldGFpbChkYXRhLCBgRXJyZXVyIEhUVFAgJHtyZXMuc3RhdHVzfWApKTsKICAgICAgICAgICAgfQogICAgICAgICAgfSk7CiAgICAgICAgICBoYXNFeGlzdGluZ1JlY2VpcHQgPSB0cnVlOwogICAgICAgICAgc2hvd1RvYXN0KCJQaG90byBkdSByZcOndSBlbnJlZ2lzdHLDqWUiKTsKICAgICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0gZWxzZSB7CiAgICAgICAgLy8gTm91dmVsbGUgdHJhbnNhY3Rpb24gcGFzIGVuY29yZSBjcsOpw6llIDogb24gZ2FyZGUgbGUgZmljaGllciBkZSBjw7R0w6ksCiAgICAgICAgLy8gaWwgc2VyYSBlbnZvecOpIGp1c3RlIGFwcsOocyBsYSBjcsOpYXRpb24gKHZvaXIgYnRuLXNhdmUpLgogICAgICAgIHBlbmRpbmdSZWNlaXB0RmlsZSA9IGZpbGU7CiAgICAgIH0KICAgIH0pOwoKICAgIHJlY2VpcHRSZW1vdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGlmIChlZGl0aW5nSWQgJiYgaGFzRXhpc3RpbmdSZWNlaXB0KSB7CiAgICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBsYSBwaG90byBkZSBjZSByZcOndSA/IikpKSByZXR1cm47CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH0vcmVjZWlwdGAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgICAgICBzaG93VG9hc3QoIlBob3RvIHN1cHByaW3DqWUiKTsKICAgICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0gZWxzZSB7CiAgICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgfQogICAgfSk7CgogICAgZnVuY3Rpb24gb3BlblJlY2VpcHRMaWdodGJveCh0cmFuc2FjdGlvbklkKSB7CiAgICAgIGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3RyYW5zYWN0aW9uSWR9L3JlY2VpcHRgLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KQogICAgICAgIC50aGVuKChyZXMpID0+IHsKICAgICAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoIkltcG9zc2libGUgZGUgY2hhcmdlciBsYSBwaG90byIpOwogICAgICAgICAgcmV0dXJuIHJlcy5ibG9iKCk7CiAgICAgICAgfSkKICAgICAgICAudGhlbigoYmxvYikgPT4gewogICAgICAgICAgY29uc3QgdXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgICAgIHJlY2VpcHRMaWdodGJveEltZy5zcmMgPSB1cmw7CiAgICAgICAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIH0pCiAgICAgICAgLmNhdGNoKChlcnIpID0+IHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWNlaXB0TGlnaHRib3goKSB7CiAgICAgIHJlY2VpcHRMaWdodGJveE92ZXJsYXkuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGlmIChyZWNlaXB0TGlnaHRib3hJbWcuc3JjKSB7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0TGlnaHRib3hJbWcuc3JjKTsKICAgICAgICByZWNlaXB0TGlnaHRib3hJbWcuc3JjID0gIiI7CiAgICAgIH0KICAgIH0KCiAgICByZWNlaXB0TGlnaHRib3hDbG9zZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlUmVjZWlwdExpZ2h0Ym94KTsKICAgIHJlY2VpcHRMaWdodGJveE92ZXJsYXkuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IHJlY2VpcHRMaWdodGJveE92ZXJsYXkpIGNsb3NlUmVjZWlwdExpZ2h0Ym94KCk7CiAgICB9KTsKCiAgICBjb25zdCBjYXRlZ29yaWVzQnlUeXBlID0gewogICAgICBleHBlbnNlOiBbCiAgICAgICAgWyJyZXN0YXVyYW50IiwgIlJlc3RhdXJhbnQiXSwKICAgICAgICBbImNvdXJzZXMiLCAiQ291cnNlcyJdLAogICAgICAgIFsidHJhbnNwb3J0IiwgIlRyYW5zcG9ydCJdLAogICAgICAgIFsibG9nZW1lbnQiLCAiTG9nZW1lbnQiXSwKICAgICAgICBbImxvaXNpcnMiLCAiTG9pc2lycyJdLAogICAgICAgIFsic2FudMOpIiwgIlNhbnTDqSJdLAogICAgICAgIFsiYXV0cmUiLCAiQXV0cmUiXSwKICAgICAgXSwKICAgICAgaW5jb21lOiBbCiAgICAgICAgWyJzYWxhaXJlIiwgIlNhbGFpcmUiXSwKICAgICAgICBbImZyZWVsYW5jZSIsICJGcmVlbGFuY2UiXSwKICAgICAgICBbInJlbWJvdXJzZW1lbnQiLCAiUmVtYm91cnNlbWVudCJdLAogICAgICAgIFsiY2FkZWF1IiwgIkNhZGVhdSJdLAogICAgICAgIFsiYXV0cmUiLCAiQXV0cmUiXSwKICAgICAgXSwKICAgIH07CgogICAgY29uc3QgYWxsQ2F0ZWdvcnlMYWJlbHMgPSBPYmplY3QuZnJvbUVudHJpZXMoCiAgICAgIFsuLi5jYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UsIC4uLmNhdGVnb3JpZXNCeVR5cGUuaW5jb21lXQogICAgKTsKCiAgICAvLyBDYXTDqWdvcmllcyBjcsOpw6llcyBwYXIgbCd1dGlsaXNhdGV1ciBkZXB1aXMgbGUgYmFuZGVhdSBkZSBzdWdnZXN0aW9uCiAgICAvLyAodm9pciBwbHVzIGJhcyksIGV0IHN1Z2dlc3Rpb25zIGlnbm9yw6llcyA6IHN0b2Nrw6llcyBjw7R0w6kgc2VydmV1cgogICAgLy8gKHRhYmxlcyBjdXN0b21fY2F0ZWdvcmllcyAvIGRpc21pc3NlZF9jYXRlZ29yeV9zdWdnZXN0aW9ucykgcGx1dMO0dAogICAgLy8gcXVlIGRhbnMgbGUgbmF2aWdhdGV1ciwgcG91ciBzdWl2cmUgc3VyIHRvdXMgbGVzIGFwcGFyZWlscyAodMOpbMOpcGhvbmUsCiAgICAvLyB0YWJsZXR0ZSwgb3JkaW5hdGV1cikgcGx1dMO0dCBxdWUgZGUgbmUgbWFyY2hlciBxdWUgbMOgIG/DuSBjJ8OpdGFpdCBjcsOpw6kuCiAgICBsZXQgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMgPSBuZXcgU2V0KCk7CiAgICBsZXQgYWxsQnVkZ2V0cyA9IFtdOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRCdWRnZXRzKCkgewogICAgICB0cnkgewogICAgICAgIGFsbEJ1ZGdldHMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9idWRnZXRzIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGVzIGJ1ZGdldHMgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfQoKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBPYmplY3RpZiBkJ8OpcGFyZ25lIG1lbnN1ZWwgKyBjb25zZWlscwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgbGV0IHNhdmluZ3NHb2FsID0gbnVsbDsgLy8geyBtb250aGx5X3RhcmdldCB9IG91IG51bGwgc2kgamFtYWlzIGNvbmZpZ3Vyw6kKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkU2F2aW5nc0dvYWwoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgc2F2aW5nc0dvYWwgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9zYXZpbmdzLWdvYWwiKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCBkZSBsJ29iamVjdGlmIGQnw6lwYXJnbmUgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidWRnZXRzLXNhdmUtYWxsLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBlbnRyaWVzID0gT2JqZWN0LmVudHJpZXMoYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeSk7CiAgICAgIGxldCBzYXZlZENvdW50ID0gMDsKICAgICAgbGV0IGhhZEVycm9yID0gZmFsc2U7CiAgICAgIGZvciAoY29uc3QgW2NhdGVnb3J5LCBpbnB1dF0gb2YgZW50cmllcykgewogICAgICAgIGNvbnN0IHJhdyA9IGlucHV0LnZhbHVlOwogICAgICAgIGlmIChyYXcgPT09ICIiIHx8IHJhdyA9PT0gbnVsbCkgY29udGludWU7CiAgICAgICAgY29uc3QgYW1vdW50ID0gTnVtYmVyKHJhdyk7CiAgICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIGNvbnRpbnVlOwogICAgICAgIHRyeSB7CiAgICAgICAgICBhd2FpdCBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpOwogICAgICAgICAgc2F2ZWRDb3VudCArPSAxOwogICAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgICAgaGFkRXJyb3IgPSB0cnVlOwogICAgICAgIH0KICAgICAgfQogICAgICBpZiAoaGFkRXJyb3IpIHsKICAgICAgICBzaG93VG9hc3QoIkNlcnRhaW5zIGJ1ZGdldHMgbidvbnQgcGFzIHB1IMOqdHJlIGVucmVnaXN0csOpcyIsIHRydWUpOwogICAgICB9IGVsc2UgaWYgKHNhdmVkQ291bnQgPT09IDApIHsKICAgICAgICBzaG93VG9hc3QoIkluZGlxdWUgYXUgbW9pbnMgdW4gbW9udGFudCBkZSBidWRnZXQgdmFsaWRlIiwgdHJ1ZSk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgc2hvd1RvYXN0KCJCdWRnZXRzIGVucmVnaXN0csOpcyIpOwogICAgICB9CiAgICAgIHJlbmRlckJ1ZGdldHMoYWxsVHJhbnNhY3Rpb25zKTsKICAgIH0pOwoKICAgIGNvbnN0IHNhdmluZ3NHb2FsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1nb2FsLWlucHV0Iik7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1nb2FsLXNhdmUtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGFtb3VudCA9IE51bWJlcihzYXZpbmdzR29hbElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIkluZGlxdWUgdW4gbW9udGFudCBkJ29iamVjdGlmIHZhbGlkZSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICB0cnkgewogICAgICAgIHNhdmluZ3NHb2FsID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvc2F2aW5ncy1nb2FsIiwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgbW9udGhseV90YXJnZXQ6IGFtb3VudCB9KSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoIk9iamVjdGlmIGVucmVnaXN0csOpIik7CiAgICAgICAgcmVuZGVyU2F2aW5ncyhhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICB9CiAgICB9KTsKCiAgICBmdW5jdGlvbiByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucykgewogICAgICBpZiAoc2F2aW5nc0dvYWwpIHNhdmluZ3NHb2FsSW5wdXQudmFsdWUgPSBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldDsKCiAgICAgIC8vIFNvbGRlIGR1IG1vaXMgZW4gY291cnMgKHJldmVudXMgLSBkw6lwZW5zZXMpLCB0b3V0IGNvbmZvbmR1LgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBsZXQgbW9udGhJbmNvbWUgPSAwOwogICAgICBsZXQgbW9udGhFeHBlbnNlcyA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gY3VycmVudE1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIG1vbnRoSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgbW9udGhFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBtb250aE5ldCA9IG1vbnRoSW5jb21lIC0gbW9udGhFeHBlbnNlczsKCiAgICAgIGNvbnN0IHByb2dyZXNzU2VjdGlvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLXNlY3Rpb24iKTsKICAgICAgY29uc3QgcHJvZ3Jlc3NUZXh0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtcHJvZ3Jlc3MtdGV4dCIpOwogICAgICBjb25zdCBwcm9ncmVzc0JhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLWJhciIpOwogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgcHJvZ3Jlc3NTZWN0aW9uLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIGNvbnN0IHRhcmdldCA9IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0OwogICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWF4KDAsIE1hdGgubWluKChtb250aE5ldCAvIHRhcmdldCkgKiAxMDAsIDEwMCkpOwogICAgICAgIHByb2dyZXNzVGV4dC50ZXh0Q29udGVudCA9IGAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChtb250aE5ldCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0KX1gOwogICAgICAgIGxldCBjbHMgPSAib2siOwogICAgICAgIGlmIChtb250aE5ldCA8IDApIGNscyA9ICJvdmVyIjsKICAgICAgICBlbHNlIGlmIChtb250aE5ldCA8IHRhcmdldCkgY2xzID0gIndhcm5pbmciOwogICAgICAgIHByb2dyZXNzQmFyLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICBwcm9ncmVzc0Jhci5zdHlsZS53aWR0aCA9IHBjdCArICIlIjsKICAgICAgfSBlbHNlIHsKICAgICAgICBwcm9ncmVzc1NlY3Rpb24uY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIH0KCiAgICAgIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCk7CiAgICAgIHJlbmRlclBsYWNlbWVudFNpbXVsYXRpb24oKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTaW11bGF0aW9uIGRlIHBsYWNlbWVudCAoaW50w6lyw6p0cyBjb21wb3PDqXMsIGNhbGN1bMOpcyBtZW5zdWVsbGVtZW50KSDigJQKICAgIC8vIHB1cmVtZW50IGPDtHTDqSBjbGllbnQgOiBhdWN1bmUgZG9ubsOpZSByw6llbGxlIGRlIGwndXRpbGlzYXRldXIgbidlbnRyZQogICAgLy8gZW4gamV1LCBzZXVsZW1lbnQgbGVzIDQgY2hhbXBzIGR1IGZvcm11bGFpcmUuCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBsZXQgcGxhY2VtZW50Q2hhcnQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIGNvbXB1dGVQbGFjZW1lbnRTZXJpZXMoaW5pdGlhbCwgbW9udGhseUNvbnRyaWJ1dGlvbiwgYW5udWFsUmF0ZVBlcmNlbnQsIHllYXJzKSB7CiAgICAgIGNvbnN0IG1vbnRocyA9IE1hdGgubWF4KDEsIE1hdGgucm91bmQoeWVhcnMgKiAxMikpOwogICAgICBjb25zdCBtb250aGx5UmF0ZSA9IE1hdGgucG93KDEgKyBhbm51YWxSYXRlUGVyY2VudCAvIDEwMCwgMSAvIDEyKSAtIDE7CiAgICAgIGxldCBiYWxhbmNlID0gaW5pdGlhbDsKICAgICAgY29uc3Qgc2VyaWVzID0gW2JhbGFuY2VdOwogICAgICBmb3IgKGxldCBtID0gMTsgbSA8PSBtb250aHM7IG0rKykgewogICAgICAgIGJhbGFuY2UgPSBiYWxhbmNlICogKDEgKyBtb250aGx5UmF0ZSkgKyBtb250aGx5Q29udHJpYnV0aW9uOwogICAgICAgIHNlcmllcy5wdXNoKGJhbGFuY2UpOwogICAgICB9CiAgICAgIHJldHVybiBzZXJpZXM7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbigpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LXBsYWNlbWVudCIpOwogICAgICBpZiAoIWNhbnZhcykgcmV0dXJuOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1jaGFydC1lbXB0eSIpOwogICAgICBjb25zdCBpbml0aWFsID0gTWF0aC5tYXgoMCwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtaW5pdGlhbCIpLnZhbHVlKSB8fCAwKTsKICAgICAgY29uc3QgbW9udGhseSA9IE1hdGgubWF4KDAsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LW1vbnRobHkiKS52YWx1ZSkgfHwgMCk7CiAgICAgIGNvbnN0IHJhdGUgPSBNYXRoLm1heCgwLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1yYXRlIikudmFsdWUpIHx8IDApOwogICAgICBjb25zdCB5ZWFycyA9IE1hdGgubWF4KDEsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LXllYXJzIikudmFsdWUpIHx8IDEpOwoKICAgICAgY29uc3Qgc2VyaWVzID0gY29tcHV0ZVBsYWNlbWVudFNlcmllcyhpbml0aWFsLCBtb250aGx5LCByYXRlLCB5ZWFycyk7CiAgICAgIGNvbnN0IG1vbnRocyA9IHNlcmllcy5sZW5ndGggLSAxOwogICAgICBjb25zdCBsYWJlbHMgPSBzZXJpZXMubWFwKChfLCBpKSA9PiAoCiAgICAgICAgaSAlIDEyID09PSAwID8gYEFuICR7aSAvIDEyfWAgOiAiIgogICAgICApKTsKCiAgICAgIGlmIChwbGFjZW1lbnRDaGFydCkgeyBwbGFjZW1lbnRDaGFydC5kZXN0cm95KCk7IHBsYWNlbWVudENoYXJ0ID0gbnVsbDsgfQogICAgICBpZiAoZW1wdHlFbCkgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgIHBsYWNlbWVudENoYXJ0ID0gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJsaW5lIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgbGFiZWw6ICJTb2xkZSBwcm9qZXTDqSIsCiAgICAgICAgICAgIGRhdGE6IHNlcmllcywKICAgICAgICAgICAgYm9yZGVyQ29sb3I6IENIQVJUX0NPTE9SU1sxXSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiAicmdiYSgzNCwgMTk3LCA5NCwgMC4xNSkiLAogICAgICAgICAgICBmaWxsOiB0cnVlLAogICAgICAgICAgICB0ZW5zaW9uOiAwLjIsCiAgICAgICAgICAgIHBvaW50UmFkaXVzOiAwLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7IGxlZ2VuZDogeyBkaXNwbGF5OiBmYWxzZSB9IH0sCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjYWxsYmFjazogKHYpID0+IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh2KSB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0sIGVtcHR5RWwpOwoKICAgICAgY29uc3QgZmluYWxCYWxhbmNlID0gc2VyaWVzW3Nlcmllcy5sZW5ndGggLSAxXTsKICAgICAgY29uc3QgdG90YWxDb250cmlidXRlZCA9IGluaXRpYWwgKyBtb250aGx5ICogbW9udGhzOwogICAgICBjb25zdCBpbnRlcmVzdEVhcm5lZCA9IGZpbmFsQmFsYW5jZSAtIHRvdGFsQ29udHJpYnV0ZWQ7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtcmVzdWx0IikuaW5uZXJIVE1MID0KICAgICAgICBgQXByw6hzICR7eWVhcnN9IGFuJHt5ZWFycyA+IDEgPyAicyIgOiAiIn0gOiA8c3Ryb25nPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGZpbmFsQmFsYW5jZSl9PC9zdHJvbmc+IGAgKwogICAgICAgIGAoZG9udCAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpbnRlcmVzdEVhcm5lZCl9IGQnaW50w6lyw6p0cywgcG91ciAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbENvbnRyaWJ1dGVkKX0gdmVyc8OpcykuYDsKICAgIH0KCiAgICBmb3IgKGNvbnN0IGlkIG9mIFsicGxhY2VtZW50LWluaXRpYWwiLCAicGxhY2VtZW50LW1vbnRobHkiLCAicGxhY2VtZW50LXJhdGUiLCAicGxhY2VtZW50LXllYXJzIl0pIHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgcmVuZGVyUGxhY2VtZW50U2ltdWxhdGlvbik7CiAgICB9CgogICAgLy8gQ29uc2VpbHMgOiBjcm9pc2UgZMOpcGFzc2VtZW50cyBkZSBidWRnZXQgKG9uZ2xldCBUYWJsZWF1IGRlIGJvcmQpIGV0CiAgICAvLyB0ZW5kYW5jZXMgcGFyIGNhdMOpZ29yaWUgcG91ciBwb2ludGVyIHZlcnMgY2UgcXVpIGFpZGUgbGUgcGx1cyDDoAogICAgLy8gYXR0ZWluZHJlIGwnb2JqZWN0aWYg4oCUIHBhcyB1bmUgSUEsIGp1c3RlIGRlcyByw6hnbGVzIHNpbXBsZXMgc3VyIGRlcwogICAgLy8gZG9ubsOpZXMgZMOpasOgIGNhbGN1bMOpZXMgYWlsbGV1cnMgZGFucyBsJ2FwcC4KICAgIGZ1bmN0aW9uIHJlbmRlclNhdmluZ3NBZHZpY2UodHJhbnNhY3Rpb25zLCBtb250aE5ldCkgewogICAgICBjb25zdCBsaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1hZHZpY2UtbGlzdCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtYWR2aWNlLWVtcHR5Iik7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgY29uc3QgYWR2aWNlID0gW107CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFsczogbW9udGhUb3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBjdXJyZW50TW9udGhLZXkpOwogICAgICBjb25zdCB0cmVuZHMgPSBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgY29uc3QgdHJlbmRCeUNhdGVnb3J5ID0gT2JqZWN0LmZyb21FbnRyaWVzKHRyZW5kcy5tYXAoKHQpID0+IFt0LmNhdGVnb3J5LCB0XSkpOwoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCwgdHJpw6llcyBwYXIgbW9udGFudCBkZQogICAgICAvLyBkw6lwYXNzZW1lbnQgZMOpY3JvaXNzYW50IOKAlCBjZSBzb250IGxlcyBsZXZpZXJzIGxlcyBwbHVzIHV0aWxlcy4KICAgICAgY29uc3Qgb3ZlckJ1ZGdldCA9IFtdOwogICAgICBmb3IgKGNvbnN0IGJ1ZGdldCBvZiBhbGxCdWRnZXRzKSB7CiAgICAgICAgY29uc3Qgc3BlbnQgPSBtb250aFRvdGFsc1tidWRnZXQuY2F0ZWdvcnldIHx8IDA7CiAgICAgICAgaWYgKHNwZW50ID4gYnVkZ2V0LmFtb3VudCkgewogICAgICAgICAgb3ZlckJ1ZGdldC5wdXNoKHsgY2F0ZWdvcnk6IGJ1ZGdldC5jYXRlZ29yeSwgc3BlbnQsIGJ1ZGdldDogYnVkZ2V0LmFtb3VudCwgb3Zlcjogc3BlbnQgLSBidWRnZXQuYW1vdW50IH0pOwogICAgICAgIH0KICAgICAgfQogICAgICBvdmVyQnVkZ2V0LnNvcnQoKGEsIGIpID0+IGIub3ZlciAtIGEub3Zlcik7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2Ygb3ZlckJ1ZGdldC5zbGljZSgwLCAzKSkgewogICAgICAgIGNvbnN0IGxhYmVsID0gZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tpdGVtLmNhdGVnb3J5XSB8fCBpdGVtLmNhdGVnb3J5KTsKICAgICAgICBjb25zdCB0cmVuZCA9IHRyZW5kQnlDYXRlZ29yeVtpdGVtLmNhdGVnb3J5XTsKICAgICAgICBsZXQgdGV4dCA9IGBUdSBhcyBkw6lwYXNzw6kgdG9uIGJ1ZGdldCA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0ub3Zlcil9IGNlIG1vaXMtY2kuYDsKICAgICAgICBpZiAodHJlbmQgJiYgdHJlbmQuZGlyZWN0aW9uID09PSAidXAiKSB7CiAgICAgICAgICB0ZXh0ICs9IGAgTGEgdGVuZGFuY2UgZXN0IMOgIGxhIGhhdXNzZSAoKyR7TWF0aC5yb3VuZCh0cmVuZC5yYXRpbyAqIDEwMCl9JSB2cyB0YSBtb3llbm5lKSDigJQgcsOpZHVpcmUgY2VzIGTDqXBlbnNlcyB0J2FpZGVyYWl0IGxlIHBsdXMgw6AgYXR0ZWluZHJlIHRvbiBvYmplY3RpZi5gOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0ZXh0ICs9IGAgRXNzYWllIGRlIHJhbWVuZXIgw6dhIHNvdXMgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5idWRnZXQpfSBsZSBtb2lzIHByb2NoYWluLmA7CiAgICAgICAgfQogICAgICAgIGFkdmljZS5wdXNoKHsgdHlwZTogIndhcm5pbmciLCBpY29uOiAi4pqg77iPIiwgdGV4dCB9KTsKICAgICAgfQoKICAgICAgLy8gQ2F0w6lnb3JpZXMgZW4gbmV0dGUgaGF1c3NlIG3Dqm1lIHNhbnMgYnVkZ2V0IGTDqXBhc3PDqSAob3Ugc2FucyBidWRnZXQKICAgICAgLy8gZMOpZmluaSBkdSB0b3V0KSA6IHVuIHNpZ25hbCB1dGlsZSBlbiBzb2kuCiAgICAgIGNvbnN0IHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCA9IHRyZW5kcwogICAgICAgIC5maWx0ZXIoKHQpID0+IHQuZGlyZWN0aW9uID09PSAidXAiICYmIHQuYXZlcmFnZSA+IDAgJiYgIW92ZXJCdWRnZXQuc29tZSgobykgPT4gby5jYXRlZ29yeSA9PT0gdC5jYXRlZ29yeSkpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGIucmF0aW8gLSBhLnJhdGlvKQogICAgICAgIC5zbGljZSgwLCAyKTsKICAgICAgZm9yIChjb25zdCB0IG9mIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydCkgewogICAgICAgIGNvbnN0IGxhYmVsID0gZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KTsKICAgICAgICBhZHZpY2UucHVzaCh7CiAgICAgICAgICB0eXBlOiAiaW5mbyIsCiAgICAgICAgICBpY29uOiAi8J+TiCIsCiAgICAgICAgICB0ZXh0OiBgVGVzIGTDqXBlbnNlcyBlbiA8c3Ryb25nPiR7bGFiZWx9PC9zdHJvbmc+IHNvbnQgZW4gaGF1c3NlIGRlICR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lIHBhciByYXBwb3J0IMOgIHRhIG1veWVubmUg4oCUIMOgIHN1cnZlaWxsZXIgc2kgdHUgdmV1eCDDqXBhcmduZXIgcGx1cy5gLAogICAgICAgIH0pOwogICAgICB9CgogICAgICAvLyBPYmplY3RpZiBhdHRlaW50IC8gZW4gYm9ubmUgdm9pZSBjZSBtb2lzLWNpLgogICAgICBpZiAoc2F2aW5nc0dvYWwgJiYgc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgPiAwKSB7CiAgICAgICAgaWYgKG1vbnRoTmV0ID49IHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KSB7CiAgICAgICAgICBhZHZpY2UudW5zaGlmdCh7CiAgICAgICAgICAgIHR5cGU6ICJwb3NpdGl2ZSIsCiAgICAgICAgICAgIGljb246ICLwn46JIiwKICAgICAgICAgICAgdGV4dDogYE9iamVjdGlmIGF0dGVpbnQgISBUdSBhcyBkw6lqw6AgbWlzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG1vbnRoTmV0KX0gZGUgY8O0dMOpIGNlIG1vaXMtY2ksIGF1LWRlbMOgIGRlIHRvbiBvYmplY3RpZiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCl9LmAsCiAgICAgICAgICB9KTsKICAgICAgICB9IGVsc2UgaWYgKG92ZXJCdWRnZXQubGVuZ3RoID09PSAwICYmIHJpc2luZ1dpdGhvdXRCdWRnZXRBbGVydC5sZW5ndGggPT09IDApIHsKICAgICAgICAgIGFkdmljZS51bnNoaWZ0KHsKICAgICAgICAgICAgdHlwZTogImluZm8iLAogICAgICAgICAgICBpY29uOiAi8J+RjSIsCiAgICAgICAgICAgIHRleHQ6IGBQYXMgZGUgZMOpcGFzc2VtZW50IGRlIGJ1ZGdldCBjZSBtb2lzLWNpLiBJbCB0ZSByZXN0ZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCAtIG1vbnRoTmV0KX0gw6Agw6ljb25vbWlzZXIgcG91ciBhdHRlaW5kcmUgdG9uIG9iamVjdGlmIGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0KX0uYCwKICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKGFkdmljZS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWR2aWNlKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gImFkdmljZS1jYXJkICIgKyBpdGVtLnR5cGU7CiAgICAgICAgY29uc3QgaWNvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBpY29uLmNsYXNzTmFtZSA9ICJhZHZpY2UtaWNvbiI7CiAgICAgICAgaWNvbi50ZXh0Q29udGVudCA9IGl0ZW0uaWNvbjsKICAgICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIHRleHQuaW5uZXJIVE1MID0gaXRlbS50ZXh0OwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoaWNvbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZCh0ZXh0KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQnVkZ2V0KGNhdGVnb3J5LCBhbW91bnQpIHsKICAgICAgY29uc3QgdXBkYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2J1ZGdldHMiLCB7CiAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGNhdGVnb3J5LCBhbW91bnQgfSksCiAgICAgIH0pOwogICAgICBjb25zdCBpZHggPSBhbGxCdWRnZXRzLmZpbmRJbmRleCgoYikgPT4gYi5jYXRlZ29yeSA9PT0gY2F0ZWdvcnkpOwogICAgICBpZiAoaWR4ID49IDApIGFsbEJ1ZGdldHNbaWR4XSA9IHVwZGF0ZWQ7CiAgICAgIGVsc2UgYWxsQnVkZ2V0cy5wdXNoKHVwZGF0ZWQpOwogICAgfQoKICAgIGNvbnN0IGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkgPSB7fTsKICAgIGNvbnN0IEJVREdFVF9ISVNUT1JZX01PTlRIUyA9IDY7CgogICAgLy8gTGVzIE4gZGVybmllcnMgbW9pcyAoY2zDqXMgIllZWVktTU0iKSwgZHUgcGx1cyBhbmNpZW4gYXUgcGx1cyByw6ljZW50LAogICAgLy8gZW4gZmluaXNzYW50IHBhciBlbmRNb250aEtleSBpbmNsdXMuCiAgICBmdW5jdGlvbiBsYXN0Tk1vbnRoS2V5cyhuLCBlbmRNb250aEtleSkgewogICAgICBjb25zdCBbeSwgbV0gPSBlbmRNb250aEtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBrZXlzID0gW107CiAgICAgIGZvciAobGV0IGkgPSBuIC0gMTsgaSA+PSAwOyBpLS0pIHsKICAgICAgICBjb25zdCBkID0gbmV3IERhdGUoeSwgbSAtIDEgLSBpLCAxKTsKICAgICAgICBrZXlzLnB1c2goZC5nZXRGdWxsWWVhcigpICsgIi0iICsgU3RyaW5nKGQuZ2V0TW9udGgoKSArIDEpLnBhZFN0YXJ0KDIsICIwIikpOwogICAgICB9CiAgICAgIHJldHVybiBrZXlzOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1saXN0Iik7CiAgICAgIGlmICghd3JhcCkgcmV0dXJuOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB7IHRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGN1cnJlbnRNb250aEtleSk7CgogICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhidWRnZXRJbnB1dHNCeUNhdGVnb3J5KSkgZGVsZXRlIGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnlba2V5XTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBjYXRlZ29yaWVzQnlUeXBlLmV4cGVuc2UpIHsKICAgICAgICBjb25zdCBidWRnZXQgPSBhbGxCdWRnZXRzLmZpbmQoKGIpID0+IGIuY2F0ZWdvcnkgPT09IHZhbHVlKTsKICAgICAgICBjb25zdCBzcGVudCA9IHRvdGFsc1t2YWx1ZV0gfHwgMDsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJidWRnZXQtcm93IjsKCiAgICAgICAgY29uc3QgaGVhZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGhlYWQuY2xhc3NOYW1lID0gImJ1ZGdldC1yb3ctaGVhZCI7CgogICAgICAgIGNvbnN0IG5hbWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIG5hbWVTcGFuLmNsYXNzTmFtZSA9ICJidWRnZXQtY2F0LW5hbWUiOwogICAgICAgIG5hbWVTcGFuLnRleHRDb250ZW50ID0gbGFiZWw7CgogICAgICAgIGNvbnN0IGFtb3VudHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50cy5jbGFzc05hbWUgPSAiYnVkZ2V0LWFtb3VudHMiOwogICAgICAgIGNvbnN0IHNwZW50U3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBzcGVudFNwYW4udGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc3BlbnQpICsgIiAvICI7CiAgICAgICAgY29uc3QgaW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGlucHV0LnR5cGUgPSAibnVtYmVyIjsKICAgICAgICBpbnB1dC5jbGFzc05hbWUgPSAiYnVkZ2V0LWlucHV0IjsKICAgICAgICBpbnB1dC5taW4gPSAiMCI7CiAgICAgICAgaW5wdXQuc3RlcCA9ICIxIjsKICAgICAgICBpbnB1dC5wbGFjZWhvbGRlciA9ICLigJQiOwogICAgICAgIGlmIChidWRnZXQpIGlucHV0LnZhbHVlID0gYnVkZ2V0LmFtb3VudDsKICAgICAgICBhbW91bnRzLmFwcGVuZENoaWxkKHNwZW50U3Bhbik7CiAgICAgICAgYW1vdW50cy5hcHBlbmRDaGlsZChpbnB1dCk7CiAgICAgICAgYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeVt2YWx1ZV0gPSBpbnB1dDsKCiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZC5hcHBlbmRDaGlsZChhbW91bnRzKTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoaGVhZCk7CgogICAgICAgIGlmIChidWRnZXQpIHsKICAgICAgICAgIGNvbnN0IHRyYWNrID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICB0cmFjay5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci10cmFjayI7CiAgICAgICAgICBjb25zdCBmaWxsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjb25zdCByYXRpbyA9IHNwZW50IC8gYnVkZ2V0LmFtb3VudDsKICAgICAgICAgIGNvbnN0IHBjdCA9IE1hdGgubWluKHJhdGlvICogMTAwLCAxMDApOwogICAgICAgICAgbGV0IGNscyA9ICJvayI7CiAgICAgICAgICBpZiAocmF0aW8gPj0gMSkgY2xzID0gIm92ZXIiOwogICAgICAgICAgZWxzZSBpZiAocmF0aW8gPj0gMC43KSBjbHMgPSAid2FybmluZyI7CiAgICAgICAgICBmaWxsLmNsYXNzTmFtZSA9ICJidWRnZXQtYmFyLWZpbGwgIiArIGNsczsKICAgICAgICAgIGZpbGwuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgICAgICB0cmFjay5hcHBlbmRDaGlsZChmaWxsKTsKICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZCh0cmFjayk7CgogICAgICAgICAgY29uc3Qgc3RyaXAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICAgIHN0cmlwLmNsYXNzTmFtZSA9ICJidWRnZXQtaGlzdG9yeS1zdHJpcCI7CiAgICAgICAgICBmb3IgKGNvbnN0IGhpc3RLZXkgb2YgbGFzdE5Nb250aEtleXMoQlVER0VUX0hJU1RPUllfTU9OVEhTLCBjdXJyZW50TW9udGhLZXkpKSB7CiAgICAgICAgICAgIGNvbnN0IHsgdG90YWxzOiBoaXN0VG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgaGlzdEtleSk7CiAgICAgICAgICAgIGNvbnN0IGhpc3RTcGVudCA9IGhpc3RUb3RhbHNbdmFsdWVdIHx8IDA7CiAgICAgICAgICAgIGNvbnN0IGRvdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgICAgaWYgKGhpc3RTcGVudCA9PT0gMCkgewogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgZW1wdHkiOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgIGNvbnN0IGhpc3RSYXRpbyA9IGhpc3RTcGVudCAvIGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgICAgICAgbGV0IGhpc3RDbHMgPSAib2siOwogICAgICAgICAgICAgIGlmIChoaXN0UmF0aW8gPj0gMSkgaGlzdENscyA9ICJvdmVyIjsKICAgICAgICAgICAgICBlbHNlIGlmIChoaXN0UmF0aW8gPj0gMC43KSBoaXN0Q2xzID0gIndhcm5pbmciOwogICAgICAgICAgICAgIGRvdC5jbGFzc05hbWUgPSAiaGlzdG9yeS1kb3QgIiArIGhpc3RDbHM7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY29uc3QgW2h5LCBobV0gPSBoaXN0S2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgICAgIGNvbnN0IG1vbnRoTGFiZWwgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShoeSwgaG0gLSAxLCAxKSk7CiAgICAgICAgICAgIGNvbnN0IGRldGFpbFRleHQgPSBgJHttb250aExhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGhpc3RTcGVudCl9IC8gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYnVkZ2V0LmFtb3VudCl9YDsKICAgICAgICAgICAgZG90LnRpdGxlID0gZGV0YWlsVGV4dDsgLy8gYWZmaWNow6kgYXUgc3Vydm9sIHN1ciBvcmRpbmF0ZXVyCiAgICAgICAgICAgIC8vIFN1ciBtb2JpbGUgaWwgbid5IGEgcGFzIGRlIHN1cnZvbCA6IHVuIHRhcCBzdXIgbGEgYmFycmUgbW9udHJlCiAgICAgICAgICAgIC8vIGxlIG3Dqm1lIGTDqXRhaWwgZGFucyB1biB0b2FzdC4KICAgICAgICAgICAgZG90LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd1RvYXN0KGRldGFpbFRleHQpKTsKICAgICAgICAgICAgc3RyaXAuYXBwZW5kQ2hpbGQoZG90KTsKICAgICAgICAgIH0KICAgICAgICAgIHJvdy5hcHBlbmRDaGlsZChzdHJpcCk7CiAgICAgICAgfQoKICAgICAgICB3cmFwLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBpdGVtcyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIik7CiAgICAgICAgZm9yIChjb25zdCB7IHR5cGUsIHZhbHVlLCBsYWJlbCB9IG9mIGl0ZW1zKSB7CiAgICAgICAgICBpZiAoY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSAmJiAhY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5zb21lKChbdl0pID0+IHYgPT09IHZhbHVlKSkgewogICAgICAgICAgICBjYXRlZ29yaWVzQnlUeXBlW3R5cGVdLnB1c2goW3ZhbHVlLCBsYWJlbF0pOwogICAgICAgICAgICBhbGxDYXRlZ29yeUxhYmVsc1t2YWx1ZV0gPSBsYWJlbDsKICAgICAgICAgIH0KICAgICAgICB9CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGVzIGNhdMOpZ29yaWVzIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWREaXNtaXNzZWRTdWdnZXN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBrZXlzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIik7CiAgICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMgPSBuZXcgU2V0KGtleXMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIHVuZSBzdWdnZXN0aW9uIGTDqWrDoCB2dWUgcsOpYXBwYXJhw650IHVuZSBmb2lzLgogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2x1Z2lmeUNhdGVnb3J5KGxhYmVsKSB7CiAgICAgIHJldHVybiAoCiAgICAgICAgbGFiZWwKICAgICAgICAgIC5ub3JtYWxpemUoIk5GRCIpLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpIC8vIGVubMOodmUgbGVzIGFjY2VudHMKICAgICAgICAgIC50b0xvd2VyQ2FzZSgpCiAgICAgICAgICAudHJpbSgpCiAgICAgICAgICAucmVwbGFjZSgvW15hLXowLTldKy9nLCAiXyIpCiAgICAgICAgICAucmVwbGFjZSgvXl8rfF8rJC9nLCAiIikgfHwgImF1dHJlIgogICAgICApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHNhdmVDdXN0b21DYXRlZ29yeSh0eXBlLCB2YWx1ZSwgbGFiZWwpIHsKICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvY3VzdG9tLWNhdGVnb3JpZXMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdHlwZSwgdmFsdWUsIGxhYmVsIH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkNhdMOpZ29yaWUgY3LDqcOpZSBpY2ksIG1haXMgcGFzIHNhdXZlZ2FyZMOpZSBzdXIgbGUgc2VydmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBjdXJyZW5jeUZvcm1hdHRlciA9IG5ldyBJbnRsLk51bWJlckZvcm1hdCgiZnItRlIiLCB7IHN0eWxlOiAiY3VycmVuY3kiLCBjdXJyZW5jeTogIkVVUiIgfSk7CiAgICBjb25zdCBkYXRlRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBkYXk6ICJudW1lcmljIiwgbW9udGg6ICJzaG9ydCIsIHllYXI6ICJudW1lcmljIiB9KTsKCiAgICAvLyDDiWNoYXBwZSB1bmUgdmFsZXVyIGF2YW50IGRlIGwnaW5zw6lyZXIgZGFucyB1biB0ZW1wbGF0ZSBIVE1MIGNvbnN0cnVpdAogICAgLy8gw6AgbGEgbWFpbiAoaW5uZXJIVE1MKSA6IG7DqWNlc3NhaXJlIHBhcnRvdXQgb8O5IHVuZSBkb25uw6llIHNhaXNpZSBwYXIKICAgIC8vIGwndXRpbGlzYXRldXIgcGV1dCBzJ3kgcmV0cm91dmVyIOKAlCBlbiBwYXJ0aWN1bGllciBsZSBsaWJlbGzDqSBkJ3VuZQogICAgLy8gY2F0w6lnb3JpZSBwZXJzb25uYWxpc8OpZSAodGV4dGUgbGlicmUsIGVucmVnaXN0csOpIGVuIGJhc2UpLCBwb3VyIMOpdml0ZXIKICAgIC8vIHF1J3VuIGxpYmVsbMOpIGR1IGdlbnJlIDxpbWcgc3JjPXggb25lcnJvcj0uLi4+IG5lIHMnZXjDqWN1dGUgY29tbWUgZHUKICAgIC8vIEhUTUwvSlMgYXUgbGlldSBkZSBzJ2FmZmljaGVyIGNvbW1lIGR1IHRleHRlIChpbmplY3Rpb24gWFNTIHN0b2Nrw6llKS4KICAgIGZ1bmN0aW9uIGVzY2FwZUh0bWwoc3RyKSB7CiAgICAgIHJldHVybiBTdHJpbmcoc3RyKS5yZXBsYWNlKC9bJjw+IiddL2csIChjaCkgPT4gKHsKICAgICAgICAiJiI6ICImYW1wOyIsICI8IjogIiZsdDsiLCAiPiI6ICImZ3Q7IiwgJyInOiAiJnF1b3Q7IiwgIiciOiAiJiMzOTsiLAogICAgICB9W2NoXSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dUb2FzdChtZXNzYWdlLCBpc0Vycm9yID0gZmFsc2UpIHsKICAgICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgdG9hc3QuY2xhc3NOYW1lID0gInRvYXN0IiArIChpc0Vycm9yID8gIiBlcnJvciIgOiAiIik7CiAgICAgIHRvYXN0LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0b2FzdCk7CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdG9hc3QucmVtb3ZlKCksIDMwMDApOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwaUZldGNoKHBhdGgsIG9wdGlvbnMgPSB7fSkgewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAgICAgLi4ub3B0aW9ucywKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAiWC1BUEktS2V5IjogQVBJX0tFWSwKICAgICAgICAgIC4uLihvcHRpb25zLmJvZHkgPyB7ICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIgfSA6IHt9KSwKICAgICAgICAgIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pLAogICAgICAgIH0sCiAgICAgIH0pOwogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gNDAxKSB7CiAgICAgICAgLy8gSmV0b24gYWJzZW50LCBpbnZhbGlkZSBvdSBleHBpcsOpIDogcmV0b3VyIMOgIGwnw6ljcmFuIGRlIHZlcnJvdWlsbGFnZQogICAgICAgIC8vIHBsdXTDtHQgcXVlIGQnYWZmaWNoZXIgdW5lIGVycmV1ciB0ZWNobmlxdWUgaW5jb21wcsOpaGVuc2libGUuCiAgICAgICAgc2hvd0xvY2tTY3JlZW4oKTsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoIlNlc3Npb24gZXhwaXLDqWUsIHJlY29ubmVjdGUtdG9pLiIpOwogICAgICB9CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgLy8gcmVzLnN0YXR1c1RleHQgZXN0IHNvdXZlbnQgdmlkZSAobmF2aWdhdGV1cnMgZW4gSFRUUC8yLCB1dGlsaXPDqSBwYXIKICAgICAgICAvLyBWZXJjZWwpLCBkb25jIG9uIG5lIHBldXQgcGFzIGNvbXB0ZXIgZGVzc3VzIGNvbW1lIG1lc3NhZ2UgcGFyCiAgICAgICAgLy8gZMOpZmF1dCA6IG9uIHJldG9tYmUgc3VyIGxlIGNvZGUgSFRUUCBwb3VyIG5lIGphbWFpcyBhZmZpY2hlciB1bgogICAgICAgIC8vIG1lc3NhZ2UgZCdlcnJldXIgdmlkZS4KICAgICAgICBsZXQgZGV0YWlsID0gcmVzLnN0YXR1c1RleHQgfHwgYEVycmV1ciBIVFRQICR7cmVzLnN0YXR1c31gOwogICAgICAgIHRyeSB7CiAgICAgICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgICAgICAgIGRldGFpbCA9IGV4dHJhY3RFcnJvckRldGFpbChkYXRhLCBkZXRhaWwpOwogICAgICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRldGFpbCk7CiAgICAgIH0KICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDIwNCkgcmV0dXJuIG51bGw7CiAgICAgIHJldHVybiByZXMuanNvbigpOwogICAgfQoKICAgIGZ1bmN0aW9uIHRvZGF5SXNvKCkgewogICAgICBjb25zdCBkID0gbmV3IERhdGUoKTsKICAgICAgY29uc3QgdHogPSBkLmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUoZC5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICBjYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIGNhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgbmV3T3B0LnZhbHVlID0gIl9fbmV3X18iOwogICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUgPSAiIjsKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICB9CgogICAgY2F0ZWdvcnlJbnB1dC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIG5ld0NhdGVnb3J5TmFtZUlucHV0LmNsYXNzTGlzdC50b2dnbGUoImhpZGRlbiIsIGNhdGVnb3J5SW5wdXQudmFsdWUgIT09ICJfX25ld19fIik7CiAgICAgIGlmIChjYXRlZ29yeUlucHV0LnZhbHVlID09PSAiX19uZXdfXyIpIG5ld0NhdGVnb3J5TmFtZUlucHV0LmZvY3VzKCk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBzZXRUeXBlKHR5cGUpIHsKICAgICAgY3VycmVudFR5cGUgPSB0eXBlOwogICAgICB0eXBlVG9nZ2xlRWwucXVlcnlTZWxlY3RvckFsbCgiLnR5cGUtYnRuIikuZm9yRWFjaCgoYnRuKSA9PiB7CiAgICAgICAgYnRuLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGJ0bi5kYXRhc2V0LnR5cGUgPT09IHR5cGUpOwogICAgICB9KTsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIGNhdGVnb3J5SW5wdXQudmFsdWUpOwogICAgfQoKICAgIHR5cGVUb2dnbGVFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi50eXBlLWJ0biIpOwogICAgICBpZiAoYnRuKSBzZXRUeXBlKGJ0bi5kYXRhc2V0LnR5cGUpOwogICAgfSk7CgogICAgZnVuY3Rpb24gb3Blbk1vZGFsKHR4ID0gbnVsbCkgewogICAgICAvLyBPbiBkaXN0aW5ndWUgIm1vZGlmaWVyIiAodHggYSB1biBpZCwgdnJhaWUgw6lkaXRpb24gZW4gYmFzZSkgZGUKICAgICAgLy8gInByw6ktcmVtcGxpciDDoCBwYXJ0aXIgZCd1biBtb2TDqGxlIiAoZHVwbGljYXRpb24gOiB0eCBmb3VybmkgbWFpcyBzYW5zCiAgICAgIC8vIGlkID0+IG9uIGNyw6llIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiBhdSBsaWV1IGQnw6ljcmFzZXIgbCdvcmlnaW5hbGUpLgogICAgICBjb25zdCBpc0VkaXQgPSBCb29sZWFuKHR4ICYmIHR4LmlkKTsKICAgICAgZWRpdGluZ0lkID0gaXNFZGl0ID8gdHguaWQgOiBudWxsOwogICAgICBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IGlzRWRpdCA/IHR4LmNhdGVnb3J5IDogbnVsbDsKICAgICAgbW9kYWxUaXRsZUVsLnRleHRDb250ZW50ID0gaXNFZGl0ID8gIk1vZGlmaWVyIGxhIHRyYW5zYWN0aW9uIiA6ICJOb3V2ZWxsZSB0cmFuc2FjdGlvbiI7CiAgICAgIHNhdmVCdG4udGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRUeXBlKHR4ID8gdHgudHlwZSA6ICJleHBlbnNlIik7CiAgICAgIGFtb3VudElucHV0LnZhbHVlID0gdHggPyB0eC5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCB0eCA/IHR4LmNhdGVnb3J5IDogImF1dHJlIik7CiAgICAgIGRlc2NyaXB0aW9uSW5wdXQudmFsdWUgPSB0eCA/ICh0eC5kZXNjcmlwdGlvbiB8fCAiIikgOiAiIjsKICAgICAgZGF0ZUlucHV0LnZhbHVlID0gdHggPyB0eC5leHBlbnNlX2RhdGUgOiB0b2RheUlzbygpOwoKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgICAgaWYgKGlzRWRpdCAmJiB0eC5yZWNlaXB0X3BhdGgpIHsKICAgICAgICBsb2FkRXhpc3RpbmdSZWNlaXB0UHJldmlldyh0eC5pZCk7CiAgICAgIH0KCiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgYW1vdW50SW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkgewogICAgICAvLyBNw6ptZSBtb250YW50L2NhdMOpZ29yaWUvZGVzY3JpcHRpb24sIG1haXMgZGF0w6kgZCdhdWpvdXJkJ2h1aSBldCBzYW5zCiAgICAgIC8vIGlkIDogbGEgc2F1dmVnYXJkZSBjcsOpZXJhIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiAodm9pciBvcGVuTW9kYWwpLgogICAgICBvcGVuTW9kYWwoeyAuLi50eCwgaWQ6IG51bGwsIGV4cGVuc2VfZGF0ZTogdG9kYXlJc28oKSB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZU1vZGFsKCkgewogICAgICBvdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdJZCA9IG51bGw7CiAgICAgIGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5ID0gbnVsbDsKICAgICAgcmVzZXRSZWNlaXB0VWkoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmFiLWFkZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJyZWN1cnJpbmciKSBvcGVuUmVjdXJyaW5nTW9kYWwoKTsKICAgICAgZWxzZSBvcGVuTW9kYWwoKTsKICAgIH0pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1jYW5jZWwiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGNsb3NlTW9kYWwpOwogICAgb3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsgaWYgKGUudGFyZ2V0ID09PSBvdmVybGF5RWwpIGNsb3NlTW9kYWwoKTsgfSk7CgogICAgc2F2ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChhbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJNb250YW50IGludmFsaWRlIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICAvLyAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIiBzw6lsZWN0aW9ubsOpIDogb24gbGEgY3LDqWUgKHNpIGVsbGUgbidleGlzdGUKICAgICAgLy8gcGFzIGTDqWrDoCBzb3VzIGNlIG5vbSkgYXZhbnQgZCdlbnJlZ2lzdHJlciBsYSB0cmFuc2FjdGlvbiBhdmVjLgogICAgICBsZXQgY2F0ZWdvcnlWYWx1ZSA9IGNhdGVnb3J5SW5wdXQudmFsdWU7CiAgICAgIGlmIChjYXRlZ29yeVZhbHVlID09PSAiX19uZXdfXyIpIHsKICAgICAgICBjb25zdCBuYW1lID0gbmV3Q2F0ZWdvcnlOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgIGlmICghbmFtZSkgewogICAgICAgICAgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIsIHRydWUpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICBjYXRlZ29yeVZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtjdXJyZW50VHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSBjYXRlZ29yeVZhbHVlKSkgewogICAgICAgICAgYXdhaXQgc2F2ZUN1c3RvbUNhdGVnb3J5KGN1cnJlbnRUeXBlLCBjYXRlZ29yeVZhbHVlLCBuYW1lKTsKICAgICAgICAgIHBvcHVsYXRlQ2F0ZWdvcmllcyhjdXJyZW50VHlwZSwgY2F0ZWdvcnlWYWx1ZSk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IGN1cnJlbnRUeXBlLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogY2F0ZWdvcnlWYWx1ZSwKICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb25JbnB1dC52YWx1ZS50cmltKCkgfHwgbnVsbCwKICAgICAgICBleHBlbnNlX2RhdGU6IGRhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgICAgY29uc3QgcHJldmlvdXNDYXRlZ29yeSA9IGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5OwogICAgICAgICAgY29uc3QgZWRpdGVkSWQgPSBlZGl0aW5nSWQ7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9YCwgeyBtZXRob2Q6ICJQVVQiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gbW9kaWZpw6llIik7CgogICAgICAgICAgLy8gU2kgbGEgY2F0w6lnb3JpZSB2aWVudCBkZSBjaGFuZ2VyIG1hbnVlbGxlbWVudCwgb24gcHJvcG9zZSBkZQogICAgICAgICAgLy8gcmVwb3J0ZXIgbGUgbcOqbWUgY2hhbmdlbWVudCBzdXIgbGVzIGF1dHJlcyB0cmFuc2FjdGlvbnMgZG9udCBsYQogICAgICAgICAgLy8gZGVzY3JpcHRpb24gcGFydGFnZSB1biBtb3QtY2zDqSBzaWduaWZpY2F0aWYgKGV4LiAiY2FzaW5vIiAvCiAgICAgICAgICAvLyAiYXUgY2FzaW5vIiAvICJwZXJ0ZSBhdSBjYXNpbm8iKSBldCBxdWkgw6l0YWllbnQgZGFucyBsJ2FuY2llbm5lCiAgICAgICAgICAvLyBjYXTDqWdvcmllIOKAlCBqYW1haXMgYXV0b21hdGlxdWUsIHRvdWpvdXJzIHN1ciBjb25maXJtYXRpb24uCiAgICAgICAgICBpZiAocHJldmlvdXNDYXRlZ29yeSAmJiBwYXlsb2FkLmNhdGVnb3J5ICE9PSBwcmV2aW91c0NhdGVnb3J5ICYmIHBheWxvYWQuZGVzY3JpcHRpb24pIHsKICAgICAgICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhwYXlsb2FkLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgaWYgKGtleXdvcmRzLnNpemUgPiAwKSB7CiAgICAgICAgICAgICAgY29uc3Qgc2ltaWxhciA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoCiAgICAgICAgICAgICAgICAodCkgPT4KICAgICAgICAgICAgICAgICAgdC5pZCAhPT0gZWRpdGVkSWQgJiYKICAgICAgICAgICAgICAgICAgdC50eXBlID09PSBwYXlsb2FkLnR5cGUgJiYKICAgICAgICAgICAgICAgICAgdC5jYXRlZ29yeSA9PT0gcHJldmlvdXNDYXRlZ29yeSAmJgogICAgICAgICAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModC5kZXNjcmlwdGlvbikpCiAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgICBpZiAoc2ltaWxhci5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICBjb25zdCBuZXdMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BheWxvYWQuY2F0ZWdvcnldIHx8IHBheWxvYWQuY2F0ZWdvcnk7CiAgICAgICAgICAgICAgICBjb25zdCBleGFtcGxlRGVzYyA9IHNpbWlsYXJbMF0uZGVzY3JpcHRpb24gfHwgIihzYW5zIGRlc2NyaXB0aW9uKSI7CiAgICAgICAgICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICAgICAgICAgICAgYEFwcGxpcXVlciBhdXNzaSBsYSBjYXTDqWdvcmllICIke25ld0xhYmVsfSIgYXV4ICR7c2ltaWxhci5sZW5ndGh9IGF1dHJlKHMpIHRyYW5zYWN0aW9uKHMpIGAgKwogICAgICAgICAgICAgICAgICBgc2ltaWxhaXJlKHMpIChleC4gIiR7ZXhhbXBsZURlc2N9IikgP2AKICAgICAgICAgICAgICAgICk7CiAgICAgICAgICAgICAgICBpZiAoY29uZmlybWVkKSB7CiAgICAgICAgICAgICAgICAgIGZvciAoY29uc3QgdCBvZiBzaW1pbGFyKSB7CiAgICAgICAgICAgICAgICAgICAgY29uc3QgZml4UGF5bG9hZCA9IHsgY2F0ZWdvcnk6IHBheWxvYWQuY2F0ZWdvcnkgfTsKICAgICAgICAgICAgICAgICAgICAvLyBDb21tZSBwb3VyIGxhIGJhbm5pw6hyZSBkZSBzdWdnZXN0aW9uIDogbGEgY2F0w6lnb3JpZQogICAgICAgICAgICAgICAgICAgIC8vIHBvcnRlIG1haW50ZW5hbnQgbCdpbmZvLCBvbiByZXRpcmUgbGUgbW90LWNsw6kgZGV2ZW51CiAgICAgICAgICAgICAgICAgICAgLy8gcmVkb25kYW50IGRlIGxhIGRlc2NyaXB0aW9uIGRlIENFUyB0cmFuc2FjdGlvbnMtbMOgCiAgICAgICAgICAgICAgICAgICAgLy8gKHBhcyBjZWxsZSBxdSdvbiB2aWVudCBkJ8OpZGl0ZXIgw6AgbGEgbWFpbikuCiAgICAgICAgICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKHQuZGVzY3JpcHRpb24sIGtleXdvcmRzKTsKICAgICAgICAgICAgICAgICAgICBpZiAoY2xlYW5lZCAhPT0gKHQuZGVzY3JpcHRpb24gfHwgbnVsbCkpIGZpeFBheWxvYWQuZGVzY3JpcHRpb24gPSBjbGVhbmVkOwogICAgICAgICAgICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3QuaWR9YCwgewogICAgICAgICAgICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGZpeFBheWxvYWQpLAogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgIHNob3dUb2FzdChgJHtzaW1pbGFyLmxlbmd0aH0gYXV0cmUocykgdHJhbnNhY3Rpb24ocykgbWlzZShzKSDDoCBqb3VyYCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiLCB7IG1ldGhvZDogIlBPU1QiLCBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSB9KTsKICAgICAgICAgIHNob3dUb2FzdChjdXJyZW50VHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IGFqb3V0w6kiIDogIkTDqXBlbnNlIGFqb3V0w6llIik7CiAgICAgICAgICBpZiAocGVuZGluZ1JlY2VpcHRGaWxlKSB7CiAgICAgICAgICAgIC8vIExhIHBob3RvIGEgw6l0w6kgY2hvaXNpZSBhdmFudCBxdWUgbGEgdHJhbnNhY3Rpb24gbidleGlzdGUgOiBvbgogICAgICAgICAgICAvLyBsJ2Vudm9pZSBtYWludGVuYW50IHF1J29uIGEgdW4gaWQuCiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBwZW5kaW5nUmVjZWlwdEZpbGUpOwogICAgICAgICAgICAgIGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2NyZWF0ZWQuaWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgICAgICAgYm9keTogZm9ybURhdGEsCiAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAgICAgICBzaG93VG9hc3QoIlRyYW5zYWN0aW9uIGNyw6nDqWUsIG1haXMgbCdlbnZvaSBkZSBsYSBwaG90byBhIMOpY2hvdcOpIiwgdHJ1ZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgY2xvc2VNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHNhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlVHJhbnNhY3Rpb24oaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSB0cmFuc2FjdGlvbiA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YXV4IGdsb2JhdXggKFNvbGRlL0TDqXBlbnNlcy9SZXZlbnVzKSA6IGNhbGN1bMOpcyBzdXIgVE9VVEVTIGxlcwogICAgLy8gdHJhbnNhY3Rpb25zLCBpbmTDqXBlbmRhbW1lbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlIOKAlCB1biBmaWx0cmUKICAgIC8vIHNlcnQgw6AgY2hlcmNoZXIgZGFucyBsYSBsaXN0ZSwgcGFzIMOgIHJlY2FsY3VsZXIgbGUgc29sZGUgcsOpZWwuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbnModHJhbnNhY3Rpb25zKSB7CiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImluY29tZSIpIHRvdGFsSW5jb21lICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGVsc2UgdG90YWxFeHBlbnNlcyArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBiYWxhbmNlID0gdG90YWxJbmNvbWUgLSB0b3RhbEV4cGVuc2VzOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJhbGFuY2UpOwogICAgICBzdW1tYXJ5QmFsYW5jZUVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKGJhbGFuY2UgPj0gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgc3VtbWFyeUV4cGVuc2VzRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIHN1bW1hcnlJbmNvbWVFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICB9CgogICAgLy8gQ29uc3RydWN0aW9uIGRlIGxhIGxpc3RlIGRlIGNhcnRlcyBhZmZpY2jDqWUgZGFucyBsJ29uZ2xldCBIaXN0b3JpcXVlIOKAlAogICAgLy8gcmXDp29pdCBkw6lqw6AgbGEgbGlzdGUgZmlsdHLDqWUgKHZvaXIgYXBwbHlIaXN0b3J5RmlsdGVycykuCiAgICBmdW5jdGlvbiByZW5kZXJUcmFuc2FjdGlvbkxpc3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGxpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgaWYgKHRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eVN0YXRlRWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnRleHRDb250ZW50ID0gYWxsVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMAogICAgICAgICAgPyAiUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4iCiAgICAgICAgICA6ICJBdWN1biByw6lzdWx0YXQgcG91ciBjZXMgZmlsdHJlcy4iOwogICAgICB9IGVsc2UgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICB9CgogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJ0eC1jYXJkICIgKyB0eC50eXBlOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAidHgtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAidHgtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbdHguY2F0ZWdvcnldIHx8IHR4LmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRhdGVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGRhdGVTcGFuLmNsYXNzTmFtZSA9ICJ0eC1kYXRlIjsKICAgICAgICBkYXRlU3Bhbi50ZXh0Q29udGVudCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHR4LmV4cGVuc2VfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZGF0ZVNwYW4pOwogICAgICAgIGlmICh0eC5yZWN1cnJpbmdfZXhwZW5zZV9pZCkgewogICAgICAgICAgY29uc3QgcmVjQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICByZWNCYWRnZS5jbGFzc05hbWUgPSAidHgtcmVjdXJyaW5nLWJhZGdlIjsKICAgICAgICAgIHJlY0JhZGdlLnRleHRDb250ZW50ID0gIvCflIEiOwogICAgICAgICAgcmVjQmFkZ2UudGl0bGUgPSAiQ3LDqcOpZSBhdXRvbWF0aXF1ZW1lbnQgZGVwdWlzIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY0JhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgICAgY29uc3QgcmVjZWlwdEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UudHlwZSA9ICJidXR0b24iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWNlaXB0LWJhZGdlIjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50ZXh0Q29udGVudCA9ICLwn6e+IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50aXRsZSA9ICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1IjsKICAgICAgICAgIHJlY2VpcHRCYWRnZS5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCAiVm9pciBsYSBwaG90byBkdSByZcOndSIpOwogICAgICAgICAgcmVjZWlwdEJhZGdlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gb3BlblJlY2VpcHRMaWdodGJveCh0eC5pZCkpOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHJlY2VpcHRCYWRnZSk7CiAgICAgICAgfQoKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAidHgtZGVzY3JpcHRpb24iOwogICAgICAgIGRlc2MudGV4dENvbnRlbnQgPSB0eC5kZXNjcmlwdGlvbiB8fCAi4oCUIjsKCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZCh0b3ApOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInR4LWFtb3VudCAiICsgdHgudHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eC50eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHR4LmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuTW9kYWwodHgpKTsKICAgICAgICBjb25zdCBkdXBsaWNhdGVCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBkdXBsaWNhdGVCdG4uY2xhc3NOYW1lID0gImljb24tYnRuIjsKICAgICAgICBkdXBsaWNhdGVCdG4udGV4dENvbnRlbnQgPSAi8J+TiyI7CiAgICAgICAgZHVwbGljYXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJEdXBsaXF1ZXIiKTsKICAgICAgICBkdXBsaWNhdGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkdXBsaWNhdGVUcmFuc2FjdGlvbih0eCkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVUcmFuc2FjdGlvbih0eC5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkdXBsaWNhdGVCdG4pOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZGVsZXRlQnRuKTsKCiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFtb3VudEVsKTsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGFjdGlvbnMpOwogICAgICAgIGxpc3RFbC5hcHBlbmRDaGlsZChjYXJkKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFLDqXN1bcOpICJjZXR0ZSBzZW1haW5lIiAoaW5kw6lwZW5kYW50IGRlcyBmaWx0cmVzIGRlIGwnaGlzdG9yaXF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN0YXJ0T2ZXZWVrSXNvKCkgewogICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCBkYXkgPSBub3cuZ2V0RGF5KCk7IC8vIDAgPSBkaW1hbmNoZSwgMSA9IGx1bmRpLCAuLi4KICAgICAgY29uc3QgZGlmZlRvTW9uZGF5ID0gZGF5ID09PSAwID8gNiA6IGRheSAtIDE7CiAgICAgIGNvbnN0IG1vbmRheSA9IG5ldyBEYXRlKG5vdyk7CiAgICAgIG1vbmRheS5zZXREYXRlKG5vdy5nZXREYXRlKCkgLSBkaWZmVG9Nb25kYXkpOwogICAgICBjb25zdCB0eiA9IG1vbmRheS5nZXRUaW1lem9uZU9mZnNldCgpOwogICAgICBjb25zdCBsb2NhbCA9IG5ldyBEYXRlKG1vbmRheS5nZXRUaW1lKCkgLSB0eiAqIDYwMDAwKTsKICAgICAgcmV0dXJuIGxvY2FsLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwgMTApOwogICAgfQoKICAgIGZ1bmN0aW9uIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzdGFydCA9IHN0YXJ0T2ZXZWVrSXNvKCk7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSA9PT0gImV4cGVuc2UiICYmIHR4LmV4cGVuc2VfZGF0ZSA+PSBzdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPD0gdG9kYXkpIHsKICAgICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgid2Vlay1zdW1tYXJ5IikudGV4dENvbnRlbnQgPQogICAgICAgIGBDZXR0ZSBzZW1haW5lIChkZXB1aXMgbHVuZGkpIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWwpfSBkw6lwZW5zw6lzYDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBSZWNoZXJjaGUgZXQgZmlsdHJlcyBkYW5zIGwnaGlzdG9yaXF1ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItY2F0ZWdvcnkiKTsKICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhhbGxDYXRlZ29yeUxhYmVscykpIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIGFwcGx5SGlzdG9yeUZpbHRlcnMoKSB7CiAgICAgIGNvbnN0IHNlYXJjaCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItc2VhcmNoIikudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IGNhdGVnb3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlU3RhcnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWRhdGUtc3RhcnQiKS52YWx1ZTsKICAgICAgY29uc3QgZGF0ZUVuZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1lbmQiKS52YWx1ZTsKCiAgICAgIGNvbnN0IGZpbHRlcmVkID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHsKICAgICAgICBpZiAoY2F0ZWdvcnkgJiYgdHguY2F0ZWdvcnkgIT09IGNhdGVnb3J5KSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKGRhdGVTdGFydCAmJiB0eC5leHBlbnNlX2RhdGUgPCBkYXRlU3RhcnQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZUVuZCAmJiB0eC5leHBlbnNlX2RhdGUgPiBkYXRlRW5kKSByZXR1cm4gZmFsc2U7CiAgICAgICAgaWYgKHNlYXJjaCkgewogICAgICAgICAgY29uc3QgaGF5c3RhY2sgPSBgJHt0eC5kZXNjcmlwdGlvbiB8fCAiIn0gJHthbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnl9YC50b0xvd2VyQ2FzZSgpOwogICAgICAgICAgaWYgKCFoYXlzdGFjay5pbmNsdWRlcyhzZWFyY2gpKSByZXR1cm4gZmFsc2U7CiAgICAgICAgfQogICAgICAgIHJldHVybiB0cnVlOwogICAgICB9KTsKICAgICAgcmVuZGVyVHJhbnNhY3Rpb25MaXN0KGZpbHRlcmVkKTsKICAgIH0KCiAgICBbImZpbHRlci1zZWFyY2giLCAiZmlsdGVyLWNhdGVnb3J5IiwgImZpbHRlci1kYXRlLXN0YXJ0IiwgImZpbHRlci1kYXRlLWVuZCJdLmZvckVhY2goKGlkKSA9PiB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIGFwcGx5SGlzdG9yeUZpbHRlcnMpOwogICAgfSk7CgogICAgbGV0IGFsbFRyYW5zYWN0aW9ucyA9IFtdOwogICAgbGV0IGN1cnJlbnRWaWV3ID0gImhpc3RvcnkiOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRUcmFuc2FjdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgdHJhbnNhY3Rpb25zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIik7CiAgICAgICAgYWxsVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zOwogICAgICAgIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpOwogICAgICAgIHVwZGF0ZVdlZWtTdW1tYXJ5KHRyYW5zYWN0aW9ucyk7CiAgICAgICAgYXBwbHlIaXN0b3J5RmlsdGVycygpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKHRyYW5zYWN0aW9ucyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT25nbGV0cyAoSGlzdG9yaXF1ZSAvIFRhYmxlYXUgZGUgYm9yZCkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHN3aXRjaFZpZXcodmlldykgewogICAgICBjdXJyZW50VmlldyA9IHZpZXc7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItaGlzdG9yeSIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJoaXN0b3J5Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXJlY3VycmluZyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZXhwb3J0Iik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2aWV3LWhpc3RvcnkiKS5zdHlsZS5kaXNwbGF5ID0gdmlldyA9PT0gImhpc3RvcnkiID8gImJsb2NrIiA6ICJub25lIjsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZGFzaGJvYXJkIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJkYXNoYm9hcmQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJyZWN1cnJpbmciKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctZXhwb3J0IikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctc2F2aW5ncyIpLmNsYXNzTGlzdC50b2dnbGUoInZpc2libGUiLCB2aWV3ID09PSAic2F2aW5ncyIpOwogICAgICBpZiAodmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICBpZiAodmlldyA9PT0gInNhdmluZ3MiKSByZW5kZXJTYXZpbmdzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIGNsb3NlTmF2RHJhd2VyKCk7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJoaXN0b3J5IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImRhc2hib2FyZCIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJyZWN1cnJpbmciKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZXhwb3J0IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJzYXZpbmdzIikpOwoKICAgIC8vIE1lbnUgImJ1cmdlciIgKG1vYmlsZSB1bmlxdWVtZW50LCB2b2lyIGxlIENTUyBAbWVkaWEgYXNzb2Npw6kpIDogbGEKICAgIC8vIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIHN1cgogICAgLy8gcGx1c2lldXJzIGxpZ25lcy4gRmVybcOpIGF1dG9tYXRpcXVlbWVudCBkw6hzIHF1J3VuIG9uZ2xldCBlc3QgY2hvaXNpCiAgICAvLyAodm9pciBzd2l0Y2hWaWV3IGNpLWRlc3N1cykgb3UgZW4gdG91Y2hhbnQgbGUgZm9uZCBhc3NvbWJyaS4KICAgIGZ1bmN0aW9uIGNsb3NlTmF2RHJhd2VyKCkgewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC5yZW1vdmUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm1lbnUtdG9nZ2xlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC50b2dnbGUoIm5hdi1kcmF3ZXItb3BlbiIpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibmF2LWRyYXdlci1iYWNrZHJvcCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VOYXZEcmF3ZXIpOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFRhYmxlYXUgZGUgYm9yZCAoZ3JhcGhpcXVlcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1vbnRoRm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogImxvbmciLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBtb250aFNob3J0Rm9ybWF0dGVyID0gbmV3IEludGwuRGF0ZVRpbWVGb3JtYXQoImZyLUZSIiwgeyBtb250aDogInNob3J0IiwgeWVhcjogIm51bWVyaWMiIH0pOwogICAgY29uc3QgQ0hBUlRfQ09MT1JTID0gWyIjM2I4MmY2IiwgIiMyMmM1NWUiLCAiI2VmNDQ0NCIsICIjZjU5ZTBiIiwgIiNhODU1ZjciLCAiIzE0YjhhNiIsICIjZWM0ODk5IiwgIiM2NDc0OGIiXTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDaGFyZ2VtZW50IGRlIENoYXJ0LmpzIDogbGEgYmlibGlvdGjDqHF1ZSB2aWVudCBkJ3VuIENETiBleHRlcm5lICh2b2lyCiAgICAvLyBsYSBiYWxpc2UgPHNjcmlwdD4gZW4gaGF1dCBkZSBwYWdlKS4gU2kgY2UgY2hhcmdlbWVudCByYXRlIChjb3VwdXJlCiAgICAvLyByw6lzZWF1LCBDRE4gbW9tZW50YW7DqW1lbnQgaW5qb2lnbmFibGUuLi4pLCBgQ2hhcnRgIG4nZXhpc3RlIHBhcyBldCB1bgogICAgLy8gYG5ldyBDaGFydCguLi4pYCBsw6h2ZSB1bmUgZXJyZXVyIG5vbiBpbnRlcmNlcHTDqWUg4oCUIHF1aSwgYXZhbnQgY2UKICAgIC8vIGNvcnJlY3RpZiwgaW50ZXJyb21wYWl0IHRvdXQgbGUgcmVzdGUgZHUgcmVuZHUgZHUgdGFibGVhdSBkZSBib3JkIHNhbnMKICAgIC8vIGF1Y3VuIG1lc3NhZ2UsIGxhaXNzYW50IGxlcyBncmFwaGlxdWVzIChldCBwYXJmb2lzIGRlcyBzZWN0aW9ucwogICAgLy8gc3VpdmFudGVzKSB2aWRlcyBpbmTDqWZpbmltZW50LCBtw6ptZSBhcHLDqHMgdW4gcmVjaGFyZ2VtZW50IGRlIGxhIHBhZ2UKICAgIC8vIHNpIGxlIENETiByZXN0YWl0IGluam9pZ25hYmxlLiBgc2FmZUNyZWF0ZUNoYXJ0YCByZW1wbGFjZSBjaGFxdWUgYXBwZWwKICAgIC8vIGRpcmVjdCDDoCBgbmV3IENoYXJ0KC4uLilgIDogc2kgbGEgYmlibGlvdGjDqHF1ZSBtYW5xdWUsIG9uIGFmZmljaGUgdW4KICAgIC8vIG1lc3NhZ2UgY2xhaXIgw6AgbGEgcGxhY2UgZHUgZ3JhcGhpcXVlIGV0IG9uIHRlbnRlIGF1dG9tYXRpcXVlbWVudCB1bgogICAgLy8gc2Vjb25kIGNoYXJnZW1lbnQgZHUgc2NyaXB0LCBwdWlzIG9uIHJlZGVzc2luZSBsYSB2dWUgY291cmFudGUgZMOocwogICAgLy8gcXUnaWwgcsOpdXNzaXQg4oCUIHNhbnMgcXVlIGwndXRpbGlzYXRldXIgYWl0IHF1b2kgcXVlIGNlIHNvaXQgw6AgZmFpcmUuCiAgICBsZXQgY2hhcnRKc1JlbG9hZEF0dGVtcHRlZCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIGlzQ2hhcnRKc1JlYWR5KCkgewogICAgICByZXR1cm4gdHlwZW9mIENoYXJ0ICE9PSAidW5kZWZpbmVkIjsKICAgIH0KCiAgICBmdW5jdGlvbiB0cnlSZWxvYWRDaGFydEpzKCkgewogICAgICBpZiAoY2hhcnRKc1JlbG9hZEF0dGVtcHRlZCkgcmV0dXJuOwogICAgICBjaGFydEpzUmVsb2FkQXR0ZW1wdGVkID0gdHJ1ZTsKICAgICAgY29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7CiAgICAgIHNjcmlwdC5zcmMgPSAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9jaGFydC5qc0A0LjQuNC9kaXN0L2NoYXJ0LnVtZC5taW4uanM/cmV0cnk9IiArIERhdGUubm93KCk7CiAgICAgIHNjcmlwdC5vbmxvYWQgPSAoKSA9PiB7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfTsKICAgICAgc2NyaXB0Lm9uZXJyb3IgPSAoKSA9PiB7CiAgICAgICAgY29uc29sZS5lcnJvcigiQ2hhcnQuanMgOiBsZSBzZWNvbmQgZXNzYWkgZGUgY2hhcmdlbWVudCBhIGF1c3NpIMOpY2hvdcOpLiIpOwogICAgICB9OwogICAgICBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHNjcmlwdCk7CiAgICB9CgogICAgZnVuY3Rpb24gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgY29uZmlnLCBlbXB0eUVsLCB1bmF2YWlsYWJsZU1lc3NhZ2UpIHsKICAgICAgaWYgKCFpc0NoYXJ0SnNSZWFkeSgpKSB7CiAgICAgICAgY29uc29sZS5lcnJvcigiQ2hhcnQuanMgbidlc3QgcGFzIGNoYXJnw6kg4oCUIGdyYXBoaXF1ZSBub24gYWZmaWNow6kuIik7CiAgICAgICAgaWYgKGNhbnZhcykgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaWYgKGVtcHR5RWwpIHsKICAgICAgICAgIGVtcHR5RWwudGV4dENvbnRlbnQgPSB1bmF2YWlsYWJsZU1lc3NhZ2UKICAgICAgICAgICAgfHwgIkdyYXBoaXF1ZSBtb21lbnRhbsOpbWVudCBpbmRpc3BvbmlibGUg4oCUIG5vdXZlbGxlIHRlbnRhdGl2ZSBlbiBjb3VycywgcsOpZXNzYWllIGRhbnMgcXVlbHF1ZXMgc2Vjb25kZXMuIjsKICAgICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgfQogICAgICAgIHRyeVJlbG9hZENoYXJ0SnMoKTsKICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQogICAgICB0cnkgewogICAgICAgIHJldHVybiBuZXcgQ2hhcnQoY2FudmFzLCBjb25maWcpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCJFcnJldXIgbG9ycyBkZSBsYSBjcsOpYXRpb24gZHUgZ3JhcGhpcXVlIDoiLCBlcnIpOwogICAgICAgIGlmIChjYW52YXMpIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGlmIChlbXB0eUVsKSB7CiAgICAgICAgICBlbXB0eUVsLnRleHRDb250ZW50ID0gIkVycmV1ciBkJ2FmZmljaGFnZSBkdSBncmFwaGlxdWUg4oCUIGVzc2FpZSBkZSByZWNoYXJnZXIgbGEgcGFnZS4iOwogICAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgIH0KICAgIH0KCiAgICBsZXQgY2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgaW5jb21lQ2F0ZWdvcnlDaGFydCA9IG51bGw7CiAgICBsZXQgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOwogICAgbGV0IHllYXJseUNoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBtb250aEtleU9mKGV4cGVuc2VEYXRlKSB7CiAgICAgIHJldHVybiBleHBlbnNlRGF0ZS5zbGljZSgwLCA3KTsgLy8gIllZWVktTU0iCiAgICB9CgogICAgLy8gVW5lIGNoYXJnZSByw6ljdXJyZW50ZSBjb21wdGUgcG91ciB1biBtb2lzIGRvbm7DqSBzaSBjZSBtb2lzIGVzdCBkYW5zIHNhCiAgICAvLyBww6lyaW9kZSBkJ2FjdGl2aXTDqSA6IHBhcyBhdmFudCBzYSBkYXRlIGRlIGTDqWJ1dCAoc2kgcG9zw6llKSwgcGFzIGFwcsOocwogICAgLy8gbGUgbW9pcyBkZSBzYSBkYXRlIGRlIGZpbiAoc2kgcG9zw6llKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSB7CiAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUgJiYgbW9udGhLZXkgPCBpdGVtLnN0YXJ0X2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUgJiYgbW9udGhLZXkgPiBpdGVtLmVuZF9kYXRlLnNsaWNlKDAsIDcpKSByZXR1cm4gZmFsc2U7CiAgICAgIHJldHVybiB0cnVlOwogICAgfQoKICAgIC8vIEpvdXIgZHUgbW9pcyBqdXNxdSdhdXF1ZWwgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBlc3QgY29uc2lkw6lyw6llIGNvbW1lCiAgICAvLyAiZMOpasOgIHByw6lsZXbDqWUiIHBvdXIgbGUgbW9pcyBgbW9udGhLZXlgIDogdG91cyBsZXMgam91cnMgcG91ciB1biBtb2lzCiAgICAvLyBkw6lqw6AgcGFzc8OpLCBhdWN1biBwb3VyIHVuIG1vaXMgZnV0dXIsIGV0IGxlIGpvdXIgZHUgam91ciBwb3VyIGxlIG1vaXMKICAgIC8vIGVuIGNvdXJzLiBQZXJtZXQgZGUgZGlzdGluZ3VlciBjZSBxdWkgZXN0IGTDqWrDoCBhcnJpdsOpIGRlIGNlIHF1aSBlc3QKICAgIC8vIHNldWxlbWVudCBwcsOpdnUgKGV4IDogdW4gYWJvbm5lbWVudCBwcsOpbGV2w6kgbGUgMjUsIG9uIGVzdCBsZSAyKS4KICAgIGZ1bmN0aW9uIHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSkgewogICAgICBpZiAobW9udGhLZXkgPCBjdXJyZW50TW9udGhLZXkpIHJldHVybiAzMTsKICAgICAgaWYgKG1vbnRoS2V5ID4gY3VycmVudE1vbnRoS2V5KSByZXR1cm4gMDsKICAgICAgcmV0dXJuIHRvZGF5RGF5OwogICAgfQoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGlmIChhbGxSZWN1cnJpbmcubGVuZ3RoID4gMCkgbW9udGhTZXQuYWRkKG1vbnRoS2V5T2YodG9kYXlJc28oKSkpOwogICAgICBjb25zdCBtb250aHMgPSBbLi4ubW9udGhTZXRdLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSAiIjsKCiAgICAgIGlmIChtb250aHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0gIiI7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gIkF1Y3VuZSBkb25uw6llIjsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICBjb25zdCBsYWJlbCA9IG1vbnRoRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIH0KICAgICAgc2VsZWN0LnZhbHVlID0gbW9udGhzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IG1vbnRoc1swXTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWNhdGVnb3JpZXMiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIpOwogICAgICBjb25zdCB1cGNvbWluZ05vdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctbm90ZSIpOwogICAgICBjb25zdCB1cGNvbWluZ1RleHRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtdXBjb21pbmctdGV4dCIpOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgdG9kYXlEYXkgPSBOdW1iZXIodG9kYXlJc28oKS5zbGljZSg4LCAxMCkpOwogICAgICBjb25zdCBjdXRvZmYgPSByZWN1cnJpbmdDdXRvZmZEYXkobW9udGhLZXksIGN1cnJlbnRNb250aEtleSwgdG9kYXlEYXkpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICAvLyBVbiBzZXVsIHNvbGRlIG5ldCAiw6AgdmVuaXIiIChyZXZlbnVzIHLDqWN1cnJlbnRzIMOgIHZlbmlyIG1vaW5zIGTDqXBlbnNlcwogICAgICAvLyByw6ljdXJyZW50ZXMgw6AgdmVuaXIpLCBwbHV0w7R0IHF1ZSBkZXV4IGNoaWZmcmVzIHPDqXBhcsOpcyA6IHBsdXMgc2ltcGxlCiAgICAgIC8vIMOgIGxpcmUgZCd1biBjb3VwIGQnxZNpbC4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUgc29udCBQQVMKICAgICAgLy8gYWpvdXTDqWVzIGljaSA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUgdnJhaWVzIHRyYW5zYWN0aW9ucwogICAgICAvLyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzIGRhbnMgYHRvdGFsc2AKICAgICAgLy8gY2ktZGVzc3VzIOKAlCBsZXMgYWpvdXRlciDDoCBub3V2ZWF1IGxlcyBjb21wdGVyYWl0IGVuIGRvdWJsZS4KICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0uZGF5X29mX21vbnRoIDw9IGN1dG9mZikgY29udGludWU7CiAgICAgICAgaWYgKGl0ZW0udHlwZSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBsYWJlbHMgPSBPYmplY3Qua2V5cyh0b3RhbHMpLm1hcCgoY2F0KSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCk7CiAgICAgIGNvbnN0IGRhdGEgPSBPYmplY3QudmFsdWVzKHRvdGFscyk7CgogICAgICBjb25zdCBuZXRVcGNvbWluZyA9IHVwY29taW5nSW5jb21lIC0gdXBjb21pbmdFeHBlbnNlOwogICAgICBpZiAobmV0VXBjb21pbmcgIT09IDApIHsKICAgICAgICBjb25zdCBzaWduID0gbmV0VXBjb21pbmcgPiAwID8gIisiIDogIuKIkiI7CiAgICAgICAgdXBjb21pbmdUZXh0RWwudGV4dENvbnRlbnQgPSBgJHtzaWdufSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChNYXRoLmFicyhuZXRVcGNvbWluZykpfSDDoCB2ZW5pcmA7CiAgICAgICAgdXBjb21pbmdOb3RlRWwudGl0bGUgPSAiUsOpY3VycmVudGVzIHBhcyBlbmNvcmUgcHLDqWxldsOpZXMvcmXDp3VlcyBjZSBtb2lzLWNpIChyZXZlbnVzIG1vaW5zIGTDqXBlbnNlcykiOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC50b2dnbGUoInBvc2l0aXZlIiwgbmV0VXBjb21pbmcgPiAwKTsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB1cGNvbWluZ05vdGVFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgfQoKICAgICAgaWYgKGNhdGVnb3J5Q2hhcnQpIHsgY2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNhdGVnb3J5Q2hhcnQgPSBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0sIGVtcHR5RWwpOwogICAgfQoKICAgIC8vIE3Dqm1lIHByaW5jaXBlIHF1ZSByZW5kZXJDYXRlZ29yeUNoYXJ0LCBjw7R0w6kgcmV2ZW51cyDigJQgcGFzIGRlIG5vdGUgIsOgCiAgICAvLyB2ZW5pciIgaWNpLCBlbGxlIHJlc3RlIHVuaXF1ZW1lbnQgc3VyIGxlIGNhbWVtYmVydCBkZXMgZMOpcGVuc2VzIHBvdXIKICAgIC8vIG5lIHBhcyBhZmZpY2hlciBsZSBtw6ptZSBjaGlmZnJlIG5ldCDDoCBkZXV4IGVuZHJvaXRzLgogICAgZnVuY3Rpb24gcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhLZXkgPSBzZWxlY3QudmFsdWU7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1pbmNvbWUtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIpOwoKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJpbmNvbWUiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGlmIChpbmNvbWVDYXRlZ29yeUNoYXJ0KSB7IGluY29tZUNhdGVnb3J5Q2hhcnQuZGVzdHJveSgpOyBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKGRhdGEubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJkb3VnaG51dCIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGRhdGEsCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogbGFiZWxzLm1hcCgoXywgaSkgPT4gQ0hBUlRfQ09MT1JTW2kgJSBDSEFSVF9DT0xPUlMubGVuZ3RoXSksCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiAiIzFhMWQyNCIsCiAgICAgICAgICAgIGJvcmRlcldpZHRoOiAyLAogICAgICAgICAgfV0sCiAgICAgICAgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBwb3NpdGlvbjogImJvdHRvbSIsIGxhYmVsczogeyBjb2xvcjogIiNlNmU2ZTYiLCBib3hXaWR0aDogMTIsIHBhZGRpbmc6IDEyLCBmb250OiB7IHNpemU6IDExIH0gfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmxhYmVsfSA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGN0eC5wYXJzZWQpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9LCBlbXB0eUVsKTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWV2b2x1dGlvbiIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1ldm9sdXRpb24tZW1wdHkiKTsKCiAgICAgIGNvbnN0IG1vbnRobHkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBrZXkgPSBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSk7CiAgICAgICAgaWYgKCFtb250aGx5W2tleV0pIG1vbnRobHlba2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgICAgbW9udGhseVtrZXldW3R4LnR5cGVdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFRvdWpvdXJzIGluY2x1cmUgbGUgbW9pcyBlbiBjb3VycyAobcOqbWUgc2FucyB0cmFuc2FjdGlvbikgcydpbCBleGlzdGUKICAgICAgLy8gZGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBwb3VyIHF1J2lsIGFwcGFyYWlzc2Ugc2FucyBhdHRlbmRyZSBsYQogICAgICAvLyBwcmVtacOocmUgdHJhbnNhY3Rpb24gZHUgbW9pcy4gTGVzIGNoYXJnZXMgZMOpasOgIHByw6lsZXbDqWVzL3Jlw6d1ZXMgbmUKICAgICAgLy8gc29udCBwbHVzIGFqb3V0w6llcyBpY2kgw6AgbGEgbWFpbiA6IGVsbGVzIGV4aXN0ZW50IGTDqXNvcm1haXMgY29tbWUgZGUKICAgICAgLy8gdnJhaWVzIHRyYW5zYWN0aW9ucyAoY3LDqcOpZXMgY8O0dMOpIHNlcnZldXIpIGV0IHNvbnQgZG9uYyBkw6lqw6AgY29tcHTDqWVzCiAgICAgIC8vIGRhbnMgYG1vbnRobHlgIHZpYSBsYSBib3VjbGUgc3VyIGB0cmFuc2FjdGlvbnNgIGNpLWRlc3N1cyDigJQgY2UgcXVpCiAgICAgIC8vIG4nZXN0IHBhcyBlbmNvcmUgYXJyaXbDqSBlc3QgcsOpc3Vtw6kgYWlsbGV1cnMgKHNvbGRlIG5ldCAiw6AgdmVuaXIiKS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwICYmICFtb250aGx5W2N1cnJlbnRNb250aEtleV0pIHsKICAgICAgICBtb250aGx5W2N1cnJlbnRNb250aEtleV0gPSB7IGV4cGVuc2U6IDAsIGluY29tZTogMCB9OwogICAgICB9CiAgICAgIGNvbnN0IG1vbnRocyA9IE9iamVjdC5rZXlzKG1vbnRobHkpLnNvcnQoKTsKCiAgICAgIGlmIChldm9sdXRpb25DaGFydCkgeyBldm9sdXRpb25DaGFydC5kZXN0cm95KCk7IGV2b2x1dGlvbkNoYXJ0ID0gbnVsbDsgfQoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGNvbnN0IGxhYmVscyA9IG1vbnRocy5tYXAoKGtleSkgPT4gewogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIHJldHVybiBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5LCBtIC0gMSwgMSkpOwogICAgICB9KTsKCiAgICAgIGNvbnN0IGRhdGFzZXRzID0gWwogICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmV4cGVuc2UpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgIHsgbGFiZWw6ICJSZXZlbnVzIiwgZGF0YTogbW9udGhzLm1hcCgoaykgPT4gbW9udGhseVtrXS5pbmNvbWUpLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICBdOwoKICAgICAgZXZvbHV0aW9uQ2hhcnQgPSBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImJhciIsCiAgICAgICAgZGF0YTogeyBsYWJlbHMsIGRhdGFzZXRzIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0sIGJlZ2luQXRaZXJvOiB0cnVlIH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9LAogICAgICAgICAgICB0b29sdGlwOiB7IGNhbGxiYWNrczogeyBsYWJlbDogKGN0eCkgPT4gYCR7Y3R4LmRhdGFzZXQubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZC55KX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSwgZW1wdHlFbCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29tcGFyZXIgZGV1eCBtb2lzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoU2V0ID0gbmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3Qgc2VsZWN0QSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKTsKICAgICAgY29uc3Qgc2VsZWN0QiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKTsKCiAgICAgIGZvciAoY29uc3Qgc2VsZWN0IG9mIFtzZWxlY3RBLCBzZWxlY3RCXSkgewogICAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwogICAgICAgIGZvciAoY29uc3Qga2V5IG9mIG1vbnRocykgewogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSBrZXk7CiAgICAgICAgICBjb25zdCBbeSwgbV0gPSBrZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIGxhYmVsLnNsaWNlKDEpOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGlmIChtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkpIHNlbGVjdC52YWx1ZSA9IHByZXZpb3VzVmFsdWU7CiAgICAgIH0KICAgICAgLy8gUGFyIGTDqWZhdXQgOiBtb2lzIGVuIGNvdXJzIHZzIG1vaXMgcHLDqWPDqWRlbnQsIHNpIGxlcyBkZXV4IGV4aXN0ZW50LgogICAgICBpZiAoIXNlbGVjdEEudmFsdWUgJiYgbW9udGhzLmxlbmd0aCA+IDApIHNlbGVjdEEudmFsdWUgPSBtb250aHNbMF07CiAgICAgIGlmICghc2VsZWN0Qi52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMSkgc2VsZWN0Qi52YWx1ZSA9IG1vbnRoc1sxXTsKICAgIH0KCiAgICBmdW5jdGlvbiBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgbW9udGhLZXkpIHsKICAgICAgY29uc3QgdG90YWxzID0ge307CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIiB8fCBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IG1vbnRoS2V5KSBjb250aW51ZTsKICAgICAgICB0b3RhbHNbdHguY2F0ZWdvcnldID0gKHRvdGFsc1t0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB0b3RhbCArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgfQogICAgICByZXR1cm4geyB0b3RhbHMsIHRvdGFsIH07CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyTW9udGhDb21wYXJpc29uKCkgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtdGFibGUtd3JhcCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtZW1wdHkiKTsKICAgICAgY29uc3QgbW9udGhBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLnZhbHVlOwogICAgICBjb25zdCBtb250aEIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikudmFsdWU7CgogICAgICBpZiAoIW1vbnRoQSB8fCAhbW9udGhCKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBjb25zdCB7IHRvdGFsczogdG90YWxzQSwgdG90YWw6IGdyYW5kQSB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyhhbGxUcmFuc2FjdGlvbnMsIG1vbnRoQSk7CiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNCLCB0b3RhbDogZ3JhbmRCIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhCKTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KFsuLi5PYmplY3Qua2V5cyh0b3RhbHNBKSwgLi4uT2JqZWN0LmtleXModG90YWxzQildKV0uc29ydCgKICAgICAgICAoYSwgYikgPT4gKHRvdGFsc0JbYl0gfHwgMCkgLSAodG90YWxzQVthXSB8fCAwKQogICAgICApOwoKICAgICAgY29uc3QgW3lhLCBtYV0gPSBtb250aEEuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgW3liLCBtYl0gPSBtb250aEIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgbGFiZWxBID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeWEsIG1hIC0gMSwgMSkpOwogICAgICBjb25zdCBsYWJlbEIgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YiwgbWIgLSAxLCAxKSk7CgogICAgICAvLyBEaWZmID0gbW9udGFudCBkdSBtb2lzIEIgbW9pbnMgY2VsdWkgZHUgbW9pcyBBLiBQb3VyIGRlcyBkw6lwZW5zZXMsCiAgICAgIC8vIGTDqXBlbnNlciBQTFVTIChkaWZmIHBvc2l0aWYpIGVzdCBsYSBtYXV2YWlzZSBub3V2ZWxsZSDihpIgcm91Z2UgOyBlbgogICAgICAvLyBkw6lwZW5zZXIgTU9JTlMgKGRpZmYgbsOpZ2F0aWYpIOKGkiB2ZXJ0LgogICAgICBmdW5jdGlvbiBkaWZmQ2VsbChhLCBiKSB7CiAgICAgICAgY29uc3QgZGlmZiA9IGIgLSBhOwogICAgICAgIGlmIChNYXRoLmFicyhkaWZmKSA8IDAuMDEpIHJldHVybiBgPHRkPuKAlDwvdGQ+YDsKICAgICAgICBjb25zdCBjbHMgPSBkaWZmID4gMCA/ICJkaWZmLW5lZ2F0aXZlIiA6ICJkaWZmLXBvc2l0aXZlIjsKICAgICAgICByZXR1cm4gYDx0ZCBjbGFzcz0iJHtjbHN9Ij4ke2RpZmYgPiAwID8gIisiIDogIiJ9JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGlmZil9PC90ZD5gOwogICAgICB9CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPiR7bGFiZWxBfTwvdGg+PHRoPiR7bGFiZWxCfTwvdGg+PHRoPkRpZmbDqXJlbmNlPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgY2F0IG9mIGNhdGVnb3JpZXMpIHsKICAgICAgICBjb25zdCBhID0gdG90YWxzQVtjYXRdIHx8IDA7CiAgICAgICAgY29uc3QgYiA9IHRvdGFsc0JbY2F0XSB8fCAwOwogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHtlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChiKX08L3RkPiR7ZGlmZkNlbGwoYSwgYil9PC90cj5gOwogICAgICB9CiAgICAgIGh0bWwgKz0gYDx0ciBjbGFzcz0idG90YWwtcm93Ij48dGQ+VG90YWwgZMOpcGVuc2VzPC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZ3JhbmRBKX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEIpfTwvdGQ+JHtkaWZmQ2VsbChncmFuZEEsIGdyYW5kQil9PC90cj5gOwogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWEiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCByZW5kZXJNb250aENvbXBhcmlzb24pOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ2FsY3VsZSwgcG91ciBjaGFxdWUgY2F0w6lnb3JpZSBkZSBkw6lwZW5zZSwgbGEgbW95ZW5uZSBtZW5zdWVsbGUsIGxlCiAgICAvLyBtb250YW50IGR1IG1vaXMgZW4gY291cnMsIGV0IGxhIHRlbmRhbmNlIChkaXJlY3Rpb24gKyByYXRpbyB2cwogICAgLy8gbW95ZW5uZSkuIFBhcnRhZ8OpIGVudHJlIGxlIHRhYmxlYXUgIk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWUiCiAgICAvLyBldCBsZXMgY29uc2VpbHMgZCfDqXBhcmduZSwgcG91ciBuZSBwYXMgZHVwbGlxdWVyIGNldHRlIGxvZ2lxdWUuCiAgICBmdW5jdGlvbiBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IG1vbnRoS2V5cyA9IFsuLi5uZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKV0uc29ydCgpOwogICAgICBpZiAobW9udGhLZXlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIFtdOwogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleXNbbW9udGhLZXlzLmxlbmd0aCAtIDFdOwogICAgICBjb25zdCBuYk1vbnRocyA9IG1vbnRoS2V5cy5sZW5ndGg7CgogICAgICAvLyB0b3RhbCBwYXIgY2F0w6lnb3JpZSwgZXQgcGFyIGNhdMOpZ29yaWUrbW9pcyAocG91ciBpc29sZXIgbGUgbW9pcyBlbiBjb3VycykKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBjb25zdCBjdXJyZW50TW9udGhCeUNhdGVnb3J5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgaWYgKHR4LnR5cGUgIT09ICJleHBlbnNlIikgY29udGludWU7CiAgICAgICAgdG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAodG90YWxzQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBpZiAobW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpID09PSBjdXJyZW50TW9udGhLZXkpIHsKICAgICAgICAgIGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICByZXR1cm4gY2F0ZWdvcmllcy5tYXAoKGNhdCkgPT4gewogICAgICAgIGNvbnN0IGF2ZXJhZ2UgPSB0b3RhbHNCeUNhdGVnb3J5W2NhdF0gLyBuYk1vbnRoczsKICAgICAgICBjb25zdCBjdXJyZW50ID0gY3VycmVudE1vbnRoQnlDYXRlZ29yeVtjYXRdIHx8IDA7CiAgICAgICAgbGV0IGRpcmVjdGlvbiA9ICJzdGFibGUiOwogICAgICAgIGxldCByYXRpbyA9IDA7CiAgICAgICAgaWYgKGF2ZXJhZ2UgPiAwKSB7CiAgICAgICAgICByYXRpbyA9IChjdXJyZW50IC0gYXZlcmFnZSkgLyBhdmVyYWdlOwogICAgICAgICAgaWYgKHJhdGlvID4gMC4xNSkgZGlyZWN0aW9uID0gInVwIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvIDwgLTAuMTUpIGRpcmVjdGlvbiA9ICJkb3duIjsKICAgICAgICB9IGVsc2UgaWYgKGN1cnJlbnQgPiAwKSB7CiAgICAgICAgICBkaXJlY3Rpb24gPSAidXAiOwogICAgICAgIH0KICAgICAgICByZXR1cm4geyBjYXRlZ29yeTogY2F0LCBhdmVyYWdlLCBjdXJyZW50LCByYXRpbywgZGlyZWN0aW9uIH07CiAgICAgIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRyZW5kLXRhYmxlLXdyYXAiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0cmVuZC1lbXB0eSIpOwoKICAgICAgY29uc3QgdHJlbmRzID0gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh0cmVuZHMubGVuZ3RoID09PSAwKSB7CiAgICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CgogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPk1veWVubmUvbW9pczwvdGg+PHRoPkNlIG1vaXMtY2k8L3RoPjx0aD5UZW5kYW5jZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IHQgb2YgdHJlbmRzKSB7CiAgICAgICAgbGV0IHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZmxhdCI+4oaSIHN0YWJsZTwvc3Bhbj5gOwogICAgICAgIGlmICh0LmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdHJlbmRIdG1sID0gdC5hdmVyYWdlID4gMAogICAgICAgICAgICA/IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSArJHtNYXRoLnJvdW5kKHQucmF0aW8gKiAxMDApfSU8L3NwYW4+YAogICAgICAgICAgICA6IGA8c3BhbiBjbGFzcz0idHJlbmQtdXAiPuKGkSBub3V2ZWF1PC9zcGFuPmA7CiAgICAgICAgfSBlbHNlIGlmICh0LmRpcmVjdGlvbiA9PT0gImRvd24iKSB7CiAgICAgICAgICB0cmVuZEh0bWwgPSBgPHNwYW4gY2xhc3M9InRyZW5kLWRvd24iPuKGkyAke01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JTwvc3Bhbj5gOwogICAgICAgIH0KICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1t0LmNhdGVnb3J5XSB8fCB0LmNhdGVnb3J5KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0LmF2ZXJhZ2UpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuY3VycmVudCl9PC90ZD48dGQ+JHt0cmVuZEh0bWx9PC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHdyYXAuaW5uZXJIVE1MID0gaHRtbDsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBCaWxhbiBhbm51ZWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IE1PTlRIX1NIT1JUX0xBQkVMUyA9IFsKICAgICAgIkphbiIsICJGw6l2IiwgIk1hciIsICJBdnIiLCAiTWFpIiwgIkp1aW4iLCAiSnVpbCIsICJBb8O7dCIsICJTZXAiLCAiT2N0IiwgIk5vdiIsICJEw6ljIiwKICAgIF07CgogICAgZnVuY3Rpb24gcG9wdWxhdGVZZWFyU2VsZWN0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0Iik7CiAgICAgIGNvbnN0IHllYXJzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSkpXS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBjdXJyZW50WWVhciA9IFN0cmluZyhuZXcgRGF0ZSgpLmdldEZ1bGxZZWFyKCkpOwogICAgICBpZiAoIXllYXJzLmluY2x1ZGVzKGN1cnJlbnRZZWFyKSkgeWVhcnMudW5zaGlmdChjdXJyZW50WWVhcik7CgogICAgICBjb25zdCBwcmV2aW91c1ZhbHVlID0gc2VsZWN0LnZhbHVlOwogICAgICBzZWxlY3QuaW5uZXJIVE1MID0geWVhcnMubWFwKCh5KSA9PiBgPG9wdGlvbiB2YWx1ZT0iJHt5fSI+JHt5fTwvb3B0aW9uPmApLmpvaW4oIiIpOwogICAgICBzZWxlY3QudmFsdWUgPSB5ZWFycy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSA/IHByZXZpb3VzVmFsdWUgOiBjdXJyZW50WWVhcjsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpOwogICAgICBjb25zdCB5ZWFyID0gc2VsZWN0LnZhbHVlOwogICAgICBpZiAoIXllYXIpIHJldHVybjsKCiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC15ZWFybHkiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktZW1wdHkiKTsKICAgICAgY29uc3QgdGFibGVXcmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIik7CgogICAgICBjb25zdCB5ZWFyVHJhbnNhY3Rpb25zID0gdHJhbnNhY3Rpb25zLmZpbHRlcigodHgpID0+IHR4LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA0KSA9PT0geWVhcik7CgogICAgICBsZXQgdG90YWxFeHBlbnNlcyA9IDA7CiAgICAgIGxldCB0b3RhbEluY29tZSA9IDA7CiAgICAgIGNvbnN0IGV4cGVuc2VCeU1vbnRoID0gQXJyYXkoMTIpLmZpbGwoMCk7CiAgICAgIGNvbnN0IGluY29tZUJ5TW9udGggPSBBcnJheSgxMikuZmlsbCgwKTsKICAgICAgY29uc3QgdG90YWxzQnlDYXRlZ29yeSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHllYXJUcmFuc2FjdGlvbnMpIHsKICAgICAgICBjb25zdCBtb250aEluZGV4ID0gTnVtYmVyKHR4LmV4cGVuc2VfZGF0ZS5zbGljZSg1LCA3KSkgLSAxOwogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgewogICAgICAgICAgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICBpbmNvbWVCeU1vbnRoW21vbnRoSW5kZXhdICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICAgICAgZXhwZW5zZUJ5TW9udGhbbW9udGhJbmRleF0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICB0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIH0KICAgICAgfQogICAgICBjb25zdCBuZXQgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CgogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXRvdGFsLWV4cGVuc2VzIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxFeHBlbnNlcyk7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktdG90YWwtaW5jb21lIikudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxJbmNvbWUpOwogICAgICBjb25zdCBuZXRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktbmV0Iik7CiAgICAgIG5ldEVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KG5ldCk7CiAgICAgIG5ldEVsLmNsYXNzTmFtZSA9ICJ5ZWFybHktc3RhdC12YWx1ZSAiICsgKG5ldCA+PSAwID8gImluY29tZSIgOiAiZXhwZW5zZSIpOwoKICAgICAgaWYgKHllYXJseUNoYXJ0KSB7IHllYXJseUNoYXJ0LmRlc3Ryb3koKTsgeWVhcmx5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoeWVhclRyYW5zYWN0aW9ucy5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICB5ZWFybHlDaGFydCA9IHNhZmVDcmVhdGVDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHM6IE1PTlRIX1NIT1JUX0xBQkVMUywKICAgICAgICAgIGRhdGFzZXRzOiBbCiAgICAgICAgICAgIHsgbGFiZWw6ICJEw6lwZW5zZXMiLCBkYXRhOiBleHBlbnNlQnlNb250aCwgYmFja2dyb3VuZENvbG9yOiAiI2VmNDQ0NCIgfSwKICAgICAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBpbmNvbWVCeU1vbnRoLCBiYWNrZ3JvdW5kQ29sb3I6ICIjMjJjNTVlIiB9LAogICAgICAgICAgXSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHNjYWxlczogewogICAgICAgICAgICB4OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgICAgeTogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICB9LAogICAgICAgICAgcGx1Z2luczogeyBsZWdlbmQ6IHsgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIgfSB9IH0sCiAgICAgICAgfSwKICAgICAgfSwgZW1wdHlFbCk7CgogICAgICBjb25zdCBjYXRlZ29yaWVzID0gT2JqZWN0LmtleXModG90YWxzQnlDYXRlZ29yeSkuc29ydCgoYSwgYikgPT4gdG90YWxzQnlDYXRlZ29yeVtiXSAtIHRvdGFsc0J5Q2F0ZWdvcnlbYV0pOwogICAgICBsZXQgaHRtbCA9IGA8dGFibGUgY2xhc3M9InNpbXBsZS10YWJsZSI+PHRoZWFkPjx0cj48dGg+Q2F0w6lnb3JpZTwvdGg+PHRoPlRvdGFsPC90aD48dGg+JSBkZSBsJ2FubsOpZTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT5gOwogICAgICBmb3IgKGNvbnN0IGNhdCBvZiBjYXRlZ29yaWVzKSB7CiAgICAgICAgY29uc3QgYW1vdW50ID0gdG90YWxzQnlDYXRlZ29yeVtjYXRdOwogICAgICAgIGNvbnN0IHBjdCA9IHRvdGFsRXhwZW5zZXMgPiAwID8gTWF0aC5yb3VuZCgoYW1vdW50IC8gdG90YWxFeHBlbnNlcykgKiAxMDApIDogMDsKICAgICAgICBodG1sICs9IGA8dHI+PHRkPiR7ZXNjYXBlSHRtbChhbGxDYXRlZ29yeUxhYmVsc1tjYXRdIHx8IGNhdCl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYW1vdW50KX08L3RkPjx0ZD4ke3BjdH0lPC90ZD48L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPC90Ym9keT48L3RhYmxlPmA7CiAgICAgIHRhYmxlV3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiByZW5kZXJZZWFybHlPdmVydmlldyhhbGxUcmFuc2FjdGlvbnMpKTsKCiAgICBmdW5jdGlvbiByZW5kZXJEYXNoYm9hcmQodHJhbnNhY3Rpb25zKSB7CiAgICAgIHBvcHVsYXRlTW9udGhTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckJ1ZGdldHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyRXZvbHV0aW9uQ2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcG9wdWxhdGVDb21wYXJlTW9udGhTZWxlY3RzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlck1vbnRoQ29tcGFyaXNvbigpOwogICAgICByZW5kZXJDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZVllYXJTZWxlY3QodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyWWVhcmx5T3ZlcnZpZXcodHJhbnNhY3Rpb25zKTsKICAgICAgc2V0dXBEYXNoYm9hcmRDaGlwcygpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFPDqWxlY3RldXIgZHUgdGFibGVhdSBkZSBib3JkIDogdW4gc2V1bCBibG9jIGFmZmljaMOpIMOgIGxhIGZvaXMgKHN1ciBsZXMKICAgIC8vIDcgZW1waWzDqXMpIHBvdXIgcXVlIMOnYSB0aWVubmUgc3VyIHVuIMOpY3JhbiBkZSB0w6lsw6lwaG9uZSBzYW5zIGTDqWZpbGVyCiAgICAvLyBzYW5zIGZpbi4gTGVzIGNhbGN1bHMvZ3JhcGhpcXVlcyBldXgtbcOqbWVzIG5lIGNoYW5nZW50IHBhcyDigJQgc2V1bGUgbGEKICAgIC8vIHZpc2liaWxpdMOpIGRlcyBibG9jcyBlc3QgcGlsb3TDqWUgcGFyIGxhIHB1Y2UgYWN0aXZlLgogICAgY29uc3QgREFTSEJPQVJEX1NFQ1RJT05TID0gWwogICAgICB7IGtleTogImV4cGVuc2VzIiwgbGFiZWw6ICJEw6lwZW5zZXMiLCByb3dJZDogImRhc2gtcm93LWV4cGVuc2VzIiB9LAogICAgICB7IGtleTogImluY29tZSIsIGxhYmVsOiAiUmV2ZW51cyIsIHJvd0lkOiAiZGFzaC1yb3ctaW5jb21lIiB9LAogICAgICB7IGtleTogImJ1ZGdldHMiLCBsYWJlbDogIkJ1ZGdldHMiLCByb3dJZDogImRhc2gtcm93LWJ1ZGdldHMiIH0sCiAgICAgIHsga2V5OiAiZXZvbHV0aW9uIiwgbGFiZWw6ICLDiXZvbHV0aW9uIiwgcm93SWQ6ICJkYXNoLXJvdy1ldm9sdXRpb24iIH0sCiAgICAgIHsga2V5OiAiY29tcGFyZSIsIGxhYmVsOiAiQ29tcGFyZXIiLCByb3dJZDogImRhc2gtcm93LWNvbXBhcmUiIH0sCiAgICAgIHsga2V5OiAidHJlbmQiLCBsYWJlbDogIlRlbmRhbmNlcyIsIHJvd0lkOiAiZGFzaC1yb3ctdHJlbmQiIH0sCiAgICAgIHsga2V5OiAieWVhcmx5IiwgbGFiZWw6ICJBbm7DqWUiLCByb3dJZDogImRhc2gtcm93LXllYXJseSIgfSwKICAgIF07CiAgICBsZXQgZGFzaGJvYXJkQWN0aXZlU2VjdGlvbiA9IERBU0hCT0FSRF9TRUNUSU9OU1swXS5rZXk7CiAgICBsZXQgZGFzaGJvYXJkQ2hpcHNCdWlsdCA9IGZhbHNlOwoKICAgIGZ1bmN0aW9uIHNob3dEYXNoYm9hcmRTZWN0aW9uKGtleSkgewogICAgICBkYXNoYm9hcmRBY3RpdmVTZWN0aW9uID0ga2V5OwogICAgICBmb3IgKGNvbnN0IHNlY3Rpb24gb2YgREFTSEJPQVJEX1NFQ1RJT05TKSB7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoc2VjdGlvbi5yb3dJZCkuY2xhc3NMaXN0LnRvZ2dsZSgiZGFzaC1oaWRkZW4iLCBzZWN0aW9uLmtleSAhPT0ga2V5KTsKICAgICAgfQogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIuZGFzaGJvYXJkLWNoaXAiKS5mb3JFYWNoKChjaGlwKSA9PiB7CiAgICAgICAgY2hpcC5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBjaGlwLmRhdGFzZXQuc2VjdGlvbiA9PT0ga2V5KTsKICAgICAgfSk7CiAgICAgIC8vIFVuIGdyYXBoaXF1ZSBDaGFydC5qcyByZWNyw6nDqSBwZW5kYW50IHF1ZSBzb24gYmxvYyDDqXRhaXQgbWFzcXXDqQogICAgICAvLyAoZGlzcGxheTpub25lKSBzZSByZXRyb3V2ZSBhdmVjIHVuIGNhbmV2YXMgZGUgdGFpbGxlIG51bGxlIGV0IG5lIHNlCiAgICAgIC8vIGNvcnJpZ2UgcGFzIHRvdXQgc2V1bCBlbiByZWRldmVuYW50IHZpc2libGUg4oCUIG9uIGZvcmNlIHVuIHJlc2l6ZQogICAgICAvLyBqdXN0ZSBhcHLDqHMgbCdhdm9pciBhZmZpY2jDqSwgcG91ciBsZXMgNCBncmFwaGlxdWVzIGNvbmNlcm7DqXMuCiAgICAgIGZvciAoY29uc3QgY2hhcnQgb2YgW2NhdGVnb3J5Q2hhcnQsIGluY29tZUNhdGVnb3J5Q2hhcnQsIGV2b2x1dGlvbkNoYXJ0LCB5ZWFybHlDaGFydF0pIHsKICAgICAgICBpZiAoY2hhcnQpIGNoYXJ0LnJlc2l6ZSgpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0dXBEYXNoYm9hcmRDaGlwcygpIHsKICAgICAgaWYgKGRhc2hib2FyZENoaXBzQnVpbHQpIHsKICAgICAgICBzaG93RGFzaGJvYXJkU2VjdGlvbihkYXNoYm9hcmRBY3RpdmVTZWN0aW9uKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1jaGlwLXJvdyIpOwogICAgICBmb3IgKGNvbnN0IHNlY3Rpb24gb2YgREFTSEJPQVJEX1NFQ1RJT05TKSB7CiAgICAgICAgY29uc3QgY2hpcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGNoaXAudHlwZSA9ICJidXR0b24iOwogICAgICAgIGNoaXAuY2xhc3NOYW1lID0gImRhc2hib2FyZC1jaGlwIjsKICAgICAgICBjaGlwLmRhdGFzZXQuc2VjdGlvbiA9IHNlY3Rpb24ua2V5OwogICAgICAgIGNoaXAudGV4dENvbnRlbnQgPSBzZWN0aW9uLmxhYmVsOwogICAgICAgIGNoaXAuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93RGFzaGJvYXJkU2VjdGlvbihzZWN0aW9uLmtleSkpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChjaGlwKTsKICAgICAgfQogICAgICBkYXNoYm9hcmRDaGlwc0J1aWx0ID0gdHJ1ZTsKICAgICAgc2hvd0Rhc2hib2FyZFNlY3Rpb24oZGFzaGJvYXJkQWN0aXZlU2VjdGlvbik7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKS5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgIHJlbmRlckNhdGVnb3J5Q2hhcnQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVySW5jb21lQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRGljdMOpZSB2b2NhbGUKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IG1pY0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItbWljIik7CiAgICBjb25zdCB2b2ljZUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWJhbm5lciIpOwoKICAgIC8vIElkIGRlIGxhIGRlcm5pw6hyZSB0cmFuc2FjdGlvbiBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUgc2Vzc2lvbiBkZQogICAgLy8gbmF2aWdhdGlvbiAocmVtaXMgw6AgesOpcm8gc2kgb24gcmVjaGFyZ2UgbGEgcGFnZSkuIFNlcnQgdW5pcXVlbWVudCDDoAogICAgLy8gYXBwbGlxdWVyIHVuZSBjb3JyZWN0aW9uICgiZW4gZmFpdCBjJ8OpdGFpdCBwbHV0w7R0Li4uIikgc3VyIGxhIGJvbm5lCiAgICAvLyB0cmFuc2FjdGlvbi4gU2FucyDDp2EsIG91IHNpIGxhIHBocmFzZSBuJ2VzdCBwYXMgdW5lIGNvcnJlY3Rpb24sIG9uCiAgICAvLyBjcsOpZSB0b3Vqb3VycyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24g4oCUIG1pZXV4IHZhdXQgdW4gZG91YmxvbiBxdSd1bmUKICAgIC8vIGTDqXBlbnNlIGNvcnJvbXB1ZSBwYXIgZXJyZXVyLgogICAgbGV0IGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNldFZvaWNlQmFubmVyKHRleHQpIHsKICAgICAgaWYgKCF0ZXh0KSB7CiAgICAgICAgdm9pY2VCYW5uZXJFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImFuc3dlciIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSAiIjsKICAgICAgfSBlbHNlIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VBbnN3ZXJCYW5uZXIodGV4dCkgewogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImFuc3dlciIpOwogICAgICB2b2ljZUJhbm5lckVsLnRleHRDb250ZW50ID0gdGV4dDsKICAgIH0KCiAgICAvLyBQcm9ub25jZSBsYSByw6lwb25zZSDDoCB1bmUgcXVlc3Rpb24gdm9jYWxlICgiQXNzaXN0YW50IHZvY2FsIHF1ZXN0aW9uIikuCiAgICAvLyBQdXIgYm9udXMgOiBzaSBsYSBzeW50aMOoc2Ugdm9jYWxlIG4nZXN0IHBhcyBkaXNwbyBvdSDDqWNob3VlLCBsYSByw6lwb25zZQogICAgLy8gcmVzdGUgYWZmaWNow6llIGRhbnMgbGUgYmFuZGVhdSwgZG9uYyBvbiBhdmFsZSBsJ2VycmV1ciBzYW5zIGJsb3F1ZXIuCiAgICBmdW5jdGlvbiBzcGVha1ZvaWNlQW5zd2VyKHRleHQpIHsKICAgICAgaWYgKCEoInNwZWVjaFN5bnRoZXNpcyIgaW4gd2luZG93KSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuY2FuY2VsKCk7CiAgICAgICAgY29uc3QgdXR0ZXJhbmNlID0gbmV3IFNwZWVjaFN5bnRoZXNpc1V0dGVyYW5jZSh0ZXh0KTsKICAgICAgICB1dHRlcmFuY2UubGFuZyA9ICJmci1GUiI7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5zcGVhayh1dHRlcmFuY2UpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQuCiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiB2b2NhbGUg4oCUIHF1YW5kIGwnSUEgYSB1biBkb3V0ZSBzdXIgbCdpbnRlcnByw6l0YXRpb24KICAgIC8vIChtb250YW50IGFwcHJveGltYXRpZiwgY2F0w6lnb3JpZSBpbmNlcnRhaW5lLi4uKSwgZWxsZSBkZW1hbmRlCiAgICAvLyBjb25maXJtYXRpb24gYXUgbGlldSBkJ2FwcGxpcXVlciBkaXJlY3RlbWVudC4gTCd1dGlsaXNhdGV1ciBwZXV0CiAgICAvLyByw6lwb25kcmUgZW4gYXBwdXlhbnQgc3VyICJDb25maXJtZXIiLyJBbm51bGVyIiwgT1UgZW4gcsOpLWFwcHV5YW50IHN1cgogICAgLy8gbGUgbWljcm8gcG91ciByw6lwb25kcmUgZGUgdml2ZSB2b2l4ICgib3VpIGMnZXN0IMOnYSIsICJub24sIGNoYW5nZSDDp2EKICAgIC8vIGVuIHJlc3RhdXJhbnQiLi4uKSDigJQgZGFucyBjZSBjYXMsIGxhIGRpY3TDqWUgc3VpdmFudGUgZXN0IGludGVycHLDqXTDqWUKICAgIC8vIGNvbW1lIHVuZSByw6lwb25zZSDDoCBDRVRURSBjb25maXJtYXRpb24gcGx1dMO0dCBxdWUgY29tbWUgdW5lIG5vdXZlbGxlCiAgICAvLyB0cmFuc2FjdGlvbiAodm9pciBwZW5kaW5nVm9pY2VBY3Rpb24sIHbDqXJpZmnDqSBkYW5zIGxlIGxpc3RlbmVyCiAgICAvLyAicmVzdWx0IiBkZSBsYSByZWNvbm5haXNzYW5jZSB2b2NhbGUgdW4gcGV1IHBsdXMgYmFzKS4KICAgIGxldCBwZW5kaW5nVm9pY2VBY3Rpb24gPSBudWxsOyAvLyB7IGtpbmQ6ICJ0cmFuc2FjdGlvbiIgfCAiZWRpdF9sYXN0IiwgZGF0YTogey4uLn0gfSBvdSBudWxsCiAgICBjb25zdCB2b2ljZUNvbmZpcm1CYW5uZXJFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ2b2ljZS1jb25maXJtLWJhbm5lciIpOwoKICAgIGZ1bmN0aW9uIGhpZGVWb2ljZUNvbmZpcm1CYW5uZXIoKSB7CiAgICAgIHBlbmRpbmdWb2ljZUFjdGlvbiA9IG51bGw7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5pbm5lckhUTUwgPSAiIjsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Vm9pY2VDb25maXJtQmFubmVyKGtpbmQsIHBhcnNlZCkgewogICAgICBwZW5kaW5nVm9pY2VBY3Rpb24gPSB7CiAgICAgICAga2luZCwKICAgICAgICBkYXRhOgogICAgICAgICAga2luZCA9PT0gInRyYW5zYWN0aW9uIgogICAgICAgICAgICA/IHBhcnNlZAogICAgICAgICAgICA6IHsKICAgICAgICAgICAgICAgIHRhcmdldDogcGFyc2VkLnRhcmdldCwKICAgICAgICAgICAgICAgIG5ld190eXBlOiBwYXJzZWQucmVxdWVzdGVkX25ld190eXBlLAogICAgICAgICAgICAgICAgbmV3X2NhdGVnb3J5OiBwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeSwKICAgICAgICAgICAgICB9LAogICAgICB9OwoKICAgICAgbGV0IHF1ZXN0aW9uOwogICAgICBpZiAoa2luZCA9PT0gInRyYW5zYWN0aW9uIikgewogICAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgICAgY29uc3QgY2F0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1twYXJzZWQuY2F0ZWdvcnldIHx8IHBhcnNlZC5jYXRlZ29yeTsKICAgICAgICBjb25zdCBkZXNjUGFydCA9IHBhcnNlZC5kZXNjcmlwdGlvbiA/IGAgKCR7cGFyc2VkLmRlc2NyaXB0aW9ufSlgIDogIiI7CiAgICAgICAgcXVlc3Rpb24gPQogICAgICAgICAgYCR7dmVyYn0gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCl9IGVuICR7Y2F0TGFiZWx9JHtkZXNjUGFydH0sIGAgKwogICAgICAgICAgYGxlICR7ZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUocGFyc2VkLmV4cGVuc2VfZGF0ZSkpfSDigJQgYydlc3QgYmllbiDDp2EgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgLy8gZWRpdF9sYXN0IDogb24gcmV0cm91dmUgbGEgdHJhbnNhY3Rpb24gY2libMOpZSBkYW5zIGFsbFRyYW5zYWN0aW9ucwogICAgICAgIC8vIChkw6lqw6AgdHJpw6kgcGFyIGRhdGUgZMOpY3JvaXNzYW50ZSkgcG91ciBkb25uZXIgdW4gY29udGV4dGUgdXRpbGUuCiAgICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IGFsbFRyYW5zYWN0aW9ucy5maWx0ZXIoKHQpID0+IHsKICAgICAgICAgIGlmIChwYXJzZWQudGFyZ2V0ID09PSAibGFzdF9leHBlbnNlIikgcmV0dXJuIHQudHlwZSA9PT0gImV4cGVuc2UiOwogICAgICAgICAgaWYgKHBhcnNlZC50YXJnZXQgPT09ICJsYXN0X2luY29tZSIpIHJldHVybiB0LnR5cGUgPT09ICJpbmNvbWUiOwogICAgICAgICAgcmV0dXJuIHRydWU7CiAgICAgICAgfSk7CiAgICAgICAgY29uc3QgdGFyZ2V0ID0gY2FuZGlkYXRlc1swXTsKICAgICAgICBjb25zdCB0YXJnZXRMYWJlbCA9IHRhcmdldAogICAgICAgICAgPyBgJHt0YXJnZXQudHlwZSA9PT0gImluY29tZSIgPyAibGUgcmV2ZW51IiA6ICJsYSBkw6lwZW5zZSJ9IGRlICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRhcmdldC5hbW91bnQpfWAgKwogICAgICAgICAgICAodGFyZ2V0LmRlc2NyaXB0aW9uID8gYCAoJHt0YXJnZXQuZGVzY3JpcHRpb259KWAgOiAiIikKICAgICAgICAgIDogImxhIHRyYW5zYWN0aW9uIGNvcnJlc3BvbmRhbnRlIjsKICAgICAgICBjb25zdCBjaGFuZ2VzID0gW107CiAgICAgICAgaWYgKHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X3R5cGUpIHsKICAgICAgICAgIGNoYW5nZXMucHVzaChgdHlwZSA6ICR7cGFyc2VkLnJlcXVlc3RlZF9uZXdfdHlwZSA9PT0gImluY29tZSIgPyAicmV2ZW51IiA6ICJkw6lwZW5zZSJ9YCk7CiAgICAgICAgfQogICAgICAgIGlmIChwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeSkgewogICAgICAgICAgY2hhbmdlcy5wdXNoKGBjYXTDqWdvcmllIDogJHthbGxDYXRlZ29yeUxhYmVsc1twYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeV0gfHwgcGFyc2VkLnJlcXVlc3RlZF9uZXdfY2F0ZWdvcnl9YCk7CiAgICAgICAgfQogICAgICAgIHF1ZXN0aW9uID0gYE1vZGlmaWVyICR7dGFyZ2V0TGFiZWx9IOKAlCAke2NoYW5nZXMuam9pbigiLCAiKSB8fCAiYXVjdW4gY2hhbmdlbWVudCByZWNvbm51In0g4oCUIGMnZXN0IGJpZW4gw6dhID9gOwogICAgICB9CgogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICB0ZXh0LnRleHRDb250ZW50ID0gcXVlc3Rpb247CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmFwcGVuZENoaWxkKHRleHQpOwoKICAgICAgY29uc3QgY29udHJvbHMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgY29udHJvbHMuY2xhc3NOYW1lID0gInZvaWNlLWNvbmZpcm0tY29udHJvbHMiOwoKICAgICAgY29uc3QgY29uZmlybUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBjb25maXJtQnRuLnRleHRDb250ZW50ID0gIuKchSBDb25maXJtZXIiOwogICAgICBjb25maXJtQnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgIGNvbmZpcm1CdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbigiY29uZmlybSIpKTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoY29uZmlybUJ0bik7CgogICAgICBjb25zdCBjYW5jZWxCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgY2FuY2VsQnRuLnRleHRDb250ZW50ID0gIuKdjCBBbm51bGVyIjsKICAgICAgY2FuY2VsQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgY2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3VibWl0Vm9pY2VDb25maXJtRGVjaXNpb24oImNhbmNlbCIpKTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoY2FuY2VsQnRuKTsKCiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKCiAgICAgIGNvbnN0IGhpbnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIGhpbnQuY2xhc3NOYW1lID0gInZvaWNlLWNvbmZpcm0taGludCI7CiAgICAgIGhpbnQudGV4dENvbnRlbnQgPSAi8J+OpCBUdSBwZXV4IGF1c3NpIHLDqXBvbmRyZSDDoCBsYSB2b2l4IGVuIHLDqS1hcHB1eWFudCBzdXIgbGUgbWljcm8uIjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQoaGludCk7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc3VibWl0Vm9pY2VDb25maXJtRGVjaXNpb24oZGVjaXNpb24pIHsKICAgICAgaWYgKCFwZW5kaW5nVm9pY2VBY3Rpb24pIHJldHVybjsKICAgICAgY29uc3QgeyBraW5kLCBkYXRhIH0gPSBwZW5kaW5nVm9pY2VBY3Rpb247CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdm9pY2UvY29uZmlybSIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBkZWNpc2lvbiwga2luZCwgcGVuZGluZzogZGF0YSB9KSwKICAgICAgICB9KTsKICAgICAgICBhd2FpdCBoYW5kbGVWb2ljZUNvbmZpcm1SZXN1bHQocmVzdWx0KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gaGFuZGxlVm9pY2VDb25maXJtUmVzdWx0KHJlc3VsdCkgewogICAgICBoaWRlVm9pY2VDb25maXJtQmFubmVyKCk7CiAgICAgIGlmIChyZXN1bHQuZGVjaXNpb24gPT09ICJjYW5jZWwiKSB7CiAgICAgICAgc2hvd1RvYXN0KCJBbm51bMOpIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIC8vIFNpbm9uLCByZXN1bHQgZXN0IHVuIHLDqXN1bHRhdCBkw6lqw6AgZmluYWxpc8OpIChWb2ljZVBhcnNlUmVzdWx0IHBvdXIKICAgICAgLy8gdW5lIHRyYW5zYWN0aW9uLCBWb2ljZUVkaXRSZXN1bHQgcG91ciB1biBlZGl0X2xhc3QpIDogb24gbGUgdHJhaXRlCiAgICAgIC8vIGV4YWN0ZW1lbnQgY29tbWUgdW4gcsOpc3VsdGF0IGRlIGRpY3TDqWUgbm9ybWFsLgogICAgICBhd2FpdCBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHJlc3VsdCk7CiAgICB9CgogICAgLy8gUG9pbnQgZCdlbnRyw6llIGNvbW11biBwb3VyIGxlIHLDqXN1bHRhdCBkJ3VuZSBkaWN0w6llICJmcmHDrmNoZSIgKGVudm95w6llCiAgICAvLyDDoCAvYXBpL3ZvaWNlL3BhcnNlKSBFVCBwb3VyIGxlIHLDqXN1bHRhdCBkw6lqw6AgZmluYWxpc8OpIGQndW5lCiAgICAvLyBjb25maXJtYXRpb24g4oCUIGxlcyBkZXV4IGNoZW1pbnMgcmV0b21iZW50IHN1ciBsZSBtw6ptZSB0cmFpdGVtZW50IHVuZQogICAgLy8gZm9pcyBxdSdvbiBzYWl0IHF1J2lsIG4neSBhIHBsdXMgZGUgZG91dGUgw6AgbGV2ZXIuCiAgICBhc3luYyBmdW5jdGlvbiBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHBhcnNlZCkgewogICAgICBpZiAocGFyc2VkLmludGVudCA9PT0gInF1ZXN0aW9uIikgewogICAgICAgIHNldFZvaWNlQW5zd2VyQmFubmVyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgIHNwZWFrVm9pY2VBbnN3ZXIocGFyc2VkLmFuc3dlcik7CiAgICAgIH0gZWxzZSBpZiAocGFyc2VkLmludGVudCA9PT0gImVkaXRfbGFzdCIpIHsKICAgICAgICBpZiAocGFyc2VkLnBlbmRpbmcpIHsKICAgICAgICAgIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoImVkaXRfbGFzdCIsIHBhcnNlZCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQW5zd2VyQmFubmVyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgc3BlYWtWb2ljZUFuc3dlcihwYXJzZWQuYW5zd2VyKTsKICAgICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICB9CiAgICAgIH0gZWxzZSBpZiAocGFyc2VkLm5lZWRzX2NvbmZpcm1hdGlvbikgewogICAgICAgIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoInRyYW5zYWN0aW9uIiwgcGFyc2VkKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBhd2FpdCBhcHBseVZvaWNlUmVzdWx0KHBhcnNlZCk7CiAgICAgIH0KICAgIH0KCiAgICBjb25zdCBTcGVlY2hSZWNvZ25pdGlvbkN0b3IgPSB3aW5kb3cuU3BlZWNoUmVjb2duaXRpb24gfHwgd2luZG93LndlYmtpdFNwZWVjaFJlY29nbml0aW9uOwoKICAgIGlmICghU3BlZWNoUmVjb2duaXRpb25DdG9yKSB7CiAgICAgIG1pY0J0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIG1pY0J0bi50aXRsZSA9ICJEaWN0w6llIHZvY2FsZSBub24gZGlzcG9uaWJsZSBzdXIgY2UgbmF2aWdhdGV1ciAodXRpbGlzZSBDaHJvbWUgb3UgRWRnZSkiOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgcmVjb2duaXRpb24gPSBuZXcgU3BlZWNoUmVjb2duaXRpb25DdG9yKCk7CiAgICAgIHJlY29nbml0aW9uLmxhbmcgPSAiZnItRlIiOwogICAgICByZWNvZ25pdGlvbi5jb250aW51b3VzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLmludGVyaW1SZXN1bHRzID0gZmFsc2U7CiAgICAgIHJlY29nbml0aW9uLm1heEFsdGVybmF0aXZlcyA9IDE7CgogICAgICBsZXQgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoInN0YXJ0IiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gdHJ1ZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgibGlzdGVuaW5nIik7CiAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIkplIHQnw6ljb3V0ZeKApiIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVuZCIsICgpID0+IHsKICAgICAgICBpc0xpc3RlbmluZyA9IGZhbHNlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJsaXN0ZW5pbmciKTsKICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJlcnJvciIsIChldmVudCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgaWYgKGV2ZW50LmVycm9yID09PSAibm8tc3BlZWNoIikgewogICAgICAgICAgc2V0Vm9pY2VCYW5uZXIoIlJpZW4gZW50ZW5kdSwgcsOpZXNzYWllLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgMjAwMCk7CiAgICAgICAgfSBlbHNlIGlmIChldmVudC5lcnJvciA9PT0gIm5vdC1hbGxvd2VkIiB8fCBldmVudC5lcnJvciA9PT0gInNlcnZpY2Utbm90LWFsbG93ZWQiKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiTWljcm8gcmVmdXPDqSDigJQgYXV0b3Jpc2UgbCdhY2PDqHMgYXUgbWljcm8gZGFucyB0b24gbmF2aWdhdGV1ci4iKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIDQwMDApOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcihudWxsKTsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIG1pY3JvIDogIiArIGV2ZW50LmVycm9yLCB0cnVlKTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigicmVzdWx0IiwgYXN5bmMgKGV2ZW50KSA9PiB7CiAgICAgICAgY29uc3QgdHJhbnNjcmlwdCA9IGV2ZW50LnJlc3VsdHNbMF1bMF0udHJhbnNjcmlwdDsKICAgICAgICBzZXRWb2ljZUJhbm5lcihgIiR7dHJhbnNjcmlwdH0iYCk7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5hZGQoInByb2Nlc3NpbmciKTsKICAgICAgICBsZXQgYmFubmVyRGVsYXkgPSAxNTAwOwogICAgICAgIHRyeSB7CiAgICAgICAgICBpZiAocGVuZGluZ1ZvaWNlQWN0aW9uKSB7CiAgICAgICAgICAgIC8vIFVuZSBiYW5uacOocmUgZGUgY29uZmlybWF0aW9uIGVzdCBhZmZpY2jDqWUgOiBjZXR0ZSBkaWN0w6llIGVzdAogICAgICAgICAgICAvLyB1bmUgcsOpcG9uc2UgKCJvdWkiLCAibm9uIiwgImNoYW5nZSDDp2EgZW4uLi4iKSDDoCBDRVRURQogICAgICAgICAgICAvLyBjb25maXJtYXRpb24sIHBhcyB1bmUgbm91dmVsbGUgdHJhbnNhY3Rpb24uCiAgICAgICAgICAgIGNvbnN0IHsga2luZCwgZGF0YSB9ID0gcGVuZGluZ1ZvaWNlQWN0aW9uOwogICAgICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9jb25maXJtIiwgewogICAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgcmVwbHlfdGV4dDogdHJhbnNjcmlwdCwga2luZCwgcGVuZGluZzogZGF0YSB9KSwKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlQ29uZmlybVJlc3VsdChyZXN1bHQpOwogICAgICAgICAgICBiYW5uZXJEZWxheSA9IDQwMDA7CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICBjb25zdCBwYXJzZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9wYXJzZSIsIHsKICAgICAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRleHQ6IHRyYW5zY3JpcHQgfSksCiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBpZiAocGFyc2VkLmludGVudCA9PT0gInF1ZXN0aW9uIikgewogICAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNjAwMDsKICAgICAgICAgICAgfSBlbHNlIGlmIChwYXJzZWQubmVlZHNfY29uZmlybWF0aW9uIHx8IHBhcnNlZC5wZW5kaW5nKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSAxNTAwOyAvLyBsYSBiYW5uacOocmUgZGUgY29uZmlybWF0aW9uIHByZW5kIGxlIHJlbGFpcyB2aXN1ZWxsZW1lbnQKICAgICAgICAgICAgfSBlbHNlIGlmIChwYXJzZWQuaW50ZW50ID09PSAiZWRpdF9sYXN0IikgewogICAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNDAwMDsKICAgICAgICAgICAgfQogICAgICAgICAgICBhd2FpdCBoYW5kbGVWb2ljZVBhcnNlUmVzdWx0KHBhcnNlZCk7CiAgICAgICAgICB9CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfSBmaW5hbGx5IHsKICAgICAgICAgIG1pY0J0bi5jbGFzc0xpc3QucmVtb3ZlKCJwcm9jZXNzaW5nIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCBiYW5uZXJEZWxheSk7CiAgICAgICAgfQogICAgICB9KTsKCiAgICAgIG1pY0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBpZiAoaXNMaXN0ZW5pbmcpIHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0b3AoKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgdHJ5IHsKICAgICAgICAgIHJlY29nbml0aW9uLnN0YXJ0KCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICAvLyBzdGFydCgpIGpldHRlIHNpIGTDqWrDoCBkw6ltYXJyw6kgOyBvbiBpZ25vcmUuCiAgICAgICAgfQogICAgICB9KTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBTdWdnZXN0aW9ucyBkZSBjYXTDqWdvcmllIOKAlCB1bmlxdWVtZW50IGFwcsOocyB1bmUgc2Fpc2llIHBhciBkaWN0w6llCiAgICAvLyB2b2NhbGUgKHVuZSBmYXV0ZSBkZSBmcmFwcGUgZW4gc2Fpc2llIG1hbnVlbGxlLCBjJ2VzdCB1bmUgZXJyZXVyIGRlCiAgICAvLyBsJ3V0aWxpc2F0ZXVyLCBwYXMgbGEgcGVpbmUgZGUgbGUgcmVsYW5jZXIgZGVzc3VzKS4KICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEID0gMzsKCiAgICAvLyBNb3RzIGRlIGxpYWlzb24gZnJhbsOnYWlzIMOgIGlnbm9yZXIgOiAiY2FzaW5vIiwgImF1IGNhc2lubyIgZXQgInBlcnRlIGF1CiAgICAvLyBjYXNpbm8iIGRvaXZlbnQgw6p0cmUgcmVjb25udXMgY29tbWUgbGEgbcOqbWUgaWTDqWUgbWFsZ3LDqSBsZXMgbW90cwogICAgLy8gZGlmZsOpcmVudHMgYXV0b3VyLCBkb25jIG9uIGNvbXBhcmUgZGVzIG1vdHMtY2zDqXMgc2lnbmlmaWNhdGlmcyBwbHV0w7R0CiAgICAvLyBxdWUgbGEgZGVzY3JpcHRpb24gY29tcGzDqHRlIHRlbGxlIHF1ZWxsZS4KICAgIGNvbnN0IERFU0NSSVBUSU9OX1NUT1BXT1JEUyA9IG5ldyBTZXQoWwogICAgICAiYSIsICJhdSIsICJhdXgiLCAiZGUiLCAiZHUiLCAiZGVzIiwgImQiLCAibGUiLCAibGEiLCAibGVzIiwgImwiLAogICAgICAidW4iLCAidW5lIiwgImNlIiwgImNldCIsICJjZXR0ZSIsICJjZXMiLCAibW9uIiwgIm1hIiwgIm1lcyIsCiAgICAgICJ0b24iLCAidGEiLCAidGVzIiwgInNvbiIsICJzYSIsICJzZXMiLCAibm90cmUiLCAibm9zIiwgInZvdHJlIiwKICAgICAgInZvcyIsICJsZXVyIiwgImxldXJzIiwgImNoZXoiLCAic3VyIiwgImRhbnMiLCAicG91ciIsICJhdmVjIiwKICAgICAgImV0IiwgIm91IiwgImVuIiwgInBhciIsCiAgICBdKTsKCiAgICAvLyBFeHRyYWl0IGxlcyBtb3RzLWNsw6lzIHNpZ25pZmljYXRpZnMgZCd1bmUgZGVzY3JpcHRpb24gKGFjY2VudHMgZXQKICAgIC8vIGNhc3NlIGlnbm9yw6lzLCBtb3RzIGRlIGxpYWlzb24gZXQgbW90cyB0cm9wIGNvdXJ0cyDDqWNhcnTDqXMpLgogICAgZnVuY3Rpb24gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMoZGVzYykgewogICAgICBjb25zdCBub3JtYWxpemVkID0gKGRlc2MgfHwgIiIpCiAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikKICAgICAgICAucmVwbGFjZSgvW8yALc2vXS9nLCAiIikgLy8gcmV0aXJlIGxlcyBhY2NlbnRzICjDqSAtPiBlLCBldGMuKQogICAgICAgIC50b0xvd2VyQ2FzZSgpOwogICAgICBjb25zdCB0b2tlbnMgPSBub3JtYWxpemVkLnNwbGl0KC9bXmEtejAtOV0rLykuZmlsdGVyKEJvb2xlYW4pOwogICAgICByZXR1cm4gbmV3IFNldCgKICAgICAgICB0b2tlbnMuZmlsdGVyKCh0KSA9PiB0Lmxlbmd0aCA+PSAzICYmICFERVNDUklQVElPTl9TVE9QV09SRFMuaGFzKHQpKQogICAgICApOwogICAgfQoKICAgIGZ1bmN0aW9uIGtleXdvcmRzSW50ZXJzZWN0KGEsIGIpIHsKICAgICAgZm9yIChjb25zdCB0b2tlbiBvZiBhKSB7CiAgICAgICAgaWYgKGIuaGFzKHRva2VuKSkgcmV0dXJuIHRydWU7CiAgICAgIH0KICAgICAgcmV0dXJuIGZhbHNlOwogICAgfQoKICAgIC8vIFJldGlyZSBkJ3VuZSBkZXNjcmlwdGlvbiBsZXMgbW90cyBxdWkgb250IHNlcnZpIMOgIGTDqXRlY3RlciBsYQogICAgLy8gY2F0w6lnb3JpZSAoZXguICJjYXNpbm8iIHVuZSBmb2lzIHF1ZSBsYSBjYXTDqWdvcmllICJjYXNpbm8iIGV4aXN0ZSkgOgogICAgLy8gdW5lIGZvaXMgcXVlIGxhIGNhdMOpZ29yaWUgcG9ydGUgbCdpbmZvcm1hdGlvbiwgbGEgcsOpcMOpdGVyIGRhbnMgbGEKICAgIC8vIGRlc2NyaXB0aW9uIG4nYXBwb3J0ZSBwbHVzIHJpZW4uIFJlbnZvaWUgbnVsbCBzaSBsYSBkZXNjcmlwdGlvbgogICAgLy8gZGV2aWVudCB2aWRlIHVuZSBmb2lzIGNlcyBtb3RzIHJldGlyw6lzLgogICAgZnVuY3Rpb24gc3RyaXBNYXRjaGVkS2V5d29yZHNGcm9tRGVzY3JpcHRpb24oZGVzY3JpcHRpb24sIGtleXdvcmRzKSB7CiAgICAgIGlmICghZGVzY3JpcHRpb24gfHwgIWtleXdvcmRzIHx8IGtleXdvcmRzLnNpemUgPT09IDApIHJldHVybiBkZXNjcmlwdGlvbiB8fCBudWxsOwogICAgICBjb25zdCB3b3JkcyA9IGRlc2NyaXB0aW9uLnNwbGl0KC9ccysvKS5maWx0ZXIoQm9vbGVhbik7CiAgICAgIGNvbnN0IGtlcHQgPSB3b3Jkcy5maWx0ZXIoKHcpID0+IHsKICAgICAgICBjb25zdCBub3JtID0gdwogICAgICAgICAgLm5vcm1hbGl6ZSgiTkZEIikKICAgICAgICAgIC5yZXBsYWNlKC9bzIAtza9dL2csICIiKQogICAgICAgICAgLnRvTG93ZXJDYXNlKCkKICAgICAgICAgIC5yZXBsYWNlKC9bXmEtejAtOV0vZywgIiIpOwogICAgICAgIHJldHVybiAha2V5d29yZHMuaGFzKG5vcm0pOwogICAgICB9KTsKICAgICAgY29uc3QgY2xlYW5lZCA9IGtlcHQuam9pbigiICIpLnRyaW0oKTsKICAgICAgcmV0dXJuIGNsZWFuZWQgfHwgbnVsbDsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBkaXNtaXNzU3VnZ2VzdGlvbihrZXkpIHsKICAgICAgZGlzbWlzc2VkU3VnZ2VzdGlvbktleXMuYWRkKGtleSk7IC8vIGltbcOpZGlhdCBjw7R0w6kgVUksIHBhcyBiZXNvaW4gZCdhdHRlbmRyZSBsZSBzZXJ2ZXVyCiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvZGlzbWlzc2VkLXN1Z2dlc3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGtleSB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSBsYSBzdWdnZXN0aW9uIHLDqWFwcGFyYcOudCB1bmUgZm9pcyBzdXIgdW4KICAgICAgICAvLyBhdXRyZSBhcHBhcmVpbCBzaSBsYSBzYXV2ZWdhcmRlIHNlcnZldXIgYSDDqWNob3XDqS4KICAgICAgfQogICAgfQoKICAgIC8vIFJlZ2FyZGUgc2kgbGEgZGVzY3JpcHRpb24gZGUgbGEgdHJhbnNhY3Rpb24gcXVpIHZpZW50IGQnw6p0cmUgYWpvdXTDqWUKICAgIC8vIChvdSBjb3JyaWfDqWUpIMOgIGxhIHZvaXggcmV2aWVudCBzb3V2ZW50LCBldCBzaSBvdWkgOgogICAgLy8gLSBzb2l0IGVsbGUgYSB0b3Vqb3VycyDDqXTDqSByYW5nw6llIGRhbnMgIkF1dHJlIiDihpIgb24gcHJvcG9zZSBkZSBjcsOpZXIKICAgIC8vICAgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGRlIGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpIDsKICAgIC8vIC0gc29pdCBlbGxlIGEgY2V0dGUgZm9pcyB1bmUgY2F0w6lnb3JpZSBkaWZmw6lyZW50ZSBkZSBkJ2hhYml0dWRlIOKGkiBvbgogICAgLy8gICBkZW1hbmRlIHNpIGNlIG4nZXN0IHBhcyB1bmUgZXJyZXVyIDsKICAgIC8vIC0gc29pdCBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZSBlc3QgZMOpasOgIGJpZW4gY2xhc3PDqWUsCiAgICAvLyAgIG1haXMgZCdhbmNpZW5uZXMgdHJhbnNhY3Rpb25zIHNpbWlsYWlyZXMgdHJhw65uZW50IGRhbnMgdW5lIGF1dHJlCiAgICAvLyAgIGNhdMOpZ29yaWUgKGV4LiAicGVydGUgYXUgY2FzaW5vIiBjbGFzc8OpZSBlbiAiTG9pc2lycyIgYXZhbnQgcXVlCiAgICAvLyAgICJjYXNpbm8iIGV4aXN0ZSBjb21tZSBjYXTDqWdvcmllKSDihpIgb24gcHJvcG9zZSBkZSBsZXMgYWxpZ25lci4KICAgIGZ1bmN0aW9uIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKGRlc2NyaXB0aW9uLCB0eXBlKSB7CiAgICAgIGNvbnN0IGtleXdvcmRzID0gZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHMoZGVzY3JpcHRpb24pOwogICAgICBpZiAoa2V5d29yZHMuc2l6ZSA9PT0gMCkgcmV0dXJuOwoKICAgICAgY29uc3Qgc2FtZURlc2NyaXB0aW9uID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigKICAgICAgICAodHgpID0+CiAgICAgICAgICB0eC50eXBlID09PSB0eXBlICYmCiAgICAgICAgICBrZXl3b3Jkc0ludGVyc2VjdChrZXl3b3JkcywgZXh0cmFjdERlc2NyaXB0aW9uS2V5d29yZHModHguZGVzY3JpcHRpb24pKQogICAgICApOwogICAgICBpZiAoc2FtZURlc2NyaXB0aW9uLmxlbmd0aCA8IENBVEVHT1JZX1NVR0dFU1RJT05fVEhSRVNIT0xEKSByZXR1cm47CgogICAgICBjb25zdCBjb3VudHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiBzYW1lRGVzY3JpcHRpb24pIGNvdW50c1t0eC5jYXRlZ29yeV0gPSAoY291bnRzW3R4LmNhdGVnb3J5XSB8fCAwKSArIDE7CiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBPYmplY3Qua2V5cyhjb3VudHMpOwogICAgICBjb25zdCBkb21pbmFudCA9IGNhdGVnb3JpZXMucmVkdWNlKChhLCBiKSA9PiAoY291bnRzW2FdID49IGNvdW50c1tiXSA/IGEgOiBiKSk7CiAgICAgIGNvbnN0IGxhdGVzdCA9IHNhbWVEZXNjcmlwdGlvblswXTsgLy8gYWxsVHJhbnNhY3Rpb25zIGVzdCB0cmnDqSBwYXIgZGF0ZSBkw6ljcm9pc3NhbnRlCgogICAgICAvLyBDbMOpIHN0YWJsZSBiYXPDqWUgc3VyIGxlcyBtb3RzLWNsw6lzICh0cmnDqXMpIHBsdXTDtHQgcXVlIGxhIGRlc2NyaXB0aW9uCiAgICAgIC8vIGV4YWN0ZSwgcG91ciBxdWUgbGUgIklnbm9yZXIiIHJlc3RlIHZhbGFibGUgbcOqbWUgc2kgbGEgZm9ybXVsYXRpb24KICAgICAgLy8gdmFyaWUgdW4gcGV1IGQndW5lIGZvaXMgw6AgbCdhdXRyZS4KICAgICAgY29uc3Qgc2lnbmF0dXJlID0gWy4uLmtleXdvcmRzXS5zb3J0KCkuam9pbigiKyIpOwoKICAgICAgbGV0IHN1Z2dlc3Rpb24gPSBudWxsOwogICAgICBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgbWlzbWF0Y2g6JHt0eXBlfToke3NpZ25hdHVyZX06JHtsYXRlc3QuY2F0ZWdvcnl9YCwKICAgICAgICAgIGtpbmQ6ICJtaXNtYXRjaCIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIGRvbWluYW50LAogICAgICAgICAgY3VycmVudDogbGF0ZXN0LmNhdGVnb3J5LAogICAgICAgICAga2V5d29yZHMsCiAgICAgICAgICB0eElkczogc2FtZURlc2NyaXB0aW9uLmZpbHRlcigodHgpID0+IHR4LmNhdGVnb3J5ID09PSBsYXRlc3QuY2F0ZWdvcnkpLm1hcCgodHgpID0+IHR4LmlkKSwKICAgICAgICB9OwogICAgICB9IGVsc2UgaWYgKGNhdGVnb3JpZXMubGVuZ3RoID09PSAxICYmIGRvbWluYW50ID09PSAiYXV0cmUiKSB7CiAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgIGtleTogYGdlbmVyaWM6JHt0eXBlfToke3NpZ25hdHVyZX1gLAogICAgICAgICAga2luZDogImdlbmVyaWMiLAogICAgICAgICAgZGVzY3JpcHRpb246IGxhdGVzdC5kZXNjcmlwdGlvbiwKICAgICAgICAgIHR5cGUsCiAgICAgICAgICBrZXl3b3JkcywKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24ubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPiAxICYmIGxhdGVzdC5jYXRlZ29yeSA9PT0gZG9taW5hbnQpIHsKICAgICAgICAvLyBMYSB0cmFuc2FjdGlvbiBsYSBwbHVzIHLDqWNlbnRlIGVzdCBkw6lqw6AgYmllbiBjbGFzc8OpZSwgbWFpcwogICAgICAgIC8vIGQnYXV0cmVzIHRyYW5zYWN0aW9ucyBzaW1pbGFpcmVzIHNvbnQgcmVzdMOpZXMgZGFucyB1bmUgY2F0w6lnb3JpZQogICAgICAgIC8vIG1pbm9yaXRhaXJlICh0eXBpcXVlbWVudCBwbHVzIGFuY2llbm5lcywgY2xhc3PDqWVzIGF2YW50IHF1ZSBsYQogICAgICAgIC8vIGNhdMOpZ29yaWUgZG9taW5hbnRlIGFjdHVlbGxlIG4nZXhpc3RlKSA6IG9uIHByb3Bvc2UgZGUgbGVzIGFsaWduZXIuCiAgICAgICAgY29uc3Qgb3V0bGllcnMgPSBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgIT09IGRvbWluYW50KTsKICAgICAgICBpZiAob3V0bGllcnMubGVuZ3RoID4gMCkgewogICAgICAgICAgY29uc3Qgb3V0bGllckNhdGVnb3JpZXMgPSBbLi4ubmV3IFNldChvdXRsaWVycy5tYXAoKHR4KSA9PiB0eC5jYXRlZ29yeSkpXTsKICAgICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICAgIGtleTogYHJlY29uY2lsZToke3R5cGV9OiR7c2lnbmF0dXJlfToke2RvbWluYW50fWAsCiAgICAgICAgICAgIGtpbmQ6ICJyZWNvbmNpbGUiLAogICAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgICB0eXBlLAogICAgICAgICAgICBkb21pbmFudCwKICAgICAgICAgICAgb3V0bGllckNhdGVnb3JpZXMsCiAgICAgICAgICAgIGtleXdvcmRzLAogICAgICAgICAgICB0eElkczogb3V0bGllcnMubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgICAgfTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGlmICghc3VnZ2VzdGlvbiB8fCBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5oYXMoc3VnZ2VzdGlvbi5rZXkpKSByZXR1cm47CiAgICAgIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbik7CiAgICB9CgogICAgZnVuY3Rpb24gaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCkgewogICAgICBsZXQgaWRzVG9GaXg7CiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJyZWNvbmNpbGUiKSB7CiAgICAgICAgLy8gSWNpIHN1Z2dlc3Rpb24udHhJZHMgZXN0IGTDqWrDoCBleGFjdGVtZW50IGwnZW5zZW1ibGUgZGVzIGFuY2llbm5lcwogICAgICAgIC8vIHRyYW5zYWN0aW9ucyDDoCBhbGlnbmVyIChwYXMgZGUgImRlcm5pw6hyZSB0cmFuc2FjdGlvbiIgw6AgcGFydCkgOiBsZQogICAgICAgIC8vIHRleHRlIGRlIGxhIGJhbm5pw6hyZSBsJ2Fubm9uY2UgZMOpasOgLCBwYXMgYmVzb2luIGQndW5lIGNvbmZpcm1hdGlvbgogICAgICAgIC8vIHN1cHBsw6ltZW50YWlyZS4KICAgICAgICBpZHNUb0ZpeCA9IHN1Z2dlc3Rpb24udHhJZHM7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgW2xhdGVzdElkLCAuLi5vdGhlcnNdID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgICBpZHNUb0ZpeCA9IFtsYXRlc3RJZF07CiAgICAgICAgaWYgKAogICAgICAgICAgb3RoZXJzLmxlbmd0aCA+IDAgJiYKICAgICAgICAgIChhd2FpdCBzaG93Q29uZmlybShgQ29ycmlnZXIgYXVzc2kgbGVzICR7b3RoZXJzLmxlbmd0aH0gdHJhbnNhY3Rpb24ocykgcHLDqWPDqWRlbnRlKHMpIGF2ZWMgbGEgbcOqbWUgZGVzY3JpcHRpb24gP2ApKQogICAgICAgICkgewogICAgICAgICAgaWRzVG9GaXgucHVzaCguLi5vdGhlcnMpOwogICAgICAgIH0KICAgICAgfQoKICAgICAgdHJ5IHsKICAgICAgICBmb3IgKGNvbnN0IGlkIG9mIGlkc1RvRml4KSB7CiAgICAgICAgICBjb25zdCBwYXlsb2FkID0geyBjYXRlZ29yeTogdGFyZ2V0VmFsdWUgfTsKICAgICAgICAgIC8vIExhIGNhdMOpZ29yaWUgcG9ydGUgbWFpbnRlbmFudCBsJ2luZm9ybWF0aW9uIDogb24gcmV0aXJlIGRlcwogICAgICAgICAgLy8gZGVzY3JpcHRpb25zIGxlKHMpIG1vdChzKS1jbMOpKHMpIHF1aSBvbnQgc2Vydmkgw6AgbGEgZMOpdGVjdGVyLAogICAgICAgICAgLy8gcG91ciDDqXZpdGVyIGxhIHJlZG9uZGFuY2UgImNhc2lubyIgZW4gY2F0w6lnb3JpZSBFVCBlbiBub3RlLgogICAgICAgICAgY29uc3QgdHggPSBhbGxUcmFuc2FjdGlvbnMuZmluZCgodCkgPT4gdC5pZCA9PT0gaWQpOwogICAgICAgICAgaWYgKHR4ICYmIHN1Z2dlc3Rpb24ua2V5d29yZHMpIHsKICAgICAgICAgICAgY29uc3QgY2xlYW5lZCA9IHN0cmlwTWF0Y2hlZEtleXdvcmRzRnJvbURlc2NyaXB0aW9uKHR4LmRlc2NyaXB0aW9uLCBzdWdnZXN0aW9uLmtleXdvcmRzKTsKICAgICAgICAgICAgaWYgKGNsZWFuZWQgIT09ICh0eC5kZXNjcmlwdGlvbiB8fCBudWxsKSkgcGF5bG9hZC5kZXNjcmlwdGlvbiA9IGNsZWFuZWQ7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIHNob3dUb2FzdChgQ2F0w6lnb3JpZSBtaXNlIMOgIGpvdXIgOiAke3RhcmdldExhYmVsfWApOwogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzaG93Q2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKHN1Z2dlc3Rpb24pIHsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2F0ZWdvcnktc3VnZ2VzdGlvbi1iYW5uZXIiKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwoKICAgICAgY29uc3QgZGVzY0xhYmVsID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiKHNhbnMgZGVzY3JpcHRpb24pIjsKICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gImdlbmVyaWMiKSB7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgVHUgYXMgdXRpbGlzw6kgIiR7ZGVzY0xhYmVsfSIgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gZm9pcywgdG91am91cnMgY2xhc3PDqSBlbiBgICsKICAgICAgICAgIGAiQXV0cmUiLiBDcsOpZXIgdW5lIGNhdMOpZ29yaWUgZMOpZGnDqWUgKG91IGxhIHJhdHRhY2hlciDDoCB1bmUgY2F0w6lnb3JpZSBleGlzdGFudGUpID9gOwogICAgICB9IGVsc2UgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gInJlY29uY2lsZSIpIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBvdXRsaWVyTGFiZWxzID0gc3VnZ2VzdGlvbi5vdXRsaWVyQ2F0ZWdvcmllcwogICAgICAgICAgLm1hcCgoYykgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY10gfHwgYykKICAgICAgICAgIC5qb2luKCIsICIpOwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCR7c3VnZ2VzdGlvbi50eElkcy5sZW5ndGh9IHRyYW5zYWN0aW9uKHMpIHNpbWlsYWlyZShzKSDDoCAiJHtkZXNjTGFiZWx9IiBzb250IGNsYXNzw6llcyBlbiBgICsKICAgICAgICAgIGAiJHtvdXRsaWVyTGFiZWxzfSIsIGFsb3JzIHF1ZSAiJHtkb21pbmFudExhYmVsfSIgZXN0IG1haW50ZW5hbnQgbGEgY2F0w6lnb3JpZSBoYWJpdHVlbGxlLiBgICsKICAgICAgICAgIGBMZXMgYWxpZ25lciBzdXIgIiR7ZG9taW5hbnRMYWJlbH0iID9gOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGN1cnJlbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uY3VycmVudF0gfHwgc3VnZ2VzdGlvbi5jdXJyZW50OwogICAgICAgIHRleHQudGV4dENvbnRlbnQgPQogICAgICAgICAgYCIke2Rlc2NMYWJlbH0iIGVzdCBoYWJpdHVlbGxlbWVudCBjbGFzc8OpIGVuICIke2RvbWluYW50TGFiZWx9IiwgbWFpcyBjZXR0ZSBmb2lzIGAgKwogICAgICAgICAgYGMnZXN0ICIke2N1cnJlbnRMYWJlbH0iLiBQYXMgZCdlcnJldXIgb3UgdW4gb3VibGkgP2A7CiAgICAgIH0KICAgICAgZWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAiY2F0ZWdvcnktc3VnZ2VzdGlvbi1jb250cm9scyI7CgogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzZWxlY3QiKTsKICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbc3VnZ2VzdGlvbi50eXBlXSkgewogICAgICAgICAgaWYgKHZhbHVlID09PSAiYXV0cmUiKSBjb250aW51ZTsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjb25zdCBuZXdPcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBuZXdPcHQudmFsdWUgPSAiX19uZXdfXyI7CiAgICAgICAgbmV3T3B0LnRleHRDb250ZW50ID0gIisgTm91dmVsbGUgY2F0w6lnb3JpZeKApiI7CiAgICAgICAgbmV3T3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQobmV3T3B0KTsKCiAgICAgICAgY29uc3QgbmV3TmFtZUlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBuZXdOYW1lSW5wdXQudHlwZSA9ICJ0ZXh0IjsKICAgICAgICBuZXdOYW1lSW5wdXQucGxhY2Vob2xkZXIgPSAiTm9tIGRlIGxhIG5vdXZlbGxlIGNhdMOpZ29yaWUiOwogICAgICAgIG5ld05hbWVJbnB1dC52YWx1ZSA9IHN1Z2dlc3Rpb24uZGVzY3JpcHRpb24gfHwgIiI7CgogICAgICAgIHNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICBuZXdOYW1lSW5wdXQuc3R5bGUuZGlzcGxheSA9IHNlbGVjdC52YWx1ZSA9PT0gIl9fbmV3X18iID8gImlubGluZS1ibG9jayIgOiAibm9uZSI7CiAgICAgICAgfSk7CgogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKHNlbGVjdCk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQobmV3TmFtZUlucHV0KTsKCiAgICAgICAgY29uc3QgYXBwbHlCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBhcHBseUJ0bi50ZXh0Q29udGVudCA9ICJBcHBsaXF1ZXIiOwogICAgICAgIGFwcGx5QnRuLmNsYXNzTmFtZSA9ICJidG4tcHJpbWFyeS1zbSI7CiAgICAgICAgYXBwbHlCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBsZXQgdGFyZ2V0VmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgICAgICBsZXQgdGFyZ2V0TGFiZWw7CiAgICAgICAgICBpZiAodGFyZ2V0VmFsdWUgPT09ICJfX25ld19fIikgewogICAgICAgICAgICBjb25zdCBuYW1lID0gbmV3TmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgICAgICAgaWYgKCFuYW1lKSB7IHNob3dUb2FzdCgiRG9ubmUgdW4gbm9tIMOgIGxhIGNhdMOpZ29yaWUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgICAgICAgIHRhcmdldFZhbHVlID0gc2x1Z2lmeUNhdGVnb3J5KG5hbWUpOwogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IG5hbWU7CiAgICAgICAgICAgIGlmICghY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdLnNvbWUoKFt2XSkgPT4gdiA9PT0gdGFyZ2V0VmFsdWUpKSB7CiAgICAgICAgICAgICAgc2F2ZUN1c3RvbUNhdGVnb3J5KHN1Z2dlc3Rpb24udHlwZSwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKTsKICAgICAgICAgICAgfQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgdGFyZ2V0TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1t0YXJnZXRWYWx1ZV0gfHwgdGFyZ2V0VmFsdWU7CiAgICAgICAgICB9CiAgICAgICAgICBhd2FpdCBhcHBseUNhdGVnb3J5U3VnZ2VzdGlvbkZpeChzdWdnZXN0aW9uLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBkb21pbmFudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5kb21pbmFudF0gfHwgc3VnZ2VzdGlvbi5kb21pbmFudDsKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gYENvcnJpZ2VyIGVuICIke2RvbWluYW50TGFiZWx9ImA7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHN1Z2dlc3Rpb24uZG9taW5hbnQsIGRvbWluYW50TGFiZWwpOwogICAgICAgIH0pOwogICAgICAgIGNvbnRyb2xzLmFwcGVuZENoaWxkKGFwcGx5QnRuKTsKICAgICAgfQoKICAgICAgY29uc3QgZGlzbWlzc0J0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBkaXNtaXNzQnRuLnRleHRDb250ZW50ID0gIklnbm9yZXIiOwogICAgICBkaXNtaXNzQnRuLmNsYXNzTmFtZSA9ICJidG4tc2Vjb25kYXJ5LXNtIjsKICAgICAgZGlzbWlzc0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgICBkaXNtaXNzU3VnZ2VzdGlvbihzdWdnZXN0aW9uLmtleSk7CiAgICAgICAgaGlkZUNhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcigpOwogICAgICB9KTsKICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoZGlzbWlzc0J0bik7CgogICAgICBlbC5hcHBlbmRDaGlsZChjb250cm9scyk7CiAgICB9CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIGNoYXJnZSByw6ljdXJyZW50ZSBjcsOpw6llIFBBUiBMQSBWT0lYIGRhbnMgY2V0dGUKICAgIC8vIHNlc3Npb24gKG3Dqm1lIHByaW5jaXBlIHF1ZSBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkLCBtYWlzIHBvdXIgdW5lCiAgICAvLyBjb3JyZWN0aW9uIHF1aSBzdWl0IGxhIGNyw6lhdGlvbiBkJ3VuZSByw6ljdXJyZW50ZSBwYXIgbGEgdm9peCkuCiAgICBsZXQgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGNvbnN0IHZlcmIgPSBwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IiA6ICJEw6lwZW5zZSI7CiAgICAgIGNvbnN0IGFtb3VudExhYmVsID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHBhcnNlZC5hbW91bnQpOwoKICAgICAgLy8gInLDqWN1cnJlbnQiLCAiYWJvbm5lbWVudCIsICJ0b3VzIGxlcyBtb2lzIi4uLiBkw6l0ZWN0w6kgcGFyIGwnSUEgOiBvbgogICAgICAvLyBjcsOpZS9jb3JyaWdlIHVuZSBjaGFyZ2UgcsOpY3VycmVudGUgYXUgbGlldSBkJ3VuZSB0cmFuc2FjdGlvbgogICAgICAvLyBwb25jdHVlbGxlLCBxdWVsIHF1ZSBzb2l0IGwnb25nbGV0IGFjdHVlbGxlbWVudCBhZmZpY2jDqSDigJQgbGUgbWljcm8KICAgICAgLy8gZXN0IGdsb2JhbCwgcGFzIGxpw6kgw6AgbCdvbmdsZXQgUsOpY3VycmVudGVzLgogICAgICBpZiAocGFyc2VkLmlzX3JlY3VycmluZykgewogICAgICAgIGNvbnN0IHJlY1BheWxvYWQgPSB7CiAgICAgICAgICB0eXBlOiBwYXJzZWQudHlwZSwKICAgICAgICAgIG5hbWU6IHBhcnNlZC5kZXNjcmlwdGlvbiB8fCAocGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIlJldmVudSByw6ljdXJyZW50IiA6ICJEw6lwZW5zZSByw6ljdXJyZW50ZSIpLAogICAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgICAgY2F0ZWdvcnk6IHBhcnNlZC5jYXRlZ29yeSwKICAgICAgICAgIGRheV9vZl9tb250aDogTnVtYmVyKHBhcnNlZC5leHBlbnNlX2RhdGUuc2xpY2UoOCwgMTApKSwKICAgICAgICB9OwoKICAgICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2xhc3RWb2ljZVJlY3VycmluZ0lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVjUGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICAgIHNob3dUb2FzdChgQ2hhcmdlIHLDqWN1cnJlbnRlIGNvcnJpZ8OpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciLCB7CiAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgbGFzdFZvaWNlUmVjdXJyaW5nSWQgPSBjcmVhdGVkLmlkOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUgOiAke3JlY1BheWxvYWQubmFtZX0gKCR7YW1vdW50TGFiZWx9KWApOwogICAgICAgIH0KICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgIGFtb3VudDogcGFyc2VkLmFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sCiAgICAgICAgZXhwZW5zZV9kYXRlOiBwYXJzZWQuZXhwZW5zZV9kYXRlLAogICAgICB9OwoKICAgICAgaWYgKHBhcnNlZC5pc19jb3JyZWN0aW9uICYmIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQpIHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtsYXN0Vm9pY2VUcmFuc2FjdGlvbklkfWAsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYENvcnJpZ8OpIDogJHt2ZXJiLnRvTG93ZXJDYXNlKCl9IGRlICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgc2hvd1RvYXN0KGAke3ZlcmJ9IGFqb3V0w6kke3BhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICIiIDogImUifSA6ICR7YW1vdW50TGFiZWx9YCk7CiAgICAgIH0KICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICBjaGVja0NhdGVnb3J5U3VnZ2VzdGlvbihwYXJzZWQuZGVzY3JpcHRpb24sIHBhcnNlZC50eXBlKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb25maXJtYXRpb24gc3R5bMOpZSAocmVtcGxhY2Ugd2luZG93LmNvbmZpcm0sIHF1aSBhZmZpY2hlIHVuZSBwb3B1cAogICAgLy8gbmF0aXZlIGR1IG5hdmlnYXRldXIgaG9ycyBjaGFydGUgZ3JhcGhpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgY29uZmlybU92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IGNvbmZpcm1NZXNzYWdlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1tb2RhbC1tZXNzYWdlIik7CiAgICBjb25zdCBjb25maXJtT2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tb2siKTsKICAgIGNvbnN0IGNvbmZpcm1DYW5jZWxCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29uZmlybS1idG4tY2FuY2VsIik7CiAgICBsZXQgY29uZmlybVJlc29sdmUgPSBudWxsOwoKICAgIGZ1bmN0aW9uIHNob3dDb25maXJtKG1lc3NhZ2UpIHsKICAgICAgY29uZmlybU1lc3NhZ2VFbC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4gewogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gcmVzb2x2ZTsKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VDb25maXJtKHJlc3VsdCkgewogICAgICBjb25maXJtT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAoY29uZmlybVJlc29sdmUpIHsKICAgICAgICBjb25maXJtUmVzb2x2ZShyZXN1bHQpOwogICAgICAgIGNvbmZpcm1SZXNvbHZlID0gbnVsbDsKICAgICAgfQogICAgfQoKICAgIGNvbmZpcm1Pa0J0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGNsb3NlQ29uZmlybSh0cnVlKSk7CiAgICBjb25maXJtQ2FuY2VsQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKGZhbHNlKSk7CiAgICBjb25maXJtT3ZlcmxheUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSBjb25maXJtT3ZlcmxheUVsKSBjbG9zZUNvbmZpcm0oZmFsc2UpOwogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gRMOpcGVuc2VzIHLDqWN1cnJlbnRlcwogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY3VycmluZy1saXN0Iik7CiAgICBjb25zdCByZWNFbXB0eVN0YXRlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWVtcHR5LXN0YXRlIik7CiAgICBjb25zdCByZWNPdmVybGF5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLW1vZGFsLW92ZXJsYXkiKTsKICAgIGNvbnN0IHJlY01vZGFsVGl0bGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHJlY1R5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtdHlwZS10b2dnbGUiKTsKICAgIGNvbnN0IHJlY05hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtbmFtZSIpOwogICAgY29uc3QgcmVjQW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWFtb3VudCIpOwogICAgY29uc3QgcmVjQ2F0ZWdvcnlJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtY2F0ZWdvcnkiKTsKICAgIGNvbnN0IHJlY0RheUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1kYXkiKTsKICAgIGNvbnN0IHJlY1N0YXJ0RGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1zdGFydC1kYXRlIik7CiAgICBjb25zdCByZWNFbmREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWVuZC1kYXRlIik7CiAgICBjb25zdCByZWNTYXZlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tc2F2ZSIpOwoKICAgIGxldCBhbGxSZWN1cnJpbmcgPSBbXTsKICAgIGxldCBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgbGV0IHJlY0N1cnJlbnRUeXBlID0gImV4cGVuc2UiOwoKICAgIGZ1bmN0aW9uIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCBzZWxlY3RlZFZhbHVlID0gbnVsbCkgewogICAgICByZWNDYXRlZ29yeUlucHV0LmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0pIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICBpZiAodmFsdWUgPT09IChzZWxlY3RlZFZhbHVlIHx8ICJhdXRyZSIpKSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHJlY0NhdGVnb3J5SW5wdXQuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNldFJlY3VycmluZ1R5cGUodHlwZSkgewogICAgICByZWNDdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHJlY1R5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZVJlY3VycmluZ0NhdGVnb3JpZXModHlwZSwgcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgcmVjVHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFJlY3VycmluZ1R5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSA9IG51bGwpIHsKICAgICAgZWRpdGluZ1JlY3VycmluZ0lkID0gaXRlbSA/IGl0ZW0uaWQgOiBudWxsOwogICAgICByZWNNb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpdGVtID8gIk1vZGlmaWVyIGxhIGNoYXJnZSByw6ljdXJyZW50ZSIgOiAiTm91dmVsbGUgY2hhcmdlIHLDqWN1cnJlbnRlIjsKICAgICAgcmVjU2F2ZUJ0bi50ZXh0Q29udGVudCA9IGl0ZW0gPyAiRW5yZWdpc3RyZXIiIDogIkFqb3V0ZXIiOwogICAgICBzZXRSZWN1cnJpbmdUeXBlKGl0ZW0gPyBpdGVtLnR5cGUgOiAiZXhwZW5zZSIpOwogICAgICByZWNOYW1lSW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5uYW1lIDogIiI7CiAgICAgIHJlY0Ftb3VudElucHV0LnZhbHVlID0gaXRlbSA/IGl0ZW0uYW1vdW50IDogIiI7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyhyZWNDdXJyZW50VHlwZSwgaXRlbSA/IGl0ZW0uY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgcmVjRGF5SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5kYXlfb2ZfbW9udGggOiAiIjsKICAgICAgcmVjU3RhcnREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uc3RhcnRfZGF0ZSA/IGl0ZW0uc3RhcnRfZGF0ZSA6ICIiOwogICAgICByZWNFbmREYXRlSW5wdXQudmFsdWUgPSBpdGVtICYmIGl0ZW0uZW5kX2RhdGUgPyBpdGVtLmVuZF9kYXRlIDogIiI7CiAgICAgIHJlY092ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjTmFtZUlucHV0LmZvY3VzKCk7CiAgICB9CgogICAgZnVuY3Rpb24gY2xvc2VSZWN1cnJpbmdNb2RhbCgpIHsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBudWxsOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VSZWN1cnJpbmdNb2RhbCk7CiAgICByZWNPdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IHJlY092ZXJsYXlFbCkgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOyB9KTsKCiAgICByZWNTYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBuYW1lID0gcmVjTmFtZUlucHV0LnZhbHVlLnRyaW0oKTsKICAgICAgY29uc3QgYW1vdW50ID0gcGFyc2VGbG9hdChyZWNBbW91bnRJbnB1dC52YWx1ZSk7CiAgICAgIGNvbnN0IGRheSA9IHBhcnNlSW50KHJlY0RheUlucHV0LnZhbHVlLCAxMCk7CgogICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJMZSBub20gZXN0IG9ibGlnYXRvaXJlIiwgdHJ1ZSk7IHJldHVybjsgfQogICAgICBpZiAoIWFtb3VudCB8fCBhbW91bnQgPD0gMCkgeyBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZGF5IHx8IGRheSA8IDEgfHwgZGF5ID4gMzEpIHsgc2hvd1RvYXN0KCJKb3VyIGR1IG1vaXMgaW52YWxpZGUgKDEgw6AgMzEpIiwgdHJ1ZSk7IHJldHVybjsgfQoKICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICB0eXBlOiByZWNDdXJyZW50VHlwZSwKICAgICAgICBuYW1lLAogICAgICAgIGFtb3VudCwKICAgICAgICBjYXRlZ29yeTogcmVjQ2F0ZWdvcnlJbnB1dC52YWx1ZSwKICAgICAgICBkYXlfb2ZfbW9udGg6IGRheSwKICAgICAgICBzdGFydF9kYXRlOiByZWNTdGFydERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICAgIGVuZF9kYXRlOiByZWNFbmREYXRlSW5wdXQudmFsdWUgfHwgbnVsbCwKICAgICAgfTsKCiAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICB0cnkgewogICAgICAgIGlmIChlZGl0aW5nUmVjdXJyaW5nSWQpIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2VkaXRpbmdSZWN1cnJpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgbW9kaWZpw6llIik7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJDaGFyZ2UgcsOpY3VycmVudGUgYWpvdXTDqWUiKTsKICAgICAgICB9CiAgICAgICAgY2xvc2VSZWN1cnJpbmdNb2RhbCgpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIHJlY1NhdmVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgfQogICAgfSk7CgogICAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlUmVjdXJyaW5nKGlkKSB7CiAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgY2V0dGUgZMOpcGVuc2UgcsOpY3VycmVudGUgPyIpKSkgcmV0dXJuOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3JlY3VycmluZy8ke2lkfWAsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkTDqXBlbnNlIHLDqWN1cnJlbnRlIHN1cHByaW3DqWUiKTsKICAgICAgICBhd2FpdCBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclJlY3VycmluZyhpdGVtcykgewogICAgICByZWNMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIHJlY0VtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gaXRlbXMubGVuZ3RoID09PSAwID8gImJsb2NrIiA6ICJub25lIjsKCiAgICAgIGNvbnN0IHRvZGF5S2V5ID0gdG9kYXlJc28oKTsKCiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBpdGVtcykgewogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwogICAgICAgIGNvbnN0IGVuZGVkID0gaXRlbS5lbmRfZGF0ZSAmJiBpdGVtLmVuZF9kYXRlIDwgdG9kYXlLZXk7CiAgICAgICAgY29uc3Qgbm90U3RhcnRlZCA9IGl0ZW0uc3RhcnRfZGF0ZSAmJiBpdGVtLnN0YXJ0X2RhdGUgPiB0b2RheUtleTsKCiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInJlYy1jYXJkICIgKyB0eXBlICsgKGVuZGVkID8gIiBlbmRlZCIgOiAiIik7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJyZWMtbWFpbiI7CgogICAgICAgIGNvbnN0IHRvcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHRvcC5jbGFzc05hbWUgPSAicmVjLXRvcCI7CiAgICAgICAgY29uc3QgYmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYmFkZ2UuY2xhc3NOYW1lID0gImNhdGVnb3J5LWJhZGdlIjsKICAgICAgICBiYWRnZS50ZXh0Q29udGVudCA9IGFsbENhdGVnb3J5TGFiZWxzW2l0ZW0uY2F0ZWdvcnldIHx8IGl0ZW0uY2F0ZWdvcnk7CiAgICAgICAgdG9wLmFwcGVuZENoaWxkKGJhZGdlKTsKICAgICAgICBpZiAoaXRlbS5zdGFydF9kYXRlKSB7CiAgICAgICAgICBjb25zdCBzdGFydEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgc3RhcnRCYWRnZS5jbGFzc05hbWUgPSAic3RhcnQtYmFkZ2UiOwogICAgICAgICAgY29uc3Qgc3RhcnRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uc3RhcnRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBzdGFydEJhZGdlLnRleHRDb250ZW50ID0gbm90U3RhcnRlZCA/IGBEw6hzIGxlICR7c3RhcnRMYWJlbH1gIDogYERlcHVpcyBsZSAke3N0YXJ0TGFiZWx9YDsKICAgICAgICAgIHRvcC5hcHBlbmRDaGlsZChzdGFydEJhZGdlKTsKICAgICAgICB9CiAgICAgICAgaWYgKGl0ZW0uZW5kX2RhdGUpIHsKICAgICAgICAgIGNvbnN0IGVuZEJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZW5kQmFkZ2UuY2xhc3NOYW1lID0gImVuZC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBlbmRMYWJlbCA9IGRhdGVGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKGl0ZW0uZW5kX2RhdGUgKyAiVDAwOjAwOjAwIikpOwogICAgICAgICAgZW5kQmFkZ2UudGV4dENvbnRlbnQgPSBlbmRlZCA/IGBUZXJtaW7DqSBsZSAke2VuZExhYmVsfWAgOiBgSnVzcXUnYXUgJHtlbmRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKGVuZEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IG5hbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBuYW1lLmNsYXNzTmFtZSA9ICJyZWMtbmFtZSI7CiAgICAgICAgbmFtZS50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKCiAgICAgICAgY29uc3Qgc3ViID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgc3ViLmNsYXNzTmFtZSA9ICJyZWMtc3ViIjsKICAgICAgICBzdWIudGV4dENvbnRlbnQgPSBgTGUgJHtpdGVtLmRheV9vZl9tb250aH0gZGUgY2hhcXVlIG1vaXNgOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChuYW1lKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHN1Yik7CgogICAgICAgIGNvbnN0IGFtb3VudEVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgYW1vdW50RWwuY2xhc3NOYW1lID0gInJlYy1hbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50RWwudGV4dENvbnRlbnQgPSAodHlwZSA9PT0gImluY29tZSIgPyAiKyAiIDogIuKIkiAiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLmFtb3VudCk7CgogICAgICAgIGNvbnN0IGFjdGlvbnMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhY3Rpb25zLmNsYXNzTmFtZSA9ICJ0eC1hY3Rpb25zIjsKICAgICAgICBjb25zdCBlZGl0QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZWRpdEJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGVkaXRCdG4udGV4dENvbnRlbnQgPSAi4pyP77iPIjsKICAgICAgICBlZGl0QnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJNb2RpZmllciIpOwogICAgICAgIGVkaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjdXJyaW5nTW9kYWwoaXRlbSkpOwogICAgICAgIGNvbnN0IGRlbGV0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGRlbGV0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4gZGFuZ2VyIjsKICAgICAgICBkZWxldGVCdG4udGV4dENvbnRlbnQgPSAi8J+Xke+4jyI7CiAgICAgICAgZGVsZXRlQnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJTdXBwcmltZXIiKTsKICAgICAgICBkZWxldGVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBkZWxldGVSZWN1cnJpbmcoaXRlbS5pZCkpOwogICAgICAgIGFjdGlvbnMuYXBwZW5kQ2hpbGQoZWRpdEJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgcmVjTGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gVG90YWwgZGVzIGTDqXBlbnNlcyByw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcyBjZSBtb2lzLWNpIChjZWxsZXMKICAgIC8vIGRvbnQgbGUgam91ciBkdSBtb2lzIG4nZXN0IHBhcyBlbmNvcmUgcGFzc8OpKSwgYWZmaWNow6kgw6AgY8O0dMOpIGRlcyAzCiAgICAvLyBjYXJ0ZXMgZHUgaGF1dCDigJQgaW5kw6lwZW5kYW50IGR1IG1vaXMgY2hvaXNpIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkLAogICAgLy8gdG91am91cnMgImxlIG1vaXMgcsOpZWwsIG1haW50ZW5hbnQiLgogICAgZnVuY3Rpb24gdXBkYXRlVXBjb21pbmdTdW1tYXJ5KCkgewogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGxldCB1cGNvbWluZ0V4cGVuc2UgPSAwOwogICAgICBsZXQgdXBjb21pbmdJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IGl0ZW0gb2YgYWxsUmVjdXJyaW5nKSB7CiAgICAgICAgaWYgKCFyZWN1cnJpbmdBY3RpdmVGb3JNb250aChpdGVtLCBjdXJyZW50TW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gdG9kYXlEYXkpIGNvbnRpbnVlOwogICAgICAgIGlmICgoaXRlbS50eXBlIHx8ICJleHBlbnNlIikgPT09ICJpbmNvbWUiKSB1cGNvbWluZ0luY29tZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICAgIGVsc2UgdXBjb21pbmdFeHBlbnNlICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbmV0ID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmciKTsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBpZiAobmV0ID09PSAwKSB7CiAgICAgICAgZWwudGV4dENvbnRlbnQgPSAi4oCUIjsKICAgICAgICBlbC5jbGFzc05hbWUgPSAidmFsdWUiOwogICAgICAgIHRvb2x0aXBFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgICBjYXJkRWwuY2xhc3NMaXN0LnJlbW92ZSgidG9vbHRpcC1ob3N0Iik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBzaWduID0gbmV0ID4gMCA/ICIrIiA6ICLiiJIiOwogICAgICBlbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldCkpfWA7CiAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSAiICsgKG5ldCA+IDAgPyAicG9zaXRpdmUiIDogIm5lZ2F0aXZlIik7CiAgICAgIGNhcmRFbC5jbGFzc0xpc3QuYWRkKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9CiAgICAgICAgYETDqXBlbnNlcyDDoCB2ZW5pciA6ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHVwY29taW5nRXhwZW5zZSl9PGJyPmAgKwogICAgICAgIGBSZXZlbnVzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdJbmNvbWUpfWA7CiAgICB9CgogICAgLy8gUGV0aXRlIGJ1bGxlIGRlIGTDqXRhaWwgZmHDp29uICJ0b29sdGlwIiBoYWJpbGzDqWUgYXV4IGNvdWxldXJzIGR1IHNpdGUsCiAgICAvLyBhdSBsaWV1IGR1IHRpdGxlIG5hdGlmIGR1IG5hdmlnYXRldXIgKGdyaXMvYmxhbmMsIGhvcnMgY2hhcnRlLCBldAogICAgLy8gaW52aXNpYmxlIGF1IHRhY3RpbGUpLiBBZmZpY2jDqWUgYXUgc3Vydm9sIChvcmRpbmF0ZXVyKSBldCBhdQogICAgLy8gdGFwL3RhcC1lbi1kZWhvcnMgKHTDqWzDqXBob25lL3RhYmxldHRlKS4KICAgIChmdW5jdGlvbiBzZXR1cFN1bW1hcnlVcGNvbWluZ1Rvb2x0aXAoKSB7CiAgICAgIGNvbnN0IGNhcmRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLWNhcmQiKTsKICAgICAgY29uc3QgdG9vbHRpcEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctdG9vbHRpcCIpOwoKICAgICAgZnVuY3Rpb24gc2hvdygpIHsKICAgICAgICBpZiAodG9vbHRpcEVsLmlubmVySFRNTCkgdG9vbHRpcEVsLmNsYXNzTGlzdC5hZGQoInZpc2libGUiKTsKICAgICAgfQogICAgICBmdW5jdGlvbiBoaWRlKCkgewogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QucmVtb3ZlKCJ2aXNpYmxlIik7CiAgICAgIH0KCiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWVudGVyIiwgc2hvdyk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJtb3VzZWxlYXZlIiwgaGlkZSk7CiAgICAgIGNhcmRFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgICAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICAgICAgICB0b29sdGlwRWwuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIpOwogICAgICB9KTsKICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBoaWRlKTsKICAgIH0pKCk7CgogICAgLy8gUmFtw6huZSB1biBqb3VyIGR1IG1vaXMgKDEtMzEpIGF1IGRlcm5pZXIgam91ciByw6llbCBkdSBtb2lzIHZpc8OpIOKAlAogICAgLy8gw6lxdWl2YWxlbnQgSlMgZGUgX2NsYW1wX2RheSBjw7R0w6kgc2VydmV1ciwgcG91ciBjYWxjdWxlciBkZSB2cmFpZXMKICAgIC8vIGRhdGVzIChuZXcgRGF0ZSguLi4pKSBwbHV0w7R0IHF1ZSBkZSBjb21wYXJlciBkZXMgam91cnMgdG91dCBzZXVscy4KICAgIGZ1bmN0aW9uIGNsYW1wRGF5SnMoeWVhciwgbW9udGhJbmRleCwgZGF5KSB7CiAgICAgIGNvbnN0IGxhc3REYXkgPSBuZXcgRGF0ZSh5ZWFyLCBtb250aEluZGV4ICsgMSwgMCkuZ2V0RGF0ZSgpOwogICAgICByZXR1cm4gTWF0aC5taW4oZGF5LCBsYXN0RGF5KTsKICAgIH0KCiAgICAvLyBQcm9jaGFpbmUgb2NjdXJyZW5jZSBkJ3VuZSBjaGFyZ2UgcsOpY3VycmVudGUgw6AgcGFydGlyIGQnYXVqb3VyZCdodWkKICAgIC8vIChzdHJpY3RlbWVudCBhcHLDqHMgYXVqb3VyZCdodWkpIDogcmVnYXJkZSBjZSBtb2lzLWNpIHB1aXMsIHNpIGJlc29pbiwKICAgIC8vIGxlcyBkZXV4IG1vaXMgc3VpdmFudHMg4oCUIHV0aWxlIGVuIGZpbiBkZSBtb2lzIHF1YW5kIHBsdXMgcmllbiBuJ2VzdAogICAgLy8gw6AgdmVuaXIgZGFucyBsZSBtb2lzIGNvdXJhbnQuCiAgICBmdW5jdGlvbiBuZXh0T2NjdXJyZW5jZUZvckl0ZW0oaXRlbSwgdG9kYXlTdHIpIHsKICAgICAgY29uc3QgW3R5LCB0bSwgdGRdID0gdG9kYXlTdHIuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3QgdG9kYXlEYXRlID0gbmV3IERhdGUodHksIHRtIC0gMSwgdGQpOwogICAgICBmb3IgKGxldCBvZmZzZXQgPSAwOyBvZmZzZXQgPD0gMjsgb2Zmc2V0KyspIHsKICAgICAgICBjb25zdCBiYXNlID0gbmV3IERhdGUodHksIHRtIC0gMSArIG9mZnNldCwgMSk7CiAgICAgICAgY29uc3QgeSA9IGJhc2UuZ2V0RnVsbFllYXIoKTsKICAgICAgICBjb25zdCBtSWR4ID0gYmFzZS5nZXRNb250aCgpOwogICAgICAgIGNvbnN0IG1vbnRoS2V5ID0gYCR7eX0tJHtTdHJpbmcobUlkeCArIDEpLnBhZFN0YXJ0KDIsICIwIil9YDsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIG1vbnRoS2V5KSkgY29udGludWU7CiAgICAgICAgY29uc3QgZGF5ID0gY2xhbXBEYXlKcyh5LCBtSWR4LCBpdGVtLmRheV9vZl9tb250aCk7CiAgICAgICAgY29uc3Qgb2NjRGF0ZSA9IG5ldyBEYXRlKHksIG1JZHgsIGRheSk7CiAgICAgICAgaWYgKG9jY0RhdGUgPiB0b2RheURhdGUpIHJldHVybiBvY2NEYXRlOwogICAgICB9CiAgICAgIHJldHVybiBudWxsOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpIHsKICAgICAgY29uc3QgcGFuZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIik7CiAgICAgIGNvbnN0IGxpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctbGlzdCIpOwogICAgICBjb25zdCB0b2RheSA9IHRvZGF5SXNvKCk7CgogICAgICBjb25zdCB1cGNvbWluZyA9IGFsbFJlY3VycmluZwogICAgICAgIC5tYXAoKGl0ZW0pID0+ICh7IGl0ZW0sIGRhdGU6IG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheSkgfSkpCiAgICAgICAgLmZpbHRlcigoeCkgPT4geC5kYXRlKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBhLmRhdGUgLSBiLmRhdGUpCiAgICAgICAgLnNsaWNlKDAsIDMpOwoKICAgICAgaWYgKHVwY29taW5nLmxlbmd0aCA9PT0gMCkgewogICAgICAgIHBhbmVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBwYW5lbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwoKICAgICAgZm9yIChjb25zdCB7IGl0ZW0sIGRhdGUgfSBvZiB1cGNvbWluZykgewogICAgICAgIGNvbnN0IGRheXMgPSBNYXRoLnJvdW5kKChkYXRlIC0gbmV3IERhdGUobmV3IERhdGUoKS5zZXRIb3VycygwLCAwLCAwLCAwKSkpIC8gODY0MDAwMDApOwogICAgICAgIGNvbnN0IGR1ZUxhYmVsID0gZGF5cyA8PSAxID8gImRlbWFpbiIgOiBgZGFucyAke2RheXN9IGpvdXJzYDsKICAgICAgICBjb25zdCB0eXBlID0gaXRlbS50eXBlIHx8ICJleHBlbnNlIjsKCiAgICAgICAgY29uc3Qgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgcm93LmNsYXNzTmFtZSA9ICJ1cGNvbWluZy1yZWN1cnJpbmctcm93IjsKICAgICAgICBjb25zdCBsZWZ0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGxlZnQuY2xhc3NOYW1lID0gIm5hbWUiOwogICAgICAgIGxlZnQudGV4dENvbnRlbnQgPSBpdGVtLm5hbWU7CiAgICAgICAgY29uc3QgZHVlU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBkdWVTcGFuLmNsYXNzTmFtZSA9ICJkdWUiOwogICAgICAgIGR1ZVNwYW4udGV4dENvbnRlbnQgPSBgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChkYXRlKX0gwrcgJHtkdWVMYWJlbH1gOwogICAgICAgIGxlZnQuYXBwZW5kQ2hpbGQoZHVlU3Bhbik7CiAgICAgICAgY29uc3QgYW1vdW50ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudC5jbGFzc05hbWUgPSAiYW1vdW50ICIgKyB0eXBlOwogICAgICAgIGFtb3VudC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQobGVmdCk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGFtb3VudCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKHJvdyk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkUmVjdXJyaW5nKCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IGl0ZW1zID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIik7CiAgICAgICAgYWxsUmVjdXJyaW5nID0gaXRlbXM7CiAgICAgICAgcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKTsKICAgICAgICByZW5kZXJVcGNvbWluZ1JlY3VycmluZ0xpc3QoKTsKICAgICAgICB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBFeHBvcnQgKEV4Y2VsIG91IHNhdXZlZ2FyZGUgSlNPTiBjb21wbMOodGUsIHVuIHNldWwgYm91dG9uIGF2ZWMgdW4KICAgIC8vIGNob2l4IGRlIGZvcm1hdCBwbHV0w7R0IHF1ZSBkZXV4IGdyb3MgYm91dG9ucyBzw6lwYXLDqXMpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBFWFBPUlRfRk9STUFUUyA9IHsKICAgICAgeGxzeDogewogICAgICAgIGhpbnQ6ICJUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2hhY3VuZSBkYW5zIHNvbiBwcm9wcmUgb25nbGV0LiIsCiAgICAgICAgdXJsOiAiL2FwaS9leHBvcnQveGxzeCIsCiAgICAgICAgZmlsZW5hbWU6ICgpID0+IGBkZXBlbnNlc18ke3RvZGF5SXNvKCl9Lnhsc3hgLAogICAgICAgIHRvYXN0U3VjY2VzczogIkV4cG9ydCB0w6lsw6ljaGFyZ8OpIiwKICAgICAgfSwKICAgICAganNvbjogewogICAgICAgIGhpbnQ6ICJBYnNvbHVtZW50IHRvdXRlcyB0ZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBvYmplY3RpZiBkJ8OpcGFyZ25lKS4gw4AgZ2FyZGVyIGRlIGPDtHTDqSA6IFN1cGFiYXNlIG5lIGZhaXQgcGFzIGRlIHNhdXZlZ2FyZGUgYXV0b21hdGlxdWUgZW4gb2ZmcmUgZ3JhdHVpdGUsIGNlIGZpY2hpZXIgZXN0IHRvbiBmaWxldCBkZSBzw6ljdXJpdMOpIGVuIGNhcyBkZSBww6lwaW4uIiwKICAgICAgICB1cmw6ICIvYXBpL2V4cG9ydC9qc29uIiwKICAgICAgICBmaWxlbmFtZTogKCkgPT4gYGthY2hpbmctc2F1dmVnYXJkZS0ke3RvZGF5SXNvKCl9Lmpzb25gLAogICAgICAgIHRvYXN0U3VjY2VzczogIlNhdXZlZ2FyZGUgdMOpbMOpY2hhcmfDqWUiLAogICAgICB9LAogICAgfTsKICAgIGxldCBjdXJyZW50RXhwb3J0Rm9ybWF0ID0gInhsc3giOwogICAgY29uc3QgZXhwb3J0Rm9ybWF0SGludEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtaGludCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImV4cG9ydC1mb3JtYXQtdG9nZ2xlIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIuZXhwb3J0LWZvcm1hdC1idG4iKTsKICAgICAgaWYgKCFidG4pIHJldHVybjsKICAgICAgY3VycmVudEV4cG9ydEZvcm1hdCA9IGJ0bi5kYXRhc2V0LmZvcm1hdDsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgiLmV4cG9ydC1mb3JtYXQtYnRuIikuZm9yRWFjaCgoYikgPT4gewogICAgICAgIGIuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYiA9PT0gYnRuKTsKICAgICAgfSk7CiAgICAgIGV4cG9ydEZvcm1hdEhpbnRFbC50ZXh0Q29udGVudCA9IEVYUE9SVF9GT1JNQVRTW2N1cnJlbnRFeHBvcnRGb3JtYXRdLmhpbnQ7CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWV4cG9ydC1kb3dubG9hZCIpOwogICAgICBjb25zdCBjb25maWcgPSBFWFBPUlRfRk9STUFUU1tjdXJyZW50RXhwb3J0Rm9ybWF0XTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiR8OpbsOpcmF0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChjb25maWcudXJsLCB7IGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSB9KTsKICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCLDiWNoZWMgZGUgbCdleHBvcnQgKCIgKyByZXMuc3RhdHVzICsgIikiKTsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBjb25zdCB1cmwgPSBVUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgICAgIGNvbnN0IGxpbmsgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7CiAgICAgICAgbGluay5ocmVmID0gdXJsOwogICAgICAgIGxpbmsuZG93bmxvYWQgPSBjb25maWcuZmlsZW5hbWUoKTsKICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGxpbmspOwogICAgICAgIGxpbmsuY2xpY2soKTsKICAgICAgICBsaW5rLnJlbW92ZSgpOwogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKICAgICAgICBzaG93VG9hc3QoY29uZmlnLnRvYXN0U3VjY2Vzcyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEdhcmRlLWZvdSBnbG9iYWwgY29udHJlIGxlIGNvbXBvcnRlbWVudCBwYXIgZMOpZmF1dCBkdSBuYXZpZ2F0ZXVyIDoKICAgIC8vIGTDqXBvc2VyIHVuIGZpY2hpZXIgTidJTVBPUlRFIE/DmSBzdXIgbGEgcGFnZSAoZW4gZGVob3JzIGQndW5lIHpvbmUKICAgIC8vIHByw6l2dWUgcG91ciDDp2EpIGZhaXQgbm9ybWFsZW1lbnQgTkFWSUdVRVIgbCdvbmdsZXQgdmVycyBjZSBmaWNoaWVyCiAgICAvLyBsb2NhbCAoZmlsZTovLy4uLiksIHF1aSB0ZW50ZSBkZSBsJ2FmZmljaGVyIGNvbW1lIHVuZSBwYWdlIOKAlCBhdmVjIHVuCiAgICAvLyBncm9zIGZpY2hpZXIgb3UgdW4gZm9ybWF0IGluYXR0ZW5kdSwgw6dhIHBldXQgcGxhbnRlciBsJ29uZ2xldAogICAgLy8gKCJBw69lIGHDr2UgYcOvZSIpLiBPbiBibG9xdWUgY2UgY29tcG9ydGVtZW50IHBhcnRvdXQsIGV0IGxhIHpvbmUgZGUKICAgIC8vIGTDqXDDtHQgZMOpZGnDqWUgKHBsdXMgYmFzKSByZXByZW5kIGxhIG1haW4gc3VyIGxlIGZpY2hpZXIgZMOpcG9zw6kuCiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ292ZXIiLCAoZSkgPT4gZS5wcmV2ZW50RGVmYXVsdCgpKTsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJkcm9wIiwgKGUpID0+IGUucHJldmVudERlZmF1bHQoKSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gSW1wb3J0IGRlIHJlbGV2w6kgYmFuY2FpcmUgKENTViBCb3Vyc29CYW5rKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gTGUgZmljaGllciBuJ2VzdCBqYW1haXMgZ2FyZMOpIGFwcsOocyBsJ2FuYWx5c2UgKG5pIGljaSwgbmkgY8O0dMOpCiAgICAvLyBzZXJ2ZXVyKSA6IHNldWwgbGUgdGFibGVhdSBgaW1wb3J0UHJldmlld1Jvd3NgIChkw6lqw6AgZGVzIHRyYW5zYWN0aW9ucwogICAgLy8gY2FuZGlkYXRlcywgcGFzIGxlIGZpY2hpZXIgYnJ1dCkgdml0IGVuIG3DqW1vaXJlIGxlIHRlbXBzIGRlIGxhIHJldnVlLgogICAgbGV0IGltcG9ydFByZXZpZXdSb3dzID0gW107IC8vIFt7IC4uLnJvdywgc2VsZWN0ZWQ6IGJvb2wgfV0KICAgIGxldCBpbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsgZXhwZW5zZToge30sIGluY29tZToge30gfTsKICAgIGNvbnN0IE1BWF9JTVBPUlRfRklMRV9TSVpFX0JZVEVTID0gMyAqIDEwMjQgKiAxMDI0OyAvLyBkb2l0IHJlc3RlciBhbGlnbsOpIGF2ZWMgbGUgYmFja2VuZAoKICAgIGNvbnN0IGltcG9ydERyb3B6b25lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWRyb3B6b25lIik7CiAgICBjb25zdCBpbXBvcnRGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWZpbGUtaW5wdXQiKTsKICAgIGNvbnN0IGltcG9ydEFuYWx5emVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LWFuYWx5emUtYnRuIik7CiAgICBjb25zdCBpbXBvcnRTdW1tYXJ5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXN1bW1hcnkiKTsKICAgIGNvbnN0IGltcG9ydFByZXZpZXdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcHJldmlldyIpOwogICAgY29uc3QgaW1wb3J0Um93c0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcm93cy1saXN0Iik7CiAgICBjb25zdCBpbXBvcnRTZWxlY3RlZENvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXNlbGVjdGVkLWNvdW50Iik7CgogICAgZnVuY3Rpb24gdXBkYXRlSW1wb3J0U2VsZWN0ZWRDb3VudCgpIHsKICAgICAgY29uc3QgbiA9IGltcG9ydFByZXZpZXdSb3dzLmZpbHRlcigocikgPT4gci5zZWxlY3RlZCkubGVuZ3RoOwogICAgICBpbXBvcnRTZWxlY3RlZENvdW50RWwudGV4dENvbnRlbnQgPSBgJHtufSBzw6lsZWN0aW9ubsOpZSR7biA+IDEgPyAicyIgOiAiIn0gc3VyICR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RofWA7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpLmRpc2FibGVkID0gbiA9PT0gMDsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJJbXBvcnRQcmV2aWV3KCkgewogICAgICBpbXBvcnRSb3dzTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IHJvdyBvZiBpbXBvcnRQcmV2aWV3Um93cykgewogICAgICAgIGNvbnN0IGVsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZWwuY2xhc3NOYW1lID0gImltcG9ydC1yb3ciICsgKHJvdy5zZWxlY3RlZCA/ICIiIDogIiBleGNsdWRlZCIpOwoKICAgICAgICBjb25zdCBjaGVja2JveCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7CiAgICAgICAgY2hlY2tib3gudHlwZSA9ICJjaGVja2JveCI7CiAgICAgICAgY2hlY2tib3guY2hlY2tlZCA9IHJvdy5zZWxlY3RlZDsKICAgICAgICBjaGVja2JveC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7CiAgICAgICAgICByb3cuc2VsZWN0ZWQgPSBjaGVja2JveC5jaGVja2VkOwogICAgICAgICAgZWwuY2xhc3NMaXN0LnRvZ2dsZSgiZXhjbHVkZWQiLCAhcm93LnNlbGVjdGVkKTsKICAgICAgICAgIHVwZGF0ZUltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgICAgICB9KTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWFpbiI7CiAgICAgICAgY29uc3QgZGVzYyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGRlc2MuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctZGVzYyI7CiAgICAgICAgY29uc3QgYW1vdW50U3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBhbW91bnRTcGFuLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWFtb3VudCAiICsgcm93LnR5cGU7CiAgICAgICAgYW1vdW50U3Bhbi50ZXh0Q29udGVudCA9IChyb3cudHlwZSA9PT0gImV4cGVuc2UiID8gIi0iIDogIisiKSArIGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChyb3cuYW1vdW50KTsKICAgICAgICBkZXNjLmFwcGVuZCgocm93LmRlc2NyaXB0aW9uIHx8ICIiKSArICIg4oCUICIpOwogICAgICAgIGRlc2MuYXBwZW5kQ2hpbGQoYW1vdW50U3Bhbik7CgogICAgICAgIGNvbnN0IG1ldGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtZXRhLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LW1ldGEiOwogICAgICAgIGxldCBtZXRhVGV4dCA9IGAke3Jvdy5leHBlbnNlX2RhdGV9IMK3ICR7cm93LmJhbmtfbGFiZWx9YDsKICAgICAgICBpZiAocm93LmlzX2ludGVybmFsX3RyYW5zZmVyKSBtZXRhVGV4dCArPSAiIMK3IHZpcmVtZW50IGludGVybmUiOwogICAgICAgIG1ldGEudGV4dENvbnRlbnQgPSBtZXRhVGV4dDsKICAgICAgICBpZiAocm93Lmxpa2VseV9kdXBsaWNhdGUpIHsKICAgICAgICAgIGNvbnN0IGR1cFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBkdXBTcGFuLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93LWR1cCI7CiAgICAgICAgICBkdXBTcGFuLnRleHRDb250ZW50ID0gIiDCtyBkw6lqw6AgcHLDqXNlbnRlID8iOwogICAgICAgICAgbWV0YS5hcHBlbmRDaGlsZChkdXBTcGFuKTsKICAgICAgICB9CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoZGVzYyk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChtZXRhKTsKCiAgICAgICAgY29uc3QgY2F0U2VsZWN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2VsZWN0Iik7CiAgICAgICAgY29uc3QgbGFiZWxzID0gcm93LnR5cGUgPT09ICJleHBlbnNlIiA/IGltcG9ydENhdGVnb3J5TGFiZWxzLmV4cGVuc2UgOiBpbXBvcnRDYXRlZ29yeUxhYmVscy5pbmNvbWU7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhsYWJlbHMpKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBpZiAodmFsdWUgPT09IHJvdy5jYXRlZ29yeSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICAgIGNhdFNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjYXRTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4geyByb3cuY2F0ZWdvcnkgPSBjYXRTZWxlY3QudmFsdWU7IH0pOwoKICAgICAgICBlbC5hcHBlbmRDaGlsZChjaGVja2JveCk7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2F0U2VsZWN0KTsKICAgICAgICBpbXBvcnRSb3dzTGlzdEVsLmFwcGVuZENoaWxkKGVsKTsKICAgICAgfQogICAgICB1cGRhdGVJbXBvcnRTZWxlY3RlZENvdW50KCk7CiAgICB9CgogICAgLy8gR2xpc3Nlci1kw6lwb3NlciBkaXJlY3RlbWVudCBzdXIgbGEgY2FydGUgKGVuIHBsdXMgZHUgc8OpbGVjdGV1cgogICAgLy8gY2xhc3NpcXVlKSA6IG9uIHJlbXBsYWNlIGxlcyBmaWNoaWVycyBkZSBsJ2lucHV0IHZpYSBEYXRhVHJhbnNmZXIsCiAgICAvLyBwb3VyIHF1ZSBsZSByZXN0ZSBkdSBmbHV4IChib3V0b24gQW5hbHlzZXIpIHJlc3RlIGluY2hhbmfDqS4KICAgIGltcG9ydERyb3B6b25lRWwuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ292ZXIiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGltcG9ydERyb3B6b25lRWwuY2xhc3NMaXN0LmFkZCgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGltcG9ydERyb3B6b25lRWwuYWRkRXZlbnRMaXN0ZW5lcigiZHJhZ2xlYXZlIiwgKCkgPT4gewogICAgICBpbXBvcnREcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgfSk7CiAgICBpbXBvcnREcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGltcG9ydERyb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICAgIGNvbnN0IGZpbGUgPSBlLmRhdGFUcmFuc2Zlci5maWxlcyAmJiBlLmRhdGFUcmFuc2Zlci5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSByZXR1cm47CiAgICAgIGNvbnN0IGR0ID0gbmV3IERhdGFUcmFuc2ZlcigpOwogICAgICBkdC5pdGVtcy5hZGQoZmlsZSk7CiAgICAgIGltcG9ydEZpbGVJbnB1dC5maWxlcyA9IGR0LmZpbGVzOwogICAgfSk7CgogICAgaW1wb3J0QW5hbHl6ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IGltcG9ydEZpbGVJbnB1dC5maWxlcyAmJiBpbXBvcnRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgeyBzaG93VG9hc3QoIkNob2lzaXMgZCdhYm9yZCB1biBmaWNoaWVyIC5jc3YiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghZmlsZS5uYW1lLnRvTG93ZXJDYXNlKCkuZW5kc1dpdGgoIi5jc3YiKSkgewogICAgICAgIHNob3dUb2FzdCgiU2V1bHMgbGVzIGZpY2hpZXJzIC5jc3Ygc29udCBhY2NlcHTDqXMgcG91ciBsJ2luc3RhbnQiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IE1BWF9JTVBPUlRfRklMRV9TSVpFX0JZVEVTKSB7CiAgICAgICAgc2hvd1RvYXN0KCJGaWNoaWVyIHRyb3Agdm9sdW1pbmV1eCAoMyBNbyBtYXhpbXVtKSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gaW1wb3J0QW5hbHl6ZUJ0bi50ZXh0Q29udGVudDsKICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGltcG9ydEFuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3Vyc+KApiI7CiAgICAgIGltcG9ydFN1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBpbXBvcnRQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICBmb3JtRGF0YS5hcHBlbmQoImZpbGUiLCBmaWxlKTsKICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGV4dHJhY3RFcnJvckRldGFpbChlcnIsIGDDiWNoZWMgZGUgbCdhbmFseXNlICgke3Jlcy5zdGF0dXN9KWApKTsKICAgICAgICB9CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgaW1wb3J0Q2F0ZWdvcnlMYWJlbHMgPSB7CiAgICAgICAgICBleHBlbnNlOiBkYXRhLmV4cGVuc2VfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICAgIGluY29tZTogZGF0YS5pbmNvbWVfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICB9OwogICAgICAgIGltcG9ydFByZXZpZXdSb3dzID0gZGF0YS5yb3dzLm1hcCgocm93KSA9PiAoewogICAgICAgICAgLi4ucm93LAogICAgICAgICAgc2VsZWN0ZWQ6ICFyb3cuaXNfaW50ZXJuYWxfdHJhbnNmZXIgJiYgIXJvdy5saWtlbHlfZHVwbGljYXRlLAogICAgICAgIH0pKTsKCiAgICAgICAgbGV0IHN1bW1hcnkgPSBgPHN0cm9uZz4ke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aH08L3N0cm9uZz4gb3DDqXJhdGlvbiR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RoID4gMSA/ICJzIiA6ICIifSBkw6l0ZWN0w6llJHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9YDsKICAgICAgICBpZiAoZGF0YS5hY2NvdW50X2JhbGFuY2UgIT0gbnVsbCkgewogICAgICAgICAgc3VtbWFyeSArPSBgIOKAlCBzb2xkZSBkdSBjb21wdGUgYXUgJHtkYXRhLmFjY291bnRfYmFsYW5jZV9kYXRlfSA6IDxzdHJvbmc+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGF0YS5hY2NvdW50X2JhbGFuY2UpfTwvc3Ryb25nPmA7CiAgICAgICAgfQogICAgICAgIGlmIChkYXRhLnNraXBwZWRfcm93cykgc3VtbWFyeSArPSBgICgke2RhdGEuc2tpcHBlZF9yb3dzfSBsaWduZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9IGlnbm9yw6llJHtkYXRhLnNraXBwZWRfcm93cyA+IDEgPyAicyIgOiAiIn0sIGlsbGlzaWJsZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9KWA7CiAgICAgICAgc3VtbWFyeSArPSAiLiBMZXMgdmlyZW1lbnRzIGludGVybmVzIGV0IGRvdWJsb25zIHByb2JhYmxlcyBzb250IGTDqWNvY2jDqXMgcGFyIGTDqWZhdXQg4oCUIHbDqXJpZmllIGF2YW50IGQnaW1wb3J0ZXIuIjsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuaW5uZXJIVE1MID0gc3VtbWFyeTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgaW1wb3J0UHJldmlld0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGltcG9ydEFuYWx5emVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBpbXBvcnRBbmFseXplQnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXRvZ2dsZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGNvbnN0IGFueVNlbGVjdGVkID0gaW1wb3J0UHJldmlld1Jvd3Muc29tZSgocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGZvciAoY29uc3Qgcm93IG9mIGltcG9ydFByZXZpZXdSb3dzKSByb3cuc2VsZWN0ZWQgPSAhYW55U2VsZWN0ZWQ7CiAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBzZWxlY3RlZCA9IGltcG9ydFByZXZpZXdSb3dzLmZpbHRlcigocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGlmIChzZWxlY3RlZC5sZW5ndGggPT09IDApIHJldHVybjsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICBgSW1wb3J0ZXIgJHtzZWxlY3RlZC5sZW5ndGh9IHRyYW5zYWN0aW9uJHtzZWxlY3RlZC5sZW5ndGggPiAxID8gInMiIDogIiJ9ID8gVsOpcmlmaWUgYmllbiBsZXMgY2F0w6lnb3JpZXMgYXZhbnQgZGUgY29uZmlybWVyLmAKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1jb21taXQtYnRuIik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkltcG9ydCBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICAgIHJvd3M6IHNlbGVjdGVkLm1hcCgocikgPT4gKHsKICAgICAgICAgICAgZXhwZW5zZV9kYXRlOiByLmV4cGVuc2VfZGF0ZSwKICAgICAgICAgICAgdHlwZTogci50eXBlLAogICAgICAgICAgICBhbW91bnQ6IHIuYW1vdW50LAogICAgICAgICAgICBjYXRlZ29yeTogci5jYXRlZ29yeSwKICAgICAgICAgICAgZGVzY3JpcHRpb246IHIuZGVzY3JpcHRpb24sCiAgICAgICAgICB9KSksCiAgICAgICAgfTsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YvY29tbWl0IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYCR7cmVzdWx0Lmluc2VydGVkfSB0cmFuc2FjdGlvbiR7cmVzdWx0Lmluc2VydGVkID4gMSA/ICJzIiA6ICIifSBpbXBvcnTDqWUke3Jlc3VsdC5pbnNlcnRlZCA+IDEgPyAicyIgOiAiIn1gKTsKICAgICAgICBpbXBvcnRQcmV2aWV3Um93cyA9IFtdOwogICAgICAgIGltcG9ydFByZXZpZXdFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICBpbXBvcnRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEltcG9ydCBnw6luw6lyaXF1ZSBwYXIgSUEgKHRvdXQgZmljaGllciAuY3N2Ly54bHN4LCBzdHJ1Y3R1cmUgcXVlbGNvbnF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbW1lIHBvdXIgbCdpbXBvcnQgQm91cnNvQmFuaywgbGUgZmljaGllciBuJ2VzdCBqYW1haXMgZ2FyZMOpIGFwcsOocwogICAgLy8gbCdhbmFseXNlIDogc2V1bGVzIGxlcyB0cmFuc2FjdGlvbnMgY2FuZGlkYXRlcyBldCBsZXMgZ3JvdXBlcyBkZQogICAgLy8gcsOpY3VycmVuY2UgZMOpdGVjdMOpcyB2aXZlbnQgZW4gbcOpbW9pcmUgbGUgdGVtcHMgZGUgbGEgcmV2dWUuCiAgICBsZXQgZ2VuZXJpY0ltcG9ydFJvd3MgPSBbXTsgLy8gW3sgLi4ucm93LCBzZWxlY3RlZDogYm9vbCB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzID0gW107IC8vIFt7IC4uLmNhbmRpZGF0ZSwgZGVjaXNpb246ICJyZWN1cnJpbmcifCJjcmVkaXQifCJpZ25vcmUiLCBlbmRfZGF0ZSB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsgZXhwZW5zZToge30sIGluY29tZToge30gfTsKICAgIGNvbnN0IE1BWF9HRU5FUklDX0lNUE9SVF9GSUxFX1NJWkVfQllURVMgPSAzICogMTAyNCAqIDEwMjQ7IC8vIGFsaWduw6kgYXZlYyBsZSBiYWNrZW5kCgogICAgY29uc3QgZ2VuZXJpY0Ryb3B6b25lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZHJvcHpvbmUiKTsKICAgIGNvbnN0IGdlbmVyaWNGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZmlsZS1pbnB1dCIpOwogICAgY29uc3QgZ2VuZXJpY0FuYWx5emVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtYW5hbHl6ZS1idG4iKTsKICAgIGNvbnN0IGdlbmVyaWNTdW1tYXJ5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc3VtbWFyeSIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctc2VjdGlvbiIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctbGlzdCIpOwogICAgY29uc3QgZ2VuZXJpY1ByZXZpZXdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1wcmV2aWV3Iik7CiAgICBjb25zdCBnZW5lcmljUm93c0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yb3dzLWxpc3QiKTsKICAgIGNvbnN0IGdlbmVyaWNTZWxlY3RlZENvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc2VsZWN0ZWQtY291bnQiKTsKCiAgICBjb25zdCBSRUNVUlJJTkdfQ0xBU1NJRklDQVRJT05fTEFCRUxTID0gewogICAgICByZWN1cnJpbmc6ICJSw6ljdXJyZW50ZSIsCiAgICAgIGNyZWRpdDogIkNyw6lkaXQgZW4gY291cnMiLAogICAgICBlbmRlZDogIkFycsOqdMOpZSIsCiAgICAgIHVuY2VydGFpbjogIsOAIGNvbmZpcm1lciIsCiAgICB9OwoKICAgIGZ1bmN0aW9uIHVwZGF0ZUdlbmVyaWNJbXBvcnRTZWxlY3RlZENvdW50KCkgewogICAgICBjb25zdCBuID0gZ2VuZXJpY0ltcG9ydFJvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKS5sZW5ndGg7CiAgICAgIGdlbmVyaWNTZWxlY3RlZENvdW50RWwudGV4dENvbnRlbnQgPSBgJHtufSBzw6lsZWN0aW9ubsOpZSR7biA+IDEgPyAicyIgOiAiIn0gc3VyICR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RofWA7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIikuZGlzYWJsZWQgPSBuID09PSAwOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRSZWN1cnJpbmdMaXN0KCkgewogICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGNhbmQgb2YgZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlIiArIChjYW5kLm5lZWRzX2NvbmZpcm1hdGlvbiA/ICIgbmVlZHMtY29uZmlybWF0aW9uIiA6ICIiKTsKCiAgICAgICAgY29uc3QgaGVhZGVyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZGVyLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLWhlYWRlciI7CiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBjYW5kLm5hbWU7CiAgICAgICAgY29uc3QgdGFnU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICB0YWdTcGFuLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLXRhZyAiICsgY2FuZC5jbGFzc2lmaWNhdGlvbjsKICAgICAgICB0YWdTcGFuLnRleHRDb250ZW50ID0gUkVDVVJSSU5HX0NMQVNTSUZJQ0FUSU9OX0xBQkVMU1tjYW5kLmNsYXNzaWZpY2F0aW9uXSB8fCBjYW5kLmNsYXNzaWZpY2F0aW9uOwogICAgICAgIGhlYWRlci5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZGVyLmFwcGVuZENoaWxkKHRhZ1NwYW4pOwoKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWV0YS5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1tZXRhIjsKICAgICAgICBjb25zdCBsYWJlbHMgPSBjYW5kLnR5cGUgPT09ICJleHBlbnNlIiA/IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5leHBlbnNlIDogZ2VuZXJpY0ltcG9ydENhdGVnb3J5TGFiZWxzLmluY29tZTsKICAgICAgICBjb25zdCBjYXRMYWJlbCA9IGxhYmVsc1tjYW5kLmNhdGVnb3J5XSB8fCBjYW5kLmNhdGVnb3J5OwogICAgICAgIG1ldGEudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY2FuZC5hbW91bnQpfSBlbnZpcm9uIMK3ICR7Y2F0TGFiZWx9IMK3IHZ1ICR7Y2FuZC5tb250aHNfc2Vlbi5sZW5ndGh9IG1vaXMgKCR7Y2FuZC5tb250aHNfc2VlblswXX0g4oaSICR7Y2FuZC5tb250aHNfc2VlbltjYW5kLm1vbnRoc19zZWVuLmxlbmd0aCAtIDFdfSlgOwogICAgICAgIGlmIChjYW5kLmluc3RhbGxtZW50X2luZm8pIHsKICAgICAgICAgIG1ldGEudGV4dENvbnRlbnQgKz0gYCDCtyDDqWNow6lhbmNlICR7Y2FuZC5pbnN0YWxsbWVudF9pbmZvLmxhc3Rfc2Vlbn0vJHtjYW5kLmluc3RhbGxtZW50X2luZm8udG90YWx9LCAke2NhbmQuaW5zdGFsbG1lbnRfaW5mby5yZW1haW5pbmd9IHJlc3RhbnRlJHtjYW5kLmluc3RhbGxtZW50X2luZm8ucmVtYWluaW5nID4gMSA/ICJzIiA6ICIifWA7CiAgICAgICAgfQoKICAgICAgICBlbC5hcHBlbmRDaGlsZChoZWFkZXIpOwogICAgICAgIGVsLmFwcGVuZENoaWxkKG1ldGEpOwoKICAgICAgICBpZiAoY2FuZC5jbGFzc2lmaWNhdGlvbiAhPT0gImVuZGVkIikgewogICAgICAgICAgY29uc3QgY2hvaWNlUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjaG9pY2VSb3cuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIjsKICAgICAgICAgIGNvbnN0IG9wdGlvbnMgPSBbCiAgICAgICAgICAgIFsicmVjdXJyaW5nIiwgIlLDqWN1cnJlbnRlIChjb250aW51ZSkiXSwKICAgICAgICAgICAgWyJjcmVkaXQiLCAiQ3LDqWRpdCAoZGF0ZSBkZSBmaW4pIl0sCiAgICAgICAgICAgIFsiaWdub3JlIiwgIk5lIHBhcyByZW5kcmUgcsOpY3VycmVudGUiXSwKICAgICAgICAgIF07CiAgICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIG9wdGlvbnMpIHsKICAgICAgICAgICAgY29uc3QgbGJsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgibGFiZWwiKTsKICAgICAgICAgICAgY29uc3QgcmFkaW8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICByYWRpby50eXBlID0gInJhZGlvIjsKICAgICAgICAgICAgcmFkaW8ubmFtZSA9IGByZWN1cnJpbmctZGVjaXNpb24tJHtjYW5kLmdyb3VwX2lkfWA7CiAgICAgICAgICAgIHJhZGlvLnZhbHVlID0gdmFsdWU7CiAgICAgICAgICAgIHJhZGlvLmNoZWNrZWQgPSBjYW5kLmRlY2lzaW9uID09PSB2YWx1ZTsKICAgICAgICAgICAgcmFkaW8uYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgICAgIGNhbmQuZGVjaXNpb24gPSB2YWx1ZTsKICAgICAgICAgICAgICByZW5kZXJHZW5lcmljSW1wb3J0UmVjdXJyaW5nTGlzdCgpOwogICAgICAgICAgICB9KTsKICAgICAgICAgICAgbGJsLmFwcGVuZENoaWxkKHJhZGlvKTsKICAgICAgICAgICAgbGJsLmFwcGVuZChsYWJlbCk7CiAgICAgICAgICAgIGNob2ljZVJvdy5hcHBlbmRDaGlsZChsYmwpOwogICAgICAgICAgfQogICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2hvaWNlUm93KTsKCiAgICAgICAgICBpZiAoY2FuZC5kZWNpc2lvbiA9PT0gImNyZWRpdCIpIHsKICAgICAgICAgICAgY29uc3QgZW5kUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICAgIGVuZFJvdy5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1lbmRkYXRlIjsKICAgICAgICAgICAgY29uc3QgZW5kTGFiZWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICAgIGVuZExhYmVsLnRleHRDb250ZW50ID0gIkZpbiBlc3RpbcOpZSA6IjsKICAgICAgICAgICAgY29uc3QgZW5kSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICBlbmRJbnB1dC50eXBlID0gImRhdGUiOwogICAgICAgICAgICBlbmRJbnB1dC52YWx1ZSA9IGNhbmQuZW5kX2RhdGUgfHwgIiI7CiAgICAgICAgICAgIGVuZElucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsgY2FuZC5lbmRfZGF0ZSA9IGVuZElucHV0LnZhbHVlOyB9KTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZExhYmVsKTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZElucHV0KTsKICAgICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoZW5kUm93KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgZW5kZWROb3RlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBlbmRlZE5vdGUuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSI7CiAgICAgICAgICBlbmRlZE5vdGUudGV4dENvbnRlbnQgPSAiU2VtYmxlIHMnw6p0cmUgYXJyw6p0w6llIHRvdXRlIHNldWxlIOKAlCBpbXBvcnTDqWUgdGVsbGUgcXVlbGxlLCBhdWN1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUuIjsKICAgICAgICAgIGVsLmFwcGVuZENoaWxkKGVuZGVkTm90ZSk7CiAgICAgICAgfQoKICAgICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmFwcGVuZENoaWxkKGVsKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRQcmV2aWV3KCkgewogICAgICBnZW5lcmljUm93c0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCByb3cgb2YgZ2VuZXJpY0ltcG9ydFJvd3MpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93IiArIChyb3cuc2VsZWN0ZWQgPyAiIiA6ICIgZXhjbHVkZWQiKTsKCiAgICAgICAgY29uc3QgY2hlY2tib3ggPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGNoZWNrYm94LnR5cGUgPSAiY2hlY2tib3giOwogICAgICAgIGNoZWNrYm94LmNoZWNrZWQgPSByb3cuc2VsZWN0ZWQ7CiAgICAgICAgY2hlY2tib3guYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgcm93LnNlbGVjdGVkID0gY2hlY2tib3guY2hlY2tlZDsKICAgICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImV4Y2x1ZGVkIiwgIXJvdy5zZWxlY3RlZCk7CiAgICAgICAgICB1cGRhdGVHZW5lcmljSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgICAgIH0pOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tYWluIjsKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kZXNjIjsKICAgICAgICBjb25zdCBhbW91bnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudFNwYW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctYW1vdW50ICIgKyByb3cudHlwZTsKICAgICAgICBhbW91bnRTcGFuLnRleHRDb250ZW50ID0gKHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyAiLSIgOiAiKyIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHJvdy5hbW91bnQpOwogICAgICAgIGRlc2MuYXBwZW5kKChyb3cucmVjdXJyaW5nX2dyb3VwX2lkID8gIvCflIEgIiA6ICIiKSArIChyb3cuZGVzY3JpcHRpb24gfHwgIiIpICsgIiDigJQgIik7CiAgICAgICAgZGVzYy5hcHBlbmRDaGlsZChhbW91bnRTcGFuKTsKCiAgICAgICAgY29uc3QgbWV0YSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1ldGEuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWV0YSI7CiAgICAgICAgbWV0YS50ZXh0Q29udGVudCA9IHJvdy5kYXRlX3ByZWNpc2lvbiA9PT0gImRheSIKICAgICAgICAgID8gYCR7cm93LmV4cGVuc2VfZGF0ZX0gwrcgJHtyb3cuc291cmNlX2xhYmVsfWAKICAgICAgICAgIDogYCR7cm93LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA3KX0gKGpvdXIgbm9uIHByw6ljaXPDqSkgwrcgJHtyb3cuc291cmNlX2xhYmVsfWA7CiAgICAgICAgaWYgKHJvdy5saWtlbHlfZHVwbGljYXRlKSB7CiAgICAgICAgICBjb25zdCBkdXBTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZHVwU3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kdXAiOwogICAgICAgICAgZHVwU3Bhbi50ZXh0Q29udGVudCA9ICIgwrcgZMOpasOgIHByw6lzZW50ZSA/IjsKICAgICAgICAgIG1ldGEuYXBwZW5kQ2hpbGQoZHVwU3Bhbik7CiAgICAgICAgfQoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobWV0YSk7CgogICAgICAgIGNvbnN0IGNhdFNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGNvbnN0IGxhYmVscyA9IHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyBnZW5lcmljSW1wb3J0Q2F0ZWdvcnlMYWJlbHMuZXhwZW5zZSA6IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5pbmNvbWU7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhsYWJlbHMpKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBpZiAodmFsdWUgPT09IHJvdy5jYXRlZ29yeSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICAgIGNhdFNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjYXRTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4geyByb3cuY2F0ZWdvcnkgPSBjYXRTZWxlY3QudmFsdWU7IH0pOwoKICAgICAgICBlbC5hcHBlbmRDaGlsZChjaGVja2JveCk7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2F0U2VsZWN0KTsKICAgICAgICBnZW5lcmljUm93c0xpc3RFbC5hcHBlbmRDaGlsZChlbCk7CiAgICAgIH0KICAgICAgdXBkYXRlR2VuZXJpY0ltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgIH0KCiAgICBnZW5lcmljRHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcmFnb3ZlciIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LmFkZCgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyYWdsZWF2ZSIsICgpID0+IHsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGdlbmVyaWNEcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgICBjb25zdCBmaWxlID0gZS5kYXRhVHJhbnNmZXIuZmlsZXMgJiYgZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBjb25zdCBkdCA9IG5ldyBEYXRhVHJhbnNmZXIoKTsKICAgICAgZHQuaXRlbXMuYWRkKGZpbGUpOwogICAgICBnZW5lcmljRmlsZUlucHV0LmZpbGVzID0gZHQuZmlsZXM7CiAgICB9KTsKCiAgICBnZW5lcmljQW5hbHl6ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IGdlbmVyaWNGaWxlSW5wdXQuZmlsZXMgJiYgZ2VuZXJpY0ZpbGVJbnB1dC5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSB7IHNob3dUb2FzdCgiQ2hvaXNpcyBkJ2Fib3JkIHVuIGZpY2hpZXIgLmNzdiBvdSAueGxzeCIsIHRydWUpOyByZXR1cm47IH0KICAgICAgY29uc3QgbG93ZXJOYW1lID0gZmlsZS5uYW1lLnRvTG93ZXJDYXNlKCk7CiAgICAgIGlmICghbG93ZXJOYW1lLmVuZHNXaXRoKCIuY3N2IikgJiYgIWxvd2VyTmFtZS5lbmRzV2l0aCgiLnhsc3giKSkgewogICAgICAgIHNob3dUb2FzdCgiRm9ybWF0cyBhY2NlcHTDqXMgOiAuY3N2IG91IC54bHN4IiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiBNQVhfR0VORVJJQ19JTVBPUlRfRklMRV9TSVpFX0JZVEVTKSB7CiAgICAgICAgc2hvd1RvYXN0KCJGaWNoaWVyIHRyb3Agdm9sdW1pbmV1eCAoMyBNbyBtYXhpbXVtKSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQ7CiAgICAgIGdlbmVyaWNBbmFseXplQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3VycyAoSUEp4oCmIjsKICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBnZW5lcmljUmVjdXJyaW5nU2VjdGlvbkVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBnZW5lcmljUHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgZmlsZSk7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvaW1wb3J0L2dlbmVyaWMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGV4dHJhY3RFcnJvckRldGFpbChlcnIsIGDDiWNoZWMgZGUgbCdhbmFseXNlICgke3Jlcy5zdGF0dXN9KWApKTsKICAgICAgICB9CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgZ2VuZXJpY0ltcG9ydENhdGVnb3J5TGFiZWxzID0gewogICAgICAgICAgZXhwZW5zZTogZGF0YS5leHBlbnNlX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgICBpbmNvbWU6IGRhdGEuaW5jb21lX2NhdGVnb3JpZXMgfHwge30sCiAgICAgICAgfTsKICAgICAgICBnZW5lcmljSW1wb3J0Um93cyA9IGRhdGEucm93cy5tYXAoKHJvdykgPT4gKHsKICAgICAgICAgIC4uLnJvdywKICAgICAgICAgIHNlbGVjdGVkOiAhcm93Lmxpa2VseV9kdXBsaWNhdGUsCiAgICAgICAgfSkpOwogICAgICAgIGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzID0gKGRhdGEucmVjdXJyaW5nX2NhbmRpZGF0ZXMgfHwgW10pLm1hcCgoY2FuZCkgPT4gKHsKICAgICAgICAgIC4uLmNhbmQsCiAgICAgICAgICBkZWNpc2lvbjogY2FuZC5jbGFzc2lmaWNhdGlvbiA9PT0gImNyZWRpdCIgPyAiY3JlZGl0IiA6IGNhbmQuY2xhc3NpZmljYXRpb24gPT09ICJlbmRlZCIgPyAiaWdub3JlIiA6ICJyZWN1cnJpbmciLAogICAgICAgICAgZW5kX2RhdGU6IGNhbmQuc3VnZ2VzdGVkX2VuZF9kYXRlIHx8IG51bGwsCiAgICAgICAgfSkpOwoKICAgICAgICBsZXQgc3VtbWFyeSA9IGA8c3Ryb25nPiR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RofTwvc3Ryb25nPiBvcMOpcmF0aW9uJHtnZW5lcmljSW1wb3J0Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9IGTDqXRlY3TDqWUke2dlbmVyaWNJbXBvcnRSb3dzLmxlbmd0aCA+IDEgPyAicyIgOiAiIn0gcGFyIGwnSUFgOwogICAgICAgIGNvbnN0IHRvQ29uZmlybSA9IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzLmZpbHRlcigoYykgPT4gYy5uZWVkc19jb25maXJtYXRpb24pLmxlbmd0aDsKICAgICAgICBpZiAodG9Db25maXJtKSBzdW1tYXJ5ICs9IGAg4oCUIDxzdHJvbmc+JHt0b0NvbmZpcm19PC9zdHJvbmc+IG1vdGlmJHt0b0NvbmZpcm0gPiAxID8gInMiIDogIiJ9IGRlIHLDqWN1cnJlbmNlIMOgIGNvbmZpcm1lciBjaS1kZXNzb3VzYDsKICAgICAgICBpZiAoZGF0YS53YXJuaW5ncyAmJiBkYXRhLndhcm5pbmdzLmxlbmd0aCkgewogICAgICAgICAgc3VtbWFyeSArPSAiPGJyPiIgKyBkYXRhLndhcm5pbmdzLm1hcCgodykgPT4gYOKaoO+4jyAke3d9YCkuam9pbigiPGJyPiIpOwogICAgICAgIH0KICAgICAgICBnZW5lcmljU3VtbWFyeUVsLmlubmVySFRNTCA9IHN1bW1hcnk7CiAgICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgICAgaWYgKGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzLmxlbmd0aCkgewogICAgICAgICAgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICAgIHJlbmRlckdlbmVyaWNJbXBvcnRSZWN1cnJpbmdMaXN0KCk7CiAgICAgICAgfQogICAgICAgIGdlbmVyaWNQcmV2aWV3RWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgcmVuZGVyR2VuZXJpY0ltcG9ydFByZXZpZXcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGdlbmVyaWNBbmFseXplQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC10b2dnbGUtYWxsLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICBjb25zdCBhbnlTZWxlY3RlZCA9IGdlbmVyaWNJbXBvcnRSb3dzLnNvbWUoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBmb3IgKGNvbnN0IHJvdyBvZiBnZW5lcmljSW1wb3J0Um93cykgcm93LnNlbGVjdGVkID0gIWFueVNlbGVjdGVkOwogICAgICByZW5kZXJHZW5lcmljSW1wb3J0UHJldmlldygpOwogICAgfSk7CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImdlbmVyaWMtaW1wb3J0LWNvbW1pdC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgc2VsZWN0ZWQgPSBnZW5lcmljSW1wb3J0Um93cy5maWx0ZXIoKHIpID0+IHIuc2VsZWN0ZWQpOwogICAgICBpZiAoc2VsZWN0ZWQubGVuZ3RoID09PSAwKSByZXR1cm47CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgYEltcG9ydGVyICR7c2VsZWN0ZWQubGVuZ3RofSB0cmFuc2FjdGlvbiR7c2VsZWN0ZWQubGVuZ3RoID4gMSA/ICJzIiA6ICIifSA/IFbDqXJpZmllIGJpZW4gbGVzIGNhdMOpZ29yaWVzIGV0IGxlcyByw6ljdXJyZW5jZXMgYXZhbnQgZGUgY29uZmlybWVyLmAKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImdlbmVyaWMtaW1wb3J0LWNvbW1pdC1idG4iKTsKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gYnRuLnRleHRDb250ZW50OwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiSW1wb3J0IGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZWN1cnJpbmdQYXlsb2FkID0gZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMKICAgICAgICAgIC5maWx0ZXIoKGMpID0+IGMuZGVjaXNpb24gPT09ICJyZWN1cnJpbmciIHx8IGMuZGVjaXNpb24gPT09ICJjcmVkaXQiKQogICAgICAgICAgLm1hcCgoYykgPT4gKHsKICAgICAgICAgICAgdHlwZTogYy50eXBlLAogICAgICAgICAgICBuYW1lOiBjLm5hbWUsCiAgICAgICAgICAgIGFtb3VudDogYy5hbW91bnQsCiAgICAgICAgICAgIGNhdGVnb3J5OiBjLmNhdGVnb3J5LAogICAgICAgICAgICBkYXlfb2ZfbW9udGg6IDEsCiAgICAgICAgICAgIHN0YXJ0X2RhdGU6IGMuc3VnZ2VzdGVkX3N0YXJ0X2RhdGUsCiAgICAgICAgICAgIGVuZF9kYXRlOiBjLmRlY2lzaW9uID09PSAiY3JlZGl0IiA/IChjLmVuZF9kYXRlIHx8IG51bGwpIDogbnVsbCwKICAgICAgICAgIH0pKTsKICAgICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgICAgdHJhbnNhY3Rpb25zOiBzZWxlY3RlZC5tYXAoKHIpID0+ICh7CiAgICAgICAgICAgIGV4cGVuc2VfZGF0ZTogci5leHBlbnNlX2RhdGUsCiAgICAgICAgICAgIHR5cGU6IHIudHlwZSwKICAgICAgICAgICAgYW1vdW50OiByLmFtb3VudCwKICAgICAgICAgICAgY2F0ZWdvcnk6IHIuY2F0ZWdvcnksCiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiByLmRlc2NyaXB0aW9uLAogICAgICAgICAgfSkpLAogICAgICAgICAgcmVjdXJyaW5nOiByZWN1cnJpbmdQYXlsb2FkLAogICAgICAgIH07CiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvaW1wb3J0L2dlbmVyaWMvY29tbWl0IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBjb25zdCBwYXJ0cyA9IFtdOwogICAgICAgIGlmIChyZXN1bHQuaW5zZXJ0ZWRfdHJhbnNhY3Rpb25zKSBwYXJ0cy5wdXNoKGAke3Jlc3VsdC5pbnNlcnRlZF90cmFuc2FjdGlvbnN9IHRyYW5zYWN0aW9uJHtyZXN1bHQuaW5zZXJ0ZWRfdHJhbnNhY3Rpb25zID4gMSA/ICJzIiA6ICIifWApOwogICAgICAgIGlmIChyZXN1bHQuaW5zZXJ0ZWRfcmVjdXJyaW5nKSBwYXJ0cy5wdXNoKGAke3Jlc3VsdC5pbnNlcnRlZF9yZWN1cnJpbmd9IGNoYXJnZSR7cmVzdWx0Lmluc2VydGVkX3JlY3VycmluZyA+IDEgPyAicyIgOiAiIn0gcsOpY3VycmVudGUke3Jlc3VsdC5pbnNlcnRlZF9yZWN1cnJpbmcgPiAxID8gInMiIDogIiJ9YCk7CiAgICAgICAgc2hvd1RvYXN0KHBhcnRzLmxlbmd0aCA/IGBJbXBvcnTDqSA6ICR7cGFydHMuam9pbigiIGV0ICIpfWAgOiAiSW1wb3J0IHRlcm1pbsOpIik7CiAgICAgICAgZ2VuZXJpY0ltcG9ydFJvd3MgPSBbXTsKICAgICAgICBnZW5lcmljSW1wb3J0Q2FuZGlkYXRlcyA9IFtdOwogICAgICAgIGdlbmVyaWNQcmV2aWV3RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICBnZW5lcmljU3VtbWFyeUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgZ2VuZXJpY0ZpbGVJbnB1dC52YWx1ZSA9ICIiOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICBsb2FkUmVjdXJyaW5nKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVzZXQtYWxsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG9rID0gYXdhaXQgc2hvd0NvbmZpcm0oCiAgICAgICAgIlN1cHByaW1lciBEw4lGSU5JVElWRU1FTlQgdG91dGVzIGxlcyBkb25uw6llcyAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcykgPyBDZXR0ZSBhY3Rpb24gZXN0IGlycsOpdmVyc2libGUuIgogICAgICApOwogICAgICBpZiAoIW9rKSByZXR1cm47CiAgICAgIC8vIERvdWJsZSBjb25maXJtYXRpb24gdnUgbGUgY2FyYWN0w6hyZSBpcnLDqXZlcnNpYmxlIGV0IGNvbXBsZXQgZGUgbCdhY3Rpb24uCiAgICAgIGNvbnN0IG9rMiA9IGF3YWl0IHNob3dDb25maXJtKCJEZXJuacOocmUgY29uZmlybWF0aW9uIDogdnJhaW1lbnQgdG91dCByw6lpbml0aWFsaXNlciA/Iik7CiAgICAgIGlmICghb2syKSByZXR1cm47CgogICAgICBjb25zdCBidG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpOwogICAgICBidG4uZGlzYWJsZWQgPSB0cnVlOwogICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL3Jlc2V0LWFsbCIsIHsgbWV0aG9kOiAiREVMRVRFIiB9KTsKICAgICAgICBzaG93VG9hc3QoIkFwcGxpY2F0aW9uIHLDqWluaXRpYWxpc8OpZSIpOwogICAgICAgIHNldFRpbWVvdXQoKCkgPT4gd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpLCA2MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyAoZXJyLm1lc3NhZ2UgfHwgInVuZSBlcnJldXIgZXN0IHN1cnZlbnVlIiksIHRydWUpOwogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJSw6lpbml0aWFsaXNlciB0b3V0ZSBsJ2FwcGxpY2F0aW9uIjsKICAgICAgfQogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUFdBIDogaW5zdGFsbGF0aW9uIHN1ciBsJ8OpY3JhbiBkJ2FjY3VlaWwKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGlmICgic2VydmljZVdvcmtlciIgaW4gbmF2aWdhdG9yKSB7CiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJsb2FkIiwgKCkgPT4gewogICAgICAgIG5hdmlnYXRvci5zZXJ2aWNlV29ya2VyLnJlZ2lzdGVyKCIvc3cuanMiKS5jYXRjaCgoKSA9PiB7fSk7CiAgICAgIH0pOwogICAgfQoKICAgIHBvcHVsYXRlQ2F0ZWdvcmllcygiZXhwZW5zZSIpOwogICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKCiAgICAvLyBSaWVuIGRlIHRvdXQgw6dhIChjaGFyZ2VtZW50IGRlcyBkb25uw6llcywgcmFjY291cmNpcyBQV0EuLi4pIG5lIGRvaXQKICAgIC8vIGTDqW1hcnJlciBhdmFudCBkJ2F2b2lyIHVuIGpldG9uIGRlIHNlc3Npb24gdmFsaWRlIOKAlCBzaW5vbiBsYSBwcmVtacOocmUKICAgIC8vIHJlcXXDqnRlIMOpY2hvdWVyYWl0IGp1c3RlIGF2ZWMgdW5lIDQwMSDDoCBsYSBwbGFjZSBkZSBtb250cmVyIGxlIHZlcnJvdS4KICAgIGlmIChBUElfS0VZICYmICFpbnZpdGVUb2tlbkZyb21VcmwgJiYgIXJlc2V0VG9rZW5Gcm9tVXJsKSB7CiAgICAgIHNob3dBcHAoKTsKICAgICAgKGFzeW5jIGZ1bmN0aW9uIGluaXQoKSB7CiAgICAgICAgLy8gQ2F0w6lnb3JpZXMgcGVyc28gKyBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgZCdhYm9yZCwgcG91ciBxdWUgbGVzCiAgICAgICAgLy8gbGlzdGVzIGTDqXJvdWxhbnRlcyBldCBsZSBiYW5kZWF1IHNvaWVudCBjb3JyZWN0cyBkw6hzIGxlIHByZW1pZXIKICAgICAgICAvLyByZW5kdSBwbHV0w7R0IHF1ZSBkZSAic2F1dGVyIiB1bmUgZm9pcyBsZSBzZXJ2ZXVyIHLDqXBvbmR1LgogICAgICAgIGF3YWl0IFByb21pc2UuYWxsKFtsb2FkQ3VzdG9tQ2F0ZWdvcmllcygpLCBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSwgbG9hZEJ1ZGdldHMoKSwgbG9hZFNhdmluZ3NHb2FsKCldKTsKICAgICAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgICAgIGF3YWl0IGxvYWRUcmFuc2FjdGlvbnMoKTsKICAgICAgICBsb2FkUmVjdXJyaW5nKCk7CgogICAgICAgIC8vIFJhY2NvdXJjaXMgUFdBIChhcHB1aSBsb25nIHN1ciBsJ2ljw7RuZSBkZSBsJ2FwcCB1bmUgZm9pcyBpbnN0YWxsw6llKSA6CiAgICAgICAgLy8gLz9zaG9ydGN1dD1hZGQgb3V2cmUgZGlyZWN0ZW1lbnQgbGUgZm9ybXVsYWlyZSBkJ2Fqb3V0LCAvP3Nob3J0Y3V0PXZvaWNlCiAgICAgICAgLy8gbGFuY2UgZGlyZWN0ZW1lbnQgbGEgZGljdMOpZSB2b2NhbGUuCiAgICAgICAgY29uc3Qgc2hvcnRjdXRQYXJhbSA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCkuZ2V0KCJzaG9ydGN1dCIpOwogICAgICAgIGlmIChzaG9ydGN1dFBhcmFtKSB7CiAgICAgICAgICAvLyBOZXR0b2llIGwnVVJMIHRvdXQgZGUgc3VpdGUgOiB1biByZWNoYXJnZW1lbnQgZGUgbGEgcGFnZSAob3UgdW4KICAgICAgICAgIC8vIHBhcnRhZ2UgZHUgbGllbikgbmUgZG9pdCBwYXMgcmVkw6ljbGVuY2hlciBsZSByYWNjb3VyY2kuCiAgICAgICAgICB3aW5kb3cuaGlzdG9yeS5yZXBsYWNlU3RhdGUoe30sICIiLCB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWUpOwogICAgICAgICAgaWYgKHNob3J0Y3V0UGFyYW0gPT09ICJhZGQiKSB7CiAgICAgICAgICAgIG9wZW5Nb2RhbCgpOwogICAgICAgICAgfSBlbHNlIGlmIChzaG9ydGN1dFBhcmFtID09PSAidm9pY2UiICYmICFtaWNCdG4uZGlzYWJsZWQpIHsKICAgICAgICAgICAgbWljQnRuLmNsaWNrKCk7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9KSgpOwogICAgfSBlbHNlIHsKICAgICAgc2hvd0xvY2tTY3JlZW4oaW5pdGlhbEF1dGhWaWV3KTsKICAgIH0KICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg=="
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
    ws_rec.append(["Type", "Nom", "Montant (€)", "Catégorie", "Jour du mois", "Date de début", "Date de fin"])
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
        ])
        ws_rec.cell(row=ws_rec.max_row, column=3).font = Font(
            color=COLOR_INCOME if rec_type == "income" else COLOR_EXPENSE
        )
    for col_letter, width in zip("ABCDEFG", [10, 24, 12, 14, 12, 14, 14]):
        ws_rec.column_dimensions[col_letter].width = width

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
        raise HTTPException(status_code=502, detail=f"Erreur API Anthropic : {exc}") from exc

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
