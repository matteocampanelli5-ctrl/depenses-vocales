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
FRONTEND_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2FjaGluZzwvdGl0bGU+CjxsaW5rIHJlbD0ibWFuaWZlc3QiIGhyZWY9Ii9tYW5pZmVzdC53ZWJtYW5pZmVzdCI+CjxtZXRhIG5hbWU9InRoZW1lLWNvbG9yIiBjb250ZW50PSIjMGYxMTE1Ij4KPGxpbmsgcmVsPSJpY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPGxpbmsgcmVsPSJhcHBsZS10b3VjaC1pY29uIiBocmVmPSIvaWNvbi0xOTIucG5nIj4KPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KPG1ldGEgbmFtZT0iYXBwbGUtbW9iaWxlLXdlYi1hcHAtc3RhdHVzLWJhci1zdHlsZSIgY29udGVudD0iYmxhY2stdHJhbnNsdWNlbnQiPgo8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC10aXRsZSIgY29udGVudD0iS2FjaGluZyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcyIgb25lcnJvcj0iY29uc29sZS5lcnJvcignQ2hhcnQuanMgOiDDqWNoZWMgZHUgcHJlbWllciBjaGFyZ2VtZW50IGRlcHVpcyBsZSBDRE4uJykiPjwvc2NyaXB0Pgo8c3R5bGU+CiAgOnJvb3QgewogICAgY29sb3Itc2NoZW1lOiBkYXJrOwogICAgLS1iZzogIzBmMTExNTsKICAgIC0tc3VyZmFjZTogIzFhMWQyNDsKICAgIC0tc3VyZmFjZS0yOiAjMjIyNjJmOwogICAgLS1ib3JkZXI6ICMyYTJlMzg7CiAgICAtLXRleHQ6ICNlNmU2ZTY7CiAgICAtLXRleHQtZGltOiAjOWFhMGFjOwogICAgLS1hY2NlbnQ6ICMzYjgyZjY7CiAgICAtLWFjY2VudC1kaW06ICMxZDRlZDg7CiAgICAtLWRhbmdlcjogI2VmNDQ0NDsKICAgIC0tc3VjY2VzczogIzIyYzU1ZTsKICAgIC0tcmFkaXVzOiAxNHB4OwogIH0KICAqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogIGJvZHkgewogICAgbWFyZ2luOiAwOwogICAgbWluLWhlaWdodDogMTAwdmg7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAiU2Vnb2UgVUkiLCBSb2JvdG8sIHNhbnMtc2VyaWY7CiAgICBwYWRkaW5nLWJvdHRvbTogNnJlbTsKICB9CiAgaGVhZGVyIHsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIDFyZW07CiAgICBtYXgtd2lkdGg6IDY0MHB4OwogICAgbWFyZ2luOiAwIGF1dG87CiAgICBwb3NpdGlvbjogcmVsYXRpdmU7CiAgfQogIGgxIHsgZm9udC1zaXplOiAxLjNyZW07IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAuc3VidGl0bGUgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuOXJlbTsgbWFyZ2luOiAwOyB9CgogIC50YWJzIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGZsZXgtd3JhcDogd3JhcDsKICAgIGdhcDogMC41cmVtOwogIH0KICAudGFiLWJ0biB7CiAgICBmbGV4OiAxOwogICAgbWluLXdpZHRoOiAxMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50YWItYnRuLmFjdGl2ZSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgY29sb3I6IHdoaXRlOyB9CgogIC8qIFN1ciBwZXRpdCDDqWNyYW4sIGxhIGJhcnJlIGQnb25nbGV0cyBkZXZpZW50IHVuIHRpcm9pciAobWVudSAiYnVyZ2VyIikKICAgICBwbHV0w7R0IHF1ZSBkZSBzJ8OpY3Jhc2VyIGVuIHBsdXNpZXVycyBsaWduZXMgOiBwbHVzIGRlIHBsYWNlIHBvdXIgbGUKICAgICBjb250ZW51LCBldCBkZXMgbGliZWxsw6lzIHRvdWpvdXJzIGxpc2libGVzIGVuIGVudGllci4gKi8KICAubWVudS10b2dnbGUtYnRuIHsKICAgIGRpc3BsYXk6IG5vbmU7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICB0b3A6IDFyZW07CiAgICBsZWZ0OiAxcmVtOwogICAgei1pbmRleDogMzA7CiAgICB3aWR0aDogNDJweDsKICAgIGhlaWdodDogNDJweDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuMnJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgLm5hdi1kcmF3ZXItYmFja2Ryb3AgewogICAgZGlzcGxheTogbm9uZTsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjU1KTsKICAgIHotaW5kZXg6IDI1OwogIH0KICBAbWVkaWEgKG1heC13aWR0aDogNjQwcHgpIHsKICAgIC5tZW51LXRvZ2dsZS1idG4geyBkaXNwbGF5OiBmbGV4OyB9CiAgICBoZWFkZXIgeyBwYWRkaW5nLWxlZnQ6IDMuNzVyZW07IH0KICAgIC50YWJzIHsKICAgICAgcG9zaXRpb246IGZpeGVkOwogICAgICB0b3A6IDA7CiAgICAgIGxlZnQ6IDA7CiAgICAgIGJvdHRvbTogMDsKICAgICAgZmxleC13cmFwOiBub3dyYXA7CiAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgICAgIHdpZHRoOiAyNDBweDsKICAgICAgbWF4LXdpZHRoOiA4MHZ3OwogICAgICBtYXJnaW46IDA7CiAgICAgIHBhZGRpbmc6IDQuNXJlbSAxcmVtIDEuNXJlbTsKICAgICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICAgIGJvcmRlci1yaWdodDogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICAgIHotaW5kZXg6IDI2OwogICAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTEwMCUpOwogICAgICB0cmFuc2l0aW9uOiB0cmFuc2Zvcm0gMC4ycyBlYXNlOwogICAgICBvdmVyZmxvdy15OiBhdXRvOwogICAgfQogICAgLnRhYi1idG4geyBmbGV4OiBub25lOyB3aWR0aDogMTAwJTsgdGV4dC1hbGlnbjogbGVmdDsgfQogICAgYm9keS5uYXYtZHJhd2VyLW9wZW4gLnRhYnMgeyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoMCk7IH0KICAgIGJvZHkubmF2LWRyYXdlci1vcGVuIC5uYXYtZHJhd2VyLWJhY2tkcm9wIHsgZGlzcGxheTogYmxvY2s7IH0KICB9CgogIC5zdW1tYXJ5IHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0byAxcmVtOwogICAgcGFkZGluZzogMCAxLjI1cmVtOwogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC42cmVtOwogICAgZmxleC13cmFwOiB3cmFwOwogIH0KICAuc3VtbWFyeS1jYXJkIHsKICAgIGZsZXg6IDE7CiAgICBtaW4td2lkdGg6IDEwMHB4OwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIHBhZGRpbmc6IDAuOXJlbSAxcmVtOwogIH0KICAuc3VtbWFyeS1jYXJkIC5sYWJlbCB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luOiAwIDAgMC4yNXJlbTsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlIHsgZm9udC1zaXplOiAxLjJyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbjogMDsgfQogIC5zdW1tYXJ5LWNhcmQgLnZhbHVlLnBvc2l0aXZlIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnN1bW1hcnktY2FyZCAudmFsdWUubmVnYXRpdmUgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudG9vbHRpcC1ob3N0IHsgcG9zaXRpb246IHJlbGF0aXZlOyBjdXJzb3I6IGhlbHA7IH0KICAuY3VzdG9tLXRvb2x0aXAgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgbGVmdDogNTAlOwogICAgYm90dG9tOiBjYWxjKDEwMCUgKyAwLjZyZW0pOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpIHRyYW5zbGF0ZVkoNHB4KTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNTVyZW0gMC43NXJlbTsKICAgIGZvbnQtc2l6ZTogMC43OHJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogICAgdGV4dC1hbGlnbjogbGVmdDsKICAgIGJveC1zaGFkb3c6IDAgOHB4IDIwcHggcmdiYSgwLCAwLCAwLCAwLjM1KTsKICAgIG9wYWNpdHk6IDA7CiAgICBwb2ludGVyLWV2ZW50czogbm9uZTsKICAgIHRyYW5zaXRpb246IG9wYWNpdHkgMC4xMnMgZWFzZSwgdHJhbnNmb3JtIDAuMTJzIGVhc2U7CiAgICB6LWluZGV4OiAyMDsKICB9CiAgLmN1c3RvbS10b29sdGlwOjphZnRlciB7CiAgICBjb250ZW50OiAiIjsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHRvcDogMTAwJTsKICAgIGxlZnQ6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsKICAgIGJvcmRlcjogNnB4IHNvbGlkIHRyYW5zcGFyZW50OwogICAgYm9yZGVyLXRvcC1jb2xvcjogdmFyKC0tc3VyZmFjZS0yKTsKICB9CiAgLmN1c3RvbS10b29sdGlwLnZpc2libGUgewogICAgb3BhY2l0eTogMTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDApOwogICAgcG9pbnRlci1ldmVudHM6IGF1dG87CiAgfQoKICBtYWluIHsKICAgIG1heC13aWR0aDogNjQwcHg7CiAgICBtYXJnaW46IDAgYXV0bzsKICAgIHBhZGRpbmc6IDAgMS4yNXJlbTsKICB9CgogIC53ZWVrLXN1bW1hcnkgewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogLTAuNHJlbSBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwIDEuMjVyZW07CiAgICBmb250LXNpemU6IDAuODJyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgdGV4dC1hbGlnbjogY2VudGVyOwogIH0KCiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24gewogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIG1hcmdpbjogMCBhdXRvIDFyZW07CiAgICBwYWRkaW5nOiAwLjlyZW0gMS4xcmVtOwogICAgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1hY2NlbnQtZGltKTsKICB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24uaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5jYXRlZ29yeS1zdWdnZXN0aW9uIHAgeyBtYXJnaW46IDAgMCAwLjdyZW07IGZvbnQtc2l6ZTogMC44OHJlbTsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgeyBkaXNwbGF5OiBmbGV4OyBmbGV4LXdyYXA6IHdyYXA7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyB9CiAgLmNhdGVnb3J5LXN1Z2dlc3Rpb24tY29udHJvbHMgc2VsZWN0LAogIC5jYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIGlucHV0W3R5cGU9InRleHQiXSB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICBwYWRkaW5nOiAwLjRyZW0gMC42cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuYnRuLXByaW1hcnktc20sIC5idG4tc2Vjb25kYXJ5LXNtIHsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNHJlbSAwLjhyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5idG4tcHJpbWFyeS1zbSB7IGJhY2tncm91bmQ6IHZhcigtLWFjY2VudCk7IGNvbG9yOiAjZmZmOyB9CiAgLmJ0bi1zZWNvbmRhcnktc20geyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoKICAuZmlsdGVyLWJhciB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC13cmFwOiB3cmFwOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjlyZW07CiAgfQogIC5maWx0ZXItYmFyIGlucHV0LAogIC5maWx0ZXItYmFyIHNlbGVjdCB7CiAgICB3aWR0aDogYXV0bzsKICAgIGZsZXg6IDEgMSAxMzBweDsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICB9CiAgI2ZpbHRlci1zZWFyY2ggeyBmbGV4OiAxIDEgMTAwJTsgfQoKICAudHgtbGlzdCB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogMC42cmVtOyB9CgogIC50eC1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLnR4LWNhcmQuaW5jb21lIHsgYm9yZGVyLWxlZnQtY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWNhcmQuZXhwZW5zZSB7IGJvcmRlci1sZWZ0LWNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CgogIC50eC1tYWluIHsgZmxleDogMTsgbWluLXdpZHRoOiAwOyB9CiAgLnR4LXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyB9CiAgLmNhdGVnb3J5LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWRhdGUgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAudHgtcmVjdXJyaW5nLWJhZGdlIHsgZm9udC1zaXplOiAwLjc1cmVtOyBvcGFjaXR5OiAwLjc7IGN1cnNvcjogaGVscDsgfQogIC50eC1yZWNlaXB0LWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43NXJlbTsKICAgIG9wYWNpdHk6IDAuODU7CiAgICBiYWNrZ3JvdW5kOiBub25lOwogICAgYm9yZGVyOiBub25lOwogICAgcGFkZGluZzogMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGxpbmUtaGVpZ2h0OiAxOwogIH0KICAudHgtZGVzY3JpcHRpb24gewogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgb3ZlcmZsb3c6IGhpZGRlbjsKICAgIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogICAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKICB9CiAgLnR4LWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC50eC1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnR4LWFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CgogIC50eC1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAwLjNyZW07IGZsZXgtc2hyaW5rOiAwOyB9CiAgLmljb24tYnRuIHsKICAgIHdpZHRoOiAzMnB4OwogICAgaGVpZ2h0OiAzMnB4OwogICAgYm9yZGVyLXJhZGl1czogOHB4OwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogIH0KICAuaWNvbi1idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjMmQzMjNkOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICAuaWNvbi1idG4uZGFuZ2VyOmhvdmVyIHsgYmFja2dyb3VuZDogIzNhMWQxZDsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmVtcHR5LXN0YXRlIHsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBwYWRkaW5nOiAzcmVtIDFyZW07CiAgICBmb250LXNpemU6IDAuOTVyZW07CiAgfQoKICAuZGFzaGJvYXJkLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLmRhc2hib2FyZC1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuZGFzaGJvYXJkLXJvdyB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMXJlbSAxLjFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyBoMyB7CiAgICBtYXJnaW46IDAgMCAwLjc1cmVtOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDYwMDsKICB9CiAgLmRhc2hib2FyZC1yb3cgLmRhc2hib2FyZC1oZWFkIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgZ2FwOiAwLjVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogIH0KICAuZGFzaGJvYXJkLXJvdyAuZGFzaGJvYXJkLWhlYWQgaDMgeyBtYXJnaW46IDA7IH0KICAuZGFzaGJvYXJkLXJvdyBzZWxlY3QgewogICAgd2lkdGg6IGF1dG87CiAgICBtaW4td2lkdGg6IDE0MHB4OwogIH0KICAuY2hhcnQtd3JhcCB7IHBvc2l0aW9uOiByZWxhdGl2ZTsgaGVpZ2h0OiAyNDBweDsgfQogIC5kYXNoYm9hcmQtZW1wdHkgewogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHBhZGRpbmc6IDJyZW0gMDsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICB9CiAgLmNhdGVnb3J5LWNoYXJ0LXJvdyAuY2hhcnQtd3JhcCB7IGZsZXg6IDE7IG1pbi13aWR0aDogMDsgfQoKICAvKiBTw6lsZWN0ZXVyIGR1IHRhYmxlYXUgZGUgYm9yZCA6IHVuIHNldWwgZ3JhcGhpcXVlL2Jsb2MgYWZmaWNow6kgw6AgbGEgZm9pcwogICAgIChhdSBsaWV1IGRlcyA3IGVtcGlsw6lzKSwgY2hvaXNpIHZpYSB1bmUgcmFuZ8OpZSBkZSBwdWNlcyBkw6lmaWxhbnRlLiAqLwogIC5kYXNoYm9hcmQtY2hpcC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGdhcDogMC41cmVtOwogICAgb3ZlcmZsb3cteDogYXV0bzsKICAgIHBhZGRpbmctYm90dG9tOiAwLjI1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMXJlbTsKICAgIC13ZWJraXQtb3ZlcmZsb3ctc2Nyb2xsaW5nOiB0b3VjaDsKICB9CiAgLmRhc2hib2FyZC1jaGlwLXJvdzo6LXdlYmtpdC1zY3JvbGxiYXIgeyBoZWlnaHQ6IDRweDsgfQogIC5kYXNoYm9hcmQtY2hpcCB7CiAgICBmbGV4OiBub25lOwogICAgcGFkZGluZzogMC41cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuZGFzaGJvYXJkLWNoaXAuYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICAuZGFzaGJvYXJkLXJvdy5kYXNoLWhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KCiAgLnllYXJseS1zdW1tYXJ5IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBnYXA6IDAuNnJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuOXJlbTsKICB9CiAgLnllYXJseS1zdGF0IHsKICAgIGZsZXg6IDE7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjdyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC4ycmVtOwogIH0KICAueWVhcmx5LXN0YXQtbGFiZWwgeyBmb250LXNpemU6IDAuNzVyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUgeyBmb250LXNpemU6IDEuMDVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAueWVhcmx5LXN0YXQtdmFsdWUuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLnllYXJseS1zdGF0LXZhbHVlLmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC51cGNvbWluZy1ub3RlIHsKICAgIHdpZHRoOiA5NnB4OwogICAgZmxleC1zaHJpbms6IDA7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNHJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwLjRyZW07CiAgICBib3JkZXI6IDFweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuNzJyZW07CiAgICBsaW5lLWhlaWdodDogMS4yNTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgfQogIC51cGNvbWluZy1ub3RlLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctc3dhdGNoIHsKICAgIHdpZHRoOiAyOHB4OwogICAgaGVpZ2h0OiAxNHB4OwogICAgYm9yZGVyOiAxLjVweCBkYXNoZWQgdmFyKC0tZGFuZ2VyKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMik7CiAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgfQogIC51cGNvbWluZy1ub3RlLnBvc2l0aXZlIC51cGNvbWluZy1zd2F0Y2ggewogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1zdWNjZXNzKTsKICAgIGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMik7CiAgfQoKICAucmVjdXJyaW5nLXNlY3Rpb24geyBkaXNwbGF5OiBub25lOyB9CiAgLnJlY3VycmluZy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQogIC5leHBvcnQtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuZXhwb3J0LXNlY3Rpb24udmlzaWJsZSB7IGRpc3BsYXk6IGJsb2NrOyB9CgogIC5leHBvcnQtZm9ybWF0LXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOyB9CiAgLmV4cG9ydC1mb3JtYXQtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjZyZW0gMC40cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC44NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5leHBvcnQtZm9ybWF0LWJ0bi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBib3JkZXItY29sb3I6IHZhcigtLWFjY2VudCk7IGNvbG9yOiB3aGl0ZTsgfQoKICAvKiBJbXBvcnQgZGUgcmVsZXbDqSBiYW5jYWlyZSAqLwogIC5pbXBvcnQtZmlsZS1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNXJlbTsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtZmlsZS1yb3cgaW5wdXRbdHlwZT0iZmlsZSJdIHsgZmxleDogMTsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuaW1wb3J0LWRyb3B6b25lIHsKICAgIGJvcmRlcjogMXB4IGRhc2hlZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIHBhZGRpbmc6IDAuNXJlbSAwLjc1cmVtIDAuNzVyZW07CiAgfQogIC5pbXBvcnQtZHJvcHpvbmUuZHJhZy1vdmVyIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyBiYWNrZ3JvdW5kOiByZ2JhKDU5LCAxMzAsIDI0NiwgMC4wOCk7IH0KICAuaW1wb3J0LWRyb3B6b25lLWhpbnQgeyBtYXJnaW46IDAuNHJlbSAwIDA7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgLmltcG9ydC1zdW1tYXJ5IHsKICAgIG1hcmdpbjogMC45cmVtIDA7CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogIH0KICAuaW1wb3J0LXN1bW1hcnkgc3Ryb25nIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLmltcG9ydC1wcmV2aWV3IHsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5pbXBvcnQtcHJldmlldy5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLmltcG9ydC1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBnYXA6IDAuNnJlbTsKICAgIHBhZGRpbmc6IDAuNnJlbSAwOwogICAgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgfQogIC5pbXBvcnQtcm93LmV4Y2x1ZGVkIHsgb3BhY2l0eTogMC40NTsgfQogIC5pbXBvcnQtcm93LW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAuaW1wb3J0LXJvdy1kZXNjIHsgZm9udC1zaXplOiAwLjg4cmVtOyBmb250LXdlaWdodDogNTAwOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuZXhwZW5zZSB7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmltcG9ydC1yb3ctZGVzYyAuaW1wb3J0LXJvdy1hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmltcG9ydC1yb3ctbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xcmVtOyB9CiAgLmltcG9ydC1yb3ctZHVwIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAuaW1wb3J0LXJvdyBzZWxlY3QgeyBmb250LXNpemU6IDAuOHJlbTsgbWF4LXdpZHRoOiAxMzBweDsgfQogIC5pbXBvcnQtYWN0aW9ucy1yb3cgewogICAgZGlzcGxheTogZmxleDsKICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICBtYXJnaW46IDAuNzVyZW0gMDsKICAgIGZvbnQtc2l6ZTogMC44MnJlbTsKICB9CiAgLmltcG9ydC1hY3Rpb25zLXJvdyBidXR0b24geyBiYWNrZ3JvdW5kOiBub25lOyBib3JkZXI6IG5vbmU7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyBjdXJzb3I6IHBvaW50ZXI7IGZvbnQtc2l6ZTogMC44MnJlbTsgcGFkZGluZzogMDsgfQoKICAvKiBJbXBvcnQgZ8OpbsOpcmlxdWUgSUEg4oCUIGJhbmRlYXUgZGUgcsOpY3VycmVuY2VzIGTDqXRlY3TDqWVzICovCiAgLnJlY3VycmluZy1jYW5kaWRhdGVzLWxpc3QgeyBtYXJnaW46IDAuNzVyZW0gMDsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlIHsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42cmVtIDAuNzVyZW07CiAgICBtYXJnaW4tYm90dG9tOiAwLjVyZW07CiAgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLm5lZWRzLWNvbmZpcm1hdGlvbiB7IGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMDcpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtaGVhZGVyIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogYmFzZWxpbmU7IGdhcDogMC41cmVtOyBmb250LXNpemU6IDAuODhyZW07IGZvbnQtd2VpZ2h0OiA1MDA7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcgeyBmb250LXNpemU6IDAuN3JlbTsgZm9udC13ZWlnaHQ6IDYwMDsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgbGV0dGVyLXNwYWNpbmc6IDAuMDNlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5jcmVkaXQgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLXRhZy5yZWN1cnJpbmcgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjdXJyaW5nLWNhbmRpZGF0ZS10YWcuZW5kZWQgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtdGFnLnVuY2VydGFpbiB7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSB7IGZvbnQtc2l6ZTogMC43NXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgbWFyZ2luLXRvcDogMC4xNXJlbTsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWNob2ljZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC45cmVtOyBtYXJnaW4tdG9wOiAwLjU1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IGZvbnQtc2l6ZTogMC44cmVtOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIGxhYmVsIHsgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAwLjNyZW07IGN1cnNvcjogcG9pbnRlcjsgfQogIC5yZWN1cnJpbmctY2FuZGlkYXRlLWVuZGRhdGUgeyBtYXJnaW4tdG9wOiAwLjQ1cmVtOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDAuNHJlbTsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLnJlY3VycmluZy1jYW5kaWRhdGUtZW5kZGF0ZSBpbnB1dFt0eXBlPSJkYXRlIl0geyBmb250LXNpemU6IDAuOHJlbTsgfQoKICAvKiBTaW11bGF0aW9uIGRlIHBsYWNlbWVudCAow6lwYXJnbmUpICovCiAgLnBsYWNlbWVudC1pbnB1dHMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogMC43NXJlbTsgbWFyZ2luLWJvdHRvbTogMXJlbTsgfQogIC5wbGFjZW1lbnQtaW5wdXRzIGxhYmVsIHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogMC4yNXJlbTsgfQogIC5wbGFjZW1lbnQtcmVzdWx0IHsKICAgIG1hcmdpbi10b3A6IDAuOXJlbTsKICAgIHBhZGRpbmc6IDAuOHJlbSAwLjlyZW07CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGZvbnQtc2l6ZTogMC44OHJlbTsKICB9CiAgLnBsYWNlbWVudC1yZXN1bHQgc3Ryb25nIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnNhdmluZ3Mtc2VjdGlvbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuc2F2aW5ncy1zZWN0aW9uLnZpc2libGUgeyBkaXNwbGF5OiBibG9jazsgfQoKICAuYnVkZ2V0cy1zYXZlLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogZmxleC1lbmQ7IG1hcmdpbi10b3A6IDAuNzVyZW07IH0KICAuc2F2aW5ncy1nb2FsLXJvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBhbGlnbi1pdGVtczogY2VudGVyOyB9CiAgLnNhdmluZ3MtZ29hbC1yb3cgaW5wdXQgeyBmbGV4OiAxOyB9CiAgLnNhdmluZ3MtcHJvZ3Jlc3MuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5zYXZpbmdzLXByb2dyZXNzLWxhYmVsIHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgbWFyZ2luOiAwLjhyZW0gMCAwLjM1cmVtOwogIH0KICAuc2F2aW5ncy1wcm9ncmVzcy1sYWJlbCBzdHJvbmcgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLmFkdmljZS1saXN0IHsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiAwLjZyZW07IG1hcmdpbi10b3A6IDAuNXJlbTsgfQogIC5hZHZpY2UtY2FyZCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZ2FwOiAwLjZyZW07CiAgICBhbGlnbi1pdGVtczogZmxleC1zdGFydDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC43cmVtIDAuODVyZW07CiAgICBmb250LXNpemU6IDAuOXJlbTsKICAgIGxpbmUtaGVpZ2h0OiAxLjQ7CiAgfQogIC5hZHZpY2UtY2FyZCAuYWR2aWNlLWljb24geyBmb250LXNpemU6IDEuMXJlbTsgZmxleC1zaHJpbms6IDA7IH0KICAuYWR2aWNlLWNhcmQucG9zaXRpdmUgeyBib3JkZXItbGVmdDogM3B4IHNvbGlkIHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmFkdmljZS1jYXJkLndhcm5pbmcgeyBib3JkZXItbGVmdDogM3B4IHNvbGlkICNmNTllMGI7IH0KICAuYWR2aWNlLWNhcmQuaW5mbyB7IGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsgfQogIC5yZWN1cnJpbmctaGludCB7CiAgICBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgbWFyZ2luOiAwIDAgMC45cmVtOwogIH0KCiAgLnVwY29taW5nLXJlY3VycmluZy1wYW5lbCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiB2YXIoLS1yYWRpdXMpOwogICAgcGFkZGluZzogMC44cmVtIDFyZW07CiAgICBtYXJnaW4tYm90dG9tOiAxcmVtOwogIH0KICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGg0IHsgbWFyZ2luOiAwIDAgMC42cmVtOyBmb250LXNpemU6IDAuOXJlbTsgY29sb3I6IHZhcigtLXRleHQtZGltKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IHsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47CiAgICBhbGlnbi1pdGVtczogYmFzZWxpbmU7CiAgICBwYWRkaW5nOiAwLjM1cmVtIDA7CiAgICBmb250LXNpemU6IDAuODhyZW07CiAgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93ICsgLnVwY29taW5nLXJlY3VycmluZy1yb3cgeyBib3JkZXItdG9wOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5uYW1lIHsgY29sb3I6IHZhcigtLXRleHQpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmR1ZSB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGZvbnQtc2l6ZTogMC43OHJlbTsgbWFyZ2luLWxlZnQ6IDAuNHJlbTsgfQogIC51cGNvbWluZy1yZWN1cnJpbmctcm93IC5hbW91bnQuaW5jb21lIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnVwY29taW5nLXJlY3VycmluZy1yb3cgLmFtb3VudC5leHBlbnNlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KCiAgLmNvbXBhcmUtc2VsZWN0cyB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC42cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC45cmVtOwogICAgZmxleC13cmFwOiB3cmFwOwogIH0KICAuY29tcGFyZS1zZWxlY3RzIHNlbGVjdCB7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgIHBhZGRpbmc6IDAuNDVyZW0gMC42cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogIH0KICAuY29tcGFyZS1zZWxlY3RzIHNwYW4geyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXNpemU6IDAuODVyZW07IH0KCiAgLnNpbXBsZS10YWJsZSB7IHdpZHRoOiAxMDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LXNpemU6IDAuODVyZW07IH0KICAuc2ltcGxlLXRhYmxlIHRoLCAuc2ltcGxlLXRhYmxlIHRkIHsgcGFkZGluZzogMC41cmVtIDAuNnJlbTsgdGV4dC1hbGlnbjogcmlnaHQ7IH0KICAuc2ltcGxlLXRhYmxlIHRoOmZpcnN0LWNoaWxkLCAuc2ltcGxlLXRhYmxlIHRkOmZpcnN0LWNoaWxkIHsgdGV4dC1hbGlnbjogbGVmdDsgfQogIC5zaW1wbGUtdGFibGUgdGhlYWQgdGggeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBmb250LXdlaWdodDogNTAwOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgdGJvZHkgdHIgKyB0ciB0ZCB7IGJvcmRlci10b3A6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB9CiAgLnNpbXBsZS10YWJsZSB0Ym9keSB0ci50b3RhbC1yb3cgdGQgeyBmb250LXdlaWdodDogNjAwOyBib3JkZXItdG9wOiAycHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQogIC5zaW1wbGUtdGFibGUgLmRpZmYtcG9zaXRpdmUgeyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAuc2ltcGxlLXRhYmxlIC5kaWZmLW5lZ2F0aXZlIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IH0KICAudHJlbmQtdXAgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50cmVuZC1kb3duIHsgY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLnRyZW5kLWZsYXQgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CgogIC5idWRnZXQtcm93IHsgbWFyZ2luLWJvdHRvbTogMC45cmVtOyB9CiAgLmJ1ZGdldC1yb3ctaGVhZCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC41cmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgbWFyZ2luLWJvdHRvbTogMC4zNXJlbTsKICB9CiAgLmJ1ZGdldC1jYXQtbmFtZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5idWRnZXQtYW1vdW50cyB7IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC4zcmVtOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLmJ1ZGdldC1pbnB1dCB7CiAgICB3aWR0aDogNjRweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgYm9yZGVyLXJhZGl1czogNnB4OwogICAgcGFkZGluZzogMC4yNXJlbSAwLjRyZW07CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgfQogIC5idWRnZXQtYmFyLXRyYWNrIHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgYm9yZGVyLXJhZGl1czogOTk5cHg7IGhlaWdodDogOHB4OyBvdmVyZmxvdzogaGlkZGVuOyB9CiAgLmJ1ZGdldC1iYXItZmlsbCB7IGhlaWdodDogMTAwJTsgYm9yZGVyLXJhZGl1czogOTk5cHg7IHRyYW5zaXRpb246IHdpZHRoIDAuMnMgZWFzZTsgfQogIC5idWRnZXQtYmFyLWZpbGwub2sgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5idWRnZXQtYmFyLWZpbGwud2FybmluZyB7IGJhY2tncm91bmQ6ICNmNTllMGI7IH0KICAuYnVkZ2V0LWJhci1maWxsLm92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmJ1ZGdldC1oaXN0b3J5LXN0cmlwIHsgZGlzcGxheTogZmxleDsgZ2FwOiA0cHg7IG1hcmdpbi10b3A6IDAuNHJlbTsgfQogIC5oaXN0b3J5LWRvdCB7CiAgICBmbGV4OiAxOwogICAgaGVpZ2h0OiA2cHg7CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC5oaXN0b3J5LWRvdC5vayB7IGJhY2tncm91bmQ6IHZhcigtLXN1Y2Nlc3MpOyB9CiAgLmhpc3RvcnktZG90Lndhcm5pbmcgeyBiYWNrZ3JvdW5kOiAjZjU5ZTBiOyB9CiAgLmhpc3RvcnktZG90Lm92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1kYW5nZXIpOyB9CiAgLmhpc3RvcnktZG90LmVtcHR5IHsgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsgb3BhY2l0eTogMC41OyB9CiAgLnJlYy1jYXJkIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgIGJvcmRlci1sZWZ0OiAzcHggc29saWQgdmFyKC0tYWNjZW50KTsKICAgIGJvcmRlci1yYWRpdXM6IHZhcigtLXJhZGl1cyk7CiAgICBwYWRkaW5nOiAwLjg1cmVtIDFyZW07CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGdhcDogMC43NXJlbTsKICAgIG1hcmdpbi1ib3R0b206IDAuNnJlbTsKICB9CiAgLnJlYy1jYXJkLmV4cGVuc2UgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC5yZWMtY2FyZC5pbmNvbWUgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KICAucmVjLWNhcmQuZW5kZWQgeyBib3JkZXItbGVmdC1jb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBvcGFjaXR5OiAwLjY7IH0KICAucmVjLW1haW4geyBmbGV4OiAxOyBtaW4td2lkdGg6IDA7IH0KICAucmVjLXRvcCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMC41cmVtOyBtYXJnaW4tYm90dG9tOiAwLjE1cmVtOyBmbGV4LXdyYXA6IHdyYXA7IH0KICAucmVjLW5hbWUgeyBmb250LXNpemU6IDAuOTVyZW07IG92ZXJmbG93OiBoaWRkZW47IHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CiAgLnJlYy1zdWIgeyBmb250LXNpemU6IDAuNzhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IH0KICAuZW5kLWJhZGdlIHsKICAgIGZvbnQtc2l6ZTogMC43cmVtOwogICAgcGFkZGluZzogMC4xNXJlbSAwLjVyZW07CiAgICBib3JkZXItcmFkaXVzOiA5OTlweDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMjM5LCA2OCwgNjgsIDAuMTUpOwogICAgY29sb3I6ICNmY2E1YTU7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAuc3RhcnQtYmFkZ2UgewogICAgZm9udC1zaXplOiAwLjdyZW07CiAgICBwYWRkaW5nOiAwLjE1cmVtIDAuNXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDk5OXB4OwogICAgYmFja2dyb3VuZDogcmdiYSg1OSwgMTMwLCAyNDYsIDAuMTUpOwogICAgY29sb3I6ICM5M2M1ZmQ7CiAgICB3aGl0ZS1zcGFjZTogbm93cmFwOwogIH0KICAucmVjLWFtb3VudCB7IGZvbnQtd2VpZ2h0OiA2MDA7IGZvbnQtc2l6ZTogMS4wNXJlbTsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQogIC5yZWMtYW1vdW50LmluY29tZSB7IGNvbG9yOiB2YXIoLS1zdWNjZXNzKTsgfQogIC5yZWMtYW1vdW50LmV4cGVuc2UgeyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KCiAgLmZhYiB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICByaWdodDogMS4yNXJlbTsKICAgIGJvdHRvbTogMS4yNXJlbTsKICAgIHdpZHRoOiA1NnB4OwogICAgaGVpZ2h0OiA1NnB4OwogICAgYm9yZGVyLXJhZGl1czogNTAlOwogICAgYm9yZGVyOiBub25lOwogICAgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50KTsKICAgIGNvbG9yOiB3aGl0ZTsKICAgIGZvbnQtc2l6ZTogMS44cmVtOwogICAgbGluZS1oZWlnaHQ6IDE7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBib3gtc2hhZG93OiAwIDRweCAxNnB4IHJnYmEoNTksIDEzMCwgMjQ2LCAwLjQpOwogIH0KICAuZmFiOmFjdGl2ZSB7IHRyYW5zZm9ybTogc2NhbGUoMC45NSk7IH0KCiAgLmZhYi1taWMgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgcmlnaHQ6IDEuMjVyZW07CiAgICBib3R0b206IDUuMjVyZW07CiAgICB3aWR0aDogNTZweDsKICAgIGhlaWdodDogNTZweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICAgIGJveC1zaGFkb3c6IDAgNHB4IDE2cHggcmdiYSgwLCAwLCAwLCAwLjMpOwogICAgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAwLjJzLCBib3JkZXItY29sb3IgMC4yczsKICB9CiAgLmZhYi1taWM6YWN0aXZlIHsgdHJhbnNmb3JtOiBzY2FsZSgwLjk1KTsgfQogIC5mYWItbWljLmxpc3RlbmluZyB7CiAgICBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjIpOwogICAgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOwogICAgYW5pbWF0aW9uOiBwdWxzZSAxLjJzIGluZmluaXRlOwogIH0KICAuZmFiLW1pYy5wcm9jZXNzaW5nIHsgb3BhY2l0eTogMC42OyBjdXJzb3I6IGRlZmF1bHQ7IH0KICAuZmFiLW1pYzpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuMzU7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KICBAa2V5ZnJhbWVzIHB1bHNlIHsKICAgIDAlLCAxMDAlIHsgYm94LXNoYWRvdzogMCAwIDAgMCByZ2JhKDIzOSwgNjgsIDY4LCAwLjQpOyB9CiAgICA1MCUgeyBib3gtc2hhZG93OiAwIDAgMCAxMHB4IHJnYmEoMjM5LCA2OCwgNjgsIDApOyB9CiAgfQoKICAudm9pY2UtYmFubmVyIHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGJvdHRvbTogOS41cmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYm9yZGVyLXJhZGl1czogMTJweDsKICAgIHBhZGRpbmc6IDAuNnJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjg1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIG1heC13aWR0aDogODV2dzsKICAgIHRleHQtYWxpZ246IGNlbnRlcjsKICAgIHotaW5kZXg6IDE1OwogIH0KICAudm9pY2UtYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudm9pY2UtYmFubmVyLmFuc3dlciB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgZm9udC13ZWlnaHQ6IDYwMDsgbGluZS1oZWlnaHQ6IDEuNDsgfQoKICAudm9pY2UtY29uZmlybS1iYW5uZXIgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgYm90dG9tOiA5LjVyZW07CiAgICBsZWZ0OiA1MCU7CiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWFjY2VudCwgIzRhN2RmZik7CiAgICBib3JkZXItcmFkaXVzOiAxMnB4OwogICAgcGFkZGluZzogMC43NXJlbSAxcmVtOwogICAgZm9udC1zaXplOiAwLjlyZW07CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBtYXgtd2lkdGg6IDg1dnc7CiAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICB6LWluZGV4OiAxNjsKICB9CiAgLnZvaWNlLWNvbmZpcm0tYmFubmVyLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAudm9pY2UtY29uZmlybS1iYW5uZXIgcCB7IG1hcmdpbjogMCAwIDAuNnJlbTsgbGluZS1oZWlnaHQ6IDEuNDsgfQogIC52b2ljZS1jb25maXJtLWJhbm5lciAudm9pY2UtY29uZmlybS1oaW50IHsgZm9udC1zaXplOiAwLjc4cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW4tdG9wOiAwLjVyZW07IH0KICAudm9pY2UtY29uZmlybS1jb250cm9scyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgfQoKICAubW9kYWwtb3ZlcmxheSB7CiAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICBpbnNldDogMDsKICAgIGJhY2tncm91bmQ6IHJnYmEoMCwgMCwgMCwgMC41NSk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGZsZXgtZW5kOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAxMDsKICB9CiAgLm1vZGFsLW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogICNpbnB1dC1uZXctY2F0ZWdvcnktbmFtZS5oaWRkZW4geyBkaXNwbGF5OiBub25lOyB9CiAgLm1vZGFsIHsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwogICAgYm9yZGVyLXJhZGl1czogMThweCAxOHB4IDAgMDsKICAgIHBhZGRpbmc6IDEuNXJlbSAxLjI1cmVtIGNhbGMoMS41cmVtICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsKICAgIHdpZHRoOiAxMDAlOwogICAgbWF4LXdpZHRoOiA2NDBweDsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogICAgZ2FwOiAwLjlyZW07CiAgfQogIC5tb2RhbCBoMiB7IG1hcmdpbjogMCAwIDAuMjVyZW07IGZvbnQtc2l6ZTogMS4xcmVtOyB9CgogIGxhYmVsIHsgZm9udC1zaXplOiAwLjhyZW07IGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiAwLjNyZW07IH0KICBpbnB1dCwgc2VsZWN0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgcGFkZGluZzogMC42NXJlbSAwLjc1cmVtOwogICAgY29sb3I6IHZhcigtLXRleHQpOwogICAgZm9udC1zaXplOiAxcmVtOwogIH0KICBpbnB1dDpmb2N1cywgc2VsZWN0OmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9CgogIC50eXBlLXRvZ2dsZSB7IGRpc3BsYXk6IGZsZXg7IGdhcDogMC41cmVtOyB9CiAgLnR5cGUtYnRuIHsKICAgIGZsZXg6IDE7CiAgICBwYWRkaW5nOiAwLjY1cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOwogICAgY29sb3I6IHZhcigtLXRleHQtZGltKTsKICAgIGZvbnQtc2l6ZTogMC45NXJlbTsKICAgIGZvbnQtd2VpZ2h0OiA1MDA7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJleHBlbnNlIl0geyBiYWNrZ3JvdW5kOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjE1KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQogIC50eXBlLWJ0bi5hY3RpdmVbZGF0YS10eXBlPSJpbmNvbWUiXSB7IGJhY2tncm91bmQ6IHJnYmEoMzQsIDE5NywgOTQsIDAuMTUpOyBib3JkZXItY29sb3I6IHZhcigtLXN1Y2Nlc3MpOyBjb2xvcjogdmFyKC0tc3VjY2Vzcyk7IH0KCiAgLm1vZGFsLWFjdGlvbnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDAuNnJlbTsgbWFyZ2luLXRvcDogMC41cmVtOyB9CiAgLmNvbmZpcm0tbW9kYWwgeyBtYXgtd2lkdGg6IDQwMHB4OyB9CiAgLmNvbmZpcm0tbW9kYWwtbWVzc2FnZSB7IGNvbG9yOiB2YXIoLS10ZXh0KTsgZm9udC1zaXplOiAwLjk1cmVtOyBtYXJnaW46IDA7IGxpbmUtaGVpZ2h0OiAxLjQ7IH0KCiAgLmhpZGRlbi1maWxlLWlucHV0IHsgZGlzcGxheTogbm9uZTsgfQogIC5yZWNlaXB0LXByZXZpZXctd3JhcCB7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgIGdhcDogMC41cmVtOwogICAgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7CiAgICBtYXJnaW4tYm90dG9tOiAwLjVyZW07CiAgfQogIC5yZWNlaXB0LXByZXZpZXctaW1nIHsKICAgIG1heC13aWR0aDogMTAwJTsKICAgIG1heC1oZWlnaHQ6IDE2MHB4OwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBvYmplY3QtZml0OiBjb250YWluOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICB9CgogIC5saWdodGJveC1vdmVybGF5IHsKICAgIHBvc2l0aW9uOiBmaXhlZDsKICAgIGluc2V0OiAwOwogICAgYmFja2dyb3VuZDogcmdiYSgwLCAwLCAwLCAwLjg1KTsKICAgIGRpc3BsYXk6IGZsZXg7CiAgICBhbGlnbi1pdGVtczogY2VudGVyOwogICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICB6LWluZGV4OiAyMDsKICAgIHBhZGRpbmc6IDEuNXJlbTsKICB9CiAgLmxpZ2h0Ym94LW92ZXJsYXkuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5saWdodGJveC1pbWcgeyBtYXgtd2lkdGg6IDEwMCU7IG1heC1oZWlnaHQ6IDgwdmg7IGJvcmRlci1yYWRpdXM6IDEwcHg7IH0KICAubGlnaHRib3gtY2xvc2UgewogICAgcG9zaXRpb246IGFic29sdXRlOwogICAgdG9wOiAxcmVtOwogICAgcmlnaHQ6IDFyZW07CiAgICB3aWR0aDogNDBweDsKICAgIGhlaWdodDogNDBweDsKICAgIGJvcmRlci1yYWRpdXM6IDUwJTsKICAgIGJvcmRlcjogbm9uZTsKICAgIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UtMik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDEuMXJlbTsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnksIGJ1dHRvbi5zZWNvbmRhcnkgewogICAgZmxleDogMTsKICAgIHBhZGRpbmc6IDAuNzVyZW07CiAgICBib3JkZXItcmFkaXVzOiAxMHB4OwogICAgYm9yZGVyOiBub25lOwogICAgZm9udC1zaXplOiAwLjk1cmVtOwogICAgZm9udC13ZWlnaHQ6IDUwMDsKICAgIGN1cnNvcjogcG9pbnRlcjsKICB9CiAgYnV0dG9uLnByaW1hcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOyBjb2xvcjogd2hpdGU7IH0KICBidXR0b24ucHJpbWFyeTpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQogIGJ1dHRvbi5zZWNvbmRhcnkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlLTIpOyBjb2xvcjogdmFyKC0tdGV4dCk7IH0KICBidXR0b24uZGFuZ2VyIHsgYmFja2dyb3VuZDogcmdiYSgyMzksIDY4LCA2OCwgMC4xNSk7IGNvbG9yOiB2YXIoLS1kYW5nZXIpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1kYW5nZXIpOyB9CiAgYnV0dG9uLmRhbmdlcjpkaXNhYmxlZCB7IG9wYWNpdHk6IDAuNjsgfQoKICAuZGFuZ2VyLXpvbmUgewogICAgYm9yZGVyLWNvbG9yOiByZ2JhKDIzOSwgNjgsIDY4LCAwLjM1KSAhaW1wb3J0YW50OwogIH0KICAuZGFuZ2VyLXpvbmUgaDMgeyBjb2xvcjogdmFyKC0tZGFuZ2VyKTsgfQoKICAudG9hc3QgewogICAgcG9zaXRpb246IGZpeGVkOwogICAgdG9wOiAxcmVtOwogICAgbGVmdDogNTAlOwogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZS0yKTsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOiAwLjZyZW0gMXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBmb250LXNpemU6IDAuODVyZW07CiAgICB6LWluZGV4OiAyMDsKICAgIG1heC13aWR0aDogOTB2dzsKICB9CiAgLnRvYXN0LmVycm9yIHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1kYW5nZXIpOyBjb2xvcjogI2ZjYTVhNTsgfQoKICAubG9jay1zY3JlZW4gewogICAgcG9zaXRpb246IGZpeGVkOwogICAgaW5zZXQ6IDA7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgICBkaXNwbGF5OiBmbGV4OwogICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgei1pbmRleDogMTAwOwogICAgcGFkZGluZzogMS41cmVtOwogIH0KICAubG9jay1zY3JlZW4uaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5sb2NrLWNhcmQgeyBtYXgtd2lkdGg6IDMyMHB4OyB3aWR0aDogMTAwJTsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgLmxvY2stZW1vamkgeyBmb250LXNpemU6IDNyZW07IG1hcmdpbi1ib3R0b206IDAuNXJlbTsgfQogIC5sb2NrLWNhcmQgaDEgeyBtYXJnaW46IDAgMCAwLjVyZW07IH0KICAubG9jay1jYXJkIHAgeyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyBtYXJnaW46IDAgMCAxLjI1cmVtOyBmb250LXNpemU6IDAuOXJlbTsgfQogIC5sb2NrLWNhcmQgaW5wdXQgewogICAgd2lkdGg6IDEwMCU7CiAgICBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOwogICAgcGFkZGluZzogMC43cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIC5sb2NrLWVycm9yIHsgY29sb3I6IHZhcigtLWRhbmdlcik7IGZvbnQtc2l6ZTogMC44NXJlbTsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5sb2NrLWVycm9yLmhpZGRlbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAubG9jay1zdWNjZXNzIHsgY29sb3I6ICM0YWRlODA7IGZvbnQtc2l6ZTogMC44NXJlbTsgbWFyZ2luLXRvcDogMC43NXJlbTsgfQogIC5sb2NrLXN1Y2Nlc3MuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5hdXRoLXZpZXcuaGlkZGVuIHsgZGlzcGxheTogbm9uZTsgfQogIC5hdXRoLXN3aXRjaCB7IG1hcmdpbi10b3A6IDEuMXJlbTsgZm9udC1zaXplOiAwLjg1cmVtOyBjb2xvcjogdmFyKC0tdGV4dC1kaW0pOyB9CiAgLmF1dGgtc3dpdGNoIGEgeyBjb2xvcjogdmFyKC0tYWNjZW50KTsgY3Vyc29yOiBwb2ludGVyOyB0ZXh0LWRlY29yYXRpb246IHVuZGVybGluZTsgfQogIC5sb2NrLWNhcmQgaW5wdXRbdHlwZT0iZW1haWwiXSwKICAubG9jay1jYXJkIGlucHV0W3R5cGU9InRleHQiXSB7CiAgICB3aWR0aDogMTAwJTsKICAgIG1hcmdpbi1ib3R0b206IDAuNzVyZW07CiAgICBwYWRkaW5nOiAwLjdyZW0gMC45cmVtOwogICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgIGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7CiAgICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0KTsKICAgIGZvbnQtc2l6ZTogMXJlbTsKICB9CiAgLnBhc3N3b3JkLWZpZWxkIHsgcG9zaXRpb246IHJlbGF0aXZlOyBtYXJnaW4tYm90dG9tOiAwLjc1cmVtOyB9CiAgLnBhc3N3b3JkLWZpZWxkIGlucHV0IHsKICAgIHdpZHRoOiAxMDAlOwogICAgbWFyZ2luLWJvdHRvbTogMDsKICAgIHBhZGRpbmc6IDAuN3JlbSAyLjZyZW0gMC43cmVtIDAuOXJlbTsKICAgIGJvcmRlci1yYWRpdXM6IDEwcHg7CiAgICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7CiAgICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgICBmb250LXNpemU6IDFyZW07CiAgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuIHsKICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTsKICAgIHJpZ2h0OiAwLjRyZW07CiAgICB0b3A6IDUwJTsKICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWSgtNTAlKTsKICAgIGJhY2tncm91bmQ6IG5vbmU7CiAgICBib3JkZXI6IG5vbmU7CiAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICBmb250LXNpemU6IDEuMXJlbTsKICAgIHBhZGRpbmc6IDAuM3JlbSAwLjVyZW07CiAgICBsaW5lLWhlaWdodDogMTsKICAgIGNvbG9yOiB2YXIoLS10ZXh0LWRpbSk7CiAgICBvcGFjaXR5OiAwLjc7CiAgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuOmhvdmVyIHsgb3BhY2l0eTogMTsgfQogIC5wYXNzd29yZC10b2dnbGUtYnRuLmFjdGl2ZSB7IG9wYWNpdHk6IDE7IGNvbG9yOiB2YXIoLS1hY2NlbnQpOyB9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgPGRpdiBjbGFzcz0ibG9jay1zY3JlZW4gaGlkZGVuIiBpZD0ibG9jay1zY3JlZW4iPgogICAgPGRpdiBjbGFzcz0ibG9jay1jYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibG9jay1lbW9qaSI+8J+SsDwvZGl2PgogICAgICA8aDE+S2FjaGluZzwvaDE+CgogICAgICA8IS0tIENvbm5leGlvbiAtLT4KICAgICAgPGRpdiBjbGFzcz0iYXV0aC12aWV3IiBpZD0iYXV0aC12aWV3LWxvZ2luIj4KICAgICAgICA8cD5Db25uZWN0ZS10b2kgcG91ciBhY2PDqWRlciDDoCB0ZXMgZG9ubsOpZXMuPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9ImxvZ2luLWVtYWlsLWlucHV0IiBwbGFjZWhvbGRlcj0iRW1haWwiIGF1dG9jb21wbGV0ZT0idXNlcm5hbWUiPgogICAgICAgIDxkaXYgY2xhc3M9InBhc3N3b3JkLWZpZWxkIj4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9ImxvZ2luLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlIiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwYXNzd29yZC10b2dnbGUtYnRuIiBkYXRhLXRhcmdldD0ibG9naW4tcGFzc3dvcmQtaW5wdXQiIGFyaWEtbGFiZWw9IkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSI+8J+RgTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9ImxvZ2luLXN1Ym1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyI+U2UgY29ubmVjdGVyPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ibG9naW4tZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPgogICAgICAgICAgPGEgaWQ9ImxvZ2luLWdvdG8tZm9yZ290Ij5Nb3QgZGUgcGFzc2Ugb3VibGnDqSA/PC9hPjxicj4KICAgICAgICAgIDxhIGlkPSJsb2dpbi1nb3RvLXNpZ251cCI+SidhaSB1biBsaWVuIGQnaW52aXRhdGlvbjwvYT4KICAgICAgICA8L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSBJbnNjcmlwdGlvbiAoc3VyIGludml0YXRpb24gdW5pcXVlbWVudCkgLS0+CiAgICAgIDxkaXYgY2xhc3M9ImF1dGgtdmlldyBoaWRkZW4iIGlkPSJhdXRoLXZpZXctc2lnbnVwIj4KICAgICAgICA8cD5DcsOpZSB0b24gY29tcHRlIMOgIHBhcnRpciBkZSB0b24gbGllbiBkJ2ludml0YXRpb24uPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0ic2lnbnVwLWludml0ZS1pbnB1dCIgcGxhY2Vob2xkZXI9IkNvZGUgZCdpbnZpdGF0aW9uIj4KICAgICAgICA8aW5wdXQgdHlwZT0iZW1haWwiIGlkPSJzaWdudXAtZW1haWwtaW5wdXQiIHBsYWNlaG9sZGVyPSJFbWFpbCIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJzaWdudXAtdXNlcm5hbWUtaW5wdXQiIHBsYWNlaG9sZGVyPSJOb20gZCd1dGlsaXNhdGV1ciIgYXV0b2NvbXBsZXRlPSJuaWNrbmFtZSI+CiAgICAgICAgPGRpdiBjbGFzcz0icGFzc3dvcmQtZmllbGQiPgogICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0ic2lnbnVwLXBhc3N3b3JkLWlucHV0IiBwbGFjZWhvbGRlcj0iTW90IGRlIHBhc3NlICg4IGNhcmFjdMOocmVzIG1pbi4pIiBhdXRvY29tcGxldGU9Im5ldy1wYXNzd29yZCI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InBhc3N3b3JkLXRvZ2dsZS1idG4iIGRhdGEtdGFyZ2V0PSJzaWdudXAtcGFzc3dvcmQtaW5wdXQiIGFyaWEtbGFiZWw9IkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSI+8J+RgTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0icHJpbWFyeSIgaWQ9InNpZ251cC1zdWJtaXQtYnRuIiBzdHlsZT0id2lkdGg6MTAwJTsiPkNyw6llciBtb24gY29tcHRlPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0ic2lnbnVwLWVycm9yIj48L3A+CiAgICAgICAgPHAgY2xhc3M9ImF1dGgtc3dpdGNoIj48YSBpZD0ic2lnbnVwLWdvdG8tbG9naW4iPkonYWkgZMOpasOgIHVuIGNvbXB0ZTwvYT48L3A+CiAgICAgIDwvZGl2PgoKICAgICAgPCEtLSBNb3QgZGUgcGFzc2Ugb3VibGnDqSAtLT4KICAgICAgPGRpdiBjbGFzcz0iYXV0aC12aWV3IGhpZGRlbiIgaWQ9ImF1dGgtdmlldy1mb3Jnb3QiPgogICAgICAgIDxwPkVudHJlIHRvbiBlbWFpbCA6IHNpIHVuIGNvbXB0ZSBleGlzdGUsIHR1IHJlY2V2cmFzIHVuIGxpZW4gZGUgcsOpaW5pdGlhbGlzYXRpb24uPC9wPgogICAgICAgIDxpbnB1dCB0eXBlPSJlbWFpbCIgaWQ9ImZvcmdvdC1lbWFpbC1pbnB1dCIgcGxhY2Vob2xkZXI9IkVtYWlsIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InByaW1hcnkiIGlkPSJmb3Jnb3Qtc3VibWl0LWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5FbnZveWVyIGxlIGxpZW48L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0ibG9jay1lcnJvciBoaWRkZW4iIGlkPSJmb3Jnb3QtZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0ibG9jay1zdWNjZXNzIGhpZGRlbiIgaWQ9ImZvcmdvdC1zdWNjZXNzIj48L3A+CiAgICAgICAgPHAgY2xhc3M9ImF1dGgtc3dpdGNoIj48YSBpZD0iZm9yZ290LWdvdG8tbG9naW4iPlJldG91ciDDoCBsYSBjb25uZXhpb248L2E+PC9wPgogICAgICA8L2Rpdj4KCiAgICAgIDwhLS0gUsOpaW5pdGlhbGlzYXRpb24gZHUgbW90IGRlIHBhc3NlIChkZXB1aXMgbGUgbGllbiByZcOndSBwYXIgZW1haWwpIC0tPgogICAgICA8ZGl2IGNsYXNzPSJhdXRoLXZpZXcgaGlkZGVuIiBpZD0iYXV0aC12aWV3LXJlc2V0Ij4KICAgICAgICA8cD5DaG9pc2lzIHVuIG5vdXZlYXUgbW90IGRlIHBhc3NlLjwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJwYXNzd29yZC1maWVsZCI+CiAgICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJyZXNldC1wYXNzd29yZC1pbnB1dCIgcGxhY2Vob2xkZXI9Ik5vdXZlYXUgbW90IGRlIHBhc3NlICg4IGNhcmFjdMOocmVzIG1pbi4pIiBhdXRvY29tcGxldGU9Im5ldy1wYXNzd29yZCI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InBhc3N3b3JkLXRvZ2dsZS1idG4iIGRhdGEtdGFyZ2V0PSJyZXNldC1wYXNzd29yZC1pbnB1dCIgYXJpYS1sYWJlbD0iQWZmaWNoZXIgbGUgbW90IGRlIHBhc3NlIj7wn5GBPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVzZXQtc3VibWl0LWJ0biIgc3R5bGU9IndpZHRoOjEwMCU7Ij5WYWxpZGVyPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImxvY2stZXJyb3IgaGlkZGVuIiBpZD0icmVzZXQtZXJyb3IiPjwvcD4KICAgICAgICA8cCBjbGFzcz0ibG9jay1zdWNjZXNzIGhpZGRlbiIgaWQ9InJlc2V0LXN1Y2Nlc3MiPjwvcD4KICAgICAgICA8cCBjbGFzcz0iYXV0aC1zd2l0Y2giPjxhIGlkPSJyZXNldC1nb3RvLWxvZ2luIj5SZXRvdXIgw6AgbGEgY29ubmV4aW9uPC9hPjwvcD4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBpZD0iYXBwLXJvb3QiIGhpZGRlbj4KICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Im1lbnUtdG9nZ2xlLWJ0biIgaWQ9Im1lbnUtdG9nZ2xlLWJ0biIgYXJpYS1sYWJlbD0iT3V2cmlyIGxlIG1lbnUiPuKYsDwvYnV0dG9uPgogIDxkaXYgY2xhc3M9Im5hdi1kcmF3ZXItYmFja2Ryb3AiIGlkPSJuYXYtZHJhd2VyLWJhY2tkcm9wIj48L2Rpdj4KICA8aGVhZGVyPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJpY29uLWJ0biBkYW5nZXIiIGlkPSJsb2dvdXQtYnRuIiB0aXRsZT0iU2UgZMOpY29ubmVjdGVyIiBhcmlhLWxhYmVsPSJTZSBkw6ljb25uZWN0ZXIiIHN0eWxlPSJwb3NpdGlvbjphYnNvbHV0ZTsgdG9wOjFyZW07IHJpZ2h0OjFyZW07Ij7ij7s8L2J1dHRvbj4KICAgIDxoMT7wn5KwIEthY2hpbmc8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5UZXMgZMOpcGVuc2VzIGV0IHJldmVudXMsIGFqb3V0w6lzIG91IMOpZGl0w6lzIG1hbnVlbGxlbWVudC48L3A+CiAgPC9oZWFkZXI+CgogIDxkaXYgY2xhc3M9InRhYnMiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0YWItYnRuIGFjdGl2ZSIgaWQ9InRhYi1oaXN0b3J5IiBkYXRhLXZpZXc9Imhpc3RvcnkiPkhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1kYXNoYm9hcmQiIGRhdGEtdmlldz0iZGFzaGJvYXJkIj5UYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1yZWN1cnJpbmciIGRhdGEtdmlldz0icmVjdXJyaW5nIj5Sw6ljdXJyZW50ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1leHBvcnQiIGRhdGEtdmlldz0iZXhwb3J0Ij5FeHBvcnQ8L2J1dHRvbj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0idGFiLWJ0biIgaWQ9InRhYi1zYXZpbmdzIiBkYXRhLXZpZXc9InNhdmluZ3MiPsOJcGFyZ25lPC9idXR0b24+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9InN1bW1hcnkiPgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIj4KICAgICAgPHAgY2xhc3M9ImxhYmVsIj5Tb2xkZTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1iYWxhbmNlIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+RMOpcGVuc2VzPC9wPgogICAgICA8cCBjbGFzcz0idmFsdWUiIGlkPSJzdW1tYXJ5LWV4cGVuc2VzIj7igJQ8L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InN1bW1hcnktY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+UmV2ZW51czwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS1pbmNvbWUiPuKAlDwvcD4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3VtbWFyeS1jYXJkIHRvb2x0aXAtaG9zdCIgaWQ9InN1bW1hcnktdXBjb21pbmctY2FyZCI+CiAgICAgIDxwIGNsYXNzPSJsYWJlbCI+w4AgdmVuaXIgY2UgbW9pcy1jaTwvcD4KICAgICAgPHAgY2xhc3M9InZhbHVlIiBpZD0ic3VtbWFyeS11cGNvbWluZyI+4oCUPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjdXN0b20tdG9vbHRpcCIgaWQ9InN1bW1hcnktdXBjb21pbmctdG9vbHRpcCI+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPHAgY2xhc3M9IndlZWstc3VtbWFyeSIgaWQ9IndlZWstc3VtbWFyeSI+PC9wPgoKICA8ZGl2IGlkPSJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIgY2xhc3M9ImNhdGVnb3J5LXN1Z2dlc3Rpb24gaGlkZGVuIj48L2Rpdj4KCiAgPG1haW4+CiAgICA8c2VjdGlvbiBpZD0idmlldy1oaXN0b3J5Ij4KICAgICAgPGRpdiBjbGFzcz0iZmlsdGVyLWJhciI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJmaWx0ZXItc2VhcmNoIiBwbGFjZWhvbGRlcj0iUmVjaGVyY2hlci4uLiI+CiAgICAgICAgPHNlbGVjdCBpZD0iZmlsdGVyLWNhdGVnb3J5Ij48b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBjYXTDqWdvcmllczwvb3B0aW9uPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZmlsdGVyLWRhdGUtc3RhcnQiIGFyaWEtbGFiZWw9IkR1Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9ImZpbHRlci1kYXRlLWVuZCIgYXJpYS1sYWJlbD0iQXUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0idHgtbGlzdCIgY2xhc3M9InR4LWxpc3QiPjwvZGl2PgogICAgICA8ZGl2IGlkPSJlbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgUmllbiBwb3VyIGwnaW5zdGFudCDigJQgYXBwdWllIHN1ciBsZSBib3V0b24gKyBwb3VyIGFqb3V0ZXIgdW5lIGTDqXBlbnNlIG91IHVuIHJldmVudS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZGFzaGJvYXJkIiBjbGFzcz0iZGFzaGJvYXJkLXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtY2hpcC1yb3ciIGlkPSJkYXNoYm9hcmQtY2hpcC1yb3ciPjwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyIgaWQ9ImRhc2gtcm93LWV4cGVuc2VzIj4KICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtaGVhZCI+CiAgICAgICAgICA8aDM+UsOpcGFydGl0aW9uIGRlcyBkw6lwZW5zZXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0iZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2F0ZWdvcnktY2hhcnQtcm93Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC1jYXRlZ29yaWVzIj48L2NhbnZhcz4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLXVwY29taW5nLW5vdGUiIGNsYXNzPSJ1cGNvbWluZy1ub3RlIGhpZGRlbiI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ1cGNvbWluZy1zd2F0Y2giPjwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9ImRhc2hib2FyZC11cGNvbWluZy10ZXh0Ij48L3NwYW4+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJkYXNoYm9hcmQtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW5lIGTDqXBlbnNlIGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1pbmNvbWUiPgogICAgICAgIDxoMz5Sw6lwYXJ0aXRpb24gZGVzIHJldmVudXMgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPgogICAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQtaW5jb21lLWNhdGVnb3JpZXMiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZC1pbmNvbWUtY2F0ZWdvcmllcy1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgQXVjdW4gcmV2ZW51IGNlIG1vaXMtbMOgLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1idWRnZXRzIj4KICAgICAgICA8aDM+QnVkZ2V0cyBtZW5zdWVscyBwYXIgY2F0w6lnb3JpZTwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIEluZGlxdWUgdW4gbW9udGFudCBwb3VyIHVuZSBjYXTDqWdvcmllIGV0IGVucmVnaXN0cmUgYXZlYyDwn5K+IOKAlCBsYSBiYXJyZQogICAgICAgICAgY29tcGFyZSBlbnN1aXRlIHRlcyBkw6lwZW5zZXMgZHUgbW9pcyBlbiBjb3VycyDDoCBjZSBwbGFmb25kICh2ZXJ0LAogICAgICAgICAgb3JhbmdlIGF1LWRlbMOgIGRlIDcwJSwgcm91Z2UgYXUtZGVsw6AgZGUgMTAwJSkuIExhIHBldGl0ZSByYW5nw6llIGRlCiAgICAgICAgICBiYXJyZXMgZW4gZGVzc291cyBtb250cmUgbCdoaXN0b3JpcXVlIGRlcyA2IGRlcm5pZXJzIG1vaXMgKHN1cnZvbGUKICAgICAgICAgIG91IHRvdWNoZSB1bmUgYmFycmUgcG91ciB2b2lyIGxlIGTDqXRhaWwpLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJidWRnZXRzLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldHMtc2F2ZS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iaWNvbi1idG4iIGlkPSJidWRnZXRzLXNhdmUtYWxsLWJ0biIgYXJpYS1sYWJlbD0iRW5yZWdpc3RyZXIgdG91cyBsZXMgYnVkZ2V0cyI+8J+SvjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy1ldm9sdXRpb24iPgogICAgICAgIDxoMz7DiXZvbHV0aW9uIG1lbnN1ZWxsZSAoZMOpcGVuc2VzIHZzIHJldmVudXMpPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LWV2b2x1dGlvbiI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGVuY29yZSBhc3NleiBkZSBkb25uw6llcy4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93IiBpZD0iZGFzaC1yb3ctY29tcGFyZSI+CiAgICAgICAgPGgzPkNvbXBhcmVyIGRldXggbW9pczwvaDM+CiAgICAgICAgPGRpdiBjbGFzcz0iY29tcGFyZS1zZWxlY3RzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYSI+PC9zZWxlY3Q+CiAgICAgICAgICA8c3Bhbj52czwvc3Bhbj4KICAgICAgICAgIDxzZWxlY3QgaWQ9ImNvbXBhcmUtbW9udGgtYiI+PC9zZWxlY3Q+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iY29tcGFyZS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJjb21wYXJlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgYXNzZXogZGUgbW9pcyBkaWZmw6lyZW50cyBwb3VyIGNvbXBhcmVyLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy10cmVuZCI+CiAgICAgICAgPGgzPk1veWVubmUgZXQgdGVuZGFuY2UgcGFyIGNhdMOpZ29yaWU8L2gzPgogICAgICAgIDxkaXYgaWQ9InRyZW5kLXRhYmxlLXdyYXAiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InRyZW5kLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciIGlkPSJkYXNoLXJvdy15ZWFybHkiPgogICAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1oZWFkIj4KICAgICAgICAgIDxoMz5CaWxhbiBhbm51ZWw8L2gzPgogICAgICAgICAgPHNlbGVjdCBpZD0ieWVhcmx5LXllYXItc2VsZWN0Ij48L3NlbGVjdD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3VtbWFyeSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+RMOpcGVuc2VzPC9zcGFuPgogICAgICAgICAgICA8c3BhbiBpZD0ieWVhcmx5LXRvdGFsLWV4cGVuc2VzIiBjbGFzcz0ieWVhcmx5LXN0YXQtdmFsdWUgZXhwZW5zZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ5ZWFybHktc3RhdCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJ5ZWFybHktc3RhdC1sYWJlbCI+UmV2ZW51czwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS10b3RhbC1pbmNvbWUiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSBpbmNvbWUiPjwvc3Bhbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ieWVhcmx5LXN0YXQiPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ieWVhcmx5LXN0YXQtbGFiZWwiPlNvbGRlIG5ldDwvc3Bhbj4KICAgICAgICAgICAgPHNwYW4gaWQ9InllYXJseS1uZXQiIGNsYXNzPSJ5ZWFybHktc3RhdC12YWx1ZSI+PC9zcGFuPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+CiAgICAgICAgICA8Y2FudmFzIGlkPSJjaGFydC15ZWFybHkiPjwvY2FudmFzPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1lbXB0eSIgY2xhc3M9ImRhc2hib2FyZC1lbXB0eSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPgogICAgICAgICAgUGFzIGRlIGRvbm7DqWVzIHBvdXIgY2V0dGUgYW5uw6llLgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9InllYXJseS1jYXRlZ29yeS10YWJsZS13cmFwIj48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctcmVjdXJyaW5nIiBjbGFzcz0icmVjdXJyaW5nLXNlY3Rpb24iPgogICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgIENoYXJnZXMgZml4ZXMgKGFib25uZW1lbnRzLCBsb3llciwgc2FsYWlyZeKApikgY29tcHTDqWVzIGF1dG9tYXRpcXVlbWVudAogICAgICAgIGNoYXF1ZSBtb2lzIGRhbnMgbGUgdGFibGVhdSBkZSBib3JkIOKAlCBwYXMgYmVzb2luIGRlIGxlcyByZWRpY3Rlci4KICAgICAgICBNZXRzIHVuZSBkYXRlIGRlIGTDqWJ1dCBzaSB1bmUgY2hhcmdlIG5lIGRvaXQgZMOpbWFycmVyIHF1ZSBwbHVzIHRhcmQsCiAgICAgICAgdW5lIGRhdGUgZGUgZmluIHNpIGVsbGUgZG9pdCBzJ2FycsOqdGVyIHVuIGpvdXIuCiAgICAgIDwvcD4KICAgICAgPGRpdiBpZD0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIiBjbGFzcz0idXBjb21pbmctcmVjdXJyaW5nLXBhbmVsIGhpZGRlbiI+CiAgICAgICAgPGg0PlByb2NoYWluZXMgw6ljaMOpYW5jZXM8L2g0PgogICAgICAgIDxkaXYgaWQ9InVwY29taW5nLXJlY3VycmluZy1saXN0Ij48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJyZWN1cnJpbmctbGlzdCI+PC9kaXY+CiAgICAgIDxkaXYgaWQ9InJlY3VycmluZy1lbXB0eS1zdGF0ZSIgY2xhc3M9ImVtcHR5LXN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgQXVjdW5lIGTDqXBlbnNlIHLDqWN1cnJlbnRlIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyICsgcG91ciBlbiBham91dGVyIHVuZS4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctZXhwb3J0IiBjbGFzcz0iZXhwb3J0LXNlY3Rpb24iPgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+RXhwb3J0ZXIgdGVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJleHBvcnQtZm9ybWF0LXRvZ2dsZSIgaWQ9ImV4cG9ydC1mb3JtYXQtdG9nZ2xlIj4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZXhwb3J0LWZvcm1hdC1idG4gYWN0aXZlIiBkYXRhLWZvcm1hdD0ieGxzeCI+RXhjZWwgKC54bHN4KTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJleHBvcnQtZm9ybWF0LWJ0biIgZGF0YS1mb3JtYXQ9Impzb24iPlNhdXZlZ2FyZGUgY29tcGzDqHRlIChKU09OKTwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCIgaWQ9ImV4cG9ydC1mb3JtYXQtaGludCI+CiAgICAgICAgICBUb3V0ZXMgdGVzIHRyYW5zYWN0aW9ucyAoZMOpcGVuc2VzIGV0IHJldmVudXMpIGV0IHRlcyBjaGFyZ2VzCiAgICAgICAgICByw6ljdXJyZW50ZXMsIGNoYWN1bmUgZGFucyBzb24gcHJvcHJlIG9uZ2xldC4KICAgICAgICA8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImJ0bi1leHBvcnQtZG93bmxvYWQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+VMOpbMOpY2hhcmdlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5JbXBvcnRlciB1biByZWxldsOpIGJhbmNhaXJlPC9oMz4KICAgICAgICA8cCBjbGFzcz0icmVjdXJyaW5nLWhpbnQiPgogICAgICAgICAgUG91ciBsJ2luc3RhbnQsIHVuaXF1ZW1lbnQgbCdleHBvcnQgQ1NWIMKrIGV4cG9ydC1vcGVyYXRpb25zLi4uIMK7IGRlCiAgICAgICAgICBCb3Vyc29CYW5rLiBMZXMgbW9udGFudHMsIGRhdGVzIGV0IGRlc2NyaXB0aW9ucyBzb250IGFuYWx5c8OpcyBpY2kKICAgICAgICAgIG3Dqm1lIChyaWVuIG4nZXN0IGVudm95w6kgYWlsbGV1cnMpIDsgdHUgY2hvaXNpcyBlbnN1aXRlIGxpZ25lIHBhcgogICAgICAgICAgbGlnbmUgcXVvaSBpbXBvcnRlciBhdmFudCB0b3V0ZSDDqWNyaXR1cmUgZW4gYmFzZS4gTGUgbnVtw6lybyBkZQogICAgICAgICAgY29tcHRlIG4nZXN0IGphbWFpcyBsdS4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWRyb3B6b25lIiBpZD0iaW1wb3J0LWRyb3B6b25lIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1maWxlLXJvdyI+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iaW1wb3J0LWZpbGUtaW5wdXQiIGFjY2VwdD0iLmNzdix0ZXh0L2NzdiI+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJpbXBvcnQtYW5hbHl6ZS1idG4iPkFuYWx5c2VyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJpbXBvcnQtZHJvcHpvbmUtaGludCI+b3UgZ2xpc3NlLWTDqXBvc2UgbGUgZmljaGllciAuY3N2IGljaTwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJpbXBvcnQtc3VtbWFyeSIgY2xhc3M9ImltcG9ydC1zdW1tYXJ5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXByZXZpZXciIGNsYXNzPSJpbXBvcnQtcHJldmlldyBoaWRkZW4iPgogICAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWFjdGlvbnMtcm93Ij4KICAgICAgICAgICAgPHNwYW4gaWQ9ImltcG9ydC1zZWxlY3RlZC1jb3VudCI+PC9zcGFuPgogICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9ImltcG9ydC10b2dnbGUtYWxsLWJ0biI+VG91dCBjb2NoZXIgLyBkw6ljb2NoZXI8L2J1dHRvbj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBpZD0iaW1wb3J0LXJvd3MtbGlzdCI+PC9kaXY+CiAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iaW1wb3J0LWNvbW1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyBtYXJnaW4tdG9wOjAuNzVyZW07Ij5JbXBvcnRlciBsYSBzw6lsZWN0aW9uPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyI+CiAgICAgICAgPGgzPkltcG9ydCBnw6luw6lyaXF1ZSBwYXIgSUEgKHRvdXQgZmljaGllcik8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBQb3VyIHVuIGZpY2hpZXIgcXVpIG5lIHZpZW50IHBhcyBkZSBCb3Vyc29CYW5rLCBvdSBxdWkgbidhIHBhcyB1bmUKICAgICAgICAgIHN0cnVjdHVyZSBjbGFzc2lxdWUgKGV4IDogdW4gdGFibGVhdSBwYXIgbW9pcywgc2FucyBkYXRlIHByw6ljaXNlIG5pCiAgICAgICAgICBjYXTDqWdvcmllKS4gTCdJQSBsaXQgbGUgZmljaGllciBldCBwcm9wb3NlIGRlcyB0cmFuc2FjdGlvbnMgw6AKICAgICAgICAgIHZhbGlkZXIgOyBzaSB1bmUgZMOpcGVuc2Ugc2VtYmxlIHNlIHLDqXDDqXRlciBjaGFxdWUgbW9pcywgZWxsZSBlc3QKICAgICAgICAgIG1pc2UgZGUgY8O0dMOpIHBvdXIgcXVlIHR1IGNvbmZpcm1lcyB0b2ktbcOqbWUgcydpbCBzJ2FnaXQgZCd1bmUKICAgICAgICAgIGNoYXJnZSByw6ljdXJyZW50ZSBvdSBkJ3VuIGNyw6lkaXQgZW4gY291cnMgZGUgcmVtYm91cnNlbWVudC4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWRyb3B6b25lIiBpZD0iZ2VuZXJpYy1pbXBvcnQtZHJvcHpvbmUiPgogICAgICAgICAgPGRpdiBjbGFzcz0iaW1wb3J0LWZpbGUtcm93Ij4KICAgICAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJnZW5lcmljLWltcG9ydC1maWxlLWlucHV0IiBhY2NlcHQ9Ii5jc3YsLnhsc3gsdGV4dC9jc3YiPgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0iZ2VuZXJpYy1pbXBvcnQtYW5hbHl6ZS1idG4iPkFuYWx5c2VyPC9idXR0b24+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJpbXBvcnQtZHJvcHpvbmUtaGludCI+b3UgZ2xpc3NlLWTDqXBvc2UgdW4gZmljaGllciAuY3N2IC8gLnhsc3ggaWNpPC9wPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImdlbmVyaWMtaW1wb3J0LXN1bW1hcnkiIGNsYXNzPSJpbXBvcnQtc3VtbWFyeSIgc3R5bGU9ImRpc3BsYXk6bm9uZTsiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9ImdlbmVyaWMtaW1wb3J0LXJlY3VycmluZy1zZWN0aW9uIiBjbGFzcz0iaGlkZGVuIj4KICAgICAgICAgIDxoNCBzdHlsZT0ibWFyZ2luLWJvdHRvbTowLjI1cmVtOyI+RMOpcGVuc2VzIHF1aSBzZW1ibGVudCBzZSByw6lww6l0ZXI8L2g0PgogICAgICAgICAgPGRpdiBpZD0iZ2VuZXJpYy1pbXBvcnQtcmVjdXJyaW5nLWxpc3QiIGNsYXNzPSJyZWN1cnJpbmctY2FuZGlkYXRlcy1saXN0Ij48L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1wcmV2aWV3IiBjbGFzcz0iaW1wb3J0LXByZXZpZXcgaGlkZGVuIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImltcG9ydC1hY3Rpb25zLXJvdyI+CiAgICAgICAgICAgIDxzcGFuIGlkPSJnZW5lcmljLWltcG9ydC1zZWxlY3RlZC1jb3VudCI+PC9zcGFuPgogICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9ImdlbmVyaWMtaW1wb3J0LXRvZ2dsZS1hbGwtYnRuIj5Ub3V0IGNvY2hlciAvIGTDqWNvY2hlcjwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IGlkPSJnZW5lcmljLWltcG9ydC1yb3dzLWxpc3QiPjwvZGl2PgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImdlbmVyaWMtaW1wb3J0LWNvbW1pdC1idG4iIHN0eWxlPSJ3aWR0aDoxMDAlOyBtYXJnaW4tdG9wOjAuNzVyZW07Ij5JbXBvcnRlciBsYSBzw6lsZWN0aW9uPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdiBjbGFzcz0iZGFzaGJvYXJkLXJvdyBkYW5nZXItem9uZSI+CiAgICAgICAgPGgzPuKaoO+4jyBab25lIGRhbmdlcmV1c2U8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBTdXBwcmltZSBkw6lmaW5pdGl2ZW1lbnQgVE9VVEVTIGxlcyBkb25uw6llcyA6IHRyYW5zYWN0aW9ucywgY2hhcmdlcwogICAgICAgICAgcsOpY3VycmVudGVzLCBjYXTDqWdvcmllcyBwZXJzb25uYWxpc8OpZXMsIHN1Z2dlc3Rpb25zIGlnbm9yw6llcywKICAgICAgICAgIGJ1ZGdldHMsIHBob3RvcyBkZSByZcOndXMgZXQgb2JqZWN0aWYgZCfDqXBhcmduZS4gUGVuc2Ugw6AgZXhwb3J0ZXIgZW4KICAgICAgICAgIEV4Y2VsIGF2YW50IHNpIGJlc29pbiDigJQgaW1wb3NzaWJsZSDDoCBhbm51bGVyLgogICAgICAgIDwvcD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJkYW5nZXIiIGlkPSJidG4tcmVzZXQtYWxsIiBzdHlsZT0id2lkdGg6MTAwJTsiPlLDqWluaXRpYWxpc2VyIHRvdXRlIGwnYXBwbGljYXRpb248L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPHNlY3Rpb24gaWQ9InZpZXctc2F2aW5ncyIgY2xhc3M9InNhdmluZ3Mtc2VjdGlvbiI+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5PYmplY3RpZiBkJ8OpcGFyZ25lIG1lbnN1ZWw8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBMZSBtb250YW50IHF1ZSB0dSB2ZXV4IGdhcmRlciBkZSBjw7R0w6kgY2hhcXVlIG1vaXMgKHJldmVudXMgbW9pbnMKICAgICAgICAgIGTDqXBlbnNlcykuIENvbXBhcsOpIMOgIHRvbiBzb2xkZSByw6llbCBkdSBtb2lzIGVuIGNvdXJzLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGNsYXNzPSJzYXZpbmdzLWdvYWwtcm93Ij4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJzYXZpbmdzLWdvYWwtaW5wdXQiIG1pbj0iMCIgc3RlcD0iMSIgcGxhY2Vob2xkZXI9IkV4IDogMTAwIj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9Imljb24tYnRuIiBpZD0ic2F2aW5ncy1nb2FsLXNhdmUtYnRuIiBhcmlhLWxhYmVsPSJFbnJlZ2lzdHJlciBsJ29iamVjdGlmIj7wn5K+PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0ic2F2aW5ncy1wcm9ncmVzcy1zZWN0aW9uIiBjbGFzcz0ic2F2aW5ncy1wcm9ncmVzcyBoaWRkZW4iPgogICAgICAgICAgPGRpdiBjbGFzcz0ic2F2aW5ncy1wcm9ncmVzcy1sYWJlbCI+CiAgICAgICAgICAgIDxzcGFuPlNvbGRlIGR1IG1vaXMgZW4gY291cnM8L3NwYW4+CiAgICAgICAgICAgIDxzdHJvbmcgaWQ9InNhdmluZ3MtcHJvZ3Jlc3MtdGV4dCI+PC9zdHJvbmc+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImJ1ZGdldC1iYXItdHJhY2siPgogICAgICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLXByb2dyZXNzLWJhciIgY2xhc3M9ImJ1ZGdldC1iYXItZmlsbCBvayI+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQtcm93Ij4KICAgICAgICA8aDM+Q29uc2VpbHM8L2gzPgogICAgICAgIDxwIGNsYXNzPSJyZWN1cnJpbmctaGludCI+CiAgICAgICAgICBCYXPDqXMgc3VyIHRlcyBidWRnZXRzIHBhciBjYXTDqWdvcmllIGV0IHRlcyB0ZW5kYW5jZXMgZGUgZMOpcGVuc2VzCiAgICAgICAgICAodm9pciBsJ29uZ2xldCBUYWJsZWF1IGRlIGJvcmQpLgogICAgICAgIDwvcD4KICAgICAgICA8ZGl2IGlkPSJzYXZpbmdzLWFkdmljZS1saXN0IiBjbGFzcz0iYWR2aWNlLWxpc3QiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InNhdmluZ3MtYWR2aWNlLWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+CiAgICAgICAgICBQYXMgZW5jb3JlIGFzc2V6IGRlIGRvbm7DqWVzIGNlIG1vaXMtY2kgcG91ciB0ZSBkb25uZXIgZGVzIGNvbnNlaWxzLgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImRhc2hib2FyZC1yb3ciPgogICAgICAgIDxoMz5TaW11bGF0aW9uIGRlIHBsYWNlbWVudDwvaDM+CiAgICAgICAgPHAgY2xhc3M9InJlY3VycmluZy1oaW50Ij4KICAgICAgICAgIFByb2plY3Rpb24gc2kgdHUgcGxhY2VzIHVuZSBzb21tZSBzdXIgdW4gbGl2cmV0IG91IHVuIHBsYWNlbWVudCDDoAogICAgICAgICAgdGF1eCBmaXhlIChpbnTDqXLDqnRzIGNvbXBvc8OpcywgY2FsY3Vsw6lzIG1lbnN1ZWxsZW1lbnQpLiBMZSB0YXV4IHBhcgogICAgICAgICAgZMOpZmF1dCAoMyUpIGNvcnJlc3BvbmQgYXUgTGl2cmV0IEEg4oCUIGNoYW5nZS1sZSBwb3VyIHNpbXVsZXIgdW4KICAgICAgICAgIGF1dHJlIHBsYWNlbWVudC4KICAgICAgICA8L3A+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LWlucHV0cyI+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtaW5pdGlhbCI+TW9udGFudCBpbml0aWFsICjigqwpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC1pbml0aWFsIiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSI1MDAiPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2PgogICAgICAgICAgICA8bGFiZWwgZm9yPSJwbGFjZW1lbnQtbW9udGhseSI+VmVyc2VtZW50IG1lbnN1ZWwgKOKCrCk8L2xhYmVsPgogICAgICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icGxhY2VtZW50LW1vbnRobHkiIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IjUwIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXJhdGUiPlRhdXggYW5udWVsICglKTwvbGFiZWw+CiAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwbGFjZW1lbnQtcmF0ZSIgbWluPSIwIiBzdGVwPSIwLjEiIHZhbHVlPSIzIj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGxhYmVsIGZvcj0icGxhY2VtZW50LXllYXJzIj5EdXLDqWUgKGFubsOpZXMpPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InBsYWNlbWVudC15ZWFycyIgbWluPSIxIiBzdGVwPSIxIiB2YWx1ZT0iNSI+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFydC13cmFwIj4KICAgICAgICAgIDxjYW52YXMgaWQ9ImNoYXJ0LXBsYWNlbWVudCI+PC9jYW52YXM+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0icGxhY2VtZW50LWNoYXJ0LWVtcHR5IiBjbGFzcz0iZGFzaGJvYXJkLWVtcHR5IiBzdHlsZT0iZGlzcGxheTpub25lOyI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icGxhY2VtZW50LXJlc3VsdCIgaWQ9InBsYWNlbWVudC1yZXN1bHQiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICA8L21haW4+CgogIDxkaXYgY2xhc3M9InZvaWNlLWJhbm5lciBoaWRkZW4iIGlkPSJ2b2ljZS1iYW5uZXIiPjwvZGl2PgogIDxkaXYgY2xhc3M9InZvaWNlLWNvbmZpcm0tYmFubmVyIGhpZGRlbiIgaWQ9InZvaWNlLWNvbmZpcm0tYmFubmVyIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJmYWItbWljIiBpZD0iZmFiLW1pYyIgYXJpYS1sYWJlbD0iRGljdGVyIHVuZSBkw6lwZW5zZSBvdSB1biByZXZlbnUsIG91IHBvc2VyIHVuZSBxdWVzdGlvbiIgdGl0bGU9IkRpY3RlIHVuZSBkw6lwZW5zZS91biByZXZlbnUsIG91IHBvc2UgdW5lIHF1ZXN0aW9uIChleCA6IMKrIGNvbWJpZW4gaidhaSBkw6lwZW5zw6kgZW4gcmVzdGF1cmFudCBjZSBtb2lzLWNpID8gwrspIj7wn46kPC9idXR0b24+CiAgPGJ1dHRvbiBjbGFzcz0iZmFiIiBpZD0iZmFiLWFkZCIgYXJpYS1sYWJlbD0iQWpvdXRlciI+KzwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9Im1vZGFsLW92ZXJsYXkiPgogICAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgICA8aDIgaWQ9Im1vZGFsLXRpdGxlIj5Ob3V2ZWxsZSB0cmFuc2FjdGlvbjwvaDI+CgogICAgICA8ZGl2IGNsYXNzPSJ0eXBlLXRvZ2dsZSIgaWQ9InR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJpbnB1dC1hbW91bnQiIHN0ZXA9IjAuMDEiIG1pbj0iMC4wMSIgcGxhY2Vob2xkZXI9IjEyLjUwIiBpbnB1dG1vZGU9ImRlY2ltYWwiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJpbnB1dC1jYXRlZ29yeSI+Q2F0w6lnb3JpZTwvbGFiZWw+CiAgICAgICAgPHNlbGVjdCBpZD0iaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICAgIDxpbnB1dAogICAgICAgICAgdHlwZT0idGV4dCIKICAgICAgICAgIGlkPSJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIKICAgICAgICAgIHBsYWNlaG9sZGVyPSJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSIKICAgICAgICAgIGNsYXNzPSJoaWRkZW4iCiAgICAgICAgICBzdHlsZT0ibWFyZ2luLXRvcDogOHB4OyIKICAgICAgICA+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRlc2NyaXB0aW9uIj5EZXNjcmlwdGlvbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJpbnB1dC1kZXNjcmlwdGlvbiIgcGxhY2Vob2xkZXI9IkV4IDogZMOpamV1bmVyIGF2ZWMgUGF1bCI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9ImlucHV0LWRhdGUiPkRhdGU8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaW5wdXQtZGF0ZSI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbD5SZcOndSAocGhvdG8sIG9wdGlvbm5lbCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0iaW5wdXQtcmVjZWlwdC1maWxlIiBjbGFzcz0iaGlkZGVuLWZpbGUtaW5wdXQiIGFjY2VwdD0iaW1hZ2UvKiIgY2FwdHVyZT0iZW52aXJvbm1lbnQiPgogICAgICAgIDxkaXYgaWQ9InJlY2VpcHQtcHJldmlldy13cmFwIiBjbGFzcz0icmVjZWlwdC1wcmV2aWV3LXdyYXAgaGlkZGVuIj4KICAgICAgICAgIDxpbWcgaWQ9InJlY2VpcHQtcHJldmlldy1pbWciIGNsYXNzPSJyZWNlaXB0LXByZXZpZXctaW1nIiBhbHQ9IlJlw6d1Ij4KICAgICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLXJlY2VpcHQtcmVtb3ZlIj5TdXBwcmltZXIgbGEgcGhvdG88L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InNlY29uZGFyeSIgaWQ9ImJ0bi1yZWNlaXB0LXBpY2siIHN0eWxlPSJ3aWR0aDoxMDAlOyI+8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iYnRuLWNhbmNlbCI+QW5udWxlcjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIGlkPSJidG4tc2F2ZSI+QWpvdXRlcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IGhpZGRlbiIgaWQ9InJlYy1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgICAgPGgyIGlkPSJyZWMtbW9kYWwtdGl0bGUiPk5vdXZlbGxlIGTDqXBlbnNlIHLDqWN1cnJlbnRlPC9oMj4KCiAgICAgIDxkaXYgY2xhc3M9InR5cGUtdG9nZ2xlIiBpZD0icmVjLXR5cGUtdG9nZ2xlIj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9InR5cGUtYnRuIGFjdGl2ZSIgZGF0YS10eXBlPSJleHBlbnNlIj7wn5K4IETDqXBlbnNlPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJ0eXBlLWJ0biIgZGF0YS10eXBlPSJpbmNvbWUiPvCfkrAgUmV2ZW51PC9idXR0b24+CiAgICAgIDwvZGl2PgoKICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtbmFtZSI+Tm9tPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InJlYy1pbnB1dC1uYW1lIiBwbGFjZWhvbGRlcj0iRXggOiBOZXRmbGl4LCBMb3llciwgU2FsYWlyZS4uLiI+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxsYWJlbCBmb3I9InJlYy1pbnB1dC1hbW91bnQiPk1vbnRhbnQgKOKCrCk8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtYW1vdW50IiBzdGVwPSIwLjAxIiBtaW49IjAuMDEiIHBsYWNlaG9sZGVyPSIxMi41MCIgaW5wdXRtb2RlPSJkZWNpbWFsIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWNhdGVnb3J5Ij5DYXTDqWdvcmllPC9sYWJlbD4KICAgICAgICA8c2VsZWN0IGlkPSJyZWMtaW5wdXQtY2F0ZWdvcnkiPjwvc2VsZWN0PgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8bGFiZWwgZm9yPSJyZWMtaW5wdXQtZGF5Ij5Kb3VyIGR1IG1vaXM8L2xhYmVsPgogICAgICAgIDxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJyZWMtaW5wdXQtZGF5IiBtaW49IjEiIG1heD0iMzEiIHN0ZXA9IjEiIHBsYWNlaG9sZGVyPSIxIMOgIDMxIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LXN0YXJ0LWRhdGUiPkRhdGUgZGUgZMOpYnV0IChvcHRpb25uZWwpPC9sYWJlbD4KICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InJlYy1pbnB1dC1zdGFydC1kYXRlIj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGxhYmVsIGZvcj0icmVjLWlucHV0LWVuZC1kYXRlIj5EYXRlIGRlIGZpbiAob3B0aW9ubmVsKTwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJyZWMtaW5wdXQtZW5kLWRhdGUiPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0icmVjLWJ0bi1jYW5jZWwiPkFubnVsZXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBpZD0icmVjLWJ0bi1zYXZlIj5Bam91dGVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkgaGlkZGVuIiBpZD0iY29uZmlybS1tb2RhbC1vdmVybGF5Ij4KICAgIDxkaXYgY2xhc3M9Im1vZGFsIGNvbmZpcm0tbW9kYWwiPgogICAgICA8aDIgaWQ9ImNvbmZpcm0tbW9kYWwtdGl0bGUiPkNvbmZpcm1lcjwvaDI+CiAgICAgIDxwIGlkPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiIGNsYXNzPSJjb25maXJtLW1vZGFsLW1lc3NhZ2UiPjwvcD4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0ic2Vjb25kYXJ5IiBpZD0iY29uZmlybS1idG4tY2FuY2VsIj5Bbm51bGVyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgaWQ9ImNvbmZpcm0tYnRuLW9rIj5Db25maXJtZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0ibGlnaHRib3gtb3ZlcmxheSBoaWRkZW4iIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LW92ZXJsYXkiPgogICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJsaWdodGJveC1jbG9zZSIgaWQ9InJlY2VpcHQtbGlnaHRib3gtY2xvc2UiIGFyaWEtbGFiZWw9IkZlcm1lciI+4pyVPC9idXR0b24+CiAgICA8aW1nIGNsYXNzPSJsaWdodGJveC1pbWciIGlkPSJyZWNlaXB0LWxpZ2h0Ym94LWltZyIgYWx0PSJSZcOndSBlbiBwbGVpbiDDqWNyYW4iPgogIDwvZGl2PgogIDwvZGl2PgoKICA8c2NyaXB0PgogICAgLy8gTGUgamV0b24gZGUgc2Vzc2lvbiAob2J0ZW51IGFwcsOocyBhdm9pciB0YXDDqSBsZSBtb3QgZGUgcGFzc2Ugc3VyIGwnw6ljcmFuCiAgICAvLyBkZSB2ZXJyb3VpbGxhZ2UpIHJlbXBsYWNlIGwnYW5jaWVubmUgY2zDqSBBUEkgY29kw6llIGVuIGR1ciBpY2kg4oCUIGNlbGxlLWNpCiAgICAvLyDDqXRhaXQgdmlzaWJsZSBwYXIgbidpbXBvcnRlIHF1aSB2aWEgIkFmZmljaGVyIGxlIGNvZGUgc291cmNlIiwgc2FucwogICAgLy8gYXVjdW4gbW90IGRlIHBhc3NlLiBMZSBqZXRvbiBlc3Qgc2lnbsOpIGPDtHTDqSBzZXJ2ZXVyIGV0IGV4cGlyZSBhcHLDqHMgOTAKICAgIC8vIGpvdXJzIDsgaWwgbmUgcsOpdsOobGUgcmllbiBkZSBzZWNyZXQgZW4gbHVpLW3Dqm1lLgogICAgY29uc3QgVE9LRU5fU1RPUkFHRV9LRVkgPSAia2FjaGluZ19zZXNzaW9uX3Rva2VuIjsKICAgIGxldCBBUElfS0VZID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oVE9LRU5fU1RPUkFHRV9LRVkpIHx8ICIiOwoKICAgIGNvbnN0IGxvY2tTY3JlZW5FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2NrLXNjcmVlbiIpOwogICAgY29uc3QgYXBwUm9vdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImFwcC1yb290Iik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyDDiWNyYW4gZGUgY29ubmV4aW9uIDogcGx1c2lldXJzIHZ1ZXMgKGNvbm5leGlvbiAvIGluc2NyaXB0aW9uIHN1cgogICAgLy8gaW52aXRhdGlvbiAvIG1vdCBkZSBwYXNzZSBvdWJsacOpIC8gcsOpaW5pdGlhbGlzYXRpb24pIGRhbnMgbGEgbcOqbWUKICAgIC8vIGNhcnRlLCB1bmUgc2V1bGUgYWZmaWNow6llIMOgIGxhIGZvaXMuID9pbnZpdGU9Li4uIGV0ID9yZXNldD0uLi4gZGFucwogICAgLy8gbCdVUkwgKGxpZW5zIHJlw6d1cyBwYXIgZW1haWwpIG91dnJlbnQgZGlyZWN0ZW1lbnQgbGEgdnVlIGNvcnJlc3BvbmRhbnRlCiAgICAvLyBhdmVjIGxlIGpldG9uIHByw6ktcmVtcGxpIOKAlCBpbCBuJ2V4aXN0ZSBwYXMgZGUgcm91dGUgc2VydmV1ciBkw6lkacOpZQogICAgLy8gcG91ciAvc2lnbnVwIG91IC9yZXNldC1wYXNzd29yZCwgdG91dCBzZSBwYXNzZSBpY2kgY8O0dMOpIGZyb250ZW5kLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBhdXRoVmlld3MgPSB7CiAgICAgIGxvZ2luOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXV0aC12aWV3LWxvZ2luIiksCiAgICAgIHNpZ251cDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImF1dGgtdmlldy1zaWdudXAiKSwKICAgICAgZm9yZ290OiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXV0aC12aWV3LWZvcmdvdCIpLAogICAgICByZXNldDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImF1dGgtdmlldy1yZXNldCIpLAogICAgfTsKCiAgICBmdW5jdGlvbiBzaG93QXV0aFZpZXcobmFtZSkgewogICAgICBmb3IgKGNvbnN0IFtrZXksIGVsXSBvZiBPYmplY3QuZW50cmllcyhhdXRoVmlld3MpKSB7CiAgICAgICAgZWwuY2xhc3NMaXN0LnRvZ2dsZSgiaGlkZGVuIiwga2V5ICE9PSBuYW1lKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dMb2NrU2NyZWVuKGluaXRpYWxWaWV3ID0gImxvZ2luIikgewogICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShUT0tFTl9TVE9SQUdFX0tFWSk7CiAgICAgIEFQSV9LRVkgPSAiIjsKICAgICAgYXBwUm9vdEVsLmhpZGRlbiA9IHRydWU7CiAgICAgIGxvY2tTY3JlZW5FbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgc2hvd0F1dGhWaWV3KGluaXRpYWxWaWV3KTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93QXBwKCkgewogICAgICBsb2NrU2NyZWVuRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGFwcFJvb3RFbC5oaWRkZW4gPSBmYWxzZTsKICAgIH0KCiAgICBmdW5jdGlvbiBzZXRBdXRoQnVzeShidG4sIGJ1c3lMYWJlbCwgaWRsZUxhYmVsKSB7CiAgICAgIGJ0bi5kaXNhYmxlZCA9ICEhYnVzeUxhYmVsOwogICAgICBidG4udGV4dENvbnRlbnQgPSBidXN5TGFiZWwgfHwgaWRsZUxhYmVsOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIHBvc3RBdXRoKHBhdGgsIHBheWxvYWQpIHsKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gocGF0aCwgewogICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgIGhlYWRlcnM6IHsgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiB9LAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICB9KTsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8ICJVbmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSwgcsOpZXNzYWllLiIpOwogICAgICB9CiAgICAgIHJldHVybiBkYXRhOwogICAgfQoKICAgIGZ1bmN0aW9uIG9uU2Vzc2lvbk9idGFpbmVkKHRva2VuKSB7CiAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKFRPS0VOX1NUT1JBR0VfS0VZLCB0b2tlbik7CiAgICAgIC8vIFJlY2hhcmdlbWVudCBjb21wbGV0IHBsdXTDtHQgcXVlIGRlIHLDqS1lbmNoYcOubmVyIGwnaW5pdCBtYW51ZWxsZW1lbnQgOgogICAgICAvLyBwbHVzIHNpbXBsZSBldCBwbHVzIHPDu3IgKG9uIHJlcGFydCBhdmVjIHVuIMOpdGF0IHByb3ByZSwgQVBJX0tFWSBsdQogICAgICAvLyBkZXB1aXMgbGUgbG9jYWxTdG9yYWdlIGNvbW1lIGF1IHRvdXQgcHJlbWllciBjaGFyZ2VtZW50KS4KICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpOwogICAgfQoKICAgIC8vIC0tLSBDb25uZXhpb24gLS0tCiAgICBjb25zdCBsb2dpbkVtYWlsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tZW1haWwtaW5wdXQiKTsKICAgIGNvbnN0IGxvZ2luUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dpbi1wYXNzd29yZC1pbnB1dCIpOwogICAgY29uc3QgbG9naW5TdWJtaXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tc3VibWl0LWJ0biIpOwogICAgY29uc3QgbG9naW5FcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWVycm9yIik7CgogICAgYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdExvZ2luKCkgewogICAgICBjb25zdCBlbWFpbCA9IGxvZ2luRW1haWxJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gbG9naW5QYXNzd29yZElucHV0LnZhbHVlOwogICAgICBpZiAoIWVtYWlsIHx8ICFwYXNzd29yZCkgcmV0dXJuOwogICAgICBsb2dpbkVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHNldEF1dGhCdXN5KGxvZ2luU3VibWl0QnRuLCAiQ29ubmV4aW9u4oCmIik7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHBvc3RBdXRoKCIvYXBpL2F1dGgvbG9naW4iLCB7IGVtYWlsLCBwYXNzd29yZCB9KTsKICAgICAgICBvblNlc3Npb25PYnRhaW5lZChkYXRhLnRva2VuKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgbG9naW5FcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgbG9naW5FcnJvckVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KGxvZ2luU3VibWl0QnRuLCBudWxsLCAiU2UgY29ubmVjdGVyIik7CiAgICAgIH0KICAgIH0KICAgIGxvZ2luU3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdExvZ2luKTsKICAgIFtsb2dpbkVtYWlsSW5wdXQsIGxvZ2luUGFzc3dvcmRJbnB1dF0uZm9yRWFjaCgoaW5wdXQpID0+IHsKICAgICAgaW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigia2V5ZG93biIsIChlKSA9PiB7IGlmIChlLmtleSA9PT0gIkVudGVyIikgYXR0ZW1wdExvZ2luKCk7IH0pOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibG9naW4tZ290by1mb3Jnb3QiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygiZm9yZ290IikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWdvdG8tc2lnbnVwIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzaG93QXV0aFZpZXcoInNpZ251cCIpKTsKCiAgICAvLyAtLS0gSW5zY3JpcHRpb24gKHN1ciBpbnZpdGF0aW9uKSAtLS0KICAgIGNvbnN0IHNpZ251cEludml0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNpZ251cC1pbnZpdGUtaW5wdXQiKTsKICAgIGNvbnN0IHNpZ251cEVtYWlsSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2lnbnVwLWVtYWlsLWlucHV0Iik7CiAgICBjb25zdCBzaWdudXBVc2VybmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNpZ251cC11c2VybmFtZS1pbnB1dCIpOwogICAgY29uc3Qgc2lnbnVwUGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtcGFzc3dvcmQtaW5wdXQiKTsKICAgIGNvbnN0IHNpZ251cFN1Ym1pdEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtc3VibWl0LWJ0biIpOwogICAgY29uc3Qgc2lnbnVwRXJyb3JFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtZXJyb3IiKTsKCiAgICBhc3luYyBmdW5jdGlvbiBhdHRlbXB0U2lnbnVwKCkgewogICAgICBjb25zdCBpbnZpdGVfdG9rZW4gPSBzaWdudXBJbnZpdGVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IGVtYWlsID0gc2lnbnVwRW1haWxJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHVzZXJuYW1lID0gc2lnbnVwVXNlcm5hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0IHBhc3N3b3JkID0gc2lnbnVwUGFzc3dvcmRJbnB1dC52YWx1ZTsKICAgICAgaWYgKCFpbnZpdGVfdG9rZW4gfHwgIWVtYWlsIHx8ICF1c2VybmFtZSB8fCAhcGFzc3dvcmQpIHsKICAgICAgICBzaWdudXBFcnJvckVsLnRleHRDb250ZW50ID0gIlRvdXMgbGVzIGNoYW1wcyBzb250IHJlcXVpcy4iOwogICAgICAgIHNpZ251cEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHNpZ251cEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHNldEF1dGhCdXN5KHNpZ251cFN1Ym1pdEJ0biwgIkNyw6lhdGlvbuKApiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL3NpZ251cCIsIHsgaW52aXRlX3Rva2VuLCBlbWFpbCwgdXNlcm5hbWUsIHBhc3N3b3JkIH0pOwogICAgICAgIG9uU2Vzc2lvbk9idGFpbmVkKGRhdGEudG9rZW4pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaWdudXBFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgc2lnbnVwRXJyb3JFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShzaWdudXBTdWJtaXRCdG4sIG51bGwsICJDcsOpZXIgbW9uIGNvbXB0ZSIpOwogICAgICB9CiAgICB9CiAgICBzaWdudXBTdWJtaXRCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhdHRlbXB0U2lnbnVwKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzaWdudXAtZ290by1sb2dpbiIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0F1dGhWaWV3KCJsb2dpbiIpKTsKCiAgICAvLyAtLS0gTW90IGRlIHBhc3NlIG91Ymxpw6kgLS0tCiAgICBjb25zdCBmb3Jnb3RFbWFpbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1lbWFpbC1pbnB1dCIpOwogICAgY29uc3QgZm9yZ290U3VibWl0QnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1zdWJtaXQtYnRuIik7CiAgICBjb25zdCBmb3Jnb3RFcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1lcnJvciIpOwogICAgY29uc3QgZm9yZ290U3VjY2Vzc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZvcmdvdC1zdWNjZXNzIik7CgogICAgYXN5bmMgZnVuY3Rpb24gYXR0ZW1wdEZvcmdvdFBhc3N3b3JkKCkgewogICAgICBjb25zdCBlbWFpbCA9IGZvcmdvdEVtYWlsSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBpZiAoIWVtYWlsKSByZXR1cm47CiAgICAgIGZvcmdvdEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGZvcmdvdFN1Y2Nlc3NFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgc2V0QXV0aEJ1c3koZm9yZ290U3VibWl0QnRuLCAiRW52b2nigKYiKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL2ZvcmdvdC1wYXNzd29yZCIsIHsgZW1haWwgfSk7CiAgICAgICAgZm9yZ290U3VjY2Vzc0VsLnRleHRDb250ZW50ID0gIlNpIHVuIGNvbXB0ZSBleGlzdGUgYXZlYyBjZXQgZW1haWwsIHVuIGxpZW4gZGUgcsOpaW5pdGlhbGlzYXRpb24gdmllbnQgZCfDqnRyZSBlbnZvecOpLiI7CiAgICAgICAgZm9yZ290U3VjY2Vzc0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHNldEF1dGhCdXN5KGZvcmdvdFN1Ym1pdEJ0biwgbnVsbCwgIkVudm95ZXIgbGUgbGllbiIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBmb3Jnb3RFcnJvckVsLnRleHRDb250ZW50ID0gZXJyLm1lc3NhZ2U7CiAgICAgICAgZm9yZ290RXJyb3JFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBzZXRBdXRoQnVzeShmb3Jnb3RTdWJtaXRCdG4sIG51bGwsICJFbnZveWVyIGxlIGxpZW4iKTsKICAgICAgfQogICAgfQogICAgZm9yZ290U3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdEZvcmdvdFBhc3N3b3JkKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmb3Jnb3QtZ290by1sb2dpbiIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc2hvd0F1dGhWaWV3KCJsb2dpbiIpKTsKCiAgICAvLyAtLS0gUsOpaW5pdGlhbGlzYXRpb24gKGRlcHVpcyBsZSBsaWVuIHJlw6d1IHBhciBlbWFpbCwgP3Jlc2V0PVRPS0VOKSAtLS0KICAgIGNvbnN0IHJlc2V0UGFzc3dvcmRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1wYXNzd29yZC1pbnB1dCIpOwogICAgY29uc3QgcmVzZXRTdWJtaXRCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVzZXQtc3VibWl0LWJ0biIpOwogICAgY29uc3QgcmVzZXRFcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlc2V0LWVycm9yIik7CiAgICBjb25zdCByZXNldFN1Y2Nlc3NFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZXNldC1zdWNjZXNzIik7CiAgICBsZXQgcGVuZGluZ1Jlc2V0VG9rZW4gPSBudWxsOwoKICAgIGFzeW5jIGZ1bmN0aW9uIGF0dGVtcHRSZXNldFBhc3N3b3JkKCkgewogICAgICBjb25zdCBuZXdfcGFzc3dvcmQgPSByZXNldFBhc3N3b3JkSW5wdXQudmFsdWU7CiAgICAgIGlmICghbmV3X3Bhc3N3b3JkIHx8ICFwZW5kaW5nUmVzZXRUb2tlbikgcmV0dXJuOwogICAgICByZXNldEVycm9yRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHJlc2V0U3VjY2Vzc0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBzZXRBdXRoQnVzeShyZXNldFN1Ym1pdEJ0biwgIlZhbGlkYXRpb27igKYiKTsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBwb3N0QXV0aCgiL2FwaS9hdXRoL3Jlc2V0LXBhc3N3b3JkIiwgeyB0b2tlbjogcGVuZGluZ1Jlc2V0VG9rZW4sIG5ld19wYXNzd29yZCB9KTsKICAgICAgICByZXNldFN1Y2Nlc3NFbC50ZXh0Q29udGVudCA9ICJNb3QgZGUgcGFzc2UgbWlzIMOgIGpvdXIsIHR1IHBldXggdGUgY29ubmVjdGVyLiI7CiAgICAgICAgcmVzZXRTdWNjZXNzRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3kocmVzZXRTdWJtaXRCdG4sIG51bGwsICJWYWxpZGVyIik7CiAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzaG93QXV0aFZpZXcoImxvZ2luIiksIDE1MDApOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICByZXNldEVycm9yRWwudGV4dENvbnRlbnQgPSBlcnIubWVzc2FnZTsKICAgICAgICByZXNldEVycm9yRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgc2V0QXV0aEJ1c3kocmVzZXRTdWJtaXRCdG4sIG51bGwsICJWYWxpZGVyIik7CiAgICAgIH0KICAgIH0KICAgIHJlc2V0U3VibWl0QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXR0ZW1wdFJlc2V0UGFzc3dvcmQpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlc2V0LWdvdG8tbG9naW4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dBdXRoVmlldygibG9naW4iKSk7CgogICAgLy8gLS0tIEFmZmljaGVyL21hc3F1ZXIgbGUgbW90IGRlIHBhc3NlIChpY8O0bmUgxZNpbCkgLS0tCiAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIucGFzc3dvcmQtdG9nZ2xlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICBjb25zdCB0YXJnZXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChidG4uZGF0YXNldC50YXJnZXQpOwogICAgICBidG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgICAgY29uc3Qgc2hvd2luZyA9IHRhcmdldC50eXBlID09PSAidGV4dCI7CiAgICAgICAgdGFyZ2V0LnR5cGUgPSBzaG93aW5nID8gInBhc3N3b3JkIiA6ICJ0ZXh0IjsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgIXNob3dpbmcpOwogICAgICAgIGJ0bi5zZXRBdHRyaWJ1dGUoImFyaWEtbGFiZWwiLCBzaG93aW5nID8gIkFmZmljaGVyIGxlIG1vdCBkZSBwYXNzZSIgOiAiTWFzcXVlciBsZSBtb3QgZGUgcGFzc2UiKTsKICAgICAgfSk7CiAgICB9KTsKCiAgICAvLyAtLS0gRMOpY29ubmV4aW9uIC0tLQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ291dC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgiU2UgZMOpY29ubmVjdGVyID8gVHUgZGV2cmFzIHJlc3NhaXNpciB0b24gbW90IGRlIHBhc3NlIHBvdXIgcmV2ZW5pci4iKTsKICAgICAgaWYgKG9rKSBzaG93TG9ja1NjcmVlbigibG9naW4iKTsKICAgIH0pOwoKICAgIC8vIC0tLSBMaWVucyByZcOndXMgcGFyIGVtYWlsICg/aW52aXRlPS4uLiBvdSA/cmVzZXQ9Li4uKSAtLS0KICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7CiAgICBjb25zdCBpbnZpdGVUb2tlbkZyb21VcmwgPSB1cmxQYXJhbXMuZ2V0KCJpbnZpdGUiKTsKICAgIGNvbnN0IHJlc2V0VG9rZW5Gcm9tVXJsID0gdXJsUGFyYW1zLmdldCgicmVzZXQiKTsKICAgIGxldCBpbml0aWFsQXV0aFZpZXcgPSAibG9naW4iOwogICAgaWYgKGludml0ZVRva2VuRnJvbVVybCkgewogICAgICBzaWdudXBJbnZpdGVJbnB1dC52YWx1ZSA9IGludml0ZVRva2VuRnJvbVVybDsKICAgICAgaW5pdGlhbEF1dGhWaWV3ID0gInNpZ251cCI7CiAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICB9IGVsc2UgaWYgKHJlc2V0VG9rZW5Gcm9tVXJsKSB7CiAgICAgIHBlbmRpbmdSZXNldFRva2VuID0gcmVzZXRUb2tlbkZyb21Vcmw7CiAgICAgIGluaXRpYWxBdXRoVmlldyA9ICJyZXNldCI7CiAgICAgIHdpbmRvdy5oaXN0b3J5LnJlcGxhY2VTdGF0ZSh7fSwgIiIsIHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZSk7CiAgICB9CgogICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInR4LWxpc3QiKTsKICAgIGNvbnN0IGVtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJlbXB0eS1zdGF0ZSIpOwogICAgY29uc3Qgc3VtbWFyeUJhbGFuY2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWJhbGFuY2UiKTsKICAgIGNvbnN0IHN1bW1hcnlFeHBlbnNlc0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktZXhwZW5zZXMiKTsKICAgIGNvbnN0IHN1bW1hcnlJbmNvbWVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LWluY29tZSIpOwoKICAgIGNvbnN0IG92ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJtb2RhbC1vdmVybGF5Iik7CiAgICBjb25zdCBtb2RhbFRpdGxlRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibW9kYWwtdGl0bGUiKTsKICAgIGNvbnN0IHR5cGVUb2dnbGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgYW1vdW50SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCBjYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWNhdGVnb3J5Iik7CiAgICBjb25zdCBuZXdDYXRlZ29yeU5hbWVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1uZXctY2F0ZWdvcnktbmFtZSIpOwogICAgY29uc3QgZGVzY3JpcHRpb25JbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1kZXNjcmlwdGlvbiIpOwogICAgY29uc3QgZGF0ZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImlucHV0LWRhdGUiKTsKICAgIGNvbnN0IHNhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXNhdmUiKTsKCiAgICBsZXQgZWRpdGluZ0lkID0gbnVsbDsgLy8gbnVsbCA9IGNyw6lhdGlvbiwgc2lub24gaWQgZGUgbGEgdHJhbnNhY3Rpb24gw6lkaXTDqWUKICAgIGxldCBlZGl0aW5nT3JpZ2luYWxDYXRlZ29yeSA9IG51bGw7IC8vIGNhdMOpZ29yaWUgZGUgbGEgdHJhbnNhY3Rpb24gYXZhbnQgw6lkaXRpb24gKHBvdXIgZMOpdGVjdGVyIHVuIGNoYW5nZW1lbnQpCiAgICBsZXQgY3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUGhvdG8gZGUgcmXDp3UgZW4gcGnDqGNlIGpvaW50ZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgcmVjZWlwdEZpbGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbnB1dC1yZWNlaXB0LWZpbGUiKTsKICAgIGNvbnN0IHJlY2VpcHRQcmV2aWV3V3JhcCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWNlaXB0LXByZXZpZXctd3JhcCIpOwogICAgY29uc3QgcmVjZWlwdFByZXZpZXdJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1wcmV2aWV3LWltZyIpOwogICAgY29uc3QgcmVjZWlwdFBpY2tCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlY2VpcHQtcGljayIpOwogICAgY29uc3QgcmVjZWlwdFJlbW92ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tcmVjZWlwdC1yZW1vdmUiKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveE92ZXJsYXkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1vdmVybGF5Iik7CiAgICBjb25zdCByZWNlaXB0TGlnaHRib3hJbWcgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjZWlwdC1saWdodGJveC1pbWciKTsKICAgIGNvbnN0IHJlY2VpcHRMaWdodGJveENsb3NlQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlY2VpcHQtbGlnaHRib3gtY2xvc2UiKTsKCiAgICAvLyBGaWNoaWVyIGNob2lzaSBtYWlzIHBhcyBlbmNvcmUgZW52b3nDqSAodW5pcXVlbWVudCBlbiBjcsOpYXRpb24sIHRhbnQgcXVlCiAgICAvLyBsYSB0cmFuc2FjdGlvbiBuJ2EgcGFzIGVuY29yZSBkJ2lkKSA7IGVuIMOpZGl0aW9uLCBsJ2Vudm9pIGVzdCBpbW3DqWRpYXQuCiAgICBsZXQgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgIGxldCByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICBsZXQgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2V0UmVjZWlwdFByZXZpZXdGcm9tQmxvYihibG9iKSB7CiAgICAgIGlmIChyZWNlaXB0UHJldmlld09iamVjdFVybCkgVVJMLnJldm9rZU9iamVjdFVSTChyZWNlaXB0UHJldmlld09iamVjdFVybCk7CiAgICAgIHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gcmVjZWlwdFByZXZpZXdPYmplY3RVcmw7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBSZW1wbGFjZXIgbGEgcGhvdG8iOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlc2V0UmVjZWlwdFVpKCkgewogICAgICBpZiAocmVjZWlwdFByZXZpZXdPYmplY3RVcmwpIHsKICAgICAgICBVUkwucmV2b2tlT2JqZWN0VVJMKHJlY2VpcHRQcmV2aWV3T2JqZWN0VXJsKTsKICAgICAgICByZWNlaXB0UHJldmlld09iamVjdFVybCA9IG51bGw7CiAgICAgIH0KICAgICAgcmVjZWlwdFByZXZpZXdJbWcuc3JjID0gIiI7CiAgICAgIHJlY2VpcHRQcmV2aWV3V3JhcC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgcmVjZWlwdFBpY2tCdG4udGV4dENvbnRlbnQgPSAi8J+TtyBBam91dGVyIHVuZSBwaG90byBkZSByZcOndSI7CiAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgcGVuZGluZ1JlY2VpcHRGaWxlID0gbnVsbDsKICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gZmFsc2U7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEV4aXN0aW5nUmVjZWlwdFByZXZpZXcodHJhbnNhY3Rpb25JZCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke3RyYW5zYWN0aW9uSWR9L3JlY2VpcHRgLCB7CiAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHJldHVybjsKICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgcmVzLmJsb2IoKTsKICAgICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGJsb2IpOwogICAgICAgIGhhc0V4aXN0aW5nUmVjZWlwdCA9IHRydWU7CiAgICAgIH0gY2F0Y2ggKF8pIHsKICAgICAgICAvLyBQYXMgZ3JhdmUgOiBsJ3V0aWxpc2F0ZXVyIHBldXQganVzdGUgcsOpZXNzYXllciBkJ291dnJpciBsYSBmaWNoZS4KICAgICAgfQogICAgfQoKICAgIHJlY2VpcHRQaWNrQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gcmVjZWlwdEZpbGVJbnB1dC5jbGljaygpKTsKCiAgICByZWNlaXB0RmlsZUlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IHJlY2VpcHRGaWxlSW5wdXQuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBpZiAoIWZpbGUudHlwZS5zdGFydHNXaXRoKCJpbWFnZS8iKSkgewogICAgICAgIHNob3dUb2FzdCgiQ2hvaXNpcyB1bmUgaW1hZ2UgKEpQRUcsIFBORywgV0VCUCBvdSBIRUlDKSIsIHRydWUpOwogICAgICAgIHJlY2VpcHRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgaWYgKGZpbGUuc2l6ZSA+IDggKiAxMDI0ICogMTAyNCkgewogICAgICAgIHNob3dUb2FzdCgiSW1hZ2UgdHJvcCBsb3VyZGUgKDggTW8gbWF4aW11bSkiLCB0cnVlKTsKICAgICAgICByZWNlaXB0RmlsZUlucHV0LnZhbHVlID0gIiI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBzZXRSZWNlaXB0UHJldmlld0Zyb21CbG9iKGZpbGUpOwoKICAgICAgaWYgKGVkaXRpbmdJZCkgewogICAgICAgIC8vIFRyYW5zYWN0aW9uIGTDqWrDoCBleGlzdGFudGUgOiBvbiBlbnZvaWUgdG91dCBkZSBzdWl0ZSwgaW5kw6lwZW5kYW1tZW50CiAgICAgICAgLy8gZHUgYm91dG9uICJFbnJlZ2lzdHJlciIgZHUgZm9ybXVsYWlyZS4KICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTsKICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIGZpbGUpOwogICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7ZWRpdGluZ0lkfS9yZWNlaXB0YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgICAgfSkudGhlbihhc3luYyAocmVzKSA9PiB7CiAgICAgICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEuZGV0YWlsIHx8IGBFcnJldXIgSFRUUCAke3Jlcy5zdGF0dXN9YCk7CiAgICAgICAgICAgIH0KICAgICAgICAgIH0pOwogICAgICAgICAgaGFzRXhpc3RpbmdSZWNlaXB0ID0gdHJ1ZTsKICAgICAgICAgIHNob3dUb2FzdCgiUGhvdG8gZHUgcmXDp3UgZW5yZWdpc3Ryw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIC8vIE5vdXZlbGxlIHRyYW5zYWN0aW9uIHBhcyBlbmNvcmUgY3LDqcOpZSA6IG9uIGdhcmRlIGxlIGZpY2hpZXIgZGUgY8O0dMOpLAogICAgICAgIC8vIGlsIHNlcmEgZW52b3nDqSBqdXN0ZSBhcHLDqHMgbGEgY3LDqWF0aW9uICh2b2lyIGJ0bi1zYXZlKS4KICAgICAgICBwZW5kaW5nUmVjZWlwdEZpbGUgPSBmaWxlOwogICAgICB9CiAgICB9KTsKCiAgICByZWNlaXB0UmVtb3ZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBpZiAoZWRpdGluZ0lkICYmIGhhc0V4aXN0aW5nUmVjZWlwdCkgewogICAgICAgIGlmICghKGF3YWl0IHNob3dDb25maXJtKCJTdXBwcmltZXIgbGEgcGhvdG8gZGUgY2UgcmXDp3UgPyIpKSkgcmV0dXJuOwogICAgICAgIHRyeSB7CiAgICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtlZGl0aW5nSWR9L3JlY2VpcHRgLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICAgICAgc2hvd1RvYXN0KCJQaG90byBzdXBwcmltw6llIik7CiAgICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIHJlc2V0UmVjZWlwdFVpKCk7CiAgICAgIH0KICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWNlaXB0TGlnaHRib3godHJhbnNhY3Rpb25JZCkgewogICAgICBmZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHt0cmFuc2FjdGlvbklkfS9yZWNlaXB0YCwgeyBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0gfSkKICAgICAgICAudGhlbigocmVzKSA9PiB7CiAgICAgICAgICBpZiAoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCJJbXBvc3NpYmxlIGRlIGNoYXJnZXIgbGEgcGhvdG8iKTsKICAgICAgICAgIHJldHVybiByZXMuYmxvYigpOwogICAgICAgIH0pCiAgICAgICAgLnRoZW4oKGJsb2IpID0+IHsKICAgICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgICByZWNlaXB0TGlnaHRib3hJbWcuc3JjID0gdXJsOwogICAgICAgICAgcmVjZWlwdExpZ2h0Ym94T3ZlcmxheS5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICB9KQogICAgICAgIC5jYXRjaCgoZXJyKSA9PiBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSkpOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlUmVjZWlwdExpZ2h0Ym94KCkgewogICAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBpZiAocmVjZWlwdExpZ2h0Ym94SW1nLnNyYykgewogICAgICAgIFVSTC5yZXZva2VPYmplY3RVUkwocmVjZWlwdExpZ2h0Ym94SW1nLnNyYyk7CiAgICAgICAgcmVjZWlwdExpZ2h0Ym94SW1nLnNyYyA9ICIiOwogICAgICB9CiAgICB9CgogICAgcmVjZWlwdExpZ2h0Ym94Q2xvc2VCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY2VpcHRMaWdodGJveCk7CiAgICByZWNlaXB0TGlnaHRib3hPdmVybGF5LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgaWYgKGUudGFyZ2V0ID09PSByZWNlaXB0TGlnaHRib3hPdmVybGF5KSBjbG9zZVJlY2VpcHRMaWdodGJveCgpOwogICAgfSk7CgogICAgY29uc3QgY2F0ZWdvcmllc0J5VHlwZSA9IHsKICAgICAgZXhwZW5zZTogWwogICAgICAgIFsicmVzdGF1cmFudCIsICJSZXN0YXVyYW50Il0sCiAgICAgICAgWyJjb3Vyc2VzIiwgIkNvdXJzZXMiXSwKICAgICAgICBbInRyYW5zcG9ydCIsICJUcmFuc3BvcnQiXSwKICAgICAgICBbImxvZ2VtZW50IiwgIkxvZ2VtZW50Il0sCiAgICAgICAgWyJsb2lzaXJzIiwgIkxvaXNpcnMiXSwKICAgICAgICBbInNhbnTDqSIsICJTYW50w6kiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICAgIGluY29tZTogWwogICAgICAgIFsic2FsYWlyZSIsICJTYWxhaXJlIl0sCiAgICAgICAgWyJmcmVlbGFuY2UiLCAiRnJlZWxhbmNlIl0sCiAgICAgICAgWyJyZW1ib3Vyc2VtZW50IiwgIlJlbWJvdXJzZW1lbnQiXSwKICAgICAgICBbImNhZGVhdSIsICJDYWRlYXUiXSwKICAgICAgICBbImF1dHJlIiwgIkF1dHJlIl0sCiAgICAgIF0sCiAgICB9OwoKICAgIGNvbnN0IGFsbENhdGVnb3J5TGFiZWxzID0gT2JqZWN0LmZyb21FbnRyaWVzKAogICAgICBbLi4uY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlLCAuLi5jYXRlZ29yaWVzQnlUeXBlLmluY29tZV0KICAgICk7CgogICAgLy8gQ2F0w6lnb3JpZXMgY3LDqcOpZXMgcGFyIGwndXRpbGlzYXRldXIgZGVwdWlzIGxlIGJhbmRlYXUgZGUgc3VnZ2VzdGlvbgogICAgLy8gKHZvaXIgcGx1cyBiYXMpLCBldCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMgOiBzdG9ja8OpZXMgY8O0dMOpIHNlcnZldXIKICAgIC8vICh0YWJsZXMgY3VzdG9tX2NhdGVnb3JpZXMgLyBkaXNtaXNzZWRfY2F0ZWdvcnlfc3VnZ2VzdGlvbnMpIHBsdXTDtHQKICAgIC8vIHF1ZSBkYW5zIGxlIG5hdmlnYXRldXIsIHBvdXIgc3VpdnJlIHN1ciB0b3VzIGxlcyBhcHBhcmVpbHMgKHTDqWzDqXBob25lLAogICAgLy8gdGFibGV0dGUsIG9yZGluYXRldXIpIHBsdXTDtHQgcXVlIGRlIG5lIG1hcmNoZXIgcXVlIGzDoCBvw7kgYyfDqXRhaXQgY3LDqcOpLgogICAgbGV0IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldCgpOwogICAgbGV0IGFsbEJ1ZGdldHMgPSBbXTsKCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkQnVkZ2V0cygpIHsKICAgICAgdHJ5IHsKICAgICAgICBhbGxCdWRnZXRzID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvYnVkZ2V0cyIpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBidWRnZXRzIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gT2JqZWN0aWYgZCfDqXBhcmduZSBtZW5zdWVsICsgY29uc2VpbHMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGxldCBzYXZpbmdzR29hbCA9IG51bGw7IC8vIHsgbW9udGhseV90YXJnZXQgfSBvdSBudWxsIHNpIGphbWFpcyBjb25maWd1csOpCgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFNhdmluZ3NHb2FsKCkgewogICAgICB0cnkgewogICAgICAgIHNhdmluZ3NHb2FsID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvc2F2aW5ncy1nb2FsIik7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIGRlIGNoYXJnZW1lbnQgZGUgbCdvYmplY3RpZiBkJ8OpcGFyZ25lIDogIiArIChlcnIubWVzc2FnZSB8fCAidW5lIGVycmV1ciBlc3Qgc3VydmVudWUiKSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnVkZ2V0cy1zYXZlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZW50cmllcyA9IE9iamVjdC5lbnRyaWVzKGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnkpOwogICAgICBsZXQgc2F2ZWRDb3VudCA9IDA7CiAgICAgIGxldCBoYWRFcnJvciA9IGZhbHNlOwogICAgICBmb3IgKGNvbnN0IFtjYXRlZ29yeSwgaW5wdXRdIG9mIGVudHJpZXMpIHsKICAgICAgICBjb25zdCByYXcgPSBpbnB1dC52YWx1ZTsKICAgICAgICBpZiAocmF3ID09PSAiIiB8fCByYXcgPT09IG51bGwpIGNvbnRpbnVlOwogICAgICAgIGNvbnN0IGFtb3VudCA9IE51bWJlcihyYXcpOwogICAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSBjb250aW51ZTsKICAgICAgICB0cnkgewogICAgICAgICAgYXdhaXQgc2F2ZUJ1ZGdldChjYXRlZ29yeSwgYW1vdW50KTsKICAgICAgICAgIHNhdmVkQ291bnQgKz0gMTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIGhhZEVycm9yID0gdHJ1ZTsKICAgICAgICB9CiAgICAgIH0KICAgICAgaWYgKGhhZEVycm9yKSB7CiAgICAgICAgc2hvd1RvYXN0KCJDZXJ0YWlucyBidWRnZXRzIG4nb250IHBhcyBwdSDDqnRyZSBlbnJlZ2lzdHLDqXMiLCB0cnVlKTsKICAgICAgfSBlbHNlIGlmIChzYXZlZENvdW50ID09PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIGF1IG1vaW5zIHVuIG1vbnRhbnQgZGUgYnVkZ2V0IHZhbGlkZSIsIHRydWUpOwogICAgICB9IGVsc2UgewogICAgICAgIHNob3dUb2FzdCgiQnVkZ2V0cyBlbnJlZ2lzdHLDqXMiKTsKICAgICAgfQogICAgICByZW5kZXJCdWRnZXRzKGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICBjb25zdCBzYXZpbmdzR29hbElucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1pbnB1dCIpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtZ29hbC1zYXZlLWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBOdW1iZXIoc2F2aW5nc0dvYWxJbnB1dC52YWx1ZSk7CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7CiAgICAgICAgc2hvd1RvYXN0KCJJbmRpcXVlIHVuIG1vbnRhbnQgZCdvYmplY3RpZiB2YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgdHJ5IHsKICAgICAgICBzYXZpbmdzR29hbCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3NhdmluZ3MtZ29hbCIsIHsKICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IG1vbnRobHlfdGFyZ2V0OiBhbW91bnQgfSksCiAgICAgICAgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJPYmplY3RpZiBlbnJlZ2lzdHLDqSIpOwogICAgICAgIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgfQogICAgfSk7CgogICAgZnVuY3Rpb24gcmVuZGVyU2F2aW5ncyh0cmFuc2FjdGlvbnMpIHsKICAgICAgaWYgKHNhdmluZ3NHb2FsKSBzYXZpbmdzR29hbElucHV0LnZhbHVlID0gc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQ7CgogICAgICAvLyBTb2xkZSBkdSBtb2lzIGVuIGNvdXJzIChyZXZlbnVzIC0gZMOpcGVuc2VzKSwgdG91dCBjb25mb25kdS4KICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgbGV0IG1vbnRoSW5jb21lID0gMDsKICAgICAgbGV0IG1vbnRoRXhwZW5zZXMgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmIChtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgIT09IGN1cnJlbnRNb250aEtleSkgY29udGludWU7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSBtb250aEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICBlbHNlIG1vbnRoRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbW9udGhOZXQgPSBtb250aEluY29tZSAtIG1vbnRoRXhwZW5zZXM7CgogICAgICBjb25zdCBwcm9ncmVzc1NlY3Rpb24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy1zZWN0aW9uIik7CiAgICAgIGNvbnN0IHByb2dyZXNzVGV4dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLXByb2dyZXNzLXRleHQiKTsKICAgICAgY29uc3QgcHJvZ3Jlc3NCYXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2F2aW5ncy1wcm9ncmVzcy1iYXIiKTsKICAgICAgaWYgKHNhdmluZ3NHb2FsICYmIHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0ID4gMCkgewogICAgICAgIHByb2dyZXNzU2VjdGlvbi5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgICBjb25zdCB0YXJnZXQgPSBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldDsKICAgICAgICBjb25zdCBwY3QgPSBNYXRoLm1heCgwLCBNYXRoLm1pbigobW9udGhOZXQgLyB0YXJnZXQpICogMTAwLCAxMDApKTsKICAgICAgICBwcm9ncmVzc1RleHQudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobW9udGhOZXQpfSAvICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRhcmdldCl9YDsKICAgICAgICBsZXQgY2xzID0gIm9rIjsKICAgICAgICBpZiAobW9udGhOZXQgPCAwKSBjbHMgPSAib3ZlciI7CiAgICAgICAgZWxzZSBpZiAobW9udGhOZXQgPCB0YXJnZXQpIGNscyA9ICJ3YXJuaW5nIjsKICAgICAgICBwcm9ncmVzc0Jhci5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci1maWxsICIgKyBjbHM7CiAgICAgICAgcHJvZ3Jlc3NCYXIuc3R5bGUud2lkdGggPSBwY3QgKyAiJSI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgcHJvZ3Jlc3NTZWN0aW9uLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB9CgogICAgICByZW5kZXJTYXZpbmdzQWR2aWNlKHRyYW5zYWN0aW9ucywgbW9udGhOZXQpOwogICAgICByZW5kZXJQbGFjZW1lbnRTaW11bGF0aW9uKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU2ltdWxhdGlvbiBkZSBwbGFjZW1lbnQgKGludMOpcsOqdHMgY29tcG9zw6lzLCBjYWxjdWzDqXMgbWVuc3VlbGxlbWVudCkg4oCUCiAgICAvLyBwdXJlbWVudCBjw7R0w6kgY2xpZW50IDogYXVjdW5lIGRvbm7DqWUgcsOpZWxsZSBkZSBsJ3V0aWxpc2F0ZXVyIG4nZW50cmUKICAgIC8vIGVuIGpldSwgc2V1bGVtZW50IGxlcyA0IGNoYW1wcyBkdSBmb3JtdWxhaXJlLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgbGV0IHBsYWNlbWVudENoYXJ0ID0gbnVsbDsKCiAgICBmdW5jdGlvbiBjb21wdXRlUGxhY2VtZW50U2VyaWVzKGluaXRpYWwsIG1vbnRobHlDb250cmlidXRpb24sIGFubnVhbFJhdGVQZXJjZW50LCB5ZWFycykgewogICAgICBjb25zdCBtb250aHMgPSBNYXRoLm1heCgxLCBNYXRoLnJvdW5kKHllYXJzICogMTIpKTsKICAgICAgY29uc3QgbW9udGhseVJhdGUgPSBNYXRoLnBvdygxICsgYW5udWFsUmF0ZVBlcmNlbnQgLyAxMDAsIDEgLyAxMikgLSAxOwogICAgICBsZXQgYmFsYW5jZSA9IGluaXRpYWw7CiAgICAgIGNvbnN0IHNlcmllcyA9IFtiYWxhbmNlXTsKICAgICAgZm9yIChsZXQgbSA9IDE7IG0gPD0gbW9udGhzOyBtKyspIHsKICAgICAgICBiYWxhbmNlID0gYmFsYW5jZSAqICgxICsgbW9udGhseVJhdGUpICsgbW9udGhseUNvbnRyaWJ1dGlvbjsKICAgICAgICBzZXJpZXMucHVzaChiYWxhbmNlKTsKICAgICAgfQogICAgICByZXR1cm4gc2VyaWVzOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclBsYWNlbWVudFNpbXVsYXRpb24oKSB7CiAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjaGFydC1wbGFjZW1lbnQiKTsKICAgICAgaWYgKCFjYW52YXMpIHJldHVybjsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtY2hhcnQtZW1wdHkiKTsKICAgICAgY29uc3QgaW5pdGlhbCA9IE1hdGgubWF4KDAsIE51bWJlcihkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LWluaXRpYWwiKS52YWx1ZSkgfHwgMCk7CiAgICAgIGNvbnN0IG1vbnRobHkgPSBNYXRoLm1heCgwLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC1tb250aGx5IikudmFsdWUpIHx8IDApOwogICAgICBjb25zdCByYXRlID0gTWF0aC5tYXgoMCwgTnVtYmVyKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwbGFjZW1lbnQtcmF0ZSIpLnZhbHVlKSB8fCAwKTsKICAgICAgY29uc3QgeWVhcnMgPSBNYXRoLm1heCgxLCBOdW1iZXIoZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBsYWNlbWVudC15ZWFycyIpLnZhbHVlKSB8fCAxKTsKCiAgICAgIGNvbnN0IHNlcmllcyA9IGNvbXB1dGVQbGFjZW1lbnRTZXJpZXMoaW5pdGlhbCwgbW9udGhseSwgcmF0ZSwgeWVhcnMpOwogICAgICBjb25zdCBtb250aHMgPSBzZXJpZXMubGVuZ3RoIC0gMTsKICAgICAgY29uc3QgbGFiZWxzID0gc2VyaWVzLm1hcCgoXywgaSkgPT4gKAogICAgICAgIGkgJSAxMiA9PT0gMCA/IGBBbiAke2kgLyAxMn1gIDogIiIKICAgICAgKSk7CgogICAgICBpZiAocGxhY2VtZW50Q2hhcnQpIHsgcGxhY2VtZW50Q2hhcnQuZGVzdHJveSgpOyBwbGFjZW1lbnRDaGFydCA9IG51bGw7IH0KICAgICAgaWYgKGVtcHR5RWwpIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICBwbGFjZW1lbnRDaGFydCA9IHNhZmVDcmVhdGVDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAibGluZSIsCiAgICAgICAgZGF0YTogewogICAgICAgICAgbGFiZWxzLAogICAgICAgICAgZGF0YXNldHM6IFt7CiAgICAgICAgICAgIGxhYmVsOiAiU29sZGUgcHJvamV0w6kiLAogICAgICAgICAgICBkYXRhOiBzZXJpZXMsCiAgICAgICAgICAgIGJvcmRlckNvbG9yOiBDSEFSVF9DT0xPUlNbMV0sCiAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogInJnYmEoMzQsIDE5NywgOTQsIDAuMTUpIiwKICAgICAgICAgICAgZmlsbDogdHJ1ZSwKICAgICAgICAgICAgdGVuc2lvbjogMC4yLAogICAgICAgICAgICBwb2ludFJhZGl1czogMCwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogeyBsZWdlbmQ6IHsgZGlzcGxheTogZmFsc2UgfSB9LAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHk6IHsgdGlja3M6IHsgY2FsbGJhY2s6ICh2KSA9PiBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodikgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9LCBlbXB0eUVsKTsKCiAgICAgIGNvbnN0IGZpbmFsQmFsYW5jZSA9IHNlcmllc1tzZXJpZXMubGVuZ3RoIC0gMV07CiAgICAgIGNvbnN0IHRvdGFsQ29udHJpYnV0ZWQgPSBpbml0aWFsICsgbW9udGhseSAqIG1vbnRoczsKICAgICAgY29uc3QgaW50ZXJlc3RFYXJuZWQgPSBmaW5hbEJhbGFuY2UgLSB0b3RhbENvbnRyaWJ1dGVkOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicGxhY2VtZW50LXJlc3VsdCIpLmlubmVySFRNTCA9CiAgICAgICAgYEFwcsOocyAke3llYXJzfSBhbiR7eWVhcnMgPiAxID8gInMiIDogIiJ9IDogPHN0cm9uZz4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChmaW5hbEJhbGFuY2UpfTwvc3Ryb25nPiBgICsKICAgICAgICBgKGRvbnQgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaW50ZXJlc3RFYXJuZWQpfSBkJ2ludMOpcsOqdHMsIHBvdXIgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodG90YWxDb250cmlidXRlZCl9IHZlcnPDqXMpLmA7CiAgICB9CgogICAgZm9yIChjb25zdCBpZCBvZiBbInBsYWNlbWVudC1pbml0aWFsIiwgInBsYWNlbWVudC1tb250aGx5IiwgInBsYWNlbWVudC1yYXRlIiwgInBsYWNlbWVudC15ZWFycyJdKSB7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKS5hZGRFdmVudExpc3RlbmVyKCJpbnB1dCIsIHJlbmRlclBsYWNlbWVudFNpbXVsYXRpb24pOwogICAgfQoKICAgIC8vIENvbnNlaWxzIDogY3JvaXNlIGTDqXBhc3NlbWVudHMgZGUgYnVkZ2V0IChvbmdsZXQgVGFibGVhdSBkZSBib3JkKSBldAogICAgLy8gdGVuZGFuY2VzIHBhciBjYXTDqWdvcmllIHBvdXIgcG9pbnRlciB2ZXJzIGNlIHF1aSBhaWRlIGxlIHBsdXMgw6AKICAgIC8vIGF0dGVpbmRyZSBsJ29iamVjdGlmIOKAlCBwYXMgdW5lIElBLCBqdXN0ZSBkZXMgcsOoZ2xlcyBzaW1wbGVzIHN1ciBkZXMKICAgIC8vIGRvbm7DqWVzIGTDqWrDoCBjYWxjdWzDqWVzIGFpbGxldXJzIGRhbnMgbCdhcHAuCiAgICBmdW5jdGlvbiByZW5kZXJTYXZpbmdzQWR2aWNlKHRyYW5zYWN0aW9ucywgbW9udGhOZXQpIHsKICAgICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInNhdmluZ3MtYWR2aWNlLWxpc3QiKTsKICAgICAgY29uc3QgZW1wdHlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzYXZpbmdzLWFkdmljZS1lbXB0eSIpOwogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGNvbnN0IGFkdmljZSA9IFtdOwoKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgeyB0b3RhbHM6IG1vbnRoVG90YWxzIH0gPSBtb250aENhdGVnb3J5VG90YWxzKHRyYW5zYWN0aW9ucywgY3VycmVudE1vbnRoS2V5KTsKICAgICAgY29uc3QgdHJlbmRzID0gY29tcHV0ZUNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIGNvbnN0IHRyZW5kQnlDYXRlZ29yeSA9IE9iamVjdC5mcm9tRW50cmllcyh0cmVuZHMubWFwKCh0KSA9PiBbdC5jYXRlZ29yeSwgdF0pKTsKCiAgICAgIC8vIENhdMOpZ29yaWVzIGVuIGTDqXBhc3NlbWVudCBkZSBidWRnZXQsIHRyacOpZXMgcGFyIG1vbnRhbnQgZGUKICAgICAgLy8gZMOpcGFzc2VtZW50IGTDqWNyb2lzc2FudCDigJQgY2Ugc29udCBsZXMgbGV2aWVycyBsZXMgcGx1cyB1dGlsZXMuCiAgICAgIGNvbnN0IG92ZXJCdWRnZXQgPSBbXTsKICAgICAgZm9yIChjb25zdCBidWRnZXQgb2YgYWxsQnVkZ2V0cykgewogICAgICAgIGNvbnN0IHNwZW50ID0gbW9udGhUb3RhbHNbYnVkZ2V0LmNhdGVnb3J5XSB8fCAwOwogICAgICAgIGlmIChzcGVudCA+IGJ1ZGdldC5hbW91bnQpIHsKICAgICAgICAgIG92ZXJCdWRnZXQucHVzaCh7IGNhdGVnb3J5OiBidWRnZXQuY2F0ZWdvcnksIHNwZW50LCBidWRnZXQ6IGJ1ZGdldC5hbW91bnQsIG92ZXI6IHNwZW50IC0gYnVkZ2V0LmFtb3VudCB9KTsKICAgICAgICB9CiAgICAgIH0KICAgICAgb3ZlckJ1ZGdldC5zb3J0KChhLCBiKSA9PiBiLm92ZXIgLSBhLm92ZXIpOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIG92ZXJCdWRnZXQuc2xpY2UoMCwgMykpIHsKICAgICAgICBjb25zdCBsYWJlbCA9IGVzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeSk7CiAgICAgICAgY29uc3QgdHJlbmQgPSB0cmVuZEJ5Q2F0ZWdvcnlbaXRlbS5jYXRlZ29yeV07CiAgICAgICAgbGV0IHRleHQgPSBgVHUgYXMgZMOpcGFzc8OpIHRvbiBidWRnZXQgPHN0cm9uZz4ke2xhYmVsfTwvc3Ryb25nPiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChpdGVtLm92ZXIpfSBjZSBtb2lzLWNpLmA7CiAgICAgICAgaWYgKHRyZW5kICYmIHRyZW5kLmRpcmVjdGlvbiA9PT0gInVwIikgewogICAgICAgICAgdGV4dCArPSBgIExhIHRlbmRhbmNlIGVzdCDDoCBsYSBoYXVzc2UgKCske01hdGgucm91bmQodHJlbmQucmF0aW8gKiAxMDApfSUgdnMgdGEgbW95ZW5uZSkg4oCUIHLDqWR1aXJlIGNlcyBkw6lwZW5zZXMgdCdhaWRlcmFpdCBsZSBwbHVzIMOgIGF0dGVpbmRyZSB0b24gb2JqZWN0aWYuYDsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgdGV4dCArPSBgIEVzc2FpZSBkZSByYW1lbmVyIMOnYSBzb3VzICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYnVkZ2V0KX0gbGUgbW9pcyBwcm9jaGFpbi5gOwogICAgICAgIH0KICAgICAgICBhZHZpY2UucHVzaCh7IHR5cGU6ICJ3YXJuaW5nIiwgaWNvbjogIuKaoO+4jyIsIHRleHQgfSk7CiAgICAgIH0KCiAgICAgIC8vIENhdMOpZ29yaWVzIGVuIG5ldHRlIGhhdXNzZSBtw6ptZSBzYW5zIGJ1ZGdldCBkw6lwYXNzw6kgKG91IHNhbnMgYnVkZ2V0CiAgICAgIC8vIGTDqWZpbmkgZHUgdG91dCkgOiB1biBzaWduYWwgdXRpbGUgZW4gc29pLgogICAgICBjb25zdCByaXNpbmdXaXRob3V0QnVkZ2V0QWxlcnQgPSB0cmVuZHMKICAgICAgICAuZmlsdGVyKCh0KSA9PiB0LmRpcmVjdGlvbiA9PT0gInVwIiAmJiB0LmF2ZXJhZ2UgPiAwICYmICFvdmVyQnVkZ2V0LnNvbWUoKG8pID0+IG8uY2F0ZWdvcnkgPT09IHQuY2F0ZWdvcnkpKQogICAgICAgIC5zb3J0KChhLCBiKSA9PiBiLnJhdGlvIC0gYS5yYXRpbykKICAgICAgICAuc2xpY2UoMCwgMik7CiAgICAgIGZvciAoY29uc3QgdCBvZiByaXNpbmdXaXRob3V0QnVkZ2V0QWxlcnQpIHsKICAgICAgICBjb25zdCBsYWJlbCA9IGVzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbdC5jYXRlZ29yeV0gfHwgdC5jYXRlZ29yeSk7CiAgICAgICAgYWR2aWNlLnB1c2goewogICAgICAgICAgdHlwZTogImluZm8iLAogICAgICAgICAgaWNvbjogIvCfk4giLAogICAgICAgICAgdGV4dDogYFRlcyBkw6lwZW5zZXMgZW4gPHN0cm9uZz4ke2xhYmVsfTwvc3Ryb25nPiBzb250IGVuIGhhdXNzZSBkZSAke01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JSBwYXIgcmFwcG9ydCDDoCB0YSBtb3llbm5lIOKAlCDDoCBzdXJ2ZWlsbGVyIHNpIHR1IHZldXggw6lwYXJnbmVyIHBsdXMuYCwKICAgICAgICB9KTsKICAgICAgfQoKICAgICAgLy8gT2JqZWN0aWYgYXR0ZWludCAvIGVuIGJvbm5lIHZvaWUgY2UgbW9pcy1jaS4KICAgICAgaWYgKHNhdmluZ3NHb2FsICYmIHNhdmluZ3NHb2FsLm1vbnRobHlfdGFyZ2V0ID4gMCkgewogICAgICAgIGlmIChtb250aE5ldCA+PSBzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCkgewogICAgICAgICAgYWR2aWNlLnVuc2hpZnQoewogICAgICAgICAgICB0eXBlOiAicG9zaXRpdmUiLAogICAgICAgICAgICBpY29uOiAi8J+OiSIsCiAgICAgICAgICAgIHRleHQ6IGBPYmplY3RpZiBhdHRlaW50ICEgVHUgYXMgZMOpasOgIG1pcyAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChtb250aE5ldCl9IGRlIGPDtHTDqSBjZSBtb2lzLWNpLCBhdS1kZWzDoCBkZSB0b24gb2JqZWN0aWYgZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQpfS5gLAogICAgICAgICAgfSk7CiAgICAgICAgfSBlbHNlIGlmIChvdmVyQnVkZ2V0Lmxlbmd0aCA9PT0gMCAmJiByaXNpbmdXaXRob3V0QnVkZ2V0QWxlcnQubGVuZ3RoID09PSAwKSB7CiAgICAgICAgICBhZHZpY2UudW5zaGlmdCh7CiAgICAgICAgICAgIHR5cGU6ICJpbmZvIiwKICAgICAgICAgICAgaWNvbjogIvCfkY0iLAogICAgICAgICAgICB0ZXh0OiBgUGFzIGRlIGTDqXBhc3NlbWVudCBkZSBidWRnZXQgY2UgbW9pcy1jaS4gSWwgdGUgcmVzdGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoc2F2aW5nc0dvYWwubW9udGhseV90YXJnZXQgLSBtb250aE5ldCl9IMOgIMOpY29ub21pc2VyIHBvdXIgYXR0ZWluZHJlIHRvbiBvYmplY3RpZiBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChzYXZpbmdzR29hbC5tb250aGx5X3RhcmdldCl9LmAsCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGlmIChhZHZpY2UubGVuZ3RoID09PSAwKSB7CiAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFkdmljZSkgewogICAgICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBjYXJkLmNsYXNzTmFtZSA9ICJhZHZpY2UtY2FyZCAiICsgaXRlbS50eXBlOwogICAgICAgIGNvbnN0IGljb24gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgaWNvbi5jbGFzc05hbWUgPSAiYWR2aWNlLWljb24iOwogICAgICAgIGljb24udGV4dENvbnRlbnQgPSBpdGVtLmljb247CiAgICAgICAgY29uc3QgdGV4dCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICB0ZXh0LmlubmVySFRNTCA9IGl0ZW0udGV4dDsKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKGljb24pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQodGV4dCk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gc2F2ZUJ1ZGdldChjYXRlZ29yeSwgYW1vdW50KSB7CiAgICAgIGNvbnN0IHVwZGF0ZWQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9idWRnZXRzIiwgewogICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBjYXRlZ29yeSwgYW1vdW50IH0pLAogICAgICB9KTsKICAgICAgY29uc3QgaWR4ID0gYWxsQnVkZ2V0cy5maW5kSW5kZXgoKGIpID0+IGIuY2F0ZWdvcnkgPT09IGNhdGVnb3J5KTsKICAgICAgaWYgKGlkeCA+PSAwKSBhbGxCdWRnZXRzW2lkeF0gPSB1cGRhdGVkOwogICAgICBlbHNlIGFsbEJ1ZGdldHMucHVzaCh1cGRhdGVkKTsKICAgIH0KCiAgICBjb25zdCBidWRnZXRJbnB1dHNCeUNhdGVnb3J5ID0ge307CiAgICBjb25zdCBCVURHRVRfSElTVE9SWV9NT05USFMgPSA2OwoKICAgIC8vIExlcyBOIGRlcm5pZXJzIG1vaXMgKGNsw6lzICJZWVlZLU1NIiksIGR1IHBsdXMgYW5jaWVuIGF1IHBsdXMgcsOpY2VudCwKICAgIC8vIGVuIGZpbmlzc2FudCBwYXIgZW5kTW9udGhLZXkgaW5jbHVzLgogICAgZnVuY3Rpb24gbGFzdE5Nb250aEtleXMobiwgZW5kTW9udGhLZXkpIHsKICAgICAgY29uc3QgW3ksIG1dID0gZW5kTW9udGhLZXkuc3BsaXQoIi0iKS5tYXAoTnVtYmVyKTsKICAgICAgY29uc3Qga2V5cyA9IFtdOwogICAgICBmb3IgKGxldCBpID0gbiAtIDE7IGkgPj0gMDsgaS0tKSB7CiAgICAgICAgY29uc3QgZCA9IG5ldyBEYXRlKHksIG0gLSAxIC0gaSwgMSk7CiAgICAgICAga2V5cy5wdXNoKGQuZ2V0RnVsbFllYXIoKSArICItIiArIFN0cmluZyhkLmdldE1vbnRoKCkgKyAxKS5wYWRTdGFydCgyLCAiMCIpKTsKICAgICAgfQogICAgICByZXR1cm4ga2V5czsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJCdWRnZXRzKHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCB3cmFwID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ1ZGdldHMtbGlzdCIpOwogICAgICBpZiAoIXdyYXApIHJldHVybjsKICAgICAgY29uc3QgY3VycmVudE1vbnRoS2V5ID0gbW9udGhLZXlPZih0b2RheUlzbygpKTsKICAgICAgY29uc3QgeyB0b3RhbHMgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBjdXJyZW50TW9udGhLZXkpOwoKICAgICAgd3JhcC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMoYnVkZ2V0SW5wdXRzQnlDYXRlZ29yeSkpIGRlbGV0ZSBidWRnZXRJbnB1dHNCeUNhdGVnb3J5W2tleV07CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZS5leHBlbnNlKSB7CiAgICAgICAgY29uc3QgYnVkZ2V0ID0gYWxsQnVkZ2V0cy5maW5kKChiKSA9PiBiLmNhdGVnb3J5ID09PSB2YWx1ZSk7CiAgICAgICAgY29uc3Qgc3BlbnQgPSB0b3RhbHNbdmFsdWVdIHx8IDA7CgogICAgICAgIGNvbnN0IHJvdyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIHJvdy5jbGFzc05hbWUgPSAiYnVkZ2V0LXJvdyI7CgogICAgICAgIGNvbnN0IGhlYWQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBoZWFkLmNsYXNzTmFtZSA9ICJidWRnZXQtcm93LWhlYWQiOwoKICAgICAgICBjb25zdCBuYW1lU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBuYW1lU3Bhbi5jbGFzc05hbWUgPSAiYnVkZ2V0LWNhdC1uYW1lIjsKICAgICAgICBuYW1lU3Bhbi50ZXh0Q29udGVudCA9IGxhYmVsOwoKICAgICAgICBjb25zdCBhbW91bnRzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudHMuY2xhc3NOYW1lID0gImJ1ZGdldC1hbW91bnRzIjsKICAgICAgICBjb25zdCBzcGVudFNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgc3BlbnRTcGFuLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHNwZW50KSArICIgLyAiOwogICAgICAgIGNvbnN0IGlucHV0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBpbnB1dC50eXBlID0gIm51bWJlciI7CiAgICAgICAgaW5wdXQuY2xhc3NOYW1lID0gImJ1ZGdldC1pbnB1dCI7CiAgICAgICAgaW5wdXQubWluID0gIjAiOwogICAgICAgIGlucHV0LnN0ZXAgPSAiMSI7CiAgICAgICAgaW5wdXQucGxhY2Vob2xkZXIgPSAi4oCUIjsKICAgICAgICBpZiAoYnVkZ2V0KSBpbnB1dC52YWx1ZSA9IGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgYW1vdW50cy5hcHBlbmRDaGlsZChzcGVudFNwYW4pOwogICAgICAgIGFtb3VudHMuYXBwZW5kQ2hpbGQoaW5wdXQpOwogICAgICAgIGJ1ZGdldElucHV0c0J5Q2F0ZWdvcnlbdmFsdWVdID0gaW5wdXQ7CgogICAgICAgIGhlYWQuYXBwZW5kQ2hpbGQobmFtZVNwYW4pOwogICAgICAgIGhlYWQuYXBwZW5kQ2hpbGQoYW1vdW50cyk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGhlYWQpOwoKICAgICAgICBpZiAoYnVkZ2V0KSB7CiAgICAgICAgICBjb25zdCB0cmFjayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgdHJhY2suY2xhc3NOYW1lID0gImJ1ZGdldC1iYXItdHJhY2siOwogICAgICAgICAgY29uc3QgZmlsbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgICAgY29uc3QgcmF0aW8gPSBzcGVudCAvIGJ1ZGdldC5hbW91bnQ7CiAgICAgICAgICBjb25zdCBwY3QgPSBNYXRoLm1pbihyYXRpbyAqIDEwMCwgMTAwKTsKICAgICAgICAgIGxldCBjbHMgPSAib2siOwogICAgICAgICAgaWYgKHJhdGlvID49IDEpIGNscyA9ICJvdmVyIjsKICAgICAgICAgIGVsc2UgaWYgKHJhdGlvID49IDAuNykgY2xzID0gIndhcm5pbmciOwogICAgICAgICAgZmlsbC5jbGFzc05hbWUgPSAiYnVkZ2V0LWJhci1maWxsICIgKyBjbHM7CiAgICAgICAgICBmaWxsLnN0eWxlLndpZHRoID0gcGN0ICsgIiUiOwogICAgICAgICAgdHJhY2suYXBwZW5kQ2hpbGQoZmlsbCk7CiAgICAgICAgICByb3cuYXBwZW5kQ2hpbGQodHJhY2spOwoKICAgICAgICAgIGNvbnN0IHN0cmlwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBzdHJpcC5jbGFzc05hbWUgPSAiYnVkZ2V0LWhpc3Rvcnktc3RyaXAiOwogICAgICAgICAgZm9yIChjb25zdCBoaXN0S2V5IG9mIGxhc3ROTW9udGhLZXlzKEJVREdFVF9ISVNUT1JZX01PTlRIUywgY3VycmVudE1vbnRoS2V5KSkgewogICAgICAgICAgICBjb25zdCB7IHRvdGFsczogaGlzdFRvdGFscyB9ID0gbW9udGhDYXRlZ29yeVRvdGFscyh0cmFuc2FjdGlvbnMsIGhpc3RLZXkpOwogICAgICAgICAgICBjb25zdCBoaXN0U3BlbnQgPSBoaXN0VG90YWxzW3ZhbHVlXSB8fCAwOwogICAgICAgICAgICBjb25zdCBkb3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICAgIGlmIChoaXN0U3BlbnQgPT09IDApIHsKICAgICAgICAgICAgICBkb3QuY2xhc3NOYW1lID0gImhpc3RvcnktZG90IGVtcHR5IjsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICBjb25zdCBoaXN0UmF0aW8gPSBoaXN0U3BlbnQgLyBidWRnZXQuYW1vdW50OwogICAgICAgICAgICAgIGxldCBoaXN0Q2xzID0gIm9rIjsKICAgICAgICAgICAgICBpZiAoaGlzdFJhdGlvID49IDEpIGhpc3RDbHMgPSAib3ZlciI7CiAgICAgICAgICAgICAgZWxzZSBpZiAoaGlzdFJhdGlvID49IDAuNykgaGlzdENscyA9ICJ3YXJuaW5nIjsKICAgICAgICAgICAgICBkb3QuY2xhc3NOYW1lID0gImhpc3RvcnktZG90ICIgKyBoaXN0Q2xzOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGNvbnN0IFtoeSwgaG1dID0gaGlzdEtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgICAgICBjb25zdCBtb250aExhYmVsID0gbW9udGhTaG9ydEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaHksIGhtIC0gMSwgMSkpOwogICAgICAgICAgICBjb25zdCBkZXRhaWxUZXh0ID0gYCR7bW9udGhMYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChoaXN0U3BlbnQpfSAvICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGJ1ZGdldC5hbW91bnQpfWA7CiAgICAgICAgICAgIGRvdC50aXRsZSA9IGRldGFpbFRleHQ7IC8vIGFmZmljaMOpIGF1IHN1cnZvbCBzdXIgb3JkaW5hdGV1cgogICAgICAgICAgICAvLyBTdXIgbW9iaWxlIGlsIG4neSBhIHBhcyBkZSBzdXJ2b2wgOiB1biB0YXAgc3VyIGxhIGJhcnJlIG1vbnRyZQogICAgICAgICAgICAvLyBsZSBtw6ptZSBkw6l0YWlsIGRhbnMgdW4gdG9hc3QuCiAgICAgICAgICAgIGRvdC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dUb2FzdChkZXRhaWxUZXh0KSk7CiAgICAgICAgICAgIHN0cmlwLmFwcGVuZENoaWxkKGRvdCk7CiAgICAgICAgICB9CiAgICAgICAgICByb3cuYXBwZW5kQ2hpbGQoc3RyaXApOwogICAgICAgIH0KCiAgICAgICAgd3JhcC5hcHBlbmRDaGlsZChyb3cpOwogICAgICB9CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZEN1c3RvbUNhdGVnb3JpZXMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9jdXN0b20tY2F0ZWdvcmllcyIpOwogICAgICAgIGZvciAoY29uc3QgeyB0eXBlLCB2YWx1ZSwgbGFiZWwgfSBvZiBpdGVtcykgewogICAgICAgICAgaWYgKGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0gJiYgIWNhdGVnb3JpZXNCeVR5cGVbdHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB2YWx1ZSkpIHsKICAgICAgICAgICAgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXS5wdXNoKFt2YWx1ZSwgbGFiZWxdKTsKICAgICAgICAgICAgYWxsQ2F0ZWdvcnlMYWJlbHNbdmFsdWVdID0gbGFiZWw7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IGRlcyBjYXTDqWdvcmllcyA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBsb2FkRGlzbWlzc2VkU3VnZ2VzdGlvbnMoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3Qga2V5cyA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2Rpc21pc3NlZC1zdWdnZXN0aW9ucyIpOwogICAgICAgIGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzID0gbmV3IFNldChrZXlzKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgLy8gUGFzIGJsb3F1YW50IDogYXUgcGlyZSB1bmUgc3VnZ2VzdGlvbiBkw6lqw6AgdnVlIHLDqWFwcGFyYcOudCB1bmUgZm9pcy4KICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNsdWdpZnlDYXRlZ29yeShsYWJlbCkgewogICAgICByZXR1cm4gKAogICAgICAgIGxhYmVsCiAgICAgICAgICAubm9ybWFsaXplKCJORkQiKS5yZXBsYWNlKC9bzIAtza9dL2csICIiKSAvLyBlbmzDqHZlIGxlcyBhY2NlbnRzCiAgICAgICAgICAudG9Mb3dlckNhc2UoKQogICAgICAgICAgLnRyaW0oKQogICAgICAgICAgLnJlcGxhY2UoL1teYS16MC05XSsvZywgIl8iKQogICAgICAgICAgLnJlcGxhY2UoL15fK3xfKyQvZywgIiIpIHx8ICJhdXRyZSIKICAgICAgKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzYXZlQ3VzdG9tQ2F0ZWdvcnkodHlwZSwgdmFsdWUsIGxhYmVsKSB7CiAgICAgIGNhdGVnb3JpZXNCeVR5cGVbdHlwZV0ucHVzaChbdmFsdWUsIGxhYmVsXSk7CiAgICAgIGFsbENhdGVnb3J5TGFiZWxzW3ZhbHVlXSA9IGxhYmVsOwogICAgICBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpOwogICAgICB0cnkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKCIvYXBpL2N1c3RvbS1jYXRlZ29yaWVzIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHR5cGUsIHZhbHVlLCBsYWJlbCB9KSwKICAgICAgICB9KTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJDYXTDqWdvcmllIGNyw6nDqWUgaWNpLCBtYWlzIHBhcyBzYXV2ZWdhcmTDqWUgc3VyIGxlIHNlcnZldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgY29uc3QgY3VycmVuY3lGb3JtYXR0ZXIgPSBuZXcgSW50bC5OdW1iZXJGb3JtYXQoImZyLUZSIiwgeyBzdHlsZTogImN1cnJlbmN5IiwgY3VycmVuY3k6ICJFVVIiIH0pOwogICAgY29uc3QgZGF0ZUZvcm1hdHRlciA9IG5ldyBJbnRsLkRhdGVUaW1lRm9ybWF0KCJmci1GUiIsIHsgZGF5OiAibnVtZXJpYyIsIG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CgogICAgLy8gw4ljaGFwcGUgdW5lIHZhbGV1ciBhdmFudCBkZSBsJ2luc8OpcmVyIGRhbnMgdW4gdGVtcGxhdGUgSFRNTCBjb25zdHJ1aXQKICAgIC8vIMOgIGxhIG1haW4gKGlubmVySFRNTCkgOiBuw6ljZXNzYWlyZSBwYXJ0b3V0IG/DuSB1bmUgZG9ubsOpZSBzYWlzaWUgcGFyCiAgICAvLyBsJ3V0aWxpc2F0ZXVyIHBldXQgcyd5IHJldHJvdXZlciDigJQgZW4gcGFydGljdWxpZXIgbGUgbGliZWxsw6kgZCd1bmUKICAgIC8vIGNhdMOpZ29yaWUgcGVyc29ubmFsaXPDqWUgKHRleHRlIGxpYnJlLCBlbnJlZ2lzdHLDqSBlbiBiYXNlKSwgcG91ciDDqXZpdGVyCiAgICAvLyBxdSd1biBsaWJlbGzDqSBkdSBnZW5yZSA8aW1nIHNyYz14IG9uZXJyb3I9Li4uPiBuZSBzJ2V4w6ljdXRlIGNvbW1lIGR1CiAgICAvLyBIVE1ML0pTIGF1IGxpZXUgZGUgcydhZmZpY2hlciBjb21tZSBkdSB0ZXh0ZSAoaW5qZWN0aW9uIFhTUyBzdG9ja8OpZSkuCiAgICBmdW5jdGlvbiBlc2NhcGVIdG1sKHN0cikgewogICAgICByZXR1cm4gU3RyaW5nKHN0cikucmVwbGFjZSgvWyY8PiInXS9nLCAoY2gpID0+ICh7CiAgICAgICAgIiYiOiAiJmFtcDsiLCAiPCI6ICImbHQ7IiwgIj4iOiAiJmd0OyIsICciJzogIiZxdW90OyIsICInIjogIiYjMzk7IiwKICAgICAgfVtjaF0pKTsKICAgIH0KCiAgICBmdW5jdGlvbiBzaG93VG9hc3QobWVzc2FnZSwgaXNFcnJvciA9IGZhbHNlKSB7CiAgICAgIGNvbnN0IHRvYXN0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIHRvYXN0LmNsYXNzTmFtZSA9ICJ0b2FzdCIgKyAoaXNFcnJvciA/ICIgZXJyb3IiIDogIiIpOwogICAgICB0b2FzdC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQodG9hc3QpOwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRvYXN0LnJlbW92ZSgpLCAzMDAwKTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBhcGlGZXRjaChwYXRoLCBvcHRpb25zID0ge30pIHsKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2gocGF0aCwgewogICAgICAgIC4uLm9wdGlvbnMsCiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgIlgtQVBJLUtleSI6IEFQSV9LRVksCiAgICAgICAgICAuLi4ob3B0aW9ucy5ib2R5ID8geyAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iIH0gOiB7fSksCiAgICAgICAgICAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KSwKICAgICAgICB9LAogICAgICB9KTsKICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDQwMSkgewogICAgICAgIC8vIEpldG9uIGFic2VudCwgaW52YWxpZGUgb3UgZXhwaXLDqSA6IHJldG91ciDDoCBsJ8OpY3JhbiBkZSB2ZXJyb3VpbGxhZ2UKICAgICAgICAvLyBwbHV0w7R0IHF1ZSBkJ2FmZmljaGVyIHVuZSBlcnJldXIgdGVjaG5pcXVlIGluY29tcHLDqWhlbnNpYmxlLgogICAgICAgIHNob3dMb2NrU2NyZWVuKCk7CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCJTZXNzaW9uIGV4cGlyw6llLCByZWNvbm5lY3RlLXRvaS4iKTsKICAgICAgfQogICAgICBpZiAoIXJlcy5vaykgewogICAgICAgIC8vIHJlcy5zdGF0dXNUZXh0IGVzdCBzb3V2ZW50IHZpZGUgKG5hdmlnYXRldXJzIGVuIEhUVFAvMiwgdXRpbGlzw6kgcGFyCiAgICAgICAgLy8gVmVyY2VsKSwgZG9uYyBvbiBuZSBwZXV0IHBhcyBjb21wdGVyIGRlc3N1cyBjb21tZSBtZXNzYWdlIHBhcgogICAgICAgIC8vIGTDqWZhdXQgOiBvbiByZXRvbWJlIHN1ciBsZSBjb2RlIEhUVFAgcG91ciBuZSBqYW1haXMgYWZmaWNoZXIgdW4KICAgICAgICAvLyBtZXNzYWdlIGQnZXJyZXVyIHZpZGUuCiAgICAgICAgbGV0IGRldGFpbCA9IHJlcy5zdGF0dXNUZXh0IHx8IGBFcnJldXIgSFRUUCAke3Jlcy5zdGF0dXN9YDsKICAgICAgICB0cnkgewogICAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgICBkZXRhaWwgPSBkYXRhLmRldGFpbCB8fCBkZXRhaWw7CiAgICAgICAgfSBjYXRjaCAoXykge30KICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZGV0YWlsKTsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1cyA9PT0gMjA0KSByZXR1cm4gbnVsbDsKICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICB9CgogICAgZnVuY3Rpb24gdG9kYXlJc28oKSB7CiAgICAgIGNvbnN0IGQgPSBuZXcgRGF0ZSgpOwogICAgICBjb25zdCB0eiA9IGQuZ2V0VGltZXpvbmVPZmZzZXQoKTsKICAgICAgY29uc3QgbG9jYWwgPSBuZXcgRGF0ZShkLmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIGNhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgY2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICAgIGNvbnN0IG5ld09wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICBuZXdPcHQudmFsdWUgPSAiX19uZXdfXyI7CiAgICAgIG5ld09wdC50ZXh0Q29udGVudCA9ICIrIE5vdXZlbGxlIGNhdMOpZ29yaWXigKYiOwogICAgICBjYXRlZ29yeUlucHV0LmFwcGVuZENoaWxkKG5ld09wdCk7CgogICAgICBuZXdDYXRlZ29yeU5hbWVJbnB1dC52YWx1ZSA9ICIiOwogICAgICBuZXdDYXRlZ29yeU5hbWVJbnB1dC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgIH0KCiAgICBjYXRlZ29yeUlucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuY2xhc3NMaXN0LnRvZ2dsZSgiaGlkZGVuIiwgY2F0ZWdvcnlJbnB1dC52YWx1ZSAhPT0gIl9fbmV3X18iKTsKICAgICAgaWYgKGNhdGVnb3J5SW5wdXQudmFsdWUgPT09ICJfX25ld19fIikgbmV3Q2F0ZWdvcnlOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIHNldFR5cGUodHlwZSkgewogICAgICBjdXJyZW50VHlwZSA9IHR5cGU7CiAgICAgIHR5cGVUb2dnbGVFbC5xdWVyeVNlbGVjdG9yQWxsKCIudHlwZS1idG4iKS5mb3JFYWNoKChidG4pID0+IHsKICAgICAgICBidG4uY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgYnRuLmRhdGFzZXQudHlwZSA9PT0gdHlwZSk7CiAgICAgIH0pOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXModHlwZSwgY2F0ZWdvcnlJbnB1dC52YWx1ZSk7CiAgICB9CgogICAgdHlwZVRvZ2dsZUVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgiLnR5cGUtYnRuIik7CiAgICAgIGlmIChidG4pIHNldFR5cGUoYnRuLmRhdGFzZXQudHlwZSk7CiAgICB9KTsKCiAgICBmdW5jdGlvbiBvcGVuTW9kYWwodHggPSBudWxsKSB7CiAgICAgIC8vIE9uIGRpc3Rpbmd1ZSAibW9kaWZpZXIiICh0eCBhIHVuIGlkLCB2cmFpZSDDqWRpdGlvbiBlbiBiYXNlKSBkZQogICAgICAvLyAicHLDqS1yZW1wbGlyIMOgIHBhcnRpciBkJ3VuIG1vZMOobGUiIChkdXBsaWNhdGlvbiA6IHR4IGZvdXJuaSBtYWlzIHNhbnMKICAgICAgLy8gaWQgPT4gb24gY3LDqWUgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uIGF1IGxpZXUgZCfDqWNyYXNlciBsJ29yaWdpbmFsZSkuCiAgICAgIGNvbnN0IGlzRWRpdCA9IEJvb2xlYW4odHggJiYgdHguaWQpOwogICAgICBlZGl0aW5nSWQgPSBpc0VkaXQgPyB0eC5pZCA6IG51bGw7CiAgICAgIGVkaXRpbmdPcmlnaW5hbENhdGVnb3J5ID0gaXNFZGl0ID8gdHguY2F0ZWdvcnkgOiBudWxsOwogICAgICBtb2RhbFRpdGxlRWwudGV4dENvbnRlbnQgPSBpc0VkaXQgPyAiTW9kaWZpZXIgbGEgdHJhbnNhY3Rpb24iIDogIk5vdXZlbGxlIHRyYW5zYWN0aW9uIjsKICAgICAgc2F2ZUJ0bi50ZXh0Q29udGVudCA9IGlzRWRpdCA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFR5cGUodHggPyB0eC50eXBlIDogImV4cGVuc2UiKTsKICAgICAgYW1vdW50SW5wdXQudmFsdWUgPSB0eCA/IHR4LmFtb3VudCA6ICIiOwogICAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoY3VycmVudFR5cGUsIHR4ID8gdHguY2F0ZWdvcnkgOiAiYXV0cmUiKTsKICAgICAgZGVzY3JpcHRpb25JbnB1dC52YWx1ZSA9IHR4ID8gKHR4LmRlc2NyaXB0aW9uIHx8ICIiKSA6ICIiOwogICAgICBkYXRlSW5wdXQudmFsdWUgPSB0eCA/IHR4LmV4cGVuc2VfZGF0ZSA6IHRvZGF5SXNvKCk7CgogICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgICBpZiAoaXNFZGl0ICYmIHR4LnJlY2VpcHRfcGF0aCkgewogICAgICAgIGxvYWRFeGlzdGluZ1JlY2VpcHRQcmV2aWV3KHR4LmlkKTsKICAgICAgfQoKICAgICAgb3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBhbW91bnRJbnB1dC5mb2N1cygpOwogICAgfQoKICAgIGZ1bmN0aW9uIGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSB7CiAgICAgIC8vIE3Dqm1lIG1vbnRhbnQvY2F0w6lnb3JpZS9kZXNjcmlwdGlvbiwgbWFpcyBkYXTDqSBkJ2F1am91cmQnaHVpIGV0IHNhbnMKICAgICAgLy8gaWQgOiBsYSBzYXV2ZWdhcmRlIGNyw6llcmEgdW5lIG5vdXZlbGxlIHRyYW5zYWN0aW9uICh2b2lyIG9wZW5Nb2RhbCkuCiAgICAgIG9wZW5Nb2RhbCh7IC4uLnR4LCBpZDogbnVsbCwgZXhwZW5zZV9kYXRlOiB0b2RheUlzbygpIH0pOwogICAgfQoKICAgIGZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgICAgIG92ZXJsYXlFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWRpdGluZ0lkID0gbnVsbDsKICAgICAgZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnkgPSBudWxsOwogICAgICByZXNldFJlY2VpcHRVaSgpOwogICAgfQoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmYWItYWRkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gInJlY3VycmluZyIpIG9wZW5SZWN1cnJpbmdNb2RhbCgpOwogICAgICBlbHNlIG9wZW5Nb2RhbCgpOwogICAgfSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLWNhbmNlbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgY2xvc2VNb2RhbCk7CiAgICBvdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4geyBpZiAoZS50YXJnZXQgPT09IG92ZXJsYXlFbCkgY2xvc2VNb2RhbCgpOyB9KTsKCiAgICBzYXZlQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KGFtb3VudElucHV0LnZhbHVlKTsKICAgICAgaWYgKCFhbW91bnQgfHwgYW1vdW50IDw9IDApIHsKICAgICAgICBzaG93VG9hc3QoIk1vbnRhbnQgaW52YWxpZGUiLCB0cnVlKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIC8vICIrIE5vdXZlbGxlIGNhdMOpZ29yaWXigKYiIHPDqWxlY3Rpb25uw6kgOiBvbiBsYSBjcsOpZSAoc2kgZWxsZSBuJ2V4aXN0ZQogICAgICAvLyBwYXMgZMOpasOgIHNvdXMgY2Ugbm9tKSBhdmFudCBkJ2VucmVnaXN0cmVyIGxhIHRyYW5zYWN0aW9uIGF2ZWMuCiAgICAgIGxldCBjYXRlZ29yeVZhbHVlID0gY2F0ZWdvcnlJbnB1dC52YWx1ZTsKICAgICAgaWYgKGNhdGVnb3J5VmFsdWUgPT09ICJfX25ld19fIikgewogICAgICAgIGNvbnN0IG5hbWUgPSBuZXdDYXRlZ29yeU5hbWVJbnB1dC52YWx1ZS50cmltKCk7CiAgICAgICAgaWYgKCFuYW1lKSB7CiAgICAgICAgICBzaG93VG9hc3QoIkRvbm5lIHVuIG5vbSDDoCBsYSBub3V2ZWxsZSBjYXTDqWdvcmllIiwgdHJ1ZSk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICAgIGNhdGVnb3J5VmFsdWUgPSBzbHVnaWZ5Q2F0ZWdvcnkobmFtZSk7CiAgICAgICAgaWYgKCFjYXRlZ29yaWVzQnlUeXBlW2N1cnJlbnRUeXBlXS5zb21lKChbdl0pID0+IHYgPT09IGNhdGVnb3J5VmFsdWUpKSB7CiAgICAgICAgICBhd2FpdCBzYXZlQ3VzdG9tQ2F0ZWdvcnkoY3VycmVudFR5cGUsIGNhdGVnb3J5VmFsdWUsIG5hbWUpOwogICAgICAgICAgcG9wdWxhdGVDYXRlZ29yaWVzKGN1cnJlbnRUeXBlLCBjYXRlZ29yeVZhbHVlKTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogY3VycmVudFR5cGUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeVZhbHVlLAogICAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbklucHV0LnZhbHVlLnRyaW0oKSB8fCBudWxsLAogICAgICAgIGV4cGVuc2VfZGF0ZTogZGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgIH07CgogICAgICBzYXZlQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoZWRpdGluZ0lkKSB7CiAgICAgICAgICBjb25zdCBwcmV2aW91c0NhdGVnb3J5ID0gZWRpdGluZ09yaWdpbmFsQ2F0ZWdvcnk7CiAgICAgICAgICBjb25zdCBlZGl0ZWRJZCA9IGVkaXRpbmdJZDsKICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2VkaXRpbmdJZH1gLCB7IG1ldGhvZDogIlBVVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBtb2RpZmnDqWUiKTsKCiAgICAgICAgICAvLyBTaSBsYSBjYXTDqWdvcmllIHZpZW50IGRlIGNoYW5nZXIgbWFudWVsbGVtZW50LCBvbiBwcm9wb3NlIGRlCiAgICAgICAgICAvLyByZXBvcnRlciBsZSBtw6ptZSBjaGFuZ2VtZW50IHN1ciBsZXMgYXV0cmVzIHRyYW5zYWN0aW9ucyBkb250IGxhCiAgICAgICAgICAvLyBkZXNjcmlwdGlvbiBwYXJ0YWdlIHVuIG1vdC1jbMOpIHNpZ25pZmljYXRpZiAoZXguICJjYXNpbm8iIC8KICAgICAgICAgIC8vICJhdSBjYXNpbm8iIC8gInBlcnRlIGF1IGNhc2lubyIpIGV0IHF1aSDDqXRhaWVudCBkYW5zIGwnYW5jaWVubmUKICAgICAgICAgIC8vIGNhdMOpZ29yaWUg4oCUIGphbWFpcyBhdXRvbWF0aXF1ZSwgdG91am91cnMgc3VyIGNvbmZpcm1hdGlvbi4KICAgICAgICAgIGlmIChwcmV2aW91c0NhdGVnb3J5ICYmIHBheWxvYWQuY2F0ZWdvcnkgIT09IHByZXZpb3VzQ2F0ZWdvcnkgJiYgcGF5bG9hZC5kZXNjcmlwdGlvbikgewogICAgICAgICAgICBjb25zdCBrZXl3b3JkcyA9IGV4dHJhY3REZXNjcmlwdGlvbktleXdvcmRzKHBheWxvYWQuZGVzY3JpcHRpb24pOwogICAgICAgICAgICBpZiAoa2V5d29yZHMuc2l6ZSA+IDApIHsKICAgICAgICAgICAgICBjb25zdCBzaW1pbGFyID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigKICAgICAgICAgICAgICAgICh0KSA9PgogICAgICAgICAgICAgICAgICB0LmlkICE9PSBlZGl0ZWRJZCAmJgogICAgICAgICAgICAgICAgICB0LnR5cGUgPT09IHBheWxvYWQudHlwZSAmJgogICAgICAgICAgICAgICAgICB0LmNhdGVnb3J5ID09PSBwcmV2aW91c0NhdGVnb3J5ICYmCiAgICAgICAgICAgICAgICAgIGtleXdvcmRzSW50ZXJzZWN0KGtleXdvcmRzLCBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3Jkcyh0LmRlc2NyaXB0aW9uKSkKICAgICAgICAgICAgICApOwogICAgICAgICAgICAgIGlmIChzaW1pbGFyLmxlbmd0aCA+IDApIHsKICAgICAgICAgICAgICAgIGNvbnN0IG5ld0xhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbcGF5bG9hZC5jYXRlZ29yeV0gfHwgcGF5bG9hZC5jYXRlZ29yeTsKICAgICAgICAgICAgICAgIGNvbnN0IGV4YW1wbGVEZXNjID0gc2ltaWxhclswXS5kZXNjcmlwdGlvbiB8fCAiKHNhbnMgZGVzY3JpcHRpb24pIjsKICAgICAgICAgICAgICAgIGNvbnN0IGNvbmZpcm1lZCA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgICAgICAgICAgICBgQXBwbGlxdWVyIGF1c3NpIGxhIGNhdMOpZ29yaWUgIiR7bmV3TGFiZWx9IiBhdXggJHtzaW1pbGFyLmxlbmd0aH0gYXV0cmUocykgdHJhbnNhY3Rpb24ocykgYCArCiAgICAgICAgICAgICAgICAgIGBzaW1pbGFpcmUocykgKGV4LiAiJHtleGFtcGxlRGVzY30iKSA/YAogICAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgICAgIGlmIChjb25maXJtZWQpIHsKICAgICAgICAgICAgICAgICAgZm9yIChjb25zdCB0IG9mIHNpbWlsYXIpIHsKICAgICAgICAgICAgICAgICAgICBjb25zdCBmaXhQYXlsb2FkID0geyBjYXRlZ29yeTogcGF5bG9hZC5jYXRlZ29yeSB9OwogICAgICAgICAgICAgICAgICAgIC8vIENvbW1lIHBvdXIgbGEgYmFubmnDqHJlIGRlIHN1Z2dlc3Rpb24gOiBsYSBjYXTDqWdvcmllCiAgICAgICAgICAgICAgICAgICAgLy8gcG9ydGUgbWFpbnRlbmFudCBsJ2luZm8sIG9uIHJldGlyZSBsZSBtb3QtY2zDqSBkZXZlbnUKICAgICAgICAgICAgICAgICAgICAvLyByZWRvbmRhbnQgZGUgbGEgZGVzY3JpcHRpb24gZGUgQ0VTIHRyYW5zYWN0aW9ucy1sw6AKICAgICAgICAgICAgICAgICAgICAvLyAocGFzIGNlbGxlIHF1J29uIHZpZW50IGQnw6lkaXRlciDDoCBsYSBtYWluKS4KICAgICAgICAgICAgICAgICAgICBjb25zdCBjbGVhbmVkID0gc3RyaXBNYXRjaGVkS2V5d29yZHNGcm9tRGVzY3JpcHRpb24odC5kZXNjcmlwdGlvbiwga2V5d29yZHMpOwogICAgICAgICAgICAgICAgICAgIGlmIChjbGVhbmVkICE9PSAodC5kZXNjcmlwdGlvbiB8fCBudWxsKSkgZml4UGF5bG9hZC5kZXNjcmlwdGlvbiA9IGNsZWFuZWQ7CiAgICAgICAgICAgICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7dC5pZH1gLCB7CiAgICAgICAgICAgICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZml4UGF5bG9hZCksCiAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgc2hvd1RvYXN0KGAke3NpbWlsYXIubGVuZ3RofSBhdXRyZShzKSB0cmFuc2FjdGlvbihzKSBtaXNlKHMpIMOgIGpvdXJgKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3RyYW5zYWN0aW9ucyIsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGN1cnJlbnRUeXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUgYWpvdXTDqSIgOiAiRMOpcGVuc2UgYWpvdXTDqWUiKTsKICAgICAgICAgIGlmIChwZW5kaW5nUmVjZWlwdEZpbGUpIHsKICAgICAgICAgICAgLy8gTGEgcGhvdG8gYSDDqXTDqSBjaG9pc2llIGF2YW50IHF1ZSBsYSB0cmFuc2FjdGlvbiBuJ2V4aXN0ZSA6IG9uCiAgICAgICAgICAgIC8vIGwnZW52b2llIG1haW50ZW5hbnQgcXUnb24gYSB1biBpZC4KICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YSgpOwogICAgICAgICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIHBlbmRpbmdSZWNlaXB0RmlsZSk7CiAgICAgICAgICAgICAgYXdhaXQgZmV0Y2goYC9hcGkvdHJhbnNhY3Rpb25zLyR7Y3JlYXRlZC5pZH0vcmVjZWlwdGAsIHsKICAgICAgICAgICAgICAgIG1ldGhvZDogIlBVVCIsCiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7ICJYLUFQSS1LZXkiOiBBUElfS0VZIH0sCiAgICAgICAgICAgICAgICBib2R5OiBmb3JtRGF0YSwKICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSBjYXRjaCAoXykgewogICAgICAgICAgICAgIHNob3dUb2FzdCgiVHJhbnNhY3Rpb24gY3LDqcOpZSwgbWFpcyBsJ2Vudm9pIGRlIGxhIHBob3RvIGEgw6ljaG91w6kiLCB0cnVlKTsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBjbG9zZU1vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgc2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVUcmFuc2FjdGlvbihpZCkgewogICAgICBpZiAoIShhd2FpdCBzaG93Q29uZmlybSgiU3VwcHJpbWVyIGNldHRlIHRyYW5zYWN0aW9uID8iKSkpIHJldHVybjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaChgL2FwaS90cmFuc2FjdGlvbnMvJHtpZH1gLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJUcmFuc2FjdGlvbiBzdXBwcmltw6llIik7CiAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhdXggZ2xvYmF1eCAoU29sZGUvRMOpcGVuc2VzL1JldmVudXMpIDogY2FsY3Vsw6lzIHN1ciBUT1VURVMgbGVzCiAgICAvLyB0cmFuc2FjdGlvbnMsIGluZMOpcGVuZGFtbWVudCBkZXMgZmlsdHJlcyBkZSBsJ2hpc3RvcmlxdWUg4oCUIHVuIGZpbHRyZQogICAgLy8gc2VydCDDoCBjaGVyY2hlciBkYW5zIGxhIGxpc3RlLCBwYXMgw6AgcmVjYWxjdWxlciBsZSBzb2xkZSByw6llbC4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9ucyh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGV0IHRvdGFsRXhwZW5zZXMgPSAwOwogICAgICBsZXQgdG90YWxJbmNvbWUgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiaW5jb21lIikgdG90YWxJbmNvbWUgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgZWxzZSB0b3RhbEV4cGVuc2VzICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGJhbGFuY2UgPSB0b3RhbEluY29tZSAtIHRvdGFsRXhwZW5zZXM7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoYmFsYW5jZSk7CiAgICAgIHN1bW1hcnlCYWxhbmNlRWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAoYmFsYW5jZSA+PSAwID8gInBvc2l0aXZlIiA6ICJuZWdhdGl2ZSIpOwogICAgICBzdW1tYXJ5RXhwZW5zZXNFbC50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgc3VtbWFyeUluY29tZUVsLnRleHRDb250ZW50ID0gY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHRvdGFsSW5jb21lKTsKICAgIH0KCiAgICAvLyBDb25zdHJ1Y3Rpb24gZGUgbGEgbGlzdGUgZGUgY2FydGVzIGFmZmljaMOpZSBkYW5zIGwnb25nbGV0IEhpc3RvcmlxdWUg4oCUCiAgICAvLyByZcOnb2l0IGTDqWrDoCBsYSBsaXN0ZSBmaWx0csOpZSAodm9pciBhcHBseUhpc3RvcnlGaWx0ZXJzKS4KICAgIGZ1bmN0aW9uIHJlbmRlclRyYW5zYWN0aW9uTGlzdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgbGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBpZiAodHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5U3RhdGVFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICBlbXB0eVN0YXRlRWwudGV4dENvbnRlbnQgPSBhbGxUcmFuc2FjdGlvbnMubGVuZ3RoID09PSAwCiAgICAgICAgICA/ICJSaWVuIHBvdXIgbCdpbnN0YW50IOKAlCBhcHB1aWUgc3VyIGxlIGJvdXRvbiArIHBvdXIgYWpvdXRlciB1bmUgZMOpcGVuc2Ugb3UgdW4gcmV2ZW51LiIKICAgICAgICAgIDogIkF1Y3VuIHLDqXN1bHRhdCBwb3VyIGNlcyBmaWx0cmVzLiI7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIH0KCiAgICAgIGZvciAoY29uc3QgdHggb2YgdHJhbnNhY3Rpb25zKSB7CiAgICAgICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGNhcmQuY2xhc3NOYW1lID0gInR4LWNhcmQgIiArIHR4LnR5cGU7CgogICAgICAgIGNvbnN0IG1haW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBtYWluLmNsYXNzTmFtZSA9ICJ0eC1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJ0eC10b3AiOwogICAgICAgIGNvbnN0IGJhZGdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGJhZGdlLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1iYWRnZSI7CiAgICAgICAgYmFkZ2UudGV4dENvbnRlbnQgPSBhbGxDYXRlZ29yeUxhYmVsc1t0eC5jYXRlZ29yeV0gfHwgdHguY2F0ZWdvcnk7CiAgICAgICAgY29uc3QgZGF0ZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgZGF0ZVNwYW4uY2xhc3NOYW1lID0gInR4LWRhdGUiOwogICAgICAgIGRhdGVTcGFuLnRleHRDb250ZW50ID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUodHguZXhwZW5zZV9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIHRvcC5hcHBlbmRDaGlsZChkYXRlU3Bhbik7CiAgICAgICAgaWYgKHR4LnJlY3VycmluZ19leHBlbnNlX2lkKSB7CiAgICAgICAgICBjb25zdCByZWNCYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIHJlY0JhZGdlLmNsYXNzTmFtZSA9ICJ0eC1yZWN1cnJpbmctYmFkZ2UiOwogICAgICAgICAgcmVjQmFkZ2UudGV4dENvbnRlbnQgPSAi8J+UgSI7CiAgICAgICAgICByZWNCYWRnZS50aXRsZSA9ICJDcsOpw6llIGF1dG9tYXRpcXVlbWVudCBkZXB1aXMgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSI7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQocmVjQmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAodHgucmVjZWlwdF9wYXRoKSB7CiAgICAgICAgICBjb25zdCByZWNlaXB0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICAgIHJlY2VpcHRCYWRnZS50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgICByZWNlaXB0QmFkZ2UuY2xhc3NOYW1lID0gInR4LXJlY2VpcHQtYmFkZ2UiOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnRleHRDb250ZW50ID0gIvCfp74iOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnRpdGxlID0gIlZvaXIgbGEgcGhvdG8gZHUgcmXDp3UiOwogICAgICAgICAgcmVjZWlwdEJhZGdlLnNldEF0dHJpYnV0ZSgiYXJpYS1sYWJlbCIsICJWb2lyIGxhIHBob3RvIGR1IHJlw6d1Iik7CiAgICAgICAgICByZWNlaXB0QmFkZ2UuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBvcGVuUmVjZWlwdExpZ2h0Ym94KHR4LmlkKSk7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQocmVjZWlwdEJhZGdlKTsKICAgICAgICB9CgogICAgICAgIGNvbnN0IGRlc2MgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBkZXNjLmNsYXNzTmFtZSA9ICJ0eC1kZXNjcmlwdGlvbiI7CiAgICAgICAgZGVzYy50ZXh0Q29udGVudCA9IHR4LmRlc2NyaXB0aW9uIHx8ICLigJQiOwoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKHRvcCk7CiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAidHgtYW1vdW50ICIgKyB0eC50eXBlOwogICAgICAgIGFtb3VudEVsLnRleHRDb250ZW50ID0gKHR4LnR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodHguYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5Nb2RhbCh0eCkpOwogICAgICAgIGNvbnN0IGR1cGxpY2F0ZUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5jbGFzc05hbWUgPSAiaWNvbi1idG4iOwogICAgICAgIGR1cGxpY2F0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5OLIjsKICAgICAgICBkdXBsaWNhdGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIkR1cGxpcXVlciIpOwogICAgICAgIGR1cGxpY2F0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGR1cGxpY2F0ZVRyYW5zYWN0aW9uKHR4KSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVRyYW5zYWN0aW9uKHR4LmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGR1cGxpY2F0ZUJ0bik7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChkZWxldGVCdG4pOwoKICAgICAgICBjYXJkLmFwcGVuZENoaWxkKG1haW4pOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYW1vdW50RWwpOwogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQoYWN0aW9ucyk7CiAgICAgICAgbGlzdEVsLmFwcGVuZENoaWxkKGNhcmQpOwogICAgICB9CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gUsOpc3Vtw6kgImNldHRlIHNlbWFpbmUiIChpbmTDqXBlbmRhbnQgZGVzIGZpbHRyZXMgZGUgbCdoaXN0b3JpcXVlKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3RhcnRPZldlZWtJc28oKSB7CiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7CiAgICAgIGNvbnN0IGRheSA9IG5vdy5nZXREYXkoKTsgLy8gMCA9IGRpbWFuY2hlLCAxID0gbHVuZGksIC4uLgogICAgICBjb25zdCBkaWZmVG9Nb25kYXkgPSBkYXkgPT09IDAgPyA2IDogZGF5IC0gMTsKICAgICAgY29uc3QgbW9uZGF5ID0gbmV3IERhdGUobm93KTsKICAgICAgbW9uZGF5LnNldERhdGUobm93LmdldERhdGUoKSAtIGRpZmZUb01vbmRheSk7CiAgICAgIGNvbnN0IHR6ID0gbW9uZGF5LmdldFRpbWV6b25lT2Zmc2V0KCk7CiAgICAgIGNvbnN0IGxvY2FsID0gbmV3IERhdGUobW9uZGF5LmdldFRpbWUoKSAtIHR6ICogNjAwMDApOwogICAgICByZXR1cm4gbG9jYWwudG9JU09TdHJpbmcoKS5zbGljZSgwLCAxMCk7CiAgICB9CgogICAgZnVuY3Rpb24gdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHN0YXJ0ID0gc3RhcnRPZldlZWtJc28oKTsKICAgICAgY29uc3QgdG9kYXkgPSB0b2RheUlzbygpOwogICAgICBsZXQgdG90YWwgPSAwOwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGlmICh0eC50eXBlID09PSAiZXhwZW5zZSIgJiYgdHguZXhwZW5zZV9kYXRlID49IHN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8PSB0b2RheSkgewogICAgICAgICAgdG90YWwgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ3ZWVrLXN1bW1hcnkiKS50ZXh0Q29udGVudCA9CiAgICAgICAgYENldHRlIHNlbWFpbmUgKGRlcHVpcyBsdW5kaSkgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbCl9IGTDqXBlbnPDqXNgOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFJlY2hlcmNoZSBldCBmaWx0cmVzIGRhbnMgbCdoaXN0b3JpcXVlCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBmdW5jdGlvbiBwb3B1bGF0ZUZpbHRlckNhdGVnb3J5T3B0aW9ucygpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1jYXRlZ29yeSIpOwogICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIE9iamVjdC5lbnRyaWVzKGFsbENhdGVnb3J5TGFiZWxzKSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gYXBwbHlIaXN0b3J5RmlsdGVycygpIHsKICAgICAgY29uc3Qgc2VhcmNoID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1zZWFyY2giKS52YWx1ZS50cmltKCkudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgY2F0ZWdvcnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyLWNhdGVnb3J5IikudmFsdWU7CiAgICAgIGNvbnN0IGRhdGVTdGFydCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXItZGF0ZS1zdGFydCIpLnZhbHVlOwogICAgICBjb25zdCBkYXRlRW5kID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZpbHRlci1kYXRlLWVuZCIpLnZhbHVlOwoKICAgICAgY29uc3QgZmlsdGVyZWQgPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKCh0eCkgPT4gewogICAgICAgIGlmIChjYXRlZ29yeSAmJiB0eC5jYXRlZ29yeSAhPT0gY2F0ZWdvcnkpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoZGF0ZVN0YXJ0ICYmIHR4LmV4cGVuc2VfZGF0ZSA8IGRhdGVTdGFydCkgcmV0dXJuIGZhbHNlOwogICAgICAgIGlmIChkYXRlRW5kICYmIHR4LmV4cGVuc2VfZGF0ZSA+IGRhdGVFbmQpIHJldHVybiBmYWxzZTsKICAgICAgICBpZiAoc2VhcmNoKSB7CiAgICAgICAgICBjb25zdCBoYXlzdGFjayA9IGAke3R4LmRlc2NyaXB0aW9uIHx8ICIifSAke2FsbENhdGVnb3J5TGFiZWxzW3R4LmNhdGVnb3J5XSB8fCB0eC5jYXRlZ29yeX1gLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgICBpZiAoIWhheXN0YWNrLmluY2x1ZGVzKHNlYXJjaCkpIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuIHRydWU7CiAgICAgIH0pOwogICAgICByZW5kZXJUcmFuc2FjdGlvbkxpc3QoZmlsdGVyZWQpOwogICAgfQoKICAgIFsiZmlsdGVyLXNlYXJjaCIsICJmaWx0ZXItY2F0ZWdvcnkiLCAiZmlsdGVyLWRhdGUtc3RhcnQiLCAiZmlsdGVyLWRhdGUtZW5kIl0uZm9yRWFjaCgoaWQpID0+IHsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgYXBwbHlIaXN0b3J5RmlsdGVycyk7CiAgICB9KTsKCiAgICBsZXQgYWxsVHJhbnNhY3Rpb25zID0gW107CiAgICBsZXQgY3VycmVudFZpZXcgPSAiaGlzdG9yeSI7CgogICAgYXN5bmMgZnVuY3Rpb24gbG9hZFRyYW5zYWN0aW9ucygpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCB0cmFuc2FjdGlvbnMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS90cmFuc2FjdGlvbnMiKTsKICAgICAgICBhbGxUcmFuc2FjdGlvbnMgPSB0cmFuc2FjdGlvbnM7CiAgICAgICAgcmVuZGVyVHJhbnNhY3Rpb25zKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgdXBkYXRlV2Vla1N1bW1hcnkodHJhbnNhY3Rpb25zKTsKICAgICAgICBhcHBseUhpc3RvcnlGaWx0ZXJzKCk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKHRyYW5zYWN0aW9ucyk7CiAgICAgICAgaWYgKGN1cnJlbnRWaWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3ModHJhbnNhY3Rpb25zKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgZGUgY2hhcmdlbWVudCA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBPbmdsZXRzIChIaXN0b3JpcXVlIC8gVGFibGVhdSBkZSBib3JkKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgZnVuY3Rpb24gc3dpdGNoVmlldyh2aWV3KSB7CiAgICAgIGN1cnJlbnRWaWV3ID0gdmlldzsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1oaXN0b3J5IikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gImhpc3RvcnkiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB2aWV3ID09PSAiZGFzaGJvYXJkIik7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItcmVjdXJyaW5nIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWV4cG9ydCIpLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHZpZXcgPT09ICJleHBvcnQiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1zYXZpbmdzIikuY2xhc3NMaXN0LnRvZ2dsZSgiYWN0aXZlIiwgdmlldyA9PT0gInNhdmluZ3MiKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZpZXctaGlzdG9yeSIpLnN0eWxlLmRpc3BsYXkgPSB2aWV3ID09PSAiaGlzdG9yeSIgPyAiYmxvY2siIDogIm5vbmUiOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1kYXNoYm9hcmQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImRhc2hib2FyZCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1yZWN1cnJpbmciKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gInJlY3VycmluZyIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1leHBvcnQiKS5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIiwgdmlldyA9PT0gImV4cG9ydCIpOwogICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidmlldy1zYXZpbmdzIikuY2xhc3NMaXN0LnRvZ2dsZSgidmlzaWJsZSIsIHZpZXcgPT09ICJzYXZpbmdzIik7CiAgICAgIGlmICh2aWV3ID09PSAiZGFzaGJvYXJkIikgcmVuZGVyRGFzaGJvYXJkKGFsbFRyYW5zYWN0aW9ucyk7CiAgICAgIGlmICh2aWV3ID09PSAic2F2aW5ncyIpIHJlbmRlclNhdmluZ3MoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgY2xvc2VOYXZEcmF3ZXIoKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWhpc3RvcnkiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoImhpc3RvcnkiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLWRhc2hib2FyZCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gc3dpdGNoVmlldygiZGFzaGJvYXJkIikpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRhYi1yZWN1cnJpbmciKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoInJlY3VycmluZyIpKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ0YWItZXhwb3J0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzd2l0Y2hWaWV3KCJleHBvcnQiKSk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidGFiLXNhdmluZ3MiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN3aXRjaFZpZXcoInNhdmluZ3MiKSk7CgogICAgLy8gTWVudSAiYnVyZ2VyIiAobW9iaWxlIHVuaXF1ZW1lbnQsIHZvaXIgbGUgQ1NTIEBtZWRpYSBhc3NvY2nDqSkgOiBsYQogICAgLy8gYmFycmUgZCdvbmdsZXRzIGRldmllbnQgdW4gdGlyb2lyIHBsdXTDtHQgcXVlIGRlIHMnw6ljcmFzZXIgc3VyCiAgICAvLyBwbHVzaWV1cnMgbGlnbmVzLiBGZXJtw6kgYXV0b21hdGlxdWVtZW50IGTDqHMgcXUndW4gb25nbGV0IGVzdCBjaG9pc2kKICAgIC8vICh2b2lyIHN3aXRjaFZpZXcgY2ktZGVzc3VzKSBvdSBlbiB0b3VjaGFudCBsZSBmb25kIGFzc29tYnJpLgogICAgZnVuY3Rpb24gY2xvc2VOYXZEcmF3ZXIoKSB7CiAgICAgIGRvY3VtZW50LmJvZHkuY2xhc3NMaXN0LnJlbW92ZSgibmF2LWRyYXdlci1vcGVuIik7CiAgICB9CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibWVudS10b2dnbGUtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGRvY3VtZW50LmJvZHkuY2xhc3NMaXN0LnRvZ2dsZSgibmF2LWRyYXdlci1vcGVuIik7CiAgICB9KTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJuYXYtZHJhd2VyLWJhY2tkcm9wIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZU5hdkRyYXdlcik7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gVGFibGVhdSBkZSBib3JkIChncmFwaGlxdWVzKQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbW9udGhGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAibG9uZyIsIHllYXI6ICJudW1lcmljIiB9KTsKICAgIGNvbnN0IG1vbnRoU2hvcnRGb3JtYXR0ZXIgPSBuZXcgSW50bC5EYXRlVGltZUZvcm1hdCgiZnItRlIiLCB7IG1vbnRoOiAic2hvcnQiLCB5ZWFyOiAibnVtZXJpYyIgfSk7CiAgICBjb25zdCBDSEFSVF9DT0xPUlMgPSBbIiMzYjgyZjYiLCAiIzIyYzU1ZSIsICIjZWY0NDQ0IiwgIiNmNTllMGIiLCAiI2E4NTVmNyIsICIjMTRiOGE2IiwgIiNlYzQ4OTkiLCAiIzY0NzQ4YiJdOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENoYXJnZW1lbnQgZGUgQ2hhcnQuanMgOiBsYSBiaWJsaW90aMOocXVlIHZpZW50IGQndW4gQ0ROIGV4dGVybmUgKHZvaXIKICAgIC8vIGxhIGJhbGlzZSA8c2NyaXB0PiBlbiBoYXV0IGRlIHBhZ2UpLiBTaSBjZSBjaGFyZ2VtZW50IHJhdGUgKGNvdXB1cmUKICAgIC8vIHLDqXNlYXUsIENETiBtb21lbnRhbsOpbWVudCBpbmpvaWduYWJsZS4uLiksIGBDaGFydGAgbidleGlzdGUgcGFzIGV0IHVuCiAgICAvLyBgbmV3IENoYXJ0KC4uLilgIGzDqHZlIHVuZSBlcnJldXIgbm9uIGludGVyY2VwdMOpZSDigJQgcXVpLCBhdmFudCBjZQogICAgLy8gY29ycmVjdGlmLCBpbnRlcnJvbXBhaXQgdG91dCBsZSByZXN0ZSBkdSByZW5kdSBkdSB0YWJsZWF1IGRlIGJvcmQgc2FucwogICAgLy8gYXVjdW4gbWVzc2FnZSwgbGFpc3NhbnQgbGVzIGdyYXBoaXF1ZXMgKGV0IHBhcmZvaXMgZGVzIHNlY3Rpb25zCiAgICAvLyBzdWl2YW50ZXMpIHZpZGVzIGluZMOpZmluaW1lbnQsIG3Dqm1lIGFwcsOocyB1biByZWNoYXJnZW1lbnQgZGUgbGEgcGFnZQogICAgLy8gc2kgbGUgQ0ROIHJlc3RhaXQgaW5qb2lnbmFibGUuIGBzYWZlQ3JlYXRlQ2hhcnRgIHJlbXBsYWNlIGNoYXF1ZSBhcHBlbAogICAgLy8gZGlyZWN0IMOgIGBuZXcgQ2hhcnQoLi4uKWAgOiBzaSBsYSBiaWJsaW90aMOocXVlIG1hbnF1ZSwgb24gYWZmaWNoZSB1bgogICAgLy8gbWVzc2FnZSBjbGFpciDDoCBsYSBwbGFjZSBkdSBncmFwaGlxdWUgZXQgb24gdGVudGUgYXV0b21hdGlxdWVtZW50IHVuCiAgICAvLyBzZWNvbmQgY2hhcmdlbWVudCBkdSBzY3JpcHQsIHB1aXMgb24gcmVkZXNzaW5lIGxhIHZ1ZSBjb3VyYW50ZSBkw6hzCiAgICAvLyBxdSdpbCByw6l1c3NpdCDigJQgc2FucyBxdWUgbCd1dGlsaXNhdGV1ciBhaXQgcXVvaSBxdWUgY2Ugc29pdCDDoCBmYWlyZS4KICAgIGxldCBjaGFydEpzUmVsb2FkQXR0ZW1wdGVkID0gZmFsc2U7CgogICAgZnVuY3Rpb24gaXNDaGFydEpzUmVhZHkoKSB7CiAgICAgIHJldHVybiB0eXBlb2YgQ2hhcnQgIT09ICJ1bmRlZmluZWQiOwogICAgfQoKICAgIGZ1bmN0aW9uIHRyeVJlbG9hZENoYXJ0SnMoKSB7CiAgICAgIGlmIChjaGFydEpzUmVsb2FkQXR0ZW1wdGVkKSByZXR1cm47CiAgICAgIGNoYXJ0SnNSZWxvYWRBdHRlbXB0ZWQgPSB0cnVlOwogICAgICBjb25zdCBzY3JpcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzY3JpcHQiKTsKICAgICAgc2NyaXB0LnNyYyA9ICJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC40L2Rpc3QvY2hhcnQudW1kLm1pbi5qcz9yZXRyeT0iICsgRGF0ZS5ub3coKTsKICAgICAgc2NyaXB0Lm9ubG9hZCA9ICgpID0+IHsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJkYXNoYm9hcmQiKSByZW5kZXJEYXNoYm9hcmQoYWxsVHJhbnNhY3Rpb25zKTsKICAgICAgICBpZiAoY3VycmVudFZpZXcgPT09ICJzYXZpbmdzIikgcmVuZGVyU2F2aW5ncyhhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9OwogICAgICBzY3JpcHQub25lcnJvciA9ICgpID0+IHsKICAgICAgICBjb25zb2xlLmVycm9yKCJDaGFydC5qcyA6IGxlIHNlY29uZCBlc3NhaSBkZSBjaGFyZ2VtZW50IGEgYXVzc2kgw6ljaG91w6kuIik7CiAgICAgIH07CiAgICAgIGRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQoc2NyaXB0KTsKICAgIH0KCiAgICBmdW5jdGlvbiBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCBjb25maWcsIGVtcHR5RWwsIHVuYXZhaWxhYmxlTWVzc2FnZSkgewogICAgICBpZiAoIWlzQ2hhcnRKc1JlYWR5KCkpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCJDaGFydC5qcyBuJ2VzdCBwYXMgY2hhcmfDqSDigJQgZ3JhcGhpcXVlIG5vbiBhZmZpY2jDqS4iKTsKICAgICAgICBpZiAoY2FudmFzKSBjYW52YXMuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICBpZiAoZW1wdHlFbCkgewogICAgICAgICAgZW1wdHlFbC50ZXh0Q29udGVudCA9IHVuYXZhaWxhYmxlTWVzc2FnZQogICAgICAgICAgICB8fCAiR3JhcGhpcXVlIG1vbWVudGFuw6ltZW50IGluZGlzcG9uaWJsZSDigJQgbm91dmVsbGUgdGVudGF0aXZlIGVuIGNvdXJzLCByw6llc3NhaWUgZGFucyBxdWVscXVlcyBzZWNvbmRlcy4iOwogICAgICAgICAgZW1wdHlFbC5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKICAgICAgICB9CiAgICAgICAgdHJ5UmVsb2FkQ2hhcnRKcygpOwogICAgICAgIHJldHVybiBudWxsOwogICAgICB9CiAgICAgIHRyeSB7CiAgICAgICAgcmV0dXJuIG5ldyBDaGFydChjYW52YXMsIGNvbmZpZyk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIGNvbnNvbGUuZXJyb3IoIkVycmV1ciBsb3JzIGRlIGxhIGNyw6lhdGlvbiBkdSBncmFwaGlxdWUgOiIsIGVycik7CiAgICAgICAgaWYgKGNhbnZhcykgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgaWYgKGVtcHR5RWwpIHsKICAgICAgICAgIGVtcHR5RWwudGV4dENvbnRlbnQgPSAiRXJyZXVyIGQnYWZmaWNoYWdlIGR1IGdyYXBoaXF1ZSDigJQgZXNzYWllIGRlIHJlY2hhcmdlciBsYSBwYWdlLiI7CiAgICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIH0KICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQogICAgfQoKICAgIGxldCBjYXRlZ29yeUNoYXJ0ID0gbnVsbDsKICAgIGxldCBpbmNvbWVDYXRlZ29yeUNoYXJ0ID0gbnVsbDsKICAgIGxldCBldm9sdXRpb25DaGFydCA9IG51bGw7CiAgICBsZXQgeWVhcmx5Q2hhcnQgPSBudWxsOwoKICAgIGZ1bmN0aW9uIG1vbnRoS2V5T2YoZXhwZW5zZURhdGUpIHsKICAgICAgcmV0dXJuIGV4cGVuc2VEYXRlLnNsaWNlKDAsIDcpOyAvLyAiWVlZWS1NTSIKICAgIH0KCiAgICAvLyBVbmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNvbXB0ZSBwb3VyIHVuIG1vaXMgZG9ubsOpIHNpIGNlIG1vaXMgZXN0IGRhbnMgc2EKICAgIC8vIHDDqXJpb2RlIGQnYWN0aXZpdMOpIDogcGFzIGF2YW50IHNhIGRhdGUgZGUgZMOpYnV0IChzaSBwb3PDqWUpLCBwYXMgYXByw6hzCiAgICAvLyBsZSBtb2lzIGRlIHNhIGRhdGUgZGUgZmluIChzaSBwb3PDqWUpLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpIHsKICAgICAgaWYgKGl0ZW0uc3RhcnRfZGF0ZSAmJiBtb250aEtleSA8IGl0ZW0uc3RhcnRfZGF0ZS5zbGljZSgwLCA3KSkgcmV0dXJuIGZhbHNlOwogICAgICBpZiAoaXRlbS5lbmRfZGF0ZSAmJiBtb250aEtleSA+IGl0ZW0uZW5kX2RhdGUuc2xpY2UoMCwgNykpIHJldHVybiBmYWxzZTsKICAgICAgcmV0dXJuIHRydWU7CiAgICB9CgogICAgLy8gSm91ciBkdSBtb2lzIGp1c3F1J2F1cXVlbCB1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGVzdCBjb25zaWTDqXLDqWUgY29tbWUKICAgIC8vICJkw6lqw6AgcHLDqWxldsOpZSIgcG91ciBsZSBtb2lzIGBtb250aEtleWAgOiB0b3VzIGxlcyBqb3VycyBwb3VyIHVuIG1vaXMKICAgIC8vIGTDqWrDoCBwYXNzw6ksIGF1Y3VuIHBvdXIgdW4gbW9pcyBmdXR1ciwgZXQgbGUgam91ciBkdSBqb3VyIHBvdXIgbGUgbW9pcwogICAgLy8gZW4gY291cnMuIFBlcm1ldCBkZSBkaXN0aW5ndWVyIGNlIHF1aSBlc3QgZMOpasOgIGFycml2w6kgZGUgY2UgcXVpIGVzdAogICAgLy8gc2V1bGVtZW50IHByw6l2dSAoZXggOiB1biBhYm9ubmVtZW50IHByw6lsZXbDqSBsZSAyNSwgb24gZXN0IGxlIDIpLgogICAgZnVuY3Rpb24gcmVjdXJyaW5nQ3V0b2ZmRGF5KG1vbnRoS2V5LCBjdXJyZW50TW9udGhLZXksIHRvZGF5RGF5KSB7CiAgICAgIGlmIChtb250aEtleSA8IGN1cnJlbnRNb250aEtleSkgcmV0dXJuIDMxOwogICAgICBpZiAobW9udGhLZXkgPiBjdXJyZW50TW9udGhLZXkpIHJldHVybiAwOwogICAgICByZXR1cm4gdG9kYXlEYXk7CiAgICB9CgogICAgZnVuY3Rpb24gcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1tb250aC1zZWxlY3QiKTsKICAgICAgY29uc3QgbW9udGhTZXQgPSBuZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKTsKICAgICAgaWYgKGFsbFJlY3VycmluZy5sZW5ndGggPiAwKSBtb250aFNldC5hZGQobW9udGhLZXlPZih0b2RheUlzbygpKSk7CiAgICAgIGNvbnN0IG1vbnRocyA9IFsuLi5tb250aFNldF0uc29ydCgpLnJldmVyc2UoKTsKICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgc2VsZWN0LmlubmVySFRNTCA9ICIiOwoKICAgICAgaWYgKG1vbnRocy5sZW5ndGggPT09IDApIHsKICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICBvcHQudmFsdWUgPSAiIjsKICAgICAgICBvcHQudGV4dENvbnRlbnQgPSAiQXVjdW5lIGRvbm7DqWUiOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgZm9yIChjb25zdCBrZXkgb2YgbW9udGhzKSB7CiAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgb3B0LnZhbHVlID0ga2V5OwogICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgIGNvbnN0IGxhYmVsID0gbW9udGhGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWwuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBsYWJlbC5zbGljZSgxKTsKICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgfQogICAgICBzZWxlY3QudmFsdWUgPSBtb250aHMuaW5jbHVkZXMocHJldmlvdXNWYWx1ZSkgPyBwcmV2aW91c1ZhbHVlIDogbW9udGhzWzBdOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJkYXNoYm9hcmQtbW9udGgtc2VsZWN0Iik7CiAgICAgIGNvbnN0IG1vbnRoS2V5ID0gc2VsZWN0LnZhbHVlOwogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtY2F0ZWdvcmllcyIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC1jYXRlZ29yaWVzLWVtcHR5Iik7CiAgICAgIGNvbnN0IHVwY29taW5nTm90ZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy1ub3RlIik7CiAgICAgIGNvbnN0IHVwY29taW5nVGV4dEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImRhc2hib2FyZC11cGNvbWluZy10ZXh0Iik7CgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBjb25zdCB0b2RheURheSA9IE51bWJlcih0b2RheUlzbygpLnNsaWNlKDgsIDEwKSk7CiAgICAgIGNvbnN0IGN1dG9mZiA9IHJlY3VycmluZ0N1dG9mZkRheShtb250aEtleSwgY3VycmVudE1vbnRoS2V5LCB0b2RheURheSk7CgogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIC8vIFVuIHNldWwgc29sZGUgbmV0ICLDoCB2ZW5pciIgKHJldmVudXMgcsOpY3VycmVudHMgw6AgdmVuaXIgbW9pbnMgZMOpcGVuc2VzCiAgICAgIC8vIHLDqWN1cnJlbnRlcyDDoCB2ZW5pciksIHBsdXTDtHQgcXVlIGRldXggY2hpZmZyZXMgc8OpcGFyw6lzIDogcGx1cyBzaW1wbGUKICAgICAgLy8gw6AgbGlyZSBkJ3VuIGNvdXAgZCfFk2lsLiBMZXMgY2hhcmdlcyBkw6lqw6AgcHLDqWxldsOpZXMvcmXDp3VlcyBuZSBzb250IFBBUwogICAgICAvLyBham91dMOpZXMgaWNpIDogZWxsZXMgZXhpc3RlbnQgZMOpc29ybWFpcyBjb21tZSBkZSB2cmFpZXMgdHJhbnNhY3Rpb25zCiAgICAgIC8vIChjcsOpw6llcyBjw7R0w6kgc2VydmV1cikgZXQgc29udCBkb25jIGTDqWrDoCBjb21wdMOpZXMgZGFucyBgdG90YWxzYAogICAgICAvLyBjaS1kZXNzdXMg4oCUIGxlcyBham91dGVyIMOgIG5vdXZlYXUgbGVzIGNvbXB0ZXJhaXQgZW4gZG91YmxlLgogICAgICBsZXQgdXBjb21pbmdFeHBlbnNlID0gMDsKICAgICAgbGV0IHVwY29taW5nSW5jb21lID0gMDsKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGFsbFJlY3VycmluZykgewogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS5kYXlfb2ZfbW9udGggPD0gY3V0b2ZmKSBjb250aW51ZTsKICAgICAgICBpZiAoaXRlbS50eXBlID09PSAiaW5jb21lIikgdXBjb21pbmdJbmNvbWUgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgICBlbHNlIHVwY29taW5nRXhwZW5zZSArPSBOdW1iZXIoaXRlbS5hbW91bnQpOwogICAgICB9CiAgICAgIGNvbnN0IGxhYmVscyA9IE9iamVjdC5rZXlzKHRvdGFscykubWFwKChjYXQpID0+IGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KTsKICAgICAgY29uc3QgZGF0YSA9IE9iamVjdC52YWx1ZXModG90YWxzKTsKCiAgICAgIGNvbnN0IG5ldFVwY29taW5nID0gdXBjb21pbmdJbmNvbWUgLSB1cGNvbWluZ0V4cGVuc2U7CiAgICAgIGlmIChuZXRVcGNvbWluZyAhPT0gMCkgewogICAgICAgIGNvbnN0IHNpZ24gPSBuZXRVcGNvbWluZyA+IDAgPyAiKyIgOiAi4oiSIjsKICAgICAgICB1cGNvbWluZ1RleHRFbC50ZXh0Q29udGVudCA9IGAke3NpZ259ICR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KE1hdGguYWJzKG5ldFVwY29taW5nKSl9IMOgIHZlbmlyYDsKICAgICAgICB1cGNvbWluZ05vdGVFbC50aXRsZSA9ICJSw6ljdXJyZW50ZXMgcGFzIGVuY29yZSBwcsOpbGV2w6llcy9yZcOndWVzIGNlIG1vaXMtY2kgKHJldmVudXMgbW9pbnMgZMOpcGVuc2VzKSI7CiAgICAgICAgdXBjb21pbmdOb3RlRWwuY2xhc3NMaXN0LnRvZ2dsZSgicG9zaXRpdmUiLCBuZXRVcGNvbWluZyA+IDApOwogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICB9IGVsc2UgewogICAgICAgIHVwY29taW5nTm90ZUVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB9CgogICAgICBpZiAoY2F0ZWdvcnlDaGFydCkgeyBjYXRlZ29yeUNoYXJ0LmRlc3Ryb3koKTsgY2F0ZWdvcnlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmIChkYXRhLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgY2F0ZWdvcnlDaGFydCA9IHNhZmVDcmVhdGVDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiZG91Z2hudXQiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVscywKICAgICAgICAgIGRhdGFzZXRzOiBbewogICAgICAgICAgICBkYXRhLAogICAgICAgICAgICBiYWNrZ3JvdW5kQ29sb3I6IGxhYmVscy5tYXAoKF8sIGkpID0+IENIQVJUX0NPTE9SU1tpICUgQ0hBUlRfQ09MT1JTLmxlbmd0aF0pLAogICAgICAgICAgICBib3JkZXJDb2xvcjogIiMxYTFkMjQiLAogICAgICAgICAgICBib3JkZXJXaWR0aDogMiwKICAgICAgICAgIH1dLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgcGx1Z2luczogewogICAgICAgICAgICBsZWdlbmQ6IHsgcG9zaXRpb246ICJib3R0b20iLCBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiwgYm94V2lkdGg6IDEyLCBwYWRkaW5nOiAxMiwgZm9udDogeyBzaXplOiAxMSB9IH0gfSwKICAgICAgICAgICAgdG9vbHRpcDogeyBjYWxsYmFja3M6IHsgbGFiZWw6IChjdHgpID0+IGAke2N0eC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkKX1gIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgfSwKICAgICAgfSwgZW1wdHlFbCk7CiAgICB9CgogICAgLy8gTcOqbWUgcHJpbmNpcGUgcXVlIHJlbmRlckNhdGVnb3J5Q2hhcnQsIGPDtHTDqSByZXZlbnVzIOKAlCBwYXMgZGUgbm90ZSAiw6AKICAgIC8vIHZlbmlyIiBpY2ksIGVsbGUgcmVzdGUgdW5pcXVlbWVudCBzdXIgbGUgY2FtZW1iZXJ0IGRlcyBkw6lwZW5zZXMgcG91cgogICAgLy8gbmUgcGFzIGFmZmljaGVyIGxlIG3Dqm1lIGNoaWZmcmUgbmV0IMOgIGRldXggZW5kcm9pdHMuCiAgICBmdW5jdGlvbiByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpOwogICAgICBjb25zdCBtb250aEtleSA9IHNlbGVjdC52YWx1ZTsKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LWluY29tZS1jYXRlZ29yaWVzIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWluY29tZS1jYXRlZ29yaWVzLWVtcHR5Iik7CgogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImluY29tZSIgfHwgbW9udGhLZXlPZih0eC5leHBlbnNlX2RhdGUpICE9PSBtb250aEtleSkgY29udGludWU7CiAgICAgICAgdG90YWxzW3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgY29uc3QgbGFiZWxzID0gT2JqZWN0LmtleXModG90YWxzKS5tYXAoKGNhdCkgPT4gYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpOwogICAgICBjb25zdCBkYXRhID0gT2JqZWN0LnZhbHVlcyh0b3RhbHMpOwoKICAgICAgaWYgKGluY29tZUNhdGVnb3J5Q2hhcnQpIHsgaW5jb21lQ2F0ZWdvcnlDaGFydC5kZXN0cm95KCk7IGluY29tZUNhdGVnb3J5Q2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAoZGF0YS5sZW5ndGggPT09IDApIHsKICAgICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwogICAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIGluY29tZUNhdGVnb3J5Q2hhcnQgPSBzYWZlQ3JlYXRlQ2hhcnQoY2FudmFzLCB7CiAgICAgICAgdHlwZTogImRvdWdobnV0IiwKICAgICAgICBkYXRhOiB7CiAgICAgICAgICBsYWJlbHMsCiAgICAgICAgICBkYXRhc2V0czogW3sKICAgICAgICAgICAgZGF0YSwKICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBsYWJlbHMubWFwKChfLCBpKSA9PiBDSEFSVF9DT0xPUlNbaSAlIENIQVJUX0NPTE9SUy5sZW5ndGhdKSwKICAgICAgICAgICAgYm9yZGVyQ29sb3I6ICIjMWExZDI0IiwKICAgICAgICAgICAgYm9yZGVyV2lkdGg6IDIsCiAgICAgICAgICB9XSwKICAgICAgICB9LAogICAgICAgIG9wdGlvbnM6IHsKICAgICAgICAgIHJlc3BvbnNpdmU6IHRydWUsCiAgICAgICAgICBtYWludGFpbkFzcGVjdFJhdGlvOiBmYWxzZSwKICAgICAgICAgIHBsdWdpbnM6IHsKICAgICAgICAgICAgbGVnZW5kOiB7IHBvc2l0aW9uOiAiYm90dG9tIiwgbGFiZWxzOiB7IGNvbG9yOiAiI2U2ZTZlNiIsIGJveFdpZHRoOiAxMiwgcGFkZGluZzogMTIsIGZvbnQ6IHsgc2l6ZTogMTEgfSB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHgubGFiZWx9IDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY3R4LnBhcnNlZCl9YCB9IH0sCiAgICAgICAgICB9LAogICAgICAgIH0sCiAgICAgIH0sIGVtcHR5RWwpOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckV2b2x1dGlvbkNoYXJ0KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY2hhcnQtZXZvbHV0aW9uIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWV2b2x1dGlvbi1lbXB0eSIpOwoKICAgICAgY29uc3QgbW9udGhseSA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IGtleSA9IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKTsKICAgICAgICBpZiAoIW1vbnRobHlba2V5XSkgbW9udGhseVtrZXldID0geyBleHBlbnNlOiAwLCBpbmNvbWU6IDAgfTsKICAgICAgICBtb250aGx5W2tleV1bdHgudHlwZV0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgIH0KICAgICAgLy8gVG91am91cnMgaW5jbHVyZSBsZSBtb2lzIGVuIGNvdXJzIChtw6ptZSBzYW5zIHRyYW5zYWN0aW9uKSBzJ2lsIGV4aXN0ZQogICAgICAvLyBkZXMgY2hhcmdlcyByw6ljdXJyZW50ZXMsIHBvdXIgcXUnaWwgYXBwYXJhaXNzZSBzYW5zIGF0dGVuZHJlIGxhCiAgICAgIC8vIHByZW1pw6hyZSB0cmFuc2FjdGlvbiBkdSBtb2lzLiBMZXMgY2hhcmdlcyBkw6lqw6AgcHLDqWxldsOpZXMvcmXDp3VlcyBuZQogICAgICAvLyBzb250IHBsdXMgYWpvdXTDqWVzIGljaSDDoCBsYSBtYWluIDogZWxsZXMgZXhpc3RlbnQgZMOpc29ybWFpcyBjb21tZSBkZQogICAgICAvLyB2cmFpZXMgdHJhbnNhY3Rpb25zIChjcsOpw6llcyBjw7R0w6kgc2VydmV1cikgZXQgc29udCBkb25jIGTDqWrDoCBjb21wdMOpZXMKICAgICAgLy8gZGFucyBgbW9udGhseWAgdmlhIGxhIGJvdWNsZSBzdXIgYHRyYW5zYWN0aW9uc2AgY2ktZGVzc3VzIOKAlCBjZSBxdWkKICAgICAgLy8gbidlc3QgcGFzIGVuY29yZSBhcnJpdsOpIGVzdCByw6lzdW3DqSBhaWxsZXVycyAoc29sZGUgbmV0ICLDoCB2ZW5pciIpLgogICAgICBjb25zdCBjdXJyZW50TW9udGhLZXkgPSBtb250aEtleU9mKHRvZGF5SXNvKCkpOwogICAgICBpZiAoYWxsUmVjdXJyaW5nLmxlbmd0aCA+IDAgJiYgIW1vbnRobHlbY3VycmVudE1vbnRoS2V5XSkgewogICAgICAgIG1vbnRobHlbY3VycmVudE1vbnRoS2V5XSA9IHsgZXhwZW5zZTogMCwgaW5jb21lOiAwIH07CiAgICAgIH0KICAgICAgY29uc3QgbW9udGhzID0gT2JqZWN0LmtleXMobW9udGhseSkuc29ydCgpOwoKICAgICAgaWYgKGV2b2x1dGlvbkNoYXJ0KSB7IGV2b2x1dGlvbkNoYXJ0LmRlc3Ryb3koKTsgZXZvbHV0aW9uQ2hhcnQgPSBudWxsOyB9CgogICAgICBpZiAobW9udGhzLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAiYmxvY2siOwoKICAgICAgY29uc3QgbGFiZWxzID0gbW9udGhzLm1hcCgoa2V5KSA9PiB7CiAgICAgICAgY29uc3QgW3ksIG1dID0ga2V5LnNwbGl0KCItIikubWFwKE51bWJlcik7CiAgICAgICAgcmV0dXJuIG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHksIG0gLSAxLCAxKSk7CiAgICAgIH0pOwoKICAgICAgY29uc3QgZGF0YXNldHMgPSBbCiAgICAgICAgeyBsYWJlbDogIkTDqXBlbnNlcyIsIGRhdGE6IG1vbnRocy5tYXAoKGspID0+IG1vbnRobHlba10uZXhwZW5zZSksIGJhY2tncm91bmRDb2xvcjogIiNlZjQ0NDQiIH0sCiAgICAgICAgeyBsYWJlbDogIlJldmVudXMiLCBkYXRhOiBtb250aHMubWFwKChrKSA9PiBtb250aGx5W2tdLmluY29tZSksIGJhY2tncm91bmRDb2xvcjogIiMyMmM1NWUiIH0sCiAgICAgIF07CgogICAgICBldm9sdXRpb25DaGFydCA9IHNhZmVDcmVhdGVDaGFydChjYW52YXMsIHsKICAgICAgICB0eXBlOiAiYmFyIiwKICAgICAgICBkYXRhOiB7IGxhYmVscywgZGF0YXNldHMgfSwKICAgICAgICBvcHRpb25zOiB7CiAgICAgICAgICByZXNwb25zaXZlOiB0cnVlLAogICAgICAgICAgbWFpbnRhaW5Bc3BlY3RSYXRpbzogZmFsc2UsCiAgICAgICAgICBzY2FsZXM6IHsKICAgICAgICAgICAgeDogeyB0aWNrczogeyBjb2xvcjogIiM5YWEwYWMiIH0sIGdyaWQ6IHsgY29sb3I6ICIjMmEyZTM4IiB9IH0sCiAgICAgICAgICAgIHk6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSwgYmVnaW5BdFplcm86IHRydWUgfSwKICAgICAgICAgIH0sCiAgICAgICAgICBwbHVnaW5zOiB7CiAgICAgICAgICAgIGxlZ2VuZDogeyBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiB9IH0sCiAgICAgICAgICAgIHRvb2x0aXA6IHsgY2FsbGJhY2tzOiB7IGxhYmVsOiAoY3R4KSA9PiBgJHtjdHguZGF0YXNldC5sYWJlbH0gOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChjdHgucGFyc2VkLnkpfWAgfSB9LAogICAgICAgICAgfSwKICAgICAgICB9LAogICAgICB9LCBlbXB0eUVsKTsKICAgIH0KCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDb21wYXJlciBkZXV4IG1vaXMKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGZ1bmN0aW9uIHBvcHVsYXRlQ29tcGFyZU1vbnRoU2VsZWN0cyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgbW9udGhTZXQgPSBuZXcgU2V0KHRyYW5zYWN0aW9ucy5tYXAoKHR4KSA9PiBtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkpKTsKICAgICAgY29uc3QgbW9udGhzID0gWy4uLm1vbnRoU2V0XS5zb3J0KCkucmV2ZXJzZSgpOwogICAgICBjb25zdCBzZWxlY3RBID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpOwogICAgICBjb25zdCBzZWxlY3RCID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYiIpOwoKICAgICAgZm9yIChjb25zdCBzZWxlY3Qgb2YgW3NlbGVjdEEsIHNlbGVjdEJdKSB7CiAgICAgICAgY29uc3QgcHJldmlvdXNWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICBzZWxlY3QuaW5uZXJIVE1MID0gIiI7CiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgbW9udGhzKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IGtleTsKICAgICAgICAgIGNvbnN0IFt5LCBtXSA9IGtleS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICAgICAgY29uc3QgbGFiZWwgPSBtb250aEZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoeSwgbSAtIDEsIDEpKTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsLmNoYXJBdCgwKS50b1VwcGVyQ2FzZSgpICsgbGFiZWwuc2xpY2UoMSk7CiAgICAgICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgICB9CiAgICAgICAgaWYgKG1vbnRocy5pbmNsdWRlcyhwcmV2aW91c1ZhbHVlKSkgc2VsZWN0LnZhbHVlID0gcHJldmlvdXNWYWx1ZTsKICAgICAgfQogICAgICAvLyBQYXIgZMOpZmF1dCA6IG1vaXMgZW4gY291cnMgdnMgbW9pcyBwcsOpY8OpZGVudCwgc2kgbGVzIGRldXggZXhpc3RlbnQuCiAgICAgIGlmICghc2VsZWN0QS52YWx1ZSAmJiBtb250aHMubGVuZ3RoID4gMCkgc2VsZWN0QS52YWx1ZSA9IG1vbnRoc1swXTsKICAgICAgaWYgKCFzZWxlY3RCLnZhbHVlICYmIG1vbnRocy5sZW5ndGggPiAxKSBzZWxlY3RCLnZhbHVlID0gbW9udGhzWzFdOwogICAgfQoKICAgIGZ1bmN0aW9uIG1vbnRoQ2F0ZWdvcnlUb3RhbHModHJhbnNhY3Rpb25zLCBtb250aEtleSkgewogICAgICBjb25zdCB0b3RhbHMgPSB7fTsKICAgICAgbGV0IHRvdGFsID0gMDsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiIHx8IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSAhPT0gbW9udGhLZXkpIGNvbnRpbnVlOwogICAgICAgIHRvdGFsc1t0eC5jYXRlZ29yeV0gPSAodG90YWxzW3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIHRvdGFsICs9IE51bWJlcih0eC5hbW91bnQpOwogICAgICB9CiAgICAgIHJldHVybiB7IHRvdGFscywgdG90YWwgfTsKICAgIH0KCiAgICBmdW5jdGlvbiByZW5kZXJNb250aENvbXBhcmlzb24oKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS10YWJsZS13cmFwIik7CiAgICAgIGNvbnN0IGVtcHR5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1lbXB0eSIpOwogICAgICBjb25zdCBtb250aEEgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1hIikudmFsdWU7CiAgICAgIGNvbnN0IG1vbnRoQiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb21wYXJlLW1vbnRoLWIiKS52YWx1ZTsKCiAgICAgIGlmICghbW9udGhBIHx8ICFtb250aEIpIHsKICAgICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGNvbnN0IHsgdG90YWxzOiB0b3RhbHNBLCB0b3RhbDogZ3JhbmRBIH0gPSBtb250aENhdGVnb3J5VG90YWxzKGFsbFRyYW5zYWN0aW9ucywgbW9udGhBKTsKICAgICAgY29uc3QgeyB0b3RhbHM6IHRvdGFsc0IsIHRvdGFsOiBncmFuZEIgfSA9IG1vbnRoQ2F0ZWdvcnlUb3RhbHMoYWxsVHJhbnNhY3Rpb25zLCBtb250aEIpOwogICAgICBjb25zdCBjYXRlZ29yaWVzID0gWy4uLm5ldyBTZXQoWy4uLk9iamVjdC5rZXlzKHRvdGFsc0EpLCAuLi5PYmplY3Qua2V5cyh0b3RhbHNCKV0pXS5zb3J0KAogICAgICAgIChhLCBiKSA9PiAodG90YWxzQltiXSB8fCAwKSAtICh0b3RhbHNBW2FdIHx8IDApCiAgICAgICk7CgogICAgICBjb25zdCBbeWEsIG1hXSA9IG1vbnRoQS5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBbeWIsIG1iXSA9IG1vbnRoQi5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCBsYWJlbEEgPSBtb250aFNob3J0Rm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZSh5YSwgbWEgLSAxLCAxKSk7CiAgICAgIGNvbnN0IGxhYmVsQiA9IG1vbnRoU2hvcnRGb3JtYXR0ZXIuZm9ybWF0KG5ldyBEYXRlKHliLCBtYiAtIDEsIDEpKTsKCiAgICAgIC8vIERpZmYgPSBtb250YW50IGR1IG1vaXMgQiBtb2lucyBjZWx1aSBkdSBtb2lzIEEuIFBvdXIgZGVzIGTDqXBlbnNlcywKICAgICAgLy8gZMOpcGVuc2VyIFBMVVMgKGRpZmYgcG9zaXRpZikgZXN0IGxhIG1hdXZhaXNlIG5vdXZlbGxlIOKGkiByb3VnZSA7IGVuCiAgICAgIC8vIGTDqXBlbnNlciBNT0lOUyAoZGlmZiBuw6lnYXRpZikg4oaSIHZlcnQuCiAgICAgIGZ1bmN0aW9uIGRpZmZDZWxsKGEsIGIpIHsKICAgICAgICBjb25zdCBkaWZmID0gYiAtIGE7CiAgICAgICAgaWYgKE1hdGguYWJzKGRpZmYpIDwgMC4wMSkgcmV0dXJuIGA8dGQ+4oCUPC90ZD5gOwogICAgICAgIGNvbnN0IGNscyA9IGRpZmYgPiAwID8gImRpZmYtbmVnYXRpdmUiIDogImRpZmYtcG9zaXRpdmUiOwogICAgICAgIHJldHVybiBgPHRkIGNsYXNzPSIke2Nsc30iPiR7ZGlmZiA+IDAgPyAiKyIgOiAiIn0ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChkaWZmKX08L3RkPmA7CiAgICAgIH0KCiAgICAgIGxldCBodG1sID0gYDx0YWJsZSBjbGFzcz0ic2ltcGxlLXRhYmxlIj48dGhlYWQ+PHRyPjx0aD5DYXTDqWdvcmllPC90aD48dGg+JHtsYWJlbEF9PC90aD48dGg+JHtsYWJlbEJ9PC90aD48dGg+RGlmZsOpcmVuY2U8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+YDsKICAgICAgZm9yIChjb25zdCBjYXQgb2YgY2F0ZWdvcmllcykgewogICAgICAgIGNvbnN0IGEgPSB0b3RhbHNBW2NhdF0gfHwgMDsKICAgICAgICBjb25zdCBiID0gdG90YWxzQltjYXRdIHx8IDA7CiAgICAgICAgaHRtbCArPSBgPHRyPjx0ZD4ke2VzY2FwZUh0bWwoYWxsQ2F0ZWdvcnlMYWJlbHNbY2F0XSB8fCBjYXQpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGEpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGIpfTwvdGQ+JHtkaWZmQ2VsbChhLCBiKX08L3RyPmA7CiAgICAgIH0KICAgICAgaHRtbCArPSBgPHRyIGNsYXNzPSJ0b3RhbC1yb3ciPjx0ZD5Ub3RhbCBkw6lwZW5zZXM8L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChncmFuZEEpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGdyYW5kQil9PC90ZD4ke2RpZmZDZWxsKGdyYW5kQSwgZ3JhbmRCKX08L3RyPmA7CiAgICAgIGh0bWwgKz0gYDwvdGJvZHk+PC90YWJsZT5gOwogICAgICB3cmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbXBhcmUtbW9udGgtYSIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsIHJlbmRlck1vbnRoQ29tcGFyaXNvbik7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiY29tcGFyZS1tb250aC1iIikuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgcmVuZGVyTW9udGhDb21wYXJpc29uKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBNb3llbm5lIGV0IHRlbmRhbmNlIHBhciBjYXTDqWdvcmllCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBDYWxjdWxlLCBwb3VyIGNoYXF1ZSBjYXTDqWdvcmllIGRlIGTDqXBlbnNlLCBsYSBtb3llbm5lIG1lbnN1ZWxsZSwgbGUKICAgIC8vIG1vbnRhbnQgZHUgbW9pcyBlbiBjb3VycywgZXQgbGEgdGVuZGFuY2UgKGRpcmVjdGlvbiArIHJhdGlvIHZzCiAgICAvLyBtb3llbm5lKS4gUGFydGFnw6kgZW50cmUgbGUgdGFibGVhdSAiTW95ZW5uZSBldCB0ZW5kYW5jZSBwYXIgY2F0w6lnb3JpZSIKICAgIC8vIGV0IGxlcyBjb25zZWlscyBkJ8OpcGFyZ25lLCBwb3VyIG5lIHBhcyBkdXBsaXF1ZXIgY2V0dGUgbG9naXF1ZS4KICAgIGZ1bmN0aW9uIGNvbXB1dGVDYXRlZ29yeVRyZW5kcyh0cmFuc2FjdGlvbnMpIHsKICAgICAgY29uc3QgbW9udGhLZXlzID0gWy4uLm5ldyBTZXQodHJhbnNhY3Rpb25zLm1hcCgodHgpID0+IG1vbnRoS2V5T2YodHguZXhwZW5zZV9kYXRlKSkpXS5zb3J0KCk7CiAgICAgIGlmIChtb250aEtleXMubGVuZ3RoID09PSAwKSByZXR1cm4gW107CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5c1ttb250aEtleXMubGVuZ3RoIC0gMV07CiAgICAgIGNvbnN0IG5iTW9udGhzID0gbW9udGhLZXlzLmxlbmd0aDsKCiAgICAgIC8vIHRvdGFsIHBhciBjYXTDqWdvcmllLCBldCBwYXIgY2F0w6lnb3JpZSttb2lzIChwb3VyIGlzb2xlciBsZSBtb2lzIGVuIGNvdXJzKQogICAgICBjb25zdCB0b3RhbHNCeUNhdGVnb3J5ID0ge307CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEJ5Q2F0ZWdvcnkgPSB7fTsKICAgICAgZm9yIChjb25zdCB0eCBvZiB0cmFuc2FjdGlvbnMpIHsKICAgICAgICBpZiAodHgudHlwZSAhPT0gImV4cGVuc2UiKSBjb250aW51ZTsKICAgICAgICB0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSA9ICh0b3RhbHNCeUNhdGVnb3J5W3R4LmNhdGVnb3J5XSB8fCAwKSArIE51bWJlcih0eC5hbW91bnQpOwogICAgICAgIGlmIChtb250aEtleU9mKHR4LmV4cGVuc2VfZGF0ZSkgPT09IGN1cnJlbnRNb250aEtleSkgewogICAgICAgICAgY3VycmVudE1vbnRoQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gPSAoY3VycmVudE1vbnRoQnlDYXRlZ29yeVt0eC5jYXRlZ29yeV0gfHwgMCkgKyBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICB9CiAgICAgIH0KCiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBPYmplY3Qua2V5cyh0b3RhbHNCeUNhdGVnb3J5KS5zb3J0KChhLCBiKSA9PiB0b3RhbHNCeUNhdGVnb3J5W2JdIC0gdG90YWxzQnlDYXRlZ29yeVthXSk7CiAgICAgIHJldHVybiBjYXRlZ29yaWVzLm1hcCgoY2F0KSA9PiB7CiAgICAgICAgY29uc3QgYXZlcmFnZSA9IHRvdGFsc0J5Q2F0ZWdvcnlbY2F0XSAvIG5iTW9udGhzOwogICAgICAgIGNvbnN0IGN1cnJlbnQgPSBjdXJyZW50TW9udGhCeUNhdGVnb3J5W2NhdF0gfHwgMDsKICAgICAgICBsZXQgZGlyZWN0aW9uID0gInN0YWJsZSI7CiAgICAgICAgbGV0IHJhdGlvID0gMDsKICAgICAgICBpZiAoYXZlcmFnZSA+IDApIHsKICAgICAgICAgIHJhdGlvID0gKGN1cnJlbnQgLSBhdmVyYWdlKSAvIGF2ZXJhZ2U7CiAgICAgICAgICBpZiAocmF0aW8gPiAwLjE1KSBkaXJlY3Rpb24gPSAidXAiOwogICAgICAgICAgZWxzZSBpZiAocmF0aW8gPCAtMC4xNSkgZGlyZWN0aW9uID0gImRvd24iOwogICAgICAgIH0gZWxzZSBpZiAoY3VycmVudCA+IDApIHsKICAgICAgICAgIGRpcmVjdGlvbiA9ICJ1cCI7CiAgICAgICAgfQogICAgICAgIHJldHVybiB7IGNhdGVnb3J5OiBjYXQsIGF2ZXJhZ2UsIGN1cnJlbnQsIHJhdGlvLCBkaXJlY3Rpb24gfTsKICAgICAgfSk7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidHJlbmQtdGFibGUtd3JhcCIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInRyZW5kLWVtcHR5Iik7CgogICAgICBjb25zdCB0cmVuZHMgPSBjb21wdXRlQ2F0ZWdvcnlUcmVuZHModHJhbnNhY3Rpb25zKTsKICAgICAgaWYgKHRyZW5kcy5sZW5ndGggPT09IDApIHsKICAgICAgICB3cmFwLmlubmVySFRNTCA9ICIiOwogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKCiAgICAgIGxldCBodG1sID0gYDx0YWJsZSBjbGFzcz0ic2ltcGxlLXRhYmxlIj48dGhlYWQ+PHRyPjx0aD5DYXTDqWdvcmllPC90aD48dGg+TW95ZW5uZS9tb2lzPC90aD48dGg+Q2UgbW9pcy1jaTwvdGg+PHRoPlRlbmRhbmNlPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgdCBvZiB0cmVuZHMpIHsKICAgICAgICBsZXQgdHJlbmRIdG1sID0gYDxzcGFuIGNsYXNzPSJ0cmVuZC1mbGF0Ij7ihpIgc3RhYmxlPC9zcGFuPmA7CiAgICAgICAgaWYgKHQuZGlyZWN0aW9uID09PSAidXAiKSB7CiAgICAgICAgICB0cmVuZEh0bWwgPSB0LmF2ZXJhZ2UgPiAwCiAgICAgICAgICAgID8gYDxzcGFuIGNsYXNzPSJ0cmVuZC11cCI+4oaRICske01hdGgucm91bmQodC5yYXRpbyAqIDEwMCl9JTwvc3Bhbj5gCiAgICAgICAgICAgIDogYDxzcGFuIGNsYXNzPSJ0cmVuZC11cCI+4oaRIG5vdXZlYXU8L3NwYW4+YDsKICAgICAgICB9IGVsc2UgaWYgKHQuZGlyZWN0aW9uID09PSAiZG93biIpIHsKICAgICAgICAgIHRyZW5kSHRtbCA9IGA8c3BhbiBjbGFzcz0idHJlbmQtZG93biI+4oaTICR7TWF0aC5yb3VuZCh0LnJhdGlvICogMTAwKX0lPC9zcGFuPmA7CiAgICAgICAgfQogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHtlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW3QuY2F0ZWdvcnldIHx8IHQuY2F0ZWdvcnkpfTwvdGQ+PHRkPiR7Y3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHQuYXZlcmFnZSl9PC90ZD48dGQ+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodC5jdXJyZW50KX08L3RkPjx0ZD4ke3RyZW5kSHRtbH08L3RkPjwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgd3JhcC5pbm5lckhUTUwgPSBodG1sOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEJpbGFuIGFubnVlbAogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgTU9OVEhfU0hPUlRfTEFCRUxTID0gWwogICAgICAiSmFuIiwgIkbDqXYiLCAiTWFyIiwgIkF2ciIsICJNYWkiLCAiSnVpbiIsICJKdWlsIiwgIkFvw7t0IiwgIlNlcCIsICJPY3QiLCAiTm92IiwgIkTDqWMiLAogICAgXTsKCiAgICBmdW5jdGlvbiBwb3B1bGF0ZVllYXJTZWxlY3QodHJhbnNhY3Rpb25zKSB7CiAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHkteWVhci1zZWxlY3QiKTsKICAgICAgY29uc3QgeWVhcnMgPSBbLi4ubmV3IFNldCh0cmFuc2FjdGlvbnMubWFwKCh0eCkgPT4gdHguZXhwZW5zZV9kYXRlLnNsaWNlKDAsIDQpKSldLnNvcnQoKS5yZXZlcnNlKCk7CiAgICAgIGNvbnN0IGN1cnJlbnRZZWFyID0gU3RyaW5nKG5ldyBEYXRlKCkuZ2V0RnVsbFllYXIoKSk7CiAgICAgIGlmICgheWVhcnMuaW5jbHVkZXMoY3VycmVudFllYXIpKSB5ZWFycy51bnNoaWZ0KGN1cnJlbnRZZWFyKTsKCiAgICAgIGNvbnN0IHByZXZpb3VzVmFsdWUgPSBzZWxlY3QudmFsdWU7CiAgICAgIHNlbGVjdC5pbm5lckhUTUwgPSB5ZWFycy5tYXAoKHkpID0+IGA8b3B0aW9uIHZhbHVlPSIke3l9Ij4ke3l9PC9vcHRpb24+YCkuam9pbigiIik7CiAgICAgIHNlbGVjdC52YWx1ZSA9IHllYXJzLmluY2x1ZGVzKHByZXZpb3VzVmFsdWUpID8gcHJldmlvdXNWYWx1ZSA6IGN1cnJlbnRZZWFyOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlclllYXJseU92ZXJ2aWV3KHRyYW5zYWN0aW9ucykgewogICAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LXllYXItc2VsZWN0Iik7CiAgICAgIGNvbnN0IHllYXIgPSBzZWxlY3QudmFsdWU7CiAgICAgIGlmICgheWVhcikgcmV0dXJuOwoKICAgICAgY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNoYXJ0LXllYXJseSIpOwogICAgICBjb25zdCBlbXB0eUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1lbXB0eSIpOwogICAgICBjb25zdCB0YWJsZVdyYXAgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgieWVhcmx5LWNhdGVnb3J5LXRhYmxlLXdyYXAiKTsKCiAgICAgIGNvbnN0IHllYXJUcmFuc2FjdGlvbnMgPSB0cmFuc2FjdGlvbnMuZmlsdGVyKCh0eCkgPT4gdHguZXhwZW5zZV9kYXRlLnNsaWNlKDAsIDQpID09PSB5ZWFyKTsKCiAgICAgIGxldCB0b3RhbEV4cGVuc2VzID0gMDsKICAgICAgbGV0IHRvdGFsSW5jb21lID0gMDsKICAgICAgY29uc3QgZXhwZW5zZUJ5TW9udGggPSBBcnJheSgxMikuZmlsbCgwKTsKICAgICAgY29uc3QgaW5jb21lQnlNb250aCA9IEFycmF5KDEyKS5maWxsKDApOwogICAgICBjb25zdCB0b3RhbHNCeUNhdGVnb3J5ID0ge307CiAgICAgIGZvciAoY29uc3QgdHggb2YgeWVhclRyYW5zYWN0aW9ucykgewogICAgICAgIGNvbnN0IG1vbnRoSW5kZXggPSBOdW1iZXIodHguZXhwZW5zZV9kYXRlLnNsaWNlKDUsIDcpKSAtIDE7CiAgICAgICAgaWYgKHR4LnR5cGUgPT09ICJpbmNvbWUiKSB7CiAgICAgICAgICB0b3RhbEluY29tZSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICAgIGluY29tZUJ5TW9udGhbbW9udGhJbmRleF0gKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHRvdGFsRXhwZW5zZXMgKz0gTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgICBleHBlbnNlQnlNb250aFttb250aEluZGV4XSArPSBOdW1iZXIodHguYW1vdW50KTsKICAgICAgICAgIHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldID0gKHRvdGFsc0J5Q2F0ZWdvcnlbdHguY2F0ZWdvcnldIHx8IDApICsgTnVtYmVyKHR4LmFtb3VudCk7CiAgICAgICAgfQogICAgICB9CiAgICAgIGNvbnN0IG5ldCA9IHRvdGFsSW5jb21lIC0gdG90YWxFeHBlbnNlczsKCiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ5ZWFybHktdG90YWwtZXhwZW5zZXMiKS50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEV4cGVuc2VzKTsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS10b3RhbC1pbmNvbWUiKS50ZXh0Q29udGVudCA9IGN1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh0b3RhbEluY29tZSk7CiAgICAgIGNvbnN0IG5ldEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS1uZXQiKTsKICAgICAgbmV0RWwudGV4dENvbnRlbnQgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQobmV0KTsKICAgICAgbmV0RWwuY2xhc3NOYW1lID0gInllYXJseS1zdGF0LXZhbHVlICIgKyAobmV0ID49IDAgPyAiaW5jb21lIiA6ICJleHBlbnNlIik7CgogICAgICBpZiAoeWVhcmx5Q2hhcnQpIHsgeWVhcmx5Q2hhcnQuZGVzdHJveSgpOyB5ZWFybHlDaGFydCA9IG51bGw7IH0KCiAgICAgIGlmICh5ZWFyVHJhbnNhY3Rpb25zLmxlbmd0aCA9PT0gMCkgewogICAgICAgIGVtcHR5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgY2FudmFzLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgICAgdGFibGVXcmFwLmlubmVySFRNTCA9ICIiOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBlbXB0eUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGNhbnZhcy5zdHlsZS5kaXNwbGF5ID0gImJsb2NrIjsKCiAgICAgIHllYXJseUNoYXJ0ID0gc2FmZUNyZWF0ZUNoYXJ0KGNhbnZhcywgewogICAgICAgIHR5cGU6ICJiYXIiLAogICAgICAgIGRhdGE6IHsKICAgICAgICAgIGxhYmVsczogTU9OVEhfU0hPUlRfTEFCRUxTLAogICAgICAgICAgZGF0YXNldHM6IFsKICAgICAgICAgICAgeyBsYWJlbDogIkTDqXBlbnNlcyIsIGRhdGE6IGV4cGVuc2VCeU1vbnRoLCBiYWNrZ3JvdW5kQ29sb3I6ICIjZWY0NDQ0IiB9LAogICAgICAgICAgICB7IGxhYmVsOiAiUmV2ZW51cyIsIGRhdGE6IGluY29tZUJ5TW9udGgsIGJhY2tncm91bmRDb2xvcjogIiMyMmM1NWUiIH0sCiAgICAgICAgICBdLAogICAgICAgIH0sCiAgICAgICAgb3B0aW9uczogewogICAgICAgICAgcmVzcG9uc2l2ZTogdHJ1ZSwKICAgICAgICAgIG1haW50YWluQXNwZWN0UmF0aW86IGZhbHNlLAogICAgICAgICAgc2NhbGVzOiB7CiAgICAgICAgICAgIHg6IHsgdGlja3M6IHsgY29sb3I6ICIjOWFhMGFjIiB9LCBncmlkOiB7IGNvbG9yOiAiIzJhMmUzOCIgfSB9LAogICAgICAgICAgICB5OiB7IHRpY2tzOiB7IGNvbG9yOiAiIzlhYTBhYyIgfSwgZ3JpZDogeyBjb2xvcjogIiMyYTJlMzgiIH0gfSwKICAgICAgICAgIH0sCiAgICAgICAgICBwbHVnaW5zOiB7IGxlZ2VuZDogeyBsYWJlbHM6IHsgY29sb3I6ICIjZTZlNmU2IiB9IH0gfSwKICAgICAgICB9LAogICAgICB9LCBlbXB0eUVsKTsKCiAgICAgIGNvbnN0IGNhdGVnb3JpZXMgPSBPYmplY3Qua2V5cyh0b3RhbHNCeUNhdGVnb3J5KS5zb3J0KChhLCBiKSA9PiB0b3RhbHNCeUNhdGVnb3J5W2JdIC0gdG90YWxzQnlDYXRlZ29yeVthXSk7CiAgICAgIGxldCBodG1sID0gYDx0YWJsZSBjbGFzcz0ic2ltcGxlLXRhYmxlIj48dGhlYWQ+PHRyPjx0aD5DYXTDqWdvcmllPC90aD48dGg+VG90YWw8L3RoPjx0aD4lIGRlIGwnYW5uw6llPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5PmA7CiAgICAgIGZvciAoY29uc3QgY2F0IG9mIGNhdGVnb3JpZXMpIHsKICAgICAgICBjb25zdCBhbW91bnQgPSB0b3RhbHNCeUNhdGVnb3J5W2NhdF07CiAgICAgICAgY29uc3QgcGN0ID0gdG90YWxFeHBlbnNlcyA+IDAgPyBNYXRoLnJvdW5kKChhbW91bnQgLyB0b3RhbEV4cGVuc2VzKSAqIDEwMCkgOiAwOwogICAgICAgIGh0bWwgKz0gYDx0cj48dGQ+JHtlc2NhcGVIdG1sKGFsbENhdGVnb3J5TGFiZWxzW2NhdF0gfHwgY2F0KX08L3RkPjx0ZD4ke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChhbW91bnQpfTwvdGQ+PHRkPiR7cGN0fSU8L3RkPjwvdHI+YDsKICAgICAgfQogICAgICBodG1sICs9IGA8L3Rib2R5PjwvdGFibGU+YDsKICAgICAgdGFibGVXcmFwLmlubmVySFRNTCA9IGh0bWw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInllYXJseS15ZWFyLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHJlbmRlclllYXJseU92ZXJ2aWV3KGFsbFRyYW5zYWN0aW9ucykpOwoKICAgIGZ1bmN0aW9uIHJlbmRlckRhc2hib2FyZCh0cmFuc2FjdGlvbnMpIHsKICAgICAgcG9wdWxhdGVNb250aFNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJDYXRlZ29yeUNoYXJ0KHRyYW5zYWN0aW9ucyk7CiAgICAgIHJlbmRlckluY29tZUNhdGVnb3J5Q2hhcnQodHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyQnVkZ2V0cyh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJFdm9sdXRpb25DaGFydCh0cmFuc2FjdGlvbnMpOwogICAgICBwb3B1bGF0ZUNvbXBhcmVNb250aFNlbGVjdHModHJhbnNhY3Rpb25zKTsKICAgICAgcmVuZGVyTW9udGhDb21wYXJpc29uKCk7CiAgICAgIHJlbmRlckNhdGVnb3J5VHJlbmRzKHRyYW5zYWN0aW9ucyk7CiAgICAgIHBvcHVsYXRlWWVhclNlbGVjdCh0cmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJZZWFybHlPdmVydmlldyh0cmFuc2FjdGlvbnMpOwogICAgICBzZXR1cERhc2hib2FyZENoaXBzKCk7CiAgICB9CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gU8OpbGVjdGV1ciBkdSB0YWJsZWF1IGRlIGJvcmQgOiB1biBzZXVsIGJsb2MgYWZmaWNow6kgw6AgbGEgZm9pcyAoc3VyIGxlcwogICAgLy8gNyBlbXBpbMOpcykgcG91ciBxdWUgw6dhIHRpZW5uZSBzdXIgdW4gw6ljcmFuIGRlIHTDqWzDqXBob25lIHNhbnMgZMOpZmlsZXIKICAgIC8vIHNhbnMgZmluLiBMZXMgY2FsY3Vscy9ncmFwaGlxdWVzIGV1eC1tw6ptZXMgbmUgY2hhbmdlbnQgcGFzIOKAlCBzZXVsZSBsYQogICAgLy8gdmlzaWJpbGl0w6kgZGVzIGJsb2NzIGVzdCBwaWxvdMOpZSBwYXIgbGEgcHVjZSBhY3RpdmUuCiAgICBjb25zdCBEQVNIQk9BUkRfU0VDVElPTlMgPSBbCiAgICAgIHsga2V5OiAiZXhwZW5zZXMiLCBsYWJlbDogIkTDqXBlbnNlcyIsIHJvd0lkOiAiZGFzaC1yb3ctZXhwZW5zZXMiIH0sCiAgICAgIHsga2V5OiAiaW5jb21lIiwgbGFiZWw6ICJSZXZlbnVzIiwgcm93SWQ6ICJkYXNoLXJvdy1pbmNvbWUiIH0sCiAgICAgIHsga2V5OiAiYnVkZ2V0cyIsIGxhYmVsOiAiQnVkZ2V0cyIsIHJvd0lkOiAiZGFzaC1yb3ctYnVkZ2V0cyIgfSwKICAgICAgeyBrZXk6ICJldm9sdXRpb24iLCBsYWJlbDogIsOJdm9sdXRpb24iLCByb3dJZDogImRhc2gtcm93LWV2b2x1dGlvbiIgfSwKICAgICAgeyBrZXk6ICJjb21wYXJlIiwgbGFiZWw6ICJDb21wYXJlciIsIHJvd0lkOiAiZGFzaC1yb3ctY29tcGFyZSIgfSwKICAgICAgeyBrZXk6ICJ0cmVuZCIsIGxhYmVsOiAiVGVuZGFuY2VzIiwgcm93SWQ6ICJkYXNoLXJvdy10cmVuZCIgfSwKICAgICAgeyBrZXk6ICJ5ZWFybHkiLCBsYWJlbDogIkFubsOpZSIsIHJvd0lkOiAiZGFzaC1yb3cteWVhcmx5IiB9LAogICAgXTsKICAgIGxldCBkYXNoYm9hcmRBY3RpdmVTZWN0aW9uID0gREFTSEJPQVJEX1NFQ1RJT05TWzBdLmtleTsKICAgIGxldCBkYXNoYm9hcmRDaGlwc0J1aWx0ID0gZmFsc2U7CgogICAgZnVuY3Rpb24gc2hvd0Rhc2hib2FyZFNlY3Rpb24oa2V5KSB7CiAgICAgIGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24gPSBrZXk7CiAgICAgIGZvciAoY29uc3Qgc2VjdGlvbiBvZiBEQVNIQk9BUkRfU0VDVElPTlMpIHsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChzZWN0aW9uLnJvd0lkKS5jbGFzc0xpc3QudG9nZ2xlKCJkYXNoLWhpZGRlbiIsIHNlY3Rpb24ua2V5ICE9PSBrZXkpOwogICAgICB9CiAgICAgIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoIi5kYXNoYm9hcmQtY2hpcCIpLmZvckVhY2goKGNoaXApID0+IHsKICAgICAgICBjaGlwLmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIGNoaXAuZGF0YXNldC5zZWN0aW9uID09PSBrZXkpOwogICAgICB9KTsKICAgICAgLy8gVW4gZ3JhcGhpcXVlIENoYXJ0LmpzIHJlY3LDqcOpIHBlbmRhbnQgcXVlIHNvbiBibG9jIMOpdGFpdCBtYXNxdcOpCiAgICAgIC8vIChkaXNwbGF5Om5vbmUpIHNlIHJldHJvdXZlIGF2ZWMgdW4gY2FuZXZhcyBkZSB0YWlsbGUgbnVsbGUgZXQgbmUgc2UKICAgICAgLy8gY29ycmlnZSBwYXMgdG91dCBzZXVsIGVuIHJlZGV2ZW5hbnQgdmlzaWJsZSDigJQgb24gZm9yY2UgdW4gcmVzaXplCiAgICAgIC8vIGp1c3RlIGFwcsOocyBsJ2F2b2lyIGFmZmljaMOpLCBwb3VyIGxlcyA0IGdyYXBoaXF1ZXMgY29uY2VybsOpcy4KICAgICAgZm9yIChjb25zdCBjaGFydCBvZiBbY2F0ZWdvcnlDaGFydCwgaW5jb21lQ2F0ZWdvcnlDaGFydCwgZXZvbHV0aW9uQ2hhcnQsIHllYXJseUNoYXJ0XSkgewogICAgICAgIGlmIChjaGFydCkgY2hhcnQucmVzaXplKCk7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXR1cERhc2hib2FyZENoaXBzKCkgewogICAgICBpZiAoZGFzaGJvYXJkQ2hpcHNCdWlsdCkgewogICAgICAgIHNob3dEYXNoYm9hcmRTZWN0aW9uKGRhc2hib2FyZEFjdGl2ZVNlY3Rpb24pOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLWNoaXAtcm93Iik7CiAgICAgIGZvciAoY29uc3Qgc2VjdGlvbiBvZiBEQVNIQk9BUkRfU0VDVElPTlMpIHsKICAgICAgICBjb25zdCBjaGlwID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgY2hpcC50eXBlID0gImJ1dHRvbiI7CiAgICAgICAgY2hpcC5jbGFzc05hbWUgPSAiZGFzaGJvYXJkLWNoaXAiOwogICAgICAgIGNoaXAuZGF0YXNldC5zZWN0aW9uID0gc2VjdGlvbi5rZXk7CiAgICAgICAgY2hpcC50ZXh0Q29udGVudCA9IHNlY3Rpb24ubGFiZWw7CiAgICAgICAgY2hpcC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHNob3dEYXNoYm9hcmRTZWN0aW9uKHNlY3Rpb24ua2V5KSk7CiAgICAgICAgcm93LmFwcGVuZENoaWxkKGNoaXApOwogICAgICB9CiAgICAgIGRhc2hib2FyZENoaXBzQnVpbHQgPSB0cnVlOwogICAgICBzaG93RGFzaGJvYXJkU2VjdGlvbihkYXNoYm9hcmRBY3RpdmVTZWN0aW9uKTsKICAgIH0KCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZGFzaGJvYXJkLW1vbnRoLXNlbGVjdCIpLmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgcmVuZGVyQ2F0ZWdvcnlDaGFydChhbGxUcmFuc2FjdGlvbnMpOwogICAgICByZW5kZXJJbmNvbWVDYXRlZ29yeUNoYXJ0KGFsbFRyYW5zYWN0aW9ucyk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEaWN0w6llIHZvY2FsZQogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgbWljQnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImZhYi1taWMiKTsKICAgIGNvbnN0IHZvaWNlQmFubmVyRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgidm9pY2UtYmFubmVyIik7CgogICAgLy8gSWQgZGUgbGEgZGVybmnDqHJlIHRyYW5zYWN0aW9uIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZSBzZXNzaW9uIGRlCiAgICAvLyBuYXZpZ2F0aW9uIChyZW1pcyDDoCB6w6lybyBzaSBvbiByZWNoYXJnZSBsYSBwYWdlKS4gU2VydCB1bmlxdWVtZW50IMOgCiAgICAvLyBhcHBsaXF1ZXIgdW5lIGNvcnJlY3Rpb24gKCJlbiBmYWl0IGMnw6l0YWl0IHBsdXTDtHQuLi4iKSBzdXIgbGEgYm9ubmUKICAgIC8vIHRyYW5zYWN0aW9uLiBTYW5zIMOnYSwgb3Ugc2kgbGEgcGhyYXNlIG4nZXN0IHBhcyB1bmUgY29ycmVjdGlvbiwgb24KICAgIC8vIGNyw6llIHRvdWpvdXJzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbiDigJQgbWlldXggdmF1dCB1biBkb3VibG9uIHF1J3VuZQogICAgLy8gZMOpcGVuc2UgY29ycm9tcHVlIHBhciBlcnJldXIuCiAgICBsZXQgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCA9IG51bGw7CgogICAgZnVuY3Rpb24gc2V0Vm9pY2VCYW5uZXIodGV4dCkgewogICAgICBpZiAoIXRleHQpIHsKICAgICAgICB2b2ljZUJhbm5lckVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiYW5zd2VyIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9ICIiOwogICAgICB9IGVsc2UgewogICAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgdm9pY2VCYW5uZXJFbC50ZXh0Q29udGVudCA9IHRleHQ7CiAgICAgIH0KICAgIH0KCiAgICBmdW5jdGlvbiBzZXRWb2ljZUFuc3dlckJhbm5lcih0ZXh0KSB7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgIHZvaWNlQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiYW5zd2VyIik7CiAgICAgIHZvaWNlQmFubmVyRWwudGV4dENvbnRlbnQgPSB0ZXh0OwogICAgfQoKICAgIC8vIFByb25vbmNlIGxhIHLDqXBvbnNlIMOgIHVuZSBxdWVzdGlvbiB2b2NhbGUgKCJBc3Npc3RhbnQgdm9jYWwgcXVlc3Rpb24iKS4KICAgIC8vIFB1ciBib251cyA6IHNpIGxhIHN5bnRow6hzZSB2b2NhbGUgbidlc3QgcGFzIGRpc3BvIG91IMOpY2hvdWUsIGxhIHLDqXBvbnNlCiAgICAvLyByZXN0ZSBhZmZpY2jDqWUgZGFucyBsZSBiYW5kZWF1LCBkb25jIG9uIGF2YWxlIGwnZXJyZXVyIHNhbnMgYmxvcXVlci4KICAgIGZ1bmN0aW9uIHNwZWFrVm9pY2VBbnN3ZXIodGV4dCkgewogICAgICBpZiAoISgic3BlZWNoU3ludGhlc2lzIiBpbiB3aW5kb3cpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgd2luZG93LnNwZWVjaFN5bnRoZXNpcy5jYW5jZWwoKTsKICAgICAgICBjb25zdCB1dHRlcmFuY2UgPSBuZXcgU3BlZWNoU3ludGhlc2lzVXR0ZXJhbmNlKHRleHQpOwogICAgICAgIHV0dGVyYW5jZS5sYW5nID0gImZyLUZSIjsKICAgICAgICB3aW5kb3cuc3BlZWNoU3ludGhlc2lzLnNwZWFrKHV0dGVyYW5jZSk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIC8vIFBhcyBibG9xdWFudC4KICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gQ29uZmlybWF0aW9uIHZvY2FsZSDigJQgcXVhbmQgbCdJQSBhIHVuIGRvdXRlIHN1ciBsJ2ludGVycHLDqXRhdGlvbgogICAgLy8gKG1vbnRhbnQgYXBwcm94aW1hdGlmLCBjYXTDqWdvcmllIGluY2VydGFpbmUuLi4pLCBlbGxlIGRlbWFuZGUKICAgIC8vIGNvbmZpcm1hdGlvbiBhdSBsaWV1IGQnYXBwbGlxdWVyIGRpcmVjdGVtZW50LiBMJ3V0aWxpc2F0ZXVyIHBldXQKICAgIC8vIHLDqXBvbmRyZSBlbiBhcHB1eWFudCBzdXIgIkNvbmZpcm1lciIvIkFubnVsZXIiLCBPVSBlbiByw6ktYXBwdXlhbnQgc3VyCiAgICAvLyBsZSBtaWNybyBwb3VyIHLDqXBvbmRyZSBkZSB2aXZlIHZvaXggKCJvdWkgYydlc3Qgw6dhIiwgIm5vbiwgY2hhbmdlIMOnYQogICAgLy8gZW4gcmVzdGF1cmFudCIuLi4pIOKAlCBkYW5zIGNlIGNhcywgbGEgZGljdMOpZSBzdWl2YW50ZSBlc3QgaW50ZXJwcsOpdMOpZQogICAgLy8gY29tbWUgdW5lIHLDqXBvbnNlIMOgIENFVFRFIGNvbmZpcm1hdGlvbiBwbHV0w7R0IHF1ZSBjb21tZSB1bmUgbm91dmVsbGUKICAgIC8vIHRyYW5zYWN0aW9uICh2b2lyIHBlbmRpbmdWb2ljZUFjdGlvbiwgdsOpcmlmacOpIGRhbnMgbGUgbGlzdGVuZXIKICAgIC8vICJyZXN1bHQiIGRlIGxhIHJlY29ubmFpc3NhbmNlIHZvY2FsZSB1biBwZXUgcGx1cyBiYXMpLgogICAgbGV0IHBlbmRpbmdWb2ljZUFjdGlvbiA9IG51bGw7IC8vIHsga2luZDogInRyYW5zYWN0aW9uIiB8ICJlZGl0X2xhc3QiLCBkYXRhOiB7Li4ufSB9IG91IG51bGwKICAgIGNvbnN0IHZvaWNlQ29uZmlybUJhbm5lckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInZvaWNlLWNvbmZpcm0tYmFubmVyIik7CgogICAgZnVuY3Rpb24gaGlkZVZvaWNlQ29uZmlybUJhbm5lcigpIHsKICAgICAgcGVuZGluZ1ZvaWNlQWN0aW9uID0gbnVsbDsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmlubmVySFRNTCA9ICIiOwogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dWb2ljZUNvbmZpcm1CYW5uZXIoa2luZCwgcGFyc2VkKSB7CiAgICAgIHBlbmRpbmdWb2ljZUFjdGlvbiA9IHsKICAgICAgICBraW5kLAogICAgICAgIGRhdGE6CiAgICAgICAgICBraW5kID09PSAidHJhbnNhY3Rpb24iCiAgICAgICAgICAgID8gcGFyc2VkCiAgICAgICAgICAgIDogewogICAgICAgICAgICAgICAgdGFyZ2V0OiBwYXJzZWQudGFyZ2V0LAogICAgICAgICAgICAgICAgbmV3X3R5cGU6IHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X3R5cGUsCiAgICAgICAgICAgICAgICBuZXdfY2F0ZWdvcnk6IHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5LAogICAgICAgICAgICAgIH0sCiAgICAgIH07CgogICAgICBsZXQgcXVlc3Rpb247CiAgICAgIGlmIChraW5kID09PSAidHJhbnNhY3Rpb24iKSB7CiAgICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgICBjb25zdCBjYXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3BhcnNlZC5jYXRlZ29yeV0gfHwgcGFyc2VkLmNhdGVnb3J5OwogICAgICAgIGNvbnN0IGRlc2NQYXJ0ID0gcGFyc2VkLmRlc2NyaXB0aW9uID8gYCAoJHtwYXJzZWQuZGVzY3JpcHRpb259KWAgOiAiIjsKICAgICAgICBxdWVzdGlvbiA9CiAgICAgICAgICBgJHt2ZXJifSBkZSAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdChwYXJzZWQuYW1vdW50KX0gZW4gJHtjYXRMYWJlbH0ke2Rlc2NQYXJ0fSwgYCArCiAgICAgICAgICBgbGUgJHtkYXRlRm9ybWF0dGVyLmZvcm1hdChuZXcgRGF0ZShwYXJzZWQuZXhwZW5zZV9kYXRlKSl9IOKAlCBjJ2VzdCBiaWVuIMOnYSA/YDsKICAgICAgfSBlbHNlIHsKICAgICAgICAvLyBlZGl0X2xhc3QgOiBvbiByZXRyb3V2ZSBsYSB0cmFuc2FjdGlvbiBjaWJsw6llIGRhbnMgYWxsVHJhbnNhY3Rpb25zCiAgICAgICAgLy8gKGTDqWrDoCB0cmnDqSBwYXIgZGF0ZSBkw6ljcm9pc3NhbnRlKSBwb3VyIGRvbm5lciB1biBjb250ZXh0ZSB1dGlsZS4KICAgICAgICBjb25zdCBjYW5kaWRhdGVzID0gYWxsVHJhbnNhY3Rpb25zLmZpbHRlcigodCkgPT4gewogICAgICAgICAgaWYgKHBhcnNlZC50YXJnZXQgPT09ICJsYXN0X2V4cGVuc2UiKSByZXR1cm4gdC50eXBlID09PSAiZXhwZW5zZSI7CiAgICAgICAgICBpZiAocGFyc2VkLnRhcmdldCA9PT0gImxhc3RfaW5jb21lIikgcmV0dXJuIHQudHlwZSA9PT0gImluY29tZSI7CiAgICAgICAgICByZXR1cm4gdHJ1ZTsKICAgICAgICB9KTsKICAgICAgICBjb25zdCB0YXJnZXQgPSBjYW5kaWRhdGVzWzBdOwogICAgICAgIGNvbnN0IHRhcmdldExhYmVsID0gdGFyZ2V0CiAgICAgICAgICA/IGAke3RhcmdldC50eXBlID09PSAiaW5jb21lIiA/ICJsZSByZXZlbnUiIDogImxhIGTDqXBlbnNlIn0gZGUgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodGFyZ2V0LmFtb3VudCl9YCArCiAgICAgICAgICAgICh0YXJnZXQuZGVzY3JpcHRpb24gPyBgICgke3RhcmdldC5kZXNjcmlwdGlvbn0pYCA6ICIiKQogICAgICAgICAgOiAibGEgdHJhbnNhY3Rpb24gY29ycmVzcG9uZGFudGUiOwogICAgICAgIGNvbnN0IGNoYW5nZXMgPSBbXTsKICAgICAgICBpZiAocGFyc2VkLnJlcXVlc3RlZF9uZXdfdHlwZSkgewogICAgICAgICAgY2hhbmdlcy5wdXNoKGB0eXBlIDogJHtwYXJzZWQucmVxdWVzdGVkX25ld190eXBlID09PSAiaW5jb21lIiA/ICJyZXZlbnUiIDogImTDqXBlbnNlIn1gKTsKICAgICAgICB9CiAgICAgICAgaWYgKHBhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5KSB7CiAgICAgICAgICBjaGFuZ2VzLnB1c2goYGNhdMOpZ29yaWUgOiAke2FsbENhdGVnb3J5TGFiZWxzW3BhcnNlZC5yZXF1ZXN0ZWRfbmV3X2NhdGVnb3J5XSB8fCBwYXJzZWQucmVxdWVzdGVkX25ld19jYXRlZ29yeX1gKTsKICAgICAgICB9CiAgICAgICAgcXVlc3Rpb24gPSBgTW9kaWZpZXIgJHt0YXJnZXRMYWJlbH0g4oCUICR7Y2hhbmdlcy5qb2luKCIsICIpIHx8ICJhdWN1biBjaGFuZ2VtZW50IHJlY29ubnUifSDigJQgYydlc3QgYmllbiDDp2EgP2A7CiAgICAgIH0KCiAgICAgIHZvaWNlQ29uZmlybUJhbm5lckVsLmlubmVySFRNTCA9ICIiOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKCiAgICAgIGNvbnN0IHRleHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJwIik7CiAgICAgIHRleHQudGV4dENvbnRlbnQgPSBxdWVzdGlvbjsKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQodGV4dCk7CgogICAgICBjb25zdCBjb250cm9scyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICBjb250cm9scy5jbGFzc05hbWUgPSAidm9pY2UtY29uZmlybS1jb250cm9scyI7CgogICAgICBjb25zdCBjb25maXJtQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGNvbmZpcm1CdG4udGV4dENvbnRlbnQgPSAi4pyFIENvbmZpcm1lciI7CiAgICAgIGNvbmZpcm1CdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgY29uZmlybUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHN1Ym1pdFZvaWNlQ29uZmlybURlY2lzaW9uKCJjb25maXJtIikpOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChjb25maXJtQnRuKTsKCiAgICAgIGNvbnN0IGNhbmNlbEJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICBjYW5jZWxCdG4udGV4dENvbnRlbnQgPSAi4p2MIEFubnVsZXIiOwogICAgICBjYW5jZWxCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBjYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbigiY2FuY2VsIikpOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChjYW5jZWxCdG4pOwoKICAgICAgdm9pY2VDb25maXJtQmFubmVyRWwuYXBwZW5kQ2hpbGQoY29udHJvbHMpOwoKICAgICAgY29uc3QgaGludCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInAiKTsKICAgICAgaGludC5jbGFzc05hbWUgPSAidm9pY2UtY29uZmlybS1oaW50IjsKICAgICAgaGludC50ZXh0Q29udGVudCA9ICLwn46kIFR1IHBldXggYXVzc2kgcsOpcG9uZHJlIMOgIGxhIHZvaXggZW4gcsOpLWFwcHV5YW50IHN1ciBsZSBtaWNyby4iOwogICAgICB2b2ljZUNvbmZpcm1CYW5uZXJFbC5hcHBlbmRDaGlsZChoaW50KTsKICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBzdWJtaXRWb2ljZUNvbmZpcm1EZWNpc2lvbihkZWNpc2lvbikgewogICAgICBpZiAoIXBlbmRpbmdWb2ljZUFjdGlvbikgcmV0dXJuOwogICAgICBjb25zdCB7IGtpbmQsIGRhdGEgfSA9IHBlbmRpbmdWb2ljZUFjdGlvbjsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS92b2ljZS9jb25maXJtIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGRlY2lzaW9uLCBraW5kLCBwZW5kaW5nOiBkYXRhIH0pLAogICAgICAgIH0pOwogICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlQ29uZmlybVJlc3VsdChyZXN1bHQpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0KICAgIH0KCiAgICBhc3luYyBmdW5jdGlvbiBoYW5kbGVWb2ljZUNvbmZpcm1SZXN1bHQocmVzdWx0KSB7CiAgICAgIGhpZGVWb2ljZUNvbmZpcm1CYW5uZXIoKTsKICAgICAgaWYgKHJlc3VsdC5kZWNpc2lvbiA9PT0gImNhbmNlbCIpIHsKICAgICAgICBzaG93VG9hc3QoIkFubnVsw6kiKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KICAgICAgLy8gU2lub24sIHJlc3VsdCBlc3QgdW4gcsOpc3VsdGF0IGTDqWrDoCBmaW5hbGlzw6kgKFZvaWNlUGFyc2VSZXN1bHQgcG91cgogICAgICAvLyB1bmUgdHJhbnNhY3Rpb24sIFZvaWNlRWRpdFJlc3VsdCBwb3VyIHVuIGVkaXRfbGFzdCkgOiBvbiBsZSB0cmFpdGUKICAgICAgLy8gZXhhY3RlbWVudCBjb21tZSB1biByw6lzdWx0YXQgZGUgZGljdMOpZSBub3JtYWwuCiAgICAgIGF3YWl0IGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocmVzdWx0KTsKICAgIH0KCiAgICAvLyBQb2ludCBkJ2VudHLDqWUgY29tbXVuIHBvdXIgbGUgcsOpc3VsdGF0IGQndW5lIGRpY3TDqWUgImZyYcOuY2hlIiAoZW52b3nDqWUKICAgIC8vIMOgIC9hcGkvdm9pY2UvcGFyc2UpIEVUIHBvdXIgbGUgcsOpc3VsdGF0IGTDqWrDoCBmaW5hbGlzw6kgZCd1bmUKICAgIC8vIGNvbmZpcm1hdGlvbiDigJQgbGVzIGRldXggY2hlbWlucyByZXRvbWJlbnQgc3VyIGxlIG3Dqm1lIHRyYWl0ZW1lbnQgdW5lCiAgICAvLyBmb2lzIHF1J29uIHNhaXQgcXUnaWwgbid5IGEgcGx1cyBkZSBkb3V0ZSDDoCBsZXZlci4KICAgIGFzeW5jIGZ1bmN0aW9uIGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocGFyc2VkKSB7CiAgICAgIGlmIChwYXJzZWQuaW50ZW50ID09PSAicXVlc3Rpb24iKSB7CiAgICAgICAgc2V0Vm9pY2VBbnN3ZXJCYW5uZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgc3BlYWtWb2ljZUFuc3dlcihwYXJzZWQuYW5zd2VyKTsKICAgICAgfSBlbHNlIGlmIChwYXJzZWQuaW50ZW50ID09PSAiZWRpdF9sYXN0IikgewogICAgICAgIGlmIChwYXJzZWQucGVuZGluZykgewogICAgICAgICAgc2hvd1ZvaWNlQ29uZmlybUJhbm5lcigiZWRpdF9sYXN0IiwgcGFyc2VkKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgc2V0Vm9pY2VBbnN3ZXJCYW5uZXIocGFyc2VkLmFuc3dlcik7CiAgICAgICAgICBzcGVha1ZvaWNlQW5zd2VyKHBhcnNlZC5hbnN3ZXIpOwogICAgICAgICAgYXdhaXQgbG9hZFRyYW5zYWN0aW9ucygpOwogICAgICAgIH0KICAgICAgfSBlbHNlIGlmIChwYXJzZWQubmVlZHNfY29uZmlybWF0aW9uKSB7CiAgICAgICAgc2hvd1ZvaWNlQ29uZmlybUJhbm5lcigidHJhbnNhY3Rpb24iLCBwYXJzZWQpOwogICAgICB9IGVsc2UgewogICAgICAgIGF3YWl0IGFwcGx5Vm9pY2VSZXN1bHQocGFyc2VkKTsKICAgICAgfQogICAgfQoKICAgIGNvbnN0IFNwZWVjaFJlY29nbml0aW9uQ3RvciA9IHdpbmRvdy5TcGVlY2hSZWNvZ25pdGlvbiB8fCB3aW5kb3cud2Via2l0U3BlZWNoUmVjb2duaXRpb247CgogICAgaWYgKCFTcGVlY2hSZWNvZ25pdGlvbkN0b3IpIHsKICAgICAgbWljQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgbWljQnRuLnRpdGxlID0gIkRpY3TDqWUgdm9jYWxlIG5vbiBkaXNwb25pYmxlIHN1ciBjZSBuYXZpZ2F0ZXVyICh1dGlsaXNlIENocm9tZSBvdSBFZGdlKSI7CiAgICB9IGVsc2UgewogICAgICBjb25zdCByZWNvZ25pdGlvbiA9IG5ldyBTcGVlY2hSZWNvZ25pdGlvbkN0b3IoKTsKICAgICAgcmVjb2duaXRpb24ubGFuZyA9ICJmci1GUiI7CiAgICAgIHJlY29nbml0aW9uLmNvbnRpbnVvdXMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24uaW50ZXJpbVJlc3VsdHMgPSBmYWxzZTsKICAgICAgcmVjb2duaXRpb24ubWF4QWx0ZXJuYXRpdmVzID0gMTsKCiAgICAgIGxldCBpc0xpc3RlbmluZyA9IGZhbHNlOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigic3RhcnQiLCAoKSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSB0cnVlOwogICAgICAgIG1pY0J0bi5jbGFzc0xpc3QuYWRkKCJsaXN0ZW5pbmciKTsKICAgICAgICBzZXRWb2ljZUJhbm5lcigiSmUgdCfDqWNvdXRl4oCmIik7CiAgICAgIH0pOwoKICAgICAgcmVjb2duaXRpb24uYWRkRXZlbnRMaXN0ZW5lcigiZW5kIiwgKCkgPT4gewogICAgICAgIGlzTGlzdGVuaW5nID0gZmFsc2U7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoImxpc3RlbmluZyIpOwogICAgICB9KTsKCiAgICAgIHJlY29nbml0aW9uLmFkZEV2ZW50TGlzdGVuZXIoImVycm9yIiwgKGV2ZW50KSA9PiB7CiAgICAgICAgaXNMaXN0ZW5pbmcgPSBmYWxzZTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LnJlbW92ZSgibGlzdGVuaW5nIik7CiAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICBpZiAoZXZlbnQuZXJyb3IgPT09ICJuby1zcGVlY2giKSB7CiAgICAgICAgICBzZXRWb2ljZUJhbm5lcigiUmllbiBlbnRlbmR1LCByw6llc3NhaWUuIik7CiAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHNldFZvaWNlQmFubmVyKG51bGwpLCAyMDAwKTsKICAgICAgICB9IGVsc2UgaWYgKGV2ZW50LmVycm9yID09PSAibm90LWFsbG93ZWQiIHx8IGV2ZW50LmVycm9yID09PSAic2VydmljZS1ub3QtYWxsb3dlZCIpIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKCJNaWNybyByZWZ1c8OpIOKAlCBhdXRvcmlzZSBsJ2FjY8OocyBhdSBtaWNybyBkYW5zIHRvbiBuYXZpZ2F0ZXVyLiIpOwogICAgICAgICAgc2V0VGltZW91dCgoKSA9PiBzZXRWb2ljZUJhbm5lcihudWxsKSwgNDAwMCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIHNldFZvaWNlQmFubmVyKG51bGwpOwogICAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgbWljcm8gOiAiICsgZXZlbnQuZXJyb3IsIHRydWUpOwogICAgICAgIH0KICAgICAgfSk7CgogICAgICByZWNvZ25pdGlvbi5hZGRFdmVudExpc3RlbmVyKCJyZXN1bHQiLCBhc3luYyAoZXZlbnQpID0+IHsKICAgICAgICBjb25zdCB0cmFuc2NyaXB0ID0gZXZlbnQucmVzdWx0c1swXVswXS50cmFuc2NyaXB0OwogICAgICAgIHNldFZvaWNlQmFubmVyKGAiJHt0cmFuc2NyaXB0fSJgKTsKICAgICAgICBtaWNCdG4uY2xhc3NMaXN0LmFkZCgicHJvY2Vzc2luZyIpOwogICAgICAgIGxldCBiYW5uZXJEZWxheSA9IDE1MDA7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGlmIChwZW5kaW5nVm9pY2VBY3Rpb24pIHsKICAgICAgICAgICAgLy8gVW5lIGJhbm5pw6hyZSBkZSBjb25maXJtYXRpb24gZXN0IGFmZmljaMOpZSA6IGNldHRlIGRpY3TDqWUgZXN0CiAgICAgICAgICAgIC8vIHVuZSByw6lwb25zZSAoIm91aSIsICJub24iLCAiY2hhbmdlIMOnYSBlbi4uLiIpIMOgIENFVFRFCiAgICAgICAgICAgIC8vIGNvbmZpcm1hdGlvbiwgcGFzIHVuZSBub3V2ZWxsZSB0cmFuc2FjdGlvbi4KICAgICAgICAgICAgY29uc3QgeyBraW5kLCBkYXRhIH0gPSBwZW5kaW5nVm9pY2VBY3Rpb247CiAgICAgICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL2NvbmZpcm0iLCB7CiAgICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyByZXBseV90ZXh0OiB0cmFuc2NyaXB0LCBraW5kLCBwZW5kaW5nOiBkYXRhIH0pLAogICAgICAgICAgICB9KTsKICAgICAgICAgICAgYXdhaXQgaGFuZGxlVm9pY2VDb25maXJtUmVzdWx0KHJlc3VsdCk7CiAgICAgICAgICAgIGJhbm5lckRlbGF5ID0gNDAwMDsKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3ZvaWNlL3BhcnNlIiwgewogICAgICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdGV4dDogdHJhbnNjcmlwdCB9KSwKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGlmIChwYXJzZWQuaW50ZW50ID09PSAicXVlc3Rpb24iKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSA2MDAwOwogICAgICAgICAgICB9IGVsc2UgaWYgKHBhcnNlZC5uZWVkc19jb25maXJtYXRpb24gfHwgcGFyc2VkLnBlbmRpbmcpIHsKICAgICAgICAgICAgICBiYW5uZXJEZWxheSA9IDE1MDA7IC8vIGxhIGJhbm5pw6hyZSBkZSBjb25maXJtYXRpb24gcHJlbmQgbGUgcmVsYWlzIHZpc3VlbGxlbWVudAogICAgICAgICAgICB9IGVsc2UgaWYgKHBhcnNlZC5pbnRlbnQgPT09ICJlZGl0X2xhc3QiKSB7CiAgICAgICAgICAgICAgYmFubmVyRGVsYXkgPSA0MDAwOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGF3YWl0IGhhbmRsZVZvaWNlUGFyc2VSZXN1bHQocGFyc2VkKTsKICAgICAgICAgIH0KICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgICB9IGZpbmFsbHkgewogICAgICAgICAgbWljQnRuLmNsYXNzTGlzdC5yZW1vdmUoInByb2Nlc3NpbmciKTsKICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gc2V0Vm9pY2VCYW5uZXIobnVsbCksIGJhbm5lckRlbGF5KTsKICAgICAgICB9CiAgICAgIH0pOwoKICAgICAgbWljQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGlmIChpc0xpc3RlbmluZykgewogICAgICAgICAgcmVjb2duaXRpb24uc3RvcCgpOwogICAgICAgICAgcmV0dXJuOwogICAgICAgIH0KICAgICAgICB0cnkgewogICAgICAgICAgcmVjb2duaXRpb24uc3RhcnQoKTsKICAgICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAgIC8vIHN0YXJ0KCkgamV0dGUgc2kgZMOpasOgIGTDqW1hcnLDqSA7IG9uIGlnbm9yZS4KICAgICAgICB9CiAgICAgIH0pOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFN1Z2dlc3Rpb25zIGRlIGNhdMOpZ29yaWUg4oCUIHVuaXF1ZW1lbnQgYXByw6hzIHVuZSBzYWlzaWUgcGFyIGRpY3TDqWUKICAgIC8vIHZvY2FsZSAodW5lIGZhdXRlIGRlIGZyYXBwZSBlbiBzYWlzaWUgbWFudWVsbGUsIGMnZXN0IHVuZSBlcnJldXIgZGUKICAgIC8vIGwndXRpbGlzYXRldXIsIHBhcyBsYSBwZWluZSBkZSBsZSByZWxhbmNlciBkZXNzdXMpLgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgY29uc3QgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQgPSAzOwoKICAgIC8vIE1vdHMgZGUgbGlhaXNvbiBmcmFuw6dhaXMgw6AgaWdub3JlciA6ICJjYXNpbm8iLCAiYXUgY2FzaW5vIiBldCAicGVydGUgYXUKICAgIC8vIGNhc2lubyIgZG9pdmVudCDDqnRyZSByZWNvbm51cyBjb21tZSBsYSBtw6ptZSBpZMOpZSBtYWxncsOpIGxlcyBtb3RzCiAgICAvLyBkaWZmw6lyZW50cyBhdXRvdXIsIGRvbmMgb24gY29tcGFyZSBkZXMgbW90cy1jbMOpcyBzaWduaWZpY2F0aWZzIHBsdXTDtHQKICAgIC8vIHF1ZSBsYSBkZXNjcmlwdGlvbiBjb21wbMOodGUgdGVsbGUgcXVlbGxlLgogICAgY29uc3QgREVTQ1JJUFRJT05fU1RPUFdPUkRTID0gbmV3IFNldChbCiAgICAgICJhIiwgImF1IiwgImF1eCIsICJkZSIsICJkdSIsICJkZXMiLCAiZCIsICJsZSIsICJsYSIsICJsZXMiLCAibCIsCiAgICAgICJ1biIsICJ1bmUiLCAiY2UiLCAiY2V0IiwgImNldHRlIiwgImNlcyIsICJtb24iLCAibWEiLCAibWVzIiwKICAgICAgInRvbiIsICJ0YSIsICJ0ZXMiLCAic29uIiwgInNhIiwgInNlcyIsICJub3RyZSIsICJub3MiLCAidm90cmUiLAogICAgICAidm9zIiwgImxldXIiLCAibGV1cnMiLCAiY2hleiIsICJzdXIiLCAiZGFucyIsICJwb3VyIiwgImF2ZWMiLAogICAgICAiZXQiLCAib3UiLCAiZW4iLCAicGFyIiwKICAgIF0pOwoKICAgIC8vIEV4dHJhaXQgbGVzIG1vdHMtY2zDqXMgc2lnbmlmaWNhdGlmcyBkJ3VuZSBkZXNjcmlwdGlvbiAoYWNjZW50cyBldAogICAgLy8gY2Fzc2UgaWdub3LDqXMsIG1vdHMgZGUgbGlhaXNvbiBldCBtb3RzIHRyb3AgY291cnRzIMOpY2FydMOpcykuCiAgICBmdW5jdGlvbiBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhkZXNjKSB7CiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSAoZGVzYyB8fCAiIikKICAgICAgICAubm9ybWFsaXplKCJORkQiKQogICAgICAgIC5yZXBsYWNlKC9bzIAtza9dL2csICIiKSAvLyByZXRpcmUgbGVzIGFjY2VudHMgKMOpIC0+IGUsIGV0Yy4pCiAgICAgICAgLnRvTG93ZXJDYXNlKCk7CiAgICAgIGNvbnN0IHRva2VucyA9IG5vcm1hbGl6ZWQuc3BsaXQoL1teYS16MC05XSsvKS5maWx0ZXIoQm9vbGVhbik7CiAgICAgIHJldHVybiBuZXcgU2V0KAogICAgICAgIHRva2Vucy5maWx0ZXIoKHQpID0+IHQubGVuZ3RoID49IDMgJiYgIURFU0NSSVBUSU9OX1NUT1BXT1JEUy5oYXModCkpCiAgICAgICk7CiAgICB9CgogICAgZnVuY3Rpb24ga2V5d29yZHNJbnRlcnNlY3QoYSwgYikgewogICAgICBmb3IgKGNvbnN0IHRva2VuIG9mIGEpIHsKICAgICAgICBpZiAoYi5oYXModG9rZW4pKSByZXR1cm4gdHJ1ZTsKICAgICAgfQogICAgICByZXR1cm4gZmFsc2U7CiAgICB9CgogICAgLy8gUmV0aXJlIGQndW5lIGRlc2NyaXB0aW9uIGxlcyBtb3RzIHF1aSBvbnQgc2Vydmkgw6AgZMOpdGVjdGVyIGxhCiAgICAvLyBjYXTDqWdvcmllIChleC4gImNhc2lubyIgdW5lIGZvaXMgcXVlIGxhIGNhdMOpZ29yaWUgImNhc2lubyIgZXhpc3RlKSA6CiAgICAvLyB1bmUgZm9pcyBxdWUgbGEgY2F0w6lnb3JpZSBwb3J0ZSBsJ2luZm9ybWF0aW9uLCBsYSByw6lww6l0ZXIgZGFucyBsYQogICAgLy8gZGVzY3JpcHRpb24gbidhcHBvcnRlIHBsdXMgcmllbi4gUmVudm9pZSBudWxsIHNpIGxhIGRlc2NyaXB0aW9uCiAgICAvLyBkZXZpZW50IHZpZGUgdW5lIGZvaXMgY2VzIG1vdHMgcmV0aXLDqXMuCiAgICBmdW5jdGlvbiBzdHJpcE1hdGNoZWRLZXl3b3Jkc0Zyb21EZXNjcmlwdGlvbihkZXNjcmlwdGlvbiwga2V5d29yZHMpIHsKICAgICAgaWYgKCFkZXNjcmlwdGlvbiB8fCAha2V5d29yZHMgfHwga2V5d29yZHMuc2l6ZSA9PT0gMCkgcmV0dXJuIGRlc2NyaXB0aW9uIHx8IG51bGw7CiAgICAgIGNvbnN0IHdvcmRzID0gZGVzY3JpcHRpb24uc3BsaXQoL1xzKy8pLmZpbHRlcihCb29sZWFuKTsKICAgICAgY29uc3Qga2VwdCA9IHdvcmRzLmZpbHRlcigodykgPT4gewogICAgICAgIGNvbnN0IG5vcm0gPSB3CiAgICAgICAgICAubm9ybWFsaXplKCJORkQiKQogICAgICAgICAgLnJlcGxhY2UoL1vMgC3Nr10vZywgIiIpCiAgICAgICAgICAudG9Mb3dlckNhc2UoKQogICAgICAgICAgLnJlcGxhY2UoL1teYS16MC05XS9nLCAiIik7CiAgICAgICAgcmV0dXJuICFrZXl3b3Jkcy5oYXMobm9ybSk7CiAgICAgIH0pOwogICAgICBjb25zdCBjbGVhbmVkID0ga2VwdC5qb2luKCIgIikudHJpbSgpOwogICAgICByZXR1cm4gY2xlYW5lZCB8fCBudWxsOwogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGRpc21pc3NTdWdnZXN0aW9uKGtleSkgewogICAgICBkaXNtaXNzZWRTdWdnZXN0aW9uS2V5cy5hZGQoa2V5KTsgLy8gaW1tw6lkaWF0IGPDtHTDqSBVSSwgcGFzIGJlc29pbiBkJ2F0dGVuZHJlIGxlIHNlcnZldXIKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9kaXNtaXNzZWQtc3VnZ2VzdGlvbnMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsga2V5IH0pLAogICAgICAgIH0pOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICAvLyBQYXMgYmxvcXVhbnQgOiBhdSBwaXJlIGxhIHN1Z2dlc3Rpb24gcsOpYXBwYXJhw650IHVuZSBmb2lzIHN1ciB1bgogICAgICAgIC8vIGF1dHJlIGFwcGFyZWlsIHNpIGxhIHNhdXZlZ2FyZGUgc2VydmV1ciBhIMOpY2hvdcOpLgogICAgICB9CiAgICB9CgogICAgLy8gUmVnYXJkZSBzaSBsYSBkZXNjcmlwdGlvbiBkZSBsYSB0cmFuc2FjdGlvbiBxdWkgdmllbnQgZCfDqnRyZSBham91dMOpZQogICAgLy8gKG91IGNvcnJpZ8OpZSkgw6AgbGEgdm9peCByZXZpZW50IHNvdXZlbnQsIGV0IHNpIG91aSA6CiAgICAvLyAtIHNvaXQgZWxsZSBhIHRvdWpvdXJzIMOpdMOpIHJhbmfDqWUgZGFucyAiQXV0cmUiIOKGkiBvbiBwcm9wb3NlIGRlIGNyw6llcgogICAgLy8gICB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgZGUgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgOwogICAgLy8gLSBzb2l0IGVsbGUgYSBjZXR0ZSBmb2lzIHVuZSBjYXTDqWdvcmllIGRpZmbDqXJlbnRlIGRlIGQnaGFiaXR1ZGUg4oaSIG9uCiAgICAvLyAgIGRlbWFuZGUgc2kgY2Ugbidlc3QgcGFzIHVuZSBlcnJldXIgOwogICAgLy8gLSBzb2l0IGxhIHRyYW5zYWN0aW9uIHF1aSB2aWVudCBkJ8OqdHJlIGFqb3V0w6llIGVzdCBkw6lqw6AgYmllbiBjbGFzc8OpZSwKICAgIC8vICAgbWFpcyBkJ2FuY2llbm5lcyB0cmFuc2FjdGlvbnMgc2ltaWxhaXJlcyB0cmHDrm5lbnQgZGFucyB1bmUgYXV0cmUKICAgIC8vICAgY2F0w6lnb3JpZSAoZXguICJwZXJ0ZSBhdSBjYXNpbm8iIGNsYXNzw6llIGVuICJMb2lzaXJzIiBhdmFudCBxdWUKICAgIC8vICAgImNhc2lubyIgZXhpc3RlIGNvbW1lIGNhdMOpZ29yaWUpIOKGkiBvbiBwcm9wb3NlIGRlIGxlcyBhbGlnbmVyLgogICAgZnVuY3Rpb24gY2hlY2tDYXRlZ29yeVN1Z2dlc3Rpb24oZGVzY3JpcHRpb24sIHR5cGUpIHsKICAgICAgY29uc3Qga2V5d29yZHMgPSBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3JkcyhkZXNjcmlwdGlvbik7CiAgICAgIGlmIChrZXl3b3Jkcy5zaXplID09PSAwKSByZXR1cm47CgogICAgICBjb25zdCBzYW1lRGVzY3JpcHRpb24gPSBhbGxUcmFuc2FjdGlvbnMuZmlsdGVyKAogICAgICAgICh0eCkgPT4KICAgICAgICAgIHR4LnR5cGUgPT09IHR5cGUgJiYKICAgICAgICAgIGtleXdvcmRzSW50ZXJzZWN0KGtleXdvcmRzLCBleHRyYWN0RGVzY3JpcHRpb25LZXl3b3Jkcyh0eC5kZXNjcmlwdGlvbikpCiAgICAgICk7CiAgICAgIGlmIChzYW1lRGVzY3JpcHRpb24ubGVuZ3RoIDwgQ0FURUdPUllfU1VHR0VTVElPTl9USFJFU0hPTEQpIHJldHVybjsKCiAgICAgIGNvbnN0IGNvdW50cyA9IHt9OwogICAgICBmb3IgKGNvbnN0IHR4IG9mIHNhbWVEZXNjcmlwdGlvbikgY291bnRzW3R4LmNhdGVnb3J5XSA9IChjb3VudHNbdHguY2F0ZWdvcnldIHx8IDApICsgMTsKICAgICAgY29uc3QgY2F0ZWdvcmllcyA9IE9iamVjdC5rZXlzKGNvdW50cyk7CiAgICAgIGNvbnN0IGRvbWluYW50ID0gY2F0ZWdvcmllcy5yZWR1Y2UoKGEsIGIpID0+IChjb3VudHNbYV0gPj0gY291bnRzW2JdID8gYSA6IGIpKTsKICAgICAgY29uc3QgbGF0ZXN0ID0gc2FtZURlc2NyaXB0aW9uWzBdOyAvLyBhbGxUcmFuc2FjdGlvbnMgZXN0IHRyacOpIHBhciBkYXRlIGTDqWNyb2lzc2FudGUKCiAgICAgIC8vIENsw6kgc3RhYmxlIGJhc8OpZSBzdXIgbGVzIG1vdHMtY2zDqXMgKHRyacOpcykgcGx1dMO0dCBxdWUgbGEgZGVzY3JpcHRpb24KICAgICAgLy8gZXhhY3RlLCBwb3VyIHF1ZSBsZSAiSWdub3JlciIgcmVzdGUgdmFsYWJsZSBtw6ptZSBzaSBsYSBmb3JtdWxhdGlvbgogICAgICAvLyB2YXJpZSB1biBwZXUgZCd1bmUgZm9pcyDDoCBsJ2F1dHJlLgogICAgICBjb25zdCBzaWduYXR1cmUgPSBbLi4ua2V5d29yZHNdLnNvcnQoKS5qb2luKCIrIik7CgogICAgICBsZXQgc3VnZ2VzdGlvbiA9IG51bGw7CiAgICAgIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ICE9PSBkb21pbmFudCkgewogICAgICAgIHN1Z2dlc3Rpb24gPSB7CiAgICAgICAgICBrZXk6IGBtaXNtYXRjaDoke3R5cGV9OiR7c2lnbmF0dXJlfToke2xhdGVzdC5jYXRlZ29yeX1gLAogICAgICAgICAga2luZDogIm1pc21hdGNoIiwKICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICB0eXBlLAogICAgICAgICAgZG9taW5hbnQsCiAgICAgICAgICBjdXJyZW50OiBsYXRlc3QuY2F0ZWdvcnksCiAgICAgICAgICBrZXl3b3JkcywKICAgICAgICAgIHR4SWRzOiBzYW1lRGVzY3JpcHRpb24uZmlsdGVyKCh0eCkgPT4gdHguY2F0ZWdvcnkgPT09IGxhdGVzdC5jYXRlZ29yeSkubWFwKCh0eCkgPT4gdHguaWQpLAogICAgICAgIH07CiAgICAgIH0gZWxzZSBpZiAoY2F0ZWdvcmllcy5sZW5ndGggPT09IDEgJiYgZG9taW5hbnQgPT09ICJhdXRyZSIpIHsKICAgICAgICBzdWdnZXN0aW9uID0gewogICAgICAgICAga2V5OiBgZ2VuZXJpYzoke3R5cGV9OiR7c2lnbmF0dXJlfWAsCiAgICAgICAgICBraW5kOiAiZ2VuZXJpYyIsCiAgICAgICAgICBkZXNjcmlwdGlvbjogbGF0ZXN0LmRlc2NyaXB0aW9uLAogICAgICAgICAgdHlwZSwKICAgICAgICAgIGtleXdvcmRzLAogICAgICAgICAgdHhJZHM6IHNhbWVEZXNjcmlwdGlvbi5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgfTsKICAgICAgfSBlbHNlIGlmIChjYXRlZ29yaWVzLmxlbmd0aCA+IDEgJiYgbGF0ZXN0LmNhdGVnb3J5ID09PSBkb21pbmFudCkgewogICAgICAgIC8vIExhIHRyYW5zYWN0aW9uIGxhIHBsdXMgcsOpY2VudGUgZXN0IGTDqWrDoCBiaWVuIGNsYXNzw6llLCBtYWlzCiAgICAgICAgLy8gZCdhdXRyZXMgdHJhbnNhY3Rpb25zIHNpbWlsYWlyZXMgc29udCByZXN0w6llcyBkYW5zIHVuZSBjYXTDqWdvcmllCiAgICAgICAgLy8gbWlub3JpdGFpcmUgKHR5cGlxdWVtZW50IHBsdXMgYW5jaWVubmVzLCBjbGFzc8OpZXMgYXZhbnQgcXVlIGxhCiAgICAgICAgLy8gY2F0w6lnb3JpZSBkb21pbmFudGUgYWN0dWVsbGUgbidleGlzdGUpIDogb24gcHJvcG9zZSBkZSBsZXMgYWxpZ25lci4KICAgICAgICBjb25zdCBvdXRsaWVycyA9IHNhbWVEZXNjcmlwdGlvbi5maWx0ZXIoKHR4KSA9PiB0eC5jYXRlZ29yeSAhPT0gZG9taW5hbnQpOwogICAgICAgIGlmIChvdXRsaWVycy5sZW5ndGggPiAwKSB7CiAgICAgICAgICBjb25zdCBvdXRsaWVyQ2F0ZWdvcmllcyA9IFsuLi5uZXcgU2V0KG91dGxpZXJzLm1hcCgodHgpID0+IHR4LmNhdGVnb3J5KSldOwogICAgICAgICAgc3VnZ2VzdGlvbiA9IHsKICAgICAgICAgICAga2V5OiBgcmVjb25jaWxlOiR7dHlwZX06JHtzaWduYXR1cmV9OiR7ZG9taW5hbnR9YCwKICAgICAgICAgICAga2luZDogInJlY29uY2lsZSIsCiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBsYXRlc3QuZGVzY3JpcHRpb24sCiAgICAgICAgICAgIHR5cGUsCiAgICAgICAgICAgIGRvbWluYW50LAogICAgICAgICAgICBvdXRsaWVyQ2F0ZWdvcmllcywKICAgICAgICAgICAga2V5d29yZHMsCiAgICAgICAgICAgIHR4SWRzOiBvdXRsaWVycy5tYXAoKHR4KSA9PiB0eC5pZCksCiAgICAgICAgICB9OwogICAgICAgIH0KICAgICAgfQoKICAgICAgaWYgKCFzdWdnZXN0aW9uIHx8IGRpc21pc3NlZFN1Z2dlc3Rpb25LZXlzLmhhcyhzdWdnZXN0aW9uLmtleSkpIHJldHVybjsKICAgICAgc2hvd0NhdGVnb3J5U3VnZ2VzdGlvbkJhbm5lcihzdWdnZXN0aW9uKTsKICAgIH0KCiAgICBmdW5jdGlvbiBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCkgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgZWwuaW5uZXJIVE1MID0gIiI7CiAgICB9CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgdGFyZ2V0VmFsdWUsIHRhcmdldExhYmVsKSB7CiAgICAgIGxldCBpZHNUb0ZpeDsKICAgICAgaWYgKHN1Z2dlc3Rpb24ua2luZCA9PT0gInJlY29uY2lsZSIpIHsKICAgICAgICAvLyBJY2kgc3VnZ2VzdGlvbi50eElkcyBlc3QgZMOpasOgIGV4YWN0ZW1lbnQgbCdlbnNlbWJsZSBkZXMgYW5jaWVubmVzCiAgICAgICAgLy8gdHJhbnNhY3Rpb25zIMOgIGFsaWduZXIgKHBhcyBkZSAiZGVybmnDqHJlIHRyYW5zYWN0aW9uIiDDoCBwYXJ0KSA6IGxlCiAgICAgICAgLy8gdGV4dGUgZGUgbGEgYmFubmnDqHJlIGwnYW5ub25jZSBkw6lqw6AsIHBhcyBiZXNvaW4gZCd1bmUgY29uZmlybWF0aW9uCiAgICAgICAgLy8gc3VwcGzDqW1lbnRhaXJlLgogICAgICAgIGlkc1RvRml4ID0gc3VnZ2VzdGlvbi50eElkczsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBbbGF0ZXN0SWQsIC4uLm90aGVyc10gPSBzdWdnZXN0aW9uLnR4SWRzOwogICAgICAgIGlkc1RvRml4ID0gW2xhdGVzdElkXTsKICAgICAgICBpZiAoCiAgICAgICAgICBvdGhlcnMubGVuZ3RoID4gMCAmJgogICAgICAgICAgKGF3YWl0IHNob3dDb25maXJtKGBDb3JyaWdlciBhdXNzaSBsZXMgJHtvdGhlcnMubGVuZ3RofSB0cmFuc2FjdGlvbihzKSBwcsOpY8OpZGVudGUocykgYXZlYyBsYSBtw6ptZSBkZXNjcmlwdGlvbiA/YCkpCiAgICAgICAgKSB7CiAgICAgICAgICBpZHNUb0ZpeC5wdXNoKC4uLm90aGVycyk7CiAgICAgICAgfQogICAgICB9CgogICAgICB0cnkgewogICAgICAgIGZvciAoY29uc3QgaWQgb2YgaWRzVG9GaXgpIHsKICAgICAgICAgIGNvbnN0IHBheWxvYWQgPSB7IGNhdGVnb3J5OiB0YXJnZXRWYWx1ZSB9OwogICAgICAgICAgLy8gTGEgY2F0w6lnb3JpZSBwb3J0ZSBtYWludGVuYW50IGwnaW5mb3JtYXRpb24gOiBvbiByZXRpcmUgZGVzCiAgICAgICAgICAvLyBkZXNjcmlwdGlvbnMgbGUocykgbW90KHMpLWNsw6kocykgcXVpIG9udCBzZXJ2aSDDoCBsYSBkw6l0ZWN0ZXIsCiAgICAgICAgICAvLyBwb3VyIMOpdml0ZXIgbGEgcmVkb25kYW5jZSAiY2FzaW5vIiBlbiBjYXTDqWdvcmllIEVUIGVuIG5vdGUuCiAgICAgICAgICBjb25zdCB0eCA9IGFsbFRyYW5zYWN0aW9ucy5maW5kKCh0KSA9PiB0LmlkID09PSBpZCk7CiAgICAgICAgICBpZiAodHggJiYgc3VnZ2VzdGlvbi5rZXl3b3JkcykgewogICAgICAgICAgICBjb25zdCBjbGVhbmVkID0gc3RyaXBNYXRjaGVkS2V5d29yZHNGcm9tRGVzY3JpcHRpb24odHguZGVzY3JpcHRpb24sIHN1Z2dlc3Rpb24ua2V5d29yZHMpOwogICAgICAgICAgICBpZiAoY2xlYW5lZCAhPT0gKHR4LmRlc2NyaXB0aW9uIHx8IG51bGwpKSBwYXlsb2FkLmRlc2NyaXB0aW9uID0gY2xlYW5lZDsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2lkfWAsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgc2hvd1RvYXN0KGBDYXTDqWdvcmllIG1pc2Ugw6Agam91ciA6ICR7dGFyZ2V0TGFiZWx9YCk7CiAgICAgICAgZGlzbWlzc1N1Z2dlc3Rpb24oc3VnZ2VzdGlvbi5rZXkpOwogICAgICAgIGhpZGVDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHNob3dDYXRlZ29yeVN1Z2dlc3Rpb25CYW5uZXIoc3VnZ2VzdGlvbikgewogICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjYXRlZ29yeS1zdWdnZXN0aW9uLWJhbm5lciIpOwogICAgICBlbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CgogICAgICBjb25zdCBkZXNjTGFiZWwgPSBzdWdnZXN0aW9uLmRlc2NyaXB0aW9uIHx8ICIoc2FucyBkZXNjcmlwdGlvbikiOwogICAgICBjb25zdCB0ZXh0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgicCIpOwogICAgICBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAiZ2VuZXJpYyIpIHsKICAgICAgICB0ZXh0LnRleHRDb250ZW50ID0KICAgICAgICAgIGBUdSBhcyB1dGlsaXPDqSAiJHtkZXNjTGFiZWx9IiAke3N1Z2dlc3Rpb24udHhJZHMubGVuZ3RofSBmb2lzLCB0b3Vqb3VycyBjbGFzc8OpIGVuIGAgKwogICAgICAgICAgYCJBdXRyZSIuIENyw6llciB1bmUgY2F0w6lnb3JpZSBkw6lkacOpZSAob3UgbGEgcmF0dGFjaGVyIMOgIHVuZSBjYXTDqWdvcmllIGV4aXN0YW50ZSkgP2A7CiAgICAgIH0gZWxzZSBpZiAoc3VnZ2VzdGlvbi5raW5kID09PSAicmVjb25jaWxlIikgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IG91dGxpZXJMYWJlbHMgPSBzdWdnZXN0aW9uLm91dGxpZXJDYXRlZ29yaWVzCiAgICAgICAgICAubWFwKChjKSA9PiBhbGxDYXRlZ29yeUxhYmVsc1tjXSB8fCBjKQogICAgICAgICAgLmpvaW4oIiwgIik7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgJHtzdWdnZXN0aW9uLnR4SWRzLmxlbmd0aH0gdHJhbnNhY3Rpb24ocykgc2ltaWxhaXJlKHMpIMOgICIke2Rlc2NMYWJlbH0iIHNvbnQgY2xhc3PDqWVzIGVuIGAgKwogICAgICAgICAgYCIke291dGxpZXJMYWJlbHN9IiwgYWxvcnMgcXVlICIke2RvbWluYW50TGFiZWx9IiBlc3QgbWFpbnRlbmFudCBsYSBjYXTDqWdvcmllIGhhYml0dWVsbGUuIGAgKwogICAgICAgICAgYExlcyBhbGlnbmVyIHN1ciAiJHtkb21pbmFudExhYmVsfSIgP2A7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgZG9taW5hbnRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3N1Z2dlc3Rpb24uZG9taW5hbnRdIHx8IHN1Z2dlc3Rpb24uZG9taW5hbnQ7CiAgICAgICAgY29uc3QgY3VycmVudExhYmVsID0gYWxsQ2F0ZWdvcnlMYWJlbHNbc3VnZ2VzdGlvbi5jdXJyZW50XSB8fCBzdWdnZXN0aW9uLmN1cnJlbnQ7CiAgICAgICAgdGV4dC50ZXh0Q29udGVudCA9CiAgICAgICAgICBgIiR7ZGVzY0xhYmVsfSIgZXN0IGhhYml0dWVsbGVtZW50IGNsYXNzw6kgZW4gIiR7ZG9taW5hbnRMYWJlbH0iLCBtYWlzIGNldHRlIGZvaXMgYCArCiAgICAgICAgICBgYydlc3QgIiR7Y3VycmVudExhYmVsfSIuIFBhcyBkJ2VycmV1ciBvdSB1biBvdWJsaSA/YDsKICAgICAgfQogICAgICBlbC5hcHBlbmRDaGlsZCh0ZXh0KTsKCiAgICAgIGNvbnN0IGNvbnRyb2xzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgIGNvbnRyb2xzLmNsYXNzTmFtZSA9ICJjYXRlZ29yeS1zdWdnZXN0aW9uLWNvbnRyb2xzIjsKCiAgICAgIGlmIChzdWdnZXN0aW9uLmtpbmQgPT09ICJnZW5lcmljIikgewogICAgICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVtzdWdnZXN0aW9uLnR5cGVdKSB7CiAgICAgICAgICBpZiAodmFsdWUgPT09ICJhdXRyZSIpIGNvbnRpbnVlOwogICAgICAgICAgY29uc3Qgb3B0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgib3B0aW9uIik7CiAgICAgICAgICBvcHQudmFsdWUgPSB2YWx1ZTsKICAgICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IG5ld09wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG5ld09wdC52YWx1ZSA9ICJfX25ld19fIjsKICAgICAgICBuZXdPcHQudGV4dENvbnRlbnQgPSAiKyBOb3V2ZWxsZSBjYXTDqWdvcmll4oCmIjsKICAgICAgICBuZXdPcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChuZXdPcHQpOwoKICAgICAgICBjb25zdCBuZXdOYW1lSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIG5ld05hbWVJbnB1dC50eXBlID0gInRleHQiOwogICAgICAgIG5ld05hbWVJbnB1dC5wbGFjZWhvbGRlciA9ICJOb20gZGUgbGEgbm91dmVsbGUgY2F0w6lnb3JpZSI7CiAgICAgICAgbmV3TmFtZUlucHV0LnZhbHVlID0gc3VnZ2VzdGlvbi5kZXNjcmlwdGlvbiB8fCAiIjsKCiAgICAgICAgc2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgICAgIG5ld05hbWVJbnB1dC5zdHlsZS5kaXNwbGF5ID0gc2VsZWN0LnZhbHVlID09PSAiX19uZXdfXyIgPyAiaW5saW5lLWJsb2NrIiA6ICJub25lIjsKICAgICAgICB9KTsKCiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoc2VsZWN0KTsKICAgICAgICBjb250cm9scy5hcHBlbmRDaGlsZChuZXdOYW1lSW5wdXQpOwoKICAgICAgICBjb25zdCBhcHBseUJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImJ1dHRvbiIpOwogICAgICAgIGFwcGx5QnRuLnRleHRDb250ZW50ID0gIkFwcGxpcXVlciI7CiAgICAgICAgYXBwbHlCdG4uY2xhc3NOYW1lID0gImJ0bi1wcmltYXJ5LXNtIjsKICAgICAgICBhcHBseUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGxldCB0YXJnZXRWYWx1ZSA9IHNlbGVjdC52YWx1ZTsKICAgICAgICAgIGxldCB0YXJnZXRMYWJlbDsKICAgICAgICAgIGlmICh0YXJnZXRWYWx1ZSA9PT0gIl9fbmV3X18iKSB7CiAgICAgICAgICAgIGNvbnN0IG5hbWUgPSBuZXdOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICAgICAgICBpZiAoIW5hbWUpIHsgc2hvd1RvYXN0KCJEb25uZSB1biBub20gw6AgbGEgY2F0w6lnb3JpZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgICAgICAgdGFyZ2V0VmFsdWUgPSBzbHVnaWZ5Q2F0ZWdvcnkobmFtZSk7CiAgICAgICAgICAgIHRhcmdldExhYmVsID0gbmFtZTsKICAgICAgICAgICAgaWYgKCFjYXRlZ29yaWVzQnlUeXBlW3N1Z2dlc3Rpb24udHlwZV0uc29tZSgoW3ZdKSA9PiB2ID09PSB0YXJnZXRWYWx1ZSkpIHsKICAgICAgICAgICAgICBzYXZlQ3VzdG9tQ2F0ZWdvcnkoc3VnZ2VzdGlvbi50eXBlLCB0YXJnZXRWYWx1ZSwgdGFyZ2V0TGFiZWwpOwogICAgICAgICAgICB9CiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICB0YXJnZXRMYWJlbCA9IGFsbENhdGVnb3J5TGFiZWxzW3RhcmdldFZhbHVlXSB8fCB0YXJnZXRWYWx1ZTsKICAgICAgICAgIH0KICAgICAgICAgIGF3YWl0IGFwcGx5Q2F0ZWdvcnlTdWdnZXN0aW9uRml4KHN1Z2dlc3Rpb24sIHRhcmdldFZhbHVlLCB0YXJnZXRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9IGVsc2UgewogICAgICAgIGNvbnN0IGRvbWluYW50TGFiZWwgPSBhbGxDYXRlZ29yeUxhYmVsc1tzdWdnZXN0aW9uLmRvbWluYW50XSB8fCBzdWdnZXN0aW9uLmRvbWluYW50OwogICAgICAgIGNvbnN0IGFwcGx5QnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgYXBwbHlCdG4udGV4dENvbnRlbnQgPSBgQ29ycmlnZXIgZW4gIiR7ZG9taW5hbnRMYWJlbH0iYDsKICAgICAgICBhcHBseUJ0bi5jbGFzc05hbWUgPSAiYnRuLXByaW1hcnktc20iOwogICAgICAgIGFwcGx5QnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICAgICAgYXdhaXQgYXBwbHlDYXRlZ29yeVN1Z2dlc3Rpb25GaXgoc3VnZ2VzdGlvbiwgc3VnZ2VzdGlvbi5kb21pbmFudCwgZG9taW5hbnRMYWJlbCk7CiAgICAgICAgfSk7CiAgICAgICAgY29udHJvbHMuYXBwZW5kQ2hpbGQoYXBwbHlCdG4pOwogICAgICB9CgogICAgICBjb25zdCBkaXNtaXNzQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgIGRpc21pc3NCdG4udGV4dENvbnRlbnQgPSAiSWdub3JlciI7CiAgICAgIGRpc21pc3NCdG4uY2xhc3NOYW1lID0gImJ0bi1zZWNvbmRhcnktc20iOwogICAgICBkaXNtaXNzQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICAgICAgIGRpc21pc3NTdWdnZXN0aW9uKHN1Z2dlc3Rpb24ua2V5KTsKICAgICAgICBoaWRlQ2F0ZWdvcnlTdWdnZXN0aW9uQmFubmVyKCk7CiAgICAgIH0pOwogICAgICBjb250cm9scy5hcHBlbmRDaGlsZChkaXNtaXNzQnRuKTsKCiAgICAgIGVsLmFwcGVuZENoaWxkKGNvbnRyb2xzKTsKICAgIH0KCiAgICAvLyBJZCBkZSBsYSBkZXJuacOocmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUgUEFSIExBIFZPSVggZGFucyBjZXR0ZQogICAgLy8gc2Vzc2lvbiAobcOqbWUgcHJpbmNpcGUgcXVlIGxhc3RWb2ljZVRyYW5zYWN0aW9uSWQsIG1haXMgcG91ciB1bmUKICAgIC8vIGNvcnJlY3Rpb24gcXVpIHN1aXQgbGEgY3LDqWF0aW9uIGQndW5lIHLDqWN1cnJlbnRlIHBhciBsYSB2b2l4KS4KICAgIGxldCBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IG51bGw7CgogICAgYXN5bmMgZnVuY3Rpb24gYXBwbHlWb2ljZVJlc3VsdChwYXJzZWQpIHsKICAgICAgY29uc3QgdmVyYiA9IHBhcnNlZC50eXBlID09PSAiaW5jb21lIiA/ICJSZXZlbnUiIDogIkTDqXBlbnNlIjsKICAgICAgY29uc3QgYW1vdW50TGFiZWwgPSBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQocGFyc2VkLmFtb3VudCk7CgogICAgICAvLyAicsOpY3VycmVudCIsICJhYm9ubmVtZW50IiwgInRvdXMgbGVzIG1vaXMiLi4uIGTDqXRlY3TDqSBwYXIgbCdJQSA6IG9uCiAgICAgIC8vIGNyw6llL2NvcnJpZ2UgdW5lIGNoYXJnZSByw6ljdXJyZW50ZSBhdSBsaWV1IGQndW5lIHRyYW5zYWN0aW9uCiAgICAgIC8vIHBvbmN0dWVsbGUsIHF1ZWwgcXVlIHNvaXQgbCdvbmdsZXQgYWN0dWVsbGVtZW50IGFmZmljaMOpIOKAlCBsZSBtaWNybwogICAgICAvLyBlc3QgZ2xvYmFsLCBwYXMgbGnDqSDDoCBsJ29uZ2xldCBSw6ljdXJyZW50ZXMuCiAgICAgIGlmIChwYXJzZWQuaXNfcmVjdXJyaW5nKSB7CiAgICAgICAgY29uc3QgcmVjUGF5bG9hZCA9IHsKICAgICAgICAgIHR5cGU6IHBhcnNlZC50eXBlLAogICAgICAgICAgbmFtZTogcGFyc2VkLmRlc2NyaXB0aW9uIHx8IChwYXJzZWQudHlwZSA9PT0gImluY29tZSIgPyAiUmV2ZW51IHLDqWN1cnJlbnQiIDogIkTDqXBlbnNlIHLDqWN1cnJlbnRlIiksCiAgICAgICAgICBhbW91bnQ6IHBhcnNlZC5hbW91bnQsCiAgICAgICAgICBjYXRlZ29yeTogcGFyc2VkLmNhdGVnb3J5LAogICAgICAgICAgZGF5X29mX21vbnRoOiBOdW1iZXIocGFyc2VkLmV4cGVuc2VfZGF0ZS5zbGljZSg4LCAxMCkpLAogICAgICAgIH07CgogICAgICAgIGlmIChwYXJzZWQuaXNfY29ycmVjdGlvbiAmJiBsYXN0Vm9pY2VSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7bGFzdFZvaWNlUmVjdXJyaW5nSWR9YCwgewogICAgICAgICAgICBtZXRob2Q6ICJQVVQiLAogICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZWNQYXlsb2FkKSwKICAgICAgICAgIH0pOwogICAgICAgICAgc2hvd1RvYXN0KGBDaGFyZ2UgcsOpY3VycmVudGUgY29ycmlnw6llIDogJHtyZWNQYXlsb2FkLm5hbWV9ICgke2Ftb3VudExhYmVsfSlgKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgY3JlYXRlZCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL3JlY3VycmluZyIsIHsKICAgICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHJlY1BheWxvYWQpLAogICAgICAgICAgfSk7CiAgICAgICAgICBsYXN0Vm9pY2VSZWN1cnJpbmdJZCA9IGNyZWF0ZWQuaWQ7CiAgICAgICAgICBzaG93VG9hc3QoYENoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSA6ICR7cmVjUGF5bG9hZC5uYW1lfSAoJHthbW91bnRMYWJlbH0pYCk7CiAgICAgICAgfQogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHBheWxvYWQgPSB7CiAgICAgICAgdHlwZTogcGFyc2VkLnR5cGUsCiAgICAgICAgYW1vdW50OiBwYXJzZWQuYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksCiAgICAgICAgZGVzY3JpcHRpb246IHBhcnNlZC5kZXNjcmlwdGlvbiwKICAgICAgICBleHBlbnNlX2RhdGU6IHBhcnNlZC5leHBlbnNlX2RhdGUsCiAgICAgIH07CgogICAgICBpZiAocGFyc2VkLmlzX2NvcnJlY3Rpb24gJiYgbGFzdFZvaWNlVHJhbnNhY3Rpb25JZCkgewogICAgICAgIGF3YWl0IGFwaUZldGNoKGAvYXBpL3RyYW5zYWN0aW9ucy8ke2xhc3RWb2ljZVRyYW5zYWN0aW9uSWR9YCwgewogICAgICAgICAgbWV0aG9kOiAiUFVUIiwKICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpLAogICAgICAgIH0pOwogICAgICAgIHNob3dUb2FzdChgQ29ycmlnw6kgOiAke3ZlcmIudG9Mb3dlckNhc2UoKX0gZGUgJHthbW91bnRMYWJlbH1gKTsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgYXBpRmV0Y2goIi9hcGkvdHJhbnNhY3Rpb25zIiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBsYXN0Vm9pY2VUcmFuc2FjdGlvbklkID0gY3JlYXRlZC5pZDsKICAgICAgICBzaG93VG9hc3QoYCR7dmVyYn0gYWpvdXTDqSR7cGFyc2VkLnR5cGUgPT09ICJpbmNvbWUiID8gIiIgOiAiZSJ9IDogJHthbW91bnRMYWJlbH1gKTsKICAgICAgfQogICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIGNoZWNrQ2F0ZWdvcnlTdWdnZXN0aW9uKHBhcnNlZC5kZXNjcmlwdGlvbiwgcGFyc2VkLnR5cGUpOwogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbmZpcm1hdGlvbiBzdHlsw6llIChyZW1wbGFjZSB3aW5kb3cuY29uZmlybSwgcXVpIGFmZmljaGUgdW5lIHBvcHVwCiAgICAvLyBuYXRpdmUgZHUgbmF2aWdhdGV1ciBob3JzIGNoYXJ0ZSBncmFwaGlxdWUpCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCBjb25maXJtT3ZlcmxheUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImNvbmZpcm0tbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgY29uZmlybU1lc3NhZ2VFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLW1vZGFsLW1lc3NhZ2UiKTsKICAgIGNvbnN0IGNvbmZpcm1Pa0J0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1vayIpOwogICAgY29uc3QgY29uZmlybUNhbmNlbEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJjb25maXJtLWJ0bi1jYW5jZWwiKTsKICAgIGxldCBjb25maXJtUmVzb2x2ZSA9IG51bGw7CgogICAgZnVuY3Rpb24gc2hvd0NvbmZpcm0obWVzc2FnZSkgewogICAgICBjb25maXJtTWVzc2FnZUVsLnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgICAgY29uZmlybU92ZXJsYXlFbC5jbGFzc0xpc3QucmVtb3ZlKCJoaWRkZW4iKTsKICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSByZXNvbHZlOwogICAgICB9KTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZUNvbmZpcm0ocmVzdWx0KSB7CiAgICAgIGNvbmZpcm1PdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGlmIChjb25maXJtUmVzb2x2ZSkgewogICAgICAgIGNvbmZpcm1SZXNvbHZlKHJlc3VsdCk7CiAgICAgICAgY29uZmlybVJlc29sdmUgPSBudWxsOwogICAgICB9CiAgICB9CgogICAgY29uZmlybU9rQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gY2xvc2VDb25maXJtKHRydWUpKTsKICAgIGNvbmZpcm1DYW5jZWxCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiBjbG9zZUNvbmZpcm0oZmFsc2UpKTsKICAgIGNvbmZpcm1PdmVybGF5RWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBpZiAoZS50YXJnZXQgPT09IGNvbmZpcm1PdmVybGF5RWwpIGNsb3NlQ29uZmlybShmYWxzZSk7CiAgICB9KTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBEw6lwZW5zZXMgcsOpY3VycmVudGVzCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBjb25zdCByZWNMaXN0RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjdXJyaW5nLWxpc3QiKTsKICAgIGNvbnN0IHJlY0VtcHR5U3RhdGVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWN1cnJpbmctZW1wdHktc3RhdGUiKTsKICAgIGNvbnN0IHJlY092ZXJsYXlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtbW9kYWwtb3ZlcmxheSIpOwogICAgY29uc3QgcmVjTW9kYWxUaXRsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1tb2RhbC10aXRsZSIpOwogICAgY29uc3QgcmVjVHlwZVRvZ2dsZUVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy10eXBlLXRvZ2dsZSIpOwogICAgY29uc3QgcmVjTmFtZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1uYW1lIik7CiAgICBjb25zdCByZWNBbW91bnRJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtYW1vdW50Iik7CiAgICBjb25zdCByZWNDYXRlZ29yeUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1pbnB1dC1jYXRlZ29yeSIpOwogICAgY29uc3QgcmVjRGF5SW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LWRheSIpOwogICAgY29uc3QgcmVjU3RhcnREYXRlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWlucHV0LXN0YXJ0LWRhdGUiKTsKICAgIGNvbnN0IHJlY0VuZERhdGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJyZWMtaW5wdXQtZW5kLWRhdGUiKTsKICAgIGNvbnN0IHJlY1NhdmVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgicmVjLWJ0bi1zYXZlIik7CgogICAgbGV0IGFsbFJlY3VycmluZyA9IFtdOwogICAgbGV0IGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICBsZXQgcmVjQ3VycmVudFR5cGUgPSAiZXhwZW5zZSI7CgogICAgZnVuY3Rpb24gcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHR5cGUsIHNlbGVjdGVkVmFsdWUgPSBudWxsKSB7CiAgICAgIHJlY0NhdGVnb3J5SW5wdXQuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3QgW3ZhbHVlLCBsYWJlbF0gb2YgY2F0ZWdvcmllc0J5VHlwZVt0eXBlXSkgewogICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgIG9wdC50ZXh0Q29udGVudCA9IGxhYmVsOwogICAgICAgIGlmICh2YWx1ZSA9PT0gKHNlbGVjdGVkVmFsdWUgfHwgImF1dHJlIikpIG9wdC5zZWxlY3RlZCA9IHRydWU7CiAgICAgICAgcmVjQ2F0ZWdvcnlJbnB1dC5hcHBlbmRDaGlsZChvcHQpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gc2V0UmVjdXJyaW5nVHlwZSh0eXBlKSB7CiAgICAgIHJlY0N1cnJlbnRUeXBlID0gdHlwZTsKICAgICAgcmVjVHlwZVRvZ2dsZUVsLnF1ZXJ5U2VsZWN0b3JBbGwoIi50eXBlLWJ0biIpLmZvckVhY2goKGJ0bikgPT4gewogICAgICAgIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBidG4uZGF0YXNldC50eXBlID09PSB0eXBlKTsKICAgICAgfSk7CiAgICAgIHBvcHVsYXRlUmVjdXJyaW5nQ2F0ZWdvcmllcyh0eXBlLCByZWNDYXRlZ29yeUlucHV0LnZhbHVlKTsKICAgIH0KCiAgICByZWNUeXBlVG9nZ2xlRWwuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIudHlwZS1idG4iKTsKICAgICAgaWYgKGJ0bikgc2V0UmVjdXJyaW5nVHlwZShidG4uZGF0YXNldC50eXBlKTsKICAgIH0pOwoKICAgIGZ1bmN0aW9uIG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtID0gbnVsbCkgewogICAgICBlZGl0aW5nUmVjdXJyaW5nSWQgPSBpdGVtID8gaXRlbS5pZCA6IG51bGw7CiAgICAgIHJlY01vZGFsVGl0bGVFbC50ZXh0Q29udGVudCA9IGl0ZW0gPyAiTW9kaWZpZXIgbGEgY2hhcmdlIHLDqWN1cnJlbnRlIiA6ICJOb3V2ZWxsZSBjaGFyZ2UgcsOpY3VycmVudGUiOwogICAgICByZWNTYXZlQnRuLnRleHRDb250ZW50ID0gaXRlbSA/ICJFbnJlZ2lzdHJlciIgOiAiQWpvdXRlciI7CiAgICAgIHNldFJlY3VycmluZ1R5cGUoaXRlbSA/IGl0ZW0udHlwZSA6ICJleHBlbnNlIik7CiAgICAgIHJlY05hbWVJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLm5hbWUgOiAiIjsKICAgICAgcmVjQW1vdW50SW5wdXQudmFsdWUgPSBpdGVtID8gaXRlbS5hbW91bnQgOiAiIjsKICAgICAgcG9wdWxhdGVSZWN1cnJpbmdDYXRlZ29yaWVzKHJlY0N1cnJlbnRUeXBlLCBpdGVtID8gaXRlbS5jYXRlZ29yeSA6ICJhdXRyZSIpOwogICAgICByZWNEYXlJbnB1dC52YWx1ZSA9IGl0ZW0gPyBpdGVtLmRheV9vZl9tb250aCA6ICIiOwogICAgICByZWNTdGFydERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5zdGFydF9kYXRlID8gaXRlbS5zdGFydF9kYXRlIDogIiI7CiAgICAgIHJlY0VuZERhdGVJbnB1dC52YWx1ZSA9IGl0ZW0gJiYgaXRlbS5lbmRfZGF0ZSA/IGl0ZW0uZW5kX2RhdGUgOiAiIjsKICAgICAgcmVjT3ZlcmxheUVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICByZWNOYW1lSW5wdXQuZm9jdXMoKTsKICAgIH0KCiAgICBmdW5jdGlvbiBjbG9zZVJlY3VycmluZ01vZGFsKCkgewogICAgICByZWNPdmVybGF5RWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgIGVkaXRpbmdSZWN1cnJpbmdJZCA9IG51bGw7CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInJlYy1idG4tY2FuY2VsIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBjbG9zZVJlY3VycmluZ01vZGFsKTsKICAgIHJlY092ZXJsYXlFbC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7IGlmIChlLnRhcmdldCA9PT0gcmVjT3ZlcmxheUVsKSBjbG9zZVJlY3VycmluZ01vZGFsKCk7IH0pOwoKICAgIHJlY1NhdmVCdG4uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IG5hbWUgPSByZWNOYW1lSW5wdXQudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KHJlY0Ftb3VudElucHV0LnZhbHVlKTsKICAgICAgY29uc3QgZGF5ID0gcGFyc2VJbnQocmVjRGF5SW5wdXQudmFsdWUsIDEwKTsKCiAgICAgIGlmICghbmFtZSkgeyBzaG93VG9hc3QoIkxlIG5vbSBlc3Qgb2JsaWdhdG9pcmUiLCB0cnVlKTsgcmV0dXJuOyB9CiAgICAgIGlmICghYW1vdW50IHx8IGFtb3VudCA8PSAwKSB7IHNob3dUb2FzdCgiTW9udGFudCBpbnZhbGlkZSIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFkYXkgfHwgZGF5IDwgMSB8fCBkYXkgPiAzMSkgeyBzaG93VG9hc3QoIkpvdXIgZHUgbW9pcyBpbnZhbGlkZSAoMSDDoCAzMSkiLCB0cnVlKTsgcmV0dXJuOyB9CgogICAgICBjb25zdCBwYXlsb2FkID0gewogICAgICAgIHR5cGU6IHJlY0N1cnJlbnRUeXBlLAogICAgICAgIG5hbWUsCiAgICAgICAgYW1vdW50LAogICAgICAgIGNhdGVnb3J5OiByZWNDYXRlZ29yeUlucHV0LnZhbHVlLAogICAgICAgIGRheV9vZl9tb250aDogZGF5LAogICAgICAgIHN0YXJ0X2RhdGU6IHJlY1N0YXJ0RGF0ZUlucHV0LnZhbHVlIHx8IG51bGwsCiAgICAgICAgZW5kX2RhdGU6IHJlY0VuZERhdGVJbnB1dC52YWx1ZSB8fCBudWxsLAogICAgICB9OwoKICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIHRyeSB7CiAgICAgICAgaWYgKGVkaXRpbmdSZWN1cnJpbmdJZCkgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7ZWRpdGluZ1JlY3VycmluZ0lkfWAsIHsgbWV0aG9kOiAiUFVUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBtb2RpZmnDqWUiKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYXdhaXQgYXBpRmV0Y2goIi9hcGkvcmVjdXJyaW5nIiwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkgfSk7CiAgICAgICAgICBzaG93VG9hc3QoIkNoYXJnZSByw6ljdXJyZW50ZSBham91dMOpZSIpOwogICAgICAgIH0KICAgICAgICBjbG9zZVJlY3VycmluZ01vZGFsKCk7CiAgICAgICAgYXdhaXQgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgcmVjU2F2ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9KTsKCiAgICBhc3luYyBmdW5jdGlvbiBkZWxldGVSZWN1cnJpbmcoaWQpIHsKICAgICAgaWYgKCEoYXdhaXQgc2hvd0NvbmZpcm0oIlN1cHByaW1lciBjZXR0ZSBkw6lwZW5zZSByw6ljdXJyZW50ZSA/IikpKSByZXR1cm47CiAgICAgIHRyeSB7CiAgICAgICAgYXdhaXQgYXBpRmV0Y2goYC9hcGkvcmVjdXJyaW5nLyR7aWR9YCwgeyBtZXRob2Q6ICJERUxFVEUiIH0pOwogICAgICAgIHNob3dUb2FzdCgiRMOpcGVuc2UgcsOpY3VycmVudGUgc3VwcHJpbcOpZSIpOwogICAgICAgIGF3YWl0IGxvYWRSZWN1cnJpbmcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyUmVjdXJyaW5nKGl0ZW1zKSB7CiAgICAgIHJlY0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgcmVjRW1wdHlTdGF0ZUVsLnN0eWxlLmRpc3BsYXkgPSBpdGVtcy5sZW5ndGggPT09IDAgPyAiYmxvY2siIDogIm5vbmUiOwoKICAgICAgY29uc3QgdG9kYXlLZXkgPSB0b2RheUlzbygpOwoKICAgICAgZm9yIChjb25zdCBpdGVtIG9mIGl0ZW1zKSB7CiAgICAgICAgY29uc3QgdHlwZSA9IGl0ZW0udHlwZSB8fCAiZXhwZW5zZSI7CiAgICAgICAgY29uc3QgZW5kZWQgPSBpdGVtLmVuZF9kYXRlICYmIGl0ZW0uZW5kX2RhdGUgPCB0b2RheUtleTsKICAgICAgICBjb25zdCBub3RTdGFydGVkID0gaXRlbS5zdGFydF9kYXRlICYmIGl0ZW0uc3RhcnRfZGF0ZSA+IHRvZGF5S2V5OwoKICAgICAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgY2FyZC5jbGFzc05hbWUgPSAicmVjLWNhcmQgIiArIHR5cGUgKyAoZW5kZWQgPyAiIGVuZGVkIiA6ICIiKTsKCiAgICAgICAgY29uc3QgbWFpbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1haW4uY2xhc3NOYW1lID0gInJlYy1tYWluIjsKCiAgICAgICAgY29uc3QgdG9wID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgdG9wLmNsYXNzTmFtZSA9ICJyZWMtdG9wIjsKICAgICAgICBjb25zdCBiYWRnZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICBiYWRnZS5jbGFzc05hbWUgPSAiY2F0ZWdvcnktYmFkZ2UiOwogICAgICAgIGJhZGdlLnRleHRDb250ZW50ID0gYWxsQ2F0ZWdvcnlMYWJlbHNbaXRlbS5jYXRlZ29yeV0gfHwgaXRlbS5jYXRlZ29yeTsKICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoYmFkZ2UpOwogICAgICAgIGlmIChpdGVtLnN0YXJ0X2RhdGUpIHsKICAgICAgICAgIGNvbnN0IHN0YXJ0QmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBzdGFydEJhZGdlLmNsYXNzTmFtZSA9ICJzdGFydC1iYWRnZSI7CiAgICAgICAgICBjb25zdCBzdGFydExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5zdGFydF9kYXRlICsgIlQwMDowMDowMCIpKTsKICAgICAgICAgIHN0YXJ0QmFkZ2UudGV4dENvbnRlbnQgPSBub3RTdGFydGVkID8gYETDqHMgbGUgJHtzdGFydExhYmVsfWAgOiBgRGVwdWlzIGxlICR7c3RhcnRMYWJlbH1gOwogICAgICAgICAgdG9wLmFwcGVuZENoaWxkKHN0YXJ0QmFkZ2UpOwogICAgICAgIH0KICAgICAgICBpZiAoaXRlbS5lbmRfZGF0ZSkgewogICAgICAgICAgY29uc3QgZW5kQmFkZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICBlbmRCYWRnZS5jbGFzc05hbWUgPSAiZW5kLWJhZGdlIjsKICAgICAgICAgIGNvbnN0IGVuZExhYmVsID0gZGF0ZUZvcm1hdHRlci5mb3JtYXQobmV3IERhdGUoaXRlbS5lbmRfZGF0ZSArICJUMDA6MDA6MDAiKSk7CiAgICAgICAgICBlbmRCYWRnZS50ZXh0Q29udGVudCA9IGVuZGVkID8gYFRlcm1pbsOpIGxlICR7ZW5kTGFiZWx9YCA6IGBKdXNxdSdhdSAke2VuZExhYmVsfWA7CiAgICAgICAgICB0b3AuYXBwZW5kQ2hpbGQoZW5kQmFkZ2UpOwogICAgICAgIH0KCiAgICAgICAgY29uc3QgbmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG5hbWUuY2xhc3NOYW1lID0gInJlYy1uYW1lIjsKICAgICAgICBuYW1lLnRleHRDb250ZW50ID0gaXRlbS5uYW1lOwoKICAgICAgICBjb25zdCBzdWIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBzdWIuY2xhc3NOYW1lID0gInJlYy1zdWIiOwogICAgICAgIHN1Yi50ZXh0Q29udGVudCA9IGBMZSAke2l0ZW0uZGF5X29mX21vbnRofSBkZSBjaGFxdWUgbW9pc2A7CgogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQodG9wKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKG5hbWUpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQoc3ViKTsKCiAgICAgICAgY29uc3QgYW1vdW50RWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBhbW91bnRFbC5jbGFzc05hbWUgPSAicmVjLWFtb3VudCAiICsgdHlwZTsKICAgICAgICBhbW91bnRFbC50ZXh0Q29udGVudCA9ICh0eXBlID09PSAiaW5jb21lIiA/ICIrICIgOiAi4oiSICIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KGl0ZW0uYW1vdW50KTsKCiAgICAgICAgY29uc3QgYWN0aW9ucyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGFjdGlvbnMuY2xhc3NOYW1lID0gInR4LWFjdGlvbnMiOwogICAgICAgIGNvbnN0IGVkaXRCdG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgICAgICBlZGl0QnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biI7CiAgICAgICAgZWRpdEJ0bi50ZXh0Q29udGVudCA9ICLinI/vuI8iOwogICAgICAgIGVkaXRCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIk1vZGlmaWVyIik7CiAgICAgICAgZWRpdEJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IG9wZW5SZWN1cnJpbmdNb2RhbChpdGVtKSk7CiAgICAgICAgY29uc3QgZGVsZXRlQnRuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiYnV0dG9uIik7CiAgICAgICAgZGVsZXRlQnRuLmNsYXNzTmFtZSA9ICJpY29uLWJ0biBkYW5nZXIiOwogICAgICAgIGRlbGV0ZUJ0bi50ZXh0Q29udGVudCA9ICLwn5eR77iPIjsKICAgICAgICBkZWxldGVCdG4uc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwgIlN1cHByaW1lciIpOwogICAgICAgIGRlbGV0ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IGRlbGV0ZVJlY3VycmluZyhpdGVtLmlkKSk7CiAgICAgICAgYWN0aW9ucy5hcHBlbmRDaGlsZChlZGl0QnRuKTsKICAgICAgICBhY3Rpb25zLmFwcGVuZENoaWxkKGRlbGV0ZUJ0bik7CgogICAgICAgIGNhcmQuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhbW91bnRFbCk7CiAgICAgICAgY2FyZC5hcHBlbmRDaGlsZChhY3Rpb25zKTsKICAgICAgICByZWNMaXN0RWwuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgICAgIH0KICAgIH0KCiAgICAvLyBUb3RhbCBkZXMgZMOpcGVuc2VzIHLDqWN1cnJlbnRlcyBwYXMgZW5jb3JlIHByw6lsZXbDqWVzIGNlIG1vaXMtY2kgKGNlbGxlcwogICAgLy8gZG9udCBsZSBqb3VyIGR1IG1vaXMgbidlc3QgcGFzIGVuY29yZSBwYXNzw6kpLCBhZmZpY2jDqSDDoCBjw7R0w6kgZGVzIDMKICAgIC8vIGNhcnRlcyBkdSBoYXV0IOKAlCBpbmTDqXBlbmRhbnQgZHUgbW9pcyBjaG9pc2kgZGFucyBsZSB0YWJsZWF1IGRlIGJvcmQsCiAgICAvLyB0b3Vqb3VycyAibGUgbW9pcyByw6llbCwgbWFpbnRlbmFudCIuCiAgICBmdW5jdGlvbiB1cGRhdGVVcGNvbWluZ1N1bW1hcnkoKSB7CiAgICAgIGNvbnN0IGN1cnJlbnRNb250aEtleSA9IG1vbnRoS2V5T2YodG9kYXlJc28oKSk7CiAgICAgIGNvbnN0IHRvZGF5RGF5ID0gTnVtYmVyKHRvZGF5SXNvKCkuc2xpY2UoOCwgMTApKTsKICAgICAgbGV0IHVwY29taW5nRXhwZW5zZSA9IDA7CiAgICAgIGxldCB1cGNvbWluZ0luY29tZSA9IDA7CiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiBhbGxSZWN1cnJpbmcpIHsKICAgICAgICBpZiAoIXJlY3VycmluZ0FjdGl2ZUZvck1vbnRoKGl0ZW0sIGN1cnJlbnRNb250aEtleSkpIGNvbnRpbnVlOwogICAgICAgIGlmIChpdGVtLmRheV9vZl9tb250aCA8PSB0b2RheURheSkgY29udGludWU7CiAgICAgICAgaWYgKChpdGVtLnR5cGUgfHwgImV4cGVuc2UiKSA9PT0gImluY29tZSIpIHVwY29taW5nSW5jb21lICs9IE51bWJlcihpdGVtLmFtb3VudCk7CiAgICAgICAgZWxzZSB1cGNvbWluZ0V4cGVuc2UgKz0gTnVtYmVyKGl0ZW0uYW1vdW50KTsKICAgICAgfQogICAgICBjb25zdCBuZXQgPSB1cGNvbWluZ0luY29tZSAtIHVwY29taW5nRXhwZW5zZTsKICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZyIpOwogICAgICBjb25zdCBjYXJkRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy1jYXJkIik7CiAgICAgIGNvbnN0IHRvb2x0aXBFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzdW1tYXJ5LXVwY29taW5nLXRvb2x0aXAiKTsKCiAgICAgIGlmIChuZXQgPT09IDApIHsKICAgICAgICBlbC50ZXh0Q29udGVudCA9ICLigJQiOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJ2YWx1ZSI7CiAgICAgICAgdG9vbHRpcEVsLmlubmVySFRNTCA9ICIiOwogICAgICAgIGNhcmRFbC5jbGFzc0xpc3QucmVtb3ZlKCJ0b29sdGlwLWhvc3QiKTsKICAgICAgICByZXR1cm47CiAgICAgIH0KCiAgICAgIGNvbnN0IHNpZ24gPSBuZXQgPiAwID8gIisiIDogIuKIkiI7CiAgICAgIGVsLnRleHRDb250ZW50ID0gYCR7c2lnbn0gJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoTWF0aC5hYnMobmV0KSl9YDsKICAgICAgZWwuY2xhc3NOYW1lID0gInZhbHVlICIgKyAobmV0ID4gMCA/ICJwb3NpdGl2ZSIgOiAibmVnYXRpdmUiKTsKICAgICAgY2FyZEVsLmNsYXNzTGlzdC5hZGQoInRvb2x0aXAtaG9zdCIpOwogICAgICB0b29sdGlwRWwuaW5uZXJIVE1MID0KICAgICAgICBgRMOpcGVuc2VzIMOgIHZlbmlyIDogJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQodXBjb21pbmdFeHBlbnNlKX08YnI+YCArCiAgICAgICAgYFJldmVudXMgw6AgdmVuaXIgOiAke2N1cnJlbmN5Rm9ybWF0dGVyLmZvcm1hdCh1cGNvbWluZ0luY29tZSl9YDsKICAgIH0KCiAgICAvLyBQZXRpdGUgYnVsbGUgZGUgZMOpdGFpbCBmYcOnb24gInRvb2x0aXAiIGhhYmlsbMOpZSBhdXggY291bGV1cnMgZHUgc2l0ZSwKICAgIC8vIGF1IGxpZXUgZHUgdGl0bGUgbmF0aWYgZHUgbmF2aWdhdGV1ciAoZ3Jpcy9ibGFuYywgaG9ycyBjaGFydGUsIGV0CiAgICAvLyBpbnZpc2libGUgYXUgdGFjdGlsZSkuIEFmZmljaMOpZSBhdSBzdXJ2b2wgKG9yZGluYXRldXIpIGV0IGF1CiAgICAvLyB0YXAvdGFwLWVuLWRlaG9ycyAodMOpbMOpcGhvbmUvdGFibGV0dGUpLgogICAgKGZ1bmN0aW9uIHNldHVwU3VtbWFyeVVwY29taW5nVG9vbHRpcCgpIHsKICAgICAgY29uc3QgY2FyZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInN1bW1hcnktdXBjb21pbmctY2FyZCIpOwogICAgICBjb25zdCB0b29sdGlwRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic3VtbWFyeS11cGNvbWluZy10b29sdGlwIik7CgogICAgICBmdW5jdGlvbiBzaG93KCkgewogICAgICAgIGlmICh0b29sdGlwRWwuaW5uZXJIVE1MKSB0b29sdGlwRWwuY2xhc3NMaXN0LmFkZCgidmlzaWJsZSIpOwogICAgICB9CiAgICAgIGZ1bmN0aW9uIGhpZGUoKSB7CiAgICAgICAgdG9vbHRpcEVsLmNsYXNzTGlzdC5yZW1vdmUoInZpc2libGUiKTsKICAgICAgfQoKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlZW50ZXIiLCBzaG93KTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoIm1vdXNlbGVhdmUiLCBoaWRlKTsKICAgICAgY2FyZEVsLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKGUpID0+IHsKICAgICAgICBlLnN0b3BQcm9wYWdhdGlvbigpOwogICAgICAgIHRvb2x0aXBFbC5jbGFzc0xpc3QudG9nZ2xlKCJ2aXNpYmxlIik7CiAgICAgIH0pOwogICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGhpZGUpOwogICAgfSkoKTsKCiAgICAvLyBSYW3DqG5lIHVuIGpvdXIgZHUgbW9pcyAoMS0zMSkgYXUgZGVybmllciBqb3VyIHLDqWVsIGR1IG1vaXMgdmlzw6kg4oCUCiAgICAvLyDDqXF1aXZhbGVudCBKUyBkZSBfY2xhbXBfZGF5IGPDtHTDqSBzZXJ2ZXVyLCBwb3VyIGNhbGN1bGVyIGRlIHZyYWllcwogICAgLy8gZGF0ZXMgKG5ldyBEYXRlKC4uLikpIHBsdXTDtHQgcXVlIGRlIGNvbXBhcmVyIGRlcyBqb3VycyB0b3V0IHNldWxzLgogICAgZnVuY3Rpb24gY2xhbXBEYXlKcyh5ZWFyLCBtb250aEluZGV4LCBkYXkpIHsKICAgICAgY29uc3QgbGFzdERheSA9IG5ldyBEYXRlKHllYXIsIG1vbnRoSW5kZXggKyAxLCAwKS5nZXREYXRlKCk7CiAgICAgIHJldHVybiBNYXRoLm1pbihkYXksIGxhc3REYXkpOwogICAgfQoKICAgIC8vIFByb2NoYWluZSBvY2N1cnJlbmNlIGQndW5lIGNoYXJnZSByw6ljdXJyZW50ZSDDoCBwYXJ0aXIgZCdhdWpvdXJkJ2h1aQogICAgLy8gKHN0cmljdGVtZW50IGFwcsOocyBhdWpvdXJkJ2h1aSkgOiByZWdhcmRlIGNlIG1vaXMtY2kgcHVpcywgc2kgYmVzb2luLAogICAgLy8gbGVzIGRldXggbW9pcyBzdWl2YW50cyDigJQgdXRpbGUgZW4gZmluIGRlIG1vaXMgcXVhbmQgcGx1cyByaWVuIG4nZXN0CiAgICAvLyDDoCB2ZW5pciBkYW5zIGxlIG1vaXMgY291cmFudC4KICAgIGZ1bmN0aW9uIG5leHRPY2N1cnJlbmNlRm9ySXRlbShpdGVtLCB0b2RheVN0cikgewogICAgICBjb25zdCBbdHksIHRtLCB0ZF0gPSB0b2RheVN0ci5zcGxpdCgiLSIpLm1hcChOdW1iZXIpOwogICAgICBjb25zdCB0b2RheURhdGUgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxLCB0ZCk7CiAgICAgIGZvciAobGV0IG9mZnNldCA9IDA7IG9mZnNldCA8PSAyOyBvZmZzZXQrKykgewogICAgICAgIGNvbnN0IGJhc2UgPSBuZXcgRGF0ZSh0eSwgdG0gLSAxICsgb2Zmc2V0LCAxKTsKICAgICAgICBjb25zdCB5ID0gYmFzZS5nZXRGdWxsWWVhcigpOwogICAgICAgIGNvbnN0IG1JZHggPSBiYXNlLmdldE1vbnRoKCk7CiAgICAgICAgY29uc3QgbW9udGhLZXkgPSBgJHt5fS0ke1N0cmluZyhtSWR4ICsgMSkucGFkU3RhcnQoMiwgIjAiKX1gOwogICAgICAgIGlmICghcmVjdXJyaW5nQWN0aXZlRm9yTW9udGgoaXRlbSwgbW9udGhLZXkpKSBjb250aW51ZTsKICAgICAgICBjb25zdCBkYXkgPSBjbGFtcERheUpzKHksIG1JZHgsIGl0ZW0uZGF5X29mX21vbnRoKTsKICAgICAgICBjb25zdCBvY2NEYXRlID0gbmV3IERhdGUoeSwgbUlkeCwgZGF5KTsKICAgICAgICBpZiAob2NjRGF0ZSA+IHRvZGF5RGF0ZSkgcmV0dXJuIG9jY0RhdGU7CiAgICAgIH0KICAgICAgcmV0dXJuIG51bGw7CiAgICB9CgogICAgZnVuY3Rpb24gcmVuZGVyVXBjb21pbmdSZWN1cnJpbmdMaXN0KCkgewogICAgICBjb25zdCBwYW5lbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJ1cGNvbWluZy1yZWN1cnJpbmctcGFuZWwiKTsKICAgICAgY29uc3QgbGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInVwY29taW5nLXJlY3VycmluZy1saXN0Iik7CiAgICAgIGNvbnN0IHRvZGF5ID0gdG9kYXlJc28oKTsKCiAgICAgIGNvbnN0IHVwY29taW5nID0gYWxsUmVjdXJyaW5nCiAgICAgICAgLm1hcCgoaXRlbSkgPT4gKHsgaXRlbSwgZGF0ZTogbmV4dE9jY3VycmVuY2VGb3JJdGVtKGl0ZW0sIHRvZGF5KSB9KSkKICAgICAgICAuZmlsdGVyKCh4KSA9PiB4LmRhdGUpCiAgICAgICAgLnNvcnQoKGEsIGIpID0+IGEuZGF0ZSAtIGIuZGF0ZSkKICAgICAgICAuc2xpY2UoMCwgMyk7CgogICAgICBpZiAodXBjb21pbmcubGVuZ3RoID09PSAwKSB7CiAgICAgICAgcGFuZWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIHBhbmVsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICBsaXN0RWwuaW5uZXJIVE1MID0gIiI7CgogICAgICBmb3IgKGNvbnN0IHsgaXRlbSwgZGF0ZSB9IG9mIHVwY29taW5nKSB7CiAgICAgICAgY29uc3QgZGF5cyA9IE1hdGgucm91bmQoKGRhdGUgLSBuZXcgRGF0ZShuZXcgRGF0ZSgpLnNldEhvdXJzKDAsIDAsIDAsIDApKSkgLyA4NjQwMDAwMCk7CiAgICAgICAgY29uc3QgZHVlTGFiZWwgPSBkYXlzIDw9IDEgPyAiZGVtYWluIiA6IGBkYW5zICR7ZGF5c30gam91cnNgOwogICAgICAgIGNvbnN0IHR5cGUgPSBpdGVtLnR5cGUgfHwgImV4cGVuc2UiOwoKICAgICAgICBjb25zdCByb3cgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICByb3cuY2xhc3NOYW1lID0gInVwY29taW5nLXJlY3VycmluZy1yb3ciOwogICAgICAgIGNvbnN0IGxlZnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbGVmdC5jbGFzc05hbWUgPSAibmFtZSI7CiAgICAgICAgbGVmdC50ZXh0Q29udGVudCA9IGl0ZW0ubmFtZTsKICAgICAgICBjb25zdCBkdWVTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGR1ZVNwYW4uY2xhc3NOYW1lID0gImR1ZSI7CiAgICAgICAgZHVlU3Bhbi50ZXh0Q29udGVudCA9IGAke2RhdGVGb3JtYXR0ZXIuZm9ybWF0KGRhdGUpfSDCtyAke2R1ZUxhYmVsfWA7CiAgICAgICAgbGVmdC5hcHBlbmRDaGlsZChkdWVTcGFuKTsKICAgICAgICBjb25zdCBhbW91bnQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgYW1vdW50LmNsYXNzTmFtZSA9ICJhbW91bnQgIiArIHR5cGU7CiAgICAgICAgYW1vdW50LnRleHRDb250ZW50ID0gKHR5cGUgPT09ICJpbmNvbWUiID8gIisgIiA6ICLiiJIgIikgKyBjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoaXRlbS5hbW91bnQpOwogICAgICAgIHJvdy5hcHBlbmRDaGlsZChsZWZ0KTsKICAgICAgICByb3cuYXBwZW5kQ2hpbGQoYW1vdW50KTsKICAgICAgICBsaXN0RWwuYXBwZW5kQ2hpbGQocm93KTsKICAgICAgfQogICAgfQoKICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWRSZWN1cnJpbmcoKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgaXRlbXMgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZWN1cnJpbmciKTsKICAgICAgICBhbGxSZWN1cnJpbmcgPSBpdGVtczsKICAgICAgICByZW5kZXJSZWN1cnJpbmcoaXRlbXMpOwogICAgICAgIHJlbmRlclVwY29taW5nUmVjdXJyaW5nTGlzdCgpOwogICAgICAgIHVwZGF0ZVVwY29taW5nU3VtbWFyeSgpOwogICAgICAgIGlmIChjdXJyZW50VmlldyA9PT0gImRhc2hib2FyZCIpIHJlbmRlckRhc2hib2FyZChhbGxUcmFuc2FjdGlvbnMpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciBkZSBjaGFyZ2VtZW50IDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfQogICAgfQoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEV4cG9ydCAoRXhjZWwgb3Ugc2F1dmVnYXJkZSBKU09OIGNvbXBsw6h0ZSwgdW4gc2V1bCBib3V0b24gYXZlYyB1bgogICAgLy8gY2hvaXggZGUgZm9ybWF0IHBsdXTDtHQgcXVlIGRldXggZ3JvcyBib3V0b25zIHPDqXBhcsOpcykKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIGNvbnN0IEVYUE9SVF9GT1JNQVRTID0gewogICAgICB4bHN4OiB7CiAgICAgICAgaGludDogIlRvdXRlcyB0ZXMgdHJhbnNhY3Rpb25zIChkw6lwZW5zZXMgZXQgcmV2ZW51cykgZXQgdGVzIGNoYXJnZXMgcsOpY3VycmVudGVzLCBjaGFjdW5lIGRhbnMgc29uIHByb3ByZSBvbmdsZXQuIiwKICAgICAgICB1cmw6ICIvYXBpL2V4cG9ydC94bHN4IiwKICAgICAgICBmaWxlbmFtZTogKCkgPT4gYGRlcGVuc2VzXyR7dG9kYXlJc28oKX0ueGxzeGAsCiAgICAgICAgdG9hc3RTdWNjZXNzOiAiRXhwb3J0IHTDqWzDqWNoYXJnw6kiLAogICAgICB9LAogICAgICBqc29uOiB7CiAgICAgICAgaGludDogIkFic29sdW1lbnQgdG91dGVzIHRlcyBkb25uw6llcyAodHJhbnNhY3Rpb25zLCBjaGFyZ2VzIHLDqWN1cnJlbnRlcywgY2F0w6lnb3JpZXMgcGVyc28sIGJ1ZGdldHMsIG9iamVjdGlmIGQnw6lwYXJnbmUpLiDDgCBnYXJkZXIgZGUgY8O0dMOpIDogU3VwYWJhc2UgbmUgZmFpdCBwYXMgZGUgc2F1dmVnYXJkZSBhdXRvbWF0aXF1ZSBlbiBvZmZyZSBncmF0dWl0ZSwgY2UgZmljaGllciBlc3QgdG9uIGZpbGV0IGRlIHPDqWN1cml0w6kgZW4gY2FzIGRlIHDDqXBpbi4iLAogICAgICAgIHVybDogIi9hcGkvZXhwb3J0L2pzb24iLAogICAgICAgIGZpbGVuYW1lOiAoKSA9PiBga2FjaGluZy1zYXV2ZWdhcmRlLSR7dG9kYXlJc28oKX0uanNvbmAsCiAgICAgICAgdG9hc3RTdWNjZXNzOiAiU2F1dmVnYXJkZSB0w6lsw6ljaGFyZ8OpZSIsCiAgICAgIH0sCiAgICB9OwogICAgbGV0IGN1cnJlbnRFeHBvcnRGb3JtYXQgPSAieGxzeCI7CiAgICBjb25zdCBleHBvcnRGb3JtYXRIaW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZXhwb3J0LWZvcm1hdC1oaW50Iik7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZXhwb3J0LWZvcm1hdC10b2dnbGUiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoIi5leHBvcnQtZm9ybWF0LWJ0biIpOwogICAgICBpZiAoIWJ0bikgcmV0dXJuOwogICAgICBjdXJyZW50RXhwb3J0Rm9ybWF0ID0gYnRuLmRhdGFzZXQuZm9ybWF0OwogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCIuZXhwb3J0LWZvcm1hdC1idG4iKS5mb3JFYWNoKChiKSA9PiB7CiAgICAgICAgYi5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCBiID09PSBidG4pOwogICAgICB9KTsKICAgICAgZXhwb3J0Rm9ybWF0SGludEVsLnRleHRDb250ZW50ID0gRVhQT1JUX0ZPUk1BVFNbY3VycmVudEV4cG9ydEZvcm1hdF0uaGludDsKICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LWRvd25sb2FkIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4tZXhwb3J0LWRvd25sb2FkIik7CiAgICAgIGNvbnN0IGNvbmZpZyA9IEVYUE9SVF9GT1JNQVRTW2N1cnJlbnRFeHBvcnRGb3JtYXRdOwogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAgICAgIGJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgIGJ0bi50ZXh0Q29udGVudCA9ICJHw6luw6lyYXRpb24gZW4gY291cnPigKYiOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKGNvbmZpZy51cmwsIHsgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9IH0pOwogICAgICAgIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoIsOJY2hlYyBkZSBsJ2V4cG9ydCAoIiArIHJlcy5zdGF0dXMgKyAiKSIpOwogICAgICAgIGNvbnN0IGJsb2IgPSBhd2FpdCByZXMuYmxvYigpOwogICAgICAgIGNvbnN0IHVybCA9IFVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICAgICAgY29uc3QgbGluayA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImEiKTsKICAgICAgICBsaW5rLmhyZWYgPSB1cmw7CiAgICAgICAgbGluay5kb3dubG9hZCA9IGNvbmZpZy5maWxlbmFtZSgpOwogICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQobGluayk7CiAgICAgICAgbGluay5jbGljaygpOwogICAgICAgIGxpbmsucmVtb3ZlKCk7CiAgICAgICAgVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwogICAgICAgIHNob3dUb2FzdChjb25maWcudG9hc3RTdWNjZXNzKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGJ0bi50ZXh0Q29udGVudCA9IG9yaWdpbmFsVGV4dDsKICAgICAgfQogICAgfSk7CgogICAgLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICAgLy8gR2FyZGUtZm91IGdsb2JhbCBjb250cmUgbGUgY29tcG9ydGVtZW50IHBhciBkw6lmYXV0IGR1IG5hdmlnYXRldXIgOgogICAgLy8gZMOpcG9zZXIgdW4gZmljaGllciBOJ0lNUE9SVEUgT8OZIHN1ciBsYSBwYWdlIChlbiBkZWhvcnMgZCd1bmUgem9uZQogICAgLy8gcHLDqXZ1ZSBwb3VyIMOnYSkgZmFpdCBub3JtYWxlbWVudCBOQVZJR1VFUiBsJ29uZ2xldCB2ZXJzIGNlIGZpY2hpZXIKICAgIC8vIGxvY2FsIChmaWxlOi8vLi4uKSwgcXVpIHRlbnRlIGRlIGwnYWZmaWNoZXIgY29tbWUgdW5lIHBhZ2Ug4oCUIGF2ZWMgdW4KICAgIC8vIGdyb3MgZmljaGllciBvdSB1biBmb3JtYXQgaW5hdHRlbmR1LCDDp2EgcGV1dCBwbGFudGVyIGwnb25nbGV0CiAgICAvLyAoIkHDr2UgYcOvZSBhw69lIikuIE9uIGJsb3F1ZSBjZSBjb21wb3J0ZW1lbnQgcGFydG91dCwgZXQgbGEgem9uZSBkZQogICAgLy8gZMOpcMO0dCBkw6lkacOpZSAocGx1cyBiYXMpIHJlcHJlbmQgbGEgbWFpbiBzdXIgbGUgZmljaGllciBkw6lwb3PDqS4KICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCJkcmFnb3ZlciIsIChlKSA9PiBlLnByZXZlbnREZWZhdWx0KCkpOwogICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gZS5wcmV2ZW50RGVmYXVsdCgpKTsKCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBJbXBvcnQgZGUgcmVsZXbDqSBiYW5jYWlyZSAoQ1NWIEJvdXJzb0JhbmspCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICAvLyBMZSBmaWNoaWVyIG4nZXN0IGphbWFpcyBnYXJkw6kgYXByw6hzIGwnYW5hbHlzZSAobmkgaWNpLCBuaSBjw7R0w6kKICAgIC8vIHNlcnZldXIpIDogc2V1bCBsZSB0YWJsZWF1IGBpbXBvcnRQcmV2aWV3Um93c2AgKGTDqWrDoCBkZXMgdHJhbnNhY3Rpb25zCiAgICAvLyBjYW5kaWRhdGVzLCBwYXMgbGUgZmljaGllciBicnV0KSB2aXQgZW4gbcOpbW9pcmUgbGUgdGVtcHMgZGUgbGEgcmV2dWUuCiAgICBsZXQgaW1wb3J0UHJldmlld1Jvd3MgPSBbXTsgLy8gW3sgLi4ucm93LCBzZWxlY3RlZDogYm9vbCB9XQogICAgbGV0IGltcG9ydENhdGVnb3J5TGFiZWxzID0geyBleHBlbnNlOiB7fSwgaW5jb21lOiB7fSB9OwogICAgY29uc3QgTUFYX0lNUE9SVF9GSUxFX1NJWkVfQllURVMgPSAzICogMTAyNCAqIDEwMjQ7IC8vIGRvaXQgcmVzdGVyIGFsaWduw6kgYXZlYyBsZSBiYWNrZW5kCgogICAgY29uc3QgaW1wb3J0RHJvcHpvbmVFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtZHJvcHpvbmUiKTsKICAgIGNvbnN0IGltcG9ydEZpbGVJbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtZmlsZS1pbnB1dCIpOwogICAgY29uc3QgaW1wb3J0QW5hbHl6ZUJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtYW5hbHl6ZS1idG4iKTsKICAgIGNvbnN0IGltcG9ydFN1bW1hcnlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtc3VtbWFyeSIpOwogICAgY29uc3QgaW1wb3J0UHJldmlld0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1wcmV2aWV3Iik7CiAgICBjb25zdCBpbXBvcnRSb3dzTGlzdEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1yb3dzLWxpc3QiKTsKICAgIGNvbnN0IGltcG9ydFNlbGVjdGVkQ291bnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtc2VsZWN0ZWQtY291bnQiKTsKCiAgICBmdW5jdGlvbiB1cGRhdGVJbXBvcnRTZWxlY3RlZENvdW50KCkgewogICAgICBjb25zdCBuID0gaW1wb3J0UHJldmlld1Jvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKS5sZW5ndGg7CiAgICAgIGltcG9ydFNlbGVjdGVkQ291bnRFbC50ZXh0Q29udGVudCA9IGAke259IHPDqWxlY3Rpb25uw6llJHtuID4gMSA/ICJzIiA6ICIifSBzdXIgJHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGh9YDsKICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1jb21taXQtYnRuIikuZGlzYWJsZWQgPSBuID09PSAwOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckltcG9ydFByZXZpZXcoKSB7CiAgICAgIGltcG9ydFJvd3NMaXN0RWwuaW5uZXJIVE1MID0gIiI7CiAgICAgIGZvciAoY29uc3Qgcm93IG9mIGltcG9ydFByZXZpZXdSb3dzKSB7CiAgICAgICAgY29uc3QgZWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJkaXYiKTsKICAgICAgICBlbC5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdyIgKyAocm93LnNlbGVjdGVkID8gIiIgOiAiIGV4Y2x1ZGVkIik7CgogICAgICAgIGNvbnN0IGNoZWNrYm94ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW5wdXQiKTsKICAgICAgICBjaGVja2JveC50eXBlID0gImNoZWNrYm94IjsKICAgICAgICBjaGVja2JveC5jaGVja2VkID0gcm93LnNlbGVjdGVkOwogICAgICAgIGNoZWNrYm94LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsKICAgICAgICAgIHJvdy5zZWxlY3RlZCA9IGNoZWNrYm94LmNoZWNrZWQ7CiAgICAgICAgICBlbC5jbGFzc0xpc3QudG9nZ2xlKCJleGNsdWRlZCIsICFyb3cuc2VsZWN0ZWQpOwogICAgICAgICAgdXBkYXRlSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgICAgIH0pOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tYWluIjsKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kZXNjIjsKICAgICAgICBjb25zdCBhbW91bnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudFNwYW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctYW1vdW50ICIgKyByb3cudHlwZTsKICAgICAgICBhbW91bnRTcGFuLnRleHRDb250ZW50ID0gKHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyAiLSIgOiAiKyIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHJvdy5hbW91bnQpOwogICAgICAgIGRlc2MuYXBwZW5kKChyb3cuZGVzY3JpcHRpb24gfHwgIiIpICsgIiDigJQgIik7CiAgICAgICAgZGVzYy5hcHBlbmRDaGlsZChhbW91bnRTcGFuKTsKCiAgICAgICAgY29uc3QgbWV0YSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1ldGEuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWV0YSI7CiAgICAgICAgbGV0IG1ldGFUZXh0ID0gYCR7cm93LmV4cGVuc2VfZGF0ZX0gwrcgJHtyb3cuYmFua19sYWJlbH1gOwogICAgICAgIGlmIChyb3cuaXNfaW50ZXJuYWxfdHJhbnNmZXIpIG1ldGFUZXh0ICs9ICIgwrcgdmlyZW1lbnQgaW50ZXJuZSI7CiAgICAgICAgbWV0YS50ZXh0Q29udGVudCA9IG1ldGFUZXh0OwogICAgICAgIGlmIChyb3cubGlrZWx5X2R1cGxpY2F0ZSkgewogICAgICAgICAgY29uc3QgZHVwU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICAgIGR1cFNwYW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctZHVwIjsKICAgICAgICAgIGR1cFNwYW4udGV4dENvbnRlbnQgPSAiIMK3IGTDqWrDoCBwcsOpc2VudGUgPyI7CiAgICAgICAgICBtZXRhLmFwcGVuZENoaWxkKGR1cFNwYW4pOwogICAgICAgIH0KCiAgICAgICAgbWFpbi5hcHBlbmRDaGlsZChkZXNjKTsKICAgICAgICBtYWluLmFwcGVuZENoaWxkKG1ldGEpOwoKICAgICAgICBjb25zdCBjYXRTZWxlY3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzZWxlY3QiKTsKICAgICAgICBjb25zdCBsYWJlbHMgPSByb3cudHlwZSA9PT0gImV4cGVuc2UiID8gaW1wb3J0Q2F0ZWdvcnlMYWJlbHMuZXhwZW5zZSA6IGltcG9ydENhdGVnb3J5TGFiZWxzLmluY29tZTsKICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIE9iamVjdC5lbnRyaWVzKGxhYmVscykpIHsKICAgICAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoIm9wdGlvbiIpOwogICAgICAgICAgb3B0LnZhbHVlID0gdmFsdWU7CiAgICAgICAgICBvcHQudGV4dENvbnRlbnQgPSBsYWJlbDsKICAgICAgICAgIGlmICh2YWx1ZSA9PT0gcm93LmNhdGVnb3J5KSBvcHQuc2VsZWN0ZWQgPSB0cnVlOwogICAgICAgICAgY2F0U2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgICAgfQogICAgICAgIGNhdFNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCJjaGFuZ2UiLCAoKSA9PiB7IHJvdy5jYXRlZ29yeSA9IGNhdFNlbGVjdC52YWx1ZTsgfSk7CgogICAgICAgIGVsLmFwcGVuZENoaWxkKGNoZWNrYm94KTsKICAgICAgICBlbC5hcHBlbmRDaGlsZChtYWluKTsKICAgICAgICBlbC5hcHBlbmRDaGlsZChjYXRTZWxlY3QpOwogICAgICAgIGltcG9ydFJvd3NMaXN0RWwuYXBwZW5kQ2hpbGQoZWwpOwogICAgICB9CiAgICAgIHVwZGF0ZUltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgIH0KCiAgICAvLyBHbGlzc2VyLWTDqXBvc2VyIGRpcmVjdGVtZW50IHN1ciBsYSBjYXJ0ZSAoZW4gcGx1cyBkdSBzw6lsZWN0ZXVyCiAgICAvLyBjbGFzc2lxdWUpIDogb24gcmVtcGxhY2UgbGVzIGZpY2hpZXJzIGRlIGwnaW5wdXQgdmlhIERhdGFUcmFuc2ZlciwKICAgIC8vIHBvdXIgcXVlIGxlIHJlc3RlIGR1IGZsdXggKGJvdXRvbiBBbmFseXNlcikgcmVzdGUgaW5jaGFuZ8OpLgogICAgaW1wb3J0RHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcmFnb3ZlciIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgaW1wb3J0RHJvcHpvbmVFbC5jbGFzc0xpc3QuYWRkKCJkcmFnLW92ZXIiKTsKICAgIH0pOwogICAgaW1wb3J0RHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcmFnbGVhdmUiLCAoKSA9PiB7CiAgICAgIGltcG9ydERyb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGltcG9ydERyb3B6b25lRWwuYWRkRXZlbnRMaXN0ZW5lcigiZHJvcCIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgaW1wb3J0RHJvcHpvbmVFbC5jbGFzc0xpc3QucmVtb3ZlKCJkcmFnLW92ZXIiKTsKICAgICAgY29uc3QgZmlsZSA9IGUuZGF0YVRyYW5zZmVyLmZpbGVzICYmIGUuZGF0YVRyYW5zZmVyLmZpbGVzWzBdOwogICAgICBpZiAoIWZpbGUpIHJldHVybjsKICAgICAgY29uc3QgZHQgPSBuZXcgRGF0YVRyYW5zZmVyKCk7CiAgICAgIGR0Lml0ZW1zLmFkZChmaWxlKTsKICAgICAgaW1wb3J0RmlsZUlucHV0LmZpbGVzID0gZHQuZmlsZXM7CiAgICB9KTsKCiAgICBpbXBvcnRBbmFseXplQnRuLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBmaWxlID0gaW1wb3J0RmlsZUlucHV0LmZpbGVzICYmIGltcG9ydEZpbGVJbnB1dC5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSB7IHNob3dUb2FzdCgiQ2hvaXNpcyBkJ2Fib3JkIHVuIGZpY2hpZXIgLmNzdiIsIHRydWUpOyByZXR1cm47IH0KICAgICAgaWYgKCFmaWxlLm5hbWUudG9Mb3dlckNhc2UoKS5lbmRzV2l0aCgiLmNzdiIpKSB7CiAgICAgICAgc2hvd1RvYXN0KCJTZXVscyBsZXMgZmljaGllcnMgLmNzdiBzb250IGFjY2VwdMOpcyBwb3VyIGwnaW5zdGFudCIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBpZiAoZmlsZS5zaXplID4gTUFYX0lNUE9SVF9GSUxFX1NJWkVfQllURVMpIHsKICAgICAgICBzaG93VG9hc3QoIkZpY2hpZXIgdHJvcCB2b2x1bWluZXV4ICgzIE1vIG1heGltdW0pIiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CgogICAgICBjb25zdCBvcmlnaW5hbFRleHQgPSBpbXBvcnRBbmFseXplQnRuLnRleHRDb250ZW50OwogICAgICBpbXBvcnRBbmFseXplQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgaW1wb3J0QW5hbHl6ZUJ0bi50ZXh0Q29udGVudCA9ICJBbmFseXNlIGVuIGNvdXJz4oCmIjsKICAgICAgaW1wb3J0U3VtbWFyeUVsLnN0eWxlLmRpc3BsYXkgPSAibm9uZSI7CiAgICAgIGltcG9ydFByZXZpZXdFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YSgpOwogICAgICAgIGZvcm1EYXRhLmFwcGVuZCgiZmlsZSIsIGZpbGUpOwogICAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKCIvYXBpL2ltcG9ydC9iYW5rLWNzdiIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgaGVhZGVyczogeyAiWC1BUEktS2V5IjogQVBJX0tFWSB9LAogICAgICAgICAgYm9keTogZm9ybURhdGEsCiAgICAgICAgfSk7CiAgICAgICAgaWYgKCFyZXMub2spIHsKICAgICAgICAgIGNvbnN0IGVyciA9IGF3YWl0IHJlcy5qc29uKCkuY2F0Y2goKCkgPT4gKHt9KSk7CiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoZXJyLmRldGFpbCB8fCBgw4ljaGVjIGRlIGwnYW5hbHlzZSAoJHtyZXMuc3RhdHVzfSlgKTsKICAgICAgICB9CiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAgICAgaW1wb3J0Q2F0ZWdvcnlMYWJlbHMgPSB7CiAgICAgICAgICBleHBlbnNlOiBkYXRhLmV4cGVuc2VfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICAgIGluY29tZTogZGF0YS5pbmNvbWVfY2F0ZWdvcmllcyB8fCB7fSwKICAgICAgICB9OwogICAgICAgIGltcG9ydFByZXZpZXdSb3dzID0gZGF0YS5yb3dzLm1hcCgocm93KSA9PiAoewogICAgICAgICAgLi4ucm93LAogICAgICAgICAgc2VsZWN0ZWQ6ICFyb3cuaXNfaW50ZXJuYWxfdHJhbnNmZXIgJiYgIXJvdy5saWtlbHlfZHVwbGljYXRlLAogICAgICAgIH0pKTsKCiAgICAgICAgbGV0IHN1bW1hcnkgPSBgPHN0cm9uZz4ke2ltcG9ydFByZXZpZXdSb3dzLmxlbmd0aH08L3N0cm9uZz4gb3DDqXJhdGlvbiR7aW1wb3J0UHJldmlld1Jvd3MubGVuZ3RoID4gMSA/ICJzIiA6ICIifSBkw6l0ZWN0w6llJHtpbXBvcnRQcmV2aWV3Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9YDsKICAgICAgICBpZiAoZGF0YS5hY2NvdW50X2JhbGFuY2UgIT0gbnVsbCkgewogICAgICAgICAgc3VtbWFyeSArPSBgIOKAlCBzb2xkZSBkdSBjb21wdGUgYXUgJHtkYXRhLmFjY291bnRfYmFsYW5jZV9kYXRlfSA6IDxzdHJvbmc+JHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoZGF0YS5hY2NvdW50X2JhbGFuY2UpfTwvc3Ryb25nPmA7CiAgICAgICAgfQogICAgICAgIGlmIChkYXRhLnNraXBwZWRfcm93cykgc3VtbWFyeSArPSBgICgke2RhdGEuc2tpcHBlZF9yb3dzfSBsaWduZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9IGlnbm9yw6llJHtkYXRhLnNraXBwZWRfcm93cyA+IDEgPyAicyIgOiAiIn0sIGlsbGlzaWJsZSR7ZGF0YS5za2lwcGVkX3Jvd3MgPiAxID8gInMiIDogIiJ9KWA7CiAgICAgICAgc3VtbWFyeSArPSAiLiBMZXMgdmlyZW1lbnRzIGludGVybmVzIGV0IGRvdWJsb25zIHByb2JhYmxlcyBzb250IGTDqWNvY2jDqXMgcGFyIGTDqWZhdXQg4oCUIHbDqXJpZmllIGF2YW50IGQnaW1wb3J0ZXIuIjsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuaW5uZXJIVE1MID0gc3VtbWFyeTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CiAgICAgICAgaW1wb3J0UHJldmlld0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgZXJyLm1lc3NhZ2UsIHRydWUpOwogICAgICB9IGZpbmFsbHkgewogICAgICAgIGltcG9ydEFuYWx5emVCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBpbXBvcnRBbmFseXplQnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiaW1wb3J0LXRvZ2dsZS1hbGwtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgICAgIGNvbnN0IGFueVNlbGVjdGVkID0gaW1wb3J0UHJldmlld1Jvd3Muc29tZSgocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGZvciAoY29uc3Qgcm93IG9mIGltcG9ydFByZXZpZXdSb3dzKSByb3cuc2VsZWN0ZWQgPSAhYW55U2VsZWN0ZWQ7CiAgICAgIHJlbmRlckltcG9ydFByZXZpZXcoKTsKICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtY29tbWl0LWJ0biIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBzZWxlY3RlZCA9IGltcG9ydFByZXZpZXdSb3dzLmZpbHRlcigocikgPT4gci5zZWxlY3RlZCk7CiAgICAgIGlmIChzZWxlY3RlZC5sZW5ndGggPT09IDApIHJldHVybjsKICAgICAgY29uc3Qgb2sgPSBhd2FpdCBzaG93Q29uZmlybSgKICAgICAgICBgSW1wb3J0ZXIgJHtzZWxlY3RlZC5sZW5ndGh9IHRyYW5zYWN0aW9uJHtzZWxlY3RlZC5sZW5ndGggPiAxID8gInMiIDogIiJ9ID8gVsOpcmlmaWUgYmllbiBsZXMgY2F0w6lnb3JpZXMgYXZhbnQgZGUgY29uZmlybWVyLmAKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1jb21taXQtYnRuIik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkltcG9ydCBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICAgIHJvd3M6IHNlbGVjdGVkLm1hcCgocikgPT4gKHsKICAgICAgICAgICAgZXhwZW5zZV9kYXRlOiByLmV4cGVuc2VfZGF0ZSwKICAgICAgICAgICAgdHlwZTogci50eXBlLAogICAgICAgICAgICBhbW91bnQ6IHIuYW1vdW50LAogICAgICAgICAgICBjYXRlZ29yeTogci5jYXRlZ29yeSwKICAgICAgICAgICAgZGVzY3JpcHRpb246IHIuZGVzY3JpcHRpb24sCiAgICAgICAgICB9KSksCiAgICAgICAgfTsKICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBhcGlGZXRjaCgiL2FwaS9pbXBvcnQvYmFuay1jc3YvY29tbWl0IiwgewogICAgICAgICAgbWV0aG9kOiAiUE9TVCIsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSwKICAgICAgICB9KTsKICAgICAgICBzaG93VG9hc3QoYCR7cmVzdWx0Lmluc2VydGVkfSB0cmFuc2FjdGlvbiR7cmVzdWx0Lmluc2VydGVkID4gMSA/ICJzIiA6ICIifSBpbXBvcnTDqWUke3Jlc3VsdC5pbnNlcnRlZCA+IDEgPyAicyIgOiAiIn1gKTsKICAgICAgICBpbXBvcnRQcmV2aWV3Um93cyA9IFtdOwogICAgICAgIGltcG9ydFByZXZpZXdFbC5jbGFzc0xpc3QuYWRkKCJoaWRkZW4iKTsKICAgICAgICBpbXBvcnRTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJub25lIjsKICAgICAgICBpbXBvcnRGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbFRleHQ7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIEltcG9ydCBnw6luw6lyaXF1ZSBwYXIgSUEgKHRvdXQgZmljaGllciAuY3N2Ly54bHN4LCBzdHJ1Y3R1cmUgcXVlbGNvbnF1ZSkKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIENvbW1lIHBvdXIgbCdpbXBvcnQgQm91cnNvQmFuaywgbGUgZmljaGllciBuJ2VzdCBqYW1haXMgZ2FyZMOpIGFwcsOocwogICAgLy8gbCdhbmFseXNlIDogc2V1bGVzIGxlcyB0cmFuc2FjdGlvbnMgY2FuZGlkYXRlcyBldCBsZXMgZ3JvdXBlcyBkZQogICAgLy8gcsOpY3VycmVuY2UgZMOpdGVjdMOpcyB2aXZlbnQgZW4gbcOpbW9pcmUgbGUgdGVtcHMgZGUgbGEgcmV2dWUuCiAgICBsZXQgZ2VuZXJpY0ltcG9ydFJvd3MgPSBbXTsgLy8gW3sgLi4ucm93LCBzZWxlY3RlZDogYm9vbCB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzID0gW107IC8vIFt7IC4uLmNhbmRpZGF0ZSwgZGVjaXNpb246ICJyZWN1cnJpbmcifCJjcmVkaXQifCJpZ25vcmUiLCBlbmRfZGF0ZSB9XQogICAgbGV0IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsgZXhwZW5zZToge30sIGluY29tZToge30gfTsKICAgIGNvbnN0IE1BWF9HRU5FUklDX0lNUE9SVF9GSUxFX1NJWkVfQllURVMgPSAzICogMTAyNCAqIDEwMjQ7IC8vIGFsaWduw6kgYXZlYyBsZSBiYWNrZW5kCgogICAgY29uc3QgZ2VuZXJpY0Ryb3B6b25lRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZHJvcHpvbmUiKTsKICAgIGNvbnN0IGdlbmVyaWNGaWxlSW5wdXQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtZmlsZS1pbnB1dCIpOwogICAgY29uc3QgZ2VuZXJpY0FuYWx5emVCdG4gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtYW5hbHl6ZS1idG4iKTsKICAgIGNvbnN0IGdlbmVyaWNTdW1tYXJ5RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc3VtbWFyeSIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ1NlY3Rpb25FbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctc2VjdGlvbiIpOwogICAgY29uc3QgZ2VuZXJpY1JlY3VycmluZ0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yZWN1cnJpbmctbGlzdCIpOwogICAgY29uc3QgZ2VuZXJpY1ByZXZpZXdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1wcmV2aWV3Iik7CiAgICBjb25zdCBnZW5lcmljUm93c0xpc3RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1yb3dzLWxpc3QiKTsKICAgIGNvbnN0IGdlbmVyaWNTZWxlY3RlZENvdW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtc2VsZWN0ZWQtY291bnQiKTsKCiAgICBjb25zdCBSRUNVUlJJTkdfQ0xBU1NJRklDQVRJT05fTEFCRUxTID0gewogICAgICByZWN1cnJpbmc6ICJSw6ljdXJyZW50ZSIsCiAgICAgIGNyZWRpdDogIkNyw6lkaXQgZW4gY291cnMiLAogICAgICBlbmRlZDogIkFycsOqdMOpZSIsCiAgICAgIHVuY2VydGFpbjogIsOAIGNvbmZpcm1lciIsCiAgICB9OwoKICAgIGZ1bmN0aW9uIHVwZGF0ZUdlbmVyaWNJbXBvcnRTZWxlY3RlZENvdW50KCkgewogICAgICBjb25zdCBuID0gZ2VuZXJpY0ltcG9ydFJvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKS5sZW5ndGg7CiAgICAgIGdlbmVyaWNTZWxlY3RlZENvdW50RWwudGV4dENvbnRlbnQgPSBgJHtufSBzw6lsZWN0aW9ubsOpZSR7biA+IDEgPyAicyIgOiAiIn0gc3VyICR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RofWA7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIikuZGlzYWJsZWQgPSBuID09PSAwOwogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRSZWN1cnJpbmdMaXN0KCkgewogICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmlubmVySFRNTCA9ICIiOwogICAgICBmb3IgKGNvbnN0IGNhbmQgb2YgZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlIiArIChjYW5kLm5lZWRzX2NvbmZpcm1hdGlvbiA/ICIgbmVlZHMtY29uZmlybWF0aW9uIiA6ICIiKTsKCiAgICAgICAgY29uc3QgaGVhZGVyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgaGVhZGVyLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLWhlYWRlciI7CiAgICAgICAgY29uc3QgbmFtZVNwYW4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgbmFtZVNwYW4udGV4dENvbnRlbnQgPSBjYW5kLm5hbWU7CiAgICAgICAgY29uc3QgdGFnU3BhbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNwYW4iKTsKICAgICAgICB0YWdTcGFuLmNsYXNzTmFtZSA9ICJyZWN1cnJpbmctY2FuZGlkYXRlLXRhZyAiICsgY2FuZC5jbGFzc2lmaWNhdGlvbjsKICAgICAgICB0YWdTcGFuLnRleHRDb250ZW50ID0gUkVDVVJSSU5HX0NMQVNTSUZJQ0FUSU9OX0xBQkVMU1tjYW5kLmNsYXNzaWZpY2F0aW9uXSB8fCBjYW5kLmNsYXNzaWZpY2F0aW9uOwogICAgICAgIGhlYWRlci5hcHBlbmRDaGlsZChuYW1lU3Bhbik7CiAgICAgICAgaGVhZGVyLmFwcGVuZENoaWxkKHRhZ1NwYW4pOwoKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWV0YS5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1tZXRhIjsKICAgICAgICBjb25zdCBsYWJlbHMgPSBjYW5kLnR5cGUgPT09ICJleHBlbnNlIiA/IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5leHBlbnNlIDogZ2VuZXJpY0ltcG9ydENhdGVnb3J5TGFiZWxzLmluY29tZTsKICAgICAgICBjb25zdCBjYXRMYWJlbCA9IGxhYmVsc1tjYW5kLmNhdGVnb3J5XSB8fCBjYW5kLmNhdGVnb3J5OwogICAgICAgIG1ldGEudGV4dENvbnRlbnQgPSBgJHtjdXJyZW5jeUZvcm1hdHRlci5mb3JtYXQoY2FuZC5hbW91bnQpfSBlbnZpcm9uIMK3ICR7Y2F0TGFiZWx9IMK3IHZ1ICR7Y2FuZC5tb250aHNfc2Vlbi5sZW5ndGh9IG1vaXMgKCR7Y2FuZC5tb250aHNfc2VlblswXX0g4oaSICR7Y2FuZC5tb250aHNfc2VlbltjYW5kLm1vbnRoc19zZWVuLmxlbmd0aCAtIDFdfSlgOwogICAgICAgIGlmIChjYW5kLmluc3RhbGxtZW50X2luZm8pIHsKICAgICAgICAgIG1ldGEudGV4dENvbnRlbnQgKz0gYCDCtyDDqWNow6lhbmNlICR7Y2FuZC5pbnN0YWxsbWVudF9pbmZvLmxhc3Rfc2Vlbn0vJHtjYW5kLmluc3RhbGxtZW50X2luZm8udG90YWx9LCAke2NhbmQuaW5zdGFsbG1lbnRfaW5mby5yZW1haW5pbmd9IHJlc3RhbnRlJHtjYW5kLmluc3RhbGxtZW50X2luZm8ucmVtYWluaW5nID4gMSA/ICJzIiA6ICIifWA7CiAgICAgICAgfQoKICAgICAgICBlbC5hcHBlbmRDaGlsZChoZWFkZXIpOwogICAgICAgIGVsLmFwcGVuZENoaWxkKG1ldGEpOwoKICAgICAgICBpZiAoY2FuZC5jbGFzc2lmaWNhdGlvbiAhPT0gImVuZGVkIikgewogICAgICAgICAgY29uc3QgY2hvaWNlUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBjaG9pY2VSb3cuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtY2hvaWNlIjsKICAgICAgICAgIGNvbnN0IG9wdGlvbnMgPSBbCiAgICAgICAgICAgIFsicmVjdXJyaW5nIiwgIlLDqWN1cnJlbnRlIChjb250aW51ZSkiXSwKICAgICAgICAgICAgWyJjcmVkaXQiLCAiQ3LDqWRpdCAoZGF0ZSBkZSBmaW4pIl0sCiAgICAgICAgICAgIFsiaWdub3JlIiwgIk5lIHBhcyByZW5kcmUgcsOpY3VycmVudGUiXSwKICAgICAgICAgIF07CiAgICAgICAgICBmb3IgKGNvbnN0IFt2YWx1ZSwgbGFiZWxdIG9mIG9wdGlvbnMpIHsKICAgICAgICAgICAgY29uc3QgbGJsID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgibGFiZWwiKTsKICAgICAgICAgICAgY29uc3QgcmFkaW8gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICByYWRpby50eXBlID0gInJhZGlvIjsKICAgICAgICAgICAgcmFkaW8ubmFtZSA9IGByZWN1cnJpbmctZGVjaXNpb24tJHtjYW5kLmdyb3VwX2lkfWA7CiAgICAgICAgICAgIHJhZGlvLnZhbHVlID0gdmFsdWU7CiAgICAgICAgICAgIHJhZGlvLmNoZWNrZWQgPSBjYW5kLmRlY2lzaW9uID09PSB2YWx1ZTsKICAgICAgICAgICAgcmFkaW8uYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgICAgIGNhbmQuZGVjaXNpb24gPSB2YWx1ZTsKICAgICAgICAgICAgICByZW5kZXJHZW5lcmljSW1wb3J0UmVjdXJyaW5nTGlzdCgpOwogICAgICAgICAgICB9KTsKICAgICAgICAgICAgbGJsLmFwcGVuZENoaWxkKHJhZGlvKTsKICAgICAgICAgICAgbGJsLmFwcGVuZChsYWJlbCk7CiAgICAgICAgICAgIGNob2ljZVJvdy5hcHBlbmRDaGlsZChsYmwpOwogICAgICAgICAgfQogICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2hvaWNlUm93KTsKCiAgICAgICAgICBpZiAoY2FuZC5kZWNpc2lvbiA9PT0gImNyZWRpdCIpIHsKICAgICAgICAgICAgY29uc3QgZW5kUm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICAgIGVuZFJvdy5jbGFzc05hbWUgPSAicmVjdXJyaW5nLWNhbmRpZGF0ZS1lbmRkYXRlIjsKICAgICAgICAgICAgY29uc3QgZW5kTGFiZWwgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICAgICAgICAgIGVuZExhYmVsLnRleHRDb250ZW50ID0gIkZpbiBlc3RpbcOpZSA6IjsKICAgICAgICAgICAgY29uc3QgZW5kSW5wdXQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgICAgICBlbmRJbnB1dC50eXBlID0gImRhdGUiOwogICAgICAgICAgICBlbmRJbnB1dC52YWx1ZSA9IGNhbmQuZW5kX2RhdGUgfHwgIiI7CiAgICAgICAgICAgIGVuZElucHV0LmFkZEV2ZW50TGlzdGVuZXIoImNoYW5nZSIsICgpID0+IHsgY2FuZC5lbmRfZGF0ZSA9IGVuZElucHV0LnZhbHVlOyB9KTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZExhYmVsKTsKICAgICAgICAgICAgZW5kUm93LmFwcGVuZENoaWxkKGVuZElucHV0KTsKICAgICAgICAgICAgZWwuYXBwZW5kQ2hpbGQoZW5kUm93KTsKICAgICAgICAgIH0KICAgICAgICB9IGVsc2UgewogICAgICAgICAgY29uc3QgZW5kZWROb3RlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgICBlbmRlZE5vdGUuY2xhc3NOYW1lID0gInJlY3VycmluZy1jYW5kaWRhdGUtbWV0YSI7CiAgICAgICAgICBlbmRlZE5vdGUudGV4dENvbnRlbnQgPSAiU2VtYmxlIHMnw6p0cmUgYXJyw6p0w6llIHRvdXRlIHNldWxlIOKAlCBpbXBvcnTDqWUgdGVsbGUgcXVlbGxlLCBhdWN1bmUgY2hhcmdlIHLDqWN1cnJlbnRlIGNyw6nDqWUuIjsKICAgICAgICAgIGVsLmFwcGVuZENoaWxkKGVuZGVkTm90ZSk7CiAgICAgICAgfQoKICAgICAgICBnZW5lcmljUmVjdXJyaW5nTGlzdEVsLmFwcGVuZENoaWxkKGVsKTsKICAgICAgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlbmRlckdlbmVyaWNJbXBvcnRQcmV2aWV3KCkgewogICAgICBnZW5lcmljUm93c0xpc3RFbC5pbm5lckhUTUwgPSAiIjsKICAgICAgZm9yIChjb25zdCByb3cgb2YgZ2VuZXJpY0ltcG9ydFJvd3MpIHsKICAgICAgICBjb25zdCBlbCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIGVsLmNsYXNzTmFtZSA9ICJpbXBvcnQtcm93IiArIChyb3cuc2VsZWN0ZWQgPyAiIiA6ICIgZXhjbHVkZWQiKTsKCiAgICAgICAgY29uc3QgY2hlY2tib3ggPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbnB1dCIpOwogICAgICAgIGNoZWNrYm94LnR5cGUgPSAiY2hlY2tib3giOwogICAgICAgIGNoZWNrYm94LmNoZWNrZWQgPSByb3cuc2VsZWN0ZWQ7CiAgICAgICAgY2hlY2tib3guYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4gewogICAgICAgICAgcm93LnNlbGVjdGVkID0gY2hlY2tib3guY2hlY2tlZDsKICAgICAgICAgIGVsLmNsYXNzTGlzdC50b2dnbGUoImV4Y2x1ZGVkIiwgIXJvdy5zZWxlY3RlZCk7CiAgICAgICAgICB1cGRhdGVHZW5lcmljSW1wb3J0U2VsZWN0ZWRDb3VudCgpOwogICAgICAgIH0pOwoKICAgICAgICBjb25zdCBtYWluID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgbWFpbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1tYWluIjsKICAgICAgICBjb25zdCBkZXNjID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICAgICAgZGVzYy5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kZXNjIjsKICAgICAgICBjb25zdCBhbW91bnRTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgIGFtb3VudFNwYW4uY2xhc3NOYW1lID0gImltcG9ydC1yb3ctYW1vdW50ICIgKyByb3cudHlwZTsKICAgICAgICBhbW91bnRTcGFuLnRleHRDb250ZW50ID0gKHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyAiLSIgOiAiKyIpICsgY3VycmVuY3lGb3JtYXR0ZXIuZm9ybWF0KHJvdy5hbW91bnQpOwogICAgICAgIGRlc2MuYXBwZW5kKChyb3cucmVjdXJyaW5nX2dyb3VwX2lkID8gIvCflIEgIiA6ICIiKSArIChyb3cuZGVzY3JpcHRpb24gfHwgIiIpICsgIiDigJQgIik7CiAgICAgICAgZGVzYy5hcHBlbmRDaGlsZChhbW91bnRTcGFuKTsKCiAgICAgICAgY29uc3QgbWV0YSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgICAgIG1ldGEuY2xhc3NOYW1lID0gImltcG9ydC1yb3ctbWV0YSI7CiAgICAgICAgbWV0YS50ZXh0Q29udGVudCA9IHJvdy5kYXRlX3ByZWNpc2lvbiA9PT0gImRheSIKICAgICAgICAgID8gYCR7cm93LmV4cGVuc2VfZGF0ZX0gwrcgJHtyb3cuc291cmNlX2xhYmVsfWAKICAgICAgICAgIDogYCR7cm93LmV4cGVuc2VfZGF0ZS5zbGljZSgwLCA3KX0gKGpvdXIgbm9uIHByw6ljaXPDqSkgwrcgJHtyb3cuc291cmNlX2xhYmVsfWA7CiAgICAgICAgaWYgKHJvdy5saWtlbHlfZHVwbGljYXRlKSB7CiAgICAgICAgICBjb25zdCBkdXBTcGFuID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgICAgICAgZHVwU3Bhbi5jbGFzc05hbWUgPSAiaW1wb3J0LXJvdy1kdXAiOwogICAgICAgICAgZHVwU3Bhbi50ZXh0Q29udGVudCA9ICIgwrcgZMOpasOgIHByw6lzZW50ZSA/IjsKICAgICAgICAgIG1ldGEuYXBwZW5kQ2hpbGQoZHVwU3Bhbik7CiAgICAgICAgfQoKICAgICAgICBtYWluLmFwcGVuZENoaWxkKGRlc2MpOwogICAgICAgIG1haW4uYXBwZW5kQ2hpbGQobWV0YSk7CgogICAgICAgIGNvbnN0IGNhdFNlbGVjdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoInNlbGVjdCIpOwogICAgICAgIGNvbnN0IGxhYmVscyA9IHJvdy50eXBlID09PSAiZXhwZW5zZSIgPyBnZW5lcmljSW1wb3J0Q2F0ZWdvcnlMYWJlbHMuZXhwZW5zZSA6IGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscy5pbmNvbWU7CiAgICAgICAgZm9yIChjb25zdCBbdmFsdWUsIGxhYmVsXSBvZiBPYmplY3QuZW50cmllcyhsYWJlbHMpKSB7CiAgICAgICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJvcHRpb24iKTsKICAgICAgICAgIG9wdC52YWx1ZSA9IHZhbHVlOwogICAgICAgICAgb3B0LnRleHRDb250ZW50ID0gbGFiZWw7CiAgICAgICAgICBpZiAodmFsdWUgPT09IHJvdy5jYXRlZ29yeSkgb3B0LnNlbGVjdGVkID0gdHJ1ZTsKICAgICAgICAgIGNhdFNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICAgIH0KICAgICAgICBjYXRTZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgKCkgPT4geyByb3cuY2F0ZWdvcnkgPSBjYXRTZWxlY3QudmFsdWU7IH0pOwoKICAgICAgICBlbC5hcHBlbmRDaGlsZChjaGVja2JveCk7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQobWFpbik7CiAgICAgICAgZWwuYXBwZW5kQ2hpbGQoY2F0U2VsZWN0KTsKICAgICAgICBnZW5lcmljUm93c0xpc3RFbC5hcHBlbmRDaGlsZChlbCk7CiAgICAgIH0KICAgICAgdXBkYXRlR2VuZXJpY0ltcG9ydFNlbGVjdGVkQ291bnQoKTsKICAgIH0KCiAgICBnZW5lcmljRHJvcHpvbmVFbC5hZGRFdmVudExpc3RlbmVyKCJkcmFnb3ZlciIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LmFkZCgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyYWdsZWF2ZSIsICgpID0+IHsKICAgICAgZ2VuZXJpY0Ryb3B6b25lRWwuY2xhc3NMaXN0LnJlbW92ZSgiZHJhZy1vdmVyIik7CiAgICB9KTsKICAgIGdlbmVyaWNEcm9wem9uZUVsLmFkZEV2ZW50TGlzdGVuZXIoImRyb3AiLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIGdlbmVyaWNEcm9wem9uZUVsLmNsYXNzTGlzdC5yZW1vdmUoImRyYWctb3ZlciIpOwogICAgICBjb25zdCBmaWxlID0gZS5kYXRhVHJhbnNmZXIuZmlsZXMgJiYgZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF07CiAgICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgICBjb25zdCBkdCA9IG5ldyBEYXRhVHJhbnNmZXIoKTsKICAgICAgZHQuaXRlbXMuYWRkKGZpbGUpOwogICAgICBnZW5lcmljRmlsZUlucHV0LmZpbGVzID0gZHQuZmlsZXM7CiAgICB9KTsKCiAgICBnZW5lcmljQW5hbHl6ZUJ0bi5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgZmlsZSA9IGdlbmVyaWNGaWxlSW5wdXQuZmlsZXMgJiYgZ2VuZXJpY0ZpbGVJbnB1dC5maWxlc1swXTsKICAgICAgaWYgKCFmaWxlKSB7IHNob3dUb2FzdCgiQ2hvaXNpcyBkJ2Fib3JkIHVuIGZpY2hpZXIgLmNzdiBvdSAueGxzeCIsIHRydWUpOyByZXR1cm47IH0KICAgICAgY29uc3QgbG93ZXJOYW1lID0gZmlsZS5uYW1lLnRvTG93ZXJDYXNlKCk7CiAgICAgIGlmICghbG93ZXJOYW1lLmVuZHNXaXRoKCIuY3N2IikgJiYgIWxvd2VyTmFtZS5lbmRzV2l0aCgiLnhsc3giKSkgewogICAgICAgIHNob3dUb2FzdCgiRm9ybWF0cyBhY2NlcHTDqXMgOiAuY3N2IG91IC54bHN4IiwgdHJ1ZSk7CiAgICAgICAgcmV0dXJuOwogICAgICB9CiAgICAgIGlmIChmaWxlLnNpemUgPiBNQVhfR0VORVJJQ19JTVBPUlRfRklMRV9TSVpFX0JZVEVTKSB7CiAgICAgICAgc2hvd1RvYXN0KCJGaWNoaWVyIHRyb3Agdm9sdW1pbmV1eCAoMyBNbyBtYXhpbXVtKSIsIHRydWUpOwogICAgICAgIHJldHVybjsKICAgICAgfQoKICAgICAgY29uc3Qgb3JpZ2luYWxUZXh0ID0gZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQ7CiAgICAgIGdlbmVyaWNBbmFseXplQnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgZ2VuZXJpY0FuYWx5emVCdG4udGV4dENvbnRlbnQgPSAiQW5hbHlzZSBlbiBjb3VycyAoSUEp4oCmIjsKICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICBnZW5lcmljUmVjdXJyaW5nU2VjdGlvbkVsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICBnZW5lcmljUHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICB0cnkgewogICAgICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgZm9ybURhdGEuYXBwZW5kKCJmaWxlIiwgZmlsZSk7CiAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goIi9hcGkvaW1wb3J0L2dlbmVyaWMiLCB7CiAgICAgICAgICBtZXRob2Q6ICJQT1NUIiwKICAgICAgICAgIGhlYWRlcnM6IHsgIlgtQVBJLUtleSI6IEFQSV9LRVkgfSwKICAgICAgICAgIGJvZHk6IGZvcm1EYXRhLAogICAgICAgIH0pOwogICAgICAgIGlmICghcmVzLm9rKSB7CiAgICAgICAgICBjb25zdCBlcnIgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGVyci5kZXRhaWwgfHwgYMOJY2hlYyBkZSBsJ2FuYWx5c2UgKCR7cmVzLnN0YXR1c30pYCk7CiAgICAgICAgfQogICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgIGdlbmVyaWNJbXBvcnRDYXRlZ29yeUxhYmVscyA9IHsKICAgICAgICAgIGV4cGVuc2U6IGRhdGEuZXhwZW5zZV9jYXRlZ29yaWVzIHx8IHt9LAogICAgICAgICAgaW5jb21lOiBkYXRhLmluY29tZV9jYXRlZ29yaWVzIHx8IHt9LAogICAgICAgIH07CiAgICAgICAgZ2VuZXJpY0ltcG9ydFJvd3MgPSBkYXRhLnJvd3MubWFwKChyb3cpID0+ICh7CiAgICAgICAgICAuLi5yb3csCiAgICAgICAgICBzZWxlY3RlZDogIXJvdy5saWtlbHlfZHVwbGljYXRlLAogICAgICAgIH0pKTsKICAgICAgICBnZW5lcmljSW1wb3J0Q2FuZGlkYXRlcyA9IChkYXRhLnJlY3VycmluZ19jYW5kaWRhdGVzIHx8IFtdKS5tYXAoKGNhbmQpID0+ICh7CiAgICAgICAgICAuLi5jYW5kLAogICAgICAgICAgZGVjaXNpb246IGNhbmQuY2xhc3NpZmljYXRpb24gPT09ICJjcmVkaXQiID8gImNyZWRpdCIgOiBjYW5kLmNsYXNzaWZpY2F0aW9uID09PSAiZW5kZWQiID8gImlnbm9yZSIgOiAicmVjdXJyaW5nIiwKICAgICAgICAgIGVuZF9kYXRlOiBjYW5kLnN1Z2dlc3RlZF9lbmRfZGF0ZSB8fCBudWxsLAogICAgICAgIH0pKTsKCiAgICAgICAgbGV0IHN1bW1hcnkgPSBgPHN0cm9uZz4ke2dlbmVyaWNJbXBvcnRSb3dzLmxlbmd0aH08L3N0cm9uZz4gb3DDqXJhdGlvbiR7Z2VuZXJpY0ltcG9ydFJvd3MubGVuZ3RoID4gMSA/ICJzIiA6ICIifSBkw6l0ZWN0w6llJHtnZW5lcmljSW1wb3J0Um93cy5sZW5ndGggPiAxID8gInMiIDogIiJ9IHBhciBsJ0lBYDsKICAgICAgICBjb25zdCB0b0NvbmZpcm0gPSBnZW5lcmljSW1wb3J0Q2FuZGlkYXRlcy5maWx0ZXIoKGMpID0+IGMubmVlZHNfY29uZmlybWF0aW9uKS5sZW5ndGg7CiAgICAgICAgaWYgKHRvQ29uZmlybSkgc3VtbWFyeSArPSBgIOKAlCA8c3Ryb25nPiR7dG9Db25maXJtfTwvc3Ryb25nPiBtb3RpZiR7dG9Db25maXJtID4gMSA/ICJzIiA6ICIifSBkZSByw6ljdXJyZW5jZSDDoCBjb25maXJtZXIgY2ktZGVzc291c2A7CiAgICAgICAgaWYgKGRhdGEud2FybmluZ3MgJiYgZGF0YS53YXJuaW5ncy5sZW5ndGgpIHsKICAgICAgICAgIHN1bW1hcnkgKz0gIjxicj4iICsgZGF0YS53YXJuaW5ncy5tYXAoKHcpID0+IGDimqDvuI8gJHt3fWApLmpvaW4oIjxicj4iKTsKICAgICAgICB9CiAgICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5pbm5lckhUTUwgPSBzdW1tYXJ5OwogICAgICAgIGdlbmVyaWNTdW1tYXJ5RWwuc3R5bGUuZGlzcGxheSA9ICJibG9jayI7CgogICAgICAgIGlmIChnZW5lcmljSW1wb3J0Q2FuZGlkYXRlcy5sZW5ndGgpIHsKICAgICAgICAgIGdlbmVyaWNSZWN1cnJpbmdTZWN0aW9uRWwuY2xhc3NMaXN0LnJlbW92ZSgiaGlkZGVuIik7CiAgICAgICAgICByZW5kZXJHZW5lcmljSW1wb3J0UmVjdXJyaW5nTGlzdCgpOwogICAgICAgIH0KICAgICAgICBnZW5lcmljUHJldmlld0VsLmNsYXNzTGlzdC5yZW1vdmUoImhpZGRlbiIpOwogICAgICAgIHJlbmRlckdlbmVyaWNJbXBvcnRQcmV2aWV3KCk7CiAgICAgIH0gY2F0Y2ggKGVycikgewogICAgICAgIHNob3dUb2FzdCgiRXJyZXVyIDogIiArIGVyci5tZXNzYWdlLCB0cnVlKTsKICAgICAgfSBmaW5hbGx5IHsKICAgICAgICBnZW5lcmljQW5hbHl6ZUJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIGdlbmVyaWNBbmFseXplQnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZ2VuZXJpYy1pbXBvcnQtdG9nZ2xlLWFsbC1idG4iKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICAgICAgY29uc3QgYW55U2VsZWN0ZWQgPSBnZW5lcmljSW1wb3J0Um93cy5zb21lKChyKSA9PiByLnNlbGVjdGVkKTsKICAgICAgZm9yIChjb25zdCByb3cgb2YgZ2VuZXJpY0ltcG9ydFJvd3MpIHJvdy5zZWxlY3RlZCA9ICFhbnlTZWxlY3RlZDsKICAgICAgcmVuZGVyR2VuZXJpY0ltcG9ydFByZXZpZXcoKTsKICAgIH0pOwoKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBhc3luYyAoKSA9PiB7CiAgICAgIGNvbnN0IHNlbGVjdGVkID0gZ2VuZXJpY0ltcG9ydFJvd3MuZmlsdGVyKChyKSA9PiByLnNlbGVjdGVkKTsKICAgICAgaWYgKHNlbGVjdGVkLmxlbmd0aCA9PT0gMCkgcmV0dXJuOwogICAgICBjb25zdCBvayA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgIGBJbXBvcnRlciAke3NlbGVjdGVkLmxlbmd0aH0gdHJhbnNhY3Rpb24ke3NlbGVjdGVkLmxlbmd0aCA+IDEgPyAicyIgOiAiIn0gPyBWw6lyaWZpZSBiaWVuIGxlcyBjYXTDqWdvcmllcyBldCBsZXMgcsOpY3VycmVuY2VzIGF2YW50IGRlIGNvbmZpcm1lci5gCiAgICAgICk7CiAgICAgIGlmICghb2spIHJldHVybjsKCiAgICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJnZW5lcmljLWltcG9ydC1jb21taXQtYnRuIik7CiAgICAgIGNvbnN0IG9yaWdpbmFsVGV4dCA9IGJ0bi50ZXh0Q29udGVudDsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIkltcG9ydCBlbiBjb3Vyc+KApiI7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgcmVjdXJyaW5nUGF5bG9hZCA9IGdlbmVyaWNJbXBvcnRDYW5kaWRhdGVzCiAgICAgICAgICAuZmlsdGVyKChjKSA9PiBjLmRlY2lzaW9uID09PSAicmVjdXJyaW5nIiB8fCBjLmRlY2lzaW9uID09PSAiY3JlZGl0IikKICAgICAgICAgIC5tYXAoKGMpID0+ICh7CiAgICAgICAgICAgIHR5cGU6IGMudHlwZSwKICAgICAgICAgICAgbmFtZTogYy5uYW1lLAogICAgICAgICAgICBhbW91bnQ6IGMuYW1vdW50LAogICAgICAgICAgICBjYXRlZ29yeTogYy5jYXRlZ29yeSwKICAgICAgICAgICAgZGF5X29mX21vbnRoOiAxLAogICAgICAgICAgICBzdGFydF9kYXRlOiBjLnN1Z2dlc3RlZF9zdGFydF9kYXRlLAogICAgICAgICAgICBlbmRfZGF0ZTogYy5kZWNpc2lvbiA9PT0gImNyZWRpdCIgPyAoYy5lbmRfZGF0ZSB8fCBudWxsKSA6IG51bGwsCiAgICAgICAgICB9KSk7CiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgICAgIHRyYW5zYWN0aW9uczogc2VsZWN0ZWQubWFwKChyKSA9PiAoewogICAgICAgICAgICBleHBlbnNlX2RhdGU6IHIuZXhwZW5zZV9kYXRlLAogICAgICAgICAgICB0eXBlOiByLnR5cGUsCiAgICAgICAgICAgIGFtb3VudDogci5hbW91bnQsCiAgICAgICAgICAgIGNhdGVnb3J5OiByLmNhdGVnb3J5LAogICAgICAgICAgICBkZXNjcmlwdGlvbjogci5kZXNjcmlwdGlvbiwKICAgICAgICAgIH0pKSwKICAgICAgICAgIHJlY3VycmluZzogcmVjdXJyaW5nUGF5bG9hZCwKICAgICAgICB9OwogICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IGFwaUZldGNoKCIvYXBpL2ltcG9ydC9nZW5lcmljL2NvbW1pdCIsIHsKICAgICAgICAgIG1ldGhvZDogIlBPU1QiLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocGF5bG9hZCksCiAgICAgICAgfSk7CiAgICAgICAgY29uc3QgcGFydHMgPSBbXTsKICAgICAgICBpZiAocmVzdWx0Lmluc2VydGVkX3RyYW5zYWN0aW9ucykgcGFydHMucHVzaChgJHtyZXN1bHQuaW5zZXJ0ZWRfdHJhbnNhY3Rpb25zfSB0cmFuc2FjdGlvbiR7cmVzdWx0Lmluc2VydGVkX3RyYW5zYWN0aW9ucyA+IDEgPyAicyIgOiAiIn1gKTsKICAgICAgICBpZiAocmVzdWx0Lmluc2VydGVkX3JlY3VycmluZykgcGFydHMucHVzaChgJHtyZXN1bHQuaW5zZXJ0ZWRfcmVjdXJyaW5nfSBjaGFyZ2Uke3Jlc3VsdC5pbnNlcnRlZF9yZWN1cnJpbmcgPiAxID8gInMiIDogIiJ9IHLDqWN1cnJlbnRlJHtyZXN1bHQuaW5zZXJ0ZWRfcmVjdXJyaW5nID4gMSA/ICJzIiA6ICIifWApOwogICAgICAgIHNob3dUb2FzdChwYXJ0cy5sZW5ndGggPyBgSW1wb3J0w6kgOiAke3BhcnRzLmpvaW4oIiBldCAiKX1gIDogIkltcG9ydCB0ZXJtaW7DqSIpOwogICAgICAgIGdlbmVyaWNJbXBvcnRSb3dzID0gW107CiAgICAgICAgZ2VuZXJpY0ltcG9ydENhbmRpZGF0ZXMgPSBbXTsKICAgICAgICBnZW5lcmljUHJldmlld0VsLmNsYXNzTGlzdC5hZGQoImhpZGRlbiIpOwogICAgICAgIGdlbmVyaWNSZWN1cnJpbmdTZWN0aW9uRWwuY2xhc3NMaXN0LmFkZCgiaGlkZGVuIik7CiAgICAgICAgZ2VuZXJpY1N1bW1hcnlFbC5zdHlsZS5kaXNwbGF5ID0gIm5vbmUiOwogICAgICAgIGdlbmVyaWNGaWxlSW5wdXQudmFsdWUgPSAiIjsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgbG9hZFJlY3VycmluZygpOwogICAgICB9IGNhdGNoIChlcnIpIHsKICAgICAgICBzaG93VG9hc3QoIkVycmV1ciA6ICIgKyBlcnIubWVzc2FnZSwgdHJ1ZSk7CiAgICAgIH0gZmluYWxseSB7CiAgICAgICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxUZXh0OwogICAgICB9CiAgICB9KTsKCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYnRuLXJlc2V0LWFsbCIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBvayA9IGF3YWl0IHNob3dDb25maXJtKAogICAgICAgICJTdXBwcmltZXIgRMOJRklOSVRJVkVNRU5UIHRvdXRlcyBsZXMgZG9ubsOpZXMgKHRyYW5zYWN0aW9ucywgY2hhcmdlcyByw6ljdXJyZW50ZXMsIGNhdMOpZ29yaWVzIHBlcnNvLCBidWRnZXRzLCBzdWdnZXN0aW9ucyBpZ25vcsOpZXMpID8gQ2V0dGUgYWN0aW9uIGVzdCBpcnLDqXZlcnNpYmxlLiIKICAgICAgKTsKICAgICAgaWYgKCFvaykgcmV0dXJuOwogICAgICAvLyBEb3VibGUgY29uZmlybWF0aW9uIHZ1IGxlIGNhcmFjdMOocmUgaXJyw6l2ZXJzaWJsZSBldCBjb21wbGV0IGRlIGwnYWN0aW9uLgogICAgICBjb25zdCBvazIgPSBhd2FpdCBzaG93Q29uZmlybSgiRGVybmnDqHJlIGNvbmZpcm1hdGlvbiA6IHZyYWltZW50IHRvdXQgcsOpaW5pdGlhbGlzZXIgPyIpOwogICAgICBpZiAoIW9rMikgcmV0dXJuOwoKICAgICAgY29uc3QgYnRuID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1yZXNldC1hbGwiKTsKICAgICAgYnRuLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgYnRuLnRleHRDb250ZW50ID0gIlLDqWluaXRpYWxpc2F0aW9uIGVuIGNvdXJz4oCmIjsKICAgICAgdHJ5IHsKICAgICAgICBhd2FpdCBhcGlGZXRjaCgiL2FwaS9yZXNldC1hbGwiLCB7IG1ldGhvZDogIkRFTEVURSIgfSk7CiAgICAgICAgc2hvd1RvYXN0KCJBcHBsaWNhdGlvbiByw6lpbml0aWFsaXPDqWUiKTsKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKSwgNjAwKTsKICAgICAgfSBjYXRjaCAoZXJyKSB7CiAgICAgICAgc2hvd1RvYXN0KCJFcnJldXIgOiAiICsgKGVyci5tZXNzYWdlIHx8ICJ1bmUgZXJyZXVyIGVzdCBzdXJ2ZW51ZSIpLCB0cnVlKTsKICAgICAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICBidG4udGV4dENvbnRlbnQgPSAiUsOpaW5pdGlhbGlzZXIgdG91dGUgbCdhcHBsaWNhdGlvbiI7CiAgICAgIH0KICAgIH0pOwoKICAgIC8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KICAgIC8vIFBXQSA6IGluc3RhbGxhdGlvbiBzdXIgbCfDqWNyYW4gZCdhY2N1ZWlsCiAgICAvLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiAgICBpZiAoInNlcnZpY2VXb3JrZXIiIGluIG5hdmlnYXRvcikgewogICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigibG9hZCIsICgpID0+IHsKICAgICAgICBuYXZpZ2F0b3Iuc2VydmljZVdvcmtlci5yZWdpc3RlcigiL3N3LmpzIikuY2F0Y2goKCkgPT4ge30pOwogICAgICB9KTsKICAgIH0KCiAgICBwb3B1bGF0ZUNhdGVnb3JpZXMoImV4cGVuc2UiKTsKICAgIHBvcHVsYXRlRmlsdGVyQ2F0ZWdvcnlPcHRpb25zKCk7CgogICAgLy8gUmllbiBkZSB0b3V0IMOnYSAoY2hhcmdlbWVudCBkZXMgZG9ubsOpZXMsIHJhY2NvdXJjaXMgUFdBLi4uKSBuZSBkb2l0CiAgICAvLyBkw6ltYXJyZXIgYXZhbnQgZCdhdm9pciB1biBqZXRvbiBkZSBzZXNzaW9uIHZhbGlkZSDigJQgc2lub24gbGEgcHJlbWnDqHJlCiAgICAvLyByZXF1w6p0ZSDDqWNob3VlcmFpdCBqdXN0ZSBhdmVjIHVuZSA0MDEgw6AgbGEgcGxhY2UgZGUgbW9udHJlciBsZSB2ZXJyb3UuCiAgICBpZiAoQVBJX0tFWSAmJiAhaW52aXRlVG9rZW5Gcm9tVXJsICYmICFyZXNldFRva2VuRnJvbVVybCkgewogICAgICBzaG93QXBwKCk7CiAgICAgIChhc3luYyBmdW5jdGlvbiBpbml0KCkgewogICAgICAgIC8vIENhdMOpZ29yaWVzIHBlcnNvICsgc3VnZ2VzdGlvbnMgaWdub3LDqWVzIGQnYWJvcmQsIHBvdXIgcXVlIGxlcwogICAgICAgIC8vIGxpc3RlcyBkw6lyb3VsYW50ZXMgZXQgbGUgYmFuZGVhdSBzb2llbnQgY29ycmVjdHMgZMOocyBsZSBwcmVtaWVyCiAgICAgICAgLy8gcmVuZHUgcGx1dMO0dCBxdWUgZGUgInNhdXRlciIgdW5lIGZvaXMgbGUgc2VydmV1ciByw6lwb25kdS4KICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChbbG9hZEN1c3RvbUNhdGVnb3JpZXMoKSwgbG9hZERpc21pc3NlZFN1Z2dlc3Rpb25zKCksIGxvYWRCdWRnZXRzKCksIGxvYWRTYXZpbmdzR29hbCgpXSk7CiAgICAgICAgcG9wdWxhdGVGaWx0ZXJDYXRlZ29yeU9wdGlvbnMoKTsKICAgICAgICBhd2FpdCBsb2FkVHJhbnNhY3Rpb25zKCk7CiAgICAgICAgbG9hZFJlY3VycmluZygpOwoKICAgICAgICAvLyBSYWNjb3VyY2lzIFBXQSAoYXBwdWkgbG9uZyBzdXIgbCdpY8O0bmUgZGUgbCdhcHAgdW5lIGZvaXMgaW5zdGFsbMOpZSkgOgogICAgICAgIC8vIC8/c2hvcnRjdXQ9YWRkIG91dnJlIGRpcmVjdGVtZW50IGxlIGZvcm11bGFpcmUgZCdham91dCwgLz9zaG9ydGN1dD12b2ljZQogICAgICAgIC8vIGxhbmNlIGRpcmVjdGVtZW50IGxhIGRpY3TDqWUgdm9jYWxlLgogICAgICAgIGNvbnN0IHNob3J0Y3V0UGFyYW0gPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpLmdldCgic2hvcnRjdXQiKTsKICAgICAgICBpZiAoc2hvcnRjdXRQYXJhbSkgewogICAgICAgICAgLy8gTmV0dG9pZSBsJ1VSTCB0b3V0IGRlIHN1aXRlIDogdW4gcmVjaGFyZ2VtZW50IGRlIGxhIHBhZ2UgKG91IHVuCiAgICAgICAgICAvLyBwYXJ0YWdlIGR1IGxpZW4pIG5lIGRvaXQgcGFzIHJlZMOpY2xlbmNoZXIgbGUgcmFjY291cmNpLgogICAgICAgICAgd2luZG93Lmhpc3RvcnkucmVwbGFjZVN0YXRlKHt9LCAiIiwgd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lKTsKICAgICAgICAgIGlmIChzaG9ydGN1dFBhcmFtID09PSAiYWRkIikgewogICAgICAgICAgICBvcGVuTW9kYWwoKTsKICAgICAgICAgIH0gZWxzZSBpZiAoc2hvcnRjdXRQYXJhbSA9PT0gInZvaWNlIiAmJiAhbWljQnRuLmRpc2FibGVkKSB7CiAgICAgICAgICAgIG1pY0J0bi5jbGljaygpOwogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfSkoKTsKICAgIH0gZWxzZSB7CiAgICAgIHNob3dMb2NrU2NyZWVuKGluaXRpYWxBdXRoVmlldyk7CiAgICB9CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
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
