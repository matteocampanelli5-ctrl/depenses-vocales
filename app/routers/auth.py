"""Comptes — inscription (sur invitation uniquement), connexion, mot de passe
oublié, vérification d'email, génération d'invitations."""

import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response

from app.config import API_SECRET_KEY
from app.db import get_supabase_client
from app.emails import _build_link, _send_email
from app.models import (
    ForgotPasswordRequest,
    InviteRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
)
from app.security import (
    _create_session_token,
    _enforce_login_lockout,
    _enforce_password_reset_lockout,
    _get_login_attempts_row,
    _get_password_reset_attempts_row,
    _hash_password,
    _hash_token,
    _new_token,
    _record_login_result,
    _record_password_reset_request,
    _verify_password,
    require_user,
)

router = APIRouter()


@router.post("/api/auth/signup", status_code=201)
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


@router.post("/api/auth/login")
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


@router.post("/api/auth/forgot-password")
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


@router.post("/api/auth/reset-password")
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


@router.get("/api/auth/verify-email")
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


@router.post("/api/auth/invite", status_code=201)
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
