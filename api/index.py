"""
Point d'entrée unique de l'API (et du frontend) pour Vercel.

Ce fichier reste à ce chemin exact (api/index.py) et expose un objet FastAPI
`app` : c'est la convention attendue par l'adaptateur @vercel/python déclaré
dans vercel.json. Il ne fait plus lui-même le travail (routes, logique
métier) — c'est un point d'entrée mince qui assemble les routeurs définis
dans le paquet app/ (voir app/__init__.py pour le détail de l'organisation).

Le frontend embarqué en base64 (ex-section BEGIN_FRONTEND_B64 de ce fichier)
vit maintenant dans app/frontend_assets.py, régénéré par build.py — voir ce
module pour le détail, et build.py pour la génération.
"""

from fastapi import FastAPI, Request

from app.routers import (
    admin,
    auth,
    budgets,
    categories,
    export,
    imports,
    loans,
    recurring,
    savings,
    transactions,
    voice,
)
from app import frontend_assets

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


# ---------------------------------------------------------------------------
# Routeurs applicatifs — un par domaine fonctionnel (voir app/routers/).
# L'ordre d'inclusion n'a pas d'incidence fonctionnelle (chaque route a un
# chemin distinct), gardé proche de l'ordre d'origine dans le monolithe pour
# faciliter la relecture.
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(voice.router)
app.include_router(frontend_assets.router)
app.include_router(transactions.router)
app.include_router(recurring.router)
app.include_router(categories.router)
app.include_router(budgets.router)
app.include_router(savings.router)
app.include_router(loans.router)
app.include_router(export.router)
app.include_router(imports.router)
