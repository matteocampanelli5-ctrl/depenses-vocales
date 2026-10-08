"""Paquet applicatif de Kaching (API + frontend embarqué).

Ce paquet a été extrait de l'ancien fichier monolithique `api/index.py` (qui
reste le point d'entrée Vercel, voir ce fichier pour le détail). Les modules
sont organisés par responsabilité :
  - config.py          : configuration (variables d'environnement) et
                          constantes/helpers partagés
  - db.py               : client Supabase
  - security.py         : mots de passe, jetons de session, anti-brute-force
  - emails.py           : envoi d'emails transactionnels + alertes admin
  - models.py           : tous les modèles Pydantic
  - frontend_assets.py  : frontend embarqué en base64 (régénéré par build.py)
  - voice_nlp.py        : assistant vocal (analyse de dates/périodes, appels
                          Claude, calcul des réponses)
  - routers/            : un routeur FastAPI par domaine fonctionnel
"""
