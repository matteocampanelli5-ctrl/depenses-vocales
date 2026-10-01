"""
Régénère l'embarquement base64 du frontend dans api/index.py.

Ce script est exécuté par Claude à chaque modification de frontend/index.html
— tu n'as pas besoin de le lancer toi-même. Il :
  1. lit frontend/index.html
  2. l'encode en base64
  3. remplace le contenu entre les marqueurs BEGIN_FRONTEND_B64 / END_FRONTEND_B64
     dans api/index.py
  4. vérifie que le base64 ré-décodé redonne EXACTEMENT le fichier source
     (pour ne jamais livrer un embarquement corrompu ou périmé)
"""

import base64
import re
from pathlib import Path

ROOT = Path(__file__).parent
FRONTEND_HTML = ROOT / "frontend" / "index.html"
API_INDEX = ROOT / "api" / "index.py"

MARKER_START = "# BEGIN_FRONTEND_B64"
MARKER_END = "# END_FRONTEND_B64"


def main() -> None:
    html = FRONTEND_HTML.read_text(encoding="utf-8")
    b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")

    source = API_INDEX.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END), re.DOTALL)
    if not pattern.search(source):
        raise SystemExit("Marqueurs BEGIN_FRONTEND_B64/END_FRONTEND_B64 introuvables dans api/index.py")

    replacement = f'{MARKER_START}\nFRONTEND_HTML_B64 = "{b64}"\n{MARKER_END}'
    API_INDEX.write_text(pattern.sub(replacement, source), encoding="utf-8")

    # Vérification anti-corruption : le base64 doit redonner le fichier source exact.
    roundtrip = base64.b64decode(b64).decode("utf-8")
    if roundtrip != html:
        raise SystemExit("ÉCHEC de vérification : le HTML ré-décodé ne correspond pas au fichier source !")

    print(f"OK — {len(html)} caractères HTML embarqués ({len(b64)} caractères en base64), vérification round-trip réussie.")


if __name__ == "__main__":
    main()
