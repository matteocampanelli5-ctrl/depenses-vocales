"""
Régénère l'embarquement base64 du frontend (et des icônes PWA) dans
app/frontend_assets.py.

Ce script est exécuté par Claude à chaque modification de frontend/index.html
ou des icônes dans frontend/icons/ — tu n'as pas besoin de le lancer toi-même.
Il :
  1. lit frontend/index.html et les 3 PNG d'icônes
  2. les encode en base64
  3. remplace le contenu entre les marqueurs BEGIN_*_B64 / END_*_B64
     correspondants dans app/frontend_assets.py
  4. vérifie que chaque base64 ré-décodé redonne EXACTEMENT le fichier source
     (pour ne jamais livrer un embarquement corrompu ou périmé)
"""

import base64
import re
from pathlib import Path

ROOT = Path(__file__).parent
FRONTEND_HTML = ROOT / "frontend" / "index.html"
FRONTEND_ASSETS = ROOT / "app" / "frontend_assets.py"

ICON_FILES = {
    "ICON_192_B64": ROOT / "frontend" / "icons" / "icon-192.png",
    "ICON_512_B64": ROOT / "frontend" / "icons" / "icon-512.png",
    "ICON_512_MASKABLE_B64": ROOT / "frontend" / "icons" / "icon-512-maskable.png",
}

MARKER_START = "# BEGIN_FRONTEND_B64"
MARKER_END = "# END_FRONTEND_B64"


def replace_block(source: str, marker_start: str, marker_end: str, replacement: str) -> str:
    pattern = re.compile(re.escape(marker_start) + r".*?" + re.escape(marker_end), re.DOTALL)
    if not pattern.search(source):
        raise SystemExit(f"Marqueurs {marker_start}/{marker_end} introuvables dans app/frontend_assets.py")
    return pattern.sub(replacement, source)


def main() -> None:
    html = FRONTEND_HTML.read_text(encoding="utf-8")
    b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")

    source = FRONTEND_ASSETS.read_text(encoding="utf-8")
    replacement = f'{MARKER_START}\nFRONTEND_HTML_B64 = "{b64}"\n{MARKER_END}'
    source = replace_block(source, MARKER_START, MARKER_END, replacement)

    # Vérification anti-corruption : le base64 doit redonner le fichier source exact.
    roundtrip = base64.b64decode(b64).decode("utf-8")
    if roundtrip != html:
        raise SystemExit("ÉCHEC de vérification : le HTML ré-décodé ne correspond pas au fichier source !")

    icon_report = []
    for var_name, icon_path in ICON_FILES.items():
        icon_bytes = icon_path.read_bytes()
        icon_b64 = base64.b64encode(icon_bytes).decode("ascii")
        marker_start = f"# BEGIN_{var_name}"
        marker_end = f"# END_{var_name}"
        replacement = f'{marker_start}\n{var_name} = "{icon_b64}"\n{marker_end}'
        source = replace_block(source, marker_start, marker_end, replacement)

        if base64.b64decode(icon_b64) != icon_bytes:
            raise SystemExit(f"ÉCHEC de vérification : {var_name} ne correspond pas au fichier source !")
        icon_report.append(f"{icon_path.name} ({len(icon_bytes)} octets)")

    FRONTEND_ASSETS.write_text(source, encoding="utf-8")

    print(
        f"OK — {len(html)} caractères HTML embarqués ({len(b64)} caractères en base64), "
        f"vérification round-trip réussie. Icônes embarquées : {', '.join(icon_report)}."
    )


if __name__ == "__main__":
    main()
