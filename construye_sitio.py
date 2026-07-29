#!/usr/bin/env python3
"""Construye la carpeta estática que GitHub Pages publicará."""
from pathlib import Path
import json
import shutil

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"


def main():
    datos = json.loads((BASE / "datos.json").read_text(encoding="utf-8"))
    html = (BASE / "index.html").read_text(encoding="utf-8")
    inicio = html.index("const SEMILLA = ")
    fin = html.index("\n\nconst NAT_COLOR", inicio)
    semilla = "const SEMILLA = " + json.dumps(datos, ensure_ascii=False, indent=1) + ";"
    html = html[:inicio] + semilla + html[fin:]

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir()
    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    shutil.copy2(BASE / "datos.json", PUBLIC / "datos.json")
    (PUBLIC / ".nojekyll").write_text("", encoding="utf-8")
    print(f"Sitio construido en {PUBLIC}")


if __name__ == "__main__":
    main()
