#!/usr/bin/env python3
"""Construye la carpeta estática que GitHub Pages publicará."""
from pathlib import Path
import json
import re
import shutil

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"


def main():
    datos = json.loads((BASE / "datos.json").read_text(encoding="utf-8"))
    html = (BASE / "index.html").read_text(encoding="utf-8")
    semilla = json.dumps(datos, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    patron = r"const FALLBACK=.*?;\nlet D=FALLBACK;"
    reemplazo = f"const FALLBACK={semilla};\nlet D=FALLBACK;"
    html, n = re.subn(patron, reemplazo, html, count=1, flags=re.S)
    if n != 1:
        raise RuntimeError("No se encontró el bloque FALLBACK en index.html")

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir()
    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    shutil.copy2(BASE / "datos.json", PUBLIC / "datos.json")
    (PUBLIC / ".nojekyll").write_text("", encoding="utf-8")
    print(f"Sitio construido en {PUBLIC}")


if __name__ == "__main__":
    main()
