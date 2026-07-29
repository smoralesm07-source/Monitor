#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construye la carpeta estática que GitHub Pages publicará.

v2 — cambios frente a la versión anterior:
  1. El `datos.json` que se publica es una versión ligera: se elimina
     `texto_enriquecido`, que el dashboard no usa y que puede pesar varios MB.
     El archivo completo sigue viviendo en la rama de estado, de modo que la
     reclasificación del histórico no pierde información.
  2. La semilla incrustada en index.html se inyecta con una función de
     reemplazo, para que ningún carácter del JSON se interprete como escape
     de expresión regular.
  3. Si la semilla resulta demasiado grande, se recorta automáticamente para
     no inflar el HTML.
"""

from pathlib import Path
import json
import re
import shutil
import sys

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"
ENTRADA = BASE / "datos.json"
PLANTILLA = BASE / "index.html"

# Campos que el dashboard no necesita y que solo agregan peso a la descarga.
CAMPOS_PESADOS = ("texto_enriquecido",)
LIMITE_SEMILLA = 1_200_000  # bytes de JSON incrustado en index.html
MAX_REGISTROS_SEMILLA = 500


def aligera(datos):
    ligero = dict(datos)
    for canal in ("prensa", "social"):
        registros = []
        for r in datos.get(canal, []) or []:
            copia = {k: v for k, v in r.items() if k not in CAMPOS_PESADOS}
            registros.append(copia)
        ligero[canal] = registros
    return ligero


def recorta(datos, limite=LIMITE_SEMILLA):
    """Reduce la semilla si excede el límite, conservando lo más reciente."""
    semilla = dict(datos)
    for tope in (MAX_REGISTROS_SEMILLA, 300, 180, 90):
        crudo = json.dumps(semilla, ensure_ascii=False, separators=(",", ":"))
        if len(crudo.encode("utf-8")) <= limite:
            return semilla, crudo
        semilla["prensa"] = (datos.get("prensa") or [])[:tope]
        semilla["social"] = (datos.get("social") or [])[:tope]
        semilla["semilla_recortada"] = True
    crudo = json.dumps(semilla, ensure_ascii=False, separators=(",", ":"))
    return semilla, crudo


def main():
    if not ENTRADA.exists():
        sys.exit("No existe datos.json; ejecuta primero monitor_uaf.py")
    if not PLANTILLA.exists():
        sys.exit("No existe index.html")

    datos = json.loads(ENTRADA.read_text(encoding="utf-8"))
    html = PLANTILLA.read_text(encoding="utf-8")

    ligero = aligera(datos)
    _, crudo = recorta(ligero)
    # `</` se escapa para que el JSON no cierre la etiqueta <script>.
    semilla = crudo.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    patron = re.compile(r"const FALLBACK=.*?;\nlet D=FALLBACK;", re.S)
    reemplazo = f"const FALLBACK={semilla};\nlet D=FALLBACK;"
    html, n = patron.subn(lambda _m: reemplazo, html, count=1)
    if n != 1:
        sys.exit("No se encontró el bloque FALLBACK en index.html")

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir(parents=True)
    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    (PUBLIC / "datos.json").write_text(
        json.dumps(ligero, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (PUBLIC / ".nojekyll").write_text("", encoding="utf-8")

    peso_html = (PUBLIC / "index.html").stat().st_size / 1024
    peso_json = (PUBLIC / "datos.json").stat().st_size / 1024
    completo = ENTRADA.stat().st_size / 1024
    print(f"Sitio construido en {PUBLIC}")
    print(f"  index.html: {peso_html:.0f} kB · datos.json publicado: {peso_json:.0f} kB "
          f"(archivo completo: {completo:.0f} kB)")
    print(f"  registros: prensa={len(ligero.get('prensa', []))} "
          f"social={len(ligero.get('social', []))}")


if __name__ == "__main__":
    main()
