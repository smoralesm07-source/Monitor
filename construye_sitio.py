#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prepara la carpeta ``public`` para GitHub Pages.

Mantiene compatibilidad con el index.html existente, publica una copia ligera de
datos.json y agrega auditoria.html cuando está disponible.
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
AUDITORIA = BASE / "auditoria.html"

CAMPOS_PESADOS = ("texto_enriquecido",)
LIMITE_SEMILLA = 1_500_000
MAX_REGISTROS_SEMILLA = 600


def aligera(datos):
    ligero = dict(datos)
    for canal in ("prensa", "social"):
        registros = []
        for r in datos.get(canal, []) or []:
            registros.append({k: v for k, v in r.items() if k not in CAMPOS_PESADOS})
        ligero[canal] = registros
    # La auditoría necesita muestras, pero no cuerpos completos.
    ligero["candidatos_pendientes"] = (datos.get("candidatos_pendientes") or [])[:500]
    ligero["muestras_descartes"] = (datos.get("muestras_descartes") or [])[:100]
    return ligero


def recorta(datos, limite=LIMITE_SEMILLA):
    semilla = dict(datos)
    for tope in (MAX_REGISTROS_SEMILLA, 400, 250, 120):
        crudo = json.dumps(semilla, ensure_ascii=False, separators=(",", ":"))
        if len(crudo.encode("utf-8")) <= limite:
            return semilla, crudo
        semilla["prensa"] = (datos.get("prensa") or [])[:tope]
        semilla["social"] = (datos.get("social") or [])[:tope]
        semilla["semilla_recortada"] = True
    return semilla, json.dumps(semilla, ensure_ascii=False, separators=(",", ":"))


def inyecta_fallback(html, crudo):
    semilla = crudo.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    patrones = [
        r"const\s+FALLBACK\s*=\s*\{.*?\};",
        r"const\s+FALLBACK\s*=\s*.*?;\s*\n",
    ]
    reemplazo = "const FALLBACK=" + semilla + ";"
    for patron in patrones:
        nuevo, n = re.subn(patron, lambda _: reemplazo, html, count=1, flags=re.S)
        if n:
            return nuevo
    # El dashboard puede no tener semilla. En ese caso se deja intacto.
    return html


def main():
    if not ENTRADA.exists():
        sys.exit("No existe datos.json; ejecuta primero monitor_uaf.py")
    if not PLANTILLA.exists():
        sys.exit("No existe index.html; conserva el dashboard actual en la raíz")

    datos = json.loads(ENTRADA.read_text(encoding="utf-8"))
    html = PLANTILLA.read_text(encoding="utf-8")
    ligero = aligera(datos)
    _, crudo = recorta(ligero)
    html = inyecta_fallback(html, crudo)

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir(parents=True)
    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    (PUBLIC / "datos.json").write_text(
        json.dumps(ligero, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    if AUDITORIA.exists():
        shutil.copy2(AUDITORIA, PUBLIC / "auditoria.html")
    (PUBLIC / ".nojekyll").write_text("", encoding="utf-8")
    print(f"Sitio construido: {PUBLIC}")


if __name__ == "__main__":
    main()
