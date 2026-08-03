#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construye la carpeta estática que GitHub Pages publicará.

Versión compatible con el módulo complementario de entidades:
- conserva el comportamiento FALLBACK del monitor;
- elimina texto_enriquecido del JSON público;
- copia entidades.html y auditoria.html cuando existen;
- agrega un acceso discreto al módulo de entidades en el monitor principal.
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

CAMPOS_PESADOS = ("texto_enriquecido",)
LIMITE_SEMILLA = 1_200_000
MAX_REGISTROS_SEMILLA = 500


def aligera(datos):
    ligero = dict(datos)
    for canal in ("prensa", "social"):
        registros = []
        for r in datos.get(canal, []) or []:
            copia = {k: v for k, v in r.items() if k not in CAMPOS_PESADOS}
            # La vista pública no necesita fragmentos contextuales completos.
            if isinstance(copia.get("entidades"), list):
                entidades_ligeras = []
                for entidad in copia["entidades"]:
                    if not isinstance(entidad, dict):
                        continue
                    e = {k: v for k, v in entidad.items() if k != "contextos"}
                    if isinstance(e.get("roles"), list):
                        e["roles"] = [
                            {"rol": rol.get("rol")}
                            for rol in e["roles"]
                            if isinstance(rol, dict) and rol.get("rol")
                        ]
                    entidades_ligeras.append(e)
                copia["entidades"] = entidades_ligeras
            registros.append(copia)
        ligero[canal] = registros
    return ligero


def recorta(datos, limite=LIMITE_SEMILLA):
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


def agrega_acceso_entidades(html: str) -> str:
    if "id=\"entitiesModuleLink\"" in html or not (BASE / "entidades.html").exists():
        return html
    acceso = """
<style id="entitiesModuleStyle">
#entitiesModuleLink{position:fixed;right:18px;bottom:18px;z-index:95;background:#062f43;color:#fff;text-decoration:none;border:1px solid #3b7382;border-radius:10px;padding:9px 12px;font:700 11px ui-sans-serif,system-ui;box-shadow:0 8px 22px rgba(6,47,67,.22)}
#entitiesModuleLink:hover{background:#087985}@media(max-width:700px){#entitiesModuleLink{right:10px;bottom:10px;padding:8px 10px}}
</style>
<a id="entitiesModuleLink" href="entidades.html" title="Explorar personas, organizaciones y coapariciones">Entidades y actores</a>
"""
    return html.replace("</body>", acceso + "\n</body>", 1)


def main():
    if not ENTRADA.exists():
        sys.exit("No existe datos.json; ejecuta primero monitor_uaf.py")
    if not PLANTILLA.exists():
        sys.exit("No existe index.html")

    datos = json.loads(ENTRADA.read_text(encoding="utf-8"))
    html = PLANTILLA.read_text(encoding="utf-8")
    ligero = aligera(datos)
    _, crudo = recorta(ligero)
    semilla = crudo.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    patron = re.compile(r"const FALLBACK=.*?;\nlet D=FALLBACK;", re.S)
    reemplazo = f"const FALLBACK={semilla};\nlet D=FALLBACK;"
    html, n = patron.subn(lambda _m: reemplazo, html, count=1)
    if n != 1:
        sys.exit("No se encontró el bloque FALLBACK en index.html")
    html = agrega_acceso_entidades(html)

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir(parents=True)
    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    (PUBLIC / "datos.json").write_text(
        json.dumps(ligero, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    for nombre in ("entidades.html", "auditoria.html"):
        origen = BASE / nombre
        if origen.exists():
            shutil.copy2(origen, PUBLIC / nombre)
    (PUBLIC / ".nojekyll").write_text("", encoding="utf-8")

    peso_html = (PUBLIC / "index.html").stat().st_size / 1024
    peso_json = (PUBLIC / "datos.json").stat().st_size / 1024
    completo = ENTRADA.stat().st_size / 1024
    print(f"Sitio construido en {PUBLIC}")
    print(f"  index.html: {peso_html:.0f} kB · datos.json publicado: {peso_json:.0f} kB (completo: {completo:.0f} kB)")
    print(f"  registros: prensa={len(ligero.get('prensa', []))} social={len(ligero.get('social', []))}")
    print(f"  módulo entidades: {'sí' if (PUBLIC / 'entidades.html').exists() else 'no'}")


if __name__ == "__main__":
    main()
