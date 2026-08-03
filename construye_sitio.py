#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construye la carpeta estática que GitHub Pages publicará.

Versión 1.0.3 compatible con el módulo complementario de entidades:
- conserva el comportamiento FALLBACK del monitor;
- reemplaza solamente la declaración FALLBACK, aunque D se inicialice más abajo;
- tolera espacios, saltos de línea y JSON con punto y coma dentro de cadenas;
- si la declaración no existe, la inserta antes de la primera referencia a FALLBACK;
- elimina texto_enriquecido del JSON público;
- copia entidades.html y auditoria.html cuando existen;
- agrega un acceso discreto al módulo de entidades.
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
        for registro in datos.get(canal, []) or []:
            if not isinstance(registro, dict):
                continue
            copia = {k: v for k, v in registro.items() if k not in CAMPOS_PESADOS}

            # La vista pública no necesita los fragmentos contextuales completos.
            if isinstance(copia.get("entidades"), list):
                entidades_ligeras = []
                for entidad in copia["entidades"]:
                    if not isinstance(entidad, dict):
                        continue
                    entidad_publica = {
                        k: v for k, v in entidad.items()
                        if k not in ("contextos", "evidencias")
                    }
                    if isinstance(entidad_publica.get("roles"), list):
                        entidad_publica["roles"] = [
                            {"rol": rol.get("rol")}
                            for rol in entidad_publica["roles"]
                            if isinstance(rol, dict) and rol.get("rol")
                        ]
                    entidades_ligeras.append(entidad_publica)
                copia["entidades"] = entidades_ligeras

            registros.append(copia)
        ligero[canal] = registros
    return ligero


def recorta(datos, limite=LIMITE_SEMILLA):
    """Reduce solo la copia FALLBACK si excede el tamaño permitido."""
    for tope in (MAX_REGISTROS_SEMILLA, 300, 180, 90):
        semilla = dict(datos)
        semilla["prensa"] = (datos.get("prensa") or [])[:tope]
        semilla["social"] = (datos.get("social") or [])[:tope]

        if (
            len(datos.get("prensa") or []) > tope
            or len(datos.get("social") or []) > tope
        ):
            semilla["semilla_recortada"] = True

        crudo = json.dumps(semilla, ensure_ascii=False, separators=(",", ":"))
        if len(crudo.encode("utf-8")) <= limite:
            return semilla, crudo

    return semilla, crudo


def _fin_objeto_javascript(texto: str, inicio: int) -> int | None:
    """Devuelve la posición posterior al objeto/arreglo JavaScript balanceado.

    FALLBACK es JSON válido incrustado en un script. El analizador controla
    cadenas y escapes para no confundirse con llaves o punto y coma dentro
    de títulos, resúmenes o URLs.
    """
    if inicio >= len(texto) or texto[inicio] not in "{[":
        return None

    pares = {"{": "}", "[": "]"}
    pila = [pares[texto[inicio]]]
    en_cadena = False
    comilla = ""
    escape = False

    for pos in range(inicio + 1, len(texto)):
        caracter = texto[pos]

        if en_cadena:
            if escape:
                escape = False
            elif caracter == "\\":
                escape = True
            elif caracter == comilla:
                en_cadena = False
            continue

        if caracter in ("'", '"', "`"):
            en_cadena = True
            comilla = caracter
        elif caracter in pares:
            pila.append(pares[caracter])
        elif caracter in ("}", "]"):
            if not pila or caracter != pila[-1]:
                return None
            pila.pop()
            if not pila:
                return pos + 1

    return None


def reemplaza_fallback(html: str, semilla: str) -> tuple[str, str]:
    """Actualiza FALLBACK sin asumir que `let D=FALLBACK` esté al lado."""

    declaracion = re.search(
        r"\b(?P<tipo>const|let|var)\s+FALLBACK\s*=\s*",
        html,
        flags=re.IGNORECASE,
    )

    if declaracion:
        inicio_valor = declaracion.end()
        while inicio_valor < len(html) and html[inicio_valor].isspace():
            inicio_valor += 1

        fin_valor = _fin_objeto_javascript(html, inicio_valor)
        if fin_valor is None:
            raise RuntimeError(
                "Se encontró la declaración FALLBACK, pero su objeto no pudo "
                "interpretarse como JSON/JavaScript balanceado."
            )

        return (
            html[:inicio_valor] + semilla + html[fin_valor:],
            "reemplazado",
        )

    # Compatibilidad con plantillas que usan FALLBACK pero no lo declaran.
    referencia_d = re.search(
        r"\b(?:let|const|var)\s+D\s*=\s*FALLBACK\b",
        html,
        flags=re.IGNORECASE,
    )
    if referencia_d:
        insercion = f"const FALLBACK={semilla};\n"
        return (
            html[:referencia_d.start()] + insercion + html[referencia_d.start():],
            "insertado-antes-de-D",
        )

    # Último respaldo: inserta la declaración al comienzo del primer script.
    apertura_script = re.search(r"<script\b[^>]*>", html, flags=re.IGNORECASE)
    if apertura_script:
        punto = apertura_script.end()
        insercion = f"\nconst FALLBACK={semilla};\n"
        return html[:punto] + insercion + html[punto:], "insertado-en-script"

    raise RuntimeError(
        "index.html no contiene una declaración FALLBACK ni una etiqueta <script> "
        "donde pueda incorporarse de forma segura."
    )


def agrega_acceso_entidades(html: str) -> str:
    if re.search(r'id\s*=\s*["\']entitiesModuleLink["\']', html, re.IGNORECASE):
        return html
    if not (BASE / "entidades.html").exists():
        return html

    acceso = """
<style id="entitiesModuleStyle">
#entitiesModuleLink{position:fixed;right:18px;bottom:18px;z-index:95;background:#062f43;color:#fff;text-decoration:none;border:1px solid #3b7382;border-radius:10px;padding:9px 12px;font:700 11px ui-sans-serif,system-ui;box-shadow:0 8px 22px rgba(6,47,67,.22)}
#entitiesModuleLink:hover{background:#087985}@media(max-width:700px){#entitiesModuleLink{right:10px;bottom:10px;padding:8px 10px}}
</style>
<a id="entitiesModuleLink" href="entidades.html" title="Explorar personas, organizaciones y coapariciones">Entidades y actores</a>
"""

    html_nuevo, cantidad = re.subn(
        r"</body\s*>",
        acceso + "\n</body>",
        html,
        count=1,
        flags=re.IGNORECASE,
    )
    if cantidad == 1:
        return html_nuevo

    # HTML incompleto: no aborta la publicación, pero conserva el acceso.
    return html + acceso


def main():
    if not ENTRADA.exists():
        sys.exit("No existe datos.json; ejecuta primero monitor_uaf.py")
    if not PLANTILLA.exists():
        sys.exit("No existe index.html")

    try:
        datos = json.loads(ENTRADA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"No fue posible leer datos.json: {exc}")

    try:
        html = PLANTILLA.read_text(encoding="utf-8")
    except OSError as exc:
        sys.exit(f"No fue posible leer index.html: {exc}")

    ligero = aligera(datos)
    _, crudo = recorta(ligero)

    # Evita que una cadena cierre accidentalmente la etiqueta <script>.
    semilla = (
        crudo.replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )

    try:
        html, estrategia = reemplaza_fallback(html, semilla)
    except RuntimeError as exc:
        sys.exit(str(exc))

    html = agrega_acceso_entidades(html)

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir(parents=True)

    (PUBLIC / "index.html").write_text(html, encoding="utf-8")
    (PUBLIC / "datos.json").write_text(
        json.dumps(ligero, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
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
    print(f"  FALLBACK: {estrategia}")
    print(
        f"  index.html: {peso_html:.0f} kB · "
        f"datos.json publicado: {peso_json:.0f} kB "
        f"(completo: {completo:.0f} kB)"
    )
    print(
        f"  registros: prensa={len(ligero.get('prensa', []))} "
        f"social={len(ligero.get('social', []))}"
    )
    print(
        "  módulo entidades: "
        f"{'sí' if (PUBLIC / 'entidades.html').exists() else 'no'}"
    )


if __name__ == "__main__":
    main()
