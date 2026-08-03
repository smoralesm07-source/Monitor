#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Módulo complementario de reconocimiento de entidades para Monitor UAF Chile.

Lee las publicaciones ya aceptadas por ``monitor_uaf.py`` desde ``datos.json`` y
las enriquece con personas, organizaciones, empresas, organismos públicos,
lugares, montos y criptoactivos y roles textuales. No modifica la decisión
original de pertinencia UAF/LAFT.

Uso:
    python modulo_entidades.py
    python modulo_entidades.py --entrada datos.json --salida datos.json
    python modulo_entidades.py --modelo es_core_news_sm
    python modulo_entidades.py --solo-reglas   # respaldo sin modelo estadístico

La escritura es atómica: si falla el procesamiento, no deja un JSON parcial.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable

VERSION_MODULO = "1.0.1-entidades-hibridas-fix-dependencias"
BASE = Path(__file__).resolve().parent
DEFAULT_INPUT = BASE / "datos.json"
DEFAULT_CONFIG = BASE / "entidades_config.json"

TIPOS_PUBLICOS = {
    "PER": "PERSONA",
    "PERSON": "PERSONA",
    "ORG": "ORGANIZACION",
    "LOC": "LUGAR",
    "GPE": "LUGAR",
    "FAC": "LUGAR",
    "MONEY": "MONTO",
    "DATE": "FECHA",
    "ORGANISMO_PUBLICO": "ORGANISMO_PUBLICO",
    "EMPRESA": "EMPRESA",
    "INSTITUCION_FINANCIERA": "INSTITUCION_FINANCIERA",
    "CRIPTOACTIVO": "CRIPTOACTIVO",
    "RUT": "RUT",
    "MONTO": "MONTO",
    "LUGAR": "LUGAR",
    "PERSONA": "PERSONA",
}

TIPOS_PRIORIDAD = {
    "ORGANISMO_PUBLICO": 90,
    "INSTITUCION_FINANCIERA": 85,
    "EMPRESA": 80,
    "PERSONA": 75,
    "ORGANIZACION": 65,
    "LUGAR": 45,
    "CRIPTOACTIVO": 40,
    "RUT": 35,
    "MONTO": 25,
    "FECHA": 15,
    "OTRO": 5,
}

CAMPOS_TEXTO = (
    "titulo",
    "resumen",
    "contexto_uaf",
    "evidencia_uaf",
    "texto_enriquecido",
)

# Razones sociales chilenas y organizaciones con sufijo jurídico.
EMPRESA_RE = re.compile(
    r"\b(?:[A-ZÁÉÍÓÚÑ][\wÁÉÍÓÚÑáéíóúñ&.'’/-]*\s+){0,8}"
    r"(?:SpA|S\.A\.?|S\.A\.C\.?|S\.A\.G\.R\.?|Ltda\.?|Limitada|E\.I\.R\.L\.?|EIRL|"
    r"Sociedad por Acciones|Sociedad Anónima)\b",
    re.UNICODE,
)

RUT_RE = re.compile(r"\b(?:RUT\s*)?(\d{1,2}(?:\.\d{3}){2}-[\dkK]|\d{7,8}-[\dkK])\b")
MONTO_RE = re.compile(
    r"(?<!\w)(?:US\$|USD|\$|€|UF)\s?\d[\d.\s]*(?:,\d+)?(?:\s?(?:millones?|mil|MM))?",
    re.IGNORECASE,
)
CRIPTO_RE = re.compile(
    r"\b(?:bitcoin|btc|ethereum|ether|eth|tether|usdt|usdc|solana|sol|"
    r"binance|coinbase|exchange(?:s)?|criptoactivos?|criptomonedas?|wallets?|billeteras?\s+digitales?)\b",
    re.IGNORECASE,
)

ESPACIOS_RE = re.compile(r"\s+")


def normaliza(texto: str) -> str:
    texto = unicodedata.normalize("NFKD", str(texto or ""))
    texto = "".join(ch for ch in texto if not unicodedata.combining(ch))
    texto = texto.casefold()
    texto = re.sub(r"[^a-z0-9]+", " ", texto)
    return ESPACIOS_RE.sub(" ", texto).strip()


def limpia_nombre(texto: str) -> str:
    texto = ESPACIOS_RE.sub(" ", str(texto or "")).strip(" \t\r\n,.;:()[]{}«»\"'")
    # Evita guardar frases completas generadas por una coincidencia demasiado amplia.
    return texto[:180]


def id_entidad(tipo: str, canonico: str) -> str:
    base = f"{tipo}|{normaliza(canonico)}".encode("utf-8")
    return "ENT-" + hashlib.sha1(base).hexdigest()[:14].upper()


def carga_config(ruta: Path) -> dict[str, Any]:
    if not ruta.exists():
        return {"aliases": [], "patrones": [], "exclusiones": [], "roles": []}
    data = json.loads(ruta.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("entidades_config.json debe contener un objeto JSON")
    return data


def mapa_aliases(config: dict[str, Any]) -> dict[str, dict[str, str]]:
    salida: dict[str, dict[str, str]] = {}
    for item in config.get("aliases", []) or []:
        if not isinstance(item, dict):
            continue
        canonico = limpia_nombre(item.get("canonico", ""))
        tipo = str(item.get("tipo", "ORGANIZACION")).upper()
        if not canonico:
            continue
        variantes = [canonico, *(item.get("variantes", []) or [])]
        for variante in variantes:
            clave = normaliza(variante)
            if clave:
                salida[clave] = {"canonico": canonico, "tipo": tipo}
    return salida


def patrones_entity_ruler(config: dict[str, Any]) -> list[dict[str, Any]]:
    patrones: list[dict[str, Any]] = []
    for item in config.get("aliases", []) or []:
        if not isinstance(item, dict):
            continue
        canonico = limpia_nombre(item.get("canonico", ""))
        tipo = str(item.get("tipo", "ORGANIZACION")).upper()
        for variante in [canonico, *(item.get("variantes", []) or [])]:
            variante = limpia_nombre(variante)
            if variante:
                patrones.append({"label": tipo, "pattern": variante, "id": canonico})
    for item in config.get("patrones", []) or []:
        if isinstance(item, dict) and item.get("label") and item.get("pattern"):
            patrones.append(item)
    return patrones


def cargar_pipeline(modelo: str, config: dict[str, Any], solo_reglas: bool = False):
    try:
        import spacy
    except Exception as exc:
        raise RuntimeError(
            "No fue posible importar spaCy o alguna de sus dependencias. "
            "Ejecuta: pip install -r requirements_entidades.txt. "
            f"Detalle original: {type(exc).__name__}: {exc}"
        ) from exc

    usado = modelo
    estadistico = not solo_reglas
    if solo_reglas or modelo == "__blank__":
        nlp = spacy.blank("es")
        usado = "es_blank_reglas"
        estadistico = False
    else:
        try:
            # Se deshabilitan componentes que no aportan al NER para acelerar la corrida.
            nlp = spacy.load(modelo, disable=["parser", "lemmatizer", "morphologizer", "attribute_ruler"])
        except Exception as exc:
            print(
                f"::warning title=Modelo NER no disponible::No se pudo cargar {modelo}: {exc}. "
                "Se utilizará EntityRuler y reglas locales.",
                file=sys.stderr,
            )
            nlp = spacy.blank("es")
            usado = "es_blank_reglas"
            estadistico = False

    if "sentencizer" not in nlp.pipe_names and "senter" not in nlp.pipe_names and "parser" not in nlp.pipe_names:
        nlp.add_pipe("sentencizer")

    if "entity_ruler" in nlp.pipe_names:
        ruler = nlp.get_pipe("entity_ruler")
    else:
        kwargs: dict[str, Any] = {
            "config": {"overwrite_ents": True, "phrase_matcher_attr": "LOWER"}
        }
        if "ner" in nlp.pipe_names:
            kwargs["after"] = "ner"
        else:
            kwargs["last"] = True
        ruler = nlp.add_pipe("entity_ruler", **kwargs)
    pats = patrones_entity_ruler(config)
    if pats:
        ruler.add_patterns(pats)
    return nlp, usado, estadistico


def texto_publicacion(registro: dict[str, Any], max_chars: int) -> str:
    partes: list[str] = []
    vistos: set[str] = set()
    for campo in CAMPOS_TEXTO:
        valor = ESPACIOS_RE.sub(" ", str(registro.get(campo, "") or "")).strip()
        if not valor:
            continue
        clave = normaliza(valor[:1000])
        if clave in vistos:
            continue
        vistos.add(clave)
        partes.append(valor)
    return "\n\n".join(partes)[:max_chars]


def campo_origen(nombre: str, registro: dict[str, Any]) -> str:
    objetivo = normaliza(nombre)
    if not objetivo:
        return "desconocido"
    for campo in CAMPOS_TEXTO:
        if objetivo in normaliza(registro.get(campo, "")):
            return campo
    return "texto"


def encuentra_oracion(texto: str, inicio: int, fin: int, limite: int = 300) -> str:
    izq = max(texto.rfind(".", 0, inicio), texto.rfind("\n", 0, inicio), texto.rfind(";", 0, inicio))
    der_candidates = [x for x in (texto.find(".", fin), texto.find("\n", fin), texto.find(";", fin)) if x >= 0]
    der = min(der_candidates) + 1 if der_candidates else min(len(texto), fin + 180)
    fragmento = ESPACIOS_RE.sub(" ", texto[max(0, izq + 1):der]).strip()
    if len(fragmento) > limite:
        rel = max(0, inicio - (izq + 1))
        desde = max(0, rel - limite // 2)
        fragmento = fragmento[desde:desde + limite]
    return fragmento


def extrae_reglas(texto: str, incluir_rut: bool = False) -> list[dict[str, Any]]:
    hallazgos: list[dict[str, Any]] = []
    for match in EMPRESA_RE.finditer(texto):
        nombre = limpia_nombre(match.group(0))
        # Requiere al menos una palabra además del sufijo jurídico.
        if len(normaliza(nombre).split()) >= 2:
            hallazgos.append({
                "texto": nombre,
                "label": "EMPRESA",
                "inicio": match.start(),
                "fin": match.end(),
                "origen": "regla_sociedad_chilena",
            })
    if incluir_rut:
        for match in RUT_RE.finditer(texto):
            hallazgos.append({
                "texto": limpia_nombre(match.group(1)), "label": "RUT",
                "inicio": match.start(1), "fin": match.end(1), "origen": "regla_rut",
            })
    for match in MONTO_RE.finditer(texto):
        hallazgos.append({
            "texto": limpia_nombre(match.group(0)), "label": "MONTO",
            "inicio": match.start(), "fin": match.end(), "origen": "regla_monto",
        })
    for match in CRIPTO_RE.finditer(texto):
        hallazgos.append({
            "texto": limpia_nombre(match.group(0)), "label": "CRIPTOACTIVO",
            "inicio": match.start(), "fin": match.end(), "origen": "regla_cripto",
        })
    return hallazgos


def roles_para_entidad(
    texto: str,
    inicio: int,
    fin: int,
    tipo: str,
    config: dict[str, Any],
) -> list[dict[str, str]]:
    ventana = texto[max(0, inicio - 110):min(len(texto), fin + 110)]
    roles: list[dict[str, str]] = []
    for regla in config.get("roles", []) or []:
        if not isinstance(regla, dict) or not regla.get("patron") or not regla.get("rol"):
            continue
        tipos = {str(x).upper() for x in regla.get("tipos", []) or []}
        if tipos and tipo not in tipos:
            continue
        try:
            if re.search(str(regla["patron"]), ventana, re.IGNORECASE | re.UNICODE):
                roles.append({
                    "rol": str(regla["rol"]),
                    "evidencia": ESPACIOS_RE.sub(" ", ventana).strip()[:240],
                })
        except re.error:
            continue
    # Una misma regla puede aparecer dos veces por variantes.
    unicos: dict[str, dict[str, str]] = {}
    for rol in roles:
        unicos.setdefault(rol["rol"], rol)
    return list(unicos.values())[:5]


def canoniza(
    texto: str,
    tipo: str,
    aliases: dict[str, dict[str, str]],
) -> tuple[str, str, bool]:
    nombre = limpia_nombre(texto)
    clave = normaliza(nombre)
    if clave in aliases:
        item = aliases[clave]
        return item["canonico"], item["tipo"], True
    return nombre, tipo, False


def procesa_publicacion(
    registro: dict[str, Any],
    doc: Any,
    texto: str,
    config: dict[str, Any],
    aliases: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    exclusiones = {normaliza(x) for x in config.get("exclusiones", []) or []}
    minimo = int(config.get("minimo_caracteres", 3) or 3)
    max_entidades = int(config.get("max_entidades_por_publicacion", 40) or 40)

    candidatos: list[dict[str, Any]] = []
    for ent in getattr(doc, "ents", []):
        tipo = TIPOS_PUBLICOS.get(str(ent.label_).upper(), "OTRO")
        if tipo == "OTRO":
            continue
        origen = "diccionario_institucional" if getattr(ent, "ent_id_", "") else "modelo_estadistico"
        candidatos.append({
            "texto": limpia_nombre(ent.text),
            "label": tipo,
            "inicio": int(ent.start_char),
            "fin": int(ent.end_char),
            "origen": origen,
        })
    candidatos.extend(extrae_reglas(texto, bool(config.get("incluir_rut", False))))

    agrupadas: dict[tuple[str, str], dict[str, Any]] = {}
    for cand in candidatos:
        original = limpia_nombre(cand.get("texto", ""))
        if len(original) < minimo or normaliza(original) in exclusiones:
            continue
        tipo_inicial = TIPOS_PUBLICOS.get(str(cand.get("label", "")).upper(), str(cand.get("label", "OTRO")).upper())
        canonico, tipo, por_alias = canoniza(original, tipo_inicial, aliases)
        if tipo == "ORGANIZACION" and re.search(r"\b(?:spa|s\.a\.?|ltda\.?|eirl)\b", original, re.I):
            tipo = "EMPRESA"
        clave = (tipo, normaliza(canonico))
        if not clave[1]:
            continue
        inicio = int(cand.get("inicio", 0))
        fin = int(cand.get("fin", inicio + len(original)))
        contexto = encuentra_oracion(texto, inicio, fin)
        roles = roles_para_entidad(texto, inicio, fin, tipo, config)
        item = agrupadas.setdefault(clave, {
            "id": id_entidad(tipo, canonico),
            "texto": original,
            "nombre_canonico": canonico,
            "tipo": tipo,
            "origen_deteccion": set(),
            "menciones": 0,
            "variantes": set(),
            "roles": {},
            "contextos": [],
            "campos": set(),
            "confianza": "alta" if por_alias or str(cand.get("origen", "")).startswith("regla_") else "media",
        })
        item["menciones"] += 1
        item["variantes"].add(original)
        item["origen_deteccion"].add(str(cand.get("origen", "modelo_estadistico")))
        item["campos"].add(campo_origen(original, registro))
        if contexto and contexto not in item["contextos"] and len(item["contextos"]) < 2:
            item["contextos"].append(contexto)
        for rol in roles:
            item["roles"].setdefault(rol["rol"], rol)
        if por_alias:
            item["confianza"] = "alta"

    salida: list[dict[str, Any]] = []
    for item in agrupadas.values():
        item["origen_deteccion"] = sorted(item["origen_deteccion"])
        item["variantes"] = sorted(item["variantes"], key=lambda x: (-len(x), x.casefold()))
        item["roles"] = list(item["roles"].values())
        item["campos"] = sorted(item["campos"])
        salida.append(item)
    salida.sort(key=lambda x: (
        -TIPOS_PRIORIDAD.get(x["tipo"], 0),
        -int(x["menciones"]),
        x["nombre_canonico"].casefold(),
    ))
    return salida[:max_entidades]


def resumen_publicacion(entidades: list[dict[str, Any]]) -> dict[str, list[str]]:
    grupos = {
        "personas": [], "empresas": [], "organizaciones": [],
        "organismos_publicos": [], "instituciones_financieras": [],
        "lugares": [], "criptoactivos": [], "montos": [],
    }
    mapping = {
        "PERSONA": "personas", "EMPRESA": "empresas", "ORGANIZACION": "organizaciones",
        "ORGANISMO_PUBLICO": "organismos_publicos",
        "INSTITUCION_FINANCIERA": "instituciones_financieras",
        "LUGAR": "lugares", "CRIPTOACTIVO": "criptoactivos", "MONTO": "montos",
    }
    for entidad in entidades:
        grupo = mapping.get(entidad.get("tipo"))
        if grupo and entidad.get("nombre_canonico") not in grupos[grupo]:
            grupos[grupo].append(entidad["nombre_canonico"])
    return {k: v[:12] for k, v in grupos.items() if v}


def genera_agregados(prensa: list[dict[str, Any]], max_pares: int = 120) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    catalogo: dict[str, dict[str, Any]] = {}
    pares: dict[tuple[str, str], dict[str, Any]] = {}

    for pub in prensa:
        entidades = pub.get("entidades", []) or []
        ids_pub: list[str] = []
        for e in entidades:
            eid = str(e.get("id", ""))
            if not eid:
                continue
            ids_pub.append(eid)
            item = catalogo.setdefault(eid, {
                "id": eid,
                "nombre": e.get("nombre_canonico", e.get("texto", "")),
                "tipo": e.get("tipo", "OTRO"),
                "publicaciones": 0,
                "menciones": 0,
                "medios": set(),
                "primera_fecha": None,
                "ultima_fecha": None,
                "roles": Counter(),
            })
            item["publicaciones"] += 1
            item["menciones"] += int(e.get("menciones", 1) or 1)
            if pub.get("medio"):
                item["medios"].add(pub["medio"])
            fecha = str(pub.get("fecha", "") or "")[:10]
            if fecha:
                item["primera_fecha"] = min(item["primera_fecha"], fecha) if item["primera_fecha"] else fecha
                item["ultima_fecha"] = max(item["ultima_fecha"], fecha) if item["ultima_fecha"] else fecha
            for rol in e.get("roles", []) or []:
                if rol.get("rol"):
                    item["roles"][rol["rol"]] += 1

        # Coaparición: compartir publicación, no relación probada.
        ids_unicos = sorted(set(ids_pub))
        # Evita explosión combinatoria en artículos con listados muy extensos.
        ids_unicos = ids_unicos[:18]
        for a, b in combinations(ids_unicos, 2):
            key = (a, b)
            par = pares.setdefault(key, {
                "origen": a, "destino": b, "publicaciones_compartidas": 0,
                "ejemplos": [],
            })
            par["publicaciones_compartidas"] += 1
            if len(par["ejemplos"]) < 3:
                par["ejemplos"].append({
                    "id": pub.get("id"), "titulo": pub.get("titulo"),
                    "fecha": pub.get("fecha"), "link": pub.get("link"),
                })

    ranking: list[dict[str, Any]] = []
    for item in catalogo.values():
        item["medios"] = sorted(item["medios"])
        item["cantidad_medios"] = len(item["medios"])
        item["roles"] = [
            {"rol": rol, "apariciones": cantidad}
            for rol, cantidad in item["roles"].most_common(6)
        ]
        ranking.append(item)
    ranking.sort(key=lambda x: (-x["publicaciones"], -x["menciones"], x["nombre"].casefold()))

    coapariciones = sorted(
        pares.values(),
        key=lambda x: (-x["publicaciones_compartidas"], x["origen"], x["destino"]),
    )[:max_pares]
    return ranking, coapariciones


def atomic_json_dump(ruta: Path, data: dict[str, Any]) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=ruta.parent, prefix=ruta.name + ".", suffix=".tmp", delete=False
    ) as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
        temporal = Path(fh.name)
    os.replace(temporal, ruta)


def enriquecer(
    datos: dict[str, Any],
    nlp: Any,
    config: dict[str, Any],
    modelo_usado: str,
    estadistico: bool,
) -> dict[str, Any]:
    prensa = datos.get("prensa", []) or []
    if not isinstance(prensa, list):
        raise ValueError("datos.json: 'prensa' debe ser una lista")

    aliases = mapa_aliases(config)
    max_chars = int(config.get("max_texto_por_publicacion", 30_000) or 30_000)
    textos = [texto_publicacion(pub, max_chars) if isinstance(pub, dict) else "" for pub in prensa]
    errores: list[dict[str, Any]] = []

    # nlp.pipe reduce el costo de procesar cientos de publicaciones.
    docs = nlp.pipe(textos, batch_size=int(config.get("batch_size", 16) or 16))
    procesadas = 0
    con_entidades = 0
    total_entidades = 0
    for idx, (pub, texto, doc) in enumerate(zip(prensa, textos, docs)):
        if not isinstance(pub, dict):
            continue
        try:
            entidades = procesa_publicacion(pub, doc, texto, config, aliases)
            pub["entidades"] = entidades
            pub["entidades_resumen"] = resumen_publicacion(entidades)
            pub["entidades_version"] = VERSION_MODULO
            procesadas += 1
            if entidades:
                con_entidades += 1
                total_entidades += len(entidades)
        except Exception as exc:  # un artículo no debe anular todo el módulo
            pub["entidades"] = []
            pub["entidades_resumen"] = {}
            pub["entidades_error"] = f"{type(exc).__name__}: {exc}"[:300]
            errores.append({"indice": idx, "id": pub.get("id"), "error": pub["entidades_error"]})

    ranking, coapariciones = genera_agregados(prensa, int(config.get("max_coapariciones", 120) or 120))
    por_tipo = Counter(e.get("tipo", "OTRO") for pub in prensa for e in (pub.get("entidades", []) or []))
    ahora = datetime.now(timezone.utc).isoformat()
    datos["modulo_entidades"] = {
        "version": VERSION_MODULO,
        "generado": ahora,
        "modelo": modelo_usado,
        "usa_modelo_estadistico": bool(estadistico),
        "metodo": "hibrido_spacy_entityruler_reglas" if estadistico else "entityruler_reglas",
        "publicaciones_procesadas": procesadas,
        "publicaciones_con_entidades": con_entidades,
        "entidades_por_publicacion": total_entidades,
        "entidades_unicas": len(ranking),
        "conteo_por_tipo": dict(sorted(por_tipo.items())),
        "errores": errores[:30],
        "ranking": ranking,
        "coapariciones": coapariciones,
        "advertencia": (
            "Las entidades y roles son estimaciones automáticas. La coaparición en una publicación "
            "no acredita relación jurídica, comercial ni delictiva. Validar antes de uso institucional."
        ),
    }
    return datos


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Enriquece datos.json con reconocimiento de entidades")
    ap.add_argument("--entrada", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--salida", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--modelo", default=os.getenv("ENTIDADES_MODELO", "es_core_news_sm"))
    ap.add_argument("--solo-reglas", action="store_true", default=False)
    ap.add_argument("--validar", action="store_true", help="valida configuración y modelo sin modificar datos")
    return ap.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    salida = args.salida or args.entrada

    # La validación comprueba configuración y pipeline sin exigir datos.json.
    config = carga_config(args.config)
    nlp, modelo_usado, estadistico = cargar_pipeline(args.modelo, config, args.solo_reglas)
    if args.validar:
        print(f"Módulo válido: {VERSION_MODULO} · modelo={modelo_usado} · estadístico={estadistico}")
        return 0

    if not args.entrada.exists():
        print(f"No existe el archivo de entrada: {args.entrada}", file=sys.stderr)
        return 2
    datos = json.loads(args.entrada.read_text(encoding="utf-8"))
    if not isinstance(datos, dict):
        raise ValueError("datos.json debe contener un objeto JSON")
    enriquecer(datos, nlp, config, modelo_usado, estadistico)
    atomic_json_dump(salida, datos)
    meta = datos["modulo_entidades"]
    print(
        "Módulo de entidades listo: "
        f"{meta['publicaciones_procesadas']} publicaciones · "
        f"{meta['entidades_unicas']} entidades únicas · modelo={meta['modelo']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
