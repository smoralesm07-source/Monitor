#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mide precisión y recall del reconocimiento contra un estándar anotado.

Compara la salida del módulo con una nómina de referencia construida a mano
sobre el corpus de prueba. Sirve para verificar que un cambio en las reglas o
en el léxico no degrade la calidad.

Uso:
    python benchmark_entidades.py --salida salida_v3.json
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path


def norm(texto: str) -> str:
    plano = unicodedata.normalize("NFKD", str(texto or ""))
    plano = "".join(c for c in plano if not unicodedata.combining(c)).casefold()
    return " ".join("".join(c if c.isalnum() else " " for c in plano).split())


# Estándar anotado manualmente sobre corpus_prueba.json.
# Clave: id del artículo -> {naturaleza -> {denominaciones esperadas}}
ORO: dict[str, dict[str, set[str]]] = {
    # --- corpus_holdout.json ---------------------------------------------
    # Anotado ANTES de ajustar las reglas contra él; los errores que expuso
    # (conector "y" uniendo entidades, cargos compuestos) quedan como
    # regresión permanente.
    "h1": {
        "PERSONA_NATURAL": {"Óscar Villablanca Ríos"},
        "PERSONA_JURIDICA": {
            "Enjoy Coquimbo S.A.", "Inmobiliaria Costanera del Elqui Ltda.",
            "Superintendencia de Casinos de Juego", "Unidad de Análisis Financiero",
            "Fundación Buen Vivir", "Juzgado de Letras de La Serena",
        },
    },
    "h2": {
        "PERSONA_NATURAL": {
            "Nelson Aravena Pinto", "Yasna Muñoz Carrasco",
            "Mario Carrera Guerrero",
        },
        "PERSONA_JURIDICA": {
            "Transportes Nortino SpA", "Comercial San Marcos Limitada",
            "Servicio Nacional de Aduanas", "Policía de Investigaciones de Chile",
            "Banco Falabella", "Andes Capital Partners",
        },
    },
    # --- corpus_prueba.json -----------------------------------------------
    "t1": {
        "PERSONA_NATURAL": {
            "Rodrigo Andrés Pizarro Meza", "Cristián Pizarro Meza",
            "Manuel Guerra Fuenzalida", "Juan Pablo Hermosilla",
        },
        "PERSONA_JURIDICA": {
            "Comercializadora Andes Sur SpA", "Inversiones Del Valle Limitada",
            "Agrícola El Peumo Ltda.", "Banco de Chile",
            "Ministerio Público / Fiscalía de Chile", "Fiscalía Oriente",
            "Unidad de Análisis Financiero", "Juzgado de Garantía de Santiago",
        },
    },
    "t2": {
        "PERSONA_NATURAL": {
            "Marcela Ortiz Vega", "Luis Alberto Fernández Cáceres", "Pedro Soto",
        },
        "PERSONA_JURIDICA": {
            "Importadora Tarapacá S.A.", "BancoEstado", "Scotiabank Chile",
            "Policía de Investigaciones de Chile", "Servicio Nacional de Aduanas",
            "Seremi de Hacienda", "Juzgado de Garantía de Iquique",
        },
    },
    "t3": {
        "PERSONA_NATURAL": {
            "Antonio Jalaff", "Álvaro Jalaff", "Daniel Sauer",
            "Rodrigo Topelberg", "Luis Hermosilla Osorio",
            "María Cecilia Pérez",
        },
        "PERSONA_JURIDICA": {
            "Factop SpA", "Sartor Finance Group", "Grupo Patio",
            "Sartor Administradora General de Fondos S.A.",
            "STF Capital Corredores de Bolsa S.A.",
            "Comisión para el Mercado Financiero",
            "Fiscalía Metropolitana Oriente",
        },
    },
    "t4": {
        "PERSONA_NATURAL": {"Sergio Muñoz Alarcón", "Cathy Barriga"},
        "PERSONA_JURIDICA": {
            "Consultora Gestión Local EIRL", "Servicios Integrales Maipú E.I.R.L.",
            "Municipalidad de Maipú", "Consejo de Defensa del Estado",
            "Tesorería General de la República",
            "Tribunal de Cuentas de la Contraloría General de la República",
        },
    },
    "t5": {
        "PERSONA_NATURAL": {"Jorge Alberto Castillo Rojas", "Karen Villalobos Núñez"},
        "PERSONA_JURIDICA": {
            "Minera Los Andes SpA", "Corte de Apelaciones de Antofagasta",
            "Tribunal Oral en lo Penal de Calama",
            "Ministerio Público / Fiscalía de Chile",
            "Policía de Investigaciones de Chile",
            "Unidad de Análisis Financiero",
        },
    },
}


def evalua(ruta: Path) -> int:
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    totales = {"tp": 0, "fp": 0, "fn": 0}
    por_naturaleza: dict[str, dict[str, int]] = {}

    for pub in datos.get("prensa", []):
        esperado = ORO.get(str(pub.get("id")))
        if not esperado:
            continue
        obtenido: dict[str, set[str]] = {"PERSONA_NATURAL": set(), "PERSONA_JURIDICA": set()}
        for ent in pub.get("entidades", []):
            nat = ent.get("naturaleza")
            if nat in obtenido:
                obtenido[nat].add(norm(ent.get("nombre_canonico", "")))

        print(f"\n{pub['id']}  {str(pub.get('titulo', ''))[:60]}")
        for nat in ("PERSONA_NATURAL", "PERSONA_JURIDICA"):
            ref = {norm(x) for x in esperado.get(nat, set())}
            got = obtenido[nat]
            tp, fp, fn = len(ref & got), len(got - ref), len(ref - got)
            totales["tp"] += tp
            totales["fp"] += fp
            totales["fn"] += fn
            acum = por_naturaleza.setdefault(nat, {"tp": 0, "fp": 0, "fn": 0})
            acum["tp"] += tp
            acum["fp"] += fp
            acum["fn"] += fn
            print(f"  {nat:17} TP={tp} FP={fp} FN={fn}")
            for falso in sorted(got - ref):
                print(f"      falso positivo : {falso}")
            for ausente in sorted(ref - got):
                print(f"      no detectado   : {ausente}")

    def metricas(d: dict[str, int]) -> tuple[float, float, float]:
        prec = d["tp"] / (d["tp"] + d["fp"]) if d["tp"] + d["fp"] else 0.0
        rec = d["tp"] / (d["tp"] + d["fn"]) if d["tp"] + d["fn"] else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return prec, rec, f1

    print("\n" + "=" * 62)
    for nat, d in sorted(por_naturaleza.items()):
        p, r, f = metricas(d)
        print(f"{nat:17}  precisión={p:.3f}  recall={r:.3f}  F1={f:.3f}")
    p, r, f = metricas(totales)
    print(f"{'GLOBAL':17}  precisión={p:.3f}  recall={r:.3f}  F1={f:.3f}")
    print(f"{'':17}  TP={totales['tp']}  FP={totales['fp']}  FN={totales['fn']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--salida", default="salida_v3.json",
                    help="datos.json ya enriquecido por modulo_entidades.py")
    args = ap.parse_args(argv)
    ruta = Path(args.salida)
    if not ruta.exists():
        print(f"No existe {ruta}", file=sys.stderr)
        return 1
    return evalua(ruta)


if __name__ == "__main__":
    raise SystemExit(main())
