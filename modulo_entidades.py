#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Análisis relacional de entidades para el Monitor UAF Chile.

Procesa exclusivamente publicaciones ya aceptadas por ``monitor_uaf.py`` y
construye una capa analítica auditable que vincula:

- entidades con artículos de prensa;
- entidades con fenómenos, delitos precedentes y sectores;
- entidades con territorios;
- entidades entre sí mediante relaciones textuales explícitas;
- artículos relacionados dentro de casos o eventos consolidados.

No determina culpabilidad ni reemplaza validación humana. Una asociación
contextual significa que una entidad aparece en una publicación clasificada en
un fenómeno; no prueba participación en ese fenómeno.

Uso:
    python modulo_entidades.py --entrada datos.json --salida datos.json
    python modulo_entidades.py --validar
    python modulo_entidades.py --solo-reglas
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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

try:
    import reconocedor_entidades as REC

    RECONOCEDOR_DISPONIBLE = True
except Exception as _exc_rec:  # pragma: no cover - degradación controlada
    REC = None
    RECONOCEDOR_DISPONIBLE = False
    print(
        "::warning title=Reconocedor v3 no disponible::"
        f"No se pudo importar reconocedor_entidades.py ({type(_exc_rec).__name__}: {_exc_rec}). "
        "Se usará el reconocimiento heredado v2.",
        file=sys.stderr,
    )

VERSION_MODULO = "3.0.0-personas-naturales-y-juridicas"
BASE = Path(__file__).resolve().parent
DEFAULT_INPUT = BASE / "datos.json"
DEFAULT_CONFIG = BASE / "entidades_config.json"

CAMPOS_TEXTO = (
    "titulo",
    "resumen",
    "contexto_uaf",
    "evidencia_uaf",
    "texto_enriquecido",
)

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
    "TRIBUNAL": "TRIBUNAL",
    "ENTIDAD_SIN_FINES_DE_LUCRO": "ENTIDAD_SIN_FINES_DE_LUCRO",
}

TIPOS_ENTIDAD_RELACIONAL = {
    "PERSONA",
    "EMPRESA",
    "ORGANIZACION",
    "ORGANISMO_PUBLICO",
    "INSTITUCION_FINANCIERA",
    "TRIBUNAL",
    "ENTIDAD_SIN_FINES_DE_LUCRO",
}

# Naturaleza jurídica: eje de clasificación de primer nivel solicitado para la
# nómina. Persona natural y persona jurídica se separan explícitamente.
NATURALEZA_POR_TIPO = {
    "PERSONA": "PERSONA_NATURAL",
    "EMPRESA": "PERSONA_JURIDICA",
    "INSTITUCION_FINANCIERA": "PERSONA_JURIDICA",
    "ORGANISMO_PUBLICO": "PERSONA_JURIDICA",
    "ORGANIZACION": "PERSONA_JURIDICA",
    "TRIBUNAL": "PERSONA_JURIDICA",
    "ENTIDAD_SIN_FINES_DE_LUCRO": "PERSONA_JURIDICA",
    "LUGAR": "NO_APLICA",
    "MONTO": "NO_APLICA",
    "FECHA": "NO_APLICA",
    "RUT": "NO_APLICA",
    "CRIPTOACTIVO": "NO_APLICA",
    "OTRO": "INDETERMINADA",
}

ETIQUETA_NATURALEZA = {
    "PERSONA_NATURAL": "Persona natural",
    "PERSONA_JURIDICA": "Persona jurídica",
    "NO_APLICA": "No aplica",
    "INDETERMINADA": "Indeterminada",
}


def naturaleza_de(tipo: Any) -> str:
    if RECONOCEDOR_DISPONIBLE:
        return REC.naturaleza_de(tipo)
    return NATURALEZA_POR_TIPO.get(str(tipo or "").upper(), "INDETERMINADA")


TIPOS_PRIORIDAD = {
    "PERSONA": 100,
    "EMPRESA": 95,
    "INSTITUCION_FINANCIERA": 92,
    "ORGANISMO_PUBLICO": 85,
    "TRIBUNAL": 84,
    "ENTIDAD_SIN_FINES_DE_LUCRO": 82,
    "ORGANIZACION": 80,
    "LUGAR": 60,
    "CRIPTOACTIVO": 50,
    "RUT": 35,
    "MONTO": 25,
    "FECHA": 10,
    "OTRO": 1,
}

ESPACIOS_RE = re.compile(r"\s+")
EMPRESA_RE = re.compile(
    r"\b(?:[A-ZÁÉÍÓÚÑ][\wÁÉÍÓÚÑáéíóúñ&.'’/-]*\s+){0,9}"
    r"(?:SpA|S\.A\.?|S\.A\.C\.?|S\.A\.G\.R\.?|Ltda\.?|Limitada|"
    r"E\.I\.R\.L\.?|EIRL|Sociedad por Acciones|Sociedad Anónima)\b",
    re.UNICODE,
)
RUT_RE = re.compile(r"\b(?:RUT\s*)?(\d{1,2}(?:\.\d{3}){2}-[\dkK]|\d{7,8}-[\dkK])\b")
MONTO_RE = re.compile(
    r"(?<!\w)(?:US\$|USD|CLP|\$|€|UF)\s?\d[\d.\s]*(?:,\d+)?(?:\s?(?:millones?|mil|MM))?",
    re.IGNORECASE,
)
CRIPTO_RE = re.compile(
    r"\b(?:bitcoin|btc|ethereum|ether|eth|tether|usdt|usdc|solana|sol|"
    r"binance|coinbase|exchange(?:s)?|criptoactivos?|criptomonedas?|"
    r"wallets?|billeteras?\s+digitales?)\b",
    re.IGNORECASE,
)

# Captura nombres propios cuando aparecen en contextos judiciales o societarios.
PERSONA_CONTEXTO_RE = re.compile(
    r"\b(?:formaliz(?:ó|o)\s+a|investiga(?:n)?\s+a|indaga(?:n)?\s+a|"
    r"detuv(?:o|ieron)\s+a|conden(?:ó|aron)\s+a|acus(?:ó|aron)\s+a|"
    r"imputad[oa]\s+|empresari[oa]\s+|abogad[oa]\s+|fiscal\s+|"
    r"representante\s+|apoderad[oa]\s+|gerente\s+|director(?:a)?\s+|"
    r"soci[oa]\s+|accionista\s+)"
    r"\s*([A-ZÁÉÍÓÚÑ][a-záéíóúñü'-]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñü'-]+){1,3})\b",
    re.UNICODE,
)

PERSONA_POSTROL_RE = re.compile(
    r"\b([A-ZÁÉÍÓÚÑ][a-záéíóúñü'-]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñü'-]+){1,3})"
    r"\s*,\s*(?:representante|apoderad[oa]|gerente|director(?:a)?|soci[oa]|accionista|"
    r"imputad[oa]|formalizad[oa]|investigad[oa]|abogad[oa]|fiscal)\b",
    re.UNICODE,
)

STOPWORDS_TITULO = {
    "de", "la", "el", "los", "las", "un", "una", "y", "en", "por", "para",
    "con", "del", "al", "que", "se", "su", "sus", "a", "ante", "sobre", "tras",
    "chile", "uaf", "unidad", "analisis", "financiero", "lavado", "activos",
}

CONF_ORDEN = {"baja": 1, "media": 2, "alta": 3}

# Configuración mínima/autocontenida. Se fusiona con entidades_config.json para
# impedir que una versión antigua desactive relaciones, roles o geografía.
CONFIG_BASE_INTERNA: dict[str, Any] = {'descripcion': 'Configuración relacional LA/FT con entidades, relaciones explícitas, roles y geografía de '
                'Chile.',
 'version': '2.1.1',
 'modelo_recomendado': 'es_core_news_sm',
 'max_texto_por_publicacion': 40000,
 'max_entidades_por_publicacion': 60,
 'max_relaciones_globales': 4500,
 'batch_size': 16,
 'minimo_caracteres': 3,
 'incluir_rut': True,
 'exclusiones': ['Chile',
                 'Gobierno',
                 'Estado',
                 'Región',
                 'lunes',
                 'martes',
                 'miércoles',
                 'jueves',
                 'viernes',
                 'sábado',
                 'domingo'],
 'aliases': [{'canonico': 'Unidad de Análisis Financiero',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['UAF', 'UAF Chile', 'Unidad de Analisis Financiero']},
             {'canonico': 'Ministerio Público / Fiscalía de Chile',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['Ministerio Público',
                            'Ministerio Publico',
                            'Fiscalía de Chile',
                            'Fiscalia de Chile',
                            'Fiscalía Nacional',
                            'Fiscalia Nacional']},
             {'canonico': 'Servicio de Impuestos Internos',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['SII', 'Servicio de Impuestos Internos']},
             {'canonico': 'Comisión para el Mercado Financiero',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['CMF',
                            'Comisión para el Mercado Financiero',
                            'Comision para el Mercado Financiero']},
             {'canonico': 'Servicio Nacional de Aduanas',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['Aduanas', 'Servicio Nacional de Aduanas']},
             {'canonico': 'Policía de Investigaciones de Chile',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['PDI', 'Policía de Investigaciones', 'Policia de Investigaciones']},
             {'canonico': 'Carabineros de Chile',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['Carabineros', 'Carabineros de Chile']},
             {'canonico': 'Tesorería General de la República',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['TGR', 'Tesorería General de la República', 'Tesoreria General de la Republica']},
             {'canonico': 'Superintendencia de Casinos de Juego',
              'tipo': 'ORGANISMO_PUBLICO',
              'variantes': ['SCJ', 'Superintendencia de Casinos de Juego']},
             {'canonico': 'Grupo de Acción Financiera',
              'tipo': 'ORGANIZACION',
              'variantes': ['GAFI', 'FATF', 'Grupo de Acción Financiera', 'Grupo de Accion Financiera']},
             {'canonico': 'GAFILAT',
              'tipo': 'ORGANIZACION',
              'variantes': ['GAFILAT',
                            'Grupo de Acción Financiera de Latinoamérica',
                            'Grupo de Accion Financiera de Latinoamerica']},
             {'canonico': 'Grupo Egmont',
              'tipo': 'ORGANIZACION',
              'variantes': ['Grupo Egmont', 'Egmont Group']},
             {'canonico': 'BancoEstado',
              'tipo': 'INSTITUCION_FINANCIERA',
              'variantes': ['BancoEstado', 'Banco Estado', 'Banco del Estado de Chile']}],
 'patrones': [{'label': 'ORGANISMO_PUBLICO',
               'pattern': [{'LOWER': 'fiscalía'}, {'LOWER': 'regional'}, {'IS_TITLE': True, 'OP': '+'}]},
              {'label': 'EMPRESA',
               'pattern': [{'LOWER': {'IN': ['inversiones', 'comercial', 'inmobiliaria', 'sociedad']}},
                           {'IS_TITLE': True, 'OP': '+'},
                           {'LOWER': {'IN': ['spa', 'ltda', 'eirl']}, 'OP': '?'}]}],
 'roles': [{'rol': 'investigado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
            'patron': '\\b(?:investigad[oa]|indagad[oa])s?\\b'},
           {'rol': 'imputado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bimputad[oa]s?\\b'},
           {'rol': 'formalizado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bformaliz(?:ó|o|ado|ada|ados|adas)\\b'},
           {'rol': 'acusado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bacusad[oa]s?\\b'},
           {'rol': 'condenado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bcondenad[oa]s?\\b'},
           {'rol': 'detenido', 'tipos': ['PERSONA'], 'patron': '\\bdetenid[oa]s?\\b'},
           {'rol': 'querellado',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bquerellad[oa]s?\\b'},
           {'rol': 'víctima',
            'tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\bvíctima(?:s)?\\b'},
           {'rol': 'representante', 'tipos': ['PERSONA'], 'patron': '\\b(?:representante|apoderad[oa])\\b'},
           {'rol': 'socio o accionista',
            'tipos': ['PERSONA'],
            'patron': '\\b(?:socio|socia|accionista)s?\\b'},
           {'rol': 'ejecutivo',
            'tipos': ['PERSONA'],
            'patron': '\\b(?:gerente|director|directora|ejecutivo|ejecutiva|presidente)\\b'},
           {'rol': 'fiscal', 'tipos': ['PERSONA'], 'patron': '\\bfiscal(?:es)?\\b'},
           {'rol': 'abogado', 'tipos': ['PERSONA'], 'patron': '\\babogad[oa]s?\\b'},
           {'rol': 'autoridad',
            'tipos': ['PERSONA'],
            'patron': '\\b(?:ministro|subsecretario|senador|diputado|director nacional|superintendente)\\b'},
           {'rol': 'querellante',
            'tipos': ['ORGANISMO_PUBLICO', 'EMPRESA', 'ORGANIZACION'],
            'patron': '\\b(?:presentó|interpuso|presenta|interpone).{0,35}querella\\b'}],
 'relaciones': [{'tipo': 'REPRESENTA_A',
                 'etiqueta': 'representa a',
                 'origen_tipos': ['PERSONA'],
                 'destino_tipos': ['EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:representante|apoderad[oa]|mandatari[oa])\\s+(?:de|del|la)\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 28},
                {'tipo': 'EJECUTIVO_DE',
                 'etiqueta': 'es ejecutivo de',
                 'origen_tipos': ['PERSONA'],
                 'destino_tipos': ['EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:gerente|director(?:a)?|presidente|ejecutiv[oa])\\s+(?:de|del|la)\\b|\\b(?:presidida|dirigida|administrada)\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 28},
                {'tipo': 'SOCIO_DE',
                 'etiqueta': 'es socio o accionista de',
                 'origen_tipos': ['PERSONA'],
                 'destino_tipos': ['EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:socio|socia|accionista|controlador(?:a)?|dueñ[oa]|propietari[oa])\\s+(?:de|del|la)\\b|\\b(?:controlada|propiedad)\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 28},
                {'tipo': 'INVESTIGA_A',
                 'etiqueta': 'investiga a',
                 'origen_tipos': ['ORGANISMO_PUBLICO'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:investiga|investigó|indaga|indagó|persigue|persiguió)\\s+(?:a|al|la|los|las)?\\b|\\b(?:investigad[oa]|indagad[oa])\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 18},
                {'tipo': 'FORMALIZA_A',
                 'etiqueta': 'formaliza a',
                 'origen_tipos': ['ORGANISMO_PUBLICO'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
                 'patron': '\\bformaliz(?:a|ó|o|aron)\\s+(?:a|al|la|los|las)?\\b|\\bformalizad[oa]s?\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 18},
                {'tipo': 'ACUSA_A',
                 'etiqueta': 'acusa a',
                 'origen_tipos': ['ORGANISMO_PUBLICO'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
                 'patron': '\\b(?:acusó|acusa|acusaron|imputó|imputa|imputaron)\\s+(?:a|al|la|los|las)?\\b|\\b(?:acusad[oa]|imputad[oa])s?\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 18},
                {'tipo': 'CONDENA_A',
                 'etiqueta': 'condena a',
                 'origen_tipos': ['ORGANISMO_PUBLICO'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION'],
                 'patron': '\\b(?:condenó|condena|condenaron)\\s+(?:a|al|la|los|las)?\\b|\\bcondenad[oa]s?\\s+por\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 18},
                {'tipo': 'QUERELLA_CONTRA',
                 'etiqueta': 'presenta querella contra',
                 'origen_tipos': ['ORGANISMO_PUBLICO', 'EMPRESA', 'ORGANIZACION', 'PERSONA'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:querella|se querelló|presentó querella|interpuso querella)\\s+(?:contra|en '
                           'contra de)\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta',
                 'max_distancia_destino': 18},
                {'tipo': 'TRANSACCION_ENTRE',
                 'etiqueta': 'registra transferencias u operaciones con',
                 'origen_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:transferencias?|transacciones?|depósitos?|giros?|pagos?|operaciones?)\\s+(?:a|hacia|desde|con|entre)\\b|\\b(?:transfirió|depositó|giró|pagó|recibió)\\b',
                 'ambito': 'entre',
                 'dirigida': False,
                 'confianza': 'media'},
                {'tipo': 'VINCULADO_CON',
                 'etiqueta': 'es vinculado o relacionado con',
                 'origen_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'destino_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'patron': '\\b(?:vinculad[oa]|relacionad[oa]|asociad[oa]|ligad[oa])s?\\s+(?:a|con)\\b',
                 'ambito': 'entre',
                 'dirigida': False,
                 'confianza': 'media'},
                {'tipo': 'UBICADA_EN',
                 'etiqueta': 'se ubica u opera en',
                 'origen_tipos': ['PERSONA', 'EMPRESA', 'ORGANIZACION', 'INSTITUCION_FINANCIERA'],
                 'destino_tipos': ['LUGAR'],
                 'patron': '\\b(?:domiciliad[oa]|ubicad[oa]|con '
                           'sede|operaba|funcionaba|residía|reside|radicad[oa])\\s+(?:en|desde)\\b',
                 'ambito': 'entre',
                 'dirigida': True,
                 'confianza': 'alta'}],
 'lugares': [{'nombre': 'Arica',
              'region': 'Arica y Parinacota',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -18.4783,
              'lon': -70.3126,
              'variantes': ['Región de Arica y Parinacota', 'Arica y Parinacota']},
             {'nombre': 'Iquique',
              'region': 'Tarapacá',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -20.2307,
              'lon': -70.1357,
              'variantes': ['Región de Tarapacá', 'Tarapacá']},
             {'nombre': 'Alto Hospicio',
              'region': 'Tarapacá',
              'pais': 'Chile',
              'nivel': 'comuna',
              'lat': -20.268,
              'lon': -70.102,
              'variantes': []},
             {'nombre': 'Antofagasta',
              'region': 'Antofagasta',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -23.6509,
              'lon': -70.3975,
              'variantes': ['Región de Antofagasta']},
             {'nombre': 'Calama',
              'region': 'Antofagasta',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -22.4567,
              'lon': -68.9237,
              'variantes': []},
             {'nombre': 'Copiapó',
              'region': 'Atacama',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -27.3668,
              'lon': -70.3323,
              'variantes': ['Copiapo', 'Región de Atacama', 'Atacama']},
             {'nombre': 'La Serena',
              'region': 'Coquimbo',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -29.9027,
              'lon': -71.2519,
              'variantes': ['Región de Coquimbo']},
             {'nombre': 'Coquimbo',
              'region': 'Coquimbo',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -29.9533,
              'lon': -71.3395,
              'variantes': []},
             {'nombre': 'Valparaíso',
              'region': 'Valparaíso',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -33.0472,
              'lon': -71.6127,
              'variantes': ['Valparaiso', 'Región de Valparaíso', 'Región de Valparaiso']},
             {'nombre': 'Viña del Mar',
              'region': 'Valparaíso',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -33.0153,
              'lon': -71.55,
              'variantes': ['Vina del Mar']},
             {'nombre': 'San Antonio',
              'region': 'Valparaíso',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -33.593,
              'lon': -71.6217,
              'variantes': []},
             {'nombre': 'Los Andes',
              'region': 'Valparaíso',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -32.8337,
              'lon': -70.5983,
              'variantes': []},
             {'nombre': 'Santiago',
              'region': 'Metropolitana de Santiago',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -33.4489,
              'lon': -70.6693,
              'variantes': ['Región Metropolitana', 'Region Metropolitana', 'Metropolitana']},
             {'nombre': 'Pudahuel',
              'region': 'Metropolitana de Santiago',
              'pais': 'Chile',
              'nivel': 'comuna',
              'lat': -33.437,
              'lon': -70.764,
              'variantes': []},
             {'nombre': 'Quilicura',
              'region': 'Metropolitana de Santiago',
              'pais': 'Chile',
              'nivel': 'comuna',
              'lat': -33.357,
              'lon': -70.729,
              'variantes': []},
             {'nombre': 'Maipú',
              'region': 'Metropolitana de Santiago',
              'pais': 'Chile',
              'nivel': 'comuna',
              'lat': -33.5106,
              'lon': -70.757,
              'variantes': ['Maipu']},
             {'nombre': 'Rancagua',
              'region': "O'Higgins",
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -34.1708,
              'lon': -70.7444,
              'variantes': ["Región de O'Higgins", "O'Higgins"]},
             {'nombre': 'Talca',
              'region': 'Maule',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -35.4264,
              'lon': -71.6554,
              'variantes': ['Región del Maule', 'Maule']},
             {'nombre': 'Curicó',
              'region': 'Maule',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -34.9828,
              'lon': -71.2394,
              'variantes': ['Curico']},
             {'nombre': 'Chillán',
              'region': 'Ñuble',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -36.6066,
              'lon': -72.1034,
              'variantes': ['Chillan', 'Región de Ñuble', 'Nuble', 'Ñuble']},
             {'nombre': 'Concepción',
              'region': 'Biobío',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -36.8201,
              'lon': -73.0444,
              'variantes': ['Concepcion', 'Región del Biobío', 'Biobio', 'Biobío']},
             {'nombre': 'Talcahuano',
              'region': 'Biobío',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -36.7249,
              'lon': -73.1168,
              'variantes': []},
             {'nombre': 'Los Ángeles',
              'region': 'Biobío',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -37.4697,
              'lon': -72.3537,
              'variantes': ['Los Angeles']},
             {'nombre': 'Temuco',
              'region': 'La Araucanía',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -38.7359,
              'lon': -72.5904,
              'variantes': ['Región de La Araucanía', 'La Araucania', 'Araucanía']},
             {'nombre': 'Valdivia',
              'region': 'Los Ríos',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -39.8196,
              'lon': -73.2452,
              'variantes': ['Región de Los Ríos', 'Los Rios']},
             {'nombre': 'Puerto Montt',
              'region': 'Los Lagos',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -41.4693,
              'lon': -72.9424,
              'variantes': ['Región de Los Lagos', 'Los Lagos']},
             {'nombre': 'Osorno',
              'region': 'Los Lagos',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -40.574,
              'lon': -73.1335,
              'variantes': []},
             {'nombre': 'Coyhaique',
              'region': 'Aysén',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -45.5752,
              'lon': -72.0662,
              'variantes': ['Coihaique', 'Región de Aysén', 'Aysen', 'Aysén']},
             {'nombre': 'Punta Arenas',
              'region': 'Magallanes',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -53.1638,
              'lon': -70.9171,
              'variantes': ['Región de Magallanes', 'Magallanes']},
             {'nombre': 'Puerto Natales',
              'region': 'Magallanes',
              'pais': 'Chile',
              'nivel': 'ciudad',
              'lat': -51.7262,
              'lon': -72.506,
              'variantes': []}],
 'schema_version': 2}


def normaliza(texto: Any) -> str:
    texto = unicodedata.normalize("NFKD", str(texto or ""))
    texto = "".join(ch for ch in texto if not unicodedata.combining(ch))
    texto = texto.casefold()
    texto = re.sub(r"[^a-z0-9]+", " ", texto)
    return ESPACIOS_RE.sub(" ", texto).strip()


def limpia_nombre(texto: Any, limite: int = 180) -> str:
    return ESPACIOS_RE.sub(" ", str(texto or "")).strip(" \t\r\n,.;:()[]{}«»\"'")[:limite]


def slug(texto: Any) -> str:
    return normaliza(texto).replace(" ", "-")[:90] or "sin-valor"


def id_estable(prefijo: str, *partes: Any, largo: int = 16) -> str:
    base = "|".join(normaliza(x) for x in partes).encode("utf-8")
    return f"{prefijo}-" + hashlib.sha1(base).hexdigest()[:largo].upper()


def id_entidad(tipo: str, canonico: str) -> str:
    return id_estable("ENT", tipo, canonico, largo=14)


def como_lista(valor: Any) -> list[Any]:
    if valor is None:
        return []
    if isinstance(valor, list):
        return valor
    if isinstance(valor, (tuple, set)):
        return list(valor)
    if isinstance(valor, str):
        return [valor] if valor.strip() else []
    return [valor]


def _clave_elemento_config(seccion: str, item: Any) -> str:
    if not isinstance(item, dict):
        return json.dumps(item, ensure_ascii=False, sort_keys=True)
    if seccion == "aliases":
        return f"{normaliza(item.get('canonico'))}|{str(item.get('tipo', '')).upper()}"
    if seccion == "lugares":
        return normaliza(item.get("nombre"))
    if seccion == "roles":
        return normaliza(item.get("rol"))
    if seccion == "relaciones":
        return str(item.get("tipo", "")).upper()
    if seccion == "patrones":
        return f"{str(item.get('label', '')).upper()}|{json.dumps(item.get('pattern'), ensure_ascii=False, sort_keys=True)}"
    return json.dumps(item, ensure_ascii=False, sort_keys=True)


def _fusiona_seccion_config(
    seccion: str,
    base: list[Any],
    usuario: list[Any],
) -> list[Any]:
    """Fusiona listas; el archivo del usuario reemplaza coincidencias puntuales.

    Una lista vacía en una configuración antigua no borra la base crítica.
    Esto evita que desaparezcan FORMALIZA_A, INVESTIGA_A o los territorios.
    """
    salida: dict[str, Any] = {}
    orden: list[str] = []
    for item in [*(base or []), *(usuario or [])]:
        clave = _clave_elemento_config(seccion, item)
        if clave not in salida:
            orden.append(clave)
        salida[clave] = item
    return [salida[k] for k in orden]


def completa_config(data: dict[str, Any] | None) -> dict[str, Any]:
    usuario = data if isinstance(data, dict) else {}
    # Copia profunda sin agregar una dependencia externa.
    base = json.loads(json.dumps(CONFIG_BASE_INTERNA, ensure_ascii=False))
    fusionada = {**base, **usuario}
    for seccion in ("aliases", "patrones", "exclusiones", "roles", "relaciones", "lugares"):
        fusionada[seccion] = _fusiona_seccion_config(
            seccion,
            list(base.get(seccion, []) or []),
            list(usuario.get(seccion, []) or []),
        )

    original_rel = len(usuario.get("relaciones", []) or [])
    original_lug = len(usuario.get("lugares", []) or [])
    original_ver = str(usuario.get("version", "sin-version"))
    fusionada["config_archivo_version"] = original_ver
    fusionada["config_completada_internamente"] = bool(
        original_rel < len(base.get("relaciones", []) or [])
        or original_lug < len(base.get("lugares", []) or [])
    )
    fusionada["version"] = str(base.get("version", "2.1.1"))

    # El reconocedor v3 aporta bancos, tribunales y organismos ausentes del
    # diccionario histórico, y habilita los tipos nuevos en las reglas
    # relacionales ya definidas.
    if RECONOCEDOR_DISPONIBLE:
        fusionada = REC.extiende_config(fusionada)
    return fusionada


def carga_config(ruta: Path) -> dict[str, Any]:
    if not ruta.exists():
        print(
            f"::warning title=Configuración de entidades ausente::No existe {ruta}; "
            "se utilizará la configuración interna v2.1.1.",
            file=sys.stderr,
        )
        return completa_config({})
    data = json.loads(ruta.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("entidades_config.json debe contener un objeto JSON")
    config = completa_config(data)
    if config.get("config_completada_internamente"):
        print(
            "::warning title=Configuración antigua completada::"
            f"entidades_config.json versión {config.get('config_archivo_version')} no contenía "
            "todas las relaciones o territorios v2; el módulo agregó la base interna.",
            file=sys.stderr,
        )
    return config


def mapa_aliases(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    salida: dict[str, dict[str, Any]] = {}
    for item in config.get("aliases", []) or []:
        if not isinstance(item, dict):
            continue
        canonico = limpia_nombre(item.get("canonico", ""))
        tipo = str(item.get("tipo", "ORGANIZACION")).upper()
        if not canonico:
            continue
        meta = {"canonico": canonico, "tipo": tipo}
        for variante in [canonico, *(item.get("variantes", []) or [])]:
            clave = normaliza(variante)
            if clave:
                salida[clave] = dict(meta)

    for lugar in config.get("lugares", []) or []:
        if not isinstance(lugar, dict):
            continue
        canonico = limpia_nombre(lugar.get("nombre", ""))
        if not canonico:
            continue
        meta = {
            "canonico": canonico,
            "tipo": "LUGAR",
            "geo": {
                "lat": lugar.get("lat"),
                "lon": lugar.get("lon"),
                "region": lugar.get("region") or canonico,
                "pais": lugar.get("pais", "Chile"),
                "nivel": lugar.get("nivel", "ciudad"),
            },
        }
        for variante in [canonico, *(lugar.get("variantes", []) or [])]:
            clave = normaliza(variante)
            if clave:
                salida[clave] = dict(meta)
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
    for lugar in config.get("lugares", []) or []:
        if not isinstance(lugar, dict):
            continue
        canonico = limpia_nombre(lugar.get("nombre", ""))
        for variante in [canonico, *(lugar.get("variantes", []) or [])]:
            variante = limpia_nombre(variante)
            if variante:
                patrones.append({"label": "LUGAR", "pattern": variante, "id": canonico})
    for item in config.get("patrones", []) or []:
        if isinstance(item, dict) and item.get("label") and item.get("pattern"):
            patrones.append(item)
    return patrones


def cargar_pipeline(modelo: str, config: dict[str, Any], solo_reglas: bool = False):
    try:
        import spacy
    except Exception as exc:
        raise RuntimeError(
            "No fue posible importar spaCy o alguna dependencia. "
            "Ejecuta: pip install -r requirements_entidades.txt. "
            f"Detalle: {type(exc).__name__}: {exc}"
        ) from exc

    usado = modelo
    estadistico = not solo_reglas
    if solo_reglas or modelo == "__blank__":
        nlp = spacy.blank("es")
        usado = "es_blank_reglas"
        estadistico = False
    else:
        try:
            nlp = spacy.load(
                modelo,
                disable=["parser", "lemmatizer", "morphologizer", "attribute_ruler"],
            )
        except Exception as exc:
            print(
                f"::warning title=Modelo NER no disponible::No se pudo cargar {modelo}: {exc}. "
                "Se utilizará EntityRuler y reglas locales.",
                file=sys.stderr,
            )
            nlp = spacy.blank("es")
            usado = "es_blank_reglas"
            estadistico = False

    if not any(x in nlp.pipe_names for x in ("sentencizer", "senter", "parser")):
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


def construye_texto(registro: dict[str, Any], max_chars: int) -> tuple[str, list[dict[str, Any]]]:
    partes: list[str] = []
    segmentos: list[dict[str, Any]] = []
    vistos: set[str] = set()
    cursor = 0
    for campo in CAMPOS_TEXTO:
        valor = ESPACIOS_RE.sub(" ", str(registro.get(campo, "") or "")).strip()
        if not valor:
            continue
        clave = normaliza(valor[:1200])
        if clave in vistos:
            continue
        vistos.add(clave)
        separador = "\n\n" if partes else ""
        cursor += len(separador)
        partes.append(separador + valor)
        segmentos.append({"campo": campo, "inicio": cursor, "fin": cursor + len(valor)})
        cursor += len(valor)
        if cursor >= max_chars:
            break
    texto = "".join(partes)[:max_chars]
    for seg in segmentos:
        seg["fin"] = min(seg["fin"], len(texto))
    return texto, segmentos


def campo_por_posicion(segmentos: list[dict[str, Any]], posicion: int) -> str:
    for seg in segmentos:
        if seg["inicio"] <= posicion <= seg["fin"]:
            return str(seg["campo"])
    return "texto"


def oraciones_con_offsets(texto: str) -> list[dict[str, Any]]:
    salida: list[dict[str, Any]] = []
    inicio = 0
    for match in re.finditer(r"(?:[.!?;]\s+|\n+)", texto):
        fin = match.end()
        frase = ESPACIOS_RE.sub(" ", texto[inicio:fin]).strip()
        if frase:
            salida.append({"inicio": inicio, "fin": fin, "texto": frase[:650]})
        inicio = fin
    if inicio < len(texto):
        frase = ESPACIOS_RE.sub(" ", texto[inicio:]).strip()
        if frase:
            salida.append({"inicio": inicio, "fin": len(texto), "texto": frase[:650]})
    return salida


def oracion_para_posicion(oraciones: list[dict[str, Any]], inicio: int, fin: int) -> dict[str, Any]:
    for idx, ora in enumerate(oraciones):
        if inicio < ora["fin"] and fin > ora["inicio"]:
            return {**ora, "indice": idx}
    return {"inicio": max(0, inicio - 120), "fin": fin + 180, "texto": "", "indice": -1}


def extrae_reglas(texto: str, incluir_rut: bool = False) -> list[dict[str, Any]]:
    """Extracción por reglas. Delega en el reconocedor v3 si está disponible."""
    if RECONOCEDOR_DISPONIBLE:
        return REC.extrae_reglas(texto, incluir_rut=incluir_rut)
    return _extrae_reglas_heredado(texto, incluir_rut)


def _extrae_reglas_heredado(texto: str, incluir_rut: bool = False) -> list[dict[str, Any]]:
    hallazgos: list[dict[str, Any]] = []
    for match in EMPRESA_RE.finditer(texto):
        nombre = limpia_nombre(match.group(0))
        if len(normaliza(nombre).split()) >= 2:
            hallazgos.append({
                "texto": nombre, "label": "EMPRESA", "inicio": match.start(),
                "fin": match.end(), "origen": "regla_sociedad_chilena",
            })
    for match in PERSONA_CONTEXTO_RE.finditer(texto):
        nombre = limpia_nombre(match.group(1))
        cola = texto[match.end(1):match.end(1) + 12]
        parece_empresa = (
            normaliza(nombre).split()[:1] and normaliza(nombre).split()[0] in
            {"inversiones", "comercial", "inmobiliaria", "sociedad", "banco", "fundacion"}
        ) or re.match(r"\s*(?:SpA|S\.A\.?|Ltda\.?|EIRL|E\.I\.R\.L\.?)\b", cola, re.I)
        if 2 <= len(nombre.split()) <= 4 and not parece_empresa:
            hallazgos.append({
                "texto": nombre, "label": "PERSONA", "inicio": match.start(1),
                "fin": match.end(1), "origen": "regla_persona_contextual",
            })
    for match in PERSONA_POSTROL_RE.finditer(texto):
        nombre = limpia_nombre(match.group(1))
        if 2 <= len(nombre.split()) <= 4:
            hallazgos.append({
                "texto": nombre, "label": "PERSONA", "inicio": match.start(1),
                "fin": match.end(1), "origen": "regla_persona_rol_posterior",
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


def roles_para_mencion(
    texto: str,
    inicio: int,
    fin: int,
    tipo: str,
    config: dict[str, Any],
) -> list[dict[str, str]]:
    ventana = texto[max(0, inicio - 130):min(len(texto), fin + 130)]
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
                    "evidencia": ESPACIOS_RE.sub(" ", ventana).strip()[:300],
                })
        except re.error:
            continue
    unicos: dict[str, dict[str, str]] = {}
    for rol in roles:
        unicos.setdefault(rol["rol"], rol)
    return list(unicos.values())[:6]


def canoniza(
    texto: str,
    tipo: str,
    aliases: dict[str, dict[str, Any]],
) -> tuple[str, str, bool, dict[str, Any] | None]:
    nombre = limpia_nombre(texto)
    clave = normaliza(nombre)
    if clave in aliases:
        item = aliases[clave]
        return item["canonico"], item["tipo"], True, item.get("geo")
    return nombre, tipo, False, None


def _fusiona_correferencias(
    entidades: list[dict[str, Any]],
    menciones: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Unifica entidades correferentes conservando la traza de cada variante."""
    mapa = REC.agrupa_correferencias(entidades)
    if not mapa:
        return entidades, menciones

    por_id = {e["id"]: e for e in entidades}
    absorbidas: set[str] = set()
    for id_origen, destino in mapa.items():
        id_destino = destino.get("id_canonico")
        if not id_destino or id_destino == id_origen:
            continue
        origen_e, destino_e = por_id.get(id_origen), por_id.get(id_destino)
        if not origen_e or not destino_e:
            continue
        destino_e["menciones"] += int(origen_e.get("menciones", 0) or 0)
        destino_e["variantes"] = sorted(
            set(destino_e.get("variantes", [])) | set(origen_e.get("variantes", [])),
            key=lambda x: (-len(x), x.casefold()),
        )
        destino_e["origen_deteccion"] = sorted(
            set(destino_e.get("origen_deteccion", [])) | set(origen_e.get("origen_deteccion", []))
        )
        destino_e["campos"] = sorted(
            set(destino_e.get("campos", [])) | set(origen_e.get("campos", []))
        )
        destino_e["senales"] = sorted(
            set(destino_e.get("senales", []))
            | set(origen_e.get("senales", []))
            | {f"correferencia:{destino.get('motivo')}"}
        )
        destino_e["confianza_score"] = round(max(
            float(destino_e.get("confianza_score", 0.5)),
            float(origen_e.get("confianza_score", 0.5)),
        ), 3)
        for rol in origen_e.get("roles", []):
            if rol not in destino_e.get("roles", []):
                destino_e.setdefault("roles", []).append(rol)
        for ctx in origen_e.get("contextos", []):
            if ctx not in destino_e.get("contextos", []) and len(destino_e.get("contextos", [])) < 6:
                destino_e.setdefault("contextos", []).append(ctx)
        for rut in origen_e.get("ruts", []):
            if rut not in destino_e.get("ruts", []):
                destino_e.setdefault("ruts", []).append(rut)
        destino_e.setdefault("formas_unificadas", []).append({
            "variante": origen_e.get("nombre_canonico"),
            "id_previo": id_origen,
            "motivo": destino.get("motivo"),
        })
        absorbidas.add(id_origen)

    for mencion in menciones:
        destino = mapa.get(mencion.get("entidad_id"))
        if destino and destino.get("id_canonico"):
            mencion["entidad_id_original"] = mencion["entidad_id"]
            mencion["entidad_id"] = destino["id_canonico"]

    return [e for e in entidades if e["id"] not in absorbidas], menciones


def procesa_publicacion(
    registro: dict[str, Any],
    doc: Any,
    texto: str,
    segmentos: list[dict[str, Any]],
    config: dict[str, Any],
    aliases: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    exclusiones = {normaliza(x) for x in config.get("exclusiones", []) or []}
    minimo = int(config.get("minimo_caracteres", 3) or 3)
    max_entidades = int(config.get("max_entidades_por_publicacion", 60) or 60)
    oraciones = oraciones_con_offsets(texto)

    candidatos: list[dict[str, Any]] = []
    for ent in getattr(doc, "ents", []):
        etiqueta_cruda = str(ent.label_).upper()
        tipo = TIPOS_PUBLICOS.get(etiqueta_cruda, "OTRO")
        if tipo == "OTRO":
            continue
        por_diccionario = bool(getattr(ent, "ent_id_", ""))
        origen = "diccionario_institucional" if por_diccionario else "modelo_estadistico"
        cand = {
            "texto": limpia_nombre(ent.text), "label": tipo,
            "naturaleza": naturaleza_de(tipo),
            "inicio": int(ent.start_char), "fin": int(ent.end_char), "origen": origen,
            "score": 0.9 if por_diccionario else 0.6,
        }
        # El diccionario institucional es autoritativo; la salida del modelo
        # estadístico se somete al arbitraje léxico del reconocedor v3, que es
        # quien decide si la cadena es persona natural, jurídica o ruido.
        if RECONOCEDOR_DISPONIBLE and not por_diccionario:
            # El modelo estadístico también produce spans que cruzan el fin de
            # oración ("… Fondos S.A. Los hermanos Ariel"); se recortan igual
            # que los de las reglas.
            cand["inicio"], cand["fin"] = REC.recorta_span(
                texto, cand["inicio"], cand["fin"]
            )
            cand["texto"] = texto[cand["inicio"]:cand["fin"]]
            izq = texto[max(0, cand["inicio"] - REC.VENTANA_CONTEXTO):cand["inicio"]]
            der = texto[cand["fin"]:cand["fin"] + REC.VENTANA_CONTEXTO]
            veredicto = REC.clasifica_cadena(cand["texto"], etiqueta_cruda, izq, der)
            if veredicto["descartar"]:
                continue
            cand["texto"] = REC.canoniza_denominacion(cand["texto"])[0]
            cand["label"] = veredicto["tipo"]
            cand["naturaleza"] = veredicto["naturaleza"]
            cand["score"] = veredicto["score"]
            cand["senales"] = veredicto["senales"]
            cand["motivo"] = veredicto["motivo"]
        candidatos.append(cand)

    candidatos.extend(extrae_reglas(texto, bool(config.get("incluir_rut", True))))

    if RECONOCEDOR_DISPONIBLE:
        # Arbitraje único de solapamientos para todos los tipos. Impide que una
        # misma cadena quede simultáneamente como PERSONA y como EMPRESA.
        candidatos = REC.depura_candidatos(candidatos)
        REC.rut_por_proximidad(texto, candidatos)
        candidatos = [c for c in candidatos if str(c.get("label", "")).upper() != "RUT"]
    else:
        depurados: list[dict[str, Any]] = []
        for cand in sorted(
            candidatos,
            key=lambda x: (int(x.get("inicio", 0)), -int(x.get("fin", 0)) + int(x.get("inicio", 0))),
        ):
            inicio = int(cand.get("inicio", 0))
            fin = int(cand.get("fin", inicio))
            tipo = TIPOS_PUBLICOS.get(str(cand.get("label", "")).upper(), str(cand.get("label", "OTRO")).upper())
            texto_cand = normaliza(cand.get("texto", ""))
            redundante = False
            for previo in depurados:
                pi, pf = int(previo.get("inicio", 0)), int(previo.get("fin", 0))
                p_tipo = TIPOS_PUBLICOS.get(str(previo.get("label", "")).upper(), str(previo.get("label", "OTRO")).upper())
                p_texto = normaliza(previo.get("texto", ""))
                solapa = inicio < pf and fin > pi
                compatibles = {tipo, p_tipo} <= {"EMPRESA", "ORGANIZACION", "INSTITUCION_FINANCIERA"}
                if solapa and compatibles and (texto_cand in p_texto or p_texto in texto_cand):
                    redundante = True
                    break
            if not redundante:
                depurados.append(cand)
        candidatos = depurados

    agrupadas: dict[tuple[str, str], dict[str, Any]] = {}
    menciones: list[dict[str, Any]] = []

    for cand in candidatos:
        original = limpia_nombre(cand.get("texto", ""))
        if len(original) < minimo or normaliza(original) in exclusiones:
            continue
        tipo_inicial = TIPOS_PUBLICOS.get(
            str(cand.get("label", "")).upper(),
            str(cand.get("label", "OTRO")).upper(),
        )
        canonico, tipo, por_alias, geo = canoniza(original, tipo_inicial, aliases)
        if tipo == "ORGANIZACION" and re.search(r"\b(?:spa|s\.a\.?|ltda\.?|eirl)\b", original, re.I):
            tipo = "EMPRESA"
        clave = (tipo, normaliza(canonico))
        if not clave[1]:
            continue
        inicio = int(cand.get("inicio", 0))
        fin = int(cand.get("fin", inicio + len(original)))
        ora = oracion_para_posicion(oraciones, inicio, fin)
        roles = roles_para_mencion(texto, inicio, fin, tipo, config)
        eid = id_entidad(tipo, canonico)
        mention = {
            "entidad_id": eid,
            "texto": original,
            "inicio": inicio,
            "fin": fin,
            "campo": campo_por_posicion(segmentos, inicio),
            "oracion_indice": ora["indice"],
            "oracion": ora["texto"],
            "origen": str(cand.get("origen", "modelo_estadistico")),
            "roles": [x["rol"] for x in roles],
        }
        menciones.append(mention)

        item = agrupadas.setdefault(clave, {
            "id": eid,
            "nombre_canonico": canonico,
            "tipo": tipo,
            "naturaleza": naturaleza_de(tipo),
            "naturaleza_label": ETIQUETA_NATURALEZA.get(naturaleza_de(tipo), "Indeterminada"),
            "variantes": set(),
            "origen_deteccion": set(),
            "menciones": 0,
            "campos": set(),
            "roles": {},
            "contextos": [],
            "menciones_detalle": [],
            "confianza": "alta" if por_alias or str(cand.get("origen", "")).startswith("regla_") else "media",
            "confianza_score": 0.0,
            "senales": set(),
            "ruts": [],
            "geo": geo,
        })
        # El score de la entidad es el máximo observado entre sus menciones:
        # basta una aparición inequívoca para consolidar la identificación.
        item["confianza_score"] = max(
            float(item.get("confianza_score", 0.0)), float(cand.get("score", 0.5) or 0.5)
        )
        for senal in cand.get("senales", []) or []:
            item["senales"].add(str(senal))
        for rut in cand.get("ruts", []) or []:
            if rut not in item["ruts"]:
                item["ruts"].append(rut)
        if por_alias:
            item["senales"].add("diccionario_institucional")
            item["confianza_score"] = max(float(item["confianza_score"]), 0.95)
        item["menciones"] += 1
        item["variantes"].add(original)
        item["origen_deteccion"].add(mention["origen"])
        item["campos"].add(mention["campo"])
        if ora["texto"] and ora["texto"] not in item["contextos"] and len(item["contextos"]) < 4:
            item["contextos"].append(ora["texto"])
        if len(item["menciones_detalle"]) < 8:
            item["menciones_detalle"].append({
                "campo": mention["campo"], "oracion": mention["oracion"],
                "origen": mention["origen"], "roles": mention["roles"],
            })
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
        item["senales"] = sorted(item["senales"])
        item["confianza_score"] = round(float(item.get("confianza_score", 0.5)), 3)
        salida.append(item)

    # Correferencia: "Marcela Ortiz" y "Marcela Ortiz Vega" son la misma persona.
    if RECONOCEDOR_DISPONIBLE:
        salida, menciones = _fusiona_correferencias(salida, menciones)

    salida.sort(key=lambda x: (
        -TIPOS_PRIORIDAD.get(x["tipo"], 0),
        -int(x["menciones"]),
        x["nombre_canonico"].casefold(),
    ))
    salida = salida[:max_entidades]
    ids_permitidos = {x["id"] for x in salida}
    menciones = [m for m in menciones if m["entidad_id"] in ids_permitidos]
    relaciones = extrae_relaciones_explicitas(texto, menciones, salida, config)
    return salida, menciones, relaciones


def extrae_relaciones_explicitas(
    texto: str,
    menciones: list[dict[str, Any]],
    entidades: list[dict[str, Any]],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    por_id = {e["id"]: e for e in entidades}
    por_oracion: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for m in menciones:
        if m.get("oracion_indice", -1) >= 0:
            por_oracion[int(m["oracion_indice"])].append(m)

    reglas = [r for r in (config.get("relaciones", []) or []) if isinstance(r, dict)]
    salida: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for _, mencs in por_oracion.items():
        # Evita explosión combinatoria en enumeraciones extensas.
        mencs = sorted(mencs, key=lambda x: x["inicio"])[:14]
        for a, b in combinations(mencs, 2):
            if a["entidad_id"] == b["entidad_id"]:
                continue
            ea, eb = por_id.get(a["entidad_id"]), por_id.get(b["entidad_id"])
            if not ea or not eb:
                continue
            ora = a.get("oracion") or b.get("oracion") or ""
            if not ora:
                continue
            entre = texto[min(a["fin"], b["fin"]):max(a["inicio"], b["inicio"])]
            for regla in reglas:
                tipo_rel = str(regla.get("tipo", "")).upper()
                patron = str(regla.get("patron", ""))
                if not tipo_rel or not patron:
                    continue
                fuentes = {str(x).upper() for x in regla.get("origen_tipos", []) or []}
                destinos = {str(x).upper() for x in regla.get("destino_tipos", []) or []}
                dirigida = bool(regla.get("dirigida", True))
                origen = destino = None
                if ea["tipo"] in fuentes and eb["tipo"] in destinos:
                    origen, destino = ea, eb
                elif eb["tipo"] in fuentes and ea["tipo"] in destinos:
                    origen, destino = eb, ea
                elif not dirigida and ea["tipo"] in fuentes and eb["tipo"] in fuentes:
                    origen, destino = sorted([ea, eb], key=lambda x: x["id"])
                if not origen or not destino:
                    continue
                ambito = str(regla.get("ambito", "entre"))
                objetivo = entre if ambito == "entre" else ora
                try:
                    coincidencia = re.search(patron, objetivo, re.IGNORECASE | re.UNICODE)
                    if not coincidencia:
                        continue
                except re.error:
                    continue

                max_destino = regla.get("max_distancia_destino")
                if max_destino is not None and ambito == "entre":
                    # La expresión relacional debe quedar próxima a la entidad
                    # que recibe la acción. Esto evita inferir, por ejemplo, que
                    # una Fiscalía formalizó a una empresa solo porque la empresa
                    # aparece después del nombre de la persona formalizada.
                    destino_mencion = a if a["entidad_id"] == destino["id"] else b
                    destino_esta_despues = destino_mencion["inicio"] > (a if destino_mencion is b else b)["inicio"]
                    distancia = (len(objetivo) - coincidencia.end()) if destino_esta_despues else coincidencia.start()
                    if distancia > int(max_destino):
                        continue
                clave = (origen["id"], destino["id"], tipo_rel, ora)
                salida[clave] = {
                    "origen": origen["id"],
                    "destino": destino["id"],
                    "tipo": tipo_rel,
                    "etiqueta": regla.get("etiqueta") or tipo_rel.replace("_", " ").lower(),
                    "categoria": "explicita",
                    "dirigida": dirigida,
                    "confianza": str(regla.get("confianza", "media")),
                    "evidencia": ora[:500],
                }
    return list(salida.values())


def taxonomias_publicacion(pub: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    def pares(campo: str, campo_label: str, excluir: set[str] | None = None):
        valores = como_lista(pub.get(campo))
        labels = como_lista(pub.get(campo_label))
        salida = []
        excluir = excluir or set()
        for i, valor in enumerate(valores):
            clave = str(valor or "").strip()
            if not clave or normaliza(clave) in excluir:
                continue
            label = str(labels[i] if i < len(labels) else clave)
            salida.append({"id": clave, "label": label})
        return salida

    fenomenos = pares("fenomenos", "fenomenos_label", {"otro", "otros"})
    if not fenomenos:
        fenomenos = pares("fenomeno", "fenomeno_label", {"otro", "otros"})
    precedentes = pares("precedentes", "precedentes_label", {"indeterminado", "no determinado"})
    topicos = pares("topicos", "topicos_label", {"otros"})
    sectores = pares("sujetos_obligados", "sujetos_obligados_label")
    if not sectores:
        sectores = pares("sectores", "sectores_label")
    impactos = pares("impacto_sujeto", "impacto_sujeto_label")
    naturaleza = pares("naturaleza", "naturaleza_label")
    return {
        "fenomenos": fenomenos,
        "precedentes": precedentes,
        "topicos": topicos,
        "sectores": sectores,
        "impactos": impactos,
        "naturaleza": naturaleza,
    }


def ubicaciones_publicacion(
    pub: dict[str, Any],
    entidades: list[dict[str, Any]],
    aliases: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    ubicaciones: dict[str, dict[str, Any]] = {}

    for e in entidades:
        if e.get("tipo") != "LUGAR":
            continue
        geo = e.get("geo") or aliases.get(normaliza(e.get("nombre_canonico", "")), {}).get("geo")
        item = {
            "id": id_estable("LOC", e.get("nombre_canonico")),
            "nombre": e.get("nombre_canonico"),
            "lat": geo.get("lat") if geo else None,
            "lon": geo.get("lon") if geo else None,
            "region": geo.get("region") if geo else None,
            "pais": geo.get("pais") if geo else "Chile",
            "nivel": geo.get("nivel") if geo else "mencion",
            "origen": "texto",
            "confianza": e.get("confianza", "media"),
        }
        ubicaciones[item["id"]] = item

    for campo in ("region", "regiones", "region_label", "comuna", "comunas", "territorio", "lugares"):
        for valor in como_lista(pub.get(campo)):
            clave = normaliza(valor)
            if not clave:
                continue
            meta = aliases.get(clave)
            canonico = meta.get("canonico") if meta else limpia_nombre(valor)
            geo = meta.get("geo") if meta else None
            item = {
                "id": id_estable("LOC", canonico),
                "nombre": canonico,
                "lat": geo.get("lat") if geo else None,
                "lon": geo.get("lon") if geo else None,
                "region": geo.get("region") if geo else canonico,
                "pais": geo.get("pais") if geo else "Chile",
                "nivel": geo.get("nivel") if geo else campo,
                "origen": f"campo_{campo}",
                "confianza": "alta" if geo else "media",
            }
            ubicaciones[item["id"]] = item
    return list(ubicaciones.values())


def tokens_titulo(titulo: str) -> set[str]:
    return {
        x for x in normaliza(titulo).split()
        if len(x) >= 4 and x not in STOPWORDS_TITULO
    }


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra



def _mejor_confianza(valores: Iterable[str]) -> str:
    orden = {"baja": 1, "media": 2, "alta": 3}
    disponibles = [str(x or "media").lower() for x in valores]
    return max(disponibles or ["media"], key=lambda x: orden.get(x, 2))


def construye_nomina_publicacion(
    entidades: list[dict[str, Any]],
    relaciones_exp: list[dict[str, Any]],
    ubicaciones: list[dict[str, Any]],
    articulo: dict[str, Any],
) -> list[dict[str, Any]]:
    """Crea una nómina auditable de entidades para una publicación."""
    por_id = {e.get("id"): e for e in entidades if e.get("id")}
    nombres = {eid: e.get("nombre_canonico") or eid for eid, e in por_id.items()}
    territorios = sorted({
        str(x.get("nombre")) for x in ubicaciones
        if isinstance(x, dict) and x.get("nombre")
    })

    relaciones_por_entidad: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel in relaciones_exp:
        origen, destino = rel.get("origen"), rel.get("destino")
        if not origen or not destino:
            continue
        etiqueta = str(rel.get("etiqueta") or rel.get("tipo") or "relacionada con")
        confianza = str(rel.get("confianza") or "media")
        if origen in por_id:
            relaciones_por_entidad[origen].append({
                "tipo": rel.get("tipo"), "etiqueta": etiqueta, "sentido": "origen",
                "contraparte_id": destino, "contraparte": nombres.get(destino, destino),
                "confianza": confianza,
            })
        if destino in por_id:
            relaciones_por_entidad[destino].append({
                "tipo": rel.get("tipo"), "etiqueta": etiqueta, "sentido": "destino",
                "contraparte_id": origen, "contraparte": nombres.get(origen, origen),
                "confianza": confianza,
            })

    nomina: list[dict[str, Any]] = []
    for entidad in entidades:
        if entidad.get("tipo") == "MONTO" or not entidad.get("id"):
            continue
        eid = entidad["id"]
        roles = sorted({
            str(x.get("rol")) for x in entidad.get("roles", [])
            if isinstance(x, dict) and x.get("rol")
        })
        rel_unicas: dict[tuple[str, str, str], dict[str, Any]] = {}
        for rel in relaciones_por_entidad.get(eid, []):
            clave = (str(rel.get("tipo") or ""), str(rel.get("sentido") or ""), str(rel.get("contraparte_id") or ""))
            rel_unicas.setdefault(clave, rel)
        relaciones = list(rel_unicas.values())

        prioridad_relacion = {
            "CONDENA_A": 100, "FORMALIZA_A": 95, "ACUSA_A": 90,
            "QUERELLA_CONTRA": 88, "INVESTIGA_A": 85,
            "REPRESENTA_A": 75, "SOCIO_DE": 74, "EJECUTIVO_DE": 73,
            "TRANSACCION_ENTRE": 65, "VINCULADO_CON": 60,
            "UBICADA_EN": 45, "OPERA_EN": 45,
        }
        relaciones.sort(key=lambda x: -prioridad_relacion.get(str(x.get("tipo") or ""), 50))

        def rol_desde_relacion(rel: dict[str, Any]) -> str:
            tipo = str(rel.get("tipo") or "")
            sentido = rel.get("sentido")
            otra = rel.get("contraparte")
            textos = {
                ("FORMALIZA_A", "destino"): f"formalizado por {otra}",
                ("FORMALIZA_A", "origen"): f"organismo que formaliza a {otra}",
                ("INVESTIGA_A", "destino"): f"investigado por {otra}",
                ("INVESTIGA_A", "origen"): f"organismo que investiga a {otra}",
                ("ACUSA_A", "destino"): f"acusado por {otra}",
                ("ACUSA_A", "origen"): f"organismo que acusa a {otra}",
                ("CONDENA_A", "destino"): f"condenado por {otra}",
                ("CONDENA_A", "origen"): f"tribunal u organismo que condena a {otra}",
                ("QUERELLA_CONTRA", "destino"): f"entidad contra la cual se presenta querella por {otra}",
                ("QUERELLA_CONTRA", "origen"): f"querellante contra {otra}",
                ("REPRESENTA_A", "origen"): f"representante de {otra}",
                ("REPRESENTA_A", "destino"): f"representada por {otra}",
                ("SOCIO_DE", "origen"): f"socio de {otra}",
                ("SOCIO_DE", "destino"): f"sociedad asociada a {otra}",
                ("EJECUTIVO_DE", "origen"): f"ejecutivo de {otra}",
                ("EJECUTIVO_DE", "destino"): f"organización donde se desempeña {otra}",
                ("TRANSACCION_ENTRE", "origen"): f"realiza transacciones con {otra}",
                ("TRANSACCION_ENTRE", "destino"): f"contraparte transaccional de {otra}",
                ("UBICADA_EN", "origen"): f"ubicado/a en {otra}",
                ("UBICADA_EN", "destino"): f"territorio donde se ubica {otra}",
                ("OPERA_EN", "origen"): f"opera en {otra}",
                ("OPERA_EN", "destino"): f"territorio donde opera {otra}",
            }
            return textos.get((tipo, sentido), (
                f"{rel['etiqueta']} {otra}" if sentido == "origen"
                else f"objeto de «{rel['etiqueta']}» por {otra}"
            ))

        roles_relacionales = []
        for rel in relaciones:
            rol_rel = rol_desde_relacion(rel)
            if rol_rel not in roles_relacionales:
                roles_relacionales.append(rol_rel)
        roles_publicos = roles_relacionales or roles
        rol_principal = roles_publicos[0] if roles_publicos else "mencionada en la publicación"

        tipo_entidad = entidad.get("tipo") or "OTRO"
        naturaleza = entidad.get("naturaleza") or naturaleza_de(tipo_entidad)
        nomina.append({
            "entidad_id": eid,
            "nombre": entidad.get("nombre_canonico") or eid,
            "tipo": tipo_entidad,
            "naturaleza": naturaleza,
            "naturaleza_label": ETIQUETA_NATURALEZA.get(naturaleza, "Indeterminada"),
            "confianza_score": round(float(entidad.get("confianza_score", 0.5) or 0.5), 3),
            "senales": list(entidad.get("senales", []))[:12],
            "ruts": list(entidad.get("ruts", [])),
            "variantes": list(entidad.get("variantes", []))[:6],
            "formas_unificadas": [
                x.get("variante") for x in entidad.get("formas_unificadas", [])
            ],
            "requiere_validacion": bool(
                float(entidad.get("confianza_score", 0.5) or 0.5) < 0.55
            ),
            "rol_principal": rol_principal,
            "roles": roles_publicos,
            "relaciones_explicitas": relaciones,
            "confianza": _mejor_confianza([
                entidad.get("confianza", "media"),
                *[x.get("confianza", "media") for x in relaciones],
            ]),
            "menciones": int(entidad.get("menciones", 1) or 1),
            "campos": sorted(set(entidad.get("campos", []))),
            "territorios_articulo": territorios,
            "fenomenos_articulo": list(articulo.get("fenomenos_label", [])),
            "precedentes_articulo": list(articulo.get("precedentes_label", [])),
            "sectores_articulo": list(articulo.get("sectores_label", [])),
            "articulo_id": articulo.get("id"),
            "articulo_titulo": articulo.get("titulo"),
            "articulo_fecha": articulo.get("fecha"),
            "articulo_medio": articulo.get("medio"),
            "articulo_link": articulo.get("link"),
        })

    prioridad = {"PERSONA": 0, "EMPRESA": 1, "INSTITUCION_FINANCIERA": 2,
                 "ORGANISMO_PUBLICO": 3, "TRIBUNAL": 4,
                 "ENTIDAD_SIN_FINES_DE_LUCRO": 5, "ORGANIZACION": 6,
                 "CRIPTOACTIVO": 7, "LUGAR": 8, "OTRO": 9}
    orden_naturaleza = {"PERSONA_NATURAL": 0, "PERSONA_JURIDICA": 1,
                        "INDETERMINADA": 2, "NO_APLICA": 3}
    nomina.sort(key=lambda x: (
        orden_naturaleza.get(x.get("naturaleza", "INDETERMINADA"), 4),
        prioridad.get(x["tipo"], 9),
        -float(x.get("confianza_score", 0) or 0),
        x["nombre"].casefold(),
    ))
    return nomina


def agrega_nominas_casos(casos: list[dict[str, Any]], articulo_por_id: dict[str, dict[str, Any]]) -> None:
    """Consolida roles y artículos para cada entidad dentro de un caso."""
    for caso in casos:
        acumulado: dict[str, dict[str, Any]] = {}
        for aid in caso.get("articulos", []):
            articulo = articulo_por_id.get(aid) or {}
            for fila in articulo.get("nomina_entidades", []):
                eid = fila.get("entidad_id")
                if not eid:
                    continue
                item = acumulado.setdefault(eid, {
                    "entidad_id": eid, "nombre": fila.get("nombre"), "tipo": fila.get("tipo"),
                    "roles": Counter(), "relaciones": {}, "articulos": [], "confianzas": [],
                    "menciones": 0, "territorios": set(),
                })
                for rol in fila.get("roles", []):
                    item["roles"][rol] += 1
                if not fila.get("roles") and fila.get("rol_principal"):
                    item["roles"][fila["rol_principal"]] += 1
                for rel in fila.get("relaciones_explicitas", []):
                    clave = (rel.get("tipo"), rel.get("sentido"), rel.get("contraparte_id"))
                    item["relaciones"].setdefault(clave, rel)
                if aid not in item["articulos"]:
                    item["articulos"].append(aid)
                item["confianzas"].append(fila.get("confianza", "media"))
                item["menciones"] += int(fila.get("menciones", 1) or 1)
                item["territorios"].update(fila.get("territorios_articulo", []))

        nomina_caso = []
        for item in acumulado.values():
            roles = [{"rol": rol, "articulos": n} for rol, n in item["roles"].most_common()]
            nomina_caso.append({
                "entidad_id": item["entidad_id"], "nombre": item["nombre"], "tipo": item["tipo"],
                "rol_principal": roles[0]["rol"] if roles else "mencionada en el caso",
                "roles": roles, "relaciones_explicitas": list(item["relaciones"].values()),
                "articulos": item["articulos"], "cantidad_articulos": len(item["articulos"]),
                "confianza": _mejor_confianza(item["confianzas"]), "menciones": item["menciones"],
                "territorios": sorted(item["territorios"]),
            })
        nomina_caso.sort(key=lambda x: (-x["cantidad_articulos"], x["nombre"].casefold()))
        caso["nomina_entidades"] = nomina_caso

def agrupa_casos(articulos: list[dict[str, Any]], entidad_tipo: dict[str, str]) -> list[dict[str, Any]]:
    if not articulos:
        return []
    ids = [a["id"] for a in articulos]
    uf = UnionFind(ids)
    por_id = {a["id"]: a for a in articulos}
    fuertes = {
        a["id"]: {
            eid for eid in a.get("entidades", [])
            if entidad_tipo.get(eid) in {"PERSONA", "EMPRESA", "INSTITUCION_FINANCIERA", "ORGANIZACION"}
        }
        for a in articulos
    }

    indice_entidad: dict[str, list[str]] = defaultdict(list)
    for aid, eids in fuertes.items():
        for eid in eids:
            indice_entidad[eid].append(aid)

    candidatos: set[tuple[str, str]] = set()
    for aids in indice_entidad.values():
        for a, b in combinations(aids[:80], 2):
            candidatos.add(tuple(sorted((a, b))))

    # También compara noticias con mismo fenómeno para rescatar casos sin entidad bien extraída.
    por_fen: dict[str, list[str]] = defaultdict(list)
    for art in articulos:
        for fen in art.get("fenomenos", []):
            por_fen[fen].append(art["id"])
    for aids in por_fen.values():
        for a, b in combinations(aids[:60], 2):
            candidatos.add(tuple(sorted((a, b))))

    for aid, bid in candidatos:
        a, b = por_id[aid], por_id[bid]
        compartidas = fuertes[aid] & fuertes[bid]
        fen_comp = set(a.get("fenomenos", [])) & set(b.get("fenomenos", []))
        pre_comp = set(a.get("precedentes", [])) & set(b.get("precedentes", []))
        sim = jaccard(set(a.get("tokens_titulo", [])), set(b.get("tokens_titulo", [])))
        if len(compartidas) >= 2:
            uf.union(aid, bid)
        elif len(compartidas) == 1 and (fen_comp or pre_comp or sim >= 0.28):
            uf.union(aid, bid)
        elif sim >= 0.55 and (fen_comp or pre_comp):
            uf.union(aid, bid)

    grupos: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for art in articulos:
        grupos[uf.find(art["id"])].append(art)

    casos: list[dict[str, Any]] = []
    for grupo in grupos.values():
        grupo = sorted(grupo, key=lambda x: (x.get("fecha") or "", x["id"]))
        entidades = Counter(eid for a in grupo for eid in a.get("entidades", []))
        fenomenos = Counter(x for a in grupo for x in a.get("fenomenos", []))
        precedentes = Counter(x for a in grupo for x in a.get("precedentes", []))
        sectores = Counter(x for a in grupo for x in a.get("sectores", []))
        lugares = Counter(x for a in grupo for x in a.get("lugares", []))
        fuertes_compartidas = [eid for eid, c in entidades.items() if c >= 2 and entidad_tipo.get(eid) in TIPOS_ENTIDAD_RELACIONAL]
        representante = max(
            grupo,
            key=lambda a: (len(a.get("entidades", [])), len(a.get("titulo", ""))),
        )
        fen_label = representante.get("fenomenos_label", [])
        top_ent = fuertes_compartidas[:2] or [eid for eid, _ in entidades.most_common(2)]
        titulo = representante.get("titulo") or "Caso sin título"
        if fen_label and top_ent:
            titulo = f"{fen_label[0]} · {titulo}"
        cid = id_estable("CAS", *(a["id"] for a in grupo))
        casos.append({
            "id": cid,
            "titulo": titulo[:220],
            "tipo": "caso_consolidado" if len(grupo) > 1 else "evento_individual",
            "confianza_agrupacion": "alta" if len(fuertes_compartidas) >= 2 else ("media" if len(grupo) > 1 else "baja"),
            "fecha_inicio": grupo[0].get("fecha"),
            "fecha_fin": grupo[-1].get("fecha"),
            "articulos": [a["id"] for a in grupo],
            "entidades": [x for x, _ in entidades.most_common(30)],
            "fenomenos": [x for x, _ in fenomenos.most_common()],
            "precedentes": [x for x, _ in precedentes.most_common()],
            "sectores": [x for x, _ in sectores.most_common()],
            "lugares": [x for x, _ in lugares.most_common()],
            "medios": sorted({a.get("medio") for a in grupo if a.get("medio")}),
            "cantidad_articulos": len(grupo),
        })
    casos.sort(key=lambda x: (-x["cantidad_articulos"], x.get("fecha_fin") or ""), reverse=False)
    return casos


def agrega_relacion(
    mapa: dict[tuple[Any, ...], dict[str, Any]],
    origen: str,
    destino: str,
    tipo: str,
    categoria: str,
    *,
    dirigida: bool = True,
    confianza: str = "media",
    peso: int = 1,
    articulo: dict[str, Any] | None = None,
    evidencia: str | None = None,
    etiqueta: str | None = None,
) -> None:
    if not origen or not destino or origen == destino:
        return
    if not dirigida and destino < origen:
        origen, destino = destino, origen
    clave = (origen, destino, tipo, categoria, dirigida)
    item = mapa.setdefault(clave, {
        "id": id_estable("REL", origen, destino, tipo, categoria),
        "origen": origen,
        "destino": destino,
        "tipo": tipo,
        "etiqueta": etiqueta or tipo.replace("_", " ").lower(),
        "categoria": categoria,
        "dirigida": dirigida,
        "confianza": confianza,
        "peso": 0,
        "articulos": [],
        "evidencias": [],
    })
    item["peso"] += max(1, int(peso or 1))
    if CONF_ORDEN.get(confianza, 1) > CONF_ORDEN.get(item["confianza"], 1):
        item["confianza"] = confianza
    if articulo:
        aid = articulo.get("id")
        if aid and aid not in item["articulos"]:
            item["articulos"].append(aid)
        if evidencia and len(item["evidencias"]) < 4:
            ev = {
                "articulo_id": aid,
                "titulo": articulo.get("titulo"),
                "fecha": articulo.get("fecha"),
                "medio": articulo.get("medio"),
                "link": articulo.get("link"),
                "texto": limpia_nombre(evidencia, 500),
            }
            if ev not in item["evidencias"]:
                item["evidencias"].append(ev)


def calcula_centralidad(entidades: list[dict[str, Any]], relaciones: list[dict[str, Any]]) -> None:
    ids = {e["id"] for e in entidades if e.get("tipo") in TIPOS_ENTIDAD_RELACIONAL}
    ady: dict[str, dict[str, float]] = {eid: {} for eid in ids}
    explicitas = Counter()
    for r in relaciones:
        a, b = r.get("origen"), r.get("destino")
        if a not in ids or b not in ids:
            continue
        if r.get("categoria") not in {"explicita", "coaparicion"}:
            continue
        factor = 3.0 if r.get("categoria") == "explicita" else 1.0
        peso = factor * float(r.get("peso", 1))
        ady[a][b] = ady[a].get(b, 0.0) + peso
        ady[b][a] = ady[b].get(a, 0.0) + peso
        if r.get("categoria") == "explicita":
            explicitas[a] += 1
            explicitas[b] += 1

    n = max(1, len(ids))
    pr = {eid: 1.0 / n for eid in ids}
    damping = 0.85
    for _ in range(25):
        nuevo = {eid: (1 - damping) / n for eid in ids}
        for origen, vecinos in ady.items():
            total = sum(vecinos.values())
            if total <= 0:
                continue
            for destino, peso in vecinos.items():
                nuevo[destino] += damping * pr[origen] * peso / total
        pr = nuevo

    raw_scores = {}
    for e in entidades:
        eid = e["id"]
        vecinos = ady.get(eid, {})
        e["grado"] = len(vecinos)
        e["grado_ponderado"] = round(sum(vecinos.values()), 2)
        e["pagerank"] = round(pr.get(eid, 0.0), 6)
        e["relaciones_explicitas"] = int(explicitas[eid])
        raw = (
            e["grado_ponderado"]
            + 4 * e["relaciones_explicitas"]
            + 2 * len(e.get("casos", []))
            + 1.5 * len(e.get("fenomenos", []))
            + 1.2 * len(e.get("lugares", []))
            + math.log1p(e.get("publicaciones", 0)) * 3
        )
        raw_scores[eid] = raw
    max_raw = max(raw_scores.values(), default=1.0) or 1.0
    for e in entidades:
        score = round(100 * raw_scores.get(e["id"], 0.0) / max_raw)
        e["score_relacional"] = score
        e["nivel_relacional"] = "alto" if score >= 70 else ("medio" if score >= 35 else "bajo")


def atomic_json_dump(ruta: Path, data: dict[str, Any]) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=ruta.parent,
        prefix=ruta.name + ".", suffix=".tmp", delete=False,
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
    max_chars = int(config.get("max_texto_por_publicacion", 40_000) or 40_000)
    batch_size = int(config.get("batch_size", 16) or 16)
    textos_segmentos = [
        construye_texto(pub, max_chars) if isinstance(pub, dict) else ("", [])
        for pub in prensa
    ]
    textos = [x[0] for x in textos_segmentos]
    docs = nlp.pipe(textos, batch_size=batch_size)

    errores: list[dict[str, Any]] = []
    entidad_global: dict[str, dict[str, Any]] = {}
    articulos: list[dict[str, Any]] = []
    articulo_por_id: dict[str, dict[str, Any]] = {}
    relaciones_map: dict[tuple[Any, ...], dict[str, Any]] = {}
    nodos_taxonomia: dict[str, dict[str, Any]] = {}
    lugares_catalogo: dict[str, dict[str, Any]] = {}

    procesadas = con_entidades = 0

    for idx, (pub, texto, segmentos, doc) in enumerate(
        (p, t[0], t[1], d) for p, t, d in zip(prensa, textos_segmentos, docs)
    ):
        if not isinstance(pub, dict):
            continue
        try:
            entidades, menciones, relaciones_exp = procesa_publicacion(
                pub, doc, texto, segmentos, config, aliases,
            )
            tax = taxonomias_publicacion(pub)
            ubicaciones = ubicaciones_publicacion(pub, entidades, aliases)
            aid = str(pub.get("id") or id_estable("ART", pub.get("link"), pub.get("titulo")))
            art_node_id = f"ART-{aid}"
            articulo = {
                "id": art_node_id,
                "id_fuente": aid,
                "titulo": pub.get("titulo") or "Sin título",
                "fecha": str(pub.get("fecha") or pub.get("fecha_iso") or "")[:10],
                "hora": pub.get("hora"),
                "medio": pub.get("medio"),
                "link": pub.get("link"),
                "resumen": pub.get("resumen", ""),
                "fenomenos": [], "fenomenos_label": [],
                "precedentes": [], "precedentes_label": [],
                "sectores": [], "sectores_label": [],
                "topicos": [], "topicos_label": [],
                "lugares": [x["id"] for x in ubicaciones],
                "entidades": [e["id"] for e in entidades if e.get("tipo") != "MONTO"],
                "tokens_titulo": sorted(tokens_titulo(pub.get("titulo", ""))),
                "uaf": bool(pub.get("uaf") or pub.get("uaf_chile")),
            }
            for categoria, prefijo, tipo_nodo in (
                ("fenomenos", "FEN", "FENOMENO"),
                ("precedentes", "PRE", "PRECEDENTE"),
                ("sectores", "SEC", "SECTOR"),
                ("topicos", "TOP", "TOPICO"),
            ):
                for item in tax[categoria]:
                    nid = id_estable(prefijo, item["id"])
                    nodos_taxonomia[nid] = {
                        "id": nid, "tipo_nodo": tipo_nodo,
                        "clave": item["id"], "nombre": item["label"],
                    }
                    articulo[categoria].append(nid)
                    articulo[categoria + "_label"].append(item["label"])
                    agrega_relacion(
                        relaciones_map, art_node_id, nid,
                        {
                            "fenomenos": "TRATA_FENOMENO",
                            "precedentes": "INVOLUCRA_PRECEDENTE",
                            "sectores": "AFECTA_SECTOR",
                            "topicos": "ABORDA_TOPICO",
                        }[categoria],
                        "clasificacion_articulo", confianza="media", articulo=articulo,
                    )

            for loc in ubicaciones:
                lugares_catalogo[loc["id"]] = {
                    **loc,
                    "tipo_nodo": "LUGAR",
                    "articulos": set(),
                    "entidades": set(),
                }
                lugares_catalogo[loc["id"]]["articulos"].add(art_node_id)
                agrega_relacion(
                    relaciones_map, art_node_id, loc["id"], "UBICADO_EN",
                    "geografica_articulo", confianza=loc.get("confianza", "media"),
                    articulo=articulo,
                )

            pub["entidades"] = entidades
            pub["relaciones_entidades"] = []
            pub["ubicaciones_detectadas"] = ubicaciones
            pub["analisis_entidades_version"] = VERSION_MODULO

            for e in entidades:
                eid = e["id"]
                global_e = entidad_global.setdefault(eid, {
                    "id": eid,
                    "tipo_nodo": "ENTIDAD",
                    "nombre": e["nombre_canonico"],
                    "tipo": e["tipo"],
                    "naturaleza": e.get("naturaleza") or naturaleza_de(e["tipo"]),
                    "naturaleza_label": ETIQUETA_NATURALEZA.get(
                        e.get("naturaleza") or naturaleza_de(e["tipo"]), "Indeterminada"
                    ),
                    "confianza_score": 0.0,
                    "senales": set(),
                    "ruts": [],
                    "variantes": set(),
                    "origen_deteccion": set(),
                    "publicaciones": 0,
                    "menciones": 0,
                    "articulos": [],
                    "medios": set(),
                    "roles": Counter(),
                    "fenomenos": Counter(),
                    "precedentes": Counter(),
                    "sectores": Counter(),
                    "topicos": Counter(),
                    "lugares": Counter(),
                    "casos": [],
                    "primera_fecha": None,
                    "ultima_fecha": None,
                    "confianza": e.get("confianza", "media"),
                })
                global_e["variantes"].update(e.get("variantes", []))
                global_e["origen_deteccion"].update(e.get("origen_deteccion", []))
                global_e["senales"].update(e.get("senales", []))
                global_e["confianza_score"] = max(
                    float(global_e.get("confianza_score", 0.0)),
                    float(e.get("confianza_score", 0.5) or 0.5),
                )
                for rut in e.get("ruts", []) or []:
                    if rut not in global_e["ruts"]:
                        global_e["ruts"].append(rut)
                global_e["publicaciones"] += 1
                global_e["menciones"] += int(e.get("menciones", 1) or 1)
                if art_node_id not in global_e["articulos"]:
                    global_e["articulos"].append(art_node_id)
                if pub.get("medio"):
                    global_e["medios"].add(pub["medio"])
                fecha = articulo.get("fecha")
                if fecha:
                    global_e["primera_fecha"] = min(global_e["primera_fecha"], fecha) if global_e["primera_fecha"] else fecha
                    global_e["ultima_fecha"] = max(global_e["ultima_fecha"], fecha) if global_e["ultima_fecha"] else fecha
                for rol in e.get("roles", []):
                    if rol.get("rol"):
                        global_e["roles"][rol["rol"]] += 1

                evidencia = (e.get("contextos") or [""])[0]
                agrega_relacion(
                    relaciones_map, eid, art_node_id, "APARECE_EN",
                    "trazabilidad", confianza=e.get("confianza", "media"),
                    peso=int(e.get("menciones", 1) or 1), articulo=articulo,
                    evidencia=evidencia,
                )

                for categoria in ("fenomenos", "precedentes", "sectores", "topicos"):
                    for nid in articulo[categoria]:
                        global_e[categoria][nid] += 1
                        etiqueta = {
                            "fenomenos": "APARECE_EN_ARTICULO_SOBRE_FENOMENO",
                            "precedentes": "APARECE_EN_ARTICULO_CON_PRECEDENTE",
                            "sectores": "APARECE_EN_ARTICULO_DE_SECTOR",
                            "topicos": "APARECE_EN_ARTICULO_SOBRE_TOPICO",
                        }[categoria]
                        agrega_relacion(
                            relaciones_map, eid, nid, etiqueta,
                            "asociacion_contextual", confianza="media",
                            articulo=articulo, evidencia=evidencia,
                        )

                # La geolocalización contextual se distingue de una ubicación explícita.
                for loc in ubicaciones:
                    global_e["lugares"][loc["id"]] += 1
                    lugares_catalogo[loc["id"]]["entidades"].add(eid)
                    directo = any(
                        normaliza(loc["nombre"]) in normaliza(ctx)
                        for ctx in e.get("contextos", [])
                    )
                    agrega_relacion(
                        relaciones_map, eid, loc["id"],
                        "MENCIONADA_EN_TERRITORIO" if not directo else "RELACIONADA_TEXTUALMENTE_CON_TERRITORIO",
                        "geografica_contextual" if not directo else "geografica_explicita",
                        confianza="media" if not directo else "alta",
                        articulo=articulo,
                        evidencia=evidencia,
                    )

            # Coaparición siempre conserva el artículo que la originó.
            ids_rel = [e["id"] for e in entidades if e.get("tipo") in TIPOS_ENTIDAD_RELACIONAL][:22]
            for ea, eb in combinations(sorted(set(ids_rel)), 2):
                agrega_relacion(
                    relaciones_map, ea, eb, "COAPARECE_CON", "coaparicion",
                    dirigida=False, confianza="baja", articulo=articulo,
                    evidencia="Entidades mencionadas en una misma publicación.",
                )

            for rel in relaciones_exp:
                agrega_relacion(
                    relaciones_map, rel["origen"], rel["destino"], rel["tipo"],
                    "explicita", dirigida=bool(rel.get("dirigida", True)),
                    confianza=rel.get("confianza", "media"), articulo=articulo,
                    evidencia=rel.get("evidencia"), etiqueta=rel.get("etiqueta"),
                )
                pub["relaciones_entidades"].append({**rel, "articulo_id": art_node_id})

            nomina = construye_nomina_publicacion(entidades, relaciones_exp, ubicaciones, articulo)
            articulo["nomina_entidades"] = nomina
            pub["nomina_entidades"] = nomina

            articulos.append(articulo)
            articulo_por_id[art_node_id] = articulo
            procesadas += 1
            if entidades:
                con_entidades += 1
        except Exception as exc:
            pub["entidades"] = []
            pub["relaciones_entidades"] = []
            pub["ubicaciones_detectadas"] = []
            pub["entidades_error"] = f"{type(exc).__name__}: {exc}"[:400]
            errores.append({"indice": idx, "id": pub.get("id"), "error": pub["entidades_error"]})

    entidad_tipo = {eid: e["tipo"] for eid, e in entidad_global.items()}
    casos = agrupa_casos(articulos, entidad_tipo)
    agrega_nominas_casos(casos, articulo_por_id)
    caso_por_articulo: dict[str, list[str]] = defaultdict(list)
    for caso in casos:
        caso_node = {
            "id": caso["id"], "tipo_nodo": "CASO", "nombre": caso["titulo"],
        }
        for aid in caso["articulos"]:
            caso_por_articulo[aid].append(caso["id"])
            art = articulo_por_id.get(aid)
            agrega_relacion(
                relaciones_map, aid, caso["id"], "PARTE_DE_CASO", "caso",
                confianza=caso["confianza_agrupacion"], articulo=art,
            )
        for eid in caso["entidades"]:
            if eid in entidad_global:
                entidad_global[eid]["casos"].append(caso["id"])
                art = articulo_por_id.get(caso["articulos"][0])
                agrega_relacion(
                    relaciones_map, eid, caso["id"], "APARECE_EN_CASO", "caso",
                    confianza="media", articulo=art,
                )

    for pub in prensa:
        aid = str(pub.get("id") or id_estable("ART", pub.get("link"), pub.get("titulo")))
        pub["caso_ids"] = caso_por_articulo.get(f"ART-{aid}", [])

    entidades_final: list[dict[str, Any]] = []
    for e in entidad_global.values():
        e["variantes"] = sorted(e["variantes"], key=lambda x: (-len(x), x.casefold()))[:20]
        e["origen_deteccion"] = sorted(e["origen_deteccion"])
        e["medios"] = sorted(e["medios"])
        e["cantidad_medios"] = len(e["medios"])
        e["roles"] = [{"rol": r, "apariciones": n} for r, n in e["roles"].most_common(8)]
        e["senales"] = sorted(e["senales"])[:15]
        e["confianza_score"] = round(float(e.get("confianza_score", 0.5)), 3)
        e["requiere_validacion"] = bool(e["confianza_score"] < 0.55)
        for campo in ("fenomenos", "precedentes", "sectores", "topicos", "lugares"):
            e[campo] = [{"id": k, "articulos": n} for k, n in e[campo].most_common()]
        entidades_final.append(e)

    relaciones = list(relaciones_map.values())
    relaciones.sort(key=lambda x: (
        0 if x["categoria"] == "explicita" else 1,
        -int(x.get("peso", 1)), x["tipo"], x["origen"], x["destino"],
    ))
    max_rel = int(config.get("max_relaciones_globales", 4500) or 4500)
    relaciones = relaciones[:max_rel]
    calcula_centralidad(entidades_final, relaciones)
    entidades_final.sort(key=lambda x: (
        -x.get("score_relacional", 0), -x.get("publicaciones", 0), x["nombre"].casefold(),
    ))

    for loc in lugares_catalogo.values():
        loc["articulos"] = sorted(loc["articulos"])
        loc["entidades"] = sorted(loc["entidades"])
        loc["cantidad_articulos"] = len(loc["articulos"])
        loc["cantidad_entidades"] = len(loc["entidades"])
    lugares = sorted(
        lugares_catalogo.values(),
        key=lambda x: (-x["cantidad_articulos"], x["nombre"].casefold()),
    )

    # Nodos planos para el explorador de grafos.
    nodos = []
    nodos.extend({
        "id": e["id"], "tipo_nodo": "ENTIDAD", "nombre": e["nombre"],
        "subtipo": e["tipo"], "naturaleza": e.get("naturaleza", "INDETERMINADA"),
        "score": e.get("score_relacional", 0),
    } for e in entidades_final)
    nodos.extend({
        "id": a["id"], "tipo_nodo": "ARTICULO", "nombre": a["titulo"],
        "fecha": a["fecha"], "medio": a["medio"], "link": a["link"],
    } for a in articulos)
    nodos.extend(nodos_taxonomia.values())
    nodos.extend({
        "id": l["id"], "tipo_nodo": "LUGAR", "nombre": l["nombre"],
        "lat": l.get("lat"), "lon": l.get("lon"), "region": l.get("region"),
    } for l in lugares)
    nodos.extend({
        "id": c["id"], "tipo_nodo": "CASO", "nombre": c["titulo"],
        "cantidad_articulos": c["cantidad_articulos"],
    } for c in casos)

    ahora = datetime.now(timezone.utc).isoformat()
    por_tipo = Counter(e.get("tipo", "OTRO") for e in entidades_final)
    por_naturaleza = Counter(
        e.get("naturaleza", "INDETERMINADA") for e in entidades_final
    )
    pendientes_validacion = sum(
        1 for e in entidades_final if e.get("requiere_validacion")
    )
    explicitas = sum(1 for r in relaciones if r["categoria"] == "explicita")

    analisis = {
        "version": VERSION_MODULO,
        "generado": ahora,
        "modelo": modelo_usado,
        "usa_modelo_estadistico": bool(estadistico),
        "metodo": "hibrido_ner_reglas_grafo_casos_geografia",
        "publicaciones_procesadas": procesadas,
        "publicaciones_con_entidades": con_entidades,
        "entidades_unicas": len(entidades_final),
        "relaciones_totales": len(relaciones),
        "relaciones_explicitas": explicitas,
        "casos": casos,
        "entidades": entidades_final,
        "articulos": articulos,
        "lugares": lugares,
        "taxonomias": list(nodos_taxonomia.values()),
        "nodos": nodos,
        "relaciones": relaciones,
        "conteo_por_tipo": dict(sorted(por_tipo.items())),
        "conteo_por_naturaleza": dict(sorted(por_naturaleza.items())),
        "personas_naturales": por_naturaleza.get("PERSONA_NATURAL", 0),
        "personas_juridicas": por_naturaleza.get("PERSONA_JURIDICA", 0),
        "entidades_por_validar": pendientes_validacion,
        "reconocedor": (
            REC.VERSION_RECONOCEDOR if RECONOCEDOR_DISPONIBLE else "heredado_v2"
        ),
        "errores": errores[:30],
        "advertencia": (
            "Las relaciones explícitas se infieren desde frases del artículo y deben validarse. "
            "Las asociaciones contextuales indican que una entidad aparece en una publicación o caso "
            "clasificado en un fenómeno, delito, sector o territorio; no acreditan participación, "
            "responsabilidad ni vínculo delictivo."
        ),
    }
    datos["analisis_entidades"] = analisis

    # Compatibilidad con el workflow y consumidores de la versión anterior.
    datos["modulo_entidades"] = {
        "version": VERSION_MODULO,
        "generado": ahora,
        "modelo": modelo_usado,
        "usa_modelo_estadistico": bool(estadistico),
        "metodo": analisis["metodo"],
        "publicaciones_procesadas": procesadas,
        "publicaciones_con_entidades": con_entidades,
        "entidades_unicas": len(entidades_final),
        "relaciones_explicitas": explicitas,
        "casos_detectados": len(casos),
        "conteo_por_tipo": analisis["conteo_por_tipo"],
        "ranking": entidades_final[:250],
        "advertencia": analisis["advertencia"],
    }
    return datos


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Construye análisis relacional de entidades LA/FT")
    ap.add_argument("--entrada", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--salida", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--modelo", default=os.getenv("ENTIDADES_MODELO", "es_core_news_sm"))
    ap.add_argument("--solo-reglas", action="store_true", default=False)
    ap.add_argument("--validar", action="store_true", help="valida configuración y pipeline")
    return ap.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    salida = args.salida or args.entrada
    config = carga_config(args.config)
    nlp, modelo_usado, estadistico = cargar_pipeline(args.modelo, config, args.solo_reglas)
    if args.validar:
        print(
            f"Módulo válido: {VERSION_MODULO} · modelo={modelo_usado} · "
            f"estadístico={estadistico} · relaciones={len(config.get('relaciones', []))} · "
            f"lugares={len(config.get('lugares', []))} · "
            f"config_archivo={config.get('config_archivo_version')} · "
            f"config_completada={config.get('config_completada_internamente', False)}"
        )
        return 0
    if not args.entrada.exists():
        print(f"No existe el archivo de entrada: {args.entrada}", file=sys.stderr)
        return 2
    datos = json.loads(args.entrada.read_text(encoding="utf-8"))
    if not isinstance(datos, dict):
        raise ValueError("datos.json debe contener un objeto JSON")
    enriquecer(datos, nlp, config, modelo_usado, estadistico)
    atomic_json_dump(salida, datos)
    meta = datos["analisis_entidades"]
    print(
        "Análisis relacional listo: "
        f"{meta['publicaciones_procesadas']} publicaciones · "
        f"{meta['entidades_unicas']} entidades "
        f"({meta.get('personas_naturales', 0)} personas naturales, "
        f"{meta.get('personas_juridicas', 0)} personas jurídicas) · "
        f"{meta['relaciones_explicitas']} relaciones explícitas · "
        f"{len(meta['casos'])} casos/eventos · modelo={meta['modelo']} · "
        f"reconocedor={meta.get('reconocedor', 'heredado_v2')}"
    )
    if meta.get("entidades_por_validar"):
        print(
            f"  {meta['entidades_por_validar']} entidades quedaron bajo el umbral "
            "de confianza y están marcadas para validación humana."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
