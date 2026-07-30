#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
monitor_uaf.py — Monitor UAF Chile · motor de vigilancia de fuentes.

v5.0 «cobertura-total-chile»

Cambios principales frente a 4.0
  1. Descubrimiento multicanal: Google News, Bing News, GDELT DOC 2.0, RSS/Atom
     propios de cada medio (autodescubiertos), news-sitemaps declarados en
     robots.txt y el sitio institucional de la UAF.
  2. Detección UAF por proximidad: la decisión ya no se veta porque en el
     artículo aparezca la palabra «Perú» o «Panamá» en otro párrafo. Se analiza
     la ventana de texto alrededor de cada mención.
  3. Barrido profundo rotativo: cada corrida lee el cuerpo completo de un lote
     de artículos recientes aún no procesados, con memoria persistente, de modo
     que en el transcurso del día se revisa prácticamente toda la producción de
     los medios prioritarios.
  4. Red endurecida: sin SSRF (bloquea redirecciones a rangos privados), límite
     de bytes, XML sin DTD/entidades, solo http/https, respeto de robots.txt.
  5. Paralelismo con límite por dominio, caché de cuerpos y presupuesto global
     de tiempo para no exceder la ventana del GitHub Action.
  6. Corrección del error que impedía enviar correo (contexto SSL inexistente).

Solo biblioteca estándar. Requiere Python 3.9+ (recomendado 3.11+).

  python3 monitor_uaf.py                    # una pasada
  python3 monitor_uaf.py --daemon           # vigila cada 15 min
  python3 monitor_uaf.py --probar-correo    # prueba SMTP
  python3 monitor_uaf.py --diagnostico      # descubre fuentes y sale
  python3 monitor_uaf.py --probar-deteccion "texto..."
"""

import argparse
import base64
import copy
import gzip
import hashlib
import html as html_mod
import ipaddress
import json
import os
import re
import socket
import smtplib
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import xml.etree.ElementTree as ET
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from functools import lru_cache
from html.parser import HTMLParser

try:
    from zoneinfo import ZoneInfo
except ImportError:  # respaldo con desfase fijo
    ZoneInfo = None

# ─────────────────────────────────────────────────────────────
# Rutas y parámetros
# ─────────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.abspath(__file__))
SALIDA = os.path.join(BASE, "datos.json")
ESTADO = os.path.join(BASE, ".monitor_estado.json")
BITACORA = os.path.join(BASE, "monitor.log")
CONFIG = os.path.join(BASE, "config.json")
FUENTES_EXTRA = os.path.join(BASE, "fuentes_extra.json")

VERSION_MONITOR = "5.1-cobertura-por-medio"
ESQUEMA_ID = 2  # cambia si cambia la forma de calcular el id de una noticia

TZ_CL = ZoneInfo("America/Santiago") if ZoneInfo else timezone(timedelta(hours=-4))

UA = "Mozilla/5.0 (compatible; MonitorUAF/5.0; +https://github.com/)"
UA_ROBOTS = "MonitorUAF"

CONFIG_EJEMPLO = {
    "correo": {
        "activo": False,
        "servidor": "smtp.gmail.com",
        "puerto": 587,
        "seguridad": "starttls",
        "usuario": "tu.correo@gmail.com",
        "clave": "clave-de-aplicacion-de-16-letras",
        "remitente_nombre": "Monitor UAF Chile",
        "destinatarios": ["tu.correo@gmail.com"],
        "minimo_para_avisar": 1,
        "silencio_minutos": 0,
        "solo_si_menciona_uaf": True,
    }
}


def _env_bool(nombre, defecto=False):
    valor = os.getenv(nombre)
    if valor is None or valor.strip() == "":
        return defecto
    return valor.strip().lower() in {"1", "true", "si", "sí", "yes", "on"}


def _env_int(nombre, defecto):
    valor = os.getenv(nombre)
    if valor is None or valor.strip() == "":
        return defecto
    try:
        return int(valor.strip())
    except ValueError:
        return defecto


# Ventanas y presupuestos (ajustables por variables de entorno).
VENTANA_DIAS = _env_int("MONITOR_VENTANA_DIAS", 30)
TIMEOUT = _env_int("MONITOR_TIMEOUT", 20)
PRESUPUESTO_SEGUNDOS = _env_int("MONITOR_PRESUPUESTO_SEG", 840)
HILOS = max(1, min(16, _env_int("MONITOR_HILOS", 8)))
MAX_BYTES_RESPUESTA = _env_int("MONITOR_MAX_BYTES", 4_000_000)
MAX_TEXTO_ANALISIS = _env_int("MONITOR_MAX_TEXTO", 20000)
MAX_TEXTO_GUARDADO = _env_int("MONITOR_MAX_TEXTO_GUARDADO", 4000)
MAX_ARTICULOS_ENRIQUECER = _env_int("MONITOR_MAX_ENRIQUECER", 320)
PRESUPUESTO_BARRIDO = _env_int("MONITOR_BARRIDO", 90)
INTERVALO_POR_HOST = float(os.getenv("MONITOR_INTERVALO_HOST", "0.9") or 0.9)
RESPETA_ROBOTS = _env_bool("MONITOR_RESPETA_ROBOTS", True)
TTL_ENDPOINTS_HORAS = _env_int("MONITOR_TTL_ENDPOINTS_H", 72)
MAX_PROCESADOS = _env_int("MONITOR_MAX_PROCESADOS", 30000)
DIAS_PROCESADOS = _env_int("MONITOR_DIAS_PROCESADOS", 21)

_INICIO = time.monotonic()


def tiempo_agotado(reserva=0):
    return (time.monotonic() - _INICIO) > max(30, PRESUPUESTO_SEGUNDOS - reserva)


# ─────────────────────────────────────────────────────────────
# Universo de fuentes chilenas
# ─────────────────────────────────────────────────────────────

# Nivel A: medios y fuentes verificadas. Alimentan feeds, sitemaps y barrido.
MEDIOS_CHILE = [
    # Prensa nacional y general
    ("La Tercera", "latercera.com", "prensa_nacional", True),
    ("Emol", "emol.com", "prensa_nacional", True),
    ("El Mercurio", "elmercurio.com", "prensa_nacional", True),
    ("La Segunda", "lasegunda.com", "prensa_nacional", False),
    ("Las Últimas Noticias", "lun.com", "prensa_nacional", False),
    ("La Cuarta", "lacuarta.com", "prensa_nacional", False),
    ("Publimetro", "publimetro.cl", "prensa_nacional", True),
    ("La Hora", "lahora.cl", "prensa_nacional", True),
    ("La Nación", "lanacion.cl", "prensa_nacional", True),
    # Económicos y de negocios
    ("Diario Financiero", "df.cl", "economico", True),
    ("Diario Financiero", "diariofinanciero.cl", "economico", True),
    ("DF SUD", "dfsud.com", "economico", False),
    ("Estrategia", "estrategia.cl", "economico", False),
    ("Revista Capital", "revistacapital.cl", "economico", True),
    ("Pulso / La Tercera", "pulso.cl", "economico", False),
    ("Mundo Marítimo", "mundomaritimo.cl", "economico", False),
    # Investigación y digitales
    ("CIPER", "ciperchile.cl", "investigacion_digital", True),
    ("El Mostrador", "elmostrador.cl", "investigacion_digital", True),
    ("Ex-Ante", "ex-ante.cl", "investigacion_digital", True),
    ("Interferencia", "interferencia.cl", "investigacion_digital", True),
    ("The Clinic", "theclinic.cl", "investigacion_digital", True),
    ("El Dínamo", "eldinamo.cl", "investigacion_digital", True),
    ("El Dínamo", "eldynamo.cl", "investigacion_digital", False),
    ("El Siglo", "elsiglo.cl", "investigacion_digital", False),
    ("El Desconcierto", "eldesconcierto.cl", "investigacion_digital", True),
    ("El Líbero", "ellibero.cl", "investigacion_digital", False),
    ("El Ciudadano", "elciudadano.com", "investigacion_digital", False),
    ("Diario UChile", "radio.uchile.cl", "investigacion_digital", False),
    ("Infogate", "infogate.cl", "investigacion_digital", False),
    ("El Periodista", "elperiodista.cl", "investigacion_digital", False),
    # Radio y televisión
    ("BioBioChile", "biobiochile.cl", "television_radio", True),
    ("Cooperativa", "cooperativa.cl", "television_radio", True),
    ("ADN Radio", "adnradio.cl", "television_radio", True),
    ("Radio Agricultura", "radioagricultura.cl", "television_radio", False),
    ("Radio Duna", "duna.cl", "television_radio", False),
    ("Radio Pauta", "pauta.cl", "television_radio", True),
    ("CNN Chile", "cnnchile.com", "television_radio", True),
    ("24 Horas", "24horas.cl", "television_radio", True),
    ("TVN", "tvn.cl", "television_radio", True),
    ("T13", "t13.cl", "television_radio", True),
    ("Canal 13", "canal13.cl", "television_radio", True),
    ("Meganoticias", "meganoticias.cl", "television_radio", True),
    ("Mega", "mega.cl", "television_radio", False),
    ("CHV Noticias", "chilevision.cl", "television_radio", True),
    ("CHV Noticias", "chvnoticias.cl", "television_radio", True),
    # Jurídico y especializado
    ("Diario Constitucional", "diarioconstitucional.cl", "juridico", False),
    ("Estado Diario", "estadodiario.com", "juridico", False),
    ("El Mercurio Legal", "legal.elmercurio.com", "juridico", False),
    # Regionales
    ("SoyChile", "soychile.cl", "regional", True),
    ("Diario Concepción", "diarioconcepcion.cl", "regional", False),
    ("El Rancagüino", "elrancaguino.cl", "regional", False),
    ("La Discusión", "ladiscusion.cl", "regional", False),
    ("Diario El Día", "diarioeldia.cl", "regional", False),
    ("El Observatodo", "elobservatodo.cl", "regional", False),
    ("El Ovallino", "elovallino.cl", "regional", False),
    ("El Martutino", "elmartutino.cl", "regional", False),
    ("La Prensa Austral", "laprensaaustral.cl", "regional", False),
    ("El Pingüino", "elpinguino.com", "regional", False),
    ("Radio Polar", "radiopolar.com", "regional", False),
    ("El Repuertero", "elrepuertero.cl", "regional", False),
    ("Diario de Valdivia", "diariodevaldivia.cl", "regional", False),
    ("El Divisadero", "eldivisadero.cl", "regional", False),
    ("El Aconcagua", "elaconcagua.cl", "regional", False),
    ("Timeline", "timeline.cl", "regional", False),
    # Institucionales (no cuentan como prensa en la portada)
    ("Unidad de Análisis Financiero", "uaf.cl", "institucional", True),
    ("Ministerio Público", "fiscaliadechile.cl", "institucional", True),
    ("Ministerio Público", "ministeriopublico.cl", "institucional", True),
    ("Poder Judicial", "pjud.cl", "institucional", True),
    ("Poder Judicial", "poderjudicial.cl", "institucional", False),
    ("CMF Chile", "cmfchile.cl", "institucional", True),
    ("PDI", "pdichile.cl", "institucional", False),
    ("PDI", "pdi.cl", "institucional", False),
    ("Carabineros", "carabineros.cl", "institucional", False),
    ("Consejo de Defensa del Estado", "cde.cl", "institucional", False),
    ("Contraloría", "contraloria.cl", "institucional", True),
    ("Banco Central", "bcentral.cl", "institucional", False),
    ("SII", "sii.cl", "institucional", True),
    ("Aduanas", "aduana.cl", "institucional", False),
    ("Senado", "senado.cl", "institucional", False),
    ("Cámara de Diputadas y Diputados", "camara.cl", "institucional", True),
    ("Biblioteca del Congreso", "bcn.cl", "institucional", False),
    ("Ministerio de Hacienda", "hacienda.cl", "institucional", False),
    ("Diario Oficial", "diariooficial.interior.gob.cl", "institucional", True),
]

DOMINIOS_CHILENOS = {host for _, host, _, _ in MEDIOS_CHILE}
NOMBRE_POR_DOMINIO = {host: nombre for nombre, host, _, _ in MEDIOS_CHILE}
TIPO_POR_DOMINIO = {host: tipo for _, host, tipo, _ in MEDIOS_CHILE}
DOMINIOS_PRIORITARIOS = [host for _, host, tipo, prio in MEDIOS_CHILE
                         if prio and tipo != "institucional"]
# Todo dominio marcado como prioritario recibe consultas «site:» en los
# buscadores: es la vía garantizada de cobertura cuando un medio no publica
# feed ni news-sitemap utilizable.
DOMINIOS_BUSQUEDA_SITIO = [host for _, host, _, prio in MEDIOS_CHILE if prio]
DOMINIOS_INSTITUCIONALES = {host for _, host, tipo, _ in MEDIOS_CHILE if tipo == "institucional"}

# Nivel B: cualquier dominio bajo el ccTLD chileno o subdominio de gobierno.
SUFIJOS_CHILENOS = (".cl",)
SUFIJOS_INSTITUCIONALES = (".gob.cl", ".gov.cl")

# Dominios que jamás deben tratarse como prensa chilena aunque terminen en .cl
DOMINIOS_VETADOS = {
    "news.google.com", "google.com", "bing.com", "youtube.com", "facebook.com",
    "x.com", "twitter.com", "instagram.com", "tiktok.com", "linkedin.com",
    "msn.com", "yahoo.com", "flipboard.com", "es.wikipedia.org",
}

NOMBRES_MEDIOS_CHILENOS = [
    "la tercera", "diario financiero", "df mas", "df más", "df sud", "emol",
    "el mercurio", "biobiochile", "radio bio bio", "radio bío bío", "ciper",
    "el mostrador", "ex-ante", "ex ante", "interferencia", "the clinic",
    "el dinamo", "el dínamo", "pauta", "radio agricultura", "cooperativa",
    "adn radio", "cnn chile", "24 horas", "t13", "tele13", "meganoticias",
    "mega", "chv noticias", "chilevision", "chilevisión", "la cuarta",
    "la segunda", "las ultimas noticias", "las últimas noticias", "soychile",
    "publimetro", "la hora", "el libero", "el líbero", "el desconcierto",
    "el ciudadano", "diario uchile", "radio uchile", "estrategia",
    "revista capital", "diario concepcion", "diario concepción",
    "el rancaguino", "el rancagüino", "la discusion", "la discusión",
    "diario el dia", "diario el día", "el observatodo", "la prensa austral",
    "el pinguino", "el pingüino", "diario constitucional", "estado diario",
    "unidad de analisis financiero", "unidad de análisis financiero",
    "fiscalia de chile", "fiscalía de chile", "ministerio publico",
    "ministerio público", "cmf chile", "poder judicial", "senado", "camara",
    "cámara de diputadas", "contraloria", "contraloría", "banco central",
    "servicio de impuestos internos", "aduanas", "diario oficial",
]

# Rutas habituales de feeds y sitemaps para el autodescubrimiento.
RUTAS_FEED = [
    "/feed", "/feed/", "/rss", "/rss/", "/rss.xml", "/feed.xml", "/index.xml",
    "/atom.xml", "/feed/rss", "/?feed=rss2", "/rss/todos.xml",
    "/arc/outboundfeeds/rss/?outputType=xml",
    "/arc/outboundfeeds/rss/category/nacional/?outputType=xml",
]
RUTAS_SITEMAP = [
    "/news-sitemap.xml", "/sitemap-news.xml", "/sitemap_news.xml",
    "/news.xml", "/sitemap-noticias.xml",
    "/arc/outboundfeeds/news-sitemap-index?outputType=xml",
    "/arc/outboundfeeds/news-sitemap/?outputType=xml",
    "/sitemap.xml", "/sitemap_index.xml", "/sitemapIndex.xml",
]

# Semillas conocidas: se validan igual, pero ahorran descubrimiento.
SEMILLAS_ENDPOINTS = {
    "latercera.com": {
        "feeds": ["https://www.latercera.com/arc/outboundfeeds/rss/?outputType=xml"],
        "sitemaps": ["https://www.latercera.com/arc/outboundfeeds/news-sitemap-index?outputType=xml"],
    },
    "df.cl": {"feeds": [], "sitemaps": ["https://www.df.cl/noticias/site/sitemap_news.xml"]},
    "biobiochile.cl": {"feeds": ["https://www.biobiochile.cl/rss/rss.xml"],
                       "sitemaps": ["https://www.biobiochile.cl/news-sitemap.xml"]},
    "emol.com": {"feeds": [], "sitemaps": ["https://www.emol.com/sitemap/sitemapIndex.xml"]},
    "elmostrador.cl": {"feeds": ["https://www.elmostrador.cl/feed/"], "sitemaps": []},
    "ciperchile.cl": {"feeds": ["https://www.ciperchile.cl/feed/"], "sitemaps": []},
    "ex-ante.cl": {"feeds": ["https://www.ex-ante.cl/feed/"], "sitemaps": []},
    "interferencia.cl": {"feeds": ["https://interferencia.cl/rss.xml"], "sitemaps": []},
    "cooperativa.cl": {"feeds": ["https://www.cooperativa.cl/noticias/site/tax/port/all/rss_2_0.xml"],
                       "sitemaps": []},
    "uaf.cl": {"feeds": [], "sitemaps": []},
}

CONSULTAS_UAF_NUCLEO = [
    '"Unidad de Análisis Financiero"',
    '"Unidad de Analisis Financiero"',
    '"UAF" "lavado de activos"',
    '"UAF" "lavado de dinero"',
    '"UAF" Chile "operaciones sospechosas"',
    '"Unidad de Análisis Financiero" "Ley 19.913"',
    '"Unidad de Análisis Financiero" Chile',
    '"director de la UAF"',
    '"reporte de operaciones sospechosas" Chile',
]

CONSULTAS_LAFT = [
    '"lavado de activos" Chile',
    '"lavado de dinero" Chile',
    'blanqueo de capitales Chile',
    '"financiamiento del terrorismo" Chile',
    '"operaciones sospechosas" Chile',
    '"cuentas puente" Chile',
    'testaferros "lavado de activos" Chile',
    '"transferencias fraccionadas" Chile',
    '"delitos precedentes" lavado Chile',
    '"beneficiario final" Chile "lavado"',
    '"debida diligencia" "lavado de activos" Chile',
    '"Sistema de Inteligencia Económica" Chile',
    '"Ley 21.121" Chile lavado',
    '"Ley 21.595" delitos económicos Chile',
    'GAFILAT Chile',
    'GAFI Chile "lavado de activos"',
    '"secreto bancario" "lavado de activos" Chile',
    '"oficial de cumplimiento" Chile',
    '"sujeto obligado" UAF Chile',
    '(formalizados OR imputados OR condenados) "lavado de activos" Chile',
    '"Tren de Aragua" (lavado OR fraude OR extorsión) Chile',
    '"Operación Tokio" Chile',
    '"caso Sartor" Chile',
    '"crimen organizado" "ruta del dinero" Chile',
    '(banco OR fintech OR "medios de pago") "lavado de activos" Chile',
    '(notario OR notaría OR conservador OR inmobiliaria) lavado Chile',
    '(casino OR automotora OR factoring OR leasing) "lavado de activos" Chile',
    '(criptomonedas OR criptoactivos) "lavado de activos" Chile',
    '(fondos OR corredora OR seguros OR AFP) "lavado de activos" Chile',
]


def construye_consultas_prensa():
    consultas = list(CONSULTAS_UAF_NUCLEO) + list(CONSULTAS_LAFT)
    for dominio in DOMINIOS_BUSQUEDA_SITIO:
        consultas.append(f'site:{dominio} ("Unidad de Análisis Financiero" OR UAF)')
        consultas.append(f'site:{dominio} ("lavado de activos" OR "lavado de dinero" '
                         f'OR "operaciones sospechosas" OR blanqueo)')
    return list(dict.fromkeys(consultas))


CONSULTAS_PRENSA = construye_consultas_prensa()

CONSULTAS_GDELT = [
    '"unidad de analisis financiero"',
    '"unidad de análisis financiero"',
    '(UAF AND "lavado de activos")',
    '"lavado de activos" AND chile',
    '"financiamiento del terrorismo" AND chile',
]

CONSULTAS_BING = CONSULTAS_UAF_NUCLEO + [
    '"lavado de activos" Chile UAF',
    '"operaciones sospechosas" UAF Chile',
    '"financiamiento del terrorismo" Chile',
] + [f'site:{d} ("Unidad de Análisis Financiero" OR "lavado de activos")'
     for d in DOMINIOS_PRIORITARIOS[:18]]

CONSULTAS_SOCIALES = [
    '"lavado de activos"',
    '"Unidad de Análisis Financiero"',
    'UAF Chile',
    '"financiamiento del terrorismo" Chile',
]
SUBREDDITS = ["chile", "RepublicaDeChile"]
PLATAFORMAS = [
    {"id": "reddit", "nombre": "Reddit", "estado": "monitoreado",
     "nota": "Consulta pública JSON; la plataforma puede limitar el acceso automatizado."},
    {"id": "bluesky", "nombre": "Bluesky", "estado": "monitoreado",
     "nota": "API pública de búsqueda de publicaciones, sin autenticación."},
]

DISPARADORES_CANDIDATO = [
    "uaf", "unidad de analisis financiero", "lavado", "blanqueo", "activos",
    "dinero", "fraude", "estafa", "extorsion", "secuestro", "tren de aragua",
    "crimen organizado", "narcotrafico", "corrupcion", "cohecho", "soborno",
    "formaliz", "imputad", "condena", "prision preventiva", "fiscalia",
    "ministerio publico", "allanamiento", "incaut", "testaferro", "cuentas",
    "transferencias", "banco", "bancaria", "fintech", "mercado pago", "cripto",
    "notario", "notaria", "inmobiliaria", "automotora", "vehiculo", "fondos",
    "corredora", "sartor", "secreto bancario", "beneficiario final",
    "operaciones sospechosas", "sujeto obligado", "cumplimiento", "cmf",
    "aduana", "zona franca", "casino", "apuestas", "factoring", "leasing",
    "contrabando", "tributari", "evasion", "facturas falsas", "delito",
    "delitos economicos", "gafilat", "gafi", "sanciones", "ofac", "pep",
]

# ─────────────────────────────────────────────────────────────
# Taxonomías (claves y etiquetas compatibles con el dashboard)
# ─────────────────────────────────────────────────────────────

FENOMENOS = {
    "sartor":   ["sartor", "azul azul", "michael clark", "larraín mery", "larrain mery",
                 "tactical sport", "antumalal"],
    "tokio":    ["operación tokio", "operacion tokio", "pérez asencio", "perez asencio",
                 "bexgroup", "bexdigital"],
    "tren_aragua": ["tren de aragua"],
    "trata":    ["trata de personas", "explotación sexual", "explotacion sexual"],
    "narco":    ["narcotráfico", "narcotrafico", "tráfico de drogas", "trafico de drogas",
                 "microtráfico", "microtrafico"],
    "normativa": ["circular", "ley 19.913", "ley n°19.913", "inteligencia económica",
                  "inteligencia economica", "secreto bancario", "21.595", "delitos económicos"],
    "corrupcion": ["cohecho", "malversación", "malversacion", "fraude al fisco", "soborno",
                   "probidad"],
}
FENOMENO_ETIQUETA = {
    "sartor": "Caso Sartor AGF", "tokio": "Operación Tokio",
    "tren_aragua": "Tren de Aragua", "trata": "Trata de personas",
    "narco": "Narcotráfico", "normativa": "Marco normativo",
    "corrupcion": "Corrupción", "otro": "Otros",
}

NATURALEZAS = {
    "policial":     ["detenid", "operativo", "allanamiento", "incaut", "desarticul",
                     "pdi", "carabineros", "policia de investigaciones", "megaoperativo",
                     "decomis", "golpe a", "captur"],
    "judicial":     ["formaliz", "prision preventiva", "cautelar", "condena", "sentencia",
                     "juzgado", "tribunal", "corte de apelaciones", "corte suprema",
                     "imputad", "querella", "audiencia", "acusacion", "sobreseimiento"],
    "politico":     ["proyecto de ley", "camara de diputados", "senado", "comision mixta",
                     "ministro", "subsecretari", "gobierno", "oposicion", "congreso",
                     "tramitacion", "veto", "indicacion"],
    "normativo":    ["circular", "reglamento", "normativa", "instructivo", "cmf",
                     "oficio circular", "entra en vigencia", "modificacion legal",
                     "ley n", "decreto"],
    "crimen_org":   ["organizacion criminal", "banda criminal", "asociacion ilicita",
                     "asociacion criminal", "estructura criminal", "red criminal",
                     "celula", "faccion", "cartel", "megabanda"],
    "investigacion": ["reportaje", "ciper", "revela", "documentos internos", "filtr",
                      "investigacion periodistica", "segun pudo establecer"],
    "institucional": ["nombra", "asume", "renuncia", "presupuesto", "dotacion",
                      "convenio", "cooperacion internacional", "gafilat", "gafi",
                      "memorandum", "capacitacion"],
    "analisis":     ["columna", "opinion", "analisis", "estudio", "informe de",
                     "experto", "seminario", "entrevista", "balance"],
}
NATURALEZA_ETIQUETA = {
    "policial": "Policial", "judicial": "Judicial", "politico": "Político-legislativo",
    "normativo": "Normativo", "crimen_org": "Crimen organizado",
    "investigacion": "Investigación periodística", "institucional": "Institucional",
    "analisis": "Análisis y opinión",
}

PRECEDENTES = {
    "narcotrafico":  ["narcotrafico", "trafico de drogas", "microtrafico", "ley 20.000",
                      "cocaina", "ketamina", "marihuana", "droga"],
    "economicos":    ["administracion desleal", "informacion falsa al mercado",
                      "delitos economicos", "21.595", "estafa", "fraude",
                      "negociacion incompatible", "uso de informacion privilegiada",
                      "opa", "sartor", "administradora general de fondos"],
    "corrupcion":    ["cohecho", "malversacion", "fraude al fisco", "soborno",
                      "probidad", "trafico de influencias", "corrupcion"],
    "trata":         ["trata de personas", "explotacion sexual", "trafico de migrantes",
                      "proxenetismo"],
    "tributarios":   ["delito tributario", "evasion", "facturas falsas", "sii",
                      "elusion", "boletas falsas"],
    "contrabando":   ["contrabando", "aduana", "internacion ilegal", "mercancia no declarada"],
    "extorsion":     ["extorsion", "secuestro", "sicariato", "amenaza", "cobro de piso"],
    "armas":         ["trafico de armas", "ley de armas", "arsenal", "municiones"],
    "terrorismo":    ["financiamiento del terrorismo", "acto terrorista", "ley antiterrorista"],
    "ciberdelito":   ["ciberdelito", "delito informatico", "phishing", "criptoactivo",
                      "estafa digital", "billetera virtual"],
    "ambiental":     ["delito ambiental", "tala ilegal", "pesca ilegal", "mineria ilegal"],
    "receptacion":   ["receptacion", "robo de vehiculos", "desarme de autos"],
}
PRECEDENTE_ETIQUETA = {
    "narcotrafico": "Narcotráfico", "economicos": "Delitos económicos",
    "corrupcion": "Corrupción", "trata": "Trata y tráfico de personas",
    "tributarios": "Delitos tributarios", "contrabando": "Contrabando y aduanero",
    "extorsion": "Extorsión y secuestro", "armas": "Tráfico de armas",
    "terrorismo": "Financiamiento del terrorismo", "ciberdelito": "Ciberdelito",
    "ambiental": "Delitos ambientales", "receptacion": "Receptación",
    "indeterminado": "No determinado",
}

ENCUADRE_NUCLEO = ["lavado de activos", "lavado de dinero", "blanqueo",
                   "activos de origen ilicito", "ruta del dinero",
                   "operaciones sospechosas", "operacion sospechosa"]

SUJETOS_OBLIGADOS = {
    "banca_finanzas": [
        "banco", "bancos", "bancari", "institucion financiera", "cooperativa de ahorro",
        "caja de compensacion", "casa de cambio", "transferencia de dinero",
        "transporte de valores", "representacion de banco extranjero",
    ],
    "mercado_valores_fondos": [
        "administradora general de fondos", "agf", "fondos mutuos", "fondo de inversion",
        "corredora de bolsa", "corredor de bolsa", "agente de valores", "bolsa de valores",
        "securitizacion", "deposito de valores", "mercado de futuro", "mercado de opciones",
    ],
    "pensiones_seguros": [
        "afp", "administradora de fondos de pensiones", "compania de seguros",
        "compañia de seguros", "aseguradora", "seguro de vida", "mutuo hipotecario",
    ],
    "fintech_pagos": [
        "fintech", "fintec", "medio de pago", "tarjeta de credito", "tarjeta de pago",
        "iniciacion de pagos", "plataforma de financiamiento colectivo", "crowdfunding",
        "custodia de instrumentos financieros", "sistema alternativo de transaccion",
        "billetera digital", "billetera virtual", "proveedor de servicios financieros",
        "mercado pago", "tenpo", "mach", "paypal", "pasarela de pago", "criptoactivo",
        "exchange de criptomonedas",
    ],
    "inmobiliario_notarial": [
        "inmobiliaria", "gestion inmobiliaria", "corredor de propiedades",
        "corredora de propiedades", "notario", "notaria", "conservador de bienes raices",
        "conservador", "compraventa de inmueble", "mercado inmobiliario",
    ],
    "vehiculos_leasing_factoring": [
        "automotora", "comercializadora de vehiculos", "arriendo de vehiculos",
        "rent a car", "leasing", "arrendamiento financiero", "factoring", "factoraje",
        "compra de vehiculos", "adquisicion de vehiculos",
    ],
    "casinos_deporte": [
        "casino de juego", "casino flotante", "hipodromo", "club de tiro", "club de caza",
        "club de pesca", "organizacion deportiva profesional", "club de futbol",
        "sociedad anonima deportiva", "sadp", "apuestas en linea", "casas de apuestas",
    ],
    "aduanas_zonas_francas": [
        "agente de aduana", "aduana", "zona franca", "usuario de zona franca",
        "sociedad administradora de zona franca", "mercancia", "internacion",
    ],
    "metales_joyas_remates": [
        "joyeria", "joyas", "piedras preciosas", "metales preciosos", "oro",
        "casa de remate", "martillero", "remate", "subasta",
    ],
    "armas": [
        "fabricacion de armas", "venta de armas", "armeria", "trafico de armas",
        "municiones", "arsenal",
    ],
    "otros_obligados": [
        "sujeto obligado", "sujetos obligados", "entidad reportante", "entidades reportantes",
        "oficial de cumplimiento", "reporte de operaciones sospechosas", "reporte ros",
        "reporte de operaciones en efectivo", "reporte roe",
    ],
}
SUJETO_OBLIGADO_ETIQUETA = {
    "banca_finanzas": "Banca y servicios financieros",
    "mercado_valores_fondos": "Mercado de valores y fondos",
    "pensiones_seguros": "Pensiones, seguros y mutuos",
    "fintech_pagos": "Fintech y medios de pago",
    "inmobiliario_notarial": "Inmobiliario, notarios y conservadores",
    "vehiculos_leasing_factoring": "Vehículos, leasing y factoring",
    "casinos_deporte": "Casinos, apuestas y deporte profesional",
    "aduanas_zonas_francas": "Aduanas y zonas francas",
    "metales_joyas_remates": "Metales, joyas y remates",
    "armas": "Fabricación y venta de armas",
    "otros_obligados": "Otros sujetos obligados",
}

IMPACTO_SUJETO = {
    "vulneracion_la": [
        "imputad", "formaliz", "condena", "investigacion penal", "allanamiento",
        "incaut", "defraud", "estafa", "utilizad para lavar", "canaliz activos",
        "operacion sospechosa", "querella", "prision preventiva",
    ],
    "cambio_regulatorio": [
        "circular", "normativa", "reglamento", "ley", "entra en vigencia", "modifica",
        "instruccion", "exigencia", "obligacion", "debida diligencia", "beneficiario final",
        "persona expuesta politicamente", "pep", "sancion", "fiscalizacion",
    ],
    "gestion_cumplimiento": [
        "oficial de cumplimiento", "programa de cumplimiento", "modelo de prevencion",
        "reporte de operaciones sospechosas", "ros", "roe", "capacitacion", "prevencion",
        "conocimiento del cliente", "kyc", "monitoreo transaccional",
    ],
    "cambio_industria": [
        "fusion", "adquisicion", "quiebra", "insolvencia", "ciberataque", "filtracion",
        "vulneracion", "fraude", "nueva tecnologia", "criptoactivo", "digitalizacion",
        "riesgo operacional", "mercado", "supervision sectorial",
    ],
}
IMPACTO_SUJETO_ETIQUETA = {
    "vulneracion_la": "Vinculación o vulneración por LA/FT",
    "cambio_regulatorio": "Cambio regulatorio o de supervisión",
    "gestion_cumplimiento": "Gestión de cumplimiento preventivo",
    "cambio_industria": "Cambio relevante en la industria",
}

TOPICOS = {
    "fiscalizacion": ["fiscaliz", "sancion", "multa", "supervision", "incumplimiento"],
    "reportes": ["reporte de operaciones sospechosas", "reporte ros", "ros",
                 "reporte de operaciones en efectivo", "roe", "sujeto obligado", "reportante"],
    "normativa": ["circular", "normativa", "reglamento", "ley 19.913", "proyecto de ley",
                  "secreto bancario", "sistema de inteligencia economica"],
    "inteligencia": ["inteligencia financiera", "analisis financiero", "operacion sospechosa",
                     "ruta del dinero", "trazabilidad", "informe financiero"],
    "investigacion_penal": ["fiscalia", "formaliz", "imputad", "tribunal", "condena",
                            "querella", "investigacion penal", "prision preventiva"],
    "crimen_organizado": ["crimen organizado", "tren de aragua", "banda criminal",
                          "organizacion criminal", "narcotrafico", "trata de personas"],
    "cooperacion": ["gafi", "gafilat", "egmont", "cooperacion", "convenio", "estrategia nacional"],
    "prevencion": ["prevencion", "lavado de activos", "financiamiento del terrorismo", "la/ft"],
    "gestion_uaf": ["director", "cuenta publica", "presupuesto", "dotacion", "capacitacion",
                    "unidad de analisis financiero informa", "uaf publica"],
    "sujetos_obligados": ["sujeto obligado", "entidad reportante", "oficial de cumplimiento",
                          "debida diligencia", "beneficiario final", "conocimiento del cliente",
                          "reporte ros", "reporte roe", "circular 62"],
    "vulneracion_sectorial": ["banco", "fintech", "inmobiliaria", "notario", "casino",
                              "automotora", "factoring", "leasing", "corredora de bolsa",
                              "aseguradora", "zona franca", "joyeria"],
}
TOPICO_ETIQUETA = {
    "fiscalizacion": "Fiscalización y sanciones",
    "reportes": "Reportes y sujetos obligados",
    "normativa": "Normativa y regulación",
    "inteligencia": "Inteligencia financiera",
    "investigacion_penal": "Investigación y persecución penal",
    "crimen_organizado": "Crimen organizado",
    "cooperacion": "Cooperación y estándares internacionales",
    "prevencion": "Prevención de LA/FT",
    "gestion_uaf": "Gestión institucional UAF",
    "sujetos_obligados": "Sujetos obligados y cumplimiento",
    "vulneracion_sectorial": "Vulneración de industrias supervisadas",
    "otros": "Otros asuntos UAF/LAFT",
}

TIPOS_MEDIO = {
    "economico": ["diario financiero", "df mas", "df más", "df sud", "pulso", "estrategia",
                  "revista capital", "mercurio inversiones", "mundo maritimo"],
    "television_radio": ["cnn chile", "24 horas", "t13", "tele13", "meganoticias", "mega",
                         "chv noticias", "chilevision", "chilevisión", "biobiochile",
                         "radio biobio", "radio bío bío", "cooperativa", "adn radio",
                         "radio agricultura", "radio duna", "pauta", "tvn", "canal 13"],
    "juridico": ["diario constitucional", "estado diario", "mercurio legal", "idealex"],
    "investigacion_digital": ["ciper", "interferencia", "el mostrador", "ex-ante", "ex ante",
                              "el desconcierto", "the clinic", "el dinamo", "el dínamo",
                              "el libero", "el líbero", "el ciudadano", "diario uchile",
                              "infogate", "el periodista"],
    "regional": ["soychile", "estrella de", "diario de atacama", "diario concepcion",
                 "diario concepción", "el austral", "el rancaguino", "el rancagüino",
                 "diario el dia", "diario el día", "la discusion", "la discusión",
                 "el observatodo", "el ovallino", "el martutino", "la prensa austral",
                 "el pinguino", "el pingüino", "radio polar", "el repuertero",
                 "diario de valdivia", "el divisadero", "el aconcagua", "timeline"],
    "institucional": ["unidad de analisis financiero", "unidad de análisis financiero", "uaf",
                      "gobierno", "ministerio", "fiscalia", "fiscalía", "ministerio publico",
                      "ministerio público", "poder judicial", "pdi", "carabineros", "senado",
                      "camara", "cámara", "gafilat", "cmf", "contraloria", "contraloría",
                      "banco central", "servicio de impuestos internos", "aduanas",
                      "diario oficial", "consejo de defensa del estado"],
    "prensa_nacional": ["emol", "la tercera", "el mercurio", "latercera", "la segunda", "lun",
                        "las ultimas noticias", "las últimas noticias", "la cuarta",
                        "publimetro", "la hora"],
}
TIPO_MEDIO_ETIQUETA = {
    "economico": "Prensa económica y financiera",
    "television_radio": "Televisión y radio",
    "juridico": "Prensa jurídica especializada",
    "investigacion_digital": "Medio digital o de investigación",
    "regional": "Prensa regional",
    "institucional": "Fuente institucional",
    "prensa_nacional": "Prensa nacional",
    "otro": "Otro medio digital",
}

ROL_SUJETO_ETIQUETA = {
    "victima": "Víctima o sector afectado",
    "canal": "Canal utilizado para mover o integrar fondos",
    "investigado": "Entidad o sector investigado",
    "regulado": "Sector afectado por regulación o supervisión",
    "mencionado": "Sector mencionado",
}

NIVEL_FUENTE_ETIQUETA = {
    "verificada": "Medio chileno verificado",
    "chilena": "Dominio chileno (.cl)",
    "institucional": "Fuente institucional chilena",
    "nombre": "Identificada por nombre del medio",
}


# ─────────────────────────────────────────────────────────────
# Utilidades de texto
# ─────────────────────────────────────────────────────────────

_lock_log = threading.Lock()


def log(msg):
    marca = datetime.now(TZ_CL).strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{marca}] {msg}"
    with _lock_log:
        print(linea, flush=True)
        try:
            with open(BITACORA, "a", encoding="utf-8") as fh:
                fh.write(linea + "\n")
        except OSError:
            pass


def normaliza(texto):
    """Minúsculas sin tildes y con espacios colapsados."""
    texto = str(texto or "").lower()
    texto = unicodedata.normalize("NFD", texto)
    texto = "".join(c for c in texto if unicodedata.category(c) != "Mn")
    return re.sub(r"\s+", " ", texto).strip()


def _patron_aguja(aguja):
    n = normaliza(aguja)
    if not n:
        return ""
    esc = re.escape(n).replace(r"\ ", r"\s+")
    if " " not in n and len(n) <= 5:
        return r"\b" + esc + r"\b"
    return esc


@lru_cache(maxsize=4096)
def _compila(agujas):
    partes = [p for p in (_patron_aguja(a) for a in agujas) if p]
    if not partes:
        return None
    return re.compile("|".join(partes))


def contiene(texto_norm, agujas):
    patron = _compila(tuple(agujas))
    return bool(patron and patron.search(texto_norm or ""))


def claves_presentes(texto_norm, taxonomia):
    return [k for k, v in taxonomia.items() if contiene(texto_norm, v)]


def limpia_html(s):
    s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", str(s or ""))
    s = re.sub(r"<[^>]+>", " ", s)
    s = html_mod.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


# ─────────────────────────────────────────────────────────────
# URLs y clasificación de fuente
# ─────────────────────────────────────────────────────────────

AGREGADORES = {"news.google.com", "google.com", "bing.com", "www.bing.com",
               "consent.google.com", "gdeltproject.org", "api.gdeltproject.org"}


def dominio_url(url):
    try:
        host = (urllib.parse.urlsplit(url or "").hostname or "").lower().strip(".")
    except ValueError:
        return ""
    for prefijo in ("www.", "m.", "amp.", "www2.", "beta."):
        if host.startswith(prefijo):
            host = host[len(prefijo):]
    return host


def _coincide_dominio(host, dominios):
    host = (host or "").lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in dominios)


def dominio_institucional(host):
    host = (host or "").lower().strip(".")
    if _coincide_dominio(host, DOMINIOS_INSTITUCIONALES):
        return True
    return host.endswith(SUFIJOS_INSTITUCIONALES)


def nivel_dominio_chileno(host):
    """Devuelve el nivel de confianza del dominio: verificada, institucional, chilena o ''."""
    host = (host or "").lower().strip(".")
    if not host or _coincide_dominio(host, DOMINIOS_VETADOS):
        return ""
    if dominio_institucional(host):
        return "institucional"
    if _coincide_dominio(host, DOMINIOS_CHILENOS):
        return "verificada"
    if host.endswith(SUFIJOS_CHILENOS):
        return "chilena"
    return ""


def url_http(url):
    try:
        p = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError:
        return False
    return p.scheme in {"http", "https"} and bool(p.hostname)


def limpia_url(url):
    """Normaliza: solo http(s), sin credenciales, sin query de rastreo ni fragmento."""
    try:
        p = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError:
        return ""
    if p.scheme not in {"http", "https"} or not p.hostname:
        return ""
    host = p.hostname.lower()
    if p.port and p.port not in (80, 443):
        host = f"{host}:{p.port}"
    query = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=False)
             if not k.lower().startswith(("utm_", "fbclid", "gclid", "mc_", "_ga"))
             and k.lower() not in {"ref", "sref", "smid", "share", "outputtype"}]
    return urllib.parse.urlunsplit((p.scheme, host, p.path, urllib.parse.urlencode(query), ""))


def clasifica_fuente(reg):
    """Determina si el registro proviene de una fuente chilena y con qué nivel.

    Si existe un dominio editorial real, ese dominio manda. El nombre del medio
    solo se usa cuando el enlace sigue siendo del agregador.
    """
    editoriales = []
    for campo in ("url_final", "link", "fuente_url"):
        host = dominio_url(reg.get(campo, ""))
        if not host or host in AGREGADORES:
            continue
        editoriales.append(host)
        nivel = nivel_dominio_chileno(host)
        if nivel:
            return True, nivel, host
    if editoriales:
        return False, "", editoriales[0]
    medio = normaliza(reg.get("medio", ""))
    if medio and any(normaliza(n) in medio for n in NOMBRES_MEDIOS_CHILENOS):
        return True, "nombre", ""
    return False, "", ""


def es_fuente_chilena(reg):
    return clasifica_fuente(reg)[0]


def es_fuente_institucional(reg):
    for campo in ("url_final", "link", "fuente_url"):
        if dominio_institucional(dominio_url(reg.get(campo, ""))):
            return True
    return False


def id_estable(url, titulo=""):
    """Identidad por URL canónica; el titular solo se usa si no hay URL utilizable."""
    base = limpia_url(url)
    if not base:
        base = "titulo:" + normaliza(titulo)
    return hashlib.sha1(normaliza(base).encode("utf-8")).hexdigest()[:14]


def hash_url(url):
    return hashlib.sha1(normaliza(limpia_url(url) or url or "").encode("utf-8")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────
# Capa de red endurecida
# ─────────────────────────────────────────────────────────────

class ErrorRed(Exception):
    pass


@lru_cache(maxsize=2048)
def _host_publico(host):
    """Evita SSRF: rechaza hosts que resuelven a rangos privados o reservados."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global or ip.is_multicast:
            return False
    return bool(infos)


def _url_segura(url):
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if p.scheme not in {"http", "https"} or not p.hostname:
        return False
    if p.port and p.port not in (80, 443):
        return False
    return _host_publico(p.hostname)


class _Redirecciones(urllib.request.HTTPRedirectHandler):
    max_repeats = 4
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _url_segura(newurl):
            raise urllib.error.HTTPError(newurl, code, "redirección no permitida", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_Redirecciones())
_OPENER.addheaders = []

# Endpoints diseñados para consulta frecuente: no requieren el intervalo de
# cortesía que se aplica a los sitios de los medios.
INTERVALO_ESPECIAL = {
    "news.google.com": 0.35, "bing.com": 0.5, "api.gdeltproject.org": 0.5,
    "public.api.bsky.app": 0.6, "reddit.com": 1.2,
}

_ultimo_por_host = {}
_lock_host = threading.Lock()


def _espera_turno(host):
    intervalo = INTERVALO_ESPECIAL.get(host, INTERVALO_POR_HOST)
    if intervalo <= 0:
        return
    while True:
        with _lock_host:
            ahora = time.monotonic()
            listo = _ultimo_por_host.get(host, 0.0) + intervalo
            if ahora >= listo:
                _ultimo_por_host[host] = ahora
                return
            espera = listo - ahora
        time.sleep(min(espera, 2.0))


def _descomprime(datos, headers):
    codificacion = (headers.get("Content-Encoding") or "").lower()
    try:
        if "gzip" in codificacion:
            return gzip.decompress(datos)
        if "deflate" in codificacion:
            return zlib.decompress(datos, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return datos
    return datos


_robots_cache = {}
_lock_robots = threading.Lock()


def _robots_permite(url):
    if not RESPETA_ROBOTS:
        return True
    host = dominio_url(url)
    p = urllib.parse.urlsplit(url)
    clave = f"{p.scheme}://{p.netloc}"
    with _lock_robots:
        parser = _robots_cache.get(clave, "pendiente")
    if parser == "pendiente":
        parser = urllib.robotparser.RobotFileParser()
        try:
            datos, _, headers = descarga(clave + "/robots.txt", accept="text/plain",
                                        max_bytes=400_000, robots=False, reintentos=1)
            texto = _decodifica(datos, headers)
            parser.parse(texto.splitlines())
        except Exception:
            parser = None  # sin robots.txt legible: se permite
        with _lock_robots:
            _robots_cache[clave] = parser
    if parser is None:
        return True
    try:
        return parser.can_fetch(UA_ROBOTS, url)
    except Exception:
        return True


def descarga(url, accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             max_bytes=None, robots=True, reintentos=2, cuerpo=None, cabeceras=None):
    """Descarga defensiva. Devuelve (bytes, url_final, headers)."""
    if not _url_segura(url):
        raise ErrorRed(f"url no permitida: {url[:120]}")
    if robots and not _robots_permite(url):
        raise ErrorRed("robots.txt no permite el acceso")
    tope = max_bytes or MAX_BYTES_RESPUESTA
    host = dominio_url(url)
    ultimo_error = None
    for intento in range(max(1, reintentos)):
        if tiempo_agotado(reserva=45):
            raise ErrorRed("presupuesto de tiempo agotado")
        _espera_turno(host)
        cab = {
            "User-Agent": UA,
            "Accept": accept,
            "Accept-Language": "es-CL,es;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
        }
        cab.update(cabeceras or {})
        req = urllib.request.Request(url, headers=cab, data=cuerpo,
                                     method="POST" if cuerpo else "GET")
        try:
            with _OPENER.open(req, timeout=TIMEOUT) as r:
                bruto = r.read(tope + 1)
                headers = dict(r.headers.items())
                final = r.geturl()
            if len(bruto) > tope:
                bruto = bruto[:tope]
            return _descomprime(bruto, headers), final, headers
        except Exception as e:  # noqa: BLE001 — cualquier fallo de red se reintenta
            ultimo_error = e
            codigo = getattr(e, "code", None)
            if codigo in (401, 403, 404, 410, 451):
                break
            time.sleep(0.7 * (intento + 1))
    raise ErrorRed(f"{type(ultimo_error).__name__}: {ultimo_error}")


def _decodifica(contenido, headers=None):
    headers = headers or {}
    ctype = headers.get("Content-Type", headers.get("content-type", ""))
    m = re.search(r"charset=[\"']?([\w.-]+)", ctype, re.I)
    codificaciones = [m.group(1)] if m else []
    cabeza = contenido[:2048]
    m2 = re.search(rb"charset=[\"']?([\w.-]+)", cabeza, re.I)
    if m2:
        try:
            codificaciones.append(m2.group(1).decode("ascii", "ignore"))
        except Exception:
            pass
    codificaciones += ["utf-8", "windows-1252", "latin-1"]
    for cod in codificaciones:
        try:
            return contenido.decode(cod)
        except (UnicodeDecodeError, LookupError):
            continue
    return contenido.decode("utf-8", errors="replace")


def xml_seguro(contenido):
    """Parsea XML rechazando DTD y entidades externas (XXE / billion laughs)."""
    if isinstance(contenido, bytes):
        muestra = contenido[:4096].lower()
        if b"<!doctype" in muestra or b"<!entity" in muestra:
            raise ErrorRed("xml con DTD rechazado")
    else:
        if "<!doctype" in contenido[:4096].lower():
            raise ErrorRed("xml con DTD rechazado")
    return ET.fromstring(contenido)


def json_seguro(contenido, headers=None):
    texto = _decodifica(contenido, headers) if isinstance(contenido, bytes) else contenido
    return json.loads(texto)


# ─────────────────────────────────────────────────────────────
# Extracción de artículos
# ─────────────────────────────────────────────────────────────

class _ParserArticulo(HTMLParser):
    """Extractor conservador de metadatos, cuerpo y enlaces salientes."""

    BLOQUES = {"p", "h1", "h2", "h3", "h4", "li", "blockquote", "figcaption"}
    OMITIR = {"script", "style", "noscript", "svg", "form", "button", "nav",
              "footer", "aside", "template", "iframe"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta = {}
        self.canonical = ""
        self.amphtml = ""
        self.feeds = []
        self.time_values = []
        self.enlaces = []
        self.article_depth = 0
        self.skip_depth = 0
        self.capture_tag = None
        self.capture_in_article = False
        self.capture = []
        self.article_blocks = []
        self.all_blocks = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        a = {str(k).lower(): (v or "") for k, v in attrs}
        if tag in self.OMITIR:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "article":
            self.article_depth += 1
        if tag == "meta":
            clave = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            valor = a.get("content", "").strip()
            if clave and valor:
                self.meta.setdefault(clave, valor)
        elif tag == "link":
            rel = a.get("rel", "").lower()
            tipo = a.get("type", "").lower()
            href = a.get("href", "").strip()
            if "canonical" in rel and href:
                self.canonical = self.canonical or href
            if "amphtml" in rel and href:
                self.amphtml = self.amphtml or href
            if "alternate" in rel and href and ("rss" in tipo or "atom" in tipo):
                self.feeds.append(href)
        elif tag == "time" and a.get("datetime"):
            self.time_values.append(a["datetime"].strip())
        elif tag == "a" and a.get("href"):
            if len(self.enlaces) < 400:
                self.enlaces.append(a["href"].strip())
        if tag in self.BLOQUES and self.capture_tag is None:
            self.capture_tag = tag
            self.capture_in_article = self.article_depth > 0
            self.capture = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.OMITIR:
            if self.skip_depth:
                self.skip_depth -= 1
            return
        if self.skip_depth:
            return
        if self.capture_tag == tag:
            texto = re.sub(r"\s+", " ", " ".join(self.capture)).strip()
            if texto:
                self.all_blocks.append(texto)
                if self.capture_in_article:
                    self.article_blocks.append(texto)
            self.capture_tag = None
            self.capture_in_article = False
            self.capture = []
        if tag == "article" and self.article_depth:
            self.article_depth -= 1

    def handle_data(self, data):
        if not self.skip_depth and self.capture_tag and data.strip():
            self.capture.append(data.strip())


def _objetos_jsonld(texto_html):
    scripts = re.findall(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        texto_html, flags=re.I | re.S,
    )
    salida = []
    for bloque in scripts[:12]:
        limpio = html_mod.unescape(bloque).strip()
        try:
            obj = json.loads(limpio)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        pendientes = obj if isinstance(obj, list) else [obj]
        guardia = 0
        while pendientes and guardia < 200:
            guardia += 1
            actual = pendientes.pop(0)
            if isinstance(actual, dict):
                salida.append(actual)
                for clave in ("@graph", "itemListElement"):
                    hijos = actual.get(clave)
                    if isinstance(hijos, list):
                        pendientes.extend(hijos)
            elif isinstance(actual, list):
                pendientes.extend(actual)
    return salida


MESES_ES = {
    "enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6,
    "julio": 7, "agosto": 8, "septiembre": 9, "setiembre": 9, "octubre": 10,
    "noviembre": 11, "diciembre": 12,
}


def parsea_fecha(cadena):
    """Fechas RFC-822 e ISO habituales en RSS/Atom → datetime en huso de Chile."""
    if not cadena:
        return None
    cadena = str(cadena).strip()
    formatos = (
        "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S", "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
    )
    for fmt in formatos:
        try:
            dt = datetime.strptime(cadena, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc if fmt.endswith("Z") else TZ_CL)
        return dt.astimezone(TZ_CL)
    return None


def parsea_fecha_flexible(valor):
    if not valor:
        return None
    valor = limpia_html(str(valor)).strip()
    if not valor:
        return None
    try:
        dt = datetime.fromisoformat(valor.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ_CL)
        return dt.astimezone(TZ_CL)
    except ValueError:
        pass
    dt = parsea_fecha(valor)
    if dt:
        return dt
    n = normaliza(valor)
    m = re.search(r"\b(\d{1,2})\s+(?:de\s+)?([a-z]+)\s+(?:de\s+)?(20\d{2})\b", n)
    if m and m.group(2) in MESES_ES:
        hora = re.search(r"\b(\d{1,2}):(\d{2})\b", n)
        h, mi = (int(hora.group(1)), int(hora.group(2))) if hora else (12, 0)
        try:
            return datetime(int(m.group(3)), MESES_ES[m.group(2)], int(m.group(1)),
                            min(h, 23), min(mi, 59), tzinfo=TZ_CL)
        except ValueError:
            return None
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", n)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 12, 0, tzinfo=TZ_CL)
        except ValueError:
            return None
    return None


RUIDO_BLOQUE = (
    "suscribete", "suscríbete", "inicia sesion", "politica de privacidad",
    "terminos y condiciones", "todos los derechos reservados", "aceptar cookies",
    "lo mas leido", "lo ultimo", "compartir en", "sigue leyendo", "newsletter",
    "regalar este articulo", "copiar enlace", "acepto los terminos",
)


def extrae_articulo(contenido, url_final="", headers=None):
    texto_html = _decodifica(contenido, headers)
    parser = _ParserArticulo()
    try:
        parser.feed(texto_html)
        parser.close()
    except Exception:
        pass

    cuerpo_json = titulo_json = descripcion_json = url_json = ""
    fecha_json = None
    for obj in _objetos_jsonld(texto_html):
        tipos = obj.get("@type", "")
        tipos = tipos if isinstance(tipos, list) else [tipos]
        es_articulo = any(str(t).lower() in {
            "article", "newsarticle", "reportagenewsarticle", "analysisnewsarticle",
            "opinionnewsarticle", "blogposting", "liveblogposting", "webpage",
        } for t in tipos)
        if not es_articulo and not obj.get("articleBody"):
            continue
        cuerpo_json = cuerpo_json or limpia_html(obj.get("articleBody", ""))
        titulo_json = titulo_json or limpia_html(obj.get("headline", ""))
        descripcion_json = descripcion_json or limpia_html(obj.get("description", ""))
        fecha_json = fecha_json or parsea_fecha_flexible(
            obj.get("datePublished") or obj.get("dateCreated") or obj.get("dateModified"))
        if not url_json:
            bruto = obj.get("url") or obj.get("mainEntityOfPage") or ""
            if isinstance(bruto, dict):
                bruto = bruto.get("@id", "") or bruto.get("url", "")
            url_json = str(bruto or "")

    meta = parser.meta
    titulo = titulo_json or meta.get("og:title", "") or meta.get("twitter:title", "")
    descripcion = (descripcion_json or meta.get("og:description", "")
                   or meta.get("twitter:description", "") or meta.get("description", ""))
    canonical = parser.canonical or meta.get("og:url", "") or url_json or url_final

    bloques = parser.article_blocks or parser.all_blocks
    filtrados = []
    for b in bloques:
        bn = normaliza(b)
        if len(b) < 45 or any(x in bn for x in map(normaliza, RUIDO_BLOQUE)):
            continue
        filtrados.append(b)
    # Se combinan JSON-LD y párrafos visibles: si la mención a la UAF está en un
    # solo lugar, conviene conservar ambas fuentes de texto.
    partes = [cuerpo_json] if cuerpo_json else []
    base_norm = normaliza(cuerpo_json)
    for bloque in filtrados:
        if normaliza(bloque)[:120] not in base_norm:
            partes.append(bloque)
    cuerpo = re.sub(r"\s+", " ", "\n".join(partes)).strip()[:MAX_TEXTO_ANALISIS]

    fecha = fecha_json
    if not fecha:
        for candidato in (meta.get("article:published_time", ""), meta.get("date", ""),
                          meta.get("datepublished", ""), meta.get("pubdate", ""),
                          meta.get("article:modified_time", ""), *parser.time_values[:6]):
            fecha = parsea_fecha_flexible(candidato)
            if fecha:
                break
    if not fecha:
        fecha = parsea_fecha_flexible(" ".join((parser.article_blocks or parser.all_blocks)[:6]))

    enlaces_uaf = [e for e in parser.enlaces if "uaf.cl" in e.lower()]
    return {
        "titulo": limpia_html(titulo),
        "descripcion": limpia_html(descripcion),
        "cuerpo": cuerpo,
        "fecha_dt": fecha,
        "canonical": canonical,
        "amphtml": parser.amphtml,
        "feeds": parser.feeds,
        "enlaza_uaf": bool(enlaces_uaf),
    }


def enriquece_articulo(reg):
    """Descarga y analiza el cuerpo del artículo. Nunca lanza excepción."""
    r = dict(reg)
    r["fuente_institucional"] = es_fuente_institucional(r)
    enlace = r.get("link", "")
    if not url_http(enlace):
        r.setdefault("texto_enriquecido", "")
        r["cuerpo_extraido"] = False
        r["enriquecido"] = False
        return r
    try:
        contenido, final, headers = descarga(enlace)
        datos = extrae_articulo(contenido, final, headers)

        canonical = urllib.parse.urljoin(final, datos.get("canonical") or "") or final
        if dominio_url(canonical) in AGREGADORES and dominio_url(final) not in AGREGADORES:
            canonical = final

        # Segundo intento en la URL canónica cuando aporta más texto.
        if (canonical and canonical != final and nivel_dominio_chileno(dominio_url(canonical))
                and len(datos.get("cuerpo", "")) < 1200):
            try:
                c2, f2, h2 = descarga(canonical)
                d2 = extrae_articulo(c2, f2, h2)
                if len(d2.get("cuerpo", "")) > len(datos.get("cuerpo", "")):
                    datos, final, canonical = d2, f2, (d2.get("canonical") or f2)
            except Exception:
                pass

        # Respaldo AMP cuando la versión principal entrega poco texto.
        base = canonical if nivel_dominio_chileno(dominio_url(canonical)) else final
        if len(datos.get("cuerpo", "")) < 300:
            for amp in _urls_amp(datos.get("amphtml"), base):
                try:
                    c3, f3, h3 = descarga(amp)
                    d3 = extrae_articulo(c3, f3, h3)
                    if len(d3.get("cuerpo", "")) > len(datos.get("cuerpo", "")):
                        datos = d3
                        break
                except Exception:
                    continue

        publica = canonical if nivel_dominio_chileno(dominio_url(canonical)) else final
        if nivel_dominio_chileno(dominio_url(publica)):
            limpia = limpia_url(publica)
            if limpia:
                r["link"] = limpia
                r["url_final"] = limpia
        titulo_actual = normaliza(r.get("titulo", ""))
        if datos.get("titulo") and (not titulo_actual or titulo_actual in {"ver noticia", "noticia"}
                                    or len(datos["titulo"]) > len(r.get("titulo", "")) + 12):
            r["titulo"] = datos["titulo"][:500]
        if datos.get("cuerpo"):
            r["texto_enriquecido"] = datos["cuerpo"]
            r["cuerpo_extraido"] = True
        else:
            r.setdefault("texto_enriquecido", "")
            r["cuerpo_extraido"] = False
        if datos.get("descripcion") and len(datos["descripcion"]) > len(r.get("resumen", "")):
            r["resumen"] = datos["descripcion"][:900]
        elif not r.get("resumen") and datos.get("cuerpo"):
            r["resumen"] = datos["cuerpo"][:900]
        if datos.get("fecha_dt") and not r.get("fecha_dt"):
            r["fecha_dt"] = datos["fecha_dt"]
        if datos.get("enlaza_uaf"):
            r["enlaza_uaf"] = True
        r["fuente_institucional"] = es_fuente_institucional(r)
        r["enriquecido"] = True
    except Exception as e:  # noqa: BLE001
        r.setdefault("texto_enriquecido", "")
        r["cuerpo_extraido"] = False
        r["enriquecido"] = False
        r["error_enriquecimiento"] = type(e).__name__
    return r


def _urls_amp(amphtml, base):
    salida = []
    if amphtml:
        absoluta = urllib.parse.urljoin(base, amphtml)
        if url_http(absoluta):
            salida.append(absoluta)
    host = dominio_url(base)
    if host in {"latercera.com", "df.cl", "diariofinanciero.cl"}:
        p = urllib.parse.urlsplit(base)
        query = [(k, v) for k, v in urllib.parse.parse_qsl(p.query) if k != "outputType"]
        query.append(("outputType", "amp"))
        salida.append(urllib.parse.urlunsplit(
            (p.scheme, p.netloc, p.path, urllib.parse.urlencode(query), "")))
    return salida[:2]


# ─────────────────────────────────────────────────────────────
# Motor de detección UAF Chile (análisis por proximidad)
# ─────────────────────────────────────────────────────────────

RE_UAF_LARGA = re.compile(r"unidad(?:es)?\s+(?:de\s+)?analisis\s+financiero")
RE_UAF_SIGLA = re.compile(r"\buaf\b|\bu\.\s?a\.\s?f\.?")
RE_UIF_GENERICA = re.compile(r"unidad\s+de\s+inteligencia\s+financiera")

VENTANA_ESTRECHA = 150
VENTANA_AMPLIA = 430

SENAL_CHILE_FUERTE = [
    "de chile", "chilena", "chileno", "uaf chile", "uaf de chile", "ley 19.913",
    "ley n 19.913", "ley no 19.913", "19.913", "uaf.cl", "santiago de chile",
    "unidad de analisis financiero de chile",
]
SENAL_CHILE_CONTEXTO = [
    "chile", "cmf", "comision para el mercado financiero", "ministerio publico",
    "fiscalia", "fiscalia nacional", "fiscalia regional", "fiscal nacional",
    "servicio de impuestos internos", "sii", "pdi", "policia de investigaciones",
    "carabineros", "gafilat", "peso chileno", "pesos chilenos", "clp",
    "unidad de fomento", "contraloria", "poder judicial", "banco central de chile",
    "consejo de defensa del estado", "aduanas", "santiago", "valparaiso",
    "ministerio de hacienda", "senado", "camara de diputados", "la moneda",
]
PAISES_EXTRANJEROS = [
    "panama", "peru", "ecuador", "paraguay", "bolivia", "colombia", "argentina",
    "uruguay", "brasil", "venezuela", "mexico", "guatemala", "honduras",
    "el salvador", "costa rica", "nicaragua", "cuba", "republica dominicana",
    "espana", "estados unidos", "italia", "francia", "portugal", "haiti",
]
GENTILICIOS_EXTRANJEROS = [
    "panamena", "panameno", "peruana", "peruano", "ecuatoriana", "ecuatoriano",
    "paraguaya", "paraguayo", "boliviana", "boliviano", "colombiana", "colombiano",
    "argentina", "argentino", "uruguaya", "uruguayo", "brasilena", "brasileno",
    "venezolana", "venezolano", "mexicana", "mexicano", "dominicana", "dominicano",
    "espanola", "espanol", "estadounidense", "guatemalteca", "hondurena",
    "salvadorena", "costarricense", "nicaraguense",
]
# Unidades homólogas extranjeras: si aparecen pegadas a la mención, no es la UAF de Chile.
ORGANISMOS_EXTRANJEROS = [
    "uafe", "uiaf", "seprelad", "sepblac", "fincen", "coaf", "senaclaft",
    "uif peru", "uif mexico", "uif argentina", "uif bolivia", "sbs peru",
]

_UNIDAD = r"(?:unidad(?:es)?\s+(?:de\s+)?analisis\s+financiero(?:\s*\(uaf\))?|\buaf\b|\buif\b)"
_PAISES = "|".join(re.escape(normaliza(p)) for p in PAISES_EXTRANJEROS)
_GENT = "|".join(re.escape(normaliza(g)) for g in GENTILICIOS_EXTRANJEROS)

# «UAF de Panamá», «Unidad de Análisis Financiero del Perú», «UAF panameña»,
# «Panamá: la UAF…», «la UAF, de Ecuador,…»
RE_CALIFICA_EXTRANJERA = re.compile(
    rf"{_UNIDAD}\s*[,:]?\s*(?:de\s+la\s+|de\s+los\s+|de\s+|del\s+)?(?:{_PAISES})\b"
    rf"|{_UNIDAD}\s*[,:]?\s*(?:{_GENT})\b"
    rf"|(?:{_PAISES})\s*[:,]\s*(?:la\s+)?{_UNIDAD}"
)
RE_ORGANISMO_EXTRANJERO = re.compile(
    "|".join(_patron_aguja(o) for o in ORGANISMOS_EXTRANJEROS))
RE_PAIS_EXTRANJERO = re.compile(
    "|".join(_patron_aguja(x) for x in (PAISES_EXTRANJEROS + GENTILICIOS_EXTRANJEROS)))

CONTEXTO_LAFT_MINIMO = ENCUADRE_NUCLEO + [
    "reporte de operaciones sospechosas", "ley 19.913", "inteligencia financiera",
    "sujeto obligado", "sujetos obligados", "oficial de cumplimiento", "gafilat",
    "gafi", "financiamiento del terrorismo", "debida diligencia",
    "beneficiario final", "delitos precedentes", "prevencion de lavado",
    "unidad de analisis financiero", "reporte ros", "entidad reportante",
    "secreto bancario", "crimen organizado", "cuentas puente", "testaferro",
    "transferencias fraccionadas", "operacion sospechosa", "roe", "ros",
    "inteligencia economica", "activos de origen ilicito", "extincion de dominio",
    "decomiso", "financiamiento ilicito", "circular 62", "ley 21.121",
]


def texto_registro(reg):
    """Texto normalizado usado para filtrar y clasificar."""
    partes = [
        reg.get("titulo", ""),
        reg.get("resumen", ""),
        reg.get("texto_enriquecido", ""),
        reg.get("contexto_uaf", ""),
        reg.get("medio", ""),
    ]
    return normaliza(" \n ".join(str(x) for x in partes if x))


def _menciones_uaf(texto):
    menciones = []
    for m in RE_UAF_LARGA.finditer(texto):
        menciones.append((m.start(), m.end(), "larga"))
    for m in RE_UAF_SIGLA.finditer(texto):
        if not any(ini <= m.start() <= fin for ini, fin, _ in menciones):
            menciones.append((m.start(), m.end(), "sigla"))
    for m in RE_UIF_GENERICA.finditer(texto):
        menciones.append((m.start(), m.end(), "uif"))
    return sorted(menciones)[:60]


def analiza_uaf(reg):
    """Decide si la mención corresponde a la UAF de Chile.

    Devuelve (es_uaf_chile, confianza, motivos, puntaje, n_menciones).
    La decisión se toma por mención y se conserva la mejor: la presencia de un
    país extranjero en otro párrafo ya no descarta la noticia completa.
    """
    texto = texto_registro(reg)
    menciones = _menciones_uaf(texto)
    enlaza_uaf = bool(reg.get("enlaza_uaf"))
    hay_laft = contiene(texto, CONTEXTO_LAFT_MINIMO)

    if not menciones and not (enlaza_uaf and hay_laft):
        return False, "sin_mencion", [], 0, 0

    chilena, nivel, host = clasifica_fuente(reg)
    if not chilena and host and not reg.get("plataforma"):
        return False, "fuente_no_chilena", ["dominio_no_chileno"], 0, len(menciones)
    institucional = es_fuente_institucional(reg)
    es_uaf_cl = "uaf.cl" in (host or "") or "uaf.cl" in normaliza(reg.get("link", ""))

    base = 0
    motivos = []
    if es_uaf_cl:
        base += 9
        motivos.append("sitio_institucional_uaf")
    elif institucional and chilena:
        base += 5
        motivos.append("fuente_institucional_chilena")
    elif nivel == "verificada":
        base += 4
        motivos.append("medio_chileno_verificado")
    elif nivel == "chilena":
        base += 3
        motivos.append("dominio_chileno")
    elif nivel == "nombre":
        base += 2
        motivos.append("nombre_medio_chileno")
    if enlaza_uaf:
        base += 4
        motivos.append("enlaza_a_uaf_cl")
    if "19.913" in texto:
        base += 3
        motivos.append("ley_19913")
    if hay_laft:
        base += 2
        motivos.append("contexto_laft")

    mejor = -99
    mejores_motivos = []
    utiles = 0
    for ini, fin, tipo in menciones:
        estrecha = texto[max(0, ini - VENTANA_ESTRECHA):fin + VENTANA_ESTRECHA]
        amplia = texto[max(0, ini - VENTANA_AMPLIA):fin + VENTANA_AMPLIA]
        if tipo in {"sigla", "uif"} and not hay_laft and not contiene(estrecha, SENAL_CHILE_FUERTE):
            continue  # «UAF» sin contexto LA/FT no es evidencia utilizable
        utiles += 1
        puntaje = base
        detalle = []
        if tipo == "larga":
            puntaje += 2
            detalle.append("nombre_completo")
        elif tipo == "uif":
            puntaje -= 1
            detalle.append("nombre_generico_uif")
        if contiene(estrecha, SENAL_CHILE_FUERTE):
            puntaje += 7
            detalle.append("chile_junto_a_la_mencion")
        elif contiene(amplia, SENAL_CHILE_FUERTE):
            puntaje += 4
            detalle.append("chile_en_el_parrafo")
        if contiene(estrecha, SENAL_CHILE_CONTEXTO):
            puntaje += 3
            detalle.append("institucionalidad_chilena_cercana")
        elif contiene(amplia, SENAL_CHILE_CONTEXTO):
            puntaje += 2
            detalle.append("institucionalidad_chilena_en_contexto")
        # El veto solo aplica cuando el país califica a la unidad («UAF de Panamá»)
        # o cuando junto a la mención aparece un organismo homólogo extranjero.
        pegado = texto[max(0, ini - 90):fin + 90]
        if RE_CALIFICA_EXTRANJERA.search(pegado) and not contiene(pegado, SENAL_CHILE_FUERTE):
            puntaje -= 9
            detalle.append("unidad_extranjera_identificada")
        elif RE_ORGANISMO_EXTRANJERO.search(pegado) and not contiene(pegado, SENAL_CHILE_FUERTE):
            puntaje -= 4
            detalle.append("organismo_homologo_extranjero_junto_a_la_mencion")
        elif RE_PAIS_EXTRANJERO.search(estrecha) and not contiene(estrecha, SENAL_CHILE_CONTEXTO):
            puntaje -= 2
            detalle.append("pais_extranjero_sin_referencia_chilena")
        elif RE_PAIS_EXTRANJERO.search(amplia):
            puntaje -= 1
            detalle.append("pais_extranjero_mencionado_en_el_texto")
        if puntaje > mejor:
            mejor = puntaje
            mejores_motivos = detalle

    if utiles == 0:
        if enlaza_uaf and hay_laft:
            mejor = base
            mejores_motivos = ["mencion_por_enlace_institucional"]
        else:
            return False, "sigla_ambigua", [], 0, len(menciones)

    motivos = list(dict.fromkeys(motivos + mejores_motivos))[:8]
    if mejor >= 8:
        return True, "alta", motivos, mejor, utiles
    if mejor >= 6:
        return True, "media", motivos, mejor, utiles
    if any(("extranjer" in m or "homologo" in m) for m in mejores_motivos):
        return False, "uaf_extranjera", motivos, mejor, utiles
    return False, "ambigua", motivos, mejor, utiles


def extrae_contexto_uaf(reg, radio_izq=130, radio_der=420):
    """Fragmento legible centrado en la mención, con acentos y mayúsculas."""
    original = " ".join(x for x in (
        reg.get("titulo", ""), reg.get("resumen", ""), reg.get("texto_enriquecido", "")) if x)
    if not original:
        original = reg.get("contexto_uaf", "") or ""
    m = re.search(r"unidad(?:es)?\s+de\s+an[aá]lisis\s+financiero|\bUAF\b", original, re.I)
    if not m:
        return (reg.get("contexto_uaf", "") or "")[:700]
    ini = max(0, m.start() - radio_izq)
    fin = min(len(original), m.end() + radio_der)
    frag = re.sub(r"\s+", " ", original[ini:fin]).strip()
    if ini:
        frag = "…" + frag
    if fin < len(original):
        frag += "…"
    return frag[:700]


# ─────────────────────────────────────────────────────────────
# Clasificación temática
# ─────────────────────────────────────────────────────────────

def clasifica_tipo_medio(reg):
    host = ""
    for campo in ("url_final", "link", "fuente_url"):
        host = dominio_url(reg.get(campo, "")) if isinstance(reg, dict) else ""
        if host and host not in AGREGADORES:
            break
    if host:
        for dominio, tipo in TIPO_POR_DOMINIO.items():
            if host == dominio or host.endswith("." + dominio):
                return tipo
        if dominio_institucional(host):
            return "institucional"
    texto = normaliza(reg.get("medio", "") if isinstance(reg, dict) else reg)
    for clave, agujas in TIPOS_MEDIO.items():
        if contiene(texto, agujas):
            return clave
    return "otro"


def clasifica_sujetos_obligados(texto):
    sectores = claves_presentes(texto, SUJETOS_OBLIGADOS)
    impactos = claves_presentes(texto, IMPACTO_SUJETO) if sectores else []
    return sectores, impactos


def clasifica_roles_sujetos(texto, sectores):
    if not sectores:
        return {}
    frases = [f.strip() for f in re.split(r"[.!?;\n]+", texto) if f.strip()]
    roles = {}
    for sector in sectores:
        agujas = SUJETOS_OBLIGADOS.get(sector, [])
        contexto = " ".join(f for f in frases if contiene(f, agujas))
        if contiene(contexto, ["victima", "afectado", "sustrajeron", "robaron a", "robo a",
                               "robar a", "resulto victima", "hackearon la cuenta",
                               "suplantacion", "fue defraudad"]):
            rol = "victima"
        elif contiene(contexto, ["utilizo", "utilizaron", "a traves de", "cuentas puente",
                                 "transferencias", "retiros", "introducirlo al sistema",
                                 "compraron", "compro", "adquirieron", "canalizo",
                                 "triangul", "fraccion"]):
            rol = "canal"
        elif contiene(contexto, ["imputad", "formaliz", "investigad", "querella", "condenad",
                                 "allanad", "sancionad", "multad"]):
            rol = "investigado"
        elif contiene(contexto, ["circular", "normativa", "fiscalizacion", "supervision",
                                 "debida diligencia", "obligacion", "sancion", "instructivo"]):
            rol = "regulado"
        else:
            rol = "mencionado"
        roles[sector] = rol
    return roles


def clasifica(reg):
    texto = texto_registro(reg)

    fenomeno = "otro"
    for clave, agujas in FENOMENOS.items():
        if contiene(texto, agujas):
            fenomeno = clave
            break

    naturaleza = "analisis"
    for clave, agujas in NATURALEZAS.items():
        if contiene(texto, agujas):
            naturaleza = clave
            break

    precedentes = claves_presentes(texto, PRECEDENTES) or ["indeterminado"]
    topicos = claves_presentes(texto, TOPICOS) or ["otros"]

    uaf_chile, confianza, motivos, puntaje, menciones = analiza_uaf(reg)
    sujetos, impactos = clasifica_sujetos_obligados(texto)
    roles = clasifica_roles_sujetos(texto, sujetos)
    if sujetos and "sujetos_obligados" not in topicos:
        topicos.append("sujetos_obligados")
    if sujetos and "vulneracion_la" in impactos and "vulneracion_sectorial" not in topicos:
        topicos.append("vulneracion_sectorial")

    _, nivel_fuente, _ = clasifica_fuente(reg)

    reg["fenomeno"] = fenomeno
    reg["naturaleza"] = naturaleza
    reg["precedentes"] = precedentes
    reg["topicos"] = topicos
    reg["tipo_medio"] = clasifica_tipo_medio(reg)
    reg["uaf"] = uaf_chile
    reg["uaf_chile"] = uaf_chile
    reg["uaf_confianza"] = confianza
    reg["uaf_motivos"] = motivos
    reg["uaf_puntaje"] = puntaje
    reg["uaf_menciones"] = menciones
    reg["contexto_uaf"] = extrae_contexto_uaf(reg) if uaf_chile else ""
    reg["sujetos_obligados"] = sujetos
    reg["impactos_sujeto"] = impactos
    reg["roles_sujetos"] = roles
    reg["roles_sujetos_label"] = {k: ROL_SUJETO_ETIQUETA.get(v, v) for k, v in roles.items()}
    reg["nucleo"] = contiene(texto, ENCUADRE_NUCLEO)
    reg["nivel_fuente"] = nivel_fuente
    reg["nivel_fuente_label"] = NIVEL_FUENTE_ETIQUETA.get(nivel_fuente, "")
    return reg


DOMINIO_LAFT = ENCUADRE_NUCLEO + [
    "crimen organizado", "gafilat", "gafi", "delitos economicos",
    "financiamiento del terrorismo", "sartor", "tren de aragua",
    "reporte de operaciones sospechosas", "delitos precedentes", "secreto bancario",
    "beneficiario final", "debida diligencia", "persona expuesta politicamente",
    "unidad de analisis financiero", "inteligencia financiera", "testaferro",
    "cuentas puente", "sociedades de papel", "empresas de papel",
]


SENAL_PATRIMONIAL = [
    "dinero", "millones", "cuentas", "cuenta bancaria", "transferencia",
    "transferencias", "bienes", "patrimonio", "incaut", "decomis", "comiso",
    "activos", "fondos", "efectivo", "criptomoneda", "criptoactivo",
    "propiedades", "inmuebles", "vehiculos", "sociedades", "empresas",
    "facturas", "boletas", "utilidades", "pagos", "remesas", "divisas",
    "extincion de dominio", "utilidad ilicita", "ganancias",
]
PRECEDENTES_TODOS = [t for lista in PRECEDENTES.values() for t in lista]


def es_pertinente(reg):
    """Descarta ruido y menciones a UAF extranjeras sin conexión chilena."""
    texto = texto_registro(reg)
    uaf_chile, estado, _, _, _ = analiza_uaf(reg)
    if uaf_chile:
        return True
    if estado in {"uaf_extranjera", "ambigua"} and not contiene(texto, DOMINIO_LAFT):
        return False
    if estado == "uaf_extranjera":
        # Nota extranjera: solo se conserva si además desarrolla el dominio LA/FT chileno.
        if not contiene(texto, ["chile", "chilena", "chileno"]):
            return False
    if reg.get("fuente_institucional") and contiene(texto, CONTEXTO_LAFT_MINIMO):
        return True
    sectores, impactos = clasifica_sujetos_obligados(texto)
    sujeto_relevante = bool(sectores and impactos and contiene(texto, DOMINIO_LAFT + [
        "oficial de cumplimiento", "sujeto obligado", "entidad reportante",
    ]))
    # Un delito precedente con dimensión patrimonial es materia de interés para
    # el monitor aunque el texto no use la expresión «lavado de activos».
    precedente_patrimonial = (contiene(texto, PRECEDENTES_TODOS)
                              and contiene(texto, SENAL_PATRIMONIAL))
    return (contiene(texto, DOMINIO_LAFT) or sujeto_relevante or precedente_patrimonial)


# ─────────────────────────────────────────────────────────────
# Lectura de feeds RSS/Atom y sitemaps
# ─────────────────────────────────────────────────────────────

def _xml_local(tag):
    return str(tag).rsplit("}", 1)[-1].lower()


def _texto_hijo(nodo, nombres):
    for hijo in nodo.iter():
        if _xml_local(hijo.tag) in nombres:
            if hijo.text and hijo.text.strip():
                return hijo.text.strip()
    return ""


def _enlace_item(nodo):
    # RSS: <link>texto</link> · Atom: <link rel="alternate" href="...">
    for hijo in nodo.iter():
        if _xml_local(hijo.tag) != "link":
            continue
        href = hijo.get("href")
        rel = (hijo.get("rel") or "alternate").lower()
        if href and rel in {"alternate", ""}:
            return href.strip()
        if hijo.text and hijo.text.strip():
            return hijo.text.strip()
    guid = _texto_hijo(nodo, {"guid", "id"})
    return guid if url_http(guid) else ""


def _decodifica_enlace_google(url):
    """Intenta recuperar la URL del medio dentro de un enlace de Google News."""
    if "news.google.com" not in (url or ""):
        return ""
    m = re.search(r"/(?:rss/)?articles/([A-Za-z0-9_\-]{20,})", url)
    if not m:
        return ""
    bruto = m.group(1)
    for variante in (bruto, bruto + "=", bruto + "==", bruto + "==="):
        try:
            crudo = base64.urlsafe_b64decode(variante)
        except Exception:
            continue
        hallado = re.search(rb"https?://[\w./\-%~?=&+#,;:@!$'()*]{12,}", crudo)
        if hallado:
            candidato = hallado.group(0).decode("utf-8", "ignore")
            candidato = candidato.split("\x01")[0].rstrip("\x00")
            if url_http(candidato) and dominio_url(candidato) not in AGREGADORES:
                return candidato
    return ""


def lee_feed(url, origen, medio_defecto="", fuente_url=""):
    """Lee un feed RSS o Atom y devuelve registros crudos."""
    salida = []
    try:
        contenido, final, headers = descarga(
            url, accept="application/rss+xml, application/atom+xml, application/xml, text/xml, */*")
        raiz = xml_seguro(contenido)
    except Exception as e:
        log(f"  ! feed {origen} ({dominio_url(url) or url[:40]}): {type(e).__name__}: {e}")
        return salida

    for nodo in raiz.iter():
        if _xml_local(nodo.tag) not in {"item", "entry"}:
            continue
        titulo = limpia_html(_texto_hijo(nodo, {"title"}))
        enlace = _enlace_item(nodo)
        if not titulo or not enlace:
            continue
        medio = medio_defecto
        fuente = fuente_url
        for hijo in nodo.iter():
            if _xml_local(hijo.tag) == "source":
                if hijo.text and hijo.text.strip():
                    medio = hijo.text.strip()
                if hijo.get("url"):
                    fuente = hijo.get("url").strip()
                break
        if not medio and " - " in titulo:
            titulo, medio = titulo.rsplit(" - ", 1)
        resumen = limpia_html(_texto_hijo(nodo, {"description", "summary", "encoded", "content"}))
        fecha = (parsea_fecha_flexible(_texto_hijo(nodo, {"pubdate", "published", "updated", "date"})))

        real = _decodifica_enlace_google(enlace) or enlace
        if not url_http(real):
            continue
        registro = {
            "titulo": titulo.strip()[:500],
            "link": real,
            "medio": (medio or medio_defecto or origen).strip()[:160],
            "resumen": resumen[:700],
            "fecha_dt": fecha,
            "origen": origen,
            "fuente_url": fuente or (f"https://{dominio_url(real)}" if dominio_url(real) else ""),
        }
        if not registro["fuente_url"] and medio_defecto:
            registro["fuente_url"] = fuente_url
        salida.append(registro)
    return salida


def _valida_endpoint(url):
    """Comprueba que la URL entregue un feed o sitemap utilizable."""
    try:
        contenido, _, _ = descarga(url, accept="application/xml,text/xml,application/rss+xml,*/*",
                                  max_bytes=1_500_000, reintentos=1)
        raiz = xml_seguro(contenido)
    except Exception:
        return ""
    tipo = _xml_local(raiz.tag)
    if tipo in {"rss", "feed", "rdf"}:
        return "feed"
    if tipo in {"urlset", "sitemapindex"}:
        return "sitemap"
    return ""


def descubre_endpoints(host, estado, limite_pruebas=8):
    """Descubre feeds y news-sitemaps de un dominio y los guarda en el estado."""
    cache = estado.setdefault("endpoints", {})
    guardado = cache.get(host)
    ahora = time.time()
    if guardado and (ahora - guardado.get("ts", 0)) < TTL_ENDPOINTS_HORAS * 3600:
        return guardado

    candidatos_feed, candidatos_sitemap = [], []
    semilla = SEMILLAS_ENDPOINTS.get(host, {})
    candidatos_feed += semilla.get("feeds", [])
    candidatos_sitemap += semilla.get("sitemaps", [])

    raiz = f"https://www.{host}" if host.count(".") == 1 else f"https://{host}"
    # 1) robots.txt declara los sitemaps
    try:
        datos, _, headers = descarga(f"https://{host}/robots.txt", accept="text/plain",
                                     max_bytes=400_000, robots=False, reintentos=1)
        for linea in _decodifica(datos, headers).splitlines():
            if linea.lower().startswith("sitemap:"):
                url = linea.split(":", 1)[1].strip()
                if url_http(url):
                    peso = 0 if re.search(r"news|noticia", url, re.I) else 1
                    candidatos_sitemap.append((peso, url))
    except Exception:
        pass
    semillas_sitemap = [c for c in candidatos_sitemap if not isinstance(c, tuple)]
    ordenados = sorted([c for c in candidatos_sitemap if isinstance(c, tuple)])
    candidatos_sitemap = semillas_sitemap + [u for _, u in ordenados]

    # 2) portada declara feeds RSS/Atom
    try:
        contenido, final, headers = descarga(raiz, max_bytes=1_500_000, reintentos=1)
        datos = extrae_articulo(contenido, final, headers)
        for href in datos.get("feeds", [])[:6]:
            absoluta = urllib.parse.urljoin(final, href)
            if url_http(absoluta):
                candidatos_feed.append(absoluta)
    except Exception:
        pass

    # 3) rutas habituales
    candidatos_feed += [raiz + ruta for ruta in RUTAS_FEED]
    candidatos_sitemap += [raiz + ruta for ruta in RUTAS_SITEMAP]

    feeds, sitemaps = [], []
    pruebas = 0
    for url in list(dict.fromkeys(candidatos_feed)):
        if len(feeds) >= 2 or pruebas >= limite_pruebas or tiempo_agotado(reserva=180):
            break
        pruebas += 1
        if _valida_endpoint(url) == "feed":
            feeds.append(url)
    pruebas = 0
    for url in list(dict.fromkeys(candidatos_sitemap)):
        if len(sitemaps) >= 2 or pruebas >= limite_pruebas or tiempo_agotado(reserva=180):
            break
        pruebas += 1
        if _valida_endpoint(url) == "sitemap":
            sitemaps.append(url)

    registro = {"feeds": feeds, "sitemaps": sitemaps, "ts": ahora}
    cache[host] = registro
    if feeds or sitemaps:
        log(f"  · fuentes de {host}: {len(feeds)} feed(s), {len(sitemaps)} sitemap(s)")
    return registro


def lee_sitemap(url, medio, host, corte, presupuesto, profundidad=0):
    """Lee un sitemap o índice y devuelve entradas recientes del dominio."""
    if profundidad > 2 or presupuesto[0] <= 0 or tiempo_agotado(reserva=120):
        return []
    presupuesto[0] -= 1
    try:
        contenido, _, _ = descarga(url, accept="application/xml,text/xml,*/*",
                                   max_bytes=6_000_000, reintentos=1)
        raiz = xml_seguro(contenido)
    except Exception as e:
        log(f"  ! sitemap {medio}: {type(e).__name__}")
        return []

    if _xml_local(raiz.tag) == "sitemapindex":
        hijos = []
        for nodo in list(raiz):
            loc = _texto_hijo(nodo, {"loc"})
            lastmod = parsea_fecha_flexible(_texto_hijo(nodo, {"lastmod"}))
            if not loc:
                continue
            if lastmod and lastmod < corte - timedelta(days=2):
                continue
            hijos.append((lastmod or datetime.now(TZ_CL), loc))
        hijos.sort(reverse=True)
        salida = []
        for _, loc in hijos[:4]:
            salida.extend(lee_sitemap(loc, medio, host, corte, presupuesto, profundidad + 1))
        return salida

    salida = []
    for nodo in list(raiz):
        if _xml_local(nodo.tag) != "url":
            continue
        loc = _texto_hijo(nodo, {"loc"})
        if not loc or not url_http(loc):
            continue
        if not nivel_dominio_chileno(dominio_url(loc)):
            continue
        titulo = _texto_hijo(nodo, {"title"})
        fecha = (parsea_fecha_flexible(_texto_hijo(nodo, {"publication_date"}))
                 or parsea_fecha_flexible(_texto_hijo(nodo, {"lastmod"})))
        if fecha and fecha < corte:
            continue
        if not titulo:
            partes = [p for p in urllib.parse.urlsplit(loc).path.split("/") if p]
            titulo = urllib.parse.unquote(partes[-1] if partes else "").replace("-", " ")[:300]
        salida.append({
            "titulo": limpia_html(titulo)[:500],
            "link": loc,
            "medio": medio,
            "resumen": "",
            "fecha_dt": fecha,
            "origen": "Sitemap de prensa chilena",
            "fuente_url": f"https://{host}",
            "origen_busqueda": "sitemap",
        })
    return salida


# ─────────────────────────────────────────────────────────────
# Canales de descubrimiento
# ─────────────────────────────────────────────────────────────

def en_paralelo(tareas, etiqueta="canal", hilos=None):
    """Ejecuta tareas sin argumentos que devuelven listas y concatena resultados."""
    salida = []
    if not tareas:
        return salida
    with ThreadPoolExecutor(max_workers=hilos or HILOS) as pool:
        futuros = [pool.submit(t) for t in tareas]
        for fut in as_completed(futuros):
            try:
                salida.extend(fut.result() or [])
            except Exception as e:  # noqa: BLE001
                log(f"  ! {etiqueta}: {type(e).__name__}")
    return salida


def recolecta_google_news():
    def tarea(q):
        def _ejecuta():
            if tiempo_agotado(reserva=260):
                return []
            consulta = f"{q} when:{min(VENTANA_DIAS, 30)}d"
            url = ("https://news.google.com/rss/search?q=" + urllib.parse.quote(consulta)
                   + "&hl=es-419&gl=CL&ceid=CL:es-419")
            hallazgos = lee_feed(url, "Google News")
            for r in hallazgos:
                r["origen_busqueda"] = f"google:{q}"[:180]
            return hallazgos
        return _ejecuta

    salida = en_paralelo([tarea(q) for q in CONSULTAS_PRENSA], "Google News")
    log(f"  · Google News → {len(salida)} resultados brutos "
        f"({len(CONSULTAS_PRENSA)} consultas, {len(DOMINIOS_BUSQUEDA_SITIO)} dirigidas por medio)")
    return salida


def recolecta_bing_news():
    def tarea(q):
        def _ejecuta():
            if tiempo_agotado(reserva=240):
                return []
            url = ("https://www.bing.com/news/search?q=" + urllib.parse.quote(q)
                   + "&format=RSS&setmkt=es-CL&setlang=es")
            hallazgos = lee_feed(url, "Bing News")
            for r in hallazgos:
                r["origen_busqueda"] = f"bing:{q}"[:180]
            return hallazgos
        return _ejecuta

    salida = en_paralelo([tarea(q) for q in CONSULTAS_BING], "Bing News")
    log(f"  · Bing News → {len(salida)} resultados brutos")
    return salida


def recolecta_gdelt():
    """GDELT DOC 2.0: índice global de noticias, sin API key."""
    salida = []
    for q in CONSULTAS_GDELT:
        if tiempo_agotado(reserva=260):
            break
        consulta = f"{q} sourcelang:spanish"
        url = ("https://api.gdeltproject.org/api/v2/doc/doc?query="
               + urllib.parse.quote(consulta)
               + "&mode=artlist&maxrecords=200&sort=datedesc&format=json"
               + f"&timespan={min(VENTANA_DIAS, 30)}d")
        try:
            contenido, _, headers = descarga(url, accept="application/json,*/*",
                                            max_bytes=3_000_000, robots=False, reintentos=1)
            datos = json_seguro(contenido, headers)
        except Exception as e:
            log(f"  ! GDELT «{q[:40]}»: {type(e).__name__}")
            continue
        for art in (datos.get("articles") or []):
            enlace = str(art.get("url", ""))
            if not url_http(enlace):
                continue
            host = dominio_url(enlace)
            if not nivel_dominio_chileno(host):
                continue
            salida.append({
                "titulo": limpia_html(art.get("title", ""))[:500],
                "link": enlace,
                "medio": NOMBRE_POR_DOMINIO.get(host, art.get("domain", host)),
                "resumen": "",
                "fecha_dt": parsea_fecha_flexible(art.get("seendate", "")),
                "origen": "GDELT",
                "fuente_url": f"https://{host}",
                "origen_busqueda": f"gdelt:{q}"[:180],
            })
    log(f"  · GDELT → {len(salida)} artículos chilenos")
    return salida


CLAVE_PERPLEXITY = os.getenv("PERPLEXITY_API_KEY", "").strip()
MODELO_PERPLEXITY = os.getenv("PERPLEXITY_MODELO", "sonar").strip() or "sonar"
CONSULTAS_PERPLEXITY = [
    "Noticias publicadas en los últimos 7 días por medios de prensa chilenos que "
    "mencionen a la Unidad de Análisis Financiero (UAF) de Chile. Entrega solo "
    "los enlaces de las notas.",
    "Noticias de los últimos 7 días en medios chilenos sobre lavado de activos, "
    "financiamiento del terrorismo u operaciones sospechosas en Chile. Entrega "
    "solo los enlaces de las notas.",
]


def recolecta_perplexity():
    """Búsqueda sintética opcional. Requiere PERPLEXITY_API_KEY (servicio de pago).

    Del resultado se usan **solo las URL citadas**: el titular, la fecha y la
    mención a la UAF se verifican después descargando el artículo con el mismo
    extractor que el resto del monitor. Nada de lo que afirme el modelo entra al
    dashboard sin comprobarse contra la fuente.
    """
    if not CLAVE_PERPLEXITY:
        return []
    salida = []
    for consulta in CONSULTAS_PERPLEXITY:
        if tiempo_agotado(reserva=200):
            break
        payload = json.dumps({
            "model": MODELO_PERPLEXITY,
            "messages": [{"role": "user", "content": consulta}],
            "search_domain_filter": DOMINIOS_PRIORITARIOS[:10],
            "search_recency_filter": "week",
            "max_tokens": 400,
        }).encode("utf-8")
        try:
            contenido, _, headers = descarga(
                "https://api.perplexity.ai/chat/completions", accept="application/json",
                max_bytes=2_000_000, robots=False, reintentos=1, cuerpo=payload,
                cabeceras={"Authorization": f"Bearer {CLAVE_PERPLEXITY}",
                           "Content-Type": "application/json"})
            datos = json_seguro(contenido, headers)
        except Exception as e:  # noqa: BLE001
            log(f"  ! Perplexity: {type(e).__name__}")
            continue
        citas = datos.get("citations") or datos.get("search_results") or []
        for cita in citas:
            url = cita.get("url") if isinstance(cita, dict) else cita
            if not url_http(str(url or "")):
                continue
            host = dominio_url(url)
            if not nivel_dominio_chileno(host):
                continue
            salida.append({
                "titulo": (cita.get("title") if isinstance(cita, dict) else "") or "Por verificar",
                "link": str(url),
                "medio": NOMBRE_POR_DOMINIO.get(host, host),
                "resumen": "",
                "fecha_dt": None,
                "origen": "Perplexity",
                "fuente_url": f"https://{host}",
                "origen_busqueda": "perplexity",
            })
    if salida:
        log(f"  · Perplexity → {len(salida)} enlaces chilenos por verificar")
    return salida


def recolecta_feeds_medios(estado):
    """Lee los feeds propios de cada medio chileno (autodescubiertos)."""
    salida = []
    hosts = [h for _, h, tipo, _ in MEDIOS_CHILE if tipo != "institucional"]
    hosts += sorted(DOMINIOS_INSTITUCIONALES)
    pendientes = [h for h in hosts
                  if (time.time() - estado.get("endpoints", {}).get(h, {}).get("ts", 0))
                  >= TTL_ENDPOINTS_HORAS * 3600]
    # Descubrimiento progresivo: unos pocos dominios nuevos por corrida.
    rotacion = int(estado.get("rotacion_descubrimiento", 0))
    cupo = _env_int("MONITOR_DESCUBRE_POR_CORRIDA", 14)
    if pendientes:
        seleccion = list(dict.fromkeys(
            pendientes[(rotacion + i) % len(pendientes)] for i in range(min(cupo, len(pendientes)))))
        resultados = {}
        lock = threading.Lock()

        def descubre(host):
            if tiempo_agotado(reserva=200):
                return []
            local = dict(estado)
            local["endpoints"] = {}
            info = descubre_endpoints(host, local)
            with lock:
                resultados[host] = info
            return []

        en_paralelo([lambda h=h: descubre(h) for h in seleccion], "descubrimiento")
        estado.setdefault("endpoints", {}).update(resultados)
        estado["rotacion_descubrimiento"] = rotacion + cupo

    tareas = []
    for host in hosts:
        info = estado.get("endpoints", {}).get(host) or {}
        for feed in (info.get("feeds") or [])[:2]:
            def tarea(feed=feed, host=host):
                if tiempo_agotado(reserva=170):
                    return []
                medio = NOMBRE_POR_DOMINIO.get(host, host)
                hallazgos = lee_feed(feed, f"Feed {medio}", medio, f"https://{host}")
                for r in hallazgos:
                    r["origen_busqueda"] = f"feed:{host}"
                return hallazgos
            tareas.append(tarea)
    salida = en_paralelo(tareas, "feeds de medios")
    con_feed = sum(1 for h in hosts if (estado.get("endpoints", {}).get(h) or {}).get("feeds"))
    log(f"  · Feeds propios de medios → {len(salida)} entradas "
        f"({con_feed}/{len(hosts)} dominios con feed detectado)")
    return salida


def recolecta_sitemaps(estado):
    corte = datetime.now(TZ_CL) - timedelta(days=3)
    tareas = []
    for host in DOMINIOS_BUSQUEDA_SITIO:
        info = estado.get("endpoints", {}).get(host) or {}
        sitemaps = info.get("sitemaps") or SEMILLAS_ENDPOINTS.get(host, {}).get("sitemaps", [])
        for url in sitemaps[:1]:
            def tarea(url=url, host=host):
                if tiempo_agotado(reserva=170):
                    return []
                medio = NOMBRE_POR_DOMINIO.get(host, host)
                return lee_sitemap(url, medio, host, corte, [8])
            tareas.append(tarea)
    salida = en_paralelo(tareas, "news-sitemaps")
    log(f"  · News-sitemaps → {len(salida)} artículos recientes ({len(tareas)} sitemaps leídos)")
    return salida


def recolecta_uaf_oficial():
    """Noticias publicadas por la propia UAF (uaf.cl)."""
    enlaces = {}
    for pagina in (1, 2):
        url_lista = (f"https://www.uaf.cl/es-cl/noticias-lista?end_date=&page={pagina}"
                     "&search=&start_date=")
        try:
            contenido, final, headers = descarga(url_lista)
            texto_html = _decodifica(contenido, headers)
        except Exception as e:
            log(f"  ! uaf.cl página {pagina}: {type(e).__name__}")
            continue
        patron = re.compile(
            r'<a[^>]+href=["\']([^"\']*noticia-detalle[^"\']*)["\'][^>]*>(.*?)</a>', re.I | re.S)
        for href, interior in patron.findall(texto_html):
            link = urllib.parse.urljoin(final, html_mod.unescape(href))
            if not url_http(link):
                continue
            texto = limpia_html(interior)
            if link not in enlaces or len(texto) > len(enlaces[link]):
                enlaces[link] = texto
    salida = []
    for link, titulo in list(enlaces.items())[:36]:
        salida.append({
            "titulo": titulo[:500] or "Noticia UAF",
            "link": link,
            "medio": "Unidad de Análisis Financiero",
            "resumen": "",
            "fecha_dt": None,
            "origen": "UAF Chile",
            "fuente_url": "https://www.uaf.cl",
            "fuente_institucional": True,
            "origen_busqueda": "uaf_directo",
        })
    log(f"  · uaf.cl → {len(salida)} noticias institucionales")
    return salida


def recolecta_bluesky():
    crudos = []
    for q in CONSULTAS_SOCIALES:
        if tiempo_agotado(reserva=120):
            break
        url = ("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?limit=50&q="
               + urllib.parse.quote(q))
        try:
            contenido, _, headers = descarga(url, accept="application/json,*/*",
                                            max_bytes=2_000_000, robots=False, reintentos=1)
            datos = json_seguro(contenido, headers)
        except Exception as e:
            log(f"  ! Bluesky «{q}»: {type(e).__name__}")
            continue
        for p in datos.get("posts", []):
            rec = p.get("record", {})
            autor = p.get("author", {})
            handle = autor.get("handle", "")
            rkey = str(p.get("uri", "")).rsplit("/", 1)[-1]
            crudos.append({
                "titulo": limpia_html(rec.get("text", ""))[:280],
                "link": f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey and handle else "",
                "medio": f"@{handle}",
                "resumen": "",
                "fecha_dt": parsea_fecha_flexible(rec.get("createdAt", "")),
                "origen": "Bluesky",
                "plataforma": "bluesky",
                "interacciones": (int(p.get("likeCount", 0) or 0) + int(p.get("repostCount", 0) or 0)
                                  + int(p.get("replyCount", 0) or 0)),
            })
    return crudos


def recolecta_reddit():
    crudos = []
    for sub in SUBREDDITS:
        for q in CONSULTAS_SOCIALES:
            if tiempo_agotado(reserva=110):
                break
            url = (f"https://www.reddit.com/r/{sub}/search.json?q=" + urllib.parse.quote(q)
                   + "&restrict_sr=1&sort=new&t=month&limit=50&raw_json=1")
            try:
                contenido, _, headers = descarga(url, accept="application/json,*/*",
                                                max_bytes=2_000_000, robots=False, reintentos=1)
                datos = json_seguro(contenido, headers)
            except Exception as e:
                log(f"  ! Reddit r/{sub}: {type(e).__name__}")
                continue
            for h in datos.get("data", {}).get("children", []):
                d = h.get("data", {})
                creado = d.get("created_utc")
                fecha = (datetime.fromtimestamp(creado, tz=timezone.utc).astimezone(TZ_CL)
                         if creado else None)
                permalink = d.get("permalink", "")
                crudos.append({
                    "titulo": limpia_html(d.get("title", ""))[:280],
                    "link": ("https://www.reddit.com" + permalink) if permalink else d.get("url", ""),
                    "medio": f"r/{sub}",
                    "resumen": limpia_html(d.get("selftext", ""))[:600],
                    "fecha_dt": fecha,
                    "origen": "Reddit",
                    "plataforma": "reddit",
                    "interacciones": int(d.get("score", 0) or 0) + int(d.get("num_comments", 0) or 0),
                    "autor": d.get("author", ""),
                })
    return crudos


def recolecta_social():
    return recolecta_reddit() + recolecta_bluesky()


# ─────────────────────────────────────────────────────────────
# Orquestación de prensa: selección, barrido y enriquecimiento
# ─────────────────────────────────────────────────────────────

PESOS_CANDIDATO = (
    (["unidad de analisis financiero", "uaf"], 14),
    (["lavado de activos", "lavado de dinero", "blanqueo", "operaciones sospechosas",
      "financiamiento del terrorismo", "gafilat", "sujeto obligado",
      "oficial de cumplimiento", "beneficiario final"], 10),
    (["tren de aragua", "crimen organizado", "testaferro", "cuentas puente",
      "formaliz", "imputad", "fraude", "estafa", "extorsion", "narcotrafico",
      "sartor", "delitos economicos", "contrabando", "cohecho"], 4),
    (["banco", "fintech", "notario", "inmobiliaria", "automotora", "factoring",
      "leasing", "casino", "corredora", "fondos", "cripto", "transferencia",
      "aduana", "zona franca", "cmf", "fiscalia"], 2),
)


def puntaje_candidato(reg):
    texto = normaliza((reg.get("titulo", "") or "") + " " + (reg.get("resumen", "") or "")
                      + " " + urllib.parse.unquote(reg.get("link", "") or ""))
    puntaje = 0
    for agujas, peso in PESOS_CANDIDATO:
        if contiene(texto, agujas):
            puntaje += peso
    if reg.get("fuente_institucional"):
        puntaje += 6
    if reg.get("nivel_fuente") == "verificada":
        puntaje += 1
    fecha = reg.get("fecha_dt")
    if fecha:
        horas = (datetime.now(TZ_CL) - fecha).total_seconds() / 3600
        if horas <= 36:
            puntaje += 3
        elif horas <= 120:
            puntaje += 1
    return puntaje


def _mezcla_candidatos(destino, reg):
    clave = id_estable(reg.get("link", ""), reg.get("titulo", ""))
    previo = destino.get(clave)
    if not previo:
        destino[clave] = reg
        return
    for campo in ("resumen", "titulo"):
        if len(str(reg.get(campo, ""))) > len(str(previo.get(campo, ""))):
            previo[campo] = reg[campo]
    if not previo.get("fecha_dt") and reg.get("fecha_dt"):
        previo["fecha_dt"] = reg["fecha_dt"]
    if reg.get("fuente_institucional"):
        previo["fuente_institucional"] = True
    if previo.get("origen") != reg.get("origen"):
        previo["origenes"] = sorted(set(previo.get("origenes", [previo.get("origen", "")]))
                                    | {reg.get("origen", "")})


INFORME_COBERTURA = {}


def _registra_cobertura(host, canal, n=1):
    if not host:
        return
    fila = INFORME_COBERTURA.setdefault(host, {"candidatos": 0, "canales": {}})
    fila["candidatos"] += n
    fila["canales"][canal] = fila["canales"].get(canal, 0) + n


# ─────────────────────────────────────────────────────────────
# Canal directo: páginas de etiquetas temáticas de cada medio
# ─────────────────────────────────────────────────────────────

# Cada medio organiza sus notas en páginas de etiqueta/tag/categoría.  Estas
# páginas son el ÍNDICE REAL de lo que publicaron, más completo que cualquier
# feed o buscador.  Una nota que mencione a la UAF en el cuerpo pero cuyo
# titular no diga «UAF» puede no aparecer en ninguna consulta de Google News;
# sin embargo, sí aparece en la página de etiqueta «lavado-de-activos» del
# medio, porque el editor la clasificó bajo esa categoría.

PAGINAS_ETIQUETA = [
    # La Tercera / Pulso
    ("latercera.com", "https://www.latercera.com/etiqueta/uaf/"),
    ("latercera.com", "https://www.latercera.com/etiqueta/lavado-de-activos/"),
    ("latercera.com", "https://www.latercera.com/etiqueta/crimen-organizado/"),
    ("latercera.com", "https://www.latercera.com/etiqueta/operacion-tokio/"),
    ("latercera.com", "https://www.latercera.com/etiqueta/tren-de-aragua/"),
    ("latercera.com", "https://www.latercera.com/etiqueta/secreto-bancario/"),
    # BioBioChile
    ("biobiochile.cl", "https://www.biobiochile.cl/lista/categorias/economia"),
    ("biobiochile.cl", "https://www.biobiochile.cl/lista/categorias/nacional"),
    # Emol
    ("emol.com", "https://www.emol.com/tag/1038099/lavado-de-activos.html"),
    ("emol.com", "https://www.emol.com/tag/1165730/uaf.html"),
    # El Mostrador
    ("elmostrador.cl", "https://www.elmostrador.cl/noticias/pais/"),
    ("elmostrador.cl", "https://www.elmostrador.cl/mercados/"),
    # CIPER
    ("ciperchile.cl", "https://www.ciperchile.cl/category/economia/"),
    # Diario Financiero
    ("df.cl", "https://www.df.cl/mercados"),
    ("df.cl", "https://www.df.cl/regulacion"),
    # CNN Chile
    ("cnnchile.com", "https://www.cnnchile.com/economia/"),
    ("cnnchile.com", "https://www.cnnchile.com/pais/"),
    # Cooperativa
    ("cooperativa.cl", "https://www.cooperativa.cl/noticias/pais/judicial/"),
    # T13
    ("t13.cl", "https://www.t13.cl/etiqueta/lavado-de-activos"),
    ("t13.cl", "https://www.t13.cl/etiqueta/uaf"),
    # 24 Horas
    ("24horas.cl", "https://www.24horas.cl/etiqueta/lavado-de-activos"),
    # Ex-Ante
    ("ex-ante.cl", "https://www.ex-ante.cl/categoria/economia/"),
    # Interferencia
    ("interferencia.cl", "https://interferencia.cl/tags/lavado-de-activos"),
    # CHV Noticias
    ("chilevision.cl", "https://www.chilevision.cl/noticias/economia"),
    # Meganoticias
    ("meganoticias.cl", "https://www.meganoticias.cl/economia/"),
]


def _extrae_enlaces_pagina(html_text, url_base):
    """Extrae todos los enlaces de artículo de una página HTML de etiqueta/categoría."""
    enlaces = {}
    patron_a = re.compile(r'<a[^>]+href=["\x27]([^"\x27]+)["\x27][^>]*>(.*?)</a>',
                           flags=re.I | re.S)
    for m in patron_a.finditer(html_text):
        href, interior = m.group(1), m.group(2)
        href = urllib.parse.urljoin(url_base, html_mod.unescape(href))
        if not url_http(href):
            continue
        host = dominio_url(href)
        if not nivel_dominio_chileno(host):
            continue
        # Filtrar solo enlaces que parecen artículos (tienen slug largo o /noticia/)
        ruta = urllib.parse.urlsplit(href).path
        if len(ruta) < 25:
            continue
        if any(x in ruta for x in ("/etiqueta/", "/tag/", "/lista/", "/canal/",
                                    "/autor/", "/categoria/", "/category/",
                                    "/compra-", "/contacto", "/politica-privacidad",
                                    "/newsletters", "/suscri")):
            continue
        titulo = limpia_html(interior).strip()
        if not titulo or len(titulo) < 12 or len(titulo) > 500:
            continue
        if href not in enlaces or len(titulo) > len(enlaces[href]):
            enlaces[href] = titulo
    return enlaces


def recolecta_etiquetas():
    """Lee las páginas de etiquetas temáticas de cada medio prioritario.

    Estas páginas son el índice editorial de artículos por tema.  Muchas notas
    que mencionan a la UAF en el cuerpo aparecen aquí bajo etiquetas como
    «lavado-de-activos» o «crimen-organizado» aunque su titular no diga UAF.
    Es la vía más confiable para no perder artículos.
    """
    salida = []
    procesados_urls = set()

    def tarea(host, url):
        def _ejecuta():
            if tiempo_agotado(reserva=200):
                return []
            try:
                contenido, final, headers = descarga(url, max_bytes=3_000_000, reintentos=1)
                texto = _decodifica(contenido, headers)
            except Exception as e:
                log(f"  ! etiqueta {host}: {type(e).__name__}")
                return []
            enlaces = _extrae_enlaces_pagina(texto, final)
            registros = []
            for href, titulo in enlaces.items():
                if href in procesados_urls:
                    continue
                procesados_urls.add(href)
                h = dominio_url(href)
                registros.append({
                    "titulo": titulo[:500],
                    "link": href,
                    "medio": NOMBRE_POR_DOMINIO.get(h, h),
                    "resumen": "",
                    "fecha_dt": None,
                    "origen": "Página de etiqueta",
                    "fuente_url": f"https://{h}",
                    "origen_busqueda": f"etiqueta:{host}",
                })
            return registros
        return _ejecuta

    tareas = [tarea(host, url) for host, url in PAGINAS_ETIQUETA]
    salida = en_paralelo(tareas, "etiquetas temáticas")
    log(f"  · Páginas de etiquetas temáticas → {len(salida)} artículos de {len(PAGINAS_ETIQUETA)} páginas")
    return salida


def recolecta_retrospectiva():
    """Consultas retrospectivas para atrapar notas que se escaparon del descubrimiento inicial.

    Google News permite «after:YYYY-MM-DD before:YYYY-MM-DD» para buscar ventanas pasadas.
    Cada corrida revisa una franja de 3 días elegida al azar de los últimos 30, de modo que en
    el transcurso de la semana se cubren prácticamente todos los días del historial.
    """
    import random
    ahora = datetime.now(TZ_CL)
    # Elegimos una ventana de 3 días entre 3 y 28 días atrás (las últimas 72h ya están bien cubiertas)
    offset = random.randint(3, min(VENTANA_DIAS - 2, 28))
    desde = (ahora - timedelta(days=offset + 2)).strftime("%Y-%m-%d")
    hasta = (ahora - timedelta(days=offset)).strftime("%Y-%m-%d")
    consultas_retro = [
        f'"Unidad de Análisis Financiero" after:{desde} before:{hasta}',
        f'"UAF" "lavado de activos" after:{desde} before:{hasta}',
        f'"lavado de activos" Chile after:{desde} before:{hasta}',
        f'"operaciones sospechosas" Chile after:{desde} before:{hasta}',
    ]
    # Añadir site: para los 8 medios de mayor volumen
    for dominio in DOMINIOS_PRIORITARIOS[:8]:
        consultas_retro.append(
            f'site:{dominio} ("Unidad de Análisis Financiero" OR "lavado de activos") '
            f'after:{desde} before:{hasta}')

    def tarea(q):
        def _ejecuta():
            if tiempo_agotado(reserva=220):
                return []
            url = ("https://news.google.com/rss/search?q=" + urllib.parse.quote(q)
                   + "&hl=es-419&gl=CL&ceid=CL:es-419")
            hallazgos = lee_feed(url, "Google News retro")
            for r in hallazgos:
                r["origen_busqueda"] = f"retro:{q}"[:180]
            return hallazgos
        return _ejecuta

    salida = en_paralelo([tarea(q) for q in consultas_retro], "retrospectiva")
    if salida:
        log(f"  · Retrospectiva {desde}/{hasta} → {len(salida)} resultados")
    return salida


def recolecta_prensa(estado, cuerpos_previos):
    INFORME_COBERTURA.clear()
    crudos = []
    crudos += recolecta_google_news()
    crudos += recolecta_bing_news()
    crudos += recolecta_gdelt()
    crudos += recolecta_perplexity()
    crudos += recolecta_feeds_medios(estado)
    crudos += recolecta_sitemaps(estado)
    crudos += recolecta_uaf_oficial()
    crudos += recolecta_etiquetas()
    crudos += recolecta_retrospectiva()

    candidatos = {}
    descartados = 0
    for r in crudos:
        limpio = limpia_url(r.get("link", ""))
        if not limpio:
            descartados += 1
            continue
        r["link"] = limpio
        chilena, nivel, host = clasifica_fuente(r)
        if not chilena:
            descartados += 1
            continue
        r["nivel_fuente"] = nivel
        if host:
            r["fuente_url"] = r.get("fuente_url") or f"https://{host}"
            if host in NOMBRE_POR_DOMINIO:
                r["medio"] = NOMBRE_POR_DOMINIO[host]
        if es_fuente_institucional(r):
            r["fuente_institucional"] = True
        _registra_cobertura(host or dominio_url(r["link"]),
                            str(r.get("origen_busqueda", "") or r.get("origen", "")).split(":")[0])
        _mezcla_candidatos(candidatos, r)

    procesados = estado.setdefault("procesados", {})
    objetivo, barrido = [], []
    for reg in candidatos.values():
        reg["_puntaje"] = puntaje_candidato(reg)
        visto = hash_url(reg["link"]) in procesados
        tiene_cuerpo = hash_url(reg["link"]) in cuerpos_previos
        if reg["_puntaje"] >= 10 or reg.get("fuente_institucional") or tiene_cuerpo:
            objetivo.append(reg)
        elif not visto:
            barrido.append(reg)

    orden = lambda r: (r["_puntaje"], r.get("fecha_dt") or datetime.min.replace(tzinfo=TZ_CL))
    objetivo.sort(key=orden, reverse=True)
    barrido.sort(key=orden, reverse=True)
    objetivo = objetivo[:MAX_ARTICULOS_ENRIQUECER]
    barrido = barrido[:PRESUPUESTO_BARRIDO]
    log(f"  · candidatos chilenos únicos: {len(candidatos)} · objetivo: {len(objetivo)} · "
        f"barrido profundo: {len(barrido)} · descartados: {descartados}")

    trabajo = objetivo + barrido
    reutilizados = 0
    pendientes, listos = [], []
    for reg in trabajo:
        cache = cuerpos_previos.get(hash_url(reg["link"]))
        if cache and cache.get("texto"):
            reg["texto_enriquecido"] = cache["texto"]
            reg["cuerpo_extraido"] = True
            reg["enriquecido"] = True
            if not reg.get("resumen"):
                reg["resumen"] = cache.get("resumen", "")[:900]
            if not reg.get("fecha_dt") and cache.get("fecha_iso"):
                reg["fecha_dt"] = parsea_fecha_flexible(cache["fecha_iso"])
            reg["fuente_institucional"] = es_fuente_institucional(reg)
            reutilizados += 1
            listos.append(reg)
        else:
            pendientes.append(reg)

    enriquecidos = list(listos)
    fallidos = 0
    if pendientes:
        with ThreadPoolExecutor(max_workers=HILOS) as pool:
            futuros = {pool.submit(enriquece_articulo, r): r for r in pendientes}
            for fut in as_completed(futuros):
                try:
                    resultado = fut.result()
                except Exception:
                    resultado = futuros[fut]
                    resultado["cuerpo_extraido"] = False
                if not resultado.get("cuerpo_extraido"):
                    fallidos += 1
                enriquecidos.append(resultado)

    ahora_ts = time.time()
    salida = []
    cuerpos = 0
    for reg in enriquecidos:
        reg.pop("_puntaje", None)
        limpio = limpia_url(reg.get("link", ""))
        if not limpio:
            continue
        reg["link"] = limpio
        procesados[hash_url(limpio)] = int(ahora_ts)
        if not es_fuente_chilena(reg):
            descartados += 1
            continue
        if reg.get("cuerpo_extraido"):
            cuerpos += 1
        salida.append(reg)
    log(f"  · prensa chilena: {len(salida)} · cuerpos nuevos: {cuerpos} · "
        f"reutilizados de caché: {reutilizados} · sin cuerpo: {fallidos}")
    return salida


# ─────────────────────────────────────────────────────────────
# Métricas
# ─────────────────────────────────────────────────────────────

def _fecha_registro(reg):
    iso = reg.get("fecha_iso")
    if iso:
        try:
            dt = datetime.fromisoformat(iso)
            return dt if dt.tzinfo else dt.replace(tzinfo=TZ_CL)
        except ValueError:
            pass
    try:
        return datetime.strptime(f"{reg['fecha']} {reg.get('hora', '00:00')}",
                                 "%Y-%m-%d %H:%M").replace(tzinfo=TZ_CL)
    except (KeyError, ValueError, TypeError):
        return None


MINIMO = datetime.min.replace(tzinfo=timezone.utc)


def _ranking(registros, clave, etiqueta=None, excluir=None):
    conteo = {}
    for r in registros:
        valores = r.get(clave, [])
        if not isinstance(valores, list):
            valores = [valores]
        for valor in valores:
            if valor in (None, "") or (excluir and valor in excluir):
                continue
            conteo[valor] = conteo.get(valor, 0) + 1
    return [{"clave": k, "label": etiqueta.get(k, k) if etiqueta else k, "n": n}
            for k, n in sorted(conteo.items(), key=lambda x: (-x[1], str(x[0])))]


CAMPOS_DETALLE = (
    "id", "fecha", "hora", "fecha_iso", "medio", "tipo_medio", "tipo_medio_label",
    "titulo", "resumen", "link", "fenomeno", "fenomeno_label", "naturaleza",
    "naturaleza_label", "precedentes", "precedentes_label", "topicos", "topicos_label",
    "sujetos_obligados", "sujetos_obligados_label", "impactos_sujeto",
    "impactos_sujeto_label", "uaf_confianza", "uaf_motivos", "uaf_puntaje",
    "contexto_uaf", "nivel_fuente", "nivel_fuente_label",
)


def calcula_metricas(prensa, social, dias, ahora):
    total = len(prensa)
    uaf_registros = [r for r in prensa if r.get("uaf")]
    uaf_prensa = [r for r in uaf_registros if not r.get("fuente_institucional")]
    uaf_institucional = [r for r in uaf_registros if r.get("fuente_institucional")]
    contexto = [r for r in prensa if not r.get("uaf")]

    por_dia = {d: {"total": 0, "uaf": 0, "contexto": 0} for d in dias}
    for r in prensa:
        if r.get("fecha") in por_dia:
            por_dia[r["fecha"]]["total"] += 1
            por_dia[r["fecha"]]["uaf" if r.get("uaf") else "contexto"] += 1

    corte24 = ahora - timedelta(hours=24)
    corte48 = ahora - timedelta(hours=48)
    corte5 = ahora - timedelta(days=5)
    uaf24 = [r for r in uaf_prensa if (_fecha_registro(r) or MINIMO) >= corte24]
    uaf_prev = [r for r in uaf_prensa if corte48 <= (_fecha_registro(r) or MINIMO) < corte24]
    uaf5 = [r for r in uaf_prensa if (_fecha_registro(r) or MINIMO) >= corte5]
    actual, previo = len(uaf24), len(uaf_prev)
    diferencia = actual - previo
    if previo:
        pct = round(diferencia / previo * 100, 1)
        direccion = "sube" if diferencia > 0 else ("baja" if diferencia < 0 else "estable")
    else:
        pct = None
        direccion = "nueva" if actual > 0 else "estable"

    fenomenos = _ranking(prensa, "fenomeno", FENOMENO_ETIQUETA)
    precedentes = _ranking(prensa, "precedentes", PRECEDENTE_ETIQUETA)
    naturalezas = _ranking(prensa, "naturaleza", NATURALEZA_ETIQUETA)
    topicos = _ranking(prensa, "topicos", TOPICO_ETIQUETA)
    tipos_medio = _ranking(prensa, "tipo_medio", TIPO_MEDIO_ETIQUETA)
    medios = _ranking(prensa, "medio")
    sujetos = _ranking(prensa, "sujetos_obligados", SUJETO_OBLIGADO_ETIQUETA)
    impactos = _ranking(prensa, "impactos_sujeto", IMPACTO_SUJETO_ETIQUETA)

    cronologia = []
    for f in fenomenos:
        celdas = []
        for d in dias:
            rs = [r for r in prensa if r.get("fenomeno") == f["clave"] and r.get("fecha") == d]
            celdas.append({"dia": d, "n": len(rs), "medios": sorted({r["medio"] for r in rs})})
        cronologia.append({"clave": f["clave"], "label": f["label"], "celdas": celdas,
                           "total": f["n"]})

    semanas, bloque = [], []
    for dia in dias:
        bloque.append(dia)
        if datetime.strptime(dia, "%Y-%m-%d").weekday() == 6 or dia == dias[-1]:
            regs = [r for r in prensa if r.get("fecha") in bloque]
            semanas.append({
                "desde": bloque[0], "hasta": bloque[-1], "total": len(regs),
                "uaf": sum(1 for r in regs if r.get("uaf")),
                "contexto": sum(1 for r in regs if not r.get("uaf")),
                "medios": len({r["medio"] for r in regs}),
            })
            bloque = []

    plataformas = []
    for p in PLATAFORMAS:
        posts = [s for s in social if s.get("plataforma") == p["id"]]
        base = dict(p)
        base.update({
            "menciones": len(posts),
            "menciones_uaf": sum(1 for s in posts if s.get("uaf")),
            "interacciones": sum(int(s.get("interacciones", 0) or 0) for s in posts),
        })
        plataformas.append(base)

    detalle = [{k: r.get(k) for k in CAMPOS_DETALLE}
               for r in sorted(uaf24, key=lambda x: (_fecha_registro(x) or MINIMO), reverse=True)]

    return {
        "uaf_portada": {
            "menciones_24h": actual,
            "menciones_previas_24h": previo,
            "diferencia": diferencia,
            "variacion_pct": pct,
            "direccion": direccion,
            "menciones_5d": len(uaf5),
            "medios_24h": len({r["medio"] for r in uaf24}),
            "medios_5d": len({r["medio"] for r in uaf5}),
            "topicos_24h": _ranking(uaf24, "topicos", TOPICO_ETIQUETA),
            "fenomenos_24h": _ranking(uaf24, "fenomeno", FENOMENO_ETIQUETA),
            "naturalezas_24h": _ranking(uaf24, "naturaleza", NATURALEZA_ETIQUETA),
            "tipos_medio_24h": _ranking(uaf24, "tipo_medio", TIPO_MEDIO_ETIQUETA),
            "medios_ranking_24h": _ranking(uaf24, "medio"),
            "sujetos_obligados_24h": _ranking(uaf24, "sujetos_obligados", SUJETO_OBLIGADO_ETIQUETA),
            "confianza_24h": _ranking(uaf24, "uaf_confianza"),
            "detalle": detalle,
        },
        "uaf_total": len(uaf_registros),
        "uaf_prensa": len(uaf_prensa),
        "uaf_institucional": len(uaf_institucional),
        "uaf_social": sum(1 for r in social if r.get("uaf")),
        "uaf_donde": detalle[:8],
        "contexto_total": len(contexto),
        "volumen": total,
        "volumen_hoy": por_dia[dias[-1]]["total"] if dias else 0,
        "dias_con_actividad": sum(1 for d in dias if por_dia[d]["total"] > 0),
        "dias_ventana": len(dias),
        "medios_unicos": len({r["medio"] for r in prensa}),
        "casos_activos": len([f for f in fenomenos if f["clave"] != "otro"]),
        "precedentes_distintos": len([p for p in precedentes if p["clave"] != "indeterminado"]),
        "fenomenos": fenomenos,
        "precedentes": precedentes,
        "naturalezas": naturalezas,
        "topicos": topicos,
        "tipos_medio": tipos_medio,
        "medios": medios,
        "sujetos_obligados": sujetos,
        "impactos_sujeto": impactos,
        "niveles_fuente": _ranking(prensa, "nivel_fuente", NIVEL_FUENTE_ETIQUETA),
        "cronologia": cronologia,
        "por_dia": por_dia,
        "semanas": semanas,
        "rankings_30d": {
            "medios": medios[:12],
            "fenomenos": [x for x in fenomenos if x["clave"] != "otro"][:12],
            "precedentes": [x for x in precedentes if x["clave"] != "indeterminado"][:12],
            "sujetos_obligados": sujetos[:12],
            "impactos_sujeto": impactos[:12],
        },
        "plataformas": plataformas,
        "social_total": len(social),
        "social_monitoreadas": len(plataformas),
        "social_sin_acceso": 0,
    }


# ─────────────────────────────────────────────────────────────
# Configuración y correo
# ─────────────────────────────────────────────────────────────

def carga_config():
    config = copy.deepcopy(CONFIG_EJEMPLO)
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as fh:
                usuario = json.load(fh)
            if isinstance(usuario.get("correo"), dict):
                config["correo"].update(usuario["correo"])
        except (OSError, json.JSONDecodeError) as e:
            log(f"! config.json ilegible: {type(e).__name__}")
    elif not os.getenv("GITHUB_ACTIONS"):
        try:
            with open(CONFIG, "w", encoding="utf-8") as fh:
                json.dump(config, fh, ensure_ascii=False, indent=2)
            log("Se creó config.json con el correo desactivado.")
        except OSError:
            pass

    c = config["correo"]
    c["activo"] = _env_bool("MONITOR_CORREO_ACTIVO", bool(c.get("activo", False)))
    c["servidor"] = os.getenv("MONITOR_SMTP_SERVIDOR", c.get("servidor", "")).strip()
    c["puerto"] = _env_int("MONITOR_SMTP_PUERTO", int(c.get("puerto", 587) or 587))
    c["seguridad"] = os.getenv("MONITOR_SMTP_SEGURIDAD", c.get("seguridad", "starttls")).strip()
    c["usuario"] = os.getenv("MONITOR_SMTP_USUARIO", c.get("usuario", "")).strip()
    c["clave"] = os.getenv("MONITOR_SMTP_CLAVE", c.get("clave", ""))
    c["remitente"] = os.getenv("MONITOR_REMITENTE", c.get("remitente", c["usuario"])).strip()
    c["remitente_nombre"] = os.getenv("MONITOR_REMITENTE_NOMBRE",
                                      c.get("remitente_nombre", "Monitor UAF Chile"))
    destinos = os.getenv("MONITOR_DESTINATARIOS")
    if destinos:
        c["destinatarios"] = [x.strip() for x in re.split(r"[,;\s]+", destinos) if "@" in x]
    c["minimo_para_avisar"] = _env_int("MONITOR_MINIMO_AVISO",
                                       int(c.get("minimo_para_avisar", 1) or 1))
    c["silencio_minutos"] = _env_int("MONITOR_SILENCIO_MINUTOS",
                                     int(c.get("silencio_minutos", 0) or 0))
    c["solo_si_menciona_uaf"] = _env_bool("MONITOR_SOLO_UAF",
                                          bool(c.get("solo_si_menciona_uaf", True)))
    return config


def _conecta_smtp(c):
    servidor = c.get("servidor", "")
    puerto = int(c.get("puerto", 587) or 587)
    seguridad = str(c.get("seguridad", "starttls")).lower().strip()
    contexto = ssl.create_default_context()
    if seguridad in {"ssl", "smtps"}:
        smtp = smtplib.SMTP_SSL(servidor, puerto, timeout=30, context=contexto)
    else:
        smtp = smtplib.SMTP(servidor, puerto, timeout=30)
        smtp.ehlo()
        if seguridad == "starttls":
            smtp.starttls(context=contexto)
            smtp.ehlo()
    usuario, clave = c.get("usuario", ""), c.get("clave", "")
    if usuario and clave:
        smtp.login(usuario, clave)
    return smtp


def _manda_mensaje(c, asunto, cuerpo_html, cuerpo_texto):
    destinatarios = [d for d in (c.get("destinatarios") or []) if "@" in d]
    remitente = c.get("remitente") or c.get("usuario", "")
    if not c.get("servidor") or not remitente or not destinatarios:
        raise ValueError("faltan servidor, remitente o destinatarios")
    msg = EmailMessage()
    msg["Subject"] = asunto
    msg["From"] = formataddr((c.get("remitente_nombre", "Monitor UAF Chile"), remitente))
    msg["To"] = ", ".join(destinatarios)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="monitor-uaf.local")
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(cuerpo_texto)
    msg.add_alternative(cuerpo_html, subtype="html")
    with _conecta_smtp(c) as smtp:
        smtp.send_message(msg)


def envia_correo(config, nuevos, metricas, estado):
    """Avisa cuando la corrida detecta noticias nuevas de prensa con UAF Chile."""
    c = config.get("correo", {})
    if not c.get("activo"):
        return False

    if c.get("solo_si_menciona_uaf", True):
        candidatos = [n for n in nuevos
                      if n.get("canal") == "prensa" and n.get("uaf_chile") is True]
    else:
        candidatos = [n for n in nuevos if n.get("canal") == "prensa"]
    minimo = max(1, int(c.get("minimo_para_avisar", 1) or 1))
    if len(candidatos) < minimo:
        log(f"Correo omitido: {len(candidatos)} noticias nuevas UAF Chile (mínimo {minimo}).")
        return False

    silencio = max(0, int(c.get("silencio_minutos", 0) or 0))
    ultimo = estado.get("ultimo_correo")
    if ultimo and silencio:
        try:
            anterior = datetime.fromisoformat(ultimo)
            if anterior.tzinfo is None:
                anterior = anterior.replace(tzinfo=TZ_CL)
            if datetime.now(TZ_CL) - anterior < timedelta(minutes=silencio):
                log("Correo omitido por período de silencio configurado.")
                return False
        except ValueError:
            pass

    esc = html_mod.escape
    filas_html, filas_texto = [], []
    for n in candidatos[:25]:
        topicos = ", ".join(n.get("topicos_label", [])) or "Sin tópico asignado"
        naturaleza = n.get("naturaleza_label", "Sin clasificación")
        fenomeno = n.get("fenomeno_label", "Otros")
        sujetos = ", ".join(n.get("sujetos_obligados_label", [])) or "No identificado"
        extracto = (n.get("contexto_uaf") or n.get("resumen") or "").strip()
        enlace = n.get("link", "") if url_http(n.get("link", "")) else ""
        extracto_html = (f'<div style="margin-top:6px;color:#44546a">{esc(extracto[:600])}</div>'
                         if extracto else "")
        titulo_html = esc(n.get("titulo", "(sin título)"))
        if enlace:
            titulo_html = (f'<a style="color:#005b78" href="{esc(enlace, quote=True)}">'
                           f'{titulo_html}</a>')
        filas_html.append(
            '<li style="margin:0 0 18px;padding:0 0 14px;border-bottom:1px solid #d9e2ec">'
            f'<div style="font-size:13px;color:#52647a"><b>{esc(n.get("medio", ""))}</b> · '
            f'{esc(n.get("fecha", ""))} {esc(n.get("hora", ""))} · '
            f'validación {esc(n.get("uaf_confianza", ""))}</div>'
            f'<div style="font-size:17px;font-weight:700;margin:4px 0">{titulo_html}</div>'
            f'<div style="font-size:13px;color:#334e68">'
            f'<b>Tópicos:</b> {esc(topicos)} · <b>Tipo:</b> {esc(naturaleza)} · '
            f'<b>Fenómeno:</b> {esc(fenomeno)} · <b>Sujeto obligado:</b> {esc(sujetos)}</div>'
            f'{extracto_html}</li>'
        )
        filas_texto.append(
            f'- {n.get("medio", "")} · {n.get("fecha", "")} {n.get("hora", "")}\n'
            f'  {n.get("titulo", "")}\n'
            f'  Tópicos: {topicos} | Tipo: {naturaleza} | Fenómeno: {fenomeno} | '
            f'Sujeto obligado: {sujetos}\n  {enlace}'
        )

    cantidad = len(candidatos)
    plural = "s" if cantidad != 1 else ""
    asunto = f"Alerta UAF Chile: {cantidad} noticia{plural} nueva{plural}"
    portada = metricas.get("uaf_portada", {}) if isinstance(metricas, dict) else {}
    total_24h = portada.get("menciones_24h", 0)
    cuerpo_html = (
        '<div style="font-family:Arial,sans-serif;max-width:780px;color:#102a43">'
        '<div style="background:#073b4c;color:white;padding:18px 22px;border-left:7px solid #18a0a8">'
        '<div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase">Monitor UAF Chile</div>'
        f'<h2 style="margin:5px 0 0">{esc(asunto)}</h2></div>'
        '<div style="padding:18px 22px;background:#f5f8fb">'
        '<p style="margin-top:0">La actualización automática detectó noticias nuevas de prensa '
        'con mención validada a la <b>Unidad de Análisis Financiero de Chile</b>.</p>'
        f'<p>Menciones UAF en prensa durante las últimas 24 horas: <b>{int(total_24h)}</b>.</p>'
        f'<ol style="padding-left:22px">{"".join(filas_html)}</ol>'
        '<p style="font-size:12px;color:#627d98">Aviso generado solo para noticias nuevas; '
        'la misma noticia no se reenvía en corridas posteriores.</p></div></div>'
    )
    try:
        _manda_mensaje(c, asunto, cuerpo_html, asunto + "\n\n" + "\n\n".join(filas_texto))
    except Exception as e:
        log(f"! fallo al enviar correo: {type(e).__name__}: {e}")
        return False

    estado["ultimo_correo"] = datetime.now(TZ_CL).isoformat()
    log(f"Correo enviado a {len(c.get('destinatarios', []))} destinatario(s).")
    return True


def prueba_correo():
    c = carga_config().get("correo", {})
    log(f"SMTP configurado: servidor={'sí' if c.get('servidor') else 'no'} · "
        f"usuario={'sí' if c.get('usuario') else 'no'} · "
        f"destinatarios={len(c.get('destinatarios') or [])}")
    try:
        _manda_mensaje(c, "Prueba del Monitor UAF Chile",
                       "<p>La configuración SMTP del Monitor UAF funciona.</p>",
                       "La configuración SMTP del Monitor UAF funciona.")
    except Exception as e:
        log(f"! prueba de correo fallida: {type(e).__name__}: {e}")
        raise SystemExit(1)
    log("Correo de prueba enviado correctamente.")


# ─────────────────────────────────────────────────────────────
# Estado, histórico y ciclo principal
# ─────────────────────────────────────────────────────────────

def carga_estado():
    estado = {"vistos": [], "procesados": {}, "endpoints": {}, "esquema": ESQUEMA_ID}
    if os.path.exists(ESTADO):
        try:
            with open(ESTADO, encoding="utf-8") as fh:
                guardado = json.load(fh)
            if isinstance(guardado, dict):
                estado.update(guardado)
        except (OSError, json.JSONDecodeError):
            log("! estado ilegible; se reinicia la memoria de la corrida")
    estado.setdefault("vistos", [])
    estado.setdefault("procesados", {})
    estado.setdefault("endpoints", {})
    if not isinstance(estado.get("procesados"), dict):
        estado["procesados"] = {}
    return estado


def guarda_estado(estado):
    estado["vistos"] = list(dict.fromkeys(estado.get("vistos", [])))[-20000:]
    limite = time.time() - DIAS_PROCESADOS * 86400
    procesados = {k: v for k, v in (estado.get("procesados") or {}).items()
                  if isinstance(v, (int, float)) and v >= limite}
    if len(procesados) > MAX_PROCESADOS:
        recientes = sorted(procesados.items(), key=lambda x: x[1], reverse=True)[:MAX_PROCESADOS]
        procesados = dict(recientes)
    estado["procesados"] = procesados
    estado["esquema"] = ESQUEMA_ID
    estado["actualizado"] = datetime.now(TZ_CL).isoformat()
    temporal = ESTADO + ".tmp"
    with open(temporal, "w", encoding="utf-8") as fh:
        json.dump(estado, fh, ensure_ascii=False)
    os.replace(temporal, ESTADO)


def carga_datos_previos():
    if not os.path.exists(SALIDA):
        return {"prensa": [], "social": []}
    try:
        with open(SALIDA, encoding="utf-8") as fh:
            datos = json.load(fh)
        return {"prensa": datos.get("prensa", []) or [], "social": datos.get("social", []) or []}
    except (OSError, json.JSONDecodeError):
        log("! datos.json previo ilegible; se parte del histórico vacío")
        return {"prensa": [], "social": []}


def indice_cuerpos(previos):
    """Caché de cuerpos ya extraídos para no volver a descargar el mismo artículo."""
    cache = {}
    for r in previos.get("prensa", []):
        enlace = r.get("link", "")
        texto = r.get("texto_enriquecido", "")
        if enlace and texto:
            cache[hash_url(enlace)] = {
                "texto": texto,
                "resumen": r.get("resumen", ""),
                "fecha_iso": r.get("fecha_iso", ""),
            }
    return cache


def _crudo_desde_registro(reg):
    return {
        "titulo": reg.get("titulo", ""),
        "resumen": reg.get("resumen", ""),
        "medio": reg.get("medio", ""),
        "fuente_url": reg.get("fuente_url", ""),
        "url_final": reg.get("url_final", ""),
        "link": reg.get("link", ""),
        "texto_enriquecido": reg.get("texto_enriquecido", ""),
        "contexto_uaf": reg.get("contexto_uaf", ""),
        "fuente_institucional": reg.get("fuente_institucional", False),
        "enlaza_uaf": reg.get("enlaza_uaf", False),
    }


def etiqueta_registro(reg):
    reg["topicos_label"] = [TOPICO_ETIQUETA.get(t, t) for t in reg.get("topicos", ["otros"])]
    reg["tipo_medio_label"] = TIPO_MEDIO_ETIQUETA.get(reg.get("tipo_medio", "otro"),
                                                      "Otro medio digital")
    reg["sujetos_obligados_label"] = [SUJETO_OBLIGADO_ETIQUETA.get(x, x)
                                      for x in reg.get("sujetos_obligados", [])]
    reg["impactos_sujeto_label"] = [IMPACTO_SUJETO_ETIQUETA.get(x, x)
                                    for x in reg.get("impactos_sujeto", [])]
    reg["fenomeno_label"] = FENOMENO_ETIQUETA.get(reg.get("fenomeno", "otro"), "Otros")
    reg["naturaleza_label"] = NATURALEZA_ETIQUETA.get(reg.get("naturaleza", "analisis"),
                                                      "Análisis y opinión")
    reg["precedentes_label"] = [PRECEDENTE_ETIQUETA.get(x, x)
                               for x in reg.get("precedentes", ["indeterminado"])]
    reg["nivel_fuente_label"] = NIVEL_FUENTE_ETIQUETA.get(reg.get("nivel_fuente", ""), "")
    return reg


def reclasifica_historico(original):
    """Aplica las reglas vigentes a un registro histórico."""
    r = dict(original)
    dt = _fecha_registro(r)
    if dt and not r.get("fecha_iso"):
        r["fecha_iso"] = dt.isoformat()
    crudo = _crudo_desde_registro(r)
    r["canal"] = r.get("canal", "prensa")
    r["fuente_institucional"] = bool(r.get("fuente_institucional")
                                     or es_fuente_institucional(crudo))
    enriquecido = clasifica(crudo)
    for campo in ("fenomeno", "naturaleza", "precedentes", "topicos", "tipo_medio", "uaf",
                  "uaf_chile", "uaf_confianza", "uaf_motivos", "uaf_puntaje", "uaf_menciones",
                  "sujetos_obligados", "impactos_sujeto", "roles_sujetos", "roles_sujetos_label",
                  "nucleo", "nivel_fuente"):
        r[campo] = enriquecido.get(campo)
    if enriquecido.get("contexto_uaf"):
        r["contexto_uaf"] = enriquecido["contexto_uaf"]
    return etiqueta_registro(r)


def mezcla_historico(previos, actuales, corte):
    combinados = {}
    for original in list(previos) + list(actuales):
        crudo = _crudo_desde_registro(original)
        canal = original.get("canal", "prensa")
        if canal == "prensa" and not es_fuente_chilena(crudo):
            continue
        if not es_pertinente(crudo):
            continue
        r = reclasifica_historico(original)
        rid = r.get("id") or id_estable(r.get("link", ""), r.get("titulo", ""))
        r["id"] = rid
        dt = _fecha_registro(r)
        if not dt or dt < corte:
            continue
        anterior = combinados.get(rid)
        if anterior and len(str(anterior.get("texto_enriquecido", ""))) > len(str(r.get("texto_enriquecido", ""))):
            continue
        combinados[rid] = r
    ordenados = sorted(combinados.values(),
                       key=lambda r: (_fecha_registro(r) or corte), reverse=True)
    vistos_titulo, unicos = {}, []
    for r in ordenados:
        clave = (normaliza(r.get("titulo", ""))[:95], normaliza(r.get("medio", "")))
        if not clave[0]:
            unicos.append(r)
            continue
        previo = vistos_titulo.get(clave)
        if previo is None:
            vistos_titulo[clave] = r
            unicos.append(r)
            continue
        # Se conserva el registro con enlace directo al medio y más contenido.
        def calidad(x):
            return (dominio_url(x.get("link", "")) not in AGREGADORES,
                    len(str(x.get("texto_enriquecido", ""))),
                    len(str(x.get("resumen", ""))))
        if calidad(r) > calidad(previo):
            unicos[unicos.index(previo)] = r
            vistos_titulo[clave] = r
    return unicos


def pasada():
    ahora = datetime.now(TZ_CL)
    corte = (ahora - timedelta(days=VENTANA_DIAS)).replace(second=0, microsecond=0)
    primer_dia = (ahora - timedelta(days=VENTANA_DIAS - 1)).date()
    dias = [(primer_dia + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(VENTANA_DIAS)]

    estado = carga_estado()
    migracion = int(estado.get("esquema", 0)) != ESQUEMA_ID
    if migracion:
        log("! cambio de esquema de identificadores: esta corrida no enviará correo")

    previos = carga_datos_previos()
    cuerpos = indice_cuerpos(previos)
    log(f"Histórico: {len(previos['prensa'])} registros · caché de cuerpos: {len(cuerpos)}")

    log("Recolectando prensa chilena…")
    crudos = recolecta_prensa(estado, cuerpos)
    log("Recolectando señal social pública…")
    crudos_soc = recolecta_social()

    if not crudos and not crudos_soc and os.path.exists(SALIDA):
        log("! ninguna fuente respondió; se conserva el datos.json anterior")
        guarda_estado(estado)
        return 0

    vistos = set(estado.get("vistos", []))
    nuevos = []

    def procesa(lote, canal):
        salida, dedup = [], set()
        for r in lote:
            if not r.get("fecha_dt"):
                # Antes se descartaba la noticia. Ahora, si la fuente es chilena y
                # pertinente, se conserva con fecha estimada al momento del hallazgo
                # y queda marcada como tal para que el analista lo sepa.
                if canal == "prensa" and r.get("cuerpo_extraido"):
                    r["fecha_dt"] = ahora
                    r["fecha_estimada"] = True
                else:
                    continue
            if r["fecha_dt"] < corte:
                continue
            if r["fecha_dt"] > ahora + timedelta(hours=6):
                continue  # fechas futuras: dato erróneo del medio
            if not url_http(r.get("link", "")):
                continue
            if canal == "prensa" and not es_fuente_chilena(r):
                continue
            if not es_pertinente(r):
                continue
            clave = id_estable(r["link"], r.get("titulo", ""))
            if clave in dedup:
                continue
            dedup.add(clave)
            r = clasifica(r)
            registro = {
                "id": clave,
                "canal": canal,
                "fecha": r["fecha_dt"].strftime("%Y-%m-%d"),
                "hora": r["fecha_dt"].strftime("%H:%M"),
                "fecha_iso": r["fecha_dt"].isoformat(),
                "medio": r.get("medio", "")[:160],
                "fuente_url": r.get("fuente_url", ""),
                "url_final": r.get("url_final", ""),
                "fuente_institucional": bool(r.get("fuente_institucional")),
                "nivel_fuente": r.get("nivel_fuente", ""),
                "origen": r.get("origen", ""),
                "origen_busqueda": str(r.get("origen_busqueda", ""))[:180],
                "enriquecido": bool(r.get("enriquecido")),
                "cuerpo_extraido": bool(r.get("cuerpo_extraido")),
                "texto_enriquecido": str(r.get("texto_enriquecido", ""))[:MAX_TEXTO_GUARDADO],
                "tipo_medio": r.get("tipo_medio", "otro"),
                "titulo": r.get("titulo", "")[:500],
                "resumen": r.get("resumen", "")[:900],
                "link": r["link"],
                "fenomeno": r.get("fenomeno", "otro"),
                "naturaleza": r.get("naturaleza", "analisis"),
                "precedentes": r.get("precedentes", ["indeterminado"]),
                "topicos": r.get("topicos", ["otros"]),
                "sujetos_obligados": r.get("sujetos_obligados", []),
                "impactos_sujeto": r.get("impactos_sujeto", []),
                "roles_sujetos": r.get("roles_sujetos", {}),
                "roles_sujetos_label": r.get("roles_sujetos_label", {}),
                "uaf": bool(r.get("uaf")),
                "uaf_chile": bool(r.get("uaf_chile")),
                "uaf_confianza": r.get("uaf_confianza", "media"),
                "uaf_motivos": r.get("uaf_motivos", []),
                "uaf_puntaje": r.get("uaf_puntaje", 0),
                "uaf_menciones": r.get("uaf_menciones", 0),
                "contexto_uaf": r.get("contexto_uaf", ""),
                "plataforma": r.get("plataforma"),
                "interacciones": int(r.get("interacciones", 0) or 0),
                "nucleo": bool(r.get("nucleo")),
                "fecha_estimada": bool(r.get("fecha_estimada")),
            }
            etiqueta_registro(registro)
            if clave not in vistos:
                registro["nuevo"] = True
                nuevos.append(registro)
                vistos.add(clave)
            salida.append(registro)
        return salida

    prensa = mezcla_historico(previos.get("prensa", []), procesa(crudos, "prensa"), corte)
    social = mezcla_historico(previos.get("social", []), procesa(crudos_soc, "social"), corte)

    metricas = calcula_metricas(prensa, social, dias, ahora)
    salida = {
        "generado": ahora.isoformat(),
        "generado_legible": ahora.strftime("%d/%m/%Y %H:%M"),
        "version_motor": VERSION_MONITOR,
        "ventana": {"dias": dias, "hoy": ahora.strftime("%Y-%m-%d"), "largo": VENTANA_DIAS},
        "metricas": metricas,
        "prensa": prensa,
        "social": social,
        "nuevos": len(nuevos),
        "consultas": (len(CONSULTAS_PRENSA) + len(CONSULTAS_BING) + len(CONSULTAS_GDELT)
                      + len(MEDIOS_CHILE) + len(CONSULTAS_SOCIALES) * (len(SUBREDDITS) + 1)),
        "cobertura_tecnica": {
            "cuerpos_extraidos": sum(1 for r in prensa if r.get("cuerpo_extraido")),
            "fuentes_institucionales": sum(1 for r in prensa if r.get("fuente_institucional")),
            "solo_fuentes_chilenas": True,
            "medios_en_lista_blanca": len(DOMINIOS_CHILENOS),
            "dominios_con_feed": sum(1 for v in (estado.get("endpoints") or {}).values()
                                     if v.get("feeds")),
            "dominios_con_sitemap": sum(1 for v in (estado.get("endpoints") or {}).values()
                                        if v.get("sitemaps")),
            "articulos_en_memoria": len(estado.get("procesados") or {}),
            "dominios_con_hallazgos": len(INFORME_COBERTURA),
            "respeta_robots": RESPETA_ROBOTS,
            "segundos_corrida": round(time.monotonic() - _INICIO, 1),
        },
    }

    # Auditoría de cobertura: cuántas noticias aportó cada dominio y cuáles
    # de los medios de la lista no entregaron nada en esta corrida.
    publicadas = {}
    for r in prensa:
        host = dominio_url(r.get("link", "")) or dominio_url(r.get("fuente_url", ""))
        fila = publicadas.setdefault(host, {"total": 0, "uaf": 0})
        fila["total"] += 1
        if r.get("uaf"):
            fila["uaf"] += 1
    cobertura_medios = []
    for host in dict.fromkeys(DOMINIOS_BUSQUEDA_SITIO + sorted(publicadas)):
        endpoints = (estado.get("endpoints", {}) or {}).get(host, {})
        pub = publicadas.get(host, {})
        cand = INFORME_COBERTURA.get(host, {})
        cobertura_medios.append({
            "medio": NOMBRE_POR_DOMINIO.get(host, host),
            "dominio": host,
            "prioritario": host in DOMINIOS_BUSQUEDA_SITIO,
            "candidatos": cand.get("candidatos", 0),
            "canales": sorted((cand.get("canales") or {}).keys()),
            "publicadas_30d": pub.get("total", 0),
            "uaf_30d": pub.get("uaf", 0),
            "feed": bool(endpoints.get("feeds")),
            "sitemap": bool(endpoints.get("sitemaps")),
        })
    cobertura_medios.sort(key=lambda x: (-x["publicadas_30d"], -x["candidatos"], x["dominio"]))
    salida["cobertura_medios"] = cobertura_medios

    silenciosos = [c["dominio"] for c in cobertura_medios
                   if c["prioritario"] and not c["candidatos"] and not c["publicadas_30d"]]
    if silenciosos:
        log(f"  ! sin hallazgos en esta corrida ({len(silenciosos)}): {', '.join(silenciosos[:22])}")
    sin_via = [c["dominio"] for c in cobertura_medios
               if c["prioritario"] and not c["feed"] and not c["sitemap"]]
    if sin_via:
        log(f"  · sin feed ni sitemap propio, dependen de buscadores ({len(sin_via)}): "
            f"{', '.join(sin_via[:22])}")

    temporal = SALIDA + ".tmp"
    with open(temporal, "w", encoding="utf-8") as fh:
        json.dump(salida, fh, ensure_ascii=False, indent=1)
    os.replace(temporal, SALIDA)

    estado["vistos"] = list(vistos)
    log(f"Listo: {len(prensa)} de prensa · {len(social)} sociales · {len(nuevos)} nuevas · "
        f"{salida['cobertura_tecnica']['segundos_corrida']}s → {SALIDA}")
    for n in nuevos[:12]:
        log(f"   NUEVA [{n['canal']}] {n['medio']} — {n['titulo'][:88]}")

    if nuevos and not migracion:
        envia_correo(carga_config(), nuevos, metricas, estado)
    guarda_estado(estado)
    return len(nuevos)


def diagnostico():
    estado = carga_estado()
    log(f"Diagnóstico de {len(MEDIOS_CHILE)} dominios (puede tardar varios minutos).")
    filas = []
    lock = threading.Lock()

    def revisa(host, tipo, prio):
        local = {"endpoints": {}}
        info = descubre_endpoints(host, local)
        with lock:
            estado.setdefault("endpoints", {})[host] = info
            filas.append((host, tipo, prio, len(info.get("feeds", [])),
                          len(info.get("sitemaps", []))))
        return []

    en_paralelo([lambda h=h, t=t, p=pr: revisa(h, t, p)
                 for _, h, t, pr in MEDIOS_CHILE], "diagnóstico")
    filas.sort(key=lambda f: (f[3] + f[4], f[0]))
    log("  dominio                              feeds sitemaps  vía")
    for host, tipo, prio, nf, ns in filas:
        via = "feed/sitemap" if (nf or ns) else ("buscadores" if prio else "sin vía propia")
        log(f"  {host:36s} {nf:5d} {ns:8d}  {via} ({tipo})")
    sin_via = [f[0] for f in filas if not f[3] and not f[4]]
    log(f"Resumen: {len(filas) - len(sin_via)}/{len(filas)} dominios con feed o sitemap propio.")
    log(f"Los {len(sin_via)} restantes se cubren con consultas site: en Google News y Bing.")
    guarda_estado(estado)


def probar_deteccion(texto, medio="La Tercera", link="https://www.latercera.com/prueba"):
    reg = {"titulo": texto[:200], "resumen": "", "texto_enriquecido": texto,
           "medio": medio, "link": link, "fuente_url": f"https://{dominio_url(link)}"}
    uaf, confianza, motivos, puntaje, menciones = analiza_uaf(reg)
    print(json.dumps({
        "uaf_chile": uaf, "confianza": confianza, "puntaje": puntaje,
        "menciones_utiles": menciones, "motivos": motivos,
        "pertinente": es_pertinente(reg),
        "contexto": extrae_contexto_uaf(reg)[:300],
    }, ensure_ascii=False, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Monitor UAF Chile · vigilancia de fuentes")
    ap.add_argument("--daemon", action="store_true", help="vigila en bucle")
    ap.add_argument("--intervalo", type=int, default=15, help="minutos entre pasadas")
    ap.add_argument("--probar-correo", action="store_true", help="envía un correo de prueba")
    ap.add_argument("--diagnostico", action="store_true", help="descubre fuentes y sale")
    ap.add_argument("--probar-deteccion", metavar="TEXTO", help="evalúa el motor UAF sobre un texto")
    args = ap.parse_args()

    if args.probar_correo:
        prueba_correo()
        return
    if args.probar_deteccion:
        probar_deteccion(args.probar_deteccion)
        return
    if args.diagnostico:
        diagnostico()
        return

    carga_config()
    if not args.daemon:
        pasada()
        return

    log(f"Vigilancia activa · cada {args.intervalo} min · Ctrl+C para detener")
    while True:
        global _INICIO
        _INICIO = time.monotonic()
        try:
            pasada()
        except KeyboardInterrupt:
            log("Detenido.")
            return
        except Exception as e:  # noqa: BLE001
            log(f"! error en la pasada: {type(e).__name__}: {e}")
        time.sleep(max(60, args.intervalo * 60))


if __name__ == "__main__":
    main()
