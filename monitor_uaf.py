#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monitor UAF Chile · motor v7.0 con doble ciclo de búsqueda.

Modos:
  rapido         Monitoreo oportuno para ejecutar cada 15 minutos.
  conciliacion   Barrido histórico profundo de los últimos 30 días.

El script usa solo la biblioteca estándar de Python. Descubre URLs mediante
buscadores de noticias, feeds, sitemaps, portadas y secciones institucionales;
descarga los artículos; valida menciones de la UAF de Chile; conserva contexto
LA/FT; y genera ``datos.json`` compatible con el dashboard anterior.

Comandos principales:
  python monitor_uaf.py --modo rapido
  python monitor_uaf.py --modo conciliacion
  python monitor_uaf.py --validar-fuentes
  python monitor_uaf.py --probar-url URL
  python monitor_uaf.py --probar-deteccion "texto"
  python monitor_uaf.py --diagnostico
"""

from __future__ import annotations

import argparse
import copy
import email.utils
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
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

# ---------------------------------------------------------------------------
# Serialización JSON segura
# ---------------------------------------------------------------------------


def json_default(obj: Any) -> Any:
    """Convierte tipos Python no nativos de JSON a valores persistibles.

    Algunos feeds, metadatos y cálculos internos pueden conservar objetos
    ``datetime`` o ``date``. El dashboard espera texto ISO-8601, por lo que
    esta conversión evita que una sola fecha detenga toda la publicación.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


# ---------------------------------------------------------------------------
# Rutas y configuración
# ---------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent
SALIDA = BASE / "datos.json"
ESTADO = BASE / ".monitor_estado.json"
BITACORA = BASE / "monitor.log"
CONFIG = BASE / "config.json"
FUENTES_ARCHIVO = BASE / "fuentes_uaf.json"
CASOS_CONTROL_ARCHIVO = BASE / "casos_control.json"

VERSION_MONITOR = "7.3-fix-serializacion-json"
ESQUEMA_ESTADO = 4
TZ_CL = ZoneInfo("America/Santiago") if ZoneInfo else timezone(timedelta(hours=-4))
UA = "Mozilla/5.0 (compatible; MonitorUAF/7.0; +https://github.com/)"
UA_ROBOTS = "MonitorUAF"

CONFIG_EJEMPLO = {
    "correo": {
        "activo": False,
        "servidor": "smtp.gmail.com",
        "puerto": 587,
        "seguridad": "starttls",
        "usuario": "tu.correo@gmail.com",
        "clave": "clave-de-aplicacion",
        "remitente_nombre": "Monitor UAF Chile",
        "destinatarios": ["tu.correo@gmail.com"],
        "minimo_para_avisar": 1,
        "silencio_minutos": 0,
        "solo_si_menciona_uaf": True,
    }
}


def env_bool(nombre: str, defecto: bool = False) -> bool:
    valor = os.getenv(nombre)
    if valor is None or not valor.strip():
        return defecto
    return valor.strip().lower() in {"1", "true", "si", "sí", "yes", "on"}


def env_int(nombre: str, defecto: int) -> int:
    valor = os.getenv(nombre)
    if valor is None or not valor.strip():
        return defecto
    try:
        return int(valor)
    except ValueError:
        return defecto


VENTANA_DIAS = env_int("MONITOR_VENTANA_DIAS", 30)
RETENCION_PROCESADOS_DIAS = env_int("MONITOR_DIAS_PROCESADOS", 45)
TIMEOUT = env_int("MONITOR_TIMEOUT", 22)
MAX_BYTES = env_int("MONITOR_MAX_BYTES", 5_000_000)
MAX_TEXTO_ANALISIS = env_int("MONITOR_MAX_TEXTO", 30_000)
MAX_TEXTO_GUARDADO = env_int("MONITOR_MAX_TEXTO_GUARDADO", 7_000)
HILOS = max(1, min(12, env_int("MONITOR_HILOS", 8)))
RESPETA_ROBOTS = env_bool("MONITOR_RESPETA_ROBOTS", True)
INTERVALO_HOST = float(os.getenv("MONITOR_INTERVALO_HOST", "0.75") or 0.75)
PRESUPUESTO_SEGUNDOS = env_int("MONITOR_PRESUPUESTO_SEG", 780)
MAX_ENRIQUECER = env_int("MONITOR_MAX_ENRIQUECER", 280)
MAX_CANDIDATOS = env_int("MONITOR_MAX_CANDIDATOS", 3_000)
MAX_SITE_QUERIES = env_int("MONITOR_MAX_SITE_QUERIES", 80)
MAX_GOOGLE_RESOLVER_RAPIDO = env_int("MONITOR_MAX_GOOGLE_RESOLVER", 120)
MAX_GOOGLE_RESOLVER_CONCILIACION = env_int("MONITOR_MAX_GOOGLE_RESOLVER_CONCILIACION", 420)
MAX_SITEMAPS_POR_FUENTE = env_int("MONITOR_MAX_SITEMAPS_FUENTE", 10)
MAX_URLS_SITEMAP = env_int("MONITOR_MAX_URLS_SITEMAP", 450)
MIN_POR_FUENTE = env_int("MONITOR_BARRIDO_MIN_FUENTE", 2)
MODO_ENV = os.getenv("MONITOR_MODO", "rapido").strip().lower()

INICIO = time.monotonic()


def tiempo_agotado(reserva: int = 0) -> bool:
    return time.monotonic() - INICIO >= max(30, PRESUPUESTO_SEGUNDOS - reserva)


# ---------------------------------------------------------------------------
# Catálogo de fuentes
# ---------------------------------------------------------------------------

def normaliza_dominio(host: str) -> str:
    host = (host or "").strip().lower().split(":")[0].rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


FUENTES_PREDETERMINADAS: list[dict[str, Any]] = [
    # Prensa nacional y económica
    {"nombre": "Diario Financiero", "dominio": "df.cl", "tipo": "economico", "prioridad": 10, "secciones": ["https://www.df.cl/"], "sitemaps": ["https://www.df.cl/noticias/site/sitemap_news.xml"]},
    {"nombre": "La Tercera / Pulso", "dominio": "latercera.com", "tipo": "prensa_nacional", "prioridad": 10, "secciones": ["https://www.latercera.com/", "https://www.latercera.com/pulso/"], "feeds": ["https://www.latercera.com/arc/outboundfeeds/rss/?outputType=xml"], "sitemaps": ["https://www.latercera.com/arc/outboundfeeds/news-sitemap-index?outputType=xml"]},
    {"nombre": "Emol", "dominio": "emol.com", "tipo": "prensa_nacional", "prioridad": 9, "secciones": ["https://www.emol.com/"], "sitemaps": ["https://www.emol.com/sitemap/sitemapIndex.xml"]},
    {"nombre": "El Mercurio", "dominio": "elmercurio.com", "tipo": "prensa_nacional", "prioridad": 8, "secciones": ["https://www.elmercurio.com/"]},
    {"nombre": "El Mostrador", "dominio": "elmostrador.cl", "tipo": "investigacion_digital", "prioridad": 8, "feeds": ["https://www.elmostrador.cl/feed/"], "secciones": ["https://www.elmostrador.cl/"]},
    {"nombre": "BioBioChile", "dominio": "biobiochile.cl", "tipo": "television_radio", "prioridad": 10, "feeds": ["https://www.biobiochile.cl/rss/rss.xml"], "sitemaps": ["https://www.biobiochile.cl/news-sitemap.xml"], "secciones": ["https://www.biobiochile.cl/"]},
    {"nombre": "Cooperativa", "dominio": "cooperativa.cl", "tipo": "television_radio", "prioridad": 9, "feeds": ["https://www.cooperativa.cl/noticias/site/tax/port/all/rss_2_0.xml"], "secciones": ["https://www.cooperativa.cl/noticias/"]},
    {"nombre": "ADN Radio", "dominio": "adnradio.cl", "tipo": "television_radio", "prioridad": 7, "feeds": ["https://www.adnradio.cl/rss/"], "secciones": ["https://www.adnradio.cl/"]},
    {"nombre": "Radio Pauta", "dominio": "pauta.cl", "tipo": "television_radio", "prioridad": 7, "feeds": ["https://www.pauta.cl/feed"], "secciones": ["https://www.pauta.cl/"]},
    {"nombre": "24 Horas", "dominio": "24horas.cl", "tipo": "television_radio", "prioridad": 8, "feeds": ["https://www.24horas.cl/rss"], "secciones": ["https://www.24horas.cl/"]},
    {"nombre": "T13", "dominio": "t13.cl", "tipo": "television_radio", "prioridad": 8, "feeds": ["https://www.t13.cl/rss"], "secciones": ["https://www.t13.cl/"]},
    {"nombre": "CHV Noticias", "dominio": "chvnoticias.cl", "tipo": "television_radio", "prioridad": 7, "feeds": ["https://www.chvnoticias.cl/feed/"], "secciones": ["https://www.chvnoticias.cl/"]},
    {"nombre": "Meganoticias", "dominio": "meganoticias.cl", "tipo": "television_radio", "prioridad": 8, "feeds": ["https://www.meganoticias.cl/rss/"], "secciones": ["https://www.meganoticias.cl/"]},
    {"nombre": "CNN Chile", "dominio": "cnnchile.com", "tipo": "television_radio", "prioridad": 8, "feeds": ["https://www.cnnchile.com/feed/"], "secciones": ["https://www.cnnchile.com/"]},
    {"nombre": "CIPER", "dominio": "ciperchile.cl", "tipo": "investigacion_digital", "prioridad": 8, "feeds": ["https://www.ciperchile.cl/feed/"], "secciones": ["https://www.ciperchile.cl/"]},
    {"nombre": "Ex-Ante", "dominio": "ex-ante.cl", "tipo": "investigacion_digital", "prioridad": 8, "feeds": ["https://www.ex-ante.cl/feed/"], "secciones": ["https://www.ex-ante.cl/"]},
    {"nombre": "Interferencia", "dominio": "interferencia.cl", "tipo": "investigacion_digital", "prioridad": 7, "feeds": ["https://interferencia.cl/rss.xml"], "secciones": ["https://interferencia.cl/"]},
    {"nombre": "El Desconcierto", "dominio": "eldesconcierto.cl", "tipo": "investigacion_digital", "prioridad": 6, "feeds": ["https://eldesconcierto.cl/feed"], "secciones": ["https://eldesconcierto.cl/"]},
    {"nombre": "El Dínamo", "dominio": "eldinamo.cl", "tipo": "investigacion_digital", "prioridad": 6, "feeds": ["https://www.eldinamo.cl/feed/"], "secciones": ["https://www.eldinamo.cl/"]},
    {"nombre": "Diario Constitucional", "dominio": "diarioconstitucional.cl", "tipo": "juridico", "prioridad": 8, "secciones": ["https://www.diarioconstitucional.cl/"]},
    {"nombre": "Estado Diario", "dominio": "estadodiario.com", "tipo": "juridico", "prioridad": 5, "secciones": ["https://estadodiario.com/"]},
    {"nombre": "Mundo Marítimo", "dominio": "mundomaritimo.cl", "tipo": "economico", "prioridad": 5, "secciones": ["https://www.mundomaritimo.cl/"]},
    {"nombre": "Reporte Minero", "dominio": "reporteminero.cl", "tipo": "sectorial", "prioridad": 6, "secciones": ["https://www.reporteminero.cl/"]},
    {"nombre": "Canal 9", "dominio": "canal9.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://www.canal9.cl/"]},
    {"nombre": "El América", "dominio": "elamerica.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://elamerica.cl/"]},
    {"nombre": "EnLaLinea.cl", "dominio": "enlalinea.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://www.enlalinea.cl/"]},
    {"nombre": "SoyChile", "dominio": "soychile.cl", "tipo": "regional", "prioridad": 6, "feeds": ["https://www.soychile.cl/rss.aspx"], "secciones": ["https://www.soychile.cl/"]},
    {"nombre": "Diario Concepción", "dominio": "diarioconcepcion.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://www.diarioconcepcion.cl/"]},
    {"nombre": "La Discusión", "dominio": "ladiscusion.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://www.ladiscusion.cl/"]},
    {"nombre": "Diario El Día", "dominio": "diarioeldia.cl", "tipo": "regional", "prioridad": 5, "secciones": ["https://www.diarioeldia.cl/"]},
    {"nombre": "El Pingüino", "dominio": "elpinguino.com", "tipo": "regional", "prioridad": 5, "secciones": ["https://elpinguino.com/"]},
    # Instituciones y servicios públicos
    {"nombre": "Unidad de Análisis Financiero", "dominio": "uaf.cl", "tipo": "institucional", "prioridad": 10, "oficial": True, "secciones": ["https://www.uaf.cl/es-cl/noticias"]},
    {"nombre": "Estrategia Antilavado", "dominio": "estrategiaantilavado.cl", "tipo": "institucional", "prioridad": 10, "oficial": True, "secciones": ["https://www.estrategiaantilavado.cl/es-cl/lista-noticia/"]},
    {"nombre": "Fiscalía de Chile", "dominio": "fiscaliadechile.cl", "tipo": "institucional", "prioridad": 9, "oficial": True, "secciones": ["https://www.fiscaliadechile.cl/actualidad/noticias"]},
    {"nombre": "Diario Oficial", "dominio": "diariooficial.interior.gob.cl", "tipo": "institucional", "prioridad": 8, "oficial": True, "secciones": ["https://www.diariooficial.interior.gob.cl/"]},
    {"nombre": "CMF", "dominio": "cmfchile.cl", "tipo": "institucional", "prioridad": 8, "oficial": True, "secciones": ["https://www.cmfchile.cl/portal/prensa/615/w3-channel.html"]},
    {"nombre": "Servicio de Impuestos Internos", "dominio": "sii.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.sii.cl/noticias/"]},
    {"nombre": "Poder Judicial", "dominio": "pjud.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.pjud.cl/prensa-y-comunicaciones/noticias-del-poder-judicial"]},
    {"nombre": "Contraloría", "dominio": "contraloria.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.contraloria.cl/web/cgr/noticias"]},
    {"nombre": "Cámara de Diputadas y Diputados", "dominio": "camara.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.camara.cl/prensa/noticias.aspx"]},
    {"nombre": "Senado", "dominio": "senado.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.senado.cl/comunicaciones/noticias"]},
    {"nombre": "Servicio Nacional de Aduanas", "dominio": "aduana.cl", "tipo": "institucional", "prioridad": 9, "oficial": True, "secciones": ["https://www.aduana.cl/noticias/aduana/2012-04-10/131546.html"]},
    {"nombre": "Tesorería General de la República", "dominio": "tgr.gob.cl", "tipo": "institucional", "prioridad": 8, "oficial": True, "secciones": ["https://www.tgr.gob.cl/noticias/"]},
    {"nombre": "Superintendencia de Pensiones", "dominio": "spensiones.cl", "tipo": "institucional", "prioridad": 8, "oficial": True, "secciones": ["https://www.spensiones.cl/portal/institucional/594/w3-propertyvalue-5936.html"]},
    {"nombre": "Superintendencia de Casinos de Juego", "dominio": "scj.gob.cl", "tipo": "institucional", "prioridad": 9, "oficial": True, "secciones": ["https://www.scj.gob.cl/noticias_scj/", "https://www.scj.gob.cl/noticias/"]},
    {"nombre": "Consejo de Defensa del Estado", "dominio": "cde.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.cde.cl/prensa/"]},
    {"nombre": "Banco Central de Chile", "dominio": "bcentral.cl", "tipo": "institucional", "prioridad": 6, "oficial": True, "secciones": ["https://www.bcentral.cl/web/banco-central/noticias-y-publicaciones"]},
    {"nombre": "Ministerio de Hacienda", "dominio": "hacienda.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.hacienda.cl/noticias-y-eventos/noticias"]},
    {"nombre": "Policía de Investigaciones", "dominio": "pdichile.cl", "tipo": "institucional", "prioridad": 7, "oficial": True, "secciones": ["https://www.pdichile.cl/centro-de-prensa"]},
    {"nombre": "Carabineros de Chile", "dominio": "carabineros.cl", "tipo": "institucional", "prioridad": 6, "oficial": True, "secciones": ["https://www.carabineros.cl/secciones/noticias/"]},
    {"nombre": "ANFACH", "dominio": "anfach.cl", "tipo": "gremial", "prioridad": 6, "secciones": ["https://www.anfach.cl/gremio/"]},
]


def cargar_fuentes() -> list[dict[str, Any]]:
    fuentes = copy.deepcopy(FUENTES_PREDETERMINADAS)
    if FUENTES_ARCHIVO.exists():
        try:
            extra = json.loads(FUENTES_ARCHIVO.read_text(encoding="utf-8"))
            if isinstance(extra, dict):
                extra = extra.get("fuentes", [])
            por_dominio = {f["dominio"]: f for f in fuentes}
            for f in extra:
                if not isinstance(f, dict) or not f.get("dominio"):
                    continue
                d = normaliza_dominio(f["dominio"])
                mezcla = dict(por_dominio.get(d, {}))
                mezcla.update(f)
                mezcla["dominio"] = d
                por_dominio[d] = mezcla
            fuentes = list(por_dominio.values())
        except Exception as exc:
            print(f"! fuentes_uaf.json inválido: {exc}", file=sys.stderr)
    for f in fuentes:
        f["dominio"] = normaliza_dominio(f["dominio"])
        f.setdefault("nombre", f["dominio"])
        f.setdefault("tipo", "otro")
        f.setdefault("prioridad", 5)
        f.setdefault("oficial", f["tipo"] == "institucional")
        f.setdefault("feeds", [])
        f.setdefault("sitemaps", [])
        f.setdefault("secciones", [f"https://{f['dominio']}/"])
    return sorted(fuentes, key=lambda x: (-int(x.get("prioridad", 0)), x["dominio"]))


FUENTES = cargar_fuentes()
FUENTE_POR_DOMINIO = {f["dominio"]: f for f in FUENTES}
DOMINIOS_CHILENOS = set(FUENTE_POR_DOMINIO)
DOMINIOS_INSTITUCIONALES = {f["dominio"] for f in FUENTES if f.get("oficial")}
DOMINIOS_MINIMOS = tuple(sorted({
    "df.cl", "latercera.com", "emol.com", "elmercurio.com", "elmostrador.cl",
    "biobiochile.cl", "cooperativa.cl", "adnradio.cl", "pauta.cl", "24horas.cl",
    "t13.cl", "chvnoticias.cl", "meganoticias.cl", "cnnchile.com", "interferencia.cl",
    "ciperchile.cl", "ex-ante.cl", "eldesconcierto.cl", "eldinamo.cl",
    "fiscaliadechile.cl", "diariooficial.interior.gob.cl", "cmfchile.cl", "sii.cl",
    "pjud.cl", "contraloria.cl", "camara.cl", "soychile.cl", "aduana.cl",
    "tgr.gob.cl", "spensiones.cl", "scj.gob.cl", "estrategiaantilavado.cl",
}))

DOMINIOS_VETADOS = {
    "news.google.com", "google.com", "www.google.com", "bing.com", "www.bing.com",
    "youtube.com", "facebook.com", "x.com", "twitter.com", "instagram.com",
    "tiktok.com", "linkedin.com", "msn.com", "yahoo.com", "flipboard.com",
}

RUTAS_FEED = [
    "/feed", "/feed/", "/rss", "/rss/", "/rss.xml", "/feed.xml", "/index.xml",
    "/atom.xml", "/?feed=rss2", "/arc/outboundfeeds/rss/?outputType=xml",
]
RUTAS_SITEMAP = [
    "/news-sitemap.xml", "/sitemap-news.xml", "/sitemap_news.xml", "/news.xml",
    "/sitemap-noticias.xml", "/sitemap.xml", "/sitemap_index.xml",
]

# ---------------------------------------------------------------------------
# Consultas y taxonomías
# ---------------------------------------------------------------------------

CONSULTAS_UAF = [
    '"Unidad de Análisis Financiero" Chile',
    '"Unidad de Analisis Financiero" Chile',
    '"UAF Chile"',
    '"la UAF" "lavado de activos" Chile',
    '"director de la UAF" Chile',
    '"director subrogante de la UAF" Chile',
    '"Ley 19.913" UAF',
    '"reportado a la UAF" Chile',
    '"informó a la UAF" Chile',
    '"informo a la UAF" Chile',
    '"antecedentes a la UAF" Chile',
    '"alertas de la UAF" Chile',
    '"remitió antecedentes a la UAF" Chile',
    '"remitio antecedentes a la UAF" Chile',
    '"solicitó a la UAF" Chile',
    '"reportes a la UAF" Chile',
    '"facultades de la UAF" Chile',
    '"experiencia en la UAF" Chile',
    '"reportes de operaciones sospechosas" UAF Chile',
]

CONSULTAS_CONTEXTO = [
    '"lavado de activos" Chile',
    '"lavado de dinero" Chile',
    '"financiamiento del terrorismo" Chile',
    '"operaciones sospechosas" Chile',
    '"cuentas puente" Chile',
    'testaferros "lavado de activos" Chile',
    '"beneficiario final" Chile lavado',
    'contrabando "lavado de activos" Chile',
    'corrupción "lavado de activos" Chile',
    'narcotráfico "lavado de activos" Chile',
    'apuestas online lavado Chile',
]

MENCION_UAF_RE = re.compile(r"\b(?:u\.?a\.?f\.?|unidad\s+de\s+an[aá]lisis\s+financiero)\b", re.I)
SENALES_LAFT = [
    "lavado de activos", "lavado de dinero", "blanqueo de capitales",
    "financiamiento del terrorismo", "operaciones sospechosas", "reporte de operaciones",
    "ros", "beneficiario final", "debida diligencia", "testaferro", "cuenta puente",
    "ruta del dinero", "economias ilicitas", "economía ilícita", "comiso",
]
SENALES_CHILE = [
    "chile", "chileno", "chilena", "ley 19.913", "ley n 19.913", "uaf.cl",
    "fiscalia de chile", "ministerio publico", "pdi", "carabineros", "aduanas",
    "cmf", "servicio de impuestos internos", "sii", "contraloria", "senado",
    "camara de diputadas", "tesoreria general", "superintendencia de casinos",
    "superintendencia de pensiones", "gafilat", "milaft", "santiago",
]
SENALES_EXTRANJERAS = [
    "uaf panama", "uaf panamá", "uaf guatemala", "uaf bolivia", "uaf paraguay",
    "uafe ecuador", "uif peru", "uif perú", "uif argentina", "uif colombia", "uif mexico",
    "unidad de analisis financiero y economico", "unidad de informacion financiera",
    "unidad de analisis financiero de panama", "unidad de analisis financiero del peru",
    "superintendencia de bancos de panama", "fiscalia de panama", "fiscalía de panamá",
]
SENALES_TEMATICAS = SENALES_LAFT + [
    "crimen organizado", "narcotrafico", "narcotráfico", "corrupcion", "corrupción",
    "fraude", "estafa", "contrabando", "trata de personas", "delitos economicos",
    "delitos económicos", "secreto bancario", "sujeto obligado", "casinos de juego",
]

FENOMENOS = {
    "contrabando": ["contrabando", "aduanas", "mercancia ilicita", "monedas de 10"],
    "crimen_organizado": ["crimen organizado", "tren de aragua", "banda criminal"],
    "corrupcion": ["corrupcion", "cohecho", "malversacion", "soborno"],
    "narcotrafico": ["narcotrafico", "trafico de drogas", "droga incautada"],
    "fraude": ["fraude", "estafa", "defraudacion"],
    "apuestas": ["apuestas online", "apuestas en linea", "juego ilegal", "casino"],
    "cibercrimen": ["cibercrimen", "fraude informatico", "criptomoneda", "criptoactivo"],
    "sartor": ["sartor"],
    "tren_de_aragua": ["tren de aragua"],
    "trata": ["trata de personas", "explotacion sexual"],
}

NATURALEZAS = {
    "institucional": ["cuenta publica", "participacion de la uaf", "jornada", "seminario", "simposio"],
    "legislativo": ["proyecto de ley", "senador", "diputado", "comision de", "boletin"],
    "regulatorio": ["circular", "normativa", "regulacion", "sancion", "fiscalizacion"],
    "judicial": ["formalizacion", "imputado", "querella", "condena", "tribunal", "fiscalia"],
    "policial": ["detenido", "allanamiento", "incautacion", "operativo", "pdi"],
    "opinion": ["/opinion/", "/columnista", "/editorial/", "columna", "carta al director"],
    "analisis": ["analisis", "estudio", "informe", "radiografia", "perfil"],
}

PRECEDENTES = {
    "corrupcion": ["corrupcion", "cohecho", "malversacion", "soborno"],
    "narcotrafico": ["narcotrafico", "trafico de drogas"],
    "contrabando": ["contrabando"],
    "fraude": ["fraude", "estafa", "defraudacion"],
    "delitos_economicos": ["delitos economicos", "ley 21.595", "administracion desleal"],
    "trata": ["trata de personas", "explotacion sexual"],
    "tributarios": ["delito tributario", "evasión", "evasion", "facturas falsas"],
}

TOPICOS = {
    "prevencion": ["prevencion", "lavado de activos", "debida diligencia", "cumplimiento"],
    "investigacion_penal": ["fiscalia", "investigacion", "formalizacion", "imputado"],
    "regulacion": ["proyecto de ley", "circular", "normativa", "regulacion"],
    "inteligencia_financiera": ["inteligencia financiera", "ruta del dinero", "uaf"],
    "crimen_organizado": ["crimen organizado", "tren de aragua", "banda criminal"],
    "fiscalizacion": ["fiscalizacion", "sancion", "multa"],
    "cooperacion": ["gafilat", "gafi", "cooperacion internacional", "milaft"],
    "tecnologia": ["transformacion digital", "tecnologia", "cibercrimen", "criptoactivo"],
    "sujetos_obligados": ["sujeto obligado", "entidad reportante", "reporte de operaciones"],
}

SUJETOS = {
    "bancos": ["banco", "banca", "entidad bancaria"],
    "fintech": ["fintech", "mercado pago", "billetera digital"],
    "casinos": ["casino de juego", "casinos de juego"],
    "notarios": ["notario", "notaria", "conservador"],
    "inmobiliarias": ["inmobiliaria", "corredor de propiedades", "bienes raices"],
    "automotoras": ["automotora", "compraventa de vehiculos", "vehiculo de lujo"],
    "valores": ["corredora de bolsa", "administradora general de fondos", "agf", "mercado de valores"],
    "remesadoras": ["remesadora", "casa de cambio", "transferencia de dinero"],
    "contadores": ["contador", "auditor externo"],
    "abogados": ["abogado", "estudio juridico"],
    "sector_publico": ["servicio publico", "municipalidad", "empresa publica"],
}

LABELS = {
    "fenomeno": {
        "contrabando": "Contrabando y comercio ilícito", "crimen_organizado": "Crimen organizado",
        "corrupcion": "Corrupción", "narcotrafico": "Narcotráfico", "fraude": "Fraude y estafas",
        "apuestas": "Apuestas y juego ilegal", "cibercrimen": "Cibercrimen y criptoactivos",
        "sartor": "Caso Sartor", "tren_de_aragua": "Tren de Aragua", "trata": "Trata de personas",
        "otro": "Otros focos",
    },
    "naturaleza": {
        "institucional": "Institucional", "legislativo": "Legislativo", "regulatorio": "Regulatorio",
        "judicial": "Judicial", "policial": "Policial", "opinion": "Opinión / editorial",
        "analisis": "Análisis / reportaje",
    },
    "precedentes": {
        "corrupcion": "Corrupción", "narcotrafico": "Narcotráfico", "contrabando": "Contrabando",
        "fraude": "Fraude y estafa", "delitos_economicos": "Delitos económicos", "trata": "Trata de personas",
        "tributarios": "Delitos tributarios", "indeterminado": "No determinado",
    },
    "topicos": {
        "prevencion": "Prevención de LA/FT", "investigacion_penal": "Investigación y persecución penal",
        "regulacion": "Regulación y legislación", "inteligencia_financiera": "Inteligencia financiera",
        "crimen_organizado": "Crimen organizado", "fiscalizacion": "Fiscalización y sanciones",
        "cooperacion": "Cooperación nacional e internacional", "tecnologia": "Tecnología y activos virtuales",
        "sujetos_obligados": "Sujetos obligados y cumplimiento", "otros": "Otros temas",
    },
    "sujetos": {
        "bancos": "Bancos", "fintech": "Fintech y medios de pago", "casinos": "Casinos de juego",
        "notarios": "Notarios y conservadores", "inmobiliarias": "Sector inmobiliario",
        "automotoras": "Automotoras", "valores": "Mercado de valores y fondos",
        "remesadoras": "Casas de cambio y remesas", "contadores": "Contadores y auditores",
        "abogados": "Abogados", "sector_publico": "Sector público",
    },
}

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------


def log(mensaje: str) -> None:
    marca = datetime.now(TZ_CL).strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{marca}] {mensaje}"
    print(linea, flush=True)
    try:
        with BITACORA.open("a", encoding="utf-8") as fh:
            fh.write(linea + "\n")
    except OSError:
        pass


def normaliza(texto: Any) -> str:
    texto = html_mod.unescape(str(texto or ""))
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto = texto.lower().replace("\u00a0", " ")
    return re.sub(r"\s+", " ", texto).strip()


def limpia_texto(texto: Any) -> str:
    texto = html_mod.unescape(str(texto or ""))
    texto = re.sub(r"<[^>]+>", " ", texto)
    texto = re.sub(r"\s+", " ", texto).strip()
    return texto


def dominio_url(url: str) -> str:
    try:
        return normaliza_dominio(urllib.parse.urlsplit(url).hostname or "")
    except Exception:
        return ""


def fuente_para_host(host: str) -> dict[str, Any] | None:
    host = normaliza_dominio(host)
    if host in FUENTE_POR_DOMINIO:
        return FUENTE_POR_DOMINIO[host]
    candidatos = [f for d, f in FUENTE_POR_DOMINIO.items() if host.endswith("." + d)]
    return max(candidatos, key=lambda f: len(f["dominio"]), default=None)


def url_canonica(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url.strip())
        if p.scheme not in {"http", "https"}:
            return ""
        host = normaliza_dominio(p.hostname or "")
        if not host:
            return ""
        puerto = f":{p.port}" if p.port and p.port not in {80, 443} else ""
        ruta = re.sub(r"/{2,}", "/", p.path or "/")
        if ruta != "/":
            ruta = ruta.rstrip("/")
        params = urllib.parse.parse_qsl(p.query, keep_blank_values=False)
        params = [(k, v) for k, v in params if not k.lower().startswith(("utm_", "fbclid", "gclid", "output"))]
        consulta = urllib.parse.urlencode(sorted(params))
        return urllib.parse.urlunsplit((p.scheme.lower(), host + puerto, ruta, consulta, ""))
    except Exception:
        return ""


def id_registro(url: str, titulo: str = "") -> str:
    base = url_canonica(url) or normaliza(titulo)
    return hashlib.sha256(base.encode("utf-8", "ignore")).hexdigest()[:24]


def contiene(texto: str, agujas: Iterable[str]) -> bool:
    t = normaliza(texto)
    return any(normaliza(a) in t for a in agujas)


def ahora_cl() -> datetime:
    return datetime.now(TZ_CL)


def parsea_fecha(valor: Any, url: str = "") -> datetime | None:
    if isinstance(valor, datetime):
        return valor.astimezone(TZ_CL) if valor.tzinfo else valor.replace(tzinfo=TZ_CL)
    s = limpia_texto(valor)
    if s:
        try:
            d = email.utils.parsedate_to_datetime(s)
            if d:
                return d.astimezone(TZ_CL) if d.tzinfo else d.replace(tzinfo=TZ_CL)
        except Exception:
            pass
        s2 = s.replace("Z", "+00:00")
        try:
            d = datetime.fromisoformat(s2)
            return d.astimezone(TZ_CL) if d.tzinfo else d.replace(tzinfo=TZ_CL)
        except Exception:
            pass
        for formato in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                return datetime.strptime(s[:10], formato).replace(tzinfo=TZ_CL)
            except ValueError:
                continue
    patrones = [
        r"/(20\d{2})/(0?[1-9]|1[0-2])/(0?[1-9]|[12]\d|3[01])(?:/|$)",
        r"[-_/](20\d{2})[-_/](0?[1-9]|1[0-2])[-_/](0?[1-9]|[12]\d|3[01])(?:[-_/]|$)",
    ]
    for patron in patrones:
        m = re.search(patron, url)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=TZ_CL)
            except ValueError:
                pass
    return None


def dentro_ventana(fecha_dt: datetime | None, dias: int = VENTANA_DIAS, margen: int = 2) -> bool:
    if not fecha_dt:
        return True
    ahora = ahora_cl()
    return ahora - timedelta(days=dias + margen) <= fecha_dt <= ahora + timedelta(days=1)


# ---------------------------------------------------------------------------
# Red segura y control por dominio
# ---------------------------------------------------------------------------

_HOST_LOCKS: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
_ULTIMO_HOST: dict[str, float] = {}
_ROBOTS_CACHE: dict[str, tuple[float, urllib.robotparser.RobotFileParser]] = {}


def ip_publica(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast)
    except ValueError:
        return False


@lru_cache(maxsize=1024)
def host_publico(host: str) -> bool:
    host = normaliza_dominio(host)
    if not host or host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    ips = {info[4][0] for info in infos}
    return bool(ips) and all(ip_publica(ip) for ip in ips)


def url_publica(url: str) -> bool:
    try:
        p = urllib.parse.urlsplit(url)
        return p.scheme in {"http", "https"} and bool(p.hostname) and host_publico(p.hostname)
    except Exception:
        return False


def robots_permite(url: str) -> bool:
    if not RESPETA_ROBOTS:
        return True
    p = urllib.parse.urlsplit(url)
    raiz = f"{p.scheme}://{p.netloc}"
    ahora = time.time()
    cached = _ROBOTS_CACHE.get(raiz)
    if cached and ahora - cached[0] < 12 * 3600:
        return cached[1].can_fetch(UA_ROBOTS, url)
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(raiz + "/robots.txt")
    try:
        req = urllib.request.Request(rp.url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=min(10, TIMEOUT)) as resp:
            texto = resp.read(300_000).decode("utf-8", "ignore")
        rp.parse(texto.splitlines())
    except Exception:
        rp.parse([])  # ante fallo, no bloquea todo el dominio
    _ROBOTS_CACHE[raiz] = (ahora, rp)
    return rp.can_fetch(UA_ROBOTS, url)


def descomprime(datos: bytes, encoding: str) -> bytes:
    e = (encoding or "").lower()
    if "gzip" in e:
        return gzip.decompress(datos)
    if "deflate" in e:
        try:
            return zlib.decompress(datos)
        except zlib.error:
            return zlib.decompress(datos, -zlib.MAX_WBITS)
    return datos


def descarga(url: str, *, permite_robots: bool = True, max_bytes: int = MAX_BYTES) -> tuple[bytes, str, dict[str, str]]:
    if not url_publica(url):
        raise ValueError("URL no pública o no resoluble")
    if permite_robots and not robots_permite(url):
        raise PermissionError("bloqueado por robots.txt")
    host = dominio_url(url)
    lock = _HOST_LOCKS[host]
    with lock:
        espera = INTERVALO_HOST - (time.monotonic() - _ULTIMO_HOST.get(host, 0.0))
        if espera > 0:
            time.sleep(espera)
        _ULTIMO_HOST[host] = time.monotonic()
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "es-CL,es;q=0.9",
        "Connection": "close",
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        final = resp.geturl()
        if not url_publica(final):
            raise ValueError("redirección no pública")
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("respuesta excede límite")
        raw = descomprime(raw, resp.headers.get("Content-Encoding", ""))
        return raw, final, {k.lower(): v for k, v in resp.headers.items()}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class DocumentoHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titulo: list[str] = []
        self.en_title = False
        self.meta: dict[str, str] = {}
        self.links: list[tuple[str, str, str]] = []
        self._a_href = ""
        self._a_rel = ""
        self._a_text: list[str] = []
        self._en_a = False
        self._en_p = False
        self._p_text: list[str] = []
        self._prof_article = 0
        self._prof_main = 0
        self.parrafos_article: list[str] = []
        self.parrafos_main: list[str] = []
        self.parrafos: list[str] = []
        self._script_tipo = ""
        self._script_text: list[str] = []
        self.json_ld: list[str] = []
        self.time_values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self.en_title = True
        elif tag == "meta":
            clave = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            contenido = a.get("content", "")
            if clave and contenido:
                self.meta[clave] = contenido
        elif tag == "link":
            href = a.get("href", "")
            rel = a.get("rel", "").lower()
            if href:
                self.links.append((href, rel, ""))
        elif tag == "a":
            self._en_a = True
            self._a_href = a.get("href", "")
            self._a_rel = a.get("rel", "")
            self._a_text = []
        elif tag == "article":
            self._prof_article += 1
        elif tag == "main":
            self._prof_main += 1
        elif tag == "p":
            self._en_p = True
            self._p_text = []
        elif tag == "script":
            self._script_tipo = a.get("type", "").lower()
            self._script_text = []
        elif tag == "time" and a.get("datetime"):
            self.time_values.append(a["datetime"])

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.en_title = False
        elif tag == "a" and self._en_a:
            texto = limpia_texto(" ".join(self._a_text))
            self.links.append((self._a_href, self._a_rel, texto))
            self._en_a = False
        elif tag == "p" and self._en_p:
            texto = limpia_texto(" ".join(self._p_text))
            if len(texto) >= 35:
                self.parrafos.append(texto)
                if self._prof_article:
                    self.parrafos_article.append(texto)
                if self._prof_main:
                    self.parrafos_main.append(texto)
            self._en_p = False
        elif tag == "article" and self._prof_article:
            self._prof_article -= 1
        elif tag == "main" and self._prof_main:
            self._prof_main -= 1
        elif tag == "script":
            if "ld+json" in self._script_tipo:
                texto = "".join(self._script_text).strip()
                if texto:
                    self.json_ld.append(texto)
            self._script_tipo = ""
            self._script_text = []

    def handle_data(self, data: str) -> None:
        if self.en_title:
            self.titulo.append(data)
        if self._en_a:
            self._a_text.append(data)
        if self._en_p:
            self._p_text.append(data)
        if self._script_tipo:
            self._script_text.append(data)


def decode_html(raw: bytes, headers: dict[str, str] | None = None) -> str:
    content_type = (headers or {}).get("content-type", "")
    m = re.search(r"charset=([\w-]+)", content_type, re.I)
    candidatos = [m.group(1)] if m else []
    candidatos += ["utf-8", "latin-1"]
    for enc in candidatos:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "ignore")


def recorre_json(obj: Any) -> Iterable[dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from recorre_json(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from recorre_json(v)


def extrae_articulo_html(raw: bytes, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    texto_html = decode_html(raw, headers)
    parser = DocumentoHTML()
    try:
        parser.feed(texto_html)
    except Exception:
        pass

    titulo = parser.meta.get("og:title") or parser.meta.get("twitter:title") or limpia_texto(" ".join(parser.titulo))
    descripcion = parser.meta.get("og:description") or parser.meta.get("description") or parser.meta.get("twitter:description") or ""
    fecha_valor = (parser.meta.get("article:published_time") or parser.meta.get("datepublished") or
                   parser.meta.get("date") or parser.meta.get("dc.date") or parser.meta.get("dcterms.date"))
    cuerpo_json = ""
    canonical = ""
    amp = ""
    for href, rel, _ in parser.links:
        abs_url = urllib.parse.urljoin(url, href)
        if "canonical" in rel.lower() and not canonical:
            canonical = abs_url
        if "amphtml" in rel.lower() and not amp:
            amp = abs_url

    for bloque in parser.json_ld:
        bloque = bloque.strip().rstrip(";")
        try:
            obj = json.loads(bloque)
        except json.JSONDecodeError:
            continue
        for nodo in recorre_json(obj):
            tipo = nodo.get("@type")
            tipos = {normaliza(x) for x in tipo} if isinstance(tipo, list) else {normaliza(tipo)}
            if tipos & {"newsarticle", "article", "reportagearticle", "blogposting"} or "articlebody" in {normaliza(k) for k in nodo}:
                titulo = nodo.get("headline") or nodo.get("name") or titulo
                descripcion = nodo.get("description") or descripcion
                cuerpo_json = nodo.get("articleBody") or cuerpo_json
                fecha_valor = nodo.get("datePublished") or nodo.get("dateCreated") or fecha_valor
                canonical = nodo.get("url") or nodo.get("mainEntityOfPage") or canonical
                if isinstance(canonical, dict):
                    canonical = canonical.get("@id", "")

    parrafos = parser.parrafos_article or parser.parrafos_main or parser.parrafos
    # Quita frases de navegación y publicidad reiteradas.
    limpios: list[str] = []
    vistos: set[str] = set()
    for p in parrafos:
        n = normaliza(p)
        if len(n) < 35 or n in vistos:
            continue
        if contiene(n, ["suscribete", "inicia sesion", "todos los derechos reservados", "compartir en facebook", "publicidad"]):
            continue
        vistos.add(n)
        limpios.append(p)
    cuerpo = limpia_texto(cuerpo_json) or "\n".join(limpios)
    if len(cuerpo) > MAX_TEXTO_ANALISIS:
        cuerpo = cuerpo[:MAX_TEXTO_ANALISIS]
    fecha_dt = parsea_fecha(fecha_valor, canonical or url)
    if not fecha_dt:
        for t in parser.time_values:
            fecha_dt = parsea_fecha(t, canonical or url)
            if fecha_dt:
                break
    return {
        "titulo": limpia_texto(titulo)[:500],
        "resumen": limpia_texto(descripcion)[:1200],
        "texto_enriquecido": cuerpo,
        "fecha_dt": fecha_dt,
        "url_final": url_canonica(canonical or url),
        "amp_url": url_canonica(amp),
        "links": parser.links,
    }


def parsea_feed(raw: bytes, base_url: str, origen: str) -> list[dict[str, Any]]:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("XML con DTD/entidades rechazado")
    raiz = ET.fromstring(raw)
    resultados: list[dict[str, Any]] = []
    items = list(raiz.findall(".//item"))
    if items:
        for item in items:
            def txt(etiqueta: str) -> str:
                nodo = item.find(etiqueta)
                return limpia_texto("".join(nodo.itertext())) if nodo is not None else ""
            link = txt("link") or txt("guid")
            if not link:
                continue
            resultados.append({
                "titulo": txt("title"), "resumen": txt("description"), "link": urllib.parse.urljoin(base_url, link),
                "fecha_dt": parsea_fecha(txt("pubDate") or txt("date"), link), "origen_busqueda": origen,
            })
        return resultados
    ns = {"a": "http://www.w3.org/2005/Atom"}

    def primer_nodo(entry: ET.Element, rutas: Iterable[str]) -> ET.Element | None:
        for ruta in rutas:
            nodo = entry.find(ruta, ns) if ruta.startswith("a:") else entry.find(ruta)
            if nodo is not None:
                return nodo
        return None

    entradas = raiz.findall(".//a:entry", ns)
    if not entradas:
        entradas = raiz.findall(".//entry")
    for entry in entradas:
        titulo_nodo = primer_nodo(entry, ("a:title", "title"))
        titulo = limpia_texto("".join(titulo_nodo.itertext())) if titulo_nodo is not None else ""
        resumen_nodo = primer_nodo(entry, ("a:summary", "a:content", "summary", "content"))
        resumen = limpia_texto("".join(resumen_nodo.itertext())) if resumen_nodo is not None else ""
        link = ""
        for ln in entry.findall("a:link", ns) + entry.findall("link"):
            href = ln.attrib.get("href", "")
            if href and ln.attrib.get("rel", "alternate") in {"alternate", ""}:
                link = href
                break
        fecha = primer_nodo(entry, ("a:published", "a:updated", "published", "updated"))
        if link:
            resultados.append({"titulo": titulo, "resumen": resumen, "link": urllib.parse.urljoin(base_url, link),
                               "fecha_dt": parsea_fecha(fecha.text if fecha is not None else "", link), "origen_busqueda": origen})
    return resultados


def parsea_sitemap(raw: bytes, base_url: str) -> tuple[list[dict[str, Any]], list[str]]:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("XML con DTD/entidades rechazado")
    raiz = ET.fromstring(raw)
    tag = raiz.tag.lower()
    urls: list[dict[str, Any]] = []
    indices: list[str] = []
    if tag.endswith("sitemapindex"):
        for sm in list(raiz):
            loc = next((limpia_texto(n.text) for n in list(sm) if n.tag.lower().endswith("loc")), "")
            if loc:
                indices.append(urllib.parse.urljoin(base_url, loc))
        return urls, indices
    for nodo in list(raiz):
        loc = ""
        lastmod = ""
        titulo = ""
        for n in nodo.iter():
            low = n.tag.lower()
            if low.endswith("loc") and not loc:
                loc = limpia_texto(n.text)
            elif low.endswith("lastmod") and not lastmod:
                lastmod = limpia_texto(n.text)
            elif low.endswith("title") and not titulo:
                titulo = limpia_texto(n.text)
        if loc:
            urls.append({"titulo": titulo, "resumen": "", "link": urllib.parse.urljoin(base_url, loc),
                         "fecha_dt": parsea_fecha(lastmod, loc), "origen_busqueda": "sitemap"})
    return urls, indices


def extrae_enlaces_pagina(raw: bytes, base_url: str, host_objetivo: str, nombre: str) -> list[dict[str, Any]]:
    parser = DocumentoHTML()
    try:
        parser.feed(decode_html(raw))
    except Exception:
        return []
    salida: list[dict[str, Any]] = []
    vistos: set[str] = set()
    for href, rel, texto in parser.links:
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        url = url_canonica(urllib.parse.urljoin(base_url, href))
        if not url or dominio_url(url) != normaliza_dominio(host_objetivo) or url in vistos:
            continue
        ruta = urllib.parse.urlsplit(url).path.lower()
        if any(x in ruta for x in ("/tag/", "/categoria/", "/autor/", "/contact", "/login", "/suscripcion")):
            continue
        if len(texto) < 18 and not re.search(r"/20\d{2}/", ruta):
            continue
        vistos.add(url)
        salida.append({"titulo": texto[:500], "resumen": "", "link": url,
                       "fecha_dt": parsea_fecha("", url), "medio": nombre,
                       "origen_busqueda": "seccion_directa"})
    return salida


# ---------------------------------------------------------------------------
# Descubrimiento
# ---------------------------------------------------------------------------

_COBERTURA: dict[str, dict[str, Any]] = {}


def cobertura(host: str, canal: str, resultados: int = 0, error: str = "") -> None:
    f = fuente_para_host(host) or {"nombre": host, "dominio": host}
    reg = _COBERTURA.setdefault(f["dominio"], {
        "fuente": f["nombre"], "dominio": f["dominio"], "canales": {}, "resultados": 0,
        "errores": [], "consultada": True,
    })
    reg["canales"][canal] = reg["canales"].get(canal, 0) + max(0, resultados)
    reg["resultados"] += max(0, resultados)
    if error and error not in reg["errores"]:
        reg["errores"].append(error[:200])


def consulta_google_news(query: str) -> list[dict[str, Any]]:
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({
        "q": query, "hl": "es-419", "gl": "CL", "ceid": "CL:es-419"
    })
    raw, final, _ = descarga(url, permite_robots=False)
    regs = parsea_feed(raw, final, "google_news")
    for r in regs:
        r["consulta"] = query
    return regs


def consulta_bing(query: str) -> list[dict[str, Any]]:
    url = "https://www.bing.com/news/search?" + urllib.parse.urlencode({"q": query, "format": "rss", "setlang": "es", "cc": "cl"})
    raw, final, _ = descarga(url, permite_robots=False)
    regs = parsea_feed(raw, final, "bing_news")
    for r in regs:
        r["consulta"] = query
    return regs


def parsea_resultados_duckduckgo(raw: bytes, query: str) -> list[dict[str, Any]]:
    texto = decode_html(raw)
    patron = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
    salida = []
    for href, titulo_html in patron.findall(texto):
        href = html_mod.unescape(href)
        p = urllib.parse.urlsplit(urllib.parse.urljoin("https://duckduckgo.com", href))
        qs = urllib.parse.parse_qs(p.query)
        url = qs.get("uddg", [href])[0]
        url = url_canonica(urllib.parse.unquote(url))
        if url:
            salida.append({"titulo": limpia_texto(titulo_html), "resumen": "", "link": url,
                           "fecha_dt": parsea_fecha("", url), "origen_busqueda": "duckduckgo", "consulta": query})
    return salida


def consulta_duckduckgo(query: str) -> list[dict[str, Any]]:
    url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
    raw, _, _ = descarga(url, permite_robots=False)
    return parsea_resultados_duckduckgo(raw, query)


def consultas_segmentadas(ahora: datetime) -> list[str]:
    consultas: list[str] = []
    inicio = (ahora - timedelta(days=VENTANA_DIAS)).date()
    cursor = inicio
    while cursor <= ahora.date():
        fin = min(cursor + timedelta(days=5), ahora.date() + timedelta(days=1))
        consultas.append(f'"Unidad de Análisis Financiero" after:{cursor.isoformat()} before:{fin.isoformat()}')
        consultas.append(f'"UAF" "lavado de activos" after:{cursor.isoformat()} before:{fin.isoformat()}')
        cursor = fin
    return consultas


def consultas_site(modo: str) -> list[tuple[str, str]]:
    fuentes = FUENTES if modo == "conciliacion" else [f for f in FUENTES if int(f.get("prioridad", 0)) >= 8]
    pares: list[tuple[str, str]] = []
    for f in fuentes:
        d = f["dominio"]
        pares.append((d, f'site:{d} "Unidad de Análisis Financiero"'))
        if modo == "conciliacion" or int(f.get("prioridad", 0)) >= 9:
            pares.append((d, f'site:{d} UAF ("lavado de activos" OR "operaciones sospechosas" OR "antecedentes a la UAF")'))
    return pares[:MAX_SITE_QUERIES]


def descubre_agregadores(modo: str) -> list[dict[str, Any]]:
    consultas = list(CONSULTAS_UAF)
    if modo == "conciliacion":
        consultas += consultas_segmentadas(ahora_cl()) + CONSULTAS_CONTEXTO
    else:
        consultas += CONSULTAS_CONTEXTO[:5]
    resultados: list[dict[str, Any]] = []
    for i, q in enumerate(consultas):
        if tiempo_agotado(180):
            break
        for nombre, fn in (("google_news", consulta_google_news), ("bing_news", consulta_bing)):
            try:
                regs = fn(q)
                resultados.extend(regs)
                log(f"{nombre}: {len(regs):3d} · {q[:74]}")
            except Exception as exc:
                log(f"! {nombre}: {type(exc).__name__}: {exc}")
        if i < (8 if modo == "conciliacion" else 3):
            try:
                resultados.extend(consulta_duckduckgo(q))
            except Exception as exc:
                log(f"! duckduckgo: {type(exc).__name__}: {exc}")
    for host, q in consultas_site(modo):
        if tiempo_agotado(180):
            break
        try:
            regs = consulta_google_news(q)
            for r in regs:
                r["origen_busqueda"] = "site_google_news"
            resultados.extend(regs)
            cobertura(host, "site_google_news", len(regs))
            if modo == "conciliacion" and len(regs) < 3 and not tiempo_agotado(170):
                try:
                    alternos = consulta_duckduckgo(q)
                    for r in alternos:
                        r["origen_busqueda"] = "site_duckduckgo"
                    resultados.extend(alternos)
                    cobertura(host, "site_duckduckgo", len(alternos))
                except Exception as exc_ddg:
                    cobertura(host, "site_duckduckgo", 0, f"{type(exc_ddg).__name__}: {exc_ddg}")
        except Exception as exc:
            cobertura(host, "site_google_news", 0, f"{type(exc).__name__}: {exc}")
    return resultados


def descubre_endpoints(fuente: dict[str, Any], modo: str) -> tuple[list[str], list[str]]:
    feeds = list(dict.fromkeys(fuente.get("feeds", [])))
    sitemaps = list(dict.fromkeys(fuente.get("sitemaps", [])))
    if modo != "conciliacion" and (feeds or sitemaps):
        return feeds, sitemaps
    host = fuente["dominio"]
    base = f"https://{host}"
    candidatos_feed = feeds + [base + ruta for ruta in RUTAS_FEED]
    candidatos_sm = sitemaps + [base + ruta for ruta in RUTAS_SITEMAP]
    # robots.txt puede declarar sitemaps.
    try:
        raw, _, _ = descarga(base + "/robots.txt", permite_robots=False, max_bytes=500_000)
        for linea in decode_html(raw).splitlines():
            if linea.lower().startswith("sitemap:"):
                candidatos_sm.append(linea.split(":", 1)[1].strip())
    except Exception:
        pass
    return list(dict.fromkeys(candidatos_feed)), list(dict.fromkeys(candidatos_sm))


def descubre_fuente(fuente: dict[str, Any], modo: str) -> list[dict[str, Any]]:
    host = fuente["dominio"]
    salida: list[dict[str, Any]] = []
    feeds, sitemaps = descubre_endpoints(fuente, modo)
    limite_feeds = len(feeds) if modo == "conciliacion" else min(3, len(feeds))
    for url in feeds[:limite_feeds]:
        if tiempo_agotado(150):
            break
        try:
            raw, final, _ = descarga(url, permite_robots=False)
            regs = parsea_feed(raw, final, "feed_directo")
            for r in regs:
                r["medio"] = fuente["nombre"]
            salida.extend(regs)
            cobertura(host, "feed", len(regs))
            if regs:
                break
        except Exception as exc:
            cobertura(host, "feed", 0, f"{type(exc).__name__}: {exc}")

    cola = list(sitemaps[:MAX_SITEMAPS_POR_FUENTE])
    vistos_sm: set[str] = set()
    visitados = 0
    while cola and visitados < MAX_SITEMAPS_POR_FUENTE and not tiempo_agotado(150):
        sm = cola.pop(0)
        if sm in vistos_sm:
            continue
        vistos_sm.add(sm)
        visitados += 1
        try:
            raw, final, _ = descarga(sm, permite_robots=False)
            regs, indices = parsea_sitemap(raw, final)
            if regs:
                recientes = [r for r in regs if dentro_ventana(r.get("fecha_dt"))]
                for r in recientes[:MAX_URLS_SITEMAP]:
                    r["medio"] = fuente["nombre"]
                salida.extend(recientes[:MAX_URLS_SITEMAP])
                cobertura(host, "sitemap", len(recientes[:MAX_URLS_SITEMAP]))
            if indices:
                # Prefiere news y sitemaps recientes; en conciliación permite índices generales.
                indices.sort(key=lambda x: ("news" not in x.lower(), "2026" not in x.lower(), x))
                cola.extend(indices[:MAX_SITEMAPS_POR_FUENTE - visitados])
        except Exception as exc:
            cobertura(host, "sitemap", 0, f"{type(exc).__name__}: {exc}")

    secciones = fuente.get("secciones", [])
    limite_sec = len(secciones) if modo == "conciliacion" else min(1, len(secciones))
    for sec in secciones[:limite_sec]:
        if tiempo_agotado(150):
            break
        try:
            raw, final, _ = descarga(sec, permite_robots=False)
            regs = extrae_enlaces_pagina(raw, final, host, fuente["nombre"])
            salida.extend(regs)
            cobertura(host, "seccion", len(regs))
        except Exception as exc:
            cobertura(host, "seccion", 0, f"{type(exc).__name__}: {exc}")
    return salida


def fuentes_para_corrida(modo: str, estado: dict[str, Any]) -> list[dict[str, Any]]:
    if modo == "conciliacion":
        return FUENTES
    prioritarias = [f for f in FUENTES if int(f.get("prioridad", 0)) >= 8]
    resto = [f for f in FUENTES if f not in prioritarias]
    n = env_int("MONITOR_FUENTES_ROTACION", 14)
    idx = int(estado.get("rotacion_fuentes", 0)) % max(1, len(resto))
    rotadas = (resto + resto)[idx:idx + n]
    estado["rotacion_fuentes"] = (idx + n) % max(1, len(resto))
    return list({f["dominio"]: f for f in prioritarias + rotadas}.values())


def descubre_directo(modo: str, estado: dict[str, Any]) -> list[dict[str, Any]]:
    fuentes = fuentes_para_corrida(modo, estado)
    salida: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(HILOS, 6)) as ex:
        futuros = {ex.submit(descubre_fuente, f, modo): f for f in fuentes}
        for fut in as_completed(futuros):
            f = futuros[fut]
            try:
                regs = fut.result()
                salida.extend(regs)
                log(f"directo {f['dominio']}: {len(regs)} candidatos")
            except Exception as exc:
                cobertura(f["dominio"], "directo", 0, f"{type(exc).__name__}: {exc}")
    return salida


def resuelve_google_news(reg: dict[str, Any]) -> dict[str, Any]:
    if tiempo_agotado(90):
        return reg
    url = reg.get("link", "")
    if dominio_url(url) != "news.google.com":
        return reg
    try:
        raw, final, headers = descarga(url, permite_robots=False, max_bytes=2_000_000)
        if dominio_url(final) != "news.google.com":
            reg["link"] = final
            return reg
        html = decode_html(raw, headers)
        # Busca canonical o un enlace externo de la fuente.
        p = DocumentoHTML()
        p.feed(html)
        candidatos = []
        for href, rel, texto in p.links:
            abs_url = urllib.parse.urljoin(final, href)
            h = dominio_url(abs_url)
            if h and h not in DOMINIOS_VETADOS and h != "news.google.com":
                candidatos.append(abs_url)
        if candidatos:
            reg["link"] = candidatos[0]
    except Exception:
        pass
    return reg


def puntaje_candidato(reg: dict[str, Any], modo: str) -> int:
    texto = normaliza((reg.get("titulo") or "") + " " + (reg.get("resumen") or ""))
    host = dominio_url(reg.get("link", ""))
    fuente = fuente_para_host(host)
    p = int(fuente.get("prioridad", 3) if fuente else 1)
    if MENCION_UAF_RE.search(texto):
        p += 18
    p += 3 * sum(1 for s in SENALES_LAFT if normaliza(s) in texto)
    if reg.get("fecha_dt"):
        edad = (ahora_cl() - reg["fecha_dt"]).days
        p += max(0, 8 - edad // 3)
    if reg.get("origen_busqueda") in {"sitemap", "feed_directo", "site_google_news"}:
        p += 3
    if modo == "conciliacion":
        p += 2
    return p


def normaliza_candidatos(registros: list[dict[str, Any]], modo: str) -> list[dict[str, Any]]:
    """Resuelve enlaces de agregadores y unifica candidatos por URL canónica.

    Los enlaces de Google News requieren una petición adicional. Se resuelven en
    paralelo y con un límite distinto por modo, evitando que esta etapa consuma
    todo el presupuesto antes del barrido directo de fuentes.
    """
    directos: list[dict[str, Any]] = []
    google: list[dict[str, Any]] = []
    vistos_google: set[str] = set()
    for original in registros:
        reg = dict(original)
        if dominio_url(reg.get("link", "")) == "news.google.com":
            clave = reg.get("link", "")
            if clave and clave not in vistos_google:
                google.append(reg)
                vistos_google.add(clave)
        else:
            directos.append(reg)

    google.sort(key=lambda r: (bool(MENCION_UAF_RE.search(normaliza((r.get("titulo") or "") + " " + (r.get("resumen") or "")))),
                               r.get("fecha_dt") or datetime.min.replace(tzinfo=TZ_CL)), reverse=True)
    limite_google = MAX_GOOGLE_RESOLVER_CONCILIACION if modo == "conciliacion" else MAX_GOOGLE_RESOLVER_RAPIDO
    google = google[:limite_google]
    resueltos: list[dict[str, Any]] = []
    if google and not tiempo_agotado(150):
        ex = ThreadPoolExecutor(max_workers=min(HILOS, 8))
        futuros = [ex.submit(resuelve_google_news, r) for r in google]
        try:
            for fut in as_completed(futuros):
                if tiempo_agotado(130):
                    for pendiente in futuros:
                        pendiente.cancel()
                    break
                try:
                    resueltos.append(fut.result())
                except Exception:
                    pass
        finally:
            ex.shutdown(wait=True, cancel_futures=True)

    por_url: dict[str, dict[str, Any]] = {}
    for reg in directos + resueltos:
        if tiempo_agotado(120):
            break
        url = url_canonica(reg.get("link", ""))
        if not url:
            continue
        host = dominio_url(url)
        fuente = fuente_para_host(host)
        if not fuente or host in DOMINIOS_VETADOS:
            continue
        fecha_dt = reg.get("fecha_dt") or parsea_fecha("", url)
        if fecha_dt and not dentro_ventana(fecha_dt):
            continue
        reg["link"] = url
        reg["fecha_dt"] = fecha_dt
        reg["medio"] = reg.get("medio") or fuente["nombre"]
        reg["fuente_url"] = f"https://{fuente['dominio']}"
        reg["tipo_fuente"] = fuente["tipo"]
        reg["fuente_institucional"] = bool(fuente.get("oficial"))
        reg["origenes_busqueda"] = [reg.get("origen_busqueda", "desconocido")]
        reg["_puntaje"] = puntaje_candidato(reg, modo)
        anterior = por_url.get(url)
        if anterior:
            anterior["origenes_busqueda"] = sorted(set(anterior.get("origenes_busqueda", []) + reg["origenes_busqueda"]))
            if len(reg.get("titulo", "")) > len(anterior.get("titulo", "")):
                anterior["titulo"] = reg["titulo"]
            if len(reg.get("resumen", "")) > len(anterior.get("resumen", "")):
                anterior["resumen"] = reg["resumen"]
            anterior["_puntaje"] = max(anterior.get("_puntaje", 0), reg["_puntaje"])
        else:
            por_url[url] = reg
    candidatos = list(por_url.values())
    candidatos.sort(key=lambda r: (r.get("_puntaje", 0), r.get("fecha_dt") or datetime.min.replace(tzinfo=TZ_CL)), reverse=True)
    return candidatos[:MAX_CANDIDATOS]


def selecciona_barrido_equilibrado(candidatos: list[dict[str, Any]], limite: int, minimo: int | None = None) -> list[dict[str, Any]]:
    minimo = MIN_POR_FUENTE if minimo is None else minimo
    por_host: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in candidatos:
        por_host[dominio_url(c.get("link", ""))].append(c)
    elegidos: list[dict[str, Any]] = []
    vistos: set[str] = set()
    hosts = sorted(por_host, key=lambda h: max((x.get("_puntaje", 0) for x in por_host[h]), default=0), reverse=True)
    for ronda in range(minimo):
        for host in hosts:
            if len(elegidos) >= limite:
                return elegidos
            if ronda < len(por_host[host]):
                c = por_host[host][ronda]
                if c["link"] not in vistos:
                    elegidos.append(c)
                    vistos.add(c["link"])
    for c in candidatos:
        if len(elegidos) >= limite:
            break
        if c["link"] not in vistos:
            elegidos.append(c)
            vistos.add(c["link"])
    return elegidos


# ---------------------------------------------------------------------------
# Extracción y validación
# ---------------------------------------------------------------------------


def enriquece_articulo(reg: dict[str, Any]) -> dict[str, Any]:
    r = dict(reg)
    if tiempo_agotado(60):
        r.update({"cuerpo_extraido": False, "estado_extraccion": "presupuesto_agotado",
                  "error_enriquecimiento": "presupuesto global agotado"})
        return r
    url = r["link"]
    try:
        raw, final, headers = descarga(url)
        content_type = headers.get("content-type", "").lower()
        if "pdf" in content_type or final.lower().endswith(".pdf"):
            r.update({"url_final": url_canonica(final), "cuerpo_extraido": False,
                      "error_enriquecimiento": "documento_pdf_sin_texto", "estado_extraccion": "pendiente_pdf"})
            return r
        art = extrae_articulo_html(raw, final, headers)
        if art.get("amp_url") and len(art.get("texto_enriquecido", "")) < 300:
            try:
                raw_amp, final_amp, h_amp = descarga(art["amp_url"])
                art_amp = extrae_articulo_html(raw_amp, final_amp, h_amp)
                if len(art_amp.get("texto_enriquecido", "")) > len(art.get("texto_enriquecido", "")):
                    art = art_amp
                    art["origen_cuerpo"] = "amp"
            except Exception:
                pass
        if art.get("titulo") and len(art["titulo"]) > len(r.get("titulo", "")):
            r["titulo"] = art["titulo"]
        if art.get("resumen") and len(art["resumen"]) > len(r.get("resumen", "")):
            r["resumen"] = art["resumen"]
        r["texto_enriquecido"] = art.get("texto_enriquecido", "")
        r["fecha_dt"] = art.get("fecha_dt") or r.get("fecha_dt") or parsea_fecha("", final)
        r["link"] = art.get("url_final") or url_canonica(final) or url
        r["url_final"] = r["link"]
        r["cuerpo_extraido"] = len(r.get("texto_enriquecido", "")) >= 180
        r["estado_extraccion"] = "completo" if r["cuerpo_extraido"] else "cuerpo_insuficiente"
        if not r["cuerpo_extraido"]:
            r["error_enriquecimiento"] = "cuerpo_insuficiente"
        return r
    except PermissionError as exc:
        r.update({"cuerpo_extraido": False, "estado_extraccion": "bloqueado_robots", "error_enriquecimiento": str(exc)})
    except urllib.error.HTTPError as exc:
        r.update({"cuerpo_extraido": False, "estado_extraccion": f"http_{exc.code}", "error_enriquecimiento": str(exc)})
    except Exception as exc:
        r.update({"cuerpo_extraido": False, "estado_extraccion": "error_descarga", "error_enriquecimiento": f"{type(exc).__name__}: {exc}"})
    return r


def texto_registro(reg: dict[str, Any]) -> str:
    return " ".join([reg.get("titulo", ""), reg.get("resumen", ""), reg.get("texto_enriquecido", "")])[:MAX_TEXTO_ANALISIS]


def ventanas_uaf(texto: str, ancho: int = 520) -> list[str]:
    return [texto[max(0, m.start() - ancho): min(len(texto), m.end() + ancho)] for m in MENCION_UAF_RE.finditer(texto)]


def analiza_uaf(reg: dict[str, Any]) -> tuple[bool, str, list[str], int, int]:
    texto_original = texto_registro(reg)
    texto = normaliza(texto_original)
    menciones = list(MENCION_UAF_RE.finditer(texto))
    if not menciones:
        return False, "sin_mencion", ["sin mención UAF"], 0, 0
    host = dominio_url(reg.get("link", ""))
    fuente = fuente_para_host(host)
    puntajes: list[tuple[int, list[str]]] = []
    for m in menciones:
        ventana = texto[max(0, m.start() - 520): min(len(texto), m.end() + 520)]
        score = 0
        motivos: list[str] = []
        mencion = m.group(0)
        if "unidad de analisis financiero" in mencion:
            score += 5; motivos.append("nombre institucional")
        elif re.fullmatch(r"u\.?a\.?f\.?", mencion):
            score += 2; motivos.append("sigla UAF")
        else:
            score += 1
        if fuente:
            score += 2; motivos.append("fuente chilena catalogada")
        if host in DOMINIOS_INSTITUCIONALES:
            score += 2; motivos.append("fuente oficial chilena")
        chile_hits = sum(1 for s in SENALES_CHILE if normaliza(s) in ventana)
        laft_hits = sum(1 for s in SENALES_LAFT if normaliza(s) in ventana)
        if chile_hits:
            score += min(6, chile_hits * 2); motivos.append("contexto institucional chileno")
        if laft_hits:
            score += min(4, laft_hits); motivos.append("contexto LA/FT")
        extranjeros = [s for s in SENALES_EXTRANJERAS if normaliza(s) in ventana]
        if extranjeros:
            score -= 8; motivos.append("contexto de unidad extranjera")
        # UAF institucional se acepta incluso en noticias de actividades sin términos LA/FT.
        if host in {"uaf.cl", "estrategiaantilavado.cl"}:
            score += 5; motivos.append("sitio del sistema antilavado chileno")
        puntajes.append((score, motivos))
    mejor, motivos = max(puntajes, key=lambda x: x[0])
    valido = mejor >= 6
    confianza = "alta" if mejor >= 10 else "media" if valido else "baja"
    return valido, confianza, motivos, mejor, len(menciones)


def extrae_contexto_uaf(reg: dict[str, Any]) -> str:
    texto = texto_registro(reg)
    vs = ventanas_uaf(texto, 240)
    if not vs:
        return ""
    mejor = max(vs, key=lambda v: sum(1 for s in SENALES_CHILE + SENALES_LAFT if normaliza(s) in normaliza(v)))
    mejor = limpia_texto(mejor)
    return ("…" if len(mejor) < len(texto) else "") + mejor[:620] + ("…" if len(mejor) > 620 else "")


def origen_mencion_uaf(reg: dict[str, Any], es_uaf: bool) -> str:
    if not es_uaf:
        return "sin_mencion"
    if MENCION_UAF_RE.search(reg.get("titulo", "")):
        return "titulo"
    if MENCION_UAF_RE.search(reg.get("resumen", "")):
        return "bajada"
    if MENCION_UAF_RE.search(reg.get("texto_enriquecido", "")):
        return "cuerpo"
    return "texto"


def es_pertinente(reg: dict[str, Any]) -> bool:
    uaf = analiza_uaf(reg)[0]
    if uaf:
        return True
    texto = normaliza(texto_registro(reg))
    hits_laft = sum(1 for s in SENALES_LAFT if normaliza(s) in texto)
    hits_crimen = sum(1 for s in SENALES_TEMATICAS if normaliza(s) in texto)
    return hits_laft >= 1 and hits_crimen >= 2


def clasifica_naturaleza(reg: dict[str, Any], texto: str) -> str:
    url = normaliza(reg.get("link", ""))
    combinado = texto + " " + url
    for clave in ("opinion", "institucional", "legislativo", "regulatorio", "judicial", "policial", "analisis"):
        if contiene(combinado, NATURALEZAS[clave]):
            return clave
    return "analisis"


def clasifica(reg: dict[str, Any]) -> dict[str, Any]:
    texto = normaliza(texto_registro(reg))
    uaf, confianza, motivos, puntaje, menciones = analiza_uaf(reg)
    fenomeno = next((k for k, v in FENOMENOS.items() if contiene(texto, v)), "otro")
    naturaleza = clasifica_naturaleza(reg, texto)
    precedentes = [k for k, v in PRECEDENTES.items() if contiene(texto, v)] or ["indeterminado"]
    topicos = [k for k, v in TOPICOS.items() if contiene(texto, v)] or ["otros"]
    sujetos = [k for k, v in SUJETOS.items() if contiene(texto, v)]
    if sujetos and "sujetos_obligados" not in topicos:
        topicos.append("sujetos_obligados")
    impactos: list[str] = []
    if sujetos:
        if contiene(texto, ["fiscalizacion", "circular", "regulacion", "obligacion", "sancion"]):
            impactos.append("regulacion_supervision")
        if contiene(texto, ["lavado", "utilizado", "canalizo", "testaferro", "cuenta puente"]):
            impactos.append("vulneracion_la")
        if contiene(texto, ["cumplimiento", "debida diligencia", "prevencion"]):
            impactos.append("cumplimiento_preventivo")
    fuente = fuente_para_host(dominio_url(reg.get("link", ""))) or {}
    roles = {s: ("regulado" if "regulacion_supervision" in impactos else "vulnerado" if "vulneracion_la" in impactos else "mencionado") for s in sujetos}
    reg.update({
        "fenomeno": fenomeno,
        "fenomeno_label": LABELS["fenomeno"].get(fenomeno, fenomeno),
        "naturaleza": naturaleza,
        "naturaleza_label": LABELS["naturaleza"].get(naturaleza, naturaleza),
        "precedentes": precedentes,
        "precedentes_label": [LABELS["precedentes"].get(x, x) for x in precedentes],
        "topicos": topicos,
        "topicos_label": [LABELS["topicos"].get(x, x) for x in topicos],
        "sujetos_obligados": sujetos,
        "sujetos_obligados_label": [LABELS["sujetos"].get(x, x) for x in sujetos],
        "impactos_sujeto": impactos,
        "impactos_sujeto_label": [{"regulacion_supervision": "Regulación o supervisión", "vulneracion_la": "Vulneración para LA", "cumplimiento_preventivo": "Cumplimiento preventivo"}.get(x, x) for x in impactos],
        "roles_sujetos": roles,
        "roles_sujetos_label": {k: v.capitalize() for k, v in roles.items()},
        "tipo_medio": fuente.get("tipo", reg.get("tipo_fuente", "otro")),
        "uaf": uaf,
        "uaf_chile": uaf,
        "uaf_confianza": confianza,
        "uaf_motivos": motivos,
        "uaf_puntaje": puntaje,
        "uaf_menciones": menciones,
        "origen_mencion_uaf": origen_mencion_uaf(reg, uaf),
        "contexto_uaf": extrae_contexto_uaf(reg) if uaf else "",
        "nucleo": uaf or contiene(texto, SENALES_LAFT),
        "fuente_institucional": bool(fuente.get("oficial", reg.get("fuente_institucional"))),
        "nivel_fuente": "institucional" if fuente.get("oficial") else "catalogada",
        "nivel_fuente_label": "Fuente institucional" if fuente.get("oficial") else "Medio catalogado",
    })
    return reg


# ---------------------------------------------------------------------------
# Estado, histórico y auditoría
# ---------------------------------------------------------------------------


def carga_json(ruta: Path, defecto: Any) -> Any:
    try:
        return json.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else copy.deepcopy(defecto)
    except Exception:
        return copy.deepcopy(defecto)


def carga_estado() -> dict[str, Any]:
    estado = carga_json(ESTADO, {})
    if estado.get("esquema") != ESQUEMA_ESTADO:
        # Conserva vistos para no reenviar correos, pero fuerza revisión de descartes antiguos.
        estado = {"vistos": estado.get("vistos", []), "rotacion_fuentes": estado.get("rotacion_fuentes", 0),
                  "esquema": ESQUEMA_ESTADO, "procesados": {}, "pendientes": {},
                  "migracion_pendiente": True}
    estado.setdefault("vistos", [])
    estado.setdefault("procesados", {})
    estado.setdefault("pendientes", {})
    estado.setdefault("esquema", ESQUEMA_ESTADO)
    return estado


def guarda_estado(estado: dict[str, Any]) -> None:
    corte = ahora_cl() - timedelta(days=RETENCION_PROCESADOS_DIAS)
    procesados = {}
    for k, v in (estado.get("procesados") or {}).items():
        f = parsea_fecha(v.get("revisado"))
        if not f or f >= corte:
            procesados[k] = v
    estado["procesados"] = dict(list(procesados.items())[-50_000:])
    estado["vistos"] = list(dict.fromkeys(estado.get("vistos", [])))[-50_000:]
    temporal = ESTADO.with_suffix(".tmp")
    temporal.write_text(json.dumps(estado, ensure_ascii=False, indent=1, default=json_default), encoding="utf-8")
    os.replace(temporal, ESTADO)


def carga_previos() -> dict[str, Any]:
    return carga_json(SALIDA, {"prensa": [], "social": [], "candidatos_pendientes": []})


def debe_revisar(c: dict[str, Any], estado: dict[str, Any], modo: str) -> bool:
    k = id_registro(c["link"], c.get("titulo", ""))
    prev = (estado.get("procesados") or {}).get(k)
    if not prev:
        return True
    revisado = parsea_fecha(prev.get("revisado"))
    if modo == "conciliacion" and prev.get("estado") not in {"aceptado_uaf", "aceptado_contexto"}:
        return not revisado or revisado < ahora_cl() - timedelta(days=5)
    if prev.get("estado") in {"error_descarga", "bloqueado_robots", "cuerpo_insuficiente", "pendiente_pdf"}:
        return not revisado or revisado < ahora_cl() - timedelta(days=2)
    return False


def razon_descarte(reg: dict[str, Any]) -> str:
    estado = reg.get("estado_extraccion", "")
    if estado and estado != "completo" and not reg.get("titulo") and not reg.get("resumen"):
        return estado
    if reg.get("fecha_dt") and not dentro_ventana(reg["fecha_dt"]):
        return "fuera_de_ventana"
    if not MENCION_UAF_RE.search(texto_registro(reg)) and not es_pertinente(reg):
        return "sin_mencion_ni_contexto_laft"
    if MENCION_UAF_RE.search(texto_registro(reg)) and not analiza_uaf(reg)[0]:
        return "uaf_ambigua_o_extranjera"
    return "no_pertinente"


def candidato_pendiente(reg: dict[str, Any], motivo: str) -> dict[str, Any]:
    f = reg.get("fecha_dt") or ahora_cl()
    return {
        "id": id_registro(reg.get("link", ""), reg.get("titulo", "")),
        "fecha": f.strftime("%Y-%m-%d"),
        "medio": reg.get("medio", dominio_url(reg.get("link", ""))),
        "titulo": reg.get("titulo") or "Sin título recuperado",
        "link": reg.get("link", ""),
        "motivo": motivo,
        "evidencia": limpia_texto(reg.get("resumen", ""))[:300],
        "origenes_busqueda": reg.get("origenes_busqueda", [reg.get("origen_busqueda", "")]),
        "ultima_revision": ahora_cl().isoformat(),
    }


def registro_publicable(reg: dict[str, Any], modo: str) -> dict[str, Any]:
    r = clasifica(dict(reg))
    fecha_dt = r.get("fecha_dt") or ahora_cl()
    r.update({
        "id": id_registro(r.get("link", ""), r.get("titulo", "")),
        "canal": "prensa",
        "fecha": fecha_dt.strftime("%Y-%m-%d"),
        "fecha_hora": fecha_dt.isoformat(),
        "fecha_legible": fecha_dt.strftime("%d/%m/%Y"),
        "medio": r.get("medio") or (fuente_para_host(dominio_url(r.get("link", ""))) or {}).get("nombre", dominio_url(r.get("link", ""))),
        "resumen": limpia_texto(r.get("resumen", ""))[:1000],
        "titulo": limpia_texto(r.get("titulo", ""))[:500],
        "texto_enriquecido": limpia_texto(r.get("texto_enriquecido", ""))[:MAX_TEXTO_GUARDADO],
        "origen_busqueda": (r.get("origenes_busqueda") or [r.get("origen_busqueda", "desconocido")])[0],
        "origenes_busqueda": sorted(set(r.get("origenes_busqueda") or [r.get("origen_busqueda", "desconocido")])),
        "incorporado_por": modo,
    })
    r.pop("_puntaje", None)
    r.pop("amp_url", None)
    r.pop("links", None)
    return r


def calidad_registro(r: dict[str, Any]) -> int:
    return (20 if r.get("cuerpo_extraido") else 0) + len(r.get("texto_enriquecido", "")) // 200 + (10 if r.get("uaf") else 0) + len(r.get("resumen", "")) // 100


def mezcla_historico(previos: list[dict[str, Any]], nuevos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    corte = ahora_cl() - timedelta(days=VENTANA_DIAS)
    por_id: dict[str, dict[str, Any]] = {}
    for r in previos + nuevos:
        fecha_dt = parsea_fecha(r.get("fecha_hora") or r.get("fecha"))
        if fecha_dt and fecha_dt < corte:
            continue
        rid = r.get("id") or id_registro(r.get("link", ""), r.get("titulo", ""))
        r["id"] = rid
        anterior = por_id.get(rid)
        if not anterior or calidad_registro(r) >= calidad_registro(anterior):
            por_id[rid] = r
        else:
            anterior["origenes_busqueda"] = sorted(set(anterior.get("origenes_busqueda", []) + r.get("origenes_busqueda", [])))
    return sorted(por_id.values(), key=lambda r: r.get("fecha_hora", r.get("fecha", "")), reverse=True)


def ranking(registros: list[dict[str, Any]], clave: str, labels: dict[str, str] | None = None) -> list[dict[str, Any]]:
    c: Counter[str] = Counter()
    for r in registros:
        valor = r.get(clave)
        valores = valor if isinstance(valor, list) else [valor]
        for v in valores:
            if v:
                c[str(v)] += 1
    return [{"clave": k, "label": (labels or {}).get(k, k), "n": n} for k, n in c.most_common(20)]


def calcula_metricas(prensa: list[dict[str, Any]], social: list[dict[str, Any]], dias: list[str], ahora: datetime) -> dict[str, Any]:
    uaf = [r for r in prensa if r.get("uaf")]
    contexto = [r for r in prensa if not r.get("uaf")]
    c24 = ahora - timedelta(hours=24)
    c48 = ahora - timedelta(hours=48)
    c5 = ahora - timedelta(days=5)
    uaf_prensa_publica = [r for r in uaf if not r.get("fuente_institucional")]
    cur = [r for r in uaf_prensa_publica if (parsea_fecha(r.get("fecha_hora")) or datetime.min.replace(tzinfo=TZ_CL)) >= c24]
    prev = [r for r in uaf_prensa_publica if c48 <= (parsea_fecha(r.get("fecha_hora")) or datetime.min.replace(tzinfo=TZ_CL)) < c24]
    five = [r for r in uaf_prensa_publica if (parsea_fecha(r.get("fecha_hora")) or datetime.min.replace(tzinfo=TZ_CL)) >= c5]
    por_dia = {d: sum(1 for r in prensa if r.get("fecha") == d) for d in dias}
    return {
        "uaf_portada": {
            "menciones_24h": len(cur), "menciones_previas_24h": len(prev), "diferencia": len(cur) - len(prev),
            "variacion_pct": round((len(cur) - len(prev)) / len(prev) * 100, 1) if prev else None,
            "direccion": "alza" if len(cur) > len(prev) else "baja" if len(cur) < len(prev) else "estable",
            "menciones_5d": len(five), "medios_24h": len({r.get("medio") for r in cur}),
            "medios_5d": len({r.get("medio") for r in five}),
            "topicos_24h": ranking(cur, "topicos", LABELS["topicos"]),
            "fenomenos_24h": ranking(cur, "fenomeno", LABELS["fenomeno"]),
            "naturalezas_24h": ranking(cur, "naturaleza", LABELS["naturaleza"]),
            "tipos_medio_24h": ranking(cur, "tipo_medio"),
            "medios_ranking_24h": ranking(cur, "medio"),
            "sujetos_obligados_24h": ranking(cur, "sujetos_obligados", LABELS["sujetos"]),
            "detalle": cur[:20],
        },
        "uaf_total": len(uaf), "uaf_prensa": len(uaf), "uaf_social": 0,
        "uaf_donde": [{"fecha": r.get("fecha"), "medio": r.get("medio"), "titulo": r.get("titulo"), "link": r.get("link")} for r in uaf[:20]],
        "contexto_total": len(contexto), "volumen": len(prensa) + len(social),
        "volumen_hoy": por_dia.get(ahora.strftime("%Y-%m-%d"), 0),
        "dias_con_actividad": sum(1 for n in por_dia.values() if n), "dias_ventana": len(dias),
        "medios_unicos": len({r.get("medio") for r in prensa}),
        "casos_activos": len({r.get("fenomeno") for r in prensa if r.get("fenomeno") not in {None, "otro"}}),
        "precedentes_distintos": len({x for r in prensa for x in r.get("precedentes", []) if x != "indeterminado"}),
        "fenomenos": ranking(prensa, "fenomeno", LABELS["fenomeno"]),
        "precedentes": ranking(prensa, "precedentes", LABELS["precedentes"]),
        "naturalezas": ranking(prensa, "naturaleza", LABELS["naturaleza"]),
        "topicos": ranking(prensa, "topicos", LABELS["topicos"]),
        "tipos_medio": ranking(prensa, "tipo_medio"),
        "sujetos_obligados": ranking(prensa, "sujetos_obligados", LABELS["sujetos"]),
        "impactos_sujeto": ranking(prensa, "impactos_sujeto"),
        "medios": ranking(prensa, "medio"), "por_dia": por_dia,
        "plataformas": [], "social_sin_acceso": 0,
    }


# ---------------------------------------------------------------------------
# Correo
# ---------------------------------------------------------------------------


def carga_config() -> dict[str, Any]:
    if not CONFIG.exists():
        try:
            CONFIG.write_text(json.dumps(CONFIG_EJEMPLO, ensure_ascii=False, indent=2, default=json_default), encoding="utf-8")
        except OSError:
            pass
    cfg = carga_json(CONFIG, CONFIG_EJEMPLO)
    correo = cfg.setdefault("correo", {})
    mapa = {
        "activo": ("MONITOR_CORREO_ACTIVO", env_bool), "servidor": ("MONITOR_SMTP_SERVIDOR", str),
        "puerto": ("MONITOR_SMTP_PUERTO", int), "seguridad": ("MONITOR_SMTP_SEGURIDAD", str),
        "usuario": ("MONITOR_SMTP_USUARIO", str), "clave": ("MONITOR_SMTP_CLAVE", str),
        "remitente_nombre": ("MONITOR_REMITENTE_NOMBRE", str), "minimo_para_avisar": ("MONITOR_MINIMO_AVISO", int),
        "silencio_minutos": ("MONITOR_SILENCIO_MINUTOS", int), "solo_si_menciona_uaf": ("MONITOR_SOLO_UAF", env_bool),
    }
    for clave, (env, conv) in mapa.items():
        valor = os.getenv(env)
        if valor is not None and valor != "":
            try:
                correo[clave] = conv(env, correo.get(clave)) if conv is env_bool else conv(valor)
            except Exception:
                pass
    dest = os.getenv("MONITOR_DESTINATARIOS")
    if dest:
        correo["destinatarios"] = [x.strip() for x in dest.split(",") if x.strip()]
    return cfg


def envia_correo(nuevos: list[dict[str, Any]], estado: dict[str, Any], modo: str) -> None:
    if modo != "rapido":
        return
    cfg = carga_config().get("correo", {})
    if not cfg.get("activo"):
        return
    silencio = max(0, int(cfg.get("silencio_minutos", 0) or 0))
    ultimo = parsea_fecha(estado.get("ultimo_correo"))
    if silencio and ultimo and ultimo > ahora_cl() - timedelta(minutes=silencio):
        log(f"Correo omitido por silencio de {silencio} minutos.")
        return
    avisos = [r for r in nuevos if r.get("uaf")]
    if not avisos or len(avisos) < int(cfg.get("minimo_para_avisar", 1)):
        return
    destinatarios = cfg.get("destinatarios") or []
    if not destinatarios:
        return
    msg = EmailMessage()
    msg["Subject"] = f"Monitor UAF Chile: {len(avisos)} nueva(s) mención(es)"
    msg["From"] = formataddr((cfg.get("remitente_nombre", "Monitor UAF Chile"), cfg.get("usuario", "")))
    msg["To"] = ", ".join(destinatarios)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    lineas = ["Se detectaron nuevas menciones verificadas de la UAF de Chile:", ""]
    for r in avisos[:25]:
        lineas += [f"{r.get('fecha_legible')} · {r.get('medio')}", r.get("titulo", ""),
                   r.get("contexto_uaf") or r.get("resumen", ""), r.get("link", ""), ""]
    msg.set_content("\n".join(lineas))
    servidor = cfg.get("servidor")
    puerto = int(cfg.get("puerto", 587))
    seguridad = str(cfg.get("seguridad", "starttls")).lower()
    usuario = cfg.get("usuario", "")
    clave = cfg.get("clave", "")
    contexto = ssl.create_default_context()
    if seguridad == "ssl":
        with smtplib.SMTP_SSL(servidor, puerto, context=contexto, timeout=30) as smtp:
            if usuario:
                smtp.login(usuario, clave)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(servidor, puerto, timeout=30) as smtp:
            smtp.ehlo()
            if seguridad == "starttls":
                smtp.starttls(context=contexto); smtp.ehlo()
            if usuario:
                smtp.login(usuario, clave)
            smtp.send_message(msg)
    estado["ultimo_correo"] = ahora_cl().isoformat()


# ---------------------------------------------------------------------------
# Ejecución principal
# ---------------------------------------------------------------------------


def ejecutar(modo: str) -> int:
    modo = modo.lower()
    if modo not in {"rapido", "conciliacion"}:
        raise ValueError("modo debe ser rapido o conciliacion")
    estado = carga_estado()
    migracion = bool(estado.pop("migracion_pendiente", False))
    previos = carga_previos()
    log(f"Inicio motor {VERSION_MONITOR} · modo={modo} · fuentes={len(FUENTES)} · migracion={migracion}")

    descubiertos = descubre_agregadores(modo)
    descubiertos += descubre_directo(modo, estado)
    candidatos = normaliza_candidatos(descubiertos, modo)
    candidatos_revision = [c for c in candidatos if debe_revisar(c, estado, modo)]
    limite = MAX_ENRIQUECER if modo == "rapido" else max(MAX_ENRIQUECER, env_int("MONITOR_MAX_ENRIQUECER_CONCILIACION", 1_100))
    minimo = MIN_POR_FUENTE if modo == "rapido" else max(6, MIN_POR_FUENTE)
    seleccion = selecciona_barrido_equilibrado(candidatos_revision, limite, minimo)
    log(f"Descubiertos={len(descubiertos)} · únicos={len(candidatos)} · a revisar={len(seleccion)}")

    enriquecidos: list[dict[str, Any]] = []
    ex = ThreadPoolExecutor(max_workers=HILOS)
    futuros = {ex.submit(enriquece_articulo, c): c for c in seleccion}
    try:
        for fut in as_completed(futuros):
            if tiempo_agotado(75):
                for pendiente in futuros:
                    pendiente.cancel()
                break
            try:
                enriquecidos.append(fut.result())
            except Exception as exc:
                c = futuros[fut]
                c["estado_extraccion"] = "error_descarga"
                c["error_enriquecimiento"] = f"{type(exc).__name__}: {exc}"
                enriquecidos.append(c)
    finally:
        ex.shutdown(wait=True, cancel_futures=True)

    aceptados: list[dict[str, Any]] = []
    pendientes: list[dict[str, Any]] = []
    descartes: Counter[str] = Counter()
    muestras_descartes: list[dict[str, Any]] = []
    revisado_iso = ahora_cl().isoformat()
    for r in enriquecidos:
        rid = id_registro(r.get("link", ""), r.get("titulo", ""))
        uaf = analiza_uaf(r)[0]
        pertinente = es_pertinente(r)
        if pertinente:
            pub = registro_publicable(r, modo)
            aceptados.append(pub)
            estado_val = "aceptado_uaf" if pub.get("uaf") else "aceptado_contexto"
        else:
            motivo = razon_descarte(r)
            estado_val = motivo
            descartes[motivo] += 1
            muestra = candidato_pendiente(r, motivo)
            # Conserva pendientes accionables; no muestra todos los descartes simples.
            if motivo in {"bloqueado_robots", "cuerpo_insuficiente", "error_descarga", "pendiente_pdf", "uaf_ambigua_o_extranjera"}:
                pendientes.append(muestra)
            if len(muestras_descartes) < 100:
                muestras_descartes.append(muestra)
        estado["procesados"][rid] = {"revisado": revisado_iso, "estado": estado_val, "url": r.get("link", "")}

    prensa = mezcla_historico(previos.get("prensa", []), aceptados)
    vistos = set(estado.get("vistos", []))
    nuevos = []
    for r in prensa:
        if r["id"] not in vistos and r in aceptados:
            r["nuevo"] = modo == "rapido" and not migracion
            r["incorporado_conciliacion"] = modo == "conciliacion"
            r["incorporado_migracion"] = migracion
            nuevos.append(r)
            vistos.add(r["id"])
        else:
            r["nuevo"] = False
    estado["vistos"] = list(vistos)

    pendientes_prev = {p.get("id"): p for p in previos.get("candidatos_pendientes", []) if p.get("id")}
    for p in pendientes:
        pendientes_prev[p["id"]] = p
    aceptados_ids = {r["id"] for r in prensa}
    pendientes_final = [p for i, p in pendientes_prev.items() if i not in aceptados_ids]
    pendientes_final.sort(key=lambda p: p.get("ultima_revision", ""), reverse=True)
    pendientes_final = pendientes_final[:500]

    ahora = ahora_cl()
    dias = [(ahora.date() - timedelta(days=i)).isoformat() for i in range(VENTANA_DIAS - 1, -1, -1)]
    metricas = calcula_metricas(prensa, [], dias, ahora)
    if modo == "conciliacion":
        estado["ultima_conciliacion"] = ahora.isoformat()
    cobertura_fuentes = []
    for f in FUENTES:
        reg = _COBERTURA.get(f["dominio"], {
            "fuente": f["nombre"], "dominio": f["dominio"], "canales": {}, "resultados": 0,
            "errores": ["no consultada en esta corrida"], "consultada": False,
        })
        reg = dict(reg)
        reg["obligatoria"] = f["dominio"] in DOMINIOS_MINIMOS
        reg["tipo"] = f["tipo"]
        reg["prioridad"] = f["prioridad"]
        cobertura_fuentes.append(reg)

    salida = {
        "generado": ahora.isoformat(), "generado_legible": ahora.strftime("%d/%m/%Y %H:%M"),
        "version_motor": VERSION_MONITOR, "modo_ejecucion": modo,
        "ventana": {"dias": dias, "hoy": ahora.strftime("%Y-%m-%d"), "largo": VENTANA_DIAS},
        "metricas": metricas, "prensa": prensa, "social": [], "nuevos": len([x for x in nuevos if x.get("nuevo")]),
        "consultas": len(CONSULTAS_UAF) + len(CONSULTAS_CONTEXTO) + len(consultas_site(modo)),
        "candidatos_pendientes": pendientes_final,
        "descartes_resumen": dict(descartes), "muestras_descartes": muestras_descartes,
        "cobertura_fuentes": cobertura_fuentes,
        "auditoria": {
            "modo": modo, "urls_descubiertas": len(descubiertos), "urls_unicas": len(candidatos),
            "urls_revisadas": len(enriquecidos), "aceptadas_corrida": len(aceptados),
            "menciones_uaf_corrida": sum(1 for r in aceptados if r.get("uaf")),
            "contexto_laft_corrida": sum(1 for r in aceptados if not r.get("uaf")),
            "pendientes_corrida": len(pendientes), "descartadas_corrida": sum(descartes.values()),
            "fuentes_configuradas": len(FUENTES), "fuentes_consultadas": sum(1 for x in cobertura_fuentes if x.get("consultada")),
            "ultima_conciliacion": estado.get("ultima_conciliacion"), "migracion_estado": migracion,
        },
        "cobertura_tecnica": {
            "cuerpos_extraidos": sum(1 for r in prensa if r.get("cuerpo_extraido")),
            "fuentes_institucionales": sum(1 for r in prensa if r.get("fuente_institucional")),
            "menciones_uaf_solo_cuerpo": sum(1 for r in prensa if r.get("uaf") and r.get("origen_mencion_uaf") == "cuerpo"),
            "solo_fuentes_chilenas": True, "medios_en_lista_blanca": len(DOMINIOS_CHILENOS),
            "fuentes_minimas_configuradas": len(DOMINIOS_MINIMOS),
            "fuentes_minimas_consultadas": sum(1 for h in DOMINIOS_MINIMOS if _COBERTURA.get(h, {}).get("consultada")),
            "articulos_en_memoria": len(estado.get("procesados", {})), "respeta_robots": RESPETA_ROBOTS,
            "retencion_procesados_dias": RETENCION_PROCESADOS_DIAS,
            "segundos_corrida": round(time.monotonic() - INICIO, 1),
        },
    }
    temporal = SALIDA.with_suffix(".tmp")
    temporal.write_text(json.dumps(salida, ensure_ascii=False, indent=1, default=json_default), encoding="utf-8")
    os.replace(temporal, SALIDA)
    if not migracion:
        try:
            envia_correo(nuevos, estado, modo)
        except Exception as exc:
            # El correo es un canal accesorio: una falla SMTP no debe impedir
            # guardar datos ni publicar el dashboard.
            estado["ultimo_error_correo"] = {
                "fecha": ahora_cl().isoformat(),
                "tipo": type(exc).__name__,
                "mensaje": str(exc)[:500],
            }
            log(f"ADVERTENCIA correo no enviado: {type(exc).__name__}: {exc}")
    else:
        log("Migración de esquema: se suprimen correos en esta corrida.")
    guarda_estado(estado)
    log(f"Listo: {len(prensa)} publicaciones · {len(nuevos)} incorporadas · {len(pendientes_final)} pendientes · {salida['cobertura_tecnica']['segundos_corrida']}s")
    return len(nuevos)


# ---------------------------------------------------------------------------
# Diagnóstico y CLI
# ---------------------------------------------------------------------------


def validar_fuentes_config() -> int:
    faltantes = [h for h in DOMINIOS_MINIMOS if h not in DOMINIOS_CHILENOS]
    duplicados = [d for d, n in Counter(f["dominio"] for f in FUENTES).items() if n > 1]
    print(json.dumps({
        "version": VERSION_MONITOR, "fuentes_configuradas": len(FUENTES), "fuentes_minimas": len(DOMINIOS_MINIMOS),
        "faltantes_en_catalogo": faltantes, "duplicados": duplicados,
        "nuevas_fuentes_institucionales": [x for x in ("aduana.cl", "tgr.gob.cl", "spensiones.cl", "scj.gob.cl", "estrategiaantilavado.cl") if x in DOMINIOS_CHILENOS],
        "retencion_procesados_dias": RETENCION_PROCESADOS_DIAS,
    }, ensure_ascii=False, indent=2, default=json_default))
    return 1 if faltantes or duplicados else 0


def evalua_url(url: str) -> dict[str, Any]:
    host = dominio_url(url)
    f = fuente_para_host(host) or {"nombre": host, "tipo": "otro", "oficial": False}
    reg = {"titulo": "", "resumen": "", "link": url, "medio": f["nombre"], "fuente_url": f"https://{host}",
           "tipo_fuente": f.get("tipo"), "fuente_institucional": f.get("oficial"), "origen_busqueda": "prueba_url"}
    r = enriquece_articulo(reg)
    uaf, confianza, motivos, puntaje, menciones = analiza_uaf(r)
    return {
        "url": url, "url_final": r.get("link"), "titulo": r.get("titulo"),
        "cuerpo_extraido": r.get("cuerpo_extraido"), "estado_extraccion": r.get("estado_extraccion"),
        "fecha": r.get("fecha_dt").isoformat() if r.get("fecha_dt") else None,
        "uaf_chile": uaf, "confianza": confianza, "puntaje": puntaje, "menciones": menciones,
        "motivos": motivos, "pertinente": es_pertinente(r), "contexto": extrae_contexto_uaf(r),
        "error": r.get("error_enriquecimiento"),
    }


def probar_url(url: str) -> None:
    print(json.dumps(evalua_url(url), ensure_ascii=False, indent=2, default=json_default))


def probar_casos_control() -> int:
    datos = carga_json(CASOS_CONTROL_ARCHIVO, {"casos": []})
    casos = datos.get("casos", []) if isinstance(datos, dict) else []
    resultados = []
    fallos = 0
    for caso in casos:
        url = caso.get("url", "")
        if not url:
            continue
        resultado = evalua_url(url)
        esperado = bool(caso.get("espera_uaf", True))
        resultado["nombre_control"] = caso.get("nombre", url)
        resultado["espera_uaf"] = esperado
        resultado["cumple"] = resultado.get("uaf_chile") is esperado
        if not resultado["cumple"]:
            fallos += 1
        resultados.append(resultado)
    print(json.dumps({"version": VERSION_MONITOR, "casos": len(resultados), "fallos": fallos,
                      "resultados": resultados}, ensure_ascii=False, indent=2, default=json_default))
    return 1 if fallos else 0


def probar_deteccion(texto: str, medio: str = "Medio chileno", link: str = "https://www.df.cl/prueba") -> None:
    reg = {"titulo": texto[:200], "resumen": "", "texto_enriquecido": texto, "medio": medio, "link": link}
    uaf, confianza, motivos, puntaje, menciones = analiza_uaf(reg)
    print(json.dumps({"uaf_chile": uaf, "confianza": confianza, "puntaje": puntaje,
                      "menciones": menciones, "motivos": motivos, "pertinente": es_pertinente(reg),
                      "contexto": extrae_contexto_uaf(reg)}, ensure_ascii=False, indent=2, default=json_default))


def diagnostico() -> None:
    print(json.dumps({
        "version": VERSION_MONITOR, "fuentes": len(FUENTES), "modo_recomendado": "conciliacion",
        "presupuesto_segundos": PRESUPUESTO_SEGUNDOS, "max_enriquecer": MAX_ENRIQUECER,
        "fuentes_por_tipo": dict(Counter(f["tipo"] for f in FUENTES)),
        "fuentes": [{"nombre": f["nombre"], "dominio": f["dominio"], "tipo": f["tipo"],
                     "feeds": len(f.get("feeds", [])), "sitemaps": len(f.get("sitemaps", [])),
                     "secciones": len(f.get("secciones", []))} for f in FUENTES],
    }, ensure_ascii=False, indent=2, default=json_default))


def prueba_correo() -> None:
    ahora = ahora_cl()
    muestra = {"uaf": True, "fecha_legible": ahora.strftime("%d/%m/%Y"), "medio": "Prueba técnica",
               "titulo": "Correo de prueba del Monitor UAF Chile", "contexto_uaf": "Configuración SMTP operativa.",
               "resumen": "", "link": "https://www.uaf.cl/"}
    estado = carga_estado()
    envia_correo([muestra], estado, "rapido")
    guarda_estado(estado)
    print("Prueba de correo ejecutada.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Monitor UAF Chile v7")
    ap.add_argument("--modo", choices=["rapido", "conciliacion"], default=MODO_ENV)
    ap.add_argument("--validar-fuentes", action="store_true")
    ap.add_argument("--probar-url", metavar="URL")
    ap.add_argument("--probar-deteccion", metavar="TEXTO")
    ap.add_argument("--probar-casos-control", action="store_true")
    ap.add_argument("--diagnostico", action="store_true")
    ap.add_argument("--probar-correo", action="store_true")
    args = ap.parse_args()
    if args.validar_fuentes:
        raise SystemExit(validar_fuentes_config())
    if args.probar_url:
        probar_url(args.probar_url); return
    if args.probar_deteccion:
        probar_deteccion(args.probar_deteccion); return
    if args.probar_casos_control:
        raise SystemExit(probar_casos_control())
    if args.diagnostico:
        diagnostico(); return
    if args.probar_correo:
        prueba_correo(); return
    carga_config()
    ejecutar(args.modo)


if __name__ == "__main__":
    main()
