#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
monitor_uaf.py — Vigilancia de fuentes para el Monitor UAF.

Consulta fuentes públicas sin API key, clasifica cada hallazgo y reescribe
datos.json. El dashboard lee ese archivo y se actualiza solo.

  python3 monitor_uaf.py              # una pasada
  python3 monitor_uaf.py --daemon     # vigila cada 15 min
  python3 monitor_uaf.py --intervalo 5 --daemon

Solo biblioteca estándar. Requiere Python 3.8+.
"""

import argparse
import copy
import hashlib
import html
import json
import os
import re
import smtplib
import ssl
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python 3.8 local: conserva el desfase fijo como respaldo
    ZoneInfo = None
from email.message import EmailMessage
from email.utils import formataddr

# ─────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.abspath(__file__))
SALIDA = os.path.join(BASE, "datos.json")
ESTADO = os.path.join(BASE, ".monitor_estado.json")
BITACORA = os.path.join(BASE, "monitor.log")
CONFIG = os.path.join(BASE, "config.json")

# Plantilla que se escribe si no existe config.json
CONFIG_EJEMPLO = {
    "correo": {
        "activo": False,
        "servidor": "smtp.gmail.com",
        "puerto": 587,
        "seguridad": "starttls",
        "usuario": "tu.correo@gmail.com",
        "clave": "clave-de-aplicacion-de-16-letras",
        "remitente_nombre": "Monitor UAF",
        "destinatarios": ["tu.correo@gmail.com"],
        "minimo_para_avisar": 1,
        "silencio_minutos": 60,
        "solo_si_menciona_uaf": False,
    }
}

VENTANA_DIAS = 30
UA = "Mozilla/5.0 (compatible; MonitorUAF/2.0; +https://github.com/)"
TIMEOUT = 25

# Huso de Chile continental con cambio automático de horario.
TZ_CL = ZoneInfo("America/Santiago") if ZoneInfo else timezone(timedelta(hours=-4))

# Conceptos vigilados. Google News recibe además el operador when:30d.
CONSULTAS_PRENSA = [
    # UAF Chile: se consulta con variantes explícitas y luego se valida contexto chileno.
    '"Unidad de Análisis Financiero" Chile',
    '"UAF Chile"',
    'site:uaf.cl "Unidad de Análisis Financiero"',
    '"Unidad de Análisis Financiero" "Ley 19.913"',
    'UAF lavado de activos Chile',

    # Dominio LA/FT chileno.
    '"lavado de activos" Chile',
    '"lavado de dinero" Chile',
    '"financiamiento del terrorismo" Chile',
    '"reporte de operaciones sospechosas" Chile',
    '"operaciones sospechosas" Chile',
    '"delitos precedentes" lavado Chile',
    '"Sistema de Inteligencia Económica" UAF Chile',
    'GAFILAT Chile',
    'GAFI Chile lavado de activos',
    'corrupción lavado de activos Chile',
    'narcotráfico lavado de activos Chile',
    'contrabando lavado de activos Chile',

    # Casos y fenómenos.
    '"Operación Tokio" Tren de Aragua',
    '"caso Sartor" formalización',

    # Sujetos obligados: regulación, vulneraciones y exposición a LA/FT.
    '("sujeto obligado" OR "entidad reportante" OR "oficial de cumplimiento") UAF Chile',
    '(bancos OR fintech OR "medios de pago" OR "transferencia de dinero") (UAF OR "lavado de activos") Chile',
    '(inmobiliarias OR notarios OR conservadores OR "corredores de propiedades") (UAF OR "lavado de activos") Chile',
    '(fondos OR corredoras OR seguros OR AFP) (UAF OR "lavado de activos" OR "debida diligencia") Chile',
    '(casinos OR automotoras OR factoring OR leasing) (UAF OR "lavado de activos") Chile',
    '("zonas francas" OR aduanas OR joyerías OR "metales preciosos") (UAF OR "lavado de activos") Chile',
]

# Solo se muestran redes con acceso automatizado público utilizable.
CONSULTAS_SOCIALES = [
    '"lavado de activos"',
    '"Unidad de Análisis Financiero"',
    'UAF Chile',
    '"financiamiento del terrorismo" Chile',
]
SUBREDDITS = ["chile"]
PLATAFORMAS = [
    {"id": "reddit", "nombre": "Reddit", "estado": "monitoreado",
     "nota": "Consulta pública JSON en r/chile; puede estar sujeta a límites de la plataforma."},
    {"id": "bluesky", "nombre": "Bluesky", "estado": "monitoreado",
     "nota": "API pública de búsqueda de publicaciones, sin autenticación."},
]

# ─────────────────────────────────────────────────────────────
# Taxonomías — clasificación por palabras clave
# ─────────────────────────────────────────────────────────────

FENOMENOS = {
    "sartor":   ["sartor", "azul azul", "michael clark", "larraín mery", "larrain mery", "tactical sport", "antumalal"],
    "tokio":    ["operación tokio", "operacion tokio", "tren de aragua", "pérez asencio", "perez asencio", "bexgroup", "bexdigital"],
    "trata":    ["trata de personas", "explotación sexual", "explotacion sexual", "calama"],
    "narco":    ["narcotráfico", "narcotrafico", "tráfico de drogas", "trafico de drogas", "microtráfico"],
    "normativa":["circular", "ley 19.913", "ley n°19.913", "inteligencia económica", "inteligencia economica", "secreto bancario", "21.595", "delitos económicos"],
    "corrupcion":["cohecho", "malversación", "malversacion", "fraude al fisco", "soborno", "probidad"],
}
FENOMENO_ETIQUETA = {
    "sartor": "Caso Sartor AGF",
    "tokio": "Operación Tokio · Tren de Aragua",
    "trata": "Trata de personas",
    "narco": "Narcotráfico",
    "normativa": "Marco normativo",
    "corrupcion": "Corrupción",
    "otro": "Otros",
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
    "investigacion":["reportaje", "ciper", "revela", "documentos internos", "filtr",
                     "investigacion periodistica", "segun pudo establecer"],
    "institucional":["nombra", "asume", "renuncia", "presupuesto", "dotacion",
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

# Delitos precedentes del lavado: el ilícito que origina los activos.
# Referencia: art. 27 Ley 19.913 y catálogo asociado.
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

# Encuadre: ¿el texto trata el lavado como eje, o es periférico?
ENCUADRE_NUCLEO = ["lavado de activos", "lavado de dinero", "blanqueo", "activos de origen ilícito",
                   "ruta del dinero", "operaciones sospechosas"]

MENCION_UAF = ["unidad de análisis financiero", "unidad de analisis financiero",
               r"\buaf\b", "análisis financiero (uaf)"]

# Señales para distinguir la UAF de Chile de unidades homónimas extranjeras.
MARCADORES_CHILE = [
    " chile", "chileno", "chilena", "santiago", "ley 19.913", "ley n 19.913",
    "uaf.cl", "uaf.gob.cl", "moneda 975", "comision para el mercado financiero",
    " cmf ", "ministerio publico", "fiscalia nacional", "fiscalia regional",
    "servicio de impuestos internos", " sii ", "pdi", "carabineros",
    "gafilat chile", "unidad de analisis financiero de chile", "uaf de chile",
    "uaf chile", "peso chileno", "pesos chilenos", " clp ", "unidad de fomento",
]

MARCADORES_UAF_EXTRANJERA = [
    "uaf panama", "uaf de panama", "unidad de analisis financiero de panama",
    "unidad de analisis financiero panama", "panama", "panameno", "panamena",
    "uaf peru", "uaf de peru", "unidad de inteligencia financiera del peru", "peru",
    "uaf paraguay", "seprelad", "paraguay", "uaf ecuador", "ecuador",
    "unidad de analisis financiero y economico", "uafe", "colombia", "uiaf",
    "republica dominicana", "uaf republica dominicana", "bolivia", "uif bolivia",
    "guatemala", "honduras", "el salvador", "costa rica", "nicaragua",
]

MEDIOS_CHILENOS = [
    "la tercera", "emol", "el mercurio", "diario financiero", "df mas", "pulso",
    "biobiochile", "radio bio bio", "cooperativa", "adn radio", "cnn chile",
    "24 horas", "t13", "tele13", "meganoticias", "chv noticias", "ciper",
    "el mostrador", "ex-ante", "interferencia", "the clinic", "soychile",
    "el desconcierto", "la segunda", "lun", "latercera", "fiscalia de chile",
    "cmf chile", "senado chile",
]

# Agrupación analítica de las 55 actividades obligadas a reportar a la UAF.
SUJETOS_OBLIGADOS = {
    "banca_finanzas": [
        "banco", "bancos", "institucion financiera", "cooperativa de ahorro",
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
    ],
    "inmobiliario_notarial": [
        "inmobiliaria", "gestion inmobiliaria", "corredor de propiedades",
        "corredora de propiedades", "notario", "notaria", "conservador de bienes raices",
        "conservador", "compraventa de inmueble", "mercado inmobiliario",
    ],
    "vehiculos_leasing_factoring": [
        "automotora", "comercializadora de vehiculos", "arriendo de vehiculos",
        "rent a car", "leasing", "arrendamiento financiero", "factoring", "factoraje",
    ],
    "casinos_deporte": [
        "casino de juego", "casino flotante", "hipodromo", "club de tiro", "club de caza",
        "club de pesca", "organizacion deportiva profesional", "club de futbol",
        "sociedad anonima deportiva", "sadp",
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
    "reportes": ["reporte de operaciones sospechosas", " reporte ros", " ros ",
                 "reporte de operaciones en efectivo", " roe ", "sujeto obligado", "reportante"],
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
    "economico": ["diario financiero", "df mas", "df más", "pulso", "bloomberg", "america economia",
                  "américa economía", "estrategia", "mercurio inversiones"],
    "television_radio": ["cnn chile", "24 horas", "t13", "meganoticias", "chv noticias",
                         "radio biobio", "radio bío bío", "cooperativa", "adn radio", "tele13"],
    "investigacion_digital": ["ciper", "interferencia", "el mostrador", "ex-ante", "el desconcierto",
                              "the clinic", "biobiochile"],
    "regional": ["soychile", "estrella de", "diario de atacama", "diario de concepcion",
                 "diario de concepción", "el austral", "el rancaguino", "el dia", "el día",
                 "la discusion", "la discusión", "el mercurio de valparaiso", "el mercurio de valparaíso"],
    "institucional": ["uaf", "gobierno", "ministerio", "fiscalia", "fiscalía", "pdi", "senado",
                      "camara", "cámara", "gafilat", "cmf"],
    "prensa_nacional": ["emol", "la tercera", "el mercurio", "latercera", "la segunda", "lun",
                        "las ultimas noticias", "las últimas noticias"],
}
TIPO_MEDIO_ETIQUETA = {
    "economico": "Prensa económica y financiera",
    "television_radio": "Televisión y radio",
    "investigacion_digital": "Medio digital o de investigación",
    "regional": "Prensa regional",
    "institucional": "Fuente institucional",
    "prensa_nacional": "Prensa nacional",
    "otro": "Otro medio digital",
}


# ─────────────────────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────────────────────

def log(msg):
    marca = datetime.now(TZ_CL).strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{marca}] {msg}"
    print(linea, flush=True)
    try:
        with open(BITACORA, "a", encoding="utf-8") as fh:
            fh.write(linea + "\n")
    except OSError:
        pass


def normaliza(texto):
    """Minúsculas sin tildes, para comparar sin sorpresas."""
    texto = texto.lower()
    texto = unicodedata.normalize("NFD", texto)
    texto = "".join(c for c in texto if unicodedata.category(c) != "Mn")
    return re.sub(r"\s+", " ", texto).strip()


def contiene(texto_norm, agujas):
    for a in agujas:
        if a.startswith(r"\b"):
            if re.search(a, texto_norm):
                return True
        elif normaliza(a) in texto_norm:
            return True
    return False


def descarga(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rss+xml, application/xml, text/xml, */*"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def limpia_html(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = (s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"')
           .replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">"))
    return re.sub(r"\s+", " ", s).strip()


def parsea_fecha(cadena):
    """RFC-822 de RSS → datetime en huso de Chile."""
    if not cadena:
        return None
    cadena = cadena.strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(cadena, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(TZ_CL)
        except ValueError:
            continue
    return None


def limpia_url(url):
    """Quita query y fragmento: ?utm_source=x no debe generar otro id."""
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def id_estable(url, titulo):
    return hashlib.sha1(normaliza(limpia_url(url) + "|" + titulo).encode("utf-8")).hexdigest()[:14]


# ─────────────────────────────────────────────────────────────
# Recolección
# ─────────────────────────────────────────────────────────────

def lee_rss(url, origen):
    """Devuelve lista de dicts crudos desde un feed RSS."""
    salida = []
    try:
        raiz = ET.fromstring(descarga(url))
    except Exception as e:
        log(f"  ! fallo en {origen}: {type(e).__name__}: {e}")
        return salida

    for item in raiz.iter("item"):
        def campo(t):
            n = item.find(t)
            return n.text if n is not None and n.text else ""

        titulo = limpia_html(campo("title"))
        enlace = (campo("link") or "").strip()
        if not titulo or not enlace:
            continue

        # Google News antepone el medio tras " - " al final del título
        medio = ""
        fuente_url = ""
        fuente = item.find("source")
        if fuente is not None and fuente.text:
            medio = fuente.text.strip()
            fuente_url = (fuente.get("url") or "").strip()
        elif " - " in titulo:
            titulo, medio = titulo.rsplit(" - ", 1)

        salida.append({
            "titulo": titulo.strip(),
            "link": enlace,
            "medio": medio.strip() or origen,
            "resumen": limpia_html(campo("description"))[:600],
            "fecha_dt": parsea_fecha(campo("pubDate")),
            "origen": origen,
            "fuente_url": fuente_url,
        })
    return salida


def recolecta_prensa():
    crudos = []
    for q in CONSULTAS_PRENSA:
        consulta = f"{q} when:{VENTANA_DIAS}d"
        url = ("https://news.google.com/rss/search?q="
               + urllib.parse.quote(consulta)
               + "&hl=es-419&gl=CL&ceid=CL:es-419")
        hallazgos = lee_rss(url, "Google News")
        log(f"  · «{q}» → {len(hallazgos)}")
        crudos.extend(hallazgos)
        time.sleep(1.0)
    return crudos


def recolecta_bluesky():
    """API pública de Bluesky: búsqueda de posts sin autenticación."""
    crudos = []
    for q in CONSULTAS_SOCIALES:
        url = ("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?limit=50&q="
               + urllib.parse.quote(q))
        try:
            datos = json.loads(descarga(url))
        except Exception as e:
            log(f"  ! fallo en Bluesky «{q}»: {type(e).__name__}")
            continue

        posts = datos.get("posts", [])
        for p in posts:
            rec = p.get("record", {})
            autor = p.get("author", {})
            handle = autor.get("handle", "")
            uri = p.get("uri", "")
            rkey = uri.rsplit("/", 1)[-1] if uri else ""
            crudos.append({
                "titulo": limpia_html(rec.get("text", ""))[:280],
                "link": f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else "",
                "medio": f"@{handle}",
                "resumen": "",
                "fecha_dt": parsea_fecha(rec.get("createdAt", "")),
                "origen": "Bluesky",
                "plataforma": "bluesky",
                "interacciones": (p.get("likeCount", 0) + p.get("repostCount", 0)
                                  + p.get("replyCount", 0)),
            })
        log(f"  · Bluesky «{q}» → {len(posts)}")
        time.sleep(1.0)
    return crudos


def recolecta_reddit():
    """Consulta JSON pública de Reddit; no incluye plataformas sin acceso automatizado."""
    crudos = []
    for sub in SUBREDDITS:
        for q in CONSULTAS_SOCIALES:
            url = (f"https://www.reddit.com/r/{sub}/search.json?q="
                   + urllib.parse.quote(q)
                   + "&restrict_sr=1&sort=new&t=month&limit=50&raw_json=1")
            try:
                datos = json.loads(descarga(url))
            except Exception as e:
                log(f"  ! fallo en Reddit r/{sub} «{q}»: {type(e).__name__}")
                continue
            hijos = datos.get("data", {}).get("children", [])
            for h in hijos:
                d = h.get("data", {})
                creado = d.get("created_utc")
                fecha_dt = datetime.fromtimestamp(creado, tz=timezone.utc).astimezone(TZ_CL) if creado else None
                permalink = d.get("permalink", "")
                crudos.append({
                    "titulo": limpia_html(d.get("title", ""))[:280],
                    "link": "https://www.reddit.com" + permalink if permalink else d.get("url", ""),
                    "medio": f"r/{sub}",
                    "resumen": limpia_html(d.get("selftext", ""))[:600],
                    "fecha_dt": fecha_dt,
                    "origen": "Reddit",
                    "plataforma": "reddit",
                    "interacciones": int(d.get("score", 0) or 0) + int(d.get("num_comments", 0) or 0),
                    "autor": d.get("author", ""),
                })
            log(f"  · Reddit r/{sub} «{q}» → {len(hijos)}")
            time.sleep(1.0)
    return crudos


def recolecta_social():
    return recolecta_reddit() + recolecta_bluesky()


# ─────────────────────────────────────────────────────────────
# Clasificación
# ─────────────────────────────────────────────────────────────

def clasifica_tipo_medio(medio):
    texto = normaliza(medio or "")
    for clave, agujas in TIPOS_MEDIO.items():
        if contiene(texto, agujas):
            return clave
    return "otro"


def _marcadores_presentes(texto, marcadores):
    encontrados = []
    for marcador in marcadores:
        m = normaliza(marcador)
        if not m:
            continue
        if len(m) <= 5 and " " not in m:
            coincide = re.search(r"\b" + re.escape(m) + r"\b", texto) is not None
        else:
            coincide = m in texto
        if coincide:
            encontrados.append(marcador)
    return encontrados


def analiza_uaf_chile(reg):
    """Determina si una mención corresponde específicamente a la UAF de Chile.

    Se prioriza precisión: una mención ambigua a «UAF» solo se acepta cuando existe
    una señal chilena en el texto o el medio. Las UAF extranjeras se excluyen salvo
    que el artículo también trate explícitamente a Chile.
    """
    texto = normaliza(reg.get("titulo", "") + " " + reg.get("resumen", ""))
    medio = normaliza(reg.get("medio", ""))
    fuente_url = normaliza(reg.get("fuente_url", "") + " " + reg.get("link", ""))
    if not contiene(texto, MENCION_UAF):
        return False, "sin_mencion", []

    chile_texto = _marcadores_presentes(texto, MARCADORES_CHILE)
    chile_medio = _marcadores_presentes(medio, MEDIOS_CHILENOS)
    extranjeros = _marcadores_presentes(texto + " " + medio, MARCADORES_UAF_EXTRANJERA)

    exacta = any(x in texto for x in (
        "unidad de analisis financiero de chile", "uaf de chile", "uaf chile",
        "unidad de analisis financiero (uaf) de chile",
    ))
    institucional = "uaf.cl" in fuente_url or "uaf.gob.cl" in fuente_url

    if extranjeros and not (exacta or chile_texto):
        return False, "uaf_extranjera", extranjeros[:4]
    if exacta or institucional:
        return True, "alta", list(dict.fromkeys(chile_texto + chile_medio + ["mencion_explicitamente_chilena"]))[:5]
    if chile_texto and chile_medio:
        return True, "alta", list(dict.fromkeys(chile_texto + chile_medio))[:5]
    if chile_texto:
        return True, "media", chile_texto[:5]
    if chile_medio and not extranjeros:
        return True, "media", chile_medio[:5]
    return False, "ambigua", []


def clasifica_sujetos_obligados(texto):
    sectores = [k for k, v in SUJETOS_OBLIGADOS.items() if contiene(texto, v)]
    impactos = [k for k, v in IMPACTO_SUJETO.items() if contiene(texto, v)] if sectores else []
    return sectores, impactos


def clasifica(reg):
    texto = normaliza(reg["titulo"] + " " + reg.get("resumen", ""))

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

    precedentes = [k for k, v in PRECEDENTES.items() if contiene(texto, v)]
    if not precedentes:
        precedentes = ["indeterminado"]

    topicos = [k for k, v in TOPICOS.items() if contiene(texto, v)]
    if not topicos:
        topicos = ["otros"]

    tipo_medio = clasifica_tipo_medio(reg.get("medio", ""))
    uaf_chile, confianza_uaf, motivos_uaf = analiza_uaf_chile(reg)
    sujetos, impactos = clasifica_sujetos_obligados(texto)
    if sujetos and "sujetos_obligados" not in topicos:
        topicos.append("sujetos_obligados")
    if sujetos and "vulneracion_la" in impactos and "vulneracion_sectorial" not in topicos:
        topicos.append("vulneracion_sectorial")

    reg["fenomeno"] = fenomeno
    reg["naturaleza"] = naturaleza
    reg["precedentes"] = precedentes
    reg["topicos"] = topicos
    reg["tipo_medio"] = tipo_medio
    reg["uaf"] = uaf_chile
    reg["uaf_chile"] = uaf_chile
    reg["uaf_confianza"] = confianza_uaf
    reg["uaf_motivos"] = motivos_uaf
    reg["sujetos_obligados"] = sujetos
    reg["impactos_sujeto"] = impactos
    reg["nucleo"] = contiene(texto, ENCUADRE_NUCLEO)
    return reg


def es_pertinente(reg):
    """Filtra ruido y excluye menciones a UAF extranjeras sin conexión chilena."""
    texto = normaliza(reg["titulo"] + " " + reg.get("resumen", ""))
    uaf_chile, estado_uaf, _ = analiza_uaf_chile(reg)
    menciona_alguna_uaf = contiene(texto, MENCION_UAF)
    if menciona_alguna_uaf and estado_uaf in {"uaf_extranjera", "ambigua"}:
        return False

    sectores, impactos = clasifica_sujetos_obligados(texto)
    dominio = ENCUADRE_NUCLEO + [
        "crimen organizado", "gafilat", "gafi", "delitos economicos",
        "financiamiento del terrorismo", "sartor", "tren de aragua",
        "reporte de operaciones sospechosas", "delitos precedentes", "secreto bancario",
        "beneficiario final", "debida diligencia", "persona expuesta politicamente",
    ]
    sujeto_relevante = bool(sectores and impactos and contiene(texto, dominio + [
        "oficial de cumplimiento", "sujeto obligado", "entidad reportante", "uaf chile",
    ]))
    return uaf_chile or contiene(texto, dominio) or sujeto_relevante


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
        return datetime.strptime(f"{reg['fecha']} {reg.get('hora', '00:00')}", "%Y-%m-%d %H:%M").replace(tzinfo=TZ_CL)
    except (KeyError, ValueError):
        return None


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
    salida = []
    for k, n in sorted(conteo.items(), key=lambda x: (-x[1], str(x[0]))):
        salida.append({"clave": k, "label": etiqueta.get(k, k) if etiqueta else k, "n": n})
    return salida


def calcula_metricas(prensa, social, dias, ahora):
    total = len(prensa)
    uaf_prensa = [r for r in prensa if r.get("uaf")]
    contexto = [r for r in prensa if not r.get("uaf")]

    por_dia = {d: {"total": 0, "uaf": 0, "contexto": 0} for d in dias}
    for r in prensa:
        if r["fecha"] in por_dia:
            por_dia[r["fecha"]]["total"] += 1
            por_dia[r["fecha"]]["uaf" if r.get("uaf") else "contexto"] += 1

    corte24 = ahora - timedelta(hours=24)
    corte48 = ahora - timedelta(hours=48)
    corte5 = ahora - timedelta(days=5)
    uaf24 = [r for r in uaf_prensa if (_fecha_registro(r) or datetime.min.replace(tzinfo=TZ_CL)) >= corte24]
    uaf_prev24 = [r for r in uaf_prensa if corte48 <= (_fecha_registro(r) or datetime.min.replace(tzinfo=TZ_CL)) < corte24]
    uaf5 = [r for r in uaf_prensa if (_fecha_registro(r) or datetime.min.replace(tzinfo=TZ_CL)) >= corte5]
    actual, previo = len(uaf24), len(uaf_prev24)
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
    sujetos_obligados = _ranking(prensa, "sujetos_obligados", SUJETO_OBLIGADO_ETIQUETA)
    impactos_sujeto = _ranking(prensa, "impactos_sujeto", IMPACTO_SUJETO_ETIQUETA)

    # Cronología y semanas para los 30 días.
    cronologia = []
    for f in fenomenos:
        celdas = []
        for d in dias:
            rs = [r for r in prensa if r["fenomeno"] == f["clave"] and r["fecha"] == d]
            celdas.append({"dia": d, "n": len(rs), "medios": sorted({r["medio"] for r in rs})})
        cronologia.append({"clave": f["clave"], "label": f["label"], "celdas": celdas, "total": f["n"]})

    semanas = []
    bloque = []
    for dia in dias:
        bloque.append(dia)
        if datetime.strptime(dia, "%Y-%m-%d").weekday() == 6 or dia == dias[-1]:
            regs = [r for r in prensa if r["fecha"] in bloque]
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
            "interacciones": sum(s.get("interacciones", 0) for s in posts),
        })
        plataformas.append(base)

    detalle_uaf24 = []
    for r in sorted(uaf24, key=lambda x: (_fecha_registro(x) or corte48), reverse=True):
        detalle_uaf24.append({k: r.get(k) for k in (
            "id", "fecha", "hora", "fecha_iso", "medio", "tipo_medio", "tipo_medio_label",
            "titulo", "resumen", "link", "fenomeno", "fenomeno_label", "naturaleza",
            "naturaleza_label", "precedentes", "precedentes_label", "topicos", "topicos_label",
            "sujetos_obligados", "sujetos_obligados_label", "impactos_sujeto", "impactos_sujeto_label",
            "uaf_confianza", "uaf_motivos"
        )})

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
            "detalle": detalle_uaf24,
        },
        "uaf_total": len(uaf_prensa),
        "uaf_prensa": len(uaf_prensa),
        "uaf_social": sum(1 for r in social if r.get("uaf")),
        "uaf_donde": detalle_uaf24[:8],
        "contexto_total": len(contexto),
        "volumen": total,
        "volumen_hoy": por_dia[dias[-1]]["total"],
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
        "sujetos_obligados": sujetos_obligados,
        "impactos_sujeto": impactos_sujeto,
        "cronologia": cronologia,
        "por_dia": por_dia,
        "semanas": semanas,
        "rankings_30d": {
            "medios": medios[:12],
            "fenomenos": [x for x in fenomenos if x["clave"] != "otro"][:12],
            "precedentes": [x for x in precedentes if x["clave"] != "indeterminado"][:12],
            "sujetos_obligados": sujetos_obligados[:12],
            "impactos_sujeto": impactos_sujeto[:12],
        },
        "plataformas": plataformas,
        "social_total": len(social),
        "social_monitoreadas": len(plataformas),
        "social_sin_acceso": 0,
    }


# ─────────────────────────────────────────────────────────────
# Configuración y correo
# ─────────────────────────────────────────────────────────────

def _env_bool(nombre, defecto=False):
    valor = os.getenv(nombre)
    if valor is None or valor == "":
        return defecto
    return valor.strip().lower() in {"1", "true", "si", "sí", "yes", "on"}


def _env_int(nombre, defecto):
    valor = os.getenv(nombre)
    if valor is None or valor == "":
        return defecto
    try:
        return int(valor)
    except ValueError:
        log(f"! variable {nombre} inválida; se usa {defecto}")
        return defecto


def carga_config():
    """Carga config.json y permite sobrescribir correo mediante variables de entorno."""
    config = copy.deepcopy(CONFIG_EJEMPLO)
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as fh:
                usuario = json.load(fh)
            config["correo"].update(usuario.get("correo", {}))
        except (OSError, json.JSONDecodeError) as e:
            log(f"! no se pudo leer config.json: {type(e).__name__}: {e}")
    elif not os.getenv("GITHUB_ACTIONS"):
        try:
            with open(CONFIG, "w", encoding="utf-8") as fh:
                json.dump(config, fh, ensure_ascii=False, indent=2)
            log("Se creó config.json con el correo desactivado.")
        except OSError as e:
            log(f"! no se pudo crear config.json: {e}")

    c = config["correo"]
    c["activo"] = _env_bool("MONITOR_CORREO_ACTIVO", bool(c.get("activo", False)))
    c["servidor"] = os.getenv("MONITOR_SMTP_SERVIDOR", c.get("servidor", ""))
    c["puerto"] = _env_int("MONITOR_SMTP_PUERTO", int(c.get("puerto", 587)))
    c["seguridad"] = os.getenv("MONITOR_SMTP_SEGURIDAD", c.get("seguridad", "starttls"))
    c["usuario"] = os.getenv("MONITOR_SMTP_USUARIO", c.get("usuario", ""))
    c["clave"] = os.getenv("MONITOR_SMTP_CLAVE", c.get("clave", ""))
    c["remitente_nombre"] = os.getenv("MONITOR_REMITENTE_NOMBRE", c.get("remitente_nombre", "Monitor UAF"))
    destinos = os.getenv("MONITOR_DESTINATARIOS")
    if destinos:
        c["destinatarios"] = [x.strip() for x in destinos.split(",") if x.strip()]
    c["minimo_para_avisar"] = _env_int("MONITOR_MINIMO_AVISO", int(c.get("minimo_para_avisar", 1)))
    c["silencio_minutos"] = _env_int("MONITOR_SILENCIO_MINUTOS", int(c.get("silencio_minutos", 60)))
    c["solo_si_menciona_uaf"] = _env_bool("MONITOR_SOLO_UAF", bool(c.get("solo_si_menciona_uaf", False)))
    return config


def _conecta_smtp(c):
    servidor = c.get("servidor", "")
    puerto = int(c.get("puerto", 587))
    seguridad = str(c.get("seguridad", "starttls")).lower()
    contexto = ssl.create_default_context()
    if seguridad in {"ssl", "smtps"}:
        smtp = smtplib.SMTP_SSL(servidor, puerto, timeout=30, context=context)
    else:
        smtp = smtplib.SMTP(servidor, puerto, timeout=30)
        smtp.ehlo()
        if seguridad == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
    usuario = c.get("usuario", "")
    clave = c.get("clave", "")
    if usuario and clave:
        smtp.login(usuario, clave)
    return smtp


def _manda_mensaje(c, asunto, html, texto):
    destinatarios = c.get("destinatarios") or []
    usuario = c.get("usuario", "")
    if not c.get("servidor") or not usuario or not destinatarios:
        raise ValueError("faltan servidor, usuario o destinatarios de correo")
    msg = EmailMessage()
    msg["Subject"] = asunto
    msg["From"] = formataddr((c.get("remitente_nombre", "Monitor UAF"), usuario))
    msg["To"] = ", ".join(destinatarios)
    msg.set_content(texto)
    msg.add_alternative(html, subtype="html")
    with _conecta_smtp(c) as smtp:
        smtp.send_message(msg)


def envia_correo(config, nuevos, metricas):
    c = config.get("correo", {})
    if not c.get("activo"):
        return False
    candidatos = [n for n in nuevos if n.get("uaf")] if c.get("solo_si_menciona_uaf") else list(nuevos)
    minimo = max(1, int(c.get("minimo_para_avisar", 1)))
    if len(candidatos) < minimo:
        log(f"Correo omitido: {len(candidatos)} menciones relevantes; mínimo {minimo}.")
        return False

    estado = carga_estado()
    ultimo = estado.get("ultimo_correo")
    if ultimo:
        try:
            anterior = datetime.fromisoformat(ultimo)
            if anterior.tzinfo is None:
                anterior = anterior.replace(tzinfo=TZ_CL)
            silencio = timedelta(minutes=max(0, int(c.get("silencio_minutos", 60))))
            if datetime.now(TZ_CL) - anterior < silencio:
                log("Correo omitido por período de silencio.")
                return False
        except ValueError:
            pass

    filas = []
    for n in candidatos[:20]:
        filas.append(
            '<li style="margin:0 0 12px">'
            f'<b>{html.escape(n["medio"])}</b> · {n["fecha"]} {n["hora"]}<br>'
            f'<a href="{html.escape(n["link"], quote=True)}">{html.escape(n["titulo"])}</a></li>'
        )
    asunto = f"Monitor UAF: {len(candidatos)} nueva{'s' if len(candidatos) != 1 else ''} mención{'es' if len(candidatos) != 1 else ''}"
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:760px">'
        f'<h2>{asunto}</h2><p>Noticias en la ventana: <b>{metricas.get("volumen", 0)}</b>. '
        f'Menciones a la UAF: <b>{metricas.get("uaf_total", 0)}</b>.</p>'
        f'<ol>{"".join(filas)}</ol></div>'
    )
    texto = asunto + "\n\n" + "\n".join(
        f'- {n["medio"]}: {n["titulo"]} ({n["link"]})' for n in candidatos[:20]
    )
    try:
        _manda_mensaje(c, asunto, html, texto)
    except Exception as e:
        log(f"! fallo al enviar correo: {type(e).__name__}: {e}")
        return False
    estado["ultimo_correo"] = datetime.now(TZ_CL).isoformat()
    guarda_estado(estado)
    log(f"Correo enviado a {len(c.get('destinatarios', []))} destinatario(s).")
    return True


def prueba_correo():
    c = carga_config().get("correo", {})
    asunto = "Prueba del Monitor UAF"
    try:
        _manda_mensaje(c, asunto, "<p>La configuración SMTP del Monitor UAF funciona.</p>",
                       "La configuración SMTP del Monitor UAF funciona.")
    except Exception as e:
        log(f"! prueba de correo fallida: {type(e).__name__}: {e}")
        raise SystemExit(1)
    log("Correo de prueba enviado correctamente.")


# ─────────────────────────────────────────────────────────────
# Ciclo principal
# ─────────────────────────────────────────────────────────────

def carga_estado():
    if os.path.exists(ESTADO):
        try:
            with open(ESTADO, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {"vistos": []}


def guarda_estado(estado):
    estado["vistos"] = estado["vistos"][-12000:]
    with open(ESTADO, "w", encoding="utf-8") as fh:
        json.dump(estado, fh, ensure_ascii=False)


def carga_datos_previos():
    if not os.path.exists(SALIDA):
        return {"prensa": [], "social": []}
    try:
        with open(SALIDA, encoding="utf-8") as fh:
            datos = json.load(fh)
        return {"prensa": datos.get("prensa", []), "social": datos.get("social", [])}
    except (OSError, json.JSONDecodeError):
        return {"prensa": [], "social": []}


def enriquece_historico(reg):
    """Reclasifica noticias históricas con las reglas vigentes.

    Esto permite corregir registros creados por versiones anteriores, incluidos
    falsos positivos de UAF extranjeras y nuevas categorías de sujetos obligados.
    """
    r = dict(reg)
    dt = _fecha_registro(r)
    if dt and not r.get("fecha_iso"):
        r["fecha_iso"] = dt.isoformat()

    crudo = {
        "titulo": r.get("titulo", ""),
        "resumen": r.get("resumen", ""),
        "medio": r.get("medio", ""),
        "fuente_url": r.get("fuente_url", ""),
        "link": r.get("link", ""),
    }
    enriquecido = clasifica(crudo)
    r.update({
        "fenomeno": enriquecido["fenomeno"],
        "naturaleza": enriquecido["naturaleza"],
        "precedentes": enriquecido["precedentes"],
        "topicos": enriquecido["topicos"],
        "tipo_medio": enriquecido["tipo_medio"],
        "uaf": enriquecido["uaf"],
        "uaf_chile": enriquecido["uaf_chile"],
        "uaf_confianza": enriquecido["uaf_confianza"],
        "uaf_motivos": enriquecido["uaf_motivos"],
        "sujetos_obligados": enriquecido["sujetos_obligados"],
        "impactos_sujeto": enriquecido["impactos_sujeto"],
        "nucleo": enriquecido["nucleo"],
    })
    r["topicos_label"] = [TOPICO_ETIQUETA.get(t, t) for t in r.get("topicos", ["otros"])]
    r["tipo_medio_label"] = TIPO_MEDIO_ETIQUETA.get(r.get("tipo_medio", "otro"), "Otro medio digital")
    r["sujetos_obligados_label"] = [SUJETO_OBLIGADO_ETIQUETA.get(x, x) for x in r.get("sujetos_obligados", [])]
    r["impactos_sujeto_label"] = [IMPACTO_SUJETO_ETIQUETA.get(x, x) for x in r.get("impactos_sujeto", [])]
    r["fenomeno_label"] = FENOMENO_ETIQUETA.get(r.get("fenomeno", "otro"), "Otros")
    r["naturaleza_label"] = NATURALEZA_ETIQUETA.get(r.get("naturaleza", "analisis"), "Análisis y opinión")
    r["precedentes_label"] = [PRECEDENTE_ETIQUETA.get(x, x) for x in r.get("precedentes", ["indeterminado"])]
    return r


def mezcla_historico(previos, actuales, corte):
    combinados = {}
    for original in list(previos) + list(actuales):
        crudo = {
            "titulo": original.get("titulo", ""),
            "resumen": original.get("resumen", ""),
            "medio": original.get("medio", ""),
            "fuente_url": original.get("fuente_url", ""),
            "link": original.get("link", ""),
        }
        if not es_pertinente(crudo):
            continue
        r = enriquece_historico(original)
        rid = r.get("id")
        if not rid:
            continue
        dt = _fecha_registro(r)
        if not dt or dt < corte:
            continue
        combinados[rid] = r
    return sorted(combinados.values(), key=lambda r: (_fecha_registro(r) or corte), reverse=True)


def pasada():
    ahora = datetime.now(TZ_CL)
    corte = (ahora - timedelta(days=VENTANA_DIAS)).replace(second=0, microsecond=0)
    primer_dia = (ahora - timedelta(days=VENTANA_DIAS - 1)).date()
    dias = [(primer_dia + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(VENTANA_DIAS)]

    previos = carga_datos_previos()
    log("Recolectando prensa…")
    crudos = recolecta_prensa()
    log("Recolectando señal social con acceso público…")
    crudos_soc = recolecta_social()

    if not crudos and not crudos_soc and os.path.exists(SALIDA):
        log("! ninguna fuente respondió; se conserva el último datos.json")
        return 0

    estado = carga_estado()
    vistos = set(estado.get("vistos", []))
    nuevos = []

    def procesa(lote, canal):
        salida, dedup = [], set()
        for r in lote:
            if not r.get("fecha_dt") or r["fecha_dt"] < corte:
                continue
            if not es_pertinente(r):
                continue
            clave = id_estable(r["link"], r["titulo"])
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
                "medio": r["medio"],
                "fuente_url": r.get("fuente_url", ""),
                "tipo_medio": r["tipo_medio"],
                "tipo_medio_label": TIPO_MEDIO_ETIQUETA.get(r["tipo_medio"], "Otro medio digital"),
                "titulo": r["titulo"],
                "resumen": r.get("resumen", ""),
                "link": r["link"],
                "fenomeno": r["fenomeno"],
                "fenomeno_label": FENOMENO_ETIQUETA.get(r["fenomeno"], "Otros"),
                "naturaleza": r["naturaleza"],
                "naturaleza_label": NATURALEZA_ETIQUETA.get(r["naturaleza"], "Análisis y opinión"),
                "precedentes": r.get("precedentes", ["indeterminado"]),
                "precedentes_label": [PRECEDENTE_ETIQUETA.get(p, p) for p in r.get("precedentes", ["indeterminado"])],
                "topicos": r.get("topicos", ["otros"]),
                "topicos_label": [TOPICO_ETIQUETA.get(t, t) for t in r.get("topicos", ["otros"])],
                "sujetos_obligados": r.get("sujetos_obligados", []),
                "sujetos_obligados_label": [SUJETO_OBLIGADO_ETIQUETA.get(t, t) for t in r.get("sujetos_obligados", [])],
                "impactos_sujeto": r.get("impactos_sujeto", []),
                "impactos_sujeto_label": [IMPACTO_SUJETO_ETIQUETA.get(t, t) for t in r.get("impactos_sujeto", [])],
                "uaf_chile": r.get("uaf_chile", r["uaf"]),
                "uaf_confianza": r.get("uaf_confianza", "media"),
                "uaf_motivos": r.get("uaf_motivos", []),
                "plataforma": r.get("plataforma"),
                "interacciones": r.get("interacciones", 0),
                "uaf": r["uaf"],
                "nucleo": r["nucleo"],
            }
            if clave not in vistos:
                registro["nuevo"] = True
                nuevos.append(registro)
                vistos.add(clave)
            salida.append(registro)
        return salida

    prensa_actual = procesa(crudos, "prensa")
    social_actual = procesa(crudos_soc, "social")
    prensa = mezcla_historico(previos.get("prensa", []), prensa_actual, corte)
    social = mezcla_historico(previos.get("social", []), social_actual, corte)

    metricas = calcula_metricas(prensa, social, dias, ahora)
    salida = {
        "generado": ahora.isoformat(),
        "generado_legible": ahora.strftime("%d/%m/%Y %H:%M"),
        "ventana": {"dias": dias, "hoy": ahora.strftime("%Y-%m-%d"), "largo": VENTANA_DIAS},
        "metricas": metricas,
        "prensa": prensa,
        "social": social,
        "nuevos": len(nuevos),
        "consultas": len(CONSULTAS_PRENSA) + len(CONSULTAS_SOCIALES) * (len(SUBREDDITS) + 1),
    }

    temporal = SALIDA + ".tmp"
    with open(temporal, "w", encoding="utf-8") as fh:
        json.dump(salida, fh, ensure_ascii=False, indent=1)
    os.replace(temporal, SALIDA)

    estado["vistos"] = list(vistos)
    guarda_estado(estado)

    log(f"Listo: {len(prensa)} menciones/noticias de prensa · {len(social)} sociales · {len(nuevos)} nuevas → {SALIDA}")
    for n in nuevos[:12]:
        log(f"   NUEVA [{n['canal']}] {n['medio']} — {n['titulo'][:88]}")

    if nuevos:
        envia_correo(carga_config(), nuevos, metricas)
    return len(nuevos)


def main():
    ap = argparse.ArgumentParser(description="Vigilancia de fuentes para el Monitor UAF")
    ap.add_argument("--daemon", action="store_true", help="vigila en bucle")
    ap.add_argument("--intervalo", type=int, default=15, help="minutos entre pasadas (por defecto 15)")
    ap.add_argument("--probar-correo", action="store_true", help="envía un correo de prueba y sale")
    args = ap.parse_args()

    if args.probar_correo:
        prueba_correo()
        return

    carga_config()  # crea config.json en el primer arranque

    if not args.daemon:
        pasada()
        return

    log(f"Vigilancia activa · cada {args.intervalo} min · Ctrl+C para detener")
    while True:
        try:
            pasada()
        except KeyboardInterrupt:
            log("Detenido.")
            return
        except Exception as e:
            log(f"! error en la pasada: {type(e).__name__}: {e}")
        time.sleep(args.intervalo * 60)


if __name__ == "__main__":
    main()
