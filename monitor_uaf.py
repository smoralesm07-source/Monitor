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

VENTANA_DIAS = 5
UA = "Mozilla/5.0 (compatible; MonitorUAF/1.0)"
TIMEOUT = 25

# Huso de Chile continental con cambio automático de horario.
TZ_CL = ZoneInfo("America/Santiago") if ZoneInfo else timezone(timedelta(hours=-4))

# Conceptos vigilados. Cada consulta se lanza contra Google News RSS.
CONSULTAS_PRENSA = [
    '"Unidad de Análisis Financiero"',
    'UAF lavado de activos Chile',
    '"lavado de activos" Chile',
    '"Operación Tokio" Tren de Aragua',
    '"caso Sartor" formalización',
    '"financiamiento del terrorismo" Chile',
    '"Sistema de Inteligencia Económica" UAF',
    '"reporte de operaciones sospechosas"',
    'GAFILAT Chile',
]

# Fuentes sociales públicas sin autenticación.
CONSULTAS_SOCIALES = [
    '"lavado de activos"',
    '"Unidad de Análisis Financiero"',
    'UAF Chile',
    '"caso Sartor"',
]
SUBREDDITS = ["chile"]

# Estado de cada plataforma. Distingue dos situaciones que no hay que confundir:
#   monitoreado    → la consultamos y sabemos si hay o no figuración
#   sin_acceso     → no la podemos consultar; la ausencia de datos no dice nada
PLATAFORMAS = [
    {"id": "reddit",   "nombre": "Reddit",           "estado": "monitoreado",
     "nota": "Búsqueda pública vía RSS en r/chile. Sin autenticación."},
    {"id": "bluesky",  "nombre": "Bluesky",          "estado": "monitoreado",
     "nota": "API pública de búsqueda de posts. Sin autenticación."},
    {"id": "x",        "nombre": "X (Twitter)",      "estado": "sin_acceso",
     "nota": "La búsqueda exige API de pago desde 2023. Sin ella no se puede afirmar "
             "que haya o no figuración."},
    {"id": "instagram","nombre": "Instagram",        "estado": "sin_acceso",
     "nota": "Graph API solo entrega datos de cuentas propias verificadas. "
             "No permite búsqueda por palabra clave."},
    {"id": "facebook", "nombre": "Facebook",         "estado": "sin_acceso",
     "nota": "CrowdTangle cerró en agosto de 2024. El reemplazo está restringido "
             "a investigadores acreditados."},
    {"id": "tiktok",   "nombre": "TikTok",           "estado": "sin_acceso",
     "nota": "Research API limitada a instituciones académicas aprobadas."},
    {"id": "linkedin", "nombre": "LinkedIn",         "estado": "sin_acceso",
     "nota": "Sin API de búsqueda pública. Es donde circula el debate de "
             "cumplimiento, así que es un punto ciego relevante."},
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
        fuente = item.find("source")
        if fuente is not None and fuente.text:
            medio = fuente.text.strip()
        elif " - " in titulo:
            titulo, medio = titulo.rsplit(" - ", 1)

        salida.append({
            "titulo": titulo.strip(),
            "link": enlace,
            "medio": medio.strip() or origen,
            "resumen": limpia_html(campo("description"))[:600],
            "fecha_dt": parsea_fecha(campo("pubDate")),
            "origen": origen,
        })
    return salida


def recolecta_prensa():
    crudos = []
    for q in CONSULTAS_PRENSA:
        url = ("https://news.google.com/rss/search?q="
               + urllib.parse.quote(q)
               + "&hl=es-419&gl=CL&ceid=CL:es-419")
        hallazgos = lee_rss(url, "Google News")
        log(f"  · «{q}» → {len(hallazgos)}")
        crudos.extend(hallazgos)
        time.sleep(1.2)  # cortesía con el servidor
    return crudos


def recolecta_bluesky():
    """API pública de Bluesky: búsqueda de posts sin autenticación."""
    crudos = []
    for q in CONSULTAS_SOCIALES:
        url = ("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?limit=25&q="
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
                "titulo": limpia_html(rec.get("text", ""))[:220],
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
        time.sleep(1.2)
    return crudos


def recolecta_social():
    crudos = []
    for sub in SUBREDDITS:
        for q in CONSULTAS_SOCIALES:
            url = (f"https://www.reddit.com/r/{sub}/search.rss?q="
                   + urllib.parse.quote(q)
                   + "&restrict_sr=1&sort=new&t=week")
            try:
                raiz = ET.fromstring(descarga(url))
            except Exception as e:
                log(f"  ! fallo en r/{sub} «{q}»: {type(e).__name__}")
                continue

            ns = {"a": "http://www.w3.org/2005/Atom"}
            entradas = raiz.findall("a:entry", ns)
            for e in entradas:
                t = e.find("a:title", ns)
                l = e.find("a:link", ns)
                u = e.find("a:updated", ns)
                au = e.find("a:author/a:name", ns)
                if t is None or l is None:
                    continue
                crudos.append({
                    "titulo": limpia_html(t.text),
                    "link": l.get("href", ""),
                    "medio": f"r/{sub}",
                    "resumen": "",
                    "fecha_dt": parsea_fecha(u.text if u is not None else ""),
                    "origen": "Reddit",
                    "plataforma": "reddit",
                    "interacciones": 0,
                    "autor": au.text if au is not None else "",
                })
            log(f"  · r/{sub} «{q}» → {len(entradas)}")
            time.sleep(1.2)
    return crudos


# ─────────────────────────────────────────────────────────────
# Clasificación
# ─────────────────────────────────────────────────────────────

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

    # Un caso puede tener varios delitos precedentes a la vez.
    precedentes = [k for k, v in PRECEDENTES.items() if contiene(texto, v)]
    if not precedentes:
        precedentes = ["indeterminado"]

    reg["fenomeno"] = fenomeno
    reg["naturaleza"] = naturaleza
    reg["precedentes"] = precedentes
    reg["uaf"] = contiene(texto, MENCION_UAF)
    reg["nucleo"] = contiene(texto, ENCUADRE_NUCLEO)
    return reg


def es_pertinente(reg):
    """Filtra ruido: debe tocar el dominio LA/FT."""
    texto = normaliza(reg["titulo"] + " " + reg.get("resumen", ""))
    disparadores = ENCUADRE_NUCLEO + MENCION_UAF + [
        "crimen organizado", "gafilat", "gafi", "delitos economicos",
        "financiamiento del terrorismo", "sartor", "tren de aragua",
    ]
    return contiene(texto, disparadores)


# ─────────────────────────────────────────────────────────────
# Métricas
# ─────────────────────────────────────────────────────────────

def calcula_metricas(prensa, social, dias):
    total = len(prensa)
    todo = prensa + social

    por_dia = {d: 0 for d in dias}
    for r in prensa:
        if r["fecha"] in por_dia:
            por_dia[r["fecha"]] += 1

    # ── Registro UAF: el indicador principal ──
    uaf_prensa = [r for r in prensa if r.get("uaf")]
    uaf_social = [r for r in social if r.get("uaf")]
    uaf_total = len(uaf_prensa) + len(uaf_social)

    # Desglose de fenómenos con detalle
    fen = {}
    for r in prensa:
        f = fen.setdefault(r["fenomeno"], {
            "clave": r["fenomeno"], "label": FENOMENO_ETIQUETA.get(r["fenomeno"], "Otros"),
            "n": 0, "medios": set(), "dias": set(), "uaf": 0, "precedentes": set(),
        })
        f["n"] += 1
        f["medios"].add(r["medio"])
        f["dias"].add(r["fecha"])
        if r.get("uaf"):
            f["uaf"] += 1
        for p in r.get("precedentes", []):
            f["precedentes"].add(p)

    fenomenos = sorted(
        ({"clave": v["clave"], "label": v["label"], "n": v["n"],
          "medios": len(v["medios"]), "dias": sorted(v["dias"]), "uaf": v["uaf"],
          "precedentes": [PRECEDENTE_ETIQUETA.get(p, p) for p in sorted(v["precedentes"])]}
         for v in fen.values()),
        key=lambda x: -x["n"])

    # Delitos precedentes — un registro puede aportar a varios
    prec = {}
    for r in prensa:
        for p in r.get("precedentes", []):
            prec[p] = prec.get(p, 0) + 1
    precedentes = sorted(
        ({"clave": k, "label": PRECEDENTE_ETIQUETA.get(k, k), "n": v} for k, v in prec.items()),
        key=lambda x: -x["n"])

    # Tipo de información
    nat = {}
    for r in prensa:
        nat[r["naturaleza"]] = nat.get(r["naturaleza"], 0) + 1
    naturalezas = sorted(
        ({"clave": k, "label": NATURALEZA_ETIQUETA.get(k, k), "n": v} for k, v in nat.items()),
        key=lambda x: -x["n"])

    # Cronología: matriz caso × día
    cronologia = []
    for f in fenomenos:
        celdas = []
        for d in dias:
            n = sum(1 for r in prensa if r["fenomeno"] == f["clave"] and r["fecha"] == d)
            medios = sorted({r["medio"] for r in prensa
                             if r["fenomeno"] == f["clave"] and r["fecha"] == d})
            celdas.append({"dia": d, "n": n, "medios": medios})
        cronologia.append({"clave": f["clave"], "label": f["label"], "celdas": celdas,
                           "total": f["n"]})

    # Estado por plataforma social
    plataformas = []
    for p in PLATAFORMAS:
        base = dict(p)
        if p["estado"] == "monitoreado":
            posts = [s for s in social if s.get("plataforma") == p["id"]]
            base["menciones"] = len(posts)
            base["menciones_uaf"] = sum(1 for s in posts if s.get("uaf"))
            base["interacciones"] = sum(s.get("interacciones", 0) for s in posts)
        else:
            base["menciones"] = None
            base["menciones_uaf"] = None
            base["interacciones"] = None
        plataformas.append(base)

    monitoreadas = [p for p in plataformas if p["estado"] == "monitoreado"]

    return {
        # Indicador principal
        "uaf_total": uaf_total,
        "uaf_prensa": len(uaf_prensa),
        "uaf_social": len(uaf_social),
        "uaf_donde": [{"medio": r["medio"], "fecha": r["fecha"], "titulo": r["titulo"],
                       "link": r["link"], "canal": r["canal"]}
                      for r in (uaf_prensa + uaf_social)][:6],

        # Conteos concretos
        "volumen": total,
        "volumen_hoy": por_dia[dias[-1]],
        "dias_con_actividad": sum(1 for d in dias if por_dia[d] > 0),
        "dias_ventana": len(dias),
        "medios_unicos": len({r["medio"] for r in prensa}),
        "casos_activos": len(fenomenos),
        "precedentes_distintos": len([p for p in precedentes if p["clave"] != "indeterminado"]),

        # Desgloses
        "fenomenos": fenomenos,
        "precedentes": precedentes,
        "naturalezas": naturalezas,
        "cronologia": cronologia,
        "por_dia": por_dia,

        # Redes
        "plataformas": plataformas,
        "social_total": len(social),
        "social_monitoreadas": len(monitoreadas),
        "social_sin_acceso": len(plataformas) - len(monitoreadas),
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
        log(f"Correo omitido: {len(candidatos)} hallazgos relevantes; mínimo {minimo}.")
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
    asunto = f"Monitor UAF: {len(candidatos)} nuevo{'s' if len(candidatos) != 1 else ''} hallazgo{'s' if len(candidatos) != 1 else ''}"
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:760px">'
        f'<h2>{asunto}</h2><p>Registros en la ventana: <b>{metricas.get("volumen", 0)}</b>. '
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
    estado["vistos"] = estado["vistos"][-4000:]
    with open(ESTADO, "w", encoding="utf-8") as fh:
        json.dump(estado, fh, ensure_ascii=False)


def pasada():
    ahora = datetime.now(TZ_CL)
    corte = (ahora - timedelta(days=VENTANA_DIAS - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    dias = [(corte + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(VENTANA_DIAS)]

    log("Recolectando prensa…")
    crudos = recolecta_prensa()
    log("Recolectando señal social…")
    crudos_soc = recolecta_social() + recolecta_bluesky()

    # Si todas las fuentes fallan, conserva el último corte publicado.
    if not crudos and not crudos_soc and os.path.exists(SALIDA):
        log("! ninguna fuente respondió; se conserva el último datos.json")
        return 0

    estado = carga_estado()
    vistos = set(estado["vistos"])
    nuevos = []

    def procesa(lote, canal):
        salida, dedup = [], set()
        for r in lote:
            if not r["fecha_dt"] or r["fecha_dt"] < corte:
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
                "medio": r["medio"],
                "titulo": r["titulo"],
                "resumen": r.get("resumen", ""),
                "link": r["link"],
                "fenomeno": r["fenomeno"],
                "fenomeno_label": FENOMENO_ETIQUETA.get(r["fenomeno"], "Otros"),
                "naturaleza": r["naturaleza"],
                "naturaleza_label": NATURALEZA_ETIQUETA.get(r["naturaleza"], "Análisis"),
                "precedentes": r.get("precedentes", ["indeterminado"]),
                "precedentes_label": [PRECEDENTE_ETIQUETA.get(p, p)
                                      for p in r.get("precedentes", ["indeterminado"])],
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

    prensa = sorted(procesa(crudos, "prensa"),
                    key=lambda r: (r["fecha"], r["hora"]), reverse=True)
    social = sorted(procesa(crudos_soc, "social"),
                    key=lambda r: (r["fecha"], r["hora"]), reverse=True)

    metricas = calcula_metricas(prensa, social, dias)

    salida = {
        "generado": ahora.isoformat(),
        "generado_legible": ahora.strftime("%d/%m/%Y %H:%M"),
        "ventana": {"dias": dias, "hoy": dias[-1], "largo": VENTANA_DIAS},
        "metricas": metricas,
        "prensa": prensa,
        "social": social,
        "nuevos": len(nuevos),
        "consultas": len(CONSULTAS_PRENSA) + len(CONSULTAS_SOCIALES) * len(SUBREDDITS),
    }

    with open(SALIDA, "w", encoding="utf-8") as fh:
        json.dump(salida, fh, ensure_ascii=False, indent=1)

    estado["vistos"] = list(vistos)
    guarda_estado(estado)

    log(f"Listo: {len(prensa)} de prensa · {len(social)} sociales · {len(nuevos)} nuevos → {SALIDA}")
    for n in nuevos[:12]:
        log(f"   NUEVO [{n['canal']}] {n['medio']} — {n['titulo'][:88]}")

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
