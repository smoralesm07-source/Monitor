#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Radar Prensa Entidades para ATLAS.

Proceso deliberadamente separado del Monitor UAF actual:
- NO importa ni modifica monitor_uaf.py.
- NO escribe datos.json, monitor-state ni atlas-press-state.
- Publica un estado independiente para que ATLAS pueda ampliar la prensa de
  Entidad 360 sin cambiar la lógica ni las alertas del monitor institucional.

El radar hace descubrimiento amplio por medios chilenos mediante Google News
RSS y conserva un histórico compacto. La resolución de identidad ocurre en
ATLAS; este proceso sólo aporta artículos candidatos de fuente abierta.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

VERSION = "1.0.0-radar-prensa-entidades"
DEFAULT_OUTPUT = Path("radar_prensa_entidades.json")
RETENTION_DAYS = 730
MAX_ARTICLES = 30000
USER_AGENT = "Mozilla/5.0 (compatible; AtlasEntityPressRadar/1.0; +https://atlasobservatorio.app/)"

SOURCES = [
    ("Diario Financiero", "df.cl"),
    ("La Tercera / Pulso", "latercera.com"),
    ("Emol", "emol.com"),
    ("El Mostrador", "elmostrador.cl"),
    ("BioBioChile", "biobiochile.cl"),
    ("Cooperativa", "cooperativa.cl"),
    ("ADN Radio", "adnradio.cl"),
    ("Radio Pauta", "pauta.cl"),
    ("24 Horas", "24horas.cl"),
    ("T13", "t13.cl"),
    ("CHV Noticias", "chvnoticias.cl"),
    ("Meganoticias", "meganoticias.cl"),
    ("CNN Chile", "cnnchile.com"),
    ("Interferencia", "interferencia.cl"),
    ("CIPER", "ciperchile.cl"),
    ("Ex-Ante", "ex-ante.cl"),
]

CORPORATE_QUERY = (
    'empresa OR sociedad OR compañía OR compania OR banco OR fintech OR fondo OR '
    'exchange OR criptomonedas OR fraude OR querella OR investigación OR investigacion OR '
    'fiscalía OR fiscalia OR sanción OR sancion OR lavado OR corrupción OR corrupcion OR '
    '"delitos económicos" OR "delitos economicos"'
)

TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")
HREF_RE = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.I)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def norm(value: Any) -> str:
    value = html.unescape(str(value or ""))
    value = value.casefold()
    value = re.sub(r"[^a-z0-9áéíóúüñ]+", " ", value)
    return SPACE_RE.sub(" ", value).strip()


def clean_html(value: Any) -> str:
    text = html.unescape(str(value or ""))
    text = TAG_RE.sub(" ", text)
    return SPACE_RE.sub(" ", text).strip()


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    try:
        dt = parsedate_to_datetime(raw)
    except Exception:
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_day(value: str | None) -> str | None:
    dt = parse_date(value)
    return dt.date().isoformat() if dt else None


def get_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    return child.text.strip() if child is not None and child.text else ""


def candidate_original_url(description: str, fallback: str) -> str:
    for url in HREF_RE.findall(description or ""):
        host = urllib.parse.urlparse(html.unescape(url)).netloc.casefold()
        if host and "google." not in host and "news.google." not in host:
            return html.unescape(url)
    return fallback


def clean_title(title: str, source: str) -> str:
    title = clean_html(title)
    if source and title.endswith(f" - {source}"):
        title = title[: -(len(source) + 3)].rstrip()
    return title


def article_id(title: str, source_domain: str, date: str | None) -> str:
    raw = f"{source_domain}|{date or ''}|{norm(title)}".encode("utf-8")
    return "EPR-" + hashlib.sha256(raw).hexdigest()[:24].upper()


def fetch(url: str, timeout: int = 25) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml, text/xml, */*;q=0.8",
            "Accept-Language": "es-CL,es;q=0.9,en;q=0.5",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def google_news_url(domain: str, query: str) -> str:
    q = urllib.parse.quote_plus(f"site:{domain} {query}".strip())
    return f"https://news.google.com/rss/search?q={q}&hl=es-419&gl=CL&ceid=CL:es-419"


def parse_feed(payload: bytes, fallback_media: str, domain: str, query_kind: str) -> list[dict[str, Any]]:
    root = ET.fromstring(payload)
    out: list[dict[str, Any]] = []
    for item in root.findall(".//item"):
        source_node = item.find("source")
        source_text = source_node.text.strip() if source_node is not None and source_node.text else fallback_media
        title = clean_title(get_text(item, "title"), source_text)
        if not title:
            continue
        description_raw = get_text(item, "description")
        summary = clean_html(description_raw)
        link = get_text(item, "link")
        url = candidate_original_url(description_raw, link)
        pub_date_raw = get_text(item, "pubDate")
        day = iso_day(pub_date_raw)
        guid = get_text(item, "guid")
        aid = article_id(title, domain, day)
        out.append(
            {
                "id": aid,
                "date": day,
                "title": title[:700],
                "media": source_text[:180] if source_text else fallback_media,
                "url": url[:1800] if url else None,
                "summary": summary[:1400] if summary else None,
                "region": None,
                "commune": None,
                "search_terms": [],
                "source_domain": domain,
                "discovery": "GOOGLE_NEWS_RSS",
                "query_kind": query_kind,
                "guid": guid[:1000] if guid else None,
            }
        )
    return out


def load_previous(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {"articles": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"articles": []}
    except Exception:
        return {"articles": []}


def merge_articles(previous: dict[str, Any], current: list[dict[str, Any]], retention_days: int) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in previous.get("articles", []) or []:
        if isinstance(row, dict) and row.get("id"):
            by_id[str(row["id"])] = row
    for row in current:
        old = by_id.get(str(row["id"]))
        if old:
            merged = dict(old)
            for key, value in row.items():
                if value not in (None, "", []):
                    merged[key] = value
            by_id[str(row["id"])] = merged
        else:
            by_id[str(row["id"])] = row

    cutoff = (utc_now() - timedelta(days=retention_days)).date()
    kept: list[dict[str, Any]] = []
    for row in by_id.values():
        try:
            day = datetime.fromisoformat(str(row.get("date") or "")[:10]).date()
        except Exception:
            day = None
        if day is None or day >= cutoff:
            kept.append(row)
    kept.sort(key=lambda x: (str(x.get("date") or ""), str(x.get("title") or "")), reverse=True)
    return kept[:MAX_ARTICLES]


def build(previous_path: Path | None, output: Path, retention_days: int) -> dict[str, Any]:
    current: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    fetched_queries = 0

    for media, domain in SOURCES:
        queries = [
            ("ULTIMOS_7_DIAS", "when:7d"),
            ("ENTIDADES_30_DIAS", f"when:30d ({CORPORATE_QUERY})"),
        ]
        for kind, query in queries:
            url = google_news_url(domain, query)
            try:
                payload = fetch(url)
                current.extend(parse_feed(payload, media, domain, kind))
                fetched_queries += 1
            except Exception as exc:
                errors.append({"media": media, "domain": domain, "query": kind, "error": str(exc)[:300]})
            time.sleep(0.15)

    # Deduplicación intra-corrida por id, privilegiando el registro con más texto.
    best: dict[str, dict[str, Any]] = {}
    for row in current:
        previous_row = best.get(row["id"])
        if previous_row is None or len(str(row.get("summary") or "")) > len(str(previous_row.get("summary") or "")):
            best[row["id"]] = row

    previous = load_previous(previous_path)
    articles = merge_articles(previous, list(best.values()), retention_days)
    generated = utc_now().isoformat().replace("+00:00", "Z")
    result = {
        "version": VERSION,
        "generated_at": generated,
        "semantics": {
            "purpose": "Descubrimiento amplio de prensa para Entidad 360 de ATLAS.",
            "identity": "La presencia de un nombre en una noticia no acredita identidad, participación ni responsabilidad.",
            "isolation": "Proceso independiente del Monitor UAF; no modifica su estado, filtros, correos ni workflow.",
        },
        "sources": [{"media": media, "domain": domain} for media, domain in SOURCES],
        "stats": {
            "articles": len(articles),
            "new_candidates": len(best),
            "queries_ok": fetched_queries,
            "queries_total": len(SOURCES) * 2,
            "errors": len(errors),
            "retention_days": retention_days,
        },
        "errors": errors[:80],
        "articles": articles,
    }
    output.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--estado-previo", type=Path, default=None)
    parser.add_argument("--salida", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--retencion-dias", type=int, default=RETENTION_DAYS)
    args = parser.parse_args()

    result = build(args.estado_previo, args.salida, max(30, min(args.retencion_dias, 1825)))
    stats = result["stats"]
    print(
        "Radar Prensa Entidades:",
        f"articulos={stats['articles']}",
        f"candidatos_corrida={stats['new_candidates']}",
        f"queries={stats['queries_ok']}/{stats['queries_total']}",
        f"errores={stats['errors']}",
    )
    # El radar tolera fallas parciales de medios; falla sólo si no hubo ninguna
    # consulta útil, porque publicar un estado vacío sería engañoso.
    if stats["queries_ok"] == 0:
        raise SystemExit("No fue posible consultar ninguna fuente del radar de entidades.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
