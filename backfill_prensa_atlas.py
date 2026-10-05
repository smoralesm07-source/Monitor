#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Backfill histórico de prensa exclusivo para ATLAS.

Amplía `radar_prensa_entidades.json` hacia atrás sin modificar Monitor UAF,
`datos.json`, alertas, correos ni estados del monitor institucional.

La búsqueda se divide en ventanas mensuales para evitar depender de una única
consulta anual de Google News. Los resultados se filtran nuevamente por fecha,
se deduplican con la misma lógica del Radar Prensa Entidades y luego se fusionan
con su estado histórico existente.
"""
from __future__ import annotations

import argparse
import calendar
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import radar_prensa_entidades as radar

VERSION = "1.0.0-atlas-press-backfill"
DEFAULT_OUTPUT = Path("radar_prensa_entidades.json")

QUERY_FAMILIES = [
    (
        "ENTIDADES_CORPORATIVO",
        radar.CORPORATE_QUERY,
    ),
    (
        "RIESGO_AML",
        'lavado OR "lavado de activos" OR fraude OR estafa OR corrupción OR corrupcion OR '
        'cohecho OR soborno OR querella OR investigación OR investigacion OR fiscalía OR fiscalia OR '
        'sanción OR sancion OR "delitos económicos" OR "delitos economicos" OR narcotráfico OR narcotrafico',
    ),
]


def month_windows(start: date, end: date) -> list[tuple[date, date]]:
    """Genera ventanas [inicio, fin_exclusivo) alineadas a mes."""
    windows: list[tuple[date, date]] = []
    cursor = start
    while cursor < end:
        last_day = calendar.monthrange(cursor.year, cursor.month)[1]
        next_month = date(cursor.year, cursor.month, last_day) + timedelta(days=1)
        window_end = min(next_month, end)
        windows.append((cursor, window_end))
        cursor = window_end
    return windows


def in_window(row: dict[str, Any], start: date, end: date) -> bool:
    raw = str(row.get("date") or "")[:10]
    try:
        d = date.fromisoformat(raw)
    except Exception:
        return False
    return start <= d < end


def fetch_one(media: str, domain: str, family: str, terms: str, start: date, end: date) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    # `before` es exclusivo en la sintaxis de búsqueda utilizada.
    query = f"({terms}) after:{start.isoformat()} before:{end.isoformat()}"
    url = radar.google_news_url(domain, query)
    try:
        payload = radar.fetch(url, timeout=30)
        rows = radar.parse_feed(payload, media, domain, f"BACKFILL_{family}")
        rows = [r for r in rows if in_window(r, start, end)]
        for row in rows:
            row["backfill"] = True
            row["backfill_window"] = f"{start.isoformat()}..{end.isoformat()}"
        return rows, None
    except Exception as exc:
        return [], {
            "media": media,
            "domain": domain,
            "family": family,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "error": str(exc)[:300],
        }


def run_backfill(previous_path: Path | None, output: Path, start: date, end: date, retention_days: int, workers: int) -> dict[str, Any]:
    windows = month_windows(start, end)
    jobs = [
        (media, domain, family, terms, w_start, w_end)
        for media, domain in radar.SOURCES
        for w_start, w_end in windows
        for family, terms in QUERY_FAMILIES
    ]

    collected: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 10))) as pool:
        futures = {
            pool.submit(fetch_one, media, domain, family, terms, w_start, w_end):
            (media, domain, family, w_start, w_end)
            for media, domain, family, terms, w_start, w_end in jobs
        }
        for fut in as_completed(futures):
            rows, error = fut.result()
            collected.extend(rows)
            if error:
                errors.append(error)
            else:
                completed += 1

    # Deduplicación de esta carga, privilegiando el registro con mejor resumen.
    best: dict[str, dict[str, Any]] = {}
    for row in collected:
        old = best.get(str(row.get("id")))
        if old is None or len(str(row.get("summary") or "")) > len(str(old.get("summary") or "")):
            best[str(row["id"])] = row

    previous = radar.load_previous(previous_path)
    before_ids = {
        str(x.get("id")) for x in (previous.get("articles") or [])
        if isinstance(x, dict) and x.get("id")
    }
    articles = radar.merge_articles(previous, list(best.values()), retention_days)
    after_ids = {str(x.get("id")) for x in articles if x.get("id")}
    added = len(after_ids - before_ids)

    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    result = dict(previous) if isinstance(previous, dict) else {}
    result.update({
        "version": radar.VERSION,
        "generated_at": generated,
        "semantics": {
            **(previous.get("semantics") or {}),
            "purpose": "Descubrimiento amplio de prensa para Entidad 360 de ATLAS.",
            "identity": "La presencia de un nombre en una noticia no acredita identidad, participación ni responsabilidad.",
            "isolation": "Proceso independiente del Monitor UAF; no modifica su estado, filtros, correos ni workflow.",
            "historical_backfill": "Carga histórica extraordinaria exclusiva para ATLAS, dividida en ventanas mensuales.",
        },
        "sources": [{"media": media, "domain": domain} for media, domain in radar.SOURCES],
        "articles": articles,
        "backfill": {
            "version": VERSION,
            "generated_at": generated,
            "start": start.isoformat(),
            "end_exclusive": end.isoformat(),
            "windows": len(windows),
            "query_families": [x[0] for x in QUERY_FAMILIES],
            "queries_total": len(jobs),
            "queries_ok": completed,
            "errors": len(errors),
            "candidates_unique": len(best),
            "articles_added": added,
        },
        "errors_backfill": errors[:200],
    })
    result["stats"] = {
        **(previous.get("stats") or {}),
        "articles": len(articles),
        "retention_days": retention_days,
        "backfill_articles_added": added,
        "backfill_queries_ok": completed,
        "backfill_queries_total": len(jobs),
    }

    output.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--estado-previo", type=Path, default=None)
    ap.add_argument("--salida", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--inicio", default=None, help="YYYY-MM-DD; por defecto, 365 días atrás")
    ap.add_argument("--fin", default=None, help="YYYY-MM-DD inclusivo; por defecto, hoy UTC")
    ap.add_argument("--retencion-dias", type=int, default=730)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()

    today = datetime.now(timezone.utc).date()
    start = date.fromisoformat(args.inicio) if args.inicio else today - timedelta(days=365)
    end_inclusive = date.fromisoformat(args.fin) if args.fin else today
    end = end_inclusive + timedelta(days=1)
    if start >= end:
        raise SystemExit("Rango de fechas inválido")

    result = run_backfill(
        args.estado_previo,
        args.salida,
        start,
        end,
        max(365, min(args.retencion_dias, 1825)),
        args.workers,
    )
    b = result["backfill"]
    print(
        "Backfill ATLAS prensa:",
        f"rango={b['start']}..{b['end_exclusive']}",
        f"consultas={b['queries_ok']}/{b['queries_total']}",
        f"candidatos={b['candidates_unique']}",
        f"agregados={b['articles_added']}",
        f"total={len(result['articles'])}",
        f"errores={b['errors']}",
    )
    if b["queries_ok"] == 0:
        raise SystemExit("El backfill no obtuvo ninguna consulta útil")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
