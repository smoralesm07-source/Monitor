#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enriquece artículos históricos de Radar Prensa para resolución de entidades en ATLAS.

Proceso aislado del Monitor operativo. Recupera, cuando es posible, el cuerpo editorial
usando el mismo extractor de monitor_uaf.py y genera un datos.json compatible con
modulo_entidades.py. Las semillas editoriales verificadas permiten reingresar omisiones
puntuales detectadas durante control de cobertura sin alterar el Monitor UAF.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import monitor_uaf as M

UA = "Mozilla/5.0 (compatible; AtlasHistoricalPress/1.1; +https://atlasobservatorio.app/)"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def article_key(article: dict[str, Any]) -> str:
    url = str(article.get("url") or article.get("link") or "").strip()
    if url:
        return f"url:{url}"
    aid = str(article.get("id") or "").strip()
    return f"id:{aid}" if aid else ""


def normalize_article(article: dict[str, Any], *, seed: bool = False) -> dict[str, Any]:
    out = dict(article)
    if "url" not in out and out.get("link"):
        out["url"] = out.get("link")
    if "date" not in out and out.get("fecha"):
        out["date"] = out.get("fecha")
    if seed:
        out["backfill"] = True
        out["verified_seed"] = True
        out.setdefault("discovery", "ATLAS_VERIFIED_SEED")
        out.setdefault("query_kind", "VERIFIED_ENTITY_MISS")
    return out


def fetch_body(article: dict[str, Any], timeout: int = 18) -> tuple[dict[str, Any], bool, str | None]:
    url = str(article.get("url") or "").strip()
    text = ""
    error = None
    ok = False
    if url.startswith("http"):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": UA,
                    "Accept-Language": "es-CL,es;q=0.9",
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = r.read(3_500_000)
                headers = {k.lower(): v for k, v in r.headers.items()}
                final_url = r.geturl()
            extracted = M.extrae_articulo_html(payload, final_url, headers)
            if isinstance(extracted, dict):
                text = str(
                    extracted.get("texto_enriquecido")
                    or extracted.get("texto")
                    or extracted.get("contenido")
                    or ""
                ).strip()
            elif isinstance(extracted, str):
                text = extracted.strip()
            ok = len(text) >= 120
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:260]

    # El resumen de una semilla verificada es evidencia editorial previamente
    # comprobada y se conserva aunque el medio bloquee la recuperación del cuerpo.
    summary = str(article.get("summary") or "").strip()
    if not text and article.get("verified_seed") and summary:
        text = summary

    pub = {
        "id": article.get("id"),
        "fecha": article.get("date"),
        "fecha_iso": article.get("date"),
        "titulo": article.get("title") or "",
        "medio": article.get("media") or "",
        "link": url,
        "resumen": summary,
        "texto_enriquecido": text,
        "region": article.get("region"),
        "comuna": article.get("commune"),
        "fenomenos": article.get("phenomena") or [],
        "search_terms": article.get("search_terms") or [],
        "verified_entity": article.get("verified_entity"),
        "fuente_atlas": "ATLAS_VERIFIED_SEED" if article.get("verified_seed") else "BACKFILL_12M_ENRIQUECIDO",
    }
    return pub, ok, error


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--radar", type=Path, default=Path("radar_prensa_entidades.json"))
    ap.add_argument("--semillas", type=Path, default=Path("semillas_prensa_atlas.json"))
    ap.add_argument("--salida", type=Path, default=Path("datos_atlas_backfill_enriquecido.json"))
    ap.add_argument("--inicio", default="2025-10-05")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    radar = load_json(args.radar)
    seed_doc = load_json(args.semillas)

    # Reprocesamos sólo el universo generado por el backfill, no todo el bridge
    # acumulado. Esto mantiene el job acotado y evita miles de descargas innecesarias.
    selected: dict[str, dict[str, Any]] = {}
    for raw in radar.get("articles", []):
        if not isinstance(raw, dict):
            continue
        date = str(raw.get("date") or "")[:10]
        is_backfill = bool(raw.get("backfill")) or str(raw.get("query_kind") or "").startswith("BACKFILL_")
        if date < args.inicio or not is_backfill:
            continue
        article = normalize_article(raw)
        key = article_key(article)
        if key:
            selected[key] = article

    seed_count = 0
    for raw in seed_doc.get("articles", []):
        if not isinstance(raw, dict):
            continue
        article = normalize_article(raw, seed=True)
        date = str(article.get("date") or "")[:10]
        if date and date < args.inicio:
            continue
        key = article_key(article)
        if key:
            selected[key] = article
            seed_count += 1

    articles = list(selected.values())
    pubs: list[dict[str, Any]] = []
    fetched = 0
    errors: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 12))) as ex:
        futures = {ex.submit(fetch_body, article): article for article in articles}
        for fut in as_completed(futures):
            try:
                pub, ok, err = fut.result()
            except Exception as exc:  # degradación por artículo; no aborta el lote
                original = futures[fut]
                pub, ok, err = fetch_body({**original, "url": ""}, timeout=1)
                err = f"worker:{type(exc).__name__}: {exc}"[:260]
            pubs.append(pub)
            if ok:
                fetched += 1
            if err:
                errors.append({"id": pub.get("id"), "medio": pub.get("medio"), "error": err})

    pubs.sort(key=lambda x: (str(x.get("fecha") or ""), str(x.get("titulo") or "")), reverse=True)
    out = {
        "prensa": pubs,
        "atlas_backfill_enrichment": {
            "start": args.inicio,
            "articles": len(pubs),
            "verified_seeds": seed_count,
            "fulltext_ok": fetched,
            "fallback_title_summary": len(pubs) - fetched,
            "errors": len(errors),
            "error_samples": errors[:80],
        },
    }
    args.salida.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(
        "Enriquecimiento ATLAS: "
        f"articulos={len(pubs)} semillas={seed_count} cuerpo_ok={fetched} "
        f"fallback={len(pubs)-fetched} errores={len(errors)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
