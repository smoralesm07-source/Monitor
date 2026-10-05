#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enriquece artículos históricos de Radar Prensa para resolución de entidades en ATLAS.

Proceso aislado del Monitor operativo. Recupera, cuando es posible, el cuerpo editorial
usando el mismo extractor de monitor_uaf.py y genera un datos.json compatible con
modulo_entidades.py. Si un medio bloquea la recuperación, conserva título + resumen.
"""
from __future__ import annotations
import argparse, json, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
import monitor_uaf as M

UA = "Mozilla/5.0 (compatible; AtlasHistoricalPress/1.0; +https://atlasobservatorio.app/)"

def fetch_body(article: dict[str, Any], timeout: int = 18) -> tuple[dict[str, Any], bool, str | None]:
    url = str(article.get("url") or "").strip()
    text = ""
    error = None
    ok = False
    if url.startswith("http"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language":"es-CL,es;q=0.9"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = r.read(3_500_000)
                headers = {k.lower(): v for k, v in r.headers.items()}
                final_url = r.geturl()
            extracted = M.extrae_articulo_html(payload, final_url, headers)
            if isinstance(extracted, dict):
                text = str(extracted.get("texto_enriquecido") or extracted.get("texto") or extracted.get("contenido") or "").strip()
            elif isinstance(extracted, str):
                text = extracted.strip()
            ok = len(text) >= 120
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:260]
    pub = {
        "id": article.get("id"),
        "fecha": article.get("date"),
        "fecha_iso": article.get("date"),
        "titulo": article.get("title") or "",
        "medio": article.get("media") or "",
        "link": url,
        "resumen": article.get("summary") or "",
        "texto_enriquecido": text,
        "region": article.get("region"),
        "comuna": article.get("commune"),
        "fenomenos": article.get("phenomena") or [],
        "fuente_atlas": "BACKFILL_12M_ENRIQUECIDO",
    }
    return pub, ok, error

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--radar", type=Path, default=Path("radar_prensa_entidades.json"))
    ap.add_argument("--salida", type=Path, default=Path("datos_atlas_backfill_enriquecido.json"))
    ap.add_argument("--inicio", default="2025-10-05")
    ap.add_argument("--workers", type=int, default=8)
    args=ap.parse_args()
    radar=json.loads(args.radar.read_text(encoding="utf-8"))
    articles=[a for a in radar.get("articles",[]) if isinstance(a,dict) and str(a.get("date") or "")[:10] >= args.inicio]
    pubs=[]; fetched=0; errors=[]
    with ThreadPoolExecutor(max_workers=max(1,min(args.workers,12))) as ex:
        futures={ex.submit(fetch_body,a): a for a in articles}
        for fut in as_completed(futures):
            pub,ok,err=fut.result(); pubs.append(pub)
            if ok: fetched += 1
            if err: errors.append({"id":pub.get("id"),"medio":pub.get("medio"),"error":err})
    pubs.sort(key=lambda x:(str(x.get("fecha") or ""),str(x.get("titulo") or "")), reverse=True)
    out={
        "prensa": pubs,
        "atlas_backfill_enrichment": {
            "start": args.inicio,
            "articles": len(pubs),
            "fulltext_ok": fetched,
            "fallback_title_summary": len(pubs)-fetched,
            "errors": len(errors),
            "error_samples": errors[:80],
        }
    }
    args.salida.write_text(json.dumps(out,ensure_ascii=False,separators=(",",":"))+"\n",encoding="utf-8")
    print(f"Enriquecimiento ATLAS: articulos={len(pubs)} cuerpo_ok={fetched} fallback={len(pubs)-fetched} errores={len(errors)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
