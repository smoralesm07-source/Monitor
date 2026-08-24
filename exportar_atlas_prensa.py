#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exporta una capa histórica compacta de entidades de prensa para ATLAS AML.

Este proceso corre DESPUÉS de modulo_entidades.py y es deliberadamente aislado:
si falla, no altera la detección de noticias, el dashboard ni el correo.

Entrada: datos.json ya enriquecido con analisis_entidades / nomina_entidades.
Estado previo: atlas_prensa.json (opcional, para conservar historia >30 días).
Salida: atlas_prensa.json, consumible en lectura por ATLAS.

Semántica:
- PRESS_ONLY: entidad observada en prensa, sin afirmar identidad canónica Atlas.
- RUT, cuando existe, se conserva como evidencia de resolución posterior.
- Nombre exacto o aproximado NUNCA promueve identidad en este exportador.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

VERSION = "1.0.0-atlas-press-bridge"
DEFAULT_INPUT = Path("datos.json")
DEFAULT_OUTPUT = Path("atlas_prensa.json")
RETENTION_DAYS = 1825  # 5 años
MAX_ARTICLES = 20000
MAX_ENTITIES = 12000
MAX_MENTIONS = 60000


def norm(value: Any) -> str:
    s = unicodedata.normalize("NFKD", str(value or ""))
    s = "".join(c for c in s if not unicodedata.combining(c)).casefold()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def press_id(name: str, nature: str, kind: str) -> str:
    raw = f"{nature}|{kind}|{norm(name)}".encode("utf-8")
    return "PRESS-" + hashlib.sha256(raw).hexdigest()[:20].upper()


def parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def atomic_dump(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write("\n")
        tmp = Path(fh.name)
    tmp.replace(path)


def article_id(pub: dict[str, Any]) -> str:
    existing = str(pub.get("id") or "").strip()
    if existing:
        return existing
    raw = f"{pub.get('link','')}|{pub.get('titulo','')}".encode("utf-8")
    return "NEWS-" + hashlib.sha256(raw).hexdigest()[:20].upper()


def load_previous(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"articles": [], "entities": [], "mentions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"articles": [], "entities": [], "mentions": []}
    except Exception:
        return {"articles": [], "entities": [], "mentions": []}


def build_current(datos: dict[str, Any]) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    articles: dict[str, dict] = {}
    entities: dict[str, dict] = {}
    mentions: dict[str, dict] = {}

    for pub in datos.get("prensa", []) or []:
        if not isinstance(pub, dict):
            continue
        aid = article_id(pub)
        date = str(pub.get("fecha") or pub.get("fecha_iso") or "")[:25]
        articles[aid] = {
            "id": aid,
            "date": date,
            "title": str(pub.get("titulo") or "Sin título")[:500],
            "media": str(pub.get("medio") or "")[:160],
            "url": str(pub.get("link") or "")[:1500],
            "summary": str(pub.get("resumen") or "")[:900],
            "uaf": bool(pub.get("uaf") or pub.get("uaf_chile")),
            "phenomena": list(pub.get("fenomenos") or pub.get("fenomenos_detectados") or [])[:12],
            "region": pub.get("region"),
            "commune": pub.get("comuna"),
        }

        nomina = pub.get("nomina_entidades") or []
        for row in nomina:
            if not isinstance(row, dict):
                continue
            nature = str(row.get("naturaleza") or "INDETERMINADA")
            kind = str(row.get("tipo") or "OTRO")
            if nature not in {"PERSONA_NATURAL", "PERSONA_JURIDICA"}:
                continue
            name = str(row.get("nombre") or "").strip()
            if len(norm(name)) < 3:
                continue
            pid = press_id(name, nature, kind)
            current = entities.setdefault(pid, {
                "press_entity_id": pid,
                "name": name,
                "normalized_name": norm(name),
                "entity_type": kind,
                "nature": nature,
                "ruts": [],
                "aliases": [],
                "first_seen": date[:10] if date else None,
                "last_seen": date[:10] if date else None,
                "article_count": 0,
                "mention_count": 0,
                "media": [],
                "roles": [],
                "confidence": 0.0,
                "requires_validation": bool(row.get("requiere_validacion")),
                "resolution_status": "PRESS_ONLY",
                "source": "RADAR_PRENSA",
            })
            for rut in row.get("ruts") or []:
                if rut and rut not in current["ruts"]:
                    current["ruts"].append(str(rut))
            for alias in row.get("variantes") or []:
                if alias and alias not in current["aliases"] and norm(alias) != current["normalized_name"]:
                    current["aliases"].append(str(alias)[:180])
            media = str(pub.get("medio") or "").strip()
            if media and media not in current["media"]:
                current["media"].append(media[:160])
            role = str(row.get("rol_principal") or "mencionada en la publicación").strip()
            if role and role not in current["roles"]:
                current["roles"].append(role[:300])
            score = float(row.get("confianza_score", 0.5) or 0.5)
            current["confidence"] = max(current["confidence"], score)
            current["requires_validation"] = current["requires_validation"] or score < 0.55
            if date:
                d = date[:10]
                current["first_seen"] = min(current["first_seen"], d) if current["first_seen"] else d
                current["last_seen"] = max(current["last_seen"], d) if current["last_seen"] else d

            mid = "MENTION-" + hashlib.sha256(f"{pid}|{aid}".encode("utf-8")).hexdigest()[:20].upper()
            mentions[mid] = {
                "mention_id": mid,
                "press_entity_id": pid,
                "article_id": aid,
                "role": role[:300],
                "roles": list(row.get("roles") or [])[:8],
                "mentions": int(row.get("menciones", 1) or 1),
                "confidence": score,
                "requires_validation": bool(row.get("requiere_validacion")),
                "territories": list(row.get("territorios_articulo") or [])[:10],
                "phenomena": list(row.get("fenomenos_articulo") or [])[:12],
                "precedents": list(row.get("precedentes_articulo") or [])[:12],
                "sectors": list(row.get("sectores_articulo") or [])[:12],
                "source": "RADAR_PRENSA",
            }

    # Recalcular conteos desde las menciones del corte actual.
    by_entity: dict[str, list[dict]] = {}
    for m in mentions.values():
        by_entity.setdefault(m["press_entity_id"], []).append(m)
    for pid, rows in by_entity.items():
        if pid in entities:
            entities[pid]["article_count"] = len({r["article_id"] for r in rows})
            entities[pid]["mention_count"] = sum(int(r.get("mentions", 1)) for r in rows)
    return articles, entities, mentions


def merge(datos: dict[str, Any], previous: dict[str, Any], retention_days: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    cur_articles, cur_entities, cur_mentions = build_current(datos)

    articles = {str(x.get("id")): x for x in previous.get("articles", []) if isinstance(x, dict) and x.get("id")}
    entities = {str(x.get("press_entity_id")): x for x in previous.get("entities", []) if isinstance(x, dict) and x.get("press_entity_id")}
    mentions = {str(x.get("mention_id")): x for x in previous.get("mentions", []) if isinstance(x, dict) and x.get("mention_id")}
    articles.update(cur_articles)
    mentions.update(cur_mentions)

    # Merge de atributos de entidad sin borrar historia anterior.
    for pid, incoming in cur_entities.items():
        old = entities.get(pid)
        if not old:
            entities[pid] = incoming
            continue
        merged = dict(old)
        for key in ("name", "normalized_name", "entity_type", "nature", "source"):
            merged[key] = incoming.get(key) or old.get(key)
        for key in ("ruts", "aliases", "media", "roles"):
            merged[key] = list(dict.fromkeys((old.get(key) or []) + (incoming.get(key) or [])))[:40]
        merged["first_seen"] = min(x for x in [old.get("first_seen"), incoming.get("first_seen")] if x) if (old.get("first_seen") or incoming.get("first_seen")) else None
        merged["last_seen"] = max(x for x in [old.get("last_seen"), incoming.get("last_seen")] if x) if (old.get("last_seen") or incoming.get("last_seen")) else None
        merged["confidence"] = max(float(old.get("confidence", 0) or 0), float(incoming.get("confidence", 0) or 0))
        merged["requires_validation"] = bool(old.get("requires_validation") or incoming.get("requires_validation"))
        merged["resolution_status"] = "PRESS_ONLY"
        entities[pid] = merged

    # Retención por fecha de artículo. Si una fecha no es parseable, se conserva
    # sólo si pertenece al corte actual.
    keep_articles: dict[str, dict] = {}
    for aid, art in articles.items():
        dt = parse_date(art.get("date"))
        if aid in cur_articles or (dt and dt >= cutoff):
            keep_articles[aid] = art
    keep_article_ids = set(keep_articles)
    keep_mentions = {mid: m for mid, m in mentions.items() if m.get("article_id") in keep_article_ids}
    active_entity_ids = {m.get("press_entity_id") for m in keep_mentions.values()}
    keep_entities = {pid: e for pid, e in entities.items() if pid in active_entity_ids}

    # Recalcular agregados históricos desde toda la retención.
    by_entity: dict[str, list[dict]] = {}
    for m in keep_mentions.values():
        by_entity.setdefault(m["press_entity_id"], []).append(m)
    for pid, e in keep_entities.items():
        rows = by_entity.get(pid, [])
        aids = {r.get("article_id") for r in rows if r.get("article_id")}
        e["article_count"] = len(aids)
        e["mention_count"] = sum(int(r.get("mentions", 1) or 1) for r in rows)
        e["media"] = sorted({keep_articles[a].get("media") for a in aids if a in keep_articles and keep_articles[a].get("media")})[:40]
        dates = [str(keep_articles[a].get("date") or "")[:10] for a in aids if a in keep_articles and keep_articles[a].get("date")]
        if dates:
            e["first_seen"] = min(dates)
            e["last_seen"] = max(dates)

    article_rows = sorted(keep_articles.values(), key=lambda x: str(x.get("date") or ""), reverse=True)[:MAX_ARTICLES]
    allowed_articles = {x["id"] for x in article_rows}
    mention_rows = [m for m in keep_mentions.values() if m.get("article_id") in allowed_articles]
    mention_rows.sort(key=lambda m: str(keep_articles.get(m.get("article_id"), {}).get("date") or ""), reverse=True)
    mention_rows = mention_rows[:MAX_MENTIONS]
    allowed_entities = {m["press_entity_id"] for m in mention_rows}
    entity_rows = [e for pid, e in keep_entities.items() if pid in allowed_entities]
    entity_rows.sort(key=lambda e: (-(int(e.get("article_count", 0) or 0)), str(e.get("name") or "").casefold()))
    entity_rows = entity_rows[:MAX_ENTITIES]
    allowed_entities = {e["press_entity_id"] for e in entity_rows}
    mention_rows = [m for m in mention_rows if m["press_entity_id"] in allowed_entities]

    return {
        "version": VERSION,
        "generated_at": now.isoformat(),
        "retention_days": retention_days,
        "source": "Monitor UAF Chile / RADAR_PRENSA",
        "semantics": {
            "identity": "PRESS_ONLY hasta resolución gobernada en ATLAS",
            "warning": "Una mención en prensa es contexto/evidencia abierta; no acredita delito ni identidad canónica por sí sola.",
        },
        "stats": {"articles": len(article_rows), "entities": len(entity_rows), "mentions": len(mention_rows)},
        "articles": article_rows,
        "entities": entity_rows,
        "mentions": mention_rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entrada", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--salida", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--estado-previo", type=Path, default=None)
    ap.add_argument("--retencion-dias", type=int, default=RETENTION_DAYS)
    args = ap.parse_args()
    datos = json.loads(args.entrada.read_text(encoding="utf-8"))
    previous = load_previous(args.estado_previo or args.salida)
    output = merge(datos, previous, max(30, args.retencion_dias))
    atomic_dump(args.salida, output)
    s = output["stats"]
    print(f"Bridge Atlas-Prensa listo: {s['entities']} entidades · {s['mentions']} menciones · {s['articles']} artículos · retención={output['retention_days']} días")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
