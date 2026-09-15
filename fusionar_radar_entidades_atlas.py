#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fusiona Radar Prensa Entidades dentro del puente de prensa de ATLAS.

No modifica el Monitor UAF ni su estado. Sólo amplía `articles` en el archivo
`atlas_prensa.json`, preservando intactos `entities` y `mentions` del bridge
histórico. La resolución de identidad sigue ocurriendo en ATLAS.
"""
from __future__ import annotations

import argparse
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

MAX_ARTICLES = 30000


def norm(value: Any) -> str:
    s = unicodedata.normalize('NFKD', str(value or ''))
    s = ''.join(c for c in s if not unicodedata.combining(c)).casefold()
    s = re.sub(r'[^a-z0-9]+', ' ', s)
    return re.sub(r'\s+', ' ', s).strip()


def signature(article: dict[str, Any]) -> str:
    date = str(article.get('date') or '')[:10]
    title = norm(article.get('title'))
    media = norm(article.get('media'))
    return f'{date}|{media}|{title}'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--atlas', type=Path, default=Path('atlas_prensa.json'))
    parser.add_argument('--radar', type=Path, default=Path('radar_prensa_entidades.json'))
    args = parser.parse_args()

    atlas = json.loads(args.atlas.read_text(encoding='utf-8'))
    radar = json.loads(args.radar.read_text(encoding='utf-8'))
    if not isinstance(atlas.get('articles'), list):
        raise SystemExit('atlas_prensa.json no contiene articles válidos')
    if not isinstance(radar.get('articles'), list):
        raise SystemExit('radar_prensa_entidades.json no contiene articles válidos')

    existing_ids = {str(a.get('id')) for a in atlas['articles'] if isinstance(a, dict) and a.get('id')}
    existing_signatures = {
        signature(a) for a in atlas['articles']
        if isinstance(a, dict) and a.get('title')
    }

    added = 0
    for article in radar['articles']:
        if not isinstance(article, dict) or not article.get('id') or not article.get('title'):
            continue
        aid = str(article['id'])
        sig = signature(article)
        if aid in existing_ids or sig in existing_signatures:
            continue
        atlas['articles'].append(article)
        existing_ids.add(aid)
        existing_signatures.add(sig)
        added += 1

    atlas['articles'].sort(
        key=lambda a: (str(a.get('date') or ''), str(a.get('title') or '')),
        reverse=True,
    )
    atlas['articles'] = atlas['articles'][:MAX_ARTICLES]
    atlas.setdefault('semantics', {})['entity_press_radar'] = (
        'Radar Prensa Entidades amplía artículos candidatos para Entidad 360; '
        'una coincidencia textual no acredita identidad, participación ni responsabilidad.'
    )
    atlas.setdefault('stats', {})['entity_radar_articles_available'] = len(radar['articles'])
    atlas['stats']['entity_radar_articles_added_last_merge'] = added
    atlas['stats']['articles_after_entity_radar_merge'] = len(atlas['articles'])
    atlas['entity_radar_generated_at'] = radar.get('generated_at')

    args.atlas.write_text(
        json.dumps(atlas, ensure_ascii=False, separators=(',', ':')) + '\n',
        encoding='utf-8',
    )
    print(
        'Fusión Radar Entidades -> Atlas:',
        f'radar={len(radar["articles"])}',
        f'agregados={added}',
        f'total_atlas={len(atlas["articles"])}',
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
