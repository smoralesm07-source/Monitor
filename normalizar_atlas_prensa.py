#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normaliza trazabilidad de Radar Prensa para ATLAS.

Backfill defensivo posterior al exportador principal:
- acepta URL en link/url/canonical_url/enlace;
- propaga fenómenos desde la publicación a sus menciones;
- no altera resolución de identidad ni scoring.
"""
from __future__ import annotations
import argparse, json, re, unicodedata
from pathlib import Path


def norm(v):
    s=unicodedata.normalize('NFKD',str(v or ''))
    s=''.join(c for c in s if not unicodedata.combining(c)).casefold()
    return re.sub(r'\s+',' ',re.sub(r'[^a-z0-9]+',' ',s)).strip()


def first(d,*keys):
    for k in keys:
        v=d.get(k)
        if v:
            return v
    return ''


def uniq(vals):
    out=[]; seen=set()
    for v in vals or []:
        s=str(v or '').strip(); k=norm(s)
        if s and k and k not in seen:
            seen.add(k); out.append(s)
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--indice',type=Path,default=Path('atlas_prensa.json'))
    ap.add_argument('--datos',type=Path,default=Path('datos_atlas_input.json'))
    args=ap.parse_args()
    idx=json.loads(args.indice.read_text(encoding='utf-8'))
    datos=json.loads(args.datos.read_text(encoding='utf-8'))

    pubs=[p for p in (datos.get('prensa') or []) if isinstance(p,dict)]
    by_title={norm(first(p,'titulo','title')):p for p in pubs if norm(first(p,'titulo','title'))}
    by_url={str(first(p,'link','url','canonical_url','enlace')).rstrip('/'):p for p in pubs if first(p,'link','url','canonical_url','enlace')}

    article_by_id={str(a.get('id')):a for a in (idx.get('articles') or []) if isinstance(a,dict)}
    fixed_urls=0; fixed_ph=0
    for a in article_by_id.values():
        p=by_title.get(norm(a.get('title')))
        if not p and a.get('url'):
            p=by_url.get(str(a.get('url')).rstrip('/'))
        if not p:
            continue
        url=str(first(p,'link','url','canonical_url','enlace')).strip()
        if url and not a.get('url'):
            a['url']=url; fixed_urls+=1
        ph=uniq((a.get('phenomena') or []) + (p.get('fenomenos') or []) + (p.get('fenomenos_detectados') or []) + (p.get('phenomena') or []))[:12]
        if ph != (a.get('phenomena') or []):
            a['phenomena']=ph; fixed_ph+=1

    propagated=0
    for m in idx.get('mentions') or []:
        if not isinstance(m,dict):
            continue
        a=article_by_id.get(str(m.get('article_id')),{})
        ph=uniq((m.get('phenomena') or []) + (a.get('phenomena') or []))[:12]
        if ph != (m.get('phenomena') or []):
            m['phenomena']=ph; propagated+=1

    idx.setdefault('semantics',{})['traceability']='URL original y fenómenos se conservan para corroboración; asociación temática no acredita participación de la entidad.'
    args.indice.write_text(json.dumps(idx,ensure_ascii=False,separators=(',',':'))+'\n',encoding='utf-8')
    print(f'Normalización Atlas-Prensa: urls_backfill={fixed_urls} articulos_fenomenos={fixed_ph} menciones_fenomenos={propagated}')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
