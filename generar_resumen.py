#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera resumen.json para el Centro de Monitoreo Estratégico UAF.

El mismo archivo funciona en:
- Monitor de prensa: detecta la colección "prensa".
- Monitor legislativo: detecta la colección "proyectos".

Uso:
    python3 generar_resumen.py

Opcional:
    python3 generar_resumen.py --entrada datos.json --salida resumen.json

Si existe una carpeta public/, también copia allí resumen.json para que sea
incluido automáticamente en el artefacto publicado por GitHub Pages.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


BASE = Path(__file__).resolve().parent


def entero(valor: Any, defecto: int = 0) -> int:
    if valor is None or valor == "":
        return defecto
    try:
        return int(valor)
    except (TypeError, ValueError):
        return defecto


def numero(valor: Any, defecto: float = 0.0) -> float:
    if valor is None or valor == "":
        return defecto
    try:
        return float(valor)
    except (TypeError, ValueError):
        return defecto


def texto(valor: Any) -> str:
    return str(valor or "").strip()


def lista(valor: Any) -> list:
    return valor if isinstance(valor, list) else []


def parsea_fecha(valor: Any) -> datetime | None:
    s = texto(valor)
    if not s:
        return None
    candidatos = [s, s.replace("Z", "+00:00")]
    if len(s) == 10:
        candidatos.append(s + "T00:00:00")
    for candidato in candidatos:
        try:
            dt = datetime.fromisoformat(candidato)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone(timedelta(hours=-4)))
            return dt
        except ValueError:
            pass
    for formato in ("%d/%m/%Y %H:%M", "%d/%m/%Y", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(s, formato)
            return dt.replace(tzinfo=timezone(timedelta(hours=-4)))
        except ValueError:
            pass
    return None


def fecha_registro(registro: dict) -> datetime | None:
    for campo in (
        "fecha_iso", "ultimo_movimiento", "fecha", "publicado",
        "fecha_publicacion", "fecha_ingreso"
    ):
        dt = parsea_fecha(registro.get(campo))
        if dt:
            if campo == "fecha" and registro.get("hora"):
                hora = texto(registro.get("hora"))
                try:
                    h, m = hora.split(":")[:2]
                    dt = dt.replace(hour=int(h), minute=int(m))
                except (ValueError, TypeError):
                    pass
            return dt
    return None


def fecha_base(datos: dict, registros: list[dict]) -> datetime:
    for campo in ("generado", "actualizado", "ultima_actualizacion"):
        dt = parsea_fecha(datos.get(campo))
        if dt:
            return dt
    fechas = [fecha_registro(x) for x in registros if isinstance(x, dict)]
    fechas = [x for x in fechas if x]
    return max(fechas) if fechas else datetime.now(timezone(timedelta(hours=-4)))


def serie_dias(registros: list[dict], referencia: datetime, dias: int = 7) -> list[dict]:
    inicio = (referencia - timedelta(days=dias - 1)).date()
    conteo = Counter()
    for registro in registros:
        dt = fecha_registro(registro)
        if dt and inicio <= dt.date() <= referencia.date():
            conteo[dt.date().isoformat()] += 1
    return [
        {
            "fecha": (inicio + timedelta(days=i)).isoformat(),
            "n": conteo[(inicio + timedelta(days=i)).isoformat()],
        }
        for i in range(dias)
    ]


def enlace_prensa(registro: dict) -> str:
    return texto(registro.get("link") or registro.get("url"))


def es_mencion_uaf(registro: dict) -> bool:
    confianza = texto(registro.get("uaf_confianza")).lower()
    return bool(
        registro.get("uaf_chile")
        or registro.get("uaf")
        or confianza in {"alta", "confirmada", "mencion_directa", "validada"}
    )


def prioridad_prensa(registro: dict) -> int:
    if es_mencion_uaf(registro):
        return 3
    if registro.get("nucleo"):
        return 2
    if lista(registro.get("sujetos_obligados")):
        return 1
    return 0


def resumen_prensa(datos: dict) -> dict:
    registros = [x for x in lista(datos.get("prensa")) if isinstance(x, dict)]
    registros.sort(key=lambda x: fecha_registro(x) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    ref = fecha_base(datos, registros)
    desde_24h = ref - timedelta(hours=24)
    desde_5d = ref - timedelta(days=5)
    desde_30d = ref - timedelta(days=30)

    ultimas_24h = [x for x in registros if fecha_registro(x) and fecha_registro(x) >= desde_24h]
    ultimos_5d = [x for x in registros if fecha_registro(x) and fecha_registro(x) >= desde_5d]
    ultimos_30d = [x for x in registros if fecha_registro(x) and fecha_registro(x) >= desde_30d]

    metricas = datos.get("metricas") if isinstance(datos.get("metricas"), dict) else {}
    portada = metricas.get("uaf_portada") if isinstance(metricas.get("uaf_portada"), dict) else {}

    menciones_24h = sum(es_mencion_uaf(x) for x in ultimas_24h)
    menciones_30d = sum(es_mencion_uaf(x) for x in ultimos_30d)
    relevancia_alta = sum(prioridad_prensa(x) >= 2 for x in ultimas_24h)

    topicos = Counter()
    for r in ultimos_30d:
        etiquetas = lista(r.get("topicos_label")) or lista(r.get("topicos"))
        for etiqueta in etiquetas:
            if texto(etiqueta):
                topicos[texto(etiqueta)] += 1
    tema_principal = topicos.most_common(1)[0][0] if topicos else ""
    if not tema_principal:
        disponibles = lista(metricas.get("topicos"))
        if disponibles and isinstance(disponibles[0], dict):
            tema_principal = texto(disponibles[0].get("label") or disponibles[0].get("etiqueta"))

    ultimo = registros[0] if registros else {}
    candidatos_alerta = sorted(
        registros[:20],
        key=lambda x: (
            prioridad_prensa(x),
            fecha_registro(x) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )[:4]

    alertas = []
    for r in candidatos_alerta:
        nivel = prioridad_prensa(r)
        alertas.append({
            "severidad": "alta" if nivel >= 3 else "media" if nivel == 2 else "info",
            "titulo": texto(r.get("titulo")) or "Publicación detectada",
            "detalle": texto(r.get("medio")) + (
                f" · {texto(r.get('fecha'))}" if texto(r.get("fecha")) else ""
            ),
            "link": enlace_prensa(r),
            "fuente": "PRENSA",
        })

    return {
        "esquema": "centro-monitor-1.0",
        "tipo": "prensa",
        "estado": "activo",
        "generado": texto(datos.get("generado")) or ref.isoformat(),
        "generado_legible": texto(datos.get("generado_legible")),
        "nuevas_24h": entero(portada.get("menciones_24h"), len(ultimas_24h))
            if portada.get("menciones_24h") is not None else len(ultimas_24h),
        "publicaciones_5d": len(ultimos_5d),
        "total_30d": len(ultimos_30d),
        "menciones_uaf": menciones_24h,
        "menciones_uaf_30d": menciones_30d,
        "relevancia_alta": relevancia_alta,
        "medios_24h": len({texto(x.get("medio")) for x in ultimas_24h if texto(x.get("medio"))}),
        "tema_principal": tema_principal,
        "ultimo": {
            "titulo": texto(ultimo.get("titulo")) or "Sin publicaciones recientes",
            "detalle": " · ".join(x for x in (
                texto(ultimo.get("medio")),
                texto(ultimo.get("fecha")),
                texto(ultimo.get("hora")),
            ) if x),
            "link": enlace_prensa(ultimo),
            "fecha": (fecha_registro(ultimo).isoformat() if ultimo and fecha_registro(ultimo) else ""),
        },
        "serie_7d": serie_dias(registros, ref, 7),
        "alertas": alertas,
        "actividad": [
            {
                "fecha": texto(datos.get("generado")) or ref.isoformat(),
                "texto": f"Barrido de prensa completado: {len(registros)} publicaciones disponibles.",
            }
        ],
    }


def enlace_proyecto(proyecto: dict) -> str:
    return texto(
        proyecto.get("link_senado")
        or proyecto.get("link_camara")
        or proyecto.get("link")
    )


def resumen_legislativo(datos: dict) -> dict:
    proyectos = [x for x in lista(datos.get("proyectos")) if isinstance(x, dict)]
    metricas = datos.get("metricas") if isinstance(datos.get("metricas"), dict) else {}
    auditoria = datos.get("auditoria") if isinstance(datos.get("auditoria"), dict) else {}
    ref = fecha_base(datos, proyectos)

    vigentes = [p for p in proyectos if p.get("vigente", True)]
    por_fecha = sorted(
        vigentes,
        key=lambda p: fecha_registro(p) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    con_novedad = sorted(
        [
            p for p in vigentes
            if texto(p.get("novedad") or p.get("novedad_detectada"))
        ],
        key=lambda p: fecha_registro(p) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    ultimo = (con_novedad[0] if con_novedad else (por_fecha[0] if por_fecha else {}))

    prioritarios = sorted(
        vigentes,
        key=lambda p: (
            texto(p.get("banda_prioridad")).lower() == "critica",
            texto(p.get("banda_prioridad")).lower() == "alta",
            texto(p.get("urgencia_clave")).lower() not in {"", "sin urgencia"},
            numero(p.get("prioridad")),
            fecha_registro(p) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )[:5]

    alertas = []
    for p in prioritarios:
        banda = texto(p.get("banda_prioridad")).lower()
        urgencia = texto(p.get("urgencia_legible"))
        severidad = "alta" if banda in {"critica", "crítica", "alta"} else (
            "media" if urgencia and urgencia.lower() != "sin urgencia" else "info"
        )
        detalle = " · ".join(x for x in (
            f"Boletín {texto(p.get('boletin'))}" if texto(p.get("boletin")) else "",
            texto(p.get("nivel_legible") or p.get("impacto_legible")),
            urgencia,
        ) if x)
        alertas.append({
            "severidad": severidad,
            "titulo": texto(p.get("titulo")) or "Proyecto en seguimiento",
            "detalle": detalle,
            "link": enlace_proyecto(p),
            "fuente": "LEGISLATIVO",
        })

    actividad = []
    for p in por_fecha[:4]:
        dt = fecha_registro(p)
        actividad.append({
            "fecha": dt.isoformat() if dt else "",
            "texto": (
                f"Boletín {texto(p.get('boletin'))}: "
                f"{texto(p.get('ultimo_tramite') or p.get('sintesis') or p.get('etapa'))}"
            ).strip(),
        })

    novedades_corrida = entero(
        auditoria.get("novedades_corrida"),
        entero(datos.get("novedades"), len(con_novedad)),
    )

    return {
        "esquema": "centro-monitor-1.0",
        "tipo": "legislativo",
        "estado": "activo",
        "generado": texto(datos.get("generado")) or ref.isoformat(),
        "generado_legible": texto(datos.get("generado_legible")),
        "proyectos_total": entero(metricas.get("total"), len(proyectos)),
        "vigentes": entero(metricas.get("vigentes"), len(vigentes)),
        "movimientos_recientes": entero(metricas.get("movimiento_7d"), len(con_novedad)),
        "movimientos_30d": entero(metricas.get("movimiento_30d")),
        "novedades_corrida": novedades_corrida,
        "impacto_directo": entero(metricas.get("impacto_directo")),
        "con_urgencia": entero(metricas.get("con_urgencia")),
        "prioridad_alta": entero(metricas.get("prioridad_critica")) + entero(metricas.get("prioridad_alta")),
        "estancados_180d": entero(metricas.get("estancados_180d")),
        "ultimo": {
            "titulo": texto(ultimo.get("titulo")) or "Sin movimientos recientes",
            "detalle": " · ".join(x for x in (
                f"Boletín {texto(ultimo.get('boletin'))}" if texto(ultimo.get("boletin")) else "",
                texto(ultimo.get("ultimo_movimiento_legible")),
                texto(ultimo.get("etapa")),
            ) if x),
            "link": enlace_proyecto(ultimo),
            "fecha": (fecha_registro(ultimo).isoformat() if ultimo and fecha_registro(ultimo) else ""),
        },
        "serie_7d": serie_dias(vigentes, ref, 7),
        "alertas": alertas,
        "actividad": actividad,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--entrada", default="datos.json")
    parser.add_argument("--salida", default="resumen.json")
    args = parser.parse_args()

    entrada = (BASE / args.entrada).resolve()
    salida = (BASE / args.salida).resolve()
    if not entrada.exists():
        raise SystemExit(f"No existe {entrada.name}")

    try:
        datos = json.loads(entrada.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"No fue posible leer {entrada.name}: {exc}") from exc

    if isinstance(datos.get("proyectos"), list):
        resumen = resumen_legislativo(datos)
    elif isinstance(datos.get("prensa"), list):
        resumen = resumen_prensa(datos)
    else:
        raise SystemExit("datos.json no contiene 'prensa' ni 'proyectos'")

    contenido = json.dumps(resumen, ensure_ascii=False, indent=2) + "\n"
    salida.write_text(contenido, encoding="utf-8")
    print(
        f"Resumen generado: {salida.name} · tipo={resumen['tipo']} · "
        f"{salida.stat().st_size} bytes"
    )

    public = BASE / "public"
    if public.exists() and public.is_dir():
        destino_publico = public / salida.name
        destino_publico.write_text(contenido, encoding="utf-8")
        print(f"Resumen copiado a: {destino_publico.relative_to(BASE)}")


if __name__ == "__main__":
    main()
