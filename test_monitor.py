#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pruebas automáticas del Monitor UAF Chile.

Corrección principal:
La integridad de semillas se valida directamente contra
semillas_verificadas.json. No se usa descubre_semillas_verificadas(),
porque esa función filtra legítimamente por la ventana móvil del dashboard.
"""

import importlib.util
import json
import unittest
from datetime import datetime
from pathlib import Path


BASE = Path(__file__).resolve().parent
RUTA_MONITOR = BASE / "monitor_uaf.py"
RUTA_SEMILLAS = BASE / "semillas_verificadas.json"

VERSION_TEST_MONITOR = "2026-08-03-fix-catalogo-uaf-v2"

SPEC = importlib.util.spec_from_file_location("monitor_uaf", RUTA_MONITOR)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"No fue posible cargar {RUTA_MONITOR}")

M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MonitorUAFV7Tests(unittest.TestCase):
    def test_barrido_equilibrado(self):
        ahora = M.ahora_cl()
        candidatos = [
            {
                "titulo": f"Noticia DF {i}",
                "link": f"https://www.df.cl/noticia-{i}",
                "fecha_dt": ahora,
                "_puntaje": 20 - i,
            }
            for i in range(4)
        ]
        candidatos += [
            {
                "titulo": f"Noticia BioBio {i}",
                "link": f"https://www.biobiochile.cl/noticias/prueba-{i}.shtml",
                "fecha_dt": ahora,
                "_puntaje": 16 - i,
            }
            for i in range(4)
        ]
        candidatos += [
            {
                "titulo": f"Noticia Emol {i}",
                "link": f"https://www.emol.com/noticias/Nacional/2026/08/03/prueba-{i}.html",
                "fecha_dt": ahora,
                "_puntaje": 12 - i,
            }
            for i in range(2)
        ]

        seleccion = M.selecciona_barrido_equilibrado(candidatos, 6)
        dominios = {M.dominio_url(x.get("link", "")) for x in seleccion}

        self.assertEqual(len(seleccion), 6)
        self.assertGreaterEqual(
            len(dominios),
            2,
            "El barrido debe evitar que un único medio ocupe todos los cupos.",
        )

    def test_catalogo_ampliado(self):
        dominios = set(M.DOMINIOS_CHILENOS)

        self.assertGreaterEqual(
            len(dominios),
            25,
            f"El catálogo chileno parece incompleto: contiene {len(dominios)} dominios.",
        )
        for dominio in (
            "df.cl",
            "latercera.com",
            "biobiochile.cl",
            "cooperativa.cl",
            "t13.cl",
            "meganoticias.cl",
        ):
            self.assertIn(dominio, dominios)

        self.assertIn(
            "uaf.cl",
            set(M.DOMINIOS_EXCLUIDOS_PUBLICACION),
            "El portal institucional uaf.cl debe excluirse de las publicaciones del monitor.",
        )

    def test_contexto_laft_sin_uaf(self):
        reg = {
            "titulo": "Fiscalía investiga esquema de lavado de activos",
            "resumen": (
                "La investigación sigue la ruta del dinero, transferencias "
                "y beneficiarios finales de una organización criminal."
            ),
            "texto_enriquecido": (
                "La Fiscalía indaga lavado de activos mediante sociedades, "
                "cuentas bancarias, testaferros y operaciones sospechosas. "
                "Los fondos habrían sido transferidos para ocultar su origen."
            ),
            "medio": "Diario Financiero",
            "link": "https://www.df.cl/economia-y-politica/prueba-contexto-laft",
            "calidad_cuerpo": "alta",
            "origen_cuerpo": "article",
        }

        self.assertFalse(M.analiza_uaf(reg)[0])
        resultado = M.evalua_contexto_laft(reg)
        self.assertTrue(resultado.get("valido"), resultado)
        self.assertGreaterEqual(int(resultado.get("puntaje", 0)), 9)

    def test_deteccion_accion_informo_a_uaf(self):
        texto = (
            "Aduanas detectó dinero oculto durante una fiscalización. "
            "Los antecedentes fueron informados a la UAF para analizar "
            "el origen de los fondos y posibles operaciones sospechosas."
        )
        reg = {
            "titulo": "Aduanas informó antecedentes a la UAF",
            "resumen": texto,
            "texto_enriquecido": texto,
            "medio": "Servicio Nacional de Aduanas",
            "link": "https://www.aduana.cl/noticia-prueba/aduana/2026-08-03/120000.html",
            "calidad_cuerpo": "alta",
            "origen_cuerpo": "article",
        }

        valido, confianza, motivos, puntaje, menciones = M.analiza_uaf(reg)
        self.assertTrue(valido, motivos)
        self.assertIn(confianza, {"media", "alta"})
        self.assertGreaterEqual(puntaje, 7)
        self.assertGreaterEqual(menciones, 1)

    def test_deteccion_uaf_chile_nombre_completo(self):
        texto = (
            "La Unidad de Análisis Financiero de Chile informó nuevas medidas "
            "para fortalecer la prevención del lavado de activos."
        )
        reg = {
            "titulo": texto,
            "resumen": "",
            "texto_enriquecido": texto,
            "medio": "Diario Constitucional",
            "link": "https://www.diarioconstitucional.cl/2026/08/03/prueba-uaf-chile/",
            "calidad_cuerpo": "alta",
            "origen_cuerpo": "article",
        }

        valido, _, motivos, _, menciones = M.analiza_uaf(reg)
        self.assertTrue(valido, motivos)
        self.assertGreaterEqual(menciones, 1)

    def test_excluye_uaf_extranjera(self):
        texto = (
            "La Unidad de Análisis Financiero de Panamá emitió una alerta. "
            "La UAF de Panamá revisará las operaciones reportadas en ese país."
        )
        reg = {
            "titulo": "La UAF de Panamá emitió una alerta",
            "resumen": texto,
            "texto_enriquecido": texto,
            "medio": "Medio extranjero",
            "link": "https://www.df.cl/prueba-referencia-extranjera",
            "calidad_cuerpo": "alta",
            "origen_cuerpo": "article",
        }

        valido, confianza, motivos, _, _ = M.analiza_uaf(reg)
        self.assertFalse(valido, motivos)
        self.assertIn(confianza, {"baja", "excluida", "sin_mencion"})

    def test_historico_excluye_portal_uaf(self):
        ahora = M.ahora_cl()
        fecha_iso = ahora.isoformat()
        fecha = ahora.strftime("%Y-%m-%d")

        registros = [
            {
                "id": "portal-uaf",
                "titulo": "Publicación del portal UAF",
                "link": "https://www.uaf.cl/prensa/archivo",
                "fecha": fecha,
                "fecha_hora": fecha_iso,
                "medio": "UAF",
                "uaf": True,
                "fecha_publicacion_verificada": True,
            },
            {
                "id": "medio-externo",
                "titulo": "Medio externo informa sobre la UAF",
                "link": "https://www.df.cl/opinion/prueba-uaf",
                "fecha": fecha,
                "fecha_hora": fecha_iso,
                "medio": "Diario Financiero",
                "uaf": True,
                "fecha_publicacion_verificada": True,
            },
        ]

        salida = M.mezcla_historico([], registros)
        hosts = {M.dominio_url(r.get("link", "")) for r in salida}

        self.assertNotIn("uaf.cl", hosts)
        self.assertIn("df.cl", hosts)

    def test_ip_privada_bloqueada(self):
        for ip in (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.10.20",
            "::1",
        ):
            with self.subTest(ip=ip):
                self.assertFalse(M.ip_publica(ip))

        self.assertTrue(M.ip_publica("8.8.8.8"))

    def test_metricas_compatibles(self):
        ahora = M.ahora_cl()
        dias = [ahora.strftime("%Y-%m-%d")]

        metricas = M.calcula_metricas([], [], dias, ahora)

        self.assertIsInstance(metricas, dict)
        self.assertIn("uaf_portada", metricas)
        self.assertIn("uaf_total", metricas)
        self.assertIn("contexto_total", metricas)
        self.assertIn("volumen", metricas)

        json.dumps(metricas, ensure_ascii=False, default=M.json_default)

    def test_parser_feed_atom(self):
        atom = b"""<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <title>Noticias de prueba</title>
          <entry>
            <title>Unidad de Analisis Financiero informa nuevas medidas</title>
            <link href="https://www.df.cl/noticia-atom-uaf"/>
            <updated>2026-08-03T10:00:00-04:00</updated>
            <summary>Informacion sobre prevencion del lavado de activos.</summary>
          </entry>
        </feed>"""

        resultados = M.parsea_feed(
            atom,
            "https://www.df.cl/feed.atom",
            "prueba_atom",
        )

        self.assertEqual(len(resultados), 1)
        self.assertEqual(M.dominio_url(resultados[0].get("link", "")), "df.cl")
        self.assertIn("Unidad de Analisis Financiero", resultados[0].get("titulo", ""))

    def test_parser_feed_rss(self):
        rss = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Noticias de prueba</title>
            <item>
              <title>Aduanas informo antecedentes a la UAF</title>
              <link>https://www.biobiochile.cl/noticias/prueba-rss-uaf.shtml</link>
              <pubDate>Mon, 03 Aug 2026 10:00:00 -0400</pubDate>
              <description>Noticia sobre operaciones sospechosas.</description>
            </item>
          </channel>
        </rss>"""

        resultados = M.parsea_feed(
            rss,
            "https://www.biobiochile.cl/rss.xml",
            "prueba_rss",
        )

        self.assertEqual(len(resultados), 1)
        self.assertEqual(
            M.dominio_url(resultados[0].get("link", "")),
            "biobiochile.cl",
        )
        self.assertIn("UAF", resultados[0].get("titulo", ""))

    def test_semillas_verificadas_garantizan_latercera_3_julio(self):
        """
        Valida el catálogo histórico completo.

        Esta prueba no debe llamar a descubre_semillas_verificadas(), porque
        esa función devuelve únicamente las semillas activas dentro de la
        ventana móvil del dashboard.
        """
        self.assertTrue(
            RUTA_SEMILLAS.exists(),
            f"No existe el archivo requerido: {RUTA_SEMILLAS}",
        )

        try:
            contenido = json.loads(RUTA_SEMILLAS.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"semillas_verificadas.json no es JSON válido: {exc}")

        semillas = (
            contenido.get("semillas", [])
            if isinstance(contenido, dict)
            else contenido
        )

        self.assertIsInstance(semillas, list)
        self.assertGreaterEqual(
            len(semillas),
            30,
            (
                "El catálogo histórico debe contener al menos 30 semillas; "
                f"se encontraron {len(semillas)}."
            ),
        )

        objetivo = (
            "https://www.latercera.com/opinion/noticia/"
            "inteligencia-financiera-para-un-mundo-geoeconomico"
        )

        por_link = {}
        for semilla in semillas:
            if not isinstance(semilla, dict):
                continue
            link = str(semilla.get("link", "")).strip().rstrip("/")
            if link:
                por_link[link] = semilla

        self.assertIn(
            objetivo,
            por_link,
            "Falta la semilla obligatoria de La Tercera del 3 de julio de 2026.",
        )

        semilla_objetivo = por_link[objetivo]
        self.assertEqual(semilla_objetivo.get("fecha"), "2026-07-03")
        self.assertIn("La Tercera", str(semilla_objetivo.get("medio", "")))
        self.assertTrue(
            semilla_objetivo.get("verificada"),
            "La publicación obligatoria debe estar marcada como verificada.",
        )

    def test_serializacion_json_datetime(self):
        fecha = datetime(2026, 8, 3, 10, 30, 0)
        texto = json.dumps(
            {"fecha": fecha},
            ensure_ascii=False,
            default=M.json_default,
        )

        self.assertIn("2026-08-03T10:30:00", texto)


if __name__ == "__main__":
    unittest.main(verbosity=2)
