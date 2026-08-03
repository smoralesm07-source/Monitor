#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import tempfile
import unittest
from pathlib import Path

import modulo_entidades as E


class AnalisisRelacionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(__file__).resolve().parent
        cls.config = E.carga_config(cls.base / "entidades_config.json")
        cls.nlp, cls.modelo, cls.estadistico = E.cargar_pipeline(
            "__blank__", cls.config, solo_reglas=True
        )

    def datos_prueba(self):
        return {
            "version_motor": "prueba",
            "prensa": [
                {
                    "id": "n1",
                    "titulo": "Fiscalía formaliza a empresario por lavado",
                    "resumen": (
                        "La Fiscalía de Chile formalizó a Juan Pérez, representante "
                        "de Inversiones Costa Sur SpA, por lavado de activos y delitos "
                        "tributarios en Valparaíso."
                    ),
                    "texto_enriquecido": (
                        "La Unidad de Análisis Financiero recibió antecedentes del "
                        "Servicio de Impuestos Internos. Juan Pérez, representante de "
                        "Inversiones Costa Sur SpA, operaba en Valparaíso. La Fiscalía "
                        "de Chile formalizó a Juan Pérez."
                    ),
                    "medio": "Medio de prueba",
                    "fecha": "2026-08-03",
                    "link": "https://ejemplo.cl/noticia-1",
                    "fenomeno": "corrupcion",
                    "fenomeno_label": "Corrupción",
                    "precedentes": ["tributarios"],
                    "precedentes_label": ["Delitos tributarios"],
                    "sujetos_obligados": ["vehiculos_leasing_factoring"],
                    "sujetos_obligados_label": ["Vehículos, leasing y factoring"],
                    "topicos": ["investigacion_penal"],
                    "topicos_label": ["Investigación y persecución penal"],
                    "uaf": True,
                },
                {
                    "id": "n2",
                    "titulo": "Nueva arista de Inversiones Costa Sur SpA",
                    "resumen": (
                        "El SII investiga a Inversiones Costa Sur SpA. Juan Pérez, "
                        "socio de Inversiones Costa Sur SpA, realizó transferencias "
                        "con BancoEstado desde Santiago."
                    ),
                    "texto_enriquecido": (
                        "El Servicio de Impuestos Internos investiga a Inversiones "
                        "Costa Sur SpA. Juan Pérez, socio de Inversiones Costa Sur SpA, "
                        "realizó transferencias con BancoEstado desde Santiago."
                    ),
                    "medio": "Otro medio",
                    "fecha": "2026-08-04",
                    "link": "https://ejemplo.cl/noticia-2",
                    "fenomeno": "corrupcion",
                    "fenomeno_label": "Corrupción",
                    "precedentes": ["tributarios"],
                    "precedentes_label": ["Delitos tributarios"],
                    "sujetos_obligados": ["banca_finanzas"],
                    "sujetos_obligados_label": ["Banca y servicios financieros"],
                    "topicos": ["investigacion_penal"],
                    "topicos_label": ["Investigación y persecución penal"],
                    "uaf": True,
                },
            ],
        }

    def test_alias_y_geografia(self):
        aliases = E.mapa_aliases(self.config)
        canonico, tipo, exacto, geo = E.canoniza("UAF", "ORGANIZACION", aliases)
        self.assertEqual(canonico, "Unidad de Análisis Financiero")
        self.assertEqual(tipo, "ORGANISMO_PUBLICO")
        self.assertTrue(exacto)
        lugar, tipo_lugar, _, geo_lugar = E.canoniza("Valparaiso", "LUGAR", aliases)
        self.assertEqual(lugar, "Valparaíso")
        self.assertEqual(tipo_lugar, "LUGAR")
        self.assertAlmostEqual(geo_lugar["lat"], -33.0472)

    def test_detecta_persona_y_empresa(self):
        texto = (
            "La Fiscalía formalizó a Juan Pérez, representante de "
            "Inversiones Costa Sur SpA."
        )
        hallazgos = E.extrae_reglas(texto)
        pares = {(x["label"], x["texto"]) for x in hallazgos}
        self.assertIn(("PERSONA", "Juan Pérez"), pares)
        self.assertIn(("EMPRESA", "Inversiones Costa Sur SpA"), pares)

    def test_construye_relaciones_trazables(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        analisis = salida["analisis_entidades"]
        entidades = {x["nombre"]: x for x in analisis["entidades"]}
        self.assertIn("Juan Pérez", entidades)
        self.assertIn("Inversiones Costa Sur SpA", entidades)

        explicitas = [
            r for r in analisis["relaciones"] if r["categoria"] == "explicita"
        ]
        tipos = {r["tipo"] for r in explicitas}
        self.assertIn("FORMALIZA_A", tipos)
        self.assertIn("REPRESENTA_A", tipos)
        self.assertIn("INVESTIGA_A", tipos)
        self.assertTrue(all(r["articulos"] for r in explicitas))
        self.assertTrue(any(r["evidencias"] for r in explicitas))

    def test_vincula_entidad_fenomeno_articulo_y_territorio(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        a = salida["analisis_entidades"]
        juan = next(x for x in a["entidades"] if x["nombre"] == "Juan Pérez")
        self.assertTrue(juan["fenomenos"])
        self.assertTrue(juan["lugares"])
        self.assertEqual(len(juan["articulos"]), 2)
        self.assertTrue(any(x["nombre"] == "Valparaíso" for x in a["lugares"]))
        self.assertTrue(any(x["nombre"] == "Santiago" for x in a["lugares"]))

    def test_agrupa_articulos_en_caso(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        casos = salida["analisis_entidades"]["casos"]
        self.assertEqual(len(casos), 1)
        self.assertEqual(casos[0]["cantidad_articulos"], 2)
        self.assertEqual(casos[0]["tipo"], "caso_consolidado")
        self.assertTrue(all(pub["caso_ids"] for pub in salida["prensa"]))

    def test_nomina_por_articulo_con_roles_y_relaciones(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        articulos = salida["analisis_entidades"]["articulos"]
        self.assertTrue(all(a.get("nomina_entidades") for a in articulos))
        primera = articulos[0]["nomina_entidades"]
        juan = next(x for x in primera if x["nombre"] == "Juan Pérez")
        self.assertTrue(any(r.startswith("formalizado por") for r in juan["roles"]))
        self.assertTrue(juan["relaciones_explicitas"])
        self.assertEqual(juan["articulo_id"], "ART-n1")

    def test_nomina_consolidada_por_caso(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        caso = salida["analisis_entidades"]["casos"][0]
        self.assertTrue(caso.get("nomina_entidades"))
        juan = next(x for x in caso["nomina_entidades"] if x["nombre"] == "Juan Pérez")
        self.assertEqual(juan["cantidad_articulos"], 2)
        self.assertTrue(juan["roles"])

    def test_config_v1_se_completa_con_relaciones_y_geografia(self):
        config_v1 = {
            "version": "1.0",
            "aliases": self.config.get("aliases", []),
            "roles": self.config.get("roles", []),
            "relaciones": [],
            "lugares": [],
        }
        completa = E.completa_config(config_v1)
        self.assertGreaterEqual(len(completa["relaciones"]), 11)
        self.assertGreaterEqual(len(completa["lugares"]), 30)
        aliases = E.mapa_aliases(completa)
        lugar, tipo, exacto, geo = E.canoniza("Valparaiso", "LUGAR", aliases)
        self.assertEqual(lugar, "Valparaíso")
        self.assertEqual(tipo, "LUGAR")
        self.assertTrue(exacto)
        self.assertAlmostEqual(geo["lat"], -33.0472)

        nlp, modelo, estadistico = E.cargar_pipeline(
            "__blank__", completa, solo_reglas=True
        )
        salida = E.enriquecer(
            self.datos_prueba(), nlp, completa, modelo, estadistico
        )
        tipos = {
            r["tipo"] for r in salida["analisis_entidades"]["relaciones"]
            if r["categoria"] == "explicita"
        }
        self.assertIn("FORMALIZA_A", tipos)
        juan = next(
            x for x in salida["analisis_entidades"]["entidades"]
            if x["nombre"] == "Juan Pérez"
        )
        self.assertTrue(juan["lugares"])

    def test_compatibilidad_workflow(self):
        salida = E.enriquecer(
            self.datos_prueba(), self.nlp, self.config, self.modelo, self.estadistico
        )
        self.assertEqual(
            salida["modulo_entidades"]["version"],
            E.VERSION_MODULO,
        )
        self.assertGreater(salida["modulo_entidades"]["entidades_unicas"], 0)

    def test_escritura_atomica(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "datos.json"
            E.atomic_json_dump(ruta, {"prensa": [], "ok": True})
            self.assertTrue(json.loads(ruta.read_text(encoding="utf-8"))["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
