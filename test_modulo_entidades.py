#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import tempfile
import unittest
from pathlib import Path

import modulo_entidades as E


class ModuloEntidadesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = E.carga_config(Path(__file__).resolve().parent / "entidades_config.json")
        cls.nlp, cls.modelo, cls.estadistico = E.cargar_pipeline("__blank__", cls.config, solo_reglas=True)

    def test_alias_uaf(self):
        aliases = E.mapa_aliases(self.config)
        canonico, tipo, exacto = E.canoniza("UAF", "ORGANIZACION", aliases)
        self.assertEqual(canonico, "Unidad de Análisis Financiero")
        self.assertEqual(tipo, "ORGANISMO_PUBLICO")
        self.assertTrue(exacto)

    def test_detecta_razon_social_chilena(self):
        texto = "La Fiscalía investiga a Inversiones Costa Sur SpA por transferencias." 
        hallazgos = E.extrae_reglas(texto)
        empresas = [x for x in hallazgos if x["label"] == "EMPRESA"]
        self.assertTrue(empresas, hallazgos)
        self.assertIn("Inversiones Costa Sur SpA", [x["texto"] for x in empresas])

    def test_enriquece_solo_publicaciones_aceptadas(self):
        datos = {
            "version_motor": "prueba",
            "prensa": [
                {
                    "id": "n1",
                    "titulo": "La UAF y el SII revisan a Inversiones Costa Sur SpA",
                    "resumen": "El representante Juan Pérez fue formalizado en Valparaíso.",
                    "texto_enriquecido": "La Unidad de Análisis Financiero recibió antecedentes del Servicio de Impuestos Internos.",
                    "medio": "Medio de prueba",
                    "fecha": "2026-08-03",
                    "link": "https://ejemplo.cl/noticia"
                }
            ]
        }
        salida = E.enriquecer(datos, self.nlp, self.config, self.modelo, self.estadistico)
        pub = salida["prensa"][0]
        nombres = {x["nombre_canonico"] for x in pub["entidades"]}
        self.assertIn("Unidad de Análisis Financiero", nombres)
        self.assertIn("Servicio de Impuestos Internos", nombres)
        self.assertIn("Inversiones Costa Sur SpA", nombres)
        self.assertIn("modulo_entidades", salida)
        self.assertGreaterEqual(salida["modulo_entidades"]["entidades_unicas"], 3)

    def test_escritura_atomica_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "datos.json"
            E.atomic_json_dump(ruta, {"prensa": [], "ok": True})
            self.assertTrue(ruta.exists())
            self.assertTrue(json.loads(ruta.read_text(encoding="utf-8"))["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
