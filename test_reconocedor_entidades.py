#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas del reconocedor de personas naturales y jurídicas (v3).

Cada caso proviene de un defecto observado al ejecutar la versión 2.1.1 sobre
texto de prensa chilena real, de modo que la suite actúa como regresión.
"""

import unittest

import reconocedor_entidades as R


class NaturalezaJuridicaTests(unittest.TestCase):
    def test_sufijo_societario_define_persona_juridica(self):
        for razon in (
            "Inversiones Costa Sur SpA",
            "Comercializadora Andes Sur S.p.A.",
            "Agrícola El Peumo Ltda.",
            "Inversiones Del Valle Limitada",
            "Consultora Gestión Local EIRL",
            "Servicios Integrales Maipú E.I.R.L.",
            "Importadora Tarapacá S.A.",
        ):
            with self.subTest(razon=razon):
                v = R.clasifica_cadena(razon)
                self.assertEqual(v["naturaleza"], "PERSONA_JURIDICA")
                self.assertFalse(v["descartar"])

    def test_razon_social_con_conector_no_se_trunca(self):
        # En v2.1.1 esto devolvía "Bolsa S.A", perdiendo la denominación.
        texto = "Participó STF Capital Corredores de Bolsa S.A. en la operación."
        hallazgos = [h for h in R.extrae_reglas(texto) if h["label"] == "EMPRESA"]
        self.assertTrue(hallazgos)
        self.assertIn("STF Capital Corredores de Bolsa", hallazgos[0]["texto"])

    def test_punto_final_de_abreviatura_se_conserva(self):
        self.assertEqual(R.limpia("Importadora Tarapacá S.A."), "Importadora Tarapacá S.A.")
        self.assertEqual(R.limpia("Frase completa."), "Frase completa")

    def test_antroponimo_es_persona_natural(self):
        for nombre in (
            "Rodrigo Andrés Pizarro Meza",
            "Marcela Ortiz Vega",
            "Karen Villalobos Núñez",
            "Álvaro Jalaff",
        ):
            with self.subTest(nombre=nombre):
                v = R.clasifica_cadena(nombre, "PER")
                self.assertEqual(v["tipo"], "PERSONA")
                self.assertEqual(v["naturaleza"], "PERSONA_NATURAL")

    def test_descarta_falsos_positivos_de_persona(self):
        for ruido in ("Según", "Sin embargo", "Caso Factop", "Operación Frontera Norte"):
            with self.subTest(ruido=ruido):
                self.assertTrue(R.clasifica_cadena(ruido, "PER")["descartar"])

    def test_sociedad_no_se_clasifica_como_persona_natural(self):
        for razon in ("Factop SpA", "Consultora Gestión Local EIRL", "Sartor Finance Group"):
            with self.subTest(razon=razon):
                v = R.clasifica_cadena(razon, "PER")
                self.assertEqual(v["naturaleza"], "PERSONA_JURIDICA")

    def test_tipifica_organos_del_estado(self):
        casos = {
            "Corte de Apelaciones de Antofagasta": "TRIBUNAL",
            "Juzgado de Garantía de Iquique": "TRIBUNAL",
            "Municipalidad de Maipú": "ORGANISMO_PUBLICO",
            "Banco de Chile": "INSTITUCION_FINANCIERA",
            "Fundación Educación 2020": "ENTIDAD_SIN_FINES_DE_LUCRO",
        }
        for nombre, tipo in casos.items():
            with self.subTest(nombre=nombre):
                self.assertEqual(R.clasifica_cadena(nombre, "ORG")["tipo"], tipo)

    def test_toda_entidad_declara_naturaleza(self):
        for tipo in ("PERSONA", "EMPRESA", "TRIBUNAL", "ORGANISMO_PUBLICO",
                     "INSTITUCION_FINANCIERA", "ENTIDAD_SIN_FINES_DE_LUCRO"):
            self.assertIn(
                R.naturaleza_de(tipo), ("PERSONA_NATURAL", "PERSONA_JURIDICA")
            )


class CanonizacionTests(unittest.TestCase):
    def test_elimina_prefijo_generico(self):
        nombre, _ = R.canoniza_denominacion("la sociedad Agrícola El Peumo Ltda.")
        self.assertEqual(nombre, "Agrícola El Peumo Ltda.")

    def test_conserva_nucleo_institucional_en_minuscula(self):
        # Recortar "seremi" dejaría "de Hacienda", que no identifica al órgano.
        nombre, _ = R.canoniza_denominacion("seremi de Hacienda")
        self.assertEqual(nombre, "Seremi de Hacienda")

    def test_span_no_cruza_fin_de_oracion(self):
        texto = "Operaba Comercializadora Andes Sur SpA. El fiscal declaró ayer."
        inicio = texto.index("Comercializadora")
        _, fin = R.recorta_span(texto, inicio, len(texto))
        self.assertEqual(texto[inicio:fin], "Comercializadora Andes Sur SpA.")


class RutTests(unittest.TestCase):
    def test_digito_verificador(self):
        self.assertEqual(R.digito_verificador("12345678"), "5")
        self.assertEqual(R.digito_verificador("76543210"), "3")

    def test_rechaza_dv_incorrecto(self):
        self.assertFalse(R.valida_rut("12.345.678-9")["valido"])

    def test_indica_naturaleza_por_rango(self):
        self.assertEqual(
            R.valida_rut("76.543.210-3")["naturaleza_indicativa"], "PERSONA_JURIDICA"
        )
        self.assertEqual(
            R.valida_rut("12.345.678-5")["naturaleza_indicativa"], "PERSONA_NATURAL"
        )

    def test_asocia_rut_a_la_entidad_mas_cercana(self):
        texto = "Ana María Soto Vergara, RUT 12.345.678-5, es representante legal."
        candidatos = R.depura_candidatos(R.extrae_reglas(texto, incluir_rut=True))
        R.rut_por_proximidad(texto, candidatos)
        personas = [c for c in candidatos if c["label"] == "PERSONA"]
        self.assertTrue(personas)
        self.assertEqual(personas[0]["ruts"][0]["rut"], "12.345.678-5")


class SolapamientoTests(unittest.TestCase):
    def test_una_cadena_no_genera_dos_tipos(self):
        # En v2.1.1 "Factop SpA" quedaba como PERSONA y como EMPRESA a la vez.
        candidatos = [
            {"texto": "Factop SpA", "label": "PERSONA", "inicio": 0, "fin": 10, "score": 0.6},
            {"texto": "Factop SpA", "label": "EMPRESA", "inicio": 0, "fin": 10, "score": 0.9},
        ]
        salida = R.depura_candidatos(candidatos)
        self.assertEqual(len(salida), 1)
        self.assertEqual(salida[0]["label"], "EMPRESA")
        self.assertTrue(salida[0]["spans_absorbidos"])

    def test_monto_no_compite_con_nombres(self):
        candidatos = [
            {"texto": "Andes SpA", "label": "EMPRESA", "inicio": 0, "fin": 9, "score": 0.9},
            {"texto": "$2.500 millones", "label": "MONTO", "inicio": 5, "fin": 20, "score": 0.9},
        ]
        self.assertEqual(len(R.depura_candidatos(candidatos)), 2)


class CorreferenciaTests(unittest.TestCase):
    def test_unifica_forma_corta_de_persona(self):
        ok, _ = R.son_correferentes_persona("Marcela Ortiz Vega", "Marcela Ortiz")
        self.assertTrue(ok)
        ok, _ = R.son_correferentes_persona("Jorge Alberto Castillo Rojas", "Castillo Rojas")
        self.assertTrue(ok)

    def test_no_unifica_hermanos_ni_homonimos_parciales(self):
        self.assertFalse(R.son_correferentes_persona("Ariel Sauer", "Daniel Sauer")[0])
        self.assertFalse(R.son_correferentes_persona("Antonio Jalaff", "Álvaro Jalaff")[0])

    def test_no_unifica_sociedades_distintas_del_mismo_grupo(self):
        ok, _ = R.son_correferentes_juridica(
            "Sartor Finance Group", "Sartor Administradora General de Fondos S.A.", "EMPRESA"
        )
        self.assertFalse(ok)

    def test_unifica_forma_corta_de_organo(self):
        ok, _ = R.son_correferentes_juridica(
            "Corte de Apelaciones de Antofagasta", "Corte de Apelaciones", "TRIBUNAL"
        )
        self.assertTrue(ok)

    def test_agrupa_correferencias_elige_la_forma_mas_completa(self):
        entidades = [
            {"id": "A", "nombre_canonico": "Marcela Ortiz", "tipo": "PERSONA",
             "naturaleza": "PERSONA_NATURAL"},
            {"id": "B", "nombre_canonico": "Marcela Ortiz Vega", "tipo": "PERSONA",
             "naturaleza": "PERSONA_NATURAL"},
        ]
        mapa = R.agrupa_correferencias(entidades)
        self.assertEqual(mapa["A"]["id_canonico"], "B")


class ConfigTests(unittest.TestCase):
    def test_extiende_config_agrega_lexico_y_amplia_relaciones(self):
        base = {
            "aliases": [],
            "roles": [],
            "relaciones": [{
                "tipo": "CONDENA_A", "patron": "condenó a", "ambito": "entre",
                "origen_tipos": ["ORGANISMO_PUBLICO"], "destino_tipos": ["PERSONA"],
            }],
        }
        salida = R.extiende_config(base)
        canonicos = {a["canonico"] for a in salida["aliases"]}
        self.assertIn("Scotiabank Chile", canonicos)
        regla = salida["relaciones"][0]
        self.assertIn("TRIBUNAL", regla["origen_tipos"])

    def test_no_duplica_al_extender_dos_veces(self):
        salida = R.extiende_config(R.extiende_config({"aliases": [], "roles": [], "relaciones": []}))
        canonicos = [a["canonico"] for a in salida["aliases"]]
        self.assertEqual(len(canonicos), len(set(canonicos)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
