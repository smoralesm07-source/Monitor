import importlib.util
import unittest
from datetime import datetime

SPEC = importlib.util.spec_from_file_location("monitor_uaf", "monitor_uaf.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MonitorUAFV7Tests(unittest.TestCase):
    def test_catalogo_ampliado(self):
        self.assertGreaterEqual(len(M.FUENTES), 45)
        for dominio in (
            "df.cl", "biobiochile.cl", "aduana.cl", "tgr.gob.cl",
            "spensiones.cl", "scj.gob.cl", "estrategiaantilavado.cl",
        ):
            self.assertIn(dominio, M.DOMINIOS_CHILENOS)
        self.assertIn("eldinamo.cl", M.DOMINIOS_CHILENOS)
        self.assertNotIn("eldynamo.cl", M.DOMINIOS_CHILENOS)
        self.assertNotIn("uaf.cl", M.DOMINIOS_CHILENOS)

    def test_deteccion_uaf_chile_nombre_completo(self):
        texto = (
            "La Unidad de Análisis Financiero de Chile recibió antecedentes "
            "sobre operaciones sospechosas y lavado de activos."
        )
        reg = {
            "titulo": texto,
            "resumen": "",
            "texto_enriquecido": texto,
            "link": "https://www.df.cl/opinion/prueba-uaf",
        }
        uaf, confianza, _, puntaje, menciones = M.analiza_uaf(reg)
        self.assertTrue(uaf)
        self.assertEqual(confianza, "alta")
        self.assertGreaterEqual(puntaje, 10)
        self.assertGreaterEqual(menciones, 1)

    def test_deteccion_accion_informo_a_uaf(self):
        texto = (
            "El Servicio Nacional de Aduanas informó a la UAF los antecedentes "
            "del contrabando detectado en Valparaíso, Chile."
        )
        reg = {
            "titulo": "Contrabando detectado por Aduanas",
            "resumen": "",
            "texto_enriquecido": texto,
            "link": "https://www.aduana.cl/noticia/prueba",
        }
        self.assertTrue(M.analiza_uaf(reg)[0])
        self.assertEqual(M.origen_mencion_uaf(reg, True), "cuerpo")

    def test_excluye_uaf_extranjera(self):
        texto = (
            "La UAF Panamá informó a la Fiscalía de Panamá sobre una operación "
            "sospechosa ocurrida en Ciudad de Panamá."
        )
        reg = {
            "titulo": texto,
            "resumen": "",
            "texto_enriquecido": texto,
            "link": "https://www.df.cl/internacional/prueba",
        }
        self.assertFalse(M.analiza_uaf(reg)[0])

    def test_contexto_laft_sin_uaf(self):
        texto = (
            "Fiscalía investiga lavado de activos, testaferros y cuentas puente "
            "utilizadas por una organización criminal en Chile."
        )
        reg = {
            "titulo": texto,
            "resumen": "",
            "texto_enriquecido": texto,
            "link": "https://www.biobiochile.cl/noticias/prueba.shtml",
        }
        self.assertTrue(M.es_pertinente(reg))
        self.assertFalse(M.analiza_uaf(reg)[0])

    def test_barrido_equilibrado(self):
        candidatos = []
        for host in ("df.cl", "biobiochile.cl", "emol.com"):
            for i in range(5):
                candidatos.append({
                    "link": f"https://{host}/2026/07/{10+i}/articulo-{i}",
                    "titulo": f"Artículo {i}",
                    "_puntaje": 20 - i,
                    "fecha_dt": None,
                })
        elegidos = M.selecciona_barrido_equilibrado(candidatos, 6, minimo=2)
        hosts = [M.dominio_url(x["link"]) for x in elegidos]
        for host in ("df.cl", "biobiochile.cl", "emol.com"):
            self.assertGreaterEqual(hosts.count(host), 2)

    def test_parser_feed_rss(self):
        xml = b"""<?xml version='1.0'?><rss><channel><item>
        <title>Noticia UAF Chile</title><link>https://www.df.cl/noticia</link>
        <description>La Unidad de Analisis Financiero</description>
        <pubDate>Wed, 29 Jul 2026 12:00:00 -0400</pubDate>
        </item></channel></rss>"""
        regs = M.parsea_feed(xml, "https://www.df.cl/", "prueba")
        self.assertEqual(len(regs), 1)
        self.assertEqual(M.dominio_url(regs[0]["link"]), "df.cl")
        self.assertIsInstance(regs[0]["fecha_dt"], datetime)

    def test_parser_feed_atom(self):
        xml = b"""<?xml version='1.0' encoding='utf-8'?>
        <feed xmlns='http://www.w3.org/2005/Atom'>
          <entry><title>Actividad de la UAF Chile</title>
          <link href='https://www.uaf.cl/es-cl/noticia-detalle?id=1'/>
          <summary>Unidad de Analisis Financiero</summary>
          <updated>2026-07-29T12:00:00-04:00</updated></entry>
        </feed>"""
        regs = M.parsea_feed(xml, "https://www.uaf.cl/", "prueba_atom")
        self.assertEqual(len(regs), 1)
        self.assertEqual(M.dominio_url(regs[0]["link"]), "uaf.cl")
        self.assertIn("Actividad", regs[0]["titulo"])
        self.assertIsInstance(regs[0]["fecha_dt"], datetime)

    def test_metricas_compatibles(self):
        ahora = M.ahora_cl()
        r = {
            "id": "1", "fecha": ahora.strftime("%Y-%m-%d"), "fecha_hora": ahora.isoformat(),
            "medio": "Diario Financiero", "titulo": "UAF", "link": "https://www.df.cl/a",
            "uaf": True, "fuente_institucional": False, "topicos": ["prevencion"],
            "fenomeno": "otro", "naturaleza": "analisis", "tipo_medio": "economico",
            "sujetos_obligados": [], "impactos_sujeto": [], "precedentes": ["indeterminado"],
        }
        dias = [ahora.strftime("%Y-%m-%d")]
        m = M.calcula_metricas([r], [], dias, ahora)
        for clave in ("uaf_portada", "uaf_total", "volumen", "por_dia", "fenomenos", "topicos"):
            self.assertIn(clave, m)
        self.assertEqual(m["uaf_total"], 1)


    def test_serializacion_json_datetime(self):
        dato = {"fecha_dt": datetime(2026, 7, 30, 9, 15)}
        texto = M.json.dumps(dato, default=M.json_default)
        self.assertIn("2026-07-30T09:15:00", texto)

    def test_semillas_verificadas_garantizan_latercera_3_julio(self):
        semillas = M.descubre_semillas_verificadas()
        self.assertGreaterEqual(len(semillas), 30)
        url = M.url_canonica("https://www.latercera.com/opinion/noticia/inteligencia-financiera-para-un-mundo-geoeconomico/")
        reg = next((x for x in semillas if x.get("link") == url), None)
        self.assertIsNotNone(reg)
        self.assertTrue(reg.get("verificacion_manual"))
        self.assertTrue(M.analiza_uaf(reg)[0])

    def test_historico_excluye_portal_uaf(self):
        ahora = M.ahora_cl()
        registros = [
            {"id":"uaf","fecha":ahora.strftime("%Y-%m-%d"),"fecha_hora":ahora.isoformat(),
             "titulo":"UAF institucional","link":"https://www.uaf.cl/es-cl/noticia-detalle?id=1","uaf":True},
            {"id":"lt","fecha":ahora.strftime("%Y-%m-%d"),"fecha_hora":ahora.isoformat(),
             "titulo":"La Tercera menciona UAF","link":"https://www.latercera.com/opinion/noticia/prueba/","uaf":True},
        ]
        mezcla = M.mezcla_historico(registros, [])
        self.assertEqual(len(mezcla), 1)
        self.assertEqual(M.dominio_url(mezcla[0]["link"]), "latercera.com")

    def test_ip_privada_bloqueada(self):
        self.assertFalse(M.ip_publica("127.0.0.1"))
        self.assertFalse(M.ip_publica("10.0.0.1"))
        self.assertTrue(M.ip_publica("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
