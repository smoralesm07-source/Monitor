import importlib.util
import unittest

SPEC = importlib.util.spec_from_file_location("monitor_uaf", "monitor_uaf.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MonitorUAFTests(unittest.TestCase):
    def test_catalogo_minimo(self):
        self.assertGreaterEqual(len(M.DOMINIOS_MINIMOS), 27)
        self.assertIn("df.cl", M.DOMINIOS_MINIMOS)
        self.assertIn("biobiochile.cl", M.DOMINIOS_MINIMOS)
        self.assertIn("eldinamo.cl", M.DOMINIOS_MINIMOS)
        self.assertNotIn("eldynamo.cl", M.DOMINIOS_MINIMOS)
        self.assertTrue(set(M.DOMINIOS_MINIMOS).issubset(M.DOMINIOS_CHILENOS))

    def test_deteccion_df(self):
        texto = ("Más allá de la UAF: conocer la ruta del dinero es tarea de todos. "
                 "La Unidad de Análisis Financiero de Chile previene el lavado de activos.")
        reg = {"titulo": texto, "medio": "Diario Financiero", "link": "https://www.df.cl/opinion/prueba",
               "fuente_url": "https://www.df.cl", "texto_enriquecido": texto}
        uaf, confianza, _, puntaje, menciones = M.analiza_uaf(reg)
        self.assertTrue(uaf)
        self.assertEqual(confianza, "alta")
        self.assertGreaterEqual(puntaje, 7)
        self.assertGreaterEqual(menciones, 1)

    def test_deteccion_biobio(self):
        texto = ("Del robo al lavado de dinero: economías ilícitas en Chile. "
                 "La UAF recibe reportes de operaciones sospechosas de entidades financieras.")
        reg = {"titulo": texto, "medio": "BioBioChile", "link": "https://www.biobiochile.cl/noticias/prueba.shtml",
               "fuente_url": "https://www.biobiochile.cl", "texto_enriquecido": texto}
        self.assertTrue(M.analiza_uaf(reg)[0])
        self.assertTrue(M.es_pertinente(reg))

    def test_parser_duckduckgo(self):
        html = b'''<html><body><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.df.cl%2Fopinion%2Fnoticia-uaf">Noticia UAF</a></body></html>'''
        resultados = M.parsea_resultados_duckduckgo(html, "UAF")
        self.assertEqual(len(resultados), 1)
        self.assertEqual(M.dominio_url(resultados[0]["link"]), "df.cl")

    def test_parser_portada(self):
        html = b'''<html><body><a href="/noticias/economia/2026/07/03/del-robo-al-lavado-de-dinero.shtml">Del robo al lavado de dinero en Chile</a></body></html>'''
        resultados = M.extrae_enlaces_portada(html, "https://www.biobiochile.cl/", "biobiochile.cl", "BioBioChile")
        self.assertEqual(len(resultados), 1)
        self.assertEqual(M.dominio_url(resultados[0]["link"]), "biobiochile.cl")
        self.assertTrue(resultados[0]["fecha_estimada"])

    def test_barrido_equilibrado(self):
        candidatos = []
        for host in ("df.cl", "biobiochile.cl", "emol.com"):
            for i in range(4):
                candidatos.append({"link": f"https://{host}/2026/07/2{i}/articulo-{i}-muy-largo",
                                   "titulo": f"Artículo {i} de {host}", "_puntaje": i, "fecha_dt": None})
        elegidos = M.selecciona_barrido_equilibrado(candidatos, 6)
        hosts = [M.dominio_url(x["link"]) for x in elegidos]
        for host in ("df.cl", "biobiochile.cl", "emol.com"):
            self.assertGreaterEqual(hosts.count(host), 2)


if __name__ == "__main__":
    unittest.main()
