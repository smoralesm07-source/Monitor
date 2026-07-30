import importlib.util
from pathlib import Path

RUTA = Path(__file__).with_name('monitor_uaf.py')
spec = importlib.util.spec_from_file_location('monitor_uaf', RUTA)
m = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(m)


def extrae(html: str, url: str = 'https://www.eldinamo.cl/sociedad/2026/07/29/prueba/'):
    return m.extrae_articulo_html(html.encode('utf-8'), url, {'content-type': 'text/html; charset=utf-8'})


def test_recomendacion_fuera_articulo_no_contamina():
    html = '''<html><head><meta property="og:title" content="Virus que causan fiebre hemorrágica"></head>
    <body><main><article><div class="article-content">
    <p>La fiebre hemorrágica puede ser producida por distintos virus y requiere diagnóstico clínico especializado.</p>
    <p>El artículo explica las vías de contagio y las medidas sanitarias aplicables en Chile.</p>
    </div></article><section class="related-posts"><p>Una columna pide fortalecer las facultades de la UAF frente al lavado de activos.</p></section></main></body></html>'''
    art = extrae(html)
    assert 'UAF' not in art['texto_enriquecido']
    reg = {**art, 'link': art['url_final'], 'medio': 'El Dínamo'}
    assert m.analiza_uaf(reg)[0] is False


def test_mencion_real_en_cuerpo_se_conserva():
    html = '''<html><head><meta property="og:title" content="Aduanas detecta operación irregular"></head>
    <body><main><article><div class="article-content">
    <p>Aduanas detectó una operación irregular en el puerto de Valparaíso durante una fiscalización.</p>
    <p>Los antecedentes fueron remitidos a la UAF para el análisis de posibles operaciones de lavado de activos.</p>
    </div></article></main></body></html>'''
    art = extrae(html, 'https://www.eldinamo.cl/pais/2026/07/29/aduanas-operacion/')
    assert 'UAF' in art['texto_enriquecido']
    assert art['calidad_cuerpo'] == 'alta'
    reg = {**art, 'link': art['url_final'], 'medio': 'El Dínamo'}
    valido, _, _, _, _ = m.analiza_uaf(reg)
    assert valido is True


def test_json_ld_tiene_prioridad_sobre_recomendaciones():
    html = '''<html><head><script type="application/ld+json">{
      "@type":"NewsArticle", "headline":"Nota sanitaria",
      "articleBody":"La nota describe virus hemorrágicos y protocolos clínicos utilizados por hospitales chilenos. También explica sus vías de contagio, los procedimientos de diagnóstico molecular, las medidas sanitarias y la prevención aplicable. No aborda materias financieras ni organismos de inteligencia financiera."
    }</script></head><body><main><p>La UAF informó nuevas obligaciones sobre lavado de activos.</p></main></body></html>'''
    art = extrae(html)
    assert art['origen_cuerpo'] == 'json_ld'
    assert 'UAF' not in art['texto_enriquecido']


def test_lee_tambien_no_corta_resto_del_articulo():
    html = '''<main><article><div class="article-content">
      <p>Primer párrafo suficientemente extenso para formar parte del contenido editorial principal.</p>
      <h3>Lee también</h3><p>La UAF publicó una noticia recomendada que no pertenece al artículo principal.</p>
      <h2>Continuación del análisis</h2>
      <p>Segundo párrafo del artículo que debe conservarse después del módulo intermedio de recomendación.</p>
    </div></article></main>'''
    art = extrae(html)
    assert 'noticia recomendada' not in art['texto_enriquecido']
    assert 'Segundo párrafo' in art['texto_enriquecido']


def test_url_falso_positivo_excluida():
    reg = {
      'link':'https://www.eldinamo.cl/sociedad/2026/07/29/tras-muerte-de-tripulante-extranjero-los-virus-que-pueden-causar-la-fiebre-hemorragica/',
      'titulo':'Tras muerte de tripulante extranjero: los virus que pueden causar la fiebre hemorrágica',
      'resumen':'',
      'texto_enriquecido':'Una recomendación ajena dice que la UAF revisó operaciones sospechosas en Chile.',
      'origen_cuerpo':'article', 'calidad_cuerpo':'alta'
    }
    valido, confianza, motivos, _, _ = m.analiza_uaf(reg)
    assert valido is False
    assert confianza == 'excluida'
    assert any('excluida' in x.lower() for x in motivos)


if __name__ == '__main__':
    tests = [v for k,v in globals().items() if k.startswith('test_') and callable(v)]
    for test in tests:
        test()
        print('OK', test.__name__)
    print(f'{len(tests)} pruebas aprobadas')
