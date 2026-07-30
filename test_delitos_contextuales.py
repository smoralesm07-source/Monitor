#!/usr/bin/env python3
from monitor_uaf import clasifica_precedentes


def reg(titulo='', resumen='', cuerpo=''):
    return {'titulo': titulo, 'resumen': resumen, 'texto_enriquecido': cuerpo, 'link': 'https://medio.cl/noticia'}


def assert_has(r, key):
    vals, ev, conf, descartados = clasifica_precedentes(r)
    assert key in vals, (vals, ev, conf, descartados)


def assert_not(r, key):
    vals, ev, conf, descartados = clasifica_precedentes(r)
    assert key not in vals, (vals, ev, conf, descartados)


def test_secuestro_real():
    assert_has(reg(
        titulo='Banda secuestró a empresario y exigió millonario rescate',
        cuerpo='La víctima permaneció en cautiverio durante dos días. La UAF recibió antecedentes financieros.'
    ), 'extorsion_secuestro')


def test_extorsion_real():
    assert_has(reg(
        titulo='Comerciantes denuncian extorsiones y cobros de protección',
        resumen='Una organización criminal exigía pagos bajo amenazas.',
        cuerpo='La investigación analiza la ruta del dinero y reportes a la UAF.'
    ), 'extorsion_secuestro')


def test_lista_generica_no_clasifica():
    assert_not(reg(
        titulo='Proyecto modifica catálogo de delitos',
        resumen='La iniciativa incluye delitos como fraude, contrabando, corrupción, secuestro y extorsión.',
        cuerpo='La norma también modifica obligaciones de reporte a la UAF.'
    ), 'extorsion_secuestro')


def test_secuestro_datos_no_clasifica():
    assert_not(reg(
        titulo='Ataque de ransomware causa secuestro de datos',
        resumen='Los archivos de la empresa quedaron cifrados.',
        cuerpo='La nota menciona prevención y lavado de activos de forma general.'
    ), 'extorsion_secuestro')


def test_descarte_explicito_no_clasifica():
    assert_not(reg(
        titulo='Fiscalía descartó secuestro en desaparición',
        resumen='El persecutor señaló que no hubo secuestro ni extorsión.',
        cuerpo='La investigación continúa por otras hipótesis.'
    ), 'extorsion_secuestro')


def test_contrabando_central_se_conserva():
    assert_has(reg(
        titulo='Aduanas detecta contrabando de monedas',
        resumen='Los antecedentes fueron remitidos a la UAF.',
        cuerpo='La carga buscaba salir del país como chatarra.'
    ), 'contrabando')


if __name__ == '__main__':
    tests = [v for k, v in globals().items() if k.startswith('test_')]
    for t in tests:
        t()
        print('OK', t.__name__)
    print(f'{len(tests)} pruebas aprobadas')
