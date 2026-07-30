#!/usr/bin/env python3
import monitor_uaf as m


def reg(titulo='', resumen='', cuerpo='', link='https://www.df.cl/prueba'):
    return {
        'titulo': titulo,
        'resumen': resumen,
        'texto_enriquecido': cuerpo,
        'link': link,
        'medio': 'Medio chileno',
        'calidad_cuerpo': 'alta',
        'origen_cuerpo': 'article',
    }


def test_ros_no_coincide_con_otros():
    r = reg('Otros resultados del seminario', 'Numerosos asistentes participaron en la jornada.')
    assert m.evalua_contexto_laft(r)['valido'] is False


def test_lavado_manos_no_es_laft():
    r = reg('Cómo realizar un correcto lavado de manos', 'Consejos para prevenir virus respiratorios.')
    assert m.evalua_pertinencia(r)['valido'] is False


def test_contexto_laft_explicito_se_conserva():
    r = reg('Informe alerta sobre lavado de activos en Chile', 'La investigación analiza operaciones sospechosas y testaferros.')
    p = m.evalua_pertinencia(r)
    assert p['valido'] is True and p['tipo'] == 'contexto_laft'


def test_uaf_accion_en_cuerpo_se_conserva():
    r = reg(cuerpo='La UAF informó que recibió reportes de operaciones sospechosas de bancos chilenos.')
    p = m.evalua_pertinencia(r)
    assert p['valido'] is True and p['tipo'] == 'uaf_directa'


def test_uaf_extranjera_se_descarta():
    r = reg('La UAF de Panamá emitió una alerta', 'La Unidad de Análisis Financiero de Panamá informó nuevas reglas.', link='https://www.df.cl/internacional/prueba')
    assert m.evalua_pertinencia(r)['valido'] is False


def test_aduanas_sola_no_es_contrabando():
    r = reg('Aduanas moderniza plataforma de atención', 'El servicio presentó un nuevo sistema de trámites digitales.')
    c = m.clasifica(r)
    assert c['fenomeno'] != 'contrabando'
    assert 'contrabando' not in c['precedentes']


def test_contrabando_real_se_conserva():
    r = reg('Aduanas detecta contrabando de monedas', 'Los antecedentes fueron remitidos a la UAF.', 'La carga intentó salir del país declarada como chatarra.')
    c = m.clasifica(r)
    assert c['fenomeno'] == 'contrabando'
    assert 'contrabando' in c['precedentes']


def test_cripto_precio_no_es_cibercrimen():
    r = reg('Bitcoin sube tras decisión de tasas', 'Inversionistas siguen el precio de la criptomoneda.')
    assert m.clasifica(r)['fenomeno'] != 'cibercrimen'


def test_ransomware_si_es_cibercrimen():
    r = reg('Empresa sufre ataque de ransomware', 'El delito informático cifró sus servidores y exigió pagos.')
    assert m.clasifica(r)['fenomeno'] == 'cibercrimen'


def test_lavado_no_implica_prevencion():
    r = reg('Fiscalía formaliza por lavado de activos', 'La causa investiga transferencias y sociedades de fachada.')
    assert 'prevencion' not in m.clasifica(r)['topicos']


def test_debida_diligencia_si_es_prevencion():
    r = reg('Bancos refuerzan debida diligencia', 'Las medidas de cumplimiento antilavado responden a obligaciones de la UAF.')
    assert 'prevencion' in m.clasifica(r)['topicos']


def test_investigacion_periodistica_no_es_penal():
    r = reg('Investigación periodística revela fallas de gestión', 'El reportaje revisó documentos administrativos sin causa penal.')
    assert 'investigacion_penal' not in m.clasifica(r)['topicos']


def test_formalizacion_si_es_investigacion_penal():
    r = reg('Fiscalía formaliza a imputados por lavado de activos', 'El tribunal revisó los antecedentes de la investigación penal.')
    assert 'investigacion_penal' in m.clasifica(r)['topicos']


def test_banco_incidental_no_es_sujeto():
    r = reg('Municipio inaugura una plaza', 'La actividad se realizó frente a una antigua sucursal de banco.')
    assert 'bancos' not in m.clasifica(r)['sujetos_obligados']


def test_banco_en_contexto_uaf_si_es_sujeto():
    r = reg(cuerpo='La UAF informó que recibió reportes de operaciones sospechosas de bancos chilenos.')
    assert 'bancos' in m.clasifica(r)['sujetos_obligados']


def test_lista_delitos_no_asigna_precedentes():
    r = reg('Proyecto actualiza catálogo legal', 'La norma enumera delitos como fraude, contrabando, corrupción, secuestro y trata de personas.')
    vals = m.clasifica(r)['precedentes']
    assert vals == ['indeterminado'], vals


def test_uaf_no_implica_inteligencia_financiera_automaticamente():
    r = reg('Exfuncionaria trabajó en la UAF', 'El perfil repasa su trayectoria profesional y académica.')
    c = m.clasifica(r)
    assert c['uaf'] is True
    assert 'inteligencia_financiera' not in c['topicos']


def test_inteligencia_financiera_explicita_se_conserva():
    r = reg('Inteligencia financiera para seguir la ruta del dinero', 'La UAF analiza reportes de operaciones sospechosas.')
    assert 'inteligencia_financiera' in m.clasifica(r)['topicos']


if __name__ == '__main__':
    tests = [v for k, v in globals().items() if k.startswith('test_') and callable(v)]
    for t in tests:
        t()
        print('OK', t.__name__)
    print(f'{len(tests)} pruebas aprobadas')
