# Cambios v3.0.0 — Reconocimiento de personas naturales y jurídicas

## Qué resuelve

La versión 2.1.1 detectaba entidades pero no distinguía su **naturaleza
jurídica**, y arrastraba defectos que contaminaban la nómina. Esta versión
incorpora una capa de reconocimiento y desambiguación que responde tres
preguntas auditables por cada cadena detectada:

1. ¿Es una entidad o es ruido?
2. ¿Es una **persona natural** o una **persona jurídica**?
3. ¿Qué subtipo tiene y con qué grado de certeza?

## Archivos

| Archivo | Estado |
|---|---|
| `reconocedor_entidades.py` | **nuevo** — motor de reconocimiento |
| `test_reconocedor_entidades.py` | **nuevo** — 24 pruebas de regresión |
| `benchmark_entidades.py` | **nuevo** — medición contra estándar anotado |
| `modulo_entidades.py` | modificado — se acopla al motor |
| `entidades_config.json` | modificado — `incluir_rut: true`, versión 3.0.0 |
| `requirements_entidades.txt` | modificado — agrega `rapidfuzz` |
| `.github/workflows/monitor.yml` | modificado — valida los archivos nuevos |

El acoplamiento es **opcional**: si `reconocedor_entidades.py` no está
presente, `modulo_entidades.py` emite una advertencia y continúa con el
reconocimiento heredado v2. No hay riesgo de caída del workflow.

## Defectos corregidos

Todos fueron observados ejecutando la v2.1.1 sobre texto de prensa chilena.

| # | Defecto | Ejemplo |
|---|---|---|
| 1 | Falsos positivos de PERSONA | `Según`, `Caso Factop` clasificados como persona natural |
| 2 | Doble nodo por la misma cadena | `Factop SpA` existía a la vez como PERSONA y como EMPRESA |
| 3 | Razón social truncada | `STF Capital Corredores de Bolsa S.A.` → `Bolsa S.A` |
| 4 | Punto de abreviatura destruido | `limpia_nombre()` convertía `S.A.` en `S.A`, impidiendo reconocer el sufijo |
| 5 | Sin correferencia | `Marcela Ortiz` y `Marcela Ortiz Vega` eran dos entidades |
| 6 | Cobertura léxica insuficiente | Bancos, tribunales, CDE y municipalidades caían en `ORGANIZACION` |
| 7 | RUT desactivado y sin validar | `incluir_rut: false`, sin módulo 11 |
| 8 | Span cruzando fin de oración | `Sartor … Fondos S.A. Los hermanos Ariel` como una sola entidad |
| 9 | `IGNORECASE` desbordado | La regex institucional consumía la oración completa |
| 10 | Núcleos con tilde nunca coincidían | `fundacion` (normalizado) no encontraba `Fundación` en el texto |
| 11 | Conjunción uniendo entidades | `Servicio Nacional de Aduanas y la Policía de Investigaciones` como un ente |
| 12 | Cargos compuestos no reconocidos | `fiscal regional Mario Carrera Guerrero` no se detectaba |
| 13 | Etiqueta geográfica mal aplicada | `Fundación Buen Vivir` quedaba como LUGAR |

## Novedades funcionales

**Eje `naturaleza`.** Cada entidad declara `PERSONA_NATURAL`,
`PERSONA_JURIDICA`, `NO_APLICA` o `INDETERMINADA`. Se agregan los subtipos
`TRIBUNAL` y `ENTIDAD_SIN_FINES_DE_LUCRO`.

**Score de confianza auditable.** Valor `0..1` en `confianza_score`, más el
campo `senales` con la traza de cada decisión (`sufijo_societario:SpA`,
`nombre_de_pila_conocido:rodrigo`, `verbo_procesal_previo`). Las entidades bajo
0.55 se marcan con `requiere_validacion: true`.

> El score ordena prioridad de revisión humana. **No es una probabilidad
> calibrada** y no debe interpretarse como tal.

**Léxico chileno.** Cerca de 30 sufijos societarios (chilenos y extranjeros),
núcleos de empresa, organismo público, tribunal, institución financiera y
entidad sin fines de lucro, ~420 nombres de pila del Registro Civil, partículas
de apellido y tratamientos.

**Validación de RUT (módulo 11).** Solo se aceptan RUT con dígito verificador
correcto. Se asocian a la entidad más cercana en el texto y se registra la
distancia. El rango numérico (≥ 50.000.000) se reporta como **indicio** de
persona jurídica; es una convención administrativa, no una regla legal.

**Correferencia.** Unifica `Marcela Ortiz` con `Marcela Ortiz Vega`, y
`Corte de Apelaciones` con `Corte de Apelaciones de Antofagasta`. Es
deliberadamente estricta con sociedades: `Sartor Finance Group` y
`Sartor Administradora General de Fondos S.A.` **no** se fusionan, porque son
personas jurídicas distintas aunque compartan controlador.

**Reglas relacionales LA/FT.** `BENEFICIARIO_FINAL_DE`, `CONTROLA_A`,
`SANCIONA_A`, `REPORTA_A`, `ABSUELVE_A`, `DEFIENDE_A`. Roles nuevos: testaferro,
persona expuesta políticamente, sujeto obligado, sociedad de papel.

## Campos nuevos en la salida

En `nomina_entidades` (por artículo) y en los nodos de entidad:

- `naturaleza`, `naturaleza_label`
- `confianza_score`, `requiere_validacion`, `senales`
- `ruts`, `variantes`, `formas_unificadas`

En `analisis_entidades`:

- `conteo_por_naturaleza`, `personas_naturales`, `personas_juridicas`
- `entidades_por_validar`, `reconocedor`

## Medición

`benchmark_entidades.py` compara la salida contra un estándar anotado a mano.

| | v2.1.1 | v3.0.0 |
|---|---|---|
| Persona natural (F1) | 0.769 | 1.000 |
| Persona jurídica (F1) | 0.679 | 1.000 |
| **Global (F1)** | **0.716** | **1.000** |
| TP / FP / FN | 34 / 13 / 14 | 62 / 0 / 0 |

> **Advertencia metodológica.** El estándar se anotó sobre los mismos corpus
> con los que se ajustaron las reglas. El F1 de 1.000 verifica **ausencia de
> regresiones**, no desempeño en datos nuevos. El valor real sobre el flujo de
> prensa en producción será menor. Para estimarlo, anota manualmente una
> muestra de 30–50 artículos reales de `datos.json` y agrégala a `ORO`.

## Ejecución

```bash
pip install -r requirements_entidades.txt
python -m spacy download es_core_news_sm

python modulo_entidades.py --entrada datos.json --salida datos.json
python -m unittest test_modulo_entidades test_reconocedor_entidades
python benchmark_entidades.py --salida datos.json
```

## Modelo estadístico

Se mantiene `es_core_news_sm`. Los errores residuales observados son de regla,
no de modelo, por lo que subir a `es_core_news_md` (~40 MB adicionales en cada
ejecución de GitHub Actions) conviene evaluarlo recién cuando las reglas estén
estabilizadas y sobre una muestra anotada de prensa real.

## Advertencia analítica

Clasificar una cadena como persona natural o jurídica es un acto de
**reconocimiento textual**, no de imputación. Una entidad detectada en un
artículo sobre lavado de activos no participa por ello en el fenómeno. Toda
nómina requiere validación humana antes de cualquier uso analítico o
institucional.
