# Analizador RES v6.0 — contrato de integración Atlas

## Estado
Candidato final optimizado para integración, pendiente de aprobación. La demo permanece fuera de Atlas.

## Principio de diseño
La analítica agregada debe poder conducir a una nómina de sociedades y, desde allí, a una ficha individual. La visualización no es un fin en sí misma: sirve para seleccionar universos de revisión reproducibles.

## Alcance
Solo utiliza `aml_res_company` y variables observables del RES: RUT, razón social, fechas, tipo societario, capital y territorio social/tributario. Se mantienen fuera socios, accionistas, representantes, administradores, beneficiario final y relaciones persona–sociedad.

## Flujo operativo propuesto
1. **Pulso** detecta cambios de escala y composición.
2. **Territorio** identifica regiones/comunas con cambio reciente.
3. **Fenómenos** permite seleccionar una señal.
4. La selección filtra una **tabla de sociedades**.
5. Clic en una fila abre la **ficha societaria RES**.

## Filtros accionables
- burbuja de intensidad × persistencia → cohortes de sociedades relacionadas con el fenómeno observable;
- fecha crítica → `constitution_date`;
- comuna crítica → `social_commune`;
- recurrencia → fecha/comuna/tipo/capital;
- familia de razón social → conjunto de RUTs identificados por denominación normalizada o serie léxica;
- búsqueda directa → RUT o razón social.

## Fechas críticas
Se comparan conteos diarios con un baseline histórico 2022–2025 del mismo mes y mismo día de semana. `|z| >= 2` se usa como apoyo exploratorio. Los feriados deben marcarse explícitamente para evitar interpretar efectos de calendario como fenómenos societarios.

**Importante:** una caída de constituciones no equivale a una baja, término o disolución societaria. La réplica actual no contiene una capa de disoluciones suficientemente poblada, por lo que esa métrica queda fuera.

## Comunas críticas
La priorización combina volumen reciente, cambio respecto de los 30 días anteriores y comparación con el mismo período del año anterior. El resultado ordena revisión; no es riesgo AML.

## Razones sociales parecidas
La v6 incorpora apoyo para:
- razones sociales normalizadas idénticas asociadas a RUT distintos;
- series léxicas dentro de una misma cohorte de constitución;
- similitud trigram como técnica exploratoria para ampliar candidatos.

La similitud nominal no implica relación societaria, control común ni irregularidad.

## Tabla de sociedades
En la demo se utiliza una muestra real ampliada para validar experiencia de uso. En Atlas, los filtros deben ejecutarse contra el universo completo de `aml_res_company`, con paginación/consulta servidor y sin descargar 1,6 millones de filas al navegador.

Columnas mínimas:
`rut`, `legal_name`, `company_code`, `constitution_date`, `social_commune`, `capital`, `cohort_size`, caracterización derivada.

## Ficha individual
Conserva tres niveles:
1. dato bruto RES;
2. caracterización derivada (rezagos, capital vs mediana del tipo, consistencia territorial, capital recurrente);
3. contexto de cohorte (`fecha + comuna + tipo + capital`).

## Regla de integración
Antes de habilitar en Atlas, validar paridad entre la demo y consultas directas a `aml_res_company` para cada señal, filtro y ficha. Ningún componente debe consumir `aml_res_relationship` ni tablas de personas.
