# Analizador RES v5.0 — contrato de integración Atlas

## Estado
Candidato final para integración, pendiente de aprobación. La demo continúa separada de Atlas.

## Cambio principal de v5
La portada introductoria fue eliminada. La navegación parte directamente en la analítica y agrega **drill-down de sociedad**: desde fenómenos, comunas y recurrencias se puede abrir una ficha individual RES.

## Alcance funcional
El módulo sigue limitado a `aml_res_company` y a fenómenos observables:
- volumen y evolución temporal;
- región y comuna;
- tipo societario;
- capital declarado;
- fechas de constitución, registro y aprobación SII;
- recurrencia fecha + comuna + tipo + capital;
- desviaciones temporales;
- patrones de razón social;
- caracterización individual de sociedades y contexto de cohorte.

## Ficha societaria
La ficha debe mostrar tres capas:

1. **Dato bruto RES**: RUT, razón social, tipo, capital, fechas, territorio social y tributario.
2. **Caracterización derivada**: rezago constitución→registro, rezago constitución→SII, capital vs. mediana del tipo, capital recurrente y consistencia territorial.
3. **Contexto de cohorte**: número de sociedades que comparten fecha + comuna + tipo + capital, más tokens de razón social vinculados al vocabulario emergente.

La ficha no infiere giro, vínculo, irregularidad ni riesgo.

## Búsqueda
En Atlas, la barra de búsqueda debe consultar el universo completo de `aml_res_company` por RUT o razón social, con sugerencias mientras se escribe. La demo usa una muestra real de sociedades asociadas a fenómenos actuales para evaluar experiencia de usuario.

## Exclusiones de diseño
No se incorporan ni se consultan socios, accionistas, representantes, administradores, personas naturales, relaciones persona–sociedad ni beneficiario final. Tampoco se generan inferencias AML.

## Vistas
1. **Pulso**.
2. **Territorio**.
3. **Fenómenos**, incluyendo ficha societaria como drill-down transversal.

## Fuente mínima
`aml_res_company`:
`rut`, `rut_key`, `legal_name`, `constitution_date`, `registry_date`, `sii_approval_date`, `source_year`, `source_month`, `social_commune`, `social_region`, `tax_commune`, `tax_region`, `company_code`, `capital`.

## Integración propuesta
Al aprobarse:
1. portar las tres vistas al estándar visual Atlas;
2. implementar consultas agregadas RES en backend;
3. implementar búsqueda por RUT/razón social y detalle por RUT;
4. calcular cohortes y métricas derivadas en backend o vistas materializadas;
5. conservar ayuda metodológica y fecha de corte;
6. validar paridad de indicadores y fichas entre demo y Atlas antes de habilitar el módulo.

## Principio metodológico
ICE-RES, los estados de fenómeno y la caracterización de ficha ordenan la exploración. No son score de riesgo ni calificación de irregularidad.
