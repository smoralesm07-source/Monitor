# Analizador RES v4.0 — contrato de integración Atlas

## Estado
Candidato final para integración, pendiente de aprobación. La demo continúa separada de Atlas.

## Alcance funcional
El módulo se limita a fenómenos observables con la réplica RES actualmente cargada:

- volumen y evolución temporal de constituciones;
- región y comuna;
- tipo societario;
- capital declarado;
- recurrencia de combinaciones fecha + comuna + tipo + capital;
- desviaciones temporales;
- patrones de razón social y vocabulario emergente.

## Exclusiones de diseño
No se incorporan ni se consultan socios, accionistas, representantes, administradores, personas naturales, relaciones persona–sociedad ni beneficiario final. Tampoco se generan inferencias AML.

## Vistas
1. **Pulso**: panorama nacional, serie histórica, mezcla societaria y momentum.
2. **Territorio**: mapa regional, lectura de ciclo, aceleraciones comunales y matriz ICE-RES.
3. **Fenómenos**: señales emergentes, persistentes, estructurales, en enfriamiento y de vigilancia; recurrencia constitutiva y vocabulario emergente.

## Fuente mínima
`aml_res_company` con:
`rut_key`, `legal_name`, `constitution_date`, `source_year`, `source_month`, `social_commune`, `social_region`, `tax_commune`, `tax_region`, `company_code`, `capital`.

El módulo no requiere `aml_res_relationship`.

## Integración propuesta
Al aprobarse:
1. portar las tres vistas a los componentes visuales de Atlas;
2. mantener la lógica de cálculo como capa RES independiente;
3. publicar agregados/flags normalizados para consumo de interfaz;
4. conservar fecha de corte y ayuda metodológica;
5. validar paridad de resultados entre demo y Atlas antes de habilitar al usuario.

## Principio metodológico
ICE-RES y los estados de fenómeno ordenan revisión analítica. No son un score de riesgo ni una calificación de irregularidad.
