# Cambios de la versión 7.0

- Doble motor: monitoreo rápido y conciliación histórica diaria.
- Catálogo ampliado a 51 fuentes, con 32 fuentes mínimas auditables.
- Búsquedas exactas, variantes de acciones hacia la UAF y consultas por dominio.
- Segmentación del período de 30 días en bloques de cinco días.
- Resolución paralela y acotada de enlaces de Google News.
- Lectura RSS, Atom, sitemaps, índices de sitemap, portadas y secciones.
- Reintentos de descartes técnicos durante la conciliación.
- Memoria técnica de 45 días.
- Supresión automática de correos durante una migración de esquema.
- Correos solo en monitoreo rápido; la conciliación no envía alertas históricas.
- Bandeja de candidatos pendientes y resumen de descartes.
- Página `auditoria.html` con cobertura por fuente.
- Catálogo externo editable en `fuentes_uaf.json`.
- Casos reales de regresión en `casos_control.json`.
- Protección SSRF, límites de tamaño, rechazo de DTD/entidades XML y respeto de `robots.txt`.
- Pruebas unitarias para detección UAF Chile, exclusión extranjera, RSS, Atom, cobertura y seguridad.
