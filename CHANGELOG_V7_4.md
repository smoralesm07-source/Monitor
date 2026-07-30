# Cambios v7.4

- Excluye `uaf.cl` del catálogo, rastreo, histórico y dashboard.
- Agrega `semillas_verificadas.json` con el resultado externo del barrido exhaustivo.
- Garantiza la publicación de semillas activas aun con paywall, bloqueo o cuerpo no recuperable.
- Agrega la columna de La Tercera del 3 de julio como prueba obligatoria.
- Publica por defecto solo menciones explícitas y validadas de UAF Chile.
- Reordena consultas `site:` para cubrir primero todos los dominios.
- Amplía consultas de acción y búsquedas segmentadas por fecha.
- Incrementa el esquema de estado a 5 para forzar conciliación limpia.
- Agrega validación del workflow: cero semillas faltantes y cero URL de `uaf.cl`.
- Cambia el artefacto de diagnóstico para generarse solo cuando la ejecución falla.
