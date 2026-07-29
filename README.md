# Monitor UAF · menciones de prensa y contexto LA/FT

Dashboard estático publicado en GitHub Pages y actualizado mediante GitHub Actions cada 15 minutos.

## Versión funcional actual

La interfaz se divide en dos niveles:

1. **Portada UAF de 24 horas:** muestra exclusivamente publicaciones de prensa que mencionan expresamente “UAF” o “Unidad de Análisis Financiero”. Compara las últimas 24 horas con las 24 horas anteriores y resume, en segundo plano, los últimos 5 días. Cuando existen menciones, detalla tópico, fenómeno o caso, tipo de información, tipo de medio, fuente y enlace.
2. **Panorama general de hasta 30 días:** reúne menciones UAF directas y noticias sobre lavado de activos, financiamiento del terrorismo, delitos precedentes, cambios normativos, fenómenos y casos investigativos.

Incluye:

- selector de 7, 15 y 30 días;
- evolución diaria;
- vista semanal;
- separación entre mención UAF y contexto LA/FT general;
- filtros por rango de fechas, caso, delito precedente, tipo de información, tipo de medio y fuente;
- tabla paginada de 10 noticias;
- indicadores de tendencia;
- rankings mensuales de medios, casos/fenómenos y delitos precedentes;
- redes únicamente cuando existe acceso automatizado público: Reddit y Bluesky;
- acumulación del histórico móvil de 30 días en la rama técnica `monitor-state`.

## Archivos principales

- `index.html`: dashboard y lógica interactiva.
- `monitor_uaf.py`: recolección, clasificación, histórico y generación de `datos.json`.
- `construye_sitio.py`: prepara los archivos publicados por GitHub Pages.
- `.github/workflows/actualizar-monitor.yml`: actualiza y publica cada 15 minutos.
- `datos.json`: último corte generado.

## Actualizar el repositorio sin Git y sin permisos de administrador

1. Descarga los archivos nuevos `index.html`, `monitor_uaf.py` y `README.md`.
2. En GitHub abre el repositorio y entra a **Code**.
3. Pulsa **Add file → Upload files**.
4. Arrastra los tres archivos. GitHub indicará que reemplazarán los existentes.
5. Escribe un mensaje como `Actualizar dashboard mensual` y pulsa **Commit changes**.
6. La carga de `index.html` o `monitor_uaf.py` inicia automáticamente el workflow. También puedes ir a **Actions → Actualizar y publicar monitor → Run workflow**.
7. Espera que la ejecución termine en verde y recarga la dirección de GitHub Pages con `Ctrl + F5`.

No necesitas instalar Git, Python ni ejecutar el computador de forma permanente.

## Cómo funciona el histórico mensual

GitHub Pages no ejecuta Python. Cada 15 minutos, GitHub Actions:

1. recupera `datos.json` y `.monitor_estado.json` desde `monitor-state`;
2. consulta las fuentes públicas;
3. combina los resultados nuevos con el histórico guardado;
4. elimina automáticamente lo que supera 30 días;
5. genera las métricas de 24 horas, 5 días y 30 días;
6. publica el sitio y vuelve a guardar el estado.

El primer corte mensual puede llenarse progresivamente si alguna fuente no entrega de inmediato todas sus publicaciones anteriores.

## Publicación inicial o verificación

En el repositorio:

1. `Settings → Pages`.
2. En `Build and deployment`, selecciona **GitHub Actions**.
3. `Settings → Actions → General → Workflow permissions`.
4. Selecciona **Read and write permissions** para permitir la rama `monitor-state`.
5. Ejecuta **Actions → Actualizar y publicar monitor → Run workflow**.

La dirección publicada normalmente será:

```text
https://TU_USUARIO.github.io/monitor-uaf/
```

## Correo electrónico opcional

Crea los secretos en:

`Settings → Secrets and variables → Actions → New repository secret`.

| Secreto | Ejemplo |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` |
| `MONITOR_SMTP_SERVIDOR` | `smtp.gmail.com` |
| `MONITOR_SMTP_PUERTO` | `587` |
| `MONITOR_SMTP_SEGURIDAD` | `starttls` |
| `MONITOR_SMTP_USUARIO` | `cuenta@dominio.cl` |
| `MONITOR_SMTP_CLAVE` | clave de aplicación o clave del relé |
| `MONITOR_DESTINATARIOS` | `uno@dominio.cl,dos@dominio.cl` |
| `MONITOR_REMITENTE_NOMBRE` | `Monitor UAF` |
| `MONITOR_MINIMO_AVISO` | `1` |
| `MONITOR_SILENCIO_MINUTOS` | `60` |
| `MONITOR_SOLO_UAF` | `true` |

Nunca guardes contraseñas dentro del código, el HTML o `datos.json`.

## Diagnóstico

En `Actions`, abre una ejecución y revisa **Ejecutar monitor**.

- `Listo: ... → datos.json`: ejecución correcta.
- `ninguna fuente respondió; se conserva el último datos.json`: caída temporal; el sitio no se vacía.
- `fallo en Google News`, `Reddit` o `Bluesky`: una fuente concreta no respondió.
- error en `Guardar estado`: revisa los permisos de escritura.
- error en Pages: confirma que la fuente seleccionada sea **GitHub Actions**.

La clasificación por palabras clave es orientativa y debe validarse analíticamente antes de usarla para conclusiones institucionales.
