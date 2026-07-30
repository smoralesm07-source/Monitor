# Monitor UAF Chile · versión 7.0

Actualización del motor de monitoreo para aumentar la cobertura de menciones a la **Unidad de Análisis Financiero de Chile (UAF)** en prensa, servicios públicos, organismos supervisores, medios sectoriales, gremiales y regionales.

Esta versión mantiene el `index.html` actual y el esquema principal de `datos.json`, pero reemplaza el proceso de recolección por una arquitectura de **doble motor**.

## 1. Cambios principales

### Monitoreo rápido

Se ejecuta cada 15 minutos y busca publicaciones recientes mediante:

- Google News RSS;
- Bing News RSS;
- DuckDuckGo como apoyo;
- RSS y Atom propios de las fuentes;
- news-sitemaps y sitemaps generales;
- portadas y secciones directas;
- consultas `site:` para fuentes prioritarias.

Su objetivo es detectar y avisar oportunamente nuevas menciones. El correo continúa enviándose únicamente en este modo y solo para nuevas menciones válidas de la UAF de Chile.

### Conciliación exhaustiva

Se ejecuta una vez al día y reconstruye los últimos 30 días mediante:

- consultas segmentadas en bloques de cinco días;
- revisión de todas las fuentes configuradas;
- más consultas `site:` por dominio;
- mayor recorrido de sitemaps e índices;
- reintento de artículos bloqueados, incompletos o previamente descartados;
- lectura de hasta 1.100 candidatos, según el presupuesto disponible.

Las publicaciones recuperadas por conciliación se incorporan al dashboard, pero **no generan correos históricos**.

### Auditoría de cobertura

La nueva página `auditoria.html` muestra:

- fuentes configuradas y efectivamente consultadas;
- canales utilizados por fuente;
- cantidad de resultados descubiertos;
- errores de conexión o extracción;
- candidatos pendientes de validación;
- motivos de descarte;
- última conciliación ejecutada;
- menciones localizadas únicamente dentro del cuerpo del artículo.

Una vez publicado, se abre en:

```text
https://TU_USUARIO.github.io/monitor-uaf/auditoria.html
```

### Catálogo ampliado

El motor incluye prensa nacional y económica, radios, televisión, medios jurídicos, regionales y fuentes institucionales. Entre las incorporaciones están:

- Servicio Nacional de Aduanas;
- Tesorería General de la República;
- Superintendencia de Pensiones;
- Superintendencia de Casinos de Juego;
- Estrategia Antilavado;
- Reporte Minero;
- ANFACH;
- Canal 9;
- El América;
- EnLaLinea.cl.

El catálogo puede modificarse sin tocar Python mediante `fuentes_uaf.json`.

### Trazabilidad de decisiones

Cada artículo queda en una de estas situaciones:

```text
descubierto → descargado → cuerpo extraído → UAF Chile validada → publicado
```

O registra un motivo técnico o analítico, por ejemplo:

```text
bloqueado_robots
cuerpo_insuficiente
error_descarga
pendiente_pdf
uaf_ambigua_o_extranjera
sin_mencion_ni_contexto_laft
fuera_de_ventana
```

Los candidatos accionables se conservan en `datos.json` y aparecen en la página de auditoría.

## 2. Archivos del paquete

| Archivo | Acción |
|---|---|
| `monitor_uaf.py` | Reemplazar el motor anterior |
| `construye_sitio.py` | Reemplazar |
| `fuentes_uaf.json` | Agregar en la raíz |
| `casos_control.json` | Agregar en la raíz |
| `auditoria.html` | Agregar en la raíz |
| `test_monitor.py` | Reemplazar |
| `.github/workflows/monitor.yml` | Reemplazar el workflow actual |
| `.gitignore` | Reemplazar o combinar |
| `index.html` | **Conservar el dashboard actual** |

## 3. Instalación en GitHub

### Desde el navegador

1. Descomprime el paquete.
2. En GitHub abre el repositorio y selecciona **Code → Add file → Upload files**.
3. Sube a la raíz:
   - `monitor_uaf.py`
   - `construye_sitio.py`
   - `fuentes_uaf.json`
   - `casos_control.json`
   - `auditoria.html`
   - `test_monitor.py`
   - `.gitignore`
4. Abre la carpeta `.github/workflows` del repositorio.
5. Reemplaza el workflow existente por `monitor.yml` incluido en este paquete.
6. Conserva `index.html` sin cambios.
7. Confirma el commit.

### Evitar workflows duplicados

Debe quedar **un solo workflow de actualización**. Si el repositorio todavía contiene archivos como:

```text
.github/workflows/actualizar-monitor.yml
.github/workflows/actualizar-monitor.yaml
```

elimínalos o desactívalos después de subir `monitor.yml`. Dos workflows provocarían ejecuciones duplicadas, competencia por la rama `monitor-state` y posibles correos repetidos.

## 4. Primera ejecución

1. Abre **Actions → Actualizar y publicar monitor UAF**.
2. Pulsa **Run workflow**.
3. Selecciona `conciliacion`.
4. Mantén `reiniciar_estado` en `false`.
5. Ejecuta.

La primera conciliación puede volver a revisar artículos antiguos porque la versión 7 cambia el esquema técnico del estado. Conserva la lista de noticias ya vistas para reducir avisos duplicados y no envía correo por la recuperación histórica.

Cuando termine en verde:

1. abre GitHub Pages;
2. actualiza con `Ctrl + F5` o `Cmd + Shift + R`;
3. revisa `auditoria.html`;
4. confirma que `version_motor` sea:

```text
7.0-doble-motor-conciliacion
```

## 5. Programación automática

El workflow ejecuta:

```text
Monitoreo rápido: minutos 07, 22, 37 y 52 de cada hora
Conciliación: una vez al día, 07:13 UTC
```

La hora UTC corresponde aproximadamente a la madrugada en Chile. GitHub puede iniciar una ejecución programada algunos minutos después cuando existe congestión.

## 6. Correo electrónico

Los secretos anteriores se mantienen:

| Secreto | Uso |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` para habilitar |
| `MONITOR_SMTP_SERVIDOR` | Servidor SMTP |
| `MONITOR_SMTP_PUERTO` | Puerto SMTP |
| `MONITOR_SMTP_SEGURIDAD` | `starttls`, `ssl` o `ninguna` |
| `MONITOR_SMTP_USUARIO` | Cuenta remitente |
| `MONITOR_SMTP_CLAVE` | Clave de aplicación o token SMTP |
| `MONITOR_DESTINATARIOS` | Correos separados por coma |
| `MONITOR_REMITENTE_NOMBRE` | Nombre visible del remitente |
| `MONITOR_MINIMO_AVISO` | Mínimo de menciones para avisar |
| `MONITOR_SILENCIO_MINUTOS` | Periodo de silencio configurado |
| `MONITOR_SOLO_UAF` | Mantener en `true` |

Para probarlo manualmente, ejecuta el workflow con `probar_correo = true`.

## 7. Comandos de validación

### Pruebas unitarias sin internet

```bash
python -m unittest -v test_monitor.py
```

### Validar catálogo

```bash
python monitor_uaf.py --validar-fuentes
```

### Probar una noticia concreta

```bash
python monitor_uaf.py --probar-url "URL"
```

### Ejecutar los casos reales de regresión

```bash
python monitor_uaf.py --probar-casos-control
```

Este último comando utiliza las URL de `casos_control.json`, entre ellas las dos publicaciones que la app había omitido:

- Diario Financiero: *Más allá de la UAF…*
- BioBioChile: *Del robo al lavado de dinero…*

No se ejecuta automáticamente en cada actualización porque depende de disponibilidad externa, paywalls y cambios de HTML de los medios.

### Ejecutar localmente

```bash
python monitor_uaf.py --modo rapido
python monitor_uaf.py --modo conciliacion
python construye_sitio.py
```

## 8. Variables avanzadas

| Variable | Rápido | Conciliación |
|---|---:|---:|
| `MONITOR_PRESUPUESTO_SEG` | 780 | 3000 |
| `MONITOR_MAX_ENRIQUECER` | 280 | 1100 |
| `MONITOR_MAX_SITE_QUERIES` | 48 | 140 |
| `MONITOR_BARRIDO_MIN_FUENTE` | 2 | 6 |
| `MONITOR_DIAS_PROCESADOS` | 45 | 45 |
| `MONITOR_MAX_GOOGLE_RESOLVER` | 120 | — |
| `MONITOR_MAX_GOOGLE_RESOLVER_CONCILIACION` | — | 420 |

Los valores ya están incluidos en el workflow y no requieren secretos.

## 9. Qué revisar en la auditoría

Después de la primera conciliación, observa especialmente:

- `Fuentes consultadas / fuentes configuradas`;
- fuentes obligatorias con estado `No consultada`;
- errores repetidos de `robots.txt`, HTTP o DNS;
- candidatos con `cuerpo_insuficiente`;
- menciones `uaf_ambigua_o_extranjera`;
- cantidad de artículos incorporados por conciliación;
- menciones encontradas solo en el cuerpo.

Una cobertura completa no significa que todas las fuentes respondan en cada ejecución. La conciliación diaria, la rotación rápida y los reintentos permiten acumular cobertura sin exceder los límites de GitHub Actions.

## 10. Limitaciones

- Los buscadores no garantizan entregar la totalidad de sus índices.
- Los medios pueden cambiar sus sitemaps, HTML, paywalls o reglas de rastreo.
- La app respeta `robots.txt` para la lectura de artículos.
- Los PDF se registran como pendientes cuando no existe texto HTML accesible.
- La clasificación automática debe validarse antes de utilizar una noticia en un informe institucional.
- GitHub Pages y `datos.json` son públicos cuando el repositorio o el sitio son públicos; no deben contener información reservada.
