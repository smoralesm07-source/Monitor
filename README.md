# Monitor UAF Chile · versión 7.4

Esta versión está orientada exclusivamente a publicaciones externas que mencionen explícitamente a la **Unidad de Análisis Financiero de Chile o UAF** durante los últimos 30 días.

## Cambios principales

### 1. Exclusión total de `www.uaf.cl`

El dominio `uaf.cl` se elimina del catálogo, del descubrimiento y del histórico mostrado. La aplicación también depura publicaciones antiguas de ese portal que pudieran permanecer en `datos.json`.

Se mantiene `estrategiaantilavado.cl`, porque es un sitio distinto y puede contener noticias externas o interinstitucionales relevantes.

### 2. Capa de publicaciones verificadas

El archivo `semillas_verificadas.json` contiene las publicaciones que ya fueron comprobadas en el barrido exhaustivo. Mientras estén dentro de la ventana de 30 días, deben aparecer en el dashboard aunque:

- el buscador deje de indexarlas;
- el medio active un muro de pago;
- `robots.txt` bloquee la descarga;
- la mención UAF esté únicamente dentro del cuerpo;
- el título no contenga las palabras UAF o Unidad de Análisis Financiero.

Esta capa incluye, entre otras, la columna de **La Tercera del 3 de julio, “Inteligencia financiera para un mundo geoeconómico”**, y el reportaje de BioBioChile sobre economías ilícitas.

### 3. Control automático de integridad

Después de cada ejecución, GitHub Actions comprueba que:

- todas las semillas verificadas que siguen dentro de los últimos 30 días estén en `datos.json`;
- no exista ninguna publicación de `uaf.cl`;
- `datos.json` sea válido;
- el motor publicado corresponda a la versión 7.4.

Si falta una publicación verificada, el workflow falla antes de publicar un dashboard incompleto y muestra las URL faltantes.

### 4. Búsqueda más profunda

La conciliación diaria incorpora:

- consultas exactas por cada dominio configurado;
- consultas por la sigla UAF;
- frases de acción como “informó a la UAF”, “antecedentes a la UAF”, “alertas de la UAF”, “facultades de la UAF” y “fortalecer a la UAF”;
- bloques temporales de cinco días;
- RSS, Atom, sitemaps, índices de sitemaps, portadas y secciones;
- Google News, Bing News y DuckDuckGo;
- reintentos de artículos bloqueados o incompletos.

El modo rápido sigue funcionando durante el día y la conciliación realiza la reconstrucción profunda una vez al día.

## Archivos que debes subir

Conserva tu `index.html` actual y reemplaza o agrega:

```text
monitor_uaf.py
construye_sitio.py
fuentes_uaf.json
semillas_verificadas.json
casos_control.json
auditoria.html
test_monitor.py
.gitignore
.github/workflows/monitor.yml
```

No subas la carpeta `__pycache__` ni archivos `.pyc`.

## Instalación

1. Sube los archivos indicados directamente a la raíz del repositorio.
2. Reemplaza `.github/workflows/monitor.yml`.
3. Comprueba que no exista otro workflow antiguo, como `actualizar-monitor.yml`.
4. Abre **Actions → Actualizar y publicar monitor UAF → Run workflow**.
5. Ejecuta:

```text
modo: conciliacion
reiniciar_estado: false
probar_correo: false
```

La migración cambia el esquema del estado, vuelve a conciliar las publicaciones y elimina del dashboard los registros anteriores de `uaf.cl`. Durante esa primera migración no envía correos históricos.

## Validación esperada

En el registro del paso **Comprobar salida del monitor** deben aparecer mensajes similares a:

```text
versión: 7.4-barrido-profundo-sin-uaf-cl
semillas activas esperadas: N
semillas faltantes: 0
```

El número `N` cambia diariamente, porque las publicaciones salen automáticamente de la ventana móvil de 30 días.

## Configuración del dashboard

El workflow establece:

```text
MONITOR_DASHBOARD_SOLO_UAF=true
```

Por tanto, el listado principal muestra solamente publicaciones con mención validada de UAF Chile. Los artículos sobre lavado de activos que no mencionan a la UAF ya no se mezclan con el resultado principal.

## Actualización de publicaciones verificadas

Cuando se compruebe manualmente una nueva noticia omitida, agrégala a `semillas_verificadas.json` con:

```json
{
  "fecha": "2026-07-30",
  "medio": "Nombre del medio",
  "titulo": "Título",
  "tema": "Resumen del tema",
  "evidencia_uaf": "Descripción breve de la mención explícita a la UAF de Chile.",
  "link": "https://...",
  "verificada": true,
  "pais": "Chile"
}
```

Esto permite que la publicación quede respaldada mientras permanezca dentro de los últimos 30 días.

## Pruebas locales

```bash
python -m unittest -v test_monitor.py
python monitor_uaf.py --validar-fuentes
python monitor_uaf.py --probar-casos-control
```

La versión 7.4 incluye 13 pruebas automáticas, incluida la comprobación específica de La Tercera del 3 de julio y la exclusión de `uaf.cl`.
