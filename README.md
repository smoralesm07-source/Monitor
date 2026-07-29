# Monitor UAF Chile · v6.0

Motor de vigilancia de prensa chilena para detectar noticias que mencionan a la **Unidad de Análisis Financiero (UAF)** o asuntos relacionados con lavado de activos, financiamiento del terrorismo, crimen organizado, sujetos obligados y delitos precedentes.

Esta versión corrige el principal punto débil de la versión anterior: **no depende de que Google News entregue una URL editorial decodificable**. Cada noticia puede descubrirse por varios canales independientes y el archivo `datos.json` registra la cobertura efectiva de cada fuente.

## 1. Cambios principales

1. **Catálogo obligatorio de 27 dominios** correspondiente al listado solicitado.
2. **Barrido directo de portadas** para encontrar artículos aunque no aparezcan en agregadores.
3. **Consultas `site:`** para todas las fuentes mínimas, no solo para los medios marcados como prioritarios.
4. **DuckDuckGo** como motor complementario mediante su página HTML sin JavaScript.
5. **Perplexity Search API opcional**, activable con una clave de API.
6. **RSS/Atom y news-sitemaps** propios, con autodescubrimiento y semillas conocidas.
7. **Reintento más rápido de fuentes fallidas**: un dominio sin feed o sitemap se vuelve a revisar en 6 horas, no en 72.
8. **Barrido equilibrado por dominio**: se reservan artículos de cada fuente mínima antes de completar el cupo global.
9. **Trazabilidad por noticia** mediante `origen_busqueda` y `origenes_busqueda`.
10. **Trazabilidad por fuente** mediante `cobertura_fuentes`.
11. Nuevos comandos de diagnóstico: `--validar-fuentes` y `--probar-url`.

> Corrección de dominio: el medio **El Dínamo** utiliza `eldinamo.cl`. El dominio `eldynamo.cl` del listado original no corresponde al medio.

## 2. Fuentes mínimas incorporadas

### Prensa nacional y económica

- Diario Financiero — `df.cl`
- La Tercera / Pulso — `latercera.com`
- Emol — `emol.com`
- El Mercurio — `elmercurio.com`
- El Mostrador — `elmostrador.cl`

### Radios y cadenas informativas

- BioBioChile — `biobiochile.cl`
- Cooperativa — `cooperativa.cl`
- ADN Radio — `adnradio.cl`
- Radio Pauta — `pauta.cl`

### Televisión

- 24 Horas — `24horas.cl`
- T13 — `t13.cl`
- CHV Noticias — `chvnoticias.cl`
- Meganoticias — `meganoticias.cl`
- CNN Chile — `cnnchile.com`

### Investigación y medios digitales

- Interferencia — `interferencia.cl`
- CIPER Chile — `ciperchile.cl`
- Ex-Ante — `ex-ante.cl`
- El Desconcierto — `eldesconcierto.cl`
- El Dínamo — `eldinamo.cl`

### Fuentes oficiales

- Ministerio Público / Fiscalía de Chile — `fiscaliadechile.cl`
- Diario Oficial — `diariooficial.interior.gob.cl`
- CMF — `cmfchile.cl`
- SII — `sii.cl`
- Poder Judicial — `pjud.cl`
- Contraloría — `contraloria.cl`
- Cámara de Diputadas y Diputados — `camara.cl`

### Regionales y agregadores

- Red SoyChile — `soychile.cl`
- Google News Chile
- Bing News RSS, como canal complementario de mejor esfuerzo
- DuckDuckGo
- GDELT DOC 2.0
- Perplexity Search API, opcional

## 3. Cómo evita los falsos negativos

El motor combina cinco niveles:

1. **Descubrimiento general:** Google News, Bing, DuckDuckGo, GDELT y Perplexity.
2. **Descubrimiento directo:** portadas, feeds y sitemaps de los medios.
3. **Barrido profundo:** descarga el cuerpo de artículos cuyo titular no contiene necesariamente “UAF”.
4. **Detección por proximidad:** analiza cada aparición de `UAF`, `Unidad de Análisis Financiero` o `Unidad de Inteligencia Financiera` dentro de su contexto.
5. **Validación chilena:** considera dominio, medio, institucionalidad cercana, Ley 19.913, organismos nacionales y enlaces a `uaf.cl`.

El barrido ahora reserva por defecto **dos artículos por fuente mínima** antes de completar el cupo. Esto evita que medios con cientos de entradas desplacen totalmente a medios con menor volumen.

## 4. Archivos que debes reemplazar

| Archivo entregado | Ubicación en el repositorio |
|---|---|
| `monitor_uaf.py` | raíz del repositorio |
| `construye_sitio.py` | raíz del repositorio |
| `monitor.yml` | `.github/workflows/monitor.yml` |
| `README.md` | raíz del repositorio |
| `.gitignore` | raíz del repositorio |
| `test_monitor.py` | raíz del repositorio, recomendado |

No es necesario reemplazar `index.html`: el formato principal de `datos.json` sigue siendo compatible. Se agregan campos nuevos que el dashboard antiguo simplemente ignorará.

## 5. Configuración de GitHub Actions

El workflow se ejecuta cada 15 minutos y utiliza:

```yaml
MONITOR_PRESUPUESTO_SEG: "780"
MONITOR_HILOS: "8"
MONITOR_BARRIDO: "90"
MONITOR_BARRIDO_MIN_FUENTE: "2"
MONITOR_MAX_ENRIQUECER: "260"
MONITOR_DESCUBRE_POR_CORRIDA: "12"
MONITOR_PORTADAS_POR_CORRIDA: "14"
MONITOR_DOMINIOS_SITE: "8"
MONITOR_DUCKDUCKGO_ACTIVO: "true"
```

Los valores pueden aumentarse, pero hacerlo incrementa el tiempo de ejecución y la carga sobre los sitios consultados.

## 6. Perplexity opcional

Perplexity no debe automatizarse mediante la interfaz web. La integración incluida utiliza su **Search API oficial** y solo se ejecuta si existen estos secretos:

| Secreto | Valor |
|---|---|
| `PERPLEXITY_API_KEY` | clave creada en Perplexity API |
| `MONITOR_PERPLEXITY_ACTIVO` | `true` |

Sin estos secretos, el monitor continúa normalmente con los demás canales.

La consulta utiliza:

- filtro de dominios para las fuentes mínimas;
- filtro de idioma español;
- país `CL`;
- resultados estructurados con título, URL, resumen y fecha.

## 7. Correo electrónico

Mantén los secretos existentes:

| Secreto | Ejemplo |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` |
| `MONITOR_SMTP_SERVIDOR` | `smtp.gmail.com` |
| `MONITOR_SMTP_PUERTO` | `587` |
| `MONITOR_SMTP_SEGURIDAD` | `starttls` |
| `MONITOR_SMTP_USUARIO` | cuenta remitente |
| `MONITOR_SMTP_CLAVE` | clave de aplicación |
| `MONITOR_DESTINATARIOS` | correos separados por coma |
| `MONITOR_REMITENTE_NOMBRE` | `Monitor UAF Chile` |
| `MONITOR_MINIMO_AVISO` | `1` |
| `MONITOR_SILENCIO_MINUTOS` | `0` |
| `MONITOR_SOLO_UAF` | `true` |

Para Gmail debes utilizar una **clave de aplicación**, no la contraseña normal de la cuenta.

## 8. Comandos de prueba

### Validar que estén configuradas las fuentes mínimas

```bash
python monitor_uaf.py --validar-fuentes
```

Resultado esperado:

```json
{
  "version": "6.0-cobertura-minima-auditable",
  "fuentes_minimas": 27,
  "faltantes_en_catalogo": [],
  "duplicados": [],
  "dominio_el_dinamo": "eldinamo.cl"
}
```

### Probar una noticia específica

```bash
python monitor_uaf.py --probar-url "https://www.df.cl/opinion/columnistas/mas-alla-de-la-uaf-conocer-la-ruta-del-dinero-es-tarea-de-todos"
```

```bash
python monitor_uaf.py --probar-url "https://www.biobiochile.cl/noticias/economia/actualidad-economica/2026/07/03/del-robo-al-lavado-de-dinero-asi-funciona-el-circulo-vicioso-de-las-economias-ilicitas-en-chile.shtml"
```

El resultado indica:

- si pudo extraer el cuerpo;
- fecha y URL canónica;
- confianza UAF;
- puntaje;
- motivos;
- contexto exacto alrededor de la mención.

### Probar solo el clasificador

```bash
python monitor_uaf.py --probar-deteccion "La Unidad de Análisis Financiero de Chile recibió antecedentes sobre operaciones sospechosas."
```

### Diagnosticar feeds y sitemaps

```bash
python monitor_uaf.py --diagnostico
```

### Ejecutar pruebas unitarias

```bash
python -m unittest -v test_monitor.py
```

## 9. Auditoría de cobertura

Cada ejecución agrega en `datos.json`:

```json
{
  "cobertura_fuentes": [
    {
      "fuente": "Diario Financiero",
      "dominio": "df.cl",
      "canales": {
        "portada": 42,
        "sitemap": 18,
        "google_news": 2
      },
      "resultados": 62,
      "errores": [],
      "obligatoria": true,
      "consultada": true
    }
  ]
}
```

Interpretación:

- `consultada: true` y `resultados: 0`: la fuente fue revisada, pero no entregó entradas útiles por los canales utilizados.
- `consultada: false`: no alcanzó a entrar en la rotación de esa corrida.
- `errores`: fallos de acceso, feed vacío, sitemap inválido u otra condición técnica.
- `canales`: cantidad de hallazgos por mecanismo.

También se agregan métricas generales:

```json
{
  "fuentes_minimas_configuradas": 27,
  "fuentes_minimas_consultadas": 20,
  "duckduckgo_activo": true,
  "perplexity_activo": false
}
```

## 10. Primera ejecución recomendada

1. Reemplaza los archivos.
2. Ejecuta localmente `python -m unittest -v test_monitor.py`.
3. Ejecuta `python monitor_uaf.py --validar-fuentes`.
4. Sube los cambios a GitHub.
5. En **Actions**, ejecuta manualmente el workflow con `reiniciar_estado: false`.
6. Revisa el log buscando las líneas:

```text
· Google News → ...
· Bing News → ...
· DuckDuckGo → ...
· Perplexity → ...
· Feeds propios de medios → ...
· News-sitemaps → ...
· Portadas directas → ...
· candidatos chilenos únicos: ...
· barrido profundo: ...
```

7. Descarga o abre `datos.json` y revisa `cobertura_fuentes` para `df.cl` y `biobiochile.cl`.

## 11. Límites reales

- Ningún sistema basado solo en fuentes públicas puede prometer cobertura absoluta.
- Un medio puede bloquear robots, modificar su HTML, retirar un feed, cerrar un sitemap o exigir autenticación.
- DuckDuckGo HTML es un canal de mejor esfuerzo, no una API contractual.
- Perplexity requiere clave, puede tener costo y está sujeto a límites de uso.
- El contenido detrás de un muro de pago puede permitir detectar título y metadatos, pero no siempre el texto completo.
- La clasificación automática sirve para priorizar y alertar; una conclusión institucional debe validarse humanamente.

La diferencia de esta versión es que una falla queda **visible y auditable**, y que cada fuente mínima dispone de rutas directas independientes de los agregadores.
