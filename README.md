# Monitor UAF Chile · v5.0 «cobertura-total-chile»

Dashboard estático publicado en GitHub Pages y actualizado por GitHub Actions cada 15 minutos.
El motor descubre noticias chilenas por seis vías, lee el cuerpo completo de los artículos y
decide si la mención corresponde a la **Unidad de Análisis Financiero de Chile**.

Identificador del motor en `datos.json`:

```text
5.0-cobertura-total-chile
```

---

## 1. Errores y vulnerabilidades corregidas

| Hallazgo | Efecto en la versión 4.0 | Corrección |
|---|---|---|
| `ssl.create_default_context()` se guardaba en `contexto`, pero se usaba `context=context` | `NameError` en cada envío: **las alertas por correo nunca salían**, solo quedaba `! fallo al enviar correo` en el log | contexto SSL corregido en STARTTLS y SMTPS |
| País extranjero en cualquier parte del texto vetaba la noticia | Una nota chilena sobre la UAF que mencionara «Perú» o «Colombia» en otro párrafo se descartaba como UAF extranjera (falso negativo) | veto solo cuando el país **califica a la unidad** («UAF de Panamá», «Ecuador: la UAF», «UAFE») |
| `urlopen` seguía redirecciones a cualquier destino | SSRF: un medio o feed comprometido podía dirigir el runner a `127.0.0.1` o al endpoint de metadatos `169.254.169.254` | validación de esquema, puerto y resolución DNS; se rechazan rangos privados, loopback, link-local y multicast, en la URL inicial y en cada redirección |
| `r.read()` sin límite | una respuesta grande agotaba la memoria del runner | tope de bytes por respuesta (4 MB por defecto) |
| `ET.fromstring` sobre XML de terceros | XXE / expansión de entidades («billion laughs») | se rechaza cualquier XML con `<!DOCTYPE` o `<!ENTITY` |
| Enlaces sin validar en `datos.json` | un feed malicioso podía dejar un `javascript:` en el `href` del dashboard | solo se aceptan `http`/`https`; el resto se descarta antes de escribir el JSON |
| `id` derivado de URL **y** titular | al editar el titular la misma nota entraba de nuevo y se reenviaba por correo | `id` derivado de la URL canónica, más una segunda deduplicación por titular y medio |
| `guarda_estado` asumía la clave `vistos` | `KeyError` con un estado parcial | estado normalizado, escritura atómica y poda por antigüedad |
| `parsea_fecha` no aceptaba ISO con microsegundos | las fechas de Bluesky quedaban nulas y los posts se perdían | parser de fechas ampliado (RFC-822, ISO, «28 de julio de 2026») |
| Reescritura del bloque `FALLBACK` con `re.subn` y cadena de reemplazo | los escapes del JSON podían interpretarse como referencias de grupo | reemplazo mediante función |
| `texto_enriquecido` completo se publicaba en Pages | el navegador descargaba varios MB por visita | se publica una versión ligera; el texto completo queda en la rama de estado |

---

## 2. Fuentes incorporadas

Antes: Google News + 4 sitemaps + `uaf.cl` + Reddit/Bluesky.
Ahora, **seis canales de descubrimiento**:

1. **Google News Chile** — consultas de dominio LA/FT y `site:` por cada medio prioritario.
2. **Bing News RSS** (`setmkt=es-CL`) — cobertura complementaria: indexa notas que Google omite.
3. **GDELT DOC 2.0** — índice global sin API key, filtrado a español y a dominios chilenos.
4. **Feeds propios de cada medio**, descubiertos automáticamente en tres pasos: `robots.txt`,
   `<link rel="alternate" type="application/rss+xml">` de la portada y rutas habituales
   (`/feed`, `/rss.xml`, `/arc/outboundfeeds/rss/?outputType=xml`, etc.). Los endpoints válidos
   se guardan en el estado con vigencia de 72 horas.
5. **News-sitemaps** declarados en `robots.txt` de los medios prioritarios.
6. **Sitio institucional `uaf.cl`** más los feeds de Fiscalía, CMF, Poder Judicial, Contraloría,
   SII, Aduanas, Senado, Cámara, Banco Central y Diario Oficial.

### Universo de medios

78 dominios verificados, con nombre y tipo de medio normalizados. Se agregaron respecto de la
versión anterior, entre otros: **Publimetro, La Hora, DF SUD, Estrategia, El Líbero,
Diario UChile, Infogate, TVN, Canal 13, Mega, Radio Duna, Radio Agricultura, Diario Constitucional,
Estado Diario, El Mercurio Legal, El Ovallino, El Martutino, El Pingüino, El Repuertero,
Mundo Marítimo** y las fuentes institucionales **Poder Judicial, Contraloría, Banco Central,
Consejo de Defensa del Estado y Biblioteca del Congreso**.

Además hay un **segundo nivel**: cualquier dominio `.cl` o `.gob.cl` que aparezca en los
buscadores entra al monitor marcado como `nivel_fuente: "chilena"`, en lugar de descartarse.
Así ya no se pierde una mención publicada por un medio regional o especializado que no esté
en la lista curada. El campo `nivel_fuente` distingue los cuatro niveles:

| Nivel | Significado |
|---|---|
| `verificada` | medio chileno de la lista curada |
| `institucional` | fuente pública chilena (`.gob.cl` o institución listada) |
| `chilena` | dominio `.cl` no curado |
| `nombre` | identificado por el nombre del medio cuando el feed no entrega dominio |

---

## 3. Detección UAF: cómo se volvió más segura

El motor ya no busca una cadena de texto: analiza **cada mención por separado** y la puntúa.

**Reconoce** `Unidad de Análisis Financiero`, `Unidades de Análisis Financiero`,
`Unidad de Análisis Financiero (UAF)`, `UAF`, `U.A.F.` y `Unidad de Inteligencia Financiera`,
con o sin tildes, en mayúsculas o minúsculas, y con el nombre partido por un salto de línea.

**Para cada mención** toma una ventana estrecha (±150 caracteres) y otra amplia (±430) y suma:

- nombre completo, ley 19.913, contexto LA/FT;
- nivel de la fuente (uaf.cl, institucional chilena, medio verificado, dominio `.cl`);
- señales chilenas junto a la mención (`de Chile`, `chilena`, Ministerio Público, CMF, Fiscalía,
  SII, PDI, Carabineros, GAFILAT, pesos chilenos, Santiago…);
- enlace saliente a `uaf.cl` dentro del artículo, que también cuenta como evidencia.

**Y descuenta** solo cuando corresponde: el veto fuerte exige que el país o el organismo
homólogo califique a la unidad (`UAF de Panamá`, `Unidad de Análisis Financiero del Perú`,
`UAF panameña`, `Ecuador: la UAF`, `UAFE`, `UIAF`, `SEPRELAD`, `SEPBLAC`, `FinCEN`, `COAF`).
Un país mencionado en otro párrafo resta 1 punto, no descarta la noticia.

La sigla `UAF` aislada, sin contexto LA/FT ni señal chilena, se sigue descartando
(`uaf_confianza: "sigla_ambigua"`), de modo que la ampliación de recall no introduce ruido.

Cada registro queda con `uaf_confianza` (`alta`, `media`, `sigla_ambigua`, `uaf_extranjera`,
`fuente_no_chilena`, `sin_mencion`), `uaf_puntaje`, `uaf_menciones` y `uaf_motivos`, para que la
decisión sea auditable. Puedes probar el motor sobre un texto cualquiera:

```bash
python3 monitor_uaf.py --probar-deteccion "La Unidad de Análisis Financiero remitió antecedentes a la Fiscalía. La red también operaba en Perú."
```

### Barrido profundo rotativo

Las búsquedas por palabra clave nunca son exhaustivas, así que cada corrida lee además el cuerpo
de hasta 70 artículos recientes de medios chilenos **aún no revisados**, elegidos de los feeds y
news-sitemaps. La memoria de artículos leídos vive en el estado (hasta 30.000 URLs, 21 días), por
lo que ninguno se lee dos veces y, con 96 corridas diarias, se cubre buena parte de la producción
de los medios prioritarios. Es lo más cercano a «infalible» que permite una fuente pública:
detecta la mención aunque el titular no diga nada y aunque ningún buscador la haya indexado.

---

## 4. Optimización

- **Paralelismo** con 6 hilos y un límite de una petición cada 0,9 s por dominio.
- **Caché de cuerpos**: si el artículo ya estaba en el histórico, no se vuelve a descargar.
  En régimen, cada corrida descarga solo lo nuevo en lugar de repetir ~190 artículos cada 15 min.
- **Taxonomías precompiladas** en expresiones regulares únicas por categoría: la reclasificación
  del histórico de 30 días pasa de miles de búsquedas de subcadena a una pasada por categoría.
- **Presupuesto de tiempo** (`MONITOR_PRESUPUESTO_SEG`, 780 s en el workflow): el motor corta
  ordenadamente antes del timeout del job y escribe siempre un `datos.json` válido.
- **Reintentos con espera** y `gzip`/`deflate` en todas las descargas.
- **Payload liviano**: `public/datos.json` se publica sin `texto_enriquecido`.
- Si ninguna fuente responde, se conserva el `datos.json` anterior en lugar de publicar un
  tablero vacío.

---

## 5. Archivos que debes subir

| Archivo | Acción |
|---|---|
| `monitor_uaf.py` | reemplazar |
| `construye_sitio.py` | reemplazar |
| `.github/workflows/monitor.yml` | reemplazar (revisa que el nombre coincida con tu workflow actual; si el tuyo se llama distinto, borra el antiguo) |
| `README.md` | reemplazar |
| `.gitignore` | reemplazar |

**`index.html` no cambia.** El esquema de `datos.json` es retrocompatible: se conservan todos los
campos que el dashboard ya usaba y solo se agregaron `nivel_fuente`, `uaf_puntaje`,
`uaf_menciones` y `niveles_fuente` en las métricas.

### Desde el navegador

1. **Code → Add file → Upload files** y arrastra los archivos.
2. Confirma que GitHub indique que reemplazará los existentes → **Commit changes**.
3. **Actions → Actualizar y publicar monitor → Run workflow**.
4. Cuando termine en verde, abre la página y pulsa `Ctrl + F5`.

La primera corrida es la más lenta: descubre feeds y sitemaps de todos los dominios y no tiene
caché. Desde la segunda, el descubrimiento se reparte en pocos dominios por corrida.

> El identificador de las noticias cambió de esquema. La primera corrida detecta el cambio,
> registra todo el histórico como visto y **no envía correo**, para no disparar una alerta
> masiva. Desde la segunda corrida el aviso funciona con normalidad.

---

## 6. Secretos y variables

En `Settings → Secrets and variables → Actions`:

| Secreto | Contenido |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` |
| `MONITOR_SMTP_SERVIDOR` | servidor SMTP |
| `MONITOR_SMTP_PUERTO` | puerto SMTP |
| `MONITOR_SMTP_SEGURIDAD` | `starttls`, `ssl` o `ninguna` |
| `MONITOR_SMTP_USUARIO` | cuenta remitente |
| `MONITOR_SMTP_CLAVE` | clave de aplicación o token SMTP |
| `MONITOR_DESTINATARIOS` | correos separados por coma o punto y coma |
| `MONITOR_REMITENTE_NOMBRE` | `Monitor UAF Chile` |
| `MONITOR_MINIMO_AVISO` | `1` |
| `MONITOR_SILENCIO_MINUTOS` | `0` |
| `MONITOR_SOLO_UAF` | `true` |

Ajustes opcionales del motor (variables de entorno del paso *Ejecutar monitor*):

| Variable | Defecto | Para qué |
|---|---|---|
| `MONITOR_PRESUPUESTO_SEG` | `720` | segundos máximos de corrida |
| `MONITOR_HILOS` | `6` | descargas simultáneas |
| `MONITOR_BARRIDO` | `70` | artículos del barrido profundo por corrida |
| `MONITOR_MAX_ENRIQUECER` | `220` | artículos con palabra clave por corrida |
| `MONITOR_RESPETA_ROBOTS` | `true` | respeta `robots.txt` al leer artículos |
| `MONITOR_INTERVALO_HOST` | `0.9` | segundos mínimos entre peticiones al mismo dominio |
| `MONITOR_VENTANA_DIAS` | `30` | ventana del histórico |
| `MONITOR_MAX_TEXTO_GUARDADO` | `4000` | caracteres de cuerpo guardados por noticia |

### Sobre `robots.txt`

El motor **respeta `robots.txt` por defecto** al descargar cuerpos de artículos. Si un medio
bloquea el acceso automatizado, el monitor conserva titular y resumen del feed y lo registra en el
log. Si la UAF cuenta con autorización o convenio con un medio, puedes poner
`MONITOR_RESPETA_ROBOTS: "false"` en el workflow; esa decisión es institucional, no técnica.

---

## 7. Qué revisar en Actions

```text
Histórico: 412 registros · caché de cuerpos: 380
  · Google News → 640 resultados brutos
  · Bing News → 88 resultados brutos
  · GDELT → 34 artículos chilenos
  · fuentes de biobiochile.cl: 1 feed(s), 1 sitemap(s)
  · Feeds propios de medios → 520 entradas
  · News-sitemaps → 310 artículos recientes
  · uaf.cl → 24 noticias institucionales
  · candidatos chilenos únicos: 806 · objetivo: 190 · barrido profundo: 70 · descartados: 402
  · prensa chilena: 244 · cuerpos nuevos: 61 · reutilizados de caché: 183 · sin cuerpo: 12
Listo: 431 de prensa · 12 sociales · 3 nuevas · 512.4s
```

Y en `datos.json`:

```json
{
  "version_motor": "5.0-cobertura-total-chile",
  "cobertura_tecnica": {
    "cuerpos_extraidos": 0,
    "fuentes_institucionales": 0,
    "medios_en_lista_blanca": 78,
    "dominios_con_feed": 0,
    "dominios_con_sitemap": 0,
    "articulos_en_memoria": 0,
    "respeta_robots": true,
    "segundos_corrida": 0
  }
}
```

Diagnóstico manual de fuentes, útil tras cambiar la lista de medios:

```bash
python3 monitor_uaf.py --diagnostico
python3 monitor_uaf.py --probar-correo
```

---

## 8. Límites que conviene tener claros

- **«Infalible» no existe con fuentes públicas.** Ningún medio garantiza que su feed o sitemap
  publique todas sus notas, y los buscadores no exponen todo su índice. El diseño reduce el riesgo
  con seis canales redundantes y el barrido rotativo, pero una nota tras muro de pago cerrado o
  fuera de todo índice puede no aparecer.
- La clasificación temática, los roles sectoriales y los delitos precedentes son automáticos por
  palabras clave: sirven para priorizar la lectura, **no para citarse en un informe institucional
  sin validación humana**.
- `uaf_confianza: "media"` corresponde a menciones donde la sigla aparece con contexto LA/FT pero
  sin señal chilena explícita; conviene revisarlas manualmente.
- Los medios cambian su HTML y sus rutas de feeds sin avisar. El autodescubrimiento se revalida
  cada 72 horas, y el log muestra qué dominios quedaron sin feed ni sitemap.
- No se usa scraping de resultados de Google con sesión de usuario ni de plataformas sin API
  pública (X, Instagram, Facebook, TikTok, LinkedIn).
