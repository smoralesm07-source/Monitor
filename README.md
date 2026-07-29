# Monitor UAF Chile · cobertura nacional con lectura de artículos

Dashboard estático publicado en GitHub Pages y actualizado mediante GitHub Actions aproximadamente cada 15 minutos.

## Cambio principal de esta versión

El monitor ya no depende únicamente del titular y la bajada que entrega Google News. Ahora trabaja en dos etapas:

1. **Descubrimiento amplio de noticias chilenas.** Busca candidatos en Google News Chile, hace consultas por dominio, revisa sitemaps de medios priorizados y consulta directamente las noticias de `uaf.cl`.
2. **Análisis del artículo completo.** Cuando la fuente pertenece a la lista de medios chilenos autorizados, descarga el artículo, extrae su cuerpo y vuelve a evaluar UAF, LA/FT, delitos precedentes, sujetos obligados, tópicos y fenómenos.

Esto permite detectar noticias donde la expresión **Unidad de Análisis Financiero** o **UAF** aparece dentro del artículo y no en el titular.

La versión del motor queda identificada en `datos.json` como:

```text
4.0-cuerpo-completo-chile
```

## Caso de control incorporado

La noticia de La Tercera sobre la falsa alerta de fraude, la amenaza atribuida al Tren de Aragua y el robo a un notario se utiliza como caso funcional de control.

El título permite descubrirla por señales como:

- fraude;
- Tren de Aragua;
- imputados;
- notario.

Después, el análisis del cuerpo identifica:

- lavado de activos;
- referencia a la UAF dentro del artículo;
- cuentas puente y testaferros;
- transferencias fraccionadas;
- Mercado Pago y banca;
- compra de vehículos;
- notario en calidad de víctima.

Por ello puede aparecer en el dashboard y activar el correo UAF cuando sea una noticia nueva.

## Fuentes y métodos de descubrimiento

### 1. Google News Chile

Se mantienen las consultas generales sobre:

- Unidad de Análisis Financiero y UAF;
- lavado de activos y lavado de dinero;
- financiamiento del terrorismo;
- operaciones sospechosas;
- cuentas puente, testaferros y transferencias fraccionadas;
- investigaciones, formalizaciones e imputaciones;
- sujetos obligados y sectores supervisados.

Además, se ejecutan búsquedas específicas `site:` para medios chilenos prioritarios, entre ellos:

- La Tercera;
- Diario Financiero;
- BioBioChile;
- Emol y El Mercurio;
- CIPER;
- El Mostrador;
- Ex-Ante;
- Cooperativa;
- CNN Chile;
- 24 Horas;
- T13;
- Meganoticias.

### 2. Sitemaps periodísticos

El monitor revisa directamente sitemaps recientes de:

- La Tercera;
- Diario Financiero;
- BioBioChile;
- Emol.

Los títulos se preseleccionan mediante señales judiciales, financieras, criminales y sectoriales. Después se descarga el cuerpo del artículo para determinar su pertinencia real.

### 3. Sitio institucional UAF Chile

Se revisan directamente las dos primeras páginas de noticias de `uaf.cl`. Estas publicaciones forman parte del panorama general de 30 días, pero no se mezclan con la métrica principal de apariciones de la UAF en medios de prensa durante las últimas 24 horas.

### 4. Redes sociales

Se mantienen únicamente las fuentes con consulta automatizada pública disponible:

- Reddit;
- Bluesky.

No se incorporan X, LinkedIn, Instagram, Facebook ni TikTok como si fueran fuentes monitoreadas.

## Filtro estricto de medios chilenos

La entrada al dashboard se controla mediante una lista blanca de dominios chilenos. Un resultado extranjero se descarta aunque Google News lo haya entregado usando la edición regional de Chile.

La validación se realiza sobre:

- dominio declarado por Google News;
- URL final después de seguir la redirección;
- URL canónica del artículo;
- nombre del medio como respaldo cuando el feed no informa el dominio.

Entre los dominios admitidos se incluyen medios nacionales, económicos, regionales e institucionales de Chile.

### Doble protección frente a noticias extranjeras

El monitor aplica dos controles:

1. **Control de fuente:** solo admite dominios incluidos expresamente en la lista chilena.
2. **Control semántico:** una noticia de un medio chileno que trate sobre la UAF de Panamá, Ecuador, Perú, Colombia u otra jurisdicción no se clasifica como UAF Chile, salvo que mencione explícitamente a la institución chilena.

En cada ejecución, el histórico de `monitor-state` se vuelve a clasificar. Así, las noticias extranjeras guardadas por versiones anteriores se eliminan automáticamente.

## Lectura del cuerpo completo

Para cada candidato chileno, el motor intenta extraer:

- titular;
- descripción;
- fecha de publicación;
- URL canónica;
- cuerpo principal del artículo.

Se utilizan, en este orden:

1. metadatos estructurados JSON-LD, especialmente `articleBody`;
2. contenido dentro de la etiqueta `<article>`;
3. párrafos sustantivos de la página;
4. versión AMP como respaldo para artículos de La Tercera cuando la versión principal entrega poco texto.

Si un medio bloquea la lectura o entrega una página incompleta, el monitor conserva el titular y el resumen RSS en vez de interrumpir toda la actualización.

## Precisión UAF Chile

Una mención se clasifica como UAF Chile cuando:

- aparece `Unidad de Análisis Financiero`, `UAF Chile` o una expresión equivalente;
- la fuente es chilena;
- existe contexto LA/FT, institucional o normativo suficiente;
- no hay señales de que se trate exclusivamente de una unidad extranjera.

La mera sigla `UAF` sin contexto financiero o LA/FT se considera ambigua y se descarta.

Cuando la mención está en el cuerpo, el monitor almacena un fragmento denominado `contexto_uaf`. Ese texto aparece en el dashboard y también puede incorporarse al aviso por correo.

## Sujetos obligados y rol dentro de la noticia

El análisis cubre, entre otros:

- banca y servicios financieros;
- mercado de valores y fondos;
- pensiones y seguros;
- fintech y medios de pago;
- inmobiliarias, notarios y conservadores;
- vehículos, leasing y factoring;
- casinos y apuestas;
- aduanas y zonas francas;
- metales, joyas y remates;
- armas;
- otros sujetos obligados.

Además, intenta distinguir el papel de cada sector:

- víctima o sector afectado;
- canal utilizado para mover o integrar fondos;
- entidad o sector investigado;
- sector afectado por regulación o supervisión;
- sector mencionado sin rol concluyente.

## Cobertura temporal e histórico

Cada ejecución:

1. recupera el histórico desde la rama `monitor-state`;
2. descubre noticias nuevas;
3. enriquece los artículos chilenos con su cuerpo;
4. reclasifica también las noticias antiguas;
5. elimina noticias extranjeras y registros que superan 30 días;
6. genera `datos.json`;
7. publica GitHub Pages;
8. guarda nuevamente el estado.

El primer corte con esta versión puede demorar más que los anteriores, porque debe descargar y analizar artículos completos. Las ejecuciones posteriores reutilizan el histórico, aunque vuelven a validar su clasificación.

## Interfaz

La portada muestra exclusivamente menciones verificadas de la UAF de Chile en medios de prensa durante las últimas 24 horas, junto con una referencia secundaria de cinco días.

El panorama general incorpora:

- períodos de 7, 15 y 30 días;
- evolución diaria y vista semanal;
- UAF directa versus contexto LA/FT;
- sujetos obligados y rol sectorial;
- rankings de medios, tópicos, casos y delitos precedentes;
- filtros interactivos mediante gráficos;
- rango de fechas;
- tabla paginada;
- fragmento preciso alrededor de la mención UAF encontrada en el cuerpo.

## Alertas por correo

Se envía un correo únicamente cuando la actualización detecta al menos una **noticia nueva de prensa** validada como UAF Chile.

El correo puede incluir:

- medio, fecha y hora;
- titular y enlace;
- fragmento alrededor de la mención UAF;
- tópico y tipo de información;
- fenómeno o caso;
- sujetos obligados y su posible rol.

No generan correo:

- noticias generales LA/FT sin una mención válida a la UAF de Chile;
- noticias extranjeras;
- publicaciones de Reddit o Bluesky;
- noticias que ya estaban registradas.

### Secretos necesarios

En `Settings → Secrets and variables → Actions`:

| Nombre | Contenido |
|---|---|
| `MONITOR_CORREO_ACTIVO` | `true` |
| `MONITOR_SMTP_SERVIDOR` | servidor SMTP |
| `MONITOR_SMTP_PUERTO` | puerto SMTP |
| `MONITOR_SMTP_SEGURIDAD` | `starttls`, `ssl` o `ninguna` |
| `MONITOR_SMTP_USUARIO` | cuenta remitente |
| `MONITOR_SMTP_CLAVE` | clave de aplicación, token o clave SMTP |
| `MONITOR_DESTINATARIOS` | correos separados por coma |
| `MONITOR_REMITENTE_NOMBRE` | `Monitor UAF Chile` |
| `MONITOR_MINIMO_AVISO` | `1` |
| `MONITOR_SILENCIO_MINUTOS` | `0` |
| `MONITOR_SOLO_UAF` | `true` |

## Archivos que debes reemplazar en GitHub

Sube a la raíz del repositorio:

1. `monitor_uaf.py`
2. `index.html`
3. `README.md`

El workflow y `construye_sitio.py` de la versión anterior siguen siendo compatibles. El ZIP completo también los incluye por seguridad.

### Actualización desde el navegador

1. Abre **Code** en el repositorio.
2. Selecciona **Add file → Upload files**.
3. Arrastra los tres archivos.
4. Confirma que GitHub indique que reemplazará los existentes.
5. Pulsa **Commit changes**.
6. Abre **Actions → Actualizar y publicar monitor**.
7. Pulsa **Run workflow** o espera el siguiente horario programado.
8. Cuando termine en verde, abre GitHub Pages y presiona `Ctrl + F5`.

## Qué revisar en Actions

En el paso **Ejecutar monitor**, la nueva versión muestra datos como:

```text
«consulta» → N resultados / M fuentes chilenas
sitemap La Tercera → N candidatos temáticos
UAF.cl directo → N noticias recientes
prensa chilena única: N · cuerpos extraídos: N · extranjeros descartados: N
```

En `datos.json` puedes confirmar:

```json
{
  "version_motor": "4.0-cuerpo-completo-chile",
  "cobertura_tecnica": {
    "cuerpos_extraidos": 0,
    "fuentes_institucionales": 0,
    "solo_fuentes_chilenas": true
  }
}
```

Los números serán diferentes en cada ejecución.

## Limitaciones

- Algunos medios pueden bloquear temporalmente la extracción automatizada o modificar su estructura HTML.
- Los buscadores no garantizan entregar todos los resultados indexados.
- Los sitemaps pueden cambiar de ubicación o limitar el número de noticias recientes.
- La clasificación temática y de roles es automática y debe validarse antes de utilizarla en informes institucionales.
- No se realiza scraping de resultados generales de Google con una sesión de usuario. Se utilizan Google News RSS, consultas por dominio, sitemaps publicados y páginas públicas de los medios.
