# Monitor UAF Chile · prensa, LA/FT y sujetos obligados

Dashboard estático publicado en GitHub Pages y actualizado mediante GitHub Actions aproximadamente cada 15 minutos.

## Cambios de esta versión

### 1. Validación específica de la UAF de Chile

La etiqueta **Mención UAF Chile** ya no se activa por cualquier aparición de la sigla `UAF`.

El motor exige señales chilenas, entre ellas:

- expresiones como `UAF Chile`, `UAF de Chile` o `Unidad de Análisis Financiero de Chile`;
- referencias a la Ley N.°19.913, CMF, SII, Ministerio Público, PDI u otras instituciones chilenas;
- fuente oficial `uaf.cl`;
- contexto territorial chileno o un medio de prensa nacional reconocido.

Las menciones a unidades extranjeras —por ejemplo, UAF de Panamá— se excluyen cuando no existe una conexión explícita con Chile. Las noticias del histórico también se reclasifican en cada ejecución, por lo que los falsos positivos antiguos desaparecen después del primer corte con esta versión.

### 2. Sujetos obligados

El monitor incorpora noticias sobre sectores obligados a reportar a la UAF, agrupando analíticamente las 55 actividades informadas por la institución:

- banca y servicios financieros;
- mercado de valores y fondos;
- pensiones, seguros y mutuos;
- fintech y medios de pago;
- inmobiliario, notarios y conservadores;
- vehículos, leasing y factoring;
- casinos, apuestas y deporte profesional;
- aduanas y zonas francas;
- metales, joyas y remates;
- fabricación y venta de armas;
- otros sujetos obligados y entidades reportantes.

Para cada sector se intenta distinguir:

- vinculación o vulneración en casos de LA/FT;
- cambio regulatorio o de supervisión;
- gestión de cumplimiento preventivo;
- cambio relevante en la industria.

### 3. Gráficos como filtros

Los siguientes elementos son interactivos:

- barras de evolución diaria;
- bloques semanales;
- ranking de sujetos obligados;
- ranking de impactos sectoriales;
- tópicos;
- medios;
- casos y fenómenos;
- delitos precedentes;
- tarjetas de cobertura UAF directa versus contexto LA/FT.

Al pulsarlos, se filtra la tabla de noticias y aparece una etiqueta con el filtro activo. Pulsar nuevamente el mismo elemento lo desactiva.

### 4. Diseño

La interfaz utiliza una identidad visual formal basada en azules profundos, turquesa y grises, asociada a la institucionalidad de la UAF Chile. El encabezado es tipográfico y no pretende reemplazar ni reproducir un logotipo oficial.

## Archivos que debes reemplazar en GitHub

Sube **estos cuatro archivos** a la raíz del repositorio:

1. `index.html`
2. `monitor_uaf.py`
3. `construye_sitio.py`
4. `README.md`

Es indispensable reemplazar `construye_sitio.py`, porque la nueva interfaz utiliza un bloque de respaldo denominado `FALLBACK`.

### Actualización sin Git ni permisos de administrador

1. En GitHub abre el repositorio y entra a **Code**.
2. Pulsa **Add file → Upload files**.
3. Arrastra los cuatro archivos anteriores.
4. Confirma que GitHub indique que reemplazará los existentes.
5. Escribe, por ejemplo, `Mejorar precisión UAF Chile y sujetos obligados`.
6. Pulsa **Commit changes**.
7. En **Actions**, abre `Actualizar y publicar monitor`.
8. Espera a que la ejecución automática termine en verde o pulsa **Run workflow**.
9. Recarga GitHub Pages con `Ctrl + F5`.

No es necesario modificar el workflow existente.

## Funcionamiento general

Cada ejecución:

1. recupera el histórico desde la rama `monitor-state`;
2. consulta Google News, Reddit y Bluesky;
3. valida la pertinencia chilena de las menciones UAF;
4. clasifica casos, delitos precedentes, tópicos y sujetos obligados;
5. elimina falsos positivos y noticias que superan 30 días;
6. genera `datos.json`;
7. publica el sitio en GitHub Pages;
8. vuelve a guardar el estado.

## Interfaz

La portada muestra exclusivamente menciones verificadas de la UAF de Chile durante las últimas 24 horas y un contexto secundario de cinco días.

El panorama general incluye:

- selector de 7, 15 y 30 días;
- evolución diaria y vista semanal;
- UAF directa versus contexto LA/FT;
- sujetos obligados e impacto sectorial;
- rankings de medios, tópicos, casos y delitos precedentes;
- filtros de rango de fechas;
- tabla paginada de 10, 20 o 50 noticias;
- señal social solo de plataformas con acceso automatizado público.

## Consideraciones analíticas

La precisión geográfica fue priorizada sobre la cobertura. Una noticia que diga solamente `UAF`, sin señales chilenas suficientes, puede ser descartada para evitar atribuir a Chile información de otra jurisdicción.

Las clasificaciones son automáticas y orientativas. Antes de citar una noticia en un informe institucional conviene revisar la fuente original y validar el tópico, sector, impacto y delito precedente asignados.

## Diagnóstico

En **Actions → Actualizar y publicar monitor**, revisa el paso **Ejecutar monitor**:

- `Listo: ... → datos.json`: ejecución correcta.
- `ninguna fuente respondió; se conserva el último datos.json`: caída temporal de fuentes.
- `fallo en Google News`, `Reddit` o `Bluesky`: una fuente concreta no respondió.
- error en `Construir sitio estático`: confirma que reemplazaste `construye_sitio.py`.
- error en `Guardar estado`: revisa los permisos de escritura del workflow.
