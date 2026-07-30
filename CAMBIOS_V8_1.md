# Monitor UAF Chile v8.1 · calidad profunda

## Objetivo

Reducir falsos positivos en dos niveles sin perder cobertura válida:

1. **Pertinencia de la publicación:** distinguir menciones directas de la UAF de Chile, contexto LA/FT sustantivo y contenido incidental o ajeno.
2. **Clasificación analítica:** asignar fenómenos, delitos precedentes, tópicos y sujetos obligados solo cuando existe evidencia contextual suficiente.

## Correcciones estructurales

### Coincidencia léxica estricta

Las expresiones dejaron de buscarse como subcadenas simples. Esto evita, por ejemplo, que la sigla `ROS` se encuentre dentro de palabras como `otros` o `numerosos`.

### Tres estados de pertinencia

Cada publicación queda clasificada como:

- `uaf_directa`: mención válida de UAF Chile.
- `contexto_laft`: relación sustantiva con lavado de activos o financiamiento del terrorismo, aunque no nombre a la UAF.
- `descartado`: coincidencia incidental, ambigua, extranjera o sin evidencia suficiente.

El correo continúa enviándose exclusivamente por menciones directas válidas de UAF Chile.

### UAF extranjeras y siglas ambiguas

Se rechazan construcciones como `UAF de Panamá` o referencias equivalentes a otras jurisdicciones. Una sigla ubicada solo en el cuerpo exige acción institucional o contexto LA/FT próximo.

### Taxonomía contextual integral

La clasificación ya no usa el artículo completo como una bolsa de palabras. Prioriza:

1. título;
2. bajada;
3. inicio del artículo;
4. ventanas alrededor de UAF;
5. ventanas alrededor de expresiones LA/FT.

Se aplican reglas independientes a fenómenos, delitos precedentes, tópicos y sujetos obligados.

## Patrones de falso positivo corregidos

- `ROS` encontrado dentro de `otros` o `numerosos`.
- `Aduanas` interpretado automáticamente como contrabando.
- Una mención de criptomonedas interpretada automáticamente como cibercrimen.
- Todo artículo que dice `lavado de activos` clasificado como prevención.
- La palabra `investigación` usada en un reportaje interpretada como investigación penal.
- Toda mención a la UAF clasificada automáticamente como inteligencia financiera.
- Bancos, notarios, municipalidades u otros sectores asignados por una mención incidental.
- Listas generales de delitos transformadas en múltiples delitos precedentes.
- UAF extranjeras atribuidas a Chile.
- Módulos de noticias relacionadas incorporados como cuerpo editorial.

## Auditoría automática

`datos.json` incorpora `auditoria_calidad`, que compara las categorías históricas con las nuevas reglas y registra:

- publicaciones retiradas;
- cambios de fenómeno;
- delitos precedentes retirados;
- tópicos retirados;
- sujetos obligados retirados.

La página `auditoria.html` muestra esos casos con medio, fecha, titular, enlace y corrección aplicada.

## Dashboard

Se eliminó del `index.html` el encabezado superior que mostraba:

- Unidad de Análisis Financiero · Chile;
- Monitoreo analítico de prensa;
- fecha, versión y número de consultas.

La fecha y versión permanecen disponibles en la barra de estado superior, ocupando menos espacio.
