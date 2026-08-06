#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Motor de reconocimiento de personas naturales y jurídicas (Chile).

Capa de reconocimiento y desambiguación que se acopla a ``modulo_entidades.py``
del Monitor UAF. Su objetivo es responder, para cada cadena detectada en prensa,
tres preguntas auditables:

1. ¿Es una entidad o es ruido? (filtro de falsos positivos)
2. ¿Es una PERSONA NATURAL o una PERSONA JURÍDICA? (naturaleza)
3. ¿Qué subtipo jurídico tiene y con qué grado de certeza? (tipo + score)

Diseño:

- Sin dependencias pesadas. Usa spaCy si está disponible (lo carga el módulo
  llamador) y ``rapidfuzz`` de forma opcional para variantes ortográficas.
- Toda decisión deja traza en ``senales``: el analista puede reconstruir por qué
  el motor clasificó una cadena de una forma u otra.
- No determina culpabilidad. Clasificar una cadena como PERSONA_NATURAL no
  implica imputación alguna.

Autor: capa v3 para Monitor UAF Chile.
"""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict

try:  # Catálogo geográfico de Chile (comunas, provincias, regiones).
    import geografia_cl as GEO

    GEOGRAFIA_DISPONIBLE = True
except Exception:  # pragma: no cover - degradación controlada
    GEO = None
    GEOGRAFIA_DISPONIBLE = False
from typing import Any, Iterable

VERSION_RECONOCEDOR = "3.0.0-personas-naturales-y-juridicas"

try:  # Coincidencia difusa opcional (variantes ortográficas y tildes perdidas).
    from rapidfuzz import fuzz as _fuzz

    RAPIDFUZZ_DISPONIBLE = True
except Exception:  # pragma: no cover - degradación controlada
    _fuzz = None
    RAPIDFUZZ_DISPONIBLE = False


# ---------------------------------------------------------------------------
# 1. Naturaleza jurídica
# ---------------------------------------------------------------------------

NATURALEZA_POR_TIPO: dict[str, str] = {
    "PERSONA": "PERSONA_NATURAL",
    "EMPRESA": "PERSONA_JURIDICA",
    "INSTITUCION_FINANCIERA": "PERSONA_JURIDICA",
    "ORGANISMO_PUBLICO": "PERSONA_JURIDICA",
    "ORGANIZACION": "PERSONA_JURIDICA",
    "ENTIDAD_SIN_FINES_DE_LUCRO": "PERSONA_JURIDICA",
    "TRIBUNAL": "PERSONA_JURIDICA",
    "LUGAR": "NO_APLICA",
    "MONTO": "NO_APLICA",
    "FECHA": "NO_APLICA",
    "RUT": "NO_APLICA",
    "CRIPTOACTIVO": "NO_APLICA",
    "OTRO": "INDETERMINADA",
}

TIPOS_PERSONA_JURIDICA = {
    "EMPRESA",
    "INSTITUCION_FINANCIERA",
    "ORGANISMO_PUBLICO",
    "ORGANIZACION",
    "ENTIDAD_SIN_FINES_DE_LUCRO",
    "TRIBUNAL",
}


def naturaleza_de(tipo: Any) -> str:
    """Devuelve PERSONA_NATURAL / PERSONA_JURIDICA / NO_APLICA / INDETERMINADA."""
    return NATURALEZA_POR_TIPO.get(str(tipo or "").upper(), "INDETERMINADA")


# ---------------------------------------------------------------------------
# 2. Normalización
# ---------------------------------------------------------------------------

_ESPACIOS = re.compile(r"\s+")


def _sin_tildes(texto: str) -> str:
    desc = unicodedata.normalize("NFKD", texto)
    return "".join(ch for ch in desc if not unicodedata.combining(ch))


def norm(texto: Any) -> str:
    """Minúsculas, sin tildes, sin puntuación: clave de comparación."""
    plano = _sin_tildes(str(texto or "")).casefold()
    plano = re.sub(r"[^a-z0-9]+", " ", plano)
    return _ESPACIOS.sub(" ", plano).strip()


# Un punto final se conserva cuando cierra una abreviatura: inicial suelta
# ("S.A."), sigla con puntos internos ("E.I.R.L.") o abreviatura corta
# capitalizada ("Ltda.", "Cía."). En cambio "Frase completa." pierde el punto.
_ABREVIATURA_FINAL = re.compile(
    r"(?:(?:^|[\s.])[A-Za-zÁÉÍÓÚÑ]\.|\.[A-Za-zÁÉÍÓÚÑ]{1,4}\.|(?:^|\s)[A-ZÁÉÍÓÚÑ][a-záéíóúñü]{1,4}\.)$"
)


def limpia(texto: Any, limite: int = 180) -> str:
    """Recorta puntuación de borde sin destruir abreviaturas societarias.

    ``"Importadora Tarapacá S.A."`` debe conservar el punto final: eliminarlo
    impide reconocer el sufijo de razón social y degrada la clasificación.
    """
    valor = _ESPACIOS.sub(" ", str(texto or "")).strip()
    valor = valor.strip(" \t\r\n,;:()[]{}«»\"'“”‘’")
    while valor.endswith(".") and not _ABREVIATURA_FINAL.search(valor):
        valor = valor[:-1].rstrip()
    while valor.startswith("."):
        valor = valor[1:].lstrip()
    return valor[:limite]


# ---------------------------------------------------------------------------
# 3. Léxico societario e institucional chileno
# ---------------------------------------------------------------------------

# Sufijos de razón social. Incluye formas chilenas y extranjeras frecuentes en
# estructuras societarias con componente transfronterizo.
# Cada alternativa se ancla con (?<![\w.]) para impedir que el sufijo "SA" se
# dispare dentro de palabras como "Bolsa" o "Casa", un falso positivo real
# observado en la versión anterior.
_INI = r"(?<![\w.])"
_FIN = r"(?![\w.])"

SUFIJOS_SOCIETARIOS = [
    _INI + r"S\.?\s?p\.?\s?A\.?" + _FIN,               # SpA, S.p.A.
    _INI + r"S\.?\s?A\.?\s?G\.?\s?R\.?" + _FIN,        # SAGR
    _INI + r"S\.?\s?A\.?\s?C\.?" + _FIN,               # SAC
    _INI + r"S\.?\s?A\.?\s?S\.?" + _FIN,               # SAS
    _INI + r"S\.\s?A\.?" + _FIN,                       # S.A. / S.A
    _INI + r"SA" + _FIN,                               # SA aislado
    _INI + r"Ltda\.?" + _FIN,
    r"\bLimitada\b",
    _INI + r"E\.?\s?I\.?\s?R\.?\s?L\.?" + _FIN,
    _INI + r"SGR" + _FIN,
    _INI + r"SCM" + _FIN,
    r"\bSociedad\s+por\s+Acciones\b",
    r"\bSociedad\s+An[oó]nima(?:\s+(?:Abierta|Cerrada|Especial))?\b",
    r"\bSociedad\s+de\s+Responsabilidad\s+Limitada\b",
    r"\bSociedad\s+Colectiva(?:\s+Civil|\s+Comercial)?\b",
    r"\bSociedad\s+en\s+Comandita(?:\s+por\s+Acciones|\s+Simple)?\b",
    r"\bC[ií]a\.?\s+Ltda\.?",
    _INI + r"Inc\.?" + _FIN,
    _INI + r"Corp\.?" + _FIN,
    _INI + r"LLC" + _FIN,
    _INI + r"LLP" + _FIN,
    _INI + r"Ltd\.?" + _FIN,
    _INI + r"PLC" + _FIN,
    _INI + r"N\.\s?V\.?" + _FIN,
    _INI + r"B\.\s?V\.?" + _FIN,
    _INI + r"GmbH" + _FIN,
    _INI + r"S\.\s?L\.?" + _FIN,
    _INI + r"S\.\s?R\.\s?L\.?" + _FIN,
    r"\bS\.\s?de\s?R\.\s?L\.",
    _INI + r"Pte\.?\s?Ltd\.?" + _FIN,
]
SUFIJO_RE = re.compile("(?:" + "|".join(SUFIJOS_SOCIETARIOS) + ")", re.IGNORECASE)

# Núcleos que encabezan razones sociales chilenas sin sufijo explícito.
NUCLEOS_EMPRESA = {
    "inversiones", "inversion", "comercial", "comercializadora", "inmobiliaria",
    "constructora", "agricola", "ganadera", "importadora", "exportadora",
    "distribuidora", "transportes", "transporte", "servicios", "consultora",
    "consultoria", "asesorias", "asesoria", "minera", "pesquera", "forestal",
    "automotriz", "corredora", "corredores", "administradora", "compania",
    "compañia", "grupo", "holding", "textil", "farmaceutica", "laboratorio",
    "editorial", "productora", "inversora", "arrendadora", "concesionaria",
    "constructora", "ingenieria", "tecnologias", "sociedad", "empresa",
    "empresas", "negocios", "comercio", "casa", "agencia", "operadora",
    "generadora", "energia", "electrica", "logistica", "naviera", "turismo",
    "hotelera", "gastronomica", "inversionista", "financiera", "leasing",
    "factoring", "corretaje", "joyeria", "casino", "clinica", "farmacia",
    "supermercados", "retail", "molinera", "azucarera", "vitivinicola", "viña",
    "vina", "salmonera", "avicola", "frigorifica", "curtiembre", "metalurgica",
}

NUCLEOS_ORGANISMO_PUBLICO = {
    "ministerio", "subsecretaria", "superintendencia", "servicio", "direccion",
    "contraloria", "consejo", "municipalidad", "ilustre municipalidad",
    "gobierno regional", "delegacion presidencial", "intendencia", "seremi",
    "secretaria regional ministerial", "aduana", "aduanas", "registro civil",
    "tesoreria", "instituto", "comision", "defensoria", "congreso",
    "camara de diputados", "senado", "unidad", "agencia nacional",
    "gendarmeria", "carabineros", "policia", "fiscalia", "ministerio publico",
    "banco central", "corfo", "sercotec", "conadi", "junaeb", "fonasa",
    "prefectura", "brigada", "subprefectura", "gobernacion", "corporacion municipal",
}

NUCLEOS_TRIBUNAL = {
    "juzgado", "tribunal", "corte", "corte suprema", "corte de apelaciones",
    "tribunal oral", "tribunal constitucional", "tribunal de cuentas",
    "juzgado de garantia", "juzgado de letras", "tribunal ambiental",
    "tribunal tributario", "tribunal de defensa de la libre competencia",
}

NUCLEOS_FINANCIERA = {
    "banco", "bancoestado", "banco estado", "corredora de bolsa",
    "corredores de bolsa", "administradora general de fondos", "agf", "afp",
    "compania de seguros", "cooperativa de ahorro", "caja de compensacion",
    "casa de cambio", "bolsa de comercio", "bolsa electronica", "mutuaria",
    "administradora de fondos", "fondo de inversion", "fondos de inversion",
    "corredora de seguros", "emisora de tarjetas", "sociedad de apoyo al giro",
}

NUCLEOS_SIN_FINES_LUCRO = {
    "fundacion", "corporacion", "asociacion", "asociacion gremial", "gremio",
    "sindicato", "club", "iglesia", "ong", "organizacion no gubernamental",
    "junta de vecinos", "cooperativa", "comunidad", "colegio de", "federacion",
    "confederacion", "camara de comercio", "camara chilena", "sociedad de socorros",
}

# Formas asociativas relevantes para LA/FT que igualmente son personas jurídicas
# o patrimonios de afectación (se marcan como jurídicas para efectos de nómina).
NUCLEOS_PATRIMONIO = {
    "sucesion", "comunidad hereditaria", "fideicomiso", "trust", "fondo",
}


def _es_nucleo(nombre_norm: str, nucleos: Iterable[str]) -> str | None:
    for nucleo in nucleos:
        if nombre_norm == nucleo or nombre_norm.startswith(nucleo + " "):
            return nucleo
    return None


# ---------------------------------------------------------------------------
# 4. Antroponimia chilena
# ---------------------------------------------------------------------------

# Nombres de pila frecuentes en Chile (Registro Civil, nacimientos 1950-2010).
# No pretende exhaustividad: es una señal positiva, no un requisito.
NOMBRES_PILA = {
    "jose", "juan", "luis", "carlos", "manuel", "francisco", "pedro", "jorge",
    "miguel", "victor", "sergio", "hector", "rene", "raul", "mario", "ramon",
    "alberto", "eduardo", "roberto", "fernando", "ricardo", "andres", "cristian",
    "cristobal", "rodrigo", "patricio", "marcelo", "gonzalo", "claudio",
    "alejandro", "felipe", "diego", "matias", "sebastian", "nicolas", "vicente",
    "benjamin", "martin", "agustin", "tomas", "joaquin", "maximiliano", "ignacio",
    "gabriel", "daniel", "david", "samuel", "esteban", "pablo", "hernan",
    "guillermo", "arturo", "enrique", "rafael", "oscar", "julio", "alfredo",
    "gustavo", "german", "leonardo", "marco", "mauricio", "jaime", "camilo",
    "emilio", "ivan", "osvaldo", "orlando", "hugo", "nelson", "waldo", "erwin",
    "boris", "aldo", "bruno", "dante", "franco", "italo", "renato", "rodolfo",
    "salvador", "santiago", "saul", "tito", "ulises", "wenceslao", "abel",
    "adrian", "alexis", "amaro", "anibal", "antonio", "ariel", "armando",
    "augusto", "aurelio", "bastian", "bernardo", "braulio", "byron", "cesar",
    "ciro", "clemente", "cristofer", "damian", "dario", "delfin", "dionisio",
    "edgardo", "edison", "efrain", "elias", "eliseo", "emiliano", "erasmo",
    "eric", "ernesto", "eugenio", "ezequiel", "fabian", "fabio", "federico",
    "fidel", "florencio", "gaspar", "genaro", "gerardo", "gilberto", "gregorio",
    "heriberto", "homero", "horacio", "humberto", "isaac", "isaias", "ismael",
    "jacinto", "javier", "jeremias", "jesus", "jonathan", "josue", "juvenal",
    "lautaro", "leandro", "leonel", "lorenzo", "lucas", "luciano", "marcial",
    "marcos", "mateo", "maximo", "moises", "napoleon", "nibaldo", "octavio",
    "olegario", "otto", "ovidio", "pascual", "patricio", "plinio", "primitivo",
    "quintin", "rene", "reinaldo", "rigoberto", "rolando", "romulo", "ruben",
    "rufino", "sandro", "segundo", "severino", "silvestre", "simon", "sixto",
    "teodoro", "tiburcio", "timoteo", "tobias", "tulio", "valentin", "vladimir",
    "walter", "wilfredo", "wilson", "yerko", "zacarias",
    "maria", "ana", "carmen", "rosa", "juana", "margarita", "teresa", "isabel",
    "patricia", "veronica", "claudia", "carolina", "andrea", "paula", "marcela",
    "alejandra", "cecilia", "monica", "ximena", "gloria", "silvia", "sandra",
    "nancy", "elizabeth", "jacqueline", "pamela", "karen", "katherine", "camila",
    "javiera", "valentina", "catalina", "constanza", "francisca", "antonia",
    "florencia", "isidora", "emilia", "josefa", "amanda", "agustina", "trinidad",
    "sofia", "martina", "fernanda", "daniela", "natalia", "paulina", "loreto",
    "macarena", "denisse", "lorena", "vivian", "viviana", "yasna", "yolanda",
    "adriana", "alba", "alicia", "amalia", "amelia", "angela", "angelica",
    "aurora", "beatriz", "berta", "blanca", "carla", "cristina", "delia",
    "dolores", "edith", "elena", "elsa", "elvira", "emma", "ester", "eugenia",
    "eva", "fabiola", "filomena", "flor", "gabriela", "genoveva", "georgina",
    "gladys", "graciela", "guadalupe", "guillermina", "herminia", "hilda",
    "ines", "irene", "iris", "irma", "isolda", "ivonne", "julia", "laura",
    "leonor", "leticia", "lidia", "liliana", "lucia", "luisa", "luz",
    "magdalena", "manuela", "marta", "matilde", "mercedes", "mireya", "miriam",
    "nelly", "nieves", "noemi", "norma", "olga", "pastora", "paz", "pilar",
    "raquel", "rebeca", "regina", "roxana", "ruth", "sara", "soledad", "sonia",
    "susana", "tamara", "valeria", "victoria", "violeta", "virginia", "wilma",
    "zoila", "solange", "priscila", "romina", "scarlett", "belen", "ignacia",
    "alvaro", "cathy", "katty", "nicole", "vanessa", "carola", "danitza",
    "jessica", "marisol", "myriam", "cecilia", "erika", "ericka", "evelyn",
    "ingrid", "karina", "lissette", "maribel", "mariela", "nadia", "olivia",
    "paola", "roxana", "sylvia", "tania", "ursula", "yenny", "yohana",
    "cristhian", "kevin", "jean", "jean pierre", "erick", "elvis", "jonatan",
    "brayan", "maicol", "michel", "michael", "steven", "alexander", "anthony",
    "franklin", "giovanni", "iker", "isaias", "jhon", "milton", "nahuel",
    "richard", "rony", "wladimir", "yerson", "hans", "karl", "peter",
    "renata", "antonella", "maite", "monserrat", "montserrat", "consuelo",
}

# Apellidos frecuentes en Chile (Registro Civil). Sirven como señal positiva
# sobre el último token: un antropónimo cuyo primer token es un nombre de pila
# conocido Y cuyo último token es un apellido conocido es prácticamente seguro.
# No es un requisito — Chile tiene una alta proporción de apellidos de origen
# migrante y mapuche fuera de esta lista.
APELLIDOS_FRECUENTES = {
    "gonzalez", "munoz", "rojas", "diaz", "perez", "soto", "contreras",
    "silva", "martinez", "sepulveda", "morales", "rodriguez", "lopez",
    "fuentes", "hernandez", "torres", "araya", "flores", "espinoza",
    "valenzuela", "castillo", "ramirez", "reyes", "gutierrez", "castro",
    "vargas", "alvarez", "vasquez", "tapia", "fernandez", "sanchez",
    "carrasco", "gomez", "cortes", "herrera", "nunez", "jara", "vergara",
    "rivera", "figueroa", "riquelme", "bravo", "vera", "molina", "vega",
    "campos", "sandoval", "orellana", "miranda", "olivares", "garcia",
    "navarro", "saavedra", "ortiz", "alarcon", "guzman", "salazar", "yanez",
    "cardenas", "medina", "aguilera", "leiva", "pena", "gallardo", "ruiz",
    "escobar", "arriagada", "aravena", "godoy", "aguirre", "maldonado",
    "cabrera", "farias", "venegas", "pinto", "salinas", "romero", "toro",
    "acuna", "poblete", "bustos", "concha", "ibanez", "parra", "leon",
    "ortega", "moreno", "arias", "avila", "bustamante", "cortez", "mora",
    "palma", "quezada", "san martin", "santander", "solis", "ulloa",
    "urrutia", "valdes", "valdivia", "villegas", "zamora", "zuniga",
    "barrera", "barrios", "becerra", "benitez", "caceres", "camus", "canales",
    "carvajal", "catalan", "cerda", "cespedes", "chavez", "cifuentes",
    "correa", "cuevas", "delgado", "donoso", "duran", "elgueta", "escalona",
    "estay", "fica", "fuenzalida", "galaz", "gajardo", "garrido", "gatica",
    "guerra", "guerrero", "hidalgo", "hormazabal", "huerta", "inostroza",
    "lagos", "lara", "lazo", "lillo", "llanos", "lobos", "loyola", "lucero",
    "luna", "mancilla", "manriquez", "marin", "marchant", "mella", "mendez",
    "mendoza", "meza", "montecinos", "montenegro", "monsalve", "moya",
    "neira", "novoa", "obreque", "ojeda", "olguin", "oyarce", "oyarzun",
    "pacheco", "padilla", "paredes", "pavez", "pizarro", "pino", "plaza",
    "ponce", "prado", "quintana", "quiroz", "ramos", "rebolledo", "retamal",
    "rios", "rivas", "roa", "roman", "rubio", "saez", "salas", "sanhueza",
    "santibanez", "sanzana", "sarmiento", "sierra", "sotomayor", "suarez",
    "tobar", "toledo", "troncoso", "uribe", "valle", "vallejos", "veas",
    "velasquez", "verdugo", "vidal", "villalobos", "villarroel", "yevenes",
    "zapata", "zavala", "acevedo", "alvarado", "andrade", "antileo", "apablaza",
    "arancibia", "astudillo", "avendano", "azocar", "baeza", "bahamondes",
    "balboa", "banda", "barra", "berrios", "bobadilla", "briones", "burgos",
    "caro", "carreno", "carrillo", "castaneda", "cerpa", "colil", "coloma",
    "cuello", "curihual", "diez", "dominguez", "echeverria", "espina",
    "fritz", "gaete", "gallegos", "gamboa", "gandara", "garay", "gonzales",
    "guajardo", "henriquez", "huaiquil", "huenchullan", "huenupan", "ibacache",
    "iturra", "jaramillo", "jimenez", "labra", "lagunas", "lam", "landeros",
    "lefian", "lemus", "levican", "linares", "liempi", "llaupe", "loncon",
    "maldonado", "mansilla", "marileo", "melillan", "melo", "millalen",
    "montoya", "morales", "mundaca", "munita", "nahuelpan", "namuncura",
    "naranjo", "nasser", "nazar", "olate", "opazo", "osorio", "oteiza",
    "painemal", "palacios", "pardo", "pastene", "pereira", "pinilla",
    "pinochet", "prieto", "puelma", "quilodran", "quintanilla", "rabanal",
    "raiman", "recabarren", "riffo", "rioseco", "rocha", "rojo", "rosales",
    "rozas", "ruminot", "sagredo", "salgado", "sanmartin", "sepulveda",
    "sierralta", "silvestre", "soto", "tapia", "tello", "tirado", "torrealba",
    "trujillo", "turra", "urra", "urzua", "valdebenito", "valdivieso",
    "vejar", "velez", "venegas", "vicencio", "vielma", "vilches", "villa",
    "villablanca", "villagra", "villagran", "villanueva", "vivanco", "wilson",
    "yanquileo", "zambrano", "zamorano", "zarate", "zenteno", "zurita",
    "hermosilla", "jalaff", "sauer", "topelberg", "barriga", "guerra",
}

# Partículas que aparecen en minúscula dentro de apellidos compuestos.
PARTICULAS_APELLIDO = {
    "de", "del", "de la", "de los", "de las", "la", "las", "los", "van", "von",
    "da", "das", "do", "dos", "di", "del", "san", "santa", "santo", "mac", "mc",
    "le", "y", "e", "el", "al", "bin", "ibn", "st",
}

TRATAMIENTOS = re.compile(
    r"\b(?:don|do[ñn]a|sr\.?|sra\.?|srta\.?|se[ñn]or|se[ñn]ora|se[ñn]orita|"
    r"dr\.?|dra\.?|prof\.?|ing\.?|abg\.?|lic\.?|mons\.?)\s+$",
    re.IGNORECASE,
)

# Cadenas capitalizadas que NUNCA son un nombre de persona. Cubre inicios de
# oración, conectores, meses, medios y sustantivos institucionales genéricos.
NO_NOMBRE = {
    "segun", "ademas", "asimismo", "sin", "embargo", "tras", "durante", "luego",
    "ayer", "hoy", "manana", "cabe", "actualmente", "tambien", "pero", "aunque",
    "mientras", "cuando", "donde", "porque", "entonces", "finalmente",
    "posteriormente", "previamente", "anteriormente", "respecto", "sobre",
    "desde", "hasta", "entre", "para", "por", "con", "este", "esta", "esto",
    "ese", "esa", "eso", "aquel", "aquella", "dicho", "dicha", "dichos",
    "otro", "otra", "otros", "otras", "todo", "toda", "todos", "todas",
    "el", "la", "los", "las", "un", "una", "unos", "unas", "al", "del",
    "no", "si", "ni", "que", "quien", "cual", "cuyo", "como", "aun",
    "caso", "operacion", "operativo", "proyecto", "ley", "decreto", "articulo",
    "region", "comuna", "provincia", "sector", "informe", "reporte", "causa",
    "juicio", "audiencia", "sentencia", "fallo", "resolucion", "oficio",
    "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
    "septiembre", "setiembre", "octubre", "noviembre", "diciembre",
    "lunes", "martes", "miercoles", "jueves", "viernes", "sabado", "domingo",
    "estado", "gobierno", "republica", "nacion", "pais", "chile", "chileno",
    "chilena", "poder", "judicial", "ejecutivo", "legislativo", "congreso",
    "twitter", "instagram", "facebook", "whatsapp", "youtube", "tiktok",
    "google", "linkedin", "telegram",
    "covid", "pandemia", "internet", "web", "online",
    "norte", "sur", "oriente", "poniente", "centro", "metropolitana",
    "primero", "segundo", "tercero", "cuarto", "quinto",
    "nuevo", "nueva", "gran", "grande", "alto", "alta", "bajo", "baja",
    "fuentes", "antecedentes", "documentos", "declaraciones",
}

# Sustantivos que, al encabezar una cadena capitalizada, indican que NO es una
# persona natural aunque el modelo estadístico la haya etiquetado como PER.
# Determinantes y sustantivos colectivos que la prensa antepone a la razón
# social. Se eliminan al canonizar: "la sociedad Agrícola El Peumo Ltda." es
# la misma entidad que "Agrícola El Peumo Ltda.".
PREFIJOS_GENERICOS = {
    "la", "el", "los", "las", "un", "una", "unos", "unas", "del", "al",
    "sociedad", "sociedades", "empresa", "empresas", "firma", "firmas",
    "compania", "compañia", "companias", "entidad", "institucion",
    "organizacion", "denominada", "llamada",
}

# Tokens finales que delatan una persona jurídica aunque no exista sufijo legal
# chileno: frecuentes en estructuras societarias con matriz extranjera.
TERMINALES_JURIDICOS = {
    "group", "groupe", "holding", "holdings", "partners", "capital", "finance",
    "financial", "management", "investments", "investment", "ventures",
    "trading", "consulting", "solutions", "technologies", "technology",
    "international", "global", "enterprises", "industries", "systems",
    "services", "associates", "company", "trust", "fund", "funds", "bank",
    "asset", "assets", "securities", "advisors", "advisory", "corporation",
}

ENCABEZADOS_EVENTO = {
    "caso", "operacion", "operativo", "megaoperativo", "plan", "programa",
    "proyecto", "arista", "causa", "querella", "sumario", "informe", "escandalo",
}

ENCABEZADOS_NO_PERSONA = (
    NUCLEOS_EMPRESA
    | NUCLEOS_ORGANISMO_PUBLICO
    | NUCLEOS_TRIBUNAL
    | NUCLEOS_FINANCIERA
    | NUCLEOS_SIN_FINES_LUCRO
    | NUCLEOS_PATRIMONIO
)

# Cargos y calidades que anteceden o siguen a una persona natural.
ROLES_PERSONA = (
    r"imputad[oa]|formalizad[oa]|condenad[oa]|acusad[oa]|querellad[oa]|"
    r"investigad[oa]|detenid[oa]|proces[oa]d[oa]|absuelt[oa]|sentenciad[oa]|"
    r"empresari[oa]|abogad[oa]|fiscal|juez|jueza|ministr[oa]|magistrad[oa]|"
    r"gerent[ea]|director(?:a)?|presidenta?|vicepresidente|socio|socia|accionista|"
    r"representante|apoderad[oa]|contador(?:a)?|auditor(?:a)?|perit[oa]|"
    r"testig[oa]|denunciante|querellante|víctima|victima|"
    r"alcalde|alcaldesa|concejal|diputad[oa]|senador(?:a)?|seremi|"
    r"subsecretari[oa]|superintendente|prefect[oa]|comisari[oa]|"
    r"ex\s?gerente|ex\s?director(?:a)?|ex\s?alcalde|ex\s?funcionari[oa]|"
    r"funcionari[oa]|ejecutiv[oa]|jefe|jefa|encargad[oa]|administrador(?:a)?|"
    r"beneficiari[oa]\s+final|controlador(?:a)?|dueñ[oa]|due[ñn][oa]|titular"
)

CONTEXTO_PERSONA_IZQ = re.compile(
    r"(?:" + ROLES_PERSONA + r")\s*(?:de\s+la|de|del)?\s*$",
    re.IGNORECASE,
)
CONTEXTO_PERSONA_DER = re.compile(
    r"^\s*,?\s*(?:de\s+\d{1,3}\s+años|\(\d{1,3}\)|" + ROLES_PERSONA + r")",
    re.IGNORECASE,
)

VERBOS_ACCION_PERSONA = re.compile(
    r"\b(?:formaliz[óo]|formalizaron|imput[óo]|imputaron|conden[óo]|condenaron|"
    r"acus[óo]|acusaron|detuv(?:o|ieron)|investiga(?:n|ron)?|indag(?:a|an|ó|o)|"
    r"querell[óo]|declar[óo]|reconoci[óo]|admiti[óo]|neg[óo]|sostuvo|afirm[óo])"
    r"\s+(?:a\s+)?$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 5. Validación de RUT (módulo 11)
# ---------------------------------------------------------------------------

RUT_RE = re.compile(
    r"(?<![\w-])(?:R\.?U\.?T\.?\s*:?\s*)?(\d{1,3}(?:\.\d{3}){1,2}|\d{7,9})\s*-\s*([\dkK])(?![\w-])"
)


def digito_verificador(cuerpo: str) -> str:
    """Calcula el dígito verificador chileno (módulo 11)."""
    suma = 0
    multiplo = 2
    for ch in reversed(cuerpo):
        suma += int(ch) * multiplo
        multiplo = 2 if multiplo == 7 else multiplo + 1
    resto = 11 - (suma % 11)
    if resto == 11:
        return "0"
    if resto == 10:
        return "K"
    return str(resto)


def valida_rut(texto: Any) -> dict[str, Any]:
    """Valida un RUT y clasifica su naturaleza según el rango numérico.

    En Chile los RUT de personas jurídicas se asignan desde 50.000.000 y los de
    personas naturales bajo ese umbral. Es una convención administrativa, no una
    regla legal, por lo que se reporta como indicio y no como certeza.
    """
    match = RUT_RE.search(str(texto or ""))
    if not match:
        return {"valido": False, "motivo": "sin_formato_rut"}
    cuerpo = re.sub(r"\D", "", match.group(1))
    dv_declarado = match.group(2).upper()
    if not cuerpo or len(cuerpo) < 7:
        return {"valido": False, "motivo": "cuerpo_corto"}
    dv_calculado = digito_verificador(cuerpo)
    valido = dv_calculado == dv_declarado
    numero = int(cuerpo)
    if numero >= 50_000_000:
        naturaleza = "PERSONA_JURIDICA"
    elif numero >= 100_000:
        naturaleza = "PERSONA_NATURAL"
    else:
        naturaleza = "INDETERMINADA"
    return {
        "valido": valido,
        "rut": f"{int(cuerpo):,}".replace(",", ".") + "-" + dv_declarado,
        "cuerpo": numero,
        "dv_declarado": dv_declarado,
        "dv_calculado": dv_calculado,
        "naturaleza_indicativa": naturaleza,
        "motivo": "ok" if valido else "dv_no_coincide",
    }


# ---------------------------------------------------------------------------
# 6. Patrones de extracción por reglas
# ---------------------------------------------------------------------------

_T = r"[A-ZÁÉÍÓÚÜÑ][\wÁÉÍÓÚÜÑáéíóúüñ&'’\.-]*"
# Token antroponímico: a diferencia de ``_T`` no admite punto interno. Sin esta
# distinción, "…Costa Sur SpA. Juan Pérez, socio de…" hacía que la regex de
# persona arrancara en "Sur SpA." y cruzara el fin de oración, perdiendo la
# detección real de "Juan Pérez".
_TP = r"[A-ZÁÉÍÓÚÜÑ][\wÁÉÍÓÚÜÑáéíóúüñ'’-]*"
_C = r"(?:de|del|la|las|los|el|lo|y|e|en|para|por|con|al|da|do|di|van|von|the|of|and)"

# Razón social con sufijo societario. Admite conectores en minúscula, lo que
# corrige el truncamiento de "…Corredores de Bolsa S.A." a "Bolsa S.A.".
RAZON_SOCIAL_RE = re.compile(
    r"\b(" + _T + r"(?:\s+(?:" + _T + r"|" + _C + r")){0,9}\s+"
    r"(?:" + "|".join(SUFIJOS_SOCIETARIOS) + r"))",
    re.UNICODE,
)

# Razón social sin sufijo, encabezada por un núcleo societario reconocible.
#
# El flag IGNORECASE se limita al núcleo mediante un grupo con ámbito ``(?i:…)``.
# Aplicarlo a toda la expresión hacía que ``_T`` aceptara tokens en minúscula y
# la captura se desbordara sobre la oración completa
# ("Ministerio Público formalizó a Rodrigo Andrés Pizarro Meza").
#
# Además, la captura debe cerrar en un token capitalizado: así el nombre nunca
# termina en una preposición arrastrada ("… SpA por más de").
def _flexible(palabra: str) -> str:
    """Convierte un núcleo normalizado en un patrón tolerante a tildes y eñes.

    Los conjuntos de núcleos se almacenan sin tildes para poder compararlos con
    ``norm()``. Insertarlos literalmente en una expresión regular hacía que
    "fundacion" jamás coincidiera con "Fundación" en el texto: todo núcleo
    acentuado quedaba fuera del reconocimiento por reglas.
    """
    equivalencias = {
        "a": "[a\u00e1]", "e": "[e\u00e9]", "i": "[i\u00ed]",
        "o": "[o\u00f3]", "u": "[u\u00fa\u00fc]", "n": "[n\u00f1]",
    }
    salida = []
    for ch in palabra:
        if ch == " ":
            salida.append(r"\s+")
        else:
            salida.append(equivalencias.get(ch, re.escape(ch)))
    return "".join(salida)


def _alternancia(nucleos) -> str:
    return "(?i:" + "|".join(
        _flexible(x) for x in sorted(nucleos, key=len, reverse=True)
    ) + ")"


_NUCLEOS_RE = _alternancia(NUCLEOS_EMPRESA | NUCLEOS_SIN_FINES_LUCRO)
RAZON_SOCIAL_NUCLEO_RE = re.compile(
    r"\b(" + _NUCLEOS_RE + r"(?:\s+(?:" + _T + r"|" + _C + r")){0,4}\s+" + _T + r")",
    re.UNICODE,
)

_ORG_PUB_RE = _alternancia(NUCLEOS_ORGANISMO_PUBLICO | NUCLEOS_TRIBUNAL)
ORGANISMO_RE = re.compile(
    r"\b(" + _ORG_PUB_RE + r"(?:\s+(?:" + _T + r"|" + _C + r")){0,8}\s+" + _T + r")",
    re.UNICODE,
)

# Persona precedida por tratamiento o cargo.
# Modificadores que la prensa intercala entre el cargo y el nombre
# ("fiscal regional Mario Carrera", "gerente general de la compañía, Óscar…").
# Es una lista cerrada: admitir cualquier palabra en minúscula haría que la
# regla capturara sustantivos comunes como si fueran apellidos.
MODIFICADORES_CARGO = (
    r"(?:general|regional|nacional|metropolitan[oa]|provincial|comunal|"
    r"jefe|jefa|subrogante|titular|adjunt[oa]|suplente|interin[oa]|"
    r"ejecutiv[oa]|comercial|legal|judicial|penal|tributari[oa]|"
    r"corporativ[oa]|de|del|la|los|las|su|empresa|compa[ñn][ií]a|sociedad|"
    r"firma|entidad|instituci[oó]n|organismo|servicio)"
)

PERSONA_PRECEDIDA_RE = re.compile(
    r"(?:(?i:\b(?:don|do[ñn]a|sr\.|sra\.|se[ñn]or|se[ñn]ora|" + ROLES_PERSONA + r")"
    r"(?:\s+" + MODIFICADORES_CARGO + r"){0,4})\s+)"
    r"(" + _TP + r"(?:\s+(?:de|del|la|los|las|van|von|da|di)){0,2}"
    r"(?:\s+" + _TP + r"){1,3})",
    re.UNICODE,
)

# Aposición tras una frase de cargo: "El gerente general de la compañía,
# Óscar Villablanca Ríos, señaló que…".
PERSONA_APOSICION_RE = re.compile(
    r"(?i:\b(?:" + ROLES_PERSONA + r"))"
    r"(?:(?i:\s+" + MODIFICADORES_CARGO + r")|\s+" + _TP + r"){0,5}"
    r"\s*,\s*"
    r"(" + _TP + r"(?:\s+(?:de|del|la|los|las|van|von|da|di)){0,2}"
    r"(?:\s+" + _TP + r"){1,3})"
    r"\s*,",
    re.UNICODE,
)

# Persona seguida de coma y cargo: "Juan Pérez, gerente de…".
PERSONA_POSTROL_RE = re.compile(
    r"\b(" + _TP + r"(?:\s+(?:de|del|la|los|las|van|von|da|di)){0,2}"
    r"(?:\s+" + _TP + r"){1,3})"
    r"\s*,\s*(?:ex\s?)?(?:" + ROLES_PERSONA + r")\b",
    re.UNICODE,
)

# Nombre seguido de RUT: la contigüidad con un identificador tributario es una
# señal fuerte de entidad, incluso sin cargo ni verbo procesal alrededor.
PERSONA_ANTES_DE_RUT_RE = re.compile(
    r"\b(" + _TP + r"(?:\s+(?:de|del|la|los|las|van|von|da|di)){0,2}"
    r"(?:\s+" + _TP + r"){1,3})"
    r"\s*,?\s*(?:[Rr]\.?[Uu]\.?[Tt]\.?|[Cc]\.?[Ii]\.?|[Rr]ol [Úú]nico [Tt]ributario)"
    r"\s*(?:[Nn]°)?\s*:?\s*\d",
    re.UNICODE,
)

# Persona objeto de acción procesal: "formalizó a Juan Pérez".
PERSONA_ACCION_RE = re.compile(
    r"(?i:\b(?:formaliz(?:ó|o|aron)|imput(?:ó|o|aron)|conden(?:ó|o|aron)|"
    r"acus(?:ó|o|aron)|detuv(?:o|ieron)|investiga(?:n|ron)?|indag(?:a|an|ó|o)|"
    r"querell(?:ó|o|aron)\s+contra|absolvi(?:ó|o|eron)|sentenci(?:ó|o|aron))"
    r"\s+a\s+)(" + _TP + r"(?:\s+(?:de|del|la|los|las|van|von|da|di)){0,2}"
    r"(?:\s+" + _TP + r"){1,3})",
    re.UNICODE,
)

MONTO_RE = re.compile(
    r"(?<!\w)(?:US\$|USD|CLP|UF|UTM|\$|€|£)\s?\d[\d.\s]*(?:,\d+)?"
    r"(?:\s?(?:millones?|mil(?:lones)?|MM|billones?))?",
    re.IGNORECASE,
)

CRIPTO_RE = re.compile(
    r"\b(?:bitcoin|btc|ethereum|ether|eth|tether|usdt|usdc|solana|monero|xmr|"
    r"criptoactivos?|criptomonedas?|stablecoins?|wallets?|billeteras?\s+digitales?|"
    r"exchange(?:s)?\s+de\s+cripto|activos?\s+virtuales?)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 7. Clasificación de una cadena candidata
# ---------------------------------------------------------------------------

def _tokens_significativos(nombre: str) -> list[str]:
    return [t for t in norm(nombre).split() if t]


def _proporcion_capitalizada(nombre: str) -> float:
    tokens = [t for t in nombre.split() if t]
    if not tokens:
        return 0.0
    validos = 0
    for tok in tokens:
        limpio = tok.strip(".,;:()'\"")
        if not limpio:
            continue
        if norm(limpio) in PARTICULAS_APELLIDO:
            validos += 1
        elif limpio[0].isupper():
            validos += 1
    return validos / len(tokens)


def canoniza_denominacion(nombre: Any) -> tuple[str, list[str]]:
    """Normaliza la forma de la denominación y devuelve las señales aplicadas.

    Elimina determinantes y colectivos genéricos en minúscula al inicio
    ("la sociedad Agrícola El Peumo Ltda." -> "Agrícola El Peumo Ltda.") y
    capitaliza la inicial cuando el núcleo institucional viene en minúscula
    ("seremi de Hacienda" -> "Seremi de Hacienda"), en lugar de recortarlo.
    """
    senales: list[str] = []
    partes = limpia(nombre).split()
    recorte = 0
    while len(partes) > 1 and norm(partes[0]) in PREFIJOS_GENERICOS:
        partes.pop(0)
        recorte += 1
    if recorte:
        senales.append(f"prefijo_generico_removido:{recorte}")
    if partes and partes[0][:1].islower():
        partes[0] = partes[0][:1].upper() + partes[0][1:]
        senales.append("inicial_normalizada")
    return " ".join(partes), senales


# Un punto seguido de espacio y mayúscula cierra la oración, salvo que forme
# parte de una abreviatura de una sola letra ("S.A.", "E.I.R.L.").
_FIN_ORACION = re.compile(r"(?<![A-ZÁÉÍÓÚÑ])\.\s+(?=[A-ZÁÉÍÓÚÑ])")


# Coordinación que une dos entidades distintas, no una denominación compuesta.
# Se corta ante "y la Policía…" (determinante), "y PDI" (sigla) o "y Servicio…"
# (núcleo institucional), pero se conserva "Electricidad y Combustibles", que
# forma parte del nombre del órgano.
_ACRONIMO = r"[A-ZÁÉÍÓÚÑ]{2,}"
_NUCLEOS_TRAS_Y = "|".join(
    _flexible(x.split()[0]) for x in sorted(
        NUCLEOS_ORGANISMO_PUBLICO | NUCLEOS_TRIBUNAL | NUCLEOS_FINANCIERA,
        key=len, reverse=True,
    )
)
_COORDINA_ENTIDADES = re.compile(
    r"\s+[ye]\s+(?:"
    r"(?:la|el|los|las)\s"
    r"|" + _ACRONIMO + r"\b"
    r"|(?i:" + _NUCLEOS_TRAS_Y + r")\b"
    r")"
)


def recorta_span(texto: str, inicio: int, fin: int) -> tuple[int, int]:
    """Acorta un span para que no cruce el fin de oración ni pase del sufijo.

    Corrige capturas como ``"Comercializadora Andes Sur SpA. El"`` o
    ``"Consultora Gestión Local EIRL y por Servicios"``, en las que la regex
    seguía consumiendo tokens capitalizados de la oración siguiente o de una
    enumeración de razones sociales distintas.
    """
    fragmento = texto[inicio:fin]

    corte_oracion = _FIN_ORACION.search(fragmento)
    if corte_oracion:
        fragmento = fragmento[:corte_oracion.start() + 1]

    corte_coord = _COORDINA_ENTIDADES.search(fragmento)
    if corte_coord:
        fragmento = fragmento[:corte_coord.start()]

    for m in SUFIJO_RE.finditer(fragmento):
        # El primer sufijo societario cierra la razón social.
        fragmento = fragmento[:m.end()]
        break

    return inicio, inicio + len(fragmento.rstrip())


def clasifica_cadena(
    nombre: str,
    tipo_sugerido: str = "",
    contexto_izq: str = "",
    contexto_der: str = "",
) -> dict[str, Any]:
    """Clasifica una cadena en tipo, naturaleza y score auditable.

    Devuelve ``{"tipo", "naturaleza", "score", "senales", "descartar", "motivo"}``.
    El score es un valor 0..1 que combina señales léxicas y contextuales; no es
    una probabilidad calibrada, sino un ordenador de prioridad para revisión
    humana.
    """
    nombre = limpia(nombre)
    senales: list[str] = []
    tipo_sugerido = str(tipo_sugerido or "").upper()

    if not nombre:
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.0,
                "senales": ["cadena_vacia"], "descartar": True, "motivo": "cadena_vacia"}

    # Una cadena que cruza el fin de una oración es un span mal delimitado.
    if re.search(r"[.!?]\s+[A-ZÁÉÍÓÚÑ]", nombre) and not SUFIJO_RE.search(nombre):
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.0,
                "senales": ["span_cruza_oracion"], "descartar": True,
                "motivo": "span_cruza_oracion"}

    nombre, senales_canon = canoniza_denominacion(nombre)
    senales.extend(senales_canon)
    if not nombre:
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.0,
                "senales": senales + ["solo_minusculas"], "descartar": True,
                "motivo": "solo_minusculas"}

    n = norm(nombre)
    toks = _tokens_significativos(nombre)

    # --- Filtros duros de ruido -------------------------------------------
    if len(n) < 3:
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.0,
                "senales": senales + ["muy_corto"], "descartar": True, "motivo": "muy_corto"}
    if all(t in NO_NOMBRE for t in toks):
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.0,
                "senales": senales + ["solo_palabras_vacias"], "descartar": True,
                "motivo": "solo_palabras_vacias"}

    # Los topónimos se resuelven con el catálogo geográfico del módulo llamador.
    # El atajo se aplica solo si la cadena no exhibe evidencia societaria: el
    # modelo estadístico etiqueta como LOC denominaciones del tipo "Fundación
    # Buen Vivir", y aceptarlas sin examen las sacaba de la nómina de personas
    # jurídicas.
    if tipo_sugerido in ("LOC", "GPE", "FAC", "LUGAR"):
        sin_evidencia_juridica = (
            not SUFIJO_RE.search(nombre)
            and not any(
                _es_nucleo(n, nucleos) for nucleos in (
                    NUCLEOS_TRIBUNAL, NUCLEOS_FINANCIERA, NUCLEOS_ORGANISMO_PUBLICO,
                    NUCLEOS_SIN_FINES_LUCRO, NUCLEOS_EMPRESA,
                )
            )
        )
        if sin_evidencia_juridica:
            return {"tipo": "LUGAR", "naturaleza": "NO_APLICA", "score": 0.7,
                    "senales": senales + ["toponimo"], "descartar": False,
                    "motivo": "toponimo"}
        senales.append("etiqueta_geografica_descartada_por_nucleo_juridico")

    # --- Persona jurídica por sufijo societario ---------------------------
    m_sufijo = SUFIJO_RE.search(nombre)
    if m_sufijo:
        senales.append(f"sufijo_societario:{m_sufijo.group(0).strip()}")
        tipo = "EMPRESA"
        if _es_nucleo(n, NUCLEOS_FINANCIERA):
            tipo = "INSTITUCION_FINANCIERA"
            senales.append("nucleo_financiero")
        elif _es_nucleo(n, NUCLEOS_SIN_FINES_LUCRO):
            tipo = "ENTIDAD_SIN_FINES_DE_LUCRO"
            senales.append("nucleo_sin_fines_de_lucro")
        return {"tipo": tipo, "naturaleza": "PERSONA_JURIDICA",
                "score": round(min(0.97, 0.85 + 0.03 * len(toks)), 3),
                "senales": senales, "descartar": False, "motivo": "sufijo_societario"}

    # --- Persona jurídica por núcleo -------------------------------------
    for nucleos, tipo, etiqueta in (
        (NUCLEOS_TRIBUNAL, "TRIBUNAL", "nucleo_tribunal"),
        (NUCLEOS_FINANCIERA, "INSTITUCION_FINANCIERA", "nucleo_financiero"),
        (NUCLEOS_ORGANISMO_PUBLICO, "ORGANISMO_PUBLICO", "nucleo_organismo_publico"),
        (NUCLEOS_SIN_FINES_LUCRO, "ENTIDAD_SIN_FINES_DE_LUCRO", "nucleo_sin_fines_de_lucro"),
        (NUCLEOS_PATRIMONIO, "ORGANIZACION", "nucleo_patrimonio_afectacion"),
        (NUCLEOS_EMPRESA, "EMPRESA", "nucleo_empresa"),
    ):
        nucleo = _es_nucleo(n, nucleos)
        if nucleo:
            senales.append(f"{etiqueta}:{nucleo}")
            # Un núcleo aislado sin especificación no identifica a nadie.
            if n == nucleo:
                return {"tipo": tipo, "naturaleza": "PERSONA_JURIDICA", "score": 0.25,
                        "senales": senales + ["nucleo_sin_denominacion"],
                        "descartar": True, "motivo": "nucleo_generico_sin_denominacion"}
            score = 0.78 if tipo != "EMPRESA" else 0.72
            return {"tipo": tipo, "naturaleza": "PERSONA_JURIDICA", "score": score,
                    "senales": senales, "descartar": False, "motivo": etiqueta}

    # --- Persona jurídica por marcador terminal ---------------------------
    # "Sartor Finance Group" o "Andes Capital Partners" no llevan sufijo legal
    # chileno, pero el token final delata una estructura societaria.
    if len(toks) >= 2 and toks[-1] in TERMINALES_JURIDICOS:
        senales.append(f"terminal_juridico:{toks[-1]}")
        tipo = "EMPRESA"
        if toks[-1] in {"bank", "finance", "financial", "securities", "fund",
                        "funds", "asset", "assets", "advisors", "advisory"}:
            tipo = "INSTITUCION_FINANCIERA"
        return {"tipo": tipo, "naturaleza": "PERSONA_JURIDICA", "score": 0.70,
                "senales": senales, "descartar": False, "motivo": "terminal_juridico"}

    # --- Descartes específicos de persona --------------------------------
    # "Caso Factop", "Operación Frontera Norte" nombran hechos, no entidades.
    if toks and toks[0] in ENCABEZADOS_EVENTO:
        return {"tipo": "OTRO", "naturaleza": "NO_APLICA", "score": 0.2,
                "senales": senales + [f"denominacion_de_evento:{toks[0]}"],
                "descartar": True, "motivo": "denominacion_de_evento"}

    if toks and toks[0] in ENCABEZADOS_NO_PERSONA:
        senales.append(f"encabezado_no_persona:{toks[0]}")
        return {"tipo": "ORGANIZACION", "naturaleza": "PERSONA_JURIDICA", "score": 0.45,
                "senales": senales, "descartar": False, "motivo": "encabezado_no_persona"}

    if re.search(r"\d", nombre):
        senales.append("contiene_digitos")
        return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": 0.1,
                "senales": senales, "descartar": True, "motivo": "contiene_digitos"}

    # --- Desambiguación geográfica ----------------------------------------
    # Una comuna con forma de nombre propio ("San Ramón", "Pedro Aguirre
    # Cerda", "Padre Hurtado") no puede convertirse en una persona natural de
    # la nómina: sería nombrar a alguien que no aparece en la noticia.
    if GEOGRAFIA_DISPONIBLE:
        geo = GEO.evalua_geografia(nombre, contexto_izq or "")
        senales.extend(str(x) for x in geo["senales"])
        if geo["es_lugar"]:
            info = geo.get("info") or {}
            resultado = {
                "tipo": "LUGAR", "naturaleza": "NO_APLICA",
                "score": 0.95 if geo["fuerza"] == "definitiva" else 0.85,
                "senales": senales, "descartar": False,
                "motivo": "toponimo_chileno",
            }
            if info:
                resultado["nombre_geografico"] = info.get("canonico")
                resultado["nivel_geografico"] = info.get("nivel")
                if info.get("region"):
                    resultado["region"] = info["region"]
            return resultado

    # --- Evaluación de persona natural ------------------------------------
    score = 0.0
    n_tokens = len(toks)
    contenido = [t for t in toks if t not in PARTICULAS_APELLIDO]

    if toks[0] in NO_NOMBRE:
        senales.append(f"inicio_palabra_vacia:{toks[0]}")
        score -= 0.60
    if any(t in NO_NOMBRE for t in contenido):
        senales.append("contiene_palabra_vacia")
        score -= 0.25

    if 2 <= len(contenido) <= 5:
        score += 0.35
        senales.append(f"longitud_antroponimica:{len(contenido)}")
    elif len(contenido) == 1:
        # Un solo token rara vez identifica: "Juan" o "Pizarro" por sí solos
        # producen nodos ambiguos que contaminan el grafo.
        score -= 0.15
        senales.append("token_unico_ambiguo")
    else:
        score -= 0.20
        senales.append("longitud_excesiva")

    cap = _proporcion_capitalizada(nombre)
    if cap >= 0.99:
        score += 0.15
        senales.append("todos_los_tokens_capitalizados")
    elif cap >= 0.8:
        score += 0.05
    else:
        score -= 0.25
        senales.append("capitalizacion_irregular")

    if contenido and contenido[0] in NOMBRES_PILA:
        score += 0.30
        senales.append(f"nombre_de_pila_conocido:{contenido[0]}")
    if len(contenido) >= 2 and contenido[1] in NOMBRES_PILA:
        score += 0.10
        senales.append("segundo_nombre_de_pila")

    tiene_pila = bool(contenido) and contenido[0] in NOMBRES_PILA
    tiene_apellido = any(t in APELLIDOS_FRECUENTES for t in contenido[1:])
    if tiene_apellido:
        score += 0.20
        senales.append("apellido_frecuente_en_chile")
    if tiene_pila and tiene_apellido:
        score += 0.10
        senales.append("estructura_nombre_apellido_completa")
    if not tiene_pila and not tiene_apellido:
        # Sin nombre de pila ni apellido reconocibles, la cadena capitalizada
        # puede ser cualquier cosa: marca, topónimo menor, título. Se exige
        # entonces evidencia contextual explícita para admitirla como persona.
        score -= 0.20
        senales.append("sin_evidencia_antroponimica_lexica")

    if TRATAMIENTOS.search(contexto_izq or ""):
        score += 0.30
        senales.append("tratamiento_previo")
    if CONTEXTO_PERSONA_IZQ.search(contexto_izq or ""):
        score += 0.25
        senales.append("cargo_o_calidad_previa")
    if VERBOS_ACCION_PERSONA.search(contexto_izq or ""):
        score += 0.25
        senales.append("verbo_procesal_previo")
    if CONTEXTO_PERSONA_DER.match(contexto_der or ""):
        score += 0.20
        senales.append("cargo_o_calidad_posterior")

    if tipo_sugerido in ("PER", "PERSON", "PERSONA"):
        score += 0.20
        senales.append("modelo_estadistico_persona")
    elif tipo_sugerido in ("ORG", "EMPRESA", "ORGANIZACION"):
        score -= 0.10
        senales.append("modelo_estadistico_organizacion")

    score = max(0.0, min(1.0, score))

    if score >= 0.55:
        return {"tipo": "PERSONA", "naturaleza": "PERSONA_NATURAL", "score": round(score, 3),
                "senales": senales, "descartar": False, "motivo": "antroponimo"}
    if score >= 0.35:
        return {"tipo": "PERSONA", "naturaleza": "PERSONA_NATURAL", "score": round(score, 3),
                "senales": senales + ["requiere_validacion_humana"], "descartar": False,
                "motivo": "antroponimo_debil"}

    if tipo_sugerido in ("ORG", "ORGANIZACION", "EMPRESA"):
        return {"tipo": "ORGANIZACION", "naturaleza": "PERSONA_JURIDICA",
                "score": round(max(score, 0.4), 3), "senales": senales,
                "descartar": False, "motivo": "organizacion_no_tipificada"}

    return {"tipo": "OTRO", "naturaleza": "INDETERMINADA", "score": round(score, 3),
            "senales": senales, "descartar": True, "motivo": "score_insuficiente"}


# ---------------------------------------------------------------------------
# 8. Extracción por reglas
# ---------------------------------------------------------------------------

VENTANA_CONTEXTO = 90


def extrae_reglas(texto: str, incluir_rut: bool = True) -> list[dict[str, Any]]:
    """Extrae candidatos mediante reglas, con contexto y clasificación."""
    hallazgos: list[dict[str, Any]] = []
    vistos: set[tuple[int, int, str]] = set()

    def agrega(inicio: int, fin: int, bruto: str, origen: str, tipo_hint: str = "") -> None:
        inicio, fin = recorta_span(texto, inicio, fin)
        nombre, _ = canoniza_denominacion(texto[inicio:fin])
        if not nombre:
            return
        izq = texto[max(0, inicio - VENTANA_CONTEXTO):inicio]
        der = texto[fin:fin + VENTANA_CONTEXTO]
        veredicto = clasifica_cadena(nombre, tipo_hint, izq, der)
        if veredicto["descartar"]:
            return
        clave = (inicio, fin, veredicto["tipo"])
        if clave in vistos:
            return
        vistos.add(clave)
        hallazgos.append({
            "texto": nombre,
            "label": veredicto["tipo"],
            "naturaleza": veredicto["naturaleza"],
            "inicio": inicio,
            "fin": fin,
            "origen": origen,
            "score": veredicto["score"],
            "senales": veredicto["senales"],
            "motivo": veredicto["motivo"],
        })

    for m in RAZON_SOCIAL_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_razon_social", "EMPRESA")
    for m in RAZON_SOCIAL_NUCLEO_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_nucleo_societario", "EMPRESA")
    for m in ORGANISMO_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_organismo", "ORGANIZACION")
    for m in PERSONA_PRECEDIDA_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_persona_cargo_previo", "PERSONA")
    for m in PERSONA_APOSICION_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_persona_aposicion_cargo", "PERSONA")
    for m in PERSONA_POSTROL_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_persona_cargo_posterior", "PERSONA")
    for m in PERSONA_ACCION_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_persona_accion_procesal", "PERSONA")
    for m in PERSONA_ANTES_DE_RUT_RE.finditer(texto):
        agrega(m.start(1), m.end(1), m.group(1), "regla_nombre_contiguo_a_rut")

    for m in MONTO_RE.finditer(texto):
        hallazgos.append({
            "texto": limpia(m.group(0)), "label": "MONTO", "naturaleza": "NO_APLICA",
            "inicio": m.start(), "fin": m.end(), "origen": "regla_monto",
            "score": 0.9, "senales": ["patron_monetario"], "motivo": "monto",
        })
    for m in CRIPTO_RE.finditer(texto):
        hallazgos.append({
            "texto": limpia(m.group(0)), "label": "CRIPTOACTIVO", "naturaleza": "NO_APLICA",
            "inicio": m.start(), "fin": m.end(), "origen": "regla_cripto",
            "score": 0.85, "senales": ["patron_criptoactivo"], "motivo": "criptoactivo",
        })

    if incluir_rut:
        for m in RUT_RE.finditer(texto):
            info = valida_rut(m.group(0))
            if not info.get("valido"):
                continue
            hallazgos.append({
                "texto": info["rut"], "label": "RUT",
                "naturaleza": info.get("naturaleza_indicativa", "INDETERMINADA"),
                "inicio": m.start(), "fin": m.end(), "origen": "regla_rut_modulo11",
                "score": 0.99, "senales": ["dv_valido", f"rango:{info['naturaleza_indicativa']}"],
                "motivo": "rut_valido", "rut": info,
            })
    return hallazgos


def rut_por_proximidad(texto: str, menciones: list[dict[str, Any]], ventana: int = 120) -> None:
    """Asocia RUT válidos a la entidad más cercana en el texto (in-place)."""
    def _es_rut(m: dict[str, Any]) -> bool:
        return str(m.get("label") or m.get("tipo") or "").upper() == "RUT"

    ruts = [m for m in menciones if _es_rut(m)]
    # El propio RUT declara naturaleza según su rango numérico; excluirlo evita
    # que se asocie consigo mismo a distancia cero.
    otras = [
        m for m in menciones
        if not _es_rut(m)
        and m.get("naturaleza") in ("PERSONA_NATURAL", "PERSONA_JURIDICA")
    ]
    for r in ruts:
        mejor, dist_mejor = None, ventana + 1
        for o in otras:
            dist = min(
                abs(int(r["inicio"]) - int(o["fin"])),
                abs(int(o["inicio"]) - int(r["fin"])),
            )
            if dist < dist_mejor:
                mejor, dist_mejor = o, dist
        if mejor is not None and dist_mejor <= ventana:
            mejor.setdefault("ruts", []).append({
                "rut": r.get("texto"),
                "distancia_caracteres": dist_mejor,
                "naturaleza_indicativa": r.get("naturaleza"),
                "confianza": "alta" if dist_mejor <= 40 else "media",
            })


# ---------------------------------------------------------------------------
# 9. Resolución de solapamientos
# ---------------------------------------------------------------------------

PRIORIDAD_ARBITRAJE = {
    "RUT": 100,
    "EMPRESA": 90,
    "INSTITUCION_FINANCIERA": 89,
    "TRIBUNAL": 88,
    "ORGANISMO_PUBLICO": 87,
    "ENTIDAD_SIN_FINES_DE_LUCRO": 86,
    "PERSONA": 80,
    "ORGANIZACION": 70,
    "LUGAR": 50,
    "CRIPTOACTIVO": 40,
    "MONTO": 30,
    "FECHA": 10,
    "OTRO": 1,
}


def depura_candidatos(candidatos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resuelve solapamientos entre candidatos de cualquier tipo.

    Corrige el defecto por el cual una misma cadena ("Factop SpA") podía quedar
    registrada a la vez como PERSONA y como EMPRESA, generando dos nodos.
    Criterio: ante spans que se solapan, gana el de mayor cobertura textual; a
    igual cobertura, el de mayor score; a igual score, el de mayor prioridad de
    tipo. MONTO, RUT y CRIPTOACTIVO no compiten con nombres.
    """
    def clave_orden(c: dict[str, Any]) -> tuple:
        largo = int(c.get("fin", 0)) - int(c.get("inicio", 0))
        return (
            -largo,
            -float(c.get("score", 0.5)),
            -PRIORIDAD_ARBITRAJE.get(str(c.get("label", "OTRO")).upper(), 0),
        )

    no_compiten = {"MONTO", "RUT", "CRIPTOACTIVO", "FECHA"}
    aceptados: list[dict[str, Any]] = []
    pasan_directo = [c for c in candidatos if str(c.get("label", "")).upper() in no_compiten]
    competidores = [c for c in candidatos if str(c.get("label", "")).upper() not in no_compiten]

    for cand in sorted(competidores, key=clave_orden):
        ci, cf = int(cand.get("inicio", 0)), int(cand.get("fin", 0))
        conflicto = False
        for prev in aceptados:
            pi, pf = int(prev.get("inicio", 0)), int(prev.get("fin", 0))
            if ci < pf and cf > pi:
                conflicto = True
                # Deja traza del span descartado para auditoría.
                prev.setdefault("spans_absorbidos", []).append({
                    "texto": cand.get("texto"),
                    "tipo": cand.get("label"),
                    "origen": cand.get("origen"),
                    "score": cand.get("score"),
                })
                break
        if not conflicto:
            aceptados.append(cand)

    return sorted(aceptados + pasan_directo, key=lambda c: int(c.get("inicio", 0)))


# ---------------------------------------------------------------------------
# 10. Correferencia de nombres
# ---------------------------------------------------------------------------

def _base_societaria(nombre: str) -> str:
    """Denominación sin sufijo societario ni núcleo genérico inicial."""
    sin_sufijo = SUFIJO_RE.sub(" ", nombre)
    return norm(sin_sufijo)


def _similitud(a: str, b: str) -> float:
    if _fuzz is not None:
        return float(_fuzz.token_sort_ratio(a, b)) / 100.0
    if a == b:
        return 1.0
    corta, larga = sorted([a, b], key=len)
    return 1.0 if corta and corta in larga else 0.0


def son_correferentes_persona(a: str, b: str) -> tuple[bool, str]:
    """Decide si dos antropónimos designan a la misma persona.

    Regla conservadora: exige inclusión de tokens y al menos dos tokens
    compartidos, de modo que "Marcela Ortiz" y "Marcela Ortiz Vega" se unifican,
    pero "Ariel Sauer" y "Daniel Sauer" no.
    """
    ta = [t for t in norm(a).split() if t not in PARTICULAS_APELLIDO]
    tb = [t for t in norm(b).split() if t not in PARTICULAS_APELLIDO]
    if not ta or not tb:
        return False, ""
    sa, sb = set(ta), set(tb)
    if sa == sb:
        return True, "tokens_identicos"
    comunes = sa & sb
    if len(comunes) >= 2 and (sa <= sb or sb <= sa):
        return True, f"inclusion_tokens:{len(comunes)}"
    # Variante ortográfica: mismo número de tokens y alta similitud.
    if len(ta) == len(tb) and len(ta) >= 2:
        sim = _similitud(" ".join(ta), " ".join(tb))
        if sim >= 0.93:
            return True, f"similitud_ortografica:{sim:.2f}"
    return False, ""


# Tipos en los que la prensa alterna forma corta y forma completa del mismo
# órgano ("Corte de Apelaciones" / "Corte de Apelaciones de Antofagasta").
TIPOS_ADMITEN_FORMA_CORTA = {
    "ORGANISMO_PUBLICO", "TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO",
}


def son_correferentes_juridica(a: str, b: str, tipo: str = "") -> tuple[bool, str]:
    """Unifica razones sociales solo ante identidad de denominación.

    Es deliberadamente estricta para sociedades: "Sartor Finance Group" y
    "Sartor Administradora General de Fondos S.A." son entidades distintas
    aunque compartan controlador, y fusionarlas induciría un error de
    identificación en la nómina.

    Para órganos públicos y tribunales sí se admite la inclusión por prefijo,
    porque la prensa alterna la forma corta y la completa del mismo órgano.
    """
    ba, bb = _base_societaria(a), _base_societaria(b)
    if not ba or not bb:
        return False, ""
    if ba == bb:
        return True, "denominacion_identica_sin_sufijo"

    if str(tipo or "").upper() in TIPOS_ADMITEN_FORMA_CORTA:
        ta, tb = ba.split(), bb.split()
        corta, larga = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
        if len(corta) >= 2 and larga[:len(corta)] == corta:
            return True, f"forma_corta_de_organo:{len(corta)}"

    sim = _similitud(ba, bb)
    if sim >= 0.97 and abs(len(ba) - len(bb)) <= 3:
        return True, f"similitud_ortografica:{sim:.2f}"
    return False, ""


def agrupa_correferencias(entidades: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Agrupa entidades correferentes y elige la forma canónica más completa.

    Devuelve ``{id_original: {"canonico", "id_canonico", "motivo"}}``.
    """
    por_naturaleza: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ent in entidades:
        nat = ent.get("naturaleza") or naturaleza_de(ent.get("tipo"))
        if nat in ("PERSONA_NATURAL", "PERSONA_JURIDICA"):
            por_naturaleza[nat].append(ent)

    mapa: dict[str, dict[str, Any]] = {}
    for nat, grupo in por_naturaleza.items():
        if nat == "PERSONA_NATURAL":
            def comparador(x: str, y: str, _t: str = "") -> tuple[bool, str]:
                return son_correferentes_persona(x, y)
        else:
            comparador = son_correferentes_juridica
        # Ordena de la forma más larga a la más corta: la más específica lidera.
        grupo = sorted(
            grupo,
            key=lambda e: (-len(str(e.get("nombre_canonico") or "")), str(e.get("id") or "")),
        )
        lideres: list[tuple[dict[str, Any], list[tuple[dict[str, Any], str]]]] = []
        for ent in grupo:
            nombre = str(ent.get("nombre_canonico") or "")
            tipo = str(ent.get("tipo") or "")
            asignado = False
            for lider, miembros in lideres:
                # Solo se unifican tipos compatibles dentro de la misma naturaleza.
                if nat == "PERSONA_JURIDICA" and tipo != str(lider.get("tipo") or ""):
                    continue
                ok, motivo = comparador(
                    str(lider.get("nombre_canonico") or ""), nombre, tipo
                )
                if ok:
                    miembros.append((ent, motivo))
                    asignado = True
                    break
            if not asignado:
                lideres.append((ent, []))

        for lider, miembros in lideres:
            for ent, motivo in miembros:
                mapa[str(ent.get("id"))] = {
                    "canonico": lider.get("nombre_canonico"),
                    "id_canonico": lider.get("id"),
                    "motivo": motivo,
                    "variante_absorbida": ent.get("nombre_canonico"),
                }
    return mapa


# ---------------------------------------------------------------------------
# 11. Léxico adicional para fusionar con entidades_config.json
# ---------------------------------------------------------------------------

ALIASES_EXTRA: list[dict[str, Any]] = [
    {"canonico": "Banco de Chile", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Banco de Chile", "Banco Edwards"]},
    {"canonico": "Banco Santander Chile", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Santander Chile", "Banco Santander", "Santander"]},
    {"canonico": "Banco de Crédito e Inversiones", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["BCI", "Banco BCI", "Banco de Credito e Inversiones"]},
    {"canonico": "Scotiabank Chile", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Scotiabank", "Scotiabank Chile", "Banco Scotiabank"]},
    {"canonico": "Itaú Chile", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Itaú", "Itau", "Banco Itaú", "Banco Itau"]},
    {"canonico": "Banco Security", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Banco Security", "Grupo Security"]},
    {"canonico": "Banco Falabella", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Banco Falabella"]},
    {"canonico": "Banco Consorcio", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Banco Consorcio"]},
    {"canonico": "Banco Internacional", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Banco Internacional"]},
    {"canonico": "Banco BICE", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["BICE", "Banco BICE"]},
    {"canonico": "Coopeuch", "tipo": "INSTITUCION_FINANCIERA",
     "variantes": ["Coopeuch"]},
    {"canonico": "Banco Central de Chile", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Banco Central", "BCCh", "Banco Central de Chile"]},
    {"canonico": "Consejo de Defensa del Estado", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["CDE", "Consejo de Defensa del Estado"]},
    {"canonico": "Contraloría General de la República", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Contraloría", "Contraloria", "CGR",
                   "Contraloría General de la República"]},
    {"canonico": "Servicio de Registro Civil e Identificación", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Registro Civil", "SRCeI"]},
    {"canonico": "Gendarmería de Chile", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Gendarmería", "Gendarmeria", "Gendarmería de Chile"]},
    {"canonico": "Corte Suprema", "tipo": "TRIBUNAL",
     "variantes": ["Corte Suprema", "Excma. Corte Suprema"]},
    {"canonico": "Ministerio de Hacienda", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Ministerio de Hacienda", "Hacienda"]},
    {"canonico": "Superintendencia de Pensiones", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Superintendencia de Pensiones", "SP"]},
    {"canonico": "Instituto de Previsión Social", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["IPS", "Instituto de Previsión Social"]},
    {"canonico": "Dirección del Trabajo", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["Dirección del Trabajo", "Direccion del Trabajo", "DT"]},
    {"canonico": "Agencia Nacional de Inteligencia", "tipo": "ORGANISMO_PUBLICO",
     "variantes": ["ANI", "Agencia Nacional de Inteligencia"]},
]

ROLES_EXTRA: list[dict[str, Any]] = [
    {"rol": "beneficiario final mencionado", "tipos": ["PERSONA"],
     "patron": r"beneficiari[oa]\s+final"},
    {"rol": "persona expuesta políticamente mencionada", "tipos": ["PERSONA"],
     "patron": r"\bPEP\b|persona\s+expuesta\s+pol[ií]ticamente"},
    {"rol": "controlador o dueño mencionado", "tipos": ["PERSONA"],
     "patron": r"controlador(?:a)?|due[ñn][oa]\s+de|propietari[oa]\s+de"},
    {"rol": "testaferro mencionado", "tipos": ["PERSONA"],
     "patron": r"testaferro|palo\s+blanco|prestanombre"},
    {"rol": "sociedad de papel mencionada", "tipos": ["EMPRESA"],
     "patron": r"sociedad(?:es)?\s+de\s+papel|empresa\s+fantasma|sociedad\s+fachada"},
    {"rol": "sujeto obligado a reportar", "tipos": ["EMPRESA", "INSTITUCION_FINANCIERA"],
     "patron": r"sujeto\s+obligado|deber\s+de\s+reportar|reporte\s+de\s+operaci[oó]n\s+sospechosa|\bROS\b"},
]

RELACIONES_EXTRA: list[dict[str, Any]] = [
    {"tipo": "BENEFICIARIO_FINAL_DE", "etiqueta": "beneficiario final de",
     "patron": r"beneficiari[oa]\s+final\s+(?:de|del)", "ambito": "entre",
     "origen_tipos": ["PERSONA"],
     "destino_tipos": ["EMPRESA", "ORGANIZACION", "INSTITUCION_FINANCIERA"],
     "dirigida": True, "confianza": "alta", "max_distancia_destino": 60},
    {"tipo": "CONTROLA_A", "etiqueta": "controla a",
     "patron": r"controla(?:dor(?:a)?)?\s+(?:de|del)?|due[ñn][oa]\s+de|propietari[oa]\s+de",
     "ambito": "entre", "origen_tipos": ["PERSONA", "EMPRESA"],
     "destino_tipos": ["EMPRESA", "ORGANIZACION"],
     "dirigida": True, "confianza": "media", "max_distancia_destino": 60},
    {"tipo": "SANCIONA_A", "etiqueta": "sanciona a",
     "patron": r"sancion(?:ó|o|aron|a)\s+a|multó\s+a|multo\s+a|formul[óo]\s+cargos\s+(?:a|contra)",
     "ambito": "entre", "origen_tipos": ["ORGANISMO_PUBLICO", "TRIBUNAL"],
     "destino_tipos": ["PERSONA", "EMPRESA", "INSTITUCION_FINANCIERA", "ORGANIZACION"],
     "dirigida": True, "confianza": "alta", "max_distancia_destino": 60},
    {"tipo": "REPORTA_A", "etiqueta": "reporta a",
     "patron": r"report[óo]\s+(?:a|al)|remiti[óo]\s+(?:a|al)|inform[óo]\s+(?:a|al)",
     "ambito": "entre",
     "origen_tipos": ["EMPRESA", "INSTITUCION_FINANCIERA", "ORGANISMO_PUBLICO"],
     "destino_tipos": ["ORGANISMO_PUBLICO"],
     "dirigida": True, "confianza": "media", "max_distancia_destino": 60},
    {"tipo": "ABSUELVE_A", "etiqueta": "absuelve a",
     "patron": r"absolvi(?:ó|o|eron)\s+a|sobrese(?:yó|yo|yeron)\s+a",
     "ambito": "entre", "origen_tipos": ["TRIBUNAL", "ORGANISMO_PUBLICO"],
     "destino_tipos": ["PERSONA", "EMPRESA"],
     "dirigida": True, "confianza": "alta", "max_distancia_destino": 60},
    {"tipo": "DEFIENDE_A", "etiqueta": "defiende a",
     "patron": r"defensa\s+(?:de|del)|abogad[oa]\s+(?:de|del)|represent[óo]\s+a",
     "ambito": "entre", "origen_tipos": ["PERSONA"],
     "destino_tipos": ["PERSONA", "EMPRESA"],
     "dirigida": True, "confianza": "media", "max_distancia_destino": 60},
]


# Los tipos nuevos deben poder participar en las reglas relacionales ya
# existentes. Sin esto, un fallo de la Corte de Apelaciones no generaba relación
# CONDENA_A, porque la regla solo admitía ORGANISMO_PUBLICO como origen.
AMPLIACION_TIPOS_RELACION: dict[str, dict[str, list[str]]] = {
    "INVESTIGA_A": {"origen_tipos": ["TRIBUNAL"],
                    "destino_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "FORMALIZA_A": {"origen_tipos": ["TRIBUNAL"],
                    "destino_tipos": ["INSTITUCION_FINANCIERA", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "ACUSA_A": {"origen_tipos": ["TRIBUNAL"],
                "destino_tipos": ["INSTITUCION_FINANCIERA", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "CONDENA_A": {"origen_tipos": ["TRIBUNAL"],
                  "destino_tipos": ["INSTITUCION_FINANCIERA", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "QUERELLA_CONTRA": {"origen_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO",
                                         "INSTITUCION_FINANCIERA"],
                        "destino_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "TRANSACCION_ENTRE": {"origen_tipos": ["ENTIDAD_SIN_FINES_DE_LUCRO"],
                          "destino_tipos": ["ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "VINCULADO_CON": {"origen_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO"],
                      "destino_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "REPRESENTA_A": {"destino_tipos": ["ENTIDAD_SIN_FINES_DE_LUCRO", "ORGANISMO_PUBLICO"]},
    "EJECUTIVO_DE": {"destino_tipos": ["ENTIDAD_SIN_FINES_DE_LUCRO", "ORGANISMO_PUBLICO"]},
    "SOCIO_DE": {"destino_tipos": ["ENTIDAD_SIN_FINES_DE_LUCRO"]},
    "UBICADA_EN": {"origen_tipos": ["TRIBUNAL", "ENTIDAD_SIN_FINES_DE_LUCRO",
                                    "ORGANISMO_PUBLICO"]},
}


def amplia_tipos_relaciones(relaciones: list[Any]) -> list[Any]:
    """Añade los tipos v3 a los extremos admitidos de cada regla existente."""
    salida: list[Any] = []
    for regla in relaciones or []:
        if not isinstance(regla, dict):
            salida.append(regla)
            continue
        regla = dict(regla)
        extra = AMPLIACION_TIPOS_RELACION.get(str(regla.get("tipo", "")).upper())
        if extra:
            for extremo, tipos in extra.items():
                actuales = [str(x).upper() for x in (regla.get(extremo) or [])]
                if not actuales:
                    continue
                for tipo in tipos:
                    if tipo not in actuales:
                        actuales.append(tipo)
                regla[extremo] = actuales
        salida.append(regla)
    return salida


def extiende_config(config: dict[str, Any]) -> dict[str, Any]:
    """Agrega el léxico y las reglas del reconocedor v3 a una config existente."""
    salida = dict(config or {})
    for seccion, extra, clave in (
        ("aliases", ALIASES_EXTRA, lambda x: norm(x.get("canonico"))),
        ("roles", ROLES_EXTRA, lambda x: norm(x.get("rol"))),
        ("relaciones", RELACIONES_EXTRA, lambda x: str(x.get("tipo", "")).upper()),
    ):
        actuales = list(salida.get(seccion, []) or [])
        existentes = {clave(x) for x in actuales if isinstance(x, dict)}
        for item in extra:
            if clave(item) not in existentes:
                actuales.append(item)
        salida[seccion] = actuales
    salida["relaciones"] = amplia_tipos_relaciones(salida.get("relaciones", []))
    salida["reconocedor_version"] = VERSION_RECONOCEDOR
    return salida
