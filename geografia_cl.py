#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Catálogo geográfico de Chile para desambiguar topónimos de antropónimos.

Muchas comunas chilenas tienen forma de nombre de persona: San Ramón, San
Miguel, Pedro Aguirre Cerda, Padre Hurtado, María Elena, Diego de Almagro,
Santa Juana. Un reconocedor entrenado con texto genérico las etiqueta como
PERSONA, lo que introduce personas naturales inexistentes en la nómina — un
error grave en un producto de inteligencia financiera, porque nombra a alguien
que no aparece en la noticia.

Este módulo aporta la división político-administrativa completa (16 regiones,
56 provincias, 346 comunas) más capitales, gentilicios y accidentes geográficos
frecuentes en prensa, junto con las reglas de desambiguación por contexto.

Fuente: división político-administrativa vigente (Ley 21.033 creó la Región de
Ñuble en 2018). Verificar contra el catálogo del INE si cambia la DPA.
"""

from __future__ import annotations

import re
import unicodedata


def _norm(texto: str) -> str:
    plano = unicodedata.normalize("NFKD", str(texto or ""))
    plano = "".join(c for c in plano if not unicodedata.combining(c)).casefold()
    return " ".join("".join(c if c.isalnum() else " " for c in plano).split())


REGIONES = [
    "Arica y Parinacota", "Tarapacá", "Antofagasta", "Atacama", "Coquimbo",
    "Valparaíso", "Metropolitana de Santiago", "Región Metropolitana",
    "Libertador General Bernardo O'Higgins", "O'Higgins", "Maule", "Ñuble",
    "Biobío", "La Araucanía", "Araucanía", "Los Ríos", "Los Lagos",
    "Aysén del General Carlos Ibáñez del Campo", "Aysén", "Aisén",
    "Magallanes y de la Antártica Chilena", "Magallanes",
]

PROVINCIAS = [
    "Arica", "Parinacota", "Iquique", "Tamarugal", "Antofagasta", "El Loa",
    "Tocopilla", "Copiapó", "Chañaral", "Huasco", "Elqui", "Choapa", "Limarí",
    "Petorca", "Los Andes", "Marga Marga", "Quillota", "San Antonio",
    "San Felipe de Aconcagua", "Isla de Pascua", "Valparaíso", "Chacabuco",
    "Cordillera", "Maipo", "Melipilla", "Santiago", "Talagante", "Cachapoal",
    "Cardenal Caro", "Colchagua", "Curicó", "Linares", "Talca", "Cauquenes",
    "Diguillín", "Itata", "Punilla", "Arauco", "Biobío", "Concepción",
    "Cautín", "Malleco", "Valdivia", "Ranco", "Chiloé", "Llanquihue", "Osorno",
    "Palena", "Coyhaique", "Aysén", "Capitán Prat", "General Carrera",
    "Antártica Chilena", "Magallanes", "Tierra del Fuego", "Última Esperanza",
]

# Las 346 comunas, agrupadas por región para facilitar el mantenimiento.
COMUNAS_POR_REGION: dict[str, list[str]] = {
    "Arica y Parinacota": ["Arica", "Camarones", "Putre", "General Lagos"],
    "Tarapacá": [
        "Iquique", "Alto Hospicio", "Pozo Almonte", "Camiña", "Colchane",
        "Huara", "Pica",
    ],
    "Antofagasta": [
        "Antofagasta", "Mejillones", "Sierra Gorda", "Taltal", "Calama",
        "Ollagüe", "San Pedro de Atacama", "Tocopilla", "María Elena",
    ],
    "Atacama": [
        "Copiapó", "Caldera", "Tierra Amarilla", "Chañaral",
        "Diego de Almagro", "Vallenar", "Alto del Carmen", "Freirina",
        "Huasco",
    ],
    "Coquimbo": [
        "La Serena", "Coquimbo", "Andacollo", "La Higuera", "Paihuano",
        "Vicuña", "Illapel", "Canela", "Los Vilos", "Salamanca", "Ovalle",
        "Combarbalá", "Monte Patria", "Punitaqui", "Río Hurtado",
    ],
    "Valparaíso": [
        "Valparaíso", "Casablanca", "Concón", "Juan Fernández", "Puchuncaví",
        "Quintero", "Viña del Mar", "Isla de Pascua", "Los Andes",
        "Calle Larga", "Rinconada", "San Esteban", "La Ligua", "Cabildo",
        "Papudo", "Petorca", "Zapallar", "Quillota", "La Calera", "Hijuelas",
        "La Cruz", "Nogales", "San Antonio", "Algarrobo", "Cartagena",
        "El Quisco", "El Tabo", "Santo Domingo", "San Felipe", "Catemu",
        "Llaillay", "Panquehue", "Putaendo", "Santa María", "Quilpué",
        "Limache", "Olmué", "Villa Alemana",
    ],
    "Metropolitana": [
        "Santiago", "Cerrillos", "Cerro Navia", "Conchalí", "El Bosque",
        "Estación Central", "Huechuraba", "Independencia", "La Cisterna",
        "La Florida", "La Granja", "La Pintana", "La Reina", "Las Condes",
        "Lo Barnechea", "Lo Espejo", "Lo Prado", "Macul", "Maipú", "Ñuñoa",
        "Pedro Aguirre Cerda", "Peñalolén", "Providencia", "Pudahuel",
        "Quilicura", "Quinta Normal", "Recoleta", "Renca", "San Joaquín",
        "San Miguel", "San Ramón", "Vitacura", "Puente Alto", "Pirque",
        "San José de Maipo", "Colina", "Lampa", "Tiltil", "San Bernardo",
        "Buin", "Calera de Tango", "Paine", "Melipilla", "Alhué", "Curacaví",
        "María Pinto", "San Pedro", "Talagante", "El Monte", "Isla de Maipo",
        "Padre Hurtado", "Peñaflor",
    ],
    "O'Higgins": [
        "Rancagua", "Codegua", "Coinco", "Coltauco", "Doñihue", "Graneros",
        "Las Cabras", "Machalí", "Malloa", "Mostazal", "Olivar", "Peumo",
        "Pichidegua", "Quinta de Tilcoco", "Rengo", "Requínoa", "San Vicente",
        "Pichilemu", "La Estrella", "Litueche", "Marchihue", "Navidad",
        "Paredones", "San Fernando", "Chépica", "Chimbarongo", "Lolol",
        "Nancagua", "Palmilla", "Peralillo", "Placilla", "Pumanque",
        "Santa Cruz",
    ],
    "Maule": [
        "Talca", "Constitución", "Curepto", "Empedrado", "Maule", "Pelarco",
        "Pencahue", "Río Claro", "San Clemente", "San Rafael", "Cauquenes",
        "Chanco", "Pelluhue", "Curicó", "Hualañé", "Licantén", "Molina",
        "Rauco", "Romeral", "Sagrada Familia", "Teno", "Vichuquén", "Linares",
        "Colbún", "Longaví", "Parral", "Retiro", "San Javier", "Villa Alegre",
        "Yerbas Buenas",
    ],
    "Ñuble": [
        "Chillán", "Bulnes", "Chillán Viejo", "El Carmen", "Pemuco", "Pinto",
        "Quillón", "San Ignacio", "Yungay", "Quirihue", "Cobquecura",
        "Coelemu", "Ninhue", "Portezuelo", "Ránquil", "Trehuaco",
        "San Carlos", "Coihueco", "Ñiquén", "San Fabián", "San Nicolás",
    ],
    "Biobío": [
        "Concepción", "Coronel", "Chiguayante", "Florida", "Hualqui", "Lota",
        "Penco", "San Pedro de la Paz", "Santa Juana", "Talcahuano", "Tomé",
        "Hualpén", "Lebu", "Arauco", "Cañete", "Contulmo", "Curanilahue",
        "Los Álamos", "Tirúa", "Los Ángeles", "Antuco", "Cabrero", "Laja",
        "Mulchén", "Nacimiento", "Negrete", "Quilaco", "Quilleco",
        "San Rosendo", "Santa Bárbara", "Tucapel", "Yumbel", "Alto Biobío",
    ],
    "La Araucanía": [
        "Temuco", "Carahue", "Cunco", "Curarrehue", "Freire", "Galvarino",
        "Gorbea", "Lautaro", "Loncoche", "Melipeuco", "Nueva Imperial",
        "Padre Las Casas", "Perquenco", "Pitrufquén", "Pucón", "Saavedra",
        "Teodoro Schmidt", "Toltén", "Vilcún", "Villarrica", "Cholchol",
        "Angol", "Collipulli", "Curacautín", "Ercilla", "Lonquimay",
        "Los Sauces", "Lumaco", "Purén", "Renaico", "Traiguén", "Victoria",
    ],
    "Los Ríos": [
        "Valdivia", "Corral", "Lanco", "Los Lagos", "Máfil", "Mariquina",
        "Paillaco", "Panguipulli", "La Unión", "Futrono", "Lago Ranco",
        "Río Bueno",
    ],
    "Los Lagos": [
        "Puerto Montt", "Calbuco", "Cochamó", "Fresia", "Frutillar",
        "Los Muermos", "Llanquihue", "Maullín", "Puerto Varas", "Castro",
        "Ancud", "Chonchi", "Curaco de Vélez", "Dalcahue", "Puqueldón",
        "Queilén", "Quellón", "Quemchi", "Quinchao", "Osorno", "Puerto Octay",
        "Purranque", "Puyehue", "Río Negro", "San Juan de la Costa",
        "San Pablo", "Chaitén", "Futaleufú", "Hualaihué", "Palena",
    ],
    "Aysén": [
        "Coyhaique", "Lago Verde", "Aysén", "Cisnes", "Guaitecas", "Cochrane",
        "O'Higgins", "Tortel", "Chile Chico", "Río Ibáñez",
    ],
    "Magallanes": [
        "Punta Arenas", "Laguna Blanca", "Río Verde", "San Gregorio",
        "Cabo de Hornos", "Antártica", "Porvenir", "Primavera", "Timaukel",
        "Natales", "Torres del Paine",
    ],
}

COMUNAS = [c for lista in COMUNAS_POR_REGION.values() for c in lista]

# Localidades, barrios y accidentes geográficos frecuentes en prensa que no son
# comunas pero aparecen con la misma función referencial.
OTROS_TOPONIMOS = [
    "Chile", "Sudamérica", "Latinoamérica", "Cono Sur", "Zona Norte",
    "Zona Sur", "Zona Central", "Gran Santiago", "Gran Concepción",
    "Gran Valparaíso", "Barrio Alto", "Sanhattan", "Ciudad Empresarial",
    "Alameda", "Plaza de Armas", "Plaza Baquedano", "Plaza Italia",
    "Costanera Center", "Puerto de San Antonio", "Puerto de Valparaíso",
    "Aeropuerto Arturo Merino Benítez", "Cordillera de los Andes",
    "Desierto de Atacama", "Cabo de Hornos", "Estrecho de Magallanes",
    "Isla de Chiloé", "Río Mapocho", "Lago Villarrica", "Valle del Elqui",
    "Colchane", "Chacalluta", "Los Libertadores", "Pino Hachado",
    "Cardenal Samoré", "Paso Jama",
]

# Países y ciudades extranjeras habituales en noticias LA/FT chilenas.
TOPONIMOS_EXTRANJEROS = [
    "Argentina", "Bolivia", "Perú", "Brasil", "Colombia", "Venezuela",
    "Ecuador", "Paraguay", "Uruguay", "México", "Panamá", "Estados Unidos",
    "España", "China", "Buenos Aires", "Lima", "La Paz", "Santa Cruz de la Sierra",
    "Bogotá", "Caracas", "Miami", "Nueva York", "Madrid", "Islas Vírgenes",
    "Islas Caimán", "Delaware", "Hong Kong", "Singapur", "Emiratos Árabes Unidos",
    "Tacna", "Mendoza", "Salta", "Jujuy", "Oruro", "Desaguadero",
]

TOPONIMOS = (
    REGIONES + PROVINCIAS + COMUNAS + OTROS_TOPONIMOS + TOPONIMOS_EXTRANJEROS
)

TOPONIMOS_NORM: set[str] = {_norm(t) for t in TOPONIMOS if _norm(t)}

# Índice para reconstruir la forma canónica y el nivel administrativo.
NIVEL_TOPONIMO: dict[str, str] = {}
FORMA_CANONICA: dict[str, str] = {}
for _t in TOPONIMOS_EXTRANJEROS:
    NIVEL_TOPONIMO.setdefault(_norm(_t), "EXTRANJERO")
    FORMA_CANONICA.setdefault(_norm(_t), _t)
for _t in OTROS_TOPONIMOS:
    NIVEL_TOPONIMO[_norm(_t)] = "LOCALIDAD"
    FORMA_CANONICA[_norm(_t)] = _t
for _t in COMUNAS:
    NIVEL_TOPONIMO[_norm(_t)] = "COMUNA"
    FORMA_CANONICA[_norm(_t)] = _t
for _t in PROVINCIAS:
    NIVEL_TOPONIMO[_norm(_t)] = "PROVINCIA"
    FORMA_CANONICA.setdefault(_norm(_t), _t)
for _t in REGIONES:
    NIVEL_TOPONIMO[_norm(_t)] = "REGION"
    FORMA_CANONICA[_norm(_t)] = _t

COMUNA_DE_REGION: dict[str, str] = {
    _norm(c): region for region, lista in COMUNAS_POR_REGION.items() for c in lista
}

# Encabezados que anteponen explícitamente un topónimo. Cuando aparecen, la
# cadena siguiente es geográfica sin lugar a duda.
ENCABEZADO_GEOGRAFICO = re.compile(
    r"(?:comuna|municipio|municipalidad|provincia|regi[oó]n|ciudad|localidad|"
    r"sector|barrio|poblaci[oó]n|villa|puerto|paso\s+fronterizo|aeropuerto|"
    r"terminal|distrito|circunscripci[oó]n|zona)\s+(?:de\s+|del\s+|la\s+|el\s+)?$",
    re.IGNORECASE,
)

# Preposiciones de lugar inmediatamente anteriores.
PREPOSICION_LUGAR = re.compile(
    r"(?:\ben|\bdesde|\bhacia|\bhasta|\bhabitantes\s+de|"
    r"\bresidentes\s+de|\bvecinos\s+de|\boriginari[oa]s?\s+de)\s+$",
    re.IGNORECASE,
)

# Cargos territoriales: "el alcalde de San Ramón" describe un lugar, no a una
# persona llamada Ramón.
CARGO_TERRITORIAL = re.compile(
    r"(?:alcalde|alcaldesa|municipalidad|municipio|concejo\s+municipal|"
    r"concejal(?:es|a)?|gobernador(?:a)?\s+regional|delegad[oa]\s+presidencial|"
    r"seremi|core|consejo\s+regional|juzgado|tribunal|fiscal[ií]a|comisar[ií]a|"
    r"prefectura|hospital|liceo|escuela|cesfam)\s+"
    r"(?:de\s+|del\s+|la\s+|el\s+)*$",
    re.IGNORECASE,
)

# Tratamientos que, si preceden a la cadena, la mantienen como persona pese a
# coincidir con un topónimo ("doña María Elena").
TRATAMIENTO_PERSONAL = re.compile(
    r"\b(?:don|do[ñn]a|sr\.?|sra\.?|srta\.?|se[ñn]or|se[ñn]ora|se[ñn]orita|"
    r"dr\.?|dra\.?)\s+$",
    re.IGNORECASE,
)


def es_toponimo(nombre: str) -> bool:
    """Coincidencia exacta con el catálogo geográfico."""
    return _norm(nombre) in TOPONIMOS_NORM


def info_toponimo(nombre: str) -> dict[str, str] | None:
    """Devuelve nivel administrativo y forma canónica, o None."""
    clave = _norm(nombre)
    if clave not in TOPONIMOS_NORM:
        return None
    datos = {
        "nivel": NIVEL_TOPONIMO.get(clave, "LOCALIDAD"),
        "canonico": FORMA_CANONICA.get(clave, nombre),
    }
    region = COMUNA_DE_REGION.get(clave)
    if region:
        datos["region"] = region
    return datos


def evalua_geografia(nombre: str, contexto_izq: str = "") -> dict[str, object]:
    """Decide si una cadena debe leerse como lugar y con qué fuerza.

    Devuelve ``{"es_lugar", "fuerza", "senales", "info"}``. La fuerza distingue
    la coincidencia de catálogo (que admite excepción por tratamiento personal)
    de la marcada explícitamente por el contexto, que no admite excepción.
    """
    senales: list[str] = []
    izq = contexto_izq or ""
    info = info_toponimo(nombre)

    if ENCABEZADO_GEOGRAFICO.search(izq):
        senales.append("encabezado_geografico_previo")
        return {"es_lugar": True, "fuerza": "definitiva", "senales": senales,
                "info": info}

    if CARGO_TERRITORIAL.search(izq) and info:
        senales.append("cargo_territorial_previo")
        return {"es_lugar": True, "fuerza": "definitiva", "senales": senales,
                "info": info}

    if not info:
        return {"es_lugar": False, "fuerza": "ninguna", "senales": senales,
                "info": None}

    senales.append(f"toponimo_catalogo:{info['nivel'].lower()}")

    # "doña María Elena" o "el señor San Martín": el tratamiento personal pesa
    # más que la homonimia con una comuna.
    if TRATAMIENTO_PERSONAL.search(izq):
        senales.append("tratamiento_personal_prevalece")
        return {"es_lugar": False, "fuerza": "descartada_por_tratamiento",
                "senales": senales, "info": info}

    if PREPOSICION_LUGAR.search(izq):
        senales.append("preposicion_de_lugar_previa")
        return {"es_lugar": True, "fuerza": "definitiva", "senales": senales,
                "info": info}

    return {"es_lugar": True, "fuerza": "catalogo", "senales": senales,
            "info": info}
