import unittest
from datetime import datetime, timezone

import exportar_atlas_prensa as B


class AtlasPressBridgeTests(unittest.TestCase):
    def sample(self):
        return {
            "prensa": [
                {
                    "id": "N1",
                    "fecha": datetime.now(timezone.utc).isoformat(),
                    "titulo": "Fiscalía investiga a Inversiones Norte SpA",
                    "medio": "Medio Demo",
                    "link": "https://example.com/n1",
                    "uaf_chile": True,
                    "nomina_entidades": [
                        {
                            "entidad_id": "ENT-X",
                            "nombre": "Inversiones Norte SpA",
                            "tipo": "EMPRESA",
                            "naturaleza": "PERSONA_JURIDICA",
                            "confianza_score": 0.93,
                            "ruts": [],
                            "variantes": ["Inversiones Norte"],
                            "requiere_validacion": False,
                            "rol_principal": "investigado por Fiscalía",
                            "roles": ["investigado por Fiscalía"],
                            "menciones": 2,
                            "fenomenos_articulo": ["Lavado de activos"],
                        }
                    ],
                }
            ]
        }

    def test_exporta_entidad_sin_rut_como_press_only(self):
        out = B.merge(self.sample(), {}, 1825)
        self.assertEqual(out["stats"]["entities"], 1)
        entity = out["entities"][0]
        self.assertTrue(entity["press_entity_id"].startswith("PRESS-"))
        self.assertEqual(entity["resolution_status"], "PRESS_ONLY")
        self.assertEqual(entity["ruts"], [])
        self.assertEqual(entity["article_count"], 1)
        self.assertEqual(entity["mention_count"], 2)

    def test_id_estable_por_nombre_tipo_naturaleza(self):
        a = B.press_id("Inversiones Norte SpA", "PERSONA_JURIDICA", "EMPRESA")
        b = B.press_id("INVERSIONES NORTE SPA", "PERSONA_JURIDICA", "EMPRESA")
        self.assertEqual(a, b)

    def test_conserva_historia_previa(self):
        old = B.merge(self.sample(), {}, 1825)
        second = {"prensa": []}
        out = B.merge(second, old, 1825)
        self.assertEqual(out["stats"]["entities"], 1)
        self.assertEqual(out["stats"]["articles"], 1)


if __name__ == "__main__":
    unittest.main()
