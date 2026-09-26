import unittest

from attack_surface_prioritizer import Asset, build_rules, score_asset, score_inventory


def asset(**kwargs):
    base = {"id": "a", "owner": "team", "last_assessed_days": 10}
    base.update(kwargs)
    return Asset.from_dict(base, 1)


def rules_hit(scored):
    return {r["rule"] for r in scored.reasons}


class ScoringTests(unittest.TestCase):
    def test_clean_internal_asset_scores_zero(self):
        scored = score_asset(asset(ports=[443]))
        self.assertEqual(scored.score, 0)
        self.assertEqual(scored.level, "low")

    def test_public_database_is_critical(self):
        scored = score_asset(asset(public=True, owner="", ports=[5432, 22]))
        self.assertEqual(rules_hit(scored), {"public", "sensitive-port", "no-owner"})
        self.assertEqual(scored.level, "critical")
        self.assertIn("PostgreSQL", next(r["detail"] for r in scored.reasons if r["rule"] == "sensitive-port"))

    def test_sensitive_ports_only_matter_when_public(self):
        self.assertNotIn("sensitive-port", rules_hit(score_asset(asset(ports=[6379]))))

    def test_missing_assessment_counts_as_never_assessed(self):
        scored = score_asset(Asset.from_dict({"id": "x", "owner": "t"}, 1))
        self.assertEqual([r["detail"] for r in scored.reasons], ["never assessed"])

    def test_public_non_production(self):
        self.assertIn("non-production", rules_hit(score_asset(asset(public=True, env="Staging"))))

    def test_score_is_capped(self):
        scored = score_asset(Asset.from_dict({
            "id": "worst", "public": True, "env": "dev", "tech": ["php"],
            "ports": [22, 80, 3306, 6379],
        }, 1))
        self.assertEqual(scored.score, 100)

    def test_ranking_is_stable(self):
        ranked = score_inventory([asset(id="b"), asset(id="a"), asset(id="c", public=True)])
        self.assertEqual([s.asset.id for s in ranked], ["c", "a", "b"])


class WeightTests(unittest.TestCase):
    def test_override_and_disable(self):
        rules = build_rules({"public": 50, "stale-assessment": 0})
        scored = score_asset(asset(public=True, last_assessed_days=500), rules)
        self.assertEqual(scored.score, 50)

    def test_unknown_rule_is_rejected(self):
        with self.assertRaises(ValueError):
            build_rules({"pubic": 10})

    def test_negative_weight_is_rejected(self):
        with self.assertRaises(ValueError):
            build_rules({"public": -5})


class ValidationTests(unittest.TestCase):
    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            Asset.from_dict({"id": "x", "ports": [70000]}, 1)

    def test_ports_must_be_a_list(self):
        with self.assertRaises(ValueError):
            Asset.from_dict({"id": "x", "ports": 443}, 1)

    def test_id_falls_back_to_host(self):
        self.assertEqual(Asset.from_dict({"host": "h.example.com"}, 3).id, "h.example.com")


if __name__ == "__main__":
    unittest.main()
