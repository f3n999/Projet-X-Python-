"""
Tests pour le module risk_scorer.py
Lance avec : python -m pytest tests/ -v
"""

import unittest
from src.risk_scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):
    """Tests du calcul de score."""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_no_rules_triggered(self):
        """Score = 0 si rien n'est declenche."""
        detection = {
            'RULE_A': {'triggered': False, 'reason': 'OK', 'weight': 10},
            'RULE_B': {'triggered': False, 'reason': 'OK', 'weight': 8},
        }
        score, metadata = self.scorer.calculate_score(detection)
        self.assertEqual(score, 0)
        self.assertEqual(metadata['risk_level'], 'SAFE')

    def test_all_rules_triggered(self):
        """Score = 100 si tout est declenche."""
        detection = {
            'RULE_A': {'triggered': True, 'reason': 'Test', 'weight': 10},
            'RULE_B': {'triggered': True, 'reason': 'Test', 'weight': 8},
        }
        score, metadata = self.scorer.calculate_score(detection)
        self.assertEqual(score, 100)
        self.assertEqual(metadata['risk_level'], 'CRITICAL')

    def test_partial_triggers(self):
        """Score proportionnel aux poids declenches."""
        detection = {
            'RULE_A': {'triggered': True, 'reason': 'Test', 'weight': 10},
            'RULE_B': {'triggered': False, 'reason': 'OK', 'weight': 10},
        }
        score, metadata = self.scorer.calculate_score(detection)
        # 10 / 20 * 100 = 50
        self.assertEqual(score, 50)
        self.assertEqual(metadata['risk_level'], 'MEDIUM')

    def test_risk_levels(self):
        """Verifie chaque seuil de risque."""
        self.assertEqual(self.scorer._get_risk_level(0), 'SAFE')
        self.assertEqual(self.scorer._get_risk_level(19), 'SAFE')
        self.assertEqual(self.scorer._get_risk_level(20), 'LOW')
        self.assertEqual(self.scorer._get_risk_level(40), 'MEDIUM')
        self.assertEqual(self.scorer._get_risk_level(60), 'HIGH')
        self.assertEqual(self.scorer._get_risk_level(80), 'CRITICAL')
        self.assertEqual(self.scorer._get_risk_level(100), 'CRITICAL')

    def test_triggered_rules_in_metadata(self):
        """Verifie que les regles declenchees sont listees dans metadata."""
        detection = {
            'PASSWORD_REQUEST': {'triggered': True, 'reason': 'Detected', 'weight': 10},
            'CLEAN_RULE': {'triggered': False, 'reason': 'OK', 'weight': 5},
        }
        _, metadata = self.scorer.calculate_score(detection)
        self.assertEqual(metadata['triggered_rules_count'], 1)
        self.assertEqual(metadata['total_rules'], 2)
        self.assertEqual(metadata['triggered_rules'][0]['name'], 'PASSWORD_REQUEST')

    def test_empty_results(self):
        """Score = 0 si aucun resultat."""
        score, metadata = self.scorer.calculate_score({})
        self.assertEqual(score, 0)


if __name__ == '__main__':
    unittest.main()
