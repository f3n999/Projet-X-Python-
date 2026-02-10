"""Tests pour le module risk_scorer."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.risk_scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):
    """Tests unitaires pour RiskScorer."""

    def setUp(self):
        self.scorer = RiskScorer()

    def test_no_rules_triggered(self):
        """Score = 0 si aucune règle déclenchée."""
        detection = {
            'RULE_A': {'triggered': False, 'reason': 'OK', 'weight': 10},
            'RULE_B': {'triggered': False, 'reason': 'OK', 'weight': 8},
        }
        score, metadata = self.scorer.calculate_score(detection)
        self.assertEqual(score, 0)
        self.assertEqual(metadata['risk_level'], 'SAFE')
        self.assertEqual(metadata['triggered_rules_count'], 0)

    def test_all_rules_triggered(self):
        """Score = 100 si toutes les règles déclenchées."""
        detection = {
            'RULE_A': {'triggered': True, 'reason': 'Bad', 'weight': 10},
            'RULE_B': {'triggered': True, 'reason': 'Bad', 'weight': 8},
        }
        score, metadata = self.scorer.calculate_score(detection)
        self.assertEqual(score, 100)
        self.assertEqual(metadata['risk_level'], 'CRITICAL')

    def test_partial_trigger(self):
        """Score proportionnel aux règles déclenchées."""
        detection = {
            'PASSWORD_REQUEST': {'triggered': True, 'reason': 'Found', 'weight': 10},
            'SUSPICIOUS_SENDER': {'triggered': False, 'reason': 'OK', 'weight': 6},
        }
        score, metadata = self.scorer.calculate_score(detection)
        # 10 / (10+6) * 100 = 62.5 -> 62
        self.assertEqual(score, 62)
        self.assertEqual(metadata['risk_level'], 'HIGH')
        self.assertEqual(metadata['triggered_rules_count'], 1)

    def test_risk_level_boundaries(self):
        """Vérifie les seuils de risque."""
        self.assertEqual(RiskScorer._get_risk_level(0), 'SAFE')
        self.assertEqual(RiskScorer._get_risk_level(19), 'SAFE')
        self.assertEqual(RiskScorer._get_risk_level(20), 'LOW')
        self.assertEqual(RiskScorer._get_risk_level(39), 'LOW')
        self.assertEqual(RiskScorer._get_risk_level(40), 'MEDIUM')
        self.assertEqual(RiskScorer._get_risk_level(59), 'MEDIUM')
        self.assertEqual(RiskScorer._get_risk_level(60), 'HIGH')
        self.assertEqual(RiskScorer._get_risk_level(79), 'HIGH')
        self.assertEqual(RiskScorer._get_risk_level(80), 'CRITICAL')
        self.assertEqual(RiskScorer._get_risk_level(100), 'CRITICAL')

    def test_empty_detection(self):
        """Score = 0 si aucun résultat."""
        score, metadata = self.scorer.calculate_score({})
        self.assertEqual(score, 0)
        self.assertEqual(metadata['risk_level'], 'SAFE')


if __name__ == '__main__':
    unittest.main()
