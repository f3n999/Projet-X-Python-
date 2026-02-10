"""
RISK SCORER - Attribution du score risque 0-100
Mission: Convertir les résultats de détection en score unique
"""

from typing import Dict, Tuple


class RiskScorer:
    """Convertit les résultats de détection en score 0-100."""

    def __init__(self):
        # Poids par règle (importance relative, 1-10)
        self.rule_weights = {
            'PASSWORD_REQUEST': 10,
            'EXECUTABLE_ATTACHMENT': 10,
            'SENSITIVE_DATA_REQUEST': 10,
            'DOMAIN_MISMATCH': 9,
            'DOMAIN_LOOKALIKE': 9,
            'SPF_FAIL': 8,
            'SUSPICIOUS_KEYWORDS_SUBJECT': 8,
            'ARTIFICIAL_URGENCY': 8,
            'IP_IN_URL': 8,
            'ENCODING_OBFUSCATION': 7,
            'SUSPICIOUS_KEYWORDS_BODY': 7,
            'SHORT_URL': 7,
            'SUSPICIOUS_HTML': 7,
            'SUSPICIOUS_SENDER': 6,
            'NO_AUTHENTICATION': 6,
        }
        self.max_score = 100

    def calculate_score(self, detection_results: Dict) -> Tuple[int, Dict]:
        """
        Calcule le score de risque final.

        Args:
            detection_results: Dict avec résultats de chaque règle

        Returns:
            Tuple (score, metadata)
        """
        total_weight = 0
        triggered_weight = 0
        triggered_rules = []

        for rule_name, result in detection_results.items():
            weight = self.rule_weights.get(rule_name, 5)
            total_weight += weight

            if result['triggered']:
                triggered_weight += weight
                triggered_rules.append({
                    'name': rule_name,
                    'weight': weight,
                    'reason': result['reason']
                })

        # Score = (poids déclenchés / poids total) * 100, plafonné à 100
        if total_weight > 0:
            score = min(int((triggered_weight / total_weight) * 100), 100)
        else:
            score = 0

        metadata = {
            'score': score,
            'triggered_rules_count': len(triggered_rules),
            'total_rules': len(detection_results),
            'triggered_rules': triggered_rules,
            'risk_level': self._get_risk_level(score)
        }

        return score, metadata

    @staticmethod
    def _get_risk_level(score: int) -> str:
        """Classe le score en niveau de risque lisible."""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'SAFE'
