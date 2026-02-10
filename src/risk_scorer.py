"""
RISK SCORER - Attribution du score de risque 0-100
Mission : Convertir les resultats de detection en un score unique

Principe :
    Chaque regle a un poids (importance).
    Le score = (somme des poids declenches / somme totale des poids) * 100
    Le score est ensuite classe en 5 niveaux de risque.
"""

from typing import Dict, Tuple


class RiskScorer:
    """
    Convertit les resultats de detection en score 0-100.

    Utilisation :
        scorer = RiskScorer()
        score, metadata = scorer.calculate_score(detection_results)
    """

    def __init__(self):
        # Poids par regle : de 6 (peu grave) a 10 (tres grave)
        # Ces poids refletent la gravite du signal en cybersecurite
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

    def calculate_score(self, detection_results: Dict) -> Tuple[int, Dict]:
        """
        Calcule le score de risque final.

        Args:
            detection_results : dictionnaire retourne par PhishingDetector.analyze()
                Format : { 'RULE_NAME': {'triggered': bool, 'reason': str, 'weight': int} }

        Returns:
            Tuple (score, metadata) :
                score    : entier de 0 a 100
                metadata : details (regles declenchees, niveau de risque, etc.)
        """
        total_weight = 0
        triggered_weight = 0
        triggered_rules = []

        for rule_name, result in detection_results.items():
            # Recuperer le poids defini, ou 5 par defaut pour les regles inconnues
            weight = self.rule_weights.get(rule_name, 5)
            total_weight += weight

            if result['triggered']:
                triggered_weight += weight
                triggered_rules.append({
                    'name': rule_name,
                    'weight': weight,
                    'reason': result['reason']
                })

        # Calcul du score : pourcentage des poids declenches
        # min() plafonne a 100
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
        """
        Classe le score en niveau de risque.

        Echelle :
            0-19   : SAFE     (aucun signal ou negligeable)
            20-39  : LOW      (quelques signaux faibles)
            40-59  : MEDIUM   (signaux moderement suspects)
            60-79  : HIGH     (probablement du phishing)
            80-100 : CRITICAL (phishing quasi certain)
        """
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
