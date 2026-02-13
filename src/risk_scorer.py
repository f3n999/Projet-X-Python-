"""
RISK SCORER - Attribution du score de risque 0-100

Principe :
    Chaque regle a un poids (importance de 6 a 10).
    Score = (somme des poids declenches / somme totale des poids) * 100
    Le score est classe en 5 niveaux : SAFE, LOW, MEDIUM, HIGH, CRITICAL
"""


class RiskScorer:
    """
    Convertit les resultats de detection en un score de 0 a 100.

    Utilisation :
        scorer = RiskScorer()
        score, metadata = scorer.calculate_score(detection_results)
    """

    def __init__(self):
        # Poids par regle : de 6 (peu grave) a 10 (tres grave)
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

    def calculate_score(self, detection_results):
        """
        Calcule le score de risque final.

        Args:
            detection_results : dictionnaire retourne par PhishingDetector.analyze()

        Returns:
            Un tuple (score, metadata) :
                score    : nombre de 0 a 100
                metadata : details (regles declenchees, niveau de risque)
        """
        total_weight = 0
        triggered_weight = 0
        triggered_rules = []

        for rule_name in detection_results:
            result = detection_results[rule_name]

            # Recuperer le poids de la regle (5 par defaut si inconnue)
            if rule_name in self.rule_weights:
                weight = self.rule_weights[rule_name]
            else:
                weight = 5

            total_weight = total_weight + weight

            # Si la regle est declenchee, ajouter son poids
            if result['triggered']:
                triggered_weight = triggered_weight + weight
                triggered_rules.append({
                    'name': rule_name,
                    'weight': weight,
                    'reason': result['reason'],
                })

        # Calcul du score : pourcentage des poids declenches
        if total_weight > 0:
            score = int((triggered_weight / total_weight) * 100)
            # Plafonner a 100
            if score > 100:
                score = 100
        else:
            score = 0

        # Determiner le niveau de risque
        risk_level = self.get_risk_level(score)

        metadata = {
            'score': score,
            'triggered_rules_count': len(triggered_rules),
            'total_rules': len(detection_results),
            'triggered_rules': triggered_rules,
            'risk_level': risk_level,
        }

        return score, metadata

    def get_risk_level(self, score):
        """
        Classe le score en niveau de risque.

        0-19   : SAFE     (aucun signal)
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
