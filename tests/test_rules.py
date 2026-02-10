"""Tests pour le module detection_rules."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detection_rules import PhishingDetector


class TestPhishingDetector(unittest.TestCase):
    """Tests unitaires pour PhishingDetector."""

    def setUp(self):
        self.detector = PhishingDetector()

    def _make_email(self, **overrides):
        """Crée un email parsé factice pour les tests."""
        base = {
            'headers': {
                'From': 'user@example.com',
                'To': 'target@company.com',
                'Subject': 'Hello',
                'Date': 'Mon, 10 Feb 2026 10:00:00 +0000',
            },
            'body': {
                'text': '',
                'html': '',
                'full_text': '',
                'full_html': ''
            },
            'urls': [],
            'emails': ['user@example.com'],
            'ips': [],
            'attachments': [],
            'authentication': {
                'raw': 'spf=pass',
                'has_auth': True
            }
        }
        base.update(overrides)
        return base

    def test_clean_email_no_triggers(self):
        """Un email propre ne devrait déclencher aucune règle critique."""
        email_data = self._make_email()
        results = self.detector.analyze(email_data)
        triggered = [name for name, r in results.items() if r['triggered']]
        # Un email basique ne devrait pas trigger password_request, urgency, etc.
        self.assertNotIn('PASSWORD_REQUEST', triggered)
        self.assertNotIn('ARTIFICIAL_URGENCY', triggered)

    def test_password_request_detection(self):
        """Détecte une demande de mot de passe."""
        email_data = self._make_email(
            body={
                'text': '', 'html': '',
                'full_text': 'Please reset your password immediately by clicking below.',
                'full_html': ''
            }
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['PASSWORD_REQUEST']['triggered'])

    def test_suspicious_keywords_subject(self):
        """Détecte les mots-clés suspects dans le sujet."""
        email_data = self._make_email()
        email_data['headers']['Subject'] = 'Urgent: Verify your account now'
        results = self.detector.analyze(email_data)
        self.assertTrue(results['SUSPICIOUS_KEYWORDS_SUBJECT']['triggered'])

    def test_executable_attachment(self):
        """Détecte une pièce jointe exécutable."""
        email_data = self._make_email(
            attachments=[{'filename': 'invoice.exe', 'size': 1024}]
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['EXECUTABLE_ATTACHMENT']['triggered'])

    def test_no_authentication(self):
        """Détecte l'absence d'authentification."""
        email_data = self._make_email(
            authentication={'raw': 'N/A', 'has_auth': False}
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['NO_AUTHENTICATION']['triggered'])

    def test_spf_fail(self):
        """Détecte un SPF échoué."""
        email_data = self._make_email(
            authentication={'raw': 'spf=fail smtp.mailfrom=evil.com', 'has_auth': True}
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['SPF_FAIL']['triggered'])

    def test_ip_in_url(self):
        """Détecte une IP dans l'URL."""
        email_data = self._make_email(
            urls=['http://192.168.1.1/login.php']
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['IP_IN_URL']['triggered'])

    def test_short_url(self):
        """Détecte les URLs raccourcies."""
        email_data = self._make_email(
            urls=['https://bit.ly/abc123']
        )
        results = self.detector.analyze(email_data)
        self.assertTrue(results['SHORT_URL']['triggered'])

    def test_levenshtein_distance(self):
        """Vérifie le calcul de distance de Levenshtein."""
        self.assertEqual(PhishingDetector._levenshtein_distance('kitten', 'sitting'), 3)
        self.assertEqual(PhishingDetector._levenshtein_distance('', 'abc'), 3)
        self.assertEqual(PhishingDetector._levenshtein_distance('same', 'same'), 0)


if __name__ == '__main__':
    unittest.main()
