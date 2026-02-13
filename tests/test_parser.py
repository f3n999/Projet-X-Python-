"""
Tests pour le module email_parser.py
Lancer avec : python -m pytest tests/ -v
"""

import unittest
from pathlib import Path
from src.email_parser import EmailParser


class TestEmailParser(unittest.TestCase):
    """Tests du parsing d'emails."""

    def setUp(self):
        """Initialise le parser avant chaque test."""
        self.parser = EmailParser()
        self.samples_dir = Path('tests/sample_emails')

    def test_parse_phishing_email(self):
        """Verifie que le parser extrait les donnees d'un email phishing."""
        result = self.parser.parse_eml_file(
            str(self.samples_dir / 'phishing_samples' / 'phishing_001.eml'))

        # Pas d'erreur
        self.assertNotIn('error', result)

        # Headers extraits
        self.assertIn('From', result['headers'])
        self.assertIn('amaz0n', result['headers']['From'])

        # URLs extraites
        self.assertGreater(len(result['urls']), 0)

        # Corps non vide
        self.assertGreater(len(result['body']['full_text']), 0)

    def test_parse_legitimate_email(self):
        """Verifie le parsing d'un email legitime."""
        result = self.parser.parse_eml_file(
            str(self.samples_dir / 'legitimate_samples' / 'legit_001.eml'))

        self.assertNotIn('error', result)
        self.assertIn('oteria.fr', result['headers']['From'])

        # Email legitime a une authentification
        self.assertTrue(result['authentication']['has_auth'])

    def test_file_not_found(self):
        """Verifie la gestion d'un fichier inexistant."""
        result = self.parser.parse_eml_file('fichier_inexistant.eml')
        self.assertIn('error', result)

    def test_emails_extracted(self):
        """Verifie l'extraction des adresses email."""
        result = self.parser.parse_eml_file(
            str(self.samples_dir / 'phishing_samples' / 'phishing_001.eml'))

        self.assertGreater(len(result['emails']), 0)

    def test_html_urls_with_beautifulsoup(self):
        """Verifie que BeautifulSoup extrait les href des balises <a>."""
        result = self.parser.parse_eml_file(
            str(self.samples_dir / 'phishing_samples' / 'phishing_001.eml'))

        # L'email phishing_001 a un <a href="http://192.168.1.100/...">
        ip_urls = []
        for url in result['urls']:
            if '192.168.1.100' in url:
                ip_urls.append(url)

        self.assertGreater(len(ip_urls), 0,
                           "BeautifulSoup devrait extraire l'URL avec IP")


if __name__ == '__main__':
    unittest.main()
