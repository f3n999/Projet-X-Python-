"""Tests pour le module email_parser."""

import sys
import os
import unittest
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.email_parser import EmailParser


class TestEmailParser(unittest.TestCase):
    """Tests unitaires pour EmailParser."""

    def setUp(self):
        self.parser = EmailParser()

    def test_file_not_found(self):
        """Vérifie qu'un fichier inexistant retourne une erreur."""
        result = self.parser.parse_eml_file('nonexistent.eml')
        self.assertIn('error', result)
        self.assertIn('File not found', result['error'])

    def test_parser_returns_expected_keys(self):
        """Vérifie la structure de retour sur un fichier de test."""
        # Créer un fichier .eml minimal pour le test
        test_eml = Path(__file__).parent / 'sample_emails' / 'test_minimal.eml'
        test_eml.parent.mkdir(parents=True, exist_ok=True)

        eml_content = (
            "From: test@example.com\r\n"
            "To: victim@example.com\r\n"
            "Subject: Test Email\r\n"
            "Date: Mon, 10 Feb 2026 10:00:00 +0000\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "This is a test email body.\r\n"
        )
        test_eml.write_text(eml_content)

        result = self.parser.parse_eml_file(str(test_eml))

        self.assertNotIn('error', result)
        expected_keys = ['headers', 'body', 'urls', 'emails', 'ips', 'attachments', 'authentication']
        for key in expected_keys:
            self.assertIn(key, result, f"Clé manquante: {key}")

        # Vérifier les headers extraits
        self.assertEqual(result['headers']['From'], 'test@example.com')
        self.assertEqual(result['headers']['Subject'], 'Test Email')

        # Vérifier le body
        self.assertIn('test email body', result['body']['full_text'].lower())

        # Nettoyage
        test_eml.unlink()

    def test_extract_emails_from_headers(self):
        """Vérifie l'extraction des adresses email."""
        test_eml = Path(__file__).parent / 'sample_emails' / 'test_emails.eml'
        test_eml.parent.mkdir(parents=True, exist_ok=True)

        eml_content = (
            "From: sender@phishing.com\r\n"
            "To: target@company.com\r\n"
            "Cc: other@company.com\r\n"
            "Subject: Test\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Contact us at support@fake.com\r\n"
        )
        test_eml.write_text(eml_content)

        result = self.parser.parse_eml_file(str(test_eml))
        self.assertGreaterEqual(len(result['emails']), 3)

        # Nettoyage
        test_eml.unlink()


if __name__ == '__main__':
    unittest.main()
