"""
Tests pour le module detection_rules.py
Lance avec : python -m pytest tests/ -v
"""

import unittest
from src.detection_rules import PhishingDetector


def make_email(subject='Test', from_addr='user@example.com',
               body_text='', body_html='', urls=None,
               attachments=None, has_auth=True,
               auth_raw='spf=pass'):
    """
    Fabrique un dictionnaire email factice pour les tests.
    Permet de tester chaque regle independamment.
    """
    return {
        'headers': {
            'From': from_addr,
            'To': 'dest@example.com',
            'Subject': subject,
            'Date': 'Mon, 10 Feb 2026 10:00:00 +0000',
        },
        'body': {
            'text': body_text[:500],
            'html': body_html[:500],
            'full_text': body_text,
            'full_html': body_html,
        },
        'urls': urls or [],
        'emails': [from_addr],
        'ips': [],
        'attachments': attachments or [],
        'authentication': {
            'raw': auth_raw,
            'has_auth': has_auth,
        }
    }


class TestDetectionRules(unittest.TestCase):
    """Tests des 15 regles de detection."""

    def setUp(self):
        self.detector = PhishingDetector()

    # ---- Regle 1 : Keywords subject ----
    def test_suspicious_keywords_subject(self):
        email = make_email(subject='Urgent: Verify Your Account')
        results = self.detector.analyze(email)
        self.assertTrue(results['SUSPICIOUS_KEYWORDS_SUBJECT']['triggered'])

    def test_clean_subject(self):
        email = make_email(subject='Meeting mardi 14h')
        results = self.detector.analyze(email)
        self.assertFalse(results['SUSPICIOUS_KEYWORDS_SUBJECT']['triggered'])

    # ---- Regle 2 : Keywords body ----
    def test_suspicious_keywords_body(self):
        body = 'Dear customer, please verify your account and confirm your identity now'
        email = make_email(body_text=body)
        results = self.detector.analyze(email)
        self.assertTrue(results['SUSPICIOUS_KEYWORDS_BODY']['triggered'])

    # ---- Regle 3 : Password request ----
    def test_password_request(self):
        body = 'Please reset your password immediately'
        email = make_email(body_text=body)
        results = self.detector.analyze(email)
        self.assertTrue(results['PASSWORD_REQUEST']['triggered'])

    # ---- Regle 4 : Sensitive data ----
    def test_sensitive_data_request(self):
        body = 'Enter your credit card number and CVV'
        email = make_email(body_text=body)
        results = self.detector.analyze(email)
        self.assertTrue(results['SENSITIVE_DATA_REQUEST']['triggered'])

    # ---- Regle 5 : Urgency ----
    def test_artificial_urgency(self):
        body = 'This is urgent! Act now or your account will be closed immediately.'
        email = make_email(body_text=body)
        results = self.detector.analyze(email)
        self.assertTrue(results['ARTIFICIAL_URGENCY']['triggered'])

    # ---- Regle 6 : Domain mismatch ----
    def test_domain_mismatch(self):
        email = make_email(
            from_addr='security@paypal.com',
            urls=['https://evil-site.com/login']
        )
        results = self.detector.analyze(email)
        self.assertTrue(results['DOMAIN_MISMATCH']['triggered'])

    # ---- Regle 8 : No auth ----
    def test_no_authentication(self):
        email = make_email(has_auth=False, auth_raw='N/A')
        results = self.detector.analyze(email)
        self.assertTrue(results['NO_AUTHENTICATION']['triggered'])

    # ---- Regle 9 : SPF fail ----
    def test_spf_fail(self):
        email = make_email(auth_raw='spf=fail smtp.mailfrom=evil.com')
        results = self.detector.analyze(email)
        self.assertTrue(results['SPF_FAIL']['triggered'])

    # ---- Regle 10 : Suspicious HTML (avec BS4) ----
    def test_suspicious_html_script(self):
        html = '<html><body><script>alert("xss")</script></body></html>'
        email = make_email(body_html=html)
        results = self.detector.analyze(email)
        self.assertTrue(results['SUSPICIOUS_HTML']['triggered'])

    def test_suspicious_html_iframe(self):
        html = '<html><body><iframe src="http://evil.com"></iframe></body></html>'
        email = make_email(body_html=html)
        results = self.detector.analyze(email)
        self.assertTrue(results['SUSPICIOUS_HTML']['triggered'])

    # ---- Regle 11 : Short URL ----
    def test_short_url(self):
        email = make_email(urls=['https://bit.ly/abc123'])
        results = self.detector.analyze(email)
        self.assertTrue(results['SHORT_URL']['triggered'])

    # ---- Regle 12 : Executable attachment ----
    def test_executable_attachment(self):
        att = [{'filename': 'invoice.exe', 'size': 1024}]
        email = make_email(attachments=att)
        results = self.detector.analyze(email)
        self.assertTrue(results['EXECUTABLE_ATTACHMENT']['triggered'])

    # ---- Regle 13 : Suspicious sender ----
    def test_suspicious_sender(self):
        email = make_email(from_addr='no-reply@suspicious.com')
        results = self.detector.analyze(email)
        self.assertTrue(results['SUSPICIOUS_SENDER']['triggered'])

    # ---- Regle 14 : IP in URL ----
    def test_ip_in_url(self):
        email = make_email(urls=['http://192.168.1.100/phishing'])
        results = self.detector.analyze(email)
        self.assertTrue(results['IP_IN_URL']['triggered'])

    # ---- Regle 15 : Encoding obfuscation ----
    def test_punycode(self):
        email = make_email(body_text='Visit xn--pple-43d.com for details')
        results = self.detector.analyze(email)
        self.assertTrue(results['ENCODING_OBFUSCATION']['triggered'])

    # ---- Clean email : rien ne se declenche ----
    def test_clean_email(self):
        email = make_email(
            subject='Reunion mardi',
            from_addr='alice@oteria.fr',
            body_text='Bonjour, on se voit mardi a 14h.',
            body_html='',
            has_auth=True,
            auth_raw='spf=pass'
        )
        results = self.detector.analyze(email)

        triggered = [name for name, r in results.items() if r['triggered']]
        self.assertEqual(len(triggered), 0,
                         f"Regles declenchees sur un email propre : {triggered}")


if __name__ == '__main__':
    unittest.main()
