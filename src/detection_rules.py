"""
DETECTION RULES - Moteur de détection heuristique
Mission: Appliquer 15+ règles pour identifier les signaux de phishing
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class DetectionRule:
    """Représente une règle de détection heuristique."""
    name: str
    description: str
    weight: int  # 1-10, poids dans le score final
    pattern: str = None
    check_func: object = None


class PhishingDetector:
    """Moteur de détection avec 15 règles heuristiques."""

    def __init__(self, suspicious_domains_file=None, phishing_keywords_file=None):
        self.suspicious_domains = (
            self._load_list(suspicious_domains_file) if suspicious_domains_file else []
        )
        self.phishing_keywords = (
            self._load_list(phishing_keywords_file) if phishing_keywords_file else []
        )

        # Mots-clés par défaut intégrés
        self.default_phishing_keywords = [
            'verify', 'confirm', 'urgent', 'action required', 'click here',
            'update payment', 'suspended', 'locked', 'compromised', 'reset password',
            'confirm identity', 'verify account', 'dear customer', 'dear client',
            'prize', 'claim', 'limited time', 'act now', 'thank you',
            'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google'
        ]

        self.rules = self._initialize_rules()

    # ========================================================================
    # CHARGEMENT FICHIERS EXTERNES
    # ========================================================================

    @staticmethod
    def _load_list(filepath: str) -> List[str]:
        """Charge une liste (domaines ou mots-clés) depuis un fichier texte."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except (FileNotFoundError, PermissionError, OSError):
            return []

    # ========================================================================
    # INITIALISATION DES REGLES
    # ========================================================================

    def _initialize_rules(self) -> List[DetectionRule]:
        """Initialise les 15 règles de détection."""
        return [
            DetectionRule(
                name='SUSPICIOUS_KEYWORDS_SUBJECT',
                description='Mots-clés phishing dans le sujet',
                weight=8
            ),
            DetectionRule(
                name='SUSPICIOUS_KEYWORDS_BODY',
                description='Mots-clés phishing dans le corps',
                weight=7
            ),
            DetectionRule(
                name='PASSWORD_REQUEST',
                description='Demande de réinitialisation de mot de passe',
                weight=10
            ),
            DetectionRule(
                name='SENSITIVE_DATA_REQUEST',
                description='Demande de SSN, numéro de carte, etc.',
                weight=10
            ),
            DetectionRule(
                name='ARTIFICIAL_URGENCY',
                description='Langage créant une fausse urgence',
                weight=8
            ),
            DetectionRule(
                name='DOMAIN_MISMATCH',
                description="Domaine du lien != domaine de l'expéditeur",
                weight=9
            ),
            DetectionRule(
                name='DOMAIN_LOOKALIKE',
                description='Domaine qui ressemble à un domaine connu (typosquatting)',
                weight=9
            ),
            DetectionRule(
                name='NO_AUTHENTICATION',
                description='Pas de résultat Authentication-Results',
                weight=6
            ),
            DetectionRule(
                name='SPF_FAIL',
                description='SPF échoué ou soft fail',
                weight=8
            ),
            DetectionRule(
                name='SUSPICIOUS_HTML',
                description='Présence de scripts ou balises dangereuses',
                weight=7
            ),
            DetectionRule(
                name='SHORT_URL',
                description='URLs raccourcies suspectes',
                weight=7
            ),
            DetectionRule(
                name='EXECUTABLE_ATTACHMENT',
                description='Pièce jointe .exe, .bat, .scr, etc.',
                weight=10
            ),
            DetectionRule(
                name='SUSPICIOUS_SENDER',
                description="Format d'adresse expéditeur suspect",
                weight=6
            ),
            DetectionRule(
                name='IP_IN_URL',
                description="Utilisation d'IP directe au lieu de domaine",
                weight=8
            ),
            DetectionRule(
                name='ENCODING_OBFUSCATION',
                description='Utilisation de punycode ou unicode suspect',
                weight=7
            )
        ]

    # ========================================================================
    # ANALYSE PRINCIPALE
    # ========================================================================

    def analyze(self, parsed_email: Dict) -> Dict[str, Dict]:
        """
        Lance toutes les règles de détection sur un email parsé.

        Returns:
            Dict : {'RULE_NAME': {'triggered': bool, 'reason': str, 'weight': int}}
        """
        results = {}
        for rule in self.rules:
            check_method = getattr(self, f'_check_{rule.name.lower()}')
            triggered, reason = check_method(parsed_email)
            results[rule.name] = {
                'triggered': triggered,
                'reason': reason,
                'weight': rule.weight
            }
        return results

    # ========================================================================
    # IMPLEMENTATIONS DES 15 REGLES
    # ========================================================================

    def _check_suspicious_keywords_subject(self, email_data: Dict) -> Tuple[bool, str]:
        """R1 : Mots-clés suspects dans le sujet."""
        subject = email_data['headers'].get('Subject', '').lower()
        keywords = self.phishing_keywords or self.default_phishing_keywords
        found = [kw for kw in keywords if kw in subject]
        if found:
            return True, f"Trouvés: {', '.join(found[:3])}"
        return False, "OK"

    def _check_suspicious_keywords_body(self, email_data: Dict) -> Tuple[bool, str]:
        """R2 : Mots-clés suspects dans le corps (seuil > 2)."""
        body = (email_data['body']['full_text'] or '').lower()[:1000]
        keywords = self.phishing_keywords or self.default_phishing_keywords
        found = [kw for kw in keywords if kw in body]
        if len(found) > 2:
            return True, f"Trouvés: {', '.join(found[:3])}"
        return False, "OK"

    def _check_password_request(self, email_data: Dict) -> Tuple[bool, str]:
        """R3 : Demande de mot de passe."""
        content = (email_data['body']['full_text'] or '').lower()
        patterns = [
            r'reset.*password', r'confirm.*password', r'verify.*password',
            r'update.*credentials', r'enter.*password'
        ]
        if any(re.search(p, content) for p in patterns):
            return True, "Demande de mot de passe détectée"
        return False, "OK"

    def _check_sensitive_data_request(self, email_data: Dict) -> Tuple[bool, str]:
        """R4 : Demande de données sensibles (SSN, carte, etc.)."""
        content = (email_data['body']['full_text'] or '').lower()
        patterns = [
            r'ssn', r'social security', r'credit card', r'card number',
            r'cvv', r'expir', r'bank account', r'swift code',
            r'routing number', r'pin code'
        ]
        if any(re.search(p, content) for p in patterns):
            return True, "Demande de données sensibles"
        return False, "OK"

    def _check_artificial_urgency(self, email_data: Dict) -> Tuple[bool, str]:
        """R5 : Urgence artificielle (seuil >= 2 indicateurs)."""
        content = (email_data['body']['full_text'] or '').lower()
        patterns = [
            r'urgent', r'immediately', r'asap', r'limited time',
            r'act now', r'click.*now', r'24.*hour', r'will be closed'
        ]
        count = sum(1 for p in patterns if re.search(p, content))
        if count >= 2:
            return True, f"{count} indicateurs d'urgence trouvés"
        return False, "OK"

    def _check_domain_mismatch(self, email_data: Dict) -> Tuple[bool, str]:
        """R6 : Domaine des URLs != domaine de l'expéditeur."""
        from_email = email_data['headers'].get('From', '').lower()
        urls = email_data['urls']

        if not from_email or not urls:
            return False, "N/A (pas de from ou URLs)"

        from_domain = from_email.split('@')[-1].rstrip('>')

        for url in urls:
            if 'http' in url.lower():
                url_domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
                if url_domain != from_domain and url_domain not in from_domain:
                    return True, f"Domaine URL {url_domain} != domaine from {from_domain}"

        return False, "OK"

    def _check_domain_lookalike(self, email_data: Dict) -> Tuple[bool, str]:
        """R7 : Typosquatting - domaine qui ressemble à un domaine légitime."""
        urls = email_data['urls']

        legitimate_domains = [
            'amazon.com', 'apple.com', 'microsoft.com', 'google.com',
            'paypal.com', 'facebook.com', 'banking.com', 'chase.com'
        ]

        lookalikes = []
        for url in urls:
            url_domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
            for legit in legitimate_domains:
                if self._levenshtein_distance(url_domain, legit) <= 2:
                    lookalikes.append(url_domain)

        if lookalikes:
            return True, f"Lookalikes détectés: {lookalikes}"
        return False, "OK"

    def _check_no_authentication(self, email_data: Dict) -> Tuple[bool, str]:
        """R8 : Absence d'Authentication-Results."""
        has_auth = email_data['authentication']['has_auth']
        if not has_auth:
            return True, "Pas d'Authentication-Results"
        return False, "OK"

    def _check_spf_fail(self, email_data: Dict) -> Tuple[bool, str]:
        """R9 : SPF échoué ou soft fail."""
        auth_results = email_data['authentication']['raw'].lower()
        spf_patterns = [r'spf=fail', r'spf=softfail', r'spf=neutral']
        if any(re.search(p, auth_results) for p in spf_patterns):
            return True, "SPF échouée"
        return False, "OK"

    def _check_suspicious_html(self, email_data: Dict) -> Tuple[bool, str]:
        """R10 : Balises HTML dangereuses (script, iframe, etc.)."""
        html = (email_data['body']['full_html'] or '').lower()
        patterns = [r'<script', r'javascript:', r'<iframe', r'onerror=', r'onload=']
        if any(re.search(p, html) for p in patterns):
            return True, "Contenu HTML suspect"
        return False, "OK"

    def _check_short_url(self, email_data: Dict) -> Tuple[bool, str]:
        """R11 : URLs raccourcies (bit.ly, tinyurl, etc.)."""
        urls = email_data['urls']
        short_url_services = ['bit.ly', 'tinyurl', 'goo.gl', 'short.link', 'ow.ly']
        found = [u for u in urls if any(s in u for s in short_url_services)]
        if found:
            return True, f"URLs raccourcies: {found}"
        return False, "OK"

    def _check_executable_attachment(self, email_data: Dict) -> Tuple[bool, str]:
        """R12 : Pièce jointe exécutable (.exe, .bat, .scr, etc.)."""
        attachments = email_data['attachments']
        dangerous_exts = ['.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.com', '.pif']
        found = [
            a for a in attachments
            if any(a['filename'].lower().endswith(ext) for ext in dangerous_exts)
        ]
        if found:
            return True, f"Fichiers dangereux: {[a['filename'] for a in found]}"
        return False, "OK"

    def _check_suspicious_sender(self, email_data: Dict) -> Tuple[bool, str]:
        """R13 : Format d'adresse expéditeur suspect."""
        from_email = email_data['headers'].get('From', '').lower()

        suspicious_patterns = [r'no-reply', r'noreply', r'notification', r'alert', r'system']
        if any(re.search(p, from_email) for p in suspicious_patterns):
            return True, "Format d'expéditeur suspect"

        if '@' in from_email:
            domain = from_email.split('@')[-1].rstrip('>')
            if not re.search(r'\.[a-z]{2,}$', domain):
                return True, f"Domaine invalide: {domain}"

        return False, "OK"

    def _check_ip_in_url(self, email_data: Dict) -> Tuple[bool, str]:
        """R14 : IP directe dans l'URL au lieu d'un domaine."""
        urls = email_data['urls']
        ip_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        found = [u for u in urls if re.search(ip_pattern, u)]
        if found:
            return True, f"IPs détectées: {found}"
        return False, "OK"

    def _check_encoding_obfuscation(self, email_data: Dict) -> Tuple[bool, str]:
        """R15 : Punycode ou encoding URL suspect."""
        content = (email_data['body']['full_text'] or '') + (email_data['body']['full_html'] or '')

        if 'xn--' in content:
            return True, "Punycode détecté"

        if '%' in content and any(c in content for c in ['%20', '%3d', '%2f']):
            return True, "Encoding URL suspect"

        return False, "OK"

    # ========================================================================
    # UTILITAIRE : DISTANCE DE LEVENSHTEIN
    # ========================================================================

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calcule la distance de Levenshtein entre deux chaînes (typosquatting)."""
        if len(s1) < len(s2):
            return PhishingDetector._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]
