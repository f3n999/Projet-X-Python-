"""
DETECTION RULES - Moteur de détection heuristique
Mission: Appliquer 15+ règles pour identifier les signaux de phishing
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class DetectionRule:
    """Une règle de détection"""
    name: str
    description: str
    weight: int  # 1-10, poids dans le score final
    pattern: str = None
    check_func = None


class PhishingDetector:
    """Moteur de détection avec 15+ règles heuristiques"""
    
    def __init__(self, suspicious_domains_file=None, phishing_keywords_file=None):
        self.suspicious_domains = self._load_domain_list(suspicious_domains_file) if suspicious_domains_file else []
        self.phishing_keywords = self._load_keyword_list(phishing_keywords_file) if phishing_keywords_file else []
        
        # Listes par défaut (intégrées)
        self.default_phishing_keywords = [
            'verify', 'confirm', 'urgent', 'action required', 'click here',
            'update payment', 'suspended', 'locked', 'compromised', 'reset password',
            'confirm identity', 'verify account', 'dear customer', 'dear client',
            'prize', 'claim', 'limited time', 'act now', 'thank you',
            'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google'
        ]
        
        self.rules = self._initialize_rules()
    
    def _load_domain_list(self, filepath: str) -> List[str]:
        """Charge une liste de domaines d'un fichier"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except:
            return []
    
    def _load_keyword_list(self, filepath: str) -> List[str]:
        """Charge une liste de mots-clés d'un fichier"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except:
            return []
    
    def _initialize_rules(self) -> List[DetectionRule]:
        """Initialise les 15 règles de détection"""
        return [
            # RÈGLE 1: Mots-clés suspects dans le sujet
            DetectionRule(
                name='SUSPICIOUS_KEYWORDS_SUBJECT',
                description='Mots-clés phishing dans le sujet',
                weight=8
            ),
            
            # RÈGLE 2: Mots-clés suspects dans le corps
            DetectionRule(
                name='SUSPICIOUS_KEYWORDS_BODY',
                description='Mots-clés phishing dans le corps',
                weight=7
            ),
            
            # RÈGLE 3: Demande de mots de passe
            DetectionRule(
                name='PASSWORD_REQUEST',
                description='Demande de réinitialisation de mot de passe',
                weight=10
            ),
            
            # RÈGLE 4: Demande de données sensibles
            DetectionRule(
                name='SENSITIVE_DATA_REQUEST',
                description='Demande de SSN, numéro de carte, etc.',
                weight=10
            ),
            
            # RÈGLE 5: Urgence artificielle
            DetectionRule(
                name='ARTIFICIAL_URGENCY',
                description='Langage créant une fausse urgence',
                weight=8
            ),
            
            # RÈGLE 6: URL suspecte (domaine != from)
            DetectionRule(
                name='DOMAIN_MISMATCH',
                description='Domaine du lien ≠ domaine de l\'expéditeur',
                weight=9
            ),
            
            # RÈGLE 7: Domaine misspelling (lookalike)
            DetectionRule(
                name='DOMAIN_LOOKALIKE',
                description='Domaine qui ressemble à un domaine connu',
                weight=9
            ),
            
            # RÈGLE 8: Pas d'authentification SPF/DKIM
            DetectionRule(
                name='NO_AUTHENTICATION',
                description='Pas de résultat Authentication-Results',
                weight=6
            ),
            
            # RÈGLE 9: Sender Policy Framework échouée
            DetectionRule(
                name='SPF_FAIL',
                description='SPF échoué ou soft fail',
                weight=8
            ),
            
            # RÈGLE 10: HTML suspecte (balises script)
            DetectionRule(
                name='SUSPICIOUS_HTML',
                description='Présence de scripts ou balises dangereuses',
                weight=7
            ),
            
            # RÈGLE 11: Courtes URLs (bit.ly, tinyurl)
            DetectionRule(
                name='SHORT_URL',
                description='URLs raccourcies suspectes',
                weight=7
            ),
            
            # RÈGLE 12: Pièce jointe exécutable
            DetectionRule(
                name='EXECUTABLE_ATTACHMENT',
                description='Pièce jointe .exe, .bat, .scr, etc.',
                weight=10
            ),
            
            # RÈGLE 13: Adresse expéditeur suspecte
            DetectionRule(
                name='SUSPICIOUS_SENDER',
                description='Format d\'adresse expéditeur suspect',
                weight=6
            ),
            
            # RÈGLE 14: IP dans URL
            DetectionRule(
                name='IP_IN_URL',
                description='Utilisation d\'IP directe au lieu de domaine',
                weight=8
            ),
            
            # RÈGLE 15: Encoding suspect
            DetectionRule(
                name='ENCODING_OBFUSCATION',
                description='Utilisation de punycode ou unicode suspect',
                weight=7
            )
        ]
    
    def analyze(self, parsed_email: Dict) -> Dict[str, Tuple[bool, str]]:
        """
        Lance toutes les règles de détection
        
        Returns:
            Dict avec résultats: {'RULE_NAME': (triggered, reason)}
        """
        results = {}
        
        for rule in self.rules:
            triggered, reason = getattr(self, f'_check_{rule.name.lower()}')(parsed_email)
            results[rule.name] = {
                'triggered': triggered,
                'reason': reason,
                'weight': rule.weight
            }
        
        return results
    
    # ===== IMPLÉMENTATIONS DES RÈGLES =====
    
    def _check_suspicious_keywords_subject(self, email: Dict) -> Tuple[bool, str]:
        subject = email['headers'].get('Subject', '').lower()
        keywords = self.phishing_keywords or self.default_phishing_keywords
        found = [kw for kw in keywords if kw in subject]
        return len(found) > 0, f"Trouvés: {', '.join(found[:3])}" if found else "OK"
    
    def _check_suspicious_keywords_body(self, email: Dict) -> Tuple[bool, str]:
        body = (email['body']['full_text'] or '').lower()[:1000]
        keywords = self.phishing_keywords or self.default_phishing_keywords
        found = [kw for kw in keywords if kw in body]
        return len(found) > 2, f"Trouvés: {', '.join(found[:3])}" if len(found) > 2 else "OK"
    
    def _check_password_request(self, email: Dict) -> Tuple[bool, str]:
        content = (email['body']['full_text'] or '').lower()
        patterns = [
            r'reset.*password', r'confirm.*password', r'verify.*password',
            r'update.*credentials', r'enter.*password'
        ]
        found = any(re.search(p, content) for p in patterns)
        return found, "Demande de mot de passe détectée" if found else "OK"
    
    def _check_sensitive_data_request(self, email: Dict) -> Tuple[bool, str]:
        content = (email['body']['full_text'] or '').lower()
        patterns = [
            r'ssn', r'social security', r'credit card', r'card number',
            r'cvv', r'expir', r'bank account', r'swift code',
            r'routing number', r'pin code'
        ]
        found = any(re.search(p, content) for p in patterns)
        return found, "Demande de données sensibles" if found else "OK"
    
    def _check_artificial_urgency(self, email: Dict) -> Tuple[bool, str]:
        content = (email['body']['full_text'] or '').lower()
        patterns = [r'urgent', r'immediately', r'asap', r'limited time',
                   r'act now', r'click.*now', r'24.*hour', r'will be closed']
        count = sum(1 for p in patterns if re.search(p, content))
        return count >= 2, f"{count} indicateurs d'urgence trouvés" if count >= 2 else "OK"
    
    def _check_domain_mismatch(self, email: Dict) -> Tuple[bool, str]:
        from_email = email['headers'].get('From', '').lower()
        urls = email['urls']
        
        if not from_email or not urls:
            return False, "N/A (pas de from ou URLs)"
        
        from_domain = from_email.split('@')[-1].rstrip('>')
        
        for url in urls:
            if 'http' in url.lower():
                url_domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
                if url_domain != from_domain and url_domain not in from_domain:
                    return True, f"Domaine URL {url_domain} ≠ domaine from {from_domain}"
        
        return False, "OK"
    
    def _check_domain_lookalike(self, email: Dict) -> Tuple[bool, str]:
        urls = email['urls']
        
        # Domaines légitime connus
        legitimate_domains = [
            'amazon.com', 'apple.com', 'microsoft.com', 'google.com',
            'paypal.com', 'facebook.com', 'banking.com', 'chase.com'
        ]
        
        lookalikes = []
        for url in urls:
            url_domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
            
            for legit in legitimate_domains:
                # Typosquatting detection simple
                if self._levenshtein_distance(url_domain, legit) <= 2:
                    lookalikes.append(url_domain)
        
        return len(lookalikes) > 0, f"Lookalikes détectés: {lookalikes}" if lookalikes else "OK"
    
    def _check_no_authentication(self, email: Dict) -> Tuple[bool, str]:
        has_auth = email['authentication']['has_auth']
        return not has_auth, "Pas d'Authentication-Results" if not has_auth else "OK"
    
    def _check_spf_fail(self, email: Dict) -> Tuple[bool, str]:
        auth_results = email['authentication']['raw'].lower()
        spf_patterns = [r'spf=fail', r'spf=softfail', r'spf=neutral']
        failed = any(re.search(p, auth_results) for p in spf_patterns)
        return failed, "SPF échouée" if failed else "OK"
    
    def _check_suspicious_html(self, email: Dict) -> Tuple[bool, str]:
        html = (email['body']['full_html'] or '').lower()
        patterns = [r'<script', r'javascript:', r'<iframe', r'onerror=', r'onload=']
        found = any(re.search(p, html) for p in patterns)
        return found, "Contenu HTML suspect" if found else "OK"
    
    def _check_short_url(self, email: Dict) -> Tuple[bool, str]:
        urls = email['urls']
        short_url_services = ['bit.ly', 'tinyurl', 'goo.gl', 'short.link', 'ow.ly']
        found = [u for u in urls if any(s in u for s in short_url_services)]
        return len(found) > 0, f"URLs raccourcies: {found}" if found else "OK"
    
    def _check_executable_attachment(self, email: Dict) -> Tuple[bool, str]:
        attachments = email['attachments']
        dangerous_exts = ['.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.com', '.pif']
        found = [a for a in attachments if any(a['filename'].lower().endswith(ext) for ext in dangerous_exts)]
        return len(found) > 0, f"Fichiers dangereux: {[a['filename'] for a in found]}" if found else "OK"
    
    def _check_suspicious_sender(self, email: Dict) -> Tuple[bool, str]:
        from_email = email['headers'].get('From', '').lower()
        
        # Format: user@domain.com ou "User" <user@domain.com>
        patterns = [r'no-reply', r'noreply', r'notification', r'alert', r'system']
        if any(re.search(p, from_email) for p in patterns):
            return True, "Format d'expéditeur suspect"
        
        # Pas de TLD valide
        if '@' in from_email:
            domain = from_email.split('@')[-1].rstrip('>')
            if not re.search(r'\.[a-z]{2,}$', domain):
                return True, f"Domaine invalide: {domain}"
        
        return False, "OK"
    
    def _check_ip_in_url(self, email: Dict) -> Tuple[bool, str]:
        urls = email['urls']
        ip_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        found = [u for u in urls if re.search(ip_pattern, u)]
        return len(found) > 0, f"IPs détectées: {found}" if found else "OK"
    
    def _check_encoding_obfuscation(self, email: Dict) -> Tuple[bool, str]:
        content = email['body']['full_text'] + email['body']['full_html']
        
        # Punycode xn--
        if 'xn--' in content:
            return True, "Punycode détecté"
        
        # Unicode suspects
        if '%' in content and any(c in content for c in ['%20', '%3d', '%2f']):
            return True, "Encoding URL suspect"
        
        return False, "OK"
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Distance de Levenshtein pour détecter les typosquatting"""
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
