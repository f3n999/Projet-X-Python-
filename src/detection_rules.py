"""
DETECTION RULES - Moteur de detection heuristique
Mission : Appliquer 15+ regles pour identifier les signaux de phishing

Chaque regle retourne un tuple (bool, str) :
    - bool : True si la regle est declenchee (signal suspect)
    - str  : raison textuelle

Les patterns regex sont testables sur https://regex101.com
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

from bs4 import BeautifulSoup


# ============================================================================
# STRUCTURE D'UNE REGLE
# ============================================================================

@dataclass
class DetectionRule:
    """
    Represente une regle de detection.

    Attributs :
        name        : identifiant unique (ex: PASSWORD_REQUEST)
        description : explication de la regle
        weight      : importance de 1 a 10 dans le score final
    """
    name: str
    description: str
    weight: int


# ============================================================================
# MOTEUR DE DETECTION
# ============================================================================

class PhishingDetector:
    """
    Moteur de detection avec 15 regles heuristiques.

    Utilisation :
        detector = PhishingDetector()
        resultats = detector.analyze(parsed_email)
    """

    def __init__(self, keywords_file: str = None, domains_file: str = None):
        """
        Initialise le detecteur.

        Args:
            keywords_file : chemin vers phishing_keywords.txt (optionnel)
            domains_file  : chemin vers suspicious_domains.txt (optionnel)
        """
        # Charger les listes depuis les fichiers rules/
        self.phishing_keywords = self._load_list(keywords_file)
        self.suspicious_domains = self._load_list(domains_file)

        # Mots-cles par defaut si aucun fichier fourni
        self.default_keywords = [
            'verify', 'confirm', 'urgent', 'action required', 'click here',
            'update payment', 'suspended', 'locked', 'compromised',
            'reset password', 'confirm identity', 'verify account',
            'dear customer', 'dear client', 'prize', 'claim',
            'limited time', 'act now', 'banking', 'paypal',
            'amazon', 'apple', 'microsoft', 'google'
        ]

        # Domaines legitimes connus (pour detection de typosquatting)
        self.legitimate_domains = [
            'google.com', 'amazon.com', 'apple.com', 'microsoft.com',
            'paypal.com', 'facebook.com', 'chase.com', 'netflix.com',
            'linkedin.com', 'twitter.com', 'instagram.com', 'yahoo.com'
        ]

        # Initialiser les 15 regles
        self.rules = self._build_rules()

    # ========================================================================
    # CHARGEMENT DES FICHIERS
    # ========================================================================

    @staticmethod
    def _load_list(filepath: str) -> List[str]:
        """
        Charge une liste depuis un fichier texte (un element par ligne).
        Ignore les lignes vides et les commentaires (#).
        """
        if not filepath:
            return []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = []
                for line in f:
                    line = line.strip().lower()
                    # Ignorer les commentaires et lignes vides
                    if line and not line.startswith('#'):
                        lines.append(line)
                return lines
        except (OSError, IOError):
            return []

    # ========================================================================
    # DEFINITION DES 15 REGLES
    # ========================================================================

    @staticmethod
    def _build_rules() -> List[DetectionRule]:
        """Definit les 15 regles de detection avec leur poids."""
        return [
            DetectionRule('SUSPICIOUS_KEYWORDS_SUBJECT',
                          'Mots-cles de phishing dans le sujet', 8),
            DetectionRule('SUSPICIOUS_KEYWORDS_BODY',
                          'Mots-cles de phishing dans le corps', 7),
            DetectionRule('PASSWORD_REQUEST',
                          'Demande de mot de passe', 10),
            DetectionRule('SENSITIVE_DATA_REQUEST',
                          'Demande de donnees sensibles (SSN, carte...)', 10),
            DetectionRule('ARTIFICIAL_URGENCY',
                          'Langage creant une fausse urgence', 8),
            DetectionRule('DOMAIN_MISMATCH',
                          'Domaine du lien different du domaine expediteur', 9),
            DetectionRule('DOMAIN_LOOKALIKE',
                          'Domaine ressemblant a un domaine connu (typosquatting)', 9),
            DetectionRule('NO_AUTHENTICATION',
                          'Pas de header Authentication-Results', 6),
            DetectionRule('SPF_FAIL',
                          'Verification SPF echouee', 8),
            DetectionRule('SUSPICIOUS_HTML',
                          'Balises HTML dangereuses (script, iframe...)', 7),
            DetectionRule('SHORT_URL',
                          'URLs raccourcies (bit.ly, tinyurl...)', 7),
            DetectionRule('EXECUTABLE_ATTACHMENT',
                          'Piece jointe executable (.exe, .bat...)', 10),
            DetectionRule('SUSPICIOUS_SENDER',
                          'Adresse expediteur suspecte', 6),
            DetectionRule('IP_IN_URL',
                          'Adresse IP utilisee au lieu de domaine dans URL', 8),
            DetectionRule('ENCODING_OBFUSCATION',
                          'Utilisation de punycode ou encodage suspect', 7),
        ]

    # ========================================================================
    # ANALYSE PRINCIPALE
    # ========================================================================

    def analyze(self, parsed_email: Dict) -> Dict:
        """
        Lance toutes les regles de detection sur un email parse.

        Args:
            parsed_email : dictionnaire retourne par EmailParser.parse_eml_file()

        Returns:
            Dict : {
                'NOM_REGLE': {
                    'triggered': bool,
                    'reason': str,
                    'weight': int
                },
                ...
            }
        """
        results = {}

        for rule in self.rules:
            # getattr cherche dynamiquement la methode _check_nom_regle
            # Exemple : rule.name = 'PASSWORD_REQUEST'
            #        -> cherche self._check_password_request
            method_name = f'_check_{rule.name.lower()}'
            check_method = getattr(self, method_name)

            triggered, reason = check_method(parsed_email)

            results[rule.name] = {
                'triggered': triggered,
                'reason': reason,
                'weight': rule.weight
            }

        return results

    # ========================================================================
    # UTILITAIRES INTERNES
    # ========================================================================

    def _get_keywords(self) -> List[str]:
        """Retourne les mots-cles : fichier si charge, sinon defaut."""
        return self.phishing_keywords if self.phishing_keywords else self.default_keywords

    @staticmethod
    def _get_body_text(email_data: Dict) -> str:
        """Recupere le texte du corps, avec fallback vide."""
        return (email_data['body']['full_text'] or '').lower()

    @staticmethod
    def _get_body_html(email_data: Dict) -> str:
        """Recupere le HTML du corps, avec fallback vide."""
        return (email_data['body']['full_html'] or '').lower()

    # ========================================================================
    # IMPLEMENTATIONS DES 15 REGLES
    # ========================================================================

    # ---- REGLE 1 : Mots-cles suspects dans le sujet ----

    def _check_suspicious_keywords_subject(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Cherche des mots-cles de phishing dans le sujet.
        Un seul mot-cle suffit car le sujet est court.
        """
        subject = email_data['headers'].get('Subject', '').lower()
        keywords = self._get_keywords()

        # 'in' cherche une sous-chaine : 'urgent' in 'Urgent: Account' -> True
        found = [kw for kw in keywords if kw in subject]

        if found:
            return True, f"Mots-cles trouves : {', '.join(found[:3])}"
        return False, "OK"

    # ---- REGLE 2 : Mots-cles suspects dans le corps ----

    def _check_suspicious_keywords_body(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Cherche des mots-cles de phishing dans le corps.
        Seuil a 3+ mots-cles car le corps est long et peut contenir
        des mots courants par hasard.
        """
        body = self._get_body_text(email_data)[:2000]
        keywords = self._get_keywords()

        found = [kw for kw in keywords if kw in body]

        if len(found) > 2:
            return True, f"Mots-cles trouves : {', '.join(found[:3])}"
        return False, "OK"

    # ---- REGLE 3 : Demande de mot de passe ----

    def _check_password_request(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les demandes de mot de passe.

        Patterns regex (testables sur https://regex101.com) :
            reset.*password  -> 'reset your password' ou 'reset the password'
            Le .* signifie "n'importe quels caracteres entre les deux mots"
        """
        body = self._get_body_text(email_data)

        patterns = [
            r'reset.*password',
            r'confirm.*password',
            r'verify.*password',
            r'update.*credentials',
            r'enter.*password',
            r'mot de passe',
        ]

        # any() retourne True des qu'un pattern matche
        if any(re.search(p, body) for p in patterns):
            return True, "Demande de mot de passe detectee"
        return False, "OK"

    # ---- REGLE 4 : Demande de donnees sensibles ----

    def _check_sensitive_data_request(self, email_data: Dict) -> Tuple[bool, str]:
        """Detecte les demandes de SSN, numero de carte, CVV, etc."""
        body = self._get_body_text(email_data)

        patterns = [
            r'social\s*security', r'credit\s*card', r'card\s*number',
            r'cvv', r'expir', r'bank\s*account', r'swift\s*code',
            r'routing\s*number', r'pin\s*code', r'\bssn\b', r'\biban\b',
            r'numero\s*de\s*carte',
        ]

        if any(re.search(p, body) for p in patterns):
            return True, "Demande de donnees sensibles detectee"
        return False, "OK"

    # ---- REGLE 5 : Urgence artificielle ----

    def _check_artificial_urgency(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte le langage d'urgence. On exige au moins 2 indicateurs
        car un seul 'urgent' peut etre legitime.
        """
        body = self._get_body_text(email_data)

        patterns = [
            r'\burgent\b', r'\bimmediately\b', r'\basap\b',
            r'limited\s*time', r'act\s*now', r'click.*now',
            r'24\s*hour', r'will\s*be\s*closed', r'expire',
            r'dernier\s*avis', r'action\s*immediate',
        ]

        # sum() compte combien de patterns matchent
        count = sum(1 for p in patterns if re.search(p, body))

        if count >= 2:
            return True, f"{count} indicateurs d'urgence trouves"
        return False, "OK"

    # ---- REGLE 6 : Mismatch domaine expediteur vs URLs ----

    def _check_domain_mismatch(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Verifie que les URLs dans l'email pointent vers le meme domaine
        que l'expediteur. Si non, c'est suspect.

        Exemple suspect :
            From: security@paypal.com
            URL:  http://evil-site.com/login
        """
        from_email = email_data['headers'].get('From', '').lower()
        urls = email_data['urls']

        if not from_email or not urls:
            return False, "N/A (pas d'expediteur ou d'URLs)"

        # Extraire le domaine de l'expediteur
        # "User <user@paypal.com>" -> "paypal.com"
        if '@' not in from_email:
            return False, "N/A (pas de @ dans From)"

        from_domain = from_email.split('@')[-1].rstrip('>')

        for url in urls:
            if 'http' not in url.lower():
                continue

            # Extraire le domaine de l'URL
            # "https://evil.com/path" -> "evil.com"
            try:
                url_domain = url.split('//')[1].split('/')[0]
            except IndexError:
                continue

            if url_domain != from_domain and url_domain not in from_domain:
                return True, f"URL {url_domain} != expediteur {from_domain}"

        return False, "OK"

    # ---- REGLE 7 : Domaine lookalike (typosquatting) ----

    def _check_domain_lookalike(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les domaines qui ressemblent a des domaines connus.

        Utilise la distance de Levenshtein : le nombre minimum de
        modifications (ajout, suppression, remplacement d'un caractere)
        pour transformer une chaine en une autre.

        Exemple : 'amaz0n.com' vs 'amazon.com' -> distance = 1
        """
        urls = email_data['urls']
        lookalikes = []

        for url in urls:
            try:
                url_domain = url.split('//')[1].split('/')[0]
            except IndexError:
                continue

            for legit_domain in self.legitimate_domains:
                distance = self._levenshtein_distance(url_domain, legit_domain)
                # Distance 1-2 = probable typosquatting
                # Distance 0 = c'est le meme domaine (pas suspect)
                if 0 < distance <= 2:
                    lookalikes.append(f"{url_domain} (vs {legit_domain})")

        if lookalikes:
            return True, f"Lookalikes : {', '.join(lookalikes[:3])}"
        return False, "OK"

    # ---- REGLE 8 : Pas d'authentification ----

    def _check_no_authentication(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Verifie la presence du header Authentication-Results.
        Son absence signifie qu'aucun serveur n'a verifie l'expediteur.
        """
        has_auth = email_data['authentication']['has_auth']

        if not has_auth:
            return True, "Pas de header Authentication-Results"
        return False, "OK"

    # ---- REGLE 9 : SPF echoue ----

    def _check_spf_fail(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Verifie si SPF (Sender Policy Framework) a echoue.

        SPF verifie que le serveur d'envoi est autorise par le domaine.
        Resultats possibles : pass, fail, softfail, neutral, none
        """
        auth_raw = email_data['authentication']['raw'].lower()

        # Regex testables sur https://regex101.com
        fail_patterns = [r'spf=fail', r'spf=softfail', r'spf=neutral']

        if any(re.search(p, auth_raw) for p in fail_patterns):
            return True, "SPF echoue ou non-concluant"
        return False, "OK"

    # ---- REGLE 10 : HTML suspect ----

    def _check_suspicious_html(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les balises HTML dangereuses avec BeautifulSoup.

        Plus fiable que les regex car BS4 parse l'arbre HTML
        correctement, meme si le HTML est malformer.
        """
        html = self._get_body_html(email_data)
        if not html:
            return False, "OK (pas de HTML)"

        soup = BeautifulSoup(html, 'html.parser')

        # Chercher les balises dangereuses
        dangerous_tags = {
            'script': 'Balise <script> detectee',
            'iframe': 'Balise <iframe> detectee',
        }

        for tag_name, message in dangerous_tags.items():
            if soup.find(tag_name):
                return True, message

        # Chercher les attributs dangereux (onerror, onload, onclick...)
        # Ces attributs executent du JavaScript
        dangerous_attrs = ['onerror', 'onload', 'onclick', 'onmouseover']
        for attr in dangerous_attrs:
            if soup.find(attrs={attr: True}):
                return True, f"Attribut {attr} detecte"

        # Chercher javascript: dans les href
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if 'javascript:' in href:
                return True, "javascript: dans href"

        return False, "OK"

    # ---- REGLE 11 : URLs raccourcies ----

    def _check_short_url(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les services de raccourcissement d'URL.
        Utilises pour cacher la destination reelle du lien.
        """
        urls = email_data['urls']

        short_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
            't.co', 'is.gd', 'buff.ly', 'adf.ly',
            'tiny.cc', 'short.link', 'cutt.ly'
        ]

        found = [u for u in urls if any(s in u.lower() for s in short_services)]

        if found:
            return True, f"URLs raccourcies : {', '.join(found[:2])}"
        return False, "OK"

    # ---- REGLE 12 : Piece jointe executable ----

    def _check_executable_attachment(self, email_data: Dict) -> Tuple[bool, str]:
        """Detecte les pieces jointes avec des extensions dangereuses."""
        attachments = email_data['attachments']

        dangerous_exts = [
            '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd',
            '.com', '.pif', '.msi', '.ps1', '.wsf', '.hta'
        ]

        found = []
        for att in attachments:
            filename = att.get('filename', '').lower()
            if any(filename.endswith(ext) for ext in dangerous_exts):
                found.append(att['filename'])

        if found:
            return True, f"Fichiers dangereux : {', '.join(found)}"
        return False, "OK"

    # ---- REGLE 13 : Expediteur suspect ----

    def _check_suspicious_sender(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Verifie si l'adresse expediteur a un format suspect.

        Suspects : no-reply, noreply, notification, alert, system
        + domaines sans TLD valide
        """
        from_email = email_data['headers'].get('From', '').lower()

        # Patterns d'expediteur generiques (souvent usurpes)
        suspect_patterns = [
            r'no-?reply', r'notification', r'\balert\b',
            r'\bsystem\b', r'\bsecurity\b', r'\badmin\b'
        ]

        if any(re.search(p, from_email) for p in suspect_patterns):
            return True, "Format d'expediteur generique/suspect"

        # Verifier que le domaine a un TLD valide
        # Regex : un point suivi d'au moins 2 lettres a la fin
        if '@' in from_email:
            domain = from_email.split('@')[-1].rstrip('>')
            if not re.search(r'\.[a-z]{2,}$', domain):
                return True, f"Domaine invalide : {domain}"

        return False, "OK"

    # ---- REGLE 14 : IP dans URL ----

    def _check_ip_in_url(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les URLs qui utilisent une adresse IP au lieu d'un domaine.
        Exemple : http://192.168.1.1/login au lieu de http://bank.com/login

        Regex : https?:// suivi de 4 groupes de 1-3 chiffres
        Testable sur https://regex101.com
        """
        urls = email_data['urls']

        # Pattern : http(s)://123.456.789.012
        ip_url_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

        found = [u for u in urls if re.search(ip_url_pattern, u)]

        if found:
            return True, f"IP dans URL : {', '.join(found[:2])}"
        return False, "OK"

    # ---- REGLE 15 : Encodage suspect (obfuscation) ----

    def _check_encoding_obfuscation(self, email_data: Dict) -> Tuple[bool, str]:
        """
        Detecte les techniques d'obfuscation :
        - Punycode (xn--) : permet d'enregistrer des domaines en unicode
          Ex: xn--pple-43d.com ressemble a apple.com
        - URL encoding (%20, %3d...) : cache les vrais caracteres
        """
        text = self._get_body_text(email_data)
        html = self._get_body_html(email_data)
        content = text + html

        # Punycode : prefixe xn-- dans les domaines internationalises
        if 'xn--' in content:
            return True, "Punycode detecte (xn--)"

        # URL encoding abusif : %20=%espace, %3d=%=, %2f=%/
        url_encoded = ['%20', '%3d', '%2f', '%3a', '%40']
        if '%' in content and any(code in content for code in url_encoded):
            return True, "Encodage URL suspect"

        return False, "OK"

    # ========================================================================
    # ALGORITHME DE LEVENSHTEIN
    # ========================================================================

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """
        Calcule la distance de Levenshtein entre deux chaines.

        C'est le nombre minimum d'operations pour transformer s1 en s2 :
            - Insertion d'un caractere
            - Suppression d'un caractere
            - Remplacement d'un caractere

        Exemples :
            'amazon.com'  vs 'amaz0n.com'  -> 1 (remplacement o->0)
            'google.com'  vs 'gooogle.com' -> 1 (insertion d'un o)
            'paypal.com'  vs 'paypa1.com'  -> 1 (remplacement l->1)

        Algorithme : programmation dynamique, complexite O(n*m)
        """
        # Optimisation : toujours s1 >= s2 en longueur
        if len(s1) < len(s2):
            return PhishingDetector._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        # Ligne precedente de la matrice de distances
        previous_row = list(range(len(s2) + 1))

        for i, c1 in enumerate(s1):
            # Nouvelle ligne : commence a i+1
            current_row = [i + 1]

            for j, c2 in enumerate(s2):
                # Cout de chaque operation
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)

                # On garde le minimum des trois
                current_row.append(min(insertions, deletions, substitutions))

            previous_row = current_row

        return previous_row[-1]
