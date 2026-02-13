"""
DETECTION RULES - 15 regles pour detecter le phishing
Chaque regle analyse un aspect de l'email et retourne :
    - True/False : si la regle est declenchee
    - Une raison textuelle

Librairies :
    - re (stdlib) : expressions regulieres
    - bs4 (externe) : BeautifulSoup pour analyser le HTML
"""

import re
from pathlib import Path
from bs4 import BeautifulSoup


class PhishingDetector:
    """
    Detecteur de phishing avec 15 regles heuristiques.

    Utilisation :
        detector = PhishingDetector()
        resultats = detector.analyze(email_parse)
    """

    def __init__(self, keywords_file=None, domains_file=None):
        """
        Initialise le detecteur.

        Args:
            keywords_file : chemin vers phishing_keywords.txt (optionnel)
            domains_file  : chemin vers suspicious_domains.txt (optionnel)
        """
        # Charger les mots-cles depuis le fichier (si fourni)
        self.phishing_keywords = self.charger_liste(keywords_file)

        # Charger les domaines suspects (si fourni)
        self.suspicious_domains = self.charger_liste(domains_file)

        # Mots-cles par defaut si aucun fichier fourni
        self.default_keywords = [
            'verify', 'confirm', 'urgent', 'action required', 'click here',
            'update payment', 'suspended', 'locked', 'compromised',
            'reset password', 'confirm identity', 'verify account',
            'dear customer', 'dear client', 'prize', 'claim',
            'limited time', 'act now', 'banking', 'paypal',
            'amazon', 'apple', 'microsoft', 'google'
        ]

        # Domaines legitimes connus (pour detecter le typosquatting)
        self.legitimate_domains = [
            'google.com', 'amazon.com', 'apple.com', 'microsoft.com',
            'paypal.com', 'facebook.com', 'chase.com', 'netflix.com',
            'linkedin.com', 'twitter.com', 'instagram.com', 'yahoo.com'
        ]

        # Definition des 15 regles avec leur poids (importance de 6 a 10)
        # Le poids represente la gravite du signal
        self.regles = [
            {'name': 'SUSPICIOUS_KEYWORDS_SUBJECT', 'description': 'Mots-cles phishing dans le sujet', 'weight': 8},
            {'name': 'SUSPICIOUS_KEYWORDS_BODY', 'description': 'Mots-cles phishing dans le corps', 'weight': 7},
            {'name': 'PASSWORD_REQUEST', 'description': 'Demande de mot de passe', 'weight': 10},
            {'name': 'SENSITIVE_DATA_REQUEST', 'description': 'Demande de donnees sensibles', 'weight': 10},
            {'name': 'ARTIFICIAL_URGENCY', 'description': 'Langage creant une fausse urgence', 'weight': 8},
            {'name': 'DOMAIN_MISMATCH', 'description': 'Domaine URL != domaine expediteur', 'weight': 9},
            {'name': 'DOMAIN_LOOKALIKE', 'description': 'Typosquatting (domaine similaire)', 'weight': 9},
            {'name': 'NO_AUTHENTICATION', 'description': 'Pas de header Authentication-Results', 'weight': 6},
            {'name': 'SPF_FAIL', 'description': 'Verification SPF echouee', 'weight': 8},
            {'name': 'SUSPICIOUS_HTML', 'description': 'Balises HTML dangereuses', 'weight': 7},
            {'name': 'SHORT_URL', 'description': 'URLs raccourcies (bit.ly...)', 'weight': 7},
            {'name': 'EXECUTABLE_ATTACHMENT', 'description': 'Piece jointe executable', 'weight': 10},
            {'name': 'SUSPICIOUS_SENDER', 'description': 'Expediteur suspect', 'weight': 6},
            {'name': 'IP_IN_URL', 'description': 'Adresse IP dans une URL', 'weight': 8},
            {'name': 'ENCODING_OBFUSCATION', 'description': 'Encodage suspect (punycode)', 'weight': 7},
        ]

    def charger_liste(self, filepath):
        """
        Charge une liste depuis un fichier texte (un element par ligne).
        Ignore les lignes vides et les commentaires (#).
        """
        if not filepath:
            return []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lignes = []
                for line in f:
                    line = line.strip().lower()
                    # Ignorer les commentaires et les lignes vides
                    if line and not line.startswith('#'):
                        lignes.append(line)
                return lignes
        except Exception:
            return []

    def get_keywords(self):
        """Retourne les mots-cles : depuis le fichier si charge, sinon ceux par defaut."""
        if self.phishing_keywords:
            return self.phishing_keywords
        return self.default_keywords

    def analyze(self, email_data):
        """
        Lance les 15 regles de detection sur un email parse.

        Args:
            email_data : dictionnaire retourne par EmailParser.parse_eml_file()

        Returns:
            Un dictionnaire avec le resultat de chaque regle :
            {
                'NOM_REGLE': {
                    'triggered': True/False,
                    'reason': 'explication',
                    'weight': poids
                }
            }
        """
        results = {}

        # Pour chaque regle, on appelle la methode correspondante
        for regle in self.regles:
            nom = regle['name']

            # Appeler la bonne methode selon le nom de la regle
            if nom == 'SUSPICIOUS_KEYWORDS_SUBJECT':
                triggered, reason = self.check_keywords_subject(email_data)
            elif nom == 'SUSPICIOUS_KEYWORDS_BODY':
                triggered, reason = self.check_keywords_body(email_data)
            elif nom == 'PASSWORD_REQUEST':
                triggered, reason = self.check_password_request(email_data)
            elif nom == 'SENSITIVE_DATA_REQUEST':
                triggered, reason = self.check_sensitive_data(email_data)
            elif nom == 'ARTIFICIAL_URGENCY':
                triggered, reason = self.check_urgency(email_data)
            elif nom == 'DOMAIN_MISMATCH':
                triggered, reason = self.check_domain_mismatch(email_data)
            elif nom == 'DOMAIN_LOOKALIKE':
                triggered, reason = self.check_domain_lookalike(email_data)
            elif nom == 'NO_AUTHENTICATION':
                triggered, reason = self.check_no_auth(email_data)
            elif nom == 'SPF_FAIL':
                triggered, reason = self.check_spf_fail(email_data)
            elif nom == 'SUSPICIOUS_HTML':
                triggered, reason = self.check_suspicious_html(email_data)
            elif nom == 'SHORT_URL':
                triggered, reason = self.check_short_url(email_data)
            elif nom == 'EXECUTABLE_ATTACHMENT':
                triggered, reason = self.check_executable_attachment(email_data)
            elif nom == 'SUSPICIOUS_SENDER':
                triggered, reason = self.check_suspicious_sender(email_data)
            elif nom == 'IP_IN_URL':
                triggered, reason = self.check_ip_in_url(email_data)
            elif nom == 'ENCODING_OBFUSCATION':
                triggered, reason = self.check_encoding_obfuscation(email_data)
            else:
                triggered, reason = False, "Regle inconnue"

            results[nom] = {
                'triggered': triggered,
                'reason': reason,
                'weight': regle['weight'],
            }

        return results

    # ================================================================
    # LES 15 REGLES DE DETECTION
    # ================================================================

    # ---- REGLE 1 : Mots-cles suspects dans le sujet ----
    def check_keywords_subject(self, email_data):
        """Cherche des mots-cles de phishing dans le sujet."""
        subject = email_data['headers'].get('Subject', '').lower()
        keywords = self.get_keywords()

        # Chercher chaque mot-cle dans le sujet
        trouves = []
        for kw in keywords:
            if kw in subject:
                trouves.append(kw)

        if trouves:
            return True, "Mots-cles trouves : " + ", ".join(trouves[:3])
        return False, "OK"

    # ---- REGLE 2 : Mots-cles suspects dans le corps ----
    def check_keywords_body(self, email_data):
        """
        Cherche des mots-cles dans le corps.
        On exige 3+ mots-cles car le corps est long.
        """
        body = (email_data['body']['full_text'] or '').lower()[:2000]
        keywords = self.get_keywords()

        trouves = []
        for kw in keywords:
            if kw in body:
                trouves.append(kw)

        # Seuil : au moins 3 mots-cles pour declencher
        if len(trouves) > 2:
            return True, "Mots-cles trouves : " + ", ".join(trouves[:3])
        return False, "OK"

    # ---- REGLE 3 : Demande de mot de passe ----
    def check_password_request(self, email_data):
        """Detecte les demandes de mot de passe dans le corps."""
        body = (email_data['body']['full_text'] or '').lower()

        # re.search() cherche un pattern dans le texte
        # .* = n'importe quoi entre les deux mots
        patterns = [
            r'reset.*password',
            r'confirm.*password',
            r'verify.*password',
            r'update.*credentials',
            r'enter.*password',
            r'mot de passe',
        ]

        for pattern in patterns:
            if re.search(pattern, body):
                return True, "Demande de mot de passe detectee"
        return False, "OK"

    # ---- REGLE 4 : Demande de donnees sensibles ----
    def check_sensitive_data(self, email_data):
        """Detecte les demandes de SSN, numero de carte, CVV, etc."""
        body = (email_data['body']['full_text'] or '').lower()

        patterns = [
            r'social\s*security', r'credit\s*card', r'card\s*number',
            r'cvv', r'expir', r'bank\s*account',
            r'\bssn\b', r'\biban\b', r'numero\s*de\s*carte',
        ]

        for pattern in patterns:
            if re.search(pattern, body):
                return True, "Demande de donnees sensibles detectee"
        return False, "OK"

    # ---- REGLE 5 : Urgence artificielle ----
    def check_urgency(self, email_data):
        """
        Detecte le langage d'urgence.
        On exige au moins 2 indicateurs (un seul 'urgent' peut etre normal).
        """
        body = (email_data['body']['full_text'] or '').lower()

        patterns = [
            r'\burgent\b', r'\bimmediately\b', r'\basap\b',
            r'limited\s*time', r'act\s*now', r'click.*now',
            r'24\s*hour', r'will\s*be\s*closed', r'expire',
            r'dernier\s*avis', r'action\s*immediate',
        ]

        # Compter combien de patterns sont trouves
        compteur = 0
        for pattern in patterns:
            if re.search(pattern, body):
                compteur = compteur + 1

        if compteur >= 2:
            return True, str(compteur) + " indicateurs d'urgence trouves"
        return False, "OK"

    # ---- REGLE 6 : Domaine expediteur != domaine des URLs ----
    def check_domain_mismatch(self, email_data):
        """
        Verifie que les URLs pointent vers le meme domaine que l'expediteur.

        Exemple suspect :
            From: security@paypal.com
            URL:  http://evil-site.com/login
        """
        from_email = email_data['headers'].get('From', '').lower()
        urls = email_data['urls']

        if not from_email or not urls:
            return False, "N/A"

        # Extraire le domaine de l'expediteur
        if '@' not in from_email:
            return False, "N/A"

        # "user@paypal.com" -> "paypal.com"
        from_domain = from_email.split('@')[-1].rstrip('>')

        for url in urls:
            if 'http' not in url.lower():
                continue

            # Extraire le domaine de l'URL : "https://evil.com/path" -> "evil.com"
            try:
                url_domain = url.split('//')[1].split('/')[0]
            except IndexError:
                continue

            # Si le domaine de l'URL est different de celui de l'expediteur
            if url_domain != from_domain and url_domain not in from_domain:
                return True, "URL " + url_domain + " != expediteur " + from_domain

        return False, "OK"

    # ---- REGLE 7 : Typosquatting (domaine qui ressemble a un vrai) ----
    def check_domain_lookalike(self, email_data):
        """
        Detecte les domaines qui ressemblent a des domaines connus.

        Exemple : 'amaz0n.com' ressemble a 'amazon.com' (le o est remplace par 0)

        On utilise la distance de Levenshtein : le nombre minimum de
        modifications pour transformer un mot en un autre.
        """
        urls = email_data['urls']
        lookalikes = []

        for url in urls:
            # Extraire le domaine de l'URL
            try:
                url_domain = url.split('//')[1].split('/')[0]
            except IndexError:
                continue

            # Comparer avec chaque domaine legitime
            for legit in self.legitimate_domains:
                distance = self.levenshtein(url_domain, legit)
                # Distance 1-2 = probablement du typosquatting
                # Distance 0 = c'est le meme domaine (pas suspect)
                if 0 < distance <= 2:
                    lookalikes.append(url_domain + " (vs " + legit + ")")

        if lookalikes:
            return True, "Lookalikes : " + ", ".join(lookalikes[:3])
        return False, "OK"

    # ---- REGLE 8 : Pas d'authentification ----
    def check_no_auth(self, email_data):
        """Verifie la presence du header Authentication-Results."""
        has_auth = email_data['authentication']['has_auth']
        if not has_auth:
            return True, "Pas de header Authentication-Results"
        return False, "OK"

    # ---- REGLE 9 : SPF echoue ----
    def check_spf_fail(self, email_data):
        """
        Verifie si SPF a echoue.
        SPF verifie que le serveur d'envoi est autorise par le domaine.
        """
        auth_raw = email_data['authentication']['raw'].lower()

        # Chercher "spf=fail" ou "spf=softfail" dans le header
        if re.search(r'spf=fail', auth_raw):
            return True, "SPF echoue"
        if re.search(r'spf=softfail', auth_raw):
            return True, "SPF softfail"
        if re.search(r'spf=neutral', auth_raw):
            return True, "SPF neutral"

        return False, "OK"

    # ---- REGLE 10 : HTML suspect ----
    def check_suspicious_html(self, email_data):
        """
        Detecte les balises HTML dangereuses avec BeautifulSoup.
        Les balises <script> et <iframe> sont suspectes dans un email.
        """
        html = (email_data['body']['full_html'] or '').lower()
        if not html:
            return False, "OK (pas de HTML)"

        # BeautifulSoup parse le HTML en arbre
        soup = BeautifulSoup(html, 'html.parser')

        # Chercher les balises dangereuses
        if soup.find('script'):
            return True, "Balise <script> detectee"
        if soup.find('iframe'):
            return True, "Balise <iframe> detectee"

        # Chercher les attributs JavaScript (onclick, onload...)
        for attr in ['onerror', 'onload', 'onclick', 'onmouseover']:
            if soup.find(attrs={attr: True}):
                return True, "Attribut " + attr + " detecte"

        # Chercher javascript: dans les liens
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if 'javascript:' in href:
                return True, "javascript: dans href"

        return False, "OK"

    # ---- REGLE 11 : URLs raccourcies ----
    def check_short_url(self, email_data):
        """Detecte les services de raccourcissement d'URL (bit.ly, tinyurl...)."""
        urls = email_data['urls']

        short_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
            't.co', 'is.gd', 'buff.ly', 'cutt.ly'
        ]

        for url in urls:
            for service in short_services:
                if service in url.lower():
                    return True, "URL raccourcie : " + url
        return False, "OK"

    # ---- REGLE 12 : Piece jointe executable ----
    def check_executable_attachment(self, email_data):
        """Detecte les pieces jointes avec des extensions dangereuses."""
        attachments = email_data['attachments']

        dangerous_exts = [
            '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd',
            '.msi', '.ps1', '.wsf', '.hta'
        ]

        for att in attachments:
            filename = att.get('filename', '').lower()
            for ext in dangerous_exts:
                if filename.endswith(ext):
                    return True, "Fichier dangereux : " + att['filename']
        return False, "OK"

    # ---- REGLE 13 : Expediteur suspect ----
    def check_suspicious_sender(self, email_data):
        """Verifie si l'adresse expediteur a un format suspect."""
        from_email = email_data['headers'].get('From', '').lower()

        # Patterns d'expediteur generiques (souvent usurpes)
        patterns = [
            r'no-?reply', r'notification', r'\balert\b',
            r'\bsystem\b', r'\bsecurity\b', r'\badmin\b'
        ]

        for pattern in patterns:
            if re.search(pattern, from_email):
                return True, "Expediteur generique/suspect"

        # Verifier que le domaine a un TLD valide (ex: .com, .fr)
        if '@' in from_email:
            domain = from_email.split('@')[-1].rstrip('>')
            if not re.search(r'\.[a-z]{2,}$', domain):
                return True, "Domaine invalide : " + domain

        return False, "OK"

    # ---- REGLE 14 : IP dans URL ----
    def check_ip_in_url(self, email_data):
        """
        Detecte les URLs qui utilisent une IP au lieu d'un domaine.
        Exemple : http://192.168.1.1/login
        """
        urls = email_data['urls']

        # Pattern : http(s)://123.456.789.012
        pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

        for url in urls:
            if re.search(pattern, url):
                return True, "IP dans URL : " + url
        return False, "OK"

    # ---- REGLE 15 : Encodage suspect ----
    def check_encoding_obfuscation(self, email_data):
        """
        Detecte les techniques d'obfuscation :
        - Punycode (xn--) : domaines unicode deguises
        - URL encoding (%20, %3d...) : caracteres caches
        """
        text = (email_data['body']['full_text'] or '').lower()
        html = (email_data['body']['full_html'] or '').lower()
        contenu = text + html

        # Punycode
        if 'xn--' in contenu:
            return True, "Punycode detecte (xn--)"

        # URL encoding abusif
        codes_suspects = ['%20', '%3d', '%2f', '%3a', '%40']
        if '%' in contenu:
            for code in codes_suspects:
                if code in contenu:
                    return True, "Encodage URL suspect"

        return False, "OK"

    # ================================================================
    # ALGORITHME DE LEVENSHTEIN (distance entre deux mots)
    # ================================================================

    def levenshtein(self, mot1, mot2):
        """
        Calcule la distance de Levenshtein entre deux mots.

        C'est le nombre minimum de modifications pour transformer mot1 en mot2 :
            - Ajouter un caractere
            - Supprimer un caractere
            - Remplacer un caractere

        Exemples :
            'amazon.com' vs 'amaz0n.com' -> distance = 1
            'paypal.com' vs 'paypa1.com' -> distance = 1
        """
        # S'assurer que mot1 est le plus long
        if len(mot1) < len(mot2):
            return self.levenshtein(mot2, mot1)

        if len(mot2) == 0:
            return len(mot1)

        # Ligne precedente de la matrice
        ligne_precedente = list(range(len(mot2) + 1))

        for i in range(len(mot1)):
            # Nouvelle ligne
            ligne_courante = [i + 1]

            for j in range(len(mot2)):
                # Cout : 0 si meme caractere, 1 sinon
                if mot1[i] != mot2[j]:
                    cout = 1
                else:
                    cout = 0

                insertion = ligne_precedente[j + 1] + 1
                suppression = ligne_courante[j] + 1
                remplacement = ligne_precedente[j] + cout

                # Garder le minimum des trois operations
                ligne_courante.append(min(insertion, suppression, remplacement))

            ligne_precedente = ligne_courante

        return ligne_precedente[-1]
