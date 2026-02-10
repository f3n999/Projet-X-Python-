"""
EMAIL PARSER - Extraction des donnees d'un email
Mission : Transformer un fichier .eml brut en dictionnaire Python exploitable

Librairies utilisees :
    - email (stdlib)  : lecture du format .eml (RFC 2822)
    - re (stdlib)     : expressions regulieres pour extraire URLs, IPs, emails
    - hashlib (stdlib): calcul de hash MD5/SHA256 des pieces jointes
    - bs4 (externe)   : BeautifulSoup pour extraire proprement les liens du HTML
    - email.header    : decodage des en-tetes encodes RFC 2047
"""

import email
import email.policy
import re
import hashlib
from pathlib import Path
from typing import Dict, List
from email.header import decode_header

from bs4 import BeautifulSoup


# ============================================================================
# CONSTANTES
# ============================================================================

# En-tetes que l'on veut recuperer dans l'email
HEADERS_OF_INTEREST = [
    'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date',
    'Return-Path', 'Reply-To', 'Received',
    'Authentication-Results', 'DKIM-Signature', 'SPF'
]

# Extensions de fichiers considerees comme dangereuses
# Source : OWASP + CERT-FR
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.com', '.pif',
    '.msi', '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg',
    '.ps1', '.wsf', '.hta', '.cpl'
]

# ---- Regex patterns ----
# On compile les regex une seule fois (performance)
# Tester sur https://regex101.com pour comprendre chaque pattern

# Adresse email : partie_locale @ domaine . extension
# Ex: user.name+tag@example.co.uk
EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
)

# URL commencant par http:// ou https:// ou www.
# On capture tout jusqu'a un espace ou caractere de fermeture
URL_REGEX = re.compile(
    r'https?://[^\s\)>\]<"\']+|www\.[^\s\)>\]<"\']+\.[a-z]+'
)

# Adresse IPv4 : 4 groupes de 1-3 chiffres separes par des points
# Ex: 192.168.1.1
IP_REGEX = re.compile(
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
)


# ============================================================================
# CLASSE PRINCIPALE
# ============================================================================

class EmailParser:
    """
    Parse les fichiers .eml et extrait les donnees critiques.

    Utilisation :
        parser = EmailParser()
        resultat = parser.parse_eml_file('email.eml')
    """

    def __init__(self):
        self.headers_of_interest = HEADERS_OF_INTEREST

    # ========================================================================
    # POINT D'ENTREE PRINCIPAL
    # ========================================================================

    def parse_eml_file(self, file_path: str) -> Dict:
        """
        Parse un fichier .eml et retourne un dictionnaire structure.

        Args:
            file_path: chemin vers le fichier .eml

        Returns:
            Dict contenant : headers, body, urls, emails, ips,
                             attachments, authentication
        """
        # Verifier que le fichier existe
        path = Path(file_path)
        if not path.exists():
            return {'error': f'Fichier introuvable : {file_path}'}

        # Lire le fichier en mode binaire (rb)
        # car un .eml peut contenir des pieces jointes binaires
        try:
            with open(file_path, 'rb') as f:
                # policy=email.policy.default retourne un EmailMessage
                # (au lieu de Message) qui supporte iter_attachments()
                msg = email.message_from_binary_file(f, policy=email.policy.default)
        except (OSError, IOError) as e:
            return {'error': f'Impossible de lire le fichier : {e}'}

        # Extraire toutes les donnees et les retourner
        return {
            'file_path': file_path,
            'headers': self._extract_headers(msg),
            'body': self._extract_body(msg),
            'urls': self._extract_urls(msg),
            'emails': self._extract_emails(msg),
            'ips': self._extract_ips(msg),
            'attachments': self._extract_attachments(msg),
            'authentication': self._extract_auth_results(msg)
        }

    # ========================================================================
    # EXTRACTION DES EN-TETES
    # ========================================================================

    def _extract_headers(self, msg) -> Dict:
        """
        Extrait les en-tetes importants de l'email.

        Certains en-tetes sont encodes en RFC 2047 (ex: =?UTF-8?B?...).
        On les decode automatiquement avec _decode_header_value.
        """
        headers = {}

        for key in self.headers_of_interest:
            # msg.get() retourne la valeur du header ou 'N/A' si absent
            value = msg.get(key, 'N/A')

            if value and value != 'N/A':
                headers[key] = self._decode_header_value(value)
            else:
                headers[key] = value

        return headers

    @staticmethod
    def _decode_header_value(header_value: str) -> str:
        """
        Decode un en-tete encode en RFC 2047.

        Exemple :
            =?UTF-8?B?VXJnZW50?= -> 'Urgent'
            =?iso-8859-1?Q?R=E9sum=E9?= -> 'Résumé'

        La fonction decode_header() de Python separe les morceaux,
        puis on les reassemble en une seule chaine.
        """
        try:
            decoded_parts = decode_header(header_value)
            result = ''

            for content, encoding in decoded_parts:
                # Si c'est des bytes, on decode avec l'encoding indique
                if isinstance(content, bytes):
                    result += content.decode(encoding or 'utf-8', errors='ignore')
                else:
                    result += content

            return result
        except (ValueError, UnicodeDecodeError):
            return header_value

    # ========================================================================
    # EXTRACTION DU CORPS
    # ========================================================================

    def _extract_body(self, msg) -> Dict:
        """
        Extrait le corps de l'email en version texte brut et HTML.

        Un email peut etre :
        - multipart : plusieurs parties (texte + HTML + pieces jointes)
        - simple    : une seule partie (texte brut)

        msg.walk() parcourt recursivement toutes les parties.
        """
        body_text = ''
        body_html = ''

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                try:
                    # get_payload(decode=True) decode le base64/quoted-printable
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue

                    # Recuperer le charset de la partie (utf-8 par defaut)
                    charset = part.get_content_charset() or 'utf-8'
                    decoded = payload.decode(charset, errors='ignore')

                    if content_type == 'text/plain':
                        body_text = decoded
                    elif content_type == 'text/html':
                        body_html = decoded

                except (UnicodeDecodeError, AttributeError, LookupError):
                    continue
        else:
            # Email simple (pas multipart)
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body_text = payload.decode(charset, errors='ignore')
            except (UnicodeDecodeError, AttributeError, LookupError):
                pass

        return {
            'text': body_text[:500],      # Apercu (500 premiers caracteres)
            'html': body_html[:500],      # Apercu HTML
            'full_text': body_text,       # Texte complet
            'full_html': body_html        # HTML complet
        }

    # ========================================================================
    # EXTRACTION DES URLs
    # ========================================================================

    def _extract_urls(self, msg) -> List[str]:
        """
        Extrait tous les URLs du message.

        Deux methodes combinees :
        1. Regex sur le texte brut (attrape les URLs en clair)
        2. BeautifulSoup sur le HTML (attrape les href des balises <a>)

        On utilise un set() pour eviter les doublons.
        """
        urls = set()

        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    content = payload.decode('utf-8', errors='ignore')
                    content_type = part.get_content_type()

                    # Methode 1 : regex sur tout le contenu
                    urls.update(URL_REGEX.findall(content))

                    # Methode 2 : BeautifulSoup sur le HTML uniquement
                    if content_type == 'text/html':
                        urls.update(self._extract_urls_from_html(content))

                except (UnicodeDecodeError, AttributeError):
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    urls.update(URL_REGEX.findall(content))
            except (UnicodeDecodeError, AttributeError):
                pass

        return list(urls)

    @staticmethod
    def _extract_urls_from_html(html_content: str) -> List[str]:
        """
        Utilise BeautifulSoup pour extraire les URLs des balises HTML.

        Plus fiable que la regex sur du HTML car :
        - Gere les attributs href, src, action
        - Ne se trompe pas avec les balises imbriquees
        - Parse correctement le HTML malformer

        Doc : https://www.crummy.com/software/BeautifulSoup/bs4/doc/
        """
        found_urls = []

        # html.parser = parser HTML integre a Python (pas de dependance C)
        soup = BeautifulSoup(html_content, 'html.parser')

        # Chercher dans les balises <a href="...">, <img src="...">,
        # <form action="...">, <iframe src="...">
        for tag in soup.find_all(['a', 'img', 'form', 'iframe', 'script']):
            # Chaque type de balise a un attribut different pour l'URL
            url = tag.get('href') or tag.get('src') or tag.get('action')
            if url and url.startswith(('http://', 'https://', 'www.')):
                found_urls.append(url)

        return found_urls

    # ========================================================================
    # EXTRACTION DES ADRESSES EMAIL
    # ========================================================================

    def _extract_emails(self, msg) -> List[str]:
        """
        Extrait toutes les adresses email du message.

        Cherche dans :
        1. Les en-tetes (From, To, Cc, Bcc, Reply-To)
        2. Le corps du message (texte + HTML)
        """
        emails = set()

        # Dans les en-tetes
        for header in ['From', 'To', 'Cc', 'Bcc', 'Reply-To']:
            value = msg.get(header, '')
            if value:
                emails.update(EMAIL_REGEX.findall(value))

        # Dans le corps
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='ignore')
                        emails.update(EMAIL_REGEX.findall(content))
                except (UnicodeDecodeError, AttributeError):
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    emails.update(EMAIL_REGEX.findall(content))
            except (UnicodeDecodeError, AttributeError):
                pass

        return list(emails)

    # ========================================================================
    # EXTRACTION DES ADRESSES IP
    # ========================================================================

    def _extract_ips(self, msg) -> List[str]:
        """
        Extrait les adresses IP depuis les en-tetes Received.

        Les en-tetes Received contiennent le chemin que l'email
        a parcouru : chaque serveur intermediaire ajoute son IP.
        """
        ips = set()

        # Parcourir tous les headers "Received"
        received_headers = msg.get_all('Received', [])
        for header_value in received_headers:
            if isinstance(header_value, str):
                ips.update(IP_REGEX.findall(header_value))

        # Header X-Originating-IP (parfois present)
        x_orig_ip = msg.get('X-Originating-IP', '')
        if x_orig_ip:
            ips.update(IP_REGEX.findall(x_orig_ip))

        return list(ips)

    # ========================================================================
    # EXTRACTION DES PIECES JOINTES
    # ========================================================================

    def _extract_attachments(self, msg) -> List[Dict]:
        """
        Extrait les pieces jointes avec :
        - Nom du fichier
        - Extension
        - Taille en octets
        - Hash MD5 et SHA256 (pour identification sur VirusTotal)
        - Flag is_dangerous si extension a risque
        """
        attachments = []

        if not msg.is_multipart():
            return attachments

        for part in msg.iter_attachments():
            filename = part.get_filename()
            if not filename:
                continue

            try:
                # Decoder le nom du fichier (peut etre en RFC 2047)
                decoded_filename = self._decode_header_value(filename)
                payload = part.get_payload(decode=True)

                if not payload:
                    continue

                # Calculer les hashes pour identification
                # MD5  : 128 bits, rapide mais collisions possibles
                # SHA256 : 256 bits, plus sur, standard en forensic
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()

                # Verifier si l'extension est dangereuse
                ext = Path(decoded_filename).suffix.lower()
                is_dangerous = ext in DANGEROUS_EXTENSIONS

                attachments.append({
                    'filename': decoded_filename,
                    'extension': ext,
                    'size': len(payload),
                    'md5': md5_hash,
                    'sha256': sha256_hash,
                    'is_dangerous': is_dangerous
                })

            except (ValueError, AttributeError, OSError):
                attachments.append({
                    'filename': filename,
                    'error': 'Echec du traitement de la piece jointe'
                })

        return attachments

    # ========================================================================
    # EXTRACTION DES RESULTATS D'AUTHENTIFICATION
    # ========================================================================

    def _extract_auth_results(self, msg) -> Dict:
        """
        Extrait le header Authentication-Results.

        Ce header contient les resultats de verification :
        - SPF  : le serveur d'envoi est-il autorise par le domaine ?
        - DKIM : la signature numerique est-elle valide ?
        - DMARC: les politiques de domaine sont-elles respectees ?

        Si ce header est absent, c'est un signal d'alerte.
        """
        auth_results = msg.get('Authentication-Results', 'N/A')

        return {
            'raw': auth_results,
            'has_auth': auth_results != 'N/A'
        }


# ============================================================================
# MODE INTERACTIF (test rapide en standalone)
# ============================================================================

if __name__ == '__main__':
    import sys
    import json

    parser = EmailParser()

    # Argument en ligne de commande ou saisie interactive
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Chemin du fichier .eml : ").strip()

    if not file_path:
        print("Aucun fichier specifie")
        sys.exit(1)

    print(f"\nAnalyse de {file_path}...")
    result = parser.parse_eml_file(file_path)

    if 'error' in result:
        print(f"Erreur : {result['error']}")
        sys.exit(1)

    print(f"Headers : {len(result['headers'])}")
    print(f"URLs    : {len(result['urls'])}")
    print(f"Emails  : {len(result['emails'])}")
    print(f"IPs     : {len(result['ips'])}")
    print(f"Pièces jointes : {len(result['attachments'])}")

    # Sauvegarde optionnelle
    save = input("\nSauvegarder en JSON ? (o/n) : ").lower().strip()
    if save == 'o':
        output_file = f"{Path(file_path).stem}_parsed.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Sauvegarde : {output_file}")
