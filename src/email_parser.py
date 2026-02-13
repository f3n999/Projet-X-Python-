"""
EMAIL PARSER - Extraction des donnees d'un email
On lit un fichier .eml et on extrait : headers, corps, URLs, emails, IPs, pieces jointes

Librairies :
    - email (stdlib)  : lire les fichiers .eml
    - re (stdlib)     : expressions regulieres (chercher des patterns dans du texte)
    - hashlib (stdlib): calculer des hash de fichiers
    - bs4 (externe)   : BeautifulSoup pour lire le HTML proprement
"""

import email
import re
import hashlib
from pathlib import Path
from bs4 import BeautifulSoup


# Regex = expressions regulieres pour trouver des patterns dans du texte
# re.compile() prepare le pattern une seule fois (plus rapide)

# Pattern pour trouver des adresses email : quelquechose@domaine.ext
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Pattern pour trouver des URLs : http://... ou https://...
URL_REGEX = re.compile(r'https?://[^\s\)>\]<"\']+')

# Pattern pour trouver des adresses IP : 4 nombres separes par des points
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Extensions de fichiers dangereuses
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd',
    '.msi', '.ps1', '.wsf', '.hta'
]


class EmailParser:
    """
    Parse un fichier .eml et extrait toutes les donnees utiles.

    Utilisation :
        parser = EmailParser()
        resultat = parser.parse_eml_file('email.eml')
    """

    def parse_eml_file(self, file_path):
        """
        Lit un fichier .eml et retourne un dictionnaire avec toutes les infos.

        Retourne un dict avec les cles :
            headers, body, urls, emails, ips, attachments, authentication
        """
        # Verifier que le fichier existe
        path = Path(file_path)
        if not path.exists():
            return {'error': 'Fichier introuvable : ' + file_path}

        # Lire le fichier .eml
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_binary_file(f)
        except Exception as e:
            return {'error': 'Impossible de lire le fichier : ' + str(e)}

        # Extraire toutes les donnees et retourner le resultat
        resultat = {
            'file_path': file_path,
            'headers': self.extraire_headers(msg),
            'body': self.extraire_body(msg),
            'urls': self.extraire_urls(msg),
            'emails': self.extraire_emails(msg),
            'ips': self.extraire_ips(msg),
            'attachments': self.extraire_attachments(msg),
            'authentication': self.extraire_auth(msg),
        }
        return resultat

    def extraire_headers(self, msg):
        """Extrait les en-tetes importants de l'email (From, To, Subject...)."""
        headers = {}
        # Liste des en-tetes qu'on veut recuperer
        cles = ['From', 'To', 'Subject', 'Date', 'Authentication-Results']

        for cle in cles:
            # msg[cle] retourne la valeur du header, ou None si absent
            valeur = msg[cle]
            if valeur:
                headers[cle] = str(valeur)
            else:
                headers[cle] = 'N/A'

        return headers

    def extraire_body(self, msg):
        """
        Extrait le corps de l'email (texte brut et HTML).

        Un email peut etre multipart (plusieurs parties : texte + HTML)
        ou simple (juste du texte).
        """
        body_text = ''
        body_html = ''

        # Email multipart = plusieurs parties
        if msg.is_multipart():
            # msg.walk() parcourt toutes les parties de l'email
            for part in msg.walk():
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    # Decoder les bytes en texte
                    contenu = payload.decode('utf-8', errors='ignore')

                    if content_type == 'text/plain':
                        body_text = contenu
                    elif content_type == 'text/html':
                        body_html = contenu
                except Exception:
                    continue
        else:
            # Email simple = une seule partie
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            except Exception:
                pass

        return {
            'text': body_text[:500],       # Apercu (500 premiers caracteres)
            'html': body_html[:500],
            'full_text': body_text,        # Texte complet
            'full_html': body_html,
        }

    def extraire_urls(self, msg):
        """
        Extrait toutes les URLs du message.

        Deux methodes :
        1. Regex : cherche les http:// dans le texte
        2. BeautifulSoup : cherche les <a href="..."> dans le HTML
        """
        urls = []

        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    contenu = payload.decode('utf-8', errors='ignore')
                    content_type = part.get_content_type()

                    # Methode 1 : regex sur le texte
                    for url in URL_REGEX.findall(contenu):
                        if url not in urls:
                            urls.append(url)

                    # Methode 2 : BeautifulSoup sur le HTML
                    if content_type == 'text/html':
                        soup = BeautifulSoup(contenu, 'html.parser')
                        for tag in soup.find_all('a'):
                            href = tag.get('href')
                            if href and href.startswith('http') and href not in urls:
                                urls.append(href)

                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    contenu = payload.decode('utf-8', errors='ignore')
                    for url in URL_REGEX.findall(contenu):
                        if url not in urls:
                            urls.append(url)
            except Exception:
                pass

        return urls

    def extraire_emails(self, msg):
        """Extrait toutes les adresses email trouvees dans le message."""
        emails = []

        # Chercher dans les headers
        for header in ['From', 'To', 'Cc', 'Reply-To']:
            valeur = msg[header]
            if valeur:
                for addr in EMAIL_REGEX.findall(str(valeur)):
                    if addr not in emails:
                        emails.append(addr)

        # Chercher dans le corps
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        contenu = payload.decode('utf-8', errors='ignore')
                        for addr in EMAIL_REGEX.findall(contenu):
                            if addr not in emails:
                                emails.append(addr)
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    contenu = payload.decode('utf-8', errors='ignore')
                    for addr in EMAIL_REGEX.findall(contenu):
                        if addr not in emails:
                            emails.append(addr)
            except Exception:
                pass

        return emails

    def extraire_ips(self, msg):
        """Extrait les adresses IP depuis les en-tetes Received."""
        ips = []

        # Les headers "Received" contiennent les IPs des serveurs
        received = msg.get_all('Received', [])
        for header_value in received:
            for ip in IP_REGEX.findall(str(header_value)):
                if ip not in ips:
                    ips.append(ip)

        return ips

    def extraire_attachments(self, msg):
        """
        Extrait les pieces jointes avec nom, taille et hash.
        Indique si l'extension est dangereuse.
        """
        attachments = []

        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            # get_filename() retourne le nom du fichier joint, ou None
            filename = part.get_filename()
            if not filename:
                continue

            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                # Calculer les hash du fichier (pour identification)
                md5 = hashlib.md5(payload).hexdigest()
                sha256 = hashlib.sha256(payload).hexdigest()

                # Verifier si l'extension est dangereuse
                extension = Path(filename).suffix.lower()
                est_dangereux = extension in DANGEROUS_EXTENSIONS

                attachments.append({
                    'filename': filename,
                    'extension': extension,
                    'size': len(payload),
                    'md5': md5,
                    'sha256': sha256,
                    'is_dangerous': est_dangereux,
                })
            except Exception:
                continue

        return attachments

    def extraire_auth(self, msg):
        """
        Extrait le header Authentication-Results.
        Ce header dit si l'email a ete verifie (SPF, DKIM).
        """
        auth = msg['Authentication-Results']
        if auth:
            return {'raw': str(auth), 'has_auth': True}
        else:
            return {'raw': 'N/A', 'has_auth': False}


# Mode standalone : on peut tester le parser tout seul
if __name__ == '__main__':
    import sys
    import json

    parser = EmailParser()

    if len(sys.argv) > 1:
        chemin = sys.argv[1]
    else:
        chemin = input("Chemin du fichier .eml : ").strip()

    resultat = parser.parse_eml_file(chemin)

    if 'error' in resultat:
        print("Erreur :", resultat['error'])
    else:
        print("Headers :", len(resultat['headers']))
        print("URLs    :", len(resultat['urls']))
        print("Emails  :", len(resultat['emails']))
        print("IPs     :", len(resultat['ips']))
        print("Pieces jointes :", len(resultat['attachments']))
        print()
        print(json.dumps(resultat, indent=2, default=str))
