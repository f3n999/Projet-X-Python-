"""
EMAIL PARSER - Extraction des artifacts d'email
Mission: Transformer un .eml brut en données exploitables
"""

import email
import re
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import hashlib
from typing import Dict, List, Tuple


class EmailParser:
    """Parse les fichiers .eml et extrait les données critiques"""
    
    def __init__(self):
        self.headers_of_interest = [
            'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date',
            'Return-Path', 'Reply-To', 'Received',
            'Authentication-Results', 'DKIM-Signature', 'SPF'
        ]
    
    def parse_eml_file(self, file_path: str) -> Dict:
        """
        Parse un fichier .eml complet
        
        Returns:
            Dict avec structure: {
                'headers': {...},
                'body': {...},
                'urls': [...],
                'emails': [...],
                'ips': [...],
                'attachments': [...]
            }
        """
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_binary_file(f)
        except Exception as e:
            return {'error': f'Failed to parse: {str(e)}'}
        
        parsed_data = {
            'file_path': file_path,
            'headers': self._extract_headers(msg),
            'body': self._extract_body(msg),
            'urls': self._extract_urls(msg),
            'emails': self._extract_emails(msg),
            'ips': self._extract_ips(msg),
            'attachments': self._extract_attachments(msg),
            'authentication': self._extract_auth_results(msg)
        }
        
        return parsed_data
    
    def _extract_headers(self, msg) -> Dict:
        """Extrait les en-têtes importants"""
        headers = {}
        for key in self.headers_of_interest:
            value = msg.get(key, 'N/A')
            headers[key] = value
        return headers
    
    def _extract_body(self, msg) -> Dict:
        """Extrait le corps en version texte et HTML"""
        body_text = ''
        body_html = ''
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                try:
                    if content_type == 'text/plain':
                        body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == 'text/html':
                        body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode('utf-8', errors='ignore')
        
        return {
            'text': body_text[:500],  # Premiers 500 chars
            'html': body_html[:500],
            'full_text': body_text,
            'full_html': body_html
        }
    
    def _extract_urls(self, msg) -> List[str]:
        """Extrait tous les URLs du message"""
        urls = []
        pattern = r'https?://[^\s\)>\]<"\']+|www\.[^\s\)>\]<"\']+\.[a-z]+'
        
        # Cherche dans le corps texte
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    urls.extend(re.findall(pattern, payload))
                except:
                    pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
                urls.extend(re.findall(pattern, body))
        
        return list(set(urls))  # Déduplique
    
    def _extract_emails(self, msg) -> List[str]:
        """Extrait toutes les adresses email"""
        emails = []
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Headers
        for header in ['From', 'To', 'Cc', 'Bcc', 'Reply-To']:
            value = msg.get(header, '')
            emails.extend(re.findall(email_pattern, value))
        
        # Corps
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    emails.extend(re.findall(email_pattern, payload))
                except:
                    pass
        
        return list(set(emails))
    
    def _extract_ips(self, msg) -> List[str]:
        """Extrait les adresses IP du header Received"""
        ips = []
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        received = msg.get_all('Received', [])
        for header_value in received:
            ips.extend(re.findall(ip_pattern, header_value))
        
        return list(set(ips))
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """Extrait les pièces jointes et leurs hashes"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.iter_attachments():
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)
                    attachment_info = {
                        'filename': filename,
                        'size': len(payload),
                        'md5': hashlib.md5(payload).hexdigest(),
                        'sha256': hashlib.sha256(payload).hexdigest()
                    }
                    attachments.append(attachment_info)
        
        return attachments
    
    def _extract_auth_results(self, msg) -> Dict:
        """Extrait les résultats d'authentification"""
        auth_results = msg.get('Authentication-Results', 'N/A')
        return {
            'raw': auth_results,
            'has_auth': auth_results != 'N/A'
        }


if __name__ == '__main__':
    parser = EmailParser()
    result = parser.parse_eml_file('test_email.eml')
    import json
    print(json.dumps(result, indent=2, default=str))
