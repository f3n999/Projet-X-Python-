"""
EMAIL PARSER - Extraction des artifacts d'email
Mission: Transformer un .eml brut en données exploitables
"""

import email
import re
import hashlib
from pathlib import Path
from typing import Dict, List
from email.header import decode_header


# ============================================================================
# CONSTANTS
# ============================================================================

HEADERS_OF_INTEREST = [
    'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date',
    'Return-Path', 'Reply-To', 'Received',
    'Authentication-Results', 'DKIM-Signature', 'SPF'
]

# Extended dangerous file extensions
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.com', '.pif',
    '.msi', '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg'
]

# Regex patterns
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
URL_PATTERN = r'https?://[^\s\)>\]<"\']+|www\.[^\s\)>\]<"\']+\.[a-z]+'
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'


# ============================================================================
# EMAIL PARSER CLASS
# ============================================================================

class EmailParser:
    """Parse les fichiers .eml et extrait les données critiques"""
    
    def __init__(self):
        self.headers_of_interest = HEADERS_OF_INTEREST
        self.email_regex = re.compile(EMAIL_PATTERN)
        self.url_regex = re.compile(URL_PATTERN)
        self.ip_regex = re.compile(IP_PATTERN)
    
    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================
    
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
                'attachments': [...],
                'authentication': {...}
            }
        """
        # Validate file
        path = Path(file_path)
        if not path.exists():
            return {'error': f'File not found: {file_path}'}
        
        # Parse .eml
        try:
            with open(file_path, 'rb') as f:
                msg = email.message_from_binary_file(f)
        except Exception as e:
            return {'error': f'Failed to parse: {str(e)}'}
        
        # Extract all data
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
    # HEADERS EXTRACTION
    # ========================================================================
    
    def _extract_headers(self, msg) -> Dict:
        """Extrait les en-têtes importants avec décodage RFC 2047"""
        headers = {}
        
        for key in self.headers_of_interest:
            value = msg.get(key, 'N/A')
            
            # Decode RFC 2047 encoded headers (e.g., =?UTF-8?B?...)
            if value and value != 'N/A':
                headers[key] = self._decode_header_value(value)
            else:
                headers[key] = value
        
        return headers
    
    @staticmethod
    def _decode_header_value(header_value: str) -> str:
        """Décode les headers encodés (RFC 2047)"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''
            
            for content, encoding in decoded_parts:
                if isinstance(content, bytes):
                    decoded_string += content.decode(encoding or 'utf-8', errors='ignore')
                else:
                    decoded_string += content
            
            return decoded_string
        except:
            return header_value
    
    # ========================================================================
    # BODY EXTRACTION
    # ========================================================================
    
    def _extract_body(self, msg) -> Dict:
        """Extrait le corps en version texte et HTML"""
        body_text = ''
        body_html = ''
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    
                    # Get charset
                    charset = part.get_content_charset() or 'utf-8'
                    decoded = payload.decode(charset, errors='ignore')
                    
                    # Store by content type
                    if content_type == 'text/plain':
                        body_text = decoded
                    elif content_type == 'text/html':
                        body_html = decoded
                
                except Exception:
                    continue
        
        else:
            # Not multipart
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body_text = payload.decode(charset, errors='ignore')
            except Exception:
                pass
        
        return {
            'text': body_text[:500],      # Preview (500 chars)
            'html': body_html[:500],      # Preview (500 chars)
            'full_text': body_text,       # Full content
            'full_html': body_html        # Full content
        }
    
    # ========================================================================
    # URLs EXTRACTION
    # ========================================================================
    
    def _extract_urls(self, msg) -> List[str]:
        """Extrait tous les URLs du message"""
        urls = set()
        
        # Extract from all parts
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='ignore')
                        urls.update(self.url_regex.findall(content))
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    urls.update(self.url_regex.findall(content))
            except Exception:
                pass
        
        return list(urls)
    
    # ========================================================================
    # EMAIL ADDRESSES EXTRACTION
    # ========================================================================
    
    def _extract_emails(self, msg) -> List[str]:
        """Extrait toutes les adresses email"""
        emails = set()
        
        # From headers
        for header in ['From', 'To', 'Cc', 'Bcc', 'Reply-To']:
            value = msg.get(header, '')
            if value:
                emails.update(self.email_regex.findall(value))
        
        # From body
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='ignore')
                        emails.update(self.email_regex.findall(content))
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    emails.update(self.email_regex.findall(content))
            except Exception:
                pass
        
        return list(emails)
    
    # ========================================================================
    # IP ADDRESSES EXTRACTION
    # ========================================================================
    
    def _extract_ips(self, msg) -> List[str]:
        """Extrait les adresses IP du header Received"""
        ips = set()
        
        # From Received headers
        received_headers = msg.get_all('Received', [])
        for header_value in received_headers:
            if isinstance(header_value, str):
                ips.update(self.ip_regex.findall(header_value))
        
        # From X-Originating-IP
        x_orig_ip = msg.get('X-Originating-IP', '')
        if x_orig_ip:
            ips.update(self.ip_regex.findall(x_orig_ip))
        
        return list(ips)
    
    # ========================================================================
    # ATTACHMENTS EXTRACTION
    # ========================================================================
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """Extrait les pièces jointes avec détection d'extensions dangereuses"""
        attachments = []
        
        if not msg.is_multipart():
            return attachments
        
        for part in msg.iter_attachments():
            filename = part.get_filename()
            
            if not filename:
                continue
            
            try:
                # Decode filename (RFC 2047)
                decoded_filename = self._decode_header_value(filename)
                
                # Get payload
                payload = part.get_payload(decode=True)
                
                if not payload:
                    continue
                
                # Calculate hashes
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
                
                # Check if dangerous
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
            
            except Exception:
                # If error, at least record filename
                attachments.append({
                    'filename': filename,
                    'error': 'Failed to process attachment'
                })
        
        return attachments
    
    # ========================================================================
    # AUTHENTICATION EXTRACTION
    # ========================================================================
    
    def _extract_auth_results(self, msg) -> Dict:
        """Extrait les résultats d'authentification (SPF, DKIM, DMARC)"""
        auth_results = msg.get('Authentication-Results', 'N/A')
        
        return {
            'raw': auth_results,
            'has_auth': auth_results != 'N/A'
        }


# ============================================================================
# INTERACTIVE MODE (Optional)
# ============================================================================

if __name__ == '__main__':
    import sys
    import json
    
    parser = EmailParser()
    
    # Get file path from command line or prompt
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter .eml file path: ").strip()
    
    if not file_path:
        print("❌ No file specified")
        sys.exit(1)
    
    # Parse the email
    print(f"\n🔍 Parsing {file_path}...")
    result = parser.parse_eml_file(file_path)
    
    # Check for errors
    if 'error' in result:
        print(f"❌ Error: {result['error']}")
        sys.exit(1)
    
    # Display summary
    print(f"\n✓ Parsed successfully!")
    print(f"  • Headers: {len(result['headers'])}")
    print(f"  • URLs: {len(result['urls'])}")
    print(f"  • Emails: {len(result['emails'])}")
    print(f"  • IPs: {len(result['ips'])}")
    print(f"  • Attachments: {len(result['attachments'])}")
    
    # Ask to save JSON
    save = input("\n💾 Save as JSON? (y/n): ").lower().strip()
    
    if save == 'y':
        output_file = f"{Path(file_path).stem}_parsed.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"✓ Saved to {output_file}")
    else:
        # Print to console
        print("\n" + "="*60)
        print(json.dumps(result, indent=2, default=str))
        print("="*60)
