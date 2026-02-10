# Phishing Email Analyzer

Outil de detection heuristique de phishing par analyse d'emails au format `.eml`.

**Cours** : Python B3 - Oteria Cyber School 2025-2026  
**Professeur** : NALDI Toni

## Fonctionnalites

- Parsing complet de fichiers `.eml` (en-tetes, corps, URLs, pieces jointes)
- 15 regles de detection heuristique
- Score de risque de 0 a 100 avec 5 niveaux (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- Export des resultats en CSV, JSON ou rapport texte
- Mode batch pour analyser un repertoire entier
- Mode interactif avec menu

## Installation

```bash
# Cloner le repo
git clone https://github.com/f3n999/Projet-X-Python-.git
cd Projet-X-Python-

# Installer les dependances
pip install -r requirements.txt
```

La seule dependance externe est **BeautifulSoup4** (parsing HTML).  
Tous les autres modules sont de la bibliotheque standard Python.

## Utilisation

```bash
# Analyser un email
python main.py analyze email.eml

# Analyser avec export JSON
python main.py analyze email.eml --format json

# Analyser un repertoire entier
python main.py batch ./emails/ --format csv

# Mode interactif
python main.py interactive

# Mode debug (verbose)
python main.py analyze email.eml --verbose
```

## Architecture

```
phishing_analyzer/
├── src/
│   ├── __init__.py
│   ├── email_parser.py       # Parsing des .eml (BeautifulSoup + regex)
│   ├── detection_rules.py    # 15 regles heuristiques
│   ├── risk_scorer.py        # Score 0-100
│   └── exporters.py          # CSV, JSON, rapports texte
├── rules/
│   ├── phishing_keywords.txt     # Mots-cles suspects (100+)
│   ├── suspicious_domains.txt    # Domaines de typosquatting (50+)
│   └── legitimate_domains.txt    # Whitelist domaines connus
├── tests/
│   ├── test_parser.py
│   ├── test_rules.py
│   ├── test_scorer.py
│   └── sample_emails/
├── main.py                   # Point d'entree CLI
├── requirements.txt
└── setup.py
```

## Pipeline d'analyse

```
Fichier .eml
     |
     v
[EmailParser] --- parse_eml_file() ---> Dict structure
     |
     v
[PhishingDetector] --- analyze() ---> 15 resultats de regles
     |
     v
[RiskScorer] --- calculate_score() ---> Score 0-100 + niveau
     |
     v
[ReportExporter] --- export_csv() / export_json() ---> Fichier de sortie
```

## Les 15 regles de detection

| # | Regle | Poids | Description |
|---|-------|-------|-------------|
| 1 | SUSPICIOUS_KEYWORDS_SUBJECT | 8 | Mots-cles phishing dans le sujet |
| 2 | SUSPICIOUS_KEYWORDS_BODY | 7 | Mots-cles phishing dans le corps (seuil: 3+) |
| 3 | PASSWORD_REQUEST | 10 | Demande de mot de passe |
| 4 | SENSITIVE_DATA_REQUEST | 10 | Demande de SSN, carte, CVV |
| 5 | ARTIFICIAL_URGENCY | 8 | Langage d'urgence (seuil: 2+ indicateurs) |
| 6 | DOMAIN_MISMATCH | 9 | Domaine URL != domaine expediteur |
| 7 | DOMAIN_LOOKALIKE | 9 | Typosquatting (distance de Levenshtein) |
| 8 | NO_AUTHENTICATION | 6 | Absence de Authentication-Results |
| 9 | SPF_FAIL | 8 | SPF echoue ou softfail |
| 10 | SUSPICIOUS_HTML | 7 | Balises script, iframe, onclick (via BS4) |
| 11 | SHORT_URL | 7 | URLs raccourcies (bit.ly, tinyurl...) |
| 12 | EXECUTABLE_ATTACHMENT | 10 | Pieces jointes .exe, .bat, .scr... |
| 13 | SUSPICIOUS_SENDER | 6 | Expediteur no-reply, alert, system... |
| 14 | IP_IN_URL | 8 | Adresse IP directe dans URL |
| 15 | ENCODING_OBFUSCATION | 7 | Punycode (xn--) ou URL encoding |

## Tests

```bash
# Lancer tous les tests
python -m pytest tests/ -v

# Ou avec unittest
python -m unittest discover tests/ -v
```

## Librairies utilisees

| Librairie | Type | Usage |
|-----------|------|-------|
| `email` | stdlib | Parsing du format .eml (RFC 2822) |
| `re` | stdlib | Expressions regulieres |
| `hashlib` | stdlib | Hash MD5/SHA256 des pieces jointes |
| `csv` | stdlib | Export CSV |
| `json` | stdlib | Export JSON |
| `argparse` | stdlib | Arguments ligne de commande |
| `pathlib` | stdlib | Manipulation de chemins |
| `beautifulsoup4` | externe | Parsing HTML (extraction URLs des balises) |

## Ressources

- [Documentation BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
- [Regex101 - Tester les regex](https://regex101.com/)
- [PEP8 - Style Guide](https://peps.python.org/pep-0008/)
- [OWASP Phishing](https://owasp.org/www-community/attacks/Phishing)
