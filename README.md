# Phishing Email Analyzer

Outil de detection de phishing par analyse d'emails au format `.eml`.

**Cours** : Python B3 - Oteria Cyber School 2025-2026
**Professeur** : NALDI Toni

## Installation

```bash
git clone https://github.com/f3n999/Projet-X-Python-.git
cd Projet-X-Python-

pip install -r requirements.txt
```

La seule dependance externe est **BeautifulSoup4** (parsing HTML).

## Utilisation

```bash
# Mode interactif (menu)
python main.py

# Analyser un email
python main.py analyze email.eml

# Analyser un dossier entier
python main.py batch ./emails/
```

## Structure du projet

```
phishing_analyzer/
├── src/
│   ├── __init__.py
│   ├── email_parser.py       # Parsing des .eml (PERSONNE 1)
│   ├── detection_rules.py    # 15 regles heuristiques (PERSONNE 2)
│   ├── risk_scorer.py        # Score 0-100 (PERSONNE 3)
│   └── exporters.py          # CSV, JSON, rapports (PERSONNE 3)
├── rules/
│   ├── phishing_keywords.txt     # Mots-cles suspects
│   ├── suspicious_domains.txt    # Domaines de typosquatting
│   └── legitimate_domains.txt    # Domaines de confiance
├── tests/
│   ├── test_parser.py
│   ├── test_rules.py
│   ├── test_scorer.py
│   └── sample_emails/
├── main.py                   # Point d'entree
├── requirements.txt
└── README.md
```

## Pipeline d'analyse

```
Fichier .eml
     |
     v
[EmailParser] --- parse_eml_file() ---> Dictionnaire structure
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
| 2 | SUSPICIOUS_KEYWORDS_BODY | 7 | Mots-cles phishing dans le corps |
| 3 | PASSWORD_REQUEST | 10 | Demande de mot de passe |
| 4 | SENSITIVE_DATA_REQUEST | 10 | Demande de donnees sensibles |
| 5 | ARTIFICIAL_URGENCY | 8 | Langage d'urgence |
| 6 | DOMAIN_MISMATCH | 9 | URL != domaine expediteur |
| 7 | DOMAIN_LOOKALIKE | 9 | Typosquatting (Levenshtein) |
| 8 | NO_AUTHENTICATION | 6 | Pas d'Authentication-Results |
| 9 | SPF_FAIL | 8 | SPF echoue |
| 10 | SUSPICIOUS_HTML | 7 | Balises script, iframe |
| 11 | SHORT_URL | 7 | URLs raccourcies (bit.ly...) |
| 12 | EXECUTABLE_ATTACHMENT | 10 | Pieces jointes .exe, .bat... |
| 13 | SUSPICIOUS_SENDER | 6 | Expediteur no-reply, alert... |
| 14 | IP_IN_URL | 8 | Adresse IP dans URL |
| 15 | ENCODING_OBFUSCATION | 7 | Punycode ou URL encoding |

## Tests

```bash
python -m pytest tests/ -v
```

## Librairies utilisees

| Librairie | Type | Usage |
|-----------|------|-------|
| `email` | stdlib | Parsing du format .eml |
| `re` | stdlib | Expressions regulieres |
| `hashlib` | stdlib | Hash MD5/SHA256 des pieces jointes |
| `csv` | stdlib | Export CSV |
| `json` | stdlib | Export JSON |
| `pathlib` | stdlib | Manipulation de chemins |
| `beautifulsoup4` | externe | Parsing HTML |
