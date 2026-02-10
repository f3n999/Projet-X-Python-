# Phishing Email Analyzer

Outil de détection heuristique de phishing par analyse de fichiers `.eml`.  
Projet Python B3 - Oteria Cyber School 2025-2026.

## Fonctionnalités

- **Parsing complet** de fichiers `.eml` (headers, corps, URLs, IPs, pièces jointes)
- **15 règles de détection** heuristiques (mots-clés, SPF, typosquatting, urgence, etc.)
- **Scoring 0-100** avec niveaux de risque (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- **Export** en CSV, JSON ou rapport texte
- **3 modes** : analyse unique, batch (répertoire), interactif

## Structure du projet

```
phishing_analyzer/
├── src/
│   ├── __init__.py
│   ├── email_parser.py        # Parsing des .eml
│   ├── detection_rules.py     # 15 règles heuristiques
│   ├── risk_scorer.py         # Scoring 0-100
│   └── exporters.py           # CSV, JSON, rapports
├── rules/
│   ├── phishing_keywords.txt
│   ├── suspicious_domains.txt
│   └── legitimate_domains.txt
├── tests/
│   ├── test_parser.py
│   ├── test_rules.py
│   ├── test_scorer.py
│   └── sample_emails/
├── main.py                    # Point d'entrée CLI
├── requirements.txt
├── setup.py
└── README.md
```

## Installation

Python 3.7+ requis. Aucune dépendance externe.

```bash
git clone <url-du-repo>
cd phishing_analyzer
```

## Utilisation

```bash
# Analyse d'un fichier
python main.py analyze email.eml

# Analyse avec export JSON
python main.py analyze email.eml --format json

# Analyse batch d'un répertoire
python main.py batch ./emails/ --format csv

# Mode interactif
python main.py interactive

# Mode debug
python main.py analyze email.eml --verbose
```

## Tests

```bash
python -m unittest discover tests/ -v
```

## Architecture

Le pipeline d'analyse suit 3 étapes :

1. **Parsing** (`EmailParser`) : extrait headers, corps, URLs, emails, IPs, pièces jointes et résultats d'authentification depuis un fichier `.eml`
2. **Détection** (`PhishingDetector`) : applique 15 règles heuristiques sur les données parsées
3. **Scoring** (`RiskScorer`) : agrège les résultats en un score 0-100 avec niveau de risque

```python
from src.email_parser import EmailParser
from src.detection_rules import PhishingDetector
from src.risk_scorer import RiskScorer

parser = EmailParser()
parsed = parser.parse_eml_file('email.eml')

detector = PhishingDetector()
detection = detector.analyze(parsed)

scorer = RiskScorer()
score, metadata = scorer.calculate_score(detection)

print(f"Score: {score}/100 - {metadata['risk_level']}")
```

## Règles de détection

| # | Règle | Poids | Description |
|---|-------|-------|-------------|
| 1 | SUSPICIOUS_KEYWORDS_SUBJECT | 8 | Mots-clés phishing dans le sujet |
| 2 | SUSPICIOUS_KEYWORDS_BODY | 7 | Mots-clés phishing dans le corps |
| 3 | PASSWORD_REQUEST | 10 | Demande de mot de passe |
| 4 | SENSITIVE_DATA_REQUEST | 10 | Demande de données sensibles |
| 5 | ARTIFICIAL_URGENCY | 8 | Fausse urgence |
| 6 | DOMAIN_MISMATCH | 9 | URL != domaine expéditeur |
| 7 | DOMAIN_LOOKALIKE | 9 | Typosquatting |
| 8 | NO_AUTHENTICATION | 6 | Pas d'Authentication-Results |
| 9 | SPF_FAIL | 8 | SPF échoué |
| 10 | SUSPICIOUS_HTML | 7 | Scripts/iframes dangereux |
| 11 | SHORT_URL | 7 | URLs raccourcies |
| 12 | EXECUTABLE_ATTACHMENT | 10 | Pièce jointe exécutable |
| 13 | SUSPICIOUS_SENDER | 6 | Expéditeur suspect |
| 14 | IP_IN_URL | 8 | IP directe dans URL |
| 15 | ENCODING_OBFUSCATION | 7 | Punycode/encoding suspect |

## Équipe

Projet réalisé à 4 personnes :
- Personne 1 : `email_parser.py`
- Personne 2 : `detection_rules.py`
- Personne 3 : `risk_scorer.py` + `exporters.py`
- Personne 4 : `main.py` + intégration + tests
