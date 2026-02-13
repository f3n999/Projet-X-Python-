"""
MAIN.PY - Point d'entree du programme
Lie les 4 modules : parser + detecteur + scorer + exporteur

Utilisation :
    python main.py                           # Mode interactif
    python main.py analyze email.eml         # Analyser un email
    python main.py batch ./emails/           # Analyser un dossier
"""

import sys
from pathlib import Path
from datetime import datetime

# Imports des 4 modules du projet
from src.email_parser import EmailParser
from src.detection_rules import PhishingDetector
from src.risk_scorer import RiskScorer
from src.exporters import ReportExporter


def analyser_email(chemin_eml, parser, detector, scorer):
    """
    Analyse un seul fichier .eml et retourne le resultat complet.

    Pipeline :
        1. Parser l'email (EmailParser)
        2. Lancer les 15 regles (PhishingDetector)
        3. Calculer le score (RiskScorer)

    Args:
        chemin_eml : chemin vers le fichier .eml
        parser     : instance de EmailParser
        detector   : instance de PhishingDetector
        scorer     : instance de RiskScorer

    Returns:
        Un dictionnaire avec toutes les infos, ou None si erreur
    """
    # ETAPE 1 : Parser l'email
    print("  [1/3] Parsing du fichier...")
    parsed = parser.parse_eml_file(chemin_eml)

    if 'error' in parsed:
        print("  ERREUR :", parsed['error'])
        return None

    # ETAPE 2 : Lancer les 15 regles de detection
    print("  [2/3] Lancement des 15 regles de detection...")
    detection_results = detector.analyze(parsed)

    # ETAPE 3 : Calculer le score
    print("  [3/3] Calcul du score de risque...")
    score, metadata = scorer.calculate_score(detection_results)

    # Assembler le resultat final
    analyse = {
        'file_path': chemin_eml,
        'file_name': Path(chemin_eml).name,
        'headers': parsed['headers'],
        'urls': parsed['urls'],
        'emails': parsed['emails'],
        'ips': parsed['ips'],
        'attachments': parsed['attachments'],
        'detection_results': detection_results,
        'score': score,
        'triggered_rules_count': metadata['triggered_rules_count'],
        'total_rules': metadata['total_rules'],
        'triggered_rules': metadata['triggered_rules'],
        'risk_level': metadata['risk_level'],
    }

    return analyse


def afficher_resultat(analyse):
    """Affiche le resultat d'analyse dans le terminal."""
    print()
    print("========================================================")
    print("          RESULTAT DE L'ANALYSE")
    print("========================================================")
    print()
    print("  From:    " + analyse['headers'].get('From', 'N/A'))
    print("  Subject: " + analyse['headers'].get('Subject', 'N/A'))
    print()
    print("  Score :  " + str(analyse['score']) + "/100 - " + analyse['risk_level'])
    print("  Regles : " + str(analyse['triggered_rules_count']) + "/" + str(analyse['total_rules']) + " declenchees")
    print()

    # Afficher les regles declenchees
    if analyse['triggered_rules']:
        print("  Regles declenchees :")
        for rule in analyse['triggered_rules']:
            print("    * " + rule['name'] + " (poids: " + str(rule['weight']) + ")")
            print("      -> " + rule['reason'])
    else:
        print("  Aucune regle declenchee")

    print()
    print("  URLs:             " + str(len(analyse['urls'])))
    print("  Emails:           " + str(len(analyse['emails'])))
    print("  IPs:              " + str(len(analyse['ips'])))
    print("  Pieces jointes:   " + str(len(analyse['attachments'])))
    print()


def mode_interactif():
    """Mode menu interactif."""
    # Initialiser les 4 composants
    parser = EmailParser()
    scorer = RiskScorer()
    exporter = ReportExporter('output')

    # Charger les fichiers de regles s'ils existent
    rules_dir = Path('rules')
    kw_file = str(rules_dir / 'phishing_keywords.txt')
    dom_file = str(rules_dir / 'suspicious_domains.txt')

    detector = PhishingDetector(
        keywords_file=kw_file if Path(kw_file).exists() else None,
        domains_file=dom_file if Path(dom_file).exists() else None,
    )

    print()
    print("========================================================")
    print("   PHISHING EMAIL ANALYZER v1.0")
    print("   Outil d'analyse heuristique d'emails")
    print("========================================================")

    while True:
        print()
        print("MENU")
        print("  1. Analyser un email")
        print("  2. Analyser un dossier (batch)")
        print("  3. Aide")
        print("  4. Quitter")
        print()

        choix = input("Choix (1-4) : ").strip()

        if choix == '1':
            # Analyser un seul email
            chemin = input("Chemin du fichier .eml : ").strip()
            if not chemin:
                print("Aucun chemin fourni.")
                continue

            analyse = analyser_email(chemin, parser, detector, scorer)
            if analyse:
                afficher_resultat(analyse)

                # Proposer l'export
                export = input("Exporter en JSON ? (o/n) : ").strip().lower()
                if export == 'o':
                    path = exporter.export_json(analyse)
                    print("Export JSON : " + path)

        elif choix == '2':
            # Analyser tous les .eml d'un dossier
            dossier = input("Chemin du dossier : ").strip()
            if not dossier:
                print("Aucun chemin fourni.")
                continue

            dir_path = Path(dossier)
            if not dir_path.exists():
                print("Dossier introuvable : " + dossier)
                continue

            # Trouver tous les .eml
            eml_files = list(dir_path.rglob('*.eml'))
            if not eml_files:
                print("Aucun fichier .eml dans " + dossier)
                continue

            print(str(len(eml_files)) + " fichiers .eml trouves")

            resultats = []
            for i, eml_file in enumerate(eml_files):
                print()
                print("[" + str(i + 1) + "/" + str(len(eml_files)) + "] " + eml_file.name)
                analyse = analyser_email(str(eml_file), parser, detector, scorer)
                if analyse:
                    afficher_resultat(analyse)
                    resultats.append({
                        'filename': analyse['file_name'],
                        'from': analyse['headers'].get('From', 'N/A'),
                        'subject': analyse['headers'].get('Subject', 'N/A'),
                        'score': analyse['score'],
                        'risk_level': analyse['risk_level'],
                        'triggered_rules': analyse['triggered_rules_count'],
                        'urls_count': len(analyse['urls']),
                        'attachments_count': len(analyse['attachments']),
                    })

            # Resume batch
            if resultats:
                print()
                print("========================================================")
                print("               RESUME BATCH")
                print("========================================================")
                total = len(resultats)
                somme = 0
                for r in resultats:
                    somme = somme + r['score']
                moyenne = somme / total
                print("  Analyses : " + str(total))
                print("  Score moyen : " + str(round(moyenne, 1)) + "/100")

                # Proposer export CSV
                export = input("Exporter en CSV ? (o/n) : ").strip().lower()
                if export == 'o':
                    path = exporter.export_csv(resultats)
                    print("Export CSV : " + path)

        elif choix == '3':
            print()
            print("  Utilisation en ligne de commande :")
            print("    python main.py                    -> Mode interactif")
            print("    python main.py analyze email.eml  -> Analyser un email")
            print("    python main.py batch ./emails/    -> Analyser un dossier")

        elif choix == '4':
            print("Au revoir.")
            break

        else:
            print("Choix invalide.")


def main():
    """
    Point d'entree du programme.

    sys.argv contient les arguments de la ligne de commande :
        sys.argv[0] = 'main.py'
        sys.argv[1] = commande ('analyze', 'batch', ou rien)
        sys.argv[2] = argument de la commande (chemin du fichier/dossier)
    """
    # Initialiser les composants
    parser = EmailParser()
    scorer = RiskScorer()
    exporter = ReportExporter('output')

    rules_dir = Path('rules')
    kw_file = str(rules_dir / 'phishing_keywords.txt')
    dom_file = str(rules_dir / 'suspicious_domains.txt')

    detector = PhishingDetector(
        keywords_file=kw_file if Path(kw_file).exists() else None,
        domains_file=dom_file if Path(dom_file).exists() else None,
    )

    # Verifier les arguments
    if len(sys.argv) < 2:
        # Pas d'argument -> mode interactif
        mode_interactif()
        return

    commande = sys.argv[1]

    if commande == 'analyze' and len(sys.argv) >= 3:
        # python main.py analyze email.eml
        chemin = sys.argv[2]
        print()
        print("Analyse de : " + chemin)
        analyse = analyser_email(chemin, parser, detector, scorer)
        if analyse:
            afficher_resultat(analyse)

            # Export JSON si demande avec --format json
            if '--format' in sys.argv and 'json' in sys.argv:
                path = exporter.export_json(analyse)
                print("Export JSON : " + path)

    elif commande == 'batch' and len(sys.argv) >= 3:
        # python main.py batch ./emails/
        dossier = sys.argv[2]
        dir_path = Path(dossier)

        if not dir_path.exists():
            print("Dossier introuvable : " + dossier)
            return

        eml_files = list(dir_path.rglob('*.eml'))
        if not eml_files:
            print("Aucun fichier .eml dans " + dossier)
            return

        print(str(len(eml_files)) + " fichiers .eml trouves")

        resultats = []
        for i, eml_file in enumerate(eml_files):
            print()
            print("[" + str(i + 1) + "/" + str(len(eml_files)) + "] " + eml_file.name)
            analyse = analyser_email(str(eml_file), parser, detector, scorer)
            if analyse:
                afficher_resultat(analyse)
                resultats.append({
                    'filename': analyse['file_name'],
                    'from': analyse['headers'].get('From', 'N/A'),
                    'subject': analyse['headers'].get('Subject', 'N/A'),
                    'score': analyse['score'],
                    'risk_level': analyse['risk_level'],
                    'triggered_rules': analyse['triggered_rules_count'],
                    'urls_count': len(analyse['urls']),
                    'attachments_count': len(analyse['attachments']),
                })

        # Export CSV
        if resultats:
            path = exporter.export_csv(resultats)
            print("Export CSV : " + path)

    elif commande == 'interactive':
        mode_interactif()

    else:
        print("Utilisation :")
        print("  python main.py                    -> Mode interactif")
        print("  python main.py analyze email.eml  -> Analyser un email")
        print("  python main.py batch ./emails/    -> Analyser un dossier")


if __name__ == '__main__':
    main()
