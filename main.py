#!/usr/bin/env python3
"""
MAIN.PY - Point d'entree et orchestration
Mission : Lier parser + detecteur + scorer + exporteur en un outil CLI

Commandes :
    python main.py analyze email.eml                 # Analyse unique
    python main.py analyze email.eml --format json   # Avec export JSON
    python main.py batch ./emails/ --format csv      # Batch
    python main.py interactive                       # Mode interactif
"""

import argparse
import sys
import textwrap
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Imports internes (les 4 modules du projet)
from src.email_parser import EmailParser
from src.detection_rules import PhishingDetector
from src.risk_scorer import RiskScorer
from src.exporters import ReportExporter


# ============================================================================
# COULEURS TERMINAL (codes ANSI)
# ============================================================================
# \033[ = sequence d'echappement ANSI
# Le terminal interprete ces codes pour colorer le texte
# \033[0m = reset (fin de couleur)

class Colors:
    """Codes ANSI pour colorer la sortie terminal."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# ============================================================================
# CLASSE PRINCIPALE CLI
# ============================================================================

class PhishingAnalyzerCLI:
    """
    Interface en ligne de commande pour l'analyseur de phishing.

    Trois modes :
        1. analyze    : analyse un seul fichier .eml
        2. batch      : analyse tous les .eml d'un repertoire
        3. interactive: menu interactif

    Le workflow interne est toujours le meme :
        parse -> detect -> score -> display/export
    """

    def __init__(self, verbose: bool = False, output_dir: str = 'output'):
        """
        Initialise les 4 composants du pipeline.

        Args:
            verbose    : afficher les messages de debug
            output_dir : repertoire pour les exports
        """
        self.parser = EmailParser()

        # Charger les fichiers de regles s'ils existent
        rules_dir = Path('rules')
        keywords_file = str(rules_dir / 'phishing_keywords.txt')
        domains_file = str(rules_dir / 'suspicious_domains.txt')

        self.detector = PhishingDetector(
            keywords_file=keywords_file if Path(keywords_file).exists() else None,
            domains_file=domains_file if Path(domains_file).exists() else None
        )

        self.scorer = RiskScorer()
        self.exporter = ReportExporter(output_dir)
        self.verbose = verbose

    # ========================================================================
    # AFFICHAGE
    # ========================================================================

    @staticmethod
    def print_banner():
        """Affiche la banniere du programme."""
        print(f"""
{Colors.BOLD}{Colors.CYAN}
========================================================
   PHISHING EMAIL ANALYZER v1.0
   Outil d'analyse heuristique d'emails
========================================================
{Colors.END}""")

    def log(self, level: str, message: str):
        """
        Affiche un message avec couleur selon le niveau.

        Args:
            level   : 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG'
            message : texte a afficher
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors = {
            'INFO': Colors.BLUE,
            'SUCCESS': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED,
            'DEBUG': Colors.CYAN,
        }

        color = colors.get(level, '')

        # DEBUG n'apparait qu'en mode verbose
        if level == 'DEBUG' and not self.verbose:
            return

        print(f"{color}[{timestamp}] {message}{Colors.END}")

    # ========================================================================
    # MODE 1 : ANALYSE UNIQUE
    # ========================================================================

    def analyze_single(self, eml_path: str, export_format: str = 'console') -> Optional[Dict]:
        """
        Analyse un seul fichier .eml.

        Pipeline :
            1. Parser l'email (EmailParser)
            2. Lancer les 15 regles (PhishingDetector)
            3. Calculer le score (RiskScorer)
            4. Afficher et/ou exporter

        Args:
            eml_path      : chemin vers le fichier .eml
            export_format : 'console', 'json', 'csv' ou 'all'

        Returns:
            Dict complet de l'analyse, ou None si erreur
        """
        eml_file = Path(eml_path)

        # --- Validation ---
        if not eml_file.exists():
            self.log('ERROR', f"Fichier introuvable : {eml_path}")
            return None

        # --- ETAPE 1 : Parsing ---
        self.log('INFO', f"Parsing : {eml_file.name}")
        parsed = self.parser.parse_eml_file(str(eml_file))

        if 'error' in parsed:
            self.log('ERROR', f"Erreur de parsing : {parsed['error']}")
            return None

        self.log('DEBUG', f"  URLs: {len(parsed['urls'])}, "
                          f"Pieces jointes: {len(parsed['attachments'])}")

        # --- ETAPE 2 : Detection ---
        self.log('INFO', "Lancement des 15 regles de detection...")
        detection_results = self.detector.analyze(parsed)

        triggered_count = sum(1 for r in detection_results.values() if r['triggered'])
        self.log('DEBUG', f"  {triggered_count} regles declenchees")

        # --- ETAPE 3 : Scoring ---
        self.log('INFO', "Calcul du score de risque...")
        score, metadata = self.scorer.calculate_score(detection_results)

        # --- Assemblage du resultat final ---
        analysis = {
            'file_path': str(eml_file),
            'file_name': eml_file.name,
            'analysis_timestamp': datetime.now().isoformat(),
            'headers': parsed['headers'],
            'urls': parsed['urls'],
            'emails': parsed['emails'],
            'ips': parsed['ips'],
            'attachments': parsed['attachments'],
            'detection_results': detection_results,
            'score': score,
            **metadata  # decompresse triggered_rules, risk_level, etc.
        }

        # --- ETAPE 4 : Affichage ---
        self._display_analysis(analysis)

        # --- ETAPE 5 : Export ---
        if export_format != 'console':
            self._export_analysis(analysis, export_format)

        return analysis

    def _display_analysis(self, analysis: Dict):
        """Affiche le resultat formate avec couleurs."""
        score = analysis['score']
        risk = analysis['risk_level']

        # Couleur selon le niveau de risque
        risk_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.YELLOW,
            'SAFE': Colors.GREEN,
        }
        color = risk_colors.get(risk, '')

        print(f"""
{Colors.BOLD}{Colors.CYAN}
========================================================
          ANALYSE TERMINEE
========================================================
{Colors.END}
  From:    {analysis['headers'].get('From', 'N/A')[:60]}
  Subject: {analysis['headers'].get('Subject', 'N/A')[:60]}

  Score :  {color}{Colors.BOLD}{score}/100 - {risk}{Colors.END}
  Regles : {analysis['triggered_rules_count']}/{analysis['total_rules']} declenchees
""")

        # Afficher les regles declenchees
        if analysis['triggered_rules']:
            print(f"  {Colors.BOLD}Regles declenchees :{Colors.END}")
            for rule in analysis['triggered_rules']:
                rule_color = Colors.RED if rule['weight'] >= 9 else Colors.YELLOW
                print(f"    {rule_color}* {rule['name']}{Colors.END} "
                      f"(poids: {rule['weight']}) - {rule['reason']}")
        else:
            print(f"  {Colors.GREEN}Aucune regle declenchee{Colors.END}")

        # Donnees extraites
        print(f"""
  URLs:    {len(analysis['urls'])}
  Emails:  {len(analysis['emails'])}
  IPs:     {len(analysis['ips'])}
  Pièces jointes: {len(analysis['attachments'])}
""")

    def _export_analysis(self, analysis: Dict, export_format: str):
        """Exporte dans le format demande."""
        formats = ['json', 'csv'] if export_format == 'all' else [export_format]

        for fmt in formats:
            try:
                if fmt == 'json':
                    path = self.exporter.export_json(analysis)
                    self.log('SUCCESS', f"Export JSON : {path}")

                elif fmt == 'csv':
                    csv_row = [{
                        'filename': analysis['file_name'],
                        'from': analysis['headers'].get('From', 'N/A'),
                        'subject': analysis['headers'].get('Subject', 'N/A'),
                        'score': analysis['score'],
                        'risk_level': analysis['risk_level'],
                        'triggered_rules': analysis['triggered_rules_count'],
                        'urls_count': len(analysis['urls']),
                        'attachments_count': len(analysis['attachments'])
                    }]
                    path = self.exporter.export_csv(csv_row)
                    self.log('SUCCESS', f"Export CSV : {path}")

            except (OSError, IOError) as e:
                self.log('ERROR', f"Echec export {fmt} : {e}")

    # ========================================================================
    # MODE 2 : BATCH
    # ========================================================================

    def analyze_batch(self, directory: str, export_format: str = 'csv'):
        """
        Analyse tous les fichiers .eml d'un repertoire.

        Args:
            directory     : chemin du repertoire
            export_format : 'csv', 'json' ou 'all'
        """
        dir_path = Path(directory)

        if not dir_path.exists():
            self.log('ERROR', f"Repertoire introuvable : {directory}")
            return

        # Chercher tous les .eml recursivement
        eml_files = list(dir_path.rglob('*.eml'))

        if not eml_files:
            self.log('WARNING', f"Aucun fichier .eml dans {directory}")
            return

        self.log('INFO', f"{len(eml_files)} fichiers .eml trouves")

        results = []
        for i, eml_file in enumerate(eml_files, 1):
            print(f"\n{Colors.CYAN}[{i}/{len(eml_files)}]{Colors.END} {eml_file.name}")

            analysis = self.analyze_single(str(eml_file), export_format='console')

            if analysis:
                results.append({
                    'filename': analysis['file_name'],
                    'from': analysis['headers'].get('From', 'N/A')[:50],
                    'subject': analysis['headers'].get('Subject', 'N/A')[:50],
                    'score': analysis['score'],
                    'risk_level': analysis['risk_level'],
                    'triggered_rules': analysis['triggered_rules_count'],
                    'urls_count': len(analysis['urls']),
                    'attachments_count': len(analysis['attachments'])
                })

        # Exporter les resultats batch
        if not results:
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        formats = ['csv', 'json'] if export_format == 'all' else [export_format]

        for fmt in formats:
            try:
                if fmt == 'csv':
                    path = self.exporter.export_csv(
                        results, f"batch_{timestamp}.csv")
                    self.log('SUCCESS', f"Batch CSV : {path}")
                elif fmt == 'json':
                    batch_data = {
                        'batch_info': {
                            'total': len(eml_files),
                            'analyzed': len(results),
                            'timestamp': datetime.now().isoformat()
                        },
                        'results': results
                    }
                    path = self.exporter.export_json(
                        batch_data, f"batch_{timestamp}.json")
                    self.log('SUCCESS', f"Batch JSON : {path}")
            except (OSError, IOError) as e:
                self.log('ERROR', f"Batch export {fmt} : {e}")

        # Resume
        self._print_batch_summary(results)

    @staticmethod
    def _print_batch_summary(results: List[Dict]):
        """Affiche un resume des resultats batch."""
        total = len(results)
        if total == 0:
            return

        avg = sum(r['score'] for r in results) / total

        # Compter par niveau
        levels = {}
        for r in results:
            level = r['risk_level']
            levels[level] = levels.get(level, 0) + 1

        print(f"""
{Colors.BOLD}{Colors.CYAN}
========================================================
               RESUME BATCH
========================================================
{Colors.END}
  Analyses :     {total}
  Score moyen :  {avg:.1f}/100
""")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']:
            count = levels.get(level, 0)
            pct = count * 100 / total
            print(f"  {level:10s} : {count} ({pct:.0f}%)")
        print()

    # ========================================================================
    # MODE 3 : INTERACTIF
    # ========================================================================

    def interactive_mode(self):
        """Mode menu interactif."""
        self.print_banner()

        while True:
            print(f"""
{Colors.BOLD}MENU{Colors.END}
  1. Analyser un email
  2. Analyser un repertoire (batch)
  3. Aide
  4. Quitter
""")
            choice = input("Choix (1-4) : ").strip()

            if choice == '1':
                path = input("Chemin du .eml : ").strip()
                fmt = input("Format (console/json/csv/all) [console] : ").strip()
                self.analyze_single(path, export_format=fmt or 'console')

            elif choice == '2':
                path = input("Chemin du repertoire : ").strip()
                fmt = input("Format (csv/json/all) [csv] : ").strip()
                self.analyze_batch(path, export_format=fmt or 'csv')

            elif choice == '3':
                print("""
  python main.py analyze email.eml
  python main.py analyze email.eml --format json
  python main.py batch ./emails/ --format csv
  python main.py interactive
  python main.py analyze email.eml --verbose
""")

            elif choice == '4':
                self.log('INFO', "Fin du programme.")
                break

            else:
                self.log('ERROR', "Choix invalide.")

            input(f"\n{Colors.BOLD}Appuyer sur Entree...{Colors.END}")


# ============================================================================
# POINT D'ENTREE
# ============================================================================

def main():
    """
    Point d'entree du programme.

    Utilise argparse pour gerer les arguments en ligne de commande.
    argparse decoupe la commande en : programme + sous-commande + arguments
    """
    cli_parser = argparse.ArgumentParser(
        prog='Phishing Analyzer',
        description='Outil de detection heuristique de phishing par email',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Exemples :
              %(prog)s analyze email.eml
              %(prog)s batch ./emails/ --format csv
              %(prog)s interactive
        """)
    )

    cli_parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    cli_parser.add_argument('--verbose', '-v', action='store_true',
                            help='Mode debug (affiche plus de details)')
    cli_parser.add_argument('--output-dir', '-o', default='output',
                            help='Repertoire de sortie (defaut: output)')

    # Sous-commandes
    subparsers = cli_parser.add_subparsers(dest='command', help='Commandes')

    # Commande : analyze
    analyze_cmd = subparsers.add_parser('analyze', help='Analyser un .eml')
    analyze_cmd.add_argument('file', help='Chemin du fichier .eml')
    analyze_cmd.add_argument('--format', '-f',
                             choices=['console', 'json', 'csv', 'all'],
                             default='console', help='Format de sortie')

    # Commande : batch
    batch_cmd = subparsers.add_parser('batch', help='Analyse batch')
    batch_cmd.add_argument('directory', help='Repertoire contenant les .eml')
    batch_cmd.add_argument('--format', '-f',
                           choices=['csv', 'json', 'all'],
                           default='csv', help='Format export')

    # Commande : interactive
    subparsers.add_parser('interactive', help='Mode interactif')

    args = cli_parser.parse_args()

    # Creer l'analyseur
    analyzer = PhishingAnalyzerCLI(
        verbose=args.verbose,
        output_dir=args.output_dir
    )

    # Router vers la bonne commande
    if args.command == 'analyze':
        analyzer.print_banner()
        analyzer.analyze_single(args.file, export_format=args.format)

    elif args.command == 'batch':
        analyzer.print_banner()
        analyzer.analyze_batch(args.directory, export_format=args.format)

    elif args.command == 'interactive':
        analyzer.interactive_mode()

    else:
        # Pas de commande = afficher l'aide
        analyzer.print_banner()
        cli_parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Interrompu par l'utilisateur{Colors.END}")
        sys.exit(1)
