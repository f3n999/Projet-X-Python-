#!/usr/bin/env python3
"""
MAIN.PY - Point d'entrée et orchestration CLI
Utilisations:
  python main.py analyze email.eml
  python main.py batch ./emails/ --format csv
  python main.py interactive
  python main.py --help
"""

import argparse
import sys
import textwrap
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from src.email_parser import EmailParser
from src.detection_rules import PhishingDetector
from src.risk_scorer import RiskScorer
from src.exporters import ReportExporter


# ============================================================================
# COULEURS TERMINAL (ANSI)
# ============================================================================

class Colors:
    """Codes ANSI pour coloriser la sortie terminal."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# CLASSE CLI PRINCIPALE
# ============================================================================

class PhishingAnalyzerCLI:
    """
    Interface CLI avec 3 modes :
    - analyze : analyse un fichier .eml unique
    - batch   : analyse tous les .eml d'un répertoire
    - interactive : menu interactif
    """

    def __init__(self, verbose: bool = False, output_dir: str = 'output'):
        self.parser = EmailParser()
        self.detector = PhishingDetector()
        self.scorer = RiskScorer()
        self.exporter = ReportExporter(output_dir)
        self.verbose = verbose
        self.output_dir = Path(output_dir)

        self.stats = {
            'total_analyzed': 0,
            'total_phishing': 0,
            'total_safe': 0,
            'avg_score': 0
        }

    # ========================================================================
    # AFFICHAGE
    # ========================================================================

    @staticmethod
    def print_header():
        """Affiche le banner de l'outil."""
        print(f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║   PHISHING EMAIL ANALYZER v1.0 - Heuristic Detection      ║
║   Cybersecurity Tool for Email Threat Assessment           ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}""")

    @staticmethod
    def print_usage():
        """Affiche les exemples d'utilisation."""
        print(f"""
{Colors.BOLD}USAGE :{Colors.ENDC}

  python main.py analyze email.eml              Analyse unique
  python main.py analyze email.eml --format json Avec export JSON
  python main.py batch ./emails/ --format csv    Batch processing
  python main.py interactive                     Mode interactif
  python main.py analyze email.eml --verbose     Mode debug

{Colors.BOLD}FORMATS DE SORTIE :{Colors.ENDC}
  console  : Rapport texte formaté (défaut)
  json     : Format JSON structuré
  csv      : Format CSV
  all      : Tous les formats
""")

    def log(self, level: str, message: str):
        """Log avec couleurs et timestamp."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors_map = {
            'INFO': Colors.BLUE,
            'SUCCESS': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED,
            'DEBUG': Colors.CYAN,
        }
        if level == 'DEBUG' and not self.verbose:
            return

        color = colors_map.get(level, Colors.ENDC)
        print(f"{color}[{timestamp}] {message}{Colors.ENDC}")

    # ========================================================================
    # MODE 1 : ANALYSE UNIQUE
    # ========================================================================

    def analyze_single_file(self, eml_path: str, export_format: str = 'console') -> Optional[Dict]:
        """Analyse un fichier .eml et retourne les résultats."""
        eml_file = Path(eml_path)

        if not eml_file.exists():
            self.log('ERROR', f"File not found: {eml_path}")
            return None

        if eml_file.suffix.lower() != '.eml':
            self.log('WARNING', f"File is not .eml: {eml_file.suffix}")

        self.log('INFO', f"Parsing: {eml_file.name}")

        # Etape 1 : Parsing
        parsed = self.parser.parse_eml_file(eml_path)
        if 'error' in parsed:
            self.log('ERROR', f"Parse error: {parsed['error']}")
            return None

        self.log('DEBUG', f"  Headers: {len(parsed['headers'])}")
        self.log('DEBUG', f"  URLs: {len(parsed['urls'])}")
        self.log('DEBUG', f"  Attachments: {len(parsed['attachments'])}")

        # Etape 2 : Détection
        self.log('INFO', "Running 15 detection rules...")
        detection_results = self.detector.analyze(parsed)
        triggered = sum(1 for r in detection_results.values() if r['triggered'])
        self.log('DEBUG', f"  {triggered} rules triggered")

        # Etape 3 : Scoring
        self.log('INFO', "Calculating risk score...")
        score, metadata = self.scorer.calculate_score(detection_results)

        # Construction du résultat final
        analysis = {
            'file_path': eml_path,
            'file_name': eml_file.name,
            'analysis_timestamp': datetime.now().isoformat(),
            'headers': parsed['headers'],
            'urls': parsed['urls'],
            'emails': parsed['emails'],
            'ips': parsed['ips'],
            'attachments': parsed['attachments'],
            'detection_results': detection_results,
            'score': score,
            **metadata
        }

        # Affichage
        self._display_result(analysis)

        # Export
        if export_format not in ('console', 'none'):
            self._export_result(analysis, export_format)

        # Stats
        self._update_stats(score, metadata['risk_level'])

        return analysis

    def _update_stats(self, score: int, risk_level: str):
        """Met à jour les statistiques internes."""
        self.stats['total_analyzed'] += 1
        n = self.stats['total_analyzed']
        self.stats['avg_score'] = (self.stats['avg_score'] * (n - 1) + score) / n

        if risk_level in ('HIGH', 'CRITICAL'):
            self.stats['total_phishing'] += 1
        else:
            self.stats['total_safe'] += 1

    def _display_result(self, analysis: Dict):
        """Affiche le rapport formaté dans le terminal."""
        score = analysis['score']
        risk_level = analysis['risk_level']

        risk_styles = {
            'CRITICAL': (Colors.RED, '!!!'),
            'HIGH':     (Colors.RED, '!! '),
            'MEDIUM':   (Colors.YELLOW, '!  '),
            'LOW':      (Colors.YELLOW, '.  '),
            'SAFE':     (Colors.GREEN, 'OK '),
        }
        risk_color, risk_icon = risk_styles.get(risk_level, (Colors.ENDC, '?  '))

        print(f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║           PHISHING EMAIL ANALYSIS REPORT                   ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.BOLD}EMAIL METADATA{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  From:              {analysis['headers'].get('From', 'N/A')[:50]}
  To:                {analysis['headers'].get('To', 'N/A')[:50]}
  Subject:           {analysis['headers'].get('Subject', 'N/A')[:50]}
  Date:              {analysis['headers'].get('Date', 'N/A')[:30]}

{Colors.BOLD}RISK ASSESSMENT{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  Risk Score:        {risk_color}{Colors.BOLD}{score}/100{Colors.ENDC}
  Risk Level:        {risk_color}{Colors.BOLD}[{risk_icon}] {risk_level}{Colors.ENDC}
  Rules Triggered:   {analysis['triggered_rules_count']}/{analysis['total_rules']}

{Colors.BOLD}TRIGGERED RULES ({analysis['triggered_rules_count']}){Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}""")

        if analysis['triggered_rules']:
            for i, rule in enumerate(analysis['triggered_rules'], 1):
                rule_color = Colors.RED if rule['weight'] >= 9 else Colors.YELLOW
                print(f"  {i}. {rule_color}{rule['name']}{Colors.ENDC} (weight: {rule['weight']})")
                print(f"     {rule['reason']}")
        else:
            print("  No suspicious rules triggered")

        # Données extraites
        print(f"""
{Colors.BOLD}EXTRACTED DATA{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  URLs:        {len(analysis['urls'])}
  Emails:      {len(analysis['emails'])}
  IPs:         {len(analysis['ips'])}
  Attachments: {len(analysis['attachments'])}

  File:        {analysis['file_name']}
  Timestamp:   {analysis['analysis_timestamp']}
""")

    def _export_result(self, analysis: Dict, export_format: str):
        """Exporte le résultat dans le(s) format(s) demandé(s)."""
        formats = ['json', 'csv'] if export_format == 'all' else [export_format]

        for fmt in formats:
            try:
                if fmt == 'json':
                    filepath = self.exporter.export_json(analysis)
                    self.log('SUCCESS', f"JSON export: {filepath}")
                elif fmt == 'csv':
                    csv_data = [{
                        'filename': analysis['file_name'],
                        'from': analysis['headers'].get('From', 'N/A'),
                        'subject': analysis['headers'].get('Subject', 'N/A'),
                        'score': analysis['score'],
                        'risk_level': analysis['risk_level'],
                        'triggered_rules': analysis['triggered_rules_count'],
                        'urls_count': len(analysis['urls']),
                        'attachments_count': len(analysis['attachments'])
                    }]
                    filepath = self.exporter.export_csv(csv_data)
                    self.log('SUCCESS', f"CSV export: {filepath}")
            except (OSError, IOError) as e:
                self.log('ERROR', f"Export failed: {str(e)}")

    # ========================================================================
    # MODE 2 : BATCH PROCESSING
    # ========================================================================

    def analyze_batch(self, directory: str, export_format: str = 'csv', recursive: bool = True):
        """Analyse tous les .eml d'un répertoire."""
        dir_path = Path(directory)

        if not dir_path.exists():
            self.log('ERROR', f"Directory not found: {directory}")
            return

        pattern = '**/*.eml' if recursive else '*.eml'
        eml_files = list(dir_path.glob(pattern))

        if not eml_files:
            self.log('WARNING', f"No .eml files found in {directory}")
            return

        self.log('INFO', f"Found {len(eml_files)} .eml files")

        results = []
        for i, eml_file in enumerate(eml_files, 1):
            print(f"\n{Colors.CYAN}[{i}/{len(eml_files)}]{Colors.ENDC} {eml_file.name}")
            analysis = self.analyze_single_file(str(eml_file), export_format='none')

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

        # Export batch
        formats = ['csv', 'json'] if export_format == 'all' else [export_format]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        for fmt in formats:
            try:
                if fmt == 'csv':
                    filepath = self.exporter.export_csv(results, f"batch_report_{timestamp}.csv")
                    self.log('SUCCESS', f"Batch CSV: {filepath}")
                elif fmt == 'json':
                    batch_data = {
                        'batch_analysis': {
                            'total_files': len(eml_files),
                            'total_analyzed': len(results),
                            'timestamp': datetime.now().isoformat()
                        },
                        'results': results
                    }
                    filepath = self.exporter.export_json(batch_data, f"batch_report_{timestamp}.json")
                    self.log('SUCCESS', f"Batch JSON: {filepath}")
            except (OSError, IOError) as e:
                self.log('ERROR', f"Batch export failed: {str(e)}")

        self._print_batch_summary(results)

    def _print_batch_summary(self, results: List[Dict]):
        """Affiche le résumé des résultats batch."""
        total = len(results)
        if total == 0:
            self.log('WARNING', "No results to summarize")
            return

        distribution = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0
        }
        for r in results:
            distribution[r['risk_level']] = distribution.get(r['risk_level'], 0) + 1

        avg_score = sum(r['score'] for r in results) / total

        print(f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║                   BATCH ANALYSIS SUMMARY                   ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}
  Total Analyzed:  {total}
  Average Score:   {avg_score:.1f}/100

  {Colors.RED}CRITICAL:{Colors.ENDC}  {distribution['CRITICAL']} ({distribution['CRITICAL'] * 100 / total:.1f}%)
  {Colors.RED}HIGH:{Colors.ENDC}      {distribution['HIGH']} ({distribution['HIGH'] * 100 / total:.1f}%)
  {Colors.YELLOW}MEDIUM:{Colors.ENDC}    {distribution['MEDIUM']} ({distribution['MEDIUM'] * 100 / total:.1f}%)
  {Colors.YELLOW}LOW:{Colors.ENDC}       {distribution['LOW']} ({distribution['LOW'] * 100 / total:.1f}%)
  {Colors.GREEN}SAFE:{Colors.ENDC}      {distribution['SAFE']} ({distribution['SAFE'] * 100 / total:.1f}%)
""")

    # ========================================================================
    # MODE 3 : INTERACTIF
    # ========================================================================

    def interactive_mode(self):
        """Lance le menu interactif."""
        self.print_header()

        while True:
            print(f"""
{Colors.BOLD}MENU{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  1. Analyser un fichier email
  2. Analyser un répertoire (batch)
  3. Aide
  4. Quitter
""")
            choice = input(f"{Colors.BOLD}Choix (1-4): {Colors.ENDC}").strip()

            if choice == '1':
                filepath = input("Chemin du fichier .eml: ").strip()
                fmt = input("Format (console/json/csv/all) [console]: ").strip() or 'console'
                self.analyze_single_file(filepath, export_format=fmt)

            elif choice == '2':
                dirpath = input("Chemin du répertoire: ").strip()
                fmt = input("Format (csv/json/all) [csv]: ").strip() or 'csv'
                recursive = input("Recherche récursive (y/n) [y]: ").strip().lower() != 'n'
                self.analyze_batch(dirpath, export_format=fmt, recursive=recursive)

            elif choice == '3':
                self.print_usage()

            elif choice == '4':
                self.log('INFO', "Exiting...")
                break

            else:
                self.log('ERROR', "Choix invalide")

            input(f"\n{Colors.BOLD}Appuyez sur Entrée...{Colors.ENDC}")


# ============================================================================
# POINT D'ENTREE
# ============================================================================

def main():
    """Parse les arguments CLI et lance le mode approprié."""
    parser_cli = argparse.ArgumentParser(
        prog='Phishing Email Analyzer',
        description='Outil de détection heuristique de phishing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Exemples:
              %(prog)s analyze email.eml
              %(prog)s batch ./emails/ --format csv
              %(prog)s interactive
        """)
    )

    parser_cli.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser_cli.add_argument('--verbose', '-v', action='store_true', help='Mode debug')
    parser_cli.add_argument('--output-dir', '-o', default='output', help='Répertoire de sortie')

    subparsers = parser_cli.add_subparsers(dest='command', help='Commandes')

    # analyze
    p_analyze = subparsers.add_parser('analyze', help='Analyser un fichier .eml')
    p_analyze.add_argument('file', help='Chemin du fichier .eml')
    p_analyze.add_argument('--format', '-f', choices=['console', 'json', 'csv', 'all'],
                           default='console', help='Format de sortie')

    # batch
    p_batch = subparsers.add_parser('batch', help='Analyser un répertoire')
    p_batch.add_argument('directory', help='Chemin du répertoire')
    p_batch.add_argument('--format', '-f', choices=['csv', 'json', 'all'],
                         default='csv', help='Format export')
    p_batch.add_argument('--recursive', '-r', action='store_true', help='Recherche récursive')

    # interactive
    subparsers.add_parser('interactive', help='Mode interactif')

    args = parser_cli.parse_args()
    cli = PhishingAnalyzerCLI(verbose=args.verbose, output_dir=args.output_dir)

    if args.command == 'analyze':
        cli.print_header()
        cli.analyze_single_file(args.file, export_format=args.format)
    elif args.command == 'batch':
        cli.print_header()
        cli.analyze_batch(args.directory, export_format=args.format, recursive=args.recursive)
    elif args.command == 'interactive':
        cli.interactive_mode()
    else:
        cli.print_header()
        cli.print_usage()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
