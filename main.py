#!/usr/bin/env python3
"""
MAIN.PY - Interface Utilisateur + Orchestration
Mission: Être le point d'entrée PROFESSIONNEL du projet

Utilisations:
  python main.py analyze email.eml                    # Analyse unique
  python main.py batch ./emails/                      # Batch processing
  python main.py interactive                          # Mode interactif
  python main.py --help                               # Aide complète
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import textwrap

# Imports internes
from src.email_parser import EmailParser
from src.detection_rules import PhishingDetector
from src.risk_scorer import RiskScorer
from src.exporters import ReportExporter


class Colors:
    """ANSI color codes pour terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class PhishingAnalyzerCLI:
    """
    Interface CLI complète avec:
    - Mode interactif (menu)
    - Mode batch (répertoire entier)
    - Mode analyse unique
    - Export multi-format
    - Logging détaillé
    """
    
    def __init__(self, verbose: bool = False, output_dir: str = 'output'):
        """Initialise l'analyseur"""
        self.parser = EmailParser()
        self.detector = PhishingDetector()
        self.scorer = RiskScorer()
        self.exporter = ReportExporter(output_dir)
        self.verbose = verbose
        self.output_dir = Path(output_dir)
        
        # Stats
        self.stats = {
            'total_analyzed': 0,
            'total_phishing': 0,
            'total_safe': 0,
            'avg_score': 0
        }
    
    def print_header(self):
        """Affiche le header"""
        header = f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║   🔍 PHISHING EMAIL ANALYZER v1.0 - Heuristic Detection   ║
║                                                            ║
║   Cybersecurity Tool for Email Threat Assessment         ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
        print(header)
    
    def print_usage(self):
        """Affiche les exemples d'usage"""
        usage = f"""
{Colors.BOLD}USAGE EXAMPLES:{Colors.ENDC}

  {Colors.GREEN}# Analyser un seul email{Colors.ENDC}
  python main.py analyze phishing_sample.eml

  {Colors.GREEN}# Analyser un seul email avec export JSON{Colors.ENDC}
  python main.py analyze email.eml --format json

  {Colors.GREEN}# Analyser tous les emails d'un dossier{Colors.ENDC}
  python main.py batch ./email_samples/ --format csv

  {Colors.GREEN}# Mode interactif (menu){Colors.ENDC}
  python main.py interactive

  {Colors.GREEN}# Verbose mode (debug){Colors.ENDC}
  python main.py analyze email.eml --verbose

  {Colors.GREEN}# Définir le répertoire de sortie{Colors.ENDC}
  python main.py batch ./emails/ --output-dir /tmp/reports/

{Colors.BOLD}FORMATS DE SORTIE:{Colors.ENDC}
  - console  : Rapport texte formaté (défaut)
  - json     : Format JSON structuré
  - csv      : Format CSV pour Excel/BI
  - all      : Tous les formats
"""
        print(usage)
    
    def log(self, level: str, message: str):
        """Logging avec couleurs"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if level == 'INFO':
            print(f"{Colors.BLUE}[{timestamp}] ℹ️  {message}{Colors.ENDC}")
        elif level == 'SUCCESS':
            print(f"{Colors.GREEN}[{timestamp}] ✓ {message}{Colors.ENDC}")
        elif level == 'WARNING':
            print(f"{Colors.YELLOW}[{timestamp}] ⚠️  {message}{Colors.ENDC}")
        elif level == 'ERROR':
            print(f"{Colors.RED}[{timestamp}] ✗ {message}{Colors.ENDC}")
        elif level == 'DEBUG' and self.verbose:
            print(f"{Colors.CYAN}[{timestamp}] 🐛 {message}{Colors.ENDC}")
    
    # ===== MODE 1: ANALYSE UNIQUE =====
    
    def analyze_single_file(self, eml_path: str, export_format: str = 'console') -> Optional[Dict]:
        """
        Analyse un fichier .eml unique
        
        Args:
            eml_path: Chemin du fichier .eml
            export_format: 'console', 'json', 'csv', 'all'
        
        Returns:
            Dict avec résultats complets
        """
        eml_file = Path(eml_path)
        
        # Validation
        if not eml_file.exists():
            self.log('ERROR', f"File not found: {eml_path}")
            return None
        
        if eml_file.suffix.lower() != '.eml':
            self.log('WARNING', f"File is not .eml: {eml_file.suffix}")
        
        self.log('INFO', f"Parsing: {eml_file.name}")
        
        # ===== ÉTAPE 1: PARSING =====
        parsed = self.parser.parse_eml_file(eml_path)
        
        if 'error' in parsed:
            self.log('ERROR', f"Parse error: {parsed['error']}")
            return None
        
        self.log('DEBUG', f"  └─ Headers extracted: {len(parsed['headers'])}")
        self.log('DEBUG', f"  └─ URLs found: {len(parsed['urls'])}")
        self.log('DEBUG', f"  └─ Attachments: {len(parsed['attachments'])}")
        
        # ===== ÉTAPE 2: DÉTECTION =====
        self.log('INFO', "Running 15 detection rules...")
        detection_results = self.detector.analyze(parsed)
        
        # Count triggered rules
        triggered = sum(1 for r in detection_results.values() if r['triggered'])
        self.log('DEBUG', f"  └─ {triggered} règles déclenchées")
        
        # ===== ÉTAPE 3: SCORING =====
        self.log('INFO', "Calculating risk score...")
        score, metadata = self.scorer.calculate_score(detection_results)
        
        # Build final analysis
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
        
        # ===== ÉTAPE 4: AFFICHAGE =====
        self._display_result(analysis)
        
        # ===== ÉTAPE 5: EXPORT =====
        if export_format != 'console':
            self._export_result(analysis, export_format)
        
        # Update stats
        self.stats['total_analyzed'] += 1
        self.stats['avg_score'] = (
            (self.stats['avg_score'] * (self.stats['total_analyzed'] - 1) + score) 
            / self.stats['total_analyzed']
        )
        
        if metadata['risk_level'] in ['HIGH', 'CRITICAL']:
            self.stats['total_phishing'] += 1
        else:
            self.stats['total_safe'] += 1
        
        return analysis
    
    def _display_result(self, analysis: Dict):
        """Affiche le rapport formaté"""
        score = analysis['score']
        risk_level = analysis['risk_level']
        
        # Colorer le risque
        if risk_level == 'CRITICAL':
            risk_color = Colors.RED
            risk_icon = '🚨'
        elif risk_level == 'HIGH':
            risk_color = Colors.RED
            risk_icon = '⚠️'
        elif risk_level == 'MEDIUM':
            risk_color = Colors.YELLOW
            risk_icon = '⚡'
        elif risk_level == 'LOW':
            risk_color = Colors.YELLOW
            risk_icon = '⚡'
        else:
            risk_color = Colors.GREEN
            risk_icon = '✓'
        
        # Affiche le rapport
        report = f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║           PHISHING EMAIL ANALYSIS REPORT                   ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}

📧 {Colors.BOLD}EMAIL METADATA{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  From:              {analysis['headers'].get('From', 'N/A')[:50]}
  To:                {analysis['headers'].get('To', 'N/A')[:50]}
  Subject:           {analysis['headers'].get('Subject', 'N/A')[:50]}
  Date:              {analysis['headers'].get('Date', 'N/A')[:30]}

🎯 {Colors.BOLD}RISK ASSESSMENT{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  Risk Score:        {risk_color}{Colors.BOLD}{score}/100{Colors.ENDC}
  Risk Level:        {risk_color}{Colors.BOLD}{risk_icon} {risk_level}{Colors.ENDC}
  Rules Triggered:   {analysis['triggered_rules_count']}/{analysis['total_rules']}

⚠️  {Colors.BOLD}TRIGGERED RULES ({analysis['triggered_rules_count']}){Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
"""
        
        if analysis['triggered_rules']:
            for i, rule in enumerate(analysis['triggered_rules'], 1):
                rule_color = Colors.RED if rule['weight'] >= 9 else Colors.YELLOW
                report += f"  {i}. {rule_color}{rule['name']}{Colors.ENDC} (weight: {rule['weight']})\n"
                report += f"     └─ {rule['reason']}\n"
        else:
            report += "  ✓ No suspicious rules triggered\n"
        
        # Data extraction
        report += f"""
🔗 {Colors.BOLD}EXTRACTED DATA{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  URLs Found:        {len(analysis['urls'])}
"""
        
        if analysis['urls']:
            for url in analysis['urls'][:3]:
                report += f"    • {url[:60]}\n"
            if len(analysis['urls']) > 3:
                report += f"    ... and {len(analysis['urls']) - 3} more\n"
        
        report += f"""  Emails Found:      {len(analysis['emails'])}
"""
        
        if analysis['emails']:
            for email in analysis['emails'][:3]:
                report += f"    • {email}\n"
            if len(analysis['emails']) > 3:
                report += f"    ... and {len(analysis['emails']) - 3} more\n"
        
        report += f"""  IPs Found:         {len(analysis['ips'])}
"""
        
        if analysis['ips']:
            for ip in analysis['ips'][:3]:
                report += f"    • {ip}\n"
            if len(analysis['ips']) > 3:
                report += f"    ... and {len(analysis['ips']) - 3} more\n"
        
        report += f"""  Attachments:       {len(analysis['attachments'])}
"""
        
        if analysis['attachments']:
            for att in analysis['attachments'][:3]:
                report += f"    • {att['filename']} ({att['size']} bytes)\n"
            if len(analysis['attachments']) > 3:
                report += f"    ... and {len(analysis['attachments']) - 3} more\n"
        
        report += f"""
⏰ {Colors.BOLD}METADATA{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  File:              {analysis['file_name']}
  Analysis Time:     {analysis['analysis_timestamp']}

{Colors.BOLD}{Colors.CYAN}
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
        print(report)
    
    def _export_result(self, analysis: Dict, export_format: str):
        """Exporte le résultat dans le format demandé"""
        if export_format == 'all':
            formats = ['json', 'csv']
        else:
            formats = [export_format]
        
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
            
            except Exception as e:
                self.log('ERROR', f"Export failed: {str(e)}")
    
    # ===== MODE 2: BATCH PROCESSING =====
    
    def analyze_batch(self, directory: str, export_format: str = 'csv', recursive: bool = True):
        """
        Analyse tous les .eml d'un répertoire
        
        Args:
            directory: Chemin du répertoire
            export_format: Format de sortie
            recursive: Chercher récursivement
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            self.log('ERROR', f"Directory not found: {directory}")
            return
        
        # Find .eml files
        pattern = '**/*.eml' if recursive else '*.eml'
        eml_files = list(dir_path.glob(pattern))
        
        if not eml_files:
            self.log('WARNING', f"No .eml files found in {directory}")
            return
        
        self.log('INFO', f"Found {len(eml_files)} .eml files")
        
        results = []
        
        for i, eml_file in enumerate(eml_files, 1):
            print(f"\n{Colors.CYAN}[{i}/{len(eml_files)}]{Colors.ENDC} Analyzing: {eml_file.name}")
            
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
        
        # Export batch results
        if export_format == 'all':
            formats = ['csv', 'json']
        else:
            formats = [export_format]
        
        for fmt in formats:
            try:
                if fmt == 'csv':
                    filepath = self.exporter.export_csv(results, 
                        f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                    self.log('SUCCESS', f"Batch CSV exported: {filepath}")
                
                elif fmt == 'json':
                    batch_data = {
                        'batch_analysis': {
                            'total_files': len(eml_files),
                            'total_analyzed': len(results),
                            'timestamp': datetime.now().isoformat()
                        },
                        'results': results
                    }
                    filepath = self.exporter.export_json(batch_data,
                        f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    self.log('SUCCESS', f"Batch JSON exported: {filepath}")
            
            except Exception as e:
                self.log('ERROR', f"Batch export failed: {str(e)}")
        
        # Print summary
        self._print_batch_summary(results)
    
    def _print_batch_summary(self, results: List[Dict]):
        """Affiche le résumé batch"""
        total = len(results)
        critical = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in results if r['risk_level'] == 'LOW')
        safe = sum(1 for r in results if r['risk_level'] == 'SAFE')
        
        avg_score = sum(r['score'] for r in results) / total if total > 0 else 0
        
        summary = f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════╗
║                   BATCH ANALYSIS SUMMARY                   ║
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}

📊 {Colors.BOLD}STATISTICS{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  Total Analyzed:    {total}
  Average Score:     {avg_score:.1f}/100

🎯 {Colors.BOLD}DISTRIBUTION{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}
  {Colors.RED}● CRITICAL:{Colors.ENDC}  {critical} ({critical*100/total:.1f}%)
  {Colors.RED}● HIGH:{Colors.ENDC}      {high} ({high*100/total:.1f}%)
  {Colors.YELLOW}● MEDIUM:{Colors.ENDC}    {medium} ({medium*100/total:.1f}%)
  {Colors.YELLOW}● LOW:{Colors.ENDC}       {low} ({low*100/total:.1f}%)
  {Colors.GREEN}● SAFE:{Colors.ENDC}      {safe} ({safe*100/total:.1f}%)

{Colors.BOLD}{Colors.CYAN}
╚════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
        print(summary)
    
    # ===== MODE 3: INTERACTIVE =====
    
    def interactive_mode(self):
        """Mode interactif avec menu"""
        self.print_header()
        
        while True:
            menu = f"""
{Colors.BOLD}MAIN MENU{Colors.ENDC}
{Colors.CYAN}────────────────────────────────────────────────────────────{Colors.ENDC}

  1. Analyze single email file
  2. Batch analyze directory
  3. Show help
  4. About
  5. Exit

{Colors.BOLD}Choose option (1-5):{Colors.ENDC} """
            
            choice = input(menu).strip()
            
            if choice == '1':
                filepath = input(f"{Colors.BOLD}Enter .eml file path:{Colors.ENDC} ").strip()
                fmt = input(f"{Colors.BOLD}Export format (console/json/csv/all) [console]:{Colors.ENDC} ").strip() or 'console'
                self.analyze_single_file(filepath, export_format=fmt)
            
            elif choice == '2':
                dirpath = input(f"{Colors.BOLD}Enter directory path:{Colors.ENDC} ").strip()
                fmt = input(f"{Colors.BOLD}Export format (csv/json/all) [csv]:{Colors.ENDC} ").strip() or 'csv'
                recursive = input(f"{Colors.BOLD}Recursive search (y/n) [y]:{Colors.ENDC} ").strip().lower() != 'n'
                self.analyze_batch(dirpath, export_format=fmt, recursive=recursive)
            
            elif choice == '3':
                self.print_usage()
            
            elif choice == '4':
                about = f"""
{Colors.BOLD}{Colors.CYAN}Phishing Email Analyzer v1.0{Colors.ENDC}
A heuristic-based phishing detection system for email security assessment.

{Colors.BOLD}Features:{Colors.ENDC}
  • 15+ detection rules
  • Risk scoring (0-100)
  • Multiple export formats
  • Batch processing
  • Interactive mode

{Colors.BOLD}Developed for:{Colors.ENDC}
Cybersecurity project - Email threat assessment

{Colors.BOLD}Contact:{Colors.ENDC}
Project Team © 2026
"""
                print(about)
            
            elif choice == '5':
                self.log('INFO', "Exiting...")
                break
            
            else:
                self.log('ERROR', "Invalid choice. Please try again.")
            
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")


def main():
    """Point d'entrée principal"""
    parser_cli = argparse.ArgumentParser(
        prog='Phishing Email Analyzer',
        description='🔍 Heuristic-based phishing email detection system',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            EXAMPLES:
              %(prog)s analyze email.eml
              %(prog)s batch ./emails/ --format csv
              %(prog)s interactive
              %(prog)s analyze email.eml --verbose
        """)
    )
    
    parser_cli.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser_cli.add_argument('--verbose', '-v', action='store_true', help='Verbose/debug mode')
    parser_cli.add_argument('--output-dir', '-o', default='output', help='Output directory (default: output)')
    
    subparsers = parser_cli.add_subparsers(dest='command', help='Commands')
    
    # Command: analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analyze single .eml file')
    analyze_parser.add_argument('file', help='Path to .eml file')
    analyze_parser.add_argument('--format', '-f', choices=['console', 'json', 'csv', 'all'],
                               default='console', help='Output format (default: console)')
    
    # Command: batch
    batch_parser = subparsers.add_parser('batch', help='Batch analyze directory')
    batch_parser.add_argument('directory', help='Path to directory with .eml files')
    batch_parser.add_argument('--format', '-f', choices=['csv', 'json', 'all'],
                             default='csv', help='Export format (default: csv)')
    batch_parser.add_argument('--recursive', '-r', action='store_true', help='Recursive search')
    
    # Command: interactive
    interactive_parser = subparsers.add_parser('interactive', help='Launch interactive menu')
    
    args = parser_cli.parse_args()
    
    # Initialise CLI
    cli = PhishingAnalyzerCLI(verbose=args.verbose, output_dir=args.output_dir)
    
    # Routing
    if args.command == 'analyze':
        cli.print_header()
        cli.analyze_single_file(args.file, export_format=args.format)
    
    elif args.command == 'batch':
        cli.print_header()
        cli.analyze_batch(args.directory, export_format=args.format, recursive=args.recursive)
    
    elif args.command == 'interactive':
        cli.interactive_mode()
    
    else:
        # No command = show usage
        cli.print_header()
        cli.print_usage()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
