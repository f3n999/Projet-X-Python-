"""
EXPORTERS - Generation de rapports et exports
Mission : Exporter les resultats d'analyse en CSV, JSON ou rapport texte

Librairies utilisees :
    - csv (stdlib)      : ecriture de fichiers CSV
    - json (stdlib)     : ecriture de fichiers JSON
    - datetime (stdlib) : horodatage des rapports
    - pathlib (stdlib)  : manipulation de chemins de fichiers
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class ReportExporter:
    """
    Exporte les resultats d'analyse dans differents formats.

    Utilisation :
        exporter = ReportExporter('output')
        exporter.export_json(analysis_result)
        exporter.export_csv(results_list)
    """

    def __init__(self, output_dir: str = 'output'):
        """
        Args:
            output_dir : repertoire de sortie pour les fichiers generes
        """
        self.output_dir = Path(output_dir)
        # Creer le repertoire s'il n'existe pas (exist_ok=True evite l'erreur)
        self.output_dir.mkdir(exist_ok=True)

    def export_csv(self, results_list: List[Dict], filename: str = None) -> str:
        """
        Exporte une liste de resultats en fichier CSV.

        Args:
            results_list : liste de dictionnaires (un par email analyse)
            filename     : nom du fichier (auto-genere si None)

        Returns:
            Chemin du fichier cree
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"phishing_report_{timestamp}.csv"

        filepath = self.output_dir / 'reports_csv' / filename
        filepath.parent.mkdir(exist_ok=True, parents=True)

        # csv.DictWriter ecrit chaque dictionnaire comme une ligne du CSV
        # fieldnames definit l'ordre des colonnes
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'filename', 'from', 'subject', 'score', 'risk_level',
                'triggered_rules', 'urls_count', 'attachments_count'
            ])
            writer.writeheader()
            writer.writerows(results_list)

        return str(filepath)

    def export_json(self, analysis_result: Dict, filename: str = None) -> str:
        """
        Exporte un resultat d'analyse en fichier JSON.

        Args:
            analysis_result : dictionnaire complet de l'analyse
            filename        : nom du fichier (auto-genere si None)

        Returns:
            Chemin du fichier cree
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"analysis_{timestamp}.json"

        filepath = self.output_dir / filename

        # indent=2 : JSON lisible (pas sur une seule ligne)
        # default=str : convertit les objets non-serialisables en string
        #               (ex: datetime -> "2026-02-10T14:30:00")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, indent=2, default=str, ensure_ascii=False)

        return str(filepath)

    def generate_report(self, analysis_result: Dict) -> str:
        """
        Genere un rapport texte formate lisible en terminal.

        Args:
            analysis_result : dictionnaire complet (score + metadata + headers)

        Returns:
            String du rapport formate
        """
        report = f"""
========================================================
          PHISHING EMAIL ANALYSIS REPORT
========================================================

--- EMAIL METADATA ---
From:        {analysis_result['headers'].get('From', 'N/A')}
To:          {analysis_result['headers'].get('To', 'N/A')}
Subject:     {analysis_result['headers'].get('Subject', 'N/A')}
Date:        {analysis_result['headers'].get('Date', 'N/A')}

--- RISK ASSESSMENT ---
Risk Score:  {analysis_result['score']}/100
Risk Level:  {analysis_result['risk_level']}
Triggered:   {analysis_result['triggered_rules_count']}/{analysis_result['total_rules']} regles

--- TRIGGERED RULES ---
"""

        for rule in analysis_result['triggered_rules']:
            report += f"  * {rule['name']} (poids: {rule['weight']})\n"
            report += f"    -> {rule['reason']}\n"

        if not analysis_result['triggered_rules']:
            report += "  Aucune regle declenchee\n"

        report += f"""
--- EXTRACTED DATA ---
URLs trouvees :        {len(analysis_result.get('urls', []))}
Emails trouves :       {len(analysis_result.get('emails', []))}
IPs trouvees :         {len(analysis_result.get('ips', []))}
Pieces jointes :       {len(analysis_result.get('attachments', []))}

--- METADATA ---
Timestamp : {datetime.now().isoformat()}
========================================================
"""

        return report
