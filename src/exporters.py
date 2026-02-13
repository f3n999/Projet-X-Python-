"""
EXPORTERS - Generation de rapports et exports

Exporte les resultats d'analyse en CSV, JSON ou rapport texte.

Librairies :
    - csv (stdlib)      : ecriture de fichiers CSV
    - json (stdlib)     : ecriture de fichiers JSON
    - datetime (stdlib) : horodatage des rapports
"""

import csv
import json
from datetime import datetime
from pathlib import Path


class ReportExporter:
    """
    Exporte les resultats d'analyse dans differents formats.

    Utilisation :
        exporter = ReportExporter('output')
        exporter.export_json(analyse)
        exporter.export_csv(liste_resultats)
    """

    def __init__(self, output_dir='output'):
        """
        Args:
            output_dir : repertoire de sortie pour les fichiers generes
        """
        self.output_dir = Path(output_dir)
        # Creer le repertoire s'il n'existe pas
        self.output_dir.mkdir(exist_ok=True)

    def export_csv(self, results_list, filename=None):
        """
        Exporte une liste de resultats en fichier CSV.

        Args:
            results_list : liste de dictionnaires (un par email analyse)
            filename     : nom du fichier (auto-genere si None)

        Returns:
            Le chemin du fichier cree
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = 'phishing_report_' + timestamp + '.csv'

        filepath = self.output_dir / 'reports_csv' / filename
        # Creer le sous-dossier reports_csv
        filepath.parent.mkdir(exist_ok=True, parents=True)

        # Ecrire le CSV
        colonnes = [
            'filename', 'from', 'subject', 'score', 'risk_level',
            'triggered_rules', 'urls_count', 'attachments_count'
        ]

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=colonnes)
            writer.writeheader()       # Ecrire la ligne d'en-tete
            writer.writerows(results_list)  # Ecrire les donnees

        return str(filepath)

    def export_json(self, analysis_result, filename=None):
        """
        Exporte un resultat d'analyse en fichier JSON.

        Args:
            analysis_result : dictionnaire complet de l'analyse
            filename        : nom du fichier (auto-genere si None)

        Returns:
            Le chemin du fichier cree
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = 'analysis_' + timestamp + '.json'

        filepath = self.output_dir / filename

        # Ecrire le JSON (indent=2 pour que ce soit lisible)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, indent=2, default=str, ensure_ascii=False)

        return str(filepath)

    def generate_report(self, analysis_result):
        """
        Genere un rapport texte lisible.

        Args:
            analysis_result : dictionnaire complet de l'analyse

        Returns:
            Le rapport sous forme de texte
        """
        # En-tete du rapport
        report = "\n"
        report = report + "========================================================\n"
        report = report + "          PHISHING EMAIL ANALYSIS REPORT\n"
        report = report + "========================================================\n"
        report = report + "\n"

        # Metadata de l'email
        report = report + "--- EMAIL METADATA ---\n"
        report = report + "From:        " + analysis_result['headers'].get('From', 'N/A') + "\n"
        report = report + "To:          " + analysis_result['headers'].get('To', 'N/A') + "\n"
        report = report + "Subject:     " + analysis_result['headers'].get('Subject', 'N/A') + "\n"
        report = report + "Date:        " + analysis_result['headers'].get('Date', 'N/A') + "\n"
        report = report + "\n"

        # Score de risque
        report = report + "--- RISK ASSESSMENT ---\n"
        report = report + "Risk Score:  " + str(analysis_result['score']) + "/100\n"
        report = report + "Risk Level:  " + analysis_result['risk_level'] + "\n"
        report = report + "Triggered:   " + str(analysis_result['triggered_rules_count'])
        report = report + "/" + str(analysis_result['total_rules']) + " regles\n"
        report = report + "\n"

        # Regles declenchees
        report = report + "--- TRIGGERED RULES ---\n"
        for rule in analysis_result['triggered_rules']:
            report = report + "  * " + rule['name'] + " (poids: " + str(rule['weight']) + ")\n"
            report = report + "    -> " + rule['reason'] + "\n"

        if not analysis_result['triggered_rules']:
            report = report + "  Aucune regle declenchee\n"

        report = report + "\n"

        # Donnees extraites
        report = report + "--- EXTRACTED DATA ---\n"
        report = report + "URLs trouvees :     " + str(len(analysis_result.get('urls', []))) + "\n"
        report = report + "Emails trouves :    " + str(len(analysis_result.get('emails', []))) + "\n"
        report = report + "IPs trouvees :      " + str(len(analysis_result.get('ips', []))) + "\n"
        report = report + "Pieces jointes :    " + str(len(analysis_result.get('attachments', []))) + "\n"
        report = report + "\n"
        report = report + "Timestamp : " + datetime.now().isoformat() + "\n"
        report = report + "========================================================\n"

        return report
