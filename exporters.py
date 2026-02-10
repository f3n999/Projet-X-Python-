"""
EXPORTERS - Génération de rapports et exports
Mission: CSV, JSON, rapports formatés
"""

import csv
import json
from datetime import datetime
from pathlib import Path


class ReportExporter:
    """Exporte les résultats dans différents formats"""
    
    def __init__(self, output_dir='output'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def export_csv(self, results_list: list, filename: str = None) -> str:
        """Exporte en CSV"""
        if filename is None:
            filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = self.output_dir / 'reports_csv' / filename
        filepath.parent.mkdir(exist_ok=True, parents=True)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'filename', 'from', 'subject', 'score', 'risk_level',
                'triggered_rules', 'urls_count', 'attachments_count'
            ])
            writer.writeheader()
            writer.writerows(results_list)
        
        return str(filepath)
    
    def export_json(self, analysis_result: Dict, filename: str = None) -> str:
        """Exporte en JSON"""
        if filename is None:
            filename = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(analysis_result, f, indent=2, default=str)
        
        return str(filepath)
    
    def generate_report(self, analysis_result: Dict) -> str:
        """Génère un rapport texte formaté"""
        report = f"""
╔════════════════════════════════════════════════════════════╗
║             PHISHING EMAIL ANALYSIS REPORT                 ║
╚════════════════════════════════════════════════════════════╝

📧 EMAIL METADATA
─────────────────────────────────────────────────────────────
From:        {analysis_result['headers']['From']}
To:          {analysis_result['headers']['To']}
Subject:     {analysis_result['headers']['Subject']}
Date:        {analysis_result['headers']['Date']}

🎯 RISK ASSESSMENT
─────────────────────────────────────────────────────────────
Risk Score:  {analysis_result['score']}/100
Risk Level:  {analysis_result['risk_level']}
Triggered:   {analysis_result['triggered_rules_count']}/{analysis_result['total_rules']} règles

⚠️ TRIGGERED RULES
─────────────────────────────────────────────────────────────
"""
        
        for rule in analysis_result['triggered_rules']:
            report += f"  • {rule['name']} (weight: {rule['weight']})\n"
            report += f"    └─ {rule['reason']}\n"
        
        report += f"""
🔗 EXTRACTION DATA
─────────────────────────────────────────────────────────────
URLs Found:        {len(analysis_result['urls'])}
Emails Found:      {len(analysis_result['emails'])}
IPs Found:         {len(analysis_result['ips'])}
Attachments:       {len(analysis_result['attachments'])}

⏰ Analysis Timestamp: {datetime.now().isoformat()}
"""
        
        return report
