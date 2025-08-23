#!/usr/bin/env python3

import json
import os
from datetime import datetime
from textwrap import wrap

class ReportGenerator:
    def __init__(self):
        self.report_data = {
            'executive_summary': '',
            'technical_findings': [],
            'risk_assessment': [],
            'recommendations': []
        }
    
    def generate_html_report(self, scan_data, output_file=None):
        """Generate a beautiful HTML report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"results/kapa_report_{timestamp}.html"
        
        # Extract key findings
        targets = scan_data.get('prioritized_targets', [])
        attacks = scan_data.get('attack_results', {})
        
        # Create HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>KAPA Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; background: #f8f9fa; }}
                .critical {{ border-color: #e74c3c; background: #fdeaea; }}
                .high {{ border-color: #e67e22; background: #fef5eb; }}
                .medium {{ border-color: #f39c12; background: #fef9e7; }}
                .low {{ border-color: #27ae60; background: #eafaf1; }}
                .finding {{ margin: 10px 0; padding: 10px; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ KAPA Security Assessment Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p>Assessment of network: {scan_data.get('network_range', 'Unknown')}</p>
                <p>Targets scanned: {len(scan_data.get('hosts', {}))}</p>
                <p>High-value targets identified: {len([t for t in targets if t.get('target_value') == 1])}</p>
            </div>
            
            <div class="section">
                <h2>🎯 High-Value Targets</h2>
                <table>
                    <tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Services</th><th>Risk Level</th></tr>
        """
        
        for target in targets:
            risk_level = "HIGH" if target.get('target_value') == 1 else "LOW"
            risk_class = "high" if risk_level == "HIGH" else "low"
            html_content += f"""
                    <tr class="{risk_class}">
                        <td>{target.get('ip', 'N/A')}</td>
                        <td>{target.get('hostname', 'N/A')}</td>
                        <td>{target.get('os', 'N/A')}</td>
                        <td>{', '.join(target.get('services', [])[:3])}</td>
                        <td>{risk_level}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
        """
        
        # Add attack results if available
        if attacks.get('smb_attacks'):
            smb = attacks['smb_attacks']
            html_content += """
            <div class="section">
                <h2>🔍 SMB Security Assessment</h2>
            """
            
            if smb.get('smb_attacks', {}).get('null_session', {}).get('vulnerable'):
                html_content += """
                <div class="finding critical">
                    <h3>❌ CRITICAL: SMB Null Session Allowed</h3>
                    <p>Attackers can access SMB shares without authentication.</p>
                </div>
                """
            else:
                html_content += """
                <div class="finding low">
                    <h3>✅ SMB Null Session Blocked</h3>
                    <p>Good security practice - anonymous access is disabled.</p>
                </div>
                """
            
            html_content += """
            </div>
            """
        
        html_content += """
            <div class="section">
                <h2>📈 Risk Assessment</h2>
                <p>Overall Network Risk: <strong>MEDIUM</strong></p>
                <ul>
                    <li>Multiple Windows systems detected</li>
                    <li>SMB services exposed</li>
                    <li>Web services detected</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>🔧 Recommendations</h2>
                <ol>
                    <li>Ensure all systems are patched and updated</li>
                    <li>Disable unnecessary services (SMB if not needed)</li>
                    <li>Implement network segmentation</li>
                    <li>Enable Windows Firewall with proper rules</li>
                    <li>Regular security assessments</li>
                </ol>
            </div>
            
            <div class="section">
                <p><em>Report generated by KAPA (Kali Automated Pentest Assistant)</em></p>
            </div>
        </body>
        </html>
        """
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def generate_text_report(self, scan_data, output_file=None):
        """Generate a simple text report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"results/kapa_report_{timestamp}.txt"
        
        report_lines = [
            "=" * 60,
            "KAPA SECURITY ASSESSMENT REPORT",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Network: {scan_data.get('network_range', 'Unknown')}",
            "",
            "SUMMARY:",
            "-" * 40,
            f"Targets found: {len(scan_data.get('hosts', {}))}",
            f"High-value targets: {len([t for t in scan_data.get('prioritized_targets', []) if t.get('target_value') == 1])}",
            "",
            "HIGH-VALUE TARGETS:",
            "-" * 40,
        ]
        
        for target in scan_data.get('prioritized_targets', []):
            if target.get('target_value') == 1:
                report_lines.append(
                    f"🔴 {target.get('ip')} - {target.get('hostname')} - {target.get('os')}"
                )
                report_lines.append(
                    f"   Services: {', '.join(target.get('services', []))}"
                )
                report_lines.append("")
        
        # Add SMB findings in simple language
        if scan_data.get('attack_results', {}).get('smb_attacks'):
            smb = scan_data['attack_results']['smb_attacks']
            report_lines.extend([
                "SMB SECURITY CHECK:",
                "-" * 40,
            ])
            
            if smb.get('smb_attacks', {}).get('null_session', {}).get('vulnerable'):
                report_lines.extend([
                    "❌ CRITICAL: SMB Null Session vulnerability found!",
                    "   Anyone can access files without password",
                    "   Recommendation: Disable null sessions immediately",
                    ""
                ])
            else:
                report_lines.extend([
                    "✅ SMB Null Sessions are properly disabled",
                    "   Good security practice implemented",
                    ""
                ])
        
        report_lines.extend([
            "RECOMMENDATIONS:",
            "-" * 40,
            "1. Patch all systems regularly",
            "2. Disable unnecessary services",
            "3. Enable firewalls",
            "4. Use strong passwords",
            "5. Regular security testing",
            "",
            "Report generated by KAPA Automated Pentest Tool"
        ])
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        return output_file

# Example usage
if __name__ == "__main__":
    # Test the report generator
    sample_data = {
        'network_range': '10.0.3.0/24',
        'prioritized_targets': [
            {'ip': '10.0.3.20', 'hostname': 'WIN-R8LVLJJ4H2M', 'os': 'Windows Server 2022', 
             'services': ['msrpc', 'netbios-ssn', 'microsoft-ds', 'http'], 'target_value': 1}
        ],
        'attack_results': {
            'smb_attacks': {
                'smb_attacks': {
                    'null_session': {'vulnerable': False}
                }
            }
        }
    }
    
    generator = ReportGenerator()
    html_report = generator.generate_html_report(sample_data, "test_report.html")
    text_report = generator.generate_text_report(sample_data, "test_report.txt")
    
    print(f"HTML report: {html_report}")
    print(f"Text report: {text_report}")
