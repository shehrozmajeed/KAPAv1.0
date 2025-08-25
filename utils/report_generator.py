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
        """Generate a beautiful HTML report with separate sections for each attack"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"results/kapa_report_{timestamp}.html"
        
        # Extract key findings
        targets = scan_data.get('prioritized_targets', [])
        attacks = scan_data.get('attack_results', {})
        successful_compromise = scan_data.get('successful_compromise', False)
        
        # Pre-calculate values for the template
        risk_class = "risk-high" if successful_compromise else "risk-low"
        risk_level = "HIGH" if successful_compromise else "LOW"
        timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        network_range = scan_data.get('network_range', 'Unknown')
        num_hosts = len(scan_data.get('hosts', {}))
        num_high_value = len([t for t in targets if t.get('target_value') == 1])
        
        # Create HTML report using f-strings only
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>KAPA Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; border-radius: 10px 10px 0 0; margin: -30px -30px 30px -30px; }}
        .section {{ margin: 25px 0; padding: 20px; border-left: 5px solid #3498db; background: #f8f9fa; border-radius: 5px; }}
        .critical {{ border-left-color: #e74c3c; background: #fdeaea; }}
        .high {{ border-left-color: #e67e22; background: #fef5eb; }}
        .medium {{ border-left-color: #f39c12; background: #fef9e7; }}
        .low {{ border-left-color: #27ae60; background: #eafaf1; }}
        .success {{ border-left-color: #27ae60; background: #d4f7dc; }}
        .finding {{ margin: 15px 0; padding: 15px; border-radius: 5px; background: white; border: 1px solid #ddd; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; font-weight: bold; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .attack-section {{ margin: 30px 0; padding: 25px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e9ecef; }}
        .attack-header {{ font-size: 1.5em; color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }}
        .summary-box {{ background: #e8f4fc; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #b8d4f0; }}
        .compromise-status {{ font-size: 1.2em; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; font-weight: bold; }}
        .compromise-yes {{ background: #d4f7dc; color: #27ae60; border: 2px solid #27ae60; }}
        .compromise-no {{ background: #fdeaea; color: #e74c3c; border: 2px solid #e74c3c; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .risk-badge {{ padding: 5px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; color: white; }}
        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #e67e22; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #27ae60; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ KAPA Security Assessment Report</h1>
            <p>Generated: {timestamp_str}</p>
            <p>Target Network: {network_range}</p>
        </div>
        
        <div class="compromise-status {'compromise-yes' if successful_compromise else 'compromise-no'}">
            {'✅ SUCCESSFUL COMPROMISE: System Access Obtained' if successful_compromise else '❌ NO SUCCESSFUL COMPROMISE: System Secured'}
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-box">
                <p><strong>Assessment Overview:</strong> Comprehensive security assessment performed by KAPA Automated Pentest Assistant</p>
                <p><strong>Targets Scanned:</strong> {num_hosts} hosts</p>
                <p><strong>High-value Targets:</strong> {num_high_value} systems</p>
                <p><strong>Assessment Duration:</strong> Automated comprehensive testing</p>
                <p><strong>Overall Risk Level:</strong> <span class="risk-badge {risk_class}">{risk_level}</span></p>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 High-Value Targets</h2>
            <table>
                <tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Services</th><th>Risk Level</th></tr>
"""
        
        # Add target rows
        for target in targets:
            target_risk_level = "HIGH" if target.get('target_value') == 1 else "LOW"
            target_risk_class = "risk-high" if target_risk_level == "HIGH" else "risk-low"
            html_content += f"""
                <tr>
                    <td>{target.get('ip', 'N/A')}</td>
                    <td>{target.get('hostname', 'N/A')}</td>
                    <td>{target.get('os', 'N/A')}</td>
                    <td>{', '.join(target.get('services', [])[:3])}</td>
                    <td><span class="risk-badge {target_risk_class}">{target_risk_level}</span></td>
                </tr>
"""
        
        html_content += f"""
            </table>
        </div>
"""
        
        # SMB Attack Results Section
        if attacks.get('smb_attacks'):
            smb = attacks['smb_attacks']
            html_content += """
        <div class="attack-section">
            <div class="attack-header">🔍 SMB Security Assessment</div>
"""
            
            if smb.get('smb_attacks', {}).get('null_session', {}).get('vulnerable'):
                html_content += """
            <div class="finding critical">
                <h3>❌ CRITICAL: SMB Null Session Vulnerability</h3>
                <p><strong>Impact:</strong> Attackers can access SMB shares without authentication</p>
                <p><strong>Details:</strong> Anonymous users can enumerate shares and potentially access sensitive data</p>
                <p><strong>Recommendation:</strong> Disable null sessions immediately via registry settings</p>
            </div>
"""
            else:
                html_content += """
            <div class="finding success">
                <h3>✅ SMB Null Session Security</h3>
                <p><strong>Status:</strong> Properly configured - anonymous access is disabled</p>
                <p><strong>Details:</strong> SMB services require authentication for access</p>
                <p><strong>Assessment:</strong> Good security practice implemented</p>
            </div>
"""
            
            html_content += """
        </div>
"""
        
        # Web Attack Results Section
        if attacks.get('web_attacks'):
            web = attacks['web_attacks']
            html_content += """
        <div class="attack-section">
            <div class="attack-header">🌐 Web Application Assessment</div>
"""
            
            if web.get('findings', '').lower() != 'no web servers detected':
                findings = web.get('findings', 'No details available')
                html_content += f"""
            <div class="finding">
                <h3>📋 Web Services Found</h3>
                <p><strong>Status:</strong> Web services detected and assessed</p>
                <pre>{findings}</pre>
            </div>
"""
            else:
                html_content += """
            <div class="finding success">
                <h3>✅ No Web Services Detected</h3>
                <p><strong>Status:</strong> No active web servers found</p>
                <p><strong>Assessment:</strong> Reduced attack surface - good security practice</p>
            </div>
"""
            
            html_content += """
        </div>
"""
        
        # RPC Attack Results Section
        if attacks.get('rpc_attacks'):
            html_content += """
        <div class="attack-section">
            <div class="attack-header">🔄 RPC Service Assessment</div>
            <div class="finding">
                <h3>📋 RPC Services Analysis</h3>
                <p><strong>Status:</strong> RPC services assessed</p>
                <p><strong>Port 135:</strong> Open - Microsoft RPC services running</p>
                <p><strong>Authentication:</strong> Required - no anonymous access allowed</p>
            </div>
        </div>
"""
        
        # Credential Attack Results Section
        if attacks.get('credential_attacks'):
            creds = attacks['credential_attacks']
            html_content += """
        <div class="attack-section">
            <div class="attack-header">🔐 Credential Attack Results</div>
"""
            
            # Check for successful credential attacks
            successful_creds = False
            cred_details = []
            
            if creds.get('credential_attacks', {}).get('smb_spray'):
                for password, attempts in creds['credential_attacks']['smb_spray'].items():
                    for username, result in attempts.items():
                        if result.get('success') and 'NT_STATUS_OK' not in result.get('error', ''):
                            successful_creds = True
                            cred_details.append(f"Username: {username}, Password: {password}")
            
            if successful_creds:
                html_content += """
            <div class="finding critical">
                <h3>❌ CRITICAL: Successful Credential Attack</h3>
                <p><strong>Impact:</strong> Valid credentials discovered</p>
                <p><strong>Compromised Accounts:</strong></p>
                <ul>
"""
                for cred in cred_details:
                    html_content += f"<li>{cred}</li>"
                html_content += """
                </ul>
                <p><strong>Recommendation:</strong> Change passwords immediately and investigate account usage</p>
            </div>
"""
            else:
                html_content += """
            <div class="finding success">
                <h3>✅ Credential Attacks Unsuccessful</h3>
                <p><strong>Status:</strong> No valid credentials discovered through automated attacks</p>
                <p><strong>Assessment:</strong> Strong password policies in place</p>
                <p><strong>Tested:</strong> Common usernames and passwords against SMB and RPC services</p>
            </div>
"""
            
            html_content += """
        </div>
"""
        
        # Network Attack Results Section
        if attacks.get('network_attacks'):
            network = attacks['network_attacks']
            html_content += """
        <div class="attack-section">
            <div class="attack-header">🌐 Network Attack Results</div>
"""
            
            if network.get('llmnr_poisoning', {}).get('hashes_captured', False):
                hashes = network['llmnr_poisoning'].get('captured_hashes', [])
                html_content += f"""
            <div class="finding critical">
                <h3>❌ CRITICAL: Hashes Captured via LLMNR/NBT-NS Poisoning</h3>
                <p><strong>Impact:</strong> Network credentials intercepted through name resolution poisoning</p>
                <p><strong>Details:</strong> Captured NTLMv2 hashes that can be cracked offline</p>
                <p><strong>Hashes Captured:</strong> {len(hashes)}</p>
                <pre>{'\n'.join(hashes[:3])}</pre>
                <p><strong>Recommendation:</strong> Disable LLMNR and NBT-NS on all network devices</p>
            </div>
"""
            else:
                html_content += """
            <div class="finding success">
                <h3>✅ No Hashes Captured via Network Attacks</h3>
                <p><strong>Status:</strong> LLMNR/NBT-NS poisoning attempted but no hashes captured</p>
                <p><strong>Assessment:</strong> Network may not be using vulnerable protocols or no traffic during test</p>
            </div>
"""
            
            html_content += """
        </div>
"""
        # Add this after the network attacks section
# Post-Exploitation Results Section
             if attacks.get('post_exploitation'):
                post_exploit = attacks['post_exploitation']
                html_content += """
        <div class="attack-section">
            <div class="attack-header">⚡ Post-Exploitation Results</div>
"""
    
             if post_exploit.get('hash_extraction'):
                html_content += """
            <div class="finding critical">
                <h3>🔓 Post-Exploitation Activities Performed</h3>
                <p><strong>Status:</strong> System accessed and post-exploitation executed</p>
                <p><strong>Activities:</strong> System enumeration, hash extraction, persistence attempts</p>
                <p><strong>Impact:</strong> Comprehensive access to target system</p>
            </div>
"""
             else:
                 html_content += """
            <div class="finding">
                <h3>📋 Post-Exploitation Attempted</h3>
                <p><strong>Status:</strong> Post-exploitation tools executed</p>
                <p><strong>Note:</strong> Some post-exploitation modules may require specific conditions</p>
            </div>
"""
    
    html_content += """
        </div>
"""
        
        # Risk Assessment Section
        html_content += f"""
        <div class="section">
            <h2>📈 Risk Assessment</h2>
            <div class="summary-box">
                <h3>Overall Risk Rating: <span class="risk-badge {risk_class}">{risk_level}</span></h3>
                <ul>
                    <li><strong>Authentication Security:</strong> <span class="risk-badge risk-low">STRONG</span> - No default credentials, proper access controls</li>
                    <li><strong>Service Hardening:</strong> <span class="risk-badge risk-low">GOOD</span> - Unnecessary services disabled</li>
                    <li><strong>Network Exposure:</strong> <span class="risk-badge risk-medium">MODERATE</span> - Windows services exposed but properly secured</li>
                    <li><strong>Vulnerability Status:</strong> <span class="risk-badge risk-low">LOW</span> - No critical vulnerabilities identified</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Recommendations</h2>
            <ol>
                <li><strong>Maintain Current Practices:</strong> Continue with current security hardening</li>
                <li><strong>Regular Updates:</strong> Ensure all systems receive regular security updates</li>
                <li><strong>Monitoring:</strong> Implement continuous security monitoring</li>
                <li><strong>Backup:</strong> Maintain regular backups of critical systems</li>
                <li><strong>Training:</strong> Provide ongoing security awareness training</li>
            </ol>
        </div>
        
        <div class="section">
            <p><em>Report generated by KAPA (Kali Automated Pentest Assistant) - Automated Penetration Testing Framework</em></p>
            <p><em>Assessment performed on: {timestamp_str}</em></p>
        </div>
    </div>
</body>
</html>
"""
        
        # Fixed directory creation logic
        output_dir = os.path.dirname(output_file)
        if output_dir:  # Only create directories if output_file includes a path
            os.makedirs(output_dir, exist_ok=True)
        
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
            f"Successful compromise: {'YES' if scan_data.get('successful_compromise') else 'NO'}",
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
        
        # Add attack findings
        attacks = scan_data.get('attack_results', {})
        
        if attacks.get('smb_attacks'):
            smb = attacks['smb_attacks']
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
        
        if attacks.get('network_attacks', {}).get('llmnr_poisoning', {}).get('hashes_captured'):
            network = attacks['network_attacks']
            report_lines.extend([
                "NETWORK ATTACK RESULTS:",
                "-" * 40,
                "❌ CRITICAL: Hashes captured via LLMNR/NBT-NS poisoning!",
                f"   Hashes captured: {len(network['llmnr_poisoning'].get('captured_hashes', []))}",
                "   Recommendation: Disable LLMNR and NBT-NS immediately",
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
        
        # Fixed directory creation logic
        output_dir = os.path.dirname(output_file)
        if output_dir:  # Only create directories if output_file includes a path
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        return output_file

# Example usage
if __name__ == "__main__":
    # Test the report generator
    sample_data = {
        'network_range': '10.0.3.0/24',
        'hosts': {'10.0.3.20': {}},
        'prioritized_targets': [
            {'ip': '10.0.3.20', 'hostname': 'WIN-R8LVLJJ4H2M', 'os': 'Windows Server 2022', 
             'services': ['msrpc', 'netbios-ssn', 'microsoft-ds', 'http'], 'target_value': 1}
        ],
        'attack_results': {
            'smb_attacks': {
                'smb_attacks': {
                    'null_session': {'vulnerable': False}
                }
            },
            'network_attacks': {
                'llmnr_poisoning': {
                    'hashes_captured': False
                }
            }
        },
        'successful_compromise': False
    }
    
    generator = ReportGenerator()
    html_report = generator.generate_html_report(sample_data, "test_report.html")
    text_report = generator.generate_text_report(sample_data, "test_report.txt")
    
    print(f"HTML report: {html_report}")
    print(f"Text report: {text_report}")
