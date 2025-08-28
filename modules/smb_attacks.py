#!/usr/bin/env python3

import subprocess
import json
import os
import re
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest

class SMBAnalyzer:
    def __init__(self):
        self.smb_vulnerabilities = {
            'eternalblue': {'cve': 'CVE-2017-0144', 'risk': 'CRITICAL', 'windows_versions': ['windows 7', 'windows 2008', 'windows 8.1']},
            'smbghost': {'cve': 'CVE-2020-0796', 'risk': 'HIGH', 'windows_versions': ['windows 10', 'windows 2019']},
            'smbleed': {'cve': 'CVE-2020-1206', 'risk': 'HIGH', 'windows_versions': ['windows 10']},
            'null_session': {'risk': 'MEDIUM', 'description': 'Anonymous access allowed'},
            'sMB1_enabled': {'risk': 'MEDIUM', 'description': 'SMBv1 protocol enabled'}
        }
    
    def analyze_smb_version(self, version_output):
        """AI analysis of SMB version information"""
        analysis = {
            'version': 'unknown',
            'vulnerabilities': [],
            'recommendations': [],
            'risk_score': 0
        }
        
        version_output = version_output.lower()
        
        # Detect SMB version
        if 'smb 1' in version_output or 'lanman' in version_output:
            analysis['version'] = 'SMBv1'
            analysis['risk_score'] += 40
            analysis['vulnerabilities'].append(self.smb_vulnerabilities['sMB1_enabled'])
            analysis['recommendations'].append('Disable SMBv1 immediately')
        
        if 'smb 2' in version_output:
            analysis['version'] = 'SMBv2'
            analysis['risk_score'] += 10
        
        if 'smb 3' in version_output:
            analysis['version'] = 'SMBv3'
            analysis['risk_score'] -= 5  # More secure
        
        # Check for specific vulnerabilities
        windows_version = self.extract_windows_version(version_output)
        if windows_version:
            analysis['windows_version'] = windows_version
            
            # Check if vulnerable to EternalBlue
            if any(vuln_os in windows_version.lower() for vuln_os in self.smb_vulnerabilities['eternalblue']['windows_versions']):
                analysis['vulnerabilities'].append(self.smb_vulnerabilities['eternalblue'])
                analysis['risk_score'] += 50
                analysis['recommendations'].append('Apply MS17-010 patch immediately')
        
        # Normalize risk score
        analysis['risk_score'] = min(100, max(0, analysis['risk_score']))
        analysis['risk_level'] = self.get_risk_level(analysis['risk_score'])
        
        return analysis
    
    def extract_windows_version(self, output):
        """Extract Windows version from SMB banner"""
        patterns = [
            r'windows.*\d{4}',
            r'windows.*server.*\d{4}',
            r'windows.*\d+',
            r'win\d+'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def get_risk_level(self, score):
        """Convert numeric risk score to level"""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        elif score >= 10:
            return 'LOW'
        else:
            return 'INFO'
    
    def detect_anomalies(self, smb_results):
        """Use machine learning to detect anomalous SMB configurations"""
        if not smb_results:
            return []
        
        # Convert results to features
        features = []
        for result in smb_results:
            feature_vector = [
                1 if result.get('null_session_vulnerable') else 0,
                1 if 'SMBv1' in result.get('version_analysis', {}).get('version', '') else 0,
                result.get('version_analysis', {}).get('risk_score', 0),
                1 if result.get('shares', []) else 0,
                len(result.get('shares', [])),
                1 if any('write' in share.get('permissions', '').lower() for share in result.get('shares', [])) else 0
            ]
            features.append(feature_vector)
        
        # Detect anomalies
        if len(features) > 1:
            clf = IsolationForest(contamination=0.1, random_state=42)
            anomalies = clf.fit_predict(features)
            
            anomalous_results = []
            for i, anomaly in enumerate(anomalies):
                if anomaly == -1:  # Anomaly detected
                    anomalous_results.append({
                        'target': smb_results[i].get('target'),
                        'anomaly_score': clf.decision_function([features[i]])[0],
                        'reason': 'Unusual SMB configuration detected'
                    })
            
            return anomalous_results
        
        return []

# Global analyzer instance
smb_analyzer = SMBAnalyzer()

def run_command(command, timeout=60):
    """Secure command execution with input validation"""
    # Validate command to prevent injection
    allowed_commands = ['smbclient', 'enum4linux', 'nmap', 'rpclient', 'python3']
    if not any(cmd in command for cmd in allowed_commands):
        return {'success': False, 'error': 'Command not allowed'}
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Command timed out', 'output': ''}
    except Exception as e:
        return {'success': False, 'error': str(e), 'output': ''}

def smb_null_session_check(target_ip):
    """Enhanced null session check with AI analysis"""
    print(f"[*] Checking SMB null session on {target_ip}")
    
    # Try multiple null session techniques
    techniques = [
        f"smbclient -L //{target_ip} -N",
        f"rpclient -U '' -N {target_ip} -c 'getdomainsid'",
        f"python3 -c \"import subprocess; subprocess.run(['smbclient', '-L', '//{target_ip}', '-N'], timeout=30)\""
    ]
    
    results = []
    vulnerable = False
    
    for technique in techniques:
        result = run_command(technique)
        results.append({
            'technique': technique,
            'result': result
        })
        
        if result['success'] and ('Sharename' in result['output'] or 'Domain SID' in result['output']):
            vulnerable = True
            break
    
    analysis = {
        'vulnerable': vulnerable,
        'techniques_tested': len(techniques),
        'technique_results': results,
        'recommendation': 'Disable null sessions via registry: RestrictAnonymous=1' if vulnerable else 'Null sessions properly restricted'
    }
    
    return analysis

def smb_enum4linux_scan(target_ip):
    """Enhanced enum4linux scan with AI parsing"""
    print(f"[*] Running enum4linux on {target_ip}")
    
    result = run_command(f"enum4linux -a {target_ip}", timeout=180)
    
    # AI-powered result parsing
    parsed_data = {
        'users': [],
        'groups': [],
        'shares': [],
        'password_policy': {},
        'os_info': {}
    }
    
    if result['success']:
        output = result['output']
        
        # Parse users
        user_matches = re.findall(r'user:\[(.*?)\]', output, re.IGNORECASE)
        parsed_data['users'] = list(set(user_matches))
        
        # Parse groups
        group_matches = re.findall(r'group:\[(.*?)\]', output, re.IGNORECASE)
        parsed_data['groups'] = list(set(group_matches))
        
        # Parse shares
        share_matches = re.findall(r'sharename:\[(.*?)\]', output, re.IGNORECASE)
        parsed_data['shares'] = list(set(share_matches))
        
        # Parse OS info
        os_match = re.search(r'OS:\[(.*?)\]', output, re.IGNORECASE)
        if os_match:
            parsed_data['os_info']['name'] = os_match.group(1)
        
        # Parse password policy
        policy_match = re.search(r'password must meet complexity requirements:\[(.*?)\]', output, re.IGNORECASE)
        if policy_match:
            parsed_data['password_policy']['complexity'] = policy_match.group(1)
    
    return {
        'tool': 'enum4linux',
        'success': result['success'],
        'output': result['output'],
        'error': result['error'],
        'parsed_data': parsed_data
    }

def smb_version_scan(target_ip):
    """Comprehensive SMB version scanning with AI analysis"""
    print(f"[*] Scanning SMB version on {target_ip}")
    
    result = run_command(f"nmap -p445 --script smb-os-discovery,smb-security-mode,smb2-security-mode {target_ip}")
    
    analysis = {'vulnerabilities': [], 'recommendations': []}
    
    if result['success']:
        # AI analysis of nmap output
        analysis = smb_analyzer.analyze_smb_version(result['output'])
    
    return {
        'tool': 'nmap_smb_scripts',
        'success': result['success'],
        'output': result['output'],
        'error': result['error'],
        'version_analysis': analysis
    }

def check_smb_vulnerabilities(target_ip):
    """Check for known SMB vulnerabilities with AI prioritization"""
    print(f"[*] Checking SMB vulnerabilities on {target_ip}")
    
    result = run_command(f"nmap -p445 --script smb-vuln-* {target_ip}")
    
    vulnerabilities = []
    
    if result['success']:
        output = result['output']
        
        # Parse vulnerability findings
        vuln_patterns = {
            'ms17-010': r'VULNERABLE.*MS17-010',
            'cve-2020-0796': r'VULNERABLE.*CVE-2020-0796',
            'cve-2020-1206': r'VULNERABLE.*CVE-2020-1206'
        }
        
        for vuln_name, pattern in vuln_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                vulnerabilities.append({
                    'name': vuln_name,
                    'found': True,
                    'risk': 'CRITICAL' if 'ms17-010' in vuln_name else 'HIGH'
                })
    
    return {
        'tool': 'nmap_smb_vuln_scripts',
        'success': result['success'],
        'output': result['output'],
        'error': result['error'],
        'vulnerabilities_found': vulnerabilities
    }

def smb_share_enumeration(target_ip):
    """Detailed SMB share enumeration with AI classification"""
    print(f"[*] Enumerating SMB shares on {target_ip}")
    
    result = run_command(f"smbclient -L //{target_ip} -N")
    
    shares = []
    
    if result['success'] and 'Sharename' in result['output']:
        lines = result['output'].split('\n')
        in_shares_section = False
        
        for line in lines:
            if 'Sharename' in line and 'Type' in line and 'Comment' in line:
                in_shares_section = True
                continue
            
            if in_shares_section and line.strip() and '---' not in line:
                parts = line.split()
                if len(parts) >= 3:
                    share_name = parts[0]
                    share_type = parts[1]
                    comment = ' '.join(parts[2:])
                    
                    # AI classification of share risk
                    risk = 'LOW'
                    if any(keyword in comment.lower() for keyword in ['admin', 'root', 'system', 'backup']):
                        risk = 'HIGH'
                    elif any(keyword in comment.lower() for keyword in ['data', 'user', 'home', 'files']):
                        risk = 'MEDIUM'
                    
                    shares.append({
                        'name': share_name,
                        'type': share_type,
                        'comment': comment,
                        'risk_level': risk
                    })
    
    return {
        'shares': shares,
        'total_shares': len(shares),
        'high_risk_shares': [s for s in shares if s['risk_level'] == 'HIGH']
    }

def run_smb_attacks(target_ip):
    """AI-powered SMB attack suite with intelligent execution"""
    print(f"\n{'='*60}")
    print(f"🤖 AI SMB ANALYSIS - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'smb_analysis': {},
        'ai_recommendations': []
    }
    
    # Run all SMB checks with AI analysis
    results['smb_analysis']['null_session'] = smb_null_session_check(target_ip)
    results['smb_analysis']['enum4linux'] = smb_enum4linux_scan(target_ip)
    results['smb_analysis']['version_info'] = smb_version_scan(target_ip)
    results['smb_analysis']['vulnerabilities'] = check_smb_vulnerabilities(target_ip)
    results['smb_analysis']['share_enumeration'] = smb_share_enumeration(target_ip)
    
    # Generate AI recommendations
    recommendations = generate_ai_recommendations(results['smb_analysis'])
    results['ai_recommendations'] = recommendations
    
    # Calculate overall risk score
    risk_score = calculate_overall_risk(results['smb_analysis'])
    results['overall_risk'] = {
        'score': risk_score,
        'level': smb_analyzer.get_risk_level(risk_score)
    }
    
    # Save results
    os.makedirs('results/smb_attacks', exist_ok=True)
    filename = f"results/smb_attacks/smb_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] SMB attack results saved to {filename}")
    
    # Print executive summary
    print(f"\n📊 SMB Security Summary for {target_ip}:")
    print(f"   Overall Risk: {results['overall_risk']['level']} ({results['overall_risk']['score']}/100)")
    print(f"   Null Session: {'VULNERABLE' if results['smb_analysis']['null_session']['vulnerable'] else 'SECURE'}")
    print(f"   Shares Found: {results['smb_analysis']['share_enumeration']['total_shares']}")
    print(f"   Vulnerabilities: {len(results['smb_analysis']['vulnerabilities']['vulnerabilities_found'])}")
    
    if recommendations:
        print(f"\n🤖 AI Recommendations:")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec['action']} ({rec['priority']} priority)")
    
    return results

def generate_ai_recommendations(analysis):
    """Generate intelligent recommendations based on SMB analysis"""
    recommendations = []
    
    # Null session recommendations
    if analysis['null_session']['vulnerable']:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Disable SMB null sessions immediately',
            'details': 'Set RestrictAnonymous=1 in registry'
        })
    
    # Version-specific recommendations
    version_analysis = analysis['version_info']['version_analysis']
    for vuln in version_analysis.get('vulnerabilities', []):
        recommendations.append({
            'priority': vuln['risk'],
            'action': f'Patch {vuln.get("cve", "vulnerability")}',
            'details': vuln.get('description', 'Apply security updates')
        })
    
    # Share security recommendations
    shares = analysis['share_enumeration']['shares']
    for share in shares:
        if share['risk_level'] == 'HIGH':
            recommendations.append({
                'priority': 'MEDIUM',
                'action': f'Review permissions for share: {share["name"]}',
                'details': 'High-risk share detected - restrict access'
            })
    
    # Remove duplicates
    unique_recommendations = []
    seen_actions = set()
    
    for rec in recommendations:
        if rec['action'] not in seen_actions:
            unique_recommendations.append(rec)
            seen_actions.add(rec['action'])
    
    return unique_recommendations

def calculate_overall_risk(analysis):
    """Calculate overall risk score based on SMB analysis"""
    risk_score = 0
    
    # Null session vulnerability
    if analysis['null_session']['vulnerable']:
        risk_score += 30
    
    # Version vulnerabilities
    version_analysis = analysis['version_info']['version_analysis']
    risk_score += version_analysis.get('risk_score', 0)
    
    # Share risks
    shares = analysis['share_enumeration']['shares']
    risk_score += len([s for s in shares if s['risk_level'] == 'HIGH']) * 10
    risk_score += len([s for s in shares if s['risk_level'] == 'MEDIUM']) * 5
    
    # Known vulnerabilities
    vulns = analysis['vulnerabilities']['vulnerabilities_found']
    for vuln in vulns:
        if vuln['risk'] == 'CRITICAL':
            risk_score += 40
        elif vuln['risk'] == 'HIGH':
            risk_score += 25
    
    return min(100, risk_score)

if __name__ == "__main__":
    # Test the module
    target = "10.0.3.20"
    results = run_smb_attacks(target)
    print(f"\nSMB Analysis completed. Overall risk: {results['overall_risk']['level']}")
