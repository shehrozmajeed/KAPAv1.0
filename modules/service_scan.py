#!/usr/bin/env python3

import nmap
import json
import os
import re
from datetime import datetime
import pandas as pd
from sklearn.cluster import DBSCAN
import numpy as np

class ServiceClassifier:
    def __init__(self):
        self.service_patterns = {
            'web_servers': ['apache', 'nginx', 'iis', 'httpd', 'tomcat', 'jetty', 'lighttpd'],
            'database': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis'],
            'file_services': ['smb', 'ftp', 'sftp', 'nfs', 'afp'],
            'remote_access': ['ssh', 'rdp', 'vnc', 'teamviewer', 'anydesk'],
            'windows_services': ['microsoft-ds', 'netbios', 'msrpc', 'active-directory'],
            'network_devices': ['router', 'switch', 'firewall', 'cisco', 'juniper'],
            'iot': ['cam', 'printer', 'scanner', 'smart', 'iot']
        }
    
    def classify_service(self, service_name, banner, port):
        """AI-powered service classification"""
        service_name = str(service_name).lower()
        banner = str(banner).lower()
        
        classifications = []
        confidence_scores = {}
        
        # Pattern matching for initial classification
        for category, patterns in self.service_patterns.items():
            for pattern in patterns:
                if pattern in service_name or pattern in banner:
                    classifications.append(category)
                    confidence_scores[category] = confidence_scores.get(category, 0) + 0.3
        
        # Port-based classification
        port_rules = {
            (20, 21): 'ftp',
            (22, 22): 'ssh',
            (23, 23): 'telnet',
            (25, 25): 'smtp',
            (53, 53): 'dns',
            (80, 80): 'http',
            (110, 110): 'pop3',
            (135, 139): 'windows_services',
            (143, 143): 'imap',
            (443, 443): 'https',
            (445, 445): 'smb',
            (993, 993): 'imaps',
            (995, 995): 'pop3s',
            (1433, 1433): 'mssql',
            (3306, 3306): 'mysql',
            (3389, 3389): 'rdp',
            (5432, 5432): 'postgresql',
            (5900, 5900): 'vnc',
            (6379, 6379): 'redis',
            (27017, 27017): 'mongodb'
        }
        
        for port_range, service_type in port_rules.items():
            if port_range[0] <= port <= port_range[1]:
                classifications.append(service_type)
                confidence_scores[service_type] = confidence_scores.get(service_type, 0) + 0.4
        
        # Banner analysis for additional confidence
        banner_indicators = {
            'apache': ['apache', 'httpd'],
            'iis': ['microsoft', 'iis'],
            'nginx': ['nginx', 'enginex'],
            'wordpress': ['wordpress', 'wp-'],
            'joomla': ['joomla'],
            'drupal': ['drupal'],
            'windows': ['windows', 'microsoft'],
            'linux': ['linux', 'ubuntu', 'debian', 'centos']
        }
        
        for indicator, keywords in banner_indicators.items():
            for keyword in keywords:
                if keyword in banner:
                    classifications.append(indicator)
                    confidence_scores[indicator] = confidence_scores.get(indicator, 0) + 0.2
        
        # Remove duplicates and calculate final confidence
        unique_classifications = list(set(classifications))
        total_confidence = sum(confidence_scores.values())
        
        if total_confidence > 0:
            normalized_confidences = {
                cls: min(0.99, confidence_scores.get(cls, 0) / total_confidence)
                for cls in unique_classifications
            }
        else:
            normalized_confidences = {'unknown': 0.5}
        
        return unique_classifications, normalized_confidences
    
    def cluster_services(self, services_data):
        """Cluster similar services for pattern recognition"""
        if not services_data:
            return []
        
        # Convert services to feature vectors
        features = []
        service_info = []
        
        for service in services_data:
            # Create feature vector: [port, is_common_port, has_known_banner]
            port = service.get('port', 0)
            is_common = 1 if port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
                                    1433, 3306, 3389, 5432, 5900, 6379, 27017] else 0
            has_banner = 1 if service.get('version') != 'unknown' and service.get('version') else 0
            
            features.append([port, is_common, has_banner])
            service_info.append(service)
        
        # Apply clustering
        if len(features) > 1:
            clustering = DBSCAN(eps=3, min_samples=1).fit(features)
            labels = clustering.labels_
            
            # Group services by cluster
            clusters = {}
            for i, label in enumerate(labels):
                if label not in clusters:
                    clusters[label] = []
                clusters[label].append(service_info[i])
            
            return clusters
        return {}

# Global classifier instance
service_classifier = ServiceClassifier()

def scan_services(hosts, intensity='normal'):
    """Enhanced service scanning with AI classification"""
    nm = nmap.PortScanner()
    results = {}
    
    # Configure scan intensity
    intensity_settings = {
        'stealth': '-sS -T2',
        'normal': '-sV -T4 --version-intensity 5',
        'aggressive': '-sV -T4 -A --version-intensity 9',
        'comprehensive': '-sV -sC -A -T4 --script vuln --version-intensity 9'
    }
    
    scan_arguments = intensity_settings.get(intensity, intensity_settings['normal'])
    
    for host in hosts:
        host_ip = host['ip']
        print(f"[+] Scanning services on {host_ip} ({intensity} mode)")
        
        try:
            # Perform service version detection with OS detection
            scan_result = nm.scan(hosts=host_ip, arguments=f'{scan_arguments} -O --script smb-os-discovery')
            
            if host_ip in nm.all_hosts():
                host_data = nm[host_ip]
                
                host_result = {
                    'hostname': host.get('hostname', 'Unknown'),
                    'mac': host.get('mac', 'Unknown'),
                    'status': host_data.state(),
                    'os_guess': host_data.get('osmatch', [{}])[0].get('name', 'Unknown') if host_data.get('osmatch') else 'Unknown',
                    'os_accuracy': host_data.get('osmatch', [{}])[0].get('accuracy', '0') if host_data.get('osmatch') else '0',
                    'ports': [],
                    'services': [],
                    'service_categories': {},
                    'scan_intensity': intensity
                }
                
                # Extract port information with AI classification
                for proto in host_data.all_protocols():
                    if proto not in ['tcp', 'udp']:
                        continue
                    
                    for port in host_data[proto].keys():
                        port_info = host_data[proto][port]
                        
                        host_result['ports'].append(port)
                        
                        service_info = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'product': port_info.get('product', 'unknown'),
                            'banner': port_info.get('banner', 'unknown'),
                            'confidence': 'unknown'
                        }
                        
                        # AI classification
                        classifications, confidences = service_classifier.classify_service(
                            service_info['service'], 
                            service_info['banner'], 
                            port
                        )
                        
                        service_info['ai_classifications'] = classifications
                        service_info['confidence_scores'] = confidences
                        
                        # Update service categories
                        for cls in classifications:
                            if cls not in host_result['service_categories']:
                                host_result['service_categories'][cls] = []
                            host_result['service_categories'][cls].append(port)
                        
                        host_result['services'].append(service_info)
                
                results[host_ip] = host_result
                
                # Print summary
                print(f"   Found {len(host_result['services'])} services")
                if host_result['service_categories']:
                    print(f"   Categories: {', '.join(host_result['service_categories'].keys())}")
                
        except Exception as e:
            print(f"Error scanning {host_ip}: {e}")
            results[host_ip] = {'error': str(e)}
    
    # Perform cross-host service clustering
    if results:
        all_services = []
        for host_data in results.values():
            if 'services' in host_data:
                all_services.extend(host_data['services'])
        
        service_clusters = service_classifier.cluster_services(all_services)
        if service_clusters:
            print(f"\n[+] Identified {len(service_clusters)} service patterns across network")
            
            # Add cluster info to results
            for host_ip, host_data in results.items():
                if 'services' in host_data:
                    host_data['service_patterns'] = len(service_clusters)
    
    return results

def save_results(results, filename=None):
    """Save scan results to JSON file with AI insights"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/scan_results_{timestamp}.json"
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Add AI insights to results
    enhanced_results = {
        'scan_timestamp': datetime.now().isoformat(),
        'total_hosts': len(results),
        'hosts_with_services': sum(1 for host in results.values() if 'services' in host),
        'service_statistics': calculate_service_stats(results),
        'detailed_results': results
    }
    
    with open(filename, 'w') as f:
        json.dump(enhanced_results, f, indent=4)
    
    print(f"[+] Results saved to {filename}")
    return filename

def calculate_service_stats(results):
    """Calculate statistics about discovered services"""
    stats = {
        'total_services': 0,
        'service_categories': {},
        'common_ports': {},
        'vulnerability_indicators': {
            'old_versions': 0,
            'default_credentials': 0,
            'unencrypted_services': 0
        }
    }
    
    # Old version patterns
    old_version_patterns = [
        r'apache.*1\.', r'nginx.*0\.', r'openssh.*4\.', r'openssh.*5\.',
        r'windows.*2000', r'windows.*xp', r'windows.*2003',
        r'mysql.*4\.', r'mysql.*5\.0', r'postgresql.*8\.'
    ]
    
    for host_data in results.values():
        if 'services' in host_data:
            for service in host_data['services']:
                stats['total_services'] += 1
                
                # Count service categories
                for category in service.get('ai_classifications', []):
                    stats['service_categories'][category] = stats['service_categories'].get(category, 0) + 1
                
                # Count common ports
                port = service.get('port', 0)
                stats['common_ports'][port] = stats['common_ports'].get(port, 0) + 1
                
                # Check for vulnerability indicators
                version = str(service.get('version', '')).lower()
                service_name = str(service.get('service', '')).lower()
                
                # Old versions
                for pattern in old_version_patterns:
                    if re.search(pattern, version, re.IGNORECASE):
                        stats['vulnerability_indicators']['old_versions'] += 1
                        break
                
                # Default credentials possible
                if any(s in service_name for s in ['ftp', 'telnet', 'http', 'vnc', 'redis']):
                    stats['vulnerability_indicators']['default_credentials'] += 1
                
                # Unencrypted services
                if any(s in service_name for s in ['ftp', 'telnet', 'http', 'smb']) and 'ssl' not in service_name:
                    stats['vulnerability_indicators']['unencrypted_services'] += 1
    
    return stats

def generate_service_report(results):
    """Generate AI-powered service analysis report"""
    report = {
        'executive_summary': '',
        'critical_findings': [],
        'recommendations': []
    }
    
    stats = calculate_service_stats(results)
    
    # Executive summary
    report['executive_summary'] = (
        f"Network scan discovered {stats['total_services']} services across "
        f"{len(results)} hosts. Identified {len(stats['service_categories'])} "
        f"different service categories with {stats['vulnerability_indicators']['old_versions']} "
        "potentially vulnerable services."
    )
    
    # Critical findings
    if stats['vulnerability_indicators']['old_versions'] > 0:
        report['critical_findings'].append({
            'type': 'outdated_software',
            'count': stats['vulnerability_indicators']['old_versions'],
            'risk': 'HIGH',
            'description': 'Outdated software versions detected with known vulnerabilities'
        })
    
    if stats['vulnerability_indicators']['unencrypted_services'] > 0:
        report['critical_findings'].append({
            'type': 'unencrypted_communication',
            'count': stats['vulnerability_indicators']['unencrypted_services'],
            'risk': 'MEDIUM',
            'description': 'Services using unencrypted communication protocols'
        })
    
    # Recommendations
    if stats['vulnerability_indicators']['old_versions'] > 0:
        report['recommendations'].append({
            'priority': 'HIGH',
            'action': 'Update outdated software immediately',
            'details': 'Identify and patch services running outdated versions'
        })
    
    if stats['vulnerability_indicators']['unencrypted_services'] > 0:
        report['recommendations'].append({
            'priority': 'MEDIUM',
            'action': 'Enable encryption for sensitive services',
            'details': 'Configure SSL/TLS for web services, use SFTP instead of FTP'
        })
    
    return report

if __name__ == "__main__":
    # Test with a single host
    test_hosts = [{'ip': '127.0.0.1', 'mac': 'test', 'hostname': 'localhost'}]
    results = scan_services(test_hosts)
    print(json.dumps(results, indent=2))
    
    # Generate report
    report = generate_service_report(results)
    print("\nAI Service Analysis Report:")
    print(json.dumps(report, indent=2))
