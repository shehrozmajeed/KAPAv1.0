#!/usr/bin/env python3

import argparse
import json
from modules.discovery import discover_hosts, get_local_network
from modules.service_scan import scan_services, save_results
from utils.target_ranker import extract_features_from_scan, predict_target_value

def main():
    parser = argparse.ArgumentParser(description='LAN-Lander: Automated LAN Penetration Testing Tool')
    parser.add_argument('--network', '-n', help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--output', '-o', help='Output file for results')
    args = parser.parse_args()
    
    network_range = args.network if args.network else get_local_network()
    
    print("=" * 60)
    print("LAN-Lander: Automated LAN Penetration Testing Tool")
    print("=" * 60)
    
    # Step 1: Discover hosts
    print("\n[Phase 1] Host Discovery")
    print("-" * 40)
    live_hosts = discover_hosts(network_range)
    
    if not live_hosts:
        print("No live hosts found. Exiting.")
        return
    
    # Step 2: Service scanning
    print("\n[Phase 2] Service Fingerprinting")
    print("-" * 40)
    scan_results = scan_services(live_hosts)
    
    # Step 3: Target prioritization with ML
    print("\n[Phase 3] Target Prioritization")
    print("-" * 40)
    prioritized_hosts = []
    
    for ip, data in scan_results.items():
        if 'services' in data:
            features = extract_features_from_scan(data)
            target_value, confidence = predict_target_value(features)
            
            prioritized_hosts.append({
                'ip': ip,
                'hostname': data.get('hostname', 'Unknown'),
                'target_value': int(target_value),
                'confidence': float(confidence),
                'os': data.get('os_guess', 'Unknown'),
                'open_ports': len(data.get('ports', [])),
                'services': [s['service'] for s in data.get('services', [])]
            })
    
    # Sort by target value (descending) and confidence (descending)
    prioritized_hosts.sort(key=lambda x: (x['target_value'], x['confidence']), reverse=True)
    
    print("Prioritized Targets:")
    for i, host in enumerate(prioritized_hosts, 1):
        value_label = "HIGH VALUE" if host['target_value'] == 1 else "LOW VALUE"
        print(f"{i}. {host['ip']} ({host['hostname']}) - {value_label} ({host['confidence']:.2%})")
        print(f"   OS: {host['os']}, Ports: {host['open_ports']}, Services: {', '.join(host['services'][:5])}")
        if len(host['services']) > 5:
            print(f"   ... and {len(host['services']) - 5} more")
    
    # Step 4: Save results
    output_data = {
        'network_range': network_range,
        'scan_timestamp': scan_results.get('timestamp', ''),
        'hosts': scan_results,
        'prioritized_targets': prioritized_hosts
    }
    
    output_file = save_results(output_data, args.output)
    
    print(f"\n[+] Scan complete. Results saved to {output_file}")
    print("[+] Next step: Launch attacks against prioritized targets")

if __name__ == "__main__":
    main()
