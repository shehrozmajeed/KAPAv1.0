#!/usr/bin/env python3

import argparse
import json
from modules.discovery import discover_hosts, get_local_network
from modules.service_scan import scan_services, save_results
from utils.target_ranker import extract_features_from_scan, predict_target_value
from modules.smb_attacks import run_smb_attacks

def main():
    parser = argparse.ArgumentParser(description='KAPA: Kali Automated Pentest Assistant')
    parser.add_argument('--network', '-n', help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface to use (default: eth0)')
    parser.add_argument('--output', '-o', help='Output file for results')
    args = parser.parse_args()
    
    network_range = args.network if args.network else get_local_network(args.interface)
    
    print("=" * 60)
    print("KAPA: Kali Automated Pentest Assistant")
    print("=" * 60)
    print(f"Using interface: {args.interface}")
    
    # Step 1: Discover hosts
    print("\n[Phase 1] Host Discovery")
    print("-" * 40)
    live_hosts = discover_hosts(network_range, args.interface)
    
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
    
    # Step 4: Launch attacks against high-value targets
    attack_results = {}
    if prioritized_hosts and prioritized_hosts[0]['target_value'] == 1:
        high_value_target = prioritized_hosts[0]['ip']
        print(f"\n[+] Launching attacks against high-value target: {high_value_target}")
        
        # Check if it has SMB services (FIXED VERSION)
        target_services = scan_results[high_value_target].get('services', [])
        smb_services = []
        for service in target_services:
            service_name = service.get('service', '').lower()
            if any(keyword in service_name for keyword in ['smb', 'microsoft-ds', 'netbios', 'msrpc']):
                smb_services.append(service)
        
        if smb_services:
            service_names = [s.get('service', '') for s in smb_services]
            print(f"[+] Target has SMB/RPC services: {service_names}")
            try:
                smb_results = run_smb_attacks(high_value_target)
                attack_results['smb_attacks'] = smb_results
                print("[+] SMB attacks completed successfully!")
            except Exception as e:
                print(f"[-] SMB attacks failed: {e}")
                attack_results['smb_attacks'] = {'error': str(e)}
        else:
            print("[-] No SMB services found on high-value target")
            service_names = [s.get('service', '') for s in target_services]
            print(f"    Available services: {service_names}")
    else:
        print("[-] No high-value targets found for attack phase")
    
    # Step 5: Save results
    output_data = {
        'network_range': network_range,
        'interface': args.interface,
        'hosts': scan_results,
        'prioritized_targets': prioritized_hosts,
        'attack_results': attack_results
    }
    
    output_file = save_results(output_data, args.output)
    
    print(f"\n[+] Scan complete. Results saved to {output_file}")
    print("[+] Next step: Launch attacks against prioritized targets")

if __name__ == "__main__":
    main()
