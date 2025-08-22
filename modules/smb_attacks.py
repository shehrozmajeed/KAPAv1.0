#!/usr/bin/env python3

import subprocess
import json
import os
from datetime import datetime

def run_command(command, timeout=60):
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

def smb_null_session_check(target_ip):
    """Check if SMB allows null sessions"""
    print(f"[*] Checking SMB null session on {target_ip}")
    
    # Try to list shares with null session
    result = run_command(f"smbclient -L //{target_ip} -N")
    
    if result['success'] and "Sharename" in result['output']:
        print(f"[+] Null session allowed on {target_ip}!")
        return {
            'vulnerable': True,
            'details': 'SMB null session allowed',
            'output': result['output']
        }
    else:
        return {
            'vulnerable': False,
            'details': 'Null session not allowed',
            'output': result['error'] if result['error'] else result['output']
        }

def smb_enum4linux_scan(target_ip):
    """Run enum4linux comprehensive enumeration"""
    print(f"[*] Running enum4linux on {target_ip}")
    
    result = run_command(f"enum4linux -a {target_ip}", timeout=120)
    
    return {
        'tool': 'enum4linux',
        'success': result['success'],
        'output': result['output'],
        'error': result['error']
    }

def smb_version_scan(target_ip):
    """Get detailed SMB version information"""
    print(f"[*] Scanning SMB version on {target_ip}")
    
    result = run_command(f"nmap -p445 --script smb-os-discovery,smb-security-mode {target_ip}")
    
    return {
        'tool': 'nmap_smb_scripts',
        'success': result['success'],
        'output': result['output'],
        'error': result['error']
    }

def check_smb_vulnerabilities(target_ip):
    """Check for known SMB vulnerabilities"""
    print(f"[*] Checking SMB vulnerabilities on {target_ip}")
    
    result = run_command(f"nmap -p445 --script smb-vuln-* {target_ip}")
    
    return {
        'tool': 'nmap_smb_vuln_scripts',
        'success': result['success'],
        'output': result['output'],
        'error': result['error']
    }

def run_smb_attacks(target_ip):
    """Main function to run all SMB attacks"""
    print(f"\n{'='*50}")
    print(f"SMB ATTACK MODULE - Target: {target_ip}")
    print(f"{'='*50}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'smb_attacks': {}
    }
    
    # Run all SMB checks
    results['smb_attacks']['null_session'] = smb_null_session_check(target_ip)
    results['smb_attacks']['enum4linux'] = smb_enum4linux_scan(target_ip)
    results['smb_attacks']['version_info'] = smb_version_scan(target_ip)
    results['smb_attacks']['vulnerabilities'] = check_smb_vulnerabilities(target_ip)
    
    # Save results
    os.makedirs('results/smb_attacks', exist_ok=True)
    filename = f"results/smb_attacks/smb_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] SMB attack results saved to {filename}")
    return results

if __name__ == "__main__":
    # Test the module
    target = "10.0.3.20"  # Your Windows target
    results = run_smb_attacks(target)
    print(f"\nSMB Attack completed. Results: {len(results['smb_attacks'])} tests performed")
