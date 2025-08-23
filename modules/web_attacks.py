#!/usr/bin/env python3

import subprocess
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse

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

def web_directory_bruteforce(target_ip, ports=[80, 443, 8080, 8443]):
    """Brute force web directories on common web ports"""
    print(f"[*] Brute forcing web directories on {target_ip}")
    
    results = {}
    
    for port in ports:
        # Check if port is open by trying a simple HTTP request
        curl_check = run_command(f"curl -s -I http://{target_ip}:{port} --connect-timeout 5")
        if "HTTP/" in curl_check.get('output', ''):
            print(f"[*] Web server found on port {port}")
            
            # Run dirb for directory brute forcing
            dirb_result = run_command(f"dirb http://{target_ip}:{port} /usr/share/wordlists/dirb/common.txt -w -o /tmp/dirb_{target_ip}_{port}.txt")
            
            # Run gobuster for more comprehensive scanning
            gobuster_result = run_command(f"gobuster dir -u http://{target_ip}:{port} -w /usr/share/wordlists/dirb/common.txt -t 50 -q")
            
            results[port] = {
                'dirb': dirb_result,
                'gobuster': gobuster_result,
                'curl_check': curl_check
            }
    
    return results

def web_vulnerability_scan(target_ip, ports=[80, 443, 8080, 8443]):
    """Scan for web vulnerabilities using nikto"""
    print(f"[*] Running web vulnerability scan on {target_ip}")
    
    results = {}
    
    for port in ports:
        # Check if web server is running
        curl_check = run_command(f"curl -s -I http://{target_ip}:{port} --connect-timeout 5")
        if "HTTP/" in curl_check.get('output', ''):
            print(f"[*] Running Nikto on port {port}")
            
            # Run nikto vulnerability scanner
            nikto_result = run_command(f"nikto -h http://{target_ip}:{port} -o /tmp/nikto_{target_ip}_{port}.txt")
            
            results[port] = {
                'nikto': nikto_result,
                'curl_check': curl_check
            }
    
    return results

def check_common_web_apps(target_ip, ports=[80, 443, 8080, 8443]):
    """Check for common web applications and technologies"""
    print(f"[*] Detecting web technologies on {target_ip}")
    
    results = {}
    
    for port in ports:
        # Use whatweb for technology detection
        whatweb_result = run_command(f"whatweb http://{target_ip}:{port} --color=never")
        
        # Use nmap http scripts for more detection
        nmap_result = run_command(f"nmap -p{port} --script http-enum,http-headers,http-title {target_ip}")
        
        results[port] = {
            'whatweb': whatweb_result,
            'nmap_http_scripts': nmap_result
        }
    
    return results

def check_http_methods(target_ip, ports=[80, 443, 8080, 8443]):
    """Check for dangerous HTTP methods"""
    print(f"[*] Testing HTTP methods on {target_ip}")
    
    results = {}
    dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'DEBUG']
    
    for port in ports:
        port_results = {}
        curl_check = run_command(f"curl -s -I http://{target_ip}:{port} --connect-timeout 5")
        
        if "HTTP/" in curl_check.get('output', ''):
            # Test OPTIONS first to see available methods
            options_result = run_command(f"curl -s -X OPTIONS http://{target_ip}:{port} -I")
            port_results['options'] = options_result
            
            # Test each dangerous method
            for method in dangerous_methods:
                method_result = run_command(f"curl -s -X {method} http://{target_ip}:{port} -I")
                if method_result['success'] and "HTTP/" in method_result.get('output', ''):
                    port_results[method.lower()] = method_result
            
            results[port] = port_results
    
    return results

def run_web_attacks(target_ip):
    """Main function to run all web attacks"""
    print(f"\n{'='*60}")
    print(f"WEB ATTACK MODULE - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'web_attacks': {}
    }
    
    # Run all web attacks
    results['web_attacks']['directory_bruteforce'] = web_directory_bruteforce(target_ip)
    results['web_attacks']['vulnerability_scan'] = web_vulnerability_scan(target_ip)
    results['web_attacks']['technology_detection'] = check_common_web_apps(target_ip)
    results['web_attacks']['http_methods'] = check_http_methods(target_ip)
    
    # Save results
    os.makedirs('results/web_attacks', exist_ok=True)
    filename = f"results/web_attacks/web_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Web attack results saved to {filename}")
    
    # Generate quick summary
    print(f"\n{'='*40}")
    print("WEB ATTACK SUMMARY")
    print(f"{'='*40}")
    
    web_ports = []
    for port, data in results['web_attacks']['technology_detection'].items():
        if data['whatweb']['output']:
            web_ports.append(port)
            print(f"Port {port}: Web server detected")
            # Extract technologies from whatweb output
            technologies = re.findall(r'\[([^\]]+)\]', data['whatweb']['output'])
            if technologies:
                print(f"  Technologies: {', '.join(technologies[:3])}")
    
    if not web_ports:
        print("No web servers detected")
    
    return results

if __name__ == "__main__":
    # Test the module
    target = "10.0.3.20"  # Your Windows target
    results = run_web_attacks(target)
    print(f"\nWeb Attack completed. Results saved.")
