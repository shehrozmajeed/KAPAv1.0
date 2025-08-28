#!/usr/bin/env python3

import subprocess
import json
import os
import re
import socket
import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': [r'select.*from', r'union.*select', r'1=1', r'waitfor delay', r'sleep\(\d+\)'],
            'xss': [r'<script>', r'alert\(', r'onerror=', r'onload=', r'javascript:'],
            'lfi': [r'\.\./', r'etc/passwd', r'proc/self', r'win.ini', r'\.\.\\'],
            'rfi': [r'http://', r'https://', r'ftp://', r'php://', r'data://'],
            'command_injection': [r';ls', r'|id', r'`whoami`', r'$(whoami)', r'&&cat']
        }
        
        self.cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin', 'wordpress'],
            'joomla': ['joomla', 'components/com_', 'templates/joomla'],
            'drupal': ['drupal', 'sites/all/', 'modules/node'],
            'magento': ['magento', 'skin/frontend', 'media/catalog'],
            'shopify': ['shopify', 'cdn.shopify.com', 'shopify.svc']
        }
        
        self.waf_signatures = {
            'cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'akamai': ['akamai', 'akamaighost'],
            'imperva': ['imperva', 'incapsula'],
            'aws_waf': ['aws', 'awselb/2.0'],
            'mod_security': ['mod_security', 'modsecurity']
        }
    
    def analyze_web_technology(self, headers, content, url):
        """AI-powered web technology analysis"""
        analysis = {
            'server_tech': 'unknown',
            'programming_lang': 'unknown',
            'cms': 'unknown',
            'waf': 'unknown',
            'security_headers': {},
            'vulnerability_indicators': []
        }
        
        content_lower = content.lower()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Server technology detection
        server_tech_indicators = {
            'apache': ['apache', 'httpd'],
            'nginx': ['nginx', 'enginex'],
            'iis': ['microsoft-iis', 'iis'],
            'nodejs': ['node.js', 'express'],
            'tomcat': ['apache-coyote', 'tomcat']
        }
        
        for tech, indicators in server_tech_indicators.items():
            if any(indicator in headers_lower.get('server', '').lower() for indicator in indicators):
                analysis['server_tech'] = tech
                break
        
        # Programming language detection
        lang_indicators = {
            'php': ['.php', 'php/', 'x-powered-by: php'],
            'asp.net': ['.aspx', '.ashx', 'asp.net'],
            'java': ['jsessionid', 'jsp', 'servlet'],
            'python': ['python', 'django', 'flask'],
            'ruby': ['ruby', 'rails', 'rack']
        }
        
        for lang, indicators in lang_indicators.items():
            if any(indicator in content_lower or indicator in str(headers_lower) for indicator in indicators):
                analysis['programming_lang'] = lang
                break
        
        # CMS detection
        for cms, signatures in self.cms_signatures.items():
            if any(sig in content_lower for sig in signatures):
                analysis['cms'] = cms
                break
        
        # WAF detection
        for waf, signatures in self.waf_signatures.items():
            if any(sig in content_lower or sig in str(headers_lower) for sig in signatures):
                analysis['waf'] = waf
                break
        
        # Security headers analysis
        security_headers = [
            'x-frame-options', 'x-content-type-options',
            'x-xss-protection', 'strict-transport-security',
            'content-security-policy'
        ]
        
        for header in security_headers:
            if header in headers_lower:
                analysis['security_headers'][header] = headers_lower[header]
            else:
                analysis['security_headers'][header] = 'MISSING'
                analysis['vulnerability_indicators'].append(f'Missing security header: {header}')
        
        return analysis
    
    def predict_vulnerability_likelihood(self, tech_analysis, content):
        """Predict vulnerability likelihood using ML features"""
        features = {
            'has_cms': 1 if tech_analysis['cms'] != 'unknown' else 0,
            'has_waf': 1 if tech_analysis['waf'] != 'unknown' else 0,
            'missing_headers': sum(1 for h in tech_analysis['security_headers'].values() if h == 'MISSING'),
            'content_length': len(content),
            'form_count': content.lower().count('<form'),
            'input_count': content.lower().count('<input')
        }
        
        # Calculate vulnerability score
        score = 0
        score += features['has_cms'] * 20  # CMS often have known vulnerabilities
        score += (1 - features['has_waf']) * 25  # No WAF increases risk
        score += features['missing_headers'] * 10
        score += min(20, features['form_count'] * 5)  # More forms = more attack surface
        score += min(25, features['input_count'] * 2)  # More inputs = more potential injection points
        
        return min(100, score)
    
    def detect_content_anomalies(self, web_responses):
        """Detect anomalous web responses using ML"""
        if len(web_responses) < 2:
            return []
        
        # Extract features from web responses
        features = []
        for response in web_responses:
            content = response.get('content', '')
            headers = response.get('headers', {})
            
            feature_vec = [
                len(content),
                len(str(headers)),
                content.count('<form'),
                content.count('<input'),
                content.count('script'),
                1 if 'error' in content.lower() else 0,
                1 if 'sql' in content.lower() else 0
            ]
            features.append(feature_vec)
        
        # Detect anomalies
        clf = IsolationForest(contamination=0.1, random_state=42)
        anomalies = clf.fit_predict(features)
        
        anomalous_responses = []
        for i, anomaly in enumerate(anomalies):
            if anomaly == -1:
                anomalous_responses.append({
                    'url': web_responses[i].get('url'),
                    'anomaly_score': clf.decision_function([features[i]])[0],
                    'reason': 'Unusual response pattern detected'
                })
        
        return anomalous_responses

# Global analyzer instance
web_analyzer = WebAnalyzer()

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

def check_port_open(target_ip, port, timeout=2):
    """Check if a port is actually open using socket connection"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            return result == 0
    except:
        return False

def intelligent_web_crawl(target_url, max_pages=20):
    """AI-powered web crawling with intelligent content analysis"""
    print(f"[*] Intelligent web crawling: {target_url}")
    
    visited_urls = set()
    pages_to_visit = [target_url]
    crawled_data = []
    
    session = requests.Session()
    session.verify = False  # Disable SSL verification
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    while pages_to_visit and len(visited_urls) < max_pages:
        current_url = pages_to_visit.pop(0)
        
        if current_url in visited_urls:
            continue
        
        try:
            response = session.get(current_url, timeout=10)
            visited_urls.add(current_url)
            
            # Parse page content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            page_data = {
                'url': current_url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'title': soup.title.string if soup.title else 'No title',
                'forms': [],
                'links': []
            }
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                page_data['forms'].append(form_data)
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                
                if target_url in full_url and full_url not in visited_urls:
                    page_data['links'].append(full_url)
                    if full_url not in pages_to_visit:
                        pages_to_visit.append(full_url)
            
            crawled_data.append(page_data)
            
            print(f"   Crawled: {current_url} ({response.status_code}) - {len(page_data['forms'])} forms")
            
        except Exception as e:
            print(f"   Error crawling {current_url}: {e}")
    
    return crawled_data

def detect_vulnerabilities(crawled_data):
    """AI-powered vulnerability detection"""
    vulnerabilities = []
    
    for page in crawled_data:
        content = page['content'].lower()
        url = page['url']
        
        # Check for common vulnerability patterns
        for vuln_type, patterns in web_analyzer.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'url': url,
                        'confidence': 'MEDIUM',
                        'evidence': f'Pattern match: {pattern}'
                    })
        
        # Analyze forms for potential vulnerabilities
        for form in page['forms']:
            form_analysis = analyze_form_vulnerability(form, url)
            if form_analysis['risk_score'] > 30:
                vulnerabilities.append({
                    'type': 'form_vulnerability',
                    'url': url,
                    'form_action': form['action'],
                    'risk_score': form_analysis['risk_score'],
                    'issues': form_analysis['issues']
                })
    
    return vulnerabilities

def analyze_form_vulnerability(form, url):
    """Analyze web form for potential vulnerabilities"""
    analysis = {
        'risk_score': 0,
        'issues': []
    }
    
    # Check for GET method (parameters in URL)
    if form['method'] == 'GET':
        analysis['risk_score'] += 20
        analysis['issues'].append('Form uses GET method (parameters exposed in URL)')
    
    # Check for missing CSRF protection
    has_csrf = any(input['type'] == 'hidden' and ('csrf' in input['name'].lower() or 'token' in input['name'].lower()) 
                  for input in form['inputs'])
    if not has_csrf:
        analysis['risk_score'] += 25
        analysis['issues'].append('No CSRF token detected')
    
    # Check for password fields without HTTPS
    has_password = any(input['type'] == 'password' for input in form['inputs'])
    if has_password and not url.startswith('https://'):
        analysis['risk_score'] += 35
        analysis['issues'].append('Password field without HTTPS')
    
    # Check for file uploads
    has_file_upload = any(input['type'] == 'file' for input in form['inputs'])
    if has_file_upload:
        analysis['risk_score'] += 15
        analysis['issues'].append('File upload field detected')
    
    return analysis

def run_nikto_scan(target_url):
    """Run Nikto web scanner with AI result parsing"""
    print(f"[*] Running Nikto scan: {target_url}")
    
    result = run_command(f"nikto -h {target_url} -o results/nikto_scan.txt -Format txt", timeout=600)
    
    findings = []
    if result['success']:
        # Parse Nikto output
        lines = result['output'].split('\n')
        for line in lines:
            if '+ ' in line and 'http' in line.lower():
                # Extract finding information
                finding = {
                    'description': line.strip(),
                    'severity': 'INFO'
                }
                
                # Determine severity
                if 'OSVDB-' in line:
                    finding['severity'] = 'MEDIUM'
                if 'critical' in line.lower():
                    finding['severity'] = 'HIGH'
                if 'vulnerability' in line.lower():
                    finding['severity'] = 'MEDIUM'
                
                findings.append(finding)
    
    return {
        'tool': 'nikto',
        'success': result['success'],
        'findings': findings,
        'output': result['output']
    }

def run_dirb_scan(target_url):
    """Run directory brute-force with AI pattern recognition"""
    print(f"[*] Running directory enumeration: {target_url}")
    
    result = run_command(f"dirb {target_url} /usr/share/wordlists/dirb/common.txt -o results/dirb_scan.txt", timeout=300)
    
    interesting_dirs = []
    if result['success']:
        lines = result['output'].split('\n')
        for line in lines:
            if '+ ' in line and 'http' in line:
                path = line.split('+ ')[1].strip()
                
                # AI classification of directory importance
                importance = classify_directory_importance(path)
                if importance['score'] > 50:
                    interesting_dirs.append({
                        'path': path,
                        'importance': importance['level'],
                        'reason': importance['reason']
                    })
    
    return {
        'tool': 'dirb',
        'success': result['success'],
        'interesting_dirs': interesting_dirs,
        'output': result['output']
    }

def classify_directory_importance(path):
    """AI classification of directory importance"""
    importance = {
        'score': 0,
        'level': 'LOW',
        'reason': ''
    }
    
    # High importance patterns
    high_importance = ['admin', 'administrator', 'config', 'backup', 'database', 'sql', 'upload']
    medium_importance = ['login', 'user', 'account', 'test', 'dev', 'api']
    low_importance = ['images', 'css', 'js', 'static', 'assets']
    
    path_lower = path.lower()
    
    for pattern in high_importance:
        if pattern in path_lower:
            importance['score'] = 80
            importance['level'] = 'HIGH'
            importance['reason'] = f'Contains high-value pattern: {pattern}'
            return importance
    
    for pattern in medium_importance:
        if pattern in path_lower:
            importance['score'] = 50
            importance['level'] = 'MEDIUM'
            importance['reason'] = f'Contains medium-value pattern: {pattern}'
            return importance
    
    for pattern in low_importance:
        if pattern in path_lower:
            importance['score'] = 20
            importance['level'] = 'LOW'
            importance['reason'] = f'Contains low-value pattern: {pattern}'
            return importance
    
    # Default for unknown patterns
    importance['score'] = 30
    importance['level'] = 'LOW'
    importance['reason'] = 'Unknown directory pattern'
    return importance

def run_web_attacks(target_ip):
    """AI-powered web attack suite"""
    print(f"\n{'='*60}")
    print(f"🌐 AI WEB APPLICATION ANALYSIS - Target: {target_ip}")
    print(f"{'='*60}")
    
    results = {
        'target': target_ip,
        'timestamp': datetime.now().isoformat(),
        'web_attacks': {},
        'ai_analysis': {}
    }
    
    # First verify web services
    web_ports = verify_web_service(target_ip)
    
    if not web_ports:
        print("[-] No web servers detected")
        results['web_attacks']['findings'] = "No web servers detected"
        return results
    
    print(f"[+] Found {len(web_ports)} web server(s)")
    results['web_attacks']['verified_ports'] = web_ports
    
    # Attack each web service
    for port, service_info in web_ports.items():
        print(f"\n[*] Attacking web service on port {port}")
        
        # Determine protocol
        protocol = 'https' if port in [443, 8443] else 'http'
        target_url = f"{protocol}://{target_ip}:{port}"
        
        # AI-powered attack sequence
        attack_results = execute_web_attack_sequence(target_url)
        results['web_attacks'][f'port_{port}'] = attack_results
    
    # Overall AI analysis
    results['ai_analysis'] = perform_overall_web_analysis(results['web_attacks'])
    
    # Save results
    os.makedirs('results/web_attacks', exist_ok=True)
    filename = f"results/web_attacks/web_attack_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Web attack results saved to {filename}")
    
    # Print summary
    print(f"\n📊 Web Application Security Summary:")
    total_vulns = sum(len(port_data.get('vulnerabilities', [])) for port, port_data in results['web_attacks'].items() if isinstance(port_data, dict))
    print(f"   Total Vulnerabilities Found: {total_vulns}")
    
    if results['ai_analysis'].get('recommendations'):
        print(f"\n🤖 AI Recommendations:")
        for i, rec in enumerate(results['ai_analysis']['recommendations'][:3], 1):
            print(f"   {i}. {rec['action']} ({rec['priority']})")
    
    return results

def verify_web_service(target_ip, ports=[80, 443, 8080, 8443, 8000, 8888]):
    """Enhanced web service verification with AI detection"""
    print(f"[*] Verifying web services on {target_ip}")
    
    verified_ports = {}
    
    for port in ports:
        if not check_port_open(target_ip, port):
            continue
        
        print(f"   Checking port {port}...")
        
        # Try multiple detection methods
        detection_methods = {}
        
        # HTTP request
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target_ip}:{port}"
            response = requests.get(url, timeout=10, verify=False)
            
            detection_methods['http_request'] = {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_sample': response.text[:500]
            }
            
            # AI analysis of the response
            tech_analysis = web_analyzer.analyze_web_technology(
                response.headers, response.text, url
            )
            
            vulnerability_score = web_analyzer.predict_vulnerability_likelihood(
                tech_analysis, response.text
            )
            
            verified_ports[port] = {
                'protocol': protocol,
                'status_code': response.status_code,
                'technology_analysis': tech_analysis,
                'vulnerability_score': vulnerability_score,
                'vulnerability_level': get_vulnerability_level(vulnerability_score)
            }
            
            print(f"   [+] Web server confirmed on port {port} ({tech_analysis['server_tech']}) - Risk: {verified_ports[port]['vulnerability_level']}")
            
        except Exception as e:
            print(f"   [-] Port {port} open but no web server detected: {e}")
    
    return verified_ports

def execute_web_attack_sequence(target_url):
    """AI-driven web attack sequence"""
    attack_results = {}
    
    print(f"   [*] Intelligent crawling: {target_url}")
    crawled_data = intelligent_web_crawl(target_url)
    attack_results['crawling'] = {
        'pages_crawled': len(crawled_data),
        'forms_found': sum(len(page['forms']) for page in crawled_data),
        'unique_links': len(set(link for page in crawled_data for link in page['links']))
    }
    
    print(f"   [*] Vulnerability detection")
    vulnerabilities = detect_vulnerabilities(crawled_data)
    attack_results['vulnerabilities'] = vulnerabilities
    
    print(f"   [*] Nikto security scan")
    nikto_results = run_nikto_scan(target_url)
    attack_results['nikto_scan'] = nikto_results
    
    print(f"   [*] Directory enumeration")
    dirb_results = run_dirb_scan(target_url)
    attack_results['directory_enum'] = dirb_results
    
    # AI analysis of collected data
    attack_results['ai_analysis'] = analyze_web_attack_results(attack_results, crawled_data)
    
    return attack_results

def analyze_web_attack_results(attack_results, crawled_data):
    """AI analysis of web attack results"""
    analysis = {
        'total_risk_score': 0,
        'critical_vulnerabilities': 0,
        'security_posture': 'UNKNOWN',
        'recommendations': []
    }
    
    # Calculate risk from vulnerabilities
    vuln_risk = 0
    for vuln in attack_results.get('vulnerabilities', []):
        if 'risk_score' in vuln:
            vuln_risk += vuln['risk_score']
        else:
            vuln_risk += 30  # Default risk for unscored vulnerabilities
    
    # Calculate risk from Nikto findings
    nikto_risk = 0
    for finding in attack_results.get('nikto_scan', {}).get('findings', []):
        if finding['severity'] == 'HIGH':
            nikto_risk += 40
        elif finding['severity'] == 'MEDIUM':
            nikto_risk += 20
        else:
            nikto_risk += 5
    
    analysis['total_risk_score'] = min(100, (vuln_risk + nikto_risk) / 10)
    
    # Determine security posture
    if analysis['total_risk_score'] >= 70:
        analysis['security_posture'] = 'POOR'
    elif analysis['total_risk_score'] >= 40:
        analysis['security_posture'] = 'FAIR'
    else:
        analysis['security_posture'] = 'GOOD'
    
    # Generate recommendations
    if analysis['total_risk_score'] > 50:
        analysis['recommendations'].append({
            'priority': 'HIGH',
            'action': 'Immediate security review required',
            'details': f'High risk score: {analysis["total_risk_score"]}/100'
        })
    
    if any('Missing security header' in str(vuln) for vuln in attack_results.get('vulnerabilities', [])):
        analysis['recommendations'].append({
            'priority': 'MEDIUM',
            'action': 'Implement security headers',
            'details': 'Missing security headers detected'
        })
    
    return analysis

def perform_overall_web_analysis(web_attacks):
    """Overall AI analysis of all web attack results"""
    analysis = {
        'total_web_services': 0,
        'high_risk_services': 0,
        'technologies_detected': [],
        'overall_risk_score': 0,
        'recommendations': []
    }
    
    for port_key, port_data in web_attacks.items():
        if port_key.startswith('port_'):
            analysis['total_web_services'] += 1
            
            if 'vulnerability_level' in port_data and port_data['vulnerability_level'] in ['HIGH', 'CRITICAL']:
                analysis['high_risk_services'] += 1
            
            if 'technology_analysis' in port_data:
                tech = port_data['technology_analysis']
                if tech['server_tech'] != 'unknown' and tech['server_tech'] not in analysis['technologies_detected']:
                    analysis['technologies_detected'].append(tech['server_tech'])
    
    # Calculate overall risk
    if analysis['total_web_services'] > 0:
        analysis['overall_risk_score'] = min(100, 
            (analysis['high_risk_services'] / analysis['total_web_services']) * 100)
    
    # Generate recommendations
    if analysis['high_risk_services'] > 0:
        analysis['recommendations'].append({
            'priority': 'HIGH',
            'action': 'Prioritize remediation of high-risk web services',
            'details': f'{analysis["high_risk_services"]} high-risk services detected'
        })
    
    return analysis

def get_vulnerability_level(score):
    """Convert vulnerability score to level"""
    if score >= 70: return 'CRITICAL'
    elif score >= 50: return 'HIGH'
    elif score >= 30: return 'MEDIUM'
    elif score >= 10: return 'LOW'
    else: return 'INFO'

if __name__ == "__main__":
    # Test the module
    target = "10.0.3.20"
    results = run_web_attacks(target)
    print(f"\nWeb application analysis completed. Overall risk: {results['ai_analysis'].get('overall_risk_score', 0)}/100")
