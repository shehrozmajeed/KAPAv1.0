import nmap
import json
import os
from datetime import datetime

def scan_services(hosts):
    """Scan services on discovered hosts"""
    nm = nmap.PortScanner()
    results = {}
    
    for host in hosts:
        host_ip = host['ip']
        print(f"[*] Scanning services on {host_ip}")
        
        try:
            # Perform service version detection with OS detection
            scan_result = nm.scan(hosts=host_ip, arguments='-sV -O --script smb-os-discovery')
            
            if host_ip in nm.all_hosts():
                host_data = nm[host_ip]
                results[host_ip] = {
                    'hostname': host['hostname'],
                    'mac': host['mac'],
                    'status': host_data.state(),
                    'os_guess': host_data.get('osmatch', [{}])[0].get('name', 'Unknown') if host_data.get('osmatch') else 'Unknown',
                    'ports': [],
                    'services': []
                }
                
                # Extract port information
                for proto in host_data.all_protocols():
                    if proto not in ['tcp', 'udp']:
                        continue
                        
                    for port in host_data[proto].keys():
                        port_info = host_data[proto][port]
                        results[host_ip]['ports'].append(port)
                        
                        service_info = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'product': port_info.get('product', 'unknown')
                        }
                        results[host_ip]['services'].append(service_info)
            
        except Exception as e:
            print(f"Error scanning {host_ip}: {e}")
            results[host_ip] = {'error': str(e)}
    
    return results

def save_results(results, filename=None):
    """Save scan results to JSON file"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/scan_results_{timestamp}.json"
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Results saved to {filename}")
    return filename

if __name__ == "__main__":
    # Test with a single host
    test_hosts = [{'ip': '127.0.0.1', 'mac': 'test', 'hostname': 'localhost'}]
    results = scan_services(test_hosts)
    print(json.dumps(results, indent=2))
