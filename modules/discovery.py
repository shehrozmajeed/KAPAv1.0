import nmap
import subprocess
from ipaddress import IPv4Network

def get_local_network(interface='eth1'):
    """Get the local network range for the specified interface"""
    try:
        # Get IP and netmask for the interface
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                             capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print(f"Interface {interface} not found. Using default network 192.168.1.0/24")
            return '192.168.1.0/24'
        
        # Extract IP and subnet from output
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                parts = line.strip().split()
                ip_with_mask = parts[1]
                ip, mask_bits = ip_with_mask.split('/')
                network = IPv4Network(f"{ip}/{mask_bits}", strict=False)
                return str(network)
        
        print(f"Interface {interface} has no IPv4 address. Using default network 192.168.1.0/24")
        return '192.168.1.0/24'
        
    except Exception as e:
        print(f"Error getting local network: {e}")
        return "192.168.1.0/24"

def discover_hosts(network_range=None, interface='eth1'):
    """Discover active hosts on the network"""
    if not network_range:
        network_range = get_local_network(interface)
    
    print(f"[*] Scanning network: {network_range}")
    
    nm = nmap.PortScanner()
    
    # First try to scan with the interface specified
    try:
        scan_result = nm.scan(hosts=network_range, arguments=f'-sn -e {interface}')
    except Exception as e:
        print(f"Error scanning with interface {interface}: {e}")
        print("Trying scan without interface specification...")
        # Fallback: scan without specifying interface
        try:
            scan_result = nm.scan(hosts=network_range, arguments='-sn')
        except Exception as e2:
            print(f"Scan failed: {e2}")
            return []
    
    live_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            # Get MAC address if available
            mac_address = 'Unknown'
            if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                mac_address = nm[host]['addresses']['mac']
            
            # Get hostname if available
            hostnames = nm[host].hostnames()
            hostname = hostnames[0]['name'] if hostnames else 'Unknown'
            
            live_hosts.append({
                'ip': host,
                'mac': mac_address,
                'hostname': hostname,
                'status': nm[host].state()
            })
    
    print(f"[+] Found {len(live_hosts)} live hosts")
    return live_hosts

if __name__ == "__main__":
    # Test the discovery function
    hosts = discover_hosts()
    for host in hosts:
        print(f"Host: {host['ip']} - MAC: {host['mac']} - Hostname: {host['hostname']}")
