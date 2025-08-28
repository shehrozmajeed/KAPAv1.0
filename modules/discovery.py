#!/usr/bin/env python3

import nmap
import subprocess
from ipaddress import IPv4Network
import socket

def get_local_network(interface='eth0'):
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
            if 'inet' in line:
                parts = line.strip().split()
                ip_with_mask = parts[1]
                ip, mask_bits = ip_with_mask.split('/')
                network = IPv4Network(f"{ip}/{mask_bits}", strict=False)
                return str(network)
        
        print(f"Interface {interface} has no IPv4 address. Using default network 192.168.1.0/24")
        return '192.168.1.0/24'
        
    except Exception as e:
        print(f"Error getting local network: {e}")
        return '192.168.1.0/24'

def discover_hosts(network_range=None, interface='eth0'):
    """Discover active hosts on the network with improved reliability"""
    if not network_range:
        network_range = get_local_network(interface)
    
    print(f"[*] Scanning network: {network_range}")
    
    nm = nmap.PortScanner()
    live_hosts = []
    
    try:
        # First try ping sweep
        scan_args = f'-sn -e {interface} --min-hostgroup 64 --min-parallelism 64'
        scan_result = nm.scan(hosts=network_range, arguments=scan_args)
        
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                # Get MAC address if available
                mac_address = 'Unknown'
                if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                    mac_address = nm[host]['addresses']['mac']
                
                # Get hostname if available
                hostnames = nm[host].hostnames()
                hostname = hostnames[0]['name'] if hostnames else 'Unknown'
                
                # Additional verification with socket
                try:
                    socket.gethostbyaddr(host)
                    hostname_verified = True
                except:
                    hostname_verified = False
                
                live_hosts.append({
                    'ip': host,
                    'mac': mac_address,
                    'hostname': hostname,
                    'hostname_verified': hostname_verified,
                    'status': nm[host].state()
                })
        
        print(f"[+] Found {len(live_hosts)} live hosts")
        return live_hosts
        
    except Exception as e:
        print(f"Error scanning with interface {interface}: {e}")
        print("Trying alternative discovery methods...")
        
        # Fallback methods
        try:
            # ARP discovery
            arp_result = subprocess.run(['arp-scan', '--localnet'], 
                                      capture_output=True, text=True, timeout=120)
            
            if arp_result.returncode == 0:
                for line in arp_result.stdout.split('\n'):
                    if line and not line.startswith('Interface:') and not line.startswith('Starting'):
                        parts = line.split()
                        if len(parts) >= 2:
                            live_hosts.append({
                                'ip': parts[0],
                                'mac': parts[1],
                                'hostname': 'Unknown',
                                'hostname_verified': False,
                                'status': 'up'
                            })
                
                print(f"[+] Found {len(live_hosts)} hosts via ARP scan")
                return live_hosts
        except:
            pass
        
        # Final fallback: sequential ping
        print("Trying sequential ping discovery...")
        network = IPv4Network(network_range)
        for ip in network.hosts():
            ip_str = str(ip)
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip_str],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    live_hosts.append({
                        'ip': ip_str,
                        'mac': 'Unknown',
                        'hostname': 'Unknown',
                        'hostname_verified': False,
                        'status': 'up'
                    })
            except:
                pass
        
        print(f"[+] Found {len(live_hosts)} hosts via ping")
        return live_hosts

if __name__ == "__main__":
    # Test the discovery function
    hosts = discover_hosts()
    for host in hosts:
        print(f"Host: {host['ip']} - MAC: {host['mac']} - Hostname: {host['hostname']}")
