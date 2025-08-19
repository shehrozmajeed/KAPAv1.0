import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set

from config import (
    INTERFACE,
    IP_RANGE,
    COMMON_PORTS,
    TCP_CONNECT_TIMEOUT,
    ICMP_WORKERS,
)
from core.network_utils import (
    arp_scan,
    ping_ip,
    resolve_mac,
    same_subnet,
    get_ip_address,
    debug,
)

# -------- Host Discovery --------

def discover_hosts(ip_range: str = IP_RANGE, interface: str = INTERFACE) -> List[Dict[str, str]]:
    """
    Hybrid discovery:
      1) ARP sweep (fast, gets MACs)
      2) Threaded ICMP ping sweep (for hosts that didn't answer ARP)
      3) Try to resolve MACs for ICMP-found hosts via targeted ARP
    """
    # Sanity/debug info
    local_ip = get_ip_address(interface)
    debug(f"Using interface={interface}, local_ip={local_ip}, target_range={ip_range}")
    if not same_subnet(ip_range, interface):
        print(f"⚠ WARNING: Interface {interface} IP {local_ip or 'N/A'} is not in {ip_range}. "
              f"Scanning may miss hosts. (Check config.py)")

    print(f"[+] Scanning LAN on {interface} in range {ip_range}...")

    # ARP scan
    hosts: List[Dict[str, str]] = arp_scan(ip_range, interface)
    known_ips: Set[str] = {h['ip'] for h in hosts}
    print(f"[+] Found {len(hosts)} host(s) via ARP.")

    # ICMP sweep (threaded)
    print("[*] Performing ICMP ping sweep for extra hosts...")
    candidates = [
        str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False).hosts()
        if str(ip) not in known_ips
    ]

    extra: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=ICMP_WORKERS) as pool:
        future_map = {pool.submit(ping_ip, ip, interface): ip for ip in candidates}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                if fut.result():
                    extra.append({'ip': ip, 'mac': '??:??:??:??:??:??'})
            except Exception:
                pass

    if extra:
        print(f"[+] Found {len(extra)} extra host(s) via ICMP.")
        hosts.extend(extra)

    # Resolve MACs for ICMP-found hosts
    unresolved = [h for h in hosts if h['mac'].startswith("??")]
    if unresolved:
        print("[*] Resolving MACs for ICMP-discovered hosts via ARP...")
        for h in unresolved:
            mac = resolve_mac(h['ip'], interface)
            if mac:
                h['mac'] = mac

    print(f"[+] Total live hosts discovered: {len(hosts)}")
    return sorted(hosts, key=lambda x: x['ip'])

# -------- Port Scan --------

def scan_ports(ip: str, ports: List[int] = None) -> List[int]:
    if ports is None:
        ports = COMMON_PORTS
    print(f"[*] Scanning ports on {ip}...")
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CONNECT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    print(f"[+] Open ports on {ip}: {open_ports if open_ports else 'None'}")
    return open_ports
