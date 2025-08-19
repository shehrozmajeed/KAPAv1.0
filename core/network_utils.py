import os
import ipaddress
import netifaces
import subprocess
from typing import Optional, List, Dict
from scapy.all import ARP, Ether, srp  # L2 only (no L3 sr1 here)
from config import (
    INTERFACE,
    IP_RANGE,
    ARP_TIMEOUT,
    ARP_RETRIES,
    PING_TIMEOUT,
)

# ---------- Helpers / Debug ----------

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback
        return True

def debug(msg: str):
    print(f"[DEBUG] {msg}")

# ---------- Interface / IP Utilities ----------

def get_ip_address(interface: str = INTERFACE) -> Optional[str]:
    """Return IPv4 address assigned to an interface, or None."""
    try:
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        return None

def get_netmask(interface: str = INTERFACE) -> Optional[str]:
    try:
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET][0]['netmask']
    except Exception:
        return None

def get_interface_cidr(interface: str = INTERFACE) -> Optional[str]:
    """Derive CIDR (e.g., 192.168.100.24/24) from interface IP+netmask."""
    ip = get_ip_address(interface)
    mask = get_netmask(interface)
    if not ip or not mask:
        return None
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return f"{ip}/{net.prefixlen}"
    except Exception:
        return None

def same_subnet(ip_range: str, interface: str = INTERFACE) -> bool:
    """Check if interface IP falls inside ip_range."""
    ip = get_ip_address(interface)
    if not ip:
        return False
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(ip_range, strict=False)
    except Exception:
        return False

# ---------- ARP Utilities ----------

def arp_scan(ip_range: str = IP_RANGE, interface: str = INTERFACE) -> List[Dict[str, str]]:
    """
    Perform an ARP sweep and return list of {'ip','mac'}.
    """
    debug(f"ARP scan on {interface} across {ip_range} (timeout={ARP_TIMEOUT}, retries={ARP_RETRIES})")
    hosts = []
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=ARP_TIMEOUT, retry=ARP_RETRIES, iface=interface, verbose=0)
        for _, r in answered:
            hosts.append({'ip': r.psrc, 'mac': r.hwsrc})
    except PermissionError:
        print("❌ Permission error: run this program with sudo/root for ARP scanning.")
    except Exception as e:
        print(f"⚠ ARP scan error: {e}")
    return hosts

def resolve_mac(ip: str, interface: str = INTERFACE) -> Optional[str]:
    """Send a single ARP who-has to resolve MAC of one IP."""
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=ARP_TIMEOUT, retry=ARP_RETRIES, iface=interface, verbose=0)
        for _, r in answered:
            return r.hwsrc
    except Exception:
        return None
    return None

# ---------- ICMP (system ping) ----------

def ping_ip(ip: str, interface: str = INTERFACE, timeout: int = PING_TIMEOUT) -> bool:
    """
    Use system ping with -I <iface> to avoid Scapy L3 warnings and pick the right NIC.
    Returns True if host replies.
    """
    try:
        # Linux ping: -c 1 one probe, -W timeout sec, -I interface for source NIC
        res = subprocess.run(
            ["ping", "-I", interface, "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False
