import re
import ipaddress
from typing import Optional

PRIVATE_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
]

PRIVATE_NETWORKS = [ipaddress.ip_network(r) for r in PRIVATE_RANGES]

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
            or any(addr in network for network in PRIVATE_NETWORKS)
        )
    except ValueError:
        return False

def is_public_ip(ip: str) -> bool:
    return is_valid_ip(ip) and not is_private_ip(ip)

def normalize_ip(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return None

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip

def ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None

def extract_ips_from_text(text: str) -> list:
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(pattern, text)
    return [ip for ip in candidates if is_valid_ip(ip)]

def get_ip_version(ip: str) -> Optional[int]:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version
    except ValueError:
        return None

def is_tor_exit_node(ip: str, tor_list: list) -> bool:
    return ip in tor_list

def calculate_subnet(ip: str, prefix: int = 24) -> Optional[str]:
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return None