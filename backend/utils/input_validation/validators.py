import re
import ipaddress

def parse_ports(port_string):
    """
    Parses and validates a port string into a list of integers.
    """
    ports = set()
    if not port_string:
        return []
    
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if not (0 < start <= end <= 65535):
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range format: {part}")
        else:
            try:
                port = int(part)
                if not (0 < port <= 65535):
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")
    
    return sorted(list(ports))

def validate_ip_address(ip_addr):
    """
    Validates the format of an IPv4 or IPv6 address.
    Returns True if valid, False otherwise.
    """
    if not ip_addr or not isinstance(ip_addr, str):
        return False
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False