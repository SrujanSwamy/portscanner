"""Input validation helpers for ports and IP addresses."""

import re
import ipaddress


def parse_ports(port_string):
    """
    Parse a port string into a sorted list of unique integers.

    Args:
        port_string (str): Comma-separated ports and/or ranges
            (e.g., "22,80,1000-1005").

    Returns:
        list[int]: Sorted unique ports.

    Raises:
        ValueError: If any port or range is invalid or out of [1, 65535].
    """
    ports = set()
    if not port_string:
        return []

    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Handle range like "1000-2000"
            try:
                start, end = map(int, part.split('-'))
                if not (0 < start <= end <= 65535):
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range format: {part}")
        else:
            # Handle single port like "80"
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
    Validate IPv4 or IPv6 address format.

    Args:
        ip_addr (str): IP address string.

    Returns:
        bool: True if valid, otherwise False.
    """
    if not ip_addr or not isinstance(ip_addr, str):
        return False
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False
