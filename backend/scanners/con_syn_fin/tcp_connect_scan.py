"""
TCP Connect Scan Module
Performs full TCP three-way handshake to determine port status
"""
import socket
from datetime import datetime


def connect_scan(target_ip, port):
    """
    Performs TCP Connect scan on a single port

    Args:
        target_ip (str): Target IP address or hostname
        port (int): Port number to scan

    Returns:
        dict: Scan result with port, status, and latency
    """
    sock = None
    try:
        # Resolve address for IPv4/IPv6 compatibility
        addr_info = socket.getaddrinfo(
            target_ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        family, socktype, proto, canonname, sockaddr = addr_info[0]

        start_time = datetime.now()

        # Attempt TCP connection
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(1)
        sock.connect(sockaddr)
        sock.close()

        end_time = datetime.now()
        latency = round((end_time - start_time).total_seconds() * 1000, 2)

        return {"port": port, "status": "Open", "latency_ms": latency}

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Connection failed - port closed
        if sock:
            sock.close()
        return {"port": port, "status": "Closed", "latency_ms": None}
    except Exception:
        # Unexpected error - port filtered
        if sock:
            sock.close()
        return {"port": port, "status": "Filtered", "latency_ms": None}
