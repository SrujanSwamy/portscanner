import socket
from datetime import datetime

def connect_scan(target_ip, port):
    """
    Performs a TCP Connect scan on a single port, supporting both IPv4 and IPv6.
    """
    sock = None  # Initialize sock to None
    try:
        # MODIFICATION: Determine address family for IPv4/IPv6
        addr_info = socket.getaddrinfo(target_ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        family, socktype, proto, canonname, sockaddr = addr_info[0]

        start_time = datetime.now()
        
        # MODIFICATION: Create socket with the correct family
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(1)
        sock.connect(sockaddr)
        sock.close()
        
        end_time = datetime.now()
        latency = round((end_time - start_time).total_seconds() * 1000, 2)
        
        return {"port": port, "status": "Open", "latency_ms": latency}

    except (socket.timeout, ConnectionRefusedError, OSError):
        if sock:
            sock.close()
        return {"port": port, "status": "Closed", "latency_ms": None}
    except Exception:
        if sock:
            sock.close()
        return {"port": port, "status": "Filtered", "latency_ms": None}