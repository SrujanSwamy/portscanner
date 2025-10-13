import socket
from datetime import datetime

def connect_scan(target_ip, port):
    """
    Performs a TCP Connect scan on a single port.
    Follows the logic from DFD 0.3.2.1.
    """
    # DFD 0.3.2.1.2: Create Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # DFD 0.3.2.1.3: Set Socket Option (Timeout)
    sock.settimeout(1)

    try:
        # DFD 0.3.2.1.4: Attempt Connection
        start_time = datetime.now()
        sock.connect((target_ip, port))
        
        # DFD 0.3.2.1.6: Close Socket
        sock.close()
        
        end_time = datetime.now()
        latency = round((end_time - start_time).total_seconds() * 1000, 2)
        
        # DFD 0.3.2.1.7: Format Result
        return {"port": port, "status": "Open", "latency_ms": latency}

    except (socket.timeout, ConnectionRefusedError):
        sock.close()
        return {"port": port, "status": "Closed", "latency_ms": None}
    except Exception:
        sock.close()
        return {"port": port, "status": "Filtered", "latency_ms": None}