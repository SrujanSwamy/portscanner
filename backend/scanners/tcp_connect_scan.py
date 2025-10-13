import socket
from datetime import datetime

def connect_scan(target_ip, port):

    # Create Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set Socket Option (Timeout)
    sock.settimeout(1)

    try:
        #  Attempt Connection
        start_time = datetime.now()
        sock.connect((target_ip, port))
        
        # Close Socket
        sock.close()
        
        end_time = datetime.now()
        latency = round((end_time - start_time).total_seconds() * 1000, 2)
        
        #  Format Result
        return {"port": port, "status": "Open", "latency_ms": latency}

    except (socket.timeout, ConnectionRefusedError):
        sock.close()
        return {"port": port, "status": "Closed", "latency_ms": None}
    except Exception:
        sock.close()
        return {"port": port, "status": "Filtered", "latency_ms": None}