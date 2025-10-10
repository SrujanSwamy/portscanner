from scapy.all import sr, sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_ip_id(target_ip):
    """Helper function to get the IP ID from a target."""
    response = sr1(IP(dst=target_ip)/TCP(flags="SA"), timeout=2, verbose=0)
    if response:
        return response.id
    return None

def idle_scan(target_ip, port, zombie_ip):
    """
    Performs a TCP Idle scan on a single port.
    Follows the logic from DFD 0.3.4.
    Requires root/administrator privileges.
    """
    try:
        # DFD 0.3.4.2: Probe Zombie IP ID (Initial)
        initial_id = get_ip_id(zombie_ip)
        if initial_id is None:
            return {"port": port, "status": "Error: Zombie not responding."}

        # DFD 0.3.4.3: Spoof SYN from Zombie to Target
        # The `sr` function is used here to send without waiting for a direct reply to us
        sr(IP(src=zombie_ip, dst=target_ip)/TCP(dport=port, flags="S"), timeout=3, verbose=0)

        # DFD 0.3.4.5: Probe Zombie again
        final_id = get_ip_id(zombie_ip)
        if final_id is None:
            return {"port": port, "status": "Error: Zombie stopped responding."}

        # DFD 0.3.4.6 & 0.3.4.7: Compare IP ID values and Infer Port State
        if (final_id - initial_id) > 1:
            # If the ID increased by more than 1, the port is open
            # (Zombie replied to target, then to us, incrementing ID twice)
            return {"port": port, "status": "Open"}
        else:
            # If ID increased by 1 or less, the port is closed or filtered
            return {"port": port, "status": "Closed|Filtered"}

    except Exception as e:
        return {"port": port, "status": f"Error: {str(e)}"}