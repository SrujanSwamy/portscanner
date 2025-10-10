from scapy.all import sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def window_scan(target_ip, port):
    """
    Performs a TCP Window scan on a single port.
    Follows the logic from DFD 0.3.2.7.
    Requires root/administrator privileges.
    """
    try:
        # DFD 0.3.2.7.2 & 0.3.2.7.3: Create and Send ACK Packet
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="A")
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=2, verbose=0)

        # DFD 0.3.2.7.5 to 0.3.2.7.8: Analyze TCP Window and Classify Port State
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).window > 0:
                return {"port": port, "status": "Open"}
            else: # Window size is 0
                return {"port": port, "status": "Closed"}
        
        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}