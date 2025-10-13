from scapy.all import sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def syn_scan(target_ip, port):
    """
    Performs a TCP SYN scan on a single port.
    Follows the logic from DFD 0.3.2.2.
    Requires root/administrator privileges to run.
    """
    try:
        # Build SYN Packet
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="S") 
        packet = ip_packet / tcp_packet

        # Send SYN Packet and wait for one response
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            return {"port": port, "status": "Filtered"}
        
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return {"port": port, "status": "Open"}
            elif response.getlayer(TCP).flags == 0x14:
                return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}