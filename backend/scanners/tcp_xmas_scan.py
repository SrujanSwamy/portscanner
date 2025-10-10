from scapy.all import sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def xmas_scan(target_ip, port):
    """
    Performs a TCP Xmas scan on a single port.
    Follows the logic from DFD 0.3.2.4.
    Requires root/administrator privileges.
    """
    try:
        # DFD 0.3.2.4.2 & 0.3.2.4.3: Set TCP Flags and Build Xmas Packet
        ip_packet = IP(dst=target_ip)
        # "FPU" for FIN, PSH, URG flags
        tcp_packet = TCP(dport=port, flags="FPU")
        packet = ip_packet / tcp_packet

        # DFD 0.3.2.4.4: Transmit Packet
        response = sr1(packet, timeout=2, verbose=0)

        # DFD 0.3.2.4.7 & 0.3.2.4.8: Evaluate Response and Classify Port Status
        if response is None:
            return {"port": port, "status": "Open|Filtered"}
        
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14: # RST/ACK
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}