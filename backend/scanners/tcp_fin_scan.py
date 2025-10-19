from scapy.all import sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def fin_scan(target_ip, port):
    """
    Performs a TCP FIN scan on a single port.
    Follows the logic from DFD 0.3.2.3.
    Requires root/administrator privileges.
    """
    try:
<<<<<<< Updated upstream:backend/scanners/tcp_fin_scan.py
        # DFD 0.3.2.3.2: Craft FIN Packet
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="F") # "F" for FIN flag
=======
        # Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="F") 
>>>>>>> Stashed changes:backend/scanners/con_syn_fin/tcp_fin_scan.py
        packet = ip_packet / tcp_packet

        # DFD 0.3.2.3.3: Send FIN Packet
        response = sr1(packet, timeout=2, verbose=0)

        # DFD 0.3.2.3.6 & 0.3.2.3.7: Analyze Response Pattern and Infer Port State
        if response is None:
            # No response means the port is likely open or filtered
            return {"port": port, "status": "Open|Filtered"}
        
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14: 
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}
        
    except Exception:
        return {"port": port, "status": "Error"}