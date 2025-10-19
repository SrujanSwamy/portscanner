from scapy.all import sr1, IP, TCP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def null_scan(target_ip, port):
    """
    Performs a TCP Null scan on a single port.
    Follows the logic from DFD 0.3.2.5.
    Requires root/administrator privileges.
    """
    try:
<<<<<<< Updated upstream:backend/scanners/tcp_null_scan.py
        # DFD 0.3.2.5.2: Create Zero-Flag Packet
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="") # Empty string for no flags
=======
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="") # No flags
>>>>>>> Stashed changes:backend/scanners/xmas_null_ack/tcp_null_scan.py
        packet = ip_packet / tcp_packet

        # DFD 0.3.2.5.3: Dispatch Packet
        response = sr1(packet, timeout=2, verbose=0)

        # DFD 0.3.2.5.6 & 0.3.2.5.7: Process Response and Determine Port State
        if response is None:
            return {"port": port, "status": "Open|Filtered"}
        
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14: 
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}