# MODIFICATION: Import IPv6 and ipaddress
from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def syn_scan(target_ip, port):
    """
    Performs a TCP SYN scan, supporting both IPv4 and IPv6.
    """
    try:
        # MODIFICATION: Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="S")
        packet = ip_packet / tcp_packet
        
        # The rest of the logic remains the same
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            return {"port": port, "status": "Filtered"}
        
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN/ACK
                # Send RST to close
                if ip_addr.version == 4:
                    rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R")
                else:
                    rst_packet = IPv6(dst=target_ip)/TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=1, verbose=0)
                return {"port": port, "status": "Open"}
            elif response.getlayer(TCP).flags == 0x14: # RST/ACK
                return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}