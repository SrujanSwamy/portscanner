from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def null_scan(target_ip, port):
    """
    Performs a TCP Null scan, supporting both IPv4 and IPv6.
    """
    try:
        # Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="") # No flags
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            return {"port": port, "status": "Open|Filtered"}
        
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14: # RST/ACK
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}