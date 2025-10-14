from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def window_scan(target_ip, port):
    """
    Performs a TCP Window scan, supporting both IPv4 and IPv6.
    """
    try:
        # Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="A")
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=2, verbose=0)

        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).window > 0:
                return {"port": port, "status": "Open"}
            else: # Window size is 0
                return {"port": port, "status": "Closed"}
        
        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}