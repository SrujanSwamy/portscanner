<<<<<<< Updated upstream
from scapy.all import sr1, IP, UDP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def udp_scan(target_ip, port):
    """
    Performs a UDP scan, supporting both IPv4 and IPv6.
    """
    try:
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        udp_packet = UDP(dport=port)
        packet = ip_packet / udp_packet
        
        response = sr1(packet, timeout=3, verbose=0)

        if response is None:
            return {"port": port, "status": "Open|Filtered"}
        
        # Check for ICMP error (v4 and v6)
        if response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
            return {"port": port, "status": "Closed"}
        if response.haslayer(ICMPv6DestUnreach) and int(response.getlayer(ICMPv6DestUnreach).code) == 4:
             return {"port": port, "status": "Closed"}
        
        if response.haslayer(UDP):
            return {"port": port, "status": "Open"}
            
        return {"port": port, "status": "Filtered"}

    except Exception:
=======
from scapy.all import sr1, IP, UDP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def udp_scan(target_ip, port):
    """
    Performs a UDP scan, supporting both IPv4 and IPv6.
    """
    try:
        # Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        udp_packet = UDP(dport=port)
        packet = ip_packet / udp_packet
        
        response = sr1(packet, timeout=3, verbose=0)

        if response is None:
            return {"port": port, "status": "Open|Filtered"}
        
        # Check for ICMP error (v4 and v6)
        if response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
            return {"port": port, "status": "Closed"}
        if response.haslayer(ICMPv6DestUnreach) and int(response.getlayer(ICMPv6DestUnreach).code) == 4:
             return {"port": port, "status": "Closed"}
        
        if response.haslayer(UDP):
            return {"port": port, "status": "Open"}
            
        return {"port": port, "status": "Filtered"}

    except Exception:
>>>>>>> Stashed changes
        return {"port": port, "status": "Error"}