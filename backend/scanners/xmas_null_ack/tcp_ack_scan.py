from scapy.all import sr1, IP, TCP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ack_scan(target_ip, port):
    """
    Performs a TCP ACK scan, supporting both IPv4 and IPv6.
    """
    try:
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="A") 
        packet = ip_packet / tcp_packet
        
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            return {"port": port, "status": "Filtered"}
            
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4: 
            return {"port": port, "status": "Unfiltered"}
            
        # Check for ICMPv4 or ICMPv6 error messages
        if response.haslayer(ICMP) or response.haslayer(ICMPv6DestUnreach):
            return {"port": port, "status": "Filtered"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}