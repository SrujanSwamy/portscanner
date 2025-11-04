"""
TCP SYN Scan Module
Performs half-open scanning using SYN packets (stealth scan)
"""
from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

# Suppress scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def syn_scan(target_ip, port):
    """
    Performs TCP SYN scan on a single port

    Args:
        target_ip (str): Target IP address (IPv4 or IPv6)
        port (int): Port number to scan

    Returns:
        dict: Scan result with port and status
    """
    try:
        # Build packet for IPv4 or IPv6
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="S")
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=1, verbose=0)

        # No response indicates filtered port
        if response is None:
            return {"port": port, "status": "Filtered"}

        if response.haslayer(TCP):
            # SYN/ACK response (0x12) indicates open port
            if response.getlayer(TCP).flags == 0x12:
                # Send RST to close connection gracefully
                if ip_addr.version == 4:
                    rst_packet = (IP(dst=target_ip) /
                                  TCP(dport=port, flags="R"))
                else:
                    rst_packet = (IPv6(dst=target_ip) /
                                  TCP(dport=port, flags="R"))
                sr1(rst_packet, timeout=1, verbose=0)
                return {"port": port, "status": "Open"}
            # RST/ACK response (0x14) indicates closed port
            elif response.getlayer(TCP).flags == 0x14:
                return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
