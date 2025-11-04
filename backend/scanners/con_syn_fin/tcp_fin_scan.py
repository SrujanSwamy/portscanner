"""
TCP FIN Scan Module
Sends TCP packets with FIN flag to detect open ports (stealth scan)
"""
from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

# Suppress scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def fin_scan(target_ip, port):
    """
    Performs TCP FIN scan on a single port

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

        tcp_packet = TCP(dport=port, flags="F")
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=2, verbose=0)

        # No response indicates open or filtered port
        if response is None:
            return {"port": port, "status": "Open|Filtered"}

        # RST/ACK response (0x14) indicates closed port
        if response.haslayer(TCP) and \
                response.getlayer(TCP).flags == 0x14:
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
