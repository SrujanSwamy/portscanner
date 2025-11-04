"""
TCP XMAS Scan

Sends a TCP segment with FIN, PSH, and URG set ("lit up like a tree").
No response implies Open|Filtered; RST/ACK implies Closed.
"""

from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def xmas_scan(target_ip, port):
    """
    Perform a TCP XMAS scan against a single port.

    Args:
        target_ip (str): Target IPv4/IPv6 address.
        port (int): Destination TCP port.

    Returns:
        dict: {"port": int, "status": str} -> Open|Filtered, Closed, or Filtered.
    """

    try:
        # Build IPv4/IPv6 base IP packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="FPU")  # FIN|PSH|URG (XMAS)
        packet = ip_packet / tcp_packet

        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            return {"port": port, "status": "Open|Filtered"}

        # RST/ACK (0x14) => Closed
        if response.haslayer(TCP) and \
                response.getlayer(TCP).flags == 0x14:
            return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
