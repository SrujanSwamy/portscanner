"""
TCP ACK Scan

Sends an ACK packet to infer firewall filtering: an RST implies the host
is reachable and the port is unfiltered; no response or ICMP unreachable
implies filtering along the path. Works with IPv4 and IPv6.
"""

from scapy.all import sr1, IP, TCP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def ack_scan(target_ip, port):
    """
    Perform a TCP ACK scan against a single port.

    Args:
        target_ip (str): Target IPv4/IPv6 address.
        port (int): Destination TCP port.

    Returns:
        dict: {"port": int, "status": str} -> Unfiltered or Filtered.
    """

    try:
        # Build IPv4/IPv6 base IP packet
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

        # RST response indicates the host is reachable (unfiltered)
        if response.haslayer(TCP) and \
                response.getlayer(TCP).flags == 0x4:
            return {"port": port, "status": "Unfiltered"}

        # ICMP unreachable implies filtering
        if response.haslayer(ICMP) or \
                response.haslayer(ICMPv6DestUnreach):
            return {"port": port, "status": "Filtered"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
