"""
UDP Scan

Infers port state using UDP and ICMP responses: no response implies
Open|Filtered; ICMP Port Unreachable indicates Closed; a UDP reply
indicates Open.
"""

from scapy.all import sr1, IP, UDP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def udp_scan(target_ip, port):
    """
    Perform a UDP scan against a single port.

    Args:
        target_ip (str): Target IPv4/IPv6 address.
        port (int): Destination UDP port to test.

    Returns:
        dict: {"port": int, "status": str} -> Open, Closed, Filtered, or Open|Filtered.
    """

    try:
        # Build IPv4/IPv6 base IP packet
        ip_addr = ipaddress.ip_address(target_ip)
        
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        udp_packet = UDP(dport=port)
        packet = ip_packet / udp_packet

        response = sr1(packet, timeout=3, verbose=0)
        
        if response is None:
            # No response: UDP often elicits no reply => Open|Filtered
            return {"port": port, "status": "Open|Filtered"}

        # ICMP Port Unreachable => Closed (IPv4: type 3 code 3; IPv6: code 4)
        if response.haslayer(ICMP) and \
                int(response.getlayer(ICMP).type) == 3 and \
                int(response.getlayer(ICMP).code) == 3:
            return {"port": port, "status": "Closed"}
        if response.haslayer(ICMPv6DestUnreach) and \
                int(response.getlayer(ICMPv6DestUnreach).code) == 4:
            return {"port": port, "status": "Closed"}

        if response.haslayer(UDP):
            # A UDP response from target implies the port is Open
            return {"port": port, "status": "Open"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
