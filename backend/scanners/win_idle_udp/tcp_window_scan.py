"""
TCP Window Scan

Sends an ACK packet and infers port state from the TCP window size in the
response: window > 0 suggests Open; window == 0 suggests Closed. No TCP
response is treated as Filtered.
"""

from scapy.all import sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def window_scan(target_ip, port):
    """
    Perform a TCP window scan against a single port.

    Args:
        target_ip (str): Target IPv4/IPv6 address.
        port (int): Destination TCP port to test.

    Returns:
        dict: {"port": int, "status": str} where status is Open, Closed, or Filtered.
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
        

        if response is not None and response.haslayer(TCP):
            # Heuristic: ACK with window > 0 => Open; window == 0 => Closed
            if response.getlayer(TCP).window > 0:
                return {"port": port, "status": "Open"}
            else:
                return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}
