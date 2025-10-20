from scapy.all import sr1, IP, TCP, ICMP, IPv6, ICMPv6DestUnreach
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ack_scan(target_ip, port):
    """
    Performs a TCP ACK scan, supporting both IPv4 and IPv6.
    """
    try:
        # Detect IP version and build the correct packet
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            ip_packet = IP(dst=target_ip)
        else:
            ip_packet = IPv6(dst=target_ip)

        tcp_packet = TCP(dport=port, flags="A") # "A" for ACK
        packet = ip_packet / tcp_packet
        
        response = sr1(packet, timeout=5, verbose=0,iface="Wi-Fi")

        if response is None:
            return {"port": port, "status": "Filtered"}
        
        tcp = response.getlayer(TCP)
        if response.haslayer(TCP) and (int(tcp.flags) & 0x04): # RST
            return {"port": port, "status": "Unfiltered"}
            
        # Check for ICMPv4 or ICMPv6 Destination Unreachable messages
        if response.haslayer(ICMP) or response.haslayer(ICMPv6DestUnreach):
            return {"port": port, "status": "Filtered"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        logging.exception("ack_scan failed")
        return {"port": port, "status": "Error", "error": str(e)}