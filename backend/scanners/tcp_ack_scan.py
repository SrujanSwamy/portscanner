from scapy.all import sr1, IP, TCP, ICMP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ack_scan(target_ip, port):
    """
    Performs a TCP ACK scan on a single port.
    Follows the logic from DFD 0.3.2.6.
    Requires root/administrator privileges.
    """
    try:
        # DFD 0.3.2.6.2 & 0.3.2.6.3: Generate and Send ACK probe
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="A") # "A" for ACK flag
        packet = ip_packet / tcp_packet
        
        response = sr1(packet, timeout=2, verbose=0)

        # DFD 0.3.2.6.6 & 0.3.2.6.7: Analyze Response and Determine Firewall Status
        if response is None:
            # If no response, port is filtered by a stateful firewall
            return {"port": port, "status": "Filtered"}
            
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4: # RST flag
            # If RST is received, port is not filtered (unfiltered)
            return {"port": port, "status": "Unfiltered"}
            
        if response.haslayer(ICMP):
             # Some firewalls might respond with ICMP errors
            return {"port": port, "status": "Filtered"}

        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}