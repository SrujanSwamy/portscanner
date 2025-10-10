from scapy.all import sr1, IP, UDP, ICMP
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def udp_scan(target_ip, port):
    """
    Performs a UDP scan on a single port.
    Follows the logic from DFD 0.3.3.
    Requires root/administrator privileges.
    """
    try:
        # DFD 0.3.3.2 & 0.3.3.3: Create and Send UDP Probe
        ip_packet = IP(dst=target_ip)
        udp_packet = UDP(dport=port)
        packet = ip_packet / udp_packet
        
        # Send a UDP packet, wait for a response
        response = sr1(packet, timeout=3, verbose=0)

        # DFD 0.3.3.6 & 0.3.3.7: Differentiate Response and Determine Port State
        if response is None:
            # No response could mean Open or Filtered
            return {"port": port, "status": "Open | Filtered"}
        
        elif response.haslayer(ICMP):
            # ICMP "port unreachable" error means the port is closed
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                return {"port": port, "status": "Closed"}
            # Other ICMP errors mean it's likely filtered
            else:
                return {"port": port, "status": "Filtered"}
        
        elif response.haslayer(UDP):
            # A UDP response means the port is open
            return {"port": port, "status": "Open"}
            
        return {"port": port, "status": "Filtered"}

    except Exception:
        return {"port": port, "status": "Error"}