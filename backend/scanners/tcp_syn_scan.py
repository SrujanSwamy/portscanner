from scapy.all import sr1, IP, TCP
import logging

# Suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def syn_scan(target_ip, port):
    """
    Performs a TCP SYN scan on a single port.
    Follows the logic from DFD 0.3.2.2.
    Requires root/administrator privileges to run.
    """
    try:
        # DFD 0.3.2.2.2: Build SYN Packet
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="S") # "S" for SYN flag
        packet = ip_packet / tcp_packet

        # DFD 0.3.2.2.3: Send SYN Packet and wait for one response
        # sr1 sends a packet and receives the first answer
        response = sr1(packet, timeout=1, verbose=0)

        # DFD 0.3.2.2.6 & 0.3.2.2.7: Parse TCP Flags and Determine Port State
        if response is None:
            return {"port": port, "status": "Filtered"}
        
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN/ACK flags
                # Send a RST packet to tear down the connection
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return {"port": port, "status": "Open"}
            elif response.getlayer(TCP).flags == 0x14: # RST/ACK flags
                return {"port": port, "status": "Closed"}

        return {"port": port, "status": "Filtered"} # No definitive TCP response

    except Exception:
        return {"port": port, "status": "Error"}