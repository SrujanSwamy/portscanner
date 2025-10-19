from scapy.all import sr, sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_ip_id(target_ip):
    """Helper function to get the IP ID from a target (supports IPv4 and IPv6)."""
    try:
        ip_addr = ipaddress.ip_address(target_ip)
        if ip_addr.version == 4:
            probe_packet = IP(dst=target_ip)/TCP(flags="SA")
        else:
            probe_packet = IPv6(dst=target_ip)/TCP(flags="SA")

        response = sr1(probe_packet, timeout=2, verbose=0)

        if response:
            if ip_addr.version == 4:
                return response.id
            else:
                return response.tc 
    except Exception:
        return None
    return None

def idle_scan(target_ip, port, zombie_ip):
    """
     Idle scanning is inherently less reliable with IPv6 due to the lack of a fragmented IP ID field.
    """
    try:
        initial_id = get_ip_id(zombie_ip)
        if initial_id is None:
            return {"port": port, "status": "Error: Zombie not responding."}

        # Build spoofed packet based on target IP version
        target_addr = ipaddress.ip_address(target_ip)
        if target_addr.version == 4:
            spoofed_packet = IP(src=zombie_ip, dst=target_ip)/TCP(dport=port, flags="S")
        else:
            spoofed_packet = IPv6(src=zombie_ip, dst=target_ip)/TCP(dport=port, flags="S")
        
        sr(spoofed_packet, timeout=3, verbose=0)

        final_id = get_ip_id(zombie_ip)
        if final_id is None:
            return {"port": port, "status": "Error: Zombie stopped responding."}

        if (final_id - initial_id) > 1:
            return {"port": port, "status": "Open"}
        else:
            return {"port": port, "status": "Closed|Filtered"}

    except Exception as e:
        return {"port": port, "status": f"Error: {str(e)}"}