"""
TCP Idle Scan

Performs a stealth scan using a "zombie" host to infer a target's port
state by observing the zombie's IP ID changes. Less reliable with IPv6
because there is no predictable fragmented IP ID field.
"""

from scapy.all import sr, sr1, IP, TCP, IPv6
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_ip_id(target_ip):
    """
    Retrieve the current identifier from a host for idle-scan inference.

    Args:
        target_ip (str): Host to probe (zombie).

    Returns:
        int | None: IPv4 IP ID or IPv6 Traffic Class; None on no response.
    """
    try:
        ip_addr = ipaddress.ip_address(target_ip)
        
        if ip_addr.version == 4:
            probe_packet = IP(dst=target_ip)/TCP(flags="SA")
        else:
            # IPv6: no predictable IP ID; use Traffic Class as a proxy.
            probe_packet = IPv6(dst=target_ip)/TCP(flags="SA")

        response = sr1(probe_packet, timeout=2, verbose=0)

        if response:
            if ip_addr.version == 4:
                print("target_ip_id",response.id)
                return response.id
            else:
                return response.tc  # Traffic Class for IPv6
    except Exception:
        return None
    return None


def idle_scan(target_ip, port, zombie_ip):
    """
    Execute a TCP Idle Scan against a single target port.

    Args:
        target_ip (str): The target host.
        port (int): Target port to test.
        zombie_ip (str): The idle "zombie" host.

    Returns:
        dict: {"port": int, "status": str} with Open or Closed|Filtered.
    """

    try:
        initial_id = get_ip_id(zombie_ip)
        
        if initial_id is None:
            return {
                "port": port,
                "status": "Error: Zombie not responding."
            }

        # Build spoofed packet based on target IP version
        target_addr = ipaddress.ip_address(target_ip)
        if target_addr.version == 4:
            spoofed_packet = IP(src=zombie_ip, dst=target_ip) / \
                TCP(dport=port, flags="S")
            print("spoofed packet: ",spoofed_packet)
        else:
            spoofed_packet = IPv6(src=zombie_ip, dst=target_ip) / \
                TCP(dport=port, flags="S")

        sr(spoofed_packet, timeout=3, verbose=0)

        final_id = get_ip_id(zombie_ip)
        if final_id is None:
            print("final id",final_id)
            return {
                "port": port,
                "status": "Error: Zombie stopped responding."
            }

        # > 1 increment implies target replied (SYN/ACK) causing zombie RST,
        # incrementing its ID again; == 1 implies only our probe was sent.
        if (final_id - initial_id) > 1:
            return {"port": port, "status": "Open"}
        else:
            return {"port": port, "status": "Closed|Filtered"}

    except Exception as e:
        return {"port": port, "status": f"Error: {str(e)}"}
