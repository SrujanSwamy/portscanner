# backend/scanners/host_discovery/ip_protocol_scan.py
from scapy.all import sr1, IP, ICMP, IPv6
import logging
import ipaddress
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Common IP Protocol Numbers and Names (subset)
IP_PROTOCOL_NAMES = {
     1: "ICMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 58: "ICMPv6", 
}

def scan(target_ip, timeout=2):
    """
    Performs an IP Protocol Scan to identify supported protocols.
    Sends raw IP packets with different protocol numbers.
    """

    try:
        if isinstance(timeout, list):
            timeout = float(timeout[0])
        else:
            timeout = float(timeout)
    except (ValueError, TypeError, IndexError):
        timeout = 2.0

    results = []
    # Scan common protocol numbers
    protocols_to_scan = list(IP_PROTOCOL_NAMES.keys()) + [0, 58, 103]

    print(f"[*] Starting IP Protocol Scan on {target_ip} for "
          f"{len(protocols_to_scan)} protocols...")

    try:
        addr = ipaddress.ip_address(target_ip)
        is_ipv6 = addr.version == 6
    except ValueError:
        return {"error": f"Invalid Target IP address format: {target_ip}"}
    except Exception as e:
        return {"error": f"Error validating IP: {str(e)}"}

    for proto_num in protocols_to_scan:
        start_time = time.time()

        # Craft raw IP packet with the specific protocol number
        if is_ipv6:
            packet = IPv6(dst=target_ip, nh=proto_num, hlim=64)
        else:
            packet = IP(dst=target_ip, proto=proto_num, ttl=64)

        # Send and receive
        response = sr1(packet, timeout=timeout, verbose=0)

        latency_ms = (time.time() - start_time) * 1000
        status = "open|filtered"  # Default: can't determine if no response

        if response is None:
            # No response - could be filtered or protocol not supported
            status = "open|filtered"
            latency_ms = None

        elif response.haslayer("ICMPv6 Dest Unreach"):
            icmp_layer = response.getlayer("ICMPv6 Dest Unreach")
            if icmp_layer.code == 1:  # Protocol unreachable
                status = "closed"
            elif icmp_layer.code in [0, 3]:  # No route, unreachable
                status = "filtered"
            else:
                status = "open|filtered"

        elif response.haslayer(ICMP):
            icmp_layer = response.getlayer(ICMP)

            # Type 3 = Destination Unreachable
            if icmp_layer.type == 3:
                # Code 2 = Protocol Unreachable
                # (DEFINITIVE: protocol closed)
                if icmp_layer.code == 2:
                    status = "closed"
                # Codes 0,1,9,10,13 = Network/Host unreachable
                # or filtered
                elif icmp_layer.code in [0, 1, 9, 10, 13]:
                    status = "filtered"
                else:
                    # Other Dest Unreachable codes
                    status = "filtered"

            # Type 0 = Echo Reply
            elif icmp_layer.type == 0:
                # Only mark as open if we were actually testing
                # ICMP (proto 1)
                if proto_num == 1:
                    status = "open"
                else:
                    # Got ICMP reply for non-ICMP protocol
                    # (shouldn't happen normally)
                    status = "open|filtered"

            # Any other ICMP type
            else:
                status = "open|filtered"

        else:
            # Got a non-ICMP response
            # Check if the response protocol matches what we sent
            if hasattr(response, 'proto') and \
                    response.proto == proto_num:
                status = "open"
            elif is_ipv6 and hasattr(response, 'nh') and \
                    response.nh == proto_num:
                status = "open"
            else:
                # Got some response but not matching protocol
                status = "open|filtered"

        results.append({
            "protocol_number": proto_num,
            "protocol_name": IP_PROTOCOL_NAMES.get(
                proto_num, f"Unknown ({proto_num})"),
            "status": status,
            "latency_ms": (
                f"{latency_ms:.2f}"
                if latency_ms is not None else "N/A")
        })

        time.sleep(0.1)

    print("[*] IP Protocol Scan finished.")

    # Ensure we return valid data
    if not results:
        print("[!] Warning: No results collected from scan")
        return {"protocols": []}

    return {"protocols": results}


# Keep for compatibility
ip_protocol_scan = scan
