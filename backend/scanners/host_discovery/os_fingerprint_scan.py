"""
OS Fingerprinting Module

Performs operating system detection using TTL analysis, DF bit inspection,
and TCP window size fingerprinting to identify target OS.
"""

from scapy.all import sr1, IP, ICMP, TCP
import logging
import ipaddress

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def scan(target_ip, ports_ignored, timeout=2):  # noqa: E501
    """
    Performs OS detection using TTL and DF bit analysis.

    Analyzes ICMP Echo Reply TTL values and DF (Don't Fragment) bit to
    identify operating system. Uses TCP fingerprinting for enhanced accuracy.

    Args:
        target_ip (str): Target IP address
        ports_ignored: Unused parameter (kept for interface compatibility)
        timeout (int|float): Response timeout in seconds

    Returns:
        dict: OS guess and analysis details
    """
    try:
        ipaddress.ip_address(target_ip)

        packet = IP(dst=target_ip, ttl=64) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            return {
                "os_guess": "Unknown / No Response",
                "detail": ("Host is down or not responding to ICMP "
                           "Echo Requests.")
            }

        if not response.haslayer(IP):
            return {
                "os_guess": "Unknown / Unexpected Response",
                "detail": "Received a non-IP response."
            }

        received_ttl = response.ttl
        df_bit_set = (response.flags == 'DF')

        os_guess = "Unknown"
        detail = f"Received TTL={received_ttl}."

        # TTL-based OS detection with DF bit analysis
        if received_ttl > 128:
            # TTL likely started at 255
            os_guess = "Solaris / Cisco / Network Device"
            detail += " TTL likely started at 255."

        elif received_ttl > 64:
            # TTL likely started at 128 (Windows default)
            os_guess = "Windows"
            detail += " TTL likely started at 128."
            detail += f" DF bit is {'SET' if df_bit_set else 'NOT SET'}."

        elif received_ttl > 32:
            # TTL likely started at 64 (Linux/Unix/macOS default)
            detail += " TTL likely started at 64."

            # Use TCP fingerprinting for better Linux/macOS distinction
            tcp_os = _tcp_fingerprint(target_ip, timeout)

            if tcp_os:
                os_guess = tcp_os
                detail += (
                    " DF bit is "
                    f"{'SET' if df_bit_set else 'NOT SET'}. "
                    "Enhanced detection via TCP fingerprinting.")
            elif df_bit_set:
                os_guess = "Linux"
                detail += " DF bit is SET (typical for Linux)."
            else:
                os_guess = "Linux / macOS / Unix"
                detail += (
                    " DF bit is NOT SET. Could be macOS, BSD, "
                    "or Linux with specific network config.")

        elif received_ttl > 0:
            os_guess = "Possible older System / Many Hops"
            detail += " TTL likely started very low or is many hops away."

        else:
            os_guess = "Unknown / TTL Expired"
            detail += " Received TTL is zero or negative."

        return {
            "os_guess": os_guess,
            "detail": detail
        }

    except PermissionError:
        return {
            "os_guess": "Error",
            "detail": ("Permission denied. ICMP scans require "
                       "root/sudo privileges.")
        }
    except ValueError:
        return {
            "os_guess": "Error",
            "detail": f"Invalid Target IP address format: {target_ip}"
        }
    except Exception as e:
        return {
            "os_guess": "Error",
            "detail": f"An unexpected error occurred: {str(e)}"
        }


def _tcp_fingerprint(target_ip, timeout=2):
    """
    Attempts TCP fingerprinting to distinguish OS based on window size.

    Args:
        target_ip (str): Target IP address
        timeout (int|float): Response timeout in seconds

    Returns:
        str|None: OS guess based on TCP window size, or None if unable to determine
    """
    try:
        # Try common ports
        for port in [80, 443, 22]:
            tcp_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            tcp_response = sr1(tcp_packet, timeout=timeout, verbose=0)

            if tcp_response and tcp_response.haslayer(TCP):
                window_size = tcp_response[TCP].window
                tcp_ttl = tcp_response[IP].ttl

                # Distinguish OS by TCP window size patterns
                if window_size == 65535:
                    return "macOS"
                elif window_size in [5840, 14600, 29200, 5720]:
                    return "Linux"

                break

        return None
    except Exception:
        return None


os_detection_scan = scan
