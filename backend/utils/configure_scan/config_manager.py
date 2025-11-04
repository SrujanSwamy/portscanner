"""
Scan configuration manager.

Validates incoming scan requests and maps the selected scan type to its
implementation function, returning a normalized configuration object.
"""

from scanners.con_syn_fin.tcp_connect_scan import connect_scan
from scanners.con_syn_fin.tcp_syn_scan import syn_scan
from scanners.con_syn_fin.tcp_fin_scan import fin_scan
from scanners.xmas_null_ack.tcp_xmas_scan import xmas_scan
from scanners.xmas_null_ack.tcp_null_scan import null_scan
from scanners.xmas_null_ack.tcp_ack_scan import ack_scan
from scanners.win_idle_udp.tcp_window_scan import window_scan
from scanners.win_idle_udp.udp_scan import udp_scan
from scanners.win_idle_udp.idle_scan import idle_scan
from scanners.host_discovery.ip_protocol_scan import (
    scan as ip_protocol_scan)
from scanners.host_discovery.os_fingerprint_scan import (
    scan as os_detection_scan)

from utils.input_validation.validators import (
    parse_ports, validate_ip_address)
"""
Scan configuration manager.

Validates incoming scan requests and maps the selected scan type to its
implementation function, returning a normalized configuration object.
"""

def configure_scan(request_data):
    """
    Validate request data and produce a scan configuration.

    Args:
        request_data (dict): Incoming request with keys: target_ip (str),
            scan_type (str), ports (str, optional), zombie_ip (str, optional).

    Returns:
        dict: {target_ip, ports_to_scan, selected_scanner, scan_type, zombie_ip}.

    Raises:
        ValueError: If inputs are missing or invalid.
    """
    target_ip = request_data.get('target_ip')
    port_string = request_data.get('ports')
    scan_type = request_data.get('scan_type')
    zombie_ip = request_data.get('zombie_ip')

    if not target_ip or not scan_type:
        raise ValueError("Missing required fields: target_ip, scan_type")
    
    if not validate_ip_address(target_ip):
        raise ValueError(
            "Invalid target IP address format (must be IPv4 or IPv6)")

    ports_to_scan = []
    if scan_type not in ["IP Protocol Scan", "OS-Detection"]:
        if not port_string:
            raise ValueError(f"port(s) are required for {scan_type}")
        ports_to_scan = parse_ports(port_string)
        if not ports_to_scan:
            raise ValueError("No valid ports specified")

    # Map scan type to implementation
    scan_functions = {
        "TCP Connect": connect_scan,
        "TCP SYN": syn_scan,
        "TCP FIN": fin_scan,
        "TCP Xmas": xmas_scan,
        "TCP Null": null_scan,
        "TCP ACK": ack_scan,
        "TCP Window": window_scan,
        "UDP": udp_scan,
        "Idle": idle_scan,
        "OS-Detection": os_detection_scan,
        "IP Protocol Scan": ip_protocol_scan
    }

    selected_scanner = scan_functions.get(scan_type)

    if not selected_scanner:
        raise ValueError("Invalid scan type")

    if scan_type == "Idle" and not zombie_ip:
        raise ValueError("Zombie IP is required for Idle Scan")

    return {
        'target_ip': target_ip,
        'ports_to_scan': ports_to_scan,
        'selected_scanner': selected_scanner,
        'scan_type': scan_type,
        'zombie_ip': zombie_ip
    }
