<<<<<<< Updated upstream
from scanners.con_syn_fin.tcp_connect_scan import connect_scan
from scanners.con_syn_fin.tcp_syn_scan import syn_scan
from scanners.con_syn_fin.tcp_fin_scan import fin_scan
from scanners.xmas_null_ack.tcp_xmas_scan import xmas_scan
from scanners.xmas_null_ack.tcp_null_scan import null_scan
from scanners.xmas_null_ack.tcp_ack_scan import ack_scan
from scanners.win_idle_udp.tcp_window_scan import window_scan
from scanners.win_idle_udp.udp_scan import udp_scan
from scanners.win_idle_udp.idle_scan import idle_scan

# Import validators to use them here
from utils.input_validation.validators import parse_ports, validate_ip_address

def configure_scan(request_data):
    """
    Validates request data and configures the scan.
    Returns a dictionary with the target_ip, ports_to_scan, and the selected scanner function.
    Raises ValueError on invalid input.
    """
    target_ip = request_data.get('target_ip')
    port_string = request_data.get('ports')
    scan_type = request_data.get('scan_type')
    zombie_ip = request_data.get('zombie_ip')

    #  Validate Inputs 
    if not all([target_ip, port_string, scan_type]):
        raise ValueError("Missing required fields: target_ip, ports, scan_type")
    
    if not validate_ip_address(target_ip):
        raise ValueError("Invalid target IP address format (must be IPv4 or IPv6)")

    ports_to_scan = parse_ports(port_string)
    if not ports_to_scan:
        raise ValueError("No valid ports specified")

    scan_functions = {
        "TCP Connect": connect_scan,
        "TCP SYN": syn_scan,
        "TCP FIN": fin_scan,
        "TCP Xmas": xmas_scan,
        "TCP Null": null_scan,
        "TCP ACK": ack_scan,
        "TCP Window": window_scan,
        "UDP": udp_scan,
        "Idle": idle_scan
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
=======
from scanners.con_syn_fin.tcp_connect_scan import connect_scan
from scanners.con_syn_fin.tcp_syn_scan import syn_scan
from scanners.con_syn_fin.tcp_fin_scan import fin_scan
from scanners.xmas_null_ack.tcp_xmas_scan import xmas_scan
from scanners.xmas_null_ack.tcp_null_scan import null_scan
from scanners.xmas_null_ack.tcp_ack_scan import ack_scan
from scanners.win_idle_udp.tcp_window_scan import window_scan
from scanners.win_idle_udp.udp_scan import udp_scan
from scanners.win_idle_udp.idle_scan import idle_scan

# Import validators to use them here
from utils.input_validation.validators import parse_ports, validate_ip_address

def configure_scan(request_data):
    """
    Validates request data and configures the scan.
    Returns a dictionary with the target_ip, ports_to_scan, and the selected scanner function.
    Raises ValueError on invalid input.
    """
    target_ip = request_data.get('target_ip')
    port_string = request_data.get('ports')
    scan_type = request_data.get('scan_type')
    zombie_ip = request_data.get('zombie_ip')

    # Validate Inputs
    if not all([target_ip, port_string, scan_type]):
        raise ValueError("Missing required fields: target_ip, ports, scan_type")
    
    if not validate_ip_address(target_ip):
        raise ValueError("Invalid target IP address format (must be IPv4 or IPv6)")

    ports_to_scan = parse_ports(port_string)
    if not ports_to_scan:
        raise ValueError("No valid ports specified")

    # Select Scanner 
    scan_functions = {
        "TCP Connect": connect_scan,
        "TCP SYN": syn_scan,
        "TCP FIN": fin_scan,
        "TCP Xmas": xmas_scan,
        "TCP Null": null_scan,
        "TCP ACK": ack_scan,
        "TCP Window": window_scan,
        "UDP": udp_scan,
        "Idle": idle_scan
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
>>>>>>> Stashed changes
    }