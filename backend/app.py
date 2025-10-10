from flask import Flask, request, jsonify
from flask_cors import CORS
import re

# Import all scanner functions from the scanners package
# This follows the "Scan Manager" design from the structure chart
from scanners.tcp_connect_scan import connect_scan
from scanners.tcp_syn_scan import syn_scan
from scanners.tcp_fin_scan import fin_scan
from scanners.tcp_xmas_scan import xmas_scan
from scanners.tcp_null_scan import null_scan
from scanners.tcp_ack_scan import ack_scan
from scanners.tcp_window_scan import window_scan
from scanners.udp_scan import udp_scan
from scanners.idle_scan import idle_scan

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

def parse_ports(port_string):
    """
    Parses a port string (e.g., "22, 80, 443", "1-1024") into a list of integers.
    This is part of the "Validate Input" process (DFD 0.1).
    """
    ports = set()
    if not port_string:
        return []
    
    # Split by comma for individual ports or ranges
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Handle ranges
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            # Handle single ports
            try:
                port = int(part)
                if 0 < port <= 65535:
                    ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")
    
    return sorted(list(ports))


@app.route('/scan', methods=['POST'])
def scan():
    """
    Main API endpoint to handle scan requests.
    """
    data = request.json
    target_ip = data.get('target_ip')
    port_string = data.get('ports')
    scan_type = data.get('scan_type')
    zombie_ip = data.get('zombie_ip') # For Idle Scan

    # --- Input Validation (DFD 0.1) ---
    if not all([target_ip, port_string, scan_type]):
        return jsonify({"error": "Missing required fields: target_ip, ports, scan_type"}), 400
    
    # Basic IP validation
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
         return jsonify({"error": "Invalid target IP address format"}), 400

    try:
        ports_to_scan = parse_ports(port_string)
        if not ports_to_scan:
            return jsonify({"error": "No valid ports specified"}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    # --- Scan Configuration & Execution (DFD 0.2 & 0.3) ---
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
        return jsonify({"error": "Invalid scan type"}), 400
        
    if scan_type == "Idle" and not zombie_ip:
        return jsonify({"error": "Zombie IP is required for Idle Scan"}), 400

    results = []
    for port in ports_to_scan:
        if scan_type == "Idle":
            result = selected_scanner(target_ip, port, zombie_ip)
        else:
            result = selected_scanner(target_ip, port)
        results.append(result)

    # --- Process and Display Results (DFD 0.4 & 0.5) ---
    return jsonify(results)

if __name__ == '__main__':
    # The application must be run with sudo for Scapy's raw socket operations
    # Port 5000 is the default for Flask
    print("Starting Flask server on http://127.0.0.1:5000")
    print("IMPORTANT: This server must be run with 'sudo' for scans requiring raw sockets.")
    app.run(host='0.0.0.0', port=5000)