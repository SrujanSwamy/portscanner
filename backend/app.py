from flask import Flask, request, jsonify
from flask_cors import CORS

# Import the new config manager
from utils.config_manager import configure_scan

app = Flask(__name__)
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    try:
        # All configuration is now done in one step
        scan_config = configure_scan(request.json)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    results = []
    
    # Use the prepared config object
    target_ip = scan_config['target_ip']
    ports_to_scan = scan_config['ports_to_scan']
    selected_scanner = scan_config['selected_scanner']
    
    # The execution loop remains the same, but it's now much cleaner
    for port in ports_to_scan:
        if scan_config['scan_type'] == "Idle":
            zombie_ip = scan_config['zombie_ip']
            result = selected_scanner(target_ip, port, zombie_ip)
        else:
            result = selected_scanner(target_ip, port)
        results.append(result)

    return jsonify(results)

if __name__ == '_main_':
    print("Starting Flask server on http://127.0.0.1:5000")
    print("IMPORTANT: This server must be run with 'sudo' for scans requiring raw sockets.")
    app.run(host='0.0.0.0', port=5000)