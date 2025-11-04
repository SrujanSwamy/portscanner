"""Flask API for authentication and network scanning.

Exposes JWT-protected endpoints for initiating host- and port-level scans.
Validates requests, selects the appropriate scanner, and returns JSON results.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS

# Assuming these imports are correct for your auth structure
import models
from config import SECRET_KEY
from auth import auth_bp
from utils.auth_utils import token_required

# Import scan configurations
from utils.configure_scan.config_manager import configure_scan

app = Flask(__name__)

# Apply secret key
app.config['SECRET_KEY'] = SECRET_KEY

# Enable CORS (Ensure origin matches your frontend, e.g., localhost:3000)
CORS(app, resources={
    r"/api/*": {
        "origins": "http://localhost:3000",
        "supports_credentials": True
    }
})

# Register auth blueprint
app.register_blueprint(auth_bp, url_prefix='/api')

# List scan types that operate on the host itself, not per-port
HOST_SCANS = {"IP Protocol Scan", "OS-Detection"}

@app.route('/api/scan', methods=['POST'])
@token_required
def scan():  # Assuming token_required provides current_user
    """
    Handle POST requests for initiating a scan. Requires JWT token.
    """
   
    try:
        scan_config = configure_scan(request.json)
    except ValueError as e:
        # Configuration or validation error
        print(f"\n[ERROR] Scan configuration failed: {e}\n")
        return jsonify({"error": str(e)}), 400
    except PermissionError as e:
        # sudo issue during config (less common)
        print("\n[ERROR] Permission denied during configuration. "
              "Ensure backend runs with sudo/root.\n")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        # Catch unexpected config errors
        app.logger.error(
            f"Unexpected error during scan configuration: {e}",
            exc_info=True)
        return jsonify({
            'error': f'An unexpected error occurred during '
                     f'configuration: {e}'
        }), 500

    # Extract validated config
    target_ip = scan_config['target_ip']
    ports_to_scan = scan_config['ports_to_scan']
    selected_scanner = scan_config['selected_scanner']
    scan_type = scan_config['scan_type']

    try:
        if scan_type in HOST_SCANS:
            print(f"Executing HOST scan: {scan_type} for "
                  f"target {target_ip}")
            # Call the scanner function ONCE.
            # Pass target_ip. The scanner function ignores the second
            # arg if not needed.
            result = selected_scanner(target_ip, ports_to_scan)
            # Return the single result object directly
            # (e.g., {'protocols': [...]} or {'error': ...})
            return jsonify(result)
        else:
            results = []
            for port in ports_to_scan:
                if scan_type == "Idle":
                    zombie_ip = scan_config.get('zombie_ip')
                    if not zombie_ip:
                        return jsonify({
                            "error": "Zombie IP missing for Idle Scan "
                                     "execution."
                        }), 400
                    result = selected_scanner(target_ip, port, zombie_ip)
                else:
                    # Pass only target_ip and port for standard
                    # port scanners
                    result = selected_scanner(target_ip, port)

                # Append result, handling potential errors from
                # individual scans
                if isinstance(result, dict) and 'error' in result:
                    results.append({
                        "port": port,
                        "status": "Error",
                        "detail": result['error']
                    })
                elif isinstance(result, dict):
                    results.append(result)
                else:  # Handle unexpected return type from scanner
                    results.append({
                        "port": port,
                        "status": "Error",
                        "detail": "Scanner returned unexpected data type"
                    })
            # Return array of port results
            return jsonify(results)

    except PermissionError as e:
        # Catch permission errors during scan execution
        # (e.g., raw socket access)
        print("\n[ERROR] Permission denied during scan execution. "
              "Ensure backend runs with sudo/root.\n")
        return jsonify({
            'error': f'Permission denied during scan: {str(e)}'
        }), 500
    except Exception as e:
        # Catch other unexpected execution errors
        app.logger.error(
            f"Scan execution failed for {scan_type} on {target_ip}: {e}",
            exc_info=True)
        return jsonify({
            "error": f"Scan failed during execution: {str(e)}"
        }), 500


if __name__ == '__main__':
    # Initialize DB (if needed for auth)
    try:
        models.init_db()
        models.delete_unverified_users()

    except Exception as e:
        print(f"Warning: Database initialization failed: {e}. "
              "Auth features may not work.")

    print("Starting Flask server on http://127.0.0.1:5000")
    print("API accessible at http://<your-ip>:5000/api")
    print("IMPORTANT: This server must be run with 'sudo' for scans "
          "requiring raw sockets.")

    # Listen on IPv6 any-address ('::'); often enables dual-stack access
    app.run(host='::', port=5000, debug=False)
