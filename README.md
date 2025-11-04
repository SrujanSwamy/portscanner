# Advanced Network Port Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![React](https://img.shields.io/badge/React-19.2-61DAFB.svg) ![Flask](https://img.shields.io/badge/Flask-2.2.2-black.svg) ![Scapy](https://img.shields.io/badge/Scapy-2.5.0-1A2C43.svg) ![JWT](https://img.shields.io/badge/JWT-Auth-green.svg)

## Overview

A comprehensive, production-ready web-based network port scanner with enterprise-grade authentication. Built for educational and professional network security analysis, this application implements 12 distinct scanning techniques inspired by Nmap, entirely from scratch using Python (Scapy + Flask) and modern React.

**Key Highlights:**
- **Secure Authentication:** JWT-based auth with email verification (OTP)
- **11 Scan Types:** Complete suite of TCP, UDP, and host discovery scans
- **Modern Architecture:** RESTful API backend + responsive React frontend
- **Rich Results:** Detailed port status, latency metrics, and export capabilities
- **Advanced Features:** OS fingerprinting, IP protocol detection, idle scanning

---

## Features

### Authentication & Security
- **User Registration** with email-based OTP verification (10-minute expiry)
- **JWT Authentication** with 24-hour token validity
- **Protected Routes** requiring authentication for all scan operations
- **Password Hashing** using bcrypt for secure credential storage
- **SQLite Database** for persistent user management

### Scanning Capabilities

#### Port Scanning (9 Techniques)
1. **TCP Connect Scan** - Full three-way handshake
2. **TCP SYN Scan** - Half-open stealth scan
3. **TCP FIN Scan** - Stealth scan using FIN packets
4. **TCP XMAS Scan** - FIN/PSH/URG flags set ("Christmas tree")
5. **TCP NULL Scan** - No flags set
6. **TCP ACK Scan** - Firewall rule mapping
7. **TCP Window Scan** - Window size analysis
8. **UDP Scan** - UDP port discovery with ICMP analysis
9. **Idle Scan** - Indirect zombie-based stealth scanning

#### Host Discovery (2 Techniques)
10. **IP Protocol Scan** - Identifies supported protocols (ICMP, TCP, UDP, etc.)
11. **OS Fingerprinting** - TTL and DF bit analysis for OS detection

#### Special Features
12. **IPv6 Support** - All scans support both IPv4 and IPv6
- **Port Range Parsing** - Individual ports, ranges, or comma-separated lists
- **Real-time Results** - Instant feedback with latency measurements
- **Export Options** - CSV and JSON formats with metadata

### User Experience
- **Intuitive Dashboard** - Clean, professional interface
- **Responsive Design** - Works seamlessly on desktop and mobile
- **Result Visualization** - Color-coded status indicators (Open, Closed, Filtered)
- **Session Management** - Last login tracking and secure logout
- **Error Handling** - Comprehensive validation and user-friendly messages

---

## Tech Stack

### Backend
- **Python 3.x** - Core language
- **Flask 2.2.2** - Lightweight web framework
- **Scapy 2.5.0** - Packet manipulation and network scanning
- **Flask-CORS 3.0.10** - Cross-Origin Resource Sharing
- **bcrypt 5.0.0** - Password hashing
- **PyJWT 2.8.0** - JSON Web Token authentication
- **SQLite** - Embedded database for user storage

### Frontend
- **React 19.2.0** - UI framework
- **Vite 6.4.0** - Modern build tool
- **React Router DOM 6.30.1** - Client-side routing
- **Axios 1.12.2** - HTTP client for API requests
- **PropTypes 15.8.1** - Runtime type checking
- **ESLint** - Code quality and style enforcement (Airbnb config)

### Development
- **WSL/Linux** - Required for raw socket operations
- **Node.js & npm** - Frontend package management
- **Git** - Version control

---

## Project Structure

```
port_working-latest/
├── backend/
│   ├── app.py                      # Main Flask application
│   ├── auth.py                     # Authentication routes (register, login, verify OTP)
│   ├── models.py                   # Database models and operations
│   ├── config.py                   # Configuration (secrets, SMTP settings)
│   ├── requirements.txt            # Python dependencies
│   ├── port_scanner.db             # SQLite database (auto-created)
│   ├── utils/
│   │   ├── auth_utils.py           # JWT decorator and OTP email sender
│   │   ├── configure_scan/
│   │   │   └── config_manager.py   # Scan configuration and validation
│   │   └── input_validation/
│   │       └── validators.py       # IP and port validation
│   └── scanners/
│       ├── con_syn_fin/
│       │   ├── tcp_connect_scan.py # Full TCP handshake
│       │   ├── tcp_syn_scan.py     # Half-open SYN scan
│       │   └── tcp_fin_scan.py     # Stealth FIN scan
│       ├── xmas_null_ack/
│       │   ├── tcp_xmas_scan.py    # XMAS tree scan
│       │   ├── tcp_null_scan.py    # NULL flag scan
│       │   └── tcp_ack_scan.py     # ACK scan for firewall detection
│       ├── win_idle_udp/
│       │   ├── tcp_window_scan.py  # Window size scan
│       │   ├── udp_scan.py         # UDP port scan
│       │   └── idle_scan.py        # Zombie-based idle scan
│       └── host_discovery/
│           ├── ip_protocol_scan.py # Protocol identification
│           └── os_fingerprint_scan.py # OS detection
│
└── frontend/
    ├── public/
    │   ├── index.html
    │   ├── manifest.json
    │   └── robots.txt
    ├── src/
    │   ├── main.jsx                # Entry point (Vite)
    │   ├── App.jsx                 # Root component with routing
    │   ├── App.css                 # Global styles
    │   ├── components/
    │   │   ├── HomePage.jsx        # Landing page
    │   │   ├── RegisterPage.jsx    # User registration
    │   │   ├── VerifyOTPPage.jsx   # OTP verification
    │   │   ├── LoginPage.jsx       # User login
    │   │   ├── ScanPage.jsx        # Main scanning interface
    │   │   ├── IPProtocolResult.jsx # Protocol scan results
    │   │   ├── OSResult.jsx        # OS detection results
    │   │   ├── Navbar.jsx          # Navigation bar
    │   │   └── ProtectedRoute.jsx  # Auth guard component
    │   ├── context/
    │   │   └── AuthContext.jsx     # Global auth state
    │   ├── services/
    │   │   └── authService.js      # API calls for authentication
    │   └── utils/
    │       └── export_results/
    │           └── export.js       # CSV/JSON export functions
    ├── package.json
    ├── vite.config.js
    └── .eslintrc.json
```

---

## Setup and Installation

### Prerequisites

- **Python 3.x** and pip
- **Node.js** (v16+) and npm
- **WSL** (Windows Subsystem for Linux) or native **Linux** environment
- **Email account** for SMTP (Gmail recommended with app password)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd port_working-latest
```

### 2. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows WSL: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure SMTP settings (edit config.py)
# - Update EMAIL_ADDRESS with your email
# - Update EMAIL_PASSWORD with your app password (Gmail: generate from account settings)
# - Update SECRET_KEY with a secure random key (generate: python -c "import secrets; print(secrets.token_hex(32))")

# Initialize database (auto-created on first run)
# Database will be created automatically when you start the server
```

### 3. Frontend Setup

```bash
# Open a new terminal, navigate to frontend directory
cd ../frontend

# Install dependencies
npm install

# Verify Vite configuration (vite.config.js should proxy API requests to backend)
```

### 4. Running the Application

#### Start Backend Server (Terminal 1)
```bash
cd backend
source venv/bin/activate

# Run with elevated privileges (required for raw sockets)
sudo $(which python3) app.py

# Server will start on http://[::]:5000
# API accessible at http://localhost:5000/api
```

#### Start Frontend Dev Server (Terminal 2)
```bash
cd frontend

# Start Vite development server
npm run dev

# Frontend will start on http://localhost:3000
# Open in browser: http://localhost:3000
```

---

## Usage Guide

### 1. User Registration
1. Navigate to **Register** page
2. Enter email and password (minimum 6 characters)
3. Submit form → 6-digit OTP sent to email (valid for 10 minutes)
4. Check email inbox (including spam/junk folders)

### 2. Email Verification
1. Enter 6-digit OTP received via email
2. Click **Verify** → account activated

### 3. Login
1. Navigate to **Login** page
2. Enter verified email and password
3. Successful login → JWT token stored (valid 24 hours)
4. View last login timestamp in navbar

### 4. Performing Scans
1. Navigate to **Scan** page (protected route)
2. Enter **Target IP** (IPv4 or IPv6)
3. Specify **Ports** (e.g., `80`, `1-1000`, `22,80,443`)
4. Select **Scan Type** from dropdown (12 options)
5. For **Idle Scan**: Provide zombie host IP
6. Click **Start Scan** → results display in real-time

### 5. Viewing Results
- **Port Scans:** Table with Port, Status, Latency
- **IP Protocol Scan:** List of supported protocols
- **OS Detection:** Best guess OS with TTL analysis
- Indicators:
  - **Open** - Port accepts connections
  - **Closed** - Port actively refuses connections
  - **Filtered** - No response (firewall/filter)
  - **Open|Filtered** - Cannot determine definitively

### 6. Exporting Results
- Click **Export to CSV** → download spreadsheet format
- Click **Export to JSON** → download with metadata (timestamps, counts)
- Files named: `scan_results_<IP>_<timestamp>.<ext>`

---

## Security Considerations

**IMPORTANT:** This tool is for **educational and authorized testing only**.

### Legal & Ethical Usage
- **Authorized Testing:** Only scan networks/systems you own or have explicit permission to test
- **Educational Purpose:** Learn network security concepts in controlled environments
- **Unauthorized Scanning:** Illegal in most jurisdictions; can result in criminal charges
- **Malicious Intent:** Never use for hacking, intrusion, or denial-of-service attacks

### Best Practices
1. **Environment Variables:** Move secrets from `config.py` to environment variables in production
2. **HTTPS:** Use SSL/TLS certificates for production deployment
3. **Rate Limiting:** Implement API rate limiting to prevent abuse
4. **Input Sanitization:** All inputs are validated, but review regularly
5. **Logging:** Monitor scan activity and failed authentication attempts
6. **Regular Updates:** Keep dependencies updated for security patches

### Known Limitations
- **Sudo Required:** Backend needs elevated privileges for raw socket operations
- **Firewall Detection:** Some scan types may be blocked by modern firewalls
- **IPv6 Idle Scan:** Less reliable due to lack of predictable IP ID field
- **Performance:** Sequential scanning (no threading) for educational clarity

---
