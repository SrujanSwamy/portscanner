# Implementation of Port Scanning Techniques

This project is a web-based port scanning tool designed for academic use. It allows users to perform network port scans using nine different techniques inspired by Nmap, but implemented from scratch. The application features a Python backend using Scapy for packet crafting and a ReactJS frontend for the user interface.

##  Tech Stack

* *Backend*: Python, Flask, Scapy
* *Frontend*: ReactJS
* *Operating System*: Linux (for raw socket operations)

---

##  Getting Started

Follow these instructions to get the project running on your local machine.

### Prerequisites

* *Linux Environment: This project **must* be run in a Linux environment for raw socket access. If you are on Windows, use the [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/install).
* *Root/Administrator Privileges*: sudo access is required to run the backend server.
* *Python 3.8+* and python3-venv.
* *Node.js v14+* and npm.

---

## Backend Setup (Flask & Scapy)

1.  *Navigate to the Backend Directory*
    Open your terminal and change to the backend directory.
    bash
    cd port-scanner-project/backend
    

2.  *Create and Activate Virtual Environment*
    If you don't have venv installed on your Linux system, run sudo apt install python3-venv.
    bash
    # Create the virtual environment
    python3 -m venv venv

    # Activate it
    source venv/bin/activate
    

3.  *Install Dependencies*
    Install the required Python packages using pip.
    bash
    pip install -r requirements.txt
    

4.  *Run the Backend Server*
    You *must* use sudo to give Scapy the necessary permissions for raw socket operations.
    bash
    sudo python3 app.py
    
    The backend server will start on http://127.0.0.1:5000. Keep this terminal running.

---

## Frontend Setup (ReactJS)

1.  *Open a New Terminal*
    Leave the backend server running and open a second terminal window.

2.  *Navigate to the Frontend Directory*
    bash
    cd port-scanner-project/frontend
    

3.  *Install Dependencies*
    Install the required Node.js packages.
    bash
    npm install
    

4.  *Run the Frontend Application*
    bash
    npm start
    
    This command will automatically open the application in your default web browser at http://localhost:3000.

---

##  Usage

Once both the backend and frontend servers are running, you can use the application through your web browser.
1.  Open http://localhost:3000.
2.  Enter the target IP address and port range you wish to scan.
3.  Select a scan technique from the dropdown menu.
4.  Click "Start Scan" to begin.
5.  Results will be displayed in a table and can be exported to CSV or JSON format.