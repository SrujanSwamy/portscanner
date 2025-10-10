# Port Scanner: Implementation of Port Scanning Techniques

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![React](https://img.shields.io/badge/React-18.x-61DAFB.svg) ![Flask](https://img.shields.io/badge/Flask-2.x-black.svg) ![Scapy](https://img.shields.io/badge/Scapy-2.5-1A2C43.svg)

## Overview

This project is a web-based network port scanner created for educational purposes. It is designed to demonstrate the functionality of various scanning techniques inspired by Nmap, but implemented entirely from scratch using Python (with Scapy and Flask) for the backend and ReactJS for the user interface. 

## Features

* **Nine Scanning Techniques:** Implements TCP Connect, SYN, FIN, Xmas, Null, ACK, Window, UDP, and Idle scans. 
* **Web-Based UI:** An intuitive interface built with ReactJS allows users to easily input target IPs, specify port ranges, and select a scan type.
* **Detailed Results:** Clearly displays the status of each scanned port as open, closed, or filtered. 
* **Data Export:** Allows scan results to be exported in both CSV and JSON formats for further analysis or record-keeping. 

## Tech Stack

* **Backend:** Python 3.x, Flask, Scapy 
* **Frontend:** ReactJS 
* **Platform:** Designed primarily for Linux or WSL (Windows Subsystem for Linux) environments to support the raw socket operations required by Scapy. 

## Folder Structure
port_scanner_project/
├── backend/
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── (all scanner modules ...)
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.css
│   │   └── App.js
│   └── package.json
└── README.md


## 🚀 Setup and Installation

### Prerequisites

* Python 3.x and Pip
* Node.js and npm

### 1. Backend Setup (in a WSL terminal)

```bash
# Navigate to the backend directory
cd port_scanner_project/backend

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

```
2. Frontend Setup (in a separate WSL terminal)
Bash
```bash
# Navigate to the frontend directory
cd port_scanner_project/frontend

# Install dependencies
npm install
```
