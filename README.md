# Port Scanner: Implementation of Port Scanning Techniques

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![React](https://img.shields.io/badge/React-18.x-61DAFB.svg) ![Flask](https://img.shields.io/badge/Flask-2.x-black.svg) ![Scapy](https://img.shields.io/badge/Scapy-2.5-1A2C43.svg)

## 📖 Overview

[cite_start]This project is a web-based network port scanner created for educational purposes. [cite: 618] [cite_start]It is designed to demonstrate the functionality of various scanning techniques inspired by Nmap, but implemented entirely from scratch using Python (with Scapy and Flask) for the backend and ReactJS for the user interface. [cite: 574, 615]

## ✨ Features

* [cite_start]**Nine Scanning Techniques:** Implements TCP Connect, SYN, FIN, Xmas, Null, ACK, Window, UDP, and Idle scans. [cite: 577]
* [cite_start]**Web-Based UI:** An intuitive interface built with ReactJS allows users to easily input target IPs, specify port ranges, and select a scan type. [cite: 633]
* [cite_start]**Detailed Results:** Clearly displays the status of each scanned port as open, closed, or filtered. [cite: 659]
* [cite_start]**Data Export:** Allows scan results to be exported in both CSV and JSON formats for further analysis or record-keeping. [cite: 635, 699]

## 🛠️ Tech Stack

* [cite_start]**Backend:** Python 3.x, Flask, Scapy [cite: 615, 640]
* [cite_start]**Frontend:** ReactJS [cite: 615, 641]
* [cite_start]**Platform:** Designed primarily for Linux or WSL (Windows Subsystem for Linux) environments to support the raw socket operations required by Scapy. [cite: 642, 713]

## 📂 Folder Structure
