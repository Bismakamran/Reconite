# Reconite  The Modular Reconnaissance & Intelligence Gathering Tool
custom-reconnaissance-tool

**Reconite** is a powerful, modular reconnaissance tool for ethical hackers, bug bounty hunters, and cybersecurity professionals. It combines multiple techniques — from WHOIS lookups to subdomain discovery, port scanning, and tech detection — into one streamlined Python-based utility.

---

## 🚀 Features

- 🌐 **WHOIS Lookup** – Get registrar, creation dates, and owner info.
- 🧠 **DNS Enumeration** – Discover A, MX, TXT, and NS records.
- 🕵️ **Subdomain Enumeration** – Harvest subdomains via crt.sh.
- 📡 **Port Scanning** – Scan common TCP ports.
- 🎯 **Banner Grabbing** – Extract service banners from open ports.
- 🧪 **Technology Detection** – Identify web tech stacks via WhatWeb.
- 🧾 **HTML Reporting** – Generates styled HTML reports with results.
- 🪵 **Logging** – Verbose or quiet logging to file and console.

---

## ⚙️ Installation


Installation
1. Clone the repository
git clone https://github.com/Bismakamran/Reconite.git

2. Set up a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

3. libraries to install 
Python 3.7+
Modules: argparse, socket, subprocess, requests, dnspython, python-whois
External tool: whatweb

# 🚀 Usage
python main.py
You'll be prompted to enter a domain (e.g., example.com). The tool will then display:

# DNS records
Service banners on common ports (21, 22, 80, 443, 8080)
Technologies detected on the website
# 📂 Modules
main.py: Entry point to the program
dns_enum.py: Handles DNS lookups
banner_grabber.py: Grabs banners from services
tech_detect.py: Uses Wappalyzer to identify technologies


📜 License
This project is licensed under the MIT License. Feel free to modify and use it for educational or ethical penetration testing purposes.

