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

First, install the required Python libraries:

# Requirements

Python 3.7+
Modules: argparse, socket, subprocess, requests, dnspython, python-whois
External tool: whatweb

# Example Workflow
# run the script:
bash
python main.py --domain example.com --whois --dns --subdomains --ports --banner --tech --verbose


📁 Output:

Saved logs in logs/tool.log

HTML report in reports/recon_report_example.com_<timestamp>.html

