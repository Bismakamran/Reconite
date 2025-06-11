import argparse
import socket
import subprocess
import requests
import dns.resolver
import whois
from datetime import datetime
import logging
import os

# Setup logging: file + console, level based on verbose flag
def setup_logging(verbose=False):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "tool.log")

    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Logging started. Level: {'DEBUG' if verbose else 'INFO'}")

# WHOIS lookup
def run_whois(domain):
    try:
        w = whois.whois(domain)
        logging.debug(f"WHOIS data retrieved for {domain}")
        return str(w)
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        return f"WHOIS lookup failed: {e}"

# DNS Enumeration
def get_records(domain):
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
            logging.debug(f"DNS {record_type} records found for {domain}: {records[record_type]}")
        except Exception as e:
            records[record_type] = []
            logging.warning(f"No DNS {record_type} records for {domain} or error: {e}")
    return records

# Subdomain Enumeration via crt.sh
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        for item in data:
            sub = item['name_value']
            if domain in sub:
                subdomains.update(sub.split('\n'))
        logging.debug(f"Subdomains found for {domain}: {len(subdomains)}")
    except Exception as e:
        logging.error(f"Subdomain enumeration failed for {domain}: {e}")
        return [f"Subdomain enumeration failed: {e}"]
    return sorted(subdomains)

# Port scanning common ports
def scan_basic_ports(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        logging.debug(f"IP for {domain} resolved to {ip}")
    except Exception as e:
        logging.error(f"Failed to resolve IP for {domain}: {e}")
        return [f"Failed to resolve IP: {e}"]

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    logging.info(f"Port {port} is open on {domain}")
        except Exception as e:
            logging.warning(f"Port scan error on port {port} for {domain}: {e}")

    return open_ports

# Banner grabbing from open ports
def grab_banner(domain, ports):
    banners = {}
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        logging.error(f"Failed to resolve IP for banner grabbing on {domain}: {e}")
        return {"error": f"Failed to resolve IP: {e}"}

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                # Send HTTP HEAD request to get banner for HTTP ports
                if port in [80, 8080, 443]:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors='ignore').strip()
                banners[port] = banner if banner else "No banner"
                logging.debug(f"Banner on port {port} for {domain}: {banner[:50]}")
        except Exception as e:
            banners[port] = "No banner or connection failed"
            logging.warning(f"Banner grab failed on port {port} for {domain}: {e}")

    return banners

# Technology detection using WhatWeb (must be installed on system)
def detect_tech(domain):
    try:
        result = subprocess.check_output(["whatweb", domain], stderr=subprocess.DEVNULL, timeout=10)
        decoded = result.decode()
        logging.debug(f"WhatWeb detection output for {domain}: {decoded[:100]}")
        return decoded
    except Exception as e:
        logging.error(f"Tech detection failed or WhatWeb not installed: {e}")
        return f"Tech detection failed or WhatWeb not installed: {e}"

# Save HTML report with styling
def save_html_report(data, domain):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/recon_report_{domain}_{timestamp}.html"
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recon Report for {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 30px; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        pre {{ background: #eee; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <h1>Recon Report for {domain}</h1>
    <p><strong>Generated:</strong> {timestamp}</p>
"""
    for section, content in data.items():
        html_content += f'<div class="section"><h2>{section}</h2>'
        if isinstance(content, (dict, list)):
            html_content += f"<pre>{str(content)}</pre>"
        else:
            html_content += f"<pre>{content}</pre>"
        html_content += "</div>"
    html_content += "</body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    logging.info(f"Report saved to {filename}")
    return filename

def main():
    parser = argparse.ArgumentParser(description="Custom Recon Tool")
    parser.add_argument("--domain", help="Target domain", required=True)
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains")
    parser.add_argument("--ports", action="store_true", help="Scan common ports")
    parser.add_argument("--banner", action="store_true", help="Grab banners from open ports")
    parser.add_argument("--tech", action="store_true", help="Detect web technologies")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug output")
    args = parser.parse_args()

    # Setup logging based on verbosity
    setup_logging(args.verbose)
    logging.info(f"Starting recon on domain: {args.domain}")

    data = {}
    domain = args.domain

    if args.whois:
        logging.info("Performing WHOIS lookup...")
        data["Whois"] = run_whois(domain)

    if args.dns:
        logging.info("Performing DNS enumeration...")
        data["DNS"] = get_records(domain)

    if args.subdomains:
        logging.info("Enumerating subdomains...")
        data["Subdomains"] = get_subdomains(domain)

    if args.ports:
        logging.info("Scanning common ports...")
        open_ports = scan_basic_ports(domain)
        data["Open Ports"] = open_ports

        # Only grab banners if ports found and banner flag is set
        if args.banner and open_ports:
            logging.info("Grabbing banners from open ports...")
            data["Banners"] = grab_banner(domain, open_ports)

    if args.tech:
        logging.info("Detecting web technologies...")
        data["Technologies"] = detect_tech(domain)

    report_path = save_html_report(data, domain)
    print(f"\n✅ Recon complete. Report saved at: {report_path}")

if __name__ == "__main__":
    main()
