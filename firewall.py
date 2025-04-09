import os
import subprocess
import threading
import logging
import signal
import sys
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

# 🔹 Logging Setup
LOG_FILE = "/var/log/hybrid_firewall.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)

# 🔹 Load Blocklists
def load_blocklist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"[ERROR] Blocklist file not found: {file_path}")
        return []

BLOCKED_IPS = load_blocklist("blocked_ips.txt")
BLOCKED_PORTS = [int(port) for port in load_blocklist("blocked_ports.txt") if port.isdigit()]
BLOCKED_KEYWORDS = load_blocklist("blocked_keywords.txt")
BLOCKED_SITES = load_blocklist("blocked_sites.txt")

# 🔹 Configure iptables Rules
def setup_iptables():
    commands = [
        "sudo iptables -F",
        "sudo iptables -P INPUT DROP",
        "sudo iptables -P FORWARD DROP",
        "sudo iptables -P OUTPUT ACCEPT",

        # Allow SSH with rate limiting (brute-force protection)
        "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set",
        "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
        "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",

        # Allow established connections
        "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",

        # SYN flood protection
        "sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",

        # Forward HTTP & HTTPS to NFQUEUE for inspection
        "sudo iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1",
        "sudo iptables -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1",
        
        # Block specific IPs
        *[f"sudo iptables -A INPUT -s {ip} -j DROP" for ip in BLOCKED_IPS],

        # Block specific Ports
        *[f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP" for port in BLOCKED_PORTS]
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"[ERROR] Failed to apply iptables rule: {cmd} - {e}")

    logging.info("[INFO] iptables rules finalized.")

# 🔹 Packet Inspection & Filtering
def inspect_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.src in BLOCKED_IPS or scapy_pkt.dst in BLOCKED_IPS:
            logging.warning(f"[BLOCKED] IP: {scapy_pkt.src} -> {scapy_pkt.dst}")
            packet.drop()
            return

        if scapy_pkt.haslayer(TCP) and (
            scapy_pkt[TCP].sport in BLOCKED_PORTS or scapy_pkt[TCP].dport in BLOCKED_PORTS):
            logging.warning(f"[BLOCKED] Suspicious Port: {scapy_pkt.src}:{scapy_pkt[TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[TCP].dport}")
            packet.drop()
            return

        if scapy_pkt.haslayer(Raw):
            try:
                http_payload = scapy_pkt[Raw].load.decode("utf-8", errors="replace")
                for keyword in BLOCKED_KEYWORDS:
                    if keyword.lower() in http_payload.lower():
                        logging.warning(f"[BLOCKED] Malicious Keyword Detected: {keyword}")
                        packet.drop()
                        return
            except UnicodeDecodeError:
                logging.error("[ERROR] Unicode decoding failed")

        packet.accept()

    except Exception as e:
        logging.error(f"[ERROR] Failed to inspect packet: {e}")
        packet.accept()

# 🔹 Setup Fail2Ban
def setup_fail2ban():
    try:
        subprocess.run("sudo apt-get install fail2ban -y", shell=True, check=True)
        subprocess.run("sudo systemctl enable fail2ban && sudo systemctl start fail2ban", shell=True, check=True)
        logging.info("[INFO] Fail2Ban setup completed.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to setup Fail2Ban: {e}")

# 🔹 Setup Squid Proxy
def setup_squid_proxy():
    try:
        subprocess.run("sudo apt-get install squid -y", shell=True, check=True)

        # Write blocked domains to a separate file
        with open("/etc/squid/blocked_sites.txt", "w") as f:
            f.write("\n".join([f".{domain}" for domain in BLOCKED_SITES]))

        squid_config = """
http_port 3128
acl allowed_ips src 192.168.1.0/24
acl blocked_sites dstdomain "/etc/squid/blocked_sites.txt"
http_access deny blocked_sites
http_access allow allowed_ips
http_access deny all
        """
        with open("/etc/squid/squid.conf", "w") as f:
            f.write(squid_config)

        subprocess.run("sudo systemctl restart squid", shell=True, check=True)
        logging.info("[INFO] Squid Proxy configured successfully.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to setup Squid Proxy: {e}")

# 🔹 Update Blocklists
def update_blocklists():
    logging.info("[INFO] Updating blocklists...")
    urls = {
        "blocked_ips.txt": "https://example.com/blocked_ips.txt",
        "blocked_ports.txt": "https://example.com/blocked_ports.txt",
        "blocked_keywords.txt": "https://example.com/blocked_keywords.txt",
        "blocked_sites.txt": "https://example.com/blocked_sites.txt"
    }

    for filename, url in urls.items():
        try:
            temp_file = filename + ".tmp"
            subprocess.run(f"wget -O {temp_file} {url}", shell=True, check=True)
            os.replace(temp_file, filename)
            logging.info(f"[INFO] Updated {filename}.")
        except Exception as e:
            logging.error(f"[ERROR] Failed to update {filename}: {e}")

# 🔹 Main Firewall Logic
def start_firewall():
    update_blocklists()
    setup_iptables()
    setup_fail2ban()
    setup_squid_proxy()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, inspect_packet)

    def cleanup(sig, frame):
        logging.info("[INFO] Stopping firewall and unbinding queue.")
        nfqueue.unbind()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    logging.info("[INFO] Firewall started. Monitoring traffic...")
    nfqueue.run()

# 🔹 Run
if __name__ == "__main__":
    start_firewall()
