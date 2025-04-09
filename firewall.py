import os
import subprocess
import threading
import logging
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

#  Logging Setup
import logging

LOG_FILE = "/var/log/firewall.log"  # This is the correct path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Log to the file
        logging.StreamHandler()  # Log to console
    ]
)

logging.info("Firewall script started!")

logging.info("Firewall script started!") 

# Load Blocklists
def load_blocklist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"[ERROR] Blocklist file not found: {file_path}")
        return []

# Remote Blocklist URLs
BLOCKLIST_URLS = {
    'blocked_ips.txt': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',  # List of malicious IPs
    'blocked_ports.txt': 'https://gist.githubusercontent.com/anonymous/1eab6d48/raw/blocked_ports.txt',  # Custom blocked ports
    'blocked_keywords.txt': 'https://gist.githubusercontent.com/anonymous/1eab6d48/raw/blocked_keywords.txt',  # Keywords like "proxy", "hack", "torrent"
    'blocked_sites.txt': 'https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt'  # Malicious domains
}


# Configure iptables Rules
def setup_iptables():
    commands = [
        "sudo iptables -P INPUT DROP",
        "sudo iptables -P FORWARD DROP",
        "sudo iptables -P OUTPUT ACCEPT",

        # Allow SSH
        "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",

        # Allow established connections
        "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",

        # Prevent SYN flood attacks
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

    # Ensure DROP policy remains active in case of failure
    subprocess.run("sudo iptables -P INPUT DROP", shell=True, check=False)
    subprocess.run("sudo iptables -P FORWARD DROP", shell=True, check=False)
    subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True, check=False)

    logging.info("[INFO] iptables rules finalized with safe default policies.")

# Packet Inspection & Filtering
def inspect_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())

        # Drop packets from blocked IPs
        if scapy_pkt.src in BLOCKED_IPS or scapy_pkt.dst in BLOCKED_IPS:
            logging.warning(f"[BLOCKED] IP: {scapy_pkt.src} -> {scapy_pkt.dst}")
            packet.drop()
            return

        # Drop packets on blocked ports
        if scapy_pkt.haslayer(TCP) and (scapy_pkt[TCP].sport in BLOCKED_PORTS or scapy_pkt[TCP].dport in BLOCKED_PORTS):
            logging.warning(f"[BLOCKED] Suspicious Port: {scapy_pkt.src}:{scapy_pkt[TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[TCP].dport}")
            packet.drop()
            return

        # Inspect HTTP traffic
        if scapy_pkt.haslayer(Raw):
            try:
                http_payload = scapy_pkt[Raw].load.decode("utf-8", errors="replace")
                for keyword in BLOCKED_KEYWORDS:
                    if keyword.lower() in http_payload.lower():
                        logging.warning(f"[BLOCKED] Malicious Keyword Detected: {keyword}")
                        packet.drop()
                        return
            except UnicodeDecodeError:
                logging.error("[ERROR] Unicode decoding failed on HTTP payload")

        packet.accept()

    except Exception as e:
        logging.error(f"[ERROR] Failed to inspect packet: {e}")
        packet.accept()

# Setup Fail2Ban to Prevent Brute-Force Attacks
def setup_fail2ban():
    try:
        subprocess.run("sudo apt-get install fail2ban -y", shell=True, check=True)
        subprocess.run("sudo systemctl enable fail2ban && sudo systemctl start fail2ban", shell=True, check=True)
        logging.info("[INFO] Fail2Ban setup completed.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to setup Fail2Ban: {e}")

# Setup Squid Proxy with Domain-Based Filtering
def setup_squid_proxy():
    try:
        subprocess.run("sudo apt-get install squid -y", shell=True, check=True)

        blocked_domains_rules = "\n".join([f".{domain}" for domain in BLOCKED_SITES])

        squid_config = f"""
http_port 3128
acl allowed_ips src 192.168.1.0/24
acl blocked_sites dstdomain {blocked_domains_rules}
http_access deny blocked_sites
http_access allow allowed_ips
http_access deny all
        """

        with open("/etc/squid/squid.conf", "w") as f:
            f.write(squid_config)

        subprocess.run("sudo systemctl restart squid", shell=True, check=True)
        logging.info("[INFO] Squid Proxy configured with domain-based filtering.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to setup Squid Proxy: {e}")

# Automate Blocklist Updates
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
            os.replace(temp_file, filename)  # Replace only if successful
            logging.info(f"[INFO] Updated {filename}.")
        except Exception as e:
            logging.error(f"[ERROR] Failed to update {filename}: {e}")

# Start the Firewall
def start_firewall():
    setup_iptables()
    setup_fail2ban()
    setup_squid_proxy()
    update_blocklists()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, inspect_packet)

    firewall_thread = threading.Thread(target=nfqueue.run, daemon=True)
    firewall_thread.start()
    logging.info("[INFO] Firewall started and running.")

# Run Firewall
if __name__ == "__main__":
    start_firewall()
