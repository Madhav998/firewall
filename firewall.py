import os
import subprocess
import threading
import logging
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

# ====================== Logging Setup ========================
LOG_FILE = "/var/log/firewall.log"

# Ensure log file exists with correct permissions
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("")
    os.chmod(LOG_FILE, 0o644)  # rw-r--r--

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logging.info("Firewall script initialized!")

# ====================== Root Check ===========================
if os.geteuid() != 0:
    logging.error("This script must be run as root. Exiting...")
    exit(1)

# ====================== Blocklist Loader =====================
def load_blocklist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.warning(f"[WARNING] Blocklist not found: {file_path}")
        return []

# ====================== Blocklist URLs =======================
BLOCKLIST_URLS = {
    'blocked_ips.txt': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    'blocked_ports.txt': 'https://gist.githubusercontent.com/anonymous/1eab6d48/raw/blocked_ports.txt',
    'blocked_keywords.txt': 'https://gist.githubusercontent.com/anonymous/1eab6d48/raw/blocked_keywords.txt',
    'blocked_sites.txt': 'https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt'
}

# ====================== Dependencies Check ====================
def install_requirements():
    try:
        subprocess.run("apt-get update && apt-get install iptables-persistent netfilter-persistent fail2ban squid python3-pip -y", shell=True, check=True)
        subprocess.run("pip3 install scapy netfilterqueue", shell=True, check=True)
        logging.info("[INFO] Dependencies installed.")
    except Exception as e:
        logging.error(f"[ERROR] Dependency installation failed: {e}")

# ====================== IPTables Setup ========================
def setup_iptables():
    commands = [
        "iptables -F",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT ACCEPT",
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
        "iptables -A INPUT -s 10.0.2.0/24 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1",
        "iptables -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1",
        *[f"iptables -A INPUT -s {ip} -j DROP" for ip in BLOCKED_IPS if not ip.startswith("10.0.2.")],
        *[f"iptables -A INPUT -p tcp --dport {port} -j DROP" for port in BLOCKED_PORTS]
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"[ERROR] iptables rule failed: {cmd} - {e}")

    subprocess.run("netfilter-persistent save", shell=True)
    logging.info("[INFO] iptables rules finalized and saved.")

# ====================== Packet Inspection =====================
def inspect_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.src in BLOCKED_IPS or scapy_pkt.dst in BLOCKED_IPS:
            logging.warning(f"[BLOCKED] IP: {scapy_pkt.src} -> {scapy_pkt.dst}")
            packet.drop()
            return

        if scapy_pkt.haslayer(TCP) and (scapy_pkt[TCP].sport in BLOCKED_PORTS or scapy_pkt[TCP].dport in BLOCKED_PORTS):
            logging.warning(f"[BLOCKED] Port: {scapy_pkt.src}:{scapy_pkt[TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[TCP].dport}")
            packet.drop()
            return

        if scapy_pkt.haslayer(Raw):
            try:
                http_payload = scapy_pkt[Raw].load.decode("utf-8", errors="replace")
                for keyword in BLOCKED_KEYWORDS:
                    if keyword.lower() in http_payload.lower():
                        logging.warning(f"[BLOCKED] Keyword Detected: {keyword}")
                        packet.drop()
                        return
            except UnicodeDecodeError:
                logging.error("[ERROR] Could not decode HTTP payload")

        packet.accept()

    except Exception as e:
        logging.error(f"[ERROR] Packet inspection failed: {e}")
        packet.accept()

# ====================== Fail2Ban Setup ========================
def setup_fail2ban():
    try:
        subprocess.run("systemctl enable fail2ban && systemctl start fail2ban", shell=True, check=True)
        logging.info("[INFO] Fail2Ban started.")
    except Exception as e:
        logging.error(f"[ERROR] Fail2Ban setup failed: {e}")

# ====================== Squid Proxy Setup =====================
def setup_squid_proxy():
    try:
        blocked_domains_rules = "\n".join([f".{domain}" for domain in BLOCKED_SITES])
        squid_config = f"""
http_port 3128
acl allowed_ips src 10.0.2.0/24
acl blocked_sites dstdomain {blocked_domains_rules}
http_access deny blocked_sites
http_access allow allowed_ips
http_access deny all
        """
        with open("/etc/squid/squid.conf", "w") as f:
            f.write(squid_config)

        subprocess.run("systemctl restart squid", shell=True, check=True)
        logging.info("[INFO] Squid Proxy configured.")
    except Exception as e:
        logging.error(f"[ERROR] Squid Proxy setup failed: {e}")

# ====================== Blocklist Auto Update =================
def update_blocklists():
    logging.info("[INFO] Updating blocklists...")
    for filename, url in BLOCKLIST_URLS.items():
        try:
            subprocess.run(f"wget -q -O {filename}.tmp {url}", shell=True, check=True)
            os.replace(f"{filename}.tmp", filename)
            logging.info(f"[INFO] {filename} updated.")
        except Exception as e:
            logging.error(f"[ERROR] Updating {filename} failed: {e}")

# ====================== Firewall Starter ======================
def start_firewall():
    global BLOCKED_IPS, BLOCKED_PORTS, BLOCKED_KEYWORDS, BLOCKED_SITES

    install_requirements()

    BLOCKED_IPS = [ip for ip in load_blocklist("blocked_ips.txt") if not ip.startswith("10.0.2.")]
    BLOCKED_PORTS = [int(p) for p in load_blocklist("blocked_ports.txt") if p.isdigit()]
    BLOCKED_KEYWORDS = load_blocklist("blocked_keywords.txt")
    BLOCKED_SITES = load_blocklist("blocked_sites.txt")

    setup_iptables()
    setup_fail2ban()
    setup_squid_proxy()

    threading.Thread(target=update_blocklists, daemon=True).start()

    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(1, inspect_packet)
        logging.info("[INFO] Firewall running. Press Ctrl+C to stop.")
        nfqueue.run()
    except KeyboardInterrupt:
        logging.info("[INFO] Stopping firewall...")
    finally:
        nfqueue.unbind()

# ====================== Main =========================
if __name__ == "__main__":
    start_firewall()
 do i have to make changes now?
