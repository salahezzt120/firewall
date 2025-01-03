import logging
import os
from scapy.all import sniff, IP, TCP, UDP
from threading import Event
from collections import defaultdict
import time

# Setup logging
LOG_DIR = "logs"
ALERT_LOG_FILE = f"{LOG_DIR}/blocked.log"
SUMMARY_LOG_FILE = f"{LOG_DIR}/summary.log"
ALLOWED_LOG_FILE = f"{LOG_DIR}/allowed.log"
Maliscious_LOG_FILE = f"{LOG_DIR}/maliscious.log"

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(level=logging.INFO)

# Initialize loggers
alert_logger = logging.getLogger("alert_logger")
summary_logger = logging.getLogger("summary_logger")
allowed_logger = logging.getLogger("allowed_logger")
malisious_logger = logging.getLogger("malisious_logger")

alert_handler = logging.FileHandler(ALERT_LOG_FILE)
summary_handler = logging.FileHandler(SUMMARY_LOG_FILE)
allowed_handler = logging.FileHandler(ALLOWED_LOG_FILE)
malisious_handler = logging.FileHandler(Maliscious_LOG_FILE)

alert_handler.setLevel(logging.WARNING)
summary_handler.setLevel(logging.INFO)
allowed_handler.setLevel(logging.INFO)
malisious_handler.setLevel(logging.INFO)

alert_logger.addHandler(alert_handler)
summary_logger.addHandler(summary_handler)
allowed_logger.addHandler(allowed_handler)
malisious_logger.addHandler(malisious_handler)

# Variables for filtering
WHITELISTED_IPS = ["192.168.1.13"]  # List of whitelisted IPs
BLACKLISTED_IPS = []
BLOCKED_PORTS = []
MAX_PACKET_SIZE = 1800  # Example size (in bytes)
DOS_THRESHOLD = 500  # Number of packets per IP in a given time interval
DOS_TIME_INTERVAL = 1  # Time interval in seconds

# Packet summary
packet_summary = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "malicious": 0
}

# DoS detection variables
ip_packet_count = defaultdict(int)
ip_last_seen = {}

# Stop flag for sniffing
stop_event = Event()

def reset_logs():
    with open(ALERT_LOG_FILE, 'w'), open(SUMMARY_LOG_FILE, 'w'), open(ALLOWED_LOG_FILE, 'w'):
        pass

def update_summary_log():
    summary_text = (
        f"Total Packets: {packet_summary['total']}\n"
        f"Allowed: {packet_summary['allowed']}\n"
        f"Blocked: {packet_summary['blocked']}\n"
        f"Malicious: {packet_summary['malicious']}\n"
    )
    with open(SUMMARY_LOG_FILE, 'w') as f:
        f.write(summary_text)

def detect_dos_attack(ip_src, dport):
    """
    Detects a DoS attack based on packet rate from a specific source IP.
    """
    global packet_summary
    if ip_src in WHITELISTED_IPS:
        return False  # Skip DoS detection for whitelisted IPs

    current_time = time.time()
    if ip_src not in ip_packet_count:
        ip_packet_count[ip_src] = 0
        ip_last_seen[ip_src] = current_time

    ip_packet_count[ip_src] += 1
    elapsed_time = current_time - ip_last_seen[ip_src]

    if elapsed_time <= DOS_TIME_INTERVAL:
        if ip_packet_count[ip_src] > DOS_THRESHOLD:
            if ip_packet_count[ip_src] == DOS_THRESHOLD + 1:  # Log the attack once
                packet_summary["malicious"] += 1
                packet_summary["blocked"] += 1
                malisious_logger.warning(f"Detected DoS Attack - Source IP: {ip_src}, Port: {dport}")
                update_summary_log()
                add_blacklisted_ip(ip_src)  # Blacklist the IP
                add_blocked_port(dport)  # Block the port
            return True
    else:
        ip_packet_count[ip_src] = 1  # Reset count after the time window
        ip_last_seen[ip_src] = current_time

    return False

def filter_packet(packet):
    global packet_summary
    packet_summary["total"] += 1

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.proto
        packet_size = len(packet)
        action = "Allowed"

        dport = None
        sport = None

        # Check if TCP or UDP, and get port information
        if packet.haslayer(TCP):
            dport = packet.dport
            sport = packet.sport
        elif packet.haslayer(UDP):
            dport = packet.dport
            sport = packet.sport

        # Skip detection for whitelisted IPs
        if ip_src in WHITELISTED_IPS:
            packet_summary["allowed"] += 1
            allowed_logger.info(f"Allowed Packet - Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Src Port: {sport}, Dst Port: {dport}, Size: {packet_size} bytes")
            update_summary_log()
            return True

        # DoS Detection
        if detect_dos_attack(ip_src, dport):
            return False

        if ip_src in BLACKLISTED_IPS:
            action = "Blocked"
            alert_logger.warning(f"Blocked: Blacklisted IP | Src: {ip_src} -> Dst: {ip_dst}, Port: {dport}")
            packet_summary["blocked"] += 1
            update_summary_log()
            return False

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if dport in BLOCKED_PORTS:
                action = "Blocked"
                packet_summary["blocked"] += 1
                alert_logger.warning(f"Blocked: Blocked Port | Src: {ip_src} -> Dst: {ip_dst}, Src Port: {sport}, Dst Port: {dport}")
                update_summary_log()
                return False

        if packet_size > MAX_PACKET_SIZE:
            action = "Blocked"
            packet_summary["blocked"] += 1
            alert_logger.warning(f"Blocked: Packet Size Exceeded | Src: {ip_src} -> Dst: {ip_dst}, Size: {packet_size} bytes, Port: {dport}")
            update_summary_log()
            return False

        if action == "Allowed":
            packet_summary["allowed"] += 1
            allowed_logger.info(f"Allowed Packet - Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Src Port: {sport}, Dst Port: {dport}, Size: {packet_size} bytes")
            update_summary_log()

def capture_packets():
    while not stop_event.is_set():
        sniff(iface="Wi-Fi", prn=filter_packet, store=0, timeout=1)

def stop_capture():
    stop_event.set()

def add_blacklisted_ip(ip):
    if ip and ip not in BLACKLISTED_IPS:
        BLACKLISTED_IPS.append(ip)

def remove_blacklisted_ip(ip):
    if ip in BLACKLISTED_IPS:
        BLACKLISTED_IPS.remove(ip)

def add_blocked_port(port):
    if port not in BLOCKED_PORTS:
        BLOCKED_PORTS.append(port)

def remove_blocked_port(port):
    if port in BLOCKED_PORTS:
        BLOCKED_PORTS.remove(port)