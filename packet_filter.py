import logging
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import threading
import time
import os

# Setup logging for alerts and summaries
LOG_DIR = "logs"
ALERT_LOG_FILE = f"{LOG_DIR}/alerts.log"
SUMMARY_LOG_FILE = f"{LOG_DIR}/summary.log"

# Ensure the logs directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure logging for alerts
logging.basicConfig(
    filename=ALERT_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Configure summary logging
summary_logger = logging.getLogger('summary')
summary_logger.setLevel(logging.INFO)
summary_handler = logging.FileHandler(SUMMARY_LOG_FILE)
summary_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
summary_logger.addHandler(summary_handler)

# Blacklisted IPs
BLACKLISTED_IPS = ["192.168.1.100", "10.0.0.5"]

# Blocked Ports
BLOCKED_PORTS = [22]

# Max allowed packet size
MAX_PACKET_SIZE = 1024  # Bytes

# Packet counters
packet_summary = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "malicious": 0
}

# Filter and log packets
def filter_packet(packet):
    global packet_summary
    packet_summary["total"] += 1

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.proto
        packet_size = len(packet)

        action = "Allowed"

        # Rule 1: Blacklisted IPs
        if ip_src in BLACKLISTED_IPS or ip_dst in BLACKLISTED_IPS:
            action = "Blocked"
            reason = "Blacklisted IP"
            packet_summary["blocked"] += 1
            packet_summary["malicious"] += 1
            logging.warning(
                f"Blocked: {reason} | Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Size: {packet_size} bytes"
            )
            return False

        # Rule 2: Blocked Ports
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dport = packet.dport if packet.haslayer(TCP) else packet.sport
            if dport in BLOCKED_PORTS:
                action = "Blocked"
                reason = "Blocked Port"
                packet_summary["blocked"] += 1
                packet_summary["malicious"] += 1
                logging.warning(
                    f"Blocked: {reason} | Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Port: {dport}"
                )
                return False

        # Rule 3: Max Packet Size
        if packet_size > MAX_PACKET_SIZE:
            action = "Blocked"
            reason = "Packet Size Exceeded"
            packet_summary["blocked"] += 1
            logging.warning(
                f"Blocked: {reason} | Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Size: {packet_size} bytes"
            )
            return False

        # Log allowed packets
        if action == "Allowed":
            packet_summary["allowed"] += 1
            logging.info(
                f"Allowed: Src: {ip_src} -> Dst: {ip_dst}, Protocol: {protocol}, Size: {packet_size} bytes"
            )

    return True

# Capture packets
def capture_packets(interface="Ethernet"):
    print(f"Capturing packets on interface {interface}...")
    sniff(iface=interface, prn=lambda x: filter_packet(x), store=0)

# Periodic summary logging (to be run in a separate thread)
def log_summary_periodically(interval=5):
    while True:
        time.sleep(interval)  # Wait for the specified interval before logging the summary
        summary_log = (
            f"Packet Summary:\n"
            f"Total Packets: {packet_summary['total']}\n"
            f"Allowed Packets: {packet_summary['allowed']}\n"
            f"Blocked Packets: {packet_summary['blocked']}\n"
            f"Malicious Packets: {packet_summary['malicious']}\n"
        )
        print(summary_log)
        summary_logger.info(summary_log)  # Log the summary to summary.log

# Periodic summary logging thread
def start_summary_thread():
    summary_thread = threading.Thread(target=log_summary_periodically, args=(5,), daemon=True)
    summary_thread.start()

if __name__ == "__main__":
    try:
        # Start the summary thread before capturing packets
        start_summary_thread()

        # Start capturing packets
        capture_packets(interface="Ethernet")

    except KeyboardInterrupt:
        print("\nStopping packet capture...")

        # Log final summary on capture stop
        final_summary_log = (
            f"Final Packet Summary:\n"
            f"Total Packets: {packet_summary['total']}\n"
            f"Allowed Packets: {packet_summary['allowed']}\n"
            f"Blocked Packets: {packet_summary['blocked']}\n"
            f"Malicious Packets: {packet_summary['malicious']}\n"
        )
        summary_logger.info(final_summary_log)  # Log the final summary to summary.log
        print(final_summary_log)
