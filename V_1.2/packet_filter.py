import logging
from scapy.all import sniff, IP, TCP, UDP
import os

# Set up logging to log alerts (log file will be in 'logs' folder)
if not os.path.exists('logs'):
    os.makedirs('logs')  # Ensure the logs directory exists

logging.basicConfig(filename='logs/alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Blacklisted IPs (Example: List of IPs to block)
BLACKLISTED_IPS = ["192.168.1.100", "10.0.0.5"]

# Blocked Ports (Example: List of ports to block)
BLOCKED_PORTS = [22]

# Max allowed packet size in bytes
MAX_PACKET_SIZE = 1024  # For example, drop packets larger than 1024 bytes

# Filter packets based on custom rules
def filter_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.proto
        packet_size = len(packet)
        
        # Rule 1: Blacklist specific IPs
        if ip_src in BLACKLISTED_IPS or ip_dst in BLACKLISTED_IPS:
            logging.warning(f"Blocked packet from blacklisted IP: {ip_src} to {ip_dst} ({protocol})")
            return False  # Drop the packet

        # Rule 2: Block traffic on specified ports (e.g., HTTP, HTTPS, SSH)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dport = packet.dport if packet.haslayer(TCP) else packet.sport
            if dport in BLOCKED_PORTS:
                logging.warning(f"Blocked traffic on port {dport} from {ip_src} to {ip_dst}")
                return False  # Drop the packet
        
        # Rule 3: Drop packets exceeding a certain size
        if packet_size > MAX_PACKET_SIZE:
            logging.warning(f"Dropped packet exceeding size limit: {packet_size} bytes from {ip_src} to {ip_dst}")
            return False  # Drop the packet

        # Log allowed packets
        logging.info(f"Allowed packet: {ip_src} -> {ip_dst}, Protocol: {protocol}, Size: {packet_size} bytes")
        return True  # Accept the packet if it passes all rules

    # If the packet doesn't have an IP layer, it is logged as ignored
    logging.info(f"Ignored non-IP packet")
    return False

# Function to capture live packets
def capture_packets(interface="Ethernet"):
    print(f"Capturing packets on interface {interface}...")
    sniff(iface=interface, prn=lambda x: filter_packet(x), store=0)  # Capture packets and apply filter_packet function

if __name__ == '__main__':
    # Start capturing packets on a specific interface (change interface as needed)
    capture_packets(interface="Ethernet")  # Replace with the correct network interface name on your system
