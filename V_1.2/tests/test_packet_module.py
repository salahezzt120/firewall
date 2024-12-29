import logging
from scapy.all import Ether, IP, TCP, UDP, send
import random

# Set up logging to log alerts (log file will be in 'logs' folder)
logging.basicConfig(filename='../logs/alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to simulate a normal packet
def simulate_normal_traffic():
    print("Simulating normal traffic")
    normal_packet = Ether()/IP(src="192.168.1.159", dst="8.8.8.8")/TCP(sport=12345, dport=80)
    send(normal_packet, verbose=False)
    print("Normal traffic simulated")

# Function to simulate a packet from a blacklisted IP
def simulate_blacklisted_ip():
    print("Simulating traffic from blacklisted IP")
    blacklisted_packet = Ether()/IP(src="192.168.1.100", dst="192.168.1.159")/TCP(sport=12345, dport=80)
    send(blacklisted_packet, verbose=False)
    print("Blacklisted IP traffic simulated")

# Function to simulate traffic on blocked ports
def simulate_blocked_ports():
    print("Simulating traffic on blocked ports")
    blocked_ports_packet = Ether()/IP(src="192.168.1.159", dst="192.168.1.2")/TCP(sport=12345, dport=443)
    send(blocked_ports_packet, verbose=False)
    print("Blocked port traffic simulated")

# Function to simulate a large packet
def simulate_large_packet():
    print("Simulating a large packet")
    large_packet = Ether()/IP(src="192.168.1.159", dst="192.168.1.2")/TCP(sport=12345, dport=80) / ("X" * 1500)
    send(large_packet, verbose=False)
    print("Large packet simulated")

# Main function to run tests
def run_tests():
    simulate_normal_traffic()
    simulate_blacklisted_ip()
    simulate_blocked_ports()
    simulate_large_packet()

if __name__ == '__main__':
    run_tests()
    print("Test completed. Check alerts.log for results.")
