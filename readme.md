# Network Traffic Monitoring
![firewall_banner](Picrures/firewall-banner.png)

## 📋 Project Description
A real-time network traffic monitoring system built using Python and Scapy. This project includes an advanced GUI for packet analysis, threat detection, and network security logging.

---

## 🌟 Features
- **Real-time Packet Capturing and Filtering**:
  - Block traffic based on blacklisted IPs and ports.
  - Detect malicious activities, including port scanning and DoS attacks.
- **Customizable GUI Interface**:
  - Live Monitoring tab for viewing allowed, blocked, and malicious traffic.
  - Firewall Rules tab for managing IPs, ports, and advanced settings.
  - Statistics tab for visualizing packet summaries.
- **Advanced Rule Configurations**:
  - Adjustable DoS detection thresholds and packet size limits.
- **Detailed Logging System**:
  - Separate logs for allowed, blocked, and malicious packets.
  - Summary logs for quick insights.

---

## 🛠️ Requirements
- Python 3.8 or higher
- Scapy library for packet manipulation
- Admin/root privileges for packet capturing
- Compatible network interface card
- `tkinter` library for GUI (pre-installed with Python)

---

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/network-traffic-monitoring.git
   cd network-traffic-monitoring
   ```

2. Install required packages:
   ```bash
   pip install scapy
   ```

---

## 🚀 Usage
### Run the GUI Application
1. Start the firewall GUI:
   ```bash
   python fireWall_GUI.py
   ```

2. Use the tabs for monitoring, managing rules, and viewing statistics.

### Run the Packet Filtering Module (Command Line)
1. Execute the packet filtering logic:
   ```bash
   python packet_filter.py
   ```

2. Optionally, execute the test suite:
   ```bash
   cd tests
   python test_packet_module.py
   ```

---

## 📁 File Structure
```
network-traffic-monitoring/
│
├── fireWall_GUI.py      # GUI application for monitoring and configuration
├── packet_filter.py     # Core packet filtering logic
├── logs/
│   ├── allowed.log      # Log of allowed packets
│   ├── blocked.log      # Log of blocked packets
│   ├── maliscious.log   # Log of malicious packets
│   └── summary.log      # Packet summary
├── tests/
│   └── test_packet_module.py
└── README.md
```

---

## ⚙️ Configuration
Customize the filtering rules in `packet_filter.py`:
- Update the `BLACKLISTED_IPS` list for IP filtering.
- Modify the `BLOCKED_PORTS` list to manage port access.
- Adjust the `MAX_PACKET_SIZE`, `DOS_THRESHOLD`, and `DOS_TIME_INTERVAL` values for advanced filtering.

---

## 📊 Logging
### Log Files:
- **allowed.log**: Logs all allowed packets.
- **blocked.log**: Logs traffic blocked due to rules.
- **maliscious.log**: Records detected malicious activities (e.g., DoS attacks).
- **summary.log**: Provides a summary of network traffic.

### Log Details:
- Timestamp of events.
- Source and destination IPs.
- Protocol information.
- Action taken (Allowed/Blocked).

---

## 📫 Support
For support, please open an issue in the repository or contact the maintainers.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
