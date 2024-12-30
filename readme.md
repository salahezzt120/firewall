# Network Traffic Monitoring
![firewall_banner](Picrures/firewall-banner.png)
## 📋 Project Description
A real-time network traffic monitoring system built using Python and Scapy. This project provides comprehensive packet analysis, threat detection, and logging capabilities for network security.

---
## 🌟 Features
- Real-time packet capturing and filtering using custom rules
- Blocked traffic based on blacklisted IPs and ports
- Detection of malicious activities (port scanning, DoS attacks)
- Detailed logging system with activity tracking
- Customizable filtering rules and configurations

---
## 🛠️ Requirements
- Python 3.8 or higher
- Scapy library for packet manipulation
- Admin/root privileges for packet capturing
- Compatible network interface card

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
1. Run the packet filtering module:
   ```bash
   python packet_filter.py
   ```

2. Execute the test suite:
   ```bash
   cd tests
   python test_packet_module.py
   ```

---
## 📁 File Structure
```
network-traffic-monitoring/
│
├── packet_filter.py    # Main packet filtering logic
├── tests/
│   └── test_packet_module.py
├── logs/
│   └── alerts.log
└── README.md
```

---
## ⚙️ Configuration
Customize the filtering rules in `packet_filter.py`:
- Modify `BLACKLISTED_IPS` list
- Update `BLOCKED_PORTS` list
- Adjust `MAX_PACKET_SIZE` value

---
## 📊 Logging
The system logs all activities in `logs/alerts.log`, including:
- Timestamp of events
- Source and destination IPs
- Protocol information
- Action taken (Allowed/Blocked)
- Malicious activity alerts

---
## 📫 Support
For support, please open an issue in the repository or contact the maintainers.

---
## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
