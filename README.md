# 📡 Network Packet Monitor (Java)

> A real-time network packet capture and analysis tool built in Java using the **pcap4j** library.

---

## 👤 Author

**GitHub:** [@hemanathan115](https://github.com/hemanathan115)

---

## 📋 Overview

Network Packet Monitor captures live network traffic and displays detailed information about each packet, including source/destination IPs, protocol type, packet size, and alerts for suspicious activity. It is designed for security analysts, network engineers, and students learning about network protocols.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📥 Packet Capture | Captures live packets from any network interface in promiscuous mode |
| 🔍 Traffic Analysis | Displays source IP, destination IP, protocol, and packet size |
| 📊 Protocol Statistics | Live stats for TCP / UDP / ICMP / Other printed every 10 seconds |
| ⚠️ Suspicious Traffic Detection | Flags high-risk ports and high packet-rate IPs (flood detection) |
| 🌐 IPv4 & IPv6 Support | Handles both IP versions automatically |

---

## 🛠️ Technologies Used

- **Language:** Java 11+
- **Packet Capture Library:** [pcap4j](https://github.com/kaitoy/pcap4j)
- **Native Dependency:** libpcap (Linux/macOS) or Npcap/WinPcap (Windows)
- **Networking APIs:** Standard Java + pcap4j packet parsing

---

## 📁 Project Structure

```
NetworkPacketMonitor/
├── NetworkPacketMonitor.java   # Main source file
└── README.md                   # Project documentation
```

---

## ⚙️ Setup & Installation

### 1. Prerequisites

| Requirement | Details |
|---|---|
| Java | JDK 11 or higher |
| Maven / Gradle | For dependency management |
| libpcap | Linux: `sudo apt install libpcap-dev` / macOS: pre-installed |
| Npcap | Windows: download from [npcap.com](https://npcap.com) |

### 2. Add pcap4j Dependency

**Maven (`pom.xml`):**
```xml
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-core</artifactId>
    <version>1.8.2</version>
</dependency>
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-packetfactory-static</artifactId>
    <version>1.8.2</version>
</dependency>
```

**Gradle (`build.gradle`):**
```groovy
implementation 'org.pcap4j:pcap4j-core:1.8.2'
implementation 'org.pcap4j:pcap4j-packetfactory-static:1.8.2'
```

### 3. Compile

```bash
javac -cp pcap4j-core-1.8.2.jar:pcap4j-packetfactory-static-1.8.2.jar NetworkPacketMonitor.java
```

### 4. Run (requires root / administrator privileges)

```bash
# Linux / macOS
sudo java -cp .:pcap4j-core-1.8.2.jar:pcap4j-packetfactory-static-1.8.2.jar NetworkPacketMonitor

# Specify interface index (e.g., interface 1)
sudo java -cp ... NetworkPacketMonitor 1
```

> **Windows:** Run the terminal as Administrator.

---

## 🖥️ Sample Output

```
=== Network Packet Monitor ===
Available interfaces:
  [0] eth0 – Ethernet
  [1] wlan0 – Wi-Fi

Capturing on: eth0
Press Ctrl+C to stop.

[TCP] 192.168.1.5:52301 → 93.184.216.34:443  | Proto: TCP   | Size:   512 bytes
[UDP] 192.168.1.5:12345 → 8.8.8.8:53         | Proto: UDP   | Size:    72 bytes
[TCP] 10.0.0.2:54001    → 10.0.0.1:4444      | Proto: TCP   | Size:   128 bytes ⚠ SUSPICIOUS PORT(4444)
[ICMP] 192.168.1.10    → 192.168.1.1         | Proto: ICMP  | Size:    84 bytes

──────────── Traffic Statistics ────────────
  Total packets : 1,204
  TCP           : 873
  UDP           : 295
  ICMP          : 30
  Other         : 6
  Total bytes   : 1,048,576
────────────────────────────────────────────
```

---

## ⚠️ Suspicious Traffic Detection

The monitor automatically flags:

- **High-risk ports** — including 22 (SSH brute force), 23 (Telnet), 445 (SMB), 3389 (RDP), 4444 (Metasploit), 5555 (ADB), and more.
- **High packet rate** — any source IP sending more than **200 packets** triggers a flood warning.

---

## 🔒 Security & Legal Notice

> This tool is intended for **authorized network monitoring only**.  
> Capturing traffic on networks you do not own or have explicit permission to monitor may be **illegal** in your jurisdiction.  
> Use responsibly.

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
