# Network Intrusion Detection System (NIDS)

A lightweight Network Intrusion Detection System implemented in Go using raw sockets for low-level packet capture.

## Features

- **Live Traffic Monitoring**: Captures network packets in real-time from selected interface
- **DDoS Detection**: Monitors packet rates per source IP and alerts on suspicious activity
- **Interactive CLI**: User-friendly menu for configuration
- **Automatic IP Blocking**: Optional iptables integration to block malicious IPs
- **Concurrent Processing**: Uses goroutines and channels for efficient real-time processing
- **Modular Design**: Easy to extend with additional detection algorithms

## Requirements

- Go 1.21 or higher
- Linux operating system (uses AF_PACKET raw sockets)
- Root privileges for raw socket access and iptables (run with `sudo`)

## Installation

```bash
git clone <your-repo>
cd nids
go build -o nids main.go
```

## Usage

Run the NIDS with root privileges:

```bash
sudo go run main.go
```

### CLI Menu Options

1. **Select Network Interface**: Choose from available network interfaces (e.g., wlan0, eth0)
2. **Set Detection Threshold**: Configure packets/second threshold for DDoS detection (default: 500)
3. **Enable IP Blocking**: Optionally enable automatic iptables blocking of suspicious IPs

### Example Output

```
=== Network Intrusion Detection System ===

Available network interfaces:
1. wlan0
2. eth0
3. lo

Select interface (1-3): 1

Set DDoS detection threshold (packets/sec) [default: 500]: 1000

Enable automatic IP blocking with iptables? (y/N): y

🚀 Starting NIDS monitoring on interface wlan0 with threshold 1000 packets/sec
📡 Packet capture started on wlan0
🔍 Anomaly detection started
🚨 Alert handler started
Press Ctrl+C to stop monitoring...

⚠️ ALERT: Possible DDoS detected from 192.168.1.100, packet rate = 1250.45 packets/sec
🚫 Blocking IP: 192.168.1.100
✅ Successfully blocked IP 192.168.1.100
```

## Architecture

### Core Components

1. **PacketInfo**: Structure containing extracted packet data
2. **DeviceStats**: Per-IP statistics tracking
3. **NIDS**: Main system structure with channels and configuration

### Key Functions

- `capturePackets()`: Captures network packets using raw sockets
- `parsePacket()`: Parses raw packet data (Ethernet, IP, TCP/UDP headers)
- `detectAnomalies()`: Analyzes traffic patterns for threats
- `alertHandler()`: Processes alerts and takes action
- `blockIP()`: Blocks malicious IPs using iptables

### Raw Socket Implementation

- **Ethernet Header Parsing**: Extracts MAC addresses and EtherType
- **IPv4 Header Parsing**: Extracts source/destination IPs and protocol
- **TCP/UDP Header Parsing**: Extracts source/destination ports
- **Manual Packet Processing**: No external dependencies for packet capture

### Concurrency Design

- **Packet Capture**: Runs in separate goroutine to avoid blocking
- **Anomaly Detection**: Processes packets and calculates rates continuously
- **Alert Handling**: Manages alerts and IP blocking in dedicated goroutine
- **Channels**: Used for communication between components

## Extending the System

The modular design allows easy extension:

1. **Port Scan Detection**: Add logic in `detectAnomalies()`
2. **Additional Protocols**: Extend `extractPacketInfo()` 
3. **Different Actions**: Modify `alertHandler()` for custom responses
4. **Logging**: Add structured logging throughout the system

## Security Notes

- Requires root privileges for packet capture
- iptables rules persist after program exit
- Consider firewall impact when enabling IP blocking
- Monitor system resources during high-traffic scenarios

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with `sudo`
2. **No Interfaces Found**: Check network interface availability
3. **Import Errors**: Run `go mod tidy` to download dependencies
4. **iptables Errors**: Ensure sudo privileges and iptables availability

### Performance Tuning

- Adjust channel buffer sizes for high-traffic environments
- Modify packet rate calculation smoothing factor
- Tune detection thresholds based on network characteristics