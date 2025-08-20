#!/bin/bash

# NIDS Demo Test Script
# This script demonstrates the NIDS functionality

echo "=== NIDS Demo Test Script ==="
echo "This script will help you test the Network Intrusion Detection System"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This demo requires root privileges for packet capture"
    echo "Please run: sudo ./test_demo.sh"
    exit 1
fi

echo "✅ Running with root privileges"
echo ""

# Check if NIDS binary exists
if [ ! -f "./nids" ]; then
    echo "📦 Building NIDS application..."
    go build -o nids main.go
    if [ $? -ne 0 ]; then
        echo "❌ Failed to build NIDS"
        exit 1
    fi
    echo "✅ NIDS built successfully"
fi

echo "🚀 Starting NIDS application..."
echo "Note: The application will show an interactive menu"
echo "Suggested test configuration:"
echo "  - Select any active network interface (usually wlan0 or eth0)"
echo "  - Set threshold to 100 packets/sec for easier testing"
echo "  - Enable or disable IP blocking as desired"
echo ""
echo "To generate test traffic for DDoS detection, you can:"
echo "  1. Open another terminal"
echo "  2. Run: ping -f <some_ip_address> (flood ping)"
echo "  3. Or use: hping3 -i u1 <target_ip> (if installed)"
echo ""
echo "Press Enter to start NIDS..."
read

./nids

