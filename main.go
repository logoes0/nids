package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Header structures for packet parsing
type EthernetHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

type IPv4Header struct {
	VersionIHL     uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP          uint32
	DstIP          uint32
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// PacketInfo represents extracted packet information
type PacketInfo struct {
	Timestamp time.Time
	SourceIP  string
	DestIP    string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Length    int
}

// DeviceStats tracks packet statistics per device
type DeviceStats struct {
	PacketCount int64
	LastSeen    time.Time
	PacketRate  float64
}

// NIDS represents the Network Intrusion Detection System
type NIDS struct {
	Interface    string
	Threshold    int
	DeviceStats  map[string]*DeviceStats
	StatsMutex   sync.RWMutex
	PacketChan   chan PacketInfo
	AlertChan    chan string
	StopChan     chan bool
	BlockEnabled bool
}

// NewNIDS creates a new NIDS instance
func NewNIDS() *NIDS {
	return &NIDS{
		DeviceStats:  make(map[string]*DeviceStats),
		PacketChan:   make(chan PacketInfo, 1000),
		AlertChan:    make(chan string, 100),
		StopChan:     make(chan bool),
		BlockEnabled: false,
	}
}

func main() {
	nids := NewNIDS()

	// Show CLI menu
	if !showMenu(nids) {
		return
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start monitoring components
	go nids.capturePackets()
	go nids.detectAnomalies()
	go nids.alertHandler()

	fmt.Printf("🚀 Starting NIDS monitoring on interface %s with threshold %d packets/sec\n",
		nids.Interface, nids.Threshold)
	fmt.Println("Press Ctrl+C to stop monitoring...")

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\n🛑 Shutting down NIDS...")
	close(nids.StopChan)
	time.Sleep(time.Second) // Give goroutines time to cleanup
}

// showMenu displays CLI menu and configures NIDS
func showMenu(nids *NIDS) bool {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== Network Intrusion Detection System ===")

	// Select network interface
	interfaces := getNetworkInterfaces()
	if len(interfaces) == 0 {
		fmt.Println("❌ No network interfaces found")
		return false
	}

	fmt.Println("\nAvailable network interfaces:")
	for i, iface := range interfaces {
		fmt.Printf("%d. %s\n", i+1, iface)
	}

	for {
		fmt.Print("\nSelect interface (1-", len(interfaces), "): ")
		if !scanner.Scan() {
			return false
		}

		choice, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil || choice < 1 || choice > len(interfaces) {
			fmt.Println("❌ Invalid selection. Please try again.")
			continue
		}

		nids.Interface = interfaces[choice-1]
		break
	}

	// Set packet threshold
	for {
		fmt.Print("\nSet DDoS detection threshold (packets/sec) [default: 500]: ")
		if !scanner.Scan() {
			return false
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			nids.Threshold = 500
			break
		}

		threshold, err := strconv.Atoi(input)
		if err != nil || threshold < 1 {
			fmt.Println("❌ Invalid threshold. Please enter a positive number.")
			continue
		}

		nids.Threshold = threshold
		break
	}

	// Optional: Enable automatic IP blocking
	fmt.Print("\nEnable automatic IP blocking with iptables? (y/N): ")
	if scanner.Scan() {
		response := strings.ToLower(strings.TrimSpace(scanner.Text()))
		nids.BlockEnabled = (response == "y" || response == "yes")
	}

	return true
}

// getNetworkInterfaces returns list of available network interfaces
func getNetworkInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error finding interfaces: %v", err)
		return nil
	}

	var validInterfaces []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			validInterfaces = append(validInterfaces, iface.Name)
		}
	}

	return validInterfaces
}

// htons converts host byte order to network byte order (16-bit)
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ntohs converts network byte order to host byte order (16-bit)
func ntohs(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ntohl converts network byte order to host byte order (32-bit)
func ntohl(i uint32) uint32 {
	return (i<<24)&0xff000000 | (i<<8)&0xff0000 | (i>>8)&0xff00 | i>>24
}

// capturePackets captures network packets using raw sockets
func (n *NIDS) capturePackets() {
	fmt.Println("📡 Opening raw socket for packet capture...")

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Printf("❌ Error creating raw socket: %v", err)
		log.Printf("💡 Make sure to run with sudo privileges")
		return
	}
	defer syscall.Close(fd)

	// Bind to specific interface if provided
	if n.Interface != "" {
		iface, err := net.InterfaceByName(n.Interface)
		if err != nil {
			log.Printf("❌ Error finding interface %s: %v", n.Interface, err)
			return
		}

		// Bind socket to interface
		addr := &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_ALL),
			Ifindex:  iface.Index,
		}

		err = syscall.Bind(fd, addr)
		if err != nil {
			log.Printf("❌ Error binding to interface %s: %v", n.Interface, err)
			return
		}
	}

	fmt.Printf("📡 Raw socket packet capture started on %s\n", n.Interface)

	buf := make([]byte, 65536)

	for {
		select {
		case <-n.StopChan:
			fmt.Println("📡 Packet capture stopped")
			return
		default:
			// Set read timeout to avoid blocking indefinitely
			syscall.SetNonblock(fd, true)
			bytesRead, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				log.Printf("❌ Error receiving packet: %v", err)
				continue
			}

			if bytesRead > 0 {
				packetInfo := n.parsePacket(buf[:bytesRead])
				if packetInfo != nil {
					select {
					case n.PacketChan <- *packetInfo:
					default:
						// Channel full, drop packet to prevent blocking
					}
				}
			}
		}
	}
}

// parsePacket parses raw packet data and extracts information
func (n *NIDS) parsePacket(data []byte) *PacketInfo {
	if len(data) < 14 {
		return nil // Too small for Ethernet header
	}

	// Parse Ethernet header
	ethHeader := (*EthernetHeader)(unsafe.Pointer(&data[0]))
	etherType := ntohs(ethHeader.EtherType)

	fmt.Printf("🔍 Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x, Type: 0x%04x\n",
		ethHeader.SrcMAC[0], ethHeader.SrcMAC[1], ethHeader.SrcMAC[2],
		ethHeader.SrcMAC[3], ethHeader.SrcMAC[4], ethHeader.SrcMAC[5],
		ethHeader.DstMAC[0], ethHeader.DstMAC[1], ethHeader.DstMAC[2],
		ethHeader.DstMAC[3], ethHeader.DstMAC[4], ethHeader.DstMAC[5],
		etherType)

	// Check if it's IPv4
	if etherType != 0x0800 {
		return nil // Not IPv4
	}

	// Parse IPv4 header
	if len(data) < 34 {
		return nil // Too small for IP header
	}

	ipHeader := (*IPv4Header)(unsafe.Pointer(&data[14]))
	headerLength := (ipHeader.VersionIHL & 0x0F) * 4

	if len(data) < 14+int(headerLength) {
		return nil // Incomplete IP header
	}

	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, ipHeader.SrcIP)
	binary.BigEndian.PutUint32(dstIP, ipHeader.DstIP)

	protocol := ""
	var srcPort, dstPort uint16

	fmt.Printf("📦 IPv4: %s -> %s, Protocol: %d, Length: %d\n",
		srcIP.String(), dstIP.String(), ipHeader.Protocol, ntohs(ipHeader.TotalLength))

	// Parse transport layer
	transportOffset := 14 + int(headerLength)

	switch ipHeader.Protocol {
	case 6: // TCP
		protocol = "TCP"
		if len(data) >= transportOffset+4 {
			tcpHeader := (*TCPHeader)(unsafe.Pointer(&data[transportOffset]))
			srcPort = ntohs(tcpHeader.SrcPort)
			dstPort = ntohs(tcpHeader.DstPort)
			fmt.Printf("🔌 TCP: %s:%d -> %s:%d\n", srcIP.String(), srcPort, dstIP.String(), dstPort)
		}
	case 17: // UDP
		protocol = "UDP"
		if len(data) >= transportOffset+4 {
			udpHeader := (*UDPHeader)(unsafe.Pointer(&data[transportOffset]))
			srcPort = ntohs(udpHeader.SrcPort)
			dstPort = ntohs(udpHeader.DstPort)
			fmt.Printf("🔌 UDP: %s:%d -> %s:%d\n", srcIP.String(), srcPort, dstIP.String(), dstPort)
		}
	case 1: // ICMP
		protocol = "ICMP"
		fmt.Printf("🔌 ICMP: %s -> %s\n", srcIP.String(), dstIP.String())
	default:
		protocol = fmt.Sprintf("Protocol-%d", ipHeader.Protocol)
	}

	return &PacketInfo{
		Timestamp: time.Now(),
		SourceIP:  srcIP.String(),
		DestIP:    dstIP.String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Length:    len(data),
	}
}

// detectAnomalies analyzes packet patterns and detects potential threats
func (n *NIDS) detectAnomalies() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Println("🔍 Anomaly detection started")

	for {
		select {
		case <-n.StopChan:
			fmt.Println("🔍 Anomaly detection stopped")
			return
		case packetInfo := <-n.PacketChan:
			n.updateDeviceStats(packetInfo)
		case <-ticker.C:
			n.checkForAnomalies()
		}
	}
}

// updateDeviceStats updates packet statistics for a device
func (n *NIDS) updateDeviceStats(packetInfo PacketInfo) {
	n.StatsMutex.Lock()
	defer n.StatsMutex.Unlock()

	sourceIP := packetInfo.SourceIP

	stats, exists := n.DeviceStats[sourceIP]
	if !exists {
		stats = &DeviceStats{
			PacketCount: 0,
			LastSeen:    packetInfo.Timestamp,
			PacketRate:  0,
		}
		n.DeviceStats[sourceIP] = stats
	}

	stats.PacketCount++

	// Calculate packet rate (packets per second)
	timeDiff := packetInfo.Timestamp.Sub(stats.LastSeen).Seconds()
	if timeDiff > 0 {
		// Smooth the rate calculation using exponential moving average
		newRate := 1.0 / timeDiff
		stats.PacketRate = 0.8*stats.PacketRate + 0.2*newRate
	}

	stats.LastSeen = packetInfo.Timestamp
}

// checkForAnomalies checks for suspicious activity patterns
func (n *NIDS) checkForAnomalies() {
	n.StatsMutex.RLock()
	defer n.StatsMutex.RUnlock()

	now := time.Now()

	for ip, stats := range n.DeviceStats {
		// Skip if device hasn't been seen recently (last 5 seconds)
		if now.Sub(stats.LastSeen) > 5*time.Second {
			continue
		}

		// Check for DDoS-like behavior
		if stats.PacketRate > float64(n.Threshold) {
			alertMsg := fmt.Sprintf("⚠️ ALERT: Possible DDoS detected from %s, packet rate = %.2f packets/sec",
				ip, stats.PacketRate)

			select {
			case n.AlertChan <- alertMsg:
			default:
				// Alert channel full, skip
			}
		}
	}
}

// alertHandler handles security alerts and takes appropriate actions
func (n *NIDS) alertHandler() {
	alertedIPs := make(map[string]time.Time)

	fmt.Println("🚨 Alert handler started")

	for {
		select {
		case <-n.StopChan:
			fmt.Println("🚨 Alert handler stopped")
			return
		case alertMsg := <-n.AlertChan:
			fmt.Println(alertMsg)

			// Extract IP from alert message for blocking
			if n.BlockEnabled {
				ip := extractIPFromAlert(alertMsg)
				if ip != "" {
					// Prevent spam blocking - only block once per IP per hour
					if lastBlocked, exists := alertedIPs[ip]; !exists || time.Since(lastBlocked) > time.Hour {
						n.blockIP(ip)
						alertedIPs[ip] = time.Now()
					}
				}
			}
		}
	}
}

// extractIPFromAlert extracts IP address from alert message
func extractIPFromAlert(alertMsg string) string {
	// Simple regex-like extraction from the alert format
	parts := strings.Split(alertMsg, " ")
	for i, part := range parts {
		if part == "from" && i+1 < len(parts) {
			ip := strings.TrimSuffix(parts[i+1], ",")
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return ""
}

// blockIP blocks an IP address using iptables
func (n *NIDS) blockIP(ip string) {
	fmt.Printf("🚫 Blocking IP: %s\n", ip)

	// Add iptables rule to drop packets from this IP
	cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("❌ Failed to block IP %s: %v\n", ip, err)
	} else {
		fmt.Printf("✅ Successfully blocked IP %s\n", ip)
	}
}
