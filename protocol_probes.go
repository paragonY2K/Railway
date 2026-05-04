package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// =============================================
// SSH PROBE — Detect SSH tunnels
// =============================================

func sshProbe(ip string, port int) (bool, string) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}

	banner := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(banner, "SSH-") {
		return true, banner
	}
	return false, banner
}

// =============================================
// SLOW DNS PROBE — Detect DNS tunnels
// =============================================

func slowDNSProbe(ip string, port int) (bool, string) {
	if port == 0 {
		port = 53
	}
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", address, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Simple DNS query for google.com
	dnsQuery := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(dnsQuery)
	if err != nil {
		return false, ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}

	if n > 12 {
		return true, fmt.Sprintf("DNS response: %d bytes", n)
	}
	return false, ""
}

// =============================================
// MULTI-PROTOCOL DETECTOR
// =============================================

type ProtocolResult struct {
	Type    string
	Banner  string
	Port    int
	Working bool
}

func detectProtocol(ip string, port int) ProtocolResult {
	result := ProtocolResult{Port: port}

	// Test SSH first
	sshOK, sshBanner := sshProbe(ip, port)
	if sshOK {
		result.Type = "SSH"
		result.Banner = sshBanner
		result.Working = true
		return result
	}

	// Test SlowDNS if port 53 or port 80
	if port == 53 || port == 80 || port == 443 || port == 8080 {
		dnsOK, dnsBanner := slowDNSProbe(ip, 53)
		if dnsOK {
			result.Type = "SLOWDNS"
			result.Banner = dnsBanner
			result.Port = 53
			result.Working = true
			return result
		}
	}

	return result
}
