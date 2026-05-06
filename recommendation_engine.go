package main

import (
	"fmt"
	"strconv"
	"strings"
)

// =============================================
// RECOMMENDATION ENGINE - ACTUAL STRUCTURES
// =============================================

type RecommendConfig struct {
	Type       string
	Network    string
	Security   string
	Payload    string
	SNI        string
	Port       int
	AppList    string
	Source     string
	Note       string
	HostHeader string
}

func getRecommendation(host string, ip string, port int, server string, httpStatus string, detectLabel string, info tlsInfo) RecommendConfig {
	var rec RecommendConfig
	cdn := detectCDNByIP(ip)
	serverLower := strings.ToLower(server)
	cnLower := strings.ToLower(info.CommonName)

	rec.Port = port

	switch {
	// =============================================
	// WEBSOCKET ON PORT 80 - VIU CDN PATTERN
	// Source: cfcdn.viu.com.ls2.dcdn.fun VLESS Config
	// =============================================
	case detectLabel == "WS" && port == 80:
		rec.Type = "VLESS / VMess WebSocket"
		rec.Network = "ws"
		rec.Security = "none"
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom, NapsternetV"
		rec.Source = "CDN WebSocket Config"
		rec.Note = "⚠️ Port 80 = No TLS. SNI not needed."

	// =============================================
	// WEBSOCKET ON PORT 443 WITH TLS
	// =============================================
	case detectLabel == "WS" && port == 443:
		rec.Type = "VLESS / VMess WebSocket TLS"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = info.CommonName
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]User-Agent: [ua][crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom"
		rec.Source = "WebSocket TLS Config"

	// =============================================
	// HDFC BANK PATTERN
	// Source: Dark Tunnel SSH Config (netbanking.hdfcbank.com)
	// =============================================
	case strings.Contains(host, "hdfc") || strings.Contains(host, "bank") || strings.Contains(host, "maybank"):
		rec.Type = "SSH / VLESS (Banking Proxy)"
		rec.Network = "ws"
		rec.Security = "none"
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]X-Online-Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "Dark Tunnel, HTTP Custom, NapsternetV"
		rec.Source = "HDFC Bank Config (verified working)"
		rec.Note = "🏦 Banking domain. X-Online-Host header is CRITICAL!"

	// =============================================
	// FACEBOOK INJECT PATTERN
	// Source: VLESS Inject Config (31.13.64.39 Facebook IP)
	// =============================================
	case strings.Contains(cnLower, "facebook") || strings.Contains(cnLower, "fbcdn") || strings.Contains(ip, "31.13.") || strings.Contains(ip, "157.240."):
		rec.Type = "VLESS / VMess Inject (Facebook)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = "*.facebook.com"
		rec.Payload = "CONNECT [host]:443 HTTP/1.1[crlf]x-connected-to: iorg-fba-edge-shv-02-ccu1.facebook.com[crlf]user-agent: FBAV/0.0.0[crlf]x-iorg-bsid: @Data[crlf][crlf]"
		rec.AppList = "Dark Tunnel, HTTP Custom"
		rec.Source = "Facebook Inject Config (verified working)"
		rec.Note = "👤 Facebook impersonation. ALL 3 headers are CRITICAL!"

	// =============================================
	// CLOUDFLARE CDN PATTERN
	// Source: Multiple CDN bughost configs
	// =============================================
	case cdn == "CLOUDFLARE" || strings.Contains(serverLower, "cloudflare"):
		rec.Type = "VMess / VLESS CDN Fronting"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Cloudflare Worker[crlf]CF-RAY: test123[crlf]Accept: */*[crlf]Connection: keep-alive[crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom, NapsternetV"
		rec.Source = "CDN Bughost Config (verified working)"
		rec.Note = "☁️ Cloudflare detected. CF-RAY header is CRITICAL!"

	// =============================================
	// GOOGLE ECOSYSTEM PATTERN
	// Source: YouTube VLESS Config
	// =============================================
	case cdn == "GOOGLE/GWS" || strings.Contains(serverLower, "sffe") || strings.Contains(serverLower, "gws") || strings.Contains(cnLower, "google"):
		rec.Type = "VLESS / Trojan (Google Ecosystem)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = "googlevideo.com"
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Accept: */*[crlf]Accept-Encoding: gzip, deflate[crlf]Accept-Language: en-US[crlf]Connection: keep-alive[crlf][crlf]"
		rec.AppList = "V2RayNG, Sing-box"
		rec.Source = "YouTube VLESS Config (verified working)"
		rec.Note = "🌐 Google infra. Try SNI: googlevideo.com, youtube.com"

	// =============================================
	// DATING SITE / DUAL PAYLOAD PATTERN
	// Source: NPV Tunnel Config (media.elitedating.nl)
	// =============================================
	case strings.Contains(host, "dating") || strings.Contains(host, "elite") || strings.Contains(detectLabel, "DUAL"):
		rec.Type = "SSH (Dual Payload)"
		rec.Network = "ws"
		rec.Security = "none"
		rec.Payload = "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: chann-sp.twitter.com[crlf][crlf]GET-RAY / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "NPV Tunnel, HTTP Custom"
		rec.Source = "NPV Tunnel Config (verified working)"
		rec.Note = "🔥 DUAL payload! First mimics Cloudflare, second upgrades to WS."

	// =============================================
	// BLOGSPOT / GOOGLE CLOUD RUN PATTERN
	// Source: VLESS Inject Config (zain.blogblog.com)
	// =============================================
	case strings.Contains(host, "blogspot") || strings.Contains(host, "blogblog") || strings.Contains(host, "run.app"):
		rec.Type = "VLESS (Google Cloud Backend)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom"
		rec.Source = "VLESS Google Cloud Config (verified working)"
		rec.Note = "☁️ Google Cloud Run backend. Blogspot domain = trusted."

	// =============================================
	// CLOUDFLARE IP AS SNI PATTERN
	// Source: HTTP Tweak Config (104.18.14.222)
	// =============================================
	case strings.Contains(info.CommonName, "104.") || strings.Contains(info.CommonName, "172."):
		rec.Type = "HTTP Tweak / Custom"
		rec.Network = "tcp"
		rec.Security = "none"
		rec.Payload = "CONNECT [host_port] HTTP/1.1[crlf]Host: www.freesite.com[crlf][crlf]"
		rec.AppList = "HTTP Tweak VPN"
		rec.Source = "HTTP Tweak Config (verified working)"
		rec.Note = "☁️ Cloudflare IP used as SNI. Use with HTTP Tweak app."

	// =============================================
	// GRPC PATTERN
	// Source: VLESS gRPC Config
	// =============================================
	case detectLabel == "GRPC" || strings.Contains(serverLower, "grpc"):
		rec.Type = "VLESS gRPC"
		rec.Network = "grpc"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "(gRPC — auto-handled by core)"
		rec.AppList = "V2RayNG, Sing-box"
		rec.Source = "VLESS gRPC Config (verified working)"
		rec.Note = "⚡ gRPC + TLS Fragment. Use chrome fingerprint."

	// =============================================
	// SSH TUNNEL DETECTED
	// =============================================
	case detectLabel == "SSH_TUNNEL":
		rec.Type = "SSH Tunnel (Direct)"
		rec.Security = "none"
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
		rec.AppList = "Dark Tunnel, HTTP Custom, NapsternetV"
		rec.Source = "Dark Tunnel SSH Config (verified working)"
		rec.Note = "🔐 SSH protocol detected. Works with proxy payload."

	// =============================================
	// SLOWDNS DETECTED
	// =============================================
	case detectLabel == "SLOWDNS":
		rec.Type = "SlowDNS Tunnel"
		rec.Security = "none"
		rec.Port = 53
		rec.Payload = "(DNS query — auto-generated by app)"
		rec.AppList = "SlowDNS"
		rec.Source = "SlowDNS Config"
		rec.Note = "🐢 SlowDNS detected. Use with SlowDNS app."

	// =============================================
	// AKAMAI CDN PATTERN
	// =============================================
	case cdn == "AKAMAI" || strings.Contains(serverLower, "akamai"):
		rec.Type = "VMess / VLESS CDN (Akamai)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Akamai Edge[crlf]X-Akamai-Request-ID: test123[crlf]Connection: keep-alive[crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom"
		rec.Source = "Akamai CDN Config (verified working)"
		rec.Note = "🛡️ Akamai detected. X-Akamai-Request-ID is CRITICAL!"

	// =============================================
	// SNI SPOOF PATTERN
	// Source: YouTube VLESS Config
	// =============================================
	case detectLabel == "SPOOF" || detectLabel == "H3_QUIC":
		rec.Type = "VLESS / Trojan TLS (SNI Spoof)"
		rec.Network = "ws"
		rec.Security = "tls"
		if info.CommonName != "" && info.CommonName != host {
			rec.SNI = info.CommonName
		} else {
			rec.SNI = "facebook.com"
		}
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Accept: */*[crlf]Connection: keep-alive[crlf][crlf]"
		rec.AppList = "V2RayNG, Sing-box"
		rec.Source = "YouTube VLESS Config (verified working)"
		rec.Note = "🎭 SNI Spoof works! Try: google.com, facebook.com, cloudflare.com"

	// =============================================
	// REALITY TUNNEL
	// =============================================
	case detectLabel == "REALITY":
		rec.Type = "VLESS Reality Tunnel"
		rec.Network = "raw"
		rec.Security = "reality"
		rec.SNI = info.CommonName
		rec.Payload = "(Reality — auto-handled by core)"
		rec.AppList = "V2RayNG, Sing-box"
		rec.Source = "Reality Tunnel Config"
		rec.Note = "🔮 Reality tunnel. Most stealth protocol."

	case strings.Contains(host, "youtube") || strings.Contains(host, "google") || strings.Contains(host, "run.app"):
		rec.Type = "VLESS + Inject (YouTube/Google)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "[method] [host_port] [protocol][crlf]Host: [host/vps][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]"
		rec.AppList = "Dark Tunnel, HTTP Custom"
		rec.Source = "YouTube VLESS Inject Config (verified working)"
		rec.Note = "🔐 SSH Bypass headers! 'Service: SSH' + 'Mode: Bypass' are CRITICAL!"

	case strings.Contains(host, "run.app"):
		rec.Type = "Trojan / VLESS (Google Cloud Run)"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "" // Trojan = no payload needed
		rec.AppList = "V2RayNG, Sing-box"
		rec.Source = "Trojan Google Cloud Run Config (verified working)"
		rec.Note = "☁️ Google Cloud Run backend. Direct TLS — NO payload needed!"

	// =============================================
	// DEFAULT
	// =============================================
	default:
		rec.Type = "Standard TLS Tunnel"
		rec.Network = "ws"
		rec.Security = "tls"
		rec.SNI = host
		rec.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf]Upgrade: websocket[crlf][crlf]"
		rec.AppList = "V2RayNG, HTTP Custom, NapsternetV"
		rec.Source = "Generic Config"
	}

	// Port-specific adjustments
	if port == 80 && rec.Security == "tls" {
		rec.Note += "\n⚠️ Port 80 has no TLS!"
		rec.Security = "none"
	}
	if port == 8080 || port == 8880 {
		rec.Note += "\n📌 Alternative port. Test with different payloads."
	}

	return rec
}

func formatRecommendation(host string, rec RecommendConfig) string {
	output := fmt.Sprintf(`💡 %s

📋 %s:
%s: %s
%s: %d
%s: %s
%s: %s`,
		toBoldUnicode("Ready to Use (Verified Template):"),
		toBoldUnicode("Bughost"),
		toBoldUnicode("Address"), host,
		toBoldUnicode("Port"), rec.Port,
		toBoldUnicode("Network"), rec.Network,
		toBoldUnicode("Security"), rec.Security,
	)

	if rec.SNI != "" {
		output += fmt.Sprintf("\n%s: %s", toBoldUnicode("SNI"), rec.SNI)
	}

	if rec.Payload != "" {
		output += fmt.Sprintf(`

💉 %s:
%s

💡 %s:
• [host] = This bughost OR your VPS`,
			toBoldUnicode("Payload (for port "+strconv.Itoa(rec.Port)+")"),
			rec.Payload,
			toBoldUnicode("Notes"),
		)
	} else {
		output += fmt.Sprintf(`

💡 %s:
🔐 Direct TLS — NO payload needed!
• Just set Address + Port + SNI
• Works with Trojan, VLESS TLS, Shadowsocks`,
			toBoldUnicode("Notes"),
		)
	}

	output += fmt.Sprintf(`

📱 %s: %s
📋 %s: %s`,
		toBoldUnicode("Apps"), rec.AppList,
		toBoldUnicode("Source"), rec.Source,
	)

	if rec.Note != "" {
		output += fmt.Sprintf("\n\n%s", rec.Note)
	}

	return output
}
