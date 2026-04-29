package main

// =============================================
// PAYLOAD BANK — Full library with [ua] support
// =============================================

var payloadList = []struct {
	Name     string
	Template string
}{
	// =============================================
	// BASIC PAYLOADS
	// =============================================
	{
		Name:     "Basic CONNECT",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host]:443[crlf][crlf]",
	},
	{
		Name:     "GET Method",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf][crlf]",
	},
	{
		Name:     "HEAD Method",
		Template: "HEAD / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf][crlf]",
	},
	{
		Name:     "OPTIONS Method",
		Template: "OPTIONS / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf][crlf]",
	},

	// =============================================
	// RARE HTTP METHODS (FIREWALL BYPASS)
	// =============================================
	{
		Name:     "PATCH Method",
		Template: "PATCH / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf][crlf]",
	},
	{
		Name:     "PUT Method",
		Template: "PUT / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: keep-alive[crlf][crlf]",
	},
	{
		Name:     "DELETE Method",
		Template: "DELETE / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf][crlf]",
	},

	// 🔥 NEW: PATCH + Double Host + WS
	{
		Name:     "PATCH Double Host WS",
		Template: "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: example.com[crlf]Service: SSH[crlf]ModeX: Bypass[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]",
	},

	// =============================================
	// SOCIAL MEDIA IMPERSONATION
	// =============================================
	{
		Name:     "FBAV Facebook",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: FBAV/0.0.0[crlf]X-FB-HTTP-Engine: Liger[crlf][crlf]",
	},
	{
		Name:     "WhatsApp Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: WhatsApp/2.0[crlf][crlf]",
	},
	{
		Name:     "Instagram Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Instagram 219.0.0.0.117 Android[crlf][crlf]",
	},
	{
		Name:     "Telegram Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Telegram/Android[crlf][crlf]",
	},
	{
		Name:     "Twitter/X Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: TwitterAndroid/10[crlf][crlf]",
	},

	// =============================================
	// PROXY FORWARDING
	// =============================================
	{
		Name:     "Proxy Forward",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Forwarded-For: 31.13.64.39[crlf][crlf]",
	},
	{
		Name:     "FBAV + Proxy",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: FBAV/0.0.0[crlf]X-Forwarded-For: 157.240.1.35[crlf][crlf]",
	},
	{
		Name:     "Double Proxy",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Forwarded-For: 31.13.64.39[crlf]X-Forwarded-Host: [host][crlf][crlf]",
	},

	// 🔥 NEW: Proxy Keep-Alive + Custom Header
	{
		Name:     "Proxy Keep-Alive Custom",
		Template: "CONNECT [host]:[port] HTTP/1.1[crlf]x-connected-to: 34.143.72.2[crlf]proxy-connection: keep-alive[crlf]connection: keep-alive[crlf]user-agent: FBAV/0.0[crlf]x-iorg-bsid: @AM2_D3[crlf][crlf]",
	},

	// =============================================
	// CDN FRONTING
	// =============================================
	{
		Name:     "CloudFront Style",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Amazon CloudFront[crlf]X-Amz-Cf-Id: test123[crlf][crlf]",
	},
	{
		Name:     "Cloudflare Style",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Cloudflare Worker[crlf]CF-RAY: test123[crlf][crlf]",
	},
	{
		Name:     "Akamai Style",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Akamai Edge[crlf]X-Akamai-Request-ID: test123[crlf][crlf]",
	},

	// =============================================
	// HTTP CUSTOM / INJECTOR STYLE
	// =============================================
	{
		Name:     "HTTP Custom Style",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Online-Host: [host][crlf]Connection: Keep-Alive[crlf][crlf]",
	},
	{
		Name:     "Maxis/Unifi Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Online-Host: [host][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]",
	},
	{
		Name:     "Celcom/Digi Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Forwarded-For: 10.0.0.1[crlf]Proxy-Authorization: Basic[crlf][crlf]",
	},

	// =============================================
	// WEBSOCKET UPGRADE
	// =============================================
	{
		Name:     "WebSocket Upgrade",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf][crlf]",
	},
	{
		Name:     "SSH Service Bypass",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]",
	},
	{
		Name:     "VPN Bypass Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Service: VPN[crlf]Mode: Bypass[crlf][crlf]",
	},

	// 🔥 NEW: Split Payload + Rotate + WS FULL
	{
		Name:     "Split-Rotate-WS Full",
		Template: "PUT / HTTP/1.1[crlf]Host: [host][crlf][crlf][split][crlf][crlf]X / HTTP/1.1[crlf]Host: [host][crlf][crlf]GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Backend: tunnel[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]",
	},

	// 🔥 NEW: WebSocket + Custom Backend
	{
		Name:     "WS + Backend Custom",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Backend: @vps[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]",
	},
}