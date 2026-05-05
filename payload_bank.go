package main

// =============================================
// PAYLOAD BANK — 28 Power Payloads
// Format: TAB indentation for phone editor
// =============================================

var payloadList = []struct {
	Name     string
	Template string
}{
	// =============================================
	// BASIC METHODS (PROVEN)
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
	// SOCIAL MEDIA (PROVEN)
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
	{
		Name:     "Facebook API Mimic Style",
		Template: "GET http://h.facebook.com/hr/zsh/api?h_token=[token] HTTP/1.1[crlf]Host: h.facebook.com[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]CONNECT [host_port] [protocol][crlf][crlf]",
	},

	// =============================================
	// PROXY FORWARDING (PROVEN)
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
	{
		Name:     "Proxy Keep-Alive Custom",
		Template: "CONNECT [host]:[port] HTTP/1.1[crlf]x-connected-to: 34.143.72.2[crlf]proxy-connection: keep-alive[crlf]connection: keep-alive[crlf]user-agent: FBAV/0.0[crlf]x-iorg-bsid: @AM2_D3[crlf][crlf]",
	},

	// =============================================
	// HTTP CUSTOM STYLE (PROVEN)
	// =============================================
	{
		Name:     "HTTP Custom Style",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]X-Online-Host: [host][crlf]Connection: Keep-Alive[crlf][crlf]",
	},
	{
		Name:     "GoogleBot UA",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)[crlf][crlf]",
	},

	// =============================================
	// WEBSOCKET UPGRADE (PROVEN)
	// =============================================
	{
		Name:     "WebSocket Upgrade",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf][crlf]",
	},
	{
		Name:     "SNI Upgrade WS",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]User-Agent: [ua][crlf][crlf]",
	},
	{
		Name:     "WS + Backend Custom",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Backend: @vps[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]",
	},

	// =============================================
	// SERVICE BYPASS (PROVEN)
	// =============================================
	{
		Name:     "SSH Service Bypass",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]",
	},
	{
		Name:     "VPN Bypass Style",
		Template: "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Service: VPN[crlf]Mode: Bypass[crlf][crlf]",
	},

	// =============================================
	// CONNECT TUNNEL (PROVEN)
	// =============================================
	{
		Name:     "CONNECT Tunnel 80",
		Template: "CONNECT [host]:80 HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf][crlf]",
	},

	// =============================================
	// ADVANCED — SPLIT TRICK
	// =============================================
	{
		Name:     "Split Trick WS",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf][split]CF-RAY / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]",
	},
	{
		Name:     "Double Host WS",
		Template: "GET / HTTP/1.1[crlf]Host: [host][crlf][split]CF-RAY / HTTP/1.1[crlf]Host: [vps][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]",
	},
	{
		Name:     "PATCH Double Host WS",
		Template: "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: example.com[crlf]Service: SSH[crlf]ModeX: Bypass[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]",
	},

	// =============================================
	// ADVANCED — CF TRACE + WS
	// =============================================
	{
		Name:     "CF Trace Trick",
		Template: "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host][crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]",
	},
	{
		Name:     "Trace WS Upgrade",
		Template: "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host][crlf][split]CF-RAY / HTTP/1.1[crlf]Host: [vps][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
	},
	{
		Name:     "Trace XFF 1111 WS",
		Template: "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host][crlf]X-Forwarded-For: 1.1.1.1[crlf][split]CF-RAY / HTTP/1.1[crlf]Host: [vps][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
	},
	{
		Name:     "PATCH SSH Bypass Style",
		Template: "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: example.com[crlf]Service: SSH[crlf]ModeX: Bypass[crlf]Upgrade: websocket[crlf]User-Agent: [ua][crlf][crlf]",
	},
	{
		Name:     "Dual CDN Trace Style",
		Template: "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host]][crlf][crlf]RNG-RAY / HTTP/1.1[crlf]Host: [host/vps][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
	},
	{
		Name:     "HDFC FLEX UAT Style",
		Template: "GET / HTTP/1.1[crlf]Host:[host][crlf]X-Online-Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
	},
}
