package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// =============================================
// CONFIG VALIDATOR STRUCTS
// =============================================

type UserConfig struct {
	ProxyHost  string
	ProxyPort  int
	SNI        string
	HostHeader string
	Payload    string
	TargetHost string
	TargetPort int
}

type ValidationResult struct {
	Step         string
	Success      bool
	Message      string
	LatencyMs    int
	ResponseCode string
	StatusCode   int
	Server       string
	CFRay        string
	Via          string
	Details      string
}

type FullValidation struct {
	Config  UserConfig
	Steps   []ValidationResult
	Success bool
	Score   int
	Summary string
}

// =============================================
// INTERACTIVE MENU
// =============================================

func showConfigValidatorMenu(chatID int64, messageID int) {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔹 Quick Test", "cfg_quick"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔸 Step by Step", "cfg_step"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📋 From Scan Result", "cfg_scan"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	text := "```\n" +
		"╭─────────────────────────╮\n" +
		"│   ⚙️ CONFIG VALIDATOR    │\n" +
		"╰─────────────────────────╯\n\n" +
		"Select test mode:\n\n" +
		"🔹 Quick — paste config\n" +
		"🔸 Step — fill one by one\n" +
		"📋 Scan — from scanner result\n```"

	if messageID == 0 {
		msg := tgbotapi.NewMessage(chatID, text)
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = &keyboard
		bot.Send(msg)
	} else {
		edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &keyboard
		bot.Send(edit)
	}

	setSessionState(chatID, "config_mode_select")
}

// =============================================
// QUICK TEST HANDLER
// =============================================

func showQuickTestPrompt(chatID int64, messageID int) {
	text := "```\n" +
		"╭─────────────────────────╮\n" +
		"│  ⚙️ QUICK CONFIG TEST   │\n" +
		"╰─────────────────────────╯\n\n" +
		"Send your config:\n\n" +
		"Format: proxy:port|sni|payload|target\n\n" +
		"Examples:\n" +
		"• thebestyou.com:80 (proxy only)\n" +
		"• thebestyou.com:80|nexus.u.com.my (proxy+sni)\n" +
		"• -|nexus.u.com.my|GET /... (sni+payload)\n" +
		"• thebestyou.com:80|-|-|vps.com (proxy+target)\n\n" +
		"Use '-' to skip a field\n```"

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💉 Pick Payload", "cfg_payload_pick"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
	edit.ParseMode = "Markdown"
	edit.ReplyMarkup = &keyboard
	bot.Send(edit)

	setSessionState(chatID, "config_quick_input")
}

// =============================================
// PAYLOAD PICKER
// =============================================

func showPayloadPicker(chatID int64, messageID int) {
	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│   💉 PAYLOAD SELECTOR   │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")
	sb.WriteString("Reply with number (1-28):\n\n")

	for i, p := range payloadList {
		if i >= 28 {
			break
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, p.Name))
	}
	sb.WriteString("```")

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	if messageID == 0 {
		msg := tgbotapi.NewMessage(chatID, sb.String())
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = &keyboard
		bot.Send(msg)
	} else {
		edit := tgbotapi.NewEditMessageText(chatID, messageID, sb.String())
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &keyboard
		bot.Send(edit)
	}

	setSessionState(chatID, "config_payload_select")
}

// =============================================
// STEP BY STEP MODE
// =============================================

func startStepByStep(chatID int64, messageID int) {
	config := UserConfig{}
	session := getSession(chatID)
	session.TempData["step_config"] = config
	session.TempData["step_current"] = 1

	showStepPrompt(chatID, messageID, 1, config)
}

func showStepPrompt(chatID int64, messageID int, step int, config UserConfig) {
	var prompt string
	var state string

	switch step {
	case 1:
		prompt = "```\n╭─────────────────────────╮\n│  ⚙️ STEP 1: PROXY HOST   │\n╰─────────────────────────╯\n\nEnter proxy host:port\n\nExample: thebestyou.com:80\nOr type '-' to skip\n```"
		state = "config_step_proxy"

	case 2:
		prompt = "```\n╭─────────────────────────╮\n│  ⚙️ STEP 2: SNI           │\n╰─────────────────────────╯\n\nEnter SNI (Server Name Indication)\n\nExample: nexus.u.com.my\nOr type '-' to skip\n```"
		state = "config_step_sni"

	case 3:
		prompt = "```\n╭─────────────────────────╮\n│  ⚙️ STEP 3: PAYLOAD       │\n╰─────────────────────────╯\n\nChoose payload option:\n```"

		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("💉 Pick from Payload Bank", "cfg_step_pick_payload"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✏️ Type Custom Payload", "cfg_step_custom_payload"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("⏭️ Skip Payload", "cfg_step_skip_payload"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
			),
		)

		edit := tgbotapi.NewEditMessageText(chatID, messageID, prompt)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &keyboard
		bot.Send(edit)
		setSessionState(chatID, "config_step_payload_choice")
		return

	case 4:
		prompt = "```\n╭─────────────────────────╮\n│  ⚙️ STEP 4: TARGET HOST   │\n╰─────────────────────────╯\n\nEnter target host:port\n\nExample: your-vps.com:443\nOr type '-' to skip\n```"
		state = "config_step_target"

	case 5:
		executeStepValidation(chatID, messageID, config)
		return

	default:
		return
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	if messageID == 0 {
		msg := tgbotapi.NewMessage(chatID, prompt)
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = &keyboard
		bot.Send(msg)
	} else {
		edit := tgbotapi.NewEditMessageText(chatID, messageID, prompt)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &keyboard
		bot.Send(edit)
	}

	setSessionState(chatID, state)
}

func handleStepInput(chatID int64, messageID int, input string) {
	session := getSession(chatID)
	config, _ := session.TempData["step_config"].(UserConfig)
	step, _ := session.TempData["step_current"].(int)

	input = strings.TrimSpace(input)

	switch step {
	case 1:
		if input != "" && input != "-" && input != "skip" {
			if h, p, err := net.SplitHostPort(input); err == nil {
				config.ProxyHost = h
				config.ProxyPort, _ = strconv.Atoi(p)
			} else {
				config.ProxyHost = input
				config.ProxyPort = 443
			}
		}
		step = 2

	case 2:
		if input != "" && input != "-" {
			config.SNI = input
		}
		step = 3

	case 4:
		if input != "" && input != "-" {
			if h, p, err := net.SplitHostPort(input); err == nil {
				config.TargetHost = h
				config.TargetPort, _ = strconv.Atoi(p)
			} else {
				config.TargetHost = input
				config.TargetPort = 443
			}
		}
		step = 5
	}

	session.TempData["step_config"] = config
	session.TempData["step_current"] = step

	summary := configSummary(config)
	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Saved!\n\n📋 Current: %s", summary))
	bot.Send(statusMsg)

	// FIX: Hantar placeholder dulu untuk dapat messageID valid
	sentMsg, _ := bot.Send(tgbotapi.NewMessage(chatID, "⏳ Loading next step..."))
	showStepPrompt(chatID, sentMsg.MessageID, step, config)
}

func executeStepValidation(chatID int64, messageID int, config UserConfig) {
	session := getSession(chatID)
	session.TempData["step_config"] = config

	inputStr := fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort)
	if config.SNI != "" {
		inputStr += "|" + config.SNI
	} else {
		inputStr += "|-"
	}
	if config.Payload != "" {
		inputStr += "|" + config.Payload
	} else {
		inputStr += "|-"
	}
	if config.TargetHost != "" {
		inputStr += fmt.Sprintf("|%s:%d", config.TargetHost, config.TargetPort)
	} else {
		inputStr += "|-"
	}

	clearSessionState(chatID)
	go executeConfigValidation(chatID, inputStr)
}

// =============================================
// FROM SCAN RESULT MODE
// =============================================

func startFromScanResult(chatID int64, messageID int) {
	session := getSession(chatID)
	target, ok := session.TempData["last_scan_target"].(string)

	if !ok || target == "" {
		msg := tgbotapi.NewMessage(chatID, "❌ No scan result found. Run a single scan first!")
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		return
	}

	host, portStr, _ := net.SplitHostPort(target)
	port := 443
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if host == "" {
		host = target
	}

	config := UserConfig{
		ProxyHost: host,
		ProxyPort: port,
		SNI:       host,
	}

	session.TempData["scan_config"] = config

	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│  📋 FROM SCAN RESULT    │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")
	sb.WriteString("Auto-filled from scan:\n")
	sb.WriteString(fmt.Sprintf("   Proxy: %s:%d\n", host, port))
	sb.WriteString(fmt.Sprintf("   SNI: %s\n", host))
	sb.WriteString("\nNow choose payload:\n```")

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💉 Pick Payload", "cfg_scan_pick_payload"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✏️ Type Custom", "cfg_scan_custom_payload"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⏭️ Skip Payload", "cfg_scan_skip_payload"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, messageID, sb.String())
	edit.ParseMode = "Markdown"
	edit.ReplyMarkup = &keyboard
	bot.Send(edit)

	setSessionState(chatID, "config_scan_payload_choice")
}

func runScanValidation(chatID int64) {
	session := getSession(chatID)
	config, ok := session.TempData["scan_config"].(UserConfig)
	if !ok {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ Session expired. Please scan first."))
		clearSessionState(chatID)
		return
	}

	inputStr := fmt.Sprintf("%s:%d|%s", config.ProxyHost, config.ProxyPort, config.SNI)
	if config.Payload != "" {
		inputStr += "|" + config.Payload
	} else {
		inputStr += "|-"
	}
	inputStr += "|-"

	clearSessionState(chatID)
	go executeConfigValidation(chatID, inputStr)
}

// =============================================
// PAYLOAD PICKER HELPERS
// =============================================

func showPayloadPickerForStep(chatID int64, messageID int) {
	showPayloadPicker(chatID, messageID)
	setSessionState(chatID, "config_step_payload_select")
}

func showPayloadPickerForScan(chatID int64, messageID int) {
	showPayloadPicker(chatID, messageID)
	setSessionState(chatID, "config_scan_payload_select")
}

func promptStepCustomPayload(chatID int64, messageID int) {
	text := "```\n✏️ Enter your custom payload:\n\nUse placeholders:\n[host] [sni] [port] [ua]\n[crlf] [split]\n\nExample:\nGET / HTTP/1.1[crlf]Host: [host][crlf][crlf]\n```"

	edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
	edit.ParseMode = "Markdown"
	bot.Send(edit)

	setSessionState(chatID, "config_step_payload_custom")
}

func promptScanCustomPayload(chatID int64, messageID int) {
	text := "```\n✏️ Enter your custom payload:\n\nUse placeholders:\n[host] [sni] [port] [ua]\n[crlf] [split]\n```"

	edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
	edit.ParseMode = "Markdown"
	bot.Send(edit)

	setSessionState(chatID, "config_scan_payload_custom")
}

// =============================================
// CORE VALIDATION ENGINE
// =============================================

func connectToHost(host string, port int, sni string) (net.Conn, int, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()

	var conn net.Conn
	var err error

	for attempt := 0; attempt <= 1; attempt++ {
		if port == 443 {
			sniUse := sni
			if sniUse == "" {
				sniUse = host
			}
			conf := &tls.Config{
				ServerName:         sniUse,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			}
			dialer := &net.Dialer{Timeout: 6 * time.Second}
			conn, err = tls.DialWithDialer(dialer, "tcp", address, conf)
		} else {
			conn, err = net.DialTimeout("tcp", address, 6*time.Second)
		}

		if err == nil {
			latency := int(time.Since(start).Milliseconds())
			return conn, latency, nil
		}

		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, int(time.Since(start).Milliseconds()), err
}

func validateUserConfig(config UserConfig) FullValidation {
	result := FullValidation{
		Config:  config,
		Success: true,
	}

	var conn net.Conn
	var lat int
	var err error

	connectHost := config.ProxyHost
	connectPort := config.ProxyPort
	stepName := "Proxy Connection"

	if connectHost == "" {
		connectHost = config.TargetHost
		connectPort = config.TargetPort
		stepName = "Direct Connection"
	}

	if connectHost == "" {
		result.Steps = append(result.Steps, ValidationResult{
			Step:    "Connection",
			Success: false,
			Message: "❌ No proxy or target host specified",
		})
		result.Success = false
		result.Summary = "Need at least proxy or target host."
		result.Score = 0
		return result
	}

	conn, lat, err = connectToHost(connectHost, connectPort, config.SNI)

	step := ValidationResult{
		Step:      stepName,
		LatencyMs: lat,
	}

	if err != nil {
		step.Success = false
		step.Message = fmt.Sprintf("❌ Connection failed: %v", err)
		result.Success = false
		result.Steps = append(result.Steps, step)
		result.Summary = "Connection failed. Check host/port."
		result.Score = 0
		return result
	}

	step.Success = true
	step.Message = fmt.Sprintf("✅ Connected to %s:%d (%dms)", connectHost, connectPort, lat)
	result.Steps = append(result.Steps, step)
	defer conn.Close()

	tlsStep := ValidationResult{Step: "TLS/SNI"}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		tlsStep.Success = true
		sniUsed := config.SNI
		if sniUsed == "" {
			sniUsed = connectHost
		}
		tlsStep.Message = fmt.Sprintf("✅ TLS established (SNI: %s)", sniUsed)
		tlsStep.Details = fmt.Sprintf("Version: %s | Cipher: %s",
			tlsVersionName(state.Version), tlsCipherName(state.CipherSuite))
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			if cert.Subject.CommonName != "" {
				tlsStep.Details += fmt.Sprintf(" | CN: %s", cert.Subject.CommonName)
			}
		}
	} else {
		tlsStep.Success = true
		tlsStep.Message = "⚠️ Plain TCP (no TLS)"
	}
	result.Steps = append(result.Steps, tlsStep)

	if config.Payload != "" {
		payloadStep := ValidationResult{Step: "Payload Injection"}
		start := time.Now()

		payload := config.Payload
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")
		payload = strings.ReplaceAll(payload, "[split]", "\r\n\r\n")

		hostForPayload := config.ProxyHost
		if hostForPayload == "" {
			hostForPayload = config.TargetHost
		}
		sniForPayload := config.SNI
		if sniForPayload == "" {
			sniForPayload = hostForPayload
		}
		portStr := strconv.Itoa(connectPort)

		payload = strings.ReplaceAll(payload, "[host]", hostForPayload)
		payload = strings.ReplaceAll(payload, "[sni]", sniForPayload)
		payload = strings.ReplaceAll(payload, "[port]", portStr)
		payload = strings.ReplaceAll(payload, "[ua]", randomUA())
		payload = strings.ReplaceAll(payload, "[vps]", config.TargetHost)
		payload = strings.ReplaceAll(payload, "[ip]", "")

		conn.SetDeadline(time.Now().Add(6 * time.Second))
		_, writeErr := conn.Write([]byte(payload))
		if writeErr != nil {
			payloadStep.Success = false
			payloadStep.Message = fmt.Sprintf("❌ Write failed: %v", writeErr)
			result.Success = false
			result.Steps = append(result.Steps, payloadStep)
			result.Summary = "Payload write failed."
			result.Score = 30
			return result
		}

		reader := bufio.NewReaderSize(conn, 16384)
		var responseBuffer strings.Builder
		totalBytes := 0

		for {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			line, _, readErr := reader.ReadLine()
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				break
			}
			responseBuffer.Write(line)
			responseBuffer.WriteString("\r\n")
			totalBytes += len(line) + 2

			if len(line) == 0 {
				body := make([]byte, 4096)
				n, _ := reader.Read(body)
				if n > 0 {
					responseBuffer.Write(body[:n])
					totalBytes += n
				}
				break
			}
		}

		payloadStep.LatencyMs = int(time.Since(start).Milliseconds())

		if totalBytes > 0 {
			resp := responseBuffer.String()
			payloadStep.Details = fmt.Sprintf("Response: %d bytes", totalBytes)

			respReader := bufio.NewReader(strings.NewReader(resp))
			httpResp, parseErr := http.ReadResponse(respReader, nil)
			if parseErr == nil && httpResp != nil {
				payloadStep.StatusCode = httpResp.StatusCode
				payloadStep.ResponseCode = fmt.Sprintf("HTTP/%d.%d %d %s",
					httpResp.ProtoMajor, httpResp.ProtoMinor,
					httpResp.StatusCode, http.StatusText(httpResp.StatusCode))
				payloadStep.Server = httpResp.Header.Get("Server")
				payloadStep.CFRay = httpResp.Header.Get("CF-RAY")
				payloadStep.Via = httpResp.Header.Get("Via")
			} else {
				firstLine := strings.SplitN(resp, "\r\n", 2)[0]
				if firstLine == "" {
					firstLine = strings.SplitN(resp, "\n", 2)[0]
				}
				payloadStep.ResponseCode = strings.TrimSpace(firstLine)
			}

			switch {
			case payloadStep.StatusCode == 200:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("✅ 200 OK (%dms)", payloadStep.LatencyMs)
			case payloadStep.StatusCode == 101:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("🔥 WebSocket 101 (%dms)", payloadStep.LatencyMs)
			case payloadStep.StatusCode >= 300 && payloadStep.StatusCode < 400:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("⚠️ Redirect %d (%dms)", payloadStep.StatusCode, payloadStep.LatencyMs)
			case payloadStep.StatusCode == 403:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("⚠️ WAF Block 403 (%dms)", payloadStep.LatencyMs)
			case payloadStep.StatusCode == 401:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("⚠️ Auth Required 401 (%dms)", payloadStep.LatencyMs)
			case payloadStep.StatusCode == 400:
				payloadStep.Success = true
				payloadStep.Message = fmt.Sprintf("⚠️ Bad Request 400 — check payload (%dms)", payloadStep.LatencyMs)
			case payloadStep.StatusCode >= 500:
				payloadStep.Success = false
				payloadStep.Message = fmt.Sprintf("❌ Server Error %d (%dms)", payloadStep.StatusCode, payloadStep.LatencyMs)
				result.Success = false
			default:
				if payloadStep.StatusCode > 0 {
					payloadStep.Success = true
					payloadStep.Message = fmt.Sprintf("⚠️ HTTP %d (%dms)", payloadStep.StatusCode, payloadStep.LatencyMs)
				} else {
					payloadStep.Success = true
					payloadStep.Message = fmt.Sprintf("⚠️ Response received (%dms)", payloadStep.LatencyMs)
				}
			}
		} else {
			payloadStep.Success = false
			payloadStep.Message = "❌ No response"
			result.Success = false
		}
		result.Steps = append(result.Steps, payloadStep)
	} else {
		result.Steps = append(result.Steps, ValidationResult{
			Step:    "Payload Injection",
			Success: true,
			Message: "⏭️ Skipped (no payload)",
		})
	}

	cdnStep := ValidationResult{Step: "CDN Detection"}
	cdnFound := false

	for _, s := range result.Steps {
		if s.CFRay != "" {
			cdnStep.Success = true
			cdnStep.Message = "☁️ Cloudflare CDN detected"
			cdnStep.Details = "CF-RAY: " + s.CFRay
			cdnFound = true
			break
		}
		if s.Server != "" {
			cdnStep.Success = true
			cdnStep.Message = "🖥️ Server: " + s.Server
			cdnFound = true
			break
		}
		if s.Via != "" {
			cdnStep.Success = true
			cdnStep.Message = "🔄 Via: " + s.Via
			cdnFound = true
			break
		}
	}

	if !cdnFound {
		cdnStep.Success = true
		cdnStep.Message = "⚠️ No CDN signature detected"
	}
	result.Steps = append(result.Steps, cdnStep)

	passed := 0
	total := 0
	for _, s := range result.Steps {
		total++
		if s.Success {
			passed++
		}
	}

	if total > 0 {
		result.Score = passed * 100 / total
	}

	switch {
	case result.Success && result.Score >= 80:
		result.Summary = "✅ CONFIG WORKING! Ready to deploy."
	case result.Success && result.Score >= 60:
		result.Summary = "⚠️ PARTIALLY WORKING — check details."
	case result.Success && result.Score >= 40:
		result.Summary = "🟡 WEAK — may work with adjustments."
	default:
		result.Summary = "❌ CONFIG FAILED — review setup."
	}

	return result
}

// =============================================
// VALIDATION EXECUTOR
// =============================================

func executeConfigValidation(chatID int64, input string) {
	defer func() {
		if r := recover(); r != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Error*\n```\n"+fmt.Sprintf("%v", r)+"\n```"))
			clearSessionState(chatID)
		}
	}()

	config := parseConfigInput(input)

	statusMsg := tgbotapi.NewMessage(chatID, "⚙️ *Validating...*\n━━━━━━━━━━━━━━━━━━━━\n⏳ Testing connection...")
	statusMsg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(statusMsg)

	result := validateUserConfig(config)

	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│  ⚙️ VALIDATION RESULT   │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")

	sb.WriteString("📋 CONFIG TESTED:\n")
	if config.ProxyHost != "" {
		sb.WriteString(fmt.Sprintf("   Proxy: %s:%d\n", config.ProxyHost, config.ProxyPort))
	}
	if config.SNI != "" {
		sb.WriteString(fmt.Sprintf("   SNI: %s\n", config.SNI))
	}
	if config.Payload != "" {
		prev := config.Payload
		if len(prev) > 60 {
			prev = prev[:60] + "..."
		}
		sb.WriteString(fmt.Sprintf("   Payload: %s\n", prev))
	}
	if config.TargetHost != "" {
		sb.WriteString(fmt.Sprintf("   Target: %s:%d\n", config.TargetHost, config.TargetPort))
	}
	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	for _, step := range result.Steps {
		icon := "✅"
		if !step.Success {
			icon = "❌"
		}
		sb.WriteString(fmt.Sprintf("%s %s\n", icon, step.Message))
		if step.Details != "" {
			sb.WriteString(fmt.Sprintf("   📝 %s\n", step.Details))
		}
		if step.ResponseCode != "" {
			sb.WriteString(fmt.Sprintf("   📡 %s\n", step.ResponseCode))
		}
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	scoreBar := ""
	barLen := 10
	filled := result.Score * barLen / 100
	if filled > barLen {
		filled = barLen
	}
	scoreBar = "[" + strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled) + "]"
	sb.WriteString(fmt.Sprintf("📊 Score: %d/100 %s\n", result.Score, scoreBar))
	sb.WriteString(fmt.Sprintf("%s\n", result.Summary))
	sb.WriteString("```")

	editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, sb.String())
	editMsg.ParseMode = "Markdown"
	editMsg.ReplyMarkup = getMainMenuKeyboard()
	bot.Send(editMsg)

	clearSessionState(chatID)
}

// =============================================
// INPUT PARSER
// =============================================

func parseConfigInput(input string) UserConfig {
	config := UserConfig{}
	parts := strings.Split(input, "|")

	if len(parts) >= 1 && parts[0] != "" && parts[0] != "-" {
		if h, p, err := net.SplitHostPort(parts[0]); err == nil {
			config.ProxyHost = h
			config.ProxyPort, _ = strconv.Atoi(p)
		} else {
			config.ProxyHost = parts[0]
			config.ProxyPort = 443
		}
	}

	if len(parts) >= 2 && parts[1] != "" && parts[1] != "-" {
		config.SNI = parts[1]
	}

	if len(parts) >= 3 && parts[2] != "" && parts[2] != "-" {
		config.Payload = parts[2]
	}

	if len(parts) >= 4 && parts[3] != "" && parts[3] != "-" {
		if h, p, err := net.SplitHostPort(parts[3]); err == nil {
			config.TargetHost = h
			config.TargetPort, _ = strconv.Atoi(p)
		} else {
			config.TargetHost = parts[3]
			config.TargetPort = 443
		}
	}

	return config
}

// =============================================
// UTILITY FUNCTIONS
// =============================================

func configSummary(config UserConfig) string {
	parts := []string{}
	if config.ProxyHost != "" {
		parts = append(parts, fmt.Sprintf("Proxy: %s:%d", config.ProxyHost, config.ProxyPort))
	}
	if config.SNI != "" {
		parts = append(parts, "SNI: "+config.SNI)
	}
	if config.Payload != "" {
		parts = append(parts, "Payload: ✓")
	}
	if config.TargetHost != "" {
		parts = append(parts, fmt.Sprintf("Target: %s:%d", config.TargetHost, config.TargetPort))
	}
	return strings.Join(parts, " | ")
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func tlsCipherName(cipher uint16) string {
	switch cipher {
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES-128-GCM"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES-256-GCM"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "ChaCha20"
	default:
		return fmt.Sprintf("0x%04x", cipher)
	}
}
