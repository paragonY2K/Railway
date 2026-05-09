package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// =============================================
// SINGLE SCAN
// =============================================

type tlsInfo struct {
	Cipher        string
	ALPN          string
	CommonName    string
	SANs          string
	ExpiresDay    *int
	Leak          int
	Server        string
	SSHWS         bool
	WSraw         string
	TLSraw        string
	LatencyMs     int
	HTTPStatus    string
	TLSStatus     string
	ContentLength int
	BodySnippet   string
	IsH3          bool
	IsReality     bool
	ProtocolVer   string
	IP            string
}

type scanRecord struct {
	host         string
	port         int
	priority     string
	status       string
	server       string
	cn           string
	tlsRaw       string
	latencyMs    int
	bugType      string
	score        int
	deepVerified string
	info         tlsInfo
	label        string
}

type scanResult struct {
	Host, IP, Priority, WSRes, TLSRes, Recommend string
	Port                                         int
	Info                                         tlsInfo
}

type VerificationResult struct {
	IsWorking     bool
	QualityScore  int
	WorkingPath   string
	WorkingHeader map[string]string
	VerifiedBug   string
	ErrorMessage  string
	IP            string
}

func formatScanResultMarkdownV2(host string, ip string, port int, info tlsInfo, detectType string, qualityScore int, isVulnerable bool, deepVerifyResult string, useCase string, allPorts map[int]string) string {
	var sb strings.Builder

	sb.WriteString("```\n")
	sb.WriteString("╭──────────────────────────────────╮\n")
	sb.WriteString("│  🎯 " + toBoldUnicode("PARAGON SINGLE SCAN") + "          │\n")
	sb.WriteString("╰──────────────────────────────────╯\n\n")

	sb.WriteString(toBoldUnicode("Target") + "   : " + host + "\n")
	sb.WriteString(toBoldUnicode("IP") + "       : " + ip + "\n")

	if len(allPorts) > 0 {
		var keys []int
		for k := range allPorts {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		var portParts []string
		for _, p := range keys {
			status := allPorts[p]
			if p == port {
				portParts = append(portParts, "["+strconv.Itoa(p)+"] "+status)
			} else {
				portParts = append(portParts, strconv.Itoa(p)+" "+status)
			}
		}
		sb.WriteString(toBoldUnicode("Ports") + "    : " + strings.Join(portParts, " | ") + "\n")
	} else {
		sb.WriteString(toBoldUnicode("Port") + "     : " + strconv.Itoa(port) + "\n")
	}

	serverDisplay := info.Server
	if serverDisplay == "" || serverDisplay == "Unknown" {
		serverDisplay = detectCDNByIP(ip)
		if serverDisplay == "" {
			serverDisplay = "Unknown"
		}
	}
	sb.WriteString(toBoldUnicode("Server") + "   : " + serverDisplay + "\n")

	statusDisplay := info.HTTPStatus
	if statusDisplay == "" {
		statusDisplay = "000"
	}

	httpIcon := "⚪"
	switch {
	case statusDisplay == "200" || statusDisplay == "201":
		httpIcon = "🟢"
	case statusDisplay == "101":
		httpIcon = "🔥"
	case strings.HasPrefix(statusDisplay, "3"):
		httpIcon = "🔵"
	case statusDisplay == "403":
		httpIcon = "🟡"
	case statusDisplay == "000":
		httpIcon = "💀"
	}
	sb.WriteString(toBoldUnicode("HTTP") + "     : " + httpIcon + " " + statusDisplay + "\n\n")

	var statusIcon, statusLabel string
	switch detectType {
	case "H3_QUIC":
		statusIcon, statusLabel = "⚡", "H3/QUIC BUG"
	case "SPOOF":
		statusIcon, statusLabel = "🎭", "SNI SPOOFABLE"
	case "WS", "WS-PORT80", "WS-TLS":
		statusIcon, statusLabel = "🔌", "WEBSOCKET OPEN"
	case "REALITY":
		statusIcon, statusLabel = "🔮", "REALITY TUNNEL"
	case "AZURE_BNI":
		statusIcon, statusLabel = "💎", "AZURE BNI BUG"
	case "CDN_FRONT":
		statusIcon, statusLabel = "☁️", "CDN FRONTING"
	case "SSH_TUNNEL":
		statusIcon, statusLabel = "🔐", "SSH TUNNEL"
	case "SLOWDNS":
		statusIcon, statusLabel = "🐢", "SLOWDNS TUNNEL"
	case "BUGHOST CONFIRMED", "CDN_HOST", "CDN BUGHOST CONFIRMED":
		statusIcon, statusLabel = "⚠️", "CDN BUGHOST"
	case "HTTP BUGHOST CONFIRMED":
		statusIcon, statusLabel = "🌐", "HTTP BUGHOST"
	case "HTTP_REDIRECT":
		statusIcon, statusLabel = "🔄", "HTTP REDIRECT"
	case "HTTP_ONLY":
		statusIcon, statusLabel = "🌐", "HTTP ONLY"
	default:
		if isVulnerable {
			statusIcon, statusLabel = "🔥", "VULNERABLE"
		} else {
			statusIcon, statusLabel = "❌", "NOT VULNERABLE"
		}
	}

	sb.WriteString(toBoldUnicode("Type") + "     : " + statusIcon + " " + toBoldUnicode(statusLabel) + "\n")
	sb.WriteString(toBoldUnicode("Category") + " : " + detectType + "\n")

	// SNI
	if info.CommonName != "" && info.CommonName != host {
		sb.WriteString(toBoldUnicode("SNI") + "      : " + info.CommonName + "\n")
	}

	scoreIcon := "🔴"
	if qualityScore >= 80 {
		scoreIcon = "🟢"
	} else if qualityScore >= 50 {
		scoreIcon = "🟡"
	} else if qualityScore >= 30 {
		scoreIcon = "🟠"
	}

	scoreBar := ""
	barLen := 10
	filled := qualityScore * barLen / 100
	if filled > barLen {
		filled = barLen
	}
	scoreBar = strings.Repeat("🟩", filled) + strings.Repeat("⬜", barLen-filled)
	sb.WriteString(toBoldUnicode("Score") + "    : " + scoreIcon + " " + strconv.Itoa(qualityScore) + "/100 " + scoreBar + "\n")

	if info.LatencyMs > 0 {
		latencyIcon := "⚡"
		if info.LatencyMs > 500 {
			latencyIcon = "🐢"
		} else if info.LatencyMs < 100 {
			latencyIcon = "🚀"
		}
		sb.WriteString(toBoldUnicode("Latency") + "  : " + latencyIcon + " " + strconv.Itoa(info.LatencyMs) + "ms\n")
	}

	if info.ALPN != "" {
		sb.WriteString(toBoldUnicode("ALPN") + "     : " + info.ALPN + "\n")
	}
	if info.Cipher != "" && info.Cipher != "0x0000" {
		sb.WriteString(toBoldUnicode("Cipher") + "   : " + info.Cipher + "\n")
	}

	if info.ContentLength > 0 {
		sizeStr := strconv.Itoa(info.ContentLength) + " bytes"
		if info.ContentLength > 1024 {
			sizeStr = fmt.Sprintf("%.1f KB", float64(info.ContentLength)/1024.0)
		}
		sb.WriteString(toBoldUnicode("Size") + "     : " + sizeStr + "\n")
	}

	if deepVerifyResult != "" {
		sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString(deepVerifyResult)
	}
	if useCase != "" {
		sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString(useCase)
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("💡 " + toBoldUnicode("Enjoying PARAGON?") + " Send /feedback\n")
	sb.WriteString("```")

	return sb.String()
}

func formatScanResultMarkdown(host string, ip string, port int, info tlsInfo, detectType string, qualityScore int, isVulnerable bool) string {
	var sb strings.Builder

	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│     🎯 SCAN COMPLETE    │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")

	sb.WriteString(fmt.Sprintf("Target   : %s\n", host))
	sb.WriteString(fmt.Sprintf("IP       : %s\n", ip))
	sb.WriteString(fmt.Sprintf("Port     : %d\n", port))

	serverDisplay := info.Server
	if serverDisplay == "" || serverDisplay == "Unknown" {
		serverDisplay = detectCDNByIP(ip)
		if serverDisplay == "" {
			serverDisplay = "Unknown"
		}
	}
	sb.WriteString(fmt.Sprintf("Server   : %s\n", serverDisplay))

	statusDisplay := info.HTTPStatus
	if statusDisplay == "" {
		statusDisplay = "000"
	}
	sb.WriteString(fmt.Sprintf("HTTP     : %s\n\n", statusDisplay))

	var statusIcon, statusLabel string
	switch detectType {
	case "H3_QUIC":
		statusIcon = "⚡"
		statusLabel = "VULNERABLE"
	case "SPOOF":
		statusIcon = "🎭"
		statusLabel = "VULNERABLE"
	case "WS":
		statusIcon = "🔌"
		statusLabel = "VULNERABLE"
	case "REALITY":
		statusIcon = "🔮"
		statusLabel = "VULNERABLE"
	case "BUGHOST CONFIRMED", "CDN_HOST":
		statusIcon = "⚠️"
		statusLabel = "POTENTIAL"
	case "CDN_ONLY":
		statusIcon = "📡"
		statusLabel = "LIMITED"
	case "HTTP_ONLY":
		statusIcon = "🌐"
		statusLabel = "WEAK"
	case "PREMIUM_SNI":
		statusIcon = "💎"
		statusLabel = "PREMIUM"
	default:
		if isVulnerable {
			statusIcon = "🔥"
			statusLabel = "VULNERABLE"
		} else {
			statusIcon = "❌"
			statusLabel = "NOT VULNERABLE"
		}
	}

	sb.WriteString(fmt.Sprintf("Status   : %s %s\n", statusIcon, statusLabel))
	sb.WriteString(fmt.Sprintf("Type     : %s\n", detectType))

	if info.CommonName != "" && info.CommonName != host {
		sb.WriteString(fmt.Sprintf("SNI      : %s\n", info.CommonName))
	}

	scoreBar := ""
	barLen := 8
	filled := qualityScore * barLen / 100
	if filled > barLen {
		filled = barLen
	}
	scoreBar = "[" + strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled) + "]"
	sb.WriteString(fmt.Sprintf("Score    : %d/100 %s\n", qualityScore, scoreBar))

	if info.LatencyMs > 0 {
		sb.WriteString(fmt.Sprintf("Latency  : %dms\n", info.LatencyMs))
	}

	if info.ALPN != "" {
		sb.WriteString(fmt.Sprintf("ALPN     : %s\n", info.ALPN))
	}

	if info.Cipher != "" && info.Cipher != "0x0000" {
		sb.WriteString(fmt.Sprintf("Cipher   : %s\n", info.Cipher))
	}

	if info.ContentLength > 0 {
		contentDisplay := fmt.Sprintf("%d bytes", info.ContentLength)
		if info.ContentLength > 1024 {
			contentDisplay = fmt.Sprintf("%.1f KB", float64(info.ContentLength)/1024.0)
		}
		sb.WriteString(fmt.Sprintf("Size     : %s\n", contentDisplay))
	}

	sb.WriteString("```")

	return sb.String()
}

func executeSingleScan(chatID int64, target string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Engine Error:* Please try again later."))
			clearSessionState(chatID)
		}
	}()

	umMutex.Lock()
	if u, exists := userData.Users[chatID]; exists {
		u.Scans++
		u.LastScan = time.Now()
	}
	umMutex.Unlock()

	select {
	case scanSemaphore <- struct{}{}:
		defer func() { <-scanSemaphore }()
	case <-time.After(30 * time.Second):
		msg := tgbotapi.NewMessage(chatID, "⚠️ *Server busy.* Please try again in a moment.")
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	sendTyping(chatID)
	target = strings.TrimSpace(target)

	if target == "" || !strings.Contains(target, ".") {
		msg := tgbotapi.NewMessage(chatID, "❌ *Invalid Format*\nExample: `google.com`")
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	// Strip path from URL if user added it
	if strings.Contains(target, "/") {
		target = strings.SplitN(target, "/", 2)[0]
	}

	host, portStr, err := net.SplitHostPort(target)
	specifiedPort := 0
	if err == nil {
		specifiedPort, _ = strconv.Atoi(portStr)
	} else {
		host = target
	}

	cacheKey := fmt.Sprintf("single:%s:%d", host, specifiedPort)
	if cached, found := resultCache.Get(cacheKey); found {
		statusText := fmt.Sprintf("📡 *Paragon Engine:* `%s`\n\n⚡ *Cached Result:*", host)
		statusMsg := tgbotapi.NewMessage(chatID, statusText)
		statusMsg.ParseMode = "Markdown"
		sentMsg, err := bot.Send(statusMsg)
		if err == nil {
			edit := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, cached)
			edit.ParseMode = "Markdown"
			edit.ReplyMarkup = getMainMenuKeyboard()
			bot.Send(edit)
		}
		clearSessionState(chatID)
		return
	}

	statusText := fmt.Sprintf("📡 *Paragon Engine:* `%s`\n\n⌛ Status: _Initializing..._", host)
	statusMsg := tgbotapi.NewMessage(chatID, statusText)
	statusMsg.ParseMode = "Markdown"

	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		clearSessionState(chatID)
		return
	}

	msgID := sentMsg.MessageID
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess := getSession(chatID)
	sess.CancelFunc = cancel

	resultChan := make(chan string, 1)
	resultPriority := make(chan string, 1)
	resultScore := make(chan int, 1)

	go func() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		updateStatus(chatID, msgID, "🔍 *Step 1:* Resolving host...")
		ip, err := resolveIPv4(host)
		if err != nil {
			select {
			case resultChan <- "❌ *Resolution Failed:* Host not found.":
			default:
			}
			return
		}

		updateStatus(chatID, msgID, "📡 *Step 2:* Probing ports...")

		var portsToTest []int
		if specifiedPort != 0 {
			portsToTest = append(portsToTest, specifiedPort)
		} else {
			portsToTest = []int{443, 80, 8080, 8880}
		}

		type portResult struct {
			port     int
			info     tlsInfo
			label    string
			priority string
			score    int
		}

		results := make(chan portResult, len(portsToTest))
		var wg sync.WaitGroup
		allResults := make(map[int]string)

		for _, port := range portsToTest {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				_, pInfo, pLabel, _ := classifyWithProbes(host, ip, p)
				pPriority, pScore := calculateScore(pLabel, pInfo)
				results <- portResult{p, pInfo, pLabel, pPriority, pScore}
			}(port)
		}

		wg.Wait()
		close(results)

		var info tlsInfo
		var detectLabel string
		var bestPriority string
		var bestScore int
		finalPort := 0

		for r := range results {
			if r.priority == "STRONG" || r.priority == "MEDI" ||
				strings.Contains(r.label, "OK") || strings.Contains(r.label, "BUGHOST") ||
				strings.Contains(r.label, "WS") || strings.Contains(r.label, "REDIRECT") {
				allResults[r.port] = "✓"
			} else {
				allResults[r.port] = "✗"
			}

			if (r.priority == "STRONG" && r.score > bestScore) || bestPriority == "" || r.score > bestScore {
				info = r.info
				detectLabel = r.label
				bestPriority = r.priority
				bestScore = r.score
				finalPort = r.port
			}
		}

		if finalPort == 0 {
			for _, port := range portsToTest {
				protoResult := detectProtocol(ip, port)
				if protoResult.Working {
					info.HTTPStatus = protoResult.Type
					info.Server = protoResult.Banner
					detectLabel = protoResult.Type
					bestPriority = "STRONG"
					bestScore = 80
					finalPort = protoResult.Port
					allResults[port] = "✓"
					break
				}
			}
		}

		if finalPort == 0 {
			select {
			case resultChan <- "❌ *Unreachable:* All ports closed.":
			default:
			}
			return
		}

		updateStatus(chatID, msgID, fmt.Sprintf("🚀 *Step 3:* Analyzing port %d...", finalPort))

		labelUpper := strings.ToUpper(detectLabel)
		isH3 := strings.Contains(labelUpper, "H3") || strings.Contains(strings.ToUpper(info.ALPN), "H3")
		cnClean := strings.ToLower(strings.ReplaceAll(info.CommonName, "*.", ""))
		isSpoof := info.CommonName != "" && !strings.Contains(strings.ToLower(host), cnClean) && !strings.Contains(cnClean, strings.ToLower(host)) && !isParentDomain(cnClean, strings.ToLower(host)) && net.ParseIP(strings.ToLower(host)) == nil

		if detectLabel == "HTTP_OK" {
			detectLabel = "HTTP_ONLY"
		}
		if detectLabel == "WS-PORT80" || detectLabel == "WS-TLS" {
			detectLabel = "WS"
		}

		priority, qualityScore := calculateScore(detectLabel, info)

		switch detectLabel {
		case "SSH_TUNNEL":
			qualityScore, priority = 85, "STRONG"
		case "SLOWDNS":
			qualityScore, priority = 75, "STRONG"
		case "HTTP_ONLY":
			qualityScore, priority = 35, "WEAK"
		case "HTTP BUGHOST CONFIRMED":
			qualityScore, priority = 55, "MEDI"
		case "HTTP_REDIRECT":
			qualityScore, priority = 45, "MEDI"
		case "CDN BUGHOST CONFIRMED":
			detectLabel = "CDN_HOST"
			qualityScore, priority = 65, "MEDI"
		case "SPOOF":
			qualityScore, priority = 80, "STRONG"
		case "REALITY":
			qualityScore, priority = 90, "STRONG"
		}

		if isH3 && detectLabel != "WS" {
			detectLabel = "H3_QUIC"
		}
		if isSpoof && detectLabel != "WS" && detectLabel != "H3_QUIC" {
			detectLabel = "SPOOF"
		}

		// =============================================
		// 🔥 IMPROVEMENT 1: CDN Confidence Boost/Penalty
		// =============================================
		cdnConfidence := calculateCDNConfidence(info, ip)
		if cdnConfidence >= 40 {
			qualityScore += 10
		} else if cdnConfidence > 0 && cdnConfidence < 40 {
			qualityScore -= 15
		}

		// =============================================
		// 🔥 IMPROVEMENT 2: Bughost Signature Scoring
		// =============================================
		sigScore := analyzeBughostSignature(info.BodySnippet)
		if sigScore > 0 {
			qualityScore += sigScore
		} else if sigScore < 0 {
			qualityScore += sigScore
		}

		// Clamp score
		if qualityScore > 100 {
			qualityScore = 100
		}
		if qualityScore < 0 {
			qualityScore = 0
		}

		// =============================================
		// Step 4: Deep Verify
		// =============================================
		deepVerifyResult := ""
		if priority == "STRONG" || (priority == "MEDI" && qualityScore >= 45) {
			updateStatus(chatID, msgID, "🔬 *Step 4:* Deep verifying connection...")
			verified := deepVerify(host, ip, finalPort, detectLabel, info)
			if verified.IsWorking {
				deepVerifyResult = fmt.Sprintf("✅ Deep Verify : %s (%d/100)", verified.VerifiedBug, verified.QualityScore)
				priority = "STRONG"
				qualityScore = (qualityScore + verified.QualityScore) / 2
			} else {
				deepVerifyResult = fmt.Sprintf("❌ Deep Verify : FAILED (%s)", verified.ErrorMessage)
				if priority == "STRONG" {
					priority = "MEDI"
				}
			}
		}

		// Clamp again after deep verify
		if qualityScore > 100 {
			qualityScore = 100
		}
		if qualityScore < 0 {
			qualityScore = 0
		}

		isVulnerable := (priority == "STRONG")
		useCase := ""
		if (priority == "STRONG" || priority == "MEDI") && qualityScore >= 45 {
			rec := getRecommendation(host, ip, finalPort, info.Server, info.HTTPStatus, detectLabel, info)
			useCase = formatRecommendation(host, rec)
		}

		res := formatScanResultMarkdownV2(host, ip, finalPort, info, detectLabel, qualityScore, isVulnerable, deepVerifyResult, useCase, allResults)
		resultCache.Set(cacheKey, res, 5*time.Minute)

		select {
		case <-ctx.Done():
			return
		default:
			resultChan <- res
			resultPriority <- priority
			resultScore <- qualityScore
		}
	}()

	select {
	case resultText := <-resultChan:
		prio := <-resultPriority
		score := <-resultScore

		var keyboard *tgbotapi.InlineKeyboardMarkup

		if prio == "STRONG" || (prio == "MEDI" && score >= 45) {
			targetData := host
			if specifiedPort != 0 {
				targetData = fmt.Sprintf("%s:%d", host, specifiedPort)
			}
			k := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("💉 Test Payloads", "payload_scan:"+targetData)),
				tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("🏠 Main Menu", "menu_main")),
			)
			keyboard = &k
		} else {
			// WEAK/FAILED — Main Menu ONLY
			k := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("🏠 Main Menu", "menu_main")),
			)
			keyboard = &k
		}

		edit := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = keyboard
		bot.Send(edit)

	case <-ctx.Done():
		updateStatus(chatID, msgID, "❌ *Scan Timeout*")
	}
	clearSessionState(chatID)
}

// =============================================
// 🔥 ACCURACY IMPROVEMENT HELPER FUNCTIONS
// =============================================

func isParentDomain(cn, host string) bool {
	cn = strings.ToLower(strings.TrimSpace(cn))
	host = strings.ToLower(strings.TrimSpace(host))

	if strings.HasSuffix(host, "."+cn) {
		return true
	}
	if strings.HasSuffix(cn, "."+host) {
		return true
	}

	cnParts := strings.Split(cn, ".")
	hostParts := strings.Split(host, ".")

	if len(cnParts) >= 2 && len(hostParts) >= 2 {
		cnSuffix := strings.Join(cnParts[len(cnParts)-2:], ".")
		hostSuffix := strings.Join(hostParts[len(hostParts)-2:], ".")
		return cnSuffix == hostSuffix
	}
	return false
}

func isGenericContent(body string) bool {
	if body == "" {
		return false
	}
	bodyLower := strings.ToLower(body)

	genericKeywords := []string{
		"welcome to nginx", "welcome to apache",
		"index of /", "apache2 ubuntu default", "nginx default",
		"parked domain", "domain parking", "buy this domain",
		"for sale", "coming soon", "under construction",
		"site not configured", "default web page", "test page",
		"captive portal",
	}

	for _, kw := range genericKeywords {
		if strings.Contains(bodyLower, kw) {
			return true
		}
	}
	return false
}

func analyzeBughostSignature(body string) int {
	score := 0
	bodyLower := strings.ToLower(body)

	// Positive signals — legit CDN/infra response
	positivePatterns := []string{
		"cf-browser-verification",
		"attention required",
		"checking your browser",
		"ddos protection by",
		"enable javascript to continue",
		"please wait while we verify",
		"ray id:",
		"just a moment",
	}

	for _, pattern := range positivePatterns {
		if strings.Contains(bodyLower, pattern) {
			score += 15
			break
		}
	}

	// Negative signals — generic server
	negativePatterns := []string{
		"welcome to nginx", "welcome to apache",
		"index of /", "apache2 ubuntu default",
		"parked domain", "buy this domain",
		"coming soon", "default web page",
	}

	for _, pattern := range negativePatterns {
		if strings.Contains(bodyLower, pattern) {
			score -= 25
			break
		}
	}

	return score
}

// calculateCDNConfidence cross-validates CDN claims
func calculateCDNConfidence(info tlsInfo, ip string) int {
	confidence := 0
	txtUpper := strings.ToUpper(info.TLSraw)

	// Header evidence
	if strings.Contains(txtUpper, "CF-RAY") {
		confidence += 30
	}
	if strings.Contains(strings.ToUpper(info.Server), "CLOUDFLARE") {
		confidence += 30
	}
	if strings.Contains(strings.ToUpper(info.Server), "CLOUDFRONT") {
		confidence += 25
	}
	if strings.Contains(strings.ToUpper(info.Server), "AKAMAI") {
		confidence += 25
	}

	// IP evidence (strongest)
	cdnIP := detectCDNByIP(ip)
	if cdnIP == "CLOUDFLARE" || cdnIP == "AWS/CF" {
		confidence += 40
	} else if cdnIP == "AKAMAI" || cdnIP == "FASTLY" || cdnIP == "IMPERVA" {
		confidence += 35
	}

	// Body evidence
	bodyUpper := strings.ToUpper(info.BodySnippet)
	if strings.Contains(bodyUpper, "CF-BROWSER-VERIFICATION") ||
		strings.Contains(bodyUpper, "CHECKING YOUR BROWSER") {
		confidence += 20
	}

	return confidence
}
