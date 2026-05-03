package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// =============================================
// DOMAIN SNIFFER - SSL CERTIFICATE EXTRACTOR
// =============================================

func sniffDomains(ip string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", conf)
	if err != nil {
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if cert.Subject.CommonName != "" && isValidDomain(cert.Subject.CommonName) {
			results <- cleanWildcard(cert.Subject.CommonName)
		}
		for _, domain := range cert.DNSNames {
			if isValidDomain(domain) {
				results <- cleanWildcard(domain)
			}
		}
	}
}

func cleanWildcard(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return domain[2:]
	}
	return domain
}

func isValidDomain(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	if strings.Contains(s, " ") || len(s) > 100 {
		return false
	}
	lower := strings.ToLower(s)
	caPatterns := []string{
		"root ca", "issuing ca", "validation", "authority",
		"digicert", "sectigo", "globalsign", "gts root",
	}
	for _, pattern := range caPatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}
	return true
}

func executeTLSSniffer(chatID int64, prefix string, startRange, endRange int, isMultiSubnet bool) {
	defer func() {
		if r := recover(); r != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Error*\n```\n"+fmt.Sprintf("%v", r)+"\n```"))
			clearSessionState(chatID)
		}
	}()

	var totalIPs int
	var targetLabel string
	var wg sync.WaitGroup

	results := make(chan string, 50000)
	uniqueDomains := make(map[string]bool)
	var mu sync.Mutex
	startTime := time.Now()

	// 1. Tentukan Total IPs & Label
	if isMultiSubnet {
		totalSubnets := endRange - startRange + 1
		totalIPs = totalSubnets * 254
		targetLabel = fmt.Sprintf("%s%d.* - %d.*", prefix, startRange, endRange)
	} else {
		totalIPs = endRange - startRange + 1
		targetLabel = fmt.Sprintf("%s%d - %d", prefix, startRange, endRange)
	}

	// 2. WORKER POOL SETUP
	jobs := make(chan string, 1000)
	numWorkers := 1000

	for w := 1; w <= numWorkers; w++ {
		go func() {
			for ip := range jobs {
				sniffDomains(ip, &wg, results)
			}
		}()
	}

	// 3. Queue jobs
	go func() {
		if isMultiSubnet {
			for octet := startRange; octet <= endRange; octet++ {
				for i := 1; i <= 254; i++ {
					wg.Add(1)
					jobs <- fmt.Sprintf("%s%d.%d", prefix, octet, i)
				}
			}
		} else {
			for i := startRange; i <= endRange; i++ {
				wg.Add(1)
				jobs <- fmt.Sprintf("%s%d", prefix, i)
			}
		}
		close(jobs)
	}()

	// 4. Status message
	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🔎 *DOMAIN SNIFF*\n━━━━━━━━━━━━━━━━━━━━\n"+
			"Target: `%s`\n"+
			"Workers: %d | IPs: %d\n\n"+
			"⏳ Scanning...",
		targetLabel, numWorkers, totalIPs))
	statusMsg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(statusMsg)

	// 5. Progress tracker (update setiap 8 saat)
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				count := len(uniqueDomains)
				mu.Unlock()
				elapsed := time.Since(startTime).Round(time.Second)
				updateStatus(chatID, sentMsg.MessageID, fmt.Sprintf(
					"🔎 *DOMAIN SNIFF*\n━━━━━━━━━━━━━━━━━━━━\n"+
						"Target: `%s`\n"+
						"Workers: %d | IPs: %d\n"+
						"Found: %d domains\n"+
						"Time: %v\n\n"+
						"⏳ Still scanning...",
					targetLabel, numWorkers, totalIPs, count, elapsed))
			case <-done:
				return
			}
		}
	}()

	// 6. Close results bila semua siap
	go func() {
		wg.Wait()
		close(results)
	}()

	// 7. Collect unique domains
	for domain := range results {
		mu.Lock()
		if !uniqueDomains[domain] {
			uniqueDomains[domain] = true
		}
		mu.Unlock()
	}

	// Stop progress tracker
	close(done)

	elapsed := time.Since(startTime).Round(time.Second)

	var sortedDomains []string
	for d := range uniqueDomains {
		sortedDomains = append(sortedDomains, d)
	}
	sort.Strings(sortedDomains)

	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│  🔎 DOMAIN SNIFF RESULT │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")
	sb.WriteString(fmt.Sprintf("Target : %s\n", targetLabel))
	sb.WriteString(fmt.Sprintf("IPs    : %d\n", totalIPs))
	sb.WriteString(fmt.Sprintf("Found  : %d domains\n", len(sortedDomains)))
	sb.WriteString(fmt.Sprintf("Time   : %v\n", elapsed))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(sortedDomains) == 0 {
		sb.WriteString("❌ No domains found.\n")
	} else {
		limit := 30
		if len(sortedDomains) < limit {
			limit = len(sortedDomains)
		}
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, sortedDomains[i]))
		}
		if len(sortedDomains) > limit {
			sb.WriteString(fmt.Sprintf("\n... and %d more\n", len(sortedDomains)-limit))
		}
	}

	sb.WriteString("\n```")

	editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, sb.String())
	editMsg.ParseMode = "Markdown"
	editMsg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(editMsg)

	if len(sortedDomains) > 0 {
		fileName := fmt.Sprintf("sniff_%s_%d.txt", strings.ReplaceAll(prefix, ".", "_"), time.Now().Unix())
		content := strings.Join(sortedDomains, "\n")
		err := os.WriteFile(fileName, []byte(content), 0644)
		if err == nil {
			doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(fileName))
			doc.Caption = fmt.Sprintf("📄 *Domain Sniff Report*\nTarget: `%s`\nFound: %d domains",
				targetLabel, len(sortedDomains))
			doc.ParseMode = "Markdown"
			bot.Send(doc)
			os.Remove(fileName)
		}
	}

	clearSessionState(chatID)
}

func handleSnifferInput(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)

	if text == "" || text == "cancel" {
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "❌ Cancelled.")
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
		return
	}

	parts := strings.Fields(text)
	if len(parts) < 1 {
		msg := tgbotapi.NewMessage(chatID, "```\n"+
			"╭─────────────────────────╮\n"+
			"│   🔎 DOMAIN SNIFF       │\n"+
			"╰─────────────────────────╯\n\n"+
			"🎯 Format: prefix start end\n\n"+
			"📋 Examples:\n"+
			"104.16.132. 1 254  → Single subnet\n"+
			"104.16. 132 135    → /22 (4 subnets)\n"+
			"104.16. 0 255      → /16 (65K IPs!)\n\n"+
			"💡 Just prefix only = auto 0-255\n"+
			"```")
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)
		return
	}

	prefix := parts[0]
	if !strings.HasSuffix(prefix, ".") {
		prefix += "."
	}

	octets := strings.Split(strings.TrimSuffix(prefix, "."), ".")

	if len(octets) == 2 {
		// Multi subnet: 104.16. 0 255
		startOctet := 0
		endOctet := 255

		if len(parts) >= 2 {
			if s, err := strconv.Atoi(parts[1]); err == nil && s >= 0 && s <= 255 {
				startOctet = s
			}
		}
		if len(parts) >= 3 {
			if e, err := strconv.Atoi(parts[2]); err == nil && e >= 0 && e <= 255 {
				endOctet = e
			}
		}

		clearSessionState(chatID)
		go executeTLSSniffer(chatID, prefix, startOctet, endOctet, true)
		return
	}

	if len(octets) == 3 {
		// Single subnet: 104.16.132. 1 254
		startIP := 1
		endIP := 254

		if len(parts) >= 2 {
			if s, err := strconv.Atoi(parts[1]); err == nil && s >= 1 && s <= 254 {
				startIP = s
			}
		}
		if len(parts) >= 3 {
			if e, err := strconv.Atoi(parts[2]); err == nil && e >= 1 && e <= 254 {
				endIP = e
			}
		}

		clearSessionState(chatID)
		go executeTLSSniffer(chatID, prefix, startIP, endIP, false)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "```\n"+
		"❌ Invalid prefix!\n\n"+
		"Use 2 segments: 104.16. 0 255\n"+
		"Or 3 segments: 104.16.132. 1 254\n```")
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = getCancelKeyboard()
	bot.Send(msg)
}
