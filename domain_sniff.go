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
// TLS CERTIFICATE SNIFFER
// =============================================

func sniffDomains(ip string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
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
		// Common Name — filter wildcard + domain only
		if cert.Subject.CommonName != "" && isValidDomain(cert.Subject.CommonName) {
			results <- cleanWildcard(cert.Subject.CommonName)
		}
		// SAN — filter semua
		for _, domain := range cert.DNSNames {
			if isValidDomain(domain) {
				results <- cleanWildcard(domain)
			}
		}
	}
}

// Buang *. prefix
func cleanWildcard(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return domain[2:]
	}
	return domain
}

// Check domain format valid
func isValidDomain(s string) bool {
	// Mesti ada dot
	if !strings.Contains(s, ".") {
		return false
	}
	// Bukan CA/Cert issuer name ( detect by spaces / panjang / caps pattern )
	if strings.Contains(s, " ") || len(s) > 100 {
		return false
	}
	// Bukan pattern CA name (mostly ada "CA", "Root", "Authority", "Validation")
	lower := strings.ToLower(s)
	caPatterns := []string{
		" ca ", " root ", " authority ", " validation ",
		" ssl ", " tls ", " rsa ", " ecc ", " ev ",
		"digicert", "sectigo", "comodo", "thawte",
		"geotrust", "globalsign", "godaddy", "gandicert",
		"cloudflare tls", "encryption everywhere", "actalis",
		"usertrust", "gts root",
	}
	for _, pattern := range caPatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}
	return true
}

func executeTLSSniffer(chatID int64, prefix string, startIP, endIP int) {
	defer func() {
		if r := recover(); r != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Error*\n```\n"+fmt.Sprintf("%v", r)+"\n```"))
			clearSessionState(chatID)
		}
	}()

	if startIP < 1 || endIP > 65535 || startIP > endIP {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid IP range. Use: 1-65535")
		bot.Send(msg)
		return
	}

	totalIPs := endIP - startIP + 1

	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🔎 *DOMAIN SNIFF*\n━━━━━━━━━━━━━━━━━━━━\n"+
			"Target: `%s%d - %d`\n"+
			"Total IPs: %d\n\n"+
			"⏳ Scanning...",
		prefix, startIP, endIP, totalIPs))
	statusMsg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(statusMsg)

	startTime := time.Now()

	var wg sync.WaitGroup
	results := make(chan string, 1000)
	uniqueDomains := make(map[string]bool)

	for i := startIP; i <= endIP; i++ {
		ip := fmt.Sprintf("%s%d", prefix, i)
		wg.Add(1)
		go sniffDomains(ip, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for domain := range results {
		if !uniqueDomains[domain] {
			uniqueDomains[domain] = true
		}
	}

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
	sb.WriteString(fmt.Sprintf("Target : %s%d - %d\n", prefix, startIP, endIP))
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
			doc.Caption = fmt.Sprintf("📄 *Domain Sniff Report*\nTarget: `%s%d-%d`\nFound: %d domains",
				prefix, startIP, endIP, len(sortedDomains))
			doc.ParseMode = "Markdown"
			bot.Send(doc)
			os.Remove(fileName)
		}
	}

	clearSessionState(chatID)
}

// =============================================
// HANDLER UNTUK DOMAIN SNIFF INPUT
// =============================================

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
		msg := tgbotapi.NewMessage(chatID, "❌ Format: `prefix start end`\nExample: `104.16.132. 1 254`")
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	prefix := parts[0]
	if !strings.HasSuffix(prefix, ".") {
		prefix += "."
	}

	startIP := 1
	endIP := 254

	if len(parts) >= 2 {
		if s, err := strconv.Atoi(parts[1]); err == nil {
			startIP = s
		}
	}
	if len(parts) >= 3 {
		if e, err := strconv.Atoi(parts[2]); err == nil {
			endIP = e
		}
	}

	clearSessionState(chatID)
	go executeTLSSniffer(chatID, prefix, startIP, endIP)
}
