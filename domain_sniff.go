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
	"sync/atomic"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// =============================================
// DOMAIN SNIFFER - SSL CERTIFICATE EXTRACTOR v2.0
// =============================================

// =============================================
// SNI PROBE CONFIG
// =============================================

type SNIProbe struct {
	SNI         string
	Priority    int
	Description string
}

var sniProbeList = []SNIProbe{
	{SNI: "", Priority: 0, Description: "Direct"},
	{SNI: "cloudflare.com", Priority: 1, Description: "CF Root"},
	{SNI: "www.cloudflare.com", Priority: 1, Description: "CF WWW"},
	{SNI: "cloudflare.net", Priority: 2, Description: "CF Net"},
}

// =============================================
// SECTOR CLASSIFICATION
// =============================================

type SectorConfig struct {
	Name     string
	Icon     string
	Keywords []string
	Priority int
}

var sectorPatterns = []SectorConfig{
	{
		Name: "Banking & Finance", Icon: "🏦",
		Keywords: []string{"bank", "finance", "pay", "payment", "loan", "mortgage", "credit", "debit", "swift", "advisor", "wealth", "capital", "invest", "trading", "forex", "merrill", "lloyds", "hsbc", "citi", "jpmorgan"},
		Priority: 1,
	},
	{
		Name: "Government & Education", Icon: "🏛️",
		Keywords: []string{".gov", ".edu", ".mil", "government", "election", "vote", "senate", "congress", "university", "college", "school", "academy"},
		Priority: 1,
	},
	{
		Name: "Healthcare", Icon: "🏥",
		Keywords: []string{"health", "medical", "hospital", "clinic", "pharma", "drug", "medicine", "patient", "kaiser", "doctor", "care", "healthcare"},
		Priority: 2,
	},
	{
		Name: "Technology & Dev", Icon: "🔧",
		Keywords: []string{"api", "dev", "staging", "admin", "console", "dashboard", "cloud", "server", "host", "aws", "azure", "docker", "k8s", "kubernetes", "backend", "bff"},
		Priority: 2,
	},
	{
		Name: "E-Commerce & Retail", Icon: "🛒",
		Keywords: []string{"shop", "store", "buy", "cart", "checkout", "order", "product", "retail", "market"},
		Priority: 3,
	},
	{
		Name: "Social & Media", Icon: "📱",
		Keywords: []string{"social", "media", "chat", "message", "video", "stream", "photo", "image", "upload", "share", "blog"},
		Priority: 3,
	},
	{
		Name: "CDN & Infrastructure", Icon: "🌐",
		Keywords: []string{"cdn", "static", "assets", "img", "images", "cdn-", "edge", "origin", "cache", "proxy"},
		Priority: 4,
	},
	{
		Name: "Email & Comms", Icon: "📧",
		Keywords: []string{"mail", "email", "smtp", "imap", "webmail", "newsletter", "subscribe", "contact"},
		Priority: 5,
	},
}

func classifySector(domain string) (string, string) {
	domainLower := strings.ToLower(domain)
	for _, sector := range sectorPatterns {
		for _, keyword := range sector.Keywords {
			if strings.Contains(domainLower, keyword) {
				return sector.Name, sector.Icon
			}
		}
	}
	return "Others", "📋"
}

// =============================================
// AUTO-SLICE CONFIG
// =============================================

type ScanBatch struct {
	ID      string
	Prefix  string
	Start   int
	End     int
	IPCount int
	Status  string
	Domains []string
}

const (
	BATCH_SIZE       = 16 // 16 subnets per batch = 4,064 IPs
	RAILWAY_WORKERS  = 200
	NORMAL_WORKERS   = 1000
	SNI_MODE_WORKERS = 400 // For SNI probing mode
)

func getOptimalWorkers() int {
	if os.Getenv("RAILWAY_ENVIRONMENT") != "" || os.Getenv("RAILWAY_MODE") == "true" {
		return 300 // ← 200 → 300 (masih safe!)
	}
	return 1000
}

func isSlash16(start, end int) bool {
	return start == 0 && end == 255
}

func autoSliceToBatches(prefix string, start, end int) []ScanBatch {
	totalSubnets := end - start + 1
	numBatches := (totalSubnets + BATCH_SIZE - 1) / BATCH_SIZE

	var batches []ScanBatch
	for i := 0; i < numBatches; i++ {
		batchStart := start + (i * BATCH_SIZE)
		batchEnd := batchStart + BATCH_SIZE - 1
		if batchEnd > end {
			batchEnd = end
		}
		subnetsInBatch := batchEnd - batchStart + 1

		batches = append(batches, ScanBatch{
			ID:      fmt.Sprintf("batch_%d", i+1),
			Prefix:  prefix,
			Start:   batchStart,
			End:     batchEnd,
			IPCount: subnetsInBatch * 254,
			Status:  "pending",
		})
	}
	return batches
}

// =============================================
// ENHANCED SNIFF WITH SNI PROBING
// =============================================

func sniffDomains(ip string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	dialer := &net.Dialer{
		Timeout: 3 * time.Second, // ← 5s → 3s!
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

// =============================================
// ENHANCED SNIFF WITH MULTI-SNI PROBING
// =============================================

func sniffDomainsWithProbes(ip string, wg *sync.WaitGroup, results chan<- string, probeStats *sync.Map) {
	defer wg.Done()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	foundOnIP := make(map[string]bool)

	for _, probe := range sniProbeList {
		conf := &tls.Config{
			ServerName:         probe.SNI,
			InsecureSkipVerify: true,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", conf)
		if err != nil {
			continue
		}

		certs := conn.ConnectionState().PeerCertificates
		conn.Close()

		for _, cert := range certs {
			// Common Name
			if cert.Subject.CommonName != "" && isValidDomain(cert.Subject.CommonName) {
				domain := cleanWildcard(cert.Subject.CommonName)
				if !foundOnIP[domain] {
					foundOnIP[domain] = true
					results <- domain
					probeStats.Store(domain, probe.Description)
				}
			}
			// SANs
			for _, san := range cert.DNSNames {
				if isValidDomain(san) {
					domain := cleanWildcard(san)
					if !foundOnIP[domain] {
						foundOnIP[domain] = true
						results <- domain
						probeStats.Store(domain, probe.Description)
					}
				}
			}
		}

		// Stop probing if got enough domains from this IP
		if len(foundOnIP) >= 10 {
			break
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

// =============================================
// SMART SCAN DISPATCHER
// =============================================

func executeTLSSniffer(chatID int64, prefix string, startRange, endRange int, isMultiSubnet bool) {
	defer func() {
		if r := recover(); r != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Error*\n```\n"+fmt.Sprintf("%v", r)+"\n```"))
			clearSessionState(chatID)
		}
	}()

	// Detect /16 and auto-slice
	if isMultiSubnet && isSlash16(startRange, endRange) {
		executeAutoSlicedScan(chatID, prefix)
		return
	}

	// Normal scan
	executeNormalScan(chatID, prefix, startRange, endRange, isMultiSubnet)
}

// =============================================
// AUTO-SLICED /16 SCAN
// =============================================

func executeAutoSlicedScan(chatID int64, prefix string) {
	batches := autoSliceToBatches(prefix, 0, 255)
	numWorkers := getOptimalWorkers()

	// Status message
	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"⚠️ *"+toBoldUnicode("/16 RANGE DETECTED")+"*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
			toBoldUnicode("Auto-splitting")+": %d batches\n"+
			toBoldUnicode("Per batch")+": ~4,064 IPs\n"+
			toBoldUnicode("Workers")+": %d (Railway-safe)\n"+
			toBoldUnicode("Est. time")+": ~%d minit\n\n"+
			"⏳ Starting auto-scan...",
		len(batches), numWorkers, len(batches)*30/60))
	statusMsg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(statusMsg)

	allDomains := make(map[string]bool)
	probeStats := &sync.Map{}
	var mu sync.Mutex
	var completedBatches int64
	startTime := time.Now()

	// Process each batch
	for i, batch := range batches {
		// Update status BEFORE each batch
		completed := atomic.LoadInt64(&completedBatches)
		barLen := 10
		filled := int(completed) * barLen / len(batches)
		if filled > barLen {
			filled = barLen
		}
		bar := strings.Repeat("🟩", filled) + strings.Repeat("⬜", barLen-filled)

		mu.Lock()
		domainCount := len(allDomains)
		mu.Unlock()

		updateStatus(chatID, sentMsg.MessageID, fmt.Sprintf(
			"🔄 *"+toBoldUnicode("AUTO-SCAN")+"*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
				"🔍 "+toBoldUnicode("Batch")+" %d/%d: %s%d.* - %d.*\n"+
				"📊 "+toBoldUnicode("Progress")+": %s\n"+
				"💎 "+toBoldUnicode("Found")+": %d domains\n"+
				"⏱️ "+toBoldUnicode("Time")+": %v\n\n"+
				"⏳ Scanning...",
			i+1, len(batches), prefix, batch.Start, batch.End,
			bar, domainCount,
			time.Since(startTime).Round(time.Second)))

		batchDomains := scanSingleBatch(batch, numWorkers)

		mu.Lock()
		for _, d := range batchDomains {
			allDomains[d] = true
		}
		mu.Unlock()

		atomic.AddInt64(&completedBatches, 1)

		// Cooldown between batches
		time.Sleep(500 * time.Millisecond)
	}

	elapsed := time.Since(startTime).Round(time.Second)

	// Final status
	updateStatus(chatID, sentMsg.MessageID, fmt.Sprintf(
		"✅ *"+toBoldUnicode("SCAN COMPLETE")+"*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
			"📊 "+toBoldUnicode("Batches")+": %d/%d done\n"+
			"💎 "+toBoldUnicode("Domains")+": %d found\n"+
			"⏱️ "+toBoldUnicode("Time")+": %v\n\n"+
			"📋 Preparing results...",
		len(batches), len(batches), len(allDomains), elapsed))

	// Sort & present results
	var sortedDomains []string
	for d := range allDomains {
		sortedDomains = append(sortedDomains, d)
	}
	sort.Strings(sortedDomains)

	// Show final result
	showFinalResult(chatID, sentMsg.MessageID, prefix+"0.* - 255.*", 65024, sortedDomains, elapsed, probeStats)
	clearSessionState(chatID)
}

// =============================================
// SINGLE BATCH SCANNER
// =============================================

func scanSingleBatch(batch ScanBatch, numWorkers int) []string {
	var wg sync.WaitGroup
	results := make(chan string, 50000)
	jobs := make(chan string, 1000)

	// Worker pool — START DULU!
	for w := 1; w <= numWorkers; w++ {
		go func() {
			for ip := range jobs {
				sniffDomains(ip, &wg, results)
			}
		}()
	}

	// Queue IPs — WAITGROUP ADD BEFORE SEND!
	for octet := batch.Start; octet <= batch.End; octet++ {
		for i := 1; i <= 254; i++ {
			wg.Add(1)
			jobs <- fmt.Sprintf("%s%d.%d", batch.Prefix, octet, i)
		}
	}
	close(jobs)

	// Wait & close results
	wg.Wait()
	close(results)

	// Collect
	uniqueDomains := make(map[string]bool)
	for d := range results {
		uniqueDomains[d] = true
	}

	var domains []string
	for d := range uniqueDomains {
		domains = append(domains, d)
	}
	return domains
}

// =============================================
// NORMAL SCAN (EXISTING BEHAVIOR)
// =============================================

func executeNormalScan(chatID int64, prefix string, startRange, endRange int, isMultiSubnet bool) {
	umMutex.Lock()
	if u, exists := userData.Users[chatID]; exists {
		u.Scans++
		u.LastScan = time.Now()
	}
	umMutex.Unlock()

	var totalIPs int
	var targetLabel string
	var wg sync.WaitGroup
	numWorkers := getOptimalWorkers()

	results := make(chan string, 50000)
	uniqueDomains := make(map[string]bool)
	probeStats := &sync.Map{}
	var mu sync.Mutex
	startTime := time.Now()

	if isMultiSubnet {
		totalSubnets := endRange - startRange + 1
		totalIPs = totalSubnets * 254
		targetLabel = fmt.Sprintf("%s%d.* - %d.*", prefix, startRange, endRange)
	} else {
		totalIPs = endRange - startRange + 1
		targetLabel = fmt.Sprintf("%s%d - %d", prefix, startRange, endRange)
	}

	jobs := make(chan string, 1000)

	for w := 1; w <= numWorkers; w++ {
		go func() {
			for ip := range jobs {
				sniffDomains(ip, &wg, results)
			}
		}()
	}

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

	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🔎 *"+toBoldUnicode("REVERSE IP LOOKUP")+"*\n━━━━━━━━━━━━━━━━━━━━\n"+
			toBoldUnicode("Target")+": `%s`\n"+
			toBoldUnicode("Workers")+": %d | "+toBoldUnicode("IPs")+": %d\n\n"+
			"⏳ Scanning...",
		targetLabel, numWorkers, totalIPs))
	statusMsg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(statusMsg)

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
					"🔎 *"+toBoldUnicode("REVERSE IP LOOKUP")+"*\n━━━━━━━━━━━━━━━━━━━━\n"+
						toBoldUnicode("Target")+": `%s`\n"+
						toBoldUnicode("Workers")+": %d | "+toBoldUnicode("IPs")+": %d\n"+
						toBoldUnicode("Found")+": %d domains\n"+
						toBoldUnicode("Time")+": %v\n\n"+
						"⏳ Still scanning...",
					targetLabel, numWorkers, totalIPs, count, elapsed))
			case <-done:
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for domain := range results {
		mu.Lock()
		if !uniqueDomains[domain] {
			uniqueDomains[domain] = true
		}
		mu.Unlock()
	}

	close(done)
	elapsed := time.Since(startTime).Round(time.Second)

	var sortedDomains []string
	for d := range uniqueDomains {
		sortedDomains = append(sortedDomains, d)
	}
	sort.Strings(sortedDomains)

	showFinalResult(chatID, sentMsg.MessageID, targetLabel, totalIPs, sortedDomains, elapsed, probeStats)
	clearSessionState(chatID)
}

// =============================================
// ENHANCED RESULT DISPLAY WITH SECTORS
// =============================================

func showFinalResult(chatID int64, messageID int, targetLabel string, totalIPs int, sortedDomains []string, elapsed time.Duration, probeStats *sync.Map) {
	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭──────────────────────────────────╮\n")
	sb.WriteString("│  🔎 " + toBoldUnicode("PARAGON REVERSE IP LOOKUP") + "           │\n")
	sb.WriteString("╰──────────────────────────────────╯\n\n")

	sb.WriteString(toBoldUnicode("Target") + " : " + targetLabel + "\n")
	sb.WriteString(toBoldUnicode("IPs") + "    : " + strconv.Itoa(totalIPs) + "\n")
	sb.WriteString(toBoldUnicode("Found") + "  : " + strconv.Itoa(len(sortedDomains)) + " domains\n")
	sb.WriteString(toBoldUnicode("Time") + "   : " + elapsed.String() + "\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(sortedDomains) == 0 {
		sb.WriteString("❌ " + toBoldUnicode("No domains found.") + "\n")
	} else {
		sectorGroups := make(map[string][]string)
		sectorIcons := make(map[string]string)

		for _, domain := range sortedDomains {
			sectorName, sectorIcon := classifySector(domain)
			sectorGroups[sectorName] = append(sectorGroups[sectorName], domain)
			sectorIcons[sectorName] = sectorIcon
		}

		type sectorResult struct {
			Name     string
			Icon     string
			Domains  []string
			Priority int
		}
		var sectors []sectorResult
		for name, domains := range sectorGroups {
			priority := 99
			for _, sp := range sectorPatterns {
				if sp.Name == name {
					priority = sp.Priority
					break
				}
			}
			sectors = append(sectors, sectorResult{
				Name:     name,
				Icon:     sectorIcons[name],
				Domains:  domains,
				Priority: priority,
			})
		}
		sort.Slice(sectors, func(i, j int) bool {
			return sectors[i].Priority < sectors[j].Priority
		})

		for _, sector := range sectors {
			sectorHeader := fmt.Sprintf("\n%s %s (%d):\n",
				sector.Icon,
				toBoldUnicode(sector.Name),
				len(sector.Domains))
			sb.WriteString(sectorHeader)

			limit := 5
			if len(sector.Domains) < limit {
				limit = len(sector.Domains)
			}
			for i := 0; i < limit; i++ {
				sb.WriteString(fmt.Sprintf("   • %s\n", sector.Domains[i]))
			}
			if len(sector.Domains) > limit {
				sb.WriteString(fmt.Sprintf("   ... +%d more\n", len(sector.Domains)-limit))
			}
		}
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("💡 " + toBoldUnicode("Use /scan <domain> to test") + "\n")
	sb.WriteString("```")

	editMsg := tgbotapi.NewEditMessageText(chatID, messageID, sb.String())
	editMsg.ParseMode = "Markdown"
	editMsg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(editMsg)

	if len(sortedDomains) > 0 {
		fileName := fmt.Sprintf("sniff_%s_%d.txt",
			strings.ReplaceAll(
				strings.ReplaceAll(targetLabel, " ", "_"),
				".", "_"),
			time.Now().Unix())
		content := strings.Join(sortedDomains, "\n")
		err := os.WriteFile(fileName, []byte(content), 0644)
		if err == nil {
			doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(fileName))
			doc.Caption = fmt.Sprintf("<b>Domain Sniff Report</b>\nTarget: %s\nFound: %d domains",
				targetLabel, len(sortedDomains))
			doc.ParseMode = "HTML"
			bot.Send(doc)
			os.Remove(fileName)
		}
	}
}

// =============================================
// INPUT HANDLER
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
		msg := tgbotapi.NewMessage(chatID, "```\n"+
			"╭──────────────────────────────────╮\n"+
			"│  🔎 "+toBoldUnicode("PARAGON REVERSE IP LOOKUP")+"                    │\n"+
			"╰──────────────────────────────────╯\n\n"+
			toBoldUnicode("Format")+": prefix start end\n\n"+
			"📋 "+toBoldUnicode("Examples")+":\n"+
			"  104.16.132. 1 254  → Single subnet\n"+
			"  104.16. 132 135    → /22 (4 subnets)\n"+
			"  104.16. 0 255      → /16 (Auto-sliced!)\n\n"+
			"⚡ "+toBoldUnicode("NEW")+": /16 auto-sliced to 16 batches\n"+
			"⚡ "+toBoldUnicode("NEW")+": Results grouped by sector\n"+
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
		"╭──────────────────────────────────╮\n"+
		"│  ❌ "+toBoldUnicode("INVALID PREFIX")+"                 │\n"+
		"╰──────────────────────────────────╯\n\n"+
		toBoldUnicode("Use 2 segments")+": 104.16. 0 255\n"+
		toBoldUnicode("Or 3 segments")+": 104.16.132. 1 254\n"+
		"```")
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = getCancelKeyboard()
	bot.Send(msg)
}
