package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
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
// CONFIG STRUCTURE
// =============================================

type TesterConfig struct {
	MaxWorkers      int
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	ConnectTimeout  time.Duration
	ChunkMinSize    int
	ChunkMaxSize    int
	JitterMinMs     int
	JitterMaxMs     int
	MaxRetries      int
	EnableKeepAlive bool
	MinTLSVersion   uint16
	MaxTLSVersion   uint16
}

func DefaultConfig() TesterConfig {
	return TesterConfig{
		MaxWorkers:      10,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		ConnectTimeout:  5 * time.Second,
		ChunkMinSize:    5,
		ChunkMaxSize:    20,
		JitterMinMs:     5,
		JitterMaxMs:     30,
		MaxRetries:      1,
		EnableKeepAlive: true,
		MinTLSVersion:   tls.VersionTLS12,
		MaxTLSVersion:   tls.VersionTLS13,
	}
}

// =============================================
// RESULT STRUCTURE
// =============================================

type PayloadTestResult struct {
	IsWorking    bool
	Payload      string
	Method       string
	ResponseCode string
	StatusCode   int
	Quality      string
	Score        int
	ResponseSize int
	LatencyMs    int
	Port         int
	Server       string
	ContentType  string
	Via          string
	CFRay        string
	Retries      int
	Error        string
	IsTimeout    bool
}

// =============================================
// WORKER POOL STRUCTURES
// =============================================

type testJob struct {
	Index    int
	IP       string
	Port     int
	Template string
	Name     string
	Host     string
	VPS      string
	SNI      string
	Config   TesterConfig
}

type testResult struct {
	Index  int
	Result PayloadTestResult
	Error  error
}

// =============================================
// STATUS COUNTER FOR BREAKDOWN
// =============================================

type StatusCount struct {
	Code  int
	Count int
}

func countStatusCodes(results []PayloadTestResult, isWorking bool) []StatusCount {
	codeMap := make(map[int]int)
	for _, r := range results {
		if r.IsWorking == isWorking && r.StatusCode > 0 {
			codeMap[r.StatusCode]++
		}
	}
	var counts []StatusCount
	for code, count := range codeMap {
		counts = append(counts, StatusCount{Code: code, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	return counts
}

func getStatusEmoji(code int) string {
	switch {
	case code == 200:
		return "🟢200"
	case code == 201:
		return "🟢201"
	case code == 101:
		return "🔥101"
	case code == 301:
		return "🔄301"
	case code == 302:
		return "🔄302"
	case code == 307, code == 308:
		return "🔄307"
	case code == 401:
		return "🔐401"
	case code == 403:
		return "⚠️403"
	case code == 400:
		return "❌400"
	case code == 404:
		return "❓404"
	case code == 405:
		return "🚫405"
	case code == 500:
		return "💥500"
	case code == 502:
		return "🚪502"
	case code == 503:
		return "⏳503"
	default:
		return fmt.Sprintf("·%d", code)
	}
}

func formatStatusCounts(counts []StatusCount, maxShow int) string {
	if len(counts) == 0 {
		return "none"
	}
	limit := maxShow
	if len(counts) < limit {
		limit = len(counts)
	}
	var parts []string
	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%s:%d", getStatusEmoji(counts[i].Code), counts[i].Count))
	}
	return strings.Join(parts, " | ")
}

// =============================================
// PROGRESS TRACKER (ATOMIC)
// =============================================

type ProgressTracker struct {
	Completed   int64
	Total       int64
	Working     int64
	Dead        int64
	mu          sync.RWMutex
	Status200   int64
	Status101   int64
	BestScore   int64
	BestMethod  string
	BestLatency int64
}

func (pt *ProgressTracker) IncrementCompleted() {
	atomic.AddInt64(&pt.Completed, 1)
}

func (pt *ProgressTracker) IncrementWorking() {
	atomic.AddInt64(&pt.Working, 1)
}

func (pt *ProgressTracker) IncrementDead() {
	atomic.AddInt64(&pt.Dead, 1)
}

func (pt *ProgressTracker) Increment200() {
	atomic.AddInt64(&pt.Status200, 1)
}

func (pt *ProgressTracker) Increment101() {
	atomic.AddInt64(&pt.Status101, 1)
}

func (pt *ProgressTracker) UpdateBest(score int, method string, latency int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if score > int(pt.BestScore) || (score == int(pt.BestScore) && latency < int(pt.BestLatency)) {
		pt.BestScore = int64(score)
		pt.BestMethod = method
		pt.BestLatency = int64(latency)
	}
}

func (pt *ProgressTracker) GetProgress() (completed, total, working, dead int64) {
	return atomic.LoadInt64(&pt.Completed),
		pt.Total,
		atomic.LoadInt64(&pt.Working),
		atomic.LoadInt64(&pt.Dead)
}

func (pt *ProgressTracker) GetStats() (status200, status101 int64, bestScore int64, bestMethod string, bestLatency int64) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return atomic.LoadInt64(&pt.Status200),
		atomic.LoadInt64(&pt.Status101),
		pt.BestScore,
		pt.BestMethod,
		pt.BestLatency
}

// =============================================
// PROGRESS BAR GENERATOR
// =============================================

func generateProgressBar(completed, total int64) string {
	const barWidth = 20
	if total == 0 {
		return "[░░░░░░░░░░░░░░░░░░░░] 0%"
	}
	progress := int(float64(completed) / float64(total) * barWidth)
	percentage := int(float64(completed) / float64(total) * 100)
	var bar strings.Builder
	bar.WriteString("[")
	for i := 0; i < barWidth; i++ {
		if i < progress {
			bar.WriteString("█")
		} else if i == progress {
			bar.WriteString("▓")
		} else {
			bar.WriteString("░")
		}
	}
	bar.WriteString(fmt.Sprintf("] %d%%", percentage))
	return bar.String()
}

func generateStatusEmoji(completed, total int64) string {
	ratio := float64(completed) / float64(total)
	switch {
	case ratio >= 1.0:
		return "✅"
	case ratio >= 0.75:
		return "🔥"
	case ratio >= 0.50:
		return "⚡"
	case ratio >= 0.25:
		return "🔄"
	default:
		return "🧪"
	}
}

// =============================================
// CORE TESTING FUNCTION
// =============================================

func testPayloadInjectionAdvanced(ip string, port int, template string, name string, host string, vps string, sni string, config TesterConfig) PayloadTestResult {
	result := PayloadTestResult{
		IsWorking:  false,
		Method:     name,
		Port:       port,
		Payload:    template,
		StatusCode: 0,
		IsTimeout:  false,
	}

	cleanPayload := strings.ReplaceAll(template, "[crlf]", "\r\n")
	cleanPayload = strings.ReplaceAll(cleanPayload, "[split]", "\r\n\r\n")
	cleanPayload = strings.ReplaceAll(cleanPayload, "[host]", host)
	cleanPayload = strings.ReplaceAll(cleanPayload, "[ip]", ip)
	cleanPayload = strings.ReplaceAll(cleanPayload, "[port]", strconv.Itoa(port))
	cleanPayload = strings.ReplaceAll(cleanPayload, "[ua]", randomUA())

	fVps := vps
	if fVps == "" {
		fVps = host
	}
	fSni := sni
	if fSni == "" {
		fSni = host
	}
	cleanPayload = strings.ReplaceAll(cleanPayload, "[vps]", fVps)
	cleanPayload = strings.ReplaceAll(cleanPayload, "[sni]", fSni)

	var conn net.Conn
	var err error
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result.Retries = attempt
		if port == 443 {
			conf := &tls.Config{
				ServerName:         fSni,
				InsecureSkipVerify: true,
				MinVersion:         config.MinTLSVersion,
				MaxVersion:         config.MaxTLSVersion,
			}
			dialer := &net.Dialer{Timeout: config.DialTimeout}
			conn, err = tls.DialWithDialer(dialer, "tcp", address, conf)
		} else {
			conn, err = net.DialTimeout("tcp", address, config.DialTimeout)
		}
		if err == nil {
			break
		}
		if attempt < config.MaxRetries {
			time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
		}
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	start := time.Now()
	conn.SetDeadline(time.Now().Add(config.ReadTimeout))
	raw := []byte(cleanPayload)
	totalWritten := 0

	if len(raw) > 0 {
		for totalWritten < len(raw) {
			remaining := len(raw) - totalWritten
			chunkSize := config.ChunkMinSize + rand.Intn(config.ChunkMaxSize-config.ChunkMinSize+1)
			if chunkSize > remaining {
				chunkSize = remaining
			}
			n, writeErr := conn.Write(raw[totalWritten : totalWritten+chunkSize])
			if writeErr != nil {
				result.LatencyMs = int(time.Since(start).Milliseconds())
				result.Error = writeErr.Error()
				return result
			}
			totalWritten += n
			if totalWritten < len(raw) {
				jitter := time.Duration(config.JitterMinMs+rand.Intn(config.JitterMaxMs-config.JitterMinMs+1)) * time.Millisecond
				time.Sleep(jitter)
			}
		}
	}

	reader := bufio.NewReaderSize(conn, 16384)
	var responseBuffer strings.Builder
	totalBytes := 0
	readTimedOut := false

	for {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		line, isPrefix, readErr := reader.ReadLine()
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				readTimedOut = true
			}
			if readErr == io.EOF {
				break
			}
			break
		}
		responseBuffer.Write(line)
		responseBuffer.WriteString("\r\n")
		totalBytes += len(line) + 2
		if len(line) == 0 && !isPrefix {
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			body := make([]byte, 65536)
			n, _ := reader.Read(body)
			if n > 0 {
				responseBuffer.Write(body[:n])
				totalBytes += n
			}
			break
		}
	}

	result.LatencyMs = int(time.Since(start).Milliseconds())

	if readTimedOut && totalBytes == 0 {
		result.IsTimeout = true
		result.Error = "read timeout (no response)"
		return result
	}

	if totalBytes > 0 {
		resp := responseBuffer.String()
		result.ResponseSize = totalBytes
		respReader := bufio.NewReader(strings.NewReader(resp))
		httpResp, parseErr := http.ReadResponse(respReader, nil)
		if parseErr == nil && httpResp != nil {
			result.StatusCode = httpResp.StatusCode
			result.ResponseCode = fmt.Sprintf("HTTP/%d.%d %d %s",
				httpResp.ProtoMajor, httpResp.ProtoMinor,
				httpResp.StatusCode, http.StatusText(httpResp.StatusCode))
			result.Server = httpResp.Header.Get("Server")
			result.ContentType = httpResp.Header.Get("Content-Type")
			result.Via = httpResp.Header.Get("Via")
			result.CFRay = httpResp.Header.Get("CF-RAY")

			switch {
			case result.StatusCode >= 200 && result.StatusCode < 300:
				result.IsWorking = true
			case result.StatusCode == 101:
				result.IsWorking = true
			case result.StatusCode >= 300 && result.StatusCode < 400:
				result.IsWorking = true
				result.Error = fmt.Sprintf("Redirect %d", result.StatusCode)
			case result.StatusCode == 401 || result.StatusCode == 407:
				result.IsWorking = true
				result.Error = fmt.Sprintf("Auth required (%d)", result.StatusCode)
			case result.StatusCode == 403:
				if result.ResponseSize > 500 {
					result.IsWorking = true
					result.Error = fmt.Sprintf("WAF/DNS blocked (%d)", result.StatusCode)
				} else {
					result.IsWorking = false
					result.Error = fmt.Sprintf("WAF silent drop (%d)", result.StatusCode)
				}
			case result.StatusCode == 405:
				result.IsWorking = false
				result.Error = fmt.Sprintf("Method not allowed (%d)", result.StatusCode)
			case result.StatusCode == 400:
				result.IsWorking = false
				result.Error = fmt.Sprintf("Bad request (%d)", result.StatusCode)
			case result.StatusCode >= 500:
				result.IsWorking = false
				result.Error = fmt.Sprintf("Server error (%d)", result.StatusCode)
			default:
				result.IsWorking = false
				result.Error = fmt.Sprintf("Unknown status (%d)", result.StatusCode)
			}

			result.Quality, result.Score = calculateQualityScore(httpResp, result)
			result.Score += calculateBonusScore(result, httpResp)

			if readTimedOut {
				result.Score -= 15
				result.Quality = "⏰ " + result.Quality
			}
			if result.Score > 100 {
				result.Score = 100
			}
			if result.Score < 0 {
				result.Score = 0
			}
		} else {
			respUpper := strings.ToUpper(resp)
			if strings.Contains(respUpper, "HTTP/") {
				firstLine := strings.SplitN(resp, "\r\n", 2)[0]
				if firstLine == "" {
					firstLine = strings.SplitN(resp, "\n", 2)[0]
				}
				result.ResponseCode = strings.TrimSpace(firstLine)
				result.Quality = "⚠️ PARSE"
				result.Score = 15
				result.IsWorking = false
				result.Error = "Failed to parse HTTP response"
			}
		}
	}

	return result
}

// =============================================
// ENHANCED QUALITY SCORING
// =============================================

func calculateQualityScore(resp *http.Response, result PayloadTestResult) (string, int) {
	statusCode := resp.StatusCode
	switch {
	case statusCode == 101:
		return "🔥 WEBSOCKET", 100
	case statusCode == 200:
		baseScore := 85
		if result.CFRay != "" {
			return "☁️ CLOUDFLARE", min(baseScore+3, 90)
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudfront") {
			return "☁️ CLOUDFRONT", min(baseScore+2, 88)
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "akamai") {
			return "☁️ AKAMAI", min(baseScore+2, 88)
		}
		contentLength := resp.ContentLength
		if contentLength > 10000 {
			return "✅ OK (LARGE)", min(baseScore+10, 98)
		}
		return "✅ OK", baseScore
	case statusCode == 301 || statusCode == 302:
		location := resp.Header.Get("Location")
		if location != "" {
			return "🔄 REDIRECT", 60
		}
		return "🔄 REDIRECT", 55
	case statusCode == 304:
		return "💾 CACHED", 45
	case statusCode == 307 || statusCode == 308:
		return "🔄 PERM REDIR", 50
	case statusCode == 400:
		return "❌ BAD REQ", 10
	case statusCode == 401:
		return "🔐 AUTH", 45
	case statusCode == 403:
		return "⚠️ CDN/WAF", 50
	case statusCode == 404:
		return "❓ NOT FOUND", 25
	case statusCode == 405:
		return "🚫 METHOD", 15
	case statusCode == 407:
		return "🔐 PROXY AUTH", 35
	case statusCode == 408:
		return "⏰ TIMEOUT", 5
	case statusCode == 429:
		return "🚦 RATE LIMIT", 15
	case statusCode == 500:
		return "💥 SRV ERROR", 30
	case statusCode == 502:
		return "🚪 BAD GATEWAY", 20
	case statusCode == 503:
		return "⏳ UNAVAIL", 15
	case statusCode == 504:
		return "⏰ GW TIMEOUT", 5
	default:
		if statusCode >= 200 && statusCode < 300 {
			return "✅ SUCCESS", 65
		}
		if statusCode >= 300 && statusCode < 400 {
			return "🔄 REDIRECT", 50
		}
		if statusCode >= 400 && statusCode < 500 {
			return "🚫 CLIENT ERR", 15
		}
		if statusCode >= 500 {
			return "💥 SERVER ERR", 10
		}
		return "❓ OTHER", 10
	}
}

func calculateBonusScore(result PayloadTestResult, resp *http.Response) int {
	bonus := 0
	if result.LatencyMs < 50 {
		bonus += 15
	} else if result.LatencyMs < 100 {
		bonus += 10
	} else if result.LatencyMs < 300 {
		bonus += 5
	} else if result.LatencyMs > 5000 {
		bonus -= 30
	} else if result.LatencyMs > 1500 {
		bonus -= 20
	} else if result.LatencyMs > 1000 {
		bonus -= 10
	}
	if result.ResponseSize > 5000 {
		bonus += 10
	} else if result.ResponseSize > 2000 {
		bonus += 5
	} else if result.ResponseSize > 500 {
		bonus += 3
	} else if result.ResponseSize < 100 && result.ResponseSize > 0 {
		bonus -= 5
	}
	contentType := strings.ToLower(result.ContentType)
	if strings.Contains(contentType, "text/html") {
		bonus += 3
	}
	if strings.Contains(contentType, "application/json") {
		bonus += 4
	}
	if result.Server != "" {
		bonus += 3
	}
	if result.Via != "" {
		bonus += 2
	}
	return bonus
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================
// WORKER POOL
// =============================================

func workerPoolTest(jobs <-chan testJob, results chan<- testResult, tracker *ProgressTracker, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		result := testPayloadInjectionAdvanced(
			job.IP, job.Port, job.Template, job.Name,
			job.Host, job.VPS, job.SNI, job.Config,
		)
		tracker.IncrementCompleted()
		if result.IsWorking {
			tracker.IncrementWorking()
			if result.StatusCode == 200 {
				tracker.Increment200()
			}
			if result.StatusCode == 101 {
				tracker.Increment101()
			}
			tracker.UpdateBest(result.Score, result.Method, result.LatencyMs)
		} else {
			tracker.IncrementDead()
		}
		results <- testResult{Index: job.Index, Result: result, Error: nil}
	}
}

// =============================================
// SMART REPLACE GUIDE
// =============================================

func smartReplaceGuide(template string, host, vps, sni string) string {
	var guide strings.Builder
	guide.WriteString("Replace:\n")
	guide.WriteString(fmt.Sprintf("  [host] → %s (or your VPS)\n", host))
	if strings.Contains(template, "[vps]") && vps != "" {
		guide.WriteString(fmt.Sprintf("  [vps]  → %s\n", vps))
	}
	if strings.Contains(template, "[sni]") && sni != "" {
		guide.WriteString(fmt.Sprintf("  [sni]  → %s\n", sni))
	}
	if strings.Contains(template, "[ua]") {
		guide.WriteString("  [ua]   → Random User-Agent\n")
	}
	if strings.Contains(template, "[port]") {
		guide.WriteString("  [port] → 443 or 80\n")
	}
	if strings.Contains(template, "[split]") {
		guide.WriteString("  [split] → double newline\n")
	}
	if strings.Contains(template, "[ip]") {
		guide.WriteString("  [ip]   → Your VPS IP\n")
	}
	return guide.String()
}

// =============================================
// BOT HANDLER
// =============================================

func executePayloadTest(chatID int64, target string) {
	defer func() {
		if r := recover(); r != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Internal Error*\n```\n"+fmt.Sprintf("%v", r)+"\n```"))
			clearSessionState(chatID)
		}
	}()

	umMutex.Lock()
	if u, exists := userData.Users[chatID]; exists {
		u.Scans++
		u.LastScan = time.Now()
	}
	umMutex.Unlock()

	target = strings.TrimSpace(target)
	if target == "" || !strings.Contains(target, ".") {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid host\n\nFormat: `host [vps] [sni]`\nExample: `airasia.com`")
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	parts := strings.Fields(target)
	host := parts[0]
	vps := ""
	sni := ""
	if len(parts) >= 2 {
		vps = parts[1]
	}
	if len(parts) >= 3 {
		sni = parts[2]
	}

	specifiedPort := 0
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		specifiedPort, _ = strconv.Atoi(p)
	}

	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf("💉 *Testing:* `%s`\n━━━━━━━━━━━━━━━━━━━━\n⏳ Resolving...", host))
	statusMsg.ParseMode = "Markdown"
	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ Failed to send status message"))
		clearSessionState(chatID)
		return
	}

	ip, err := resolveIPv4(host)
	if err != nil {
		updateStatus(chatID, sentMsg.MessageID, fmt.Sprintf("❌ Failed to resolve: %s", host))
		clearSessionState(chatID)
		return
	}

	var portsToTest []int
	if specifiedPort != 0 {
		portsToTest = []int{specifiedPort}
	} else {
		portsToTest = []int{443, 80}
	}

	totalTests := len(payloadList) * len(portsToTest)
	config := DefaultConfig()

	jobs := make(chan testJob, totalTests)
	results := make(chan testResult, totalTests)
	var wg sync.WaitGroup

	tracker := &ProgressTracker{Total: int64(totalTests)}

	for i := 0; i < config.MaxWorkers; i++ {
		wg.Add(1)
		go workerPoolTest(jobs, results, tracker, &wg)
	}

	jobIndex := 0
	for _, port := range portsToTest {
		for _, p := range payloadList {
			jobs <- testJob{
				Index:    jobIndex,
				IP:       ip,
				Port:     port,
				Template: p.Template,
				Name:     p.Name,
				Host:     host,
				VPS:      vps,
				SNI:      sni,
				Config:   config,
			}
			jobIndex++
		}
	}
	close(jobs)

	stopProgress := make(chan bool)
	progressDone := make(chan bool)

	go func() {
		ticker := time.NewTicker(800 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				completed, total, working, dead := tracker.GetProgress()
				status200, status101, bestScore, bestMethod, bestLatency := tracker.GetStats()
				bar := generateProgressBar(completed, total)
				emoji := generateStatusEmoji(completed, total)
				progressText := fmt.Sprintf(
					"💉 *Testing:* `%s`\nIP: `%s` | Ports: %v\n━━━━━━━━━━━━━━━━━━━━\n"+
						"%s %s\n🧪 Tested: %d/%d\n✅ Alive: %d | ❌ Dead: %d\n🟢 200 OK: %d | 🔥 WS: %d\n",
					host, ip, portsToTest, emoji, bar, completed, total, working, dead, status200, status101)
				if bestScore > 0 {
					progressText += fmt.Sprintf("⭐ Best: %s (%d/100, %dms)\n", bestMethod, bestScore, bestLatency)
				}
				progressText += "━━━━━━━━━━━━━━━━━━━━\n⚡ 10 workers | DPI Bypass"
				updateStatus(chatID, sentMsg.MessageID, progressText)
			case <-stopProgress:
				progressDone <- true
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []PayloadTestResult
	for r := range results {
		allResults = append(allResults, r.Result)
	}

	stopProgress <- true
	<-progressDone

	// =============================================
	// CATEGORIZE + VALIDATE + BUGHOST DETECTION
	// =============================================
	matchCount := 0
	rejectedCount := 0
	deadCount := 0
	cdnDetected := false
	sniMismatch := false
	serverType := ""
	cdnList := make(map[string]bool)

	for _, r := range allResults {
		if !r.IsWorking {
			if r.IsTimeout || (r.Error != "" && (strings.Contains(r.Error, "timeout") || strings.Contains(r.Error, "no response"))) {
				deadCount++
			} else {
				rejectedCount++
			}
			continue
		}
		matchCount++
		if r.Server != "" {
			serverLower := strings.ToLower(r.Server)
			if strings.Contains(serverLower, "cloudflare") {
				cdnDetected = true
				cdnList["Cloudflare"] = true
			} else if strings.Contains(serverLower, "akamai") {
				cdnDetected = true
				cdnList["Akamai"] = true
			} else if strings.Contains(serverLower, "gws") || strings.Contains(serverLower, "google") {
				cdnDetected = true
				cdnList["Google"] = true
			} else if strings.Contains(serverLower, "cloudfront") {
				cdnDetected = true
				cdnList["AWS CloudFront"] = true
			} else if strings.Contains(serverLower, "gunicorn") || strings.Contains(serverLower, "nginx") || strings.Contains(serverLower, "apache") {
				if !cdnDetected {
					serverType = r.Server
				}
			}
		}
		if r.CFRay != "" {
			cdnDetected = true
			cdnList["Cloudflare"] = true
		}
	}

	cdnListStr := ""
	if len(cdnList) > 0 {
		var cdnNames []string
		for name := range cdnList {
			cdnNames = append(cdnNames, name)
		}
		cdnListStr = strings.Join(cdnNames, " + ")
	}

	if sni != "" && sni != host {
		sniMismatch = true
	}

	totalAlive := matchCount + rejectedCount
	aliveRatio := float64(0)
	if totalAlive > 0 {
		aliveRatio = float64(matchCount) / float64(totalAlive) * 100
	}

	var validationStatus string
	var validationMessage string
	var extraInfo []string

	if cdnDetected && cdnListStr != "" {
		extraInfo = append(extraInfo, fmt.Sprintf("🌐 CDN: %s", cdnListStr))
	} else if serverType != "" {
		extraInfo = append(extraInfo, fmt.Sprintf("🖥️ Server: %s", serverType))
	}
	if sniMismatch {
		extraInfo = append(extraInfo, "🎭 SNI Spoof: Possible")
	}
	extraInfo = append(extraInfo, fmt.Sprintf("📊 Match Rate: %.0f%% (%d/%d)", aliveRatio, matchCount, totalAlive))

	switch {
	case cdnDetected && matchCount > 10:
		validationStatus = "🔥 CDN BUGHOST"
		validationMessage = fmt.Sprintf("CDN detected (%s) + %d payloads matched — confirmed bughost ready to use!", cdnListStr, matchCount)
	case matchCount > 40 && rejectedCount == 0:
		validationStatus = "🔴 GENERIC SERVER"
		validationMessage = "Almost all payloads accepted — likely generic/test server, NOT a bughost!"
	case matchCount > 20 && rejectedCount > 5:
		validationStatus = "🔥 STRONG BUGHOST"
		validationMessage = "Many payloads matched with some rejected — this is real bughost behavior!"
	case matchCount >= 10 && rejectedCount > 0:
		validationStatus = "🟢 CONFIRMED BUGHOST"
		validationMessage = "Payloads matched — bughost ready to use!"
	case matchCount >= 5:
		validationStatus = "🟡 POSSIBLE BUGHOST"
		validationMessage = "Some payloads matched — test manually for zero rated."
	case matchCount > 0:
		validationStatus = "⚠️ WEAK SIGNAL"
		validationMessage = "Very few payloads matched — might be false positive."
	default:
		validationStatus = "🔴 DEAD HOST"
		validationMessage = "No payload matched — host may be down or not a bughost."
	}

	// =============================================
	// FILTER & SORT
	// =============================================
	var workingResults []PayloadTestResult
	for _, r := range allResults {
		if r.IsWorking {
			workingResults = append(workingResults, r)
		}
	}

	sort.Slice(workingResults, func(i, j int) bool {
		iIs200 := workingResults[i].StatusCode == 200
		jIs200 := workingResults[j].StatusCode == 200
		if iIs200 && !jIs200 {
			return true
		}
		if !iIs200 && jIs200 {
			return false
		}
		if workingResults[i].Score != workingResults[j].Score {
			return workingResults[i].Score > workingResults[j].Score
		}
		if workingResults[i].LatencyMs != workingResults[j].LatencyMs {
			return workingResults[i].LatencyMs < workingResults[j].LatencyMs
		}
		iIsWS := workingResults[i].StatusCode == 101
		jIsWS := workingResults[j].StatusCode == 101
		return iIsWS && !jIsWS
	})

	// =============================================
	// BUILD FINAL SUMMARY
	// =============================================
	qualityCount := make(map[string]int)
	for _, r := range workingResults {
		qualityCount[r.Quality]++
	}

	// Status breakdown
	matchCounts := countStatusCodes(allResults, true)
	rejectedCounts := countStatusCodes(allResults, false)
	matchBreakdown := formatStatusCounts(matchCounts, 4)
	rejectedBreakdown := formatStatusCounts(rejectedCounts, 3)

	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│   💉 PAYLOAD TESTER     │\n")
	sb.WriteString("│   ⚡ Advanced Engine    │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")
	sb.WriteString(fmt.Sprintf("Host : %s\n", host))
	sb.WriteString(fmt.Sprintf("IP   : %s\n", ip))
	if vps != "" {
		sb.WriteString(fmt.Sprintf("VPS  : %s\n", vps))
	}
	if sni != "" {
		sb.WriteString(fmt.Sprintf("SNI  : %s\n", sni))
	}
	sb.WriteString(fmt.Sprintf("Ports: %v\n", portsToTest))
	sb.WriteString(fmt.Sprintf("Engine: %d workers | DPI Bypass\n\n", config.MaxWorkers))
	sb.WriteString(fmt.Sprintf("%s\n", validationStatus))
	sb.WriteString(fmt.Sprintf("%s\n", validationMessage))
	for _, info := range extraInfo {
		sb.WriteString(fmt.Sprintf("%s\n", info))
	}

	// Smart summary with breakdown
	if matchCount > 0 && rejectedCount > 0 {
		sb.WriteString(fmt.Sprintf("\n✅ Match: %d (%s) | ❌ Rejected: %d (%s) | 💀 Dead: %d\n",
			matchCount, matchBreakdown, rejectedCount, rejectedBreakdown, deadCount))
	} else if matchCount > 0 {
		sb.WriteString(fmt.Sprintf("\n✅ Match: %d (%s) | ❌ Rejected: %d | 💀 Dead: %d\n",
			matchCount, matchBreakdown, rejectedCount, deadCount))
	} else {
		sb.WriteString(fmt.Sprintf("\n✅ Match: %d | ❌ Rejected: %d | 💀 Dead: %d\n",
			matchCount, rejectedCount, deadCount))
	}
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if len(qualityCount) > 0 {
		sb.WriteString("\n📊 Response Breakdown:\n")
		type qc struct {
			name  string
			count int
		}
		var qcs []qc
		for q, c := range qualityCount {
			qcs = append(qcs, qc{q, c})
		}
		sort.Slice(qcs, func(i, j int) bool {
			priority := map[string]int{
				"✅ OK": 1, "✅ OK (LARGE)": 2, "🔥 WEBSOCKET": 3,
				"☁️ CLOUDFLARE": 4, "☁️ CLOUDFRONT": 5,
				"🔄 REDIRECT": 6, "🔐 AUTH": 7, "⚠️ CDN/WAF": 8,
			}
			pi, _ := priority[qcs[i].name]
			pj, _ := priority[qcs[j].name]
			if pi == 0 {
				pi = 99
			}
			if pj == 0 {
				pj = 99
			}
			return pi < pj
		})
		for _, qc := range qcs {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", qc.name, qc.count))
		}
	}

	if len(workingResults) > 0 {
		limit := 5
		if len(workingResults) < limit {
			limit = len(workingResults)
		}
		sb.WriteString(fmt.Sprintf("\n🔥 TOP %d MATCHED PAYLOADS:\n\n", limit))
		for i := 0; i < limit; i++ {
			r := workingResults[i]
			sb.WriteString(fmt.Sprintf("%s [%s] Port:%d | %dms | %d/100\n",
				r.Quality, r.Method, r.Port, r.LatencyMs, r.Score))
			sb.WriteString(fmt.Sprintf("   Status: %s\n", r.ResponseCode))
			if r.Server != "" {
				sb.WriteString(fmt.Sprintf("   Server: %s\n", r.Server))
			}
			if r.CFRay != "" {
				sb.WriteString(fmt.Sprintf("   CDN: Cloudflare\n"))
			}
			sb.WriteString(fmt.Sprintf("   Payload: `%s`\n", r.Payload))
			sb.WriteString("   ────────────────────────\n")
		}
	} else {
		sb.WriteString("\n❌ No payload matched.\n")
	}
	sb.WriteString("```")

	editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, sb.String())
	editMsg.ParseMode = "Markdown"
	editMsg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(editMsg)

	if len(workingResults) > 0 {
		fileName := fmt.Sprintf("payload_%s_%d.txt", strings.ReplaceAll(host, ".", "_"), time.Now().Unix())
		fileContent := buildPayloadFile(host, ip, vps, sni, portsToTest, workingResults, allResults, config)
		err := os.WriteFile(fileName, []byte(fileContent), 0644)
		if err == nil {
			doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(fileName))
			doc.Caption = fmt.Sprintf("📄 *Payload Report*\nHost: `%s`\n%s\n✅ Match: %d (%s) | ❌ Rejected: %d | 💀 Dead: %d\n⚡ %d workers",
				host, validationStatus, matchCount, matchBreakdown, rejectedCount, deadCount, config.MaxWorkers)
			doc.ParseMode = "Markdown"
			bot.Send(doc)
			os.Remove(fileName)
		}
	}

	clearSessionState(chatID)
}

// =============================================
// FILE BUILDER
// =============================================

func buildPayloadFile(host, ip, vps, sni string, ports []int, working, all []PayloadTestResult, config TesterConfig) string {
	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════\n")
	sb.WriteString("    💉 PAYLOAD TEST REPORT\n")
	sb.WriteString("    ⚡ Advanced Engine v2.0\n")
	sb.WriteString("═══════════════════════════════════════\n\n")
	sb.WriteString(fmt.Sprintf("Host   : %s\n", host))
	sb.WriteString(fmt.Sprintf("IP     : %s\n", ip))
	if vps != "" {
		sb.WriteString(fmt.Sprintf("VPS    : %s\n", vps))
	}
	if sni != "" {
		sb.WriteString(fmt.Sprintf("SNI    : %s\n", sni))
	}
	sb.WriteString(fmt.Sprintf("Ports  : %v\n", ports))
	sb.WriteString(fmt.Sprintf("Date   : %s\n", time.Now().Format("02 Jan 2006 15:04:05")))
	sb.WriteString(fmt.Sprintf("Engine : %d workers | DPI Bypass\n", config.MaxWorkers))
	sb.WriteString(fmt.Sprintf("Total  : %d working / %d tested\n\n", len(working), len(all)))

	sb.WriteString("✅ WORKING PAYLOADS (by score, 200 first)\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	for i, r := range working {
		sb.WriteString(fmt.Sprintf("%d. [%s] Port:%d | %dms | Score: %d/100 | %s\n",
			i+1, r.Method, r.Port, r.LatencyMs, r.Score, r.Quality))
		sb.WriteString(fmt.Sprintf("Status  : %s (HTTP %d)\n", r.ResponseCode, r.StatusCode))
		if r.Server != "" {
			sb.WriteString(fmt.Sprintf("Server  : %s\n", r.Server))
		}
		if r.ContentType != "" {
			sb.WriteString(fmt.Sprintf("Type    : %s\n", r.ContentType))
		}
		if r.CFRay != "" {
			sb.WriteString(fmt.Sprintf("CDN     : Cloudflare (CF-RAY: %s)\n", r.CFRay))
		}
		if r.Via != "" {
			sb.WriteString(fmt.Sprintf("Via     : %s\n", r.Via))
		}
		if r.Retries > 0 {
			sb.WriteString(fmt.Sprintf("Retries : %d\n", r.Retries))
		}
		sb.WriteString(fmt.Sprintf("Size    : %d bytes\n", r.ResponseSize))
		sb.WriteString(fmt.Sprintf("Payload :\n%s\n\n", r.Payload))
		sb.WriteString(smartReplaceGuide(r.Payload, host, vps, sni))
		sb.WriteString("\n────────────────────────────────────\n\n")
	}

	if len(all)-len(working) > 0 {
		sb.WriteString(fmt.Sprintf("\n❌ FAILED PAYLOADS (%d)\n", len(all)-len(working)))
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		for _, r := range all {
			if !r.IsWorking {
				sb.WriteString(fmt.Sprintf("• %s (Port:%d)", r.Method, r.Port))
				if r.Error != "" {
					sb.WriteString(fmt.Sprintf(" — %s", r.Error))
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// =============================================
// ENHANCED USER AGENT ROTATION
// =============================================

func randomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"FBAV/0.0.0",
		"WhatsApp/2.23.25.84 Android 13",
		"Telegram/Android 10.6.0",
		"TwitterAndroid/10",
		"Instagram 219.0.0.0.117 Android (28/9; 420dpi; 1080x1920; Xiaomi; Redmi Note 8; ginkgo; qcom; en_US)",
		"okhttp/4.11.0",
		"curl/8.4.0",
		"python-requests/2.31.0",
	}
	return uas[rand.Intn(len(uas))]
}
