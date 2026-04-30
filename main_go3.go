package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var bot *tgbotapi.BotAPI

var proxyURL = "https://corsproxy.io/?"

var (
	adminChatID  int64 = 107410007
	userData           = &UserData{Users: make(map[int64]*UserInfo)}
	umMutex      sync.RWMutex
	userDataFile = "/tmp/user_data.json"
)

// ==================== LOGGING INIT ====================

func initLogger() {
	logDir := "/tmp/typhoon_logs"
	os.MkdirAll(logDir, 0755)

	// Create log file
	logPath := logDir + fmt.Sprintf("/bot_%s.log", time.Now().Format("20060102"))
	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Fallback to stdout only if file fails
		fmt.Printf("⚠️ Failed to create log file (using stdout only): %v\n", err)
		logger = log.New(os.Stdout, "[TYPHOON] ", log.LstdFlags)
		logger.Printf("🚀 Bot starting - Version: %s (stdout mode)", version)
		return
	}

	// Multi-writer: Railway console + file backup
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "[TYPHOON] ", log.LstdFlags)

	// Startup banner (visible in Railway logs)
	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Printf("🚀 Bot Starting")
	logger.Printf("📦 Version: %s", version)
	logger.Printf("📅 Date: %s", time.Now().Format("2006-01-02 15:04:05"))
	logger.Printf("📁 Log: %s", logPath)
	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func logError(context string, err error) {
	msg := fmt.Sprintf("❌ ERROR [%s]: %v", context, err)

	if logger != nil {
		logger.Printf(msg)
		logger.Printf("   Stack: %s", string(debug.Stack()))
	}

	// Always print to stderr for Railway capture
	fmt.Fprintf(os.Stderr, "%s\n", msg)
}

func logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf("ℹ️ %s", fmt.Sprintf(format, args...))

	if logger != nil {
		logger.Printf(msg)
	} else {
		fmt.Println(msg)
	}
}

func logDebug(format string, args ...interface{}) {
	// Only log debug if verbose mode enabled
	if os.Getenv("DEBUG") == "true" {
		msg := fmt.Sprintf("🔍 %s", fmt.Sprintf(format, args...))
		if logger != nil {
			logger.Printf(msg)
		}
	}
}

func logWarn(format string, args ...interface{}) {
	msg := fmt.Sprintf("⚠️ %s", fmt.Sprintf(format, args...))

	if logger != nil {
		logger.Printf(msg)
	} else {
		fmt.Println(msg)
	}
}

func banUser(chatID int64) {
	umMutex.Lock()
	defer umMutex.Unlock()
	if u, exists := userData.Users[chatID]; exists {
		u.Banned = true
	}
	saveUserData()
}

func unbanUser(chatID int64) {
	umMutex.Lock()
	defer umMutex.Unlock()
	if u, exists := userData.Users[chatID]; exists {
		u.Banned = false
	}
	saveUserData()
}

func isBanned(chatID int64) bool {
	umMutex.RLock()
	defer umMutex.RUnlock()
	if u, exists := userData.Users[chatID]; exists {
		return u.Banned
	}
	return false
}

func isSubscribed(chatID int64) bool {
	if chatID == adminChatID {
		return true
	}

	member, err := bot.GetChatMember(tgbotapi.GetChatMemberConfig{
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			UserID: chatID,
			ChatID: -1003032982276,
		},
	})
	if err != nil {
		fmt.Printf("❌ isSubscribed error for %d: %v\n", chatID, err)
		return false
	}
	fmt.Printf("✅ User %d status: '%s'\n", chatID, member.Status)
	return member.Status == "member" || member.Status == "creator" || member.Status == "administrator"
}

func getAdminID() int64 {
	return adminChatID
}

func getUserID(update tgbotapi.Update) int64 {
	if update.Message != nil {
		return update.Message.Chat.ID
	}
	if update.CallbackQuery != nil {
		return update.CallbackQuery.Message.Chat.ID
	}
	return 0
}

func getUserName(update tgbotapi.Update) string {
	if update.Message != nil {
		return update.Message.From.UserName
	}
	if update.CallbackQuery != nil {
		return update.CallbackQuery.From.UserName
	}
	return "unknown"
}

func trackUserActivity(update tgbotapi.Update) {
	chatID := getUserID(update)
	if chatID == 0 {
		return
	}

	var username, firstName, lastName string

	if update.Message != nil && update.Message.From != nil {
		username = update.Message.From.UserName
		firstName = update.Message.From.FirstName
		lastName = update.Message.From.LastName
	} else if update.CallbackQuery != nil && update.CallbackQuery.From != nil {
		username = update.CallbackQuery.From.UserName
		firstName = update.CallbackQuery.From.FirstName
		lastName = update.CallbackQuery.From.LastName
	}

	umMutex.Lock()
	defer umMutex.Unlock()

	if _, exists := userData.Users[chatID]; !exists {
		userData.Users[chatID] = &UserInfo{
			Username:  username,
			FirstName: firstName,
			LastName:  lastName,
			LastSeen:  time.Now(),
		}
	}

	u := userData.Users[chatID]
	u.Username = username
	u.FirstName = firstName
	u.LastName = lastName
	u.Scans++
	u.LastSeen = time.Now()

	saveUserData()
}

// ============================================================
// NEW: Performance logging untuk CIDR scan
// ============================================================
func logScanStart(cidr string, totalIPs int, ports []int) {
	if logger != nil {
		logger.Printf("🔍 SCAN START | CIDR: %s | IPs: %d | Ports: %v", cidr, totalIPs, ports)
	}
}

func logScanComplete(cidr string, strongCount int, mediCount int, weakCount int, duration time.Duration, totalJobs int) {
	if logger != nil {
		logger.Printf("✅ SCAN DONE | CIDR: %s | STRONG: %d | MEDI: %d | WEAK: %d | Time: %v | Jobs: %d",
			cidr, strongCount, mediCount, weakCount, duration, totalJobs)
	}
}

func logScanProgress(cidr string, completed int64, total int64, found int, speed float64) {
	if logger != nil {
		logger.Printf("📊 PROGRESS | %s | %d/%d (%.1f%%) | Found: %d | Speed: %.1f/s",
			cidr, completed, total, float64(completed)/float64(total)*100, found, speed)
	}
}

// ============================================================
// Enhanced recoverPanic with Railway error context
// ============================================================
func recoverPanic(chatID int64) {
	if r := recover(); r != nil {
		errMsg := fmt.Sprintf("PANIC: %v", r)
		logError("RECOVER", fmt.Errorf(errMsg))

		// Print stack trace untuk Railway logs
		fmt.Fprintf(os.Stderr, "FATAL PANIC: %v\n%s\n", r, string(debug.Stack()))

		if chatID != 0 {
			msg := tgbotapi.NewMessage(chatID, "❌ *Internal Error*\nThe admin has been notified automatically.")
			msg.ParseMode = "Markdown"
			bot.Send(msg)

			// Notify admin
			adminID := os.Getenv("ADMIN_CHAT_ID")
			if adminID != "" {
				if id, err := strconv.ParseInt(adminID, 10, 64); err == nil {
					adminMsg := tgbotapi.NewMessage(id,
						fmt.Sprintf("🚨 *PANIC ALERT*\n\nError: %v\n\nCheck Railway logs for stack trace.", r))
					adminMsg.ParseMode = "Markdown"
					bot.Send(adminMsg)
				}
			}
		}

		// Force flush log before exit
		time.Sleep(100 * time.Millisecond)
	}
}

// ==================== DNS INIT ====================
func init() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
}

// ==================== USER SESSION MANAGEMENT ====================
type UserSession struct {
	ChatID        int64
	State         string
	TempData      map[string]interface{}
	LastActivity  time.Time
	CancelFunc    context.CancelFunc
	CurrentScanID string
}

var (
	userSessions = make(map[int64]*UserSession)
	sessionMutex sync.RWMutex
)

// ==================== SCAN TASK TRACKING ====================
type ScanTask struct {
	ID        string
	ChatID    int64
	Type      string
	Target    string
	StartTime time.Time
	Status    string
	Result    string
}

var (
	activeTasks = make(map[string]*ScanTask)
	taskMutex   sync.RWMutex
)

var bannedExt = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true,
	"webp": true, "svg": true, "ico": true,
}

// ==================== STORAGE PATH ====================
var (
	homeDir, _  = os.UserHomeDir()
	storagePath = os.TempDir() + "/"
)

// ==================== PREMIUM SNI WHITELIST (UNCHANGED) ====================
var premiumSNI = map[string]bool{
	"h.facebook.com":                true,
	"freebasics.com":                true,
	"freebasics.facebook.com":       true,
	"internet.org":                  true,
	"0.freebasics.com":              true,
	"1.freebasics.com":              true,
	"yt3.ggpht.com":                 true,
	"yt3.googleusercontent.com":     true,
	"lh3.googleusercontent.com":     true,
	"lh4.googleusercontent.com":     true,
	"lh5.googleusercontent.com":     true,
	"lh6.googleusercontent.com":     true,
	"connectivitycheck.gstatic.com": true,
	"www.gstatic.com":               true,
	"encrypted-tbn0.gstatic.com":    true,
	"encrypted-tbn1.gstatic.com":    true,
	"encrypted-tbn2.gstatic.com":    true,
	"encrypted-tbn3.gstatic.com":    true,
	"www.bing.com":                  true,
	"bing.com":                      true,
	"th.bing.com":                   true,
	"cdninstagram.com":              true,
	"scontent.cdninstagram.com":     true,
	"pbs.twimg.com":                 true,
	"video.twimg.com":               true,
}

var smartFilterDomains = map[string]string{
	"google": "GOOGLE/GWS", "youtube": "GOOGLE/GWS", "gmail": "GOOGLE/GWS",
	"facebook": "FACEBOOK", "fbcdn": "FACEBOOK", "instagram": "FACEBOOK",
	"microsoft": "AZURE", "live": "AZURE", "bing": "AZURE",
	"apple": "APPLE", "icloud": "APPLE",
	"cloudflare": "CLOUDFLARE", "fastly": "FASTLY", "akamai": "AKAMAI",
	"amazonaws": "AWS", "netflix": "NETFLIX", "twitter": "TWITTER", "x.com": "TWITTER",
}

const (
	reset       = "\033[0m"
	bold        = "\033[1m"
	matrixGreen = "\033[38;2;160;130;0m"
	neonPurple  = "\033[38;2;130;100;0m"
	brightCyan  = "\033[38;2;255;215;0m"
	brightGreen = "\033[38;2;255;215;0m"
	neonBlue    = "\033[38;2;255;215;0m"
	yellow      = "\033[38;2;255;215;0m"
	red         = "\033[38;2;255;49;49m"
	neonPink    = "\033[38;2;255;111;255m"
	premiumGold = "\033[1;38;2;255;215;0m"
)

// ==================== GLOBAL CONFIGURATION ====================
var (
	timeout        = 8 * time.Second
	maxConcurrency = 10
	vpsTunnelHost  = ""
	version        = "v3.8"
	author         = "TyphoonX"
	scansCount     = 0
	startTime      = time.Now()
	systemStatus   = "READY"
)

var (
	strongLeak = []string{"127.0.0.1", "localhost", "ip=", "colo="}
	weakLeak   = []string{
		"cf-ray", "cf-ray:", "server: nginx", "server: cloudflare",
		"server: akamaighost", "server: incapsula", "x-cdn: incapsula",
		"server: gse", "server: ecd", "via: 1.1 google", "x-amz-cf-id",
		"x-azure-ref", "x-served-by", "x-gcore-request-id", "x-iinfo", "visid_incap",
	}
	noise = []string{"cf-cache-status", "keep-alive", "connection: keep-alive"}
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var domainRegex = regexp.MustCompile(`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`)

var (
	logFile *os.File
	logger  *log.Logger
)

// =========================================================================
// DATA STRUCTURES
// =========================================================================

type UserInfo struct {
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Scans     int       `json:"scans"`
	LastSeen  time.Time `json:"last_seen"`
	Banned    bool      `json:"banned"`
	Expiry    string    `json:"expiry"`
}

type UserData struct {
	AdminID     int64               `json:"admin_id"`
	Users       map[int64]*UserInfo `json:"users"`
	LastUpdated time.Time           `json:"last_updated"`
}

func saveUserData() {
	userData.LastUpdated = time.Now()
	data, _ := json.Marshal(userData)
	os.WriteFile(userDataFile, data, 0644)
}

func loadUserData() {
	data, err := os.ReadFile(userDataFile)
	if err == nil {
		var ud UserData
		if json.Unmarshal(data, &ud) == nil {
			userData = &ud
		}
	}
}

type LicenseData struct {
	Status     string              `json:"status"`
	MOTD       string              `json:"motd"`
	Blacklist  []string            `json:"blacklist"`
	TrialsUsed []string            `json:"trials_used"`
	ActiveNow  map[string]string   `json:"active_now"`
	Users      map[string]UserInfo `json:"users"`
}

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

type massScanSummary struct {
	TotalHosts  int
	TotalPorts  int
	StrongCount int
	MediumCount int
	WeakCount   int
	StartTime   time.Time
	EndTime     time.Time
	OutputFile  string
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

var (
	jobsCompleted int64
	totalJobs     int64
)

var (
	scanSemaphore = make(chan struct{}, 5)
)

type scanCache struct {
	sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	result  string
	expires time.Time
}

var resultCache = &scanCache{
	entries: make(map[string]cacheEntry),
}

func (c *scanCache) Get(key string) (string, bool) {
	c.RLock()
	defer c.RUnlock()
	entry, exists := c.entries[key]
	if !exists || time.Now().After(entry.expires) {
		return "", false
	}
	return entry.result, true
}

func (c *scanCache) Set(key string, result string, ttl time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.entries[key] = cacheEntry{
		result:  result,
		expires: time.Now().Add(ttl),
	}
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "i/o timeout")
}

// =============================================================================
// [PATCHED] LICENSE VERIFICATION - BYPASSED
// =============================================================================

func getHWID() string {
	var data string
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		data = string(b)
	} else if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		data = string(b)
	} else {
		data = fmt.Sprintf("%s-%s-%s", runtime.GOOS, runtime.GOARCH, os.Getenv("USER"))
	}
	hash := sha256.Sum256([]byte(strings.TrimSpace(data)))
	return fmt.Sprintf("%x", hash)[:12]
}

func getSecureLink() string {
	// [PATCHED] Return empty - license bypassed
	return ""
}

func SupremeVerify() bool {
	// [PATCHED] Direct bypass for Railway deployment
	fmt.Println("✅ RAILWAY DEPLOYMENT - LICENSE BYPASSED")
	fmt.Printf("🚀 PARAGON SNI PRO %s - Starting...\n", version)
	return true
}

func visualLength(s string) int {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	clean := re.ReplaceAllString(s, "")
	return utf8.RuneCountInString(clean)
}

// =============================================================================
// CORE SCANNING FUNCTIONS (100% UNCHANGED LOGIC)
// =============================================================================

func getCustomDialer() *net.Dialer {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	return &net.Dialer{
		Timeout:  timeout,
		Resolver: resolver,
	}
}

func resolveIPv4(host string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no ipv4 found")
}

func leakScore(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	txt := strings.ToLower(string(buf))
	for _, n := range noise {
		txt = strings.ReplaceAll(txt, strings.ToLower(n), "")
	}
	score := 0
	for _, t := range strongLeak {
		if strings.Contains(txt, t) {
			score += 20
		}
	}
	for _, t := range weakLeak {
		if strings.Contains(txt, t) {
			score += 5
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func detectServer(buf []byte) string {
	txt := strings.ToLower(string(buf))
	switch {
	case strings.Contains(txt, "server: gws") ||
		strings.Contains(txt, "server: gfe") ||
		strings.Contains(txt, "server: google") ||
		strings.Contains(txt, "via: 1.1 google"):
		return "Google Frontend"
	case strings.Contains(txt, "cloudflare") || strings.Contains(txt, "cf-ray"):
		return "Cloudflare"
	case strings.Contains(txt, "incapsula") || strings.Contains(txt, "x-iinfo") || strings.Contains(txt, "visid_incap"):
		return "Imperva/Incapsula"
	case strings.Contains(txt, "x-amz-cf-id") || strings.Contains(txt, "cloudfront"):
		return "Amazon CloudFront"
	case strings.Contains(txt, "akamai") || strings.Contains(txt, "server: akamaighost"):
		return "Akamai"
	case strings.Contains(txt, "x-served-by") || strings.Contains(txt, "fastly"):
		return "Fastly"
	case strings.Contains(txt, "x-azure-ref") || strings.Contains(txt, "azure"):
		return "Azure Front Door"
	case strings.Contains(txt, "x-gcore-request-id"):
		return "Gcore"
	case strings.Contains(txt, "server: gse"):
		return "Google Edge"
	case strings.Contains(txt, "server: ecd"):
		return "Edgecast"
	// NEW: Additional CDN patterns
	case strings.Contains(txt, "vercel") || strings.Contains(txt, "x-vercel"):
		return "Vercel"
	case strings.Contains(txt, "netlify") || strings.Contains(txt, "x-nf-request-id"):
		return "Netlify"
	case strings.Contains(txt, "heroku") || strings.Contains(txt, "x-heroku"):
		return "Heroku"
	case strings.Contains(txt, "x-bunny"):
		return "BunnyCDN"
	case strings.Contains(txt, "x-sucuri") || strings.Contains(txt, "sucuri"):
		return "Sucuri"
	case strings.Contains(txt, "nginx"):
		return "nginx"
	case strings.Contains(txt, "apache"):
		return "Apache"
	case strings.Contains(txt, "litespeed"):
		return "LiteSpeed"
	case strings.Contains(txt, "microsoft-iis") || strings.Contains(txt, "iis"):
		return "Microsoft IIS"
	case strings.Contains(txt, "openresty"):
		return "OpenResty"
	case strings.Contains(txt, "varnish"):
		return "Varnish"
	case strings.Contains(txt, "haproxy"):
		return "HAProxy"
	case strings.Contains(txt, "caddy"):
		return "Caddy"
	}
	lines := strings.Split(txt, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "server:") {
			serverVal := strings.TrimSpace(strings.TrimPrefix(line, "server:"))
			if serverVal != "" && len(serverVal) < 50 {
				return strings.ToTitle(serverVal)
			}
		}
	}
	return "Unknown"
}

func detectCDNByIP(ip string) string {
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return ""
	}
	if isInCIDR(ipObj, "104.16.0.0/12") ||
		isInCIDR(ipObj, "172.64.0.0/13") ||
		isInCIDR(ipObj, "131.0.72.0/22") ||
		isInCIDR(ipObj, "173.245.48.0/20") ||
		isInCIDR(ipObj, "103.21.244.0/22") ||
		isInCIDR(ipObj, "103.22.200.0/22") ||
		isInCIDR(ipObj, "103.31.4.0/22") ||
		isInCIDR(ipObj, "141.101.64.0/18") ||
		isInCIDR(ipObj, "108.162.192.0/18") ||
		isInCIDR(ipObj, "190.93.240.0/20") ||
		isInCIDR(ipObj, "188.114.96.0/20") ||
		isInCIDR(ipObj, "197.234.240.0/22") ||
		isInCIDR(ipObj, "198.41.128.0/17") ||
		isInCIDR(ipObj, "162.158.0.0/15") ||
		isInCIDR(ipObj, "104.24.0.0/14") {
		return "CLOUDFLARE"
	}
	if isInCIDR(ipObj, "13.32.0.0/15") ||
		isInCIDR(ipObj, "13.224.0.0/14") ||
		isInCIDR(ipObj, "13.248.64.0/18") ||
		isInCIDR(ipObj, "64.252.64.0/18") ||
		isInCIDR(ipObj, "143.204.0.0/14") ||
		isInCIDR(ipObj, "144.220.0.0/16") ||
		isInCIDR(ipObj, "205.251.192.0/18") ||
		isInCIDR(ipObj, "99.86.0.0/15") ||
		isInCIDR(ipObj, "18.160.0.0/15") ||
		isInCIDR(ipObj, "18.164.0.0/15") ||
		isInCIDR(ipObj, "18.172.0.0/15") ||
		isInCIDR(ipObj, "18.238.0.0/15") {
		return "AWS/CF"
	}
	if isInCIDR(ipObj, "2.16.0.0/13") ||
		isInCIDR(ipObj, "2.20.0.0/14") ||
		isInCIDR(ipObj, "23.32.0.0/11") ||
		isInCIDR(ipObj, "23.192.0.0/11") ||
		isInCIDR(ipObj, "23.64.0.0/14") ||
		isInCIDR(ipObj, "23.72.0.0/13") ||
		isInCIDR(ipObj, "23.200.0.0/13") ||
		isInCIDR(ipObj, "23.208.0.0/12") ||
		isInCIDR(ipObj, "23.224.0.0/12") ||
		isInCIDR(ipObj, "72.246.0.0/15") ||
		isInCIDR(ipObj, "96.16.0.0/15") ||
		isInCIDR(ipObj, "104.64.0.0/10") {
		return "AKAMAI"
	}
	if isInCIDR(ipObj, "151.101.0.0/16") ||
		isInCIDR(ipObj, "157.52.64.0/18") ||
		isInCIDR(ipObj, "199.232.0.0/16") ||
		isInCIDR(ipObj, "23.235.32.0/20") ||
		isInCIDR(ipObj, "146.75.0.0/16") {
		return "FASTLY"
	}
	if isInCIDR(ipObj, "45.60.0.0/16") ||
		isInCIDR(ipObj, "149.126.0.0/16") ||
		isInCIDR(ipObj, "199.83.128.0/18") ||
		isInCIDR(ipObj, "198.143.32.0/19") ||
		isInCIDR(ipObj, "172.98.72.0/21") ||
		isInCIDR(ipObj, "107.154.0.0/16") ||
		isInCIDR(ipObj, "104.244.0.0/20") {
		return "IMPERVA"
	}
	if isInCIDR(ipObj, "8.8.8.0/24") ||
		isInCIDR(ipObj, "8.8.4.0/24") ||
		isInCIDR(ipObj, "35.0.0.0/15") ||
		isInCIDR(ipObj, "35.16.0.0/14") ||
		isInCIDR(ipObj, "35.32.0.0/15") ||
		isInCIDR(ipObj, "35.48.0.0/14") ||
		isInCIDR(ipObj, "35.64.0.0/11") ||
		isInCIDR(ipObj, "35.128.0.0/15") ||
		isInCIDR(ipObj, "35.144.0.0/14") ||
		isInCIDR(ipObj, "35.152.0.0/13") ||
		isInCIDR(ipObj, "35.176.0.0/14") ||
		isInCIDR(ipObj, "35.184.0.0/13") ||
		isInCIDR(ipObj, "35.192.0.0/14") ||
		isInCIDR(ipObj, "35.200.0.0/13") ||
		isInCIDR(ipObj, "35.208.0.0/12") ||
		isInCIDR(ipObj, "35.224.0.0/12") ||
		isInCIDR(ipObj, "35.240.0.0/13") ||
		isInCIDR(ipObj, "108.170.192.0/18") ||
		isInCIDR(ipObj, "108.177.0.0/17") ||
		isInCIDR(ipObj, "130.211.0.0/16") ||
		isInCIDR(ipObj, "172.217.0.0/16") ||
		isInCIDR(ipObj, "172.253.0.0/16") ||
		isInCIDR(ipObj, "173.194.0.0/16") ||
		isInCIDR(ipObj, "209.85.128.0/17") ||
		isInCIDR(ipObj, "216.58.192.0/19") {
		return "GOOGLE/GWS"
	}
	return ""
}

func isInCIDR(ip net.IP, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(ip)
}

func wsProbe(host, ip string, port int) (bool, string) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	var req strings.Builder
	req.Grow(256)
	req.WriteString("GET / HTTP/1.1\r\n")
	req.WriteString("Host: ")
	req.WriteString(host)
	req.WriteString("\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("User-Agent: Mozilla/5.0\r\n\r\n")

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(req.String()))
	if err != nil {
		return false, ""
	}

	// Loop read untuk full response (elak partial read)
	var fullResp bytes.Buffer
	fullResp.Grow(4096)

	buf := make([]byte, 1024)
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			fullResp.Write(buf[:n])
			totalRead += n
		}
		if err != nil || totalRead > 4096 {
			break
		}
		if bytes.Contains(fullResp.Bytes(), []byte("\r\n\r\n")) && totalRead > 100 {
			break
		}
	}

	if fullResp.Len() == 0 {
		return false, ""
	}

	rawResp := fullResp.String()
	txt := strings.ToLower(rawResp)

	if strings.Contains(txt, "101") && strings.Contains(txt, "switching protocols") {
		return true, rawResp
	}

	return false, rawResp
}

func doTLS(host, ip string, port int) (string, tlsInfo) {
	start := time.Now()
	info := tlsInfo{IP: ip}
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}

	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		if isNetworkError(err) {
			info.TLSStatus = "✗ Network FAIL"
			info.LatencyMs = int(time.Since(start).Milliseconds())
			return "FAIL", info
		}
		conf.ServerName = ""
		conn, err = tls.DialWithDialer(dialer, "tcp", address, conf)
		if err != nil {
			info.TLSStatus = "✗ Handshake FAIL"
			info.LatencyMs = int(time.Since(start).Milliseconds())
			return "FAIL", info
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Cipher = fmt.Sprintf("0x%04x", state.CipherSuite)
	info.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		info.CommonName = state.PeerCertificates[0].Subject.CommonName
	}

	hostHeader := host
	if port != 443 && port != 80 {
		hostHeader = fmt.Sprintf("%s:%d", host, port)
	}

	var payload strings.Builder
	payload.Grow(200)
	payload.WriteString("GET / HTTP/1.1\r\n")
	payload.WriteString("Host: ")
	payload.WriteString(hostHeader)
	payload.WriteString("\r\n")
	payload.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	payload.WriteString("Accept: */*\r\n")
	payload.WriteString("Connection: close\r\n\r\n")

	conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(payload.String()))

	var fullResponse bytes.Buffer
	fullResponse.Grow(25000)

	buffer := make([]byte, 4096)
	totalRead := 0
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			fullResponse.Write(buffer[:n])
			totalRead += n
		}
		if err != nil || totalRead > 25000 {
			break
		}
	}

	respStr := fullResponse.String()

	if len(respStr) >= 12 {
		info.HTTPStatus = respStr[9:12]
	} else if fullResponse.Len() > 0 {
		info.HTTPStatus = "200"
	}

	if idx := strings.Index(respStr, "\r\n\r\n"); idx != -1 {
		body := respStr[idx+4:]
		info.ContentLength = len(body)
		if len(body) > 700 {
			info.BodySnippet = body[:700]
		} else {
			info.BodySnippet = body
		}
	}

	info.Leak = leakScore(fullResponse.Bytes())
	info.Server = detectServer(fullResponse.Bytes())
	info.TLSraw = respStr
	info.LatencyMs = int(time.Since(start).Milliseconds())

	fullResponse.Reset()

	return "OK", info
}

func doHTTP(host, ip string, port int) (string, tlsInfo) {
	start := time.Now()
	info := tlsInfo{IP: ip}
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		info.HTTPStatus = "✗ Connection FAIL"
		info.LatencyMs = int(time.Since(start).Milliseconds())
		return "FAIL", info
	}
	defer conn.Close()

	hostHeader := host
	if port != 80 && port != 443 {
		hostHeader = fmt.Sprintf("%s:%d", host, port)
	}

	var payload strings.Builder
	payload.Grow(200)
	payload.WriteString("GET / HTTP/1.1\r\n")
	payload.WriteString("Host: ")
	payload.WriteString(hostHeader)
	payload.WriteString("\r\n")
	payload.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	payload.WriteString("Accept: */*\r\n")
	payload.WriteString("Connection: close\r\n\r\n")

	conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(payload.String()))

	var full bytes.Buffer
	full.Grow(25000)

	buffer := make([]byte, 4096)
	totalRead := 0
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			full.Write(buffer[:n])
			totalRead += n
		}
		if err != nil || totalRead > 25000 {
			break
		}
	}

	respStr := full.String()
	if len(respStr) > 0 {
		statusLines := strings.SplitN(respStr, "\r\n", 2)
		parts := strings.Split(statusLines[0], " ")
		if len(parts) >= 2 {
			info.HTTPStatus = parts[1]
		} else {
			info.HTTPStatus = "200"
		}
	}

	if idx := strings.Index(respStr, "\r\n\r\n"); idx != -1 {
		body := respStr[idx+4:]
		info.ContentLength = len(body)
		if len(body) > 700 {
			info.BodySnippet = body[:700]
		} else {
			info.BodySnippet = body
		}
	}

	info.Leak = leakScore(full.Bytes())
	info.Server = detectServer(full.Bytes())
	info.TLSraw = respStr
	info.LatencyMs = int(time.Since(start).Milliseconds())
	if info.HTTPStatus == "" {
		info.HTTPStatus = "000"
	}

	full.Reset()

	return "OK", info
}

func probePorts(ip string, specifiedPort int) (finalPort int, udpQUICOpen bool) {
	// Kalau user specify port, check direct
	if specifiedPort != 0 {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(specifiedPort)), timeout)
		if err == nil {
			conn.Close()
			return specifiedPort, false
		}
		return 0, false
	}

	type probeResult struct {
		port int
		open bool
	}

	results := make(chan probeResult, 3)

	// TCP 443
	go func() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
		if err == nil {
			conn.Close()
			results <- probeResult{443, true}
		} else {
			results <- probeResult{443, false}
		}
	}()

	// TCP 80
	go func() {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), timeout)
		if err == nil {
			conn.Close()
			results <- probeResult{80, true}
		} else {
			results <- probeResult{80, false}
		}
	}()

	// UDP 443 (QUIC)
	go func() {
		serverAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "443"))
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err == nil {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("\x00"))
			results <- probeResult{443, true}
		} else {
			results <- probeResult{0, false}
		}
	}()

	tcp443Open := false
	tcp80Open := false
	udpQUICOpen = false

	for i := 0; i < 3; i++ {
		res := <-results
		if res.open {
			switch res.port {
			case 443:
				if !tcp443Open {
					tcp443Open = true
				} else {
					udpQUICOpen = true
				}
			case 80:
				tcp80Open = true
			}
		}
	}

	if udpQUICOpen {
		return 443, true
	} else if tcp443Open {
		return 443, false
	} else if tcp80Open {
		return 80, false
	}
	return 0, false
}

func calculateScore(detectLabel string, info tlsInfo) (string, int) {
	labelUpper := strings.ToUpper(detectLabel)

	var priority string
	var qualityScore int

	switch {
	case strings.Contains(labelUpper, "H3_QUIC") || strings.Contains(labelUpper, "H3 QUIC"):
		priority = "STRONG"
		qualityScore = 95
	case strings.Contains(labelUpper, "SPOOF"):
		priority = "STRONG"
		qualityScore = 90
	case strings.Contains(labelUpper, "REALITY"):
		priority = "STRONG"
		qualityScore = 88
	case strings.Contains(labelUpper, "WS") || strings.Contains(labelUpper, "101"):
		priority = "STRONG"
		qualityScore = 85
	case strings.Contains(labelUpper, "BUGHOST CONFIRMED") || strings.Contains(labelUpper, "CDN_HOST"):
		priority = "MEDI"
		qualityScore = 65
	case strings.Contains(labelUpper, "CDN_ONLY"):
		priority = "MEDI"
		qualityScore = 45
	case strings.Contains(labelUpper, "HTTP"):
		priority = "WEAK"
		qualityScore = 30
	default:
		priority = "WEAK"
		qualityScore = 20
	}

	// Latency adjustment
	if info.LatencyMs > 0 {
		switch {
		case info.LatencyMs < 100:
			qualityScore += 5
		case info.LatencyMs > 500:
			qualityScore -= 15
		case info.LatencyMs > 300:
			qualityScore -= 5
		}
	}

	// Content length bonus
	if info.ContentLength > 1000 {
		qualityScore += 5
	}

	// Cipher bonus
	if info.Cipher != "" && info.Cipher != "0x0000" {
		qualityScore += 3
	}

	// Clamp 0-100
	if qualityScore > 100 {
		qualityScore = 100
	}
	if qualityScore < 0 {
		qualityScore = 0
	}

	return priority, qualityScore
}

// =============================================================================
// CLASSIFICATION & DEEP VERIFICATION
// =============================================================================

func classifyWithProbes(host string, ip string, port int) (string, tlsInfo, string, string) {
	var info tlsInfo

	logToDisk := func(label string, extra tlsInfo, rank string) {
		f, err := os.OpenFile("scanner_debug.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		timestamp := time.Now().Format("15:04:05")
		logEntry := fmt.Sprintf("[%s] %s:%d | %s | RANK:%s | Status:%s | Len:%d | Server:%s | CN:%s | Cipher:%s | ALPN:%s\n",
			timestamp, host, port, label, rank, extra.HTTPStatus, extra.ContentLength, extra.Server, extra.CommonName, extra.Cipher, extra.ALPN)
		_, _ = f.WriteString(logEntry)
	}

	hostClean := strings.ToLower(strings.TrimSpace(host))

	var tlsCached bool
	var tlsCachedInfo tlsInfo
	var tlsStatusCached string

	getTLSInfo := func() (string, tlsInfo) {
		if !tlsCached {
			tlsStatusCached, tlsCachedInfo = doTLS(host, ip, port)
			tlsCached = true
		}
		return tlsStatusCached, tlsCachedInfo
	}

	// ==================== TIER 0: BIG TECH NATIVE (NOT BUGHOST) ====================
	bigTechDomains := []string{
		"google.com", "google.co", "google.com.my",
		"youtube.com", "youtu.be", "ytimg.com",
		"facebook.com", "fb.com", "fbcdn.net", "instagram.com",
		"microsoft.com", "live.com", "bing.com", "office.com", "azure.com", "azurefd.net",
		"apple.com", "icloud.com",
		"amazon.com", "amazonaws.com", "aws.amazon.com",
		"twitter.com", "x.com", "twimg.com",
		"netflix.com", "nflxvideo.net",
		"cloudflare.com", "cloudflare.net",
		"akamai.com", "akamaiedge.net",
		"fastly.com", "fastly.net",
		"speedtest.net", "ookla.com",
		"github.com", "gitlab.com",
		"wikipedia.org", "wikimedia.org",
		"whatsapp.com", "telegram.org", "t.me",
		"tiktok.com", "spotify.com",
		"yahoo.com", "ebay.com", "paypal.com",
		"linkedin.com", "reddit.com",
	}

	isBigTechNative := false
	for _, domain := range bigTechDomains {
		if hostClean == domain || hostClean == "www."+domain {
			isBigTechNative = true
			break
		}
	}
	// ← PASTIKAN ADA NI

	if isBigTechNative {
		// Still get TLS info for display
		_, tlsInfoLocal := getTLSInfo()
		info = tlsInfoLocal
		if info.HTTPStatus == "" {
			info.HTTPStatus = "200"
		}
		info.Server = "Big Tech Native"
		logToDisk("BIG_TECH_NATIVE", info, "NATIVE")
		return "NATIVE_CDN", info, "NATIVE CDN", "FAST PATH"
	}

	// ==================== TIER 1: WEB SOCKET PROBE ====================
	wsOK, wsRaw := wsProbe(host, ip, port)
	if wsOK && len(strings.TrimSpace(wsRaw)) >= 10 {
		_, tlsInfoLocal := getTLSInfo()
		info = tlsInfoLocal
		info.SSHWS = true
		info.WSraw = wsRaw
		info.HTTPStatus = "101"

		logToDisk("WS_VULN_FOUND", info, "STRONG")
		return "STRONG", info, "101 Switching Protocols", "TLS OK"
	}

	// ==================== TIER 2: TLS & BEHAVIORAL ANALYSIS ====================
	tlsStatus, tlsInfoLocal := getTLSInfo()
	info = tlsInfoLocal

	if tlsStatus == "OK" {
		server := strings.ToUpper(info.Server)
		rawHeaders := strings.ToUpper(info.TLSraw)
		snippetUpper := strings.ToUpper(info.BodySnippet)
		alpnUpper := strings.ToUpper(info.ALPN)

		if info.HTTPStatus == "" {
			info.HTTPStatus = "200"
		}

		// Custom Port Detection
		if port != 443 && port != 80 && port != 8080 && port != 8443 && info.HTTPStatus != "000" {
			if port > 10000 {
				logToDisk("HIGH_PORT_BUG", info, "STRONG")
			} else {
				logToDisk("CUSTOM_PORT_ALIVE", info, "STRONG")
			}
			return "STRONG", info, "CUSTOM PORT BUG", tlsStatus
		}

		// H3 / QUIC Detection
		isH3 := strings.Contains(alpnUpper, "H3") ||
			(strings.Contains(rawHeaders, "ALT-SVC") && len(rawHeaders) > 50)
		if isH3 {
			quicVersion := ""
			if strings.Contains(rawHeaders, "H3-29") || strings.Contains(rawHeaders, "H3-32") {
				quicVersion = " (KNOWN QUIC VERSION)"
			}
			logToDisk("STRONG_H3_QUIC_FOUND", info, "STRONG")
			return "STRONG", info, "H3 QUIC BUG" + quicVersion, tlsStatus
		}

		// Reality Tunnel Detection
		isTLS13 := strings.Contains(info.Cipher, "AES_256_GCM") ||
			strings.Contains(info.Cipher, "CHACHA20") ||
			strings.Contains(info.Cipher, "TLS_AES")
		isBigTech := strings.Contains(info.CommonName, "google") ||
			strings.Contains(info.CommonName, "microsoft") ||
			strings.Contains(info.CommonName, "apple") ||
			strings.Contains(info.CommonName, "cloudflare") ||
			strings.Contains(info.CommonName, "facebook") ||
			strings.Contains(info.CommonName, "twitter")

		if isTLS13 && isBigTech && (info.Server == "" || info.Server == "UNKNOWN" || alpnUpper == "") {
			logToDisk("REALITY_TUNNEL_DETECTED", info, "STRONG")
			return "STRONG", info, "REALITY TUNNEL BUG", tlsStatus
		}

		// CDN Bug Detection
		isCDN := strings.Contains(server, "CLOUDFRONT") || strings.Contains(rawHeaders, "X-AMZ-") ||
			strings.Contains(server, "CLOUDFLARE") || strings.Contains(rawHeaders, "CF-RAY") ||
			strings.Contains(server, "AKAMAI") || strings.Contains(server, "AZURE") ||
			strings.Contains(server, "GCP") || strings.Contains(server, "GOOGLE") ||
			strings.Contains(snippetUpper, "<!DOCTYPE") || strings.Contains(snippetUpper, "<HTML")

		if isCDN {
			isGenericPage := strings.Contains(snippetUpper, "APP SERVICE - ANTARES") ||
				strings.Contains(snippetUpper, "DIRECT IP ACCESS NOT ALLOWED") ||
				strings.Contains(snippetUpper, "SITE NOT FOUND") ||
				strings.Contains(snippetUpper, "PAGE NOT FOUND") ||
				strings.Contains(snippetUpper, "ERROR 404") ||
				strings.Contains(snippetUpper, "NO SUCH SITE") ||
				strings.Contains(snippetUpper, "BAD REQUEST") ||
				strings.Contains(snippetUpper, "ACCESS DENIED")

			maxLen := 50000
			if strings.Contains(snippetUpper, "<!DOCTYPE") || strings.Contains(snippetUpper, "<HTML") {
				maxLen = 5000
			}

			if !isGenericPage && info.ContentLength < maxLen {
				if strings.Contains(server, "CLOUDFLARE") && !strings.Contains(info.CommonName, "cloudflare") {
					logToDisk("CDN_MISMATCH_BUG", info, "STRONG")
				} else {
					logToDisk("CDN_BUGHOST_CONFIRMED", info, "STRONG")
				}
				return "STRONG", info, "BUGHOST CONFIRMED", tlsStatus
			}
		}

		// SNI Spoof Candidate
		bigTechSuffix := []string{
			".google.com", ".googlevideo.com", ".ggpht.com", ".gstatic.com",
			".apple.com", ".icloud.com", ".mzstatic.com",
			".microsoft.com", ".azure.com", ".office.com", ".live.com",
			".cloudflare.com", ".cloudflare.net",
			".facebook.com", ".fbcdn.net",
			".amazon.com", ".amazonaws.com", ".cloudfront.net",
			".akamai.com", ".akamaiedge.net",
			".twitter.com", ".twimg.com",
			".netflix.com", ".nflxvideo.net",
		}
		for _, suffix := range bigTechSuffix {
			if strings.HasSuffix(hostClean, suffix) || hostClean == strings.TrimPrefix(suffix, ".") {
				return "POTENTIAL", info, "SNI SPOOF CANDIDATE", "BIG TECH"
			}
		}

		// Unknown but Responsive
		if info.HTTPStatus != "000" && info.ContentLength > 0 && info.ContentLength < 10000 {
			logToDisk("UNKNOWN_RESPONSIVE", info, "POTENTIAL")
			return "POTENTIAL", info, "UNKNOWN RESPONSIVE", tlsStatus
		}
	}

	// ==================== TIER 3: HTTP BACKUP ====================
	httpStatus, httpInfo := doHTTP(host, ip, port)
	if httpStatus == "OK" && httpInfo.ContentLength > 10 {
		if strings.Contains(httpInfo.TLSraw, "301") || strings.Contains(httpInfo.TLSraw, "302") {
			logToDisk("HTTP_REDIRECT", httpInfo, "WEAK")
			return "WEAK", httpInfo, "HTTP REDIRECT", "PLAIN_HTTP"
		}
		logToDisk("HTTP_ONLY", httpInfo, "WEAK")
		return "WEAK", httpInfo, "NONE", "PLAIN_HTTP"
	}

	logToDisk("DEAD_HOST", info, "WEAK")
	return "WEAK", info, "NONE", "NO_RESPONSE"
}

func verifyWebSocketReal(host string, port int, path string) VerificationResult {
	result := VerificationResult{
		IsWorking:     false,
		QualityScore:  0,
		WorkingPath:   path,
		WorkingHeader: make(map[string]string),
	}
	testPaths := []string{path}
	if path == "" || path == "/" {
		testPaths = []string{"/", "/ws", "/socket", "/websocket", "/wss", "/v2/ws", "/api/ws", "/stream"}
	}
	for _, testPath := range testPaths {
		address := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 8*time.Second)
		if err != nil {
			continue
		}
		headers := []map[string]string{
			{"Host": host, "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"},
			{"Host": host, "Connection": "Upgrade", "Upgrade": "websocket", "Origin": "https://" + host, "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"},
			{"Host": host, "Connection": "Upgrade", "Upgrade": "websocket", "X-Forwarded-For": "127.0.0.1", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"},
			{"Host": host + ":" + strconv.Itoa(port), "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13"},
		}
		for _, headerSet := range headers {
			req := fmt.Sprintf("GET %s HTTP/1.1\r\n", testPath)
			for k, v := range headerSet {
				req += fmt.Sprintf("%s: %s\r\n", k, v)
			}
			req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
			req += "\r\n"
			conn.SetDeadline(time.Now().Add(6 * time.Second))
			_, err = conn.Write([]byte(req))
			if err != nil {
				continue
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				continue
			}
			resp := string(buf[:n])
			if strings.Contains(resp, "101") && strings.Contains(strings.ToLower(resp), "switching protocols") {
				result.IsWorking = true
				result.WorkingPath = testPath
				result.WorkingHeader = headerSet
				result.QualityScore = 90
				result.VerifiedBug = "WEBSOCKET CONFIRMED"
				frame := []byte{0x81, 0x04, 0x70, 0x69, 0x6e, 0x67}
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, err = conn.Write(frame)
				if err == nil {
					result.QualityScore = 100
					result.VerifiedBug = "WEBSOCKET FULLY WORKING"
				}
				conn.Close()
				return result
			}
			conn.Close()
		}
		conn.Close()
	}
	return result
}

func verifySNISpoof(host string, port int, spoofSNI string) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  "SNI SPOOF",
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conf := &tls.Config{
		ServerName:         spoofSNI,
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		result.ErrorMessage = err.Error()
		return result
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		result.ErrorMessage = err.Error()
		return result
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		result.ErrorMessage = err.Error()
		return result
	}
	resp := string(buf[:n])
	if strings.Contains(resp, "200") || strings.Contains(resp, "301") || strings.Contains(resp, "302") ||
		strings.Contains(resp, "403") || strings.Contains(resp, "404") {
		if !strings.Contains(resp, "cf-ray") && !strings.Contains(resp, "x-amz-cf-id") {
			result.IsWorking = true
			result.QualityScore = 85
			if len(resp) > 2000 {
				result.QualityScore = 95
			}
			return result
		}
	}
	result.QualityScore = 30
	result.ErrorMessage = "WAF still blocking"
	return result
}

func verifyQUICReal(host string, port int) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  "HTTP/3",
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	conn.Write([]byte(req))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(strings.ToLower(resp), "alt-svc") || !strings.Contains(strings.ToLower(resp), "h3") {
		return result
	}
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		result.IsWorking = true
		result.QualityScore = 60
		result.VerifiedBug = "HTTP/3_TCP_ONLY"
		return result
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		result.IsWorking = true
		result.QualityScore = 65
		result.VerifiedBug = "HTTP/3_UDP_BLOCKED"
		return result
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = udpConn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if err != nil {
		result.IsWorking = true
		result.QualityScore = 70
		result.VerifiedBug = "HTTP/3_UDP_WRITE_FAIL"
		return result
	}
	udpBuf := make([]byte, 1500)
	_, err = udpConn.Read(udpBuf)
	if err != nil {
		result.IsWorking = true
		result.QualityScore = 80
		result.VerifiedBug = "HTTP/3_QUIC_OPEN"
		return result
	}
	result.IsWorking = true
	result.QualityScore = 90
	result.VerifiedBug = "HTTP/3_QUIC_WORKING"
	return result
}

func verifyAzureBNI(host string, port int) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  "AZURE BNI",
	}
	testHeaders := []map[string]string{
		{"Host": host, "X-BNI-JA": "true"},
		{"Host": host, "X-BNI-JA": "1"},
		{"Host": host, "X-Forwarded-Host": host},
		{"Host": host, "X-Original-Host": host},
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	for i, headers := range testHeaders {
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			continue
		}
		req := "GET / HTTP/1.1\r\n"
		for k, v := range headers {
			req += fmt.Sprintf("%s: %s\r\n", k, v)
		}
		req += "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
		conn.SetDeadline(time.Now().Add(6 * time.Second))
		conn.Write([]byte(req))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}
		resp := string(buf[:n])
		if strings.Contains(resp, "200") || strings.Contains(resp, "301") || strings.Contains(resp, "302") {
			if !strings.Contains(resp, "Microsoft-Azure") {
				result.IsWorking = true
				result.QualityScore = 80 - (i * 5)
				result.WorkingHeader = headers
				return result
			}
		}
	}
	return result
}

func verifyCDNFronting(host string, port int) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  "CDN FRONTING",
	}
	frontingTests := []struct {
		sni     string
		host    string
		quality int
	}{
		{host, host, 50},
		{"cloudfront.net", host, 70},
		{"cloudflare.com", host, 60},
		{"azurefd.net", host, 65},
		{"fastly.net", host, 60},
	}
	for _, test := range frontingTests {
		address := net.JoinHostPort(host, strconv.Itoa(port))
		conf := &tls.Config{
			ServerName:         test.sni,
			InsecureSkipVerify: true,
		}
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
		if err != nil {
			continue
		}
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", test.host)
		conn.SetDeadline(time.Now().Add(6 * time.Second))
		conn.Write([]byte(req))
		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil && err != io.EOF {
			continue
		}
		resp := string(buf[:n])
		if strings.Contains(resp, "200") || strings.Contains(resp, "301") || strings.Contains(resp, "302") {
			if !strings.Contains(resp, "CloudFront") && !strings.Contains(resp, "Bad request") {
				result.IsWorking = true
				result.QualityScore = test.quality
				result.WorkingHeader = map[string]string{"SNI": test.sni, "Host": test.host}
				return result
			}
		}
	}
	return result
}

func verifyDirectTLSSNI(host string, port int) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  "DIRECT TLS SNI",
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		return result
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(req))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return result
	}
	resp := string(buf[:n])
	if strings.Contains(resp, "200") || strings.Contains(resp, "301") ||
		strings.Contains(resp, "302") || strings.Contains(resp, "403") ||
		strings.Contains(resp, "404") || strings.Contains(resp, "400") ||
		strings.Contains(resp, "503") {
		result.IsWorking = true
		result.QualityScore = 80
		result.VerifiedBug = "DIRECT TLS SNI WORKING"
		return result
	}
	if conn.ConnectionState().HandshakeComplete {
		result.IsWorking = true
		result.QualityScore = 70
		result.VerifiedBug = "TLS_HANDSHAKE_OK"
		return result
	}
	return result
}

func deepVerify(host string, ip string, port int, detectLabel string, info tlsInfo) VerificationResult {
	result := VerificationResult{
		IsWorking:    false,
		QualityScore: 0,
		VerifiedBug:  detectLabel,
	}
	result.IP = ip
	if strings.HasPrefix(info.HTTPStatus, "✗") {
		return result
	}
	resultChan := make(chan VerificationResult, 20)
	var wg sync.WaitGroup

	launchSNITests := func(targets []string) {
		for _, sni := range targets {
			if sni == "" {
				continue
			}
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				res := verifySNISpoof(host, port, s)
				if res.IsWorking {
					select {
					case resultChan <- res:
					default:
					}
				}
			}(sni)
		}
	}

	launchWSTests := func(paths []string) {
		for _, path := range paths {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				res := verifyWebSocketReal(host, port, p)
				if res.IsWorking {
					select {
					case resultChan <- res:
					default:
					}
				}
			}(path)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := verifyDirectTLSSNI(host, port)
		if res.IsWorking {
			cdn := detectCDNByIP(ip)
			if cdn == "CLOUDFLARE" || cdn == "AKAMAI" || cdn == "FASTLY" ||
				cdn == "AWS/CF" || cdn == "IMPERVA" || cdn == "TWITTER" ||
				cdn == "FACEBOOK" {
				res.QualityScore += 10
				if res.QualityScore > 100 {
					res.QualityScore = 100
				}
			}
			select {
			case resultChan <- res:
			default:
			}
		}
	}()

	switch {
	case detectLabel == "H3_QUIC_BUG" || strings.Contains(detectLabel, "HTTP/3"):
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := verifyQUICReal(host, port)
			if res.IsWorking {
				select {
				case resultChan <- res:
				default:
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := verifyWebSocketReal(host, port, "")
			if res.IsWorking {
				select {
				case resultChan <- res:
				default:
				}
			}
		}()
	case detectLabel == "REALITY_TUNNEL_BUG" || strings.Contains(detectLabel, "REALITY"):
		launchSNITests([]string{
			"www.google.com",
			"www.cloudflare.com",
			"www.microsoft.com",
			"www.amazon.com",
			host,
		})
	case strings.Contains(info.HTTPStatus, "101") || detectLabel == "WS" || info.SSHWS:
		launchWSTests([]string{"/", "/ws", "/websocket", "/socket", "/wss", "/v2/ws"})
	case strings.Contains(detectLabel, "AZURE") || strings.Contains(info.TLSraw, "x-bni-ja"):
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := verifyAzureBNI(host, port)
			if res.IsWorking {
				select {
				case resultChan <- res:
				default:
				}
			}
		}()
		launchWSTests([]string{"/", "/ws"})
	case strings.Contains(strings.ToUpper(info.Server), "CLOUDFRONT") ||
		strings.Contains(strings.ToUpper(info.TLSraw), "CLOUDFRONT") ||
		strings.Contains(strings.ToUpper(info.TLSraw), "X-AMZ-CF-ID"):
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := verifyCDNFronting(host, port)
			if res.IsWorking {
				select {
				case resultChan <- res:
				default:
				}
			}
		}()
		launchSNITests([]string{
			"www.cloudfront.com",
			"d3ag4hukkh62yn.cloudfront.net",
			host,
		})
	case info.CommonName != "" && !strings.Contains(host, strings.ReplaceAll(info.CommonName, "*.", "")):
		launchSNITests([]string{info.CommonName, host})
	default:
		launchWSTests([]string{"/", "/ws", "/websocket"})
		launchSNITests([]string{
			"www.google.com",
			"www.cloudflare.com",
			"www.bing.com",
			host,
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := verifyCDNFronting(host, port)
			if res.IsWorking {
				select {
				case resultChan <- res:
				default:
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var bestResult VerificationResult
	for res := range resultChan {
		if res.IsWorking {
			if res.QualityScore > bestResult.QualityScore {
				bestResult = res
			}
		}
	}
	if bestResult.IsWorking {
		result = bestResult
	}

	if result.IsWorking {
		if info.LatencyMs > 500 {
			result.QualityScore -= 15
			if result.QualityScore < 0 {
				result.QualityScore = 0
			}
		} else if info.LatencyMs < 100 {
			result.QualityScore += 5
			if result.QualityScore > 100 {
				result.QualityScore = 100
			}
		}
		cdn := detectCDNByIP(ip)
		if cdn == "CLOUDFLARE" || cdn == "AKAMAI" || cdn == "FASTLY" || cdn == "AWS/CF" || cdn == "IMPERVA" {
			result.QualityScore += 10
			if result.QualityScore > 100 {
				result.QualityScore = 100
			}
		}
		if strings.Contains(info.HTTPStatus, "200") {
			result.QualityScore += 5
			if result.QualityScore > 100 {
				result.QualityScore = 100
			}
		}
		if info.LatencyMs > 800 {
			result.QualityScore -= 10
			if result.QualityScore < 0 {
				result.QualityScore = 0
			}
		}
	}
	return result
}

// =============================================================================
// SUBDOMAIN ENUMERATION & UTILITY FUNCTIONS
// =============================================================================

func subdomainEnum(domain string, progressChan chan<- string) ([]string, error) {
	domain = strings.ToLower(domain)
	foundSubs := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sources := []string{"crt.sh", "HackerTarget", "RapidDNS", "Wayback", "CertSpotter", "AnubisDB"}
	completed := 0
	var progressMu sync.Mutex

	updateProgress := func(source string, status string, count int) {
		progressMu.Lock()
		completed++
		current := completed
		progressMu.Unlock()
		progressChan <- fmt.Sprintf("📡 %s: %s (found: %d) [%d/%d]", source, status, count, current, len(sources))
	}

	fetchWithRetry := func(url string) []byte {
		client := &http.Client{Timeout: 30 * time.Second}
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return body
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(time.Duration(1+i) * time.Second)
		}
		return nil
	}

	runScanner := func(name string, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { recover() }()
			f()
		}()
	}

	// 1. crt.sh
	runScanner("crt.sh", func() {
		body := fetchWithRetry(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
		count := 0
		if body != nil {
			var entries []struct {
				NameValue string `json:"name_value"`
			}
			if json.Unmarshal(body, &entries) == nil {
				mu.Lock()
				for _, e := range entries {
					for _, s := range strings.Split(e.NameValue, "\n") {
						s = strings.TrimSpace(s)
						if strings.HasSuffix(s, domain) && !strings.Contains(s, "*") {
							if !foundSubs[s] {
								foundSubs[s] = true
								count++
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("crt.sh", "✅", count)
	})

	// 2. HackerTarget
	runScanner("HackerTarget", func() {
		body := fetchWithRetry(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
		count := 0
		if body != nil {
			mu.Lock()
			for _, line := range strings.Split(string(body), "\n") {
				if parts := strings.Split(line, ","); len(parts) > 0 {
					sub := strings.TrimSpace(parts[0])
					if strings.HasSuffix(sub, domain) {
						if !foundSubs[sub] {
							foundSubs[sub] = true
							count++
						}
					}
				}
			}
			mu.Unlock()
		}
		updateProgress("HackerTarget", "✅", count)
	})

	// 3. RapidDNS
	runScanner("RapidDNS", func() {
		body := fetchWithRetry(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
		count := 0
		if body != nil {
			re := regexp.MustCompile(`[a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain))
			matches := re.FindAllString(string(body), -1)
			mu.Lock()
			for _, m := range matches {
				if !foundSubs[m] {
					foundSubs[m] = true
					count++
				}
			}
			mu.Unlock()
		}
		updateProgress("RapidDNS", "✅", count)
	})

	// 4. Wayback
	runScanner("Wayback", func() {
		body := fetchWithRetry(fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain))
		count := 0
		if body != nil {
			var data [][]string
			if json.Unmarshal(body, &data) == nil && len(data) > 1 {
				mu.Lock()
				for _, row := range data[1:] {
					if len(row) > 0 {
						parts := strings.Split(row[0], "/")
						if len(parts) > 2 {
							host := parts[2]
							if idx := strings.Index(host, ":"); idx != -1 {
								host = host[:idx]
							}
							if strings.HasSuffix(host, domain) {
								if !foundSubs[host] {
									foundSubs[host] = true
									count++
								}
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("Wayback", "✅", count)
	})

	// 5. CertSpotter
	runScanner("CertSpotter", func() {
		body := fetchWithRetry(fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain))
		count := 0
		if body != nil {
			var entries []struct {
				DNSNames []string `json:"dns_names"`
			}
			if json.Unmarshal(body, &entries) == nil {
				mu.Lock()
				for _, e := range entries {
					for _, name := range e.DNSNames {
						if strings.HasSuffix(name, domain) && !strings.Contains(name, "*") {
							if !foundSubs[name] {
								foundSubs[name] = true
								count++
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("CertSpotter", "✅", count)
	})

	// 6. AnubisDB
	runScanner("AnubisDB", func() {
		body := fetchWithRetry(fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain))
		count := 0
		if body != nil {
			var subs []string
			if json.Unmarshal(body, &subs) == nil {
				mu.Lock()
				for _, s := range subs {
					if strings.HasSuffix(s, domain) {
						if !foundSubs[s] {
							foundSubs[s] = true
							count++
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("AnubisDB", "✅", count)
	})

	wg.Wait()
	close(progressChan)

	var result []string
	for s := range foundSubs {
		result = append(result, s)
	}
	sort.Strings(result)
	return result, nil
}

func subdomainEnumWithProgress(chatID int64, msgID int, domain string) []string {
	domain = strings.ToLower(domain)

	foundSubs := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sources := []string{"crt.sh", "HackerTarget", "RapidDNS", "Wayback", "CertSpotter", "AnubisDB"}
	completed := 0
	var progressMu sync.Mutex

	updateProgress := func(source string, status string, count int) {
		progressMu.Lock()
		completed++
		current := completed
		progressMu.Unlock()

		text := fmt.Sprintf("🔎 *Subdomain Enumeration*\n━━━━━━━━━━━━━━━━━━━━\n\nTarget: `%s`\n\n📡 %s: %s (found: %d)\n📊 Progress: %d/%d sources",
			escapeMarkdownV2(domain), source, status, count, current, len(sources))

		editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
		editMsg.ParseMode = "MarkdownV2"
		bot.Send(editMsg)
	}

	fetchWithRetry := func(url string) []byte {
		client := &http.Client{Timeout: 30 * time.Second}
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return body
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(time.Duration(1+i) * time.Second)
		}
		return nil
	}

	// 1. crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := fetchWithRetry(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
		count := 0
		if body != nil {
			var entries []struct {
				NameValue string `json:"name_value"`
			}
			if json.Unmarshal(body, &entries) == nil {
				mu.Lock()
				for _, e := range entries {
					for _, s := range strings.Split(e.NameValue, "\n") {
						s = strings.TrimSpace(s)
						if strings.HasSuffix(s, domain) && !strings.Contains(s, "*") {
							if !foundSubs[s] {
								foundSubs[s] = true
								count++
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("crt.sh", "✅ done", count)
	}()

	// 2. HackerTarget
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := fetchWithRetry(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
		count := 0
		if body != nil {
			mu.Lock()
			for _, line := range strings.Split(string(body), "\n") {
				if parts := strings.Split(line, ","); len(parts) > 0 {
					sub := strings.TrimSpace(parts[0])
					if strings.HasSuffix(sub, domain) {
						if !foundSubs[sub] {
							foundSubs[sub] = true
							count++
						}
					}
				}
			}
			mu.Unlock()
		}
		updateProgress("HackerTarget", "✅ done", count)
	}()

	// 3. RapidDNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := fetchWithRetry(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
		count := 0
		if body != nil {
			re := regexp.MustCompile(`[a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain))
			matches := re.FindAllString(string(body), -1)
			mu.Lock()
			for _, m := range matches {
				if !foundSubs[m] {
					foundSubs[m] = true
					count++
				}
			}
			mu.Unlock()
		}
		updateProgress("RapidDNS", "✅ done", count)
	}()

	// 4. Wayback Machine
	wg.Add(1)
	go func() {
		defer wg.Done()
		url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
		body := fetchWithRetry(url)
		count := 0
		if body != nil {
			var data [][]string
			if json.Unmarshal(body, &data) == nil && len(data) > 1 {
				mu.Lock()
				for _, row := range data[1:] {
					if len(row) > 0 {
						rawUrl := row[0]
						parts := strings.Split(rawUrl, "/")
						if len(parts) > 2 {
							host := parts[2]
							if idx := strings.Index(host, ":"); idx != -1 {
								host = host[:idx]
							}
							if strings.HasSuffix(host, domain) {
								if !foundSubs[host] {
									foundSubs[host] = true
									count++
								}
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("Wayback", "✅ done", count)
	}()

	// 5. CertSpotter
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := fetchWithRetry(fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain))
		count := 0
		if body != nil {
			var entries []struct {
				DNSNames []string `json:"dns_names"`
			}
			if json.Unmarshal(body, &entries) == nil {
				mu.Lock()
				for _, e := range entries {
					for _, name := range e.DNSNames {
						if strings.HasSuffix(name, domain) && !strings.Contains(name, "*") {
							if !foundSubs[name] {
								foundSubs[name] = true
								count++
							}
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("CertSpotter", "✅ done", count)
	}()

	// 6. AnubisDB
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := fetchWithRetry(fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain))
		count := 0
		if body != nil {
			var subs []string
			if json.Unmarshal(body, &subs) == nil {
				mu.Lock()
				for _, s := range subs {
					if strings.HasSuffix(s, domain) {
						if !foundSubs[s] {
							foundSubs[s] = true
							count++
						}
					}
				}
				mu.Unlock()
			}
		}
		updateProgress("AnubisDB", "✅ done", count)
	}()

	wg.Wait()

	var result []string
	for s := range foundSubs {
		result = append(result, s)
	}
	sort.Strings(result)

	return result
}

func doReverseIPLookup(ip string) ([]string, error) {
	resolver := getCustomDialer().Resolver
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	hostnames, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		if netErr, ok := err.(*net.DNSError); ok && netErr.IsNotFound {
			return nil, fmt.Errorf("NOT_FOUND")
		}
		return nil, fmt.Errorf("DNS_TIMEOUT")
	}
	for i, host := range hostnames {
		hostnames[i] = strings.TrimSuffix(host, ".")
	}
	return hostnames, nil
}

func extractDomains(text string) []string {
	re := regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|gov|edu|mil|biz|info|me|co|us|uk|ca|de|jp|fr|au|ru|ch|it|nl|se|no|es|online|tech|xyz|xyz|app|dev|shop|store)\b`)
	return re.FindAllString(text, -1)
}

func removeDuplicates(domains []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, d := range domains {
		d = strings.ToLower(d)
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	sort.Strings(unique)
	return unique
}

func nextIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ParsePorts(portString string) ([]int, error) {
	var ports []int
	parts := strings.Split(portString, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range values: %s", part)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid single port value: %s", part)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func generateWorkingConfig(host string, port int, result VerificationResult) string {
	if !result.IsWorking {
		return "NOT WORKING"
	}
	var config string
	switch result.VerifiedBug {
	case "WEBSOCKET CONFIRMED", "WEBSOCKET FULLY WORKING":
		config = fmt.Sprintf("[VLESS + WebSocket]\nAddress: %s\nPort: %d\nPath: %s\nHost: %s\nSecurity: none\nNetwork: ws\nQuality: %d/100",
			host, port, result.WorkingPath, host, result.QualityScore)
	case "SNI SPOOF":
		spoofSNI := host
		if val, ok := result.WorkingHeader["SNI"]; ok {
			spoofSNI = val
		}
		config = fmt.Sprintf("[VLESS + TLS SNI Spoof]\nAddress: %s\nPort: %d\nSNI: %s\nSecurity: tls\nQuality: %d/100",
			host, port, spoofSNI, result.QualityScore)
	case "HTTP/3 QUIC AVAILABLE":
		config = fmt.Sprintf("[Hysteria2 / XTLS + QUIC]\nAddress: %s\nPort: %d\nProtocol: udp\nType: http/3\nQuality: %d/100",
			host, port, result.QualityScore)
	case "AZURE BNI":
		config = fmt.Sprintf("[VLESS + WS Azure BNI]\nAddress: %s\nPort: %d\nHeaders: X-BNI-JA: true\nQuality: %d/100",
			host, port, result.QualityScore)
	case "CDN FRONTING":
		config = fmt.Sprintf("[V2Ray + HTTP CDN Fronting]\nAddress: %s\nPort: %d\nHost Header: %s\nQuality: %d/100",
			host, port, host, result.QualityScore)
	default:
		config = fmt.Sprintf("[Standard Tunnel]\nAddress: %s\nPort: %d\nQuality: %d/100",
			host, port, result.QualityScore)
	}
	return config
}

func getProgressBar(percent float64, width int) string {
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

func handleMassScanFile(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	document := update.Message.Document

	if !strings.HasSuffix(document.FileName, ".txt") {
		msg := tgbotapi.NewMessage(chatID, "❌ Please upload a `.txt` file.")
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)
		return
	}

	// Download file
	fileConfig := tgbotapi.FileConfig{FileID: document.FileID}
	file, err := bot.GetFile(fileConfig)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ Failed to download file")
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	// Save to temp file
	tmpFile := filepath.Join(os.TempDir(), document.FileID+".txt")
	err = downloadFileToPath(file, tmpFile, bot)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ Failed to save file")
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	// Parse hosts
	f, err := os.Open(tmpFile)
	if err != nil {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ Failed to read file"))
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var hosts []string
	for scanner.Scan() {
		if host := strings.TrimSpace(scanner.Text()); host != "" {
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ No valid hosts found"))
		clearSessionState(chatID)
		return
	}

	if len(hosts) > 500 {
		hosts = hosts[:500]
	}

	// --- CRITICAL SESSION STORAGE ---
	session := getSession(chatID)
	if session.TempData == nil {
		session.TempData = make(map[string]interface{})
	}
	session.TempData["mass_hosts"] = hosts
	session.State = "awaiting_mass_ports"

	// --- FIX MARKDOWN V2 (ESCAPE CHARACTERS) ---
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Use Default (443,80,8080)", "mass_ports_default"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	// Kita guna string biasa (Markdown V1 style) tapi hantar tanpa ParseMode
	// atau guna escape manual untuk V2
	reportMsg := fmt.Sprintf(
		"📊 *Loaded %d hosts*\n\n"+
			"Enter ports to scan:\n"+
			"• Single: 443\n"+
			"• Multiple: 443,80,8080\n"+
			"• Range: `8000-8010`\n\n"+
			"Or use default ports:",
		len(hosts))

	msg := tgbotapi.NewMessage(chatID, reportMsg)
	msg.ParseMode = "Markdown" // Tukar ke Markdown biasa (V1) supaya selamat
	msg.ReplyMarkup = keyboard

	_, err = bot.Send(msg)
	if err != nil {
		// Fallback kalau V1/V2 pun mampus
		msg.ParseMode = ""
		bot.Send(msg)
	}
}

func handleMassScanPorts(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)

	var ports []int
	if text == "" {
		ports = []int{443, 80, 8080}
	} else {
		var err error
		ports, err = ParsePorts(text)
		if err != nil || len(ports) == 0 {
			msg := tgbotapi.NewMessage(chatID, "❌ Invalid port format. Using default ports (443,80,8080).")
			bot.Send(msg)
			ports = []int{443, 80, 8080}
		}
	}

	session := getSession(chatID)
	hosts, ok := session.TempData["mass_hosts"].([]string)
	if !ok {
		msg := tgbotapi.NewMessage(chatID, "❌ Session expired. Please start over.")
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🔄 *Starting Mass Scan*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
			"📊 %d hosts × %d ports = %d scans\n"+
			"⏳ Initializing...",
		len(hosts), len(ports), len(hosts)*len(ports)))
	statusMsg.ParseMode = "Markdown"
	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		log.Printf("❌ Failed to send status: %v", err)
		return
	}

	go executeMassScan(chatID, sentMsg.MessageID, hosts, ports)
}

func executeMassScan(chatID int64, statusMsgID int, hosts []string, ports []int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in Mass scan: %v", r)
			updateStatus(chatID, statusMsgID, "```\n❌ ENGINE CRASHED\n━━━━━━━━━━━━━━━━━━━━\nCritical failure in scanner logic.\n```")
			clearSessionState(chatID)
		}
	}()

	startTime := time.Now()

	// 1. DEDUP & CLEANING
	seenHosts := make(map[string]bool)
	uniqueHosts := make([]string, 0)
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seenHosts[h] {
			seenHosts[h] = true
			uniqueHosts = append(uniqueHosts, h)
		}
	}
	hosts = uniqueHosts
	totalHosts := len(hosts)
	totalJobs := int64(totalHosts) * int64(len(ports))

	var mu sync.Mutex
	hostPriority := make(map[string]string)
	allResults := make(map[string]*scanRecord)
	var strongCandidates []scanRecord
	var completedJobs int64

	// ==================== STAGE 1: RAW PROBING ====================
	updateStatus(chatID, statusMsgID, "🔄 *Stage 1/2:* Scanning for live holes...")

	ticker := time.NewTicker(2 * time.Second)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				completed := atomic.LoadInt64(&completedJobs)
				if completed >= totalJobs {
					return
				}
				if completed == 0 {
					continue
				}
				percent := float64(completed) / float64(totalJobs) * 100

				mu.Lock()
				found := len(strongCandidates)
				mu.Unlock()

				text := fmt.Sprintf(
					"🔄 *Stage 1/2: Probing...*\n\n📊 Progress: `%.0f%%` (%d/%d)\n💎 Candidates: `%d`",
					percent, completed, totalJobs, found,
				)
				updateStatus(chatID, statusMsgID, text)
			case <-done:
				return
			}
		}
	}()

	concurrency := 150
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, h := range hosts {
		for _, port := range ports {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(targetHost string, targetPort int) {
				defer wg.Done()
				defer func() { <-semaphore }()
				defer func() {
					if r := recover(); r != nil {
						atomic.AddInt64(&completedJobs, 1)
					}
				}()

				// 1. Resolve IP
				ip, err := resolveIPv4(targetHost)
				if err != nil {
					atomic.AddInt64(&completedJobs, 1)
					return
				}

				// 2. Run Engine
				_, info, label, tlsRaw := classifyWithProbes(targetHost, ip, targetPort)
				info.IP = ip

				if info.HTTPStatus == "" || info.HTTPStatus == "000" {
					atomic.AddInt64(&completedJobs, 1)
					return
				}

				// 3. Preliminary Scoring
				finalPrio, qualityScore := calculateScore(label, info)

				// Determine bugType
				labelUpper := strings.ToUpper(label)
				bugType := "CDN_HOST"
				switch {
				case strings.Contains(labelUpper, "H3") || strings.Contains(labelUpper, "QUIC"):
					bugType = "H3_QUIC"
				case strings.Contains(info.HTTPStatus, "101") || strings.Contains(labelUpper, "WS"):
					bugType = "WS"
				case strings.Contains(labelUpper, "REALITY"):
					bugType = "REALITY"
				case strings.Contains(labelUpper, "SPOOF") || labelUpper == "BUGHOST CONFIRMED":
					bugType = "SPOOF"
				}

				record := &scanRecord{
					host:      targetHost,
					port:      targetPort,
					priority:  finalPrio,
					status:    info.HTTPStatus,
					server:    info.Server,
					cn:        info.CommonName,
					tlsRaw:    tlsRaw,
					latencyMs: info.LatencyMs,
					bugType:   bugType,
					score:     qualityScore,
					info:      info,
					label:     label,
				}

				mu.Lock()
				key := targetHost + ":" + strconv.Itoa(targetPort)
				if existing, exists := allResults[key]; !exists || qualityScore > existing.score {
					allResults[key] = record
				}

				if finalPrio == "STRONG" {
					strongCandidates = append(strongCandidates, *record)
				}

				if priorityToRank(finalPrio) > priorityToRank(hostPriority[targetHost]) {
					hostPriority[targetHost] = finalPrio
				}
				mu.Unlock()

				atomic.AddInt64(&completedJobs, 1)
			}(h, port)
		}
	}
	wg.Wait()
	ticker.Stop()
	close(done)

	stage1Elapsed := time.Since(startTime).Round(time.Second)

	// ==================== STAGE 2: STRICT DEEP VERIFY ====================
	var deepVerifiedCount, deepFailedCount int64
	verifiedTargets := make([]map[string]string, 0)
	failedTargets := make([]map[string]string, 0)

	// Dedup strong candidates
	seen := make(map[string]bool)
	uniqueCandidates := make([]scanRecord, 0)
	for _, c := range strongCandidates {
		key := c.host + ":" + strconv.Itoa(c.port)
		if !seen[key] && c.info.IP != "" {
			seen[key] = true
			uniqueCandidates = append(uniqueCandidates, c)
		}
	}
	strongCandidates = uniqueCandidates

	if len(strongCandidates) > 0 {
		updateStatus(chatID, statusMsgID, fmt.Sprintf(
			"🔬 *Stage 2/2:* Deep Verifying %d candidates...\n\n⚡ Stage 1 done in %v",
			len(strongCandidates), stage1Elapsed))

		var dvWg sync.WaitGroup
		dvSemaphore := make(chan struct{}, 30)
		var dvCompleted int64

		dvTicker := time.NewTicker(3 * time.Second)
		dvDone := make(chan bool)
		go func() {
			for {
				select {
				case <-dvTicker.C:
					done := atomic.LoadInt64(&dvCompleted)
					total := int64(len(strongCandidates))
					verified := atomic.LoadInt64(&deepVerifiedCount)
					failed := atomic.LoadInt64(&deepFailedCount)

					percent := 0.0
					if total > 0 {
						percent = float64(done) / float64(total) * 100
					}

					text := fmt.Sprintf(
						"🔬 *Stage 2/2: Deep Verifying...*\n\n"+
							"📊 Progress: %.0f%% (%d/%d)\n"+
							"✅ Passed: %d | ❌ Failed: %d",
						percent, done, total, verified, failed,
					)
					updateStatus(chatID, statusMsgID, text)
				case <-dvDone:
					return
				}
			}
		}()

		for _, c := range strongCandidates {
			dvWg.Add(1)
			dvSemaphore <- struct{}{}

			go func(cand scanRecord) {
				defer dvWg.Done()
				defer func() { <-dvSemaphore }()
				defer func() {
					if r := recover(); r != nil {
						atomic.AddInt64(&dvCompleted, 1)
						atomic.AddInt64(&deepFailedCount, 1)
					}
				}()

				ip := cand.info.IP
				if ip == "" {
					var err error
					ip, err = resolveIPv4(cand.host)
					if err != nil || ip == "" {
						atomic.AddInt64(&dvCompleted, 1)
						atomic.AddInt64(&deepFailedCount, 1)
						return
					}
				}

				verified := deepVerify(cand.host, ip, cand.port, cand.label, cand.info)

				mu.Lock()
				key := cand.host + ":" + strconv.Itoa(cand.port)

				isBloated := cand.info.ContentLength > 25000
				finalScore := verified.QualityScore
				if isBloated && !strings.Contains(cand.info.HTTPStatus, "101") {
					finalScore = finalScore / 3
				}

				vu := strings.ToUpper(verified.VerifiedBug)
				isStandardCDN := strings.Contains(vu, "DIRECT TLS") && cand.port == 443
				if isStandardCDN {
					cnClean := strings.ToLower(strings.ReplaceAll(cand.info.CommonName, "*.", ""))
					hostClean := strings.ToLower(cand.host)
					cdnMismatch := cnClean != "" && !strings.Contains(hostClean, cnClean) && !strings.Contains(cnClean, hostClean)

					if !cdnMismatch {
						finalScore = finalScore / 3
					}
				}

				if verified.IsWorking && finalScore >= 65 {
					newBugType := verified.VerifiedBug
					newLabel := verified.VerifiedBug

					switch {
					case strings.Contains(vu, "WEBSOCKET"):
						newBugType = "WS_PRO"
						newLabel = "WS"
					case strings.Contains(vu, "HTTP/3") || strings.Contains(vu, "QUIC"):
						newBugType = "H3_QUIC"
						newLabel = "H3_QUIC"
					case strings.Contains(cand.label, "REALITY"):
						newBugType = "REALITY_FIX"
						newLabel = "REALITY"
					case strings.Contains(vu, "SNI SPOOF"):
						newBugType = "SPOOF"
						newLabel = "SPOOF"
					case strings.Contains(vu, "CDN"):
						newBugType = "CDN_FRONT"
						newLabel = "CDN_FRONT"
					}

					newStatus := "VERIFIED"
					newServer := cand.info.Server
					newCN := cand.info.CommonName
					if verified.WorkingHeader != nil {
						if sni, ok := verified.WorkingHeader["SNI"]; ok && sni != "" {
							newCN = sni
						}
					}

					deepVerifiedStr := fmt.Sprintf("YES (%s|%d)", newBugType, finalScore)

					if rec, exists := allResults[key]; exists {
						rec.deepVerified = deepVerifiedStr
						rec.score = finalScore
						rec.priority = "STRONG"
						rec.bugType = newBugType
						rec.status = newStatus
						rec.server = newServer
						rec.cn = newCN
						rec.label = newLabel
					}

					verifiedTargets = append(verifiedTargets, map[string]string{
						"host":          cand.host,
						"port":          strconv.Itoa(cand.port),
						"sni":           newCN,
						"tag":           newBugType,
						"status":        newStatus,
						"score":         strconv.Itoa(finalScore),
						"server":        newServer,
						"cn":            newCN,
						"deep_verified": deepVerifiedStr,
						"latency":       strconv.Itoa(cand.latencyMs),
					})

					hostPriority[cand.host] = "STRONG"
					atomic.AddInt64(&deepVerifiedCount, 1)

				} else {
					errorMsg := verified.ErrorMessage
					if errorMsg == "" {
						errorMsg = "Low quality / Fake bughost"
					}

					deepVerifiedStr := fmt.Sprintf("FAILED (%s)", errorMsg)
					newScore := cand.score / 3
					if newScore < 5 {
						newScore = 5
					}

					if rec, exists := allResults[key]; exists {
						rec.deepVerified = deepVerifiedStr
						rec.score = newScore
						rec.priority = "WEAK"
					}

					failedTargets = append(failedTargets, map[string]string{
						"host":          cand.host,
						"port":          strconv.Itoa(cand.port),
						"tag":           cand.bugType,
						"status":        "FAILED",
						"score":         strconv.Itoa(newScore),
						"server":        cand.info.Server,
						"cn":            cand.info.CommonName,
						"deep_verified": deepVerifiedStr,
						"latency":       strconv.Itoa(cand.latencyMs),
					})

					hostPriority[cand.host] = "WEAK"
					atomic.AddInt64(&deepFailedCount, 1)
				}
				mu.Unlock()

				atomic.AddInt64(&dvCompleted, 1)
			}(c)
		}

		dvWg.Wait()
		dvTicker.Stop()
		close(dvDone)
	}

	// ==================== TULIS CSV ====================
	csvFile := filepath.Join(os.TempDir(), fmt.Sprintf("Paragon_Mass_%d.csv", time.Now().Unix()))
	out, err := os.Create(csvFile)
	if err == nil {
		writer := csv.NewWriter(out)
		writer.Write([]string{"Host", "Port", "Priority", "Status", "Server", "CN", "TLS_Raw", "Latency(ms)", "BugType", "Score", "DeepVerified"})

		mu.Lock()
		for _, rec := range allResults {
			writer.Write([]string{
				rec.host, strconv.Itoa(rec.port), rec.priority, rec.status,
				rec.server, rec.cn, rec.tlsRaw, strconv.Itoa(rec.latencyMs), rec.bugType, strconv.Itoa(rec.score), rec.deepVerified,
			})
		}
		mu.Unlock()
		writer.Flush()
		out.Close()
	}

	// ==================== FINAL REPORT ====================
	elapsed := time.Since(startTime).Round(time.Second)
	speed := 0.0
	if elapsed.Seconds() > 0 {
		speed = float64(totalJobs) / elapsed.Seconds()
	}

	sort.Slice(verifiedTargets, func(i, j int) bool {
		scoreI, _ := strconv.Atoi(verifiedTargets[i]["score"])
		scoreJ, _ := strconv.Atoi(verifiedTargets[j]["score"])
		return scoreI > scoreJ
	})

	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("╭──────────────────────────╮\n")
	sb.WriteString("│  💎 PARAGON MASS RESULT  │\n")
	sb.WriteString("╰──────────────────────────╯\n")
	sb.WriteString(fmt.Sprintf("Hosts : %d | Jobs: %d\n", totalHosts, totalJobs))
	sb.WriteString(fmt.Sprintf("Time  : %v | Speed: %.1f/s\n", elapsed, speed))
	sb.WriteString(fmt.Sprintf("🔬 OK : %d | ❌ Fake: %d\n",
		atomic.LoadInt64(&deepVerifiedCount),
		atomic.LoadInt64(&deepFailedCount)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if len(verifiedTargets) > 0 {
		sb.WriteString("\n✅ VERIFIED TARGETS:\n\n")
		limit := 10
		for i, v := range verifiedTargets {
			if i >= limit {
				break
			}
			icon := "✅"
			tag := v["tag"]
			switch tag {
			case "H3_QUIC":
				icon = "⚡"
				tag = "H3/QUIC"
			case "WS_PRO", "WS":
				icon = "🔌"
				tag = "WS-PRO"
			case "REALITY_FIX", "REALITY":
				icon = "🔮"
				tag = "REALITY"
			case "SPOOF":
				icon = "🎭"
				tag = "SPOOF"
			case "CDN_FRONT":
				icon = "☁️"
				tag = "CDN-FRONT"
			}
			sb.WriteString(fmt.Sprintf("%s %-18s [%s]\n", icon, v["host"], tag))
			sb.WriteString(fmt.Sprintf("   PORT: %-5s | SC: %-3s | L: %-4sms\n", v["port"], v["score"], v["latency"]))
			sb.WriteString(fmt.Sprintf("   CDN: %s\n", v["server"]))
			sb.WriteString(fmt.Sprintf("   SNI: %s\n", v["cn"]))
			sb.WriteString(fmt.Sprintf("   🔬: %s\n", v["deep_verified"]))
			sb.WriteString("   ────────────────────────\n")
		}
	}

	if len(failedTargets) > 0 {
		sb.WriteString(fmt.Sprintf("\n❌ FAILED (%d):\n", len(failedTargets)))
		limit := 3
		for i, v := range failedTargets {
			if i >= limit {
				sb.WriteString(fmt.Sprintf("   ... and %d more\n", len(failedTargets)-limit))
				break
			}
			sb.WriteString(fmt.Sprintf("   • %-18s [%s] | %s\n",
				v["host"], v["tag"], v["deep_verified"]))
		}
	}

	if len(verifiedTargets) == 0 {
		sb.WriteString("\n⚠️ No high-quality bug found.\n")
	}
	sb.WriteString("```")

	updateStatus(chatID, statusMsgID, sb.String())

	// Hantar CSV file
	fileBytes, _ := os.ReadFile(csvFile)
	if len(fileBytes) > 0 {
		doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
			Name:  fmt.Sprintf("DeepVerify_%s.csv", time.Now().Format("150405")),
			Bytes: fileBytes,
		})
		doc.Caption = fmt.Sprintf("📄 *Deep Verify Report*\n🔥 *Candidates:* %d\n✅ *Verified:* %d\n❌ *Failed:* %d\n⏱ *Time:* %v",
			len(strongCandidates),
			atomic.LoadInt64(&deepVerifiedCount),
			atomic.LoadInt64(&deepFailedCount),
			elapsed)
		doc.ParseMode = "Markdown"
		bot.Send(doc)
	}

	os.Remove(csvFile)
	clearSessionState(chatID)
}

func handleCIDRInput(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	cidr := strings.TrimSpace(update.Message.Text)

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ Invalid CIDR format. Example: `57.144.120.0/24`")
		msg.ParseMode = "MarkdownV2"
		bot.Send(msg)
		return
	}

	ones, bits := ipnet.Mask.Size()
	totalIPs := 1 << (bits - ones)
	if totalIPs > 2 {
		totalIPs -= 2
	}

	if totalIPs > 256 {
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❌ Range too large: %d IPs. Maximum is 256 (CIDR /24).", totalIPs))
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	session := getSession(chatID)
	session.TempData["cidr"] = cidr
	session.TempData["total_ips"] = totalIPs
	session.State = "awaiting_cidr_ports"

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Use Default (443,80)", "cidr_ports_default"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🌐 *CIDR: %s*\n"+
			"Total IPs: %d\n\n"+
			"Enter ports to scan:\n"+
			"Example: `443,80,8080` or `8000-8010`",
		escapeMarkdownV2(cidr), totalIPs))
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}

func priorityToRank(p string) int {
	switch strings.ToUpper(p) {
	case "H3_QUIC":
		return 10
	case "REALITY":
		return 9
	case "WS":
		return 8
	case "SPOOF":
		return 7
	case "CDN_HOST":
		return 6

	case "STRONG":
		return 3
	case "MEDI":
		return 2
	case "WEAK":
		return 1
	default:
		return 0
	}
}

func executeCIDRScan(chatID int64, statusMsgID int, cidr string, ipnet *net.IPNet, ports []int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in CIDR scan: %v", r)
			updateStatus(chatID, statusMsgID, "```\n❌ ENGINE ERROR\n━━━━━━━━━━━━━━━━━━━━\nCIDR scan failed unexpectedly.\nPlease try a smaller range.\n```")
			clearSessionState(chatID)
		}
	}()

	startTime := time.Now()
	ones, bits := ipnet.Mask.Size()
	totalIPs := 1 << (bits - ones)
	if totalIPs > 2 {
		totalIPs -= 2
	}

	totalIPs64 := int64(totalIPs)
	totalJobs := totalIPs64 * int64(len(ports))

	if totalIPs > 1024 {
		updateStatus(chatID, statusMsgID, fmt.Sprintf(
			"⚠️ *Range Too Large*\n\nYour range: `%s` (%d IPs)\nMaximum: 1024 IPs\n\nPlease use a smaller range like /24",
			cidr, totalIPs))
		return
	}
	csvFile := filepath.Join(os.TempDir(), fmt.Sprintf("Paragon_CIDR_%d.csv", time.Now().Unix()))
	out, err := os.Create(csvFile)
	if err != nil {
		updateStatus(chatID, statusMsgID, "❌ Failed to create report file.")
		return
	}
	defer out.Close()

	writer := csv.NewWriter(out)
	writer.Write([]string{"IP", "Port", "Priority", "Status", "Server", "CN", "TLS_Raw", "Latency(ms)", "BugType", "Score"})

	var mu sync.Mutex
	ipPriority := make(map[string]string)
	sniSpoofableHosts := make([]map[string]string, 0)
	var completedJobs int64

	ticker := time.NewTicker(5 * time.Second)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-ticker.C:
				completed := atomic.LoadInt64(&completedJobs)
				if completed >= totalJobs {
					return
				}
				if completed == 0 {
					continue
				}

				percent := float64(completed) / float64(totalJobs) * 100
				barLen := 15
				filled := int(percent / 100 * float64(barLen))
				if filled > barLen {
					filled = barLen
				}
				bar := strings.Repeat("▰", filled) + strings.Repeat("▱", barLen-filled)

				mu.Lock()
				found := len(sniSpoofableHosts)
				mu.Unlock()

				elapsedLive := time.Since(startTime)
				speedLive := float64(completed) / elapsedLive.Seconds()

				text := fmt.Sprintf(
					"🔄 *Scanning Network...*\n\n"+
						"🎯 Target: `%s`\n"+
						"📊 Progress: `%s` %.0f%%\n\n"+
						"⚡ Speed: %.1f/s\n"+
						"💎 Found: %d potential targets",
					cidr, bar, percent, speedLive, found,
				)
				updateStatus(chatID, statusMsgID, text)
			case <-done:
				return
			}
		}
	}()

	concurrency := 50
	if totalIPs > 256 {
		concurrency = 120
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	currentIP := make(net.IP, len(ipnet.IP))
	copy(currentIP, ipnet.IP.Mask(ipnet.Mask))

	for i := 0; i < totalIPs; i++ {
		nextIP(currentIP)
		ipStr := currentIP.String()

		for _, port := range ports {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(targetIP string, targetPort int) {
				defer wg.Done()
				defer func() { <-semaphore }()
				defer func() {
					if r := recover(); r != nil {
						atomic.AddInt64(&completedJobs, 1)
					}
				}()

				probeDone := make(chan struct{}, 1)
				var info tlsInfo
				var label string
				var tlsRaw string

				go func() {
					_, info, label, tlsRaw = classifyWithProbes(targetIP, targetIP, targetPort)
					probeDone <- struct{}{}
				}()

				select {
				case <-probeDone:
				case <-time.After(12 * time.Second):
					atomic.AddInt64(&completedJobs, 1)
					return
				}

				if info.HTTPStatus == "" || info.HTTPStatus == "000" {
					atomic.AddInt64(&completedJobs, 1)
					return
				}

				finalPrio, qualityScore := calculateScore(label, info)

				labelUpper := strings.ToUpper(label)
				bugType := "CDN_HOST"
				switch {
				case strings.Contains(labelUpper, "H3") || strings.Contains(labelUpper, "QUIC"):
					bugType = "H3_QUIC"
				case strings.Contains(info.HTTPStatus, "101") || strings.Contains(labelUpper, "WS"):
					bugType = "WS"
				case strings.Contains(labelUpper, "REALITY"):
					bugType = "REALITY"
				case strings.Contains(labelUpper, "SPOOF") || labelUpper == "BUGHOST CONFIRMED":
					bugType = "SPOOF"
				case strings.Contains(labelUpper, "CDN"):
					bugType = "CDN_HOST"
				}

				mu.Lock()
				if finalPrio == "STRONG" {
					sniSpoofableHosts = append(sniSpoofableHosts, map[string]string{
						"ip": targetIP, "port": strconv.Itoa(targetPort),
						"sni": info.CommonName, "tag": bugType, "status": info.HTTPStatus,
						"score": strconv.Itoa(qualityScore), "server": info.Server, "cn": info.CommonName,
					})
				}

				if priorityToRank(finalPrio) > priorityToRank(ipPriority[targetIP]) {
					ipPriority[targetIP] = finalPrio
				}

				writer.Write([]string{
					targetIP, strconv.Itoa(targetPort), finalPrio, info.HTTPStatus,
					info.Server, info.CommonName, tlsRaw, strconv.Itoa(info.LatencyMs), bugType, strconv.Itoa(qualityScore),
				})
				mu.Unlock()

				atomic.AddInt64(&completedJobs, 1)
			}(ipStr, port)
		}
	}

	wg.Wait()
	ticker.Stop()
	close(done)
	writer.Flush()
	out.Close()

	sCount, mCount, wCount := 0, 0, 0
	for _, p := range ipPriority {
		switch p {
		case "STRONG":
			sCount++
		case "MEDI":
			mCount++
		case "WEAK":
			wCount++
		}
	}

	elapsed := time.Since(startTime).Round(time.Second)
	if elapsed <= 0 {
		elapsed = 1 * time.Second
	}
	speed := float64(totalJobs) / elapsed.Seconds()

	sort.Slice(sniSpoofableHosts, func(i, j int) bool {
		scoreI, _ := strconv.Atoi(sniSpoofableHosts[i]["score"])
		scoreJ, _ := strconv.Atoi(sniSpoofableHosts[j]["score"])
		return scoreI > scoreJ
	})

	var summary strings.Builder
	summary.WriteString("```\n")
	summary.WriteString("╭──────────────────────────╮\n")
	summary.WriteString("│  🛡️ PARAGON CIDR AUDIT DONE    │\n")
	summary.WriteString("╰──────────────────────────╯\n")
	summary.WriteString(fmt.Sprintf("Target : %s\n", cidr))
	summary.WriteString(fmt.Sprintf("Range  : %d IPs | %d Jobs\n", totalIPs, totalJobs))
	summary.WriteString(fmt.Sprintf("Time   : %v\n", elapsed))
	summary.WriteString(fmt.Sprintf("Speed  : %.1f/s\n", speed))
	summary.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if len(sniSpoofableHosts) > 0 {
		summary.WriteString("\n💎 TOP BUGHOSTS FOUND:\n\n")
		limit := 15
		for i, h := range sniSpoofableHosts {
			if i >= limit {
				break
			}

			icon := "🔥"
			labelTag := h["tag"]
			switch h["tag"] {
			case "H3_QUIC":
				icon = "⚡"
				labelTag = "H3/QUIC"
			case "WS":
				icon = "🔌"
				labelTag = "WS-PRO"
			case "REALITY":
				icon = "🔮"
				labelTag = "REALITY"
			case "SPOOF":
				icon = "🎭"
				labelTag = "SPOOF"
			case "CDN_HOST":
				icon = "☁️"
				labelTag = "CDN-ONLY"
			}

			summary.WriteString(fmt.Sprintf("%s %-15s [%s]\n", icon, h["ip"], labelTag))
			summary.WriteString(fmt.Sprintf("   PORT: %-5s STATUS: %s SCORE: %s\n", h["port"], h["status"], h["score"]))
			summary.WriteString(fmt.Sprintf("   CDN: %s\n", h["server"]))
			if h["cn"] != "" {
				summary.WriteString(fmt.Sprintf("   CN: %s\n", h["cn"]))
			}
			if h["sni"] != "" && h["sni"] != h["cn"] {
				summary.WriteString(fmt.Sprintf("   SNI: %s\n", h["sni"]))
			}
			summary.WriteString("   ────────────────────────\n")
		}
	} else {
		summary.WriteString("\n⚠️ No vulnerable hosts found.\n")
	}
	summary.WriteString("```")

	updateStatus(chatID, statusMsgID, summary.String())

	fileBytes, _ := os.ReadFile(csvFile)
	if len(fileBytes) > 0 {
		doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
			Name:  fmt.Sprintf("Report_%s.csv", strings.ReplaceAll(cidr, "/", "_")),
			Bytes: fileBytes,
		})
		doc.Caption = fmt.Sprintf("📄 *Full Report:* `%s`\n🔥 *Strong Targets:* %d\n⚡ *Speed:* %.1f/s", cidr, sCount, speed)
		doc.ParseMode = "Markdown"
		bot.Send(doc)
	}

	os.Remove(csvFile)
	clearSessionState(chatID)
}

func handleCIDRPorts(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)

	var ports []int
	if text == "" {
		ports = []int{443, 80}
	} else {
		var err error
		ports, err = ParsePorts(text)
		if err != nil || len(ports) == 0 {
			msg := tgbotapi.NewMessage(chatID, "❌ Invalid ports. Using default (443,80).")
			bot.Send(msg)
			ports = []int{443, 80}
		}
	}

	session := getSession(chatID)
	cidr, ok := session.TempData["cidr"].(string)
	if !ok {
		msg := tgbotapi.NewMessage(chatID, "❌ Session expired.")
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	_, ipnet, _ := net.ParseCIDR(cidr)

	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"🚀 *CIDR Scan Initialized*\n━━━━━━━━━━━━━━━━━━━━\n"+
			"🎯 Target: `%s`\n"+
			"🔍 Ports: %v\n\n"+
			"⏳ Starting scan...",
		cidr, ports))
	statusMsg.ParseMode = "Markdown"

	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		log.Printf("Failed to send status message: %v", err)
		return
	}

	go executeCIDRScan(chatID, sentMsg.MessageID, cidr, ipnet, ports)

	clearSessionState(chatID)
}

func handleExtractDomains(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := update.Message.Text

	domains := extractDomains(text)
	domains = removeDuplicates(domains)

	var result strings.Builder
	result.WriteString("*📝 DOMAIN EXTRACTION*\n")
	result.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(domains) == 0 {
		result.WriteString("❌ No valid domains found.\n")
	} else {
		result.WriteString(fmt.Sprintf("✅ Found *%d* domains:\n\n", len(domains)))
		limit := 30
		if len(domains) < limit {
			limit = len(domains)
		}
		for i := 0; i < limit; i++ {
			result.WriteString(fmt.Sprintf("• `%s`\n", escapeMarkdownV2(domains[i])))
		}
		if len(domains) > 30 {
			result.WriteString(fmt.Sprintf("\n_...and %d more_\n", len(domains)-30))
		}

		// Save to file
		tmpFile := os.TempDir() + fmt.Sprintf("/domains_%d.txt", time.Now().Unix())
		os.WriteFile(tmpFile, []byte(strings.Join(domains, "\n")), 0644)

		fileBytes, _ := os.ReadFile(tmpFile)
		fileMsg := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
			Name:  fmt.Sprintf("extracted_domains_%s.txt", time.Now().Format("150405")),
			Bytes: fileBytes,
		})
		fileMsg.Caption = fmt.Sprintf("📄 %d domains", len(domains))
		bot.Send(fileMsg)
		os.Remove(tmpFile)
	}

	result.WriteString("\n━━━━━━━━━━━━━━━━━━━━")

	msg := tgbotapi.NewMessage(chatID, result.String())
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(msg)

	clearSessionState(chatID)
}

// =============================================================================
// TELEGRAM BOT HANDLERS
// =============================================================================

func escapeMarkdownV2(text string) string {
	specialChars := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}
	for _, char := range specialChars {
		text = strings.ReplaceAll(text, char, "\\"+char)
	}
	return text
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

func formatSubdomainResultMarkdown(domain string, subdomains []string) string {
	var sb strings.Builder

	// Header
	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│  🔎 SUBDOMAIN RESULTS   │\n")
	sb.WriteString("╰─────────────────────────╯\n\n")

	sb.WriteString(fmt.Sprintf("Domain   : %s\n", domain))
	sb.WriteString(fmt.Sprintf("Found    : %d subdomains\n", len(subdomains)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(subdomains) == 0 {
		sb.WriteString("❌ No subdomains found\n")
	} else {
		// Show max 10 in chat, rest in file
		limit := 10
		if len(subdomains) < limit {
			limit = len(subdomains)
		}

		sb.WriteString("📋 Top Results:\n\n")
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, subdomains[i]))
		}

		if len(subdomains) > limit {
			sb.WriteString(fmt.Sprintf("\n  ... and %d more\n", len(subdomains)-limit))
			sb.WriteString("  📄 Full list sent as file below\n")
		}
	}

	sb.WriteString("\n```")

	return sb.String()
}

func getMainMenuKeyboard() *tgbotapi.InlineKeyboardMarkup {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔍 Single Scan", "menu_single"),
			tgbotapi.NewInlineKeyboardButtonData("📊 Mass Scan", "menu_mass"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 CIDR Scan", "menu_cidr"),
			tgbotapi.NewInlineKeyboardButtonData("🔎 Subdomain", "menu_sub"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Reverse DNS", "menu_reverse"),
			tgbotapi.NewInlineKeyboardButtonData("📝 Extract Domains", "menu_extract"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💉 Payload Test", "menu_payload"),
			tgbotapi.NewInlineKeyboardButtonData("⚙️ Config Validator", "menu_cfgval"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🆔 My HWID", "menu_hwid"),
			tgbotapi.NewInlineKeyboardButtonData("ℹ️ About", "menu_about"),
		),
	)
	return &keyboard
}

func getCancelKeyboard() *tgbotapi.InlineKeyboardMarkup {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🏠 Main Menu", "menu_main"),
		),
	)
	return &keyboard
}

func getMainMenuOnlyKeyboard() *tgbotapi.InlineKeyboardMarkup {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🏠 Back to Main Menu", "menu_main"),
		),
	)
	return &keyboard
}

func getSession(chatID int64) *UserSession {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	session, exists := userSessions[chatID]
	if !exists {
		session = &UserSession{
			ChatID:       chatID,
			State:        "idle",
			TempData:     make(map[string]interface{}),
			LastActivity: time.Now(),
		}
		userSessions[chatID] = session
	}
	session.LastActivity = time.Now()
	return session
}

func downloadFileToPath(fileConfig tgbotapi.File, path string, bot *tgbotapi.BotAPI) error {
	url := fileConfig.Link(bot.Token)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func setSessionState(chatID int64, state string) {
	session := getSession(chatID)
	session.State = state
}

func clearSessionState(chatID int64) {
	session := getSession(chatID)
	session.State = "idle"
	session.TempData = make(map[string]interface{})
}

func sendTyping(chatID int64) {
	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatTyping))
}

func handleStart(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID

	if !isSubscribed(update.Message.From.ID) {
		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonURL("🔊 Join @supremebughost", "https://t.me/supremebughost"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✅ I've Joined", "check_subscription"),
			),
		)

		msg := tgbotapi.NewMessage(chatID,
			"👋 *Welcome to PARAGON SNI Pro!*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
				"📢 To keep this bot running and get the latest bughost lists, please join our official channel.\n\n"+
				"👉 Click below to join, then press the button to start.")
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = &keyboard
		bot.Send(msg)
		return
	}

	hwid := getHWID()
	banner := "🔥 PARAGON SNI PRO " + version + "\n"
	banner += "━━━━━━━━━━━━━━━━━━━━\n"
	banner += "Developer: @" + author + "\n"
	banner += "HWID: " + hwid + "\n"
	banner += "Status: ✅ Active\n"
	banner += "━━━━━━━━━━━━━━━━━━━━\n\n"
	banner += "Select an option:"

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔍 Single Scan", "menu_single"),
			tgbotapi.NewInlineKeyboardButtonData("📊 Mass Scan", "menu_mass"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 CIDR Scan", "menu_cidr"),
			tgbotapi.NewInlineKeyboardButtonData("🔎 Subdomain", "menu_sub"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Reverse DNS", "menu_reverse"),
			tgbotapi.NewInlineKeyboardButtonData("📝 Extract Domains", "menu_extract"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💉 Payload Test", "menu_payload"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🆔 My HWID", "menu_hwid"),
			tgbotapi.NewInlineKeyboardButtonData("ℹ️ About", "menu_about"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, banner)
	msg.ReplyMarkup = &keyboard
	bot.Send(msg)
}

func handleHWID(update tgbotapi.Update) {
	chatID := int64(0)
	if update.Message != nil {
		chatID = update.Message.Chat.ID
	} else if update.CallbackQuery != nil {
		chatID = update.CallbackQuery.Message.Chat.ID
	}

	hwid := getHWID()
	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("*🆔 Your Hardware ID*\n━━━━━━━━━━━━━━━━━━━━\n\n`%s`\n\n━━━━━━━━━━━━━━━━━━━━\n\n_Provide this ID for license activation_", hwid))
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(msg)
}

func handleAbout(update tgbotapi.Update) {
	chatID := int64(0)
	if update.Message != nil {
		chatID = update.Message.Chat.ID
	} else if update.CallbackQuery != nil {
		chatID = update.CallbackQuery.Message.Chat.ID
	}

	about := fmt.Sprintf(
		"*ℹ️ PARAGON SNI PRO %s*\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"*Developer:* %s\n"+
			"*Engine:* Go High\\-Performance\n"+
			"*Features:*\n"+
			"• Multi\\-protocol \\(TLS/HTTP/WS\\)\n"+
			"• CDN/WAF Bypass Detection\n"+
			"• Premium SNI Database\n"+
			"• Subdomain Enumeration\n"+
			"• CIDR Range Scanning\n"+
			"━━━━━━━━━━━━━━━━━━━━",
		version, author)

	msg := tgbotapi.NewMessage(chatID, about)
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(msg)
}

func executeSingleScan(chatID int64, target string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Engine Error:* Please try again later."))
			clearSessionState(chatID)
		}
	}()

	// Rate limiter
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

	host, portStr, err := net.SplitHostPort(target)
	specifiedPort := 0
	if err == nil {
		specifiedPort, _ = strconv.Atoi(portStr)
	} else {
		host = target
	}

	// Cache check
	cacheKey := fmt.Sprintf("single:%s:%d", host, specifiedPort)
	if cached, found := resultCache.Get(cacheKey); found {
		statusText := fmt.Sprintf("📡 *Paragon Engine:* `%s`\n\n⚡ *Cached Result:*", host)
		statusMsg := tgbotapi.NewMessage(chatID, statusText)
		statusMsg.ParseMode = "Markdown"
		sentMsg, _ := bot.Send(statusMsg)

		edit := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, cached)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(edit)
		clearSessionState(chatID)
		return
	}

	statusText := fmt.Sprintf("📡 *Paragon Engine:* `%s`\n\n⌛ Status: _Initializing..._", host)
	statusMsg := tgbotapi.NewMessage(chatID, statusText)
	statusMsg.ParseMode = "Markdown"

	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Processing scan... please wait.")
		sentMsg, _ = bot.Send(msg)
	}

	msgID := sentMsg.MessageID
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resultChan := make(chan string, 1)
	resultPriority := make(chan string, 1)
	resultScore := make(chan int, 1)

	go func() {
		select {
		case <-ctx.Done():
			resultChan <- "❌ *Scan Timeout*"
			resultPriority <- "WEAK"
			resultScore <- 0
			return
		default:
		}

		updateStatus(chatID, msgID, "🔍 *Step 1:* Resolving host...")
		ip, err := resolveIPv4(host)
		if err != nil {
			resultChan <- "❌ *Resolution Failed:* Host not found."
			resultPriority <- "WEAK"
			resultScore <- 0
			return
		}

		select {
		case <-ctx.Done():
			resultChan <- "❌ *Scan Timeout*"
			resultPriority <- "WEAK"
			resultScore <- 0
			return
		case <-time.After(300 * time.Millisecond):
		}

		updateStatus(chatID, msgID, "📡 *Step 2:* Probing ports...")
		finalPort, udpQUICOpen := probePorts(ip, specifiedPort)

		if finalPort == 0 {
			resultChan <- "❌ *Unreachable:* Target ports are closed."
			resultPriority <- "WEAK"
			resultScore <- 0
			return
		}

		updateStatus(chatID, msgID, "🚀 *Step 3:* Analyzing payload...")

		_, info, detectLabel, _ := classifyWithProbes(host, ip, finalPort)

		// Reclassify dari stage 1
		labelUpper := strings.ToUpper(detectLabel)
		isH3 := strings.Contains(labelUpper, "H3") || strings.Contains(labelUpper, "QUIC") || strings.Contains(strings.ToUpper(info.ALPN), "H3")

		cnClean := strings.ToLower(strings.ReplaceAll(info.CommonName, "*.", ""))
		hostClean := strings.ToLower(host)
		isSpoof := info.CommonName != "" && !strings.Contains(hostClean, cnClean) && !strings.Contains(cnClean, hostClean) && info.HTTPStatus != "" && info.HTTPStatus != "000"

		if isH3 && udpQUICOpen {
			detectLabel = "H3_QUIC"
		} else if isSpoof {
			detectLabel = "SPOOF"
		} else if strings.Contains(labelUpper, "WS") || strings.Contains(info.HTTPStatus, "101") {
			detectLabel = "WS"
		} else if strings.Contains(labelUpper, "REALITY") {
			detectLabel = "REALITY"
		}

		priority, qualityScore := calculateScore(detectLabel, info)

		// =============================================
		// DEEP VERIFY DENGAN FULL DATA UPDATE
		// =============================================
		deepVerifyResult := ""

		if priority == "STRONG" {
			updateStatus(chatID, msgID, "🔬 *Step 4:* Deep verifying connection...")

			verified := deepVerify(host, ip, finalPort, detectLabel, info)

			if verified.IsWorking && verified.QualityScore >= 50 {

				// Update detectLabel based on deep verify result
				vu := strings.ToUpper(verified.VerifiedBug)
				switch {
				case strings.Contains(vu, "WEBSOCKET"):
					detectLabel = "WS"
				case strings.Contains(vu, "HTTP/3") || strings.Contains(vu, "QUIC"):
					detectLabel = "H3_QUIC"
				case strings.Contains(vu, "SNI SPOOF"):
					detectLabel = "SPOOF"
				case strings.Contains(vu, "AZURE"):
					detectLabel = "AZURE_BNI"
				case strings.Contains(vu, "CDN FRONTING"):
					detectLabel = "CDN_FRONT"
				case strings.Contains(vu, "REALITY"):
					detectLabel = "REALITY"
				}

				// Update info dengan data dari deep verify
				if verified.WorkingHeader != nil {
					if sni, ok := verified.WorkingHeader["SNI"]; ok && sni != "" {
						info.CommonName = sni
					}
					if hostHeader, ok := verified.WorkingHeader["Host"]; ok && hostHeader != "" {
						info.Server = "VERIFIED-" + info.Server
					}
				}

				// Recalculate score dengan weight
				qualityScore = (qualityScore + verified.QualityScore) / 2
				if qualityScore > 100 {
					qualityScore = 100
				}

				deepVerifyResult = fmt.Sprintf("✅ Deep Verify : %s (%d/100)", verified.VerifiedBug, verified.QualityScore)
				priority = "STRONG"

			} else {
				// Failed deep verify - downgrade ke WEAK
				errorMsg := verified.ErrorMessage
				if errorMsg == "" {
					errorMsg = "No valid response"
				}

				deepVerifyResult = fmt.Sprintf("❌ Deep Verify : FAILED (%s)", errorMsg)
				priority = "WEAK"
				qualityScore = qualityScore / 4
				if qualityScore < 10 {
					qualityScore = 10
				}
			}
		}

		// isVulnerable hanya TRUE kalau STRONG lepas deep verify
		isVulnerable := (priority == "STRONG")

		res := formatScanResultMarkdownV2(host, ip, finalPort, info, detectLabel, qualityScore, isVulnerable, deepVerifyResult)

		resultCache.Set(cacheKey, res, 5*time.Minute)
		resultChan <- res
		resultPriority <- priority
		resultScore <- qualityScore
	}()

	select {
	case resultText := <-resultChan:
		finalPriority := <-resultPriority
		finalScore := <-resultScore

		// =============================================
		// DYNAMIC KEYBOARD — SHOW PAYLOAD TEST BUTTON
		// IF SCORE >= 80 & PRIORITY = STRONG
		// =============================================
		var replyMarkup *tgbotapi.InlineKeyboardMarkup

		if finalPriority == "STRONG" && finalScore >= 80 {
			payloadTarget := host
			if specifiedPort != 0 {
				payloadTarget = fmt.Sprintf("%s:%d", host, specifiedPort)
			}

			keyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData(
						"💉 Test Payloads Here",
						fmt.Sprintf("payload_scan:%s", payloadTarget),
					),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("🏠 Main Menu", "menu_main"),
				),
			)
			replyMarkup = &keyboard

			// Save target to session for payload test
			session := getSession(chatID)
			session.TempData["payload_target"] = target
		} else {
			replyMarkup = getMainMenuKeyboard()
		}

		edit := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = replyMarkup
		bot.Send(edit)

	case <-ctx.Done():
		updateStatus(chatID, msgID, "❌ *Scan Timeout*")
	}
	clearSessionState(chatID)
}

// =============================================
// FORMAT FUNCTION WITH DEEP VERIFY SUPPORT
// =============================================
func formatScanResultMarkdownV2(host string, ip string, port int, info tlsInfo, detectType string, qualityScore int, isVulnerable bool, deepVerifyResult string) string {
	var sb strings.Builder

	sb.WriteString("```\n")
	sb.WriteString("╭─────────────────────────╮\n")
	sb.WriteString("│  🎯 PARAGON SINGLE SCAN COMPLETE    │\n")
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

	// Better status classification
	var statusIcon, statusLabel string
	switch detectType {
	case "H3_QUIC":
		statusIcon = "⚡"
		statusLabel = "H3/QUIC BUG"
	case "SPOOF":
		statusIcon = "🎭"
		statusLabel = "SNI SPOOFABLE"
	case "WS":
		statusIcon = "🔌"
		statusLabel = "WEBSOCKET OPEN"
	case "REALITY":
		statusIcon = "🔮"
		statusLabel = "REALITY TUNNEL"
	case "AZURE_BNI":
		statusIcon = "💎"
		statusLabel = "AZURE BNI BUG"
	case "CDN_FRONT":
		statusIcon = "☁️"
		statusLabel = "CDN FRONTING"
	case "BUGHOST CONFIRMED", "CDN_HOST":
		statusIcon = "⚠️"
		statusLabel = "CDN BUGHOST"
	case "CDN_ONLY":
		statusIcon = "📡"
		statusLabel = "CDN DETECTED"
	case "HTTP_ONLY":
		statusIcon = "🌐"
		statusLabel = "HTTP ONLY"
	case "PREMIUM_SNI":
		statusIcon = "💎"
		statusLabel = "PREMIUM SNI"
	default:
		if isVulnerable {
			statusIcon = "🔥"
			statusLabel = "VULNERABLE"
		} else {
			statusIcon = "❌"
			statusLabel = "NOT VULNERABLE"
		}
	}

	sb.WriteString(fmt.Sprintf("Type     : %s %s\n", statusIcon, statusLabel))
	sb.WriteString(fmt.Sprintf("Category : %s\n", detectType))

	if info.CommonName != "" && info.CommonName != host {
		sb.WriteString(fmt.Sprintf("SNI      : %s\n", info.CommonName))
	}

	// Score bar
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

	// Deep verify result - integrated into block
	if deepVerifyResult != "" {
		sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString(deepVerifyResult)
	}

	sb.WriteString("\n```")

	return sb.String()
}

func executeSubdomainScan(chatID int64, domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🔍 *Scanning Subdomains:* `%s`\n━━━━━━━━━━━━━━━━━━━━\n📡 Initializing...", domain))
	msg.ParseMode = "Markdown"
	sentMsg, _ := bot.Send(msg)

	progressChan := make(chan string, 20)
	var finalSubs []string
	done := make(chan bool)

	go func() {
		finalSubs, _ = subdomainEnum(domain, progressChan)
		done <- true
	}()

	func() {
		for {
			select {
			case status, ok := <-progressChan:
				if ok {
					text := fmt.Sprintf("🔎 *Subdomain Enumeration*\n━━━━━━━━━━━━━━━━━━━━\n\nTarget: `%s`\n\n%s", domain, status)
					edit := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, text)
					edit.ParseMode = "Markdown"
					bot.Send(edit)
					time.Sleep(350 * time.Millisecond)
				}
			case <-done:
				return
			}
		}
	}()

	// Guna function formatting baru
	resultText := formatSubdomainResultMarkdown(domain, finalSubs)

	editFinal := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, resultText)
	editFinal.ParseMode = "Markdown"
	bot.Send(editFinal)

	if len(finalSubs) > 0 {
		fileName := fmt.Sprintf("subdomains_%s.txt", strings.ReplaceAll(domain, ".", "_"))
		content := strings.Join(finalSubs, "\n")

		err := os.WriteFile(fileName, []byte(content), 0644)
		if err == nil {
			doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(fileName))
			doc.Caption = fmt.Sprintf("📄 Full Result for: `%s`", domain)
			bot.Send(doc)
			os.Remove(fileName)
		}
	}
}

func executeReverseLookup(chatID int64, ip string) {
	defer recoverPanic(chatID)
	defer clearSessionState(chatID)

	sendTyping(chatID)

	hosts, err := doReverseIPLookup(ip)

	var resultText strings.Builder
	resultText.WriteString("*🔄 Reverse DNS Lookup*\n")
	resultText.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")
	resultText.WriteString(fmt.Sprintf("*IP:* `%s`\n\n", escapeMarkdownV2(ip)))

	if err != nil || len(hosts) == 0 {
		resultText.WriteString("❌ No PTR records found\n")
	} else {
		resultText.WriteString(fmt.Sprintf("*Found %d hostname(s):*\n", len(hosts)))
		for _, h := range hosts {
			resultText.WriteString(fmt.Sprintf("  • `%s`\n", escapeMarkdownV2(h)))
		}
	}
	resultText.WriteString("\n━━━━━━━━━━━━━━━━━━━━")

	msg := tgbotapi.NewMessage(chatID, resultText.String())
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(msg)
}

func handleCallbackQuery(update tgbotapi.Update) {
	callback := update.CallbackQuery
	chatID := callback.Message.Chat.ID
	data := callback.Data

	trackUserActivity(update)
	if isBanned(chatID) {
		bot.Send(tgbotapi.NewCallback(callback.ID, "🚫 Access Denied: Banned"))
		return
	}

	if !isSubscribed(chatID) && data != "check_subscription" && !strings.HasPrefix(data, "payload_scan:") {
		bot.Send(tgbotapi.NewCallback(callback.ID, "⚠️ Subscription Required!"))

		msg := tgbotapi.NewMessage(chatID, "🚫 *ACCESS RESTRICTED*\n━━━━━━━━━━━━━━━━━━━━\n\nYou must join our official channel to use this bot.\n\nTarget: @supremebughost\n━━━━━━━━━━━━━━━━━━━━")
		msg.ParseMode = "Markdown"

		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonURL("📢 Join Channel", "https://t.me/supremebughost"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✅ Verify Subscription", "check_subscription"),
			),
		)
		msg.ReplyMarkup = keyboard
		bot.Send(msg)
		return
	}

	fmt.Printf("🔥 Callback received: data=%s from chatID=%d\n", data, chatID)
	if data != "check_subscription" && !strings.HasPrefix(data, "payload_scan:") {
		bot.Send(tgbotapi.NewCallback(callback.ID, ""))
	}

	switch data {
	case "menu_main":
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "*🔥 PARAGON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\n\n*Select an option:*")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)

	case "menu_hwid":
		hwid := getHWID()
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("*🆔 Your Hardware ID*\n━━━━━━━━━━━━━━━━━━━━\n\n`%s`\n\n━━━━━━━━━━━━━━━━━━━━\n\n_Provide this ID for license activation_", hwid))
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)

	case "menu_about":
		about := fmt.Sprintf("ℹ️ PARAGON SNI PRO %s\n━━━━━━━━━━━━━━━━━━━━\nDeveloper: %s\nEngine: Go High-Performance\nFeatures:\n- Multi-protocol (TLS/HTTP/WS)\n- CDN/WAF Bypass Detection\n- Premium SNI Database\n- Subdomain Enumeration\n- CIDR Range Scanning\n━━━━━━━━━━━━━━━━━━━━", version, author)
		msg := tgbotapi.NewMessage(chatID, about)
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)

	case "menu_single":
		setSessionState(chatID, "awaiting_single_target")
		msg := tgbotapi.NewMessage(chatID, "*🔍 Single Target Scan*\n━━━━━━━━━━━━━━━━━━━━\n\nSend target now:\n• `facebook.com`\n• `1.1.1.1:443`")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_sub":
		setSessionState(chatID, "awaiting_subdomain_target")
		msg := tgbotapi.NewMessage(chatID, "*🔎 Subdomain Enumeration*\n━━━━━━━━━━━━━━━━━━━━\n\nSend domain: `example.com`")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_reverse":
		setSessionState(chatID, "awaiting_reverse_target")
		msg := tgbotapi.NewMessage(chatID, "*🔄 Reverse DNS Lookup*\n━━━━━━━━━━━━━━━━━━━━\n\nSend IP: `8.8.8.8`")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_mass":
		clearSessionState(chatID)
		setSessionState(chatID, "awaiting_mass_file")
		bot.Send(tgbotapi.NewCallback(callback.ID, "📊 Ready for Mass Scan"))

		msg := tgbotapi.NewMessage(chatID,
			"📊 *MASS SCAN ENGINE*\n"+
				"━━━━━━━━━━━━━━━━━━━━\n\n"+
				"Please upload a `.txt` file containing your targets.\n\n"+
				"*File Requirements:*\n"+
				"• Maximum: 500 lines per file\n"+
				"• Format: `example.com` or `IP:Port` per line\n\n"+
				"━━━━━━━━━━━━━━━━━━━━\n"+
				"_Engine status: Ready to receive file..._")
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)
		return

	case "menu_cidr":
		setSessionState(chatID, "awaiting_cidr_input")
		msg := tgbotapi.NewMessage(chatID, "*🌐 CIDR SCAN*\n━━━━━━━━━━━━━━━━━━━━\n\nSend CIDR: `57.144.120.0/24`")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_extract":
		setSessionState(chatID, "awaiting_extract_text")
		msg := tgbotapi.NewMessage(chatID, "*📝 EXTRACT DOMAINS*\n━━━━━━━━━━━━━━━━━━━━\n\nSend any text with domains")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_payload":
		setSessionState(chatID, "awaiting_payload_host")
		msg := tgbotapi.NewMessage(chatID, "*💉 Payload Injection Tester*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
			"📝 *Input Format:*\n"+
			"`host` — Basic test\n"+
			"`host vps` — With VPS\n"+
			"`host vps sni` — Full custom\n\n"+
			"📋 *Examples:*\n"+
			"`airasia.com`\n"+
			"`airasia.com myvps.com`\n"+
			"`airasia.com myvps.com facebook.com`\n"+
			"`applynow.hdfc.bank.in:80`\n\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"_Send host to begin..._")
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

	case "menu_config":
		showConfigValidatorMenu(chatID, callback.Message.MessageID)
		return

	case "cfg_quick":
		showQuickTestPrompt(chatID, callback.Message.MessageID)
		return

	case "cfg_payload_pick":
		showPayloadPicker(chatID, callback.Message.MessageID)
		return

	case "mass_ports_default":
		session := getSession(chatID)
		hosts, ok := session.TempData["mass_hosts"].([]string)
		if !ok {
			msg := tgbotapi.NewMessage(chatID, "❌ Session expired. Start over.")
			msg.ReplyMarkup = getMainMenuOnlyKeyboard()
			bot.Send(msg)
			return
		}
		statusMsg := tgbotapi.NewMessage(chatID, "🚀 *Initializing Turbo Mass Scan...*")
		statusMsg.ParseMode = "Markdown"
		sentMsg, err := bot.Send(statusMsg)
		if err != nil {
			return
		}
		go executeMassScan(chatID, sentMsg.MessageID, hosts, []int{443, 80, 8080})
		clearSessionState(chatID)

		// Step by Step
	case "cfg_step":
		startStepByStep(chatID, callback.Message.MessageID)
		return

	case "cfg_step_pick_payload":
		showPayloadPickerForStep(chatID, callback.Message.MessageID)
		return

	case "cfg_step_custom_payload":
		promptStepCustomPayload(chatID, callback.Message.MessageID)
		return

	case "cfg_step_skip_payload":
		session := getSession(chatID)
		config, _ := session.TempData["step_config"].(UserConfig)
		config.Payload = ""
		session.TempData["step_config"] = config
		session.TempData["step_current"] = 4
		showStepPrompt(chatID, callback.Message.MessageID, 4, config)
		return

	// From Scan Result
	case "cfg_scan":
		startFromScanResult(chatID, callback.Message.MessageID)
		return

	case "cfg_scan_pick_payload":
		showPayloadPickerForScan(chatID, callback.Message.MessageID)
		return

	case "cfg_scan_custom_payload":
		promptScanCustomPayload(chatID, callback.Message.MessageID)
		return

	case "cfg_scan_skip_payload":
		runScanValidation(chatID)
		return

	case "cidr_ports_default":
		session := getSession(chatID)
		cidr, ok := session.TempData["cidr"].(string)
		if !ok {
			msg := tgbotapi.NewMessage(chatID, "❌ Session expired.")
			msg.ReplyMarkup = getMainMenuOnlyKeyboard()
			bot.Send(msg)
			return
		}
		_, ipnet, _ := net.ParseCIDR(cidr)
		statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🚀 *CIDR Scan Started*\n🎯 Target: `%s`\n🔍 Ports: 443, 80", cidr))
		statusMsg.ParseMode = "Markdown"
		sentMsg, err := bot.Send(statusMsg)
		if err != nil {
			return
		}
		go executeCIDRScan(chatID, sentMsg.MessageID, cidr, ipnet, []int{443, 80})
		clearSessionState(chatID)

	case "menu_cancel":
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "❌ Cancelled. Returning to menu.")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)

	case "check_subscription":
		if isSubscribed(chatID) {
			bot.Send(tgbotapi.NewDeleteMessage(chatID, callback.Message.MessageID))
			bot.Send(tgbotapi.NewCallback(callback.ID, "✅ Verified! Welcome back."))

			msg := tgbotapi.NewMessage(chatID, "*🔥 PARAGON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\n\n*Select an option:*")
			msg.ParseMode = "MarkdownV2"
			msg.ReplyMarkup = getMainMenuKeyboard()
			bot.Send(msg)
		} else {
			bot.Send(tgbotapi.NewCallback(callback.ID, "❌ Verification Failed: Join @supremebughost first!"))
		}

	default:
		// =============================================
		// AUTO PAYLOAD TEST FROM SCAN RESULT
		// =============================================
		if strings.HasPrefix(data, "payload_scan:") {
			target := strings.TrimPrefix(data, "payload_scan:")
			bot.Send(tgbotapi.NewCallback(callback.ID, "💉 Starting payload test..."))

			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("💉 *Auto-Testing:* `%s`\n━━━━━━━━━━━━━━━━━━━━\n⏳ Starting...", target))
			msg.ParseMode = "Markdown"
			bot.Send(msg)

			go executePayloadTest(chatID, target)
			return
		}

		msg := tgbotapi.NewMessage(chatID, "Unknown option. Please use /start")
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
	}
}

func handleMessage(update tgbotapi.Update) {
	if update.Message == nil {
		return
	}

	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)
	session := getSession(chatID)

	trackUserActivity(update)

	// 1. Safety & Subscription
	if isBanned(chatID) {
		return
	}
	if !isSubscribed(chatID) {
		msg := tgbotapi.NewMessage(chatID, "🚫 *ACCESS DENIED*\n━━━━━━━━━━━━━━━━━━━━\nPlease join our official channel to use the scanner.\n\nTarget: @supremebughost")
		msg.ParseMode = "Markdown"
		bot.Send(msg)
		return
	}

	// 2. Filter input
	if text == "" && update.Message.Document == nil {
		return
	}
	if strings.HasPrefix(text, "/") {
		return
	}

	// 3. State Handler
	switch session.State {

	case "awaiting_mass_file":
		if update.Message.Document != nil {
			handleMassScanFile(update)
			return
		}

	case "awaiting_mass_ports":
		if text == "" {
			return
		}

		var ports []int
		inputPorts := strings.Fields(strings.ReplaceAll(text, ",", " "))
		for _, p := range inputPorts {
			val, err := strconv.Atoi(p)
			if err == nil && val > 0 && val <= 65535 {
				ports = append(ports, val)
			}
		}

		if len(ports) == 0 {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Invalid port!*\nEnter valid port numbers (1-65535).\nExample: `443, 80, 8080`"))
			return
		}

		var hosts []string
		if data, ok := session.TempData["mass_hosts"]; ok {
			hosts, _ = data.([]string)
		} else if data, ok := session.TempData["hosts"]; ok {
			hosts, _ = data.([]string)
		}

		if len(hosts) == 0 {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ *Session Expired!*\nPlease upload your `.txt` file again."))
			clearSessionState(chatID)
			return
		}

		clearSessionState(chatID)
		statusMsg, _ := bot.Send(tgbotapi.NewMessage(chatID, "🚀 *Initializing Mass Engine...*"))
		go executeMassScan(chatID, statusMsg.MessageID, hosts, ports)
		return

	case "awaiting_single_target":
		clearSessionState(chatID)
		go executeSingleScan(chatID, text)
		return

	case "awaiting_cidr_input":
		handleCIDRInput(update)
		return

	case "awaiting_subdomain_target":
		clearSessionState(chatID)
		go executeSubdomainScan(chatID, text)
		return

	case "awaiting_extract_text":
		handleExtractDomains(update)
		return

	case "awaiting_reverse_target":
		clearSessionState(chatID)
		go executeReverseLookup(chatID, text)
		return

	case "awaiting_payload_host":
		clearSessionState(chatID)
		go executePayloadTest(chatID, text)
		return

	// =============================================
	// CONFIG VALIDATOR MESSAGE HANDLERS
	// =============================================
	case "config_quick_input":
		clearSessionState(chatID)
		go executeConfigValidation(chatID, text)
		return

	case "config_payload_select":
		idx, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil && idx >= 1 && idx <= len(payloadList) {
			selectedPayload := payloadList[idx-1].Template
			session.TempData["selected_payload"] = selectedPayload

			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Selected: *%s*\n\nNow send your config:\nFormat: `proxy:port|sni|-|target`\n\nThe payload will be auto-inserted.", payloadList[idx-1].Name))
			msg.ParseMode = "Markdown"
			msg.ReplyMarkup = getCancelKeyboard()
			bot.Send(msg)

			setSessionState(chatID, "config_quick_input")
		} else {
			msg := tgbotapi.NewMessage(chatID, "❌ Invalid number. Pick 1-28.")
			bot.Send(msg)
		}
		return

	case "config_step_proxy":
		handleStepInput(chatID, 0, text)
		return

	case "config_step_sni":
		handleStepInput(chatID, 0, text)
		return

	case "config_step_target":
		handleStepInput(chatID, 0, text)
		return

	case "config_step_payload_select":
		idx, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil && idx >= 1 && idx <= len(payloadList) {
			session := getSession(chatID)
			config, _ := session.TempData["step_config"].(UserConfig)
			config.Payload = payloadList[idx-1].Template
			session.TempData["step_config"] = config
			session.TempData["step_current"] = 4

			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Selected: *%s*", payloadList[idx-1].Name))
			msg.ParseMode = "Markdown"
			bot.Send(msg)

			sentMsg, _ := bot.Send(tgbotapi.NewMessage(chatID, "⏳ Loading next step..."))
			showStepPrompt(chatID, sentMsg.MessageID, 4, config)
		} else {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ Invalid number. Pick 1-28."))
		}
		return

	case "config_step_payload_custom":
		session := getSession(chatID)
		config, _ := session.TempData["step_config"].(UserConfig)
		config.Payload = text
		session.TempData["step_config"] = config
		session.TempData["step_current"] = 4

		msg := tgbotapi.NewMessage(chatID, "✅ Custom payload saved!")
		bot.Send(msg)

		sentMsg, _ := bot.Send(tgbotapi.NewMessage(chatID, "⏳ Loading next step..."))
		showStepPrompt(chatID, sentMsg.MessageID, 4, config)
		return

	case "config_scan_payload_select":
		idx, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil && idx >= 1 && idx <= len(payloadList) {
			session := getSession(chatID)
			config, _ := session.TempData["scan_config"].(UserConfig)
			config.Payload = payloadList[idx-1].Template
			session.TempData["scan_config"] = config

			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Selected: *%s*\n⏳ Running validation...", payloadList[idx-1].Name))
			msg.ParseMode = "Markdown"
			bot.Send(msg)

			runScanValidation(chatID)
		} else {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ Invalid number. Pick 1-28."))
		}
		return

	case "config_scan_payload_custom":
		session := getSession(chatID)
		config, _ := session.TempData["scan_config"].(UserConfig)
		config.Payload = text
		session.TempData["scan_config"] = config

		msg := tgbotapi.NewMessage(chatID, "✅ Custom payload saved!\n⏳ Running validation...")
		bot.Send(msg)

		runScanValidation(chatID)
		return
	}

	if text != "" && strings.Contains(text, ".") && !strings.Contains(text, " ") {
		if strings.Contains(text, "/") {
			setSessionState(chatID, "awaiting_cidr_input")
			handleCIDRInput(update)
			return
		}
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "🚀 *Direct Scan Detected*")
		bot.Send(msg)
		go executeSingleScan(chatID, text)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "*🔥 PARAGON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\nSelect an option below to begin:")
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = getMainMenuKeyboard()
	bot.Send(msg)
}

func handleBanCommand(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	if chatID != adminChatID {
		return
	}

	args := strings.Fields(update.Message.Text)
	if len(args) < 2 {
		bot.Send(tgbotapi.NewMessage(chatID, "Usage: /ban <user_id>"))
		return
	}
	targetID, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ Invalid ID"))
		return
	}
	banUser(targetID)
	bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("🚫 Banned: %d", targetID)))
}

func handleUnbanCommand(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	if chatID != adminChatID {
		return
	}

	args := strings.Fields(update.Message.Text)
	if len(args) < 2 {
		bot.Send(tgbotapi.NewMessage(chatID, "Usage: /unban <user_id>"))
		return
	}
	targetID, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		bot.Send(tgbotapi.NewMessage(chatID, "❌ Invalid ID"))
		return
	}
	unbanUser(targetID)
	bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Unbanned: %d", targetID)))
}

func handleUsersCommand(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	if chatID != adminChatID {
		return
	}

	umMutex.RLock()
	totalUsers := len(userData.Users)
	totalScans := 0
	bannedCount := 0
	for _, u := range userData.Users {
		totalScans += u.Scans
		if u.Banned {
			bannedCount++
		}
	}
	umMutex.RUnlock()

	msg := fmt.Sprintf("📊 *Bot Stats*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
		"👥 Users: %d\n"+
		"🔍 Scans: %d\n"+
		"🚫 Banned: %d", totalUsers, totalScans, bannedCount)
	bot.Send(tgbotapi.NewMessage(chatID, msg))
}

func handleUserListCommand(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	if chatID != adminChatID {
		return
	}

	umMutex.RLock()
	defer umMutex.RUnlock()

	type userEntry struct {
		ID   int64
		Info *UserInfo
	}
	var users []userEntry
	for id, u := range userData.Users {
		users = append(users, userEntry{ID: id, Info: u})
	}

	sort.Slice(users, func(i, j int) bool {
		if users[i].Info.Banned != users[j].Info.Banned {
			return !users[i].Info.Banned
		}
		return users[i].Info.Scans > users[j].Info.Scans
	})

	var sb strings.Builder
	sb.WriteString("*📋 User List*\n━━━━━━━━━━━━━━━━━━━━\n\n")

	limit := 50
	if len(users) < limit {
		limit = len(users)
	}

	for i := 0; i < limit; i++ {
		u := users[i]
		status := "✅"
		if u.Info.Banned {
			status = "🚫"
		}
		name := u.Info.FirstName
		if u.Info.Username != "" {
			name = "@" + u.Info.Username
		}
		sb.WriteString(fmt.Sprintf("%s %s | `%d` | %d scans\n",
			status, name, u.ID, u.Info.Scans))
	}

	if len(users) > 50 {
		sb.WriteString(fmt.Sprintf("\n_...and %d more_", len(users)-50))
	}

	bot.Send(tgbotapi.NewMessage(chatID, sb.String()))
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	loadUserData()

	// License bypass
	if !SupremeVerify() {
		fmt.Println("License verification failed. Exiting.")
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	botToken := os.Getenv("BOT_TOKEN")
	if botToken == "" {
		fmt.Println("❌ ERROR: BOT_TOKEN environment variable not set")
		os.Exit(1)
	}
	fmt.Printf("✅ Bot token loaded from environment\n")

	var err error
	bot, err = tgbotapi.NewBotAPI(botToken)
	if err != nil {
		fmt.Printf("❌ Failed to initialize bot: %v\n", err)
		os.Exit(1)
	}

	bot.Debug = false
	fmt.Printf("✅ Bot authorized as: @%s\n", bot.Self.UserName)

	commands := []tgbotapi.BotCommand{
		{Command: "start", Description: "🚀 Main Menu"},
		{Command: "scan", Description: "🔍 Single Scan"},
		{Command: "ban", Description: "🚫 Ban user"},
		{Command: "unban", Description: "✅ Unban user"},
		{Command: "users", Description: "📊 Bot stats"},
		{Command: "userlist", Description: "📋 User list"},
	}
	bot.Request(tgbotapi.NewSetMyCommands(commands...))

	fmt.Printf("📡 Bot is now polling for updates...\n")
	fmt.Printf("🌐 Railway deployment - Ready to scan!\n")

	go func() {
		time.Sleep(2 * time.Second)
		req, _ := http.NewRequest("GET", "https://api.telegram.org/bot"+botToken+"/deleteWebhook?drop_pending_updates=true", nil)
		client := &http.Client{Timeout: 5 * time.Second}
		client.Do(req)
		fmt.Println("✅ Webhook cleared")
	}()

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		})
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		fmt.Printf("💓 Health check server started on port %s\n", port)
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			fmt.Printf("❌ Health check server error: %v\n", err)
		}
	}()

	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 60

	updates := bot.GetUpdatesChan(updateConfig)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n🛑 Shutting down bot...")
		bot.StopReceivingUpdates()
		os.Exit(0)
	}()

	go func() {
		for {
			time.Sleep(30 * time.Minute)
			sessionMutex.Lock()
			for chatID, session := range userSessions {
				if time.Since(session.LastActivity) > 1*time.Hour {
					delete(userSessions, chatID)
				}
			}
			sessionMutex.Unlock()
		}
	}()

	for update := range updates {
		if update.CallbackQuery != nil {
			handleCallbackQuery(update)
			continue
		}

		if update.Message != nil {
			if update.Message.IsCommand() {
				if update.Message.Command() != "start" && !isSubscribed(update.Message.Chat.ID) {
					if update.Message.Chat.ID != adminChatID {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Subscribe to @supremebughost first! Use /start")
						bot.Send(msg)
						continue
					}
				}

				switch update.Message.Command() {
				case "start":
					handleStart(update)
				case "id":
					handleHWID(update)
				case "about":
					handleAbout(update)
				case "ban":
					handleBanCommand(update)
				case "unban":
					handleUnbanCommand(update)
				case "users", "stats":
					handleUsersCommand(update)
				case "userlist":
					handleUserListCommand(update)
				case "cancel":
					clearSessionState(update.Message.Chat.ID)
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Cancelled. Back to menu.")
					msg.ReplyMarkup = getMainMenuKeyboard()
					bot.Send(msg)
				case "scan", "single":
					args := strings.SplitN(update.Message.Text, " ", 2)
					if len(args) < 2 {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Usage: /scan <target>\nExample: /scan facebook.com")
						bot.Send(msg)
					} else {
						bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("🔍 Scanning: %s", args[1])))
						go executeSingleScan(update.Message.Chat.ID, args[1])
					}
				default:
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unknown command. Use /start, /scan <target>, or /cancel")
					bot.Send(msg)
				}
				continue
			}
			handleMessage(update)
		}
	}
}

func updateStatus(chatID int64, messageID int, text string) {
	editMsg := tgbotapi.NewEditMessageText(chatID, messageID, text)
	editMsg.ParseMode = "Markdown"
	_, err := bot.Send(editMsg)
	if err != nil {
		// Ignore "message is not modified" errors - they're harmless
		if strings.Contains(err.Error(), "not modified") {
			return
		}
		// Only log real errors
		log.Printf("Update Error: %v", err)
	}
}
