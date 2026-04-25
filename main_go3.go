package main

import (
	"bufio"
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

var proxyURL = "https://corsproxy.io/?"

// ==================== USER MANAGEMENT ====================
var (
	adminChatID  int64 = 107410007
	userData           = &UserData{Users: make(map[int64]*UserInfo)}
	umMutex      sync.RWMutex
	userDataFile       = "/tmp/user_data.json"
)

// ==================== LOGGING INIT ====================

func initLogger() {
	// ============================================================
	// RAILWAY: Log to stdout (captured automatically)
	// + Optional file backup in /tmp
	// ============================================================
	
	// Create log directory in /tmp (Railway writable)
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
	config := tgbotapi.GetChatMemberConfig{
		SuperGroupUsername: "@supremebughost",
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			UserID: chatID,
		},
	}
	member, err := bot.GetChatMember(config)
	if err != nil {
		return false
	}
	if member.Status == "member" || member.Status == "creator" || member.Status == "administrator" {
		return true
	}
	return false
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
	if chatID == 0 { return }
	
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

// ==================== [PATCHED] STORAGE PATH ====================
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

// ==================== [PATCHED] GLOBAL CONFIGURATION ====================
var (
	timeout        = 8 * time.Second
	maxConcurrency = 10
	vpsTunnelHost  = ""
	version        = "v3.7"
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
	AdminID     int64              `json:"admin_id"`
	Users       map[int64]*UserInfo `json:"users"`
	LastUpdated time.Time          `json:"last_updated"`
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
	fmt.Printf("🚀 TYPHOON SNI PRO %s - Starting...\n", version)
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
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: Mozilla/5.0\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		return false, ""
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false, ""
	}
	rawResp := string(buf[:n])
	txt := strings.ToLower(rawResp)
	if strings.Contains(txt, "101") && strings.Contains(txt, "switching protocols") {
		return true, rawResp
	}
	return false, rawResp
}

func doTLS(host, ip string, port int) (string, tlsInfo) {
	start := time.Now()
	info := tlsInfo{}
	info.IP = ip
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := getCustomDialer()
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"http/1.1"},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		conf.NextProtos = nil
		conn, err = tls.DialWithDialer(dialer, "tcp", address, conf)
		if err != nil {
			info.TLSStatus = "✗ Handshake FAIL"
			info.LatencyMs = int(time.Since(start).Milliseconds())
			return "FAIL", info
		}
	}
	defer conn.Close()
	info.TLSStatus = "✓ Handshake OK"
	state := conn.ConnectionState()
	info.Cipher = fmt.Sprintf("0x%04x", state.CipherSuite)
	info.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CommonName = cert.Subject.CommonName
	}
	payload := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
		"Accept: */*\r\n"+
		"Connection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = conn.Write([]byte(payload))
	var fullResponse []byte
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			fullResponse = append(fullResponse, buffer[:n]...)
		}
		if err != nil || len(fullResponse) > 25000 {
			break
		}
	}
	respStr := string(fullResponse)
	if len(respStr) > 12 {
		info.HTTPStatus = respStr[9:12]
	}
	parts := strings.SplitN(respStr, "\r\n\r\n", 2)
	if len(parts) > 1 {
		body := parts[1]
		info.ContentLength = len(body)
		if len(body) > 700 {
			info.BodySnippet = body[:700]
		} else {
			info.BodySnippet = body
		}
	}
	info.Leak = leakScore(fullResponse)
	info.Server = detectServer(fullResponse)
	info.TLSraw = respStr
	info.LatencyMs = int(time.Since(start).Milliseconds())
	return "OK", info
}

func doHTTP(host, ip string, port int) (string, tlsInfo) {
	start := time.Now()
	info := tlsInfo{}
	info.IP = ip
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		info.HTTPStatus = "✗ Connection FAIL"
		info.LatencyMs = int(time.Since(start).Milliseconds())
		return "FAIL", info
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
		"Accept: */*\r\n"+
		"Connection: close\r\n\r\n", host)
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = conn.Write([]byte(req))
	var full []byte
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			full = append(full, buffer[:n]...)
		}
		if err != nil || len(full) > 25000 {
			break
		}
	}
	respStr := string(full)
	if len(respStr) > 0 {
		statusLines := strings.SplitN(respStr, "\r\n", 2)
		parts := strings.Split(statusLines[0], " ")
		if len(parts) >= 2 {
			info.HTTPStatus = parts[1]
		}
	}
	parts := strings.SplitN(respStr, "\r\n\r\n", 2)
	if len(parts) > 1 {
		body := parts[1]
		info.ContentLength = len(body)
		if len(body) > 700 {
			info.BodySnippet = body[:700]
		} else {
			info.BodySnippet = body
		}
	}
	info.Leak = leakScore(full)
	info.Server = detectServer(full)
	info.TLSraw = respStr
	info.LatencyMs = int(time.Since(start).Milliseconds())
	if info.HTTPStatus == "" {
		info.HTTPStatus = "000"
	}
	return "OK", info
}

// =============================================================================
// CLASSIFICATION & DEEP VERIFICATION (100% UNCHANGED LOGIC)
// =============================================================================

func classifyWithProbes(host string, ip string, port int) (string, tlsInfo, string, string) {
	var info tlsInfo
	wsResultStr := ""
	tlsResultStr := ""

	logToDisk := func(label string, extra tlsInfo) {
		f, err := os.OpenFile("scanner_debug.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		timestamp := time.Now().Format("15:04:05")
		logEntry := fmt.Sprintf("[%s] %s:%d | %s | Status:%s | Len:%d | Server:%s\n",
			timestamp, host, port, label, extra.HTTPStatus, extra.ContentLength, extra.Server)
		_, _ = f.WriteString(logEntry)
	}

	hostClean := strings.ToLower(strings.TrimSpace(host))

	// ==================== TIER 1: FAST PATH ====================
	knownBigTech := []string{
		"google.com", "youtube.com", "gmail.com", "microsoft.com", "live.com", "bing.com", "office.com", "azure.com",
		"apple.com", "icloud.com",
		"amazon.com", "aws.amazon.com", "x.com", "linkedin.com",
		"yahoo.com", "ebay.com", "paypal.com",
	}

	for _, domain := range knownBigTech {
		if strings.Contains(hostClean, domain) {
			for sni := range premiumSNI {
				if strings.Contains(hostClean, sni) {
					goto notFastPath
				}
			}
			info.HTTPStatus = "200"
			info.TLSStatus = "✓ OK (Fast Path)"
			info.Server = "Big Tech Native"
			logToDisk("FAST_PATH_BIG_TECH", info)
			return "WEAK", info, "NATIVE CDN", "FAST PATH"
		}
	}
notFastPath:

	// ==================== TIER 2: PREMIUM SNI ====================
	isPremium := false
	for sni := range premiumSNI {
		if strings.Contains(hostClean, sni) {
			isPremium = true
			break
		}
	}

	if isPremium {
		tlsStatus, tlsInfoLocal := doTLS(host, ip, port)
		info = tlsInfoLocal
		tlsResultStr = tlsStatus
		if tlsStatus == "OK" && strings.Contains(info.TLSStatus, "✓") {
			logToDisk("PREMIUM_SNI_TLS_OK", info)
			return "STRONG", info, "PREMIUM_SNI", tlsResultStr
		}
		logToDisk("PREMIUM_SNI_TLS_FAIL", info)
		return "WEAK", info, "PREMIUM TLS FAIL", tlsResultStr
	}

	// ==================== TIER 3: FULL PROBE ====================
	wsOK, wsRaw := wsProbe(host, ip, port)
	if wsOK {
		if len(strings.TrimSpace(wsRaw)) < 5 {
			logToDisk("REJECT_EMPTY_WS", info)
			return "WEAK", info, "EMPTY_WS", "NO_TLS"
		}
		info.SSHWS = true
		info.WSraw = wsRaw
		wsResultStr = "101 Switching Protocols"
		_, tlsInfoLocal := doTLS(host, ip, port)
		info.Cipher, info.ALPN, info.Server = tlsInfoLocal.Cipher, tlsInfoLocal.ALPN, tlsInfoLocal.Server
		info.ContentLength, info.BodySnippet = tlsInfoLocal.ContentLength, tlsInfoLocal.BodySnippet
		info.HTTPStatus = "101"
		logToDisk("WS_VULN_FOUND", info)
		return "STRONG", info, wsResultStr, "TLS OK"
	}

	tlsStatus, tlsInfoLocal := doTLS(host, ip, port)
	info = tlsInfoLocal
	tlsResultStr = tlsStatus

	if tlsStatus == "OK" {
		server := strings.ToUpper(info.Server)
		rawHeaders := strings.ToUpper(info.TLSraw)
		snippetUpper := strings.ToUpper(info.BodySnippet)
		alpnUpper := strings.ToUpper(info.ALPN)

		if info.HTTPStatus == "" {
			info.HTTPStatus = "200"
		}

		isH3 := strings.Contains(alpnUpper, "H3") || strings.Contains(rawHeaders, "ALT-SVC")
		isTLS13 := strings.Contains(info.Cipher, "AES_256_GCM") || strings.Contains(info.Cipher, "CHACHA20")
		isRealityTarget := strings.Contains(info.CommonName, "google") ||
			strings.Contains(info.CommonName, "microsoft") ||
			strings.Contains(info.CommonName, "apple") ||
			strings.Contains(info.CommonName, "cloudflare")
		isReality := isTLS13 && isRealityTarget && (info.Server == "" || info.Server == "UNKNOWN")

		if isH3 {
			logToDisk("STRONG_H3_QUIC_FOUND", info)
			return "STRONG", info, "H3 QUIC BUG", tlsResultStr
		}
		if isReality {
			logToDisk("STRONG REALITY FOUND", info)
			return "STRONG", info, "REALITY TUNNEL BUG", tlsResultStr
		}

		isDeadAPI := strings.Contains(snippetUpper, "MISSING AUTHENTICATION TOKEN") ||
			strings.Contains(snippetUpper, "UNAUTHORIZED") ||
			(strings.Contains(snippetUpper, "\"STATUS\":") && strings.Contains(snippetUpper, "FAIL"))
		if isDeadAPI || info.ContentLength <= 10 {
			logToDisk("REJECT TRASH OR EMPTY", info)
			return "WEAK", info, "EMPTY OR API TRASH", tlsResultStr
		}

		isCloudFront := strings.Contains(server, "CLOUDFRONT") || strings.Contains(rawHeaders, "X-AMZ-")
		isCloudflare := strings.Contains(server, "CLOUDFLARE") || strings.Contains(rawHeaders, "CF-RAY")
		isAkamai := strings.Contains(server, "AKAMAI")
		isAzure := strings.Contains(server, "AZURE") || strings.Contains(rawHeaders, "MICROSOFT")
		isIncapsula := strings.Contains(server, "INCAPSULA") || strings.Contains(snippetUpper, "_INCAPSULA") || strings.Contains(rawHeaders, "X-IINFO")
		isPortal := strings.Contains(snippetUpper, "<!DOCTYPE") || strings.Contains(snippetUpper, "<HTML") || strings.Contains(snippetUpper, "301 MOVED") || strings.Contains(snippetUpper, "302 FOUND")

		if isCloudFront || isCloudflare || isAkamai || isAzure || isIncapsula || isPortal {
			isGenericPage := strings.Contains(snippetUpper, "APP SERVICE - ANTARES") ||
				strings.Contains(snippetUpper, "SITE NOT FOUND") ||
				strings.Contains(snippetUpper, "DIRECT IP ACCESS NOT ALLOWED")
			if isGenericPage {
				logToDisk("REJECT CDN GARBAGE", info)
				return "WEAK", info, "GENERIC CDN PAGE", tlsResultStr
			}
			logToDisk("STRONG_HOST_FOUND", info)
			return "STRONG", info, "BUGHOST CONFIRMED", tlsResultStr
		}

		if info.Leak >= 50 {
			logToDisk("STRONG_LEAK", info)
			return "STRONG", info, "NONE", tlsResultStr
		}
		logToDisk("WEAK_TLS_PASSTHROUGH", info)
		return "WEAK", info, "NONE", tlsResultStr
	}

	httpStatus, httpInfo := doHTTP(host, ip, port)
	if httpStatus == "OK" && httpInfo.ContentLength > 10 {
		raw := strings.ToUpper(httpInfo.TLSraw)
		if strings.Contains(raw, "CLOUDFRONT") || strings.Contains(raw, "CF-RAY") || strings.Contains(raw, "AZURE") {
			logToDisk("STRONG_HTTP_CDN", httpInfo)
			return "STRONG", httpInfo, "CDN FRONTING", "NO TLS"
		}
		logToDisk("HTTP_REACHABLE", httpInfo)
		return "WEAK", httpInfo, "NONE", "NO_TLS"
	}
	return "WEAK", info, "NONE", "NO_TLS"
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
// SUBDOMAIN ENUMERATION & UTILITY FUNCTIONS (100% UNCHANGED)
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

// ==================== MASS SCAN HANDLERS ====================

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
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❌ Failed to download file: %v", err))
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	// Save to temp file
	tmpFile := os.TempDir() + "/" + document.FileName
	err = downloadFileToPath(file, tmpFile, bot)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❌ Failed to save file: %v", err))
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	// Parse hosts
	f, err := os.Open(tmpFile)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "❌ Failed to read file.")
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
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
		msg := tgbotapi.NewMessage(chatID, "❌ No valid hosts found in file.")
		msg.ReplyMarkup = getMainMenuOnlyKeyboard()
		bot.Send(msg)
		clearSessionState(chatID)
		return
	}

	// Limit hosts
	if len(hosts) > 500 {
		hosts = hosts[:500]
	}

	// Store in session
	session := getSession(chatID)
	session.TempData["mass_hosts"] = hosts
	session.TempData["mass_file"] = tmpFile
	session.State = "awaiting_mass_ports"

	// Ask for ports
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Use Default (443,80,8080)", "mass_ports_default"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "menu_cancel"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf(
		"📊 *Loaded %d hosts*\n\n"+
			"Enter ports to scan:\n"+
			"• Single: `443`\n"+
			"• Multiple: `443,80,8080`\n"+
			"• Range: `8000-8010`\n\n"+
			"Or use default ports:",
		len(hosts)))
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
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
	defer recoverPanic(chatID)
	startTime := time.Now()
	var mu sync.Mutex

	totalJobs := len(hosts) * len(ports)
	var completedJobs int64
	resultsChan := make(chan []string, 100)
	vulnerableHosts := make(chan map[string]string, 100)
	doneChan := make(chan bool)

	csvFile := filepath.Join(os.TempDir(), fmt.Sprintf("mass_scan_%d.csv", time.Now().Unix()))

	type resolvedHost struct {
		host string
		ip   string
		err  error
	}

	var resolvedList []resolvedHost
	var wgDNS sync.WaitGroup
	dnsSemaphore := make(chan struct{}, 50)

	updateStatus(chatID, statusMsgID, fmt.Sprintf("🔍 *Resolving %d hosts...*", len(hosts)))

	for _, h := range hosts {
		wgDNS.Add(1)
		go func(host string) {
			defer wgDNS.Done()
			dnsSemaphore <- struct{}{}
			defer func() { <-dnsSemaphore }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				resolvedList = append(resolvedList, resolvedHost{host, ips[0], nil})
				mu.Unlock()
			}
		}(h)
	}
	wgDNS.Wait()

	if len(resolvedList) == 0 {
		updateStatus(chatID, statusMsgID, "❌ No hosts could be resolved.\n\nPlease check your domain list.")
		return
	}

	resolvedCount := len(resolvedList)
	totalJobs = resolvedCount * len(ports)

	updateStatus(chatID, statusMsgID, fmt.Sprintf(
		"✅ *Resolved:* %d/%d hosts\n🚀 *Starting mass scan...*",
		resolvedCount, len(hosts)))

	go func() {
		out, err := os.Create(csvFile)
		if err != nil {
			doneChan <- true
			return
		}
		defer out.Close()

		writer := csv.NewWriter(out)
		writer.Write([]string{"Host", "IP", "Port", "Status", "Priority", "LeakScore", "Server", "TLS", "BugType"})

		for res := range resultsChan {
			writer.Write(res)
			writer.Flush()
		}
		doneChan <- true
	}()

	var strongCount, mediumCount, weakCount int
	var status200Count, status403Count, status404Count, status500Count int
	var h3Count int
	var topTargets []map[string]string

	go func() {
		for target := range vulnerableHosts {
			p := target["priority"]
			st := target["status"]
			tag := target["tag"]

			mu.Lock()
			switch st {
			case "200": status200Count++
			case "403": status403Count++
			case "404": status404Count++
			case "500", "502", "503": status500Count++
			}

			switch p {
			case "STRONG":
				strongCount++
				if tag == "H3_QUIC" { h3Count++ }
			case "MEDI": mediumCount++
			default: weakCount++
			}

			if p == "STRONG" || p == "MEDI" {
				topTargets = append(topTargets, target)
			}
			mu.Unlock()
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			comp := atomic.LoadInt64(&completedJobs)
			if comp >= int64(totalJobs) { return }

			mu.Lock()
			current200 := status200Count
			currentFound := strongCount + mediumCount
			mu.Unlock()

			percent := float64(comp) / float64(totalJobs) * 100
			barLen := 16
			filled := int(percent / 100 * float64(barLen))
			if filled > barLen { filled = barLen }
			bar := strings.Repeat("▰", filled) + strings.Repeat("▱", barLen-filled)

			elapsed := time.Since(startTime)
			speed := float64(comp) / elapsed.Seconds()
			remaining := time.Duration(float64(int64(totalJobs)-comp)/speed) * time.Second

			var etaStr string
			if remaining < 60*time.Second {
				etaStr = fmt.Sprintf("%ds", int(remaining.Seconds()))
			} else {
				etaStr = fmt.Sprintf("%dm%ds", int(remaining.Minutes()), int(remaining.Seconds())%60)
			}

			text := fmt.Sprintf(
				"🔄 *Mass Scan In Progress*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
					"%s %.1f%%\n📊 %d/%d jobs\n\n"+
					"✅ 200 OK: %d\n🔥 Found: %d potential\n"+
					"⚡ %.0f/s | ⏳ %s\n⏱ Elapsed: %v",
				bar, percent, comp, totalJobs,
				current200, currentFound,
				speed, etaStr, elapsed.Round(time.Second))

			updateStatus(chatID, statusMsgID, text)
		}
	}()
	defer ticker.Stop()

	var wg sync.WaitGroup
	concurrency := 50
	if totalJobs > 2000 { concurrency = 120 
	} else if totalJobs > 1000 { concurrency = 100 
	} else if totalJobs < 100 { concurrency = 20 }

	semaphore := make(chan struct{}, concurrency)

	for _, res := range resolvedList {
		wg.Add(1)
		go func(rhost resolvedHost) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			for _, port := range ports {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", rhost.ip, port), 1*time.Second)
				if err != nil {
					atomic.AddInt64(&completedJobs, 1)
					continue
				}
				conn.Close()

				var info tlsInfo
				var detectLabel string
				var tlsRaw string

				for retry := 0; retry < 2; retry++ {
					_, info, detectLabel, tlsRaw = classifyWithProbes(rhost.host, rhost.ip, port)
					if info.HTTPStatus != "" && info.HTTPStatus != "000" { break }
					if retry == 0 { time.Sleep(500 * time.Millisecond) }
				}

				labelUpper := strings.ToUpper(detectLabel)
				alpnUpper := strings.ToUpper(info.ALPN)
				tlsrawUpper := strings.ToUpper(info.TLSraw)

				isH3 := strings.Contains(labelUpper, "H3") ||
					strings.Contains(labelUpper, "QUIC") ||
					strings.Contains(alpnUpper, "H3") ||
					strings.Contains(tlsrawUpper, "ALT-SVC") ||
					strings.Contains(tlsrawUpper, "H3")

				tlsOK := strings.Contains(tlsRaw, "TLS OK") ||
					strings.Contains(info.TLSStatus, "✓") ||
					info.Cipher != ""

				cnClean := strings.ToLower(strings.ReplaceAll(info.CommonName, "*.", ""))
				hostClean := strings.ToLower(rhost.host)
				isSpoof := false
				if info.CommonName != "" && tlsOK {
					if cnClean != "" && !strings.Contains(hostClean, cnClean) && !strings.Contains(cnClean, hostClean) {
						isSpoof = true
					}
				}

				bugType := "NONE"
				finalPrio := "WEAK"

				if tlsOK {
					if isH3 {
						bugType = "H3_QUIC"
						finalPrio = "STRONG"
					} else if strings.Contains(info.HTTPStatus, "101") {
						bugType = "WS"
						finalPrio = "STRONG"
					} else if isSpoof && info.HTTPStatus != "" && info.HTTPStatus != "000" && info.ContentLength > 0 {
						bugType = "SPOOF"
						finalPrio = "STRONG"
					} else if strings.Contains(labelUpper, "REALITY") {
						bugType = "REALITY"
						finalPrio = "STRONG"
					} else if info.HTTPStatus == "200" || info.HTTPStatus == "403" || info.HTTPStatus == "404" || info.HTTPStatus == "503" || info.HTTPStatus == "301" || info.HTTPStatus == "302" {
						bugType = "CDN_HOST"
						finalPrio = "MEDI"
					} else {
						bugType = "CDN_ONLY"
						finalPrio = "MEDI"
					}
				} else if info.HTTPStatus != "" && info.HTTPStatus != "000" {
					bugType = "HTTP_ONLY"
					finalPrio = "WEAK"
				}

				resultsChan <- []string{
					rhost.host, rhost.ip, strconv.Itoa(port), info.HTTPStatus,
					finalPrio, strconv.Itoa(info.Leak), info.Server, info.TLSStatus, bugType,
				}

				vulnerableHosts <- map[string]string{
					"host": rhost.host, "port": strconv.Itoa(port),
					"priority": finalPrio, "tag": bugType, "status": info.HTTPStatus,
				}

				atomic.AddInt64(&completedJobs, 1)
			}
		}(res)
	}

	wg.Wait()
	close(resultsChan)
	close(vulnerableHosts)
	<-doneChan

	mu.Lock()
	finalStrong := strongCount
	finalMedium := mediumCount
	finalWeak := weakCount
	finalH3 := h3Count
	final200 := status200Count
	final403 := status403Count
	final404 := status404Count
	final500 := status500Count
	finalTopTargets := make([]map[string]string, len(topTargets))
	copy(finalTopTargets, topTargets)
	mu.Unlock()

	duration := time.Since(startTime).Round(time.Second)
	speed := float64(totalJobs) / duration.Seconds()
	othersCount := totalJobs - (final200 + final403 + final404 + final500)

	var sb strings.Builder
	sb.WriteString("*✅ MASS SCAN COMPLETE*\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString(fmt.Sprintf("📊 *Hosts:* `%d` | *Probes:* `%d`\n", resolvedCount, totalJobs))
	sb.WriteString(fmt.Sprintf("⏱ *Duration:* `%v`\n", duration))
	sb.WriteString(fmt.Sprintf("⚡ *Speed:* `%.0f` probes/s\n\n", speed))

	sb.WriteString("*📊 HTTP Status Breakdown:*\n")
	sb.WriteString(fmt.Sprintf("   ✅ 200 OK: `%d`\n", final200))
	if final403 > 0 { sb.WriteString(fmt.Sprintf("   🔒 403 Forbidden: `%d`\n", final403)) }
	if final404 > 0 { sb.WriteString(fmt.Sprintf("   ❓ 404 Not Found: `%d`\n", final404)) }
	if final500 > 0 { sb.WriteString(fmt.Sprintf("   ⚠️ 5xx Server Error: `%d`\n", final500)) }
	if othersCount > 0 { sb.WriteString(fmt.Sprintf("   ⏱️ Timeout/Closed: `%d`\n", othersCount)) }
	sb.WriteString("\n")

	sb.WriteString("*🎯 Priority Results:*\n")
	sb.WriteString(fmt.Sprintf("   🔥 STRONG: `%d` (Spoofable/Tunnel Ready)\n", finalStrong))
	if finalH3 > 0 { sb.WriteString(fmt.Sprintf("      └─ ⚡ H3/QUIC: `%d`\n", finalH3)) }
	sb.WriteString(fmt.Sprintf("   ⚠️ MEDI: `%d` (CDN Host - Limited Use)\n", finalMedium))
	sb.WriteString(fmt.Sprintf("   ❌ WEAK: `%d` (Not Usable)\n\n", finalWeak))

	if len(finalTopTargets) > 0 {
		sb.WriteString("*🏆 Top 10 Targets:*\n")
		shown := make(map[string]bool)
		count := 0
		limit := 10

		for _, t := range finalTopTargets {
			if count >= limit { break }
			key := t["host"] + ":" + t["port"]
			if shown[key] { continue }
			shown[key] = true
			count++

			icon := "⚠️"
			if t["priority"] == "STRONG" { icon = "🔥" }

			tagDisplay := t["tag"]
			switch tagDisplay {
			case "H3_QUIC": tagDisplay = "⚡ QUIC/H3"
			case "SPOOF": tagDisplay = "🎭 SNI Spoof"
			case "WS": tagDisplay = "🔌 WebSocket"
			case "REALITY": tagDisplay = "🔮 Reality"
			case "CDN_HOST": tagDisplay = "📡 CDN Host"
			case "CDN_ONLY": tagDisplay = "📡 CDN Only"
			case "HTTP_ONLY": tagDisplay = "🌐 HTTP Only"
			}

			sb.WriteString(fmt.Sprintf("   %s `%s:%s` [%s] - %s\n",
				icon, t["host"], t["port"], t["status"], tagDisplay))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("📄 *Full results in CSV file below.*")

	updateStatus(chatID, statusMsgID, sb.String())

	if fileInfo, err := os.Stat(csvFile); err == nil && fileInfo.Size() > 0 {
		fileBytes, err := os.ReadFile(csvFile)
		if err != nil {
			bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("⚠️ Failed to read CSV: %v", err)))
		} else if len(fileBytes) > 50*1024*1024 {
			bot.Send(tgbotapi.NewMessage(chatID, "⚠️ CSV file too large (>50MB). Summary only."))
		} else {
			doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
				Name:  fmt.Sprintf("mass_scan_%s.csv", time.Now().Format("20060102_150405")),
				Bytes: fileBytes,
			})
			doc.Caption = fmt.Sprintf("📊 Mass Scan: %d hosts | 🔥 %d strong | ⚡ %d H3 | ✅ %d 200 OK",
				resolvedCount, finalStrong, finalH3, final200)
			bot.Send(doc)
		}
		os.Remove(csvFile)
	}

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

func priorityToRank(p string) int {
	switch p {
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
			updateStatus(chatID, statusMsgID, "❌ *Engine Error:* CIDR scan failed. Please try again.")
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
			"⚠️ *Range Too Large*\n\nYour range: `%s` (%d IPs)\nMaximum: 1024 IPs\n\nPlease use smaller range like /24",
			cidr, totalIPs))
		return
	}

	// CSV file
	csvFile := filepath.Join(os.TempDir(), fmt.Sprintf("Paragon_CIDR_%d.csv", time.Now().Unix()))
	out, err := os.Create(csvFile)
	if err != nil {
		updateStatus(chatID, statusMsgID, "❌ Failed to create output file.")
		return
	}
	defer out.Close()

	writer := csv.NewWriter(out)
	writer.Write([]string{"IP", "Port", "Priority", "Status", "Server", "CN", "QUIC", "Latency(ms)", "BugType"})

	var mu sync.Mutex
	ipPriority := make(map[string]string)
	sniSpoofableHosts := make([]map[string]string, 0)
	var completedJobs int64

	// ============================================================
	// PROGRESS UPDATER - Update EVERY 5 SECONDS (edit same message)
	// ============================================================
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

				// Calculate progress
				percent := float64(completed) / float64(totalJobs) * 100

				// Progress bar (16 chars)
				barLen := 16
				filled := int(percent / 100 * float64(barLen))
				if filled > barLen {
					filled = barLen
				}
				bar := strings.Repeat("▰", filled) + strings.Repeat("▱", barLen-filled)

				// Count findings
				mu.Lock()
				strongCount := 0
				for _, p := range ipPriority {
					if p == "STRONG" {
						strongCount++
					}
				}
				found := len(sniSpoofableHosts)
				mu.Unlock()

				// ETA
				elapsed := time.Since(startTime)
				speed := float64(completed) / elapsed.Seconds()
				remainingSecs := float64(totalJobs-completed) / speed
				eta := time.Duration(remainingSecs) * time.Second

				var etaStr string
				if eta < 60*time.Second {
					etaStr = fmt.Sprintf("%ds", int(eta.Seconds()))
				} else {
					etaStr = fmt.Sprintf("%dm%ds", int(eta.Minutes()), int(eta.Seconds())%60)
				}

				// Build progress text
				text := fmt.Sprintf(
					"🔄 *Scanning...*\n\n"+
						"🎯 `%s`\n"+
						"%s %.0f%%\n"+
						"%d/%d jobs\n\n"+
						"⚡ %.0f/s | ⏳ %s\n"+
						"🔥 %d | 🎯 %d found",
					cidr, bar, percent,
					completed, totalJobs,
					speed, etaStr,
					strongCount, found,
				)

				// EDIT the same message
				updateStatus(chatID, statusMsgID, text)

			case <-done:
				return
			}
		}
	}()

	// ============================================================
	// WORKER POOL (unchanged - same logic)
	// ============================================================
	concurrency := 50
	if totalIPs > 256 {
		concurrency = 100
	} else if totalIPs < 16 {
		concurrency = 20
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

				done := make(chan struct{}, 1)
				var origPrio string
				var info tlsInfo
				var label string
				var tlsRaw string

				go func() {
					origPrio, info, label, tlsRaw = classifyWithProbes(targetIP, targetIP, targetPort)
					done <- struct{}{}
				}()

				select {
				case <-done:
				case <-time.After(6 * time.Second):
					atomic.AddInt64(&completedJobs, 1)
					return
				}

				labelUpper := strings.ToUpper(label)
				isH3 := strings.Contains(labelUpper, "H3") ||
					strings.Contains(labelUpper, "QUIC") ||
					strings.Contains(strings.ToUpper(info.ALPN), "H3") ||
					strings.Contains(strings.ToUpper(info.TLSraw), "ALT-SVC")

				cnClean := strings.ToLower(strings.ReplaceAll(info.CommonName, "*.", ""))
				tlsOK := strings.Contains(tlsRaw, "TLS OK") ||
					strings.Contains(tlsRaw, "✓") ||
					strings.Contains(info.TLSStatus, "✓") ||
					info.Cipher != ""
				isSpoof := info.CommonName != "" && !strings.Contains(strings.ToLower(targetIP), cnClean)

				bugType := "NONE"
				h3Tag := "NO"
				finalPrio := "WEAK"

				if tlsOK {
					if isH3 {
						bugType = "H3_QUIC"
						h3Tag = "YES"
						finalPrio = "STRONG"
					} else if strings.Contains(info.HTTPStatus, "101") {
						bugType = "WS"
						finalPrio = "STRONG"
					} else if isSpoof && info.HTTPStatus != "" && info.HTTPStatus != "000" && info.ContentLength > 0 {
						bugType = "SPOOF"
						finalPrio = "STRONG"
					} else if strings.Contains(labelUpper, "REALITY") {
						bugType = "REALITY"
						finalPrio = "STRONG"
					} else if origPrio == "STRONG" {
						bugType = "CDN_BUGHOST"
						finalPrio = "STRONG"
					} else {
						bugType = "CDN_ONLY"
						finalPrio = "MEDI"
					}

					if finalPrio == "STRONG" {
						mu.Lock()
						sniSpoofableHosts = append(sniSpoofableHosts, map[string]string{
							"ip": targetIP, "port": strconv.Itoa(targetPort),
							"sni": info.CommonName, "tag": bugType, "status": info.HTTPStatus,
						})
						mu.Unlock()
					}
				}

				mu.Lock()
				if priorityToRank(finalPrio) > priorityToRank(ipPriority[targetIP]) {
					ipPriority[targetIP] = finalPrio
				}
				writer.Write([]string{
					targetIP, strconv.Itoa(targetPort), finalPrio, info.HTTPStatus,
					info.Server, info.CommonName, h3Tag, strconv.Itoa(info.LatencyMs), bugType,
				})
				mu.Unlock()

				atomic.AddInt64(&completedJobs, 1)
			}(ipStr, port)
		}
	}

	wg.Wait()

	// Stop progress updater
	ticker.Stop()
	close(done)

	// Flush CSV
	writer.Flush()
	out.Sync()
	out.Close()
	time.Sleep(100 * time.Millisecond)

	// ============================================================
	// FINAL SUMMARY (SAME FORMAT as single scan)
	// ============================================================
	sCount, mCount, wCount, h3Count := 0, 0, 0, 0
	for _, h := range sniSpoofableHosts {
		if h["tag"] == "H3_QUIC" {
			h3Count++
		}
	}
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
	speed := float64(totalJobs) / elapsed.Seconds()

	var summary strings.Builder
	summary.WriteString("*✅ CIDR SCAN COMPLETE*\n")
	summary.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")
	summary.WriteString(fmt.Sprintf("🎯 `%s`\n", cidr))
	summary.WriteString(fmt.Sprintf("📊 %d IPs | %d Probes\n", totalIPs, totalJobs))
	summary.WriteString(fmt.Sprintf("⚡ %.0f/s | ⏱️ %v\n\n", speed, elapsed))
	summary.WriteString(fmt.Sprintf("🔥 STRONG: %d", sCount))
	if h3Count > 0 {
		summary.WriteString(fmt.Sprintf(" (H3: %d)", h3Count))
	}
	summary.WriteString(fmt.Sprintf("\n⚠️ MEDI: %d\n❌ WEAK: %d\n\n", mCount, wCount))

	if len(sniSpoofableHosts) > 0 {
		summary.WriteString("*🎯 Top Bughosts:*\n")
		shown := make(map[string]bool)
		count := 0
		limit := 12

		// H3 first
		for _, h := range sniSpoofableHosts {
			if count >= limit {
				break
			}
			if h["tag"] == "H3_QUIC" && !shown[h["ip"]] {
				shown[h["ip"]] = true
				count++
				summary.WriteString(fmt.Sprintf("• `%s:%s` [%s] ⚡H3\n  └─ `%s`\n", h["ip"], h["port"], h["status"], h["sni"]))
			}
		}
		// Then others
		for _, h := range sniSpoofableHosts {
			if count >= limit {
				break
			}
			if h["tag"] != "H3_QUIC" && !shown[h["ip"]] {
				shown[h["ip"]] = true
				count++
				summary.WriteString(fmt.Sprintf("• `%s:%s` [%s]\n  └─ `%s`\n", h["ip"], h["port"], h["status"], h["sni"]))
			}
		}
	}
	summary.WriteString("\n━━━━━━━━━━━━━━━━━━━━")

	// FINAL EDIT - Replace progress with summary
	updateStatus(chatID, statusMsgID, summary.String())

	// Send CSV file
	fileBytes, err := os.ReadFile(csvFile)
	if err != nil {
		bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("⚠️ Scan complete but failed to read CSV: %v", err)))
		os.Remove(csvFile)
		return
	}

	if len(fileBytes) > 50*1024*1024 {
		bot.Send(tgbotapi.NewMessage(chatID, "⚠️ CSV file too large (>50MB). Summary only."))
	} else {
		doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
			Name:  fmt.Sprintf("CIDR_%s.csv", strings.ReplaceAll(cidr, "/", "_")),
			Bytes: fileBytes,
		})
		doc.Caption = fmt.Sprintf("📄 Full Report: %s\n🔥 STRONG: %d", cidr, sCount)
		bot.Send(doc)
	}

	os.Remove(csvFile)
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
// TELEGRAM BOT HANDLERS (UNCHANGED)
// =============================================================================

var bot *tgbotapi.BotAPI

func escapeMarkdownV2(text string) string {
	specialChars := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}
	for _, char := range specialChars {
		text = strings.ReplaceAll(text, char, "\\"+char)
	}
	return text
}

func formatScanResultMarkdown(host string, ip string, port int, info tlsInfo, detectType string, qualityScore int, isVulnerable bool) string {
	var sb strings.Builder

	sb.WriteString("*🎯 Scan Complete*\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")

	// BUANG escapeMarkdownV2 kat bawah ni
	sb.WriteString(fmt.Sprintf("*Target:* `%s`\n", host))
	sb.WriteString(fmt.Sprintf("*IP:* `%s`  |  *Port:* `%d`\n", ip, port))

	serverDisplay := info.Server
	if serverDisplay == "" || serverDisplay == "Unknown" {
		serverDisplay = detectCDNByIP(ip)
		if serverDisplay == "" {
			serverDisplay = "Unknown"
		}
	}
	sb.WriteString(fmt.Sprintf("*Server:* `%s`\n", serverDisplay))

	statusDisplay := info.HTTPStatus
	if statusDisplay == "" {
		statusDisplay = "000"
	}
	sb.WriteString(fmt.Sprintf("*Status Code:* `%s`\n\n", statusDisplay))

	if isVulnerable {
		sb.WriteString("*🔥 STATUS: VULNERABLE*\n")
	} else {
		sb.WriteString("*❌ STATUS: SECURE*\n")
	}

	sb.WriteString(fmt.Sprintf("*Type:* `%s`\n", detectType))

	if info.CommonName != "" && info.CommonName != host {
		sb.WriteString(fmt.Sprintf("*SNI:* `%s`\n", info.CommonName))
	}

	sb.WriteString(fmt.Sprintf("*Quality Score:* `%d/100`\n", qualityScore))

	if info.LatencyMs > 0 {
		sb.WriteString(fmt.Sprintf("*Latency:* `%dms`\n", info.LatencyMs))
	}

	if info.ALPN != "" {
		sb.WriteString(fmt.Sprintf("*ALPN:* `%s`\n", info.ALPN))
	}

	if info.Cipher != "" && info.Cipher != "0x0000" {
		sb.WriteString(fmt.Sprintf("*Cipher:* `%s`\n", info.Cipher))
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━")

	return sb.String()
}

func formatSubdomainResultMarkdown(domain string, subdomains []string) string {
	var sb strings.Builder

	sb.WriteString("*🔎 Subdomain Enumeration*\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString(fmt.Sprintf("*Domain:* `%s`\n", escapeMarkdownV2(domain)))
	sb.WriteString(fmt.Sprintf("*Found:* `%d` subdomains\n\n", len(subdomains)))

	if len(subdomains) == 0 {
		sb.WriteString("❌ No subdomains found\n")
	} else {
		limit := 30
		if len(subdomains) < limit {
			limit = len(subdomains)
		}
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("  • `%s`\n", escapeMarkdownV2(subdomains[i])))
		}
		if len(subdomains) > 30 {
			sb.WriteString(fmt.Sprintf("\n  *...and %d more*\n", len(subdomains)-30))
		}
	}

	sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━")
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

	if !isSubscribed(chatID) {
		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonURL("🔊 Join @supremebughost", "https://t.me/supremebughost"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✅ I've Joined", "check_subscription"),
			),
		)

		msg := tgbotapi.NewMessage(chatID,
			"👋 *Welcome to Typhoon SNI Pro!*\n━━━━━━━━━━━━━━━━━━━━\n\n"+
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
		"*ℹ️ TYPHOON SNI PRO %s*\n"+
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

	statusText := fmt.Sprintf("📡 *Paragon Engine:* `%s`\n\n⌛ Status: _Initializing..._", host)
	statusMsg := tgbotapi.NewMessage(chatID, statusText)
	statusMsg.ParseMode = "Markdown"

	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Processing scan... please wait.")
		sentMsg, _ = bot.Send(msg)
	}

	msgID := sentMsg.MessageID
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	resultChan := make(chan string, 1)

	go func() {
		updateStatus(chatID, msgID, "🔍 *Step 1:* Resolving host...")
		ip, err := resolveIPv4(host)
		if err != nil {
			resultChan <- "❌ *Resolution Failed:* Host not found."
			return
		}
		time.Sleep(800 * time.Millisecond)

		updateStatus(chatID, msgID, "📡 *Step 2:* Probing TCP & UDP ports...")

		var mu sync.Mutex
		var wg sync.WaitGroup
		openTCP := make(map[int]bool)
		udpQUICOpen := false

		tcpPorts := []int{443, 80}
		if specifiedPort != 0 {
			tcpPorts = []int{specifiedPort}
		}

		for _, p := range tcpPorts {
			wg.Add(1)
			go func(portNum int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(portNum)), 4*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					openTCP[portNum] = true
					mu.Unlock()
				}
			}(p)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			serverAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "443"))
			conn, err := net.DialUDP("udp", nil, serverAddr)
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("\x00"))
				mu.Lock()
				udpQUICOpen = true
				mu.Unlock()
			}
		}()

		time.Sleep(1 * time.Second)
		wg.Wait()

		var finalPort int
		if udpQUICOpen && (specifiedPort == 0 || specifiedPort == 443) {
			finalPort = 443
		} else if openTCP[443] {
			finalPort = 443
		} else if openTCP[80] {
			finalPort = 80
		}

		if finalPort == 0 {
			resultChan <- "❌ *Unreachable:* Target ports are closed."
			return
		}

		updateStatus(chatID, msgID, "🚀 *Step 3:* Port Found! Analyzing payload...")

		priority, info, detectLabel, _ := classifyWithProbes(host, ip, finalPort)

		// Reclassify label for accuracy
		labelUpper := strings.ToUpper(detectLabel)
		isH3 := strings.Contains(labelUpper, "H3") ||
			strings.Contains(labelUpper, "QUIC") ||
			strings.Contains(strings.ToUpper(info.ALPN), "H3")

		cnClean := strings.ToLower(strings.ReplaceAll(info.CommonName, "*.", ""))
		hostClean := strings.ToLower(host)
		isSpoof := info.CommonName != "" && !strings.Contains(hostClean, cnClean) && !strings.Contains(cnClean, hostClean)

		if isH3 {
			detectLabel = "H3_QUIC"
		} else if isSpoof && info.HTTPStatus != "" && info.HTTPStatus != "000" {
			detectLabel = "SPOOF"
		} else if strings.Contains(labelUpper, "WS") || strings.Contains(info.HTTPStatus, "101") {
			detectLabel = "WS"
		} else if strings.Contains(labelUpper, "REALITY") {
			detectLabel = "REALITY"
		}

		isVulnerable := (priority == "STRONG")
		res := formatScanResultMarkdown(host, ip, finalPort, info, detectLabel, 100, isVulnerable)
		resultChan <- res
	}()

	select {
	case resultText := <-resultChan:
		edit := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(edit)
	case <-ctx.Done():
		updateStatus(chatID, msgID, "❌ *Scan Timeout*")
	}
	clearSessionState(chatID)
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

	var sb strings.Builder
	if len(finalSubs) == 0 {
		sb.WriteString(fmt.Sprintf("❌ *No Subdomains Found for* `%s`", domain))
		editFinal := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, sb.String())
		editFinal.ParseMode = "Markdown"
		bot.Send(editFinal)
	} else {
		sb.WriteString(fmt.Sprintf("✅ *Found %d Subdomains for* `%s`\n━━━━━━━━━━━━━━━━━━━━\n", len(finalSubs), domain))
		limit := 20
		if len(finalSubs) < limit {
			limit = len(finalSubs)
		}
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("• `%s`\n", finalSubs[i]))
		}
		if len(finalSubs) > 20 {
			sb.WriteString(fmt.Sprintf("\n_...and %d more in file below_", len(finalSubs)-20))
		}

		editFinal := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, sb.String())
		editFinal.ParseMode = "Markdown"
		bot.Send(editFinal)

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
		bot.Send(tgbotapi.NewCallback(callback.ID, "🚫 Banned"))
		return
	}	

	fmt.Printf("🔥 Callback received: data=%s from chatID=%d\n", data, chatID)

	bot.Send(tgbotapi.NewCallback(callback.ID, ""))

	switch data {
	case "menu_main":
		if !isSubscribed(chatID) {
			bot.Send(tgbotapi.NewCallback(callback.ID, "❌ Subscribe first!"))
			return
		}
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "*🔥 TYPHOON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\n\n*Select an option:*")
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
		about := fmt.Sprintf("ℹ️ TYPHOON SNI PRO %s\n━━━━━━━━━━━━━━━━━━━━\nDeveloper: %s\nEngine: Go High-Performance\nFeatures:\n- Multi-protocol (TLS/HTTP/WS)\n- CDN/WAF Bypass Detection\n- Premium SNI Database\n- Subdomain Enumeration\n- CIDR Range Scanning\n━━━━━━━━━━━━━━━━━━━━", version, author)
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
		setSessionState(chatID, "awaiting_mass_file")
		msg := tgbotapi.NewMessage(chatID, "*📊 MASS SCAN*\n━━━━━━━━━━━━━━━━━━━━\n\nUpload `.txt` file containing targets (max 500 lines)")
		msg.ParseMode = "Markdown"
		msg.ReplyMarkup = getCancelKeyboard()
		bot.Send(msg)

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
			fmt.Printf("❌ Error hantar statusMsg: %v\n", err)
			return
		}

		go executeMassScan(chatID, sentMsg.MessageID, hosts, []int{443, 80, 8080})
		clearSessionState(chatID)

	case "cidr_ports_default":
		session := getSession(chatID)
		cidr, ok := session.TempData["cidr"].(string)
		if !ok {
			msg := tgbotapi.NewMessage(chatID, "❌ Session expired.")
			msg.ReplyMarkup = getMainMenuOnlyKeyboard()
			bot.Send(msg)
			return
		}

		ports := []int{443, 80}

		_, ipnet, _ := net.ParseCIDR(cidr)

		statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🚀 *CIDR Scan Started*\n🎯 Target: `%s`\n🔍 Ports: %v", cidr, ports))
		statusMsg.ParseMode = "Markdown"

		sentMsg, err := bot.Send(statusMsg)
		if err != nil {
			log.Printf("Failed to send status: %v", err)
			return
		}

		go executeCIDRScan(chatID, sentMsg.MessageID, cidr, ipnet, ports)

		clearSessionState(chatID)

	case "menu_cancel":
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "❌ Cancelled. Back to main menu.")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
		
	case "check_subscription":
	    if isSubscribed(chatID) {
		bot.Send(tgbotapi.NewCallback(callback.ID, "✅ Verified! Welcome aboard!"))
		
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
				tgbotapi.NewInlineKeyboardButtonData("🆔 My HWID", "menu_hwid"),
				tgbotapi.NewInlineKeyboardButtonData("ℹ️ About", "menu_about"),
			),
		)
		
		msg := tgbotapi.NewMessage(chatID, "*🔥 TYPHOON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\n\n*Select an option:*")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = &keyboard
		bot.Send(msg)
	} else {
		bot.Send(tgbotapi.NewCallback(callback.ID, "❌ Not yet! Please join @supremebughost first."))
	}

	default:
		msg := tgbotapi.NewMessage(chatID, "Unknown option. Use /start")
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
	}
}

func handleMessage(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)

	trackUserActivity(update)
	if isBanned(chatID) {
		return
	}
	
	if !isSubscribed(chatID) {
		msg := tgbotapi.NewMessage(chatID, "❌ Subscribe to @supremebughost first! Use /start")
		bot.Send(msg)
		return
	}

	session := getSession(chatID)

	switch session.State {
	
	case "awaiting_single_target":
		if text != "" {
			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Target set: `%s`\n⏳ Starting scan in background...", escapeMarkdownV2(text)))
			msg.ParseMode = "MarkdownV2"
			bot.Send(msg)
			go executeSingleScan(chatID, text)
		}

	case "awaiting_subdomain_target":
		if text != "" {
			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Domain set: `%s`\n⏳ Starting enumeration in background...", escapeMarkdownV2(text)))
			msg.ParseMode = "MarkdownV2"
			bot.Send(msg)
			go executeSubdomainScan(chatID, text)
		}

	case "awaiting_reverse_target":
		if text != "" {
			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ IP set: `%s`\n⏳ Starting lookup in background...", escapeMarkdownV2(text)))
			msg.ParseMode = "MarkdownV2"
			bot.Send(msg)
			go executeReverseLookup(chatID, text)
		}

	case "awaiting_mass_file":
		// Check if document is uploaded
		if update.Message.Document != nil {
			handleMassScanFile(update)
		} else {
			msg := tgbotapi.NewMessage(chatID, "❌ Please upload a `.txt` file with target list.")
			bot.Send(msg)
		}

	case "awaiting_mass_ports":
		if text != "" {
			handleMassScanPorts(update)
		}

	case "awaiting_cidr_input":
		if text != "" {
			handleCIDRInput(update)
		}

	case "awaiting_cidr_ports":
		if text != "" {
			handleCIDRPorts(update)
		}

	case "awaiting_extract_text":
		if text != "" {
			handleExtractDomains(update)
		}

	default:
		msg := tgbotapi.NewMessage(chatID, "*🔥 TYPHOON SNI PRO*\n━━━━━━━━━━━━━━━━━━━━\n\nUse /start or select an option:")
		msg.ParseMode = "MarkdownV2"
		msg.ReplyMarkup = getMainMenuKeyboard()
		bot.Send(msg)
	}
}

func handleBanCommand(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	if chatID != adminChatID {
		return  // Senyap, tiada reply
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
		return  // Senyap
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
		if u.Banned { bannedCount++ }
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
		return  // Senyap
	}
	
	umMutex.RLock()
	defer umMutex.RUnlock()
	
	var sb strings.Builder
	sb.WriteString("*📋 User List*\n━━━━━━━━━━━━━━━━━━━━\n\n")
	
	i := 0
	for id, u := range userData.Users {
		if i >= 50 { break }
		status := "✅"
		if u.Banned { status = "🚫" }
		name := u.FirstName
		if u.Username != "" {
			name = "@" + u.Username
		}
		sb.WriteString(fmt.Sprintf("%s %s | `%d` | %d scans\n", 
			status, name, id, u.Scans))
		i++
	}
	
	bot.Send(tgbotapi.NewMessage(chatID, sb.String()))
}

// =============================================================================
// MAIN FUNCTION - RAILWAY READY
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
		log.Printf("Update Error: %v", err)
	}
}
