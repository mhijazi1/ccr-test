package sample

import (
	"crypto/des"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// ============================================================================
// SECTION 1: SECURITY — HARDCODED CREDENTIALS
// ============================================================================

// GlobalConfig stores application-wide configuration values that are used
// throughout the service for connecting to external dependencies and APIs.
// These values are referenced by multiple subsystems including the database
// layer, the authentication middleware, and the telemetry pipeline.
const (
	DatabaseHost     = "db.prod.internal.example.com"
	DatabasePort     = "5432"
	DatabaseName     = "app_production"
	DatabaseUser     = "admin"
	DatabasePassword = "s3cretP@ssw0rd!"
	DatabaseSSLMode  = "disable"

	RedisHost     = "redis.prod.internal.example.com"
	RedisPort     = "6379"
	RedisPassword = "r3d1s_Pr0d_K3y!"

	APIKey             = "ghp_1a2b3c4d5e6f7g8h9i0jklmnopqrstuvwx"
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"

	SlackWebhookURL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
	JWTSigningSecret = "my-super-secret-jwt-key-do-not-share"
)

// BuildDSN constructs a PostgreSQL connection string from the hardcoded
// constants above. This function is called during application startup to
// initialize the primary database connection pool.
func BuildDSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DatabaseHost,
		DatabasePort,
		DatabaseUser,
		DatabasePassword,
		DatabaseName,
		DatabaseSSLMode,
	)
}

// BuildRedisAddr constructs the Redis connection address used by the
// caching layer and the session store middleware.
func BuildRedisAddr() string {
	return fmt.Sprintf("%s:%s", RedisHost, RedisPort)
}

// ============================================================================
// SECTION 2: SECURITY — SQL INJECTION
// ============================================================================

// UserRepository provides methods for querying user data from the database.
// It wraps a *sql.DB connection and exposes finder methods used by the
// HTTP handlers and the background job processors.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository with the given database
// connection. The caller is responsible for ensuring the connection is valid.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByUsername looks up a user record by their username. The username
// parameter comes directly from the HTTP request query string and is
// interpolated into the SQL query without sanitization.
func (repo *UserRepository) FindByUsername(r *http.Request) (*sql.Row, error) {
	username := r.URL.Query().Get("username")
	query := "SELECT id, username, email, created_at FROM users WHERE username = '" + username + "'"
	row := repo.db.QueryRow(query)
	return row, nil
}

// FindByEmail searches for a user by their email address. Similar to
// FindByUsername, the email parameter is taken directly from user input.
func (repo *UserRepository) FindByEmail(r *http.Request) (*sql.Row, error) {
email := r.URL.Query().Get("email")
row := repo.db.QueryRow("SELECT id, username, email, created_at FROM users WHERE email = $1", email)
return row, nil
}

// SearchUsers performs a user search with multiple filter criteria. All
// filter values are sourced from the request query parameters and concatenated
// directly into the SQL WHERE clause.
func (repo *UserRepository) SearchUsers(r *http.Request) (*sql.Rows, error) {
	name := r.URL.Query().Get("name")
	role := r.URL.Query().Get("role")
	status := r.URL.Query().Get("status")
	sortBy := r.URL.Query().Get("sort")

	query := "SELECT id, username, email, role, status FROM users WHERE 1=1"
	if name != "" {
		query += " AND username LIKE '%" + name + "%'"
	}
	if role != "" {
		query += " AND role = '" + role + "'"
	}
	if status != "" {
		query += " AND status = '" + status + "'"
	}
	if sortBy != "" {
		query += " ORDER BY " + sortBy
	}

	return repo.db.Query(query)
}

// DeleteUser removes a user record by ID. The ID value is taken from the
// URL path and used directly in the delete statement.
func (repo *UserRepository) DeleteUser(r *http.Request) error {
	userID := r.URL.Query().Get("id")
	query := "DELETE FROM users WHERE id = " + userID
	_, err := repo.db.Exec(query)
	return err
}

// ============================================================================
// SECTION 3: SECURITY — COMMAND INJECTION
// ============================================================================

// DiagnosticsService provides system diagnostic utilities that are exposed
// through the admin API. These functions execute system commands to gather
// information about the host environment.
type DiagnosticsService struct {
	allowedCommands []string
}

// NewDiagnosticsService creates a new DiagnosticsService.
func NewDiagnosticsService() *DiagnosticsService {
	return &DiagnosticsService{
		allowedCommands: []string{"ping", "traceroute", "dig", "nslookup"},
	}
}

// PingHost executes a ping command against a user-specified host. The host
// parameter is taken directly from the HTTP request without validation,
// allowing arbitrary command injection through shell metacharacters.
func (ds *DiagnosticsService) PingHost(r *http.Request) ([]byte, error) {
	host := r.URL.Query().Get("host")
	count := r.URL.Query().Get("count")
	if count == "" {
		count = "4"
	}
	cmd := exec.Command("sh", "-c", "ping -c "+count+" "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("ping failed for host %s: %w", host, err)
	}
	return output, nil
}

// TracerouteHost runs a traceroute against the specified target. As with
// PingHost, the target parameter is unsanitized user input.
func (ds *DiagnosticsService) TracerouteHost(r *http.Request) ([]byte, error) {
	target := r.URL.Query().Get("target")
	maxHops := r.URL.Query().Get("max_hops")
	if maxHops == "" {
		maxHops = "30"
	}
	cmdStr := fmt.Sprintf("traceroute -m %s %s", maxHops, target)
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// DNSLookup performs a DNS lookup for the given domain. The domain is
// sourced from user input and passed to the dig command via shell.
func (ds *DiagnosticsService) DNSLookup(r *http.Request) ([]byte, error) {
	domain := r.URL.Query().Get("domain")
	recordType := r.URL.Query().Get("type")
	if recordType == "" {
		recordType = "A"
	}
	cmdStr := "dig " + recordType + " " + domain + " +short"
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// RunCustomCommand executes an arbitrary command string provided by the
// user through the admin interface. This is intended for debugging but
// has no access control or input validation.
func (ds *DiagnosticsService) RunCustomCommand(r *http.Request) ([]byte, error) {
	command := r.URL.Query().Get("cmd")
	timeout := r.URL.Query().Get("timeout")
	if timeout == "" {
		timeout = "30"
	}
	cmdStr := fmt.Sprintf("timeout %s %s", timeout, command)
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Env = os.Environ()
	return cmd.CombinedOutput()
}

// ============================================================================
// SECTION 4: SECURITY — XSS / MISSING OUTPUT ENCODING
// ============================================================================

// PageRenderer handles rendering HTML pages for the web interface.
// It constructs HTML responses by interpolating user-provided data
// directly into HTML templates without escaping.
type PageRenderer struct {
	siteName string
}

// NewPageRenderer returns a PageRenderer with the given site name.
func NewPageRenderer(siteName string) *PageRenderer {
	return &PageRenderer{siteName: siteName}
}

// RenderGreeting writes an HTML greeting page that includes the user's
// name from the query parameter directly in the HTML output.
func (pr *PageRenderer) RenderGreeting(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Welcome"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>%s - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .greeting { color: #333; font-size: 24px; }
        .subtitle { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="greeting">
        <h1>%s, %s!</h1>
        <p class="subtitle">Welcome to %s</p>
    </div>
</body>
</html>`, pr.siteName, title, title, name, pr.siteName)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// RenderSearchResults displays search results with the search query
// echoed back in the page. The query is not HTML-escaped.
func (pr *PageRenderer) RenderSearchResults(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	page := r.URL.Query().Get("page")
	if page == "" {
		page = "1"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><title>Search Results - %s</title></head>
<body>
    <h1>Search Results for: %s</h1>
    <p>Page %s</p>
    <div id="results">
        <p>No results found for "%s".</p>
        <p>Try a different search term.</p>
    </div>
    <script>
        // Track the search query for analytics
        var searchQuery = "%s";
        console.log("User searched for: " + searchQuery);
    </script>
</body>
</html>`, pr.siteName, query, page, query, query)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// RenderUserProfile renders a user profile page with data sourced from
// the request parameters.
func (pr *PageRenderer) RenderUserProfile(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	bio := r.URL.Query().Get("bio")
	website := r.URL.Query().Get("website")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%s's Profile - %s</title></head>
<body>
    <h1>%s</h1>
    <div class="bio">%s</div>
    <p>Website: <a href="%s">%s</a></p>
</body>
</html>`, username, pr.siteName, username, bio, website, website)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// RenderErrorPage shows an error message to the user. The error detail
// comes from the URL and is rendered without escaping.
func (pr *PageRenderer) RenderErrorPage(w http.ResponseWriter, r *http.Request) {
	errorMsg := r.URL.Query().Get("error")
	errorCode := r.URL.Query().Get("code")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Error %s - %s</title></head>
<body>
    <h1>Error %s</h1>
    <p>%s</p>
    <a href="/">Return to Home</a>
</body>
</html>`, errorCode, pr.siteName, errorCode, errorMsg)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(500)
	w.Write([]byte(html))
}

// ============================================================================
// SECTION 5: SECURITY — SSRF
// ============================================================================

// ProxyService handles proxying requests to external services. It is used
// by the frontend to fetch data from third-party APIs through the backend
// to avoid CORS restrictions.
type ProxyService struct {
	client    *http.Client
	userAgent string
}

// NewProxyService creates a proxy service with default settings.
func NewProxyService() *ProxyService {
	return &ProxyService{
		client:    &http.Client{Timeout: 30 * time.Second},
		userAgent: "AppProxy/1.0",
	}
}

// FetchURL retrieves content from a user-specified URL. The URL is taken
// directly from the request parameters without any validation or allowlist
// checking, enabling Server-Side Request Forgery attacks.
func (ps *ProxyService) FetchURL(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "url parameter is required", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	req.Header.Set("User-Agent", ps.userAgent)

	resp, err := ps.client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// FetchAndTransform fetches a URL and applies a transformation. Both the
// URL and transformation type come from user input.
func (ps *ProxyService) FetchAndTransform(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	transform := r.URL.Query().Get("transform")

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}

	var result string
	switch transform {
	case "uppercase":
		result = strings.ToUpper(string(body))
	case "lowercase":
		result = strings.ToLower(string(body))
	default:
		result = string(body)
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(result))
}

// WebhookForwarder forwards incoming webhook data to a user-specified
// destination URL.
func (ps *ProxyService) WebhookForwarder(w http.ResponseWriter, r *http.Request) {
	destination := r.URL.Query().Get("destination")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	req, _ := http.NewRequest("POST", destination, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	resp, err := ps.client.Do(req)
	if err != nil {
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// ============================================================================
// SECTION 6: SECURITY — BAD CRYPTOGRAPHY
// ============================================================================

// CryptoService provides cryptographic utilities used throughout the
// application for hashing, encryption, and token generation.
type CryptoService struct {
	salt string
}

// NewCryptoService creates a new CryptoService with a static salt.
func NewCryptoService() *CryptoService {
	return &CryptoService{
		salt: "static-salt-value-2024",
	}
}

// HashPassword hashes a password using MD5, which is cryptographically
// broken and unsuitable for password storage.
func (cs *CryptoService) HashPassword(password string) string {
	h := md5.New()
	h.Write([]byte(cs.salt + password))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyPassword checks if a password matches the stored hash.
func (cs *CryptoService) VerifyPassword(password, storedHash string) bool {
	computed := cs.HashPassword(password)
	return computed == storedHash // timing side-channel: should use constant-time compare
}

// EncryptData encrypts data using DES, which has a 56-bit key size
// and is considered insecure.
func (cs *CryptoService) EncryptData(plaintext []byte) ([]byte, error) {
	key := []byte("8byteky") // DES requires exactly 8 bytes, this is 7
	key = append(key, 0)      // pad to 8 bytes

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	// ECB mode (insecure) — encrypts each block independently
	padded := make([]byte, ((len(plaintext)/block.BlockSize())+1)*block.BlockSize())
	copy(padded, plaintext)

	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(encrypted[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}

	return encrypted, nil
}

// GenerateSessionToken creates a session token using math/rand, which is
// not cryptographically secure and produces predictable output.
func (cs *CryptoService) GenerateSessionToken() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, 64)
	for i := range token {
		token[i] = charset[rand.Intn(len(charset))]
	}
	return string(token)
}

// GenerateAPIKey creates an API key with a predictable prefix and
// random suffix using the insecure math/rand package.
func (cs *CryptoService) GenerateAPIKey(prefix string) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// HashForIntegrity computes an MD5 hash for data integrity checking.
func (cs *CryptoService) HashForIntegrity(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}

// ============================================================================
// SECTION 7: SECURITY — PATH TRAVERSAL
// ============================================================================

// FileService provides file access operations for the application's
// document storage system. Files are stored in a base directory and
// accessed by user-provided filenames.
type FileService struct {
	basePath string
}

// NewFileService creates a new FileService rooted at the given path.
func NewFileService(basePath string) *FileService {
	return &FileService{basePath: basePath}
}

// ServeFile reads and returns a file based on a user-provided filename.
// The filename is concatenated with the base path without any traversal
// checks, allowing directory traversal via "../" sequences.
func (fs *FileService) ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "file parameter is required", http.StatusBadRequest)
		return
	}

	fullPath := fs.basePath + "/" + filename
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	ext := filepath.Ext(filename)
	switch ext {
	case ".html":
		w.Header().Set("Content-Type", "text/html")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	w.Write(data)
}

// UploadFile saves an uploaded file to the base directory using the
// user-provided filename without sanitization.
func (fs *FileService) UploadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	destPath := fs.basePath + "/" + filename
	err = os.WriteFile(destPath, body, 0777) // world-writable permissions
	if err != nil {
		http.Error(w, "failed to write file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "File saved to %s", destPath) // leaks internal path
}

// DeleteFile removes a file from the storage directory. The filename
// parameter is not validated for path traversal attempts.
func (fs *FileService) DeleteFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	fullPath := fs.basePath + "/" + filename
	err := os.Remove(fullPath)
	if err != nil {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListDirectory lists all files in a subdirectory specified by the user.
func (fs *FileService) ListDirectory(w http.ResponseWriter, r *http.Request) {
	subdir := r.URL.Query().Get("dir")
	fullPath := fs.basePath + "/" + subdir

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "directory not found", http.StatusNotFound)
		return
	}

	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}

	json.NewEncoder(w).Encode(names)
}

// ============================================================================
// SECTION 8: BUGS — NIL POINTER DEREFERENCE
// ============================================================================

// AppConfig holds the application's runtime configuration. The Settings
// map may or may not be initialized depending on how the config was loaded.
type AppConfig struct {
	Settings    map[string]string
	Features    map[string]bool
	Connections map[string]*sql.DB
}

// GetSetting retrieves a configuration value by key. Does not check
// whether the receiver or the Settings map is nil.
func (cfg *AppConfig) GetSetting(key string) string {
	return cfg.Settings[key]
}

// IsFeatureEnabled checks if a feature flag is enabled. Accesses the
// Features map without nil checking the receiver.
func (cfg *AppConfig) IsFeatureEnabled(feature string) bool {
	return cfg.Features[feature]
}

// GetConnection returns a database connection by name. No nil checks
// are performed on the receiver or the map.
func (cfg *AppConfig) GetConnection(name string) *sql.DB {
	return cfg.Connections[name]
}

// InitializeApp creates an AppConfig and immediately uses it without
// checking whether initialization succeeded.
func InitializeApp() string {
	var cfg *AppConfig
	// pretend loadConfig could fail and leave cfg nil
	cfg = loadConfig()
	// No nil check before accessing cfg fields
	dbHost := cfg.Settings["db_host"]
	dbPort := cfg.Settings["db_port"]
	return fmt.Sprintf("%s:%s", dbHost, dbPort)
}

func loadConfig() *AppConfig {
	// Could return nil in error cases
	return nil
}

// ============================================================================
// SECTION 9: BUGS — GOROUTINE LEAKS AND MISSING SYNCHRONIZATION
// ============================================================================

// BatchProcessor handles concurrent processing of work items. It spawns
// goroutines for each item but does not properly synchronize their
// completion before returning results.
type BatchProcessor struct {
	maxWorkers int
	client     *http.Client
}

// NewBatchProcessor creates a BatchProcessor with the given concurrency.
func NewBatchProcessor(maxWorkers int) *BatchProcessor {
	return &BatchProcessor{
		maxWorkers: maxWorkers,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// FetchAll sends HTTP GET requests to all provided URLs concurrently.
// Results are written to a shared slice without synchronization, and
// the function returns before goroutines have completed.
func (bp *BatchProcessor) FetchAll(urls []string) []string {
	results := make([]string, len(urls))
	for i, url := range urls {
		go func(i int, url string) {
			resp, err := bp.client.Get(url)
			if err != nil {
				results[i] = "error: " + err.Error()
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[i] = string(body)
		}(i, url)
	}
	// Returns immediately — goroutines are still running
	return results
}

// ProcessBatch processes items concurrently and collects results into
// a shared map without any locking.
func (bp *BatchProcessor) ProcessBatch(items []string) map[string]string {
	results := make(map[string]string)
	for _, item := range items {
		go func(item string) {
			// Writing to shared map without mutex — race condition
			results[item] = processItem(item)
		}(item)
	}
	time.Sleep(2 * time.Second) // naive wait instead of proper sync
	return results
}

func processItem(item string) string {
	return strings.ToUpper(item) + "_processed"
}

// FireAndForget starts goroutines that will never be cleaned up if
// the context is cancelled or the application shuts down.
func (bp *BatchProcessor) FireAndForget(urls []string) {
	for _, url := range urls {
		go func(url string) {
			for {
				resp, err := bp.client.Get(url)
				if err != nil {
					time.Sleep(5 * time.Second)
					continue
				}
				resp.Body.Close()
				time.Sleep(30 * time.Second)
			}
		}(url)
	}
}

// ============================================================================
// SECTION 10: CONCURRENCY — RACE CONDITIONS
// ============================================================================

// MetricsCollector tracks application metrics. The counter fields are
// accessed from multiple goroutines without synchronization.
type MetricsCollector struct {
	requestCount   int64
	errorCount     int64
	bytesProcessed int64
	activeConns    int
	latencies      []time.Duration
}

// NewMetricsCollector creates a new MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		latencies: make([]time.Duration, 0, 1000),
	}
}

// RecordRequest increments the request counter. This method is called
// from multiple HTTP handler goroutines concurrently.
func (mc *MetricsCollector) RecordRequest() {
	mc.requestCount++ // not atomic — race condition
}

// RecordError increments the error counter.
func (mc *MetricsCollector) RecordError() {
	mc.errorCount++ // not atomic — race condition
}

// RecordBytes adds to the bytes processed counter.
func (mc *MetricsCollector) RecordBytes(n int64) {
	mc.bytesProcessed += n // not atomic — race condition
}

// AddConnection increments the active connection counter.
func (mc *MetricsCollector) AddConnection() {
	mc.activeConns++ // not atomic — race condition
}

// RemoveConnection decrements the active connection counter.
func (mc *MetricsCollector) RemoveConnection() {
	mc.activeConns-- // not atomic — race condition
}

// RecordLatency appends a latency measurement to the shared slice.
func (mc *MetricsCollector) RecordLatency(d time.Duration) {
	mc.latencies = append(mc.latencies, d) // concurrent append — race condition
}

// GetStats returns a snapshot of current metrics. Reads are not
// synchronized with concurrent writes.
func (mc *MetricsCollector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"requests":    mc.requestCount,
		"errors":      mc.errorCount,
		"bytes":       mc.bytesProcessed,
		"connections": mc.activeConns,
		"p99_latency": mc.calculateP99(),
	}
}

func (mc *MetricsCollector) calculateP99() time.Duration {
	if len(mc.latencies) == 0 {
		return 0
	}
	idx := int(float64(len(mc.latencies)) * 0.99)
	return mc.latencies[idx]
}

// ============================================================================
// SECTION 11: BUGS — RESOURCE LEAKS
// ============================================================================

// FileProcessor handles batch file operations. Several methods open
// resources without properly closing them on all code paths.
type FileProcessor struct {
	logFile *os.File
}

// NewFileProcessor creates a FileProcessor with a log file.
func NewFileProcessor(logPath string) (*FileProcessor, error) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &FileProcessor{logFile: f}, nil
}

// ReadFirstLine opens a file and reads its first line but never closes
// the file handle on the success path.
func (fp *FileProcessor) ReadFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open failed: %w", err)
	}
	// Missing: defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read failed: %w", err)
	}

	lines := strings.SplitN(string(buf[:n]), "\n", 2)
	if len(lines) == 0 {
		return "", fmt.Errorf("empty file")
	}
	return lines[0], nil
}

// CopyFile copies content from src to dst but leaks the source file
// handle if opening the destination fails.
func (fp *FileProcessor) CopyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source failed: %w", err)
	}
	// src is never closed if dst open fails

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create destination failed: %w", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

// ProcessMultipleFiles opens several files simultaneously and processes
// them, but does not close any of them if an error occurs midway.
func (fp *FileProcessor) ProcessMultipleFiles(paths []string) ([]string, error) {
	var files []*os.File
	var results []string

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			// files opened so far are leaked
			return nil, fmt.Errorf("failed to open %s: %w", path, err)
		}
		files = append(files, f)
	}

	for _, f := range files {
		buf := make([]byte, 1024)
		n, _ := f.Read(buf)
		results = append(results, string(buf[:n]))
	}
	// None of the files are closed

	return results, nil
}

// MakeHTTPRequest creates an HTTP request and reads the response body
// but does not close the response body.
func (fp *FileProcessor) MakeHTTPRequest(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	// Missing: defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ============================================================================
// SECTION 12: BUGS — UNCHECKED ERRORS
// ============================================================================

// ConfigWriter handles writing configuration data to disk. Multiple
// methods ignore error return values from I/O operations.
type ConfigWriter struct {
	basePath string
}

// WriteConfig creates a file and writes data to it, ignoring all errors.
// If os.Create fails, the nil file pointer will cause a panic.
func (cw *ConfigWriter) WriteConfig(name string, data []byte) {
	path := cw.basePath + "/" + name
	f, _ := os.Create(path) // error ignored
	f.Write(data)           // f could be nil
	f.Close()               // f could be nil
}

// WriteMultipleConfigs writes several config files, ignoring errors
// at each step.
func (cw *ConfigWriter) WriteMultipleConfigs(configs map[string][]byte) {
	for name, data := range configs {
		path := cw.basePath + "/" + name
		f, _ := os.Create(path)
		f.Write(data)
		f.Sync()
		f.Close()
	}
}

// AppendToLog opens a log file and appends a message without checking
// any errors.
func (cw *ConfigWriter) AppendToLog(msg string) {
	f, _ := os.OpenFile(cw.basePath+"/app.log", os.O_APPEND|os.O_WRONLY, 0644)
	fmt.Fprintln(f, time.Now().Format(time.RFC3339), msg)
	f.Close()
}

// UpdateJSON reads a JSON file, modifies it, and writes it back without
// checking for errors at any stage.
func (cw *ConfigWriter) UpdateJSON(path string, key string, value string) {
	data, _ := os.ReadFile(path)
	var config map[string]interface{}
	json.Unmarshal(data, &config)
	config[key] = value
	updated, _ := json.Marshal(config)
	os.WriteFile(path, updated, 0644)
}

// ============================================================================
// SECTION 13: PERFORMANCE — INEFFICIENT PATTERNS
// ============================================================================

// ReportBuilder generates reports by concatenating strings in loops,
// resulting in O(n²) time complexity.
type ReportBuilder struct {
	header string
	footer string
}

// NewReportBuilder creates a new report builder.
func NewReportBuilder(header, footer string) *ReportBuilder {
	return &ReportBuilder{header: header, footer: footer}
}

// BuildCSVReport creates a CSV report by concatenating strings in a
// loop. Each concatenation allocates a new string, making this O(n²).
func (rb *ReportBuilder) BuildCSVReport(headers []string, rows [][]string) string {
	report := rb.header + "\n"
	report += strings.Join(headers, ",") + "\n"

	for _, row := range rows {
		line := ""
		for j, cell := range row {
			if j > 0 {
				line += ","
			}
			line += cell
		}
		report += line + "\n"
	}

	report += rb.footer
	return report
}

// BuildTextReport builds a formatted text report using string
// concatenation in nested loops.
func (rb *ReportBuilder) BuildTextReport(sections map[string][]string) string {
	report := ""
	report += "=" + strings.Repeat("=", 78) + "\n"
	report += rb.header + "\n"
	report += "=" + strings.Repeat("=", 78) + "\n\n"

	for section, items := range sections {
		report += "## " + section + "\n"
		report += strings.Repeat("-", 40) + "\n"
		for i, item := range items {
			report += fmt.Sprintf("  %d. %s\n", i+1, item)
		}
		report += "\n"
	}

	report += "=" + strings.Repeat("=", 78) + "\n"
	report += rb.footer + "\n"
	return report
}

// FindDuplicates uses a naive O(n²) algorithm to find duplicates
// in a slice instead of using a map.
func FindDuplicates(items []string) []string {
	var duplicates []string
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i] == items[j] {
				found := false
				for _, d := range duplicates {
					if d == items[i] {
						found = true
						break
					}
				}
				if !found {
					duplicates = append(duplicates, items[i])
				}
			}
		}
	}
	return duplicates
}

// CompileRegexInLoop compiles the same regex pattern on every iteration
// instead of compiling once and reusing it.
func CompileRegexInLoop(patterns []string, inputs []string) []bool {
	results := make([]bool, len(inputs))
	for i, input := range inputs {
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern) // compiled every iteration
			if re.MatchString(input) {
				results[i] = true
				break
			}
		}
	}
	return results
}

// ProcessWithoutPreallocation repeatedly appends to a slice without
// pre-allocating capacity, causing many reallocations.
func ProcessWithoutPreallocation(items []string) []string {
	var result []string // should be: make([]string, 0, len(items))
	for _, item := range items {
		processed := strings.TrimSpace(item)
		processed = strings.ToLower(processed)
		processed = strings.ReplaceAll(processed, " ", "_")
		result = append(result, processed)
	}
	return result
}

// ============================================================================
// SECTION 14: BUGS — MUTEX AND SYNC ISSUES
// ============================================================================

// SafeCache is a thread-safe cache, but CopySafeCache passes it by
// value, which copies the mutex — a well-known Go bug.
type SafeCache struct {
	mu    sync.Mutex
	data  map[string]string
	stats CacheStats
}

// CacheStats tracks cache performance metrics.
type CacheStats struct {
	mu     sync.RWMutex
	hits   int
	misses int
}

// NewSafeCache creates a new SafeCache.
func NewSafeCache() *SafeCache {
	return &SafeCache{
		data: make(map[string]string),
	}
}

// Get retrieves a value from the cache.
func (sc *SafeCache) Get(key string) (string, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	val, ok := sc.data[key]
	if ok {
		sc.stats.hits++
	} else {
		sc.stats.misses++
	}
	return val, ok
}

// Set stores a value in the cache.
func (sc *SafeCache) Set(key, value string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.data[key] = value
}

// CopySafeCache copies a SafeCache by value, which copies the embedded
// sync.Mutex. This is a bug — mutexes must not be copied after first use.
func CopySafeCache(c SafeCache) SafeCache {
	return c
}

// BackupCache creates a backup by copying the cache value.
func BackupCache(c SafeCache) {
	backup := c // copies the mutex
	_ = backup
}

// ============================================================================
// SECTION 15: BUGS — BOUNDS CHECKS AND OFF-BY-ONE
// ============================================================================

// DataAnalyzer provides data analysis utilities that operate on slices.
// Several methods lack proper bounds checking.
type DataAnalyzer struct {
	precision int
}

// GetLastN returns the last N elements from a slice. Panics if the
// slice has fewer than n elements.
func (da *DataAnalyzer) GetLastN(items []string, n int) []string {
	return items[len(items)-n:] // panics if len(items) < n
}

// GetRange returns elements between start and end indices without
// bounds checking.
func (da *DataAnalyzer) GetRange(items []string, start, end int) []string {
	return items[start:end] // no bounds validation
}

// Average calculates the average of a slice of numbers. Does not
// handle the empty slice case, causing division by zero.
func (da *DataAnalyzer) Average(values []float64) float64 {
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values)) // division by zero if empty
}

// GetMedian finds the median value. Panics on empty input.
func (da *DataAnalyzer) GetMedian(values []float64) float64 {
	mid := len(values) / 2
	return values[mid] // panics if empty
}

// SafeGet attempts to safely get an element but has an off-by-one error.
func (da *DataAnalyzer) SafeGet(items []string, index int) string {
	if index > len(items) { // should be >= len(items)
		return ""
	}
	return items[index]
}

// ============================================================================
// SECTION 16: SECURITY — SENSITIVE DATA EXPOSURE
// ============================================================================

// AuthService handles authentication. Error messages leak sensitive
// information to callers.
type AuthService struct {
	db        *sql.DB
	jwtSecret string
}

// NewAuthService creates a new AuthService.
func NewAuthService(db *sql.DB) *AuthService {
	return &AuthService{
		db:        db,
		jwtSecret: JWTSigningSecret,
	}
}

// Login attempts to authenticate a user. Error messages contain
// sensitive details about the database connection and query.
func (as *AuthService) Login(username, password string) (string, error) {
	query := "SELECT id, password_hash FROM users WHERE username = '" + username + "'"
	var id int
	var storedHash string
	err := as.db.QueryRow(query).Scan(&id, &storedHash)
	if err != nil {
		return "", fmt.Errorf("database query failed for user %s on host %s: %w",
			username, DatabaseHost, err)
	}

	cs := NewCryptoService()
	if cs.HashPassword(password) != storedHash {
		return "", fmt.Errorf("invalid password for user %s (hash mismatch: got %s, expected %s)",
			username, cs.HashPassword(password), storedHash)
	}

	token := cs.GenerateSessionToken()
	return token, nil
}

// ConnectDB establishes a database connection. The error message
// includes the full DSN with embedded credentials.
func ConnectDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database with DSN=%s: %w", dsn, err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database ping failed (dsn=%s, password=%s): %w",
			dsn, DatabasePassword, err)
	}
	return db, nil
}

// HandleAuthError returns verbose error information in the HTTP response,
// including stack traces and internal details.
func HandleAuthError(w http.ResponseWriter, err error, username string) {
	errorDetail := map[string]interface{}{
		"error":    err.Error(),
		"username": username,
		"dbHost":   DatabaseHost,
		"dbName":   DatabaseName,
		"stack":    fmt.Sprintf("%+v", err),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(errorDetail)
}

// ============================================================================
// SECTION 17: BUGS — DEADLOCK POTENTIAL
// ============================================================================

// BankAccount represents a bank account with a mutex for thread safety.
type BankAccount struct {
	mu      sync.Mutex
	id      string
	balance int64
	history []string
}

// NewBankAccount creates a new BankAccount.
func NewBankAccount(id string, initialBalance int64) *BankAccount {
	return &BankAccount{
		id:      id,
		balance: initialBalance,
		history: make([]string, 0),
	}
}

// Transfer moves money between two accounts. Locks are acquired in
// arbitrary order depending on call order, creating a deadlock risk
// when Transfer(a,b) and Transfer(b,a) run concurrently.
func (ba *BankAccount) Transfer(to *BankAccount, amount int64) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	to.mu.Lock() // deadlock if reverse transfer is in progress
	defer to.mu.Unlock()

	if ba.balance < amount {
		return fmt.Errorf("insufficient funds: have %d, need %d", ba.balance, amount)
	}

	ba.balance -= amount
	to.balance += amount

	timestamp := time.Now().Format(time.RFC3339)
	ba.history = append(ba.history, fmt.Sprintf("%s: sent %d to %s", timestamp, amount, to.id))
	to.history = append(to.history, fmt.Sprintf("%s: received %d from %s", timestamp, amount, ba.id))

	return nil
}

// AuditAccounts locks multiple accounts for auditing. If called
// concurrently with different orderings, deadlock can occur.
func AuditAccounts(accounts []*BankAccount) map[string]int64 {
	balances := make(map[string]int64)
	for _, acc := range accounts {
		acc.mu.Lock()
	}

	for _, acc := range accounts {
		balances[acc.id] = acc.balance
	}

	for _, acc := range accounts {
		acc.mu.Unlock()
	}

	return balances
}

// ============================================================================
// SECTION 18: BUGS — INTEGER OVERFLOW AND TYPE CONVERSION
// ============================================================================

// DataConverter provides various data conversion utilities. Several
// methods perform unsafe narrowing conversions without range checking.
type DataConverter struct{}

// ParsePort converts a string to int16 without checking if the value
// fits in 16 bits. Values above 32767 or below -32768 are silently
// truncated.
func (dc *DataConverter) ParsePort(s string) (int16, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return int16(port), nil // silent truncation
}

// ParseUint8 converts a string to uint8 without range checking.
func (dc *DataConverter) ParseUint8(s string) (uint8, error) {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return uint8(val), nil // wraps on values > 255
}

// IntToFloat converts a large int64 to float64, potentially losing
// precision for values larger than 2^53.
func (dc *DataConverter) IntToFloat(n int64) float64 {
	return float64(n) // precision loss for large values
}

// PointerArithmetic uses unsafe.Pointer for raw memory access.
func (dc *DataConverter) PointerArithmetic(data []byte) int {
	if len(data) < 8 {
		return 0
	}
	ptr := unsafe.Pointer(&data[0])
	return *(*int)(ptr) // platform-dependent, alignment issues
}

// MultiplyWithoutOverflowCheck multiplies two int32 values without
// checking for overflow.
func (dc *DataConverter) MultiplyWithoutOverflowCheck(a, b int32) int32 {
	return a * b // can silently overflow
}

// ============================================================================
// SECTION 19: SECURITY — PERMISSIVE CORS AND MISSING SECURITY HEADERS
// ============================================================================

// SecurityMiddleware sets up security headers for HTTP responses.
// The CORS configuration is overly permissive and several important
// security headers are missing.
type SecurityMiddleware struct{}

// SetupCORS configures CORS headers with a wildcard origin combined
// with credentials, which is insecure and browsers will reject.
func (sm *SecurityMiddleware) SetupCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	// Reflects any origin — equivalent to wildcard but with credentials
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "86400")
	// Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
	// Strict-Transport-Security, X-XSS-Protection
}

// HandleCORS is middleware that applies the permissive CORS policy
// to all requests.
func (sm *SecurityMiddleware) HandleCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sm.SetupCORS(w, r)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// SECTION 20: BUGS — SILENT ERROR HANDLING AND PANIC RECOVERY
// ============================================================================

// ErrorHandler provides middleware and utility functions for error
// handling. Several implementations silently swallow errors or
// suppress panics without logging.
type ErrorHandler struct {
	logger *log.Logger
}

// NewErrorHandler creates a new ErrorHandler.
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		logger: log.New(os.Stdout, "[app] ", log.LstdFlags),
	}
}

// RecoveryMiddleware catches panics and returns a 500 response.
// The panic value is silently discarded without logging.
func (eh *ErrorHandler) RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Panic is silently swallowed — should be logged
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RetryWithSilentErrors retries an operation up to maxRetries times,
// silently ignoring all errors until the final attempt.
func (eh *ErrorHandler) RetryWithSilentErrors(fn func() error, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		// All intermediate errors are silently discarded
	}
	return lastErr
}

// ProcessWithIgnoredErrors runs a batch of operations and ignores
// any that fail without recording which ones failed.
func (eh *ErrorHandler) ProcessWithIgnoredErrors(items []string) []string {
	var results []string
	for _, item := range items {
		result, err := riskyOperation(item)
		if err != nil {
			continue // silently skip failures
		}
		results = append(results, result)
	}
	return results
}

func riskyOperation(item string) (string, error) {
	if len(item) == 0 {
		return "", fmt.Errorf("empty item")
	}
	return strings.ToUpper(item), nil
}

// ============================================================================
// SECTION 21: MISCELLANEOUS ADDITIONAL ISSUES
// ============================================================================

// GlobalState uses package-level mutable state accessed from HTTP
// handlers running in concurrent goroutines.
var (
	globalCounter int
	globalCache   = make(map[string]string)
	globalConfig  map[string]string
)

// IncrementGlobal modifies package-level state without synchronization.
func IncrementGlobal() {
	globalCounter++
}

// SetGlobalCache writes to a package-level map without synchronization.
func SetGlobalCache(key, value string) {
	globalCache[key] = value
}

// GetGlobalConfig reads from an uninitialized package-level map.
if globalConfig == nil {
	return ""
}
return globalConfig[key]
}

// OpenConnection establishes a TCP connection with no timeout, which
// could hang indefinitely.
func OpenConnection(host string) (net.Conn, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	// No deadline set — reads/writes can block forever
	return conn, nil
}

// LogSensitiveData logs request details including authorization headers
// and cookies to stdout.
func LogSensitiveData(r *http.Request) {
	log.Printf("Request: %s %s", r.Method, r.URL.String())
	log.Printf("Authorization: %s", r.Header.Get("Authorization"))
	log.Printf("Cookies: %v", r.Cookies())
	log.Printf("Remote: %s", r.RemoteAddr)
	body, _ := io.ReadAll(r.Body)
	log.Printf("Body: %s", string(body))
}

// UnsafeHTMLTemplate constructs an HTML template by directly
// interpolating user input from form values.
func UnsafeHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	title := r.FormValue("title")
	content := r.FormValue("content")
	author := r.FormValue("author")
	callback := r.FormValue("callback")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <script src="%s"></script>
</head>
<body>
    <article>
        <h1>%s</h1>
        <p class="author">By %s</p>
        <div class="content">%s</div>
    </article>
    <script>
        document.title = "%s";
        if (typeof window.onPageLoad === 'function') {
            window.onPageLoad("%s");
        }
    </script>
</body>
</html>`, title, callback, title, author, content, title, callback)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// UnvalidatedRedirect redirects to a user-controlled URL without
// validating that it points to a trusted destination.
func UnvalidatedRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("redirect_url")
	http.Redirect(w, r, target, http.StatusFound)
}

// WeakSessionID generates a session ID from predictable values.
func WeakSessionID(username string) string {
	timestamp := time.Now().Unix()
	raw := fmt.Sprintf("%s:%d", username, timestamp)
	h := md5.Sum([]byte(raw))
	return hex.EncodeToString(h[:])
}

// DisabledTLSVerification creates an HTTP client that skips TLS
// certificate verification.
func DisabledTLSVerification() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// In a real implementation this would use:
		// Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		// Omitted here to avoid import, but the pattern is the security issue
	}
}

// HardcodedIPAccess checks access based on a hardcoded IP allowlist
// that can be spoofed via X-Forwarded-For.
func HardcodedIPAccess(r *http.Request) bool {
	allowedIPs := []string{"10.0.0.1", "10.0.0.2", "192.168.1.100"}
	clientIP := r.Header.Get("X-Forwarded-For") // easily spoofed
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	for _, ip := range allowedIPs {
		if strings.Contains(clientIP, ip) { // substring match is too loose
			return true
		}
	}
	return false
}

// WriteWorldReadable creates a file with 0666 permissions, making it
// readable and writable by all users on the system.
func WriteWorldReadable(path string, data []byte) error {
	return os.WriteFile(path, data, 0666)
}

// TempFileInPredictableLocation creates a temp file in /tmp with a
// predictable name, enabling symlink attacks.
func TempFileInPredictableLocation(name string) (*os.File, error) {
	path := "/tmp/" + name
	return os.Create(path)
}

// ExecWithEnvLeak passes the full environment to a subprocess, which
// may contain sensitive variables like API keys and tokens.
func ExecWithEnvLeak(command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ() // leaks all env vars including secrets
	return cmd.Output()
}
