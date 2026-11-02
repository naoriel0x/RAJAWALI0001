package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

var lurePathKeywords = []string{
	"admin", "backup", "config", "secret", "private",
	"db", "database", "credentials", "passwd", "shadow",
	".git", ".env", "wp-admin", "phpmyadmin",
}

var crawlerUserAgents = []string{
	"nmap", "nikto", "gobuster", "dirbuster", "masscan",
	"sqlmap", "zgrab", "shodan", "censys", "python-requests",
	"curl", "wget", "go-http-client",
}

type Handler struct {
	logger *Logger
}

func NewHandler(logger *Logger) *Handler {
	return &Handler{logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srcIP, srcPort := parseRemoteAddr(r.RemoteAddr)
	path := r.URL.Path
	method := r.Method
	userAgent := r.Header.Get("User-Agent")

	headers := make(map[string]any)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	log.Info().
		Str("ip", srcIP).
		Str("method", method).
		Str("path", path).
		Str("ua", userAgent).
		Msg("HTTP request received")

	isCrawler := h.detectCrawler(userAgent)
	isLure := h.isLurePath(path)

	if isLure {
		h.logger.LogLureAccess(srcIP, srcPort, path)
		h.serveLure(w, path)
		return
	}

	if isCrawler {
		h.logger.LogCrawl(srcIP, srcPort, path, userAgent)
	} else {
		h.logger.LogRequest(srcIP, srcPort, method, path, userAgent, headers)
	}

	h.serveResponse(w, r)
}

func (h *Handler) serveResponse(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
	w.Header().Set("X-Powered-By", "PHP/8.1.2")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	switch {
	case path == "/" || path == "/index.html":
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakeIndexHTML())

	case strings.HasPrefix(path, "/api/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"Unauthorized","message":"Authentication required"}`)

	case path == "/login" || path == "/admin/login":
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakeLoginHTML())

	case path == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config/\nDisallow: /private/\n")

	case path == "/health":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)

	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, fake404HTML())
	}
}

func (h *Handler) serveLure(w http.ResponseWriter, path string) {
	w.Header().Set("Server", "Apache/2.4.52 (Ubuntu)")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if strings.Contains(path, "credential") || strings.Contains(path, "passwd") {
		fmt.Fprint(w, `{"users":[{"username":"admin","password":"$2y$10$fakehashedpassword"},{"username":"root","password":"$2y$10$fakehashedpassword2"}]}`)
		return
	}
	if strings.Contains(path, "config") || strings.Contains(path, ".env") {
		fmt.Fprint(w, `{"db_host":"10.0.0.5","db_user":"app_user","db_pass":"Sup3rS3cret!","db_name":"production"}`)
		return
	}
	if strings.Contains(path, "backup") {
		fmt.Fprint(w, `{"backup_path":"/var/backups/db_backup_2024.sql.gz","size":"2.3GB","encrypted":false}`)
		return
	}

	fmt.Fprint(w, `{"status":"found","data":"restricted"}`)
}

func (h *Handler) detectCrawler(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, crawler := range crawlerUserAgents {
		if strings.Contains(ua, crawler) {
			return true
		}
	}
	return false
}

func (h *Handler) isLurePath(path string) bool {
	p := strings.ToLower(path)
	for _, keyword := range lurePathKeywords {
		if strings.Contains(p, keyword) {
			return true
		}
	}
	return false
}

func parseRemoteAddr(addr string) (string, int) {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return addr, 0
	}
	ip := strings.Join(parts[:len(parts)-1], ":")
	port := 0
	fmt.Sscanf(parts[len(parts)-1], "%d", &port)
	return ip, port
}

func fakeIndexHTML() string {
	return `<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body>
<h1>Internal System Portal</h1>
<p>Please <a href="/login">login</a> to continue.</p>
<!-- TODO: remove debug endpoint /api/debug before production -->
</body></html>`
}

func fakeLoginHTML() string {
	return `<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h2>System Login</h2>
<form method="POST" action="/api/auth">
  <input type="text" name="username" placeholder="Username"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <button type="submit">Login</button>
</form>
</body></html>`
}

func fake404HTML() string {
	return `<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>`
}