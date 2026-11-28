package autopwn

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPorts is the reconnaissance set used when the caller does not pass
// one: the usual footholds plus the services the decision layer can exploit.
var DefaultPorts = []int{
	21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389,
	5432, 5900, 6379, 7001, 8080, 8443, 9000, 9200, 27017,
}

// PortFinding is one reachable TCP port plus whatever the service volunteered
// in its banner (and, for web ports, the Server header).
type PortFinding struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
	Product string `json:"product,omitempty"`
}

var webPorts = map[int]bool{80: true, 443: true, 8000: true, 8080: true, 8443: true, 9000: true, 9200: true}
var tlsPorts = map[int]bool{443: true, 8443: true}

// ScanTarget dials every port concurrently and reads a banner. It returns only
// the reachable ports, sorted, so two runs against the same host produce the
// same plan.
func ScanTarget(ctx context.Context, target string, ports []int, timeout time.Duration, workers int) []PortFinding {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if workers <= 0 {
		workers = 32
	}
	seen := make(map[int]bool, len(ports))
	uniq := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	sort.Ints(uniq)

	var (
		mu    sync.Mutex
		found []PortFinding
		sem   = make(chan struct{}, workers)
		wg    sync.WaitGroup
	)
	for _, port := range uniq {
		select {
		case <-ctx.Done():
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			f, ok := probePort(ctx, target, port, timeout)
			if !ok {
				return
			}
			mu.Lock()
			found = append(found, f)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
	return found
}

// probePort is one TCP connect + banner read. Open means "handshake completed";
// a silent service is still a finding, just without a product string.
func probePort(ctx context.Context, target string, port int, timeout time.Duration) (PortFinding, bool) {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return PortFinding{}, false
	}
	defer func() { _ = conn.Close() }()

	f := PortFinding{Port: port, Service: serviceForPort(port)}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if webPorts[port] {
		if tlsPorts[port] {
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: target}) //nolint:gosec // scanning lab targets
			if err := tc.Handshake(); err == nil {
				_, _ = tc.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n"))
				buf, _ := io.ReadAll(io.LimitReader(tc, 2048))
				f.Banner = firstLines(string(buf), 6)
			}
		} else {
			_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n"))
			buf, _ := io.ReadAll(io.LimitReader(conn, 2048))
			f.Banner = firstLines(string(buf), 6)
		}
	} else {
		if port == 6379 { // Redis answers PING without auth on misconfigured hosts
			_, _ = conn.Write([]byte("PING\r\n"))
		}
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			f.Banner = firstLines(string(buf[:n]), 3)
		}
	}
	f.Product, f.Service = classify(f.Service, f.Banner)
	return f, true
}

func firstLines(s string, n int) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	out := strings.Join(lines, " | ")
	if len(out) > 400 {
		out = out[:400] + "…"
	}
	return out
}

func serviceForPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 587:
		return "smtp"
	case 80, 8000, 8080, 9000:
		return "http"
	case 110:
		return "pop3"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 443, 8443:
		return "https"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 7001:
		return "weblogic"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	}
	return "unknown"
}

// productPatterns maps banner substrings to a canonical "product version" that
// the rule table can match on.
var productPatterns = []struct {
	needle  string
	product string
	service string
}{
	{"vsftpd 2.3.4", "vsftpd 2.3.4", "ftp"},
	{"proftpd", "proftpd", "ftp"},
	{"openssh", "openssh", "ssh"},
	{"apache/2.4.49", "apache 2.4.49", "http"},
	{"apache tomcat", "tomcat", "http"},
	{"apache-coyote", "tomcat", "http"},
	{"struts", "struts2", "http"},
	{"jenkins", "jenkins", "http"},
	{"weblogic", "weblogic", "http"},
	{"spring", "spring", "http"},
	{"microsoft-iis", "iis", "http"},
	{"nginx", "nginx", "http"},
	{"redis", "redis", "redis"},
	{"mysql", "mysql", "mysql"},
	{"mariadb", "mariadb", "mysql"},
	{"postgresql", "postgres", "postgres"},
	{"elasticsearch", "elasticsearch", "elasticsearch"},
	{"microsoft windows", "windows", "smb"},
	{"samba", "samba", "smb"},
	{"vmware", "vmware", "vcenter"},
}

// classify keeps the port-derived service unless the banner tells a better
// story, and extracts a product string for rule matching.
func classify(service, banner string) (product, svc string) {
	low := strings.ToLower(banner)
	svc = service
	for _, p := range productPatterns {
		if strings.Contains(low, p.needle) {
			product = p.product
			if p.service != "" {
				svc = p.service
			}
			break
		}
	}
	if product == "" && service == "smb" {
		product = "smb"
	}
	return product, svc
}
