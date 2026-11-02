package recon

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type portHit struct {
	port      int
	timestamp time.Time
}

type scanTracker struct {
	mu      sync.Mutex
	hits    map[string][]portHit
	window  time.Duration
	threshold int
}

func newScanTracker(windowSec, threshold int) *scanTracker {
	return &scanTracker{
		hits:      make(map[string][]portHit),
		window:    time.Duration(windowSec) * time.Second,
		threshold: threshold,
	}
}

func (t *scanTracker) record(ip string, port int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-t.window)

	filtered := t.hits[ip][:0]
	for _, h := range t.hits[ip] {
		if h.timestamp.After(cutoff) {
			filtered = append(filtered, h)
		}
	}
	filtered = append(filtered, portHit{port: port, timestamp: now})
	t.hits[ip] = filtered

	return len(filtered) >= t.threshold
}

func (t *scanTracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.window * 2)
	for ip, hits := range t.hits {
		var fresh []portHit
		for _, h := range hits {
			if h.timestamp.After(cutoff) {
				fresh = append(fresh, h)
			}
		}
		if len(fresh) == 0 {
			delete(t.hits, ip)
		} else {
			t.hits[ip] = fresh
		}
	}
}

type PortScanner struct {
	tracker  *scanTracker
	alerter  *EarlyAlerter
	ports    []int
	quit     chan struct{}
	listeners []net.Listener
}

func NewPortScanner(alerter *EarlyAlerter, windowSec, threshold int) *PortScanner {
	decoyPorts := []int{
		21, 23, 25, 80, 110, 143, 443,
		3306, 5432, 6379, 8443, 9200, 27017,
	}

	return &PortScanner{
		tracker:  newScanTracker(windowSec, threshold),
		alerter:  alerter,
		ports:    decoyPorts,
		quit:     make(chan struct{}),
	}
}

func (ps *PortScanner) Start() {
	for _, port := range ps.ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			log.Debug().Int("port", port).Msg("Recon port already in use, skipping")
			continue
		}
		ps.listeners = append(ps.listeners, ln)
		go ps.listenPort(ln, port)
	}

	go ps.runCleanup()

	log.Info().
		Int("decoy_ports", len(ps.listeners)).
		Msg("Port scan detector active")
}

func (ps *PortScanner) Stop() {
	close(ps.quit)
	for _, ln := range ps.listeners {
		ln.Close()
	}
}

func (ps *PortScanner) listenPort(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ps.quit:
				return
			default:
				continue
			}
		}

		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		conn.Close()

		log.Debug().Str("ip", ip).Int("port", port).Msg("Decoy port hit")

		isScanning := ps.tracker.record(ip, port)
		if isScanning {
			log.Warn().
				Str("ip", ip).
				Int("port", port).
				Msg("Port scan detected — early warning triggered")

			ps.alerter.SendReconAlert(ip, "port_scan", map[string]any{
				"port":    port,
				"message": "IP hitting multiple decoy ports — reconnaissance detected",
			})
		}
	}
}

func (ps *PortScanner) runCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ps.quit:
			return
		case <-ticker.C:
			ps.tracker.cleanup()
		}
	}
}