package recon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type reconEvent struct {
	EventType  string         `json:"event_type"`
	SrcIP      string         `json:"src_ip"`
	Protocol   string         `json:"protocol"`
	ParsedData map[string]any `json:"parsed_data"`
}

type EarlyAlerter struct {
	backendURL    string
	honeypotToken string
	client        *http.Client
	alerted       map[string]time.Time
	mu            sync.Mutex
}

func NewEarlyAlerter(backendURL, honeypotToken string) *EarlyAlerter {
	return &EarlyAlerter{
		backendURL:    backendURL,
		honeypotToken: honeypotToken,
		client:        &http.Client{Timeout: 5 * time.Second},
		alerted:       make(map[string]time.Time),
	}
}

func (a *EarlyAlerter) SendReconAlert(ip, reconType string, data map[string]any) {
	key := fmt.Sprintf("%s:%s", ip, reconType)

	a.mu.Lock()
	if last, ok := a.alerted[key]; ok {
		if time.Since(last) < 5*time.Minute {
			a.mu.Unlock()
			return
		}
	}
	a.alerted[key] = time.Now()
	a.mu.Unlock()

	eventTypeMap := map[string]string{
		"port_scan":    "port_scan",
		"dns_recon":    "dns_recon",
		"threat_intel": "threat_intel",
		"banner_grab":  "banner_grab",
	}

	eventType, ok := eventTypeMap[reconType]
	if !ok {
		eventType = "port_scan"
	}

	payload := reconEvent{
		EventType:  eventType,
		SrcIP:      ip,
		Protocol:   "tcp",
		ParsedData: data,
	}

	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal recon alert")
			return
		}

		url := fmt.Sprintf("%s/api/logs/ingest", a.backendURL)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Honeypot-Token", a.honeypotToken)
		}
		var resp *http.Response
		if err == nil {
			resp, err = a.client.Do(req)
		}
		if err != nil {
			log.Error().Err(err).Str("ip", ip).Msg("Failed to send recon alert to backend")
			return
		}
		defer resp.Body.Close()

		log.Info().
			Str("ip", ip).
			Str("type", reconType).
			Int("status", resp.StatusCode).
			Msg("Early recon alert sent")
	}()
}

func (a *EarlyAlerter) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for k, t := range a.alerted {
		if t.Before(cutoff) {
			delete(a.alerted, k)
		}
	}
}
