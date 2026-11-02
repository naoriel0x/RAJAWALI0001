package recon

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type IPReputation struct {
	IsPublic            bool    `json:"isPublic"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode         string  `json:"countryCode"`
	TotalReports        int     `json:"totalReports"`
	ISP                 string  `json:"isp"`
	Domain              string  `json:"domain"`
}

type abuseIPDBResponse struct {
	Data IPReputation `json:"data"`
}

type ThreatIntelChecker struct {
	apiKey  string
	client  *resty.Client
	cache   map[string]*cachedResult
	mu      sync.Mutex
	alerter *EarlyAlerter
}

type cachedResult struct {
	rep       IPReputation
	cachedAt  time.Time
}

func NewThreatIntelChecker(apiKey string, alerter *EarlyAlerter) *ThreatIntelChecker {
	return &ThreatIntelChecker{
		apiKey:  apiKey,
		client:  resty.New().SetTimeout(8 * time.Second),
		cache:   make(map[string]*cachedResult),
		alerter: alerter,
	}
}

func (t *ThreatIntelChecker) CheckIP(ip string) {
	if t.apiKey == "" {
		return
	}

	go func() {
		rep, err := t.queryAbuseIPDB(ip)
		if err != nil {
			log.Error().Err(err).Str("ip", ip).Msg("Threat intel check failed")
			return
		}

		if rep.AbuseConfidenceScore >= 25 || rep.TotalReports > 5 {
			log.Warn().
				Str("ip", ip).
				Int("score", rep.AbuseConfidenceScore).
				Int("reports", rep.TotalReports).
				Str("isp", rep.ISP).
				Msg("Known malicious IP detected")

			t.alerter.SendReconAlert(ip, "threat_intel", map[string]any{
				"abuse_confidence": rep.AbuseConfidenceScore,
				"total_reports":    rep.TotalReports,
				"country":          rep.CountryCode,
				"isp":              rep.ISP,
				"message":          fmt.Sprintf("IP flagged on AbuseIPDB with %d%% confidence", rep.AbuseConfidenceScore),
			})
		}
	}()
}

func (t *ThreatIntelChecker) queryAbuseIPDB(ip string) (*IPReputation, error) {
	t.mu.Lock()
	if cached, ok := t.cache[ip]; ok {
		if time.Since(cached.cachedAt) < 24*time.Hour {
			t.mu.Unlock()
			return &cached.rep, nil
		}
	}
	t.mu.Unlock()

	resp, err := t.client.R().
		SetHeader("Key", t.apiKey).
		SetHeader("Accept", "application/json").
		SetQueryParams(map[string]string{
			"ipAddress":    ip,
			"maxAgeInDays": "90",
		}).
		Get("https://api.abuseipdb.com/api/v2/check")

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var result abuseIPDBResponse
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	t.mu.Lock()
	t.cache[ip] = &cachedResult{rep: result.Data, cachedAt: time.Now()}
	t.mu.Unlock()

	return &result.Data, nil
}