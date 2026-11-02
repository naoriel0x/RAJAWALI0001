package recon

import (
	"strings"

	"github.com/rs/zerolog/log"
)

var suspiciousDNSPatterns = []string{
	"admin", "vpn", "internal", "dev", "staging",
	"backup", "db", "database", "secret", "private",
	"api", "mail", "smtp", "ftp", "ssh",
}

type DNSMonitor struct {
	alerter *EarlyAlerter
}

func NewDNSMonitor(alerter *EarlyAlerter) *DNSMonitor {
	return &DNSMonitor{alerter: alerter}
}

func (d *DNSMonitor) Inspect(srcIP, query string) {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return
	}

	for _, pattern := range suspiciousDNSPatterns {
		if strings.Contains(query, pattern) {
			log.Warn().
				Str("ip", srcIP).
				Str("query", query).
				Str("pattern", pattern).
				Msg("Suspicious DNS recon detected")

			d.alerter.SendReconAlert(srcIP, "dns_recon", map[string]any{
				"query":   query,
				"pattern": pattern,
				"message": "Suspicious DNS query indicating infrastructure reconnaissance",
			})
			return
		}
	}
}