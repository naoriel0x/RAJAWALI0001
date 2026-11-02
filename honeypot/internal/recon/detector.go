package recon

import (
	"github.com/rajawali/honeypot/config"
	"github.com/rs/zerolog/log"
)

type Detector struct {
	cfg          *config.Config
	alerter      *EarlyAlerter
	portScanner  *PortScanner
	intelChecker *ThreatIntelChecker
	quit         chan struct{}
}

func NewDetector(cfg *config.Config) *Detector {
	alerter := NewEarlyAlerter(cfg.BackendURL, cfg.HoneypotToken)
	portScanner := NewPortScanner(alerter, cfg.ReconWindow, cfg.ReconPortThresh)
	intelChecker := NewThreatIntelChecker(cfg.AbuseIPDBKey, alerter)

	return &Detector{
		cfg:          cfg,
		alerter:      alerter,
		portScanner:  portScanner,
		intelChecker: intelChecker,
		quit:         make(chan struct{}),
	}
}

func (d *Detector) Start() {
	if !d.cfg.ReconEnabled {
		log.Info().Msg("Layer 1 recon detection disabled via config")
		return
	}

	d.portScanner.Start()

	log.Info().
		Int("port_threshold", d.cfg.ReconPortThresh).
		Int("window_sec", d.cfg.ReconWindow).
		Msg("Layer 1 — Recon Detector fully active")
}

func (d *Detector) Stop() {
	close(d.quit)
	d.portScanner.Stop()
	log.Info().Msg("Layer 1 — Recon Detector stopped")
}

func (d *Detector) CheckIP(ip string) {
	d.intelChecker.CheckIP(ip)
}
