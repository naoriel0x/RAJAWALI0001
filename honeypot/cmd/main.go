package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rajawali/honeypot/config"
	httphoney "github.com/rajawali/honeypot/internal/http"
	"github.com/rajawali/honeypot/internal/recon"
	sshhoney "github.com/rajawali/honeypot/internal/ssh"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("RAJAWALI Honeypot Engine starting...")
	cfg := config.Load()
	log.Info().
		Str("env", cfg.Env).
		Str("backend", cfg.BackendURL).
		Int("ssh_port", cfg.SSHPort).
		Int("http_port", cfg.HTTPPort).
		Msg("Config loaded")

	reconDetector := recon.NewDetector(cfg)
	go reconDetector.Start()
	log.Info().Msg("Layer 1 - Recon Detector started")

	sshServer := sshhoney.NewServer(cfg)
	go sshServer.Start()
	log.Info().Int("port", cfg.SSHPort).Msg("Layer 2 - SSH Honeypot started")

	httpServer := httphoney.NewServer(cfg)
	go httpServer.Start()
	log.Info().Int("port", cfg.HTTPPort).Msg("Layer 2 - HTTP Honeypot started")

	log.Info().Msg("RAJAWALI ready — waiting for attackers...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("RAJAWALI shutting down...")
	reconDetector.Stop()
	sshServer.Stop()
	httpServer.Stop()
}