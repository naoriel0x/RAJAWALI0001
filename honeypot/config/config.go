package config

import (
	"os"
	"strconv"

	"github.com/rs/zerolog/log"
)

type Config struct {
	Env           string
	BackendURL    string
	HoneypotToken string

	SSHPort  int
	HTTPPort int

	SSHBanner   string
	SSHHostname string

	AbuseIPDBKey string

	ReconEnabled    bool
	ReconWindow     int
	ReconPortThresh int
}

func Load() *Config {
	cfg := &Config{
		Env:             getEnv("ENV", "development"),
		BackendURL:      getEnv("BACKEND_URL", "http://localhost:8000"),
		HoneypotToken:   getEnv("HONEYPOT_TOKEN", ""),
		SSHPort:         getEnvInt("SSH_PORT", 2222),
		HTTPPort:        getEnvInt("HTTP_PORT", 8080),
		SSHBanner:       getEnv("SSH_BANNER", "Ubuntu 22.04.3 LTS"),
		SSHHostname:     getEnv("SSH_HOSTNAME", "prod-server-01"),
		AbuseIPDBKey:    getEnv("ABUSE_CH_API_KEY", ""),
		ReconEnabled:    getEnvBool("RECON_ENABLED", true),
		ReconWindow:     getEnvInt("RECON_WINDOW_SECONDS", 60),
		ReconPortThresh: getEnvInt("RECON_PORT_THRESHOLD", 10),
	}

	log.Info().
		Str("env", cfg.Env).
		Str("backend", cfg.BackendURL).
		Int("ssh_port", cfg.SSHPort).
		Int("http_port", cfg.HTTPPort).
		Bool("recon_enabled", cfg.ReconEnabled).
		Msg("RAJAWALI config loaded")

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Warn().Str("key", key).Str("value", v).Msg("Invalid int env var, using fallback")
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
