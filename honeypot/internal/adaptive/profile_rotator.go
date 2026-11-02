package adaptive

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type Profile struct {
	Name       string
	SSHBanner  string
	Hostname   string
	ServerHeader string
	OSRelease  string
}

var profiles = []Profile{
	{
		Name:         "ubuntu-prod",
		SSHBanner:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		Hostname:     "prod-server-01",
		ServerHeader: "Apache/2.4.52 (Ubuntu)",
		OSRelease:    "Ubuntu 22.04.3 LTS",
	},
	{
		Name:         "debian-staging",
		SSHBanner:    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
		Hostname:     "staging-web-02",
		ServerHeader: "nginx/1.18.0 (Debian)",
		OSRelease:    "Debian GNU/Linux 10 (buster)",
	},
	{
		Name:         "ubuntu-dev",
		SSHBanner:    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
		Hostname:     "dev-api-server",
		ServerHeader: "nginx/1.24.0",
		OSRelease:    "Ubuntu 20.04.6 LTS",
	},
}

type ProfileRotator struct {
	mu       sync.RWMutex
	current  Profile
	interval time.Duration
	quit     chan struct{}
}

func NewProfileRotator(intervalMinutes int) *ProfileRotator {
	pr := &ProfileRotator{
		current:  profiles[0],
		interval: time.Duration(intervalMinutes) * time.Minute,
		quit:     make(chan struct{}),
	}
	return pr
}

func (pr *ProfileRotator) Start() {
	log.Info().
		Str("profile", pr.current.Name).
		Dur("interval", pr.interval).
		Msg("Profile rotator started")

	go func() {
		ticker := time.NewTicker(pr.interval)
		defer ticker.Stop()
		idx := 0
		for {
			select {
			case <-pr.quit:
				return
			case <-ticker.C:
				idx = (idx + 1) % len(profiles)
				pr.mu.Lock()
				pr.current = profiles[idx]
				pr.mu.Unlock()

				log.Info().
					Str("new_profile", pr.current.Name).
					Str("hostname", pr.current.Hostname).
					Msg("Honeypot profile rotated")
			}
		}
	}()
}

func (pr *ProfileRotator) Stop() {
	close(pr.quit)
}

func (pr *ProfileRotator) GetCurrent() Profile {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.current
}

func (pr *ProfileRotator) GetHostname() string {
	return pr.GetCurrent().Hostname
}

func (pr *ProfileRotator) GetSSHBanner() string {
	return pr.GetCurrent().SSHBanner
}