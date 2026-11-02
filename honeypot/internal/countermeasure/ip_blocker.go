package countermeasure

import (
	"os/exec"
	"sync"

	"github.com/rs/zerolog/log"
)

type IPBlocker struct {
	mu      sync.Mutex
	blocked map[string]bool
}

func NewIPBlocker() *IPBlocker {
	return &IPBlocker{
		blocked: make(map[string]bool),
	}
}

func (b *IPBlocker) Block(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.blocked[ip] {
		log.Debug().Str("ip", ip).Msg("IP already blocked")
		return nil
	}

	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("ip", ip).Msg("Failed to block IP via iptables")
		return err
	}

	b.blocked[ip] = true
	log.Warn().Str("ip", ip).Msg("IP blocked via iptables")
	return nil
}

func (b *IPBlocker) Unblock(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.blocked[ip] {
		return nil
	}

	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("ip", ip).Msg("Failed to unblock IP")
		return err
	}

	delete(b.blocked, ip)
	log.Info().Str("ip", ip).Msg("IP unblocked")
	return nil
}

func (b *IPBlocker) IsBlocked(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked[ip]
}

func (b *IPBlocker) BlockedList() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	list := make([]string, 0, len(b.blocked))
	for ip := range b.blocked {
		list = append(list, ip)
	}
	return list
}