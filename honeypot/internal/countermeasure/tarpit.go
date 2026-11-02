package countermeasure

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type TarpitEntry struct {
	IP        string
	DelayMs   int
	AppliedAt time.Time
	HitCount  int
}

type Tarpit struct {
	mu      sync.Mutex
	entries map[string]*TarpitEntry
	baseMs  int
	maxMs   int
}

func NewTarpit(baseDelayMs, maxDelayMs int) *Tarpit {
	return &Tarpit{
		entries: make(map[string]*TarpitEntry),
		baseMs:  baseDelayMs,
		maxMs:   maxDelayMs,
	}
}

func (t *Tarpit) Apply(ip string) {
	t.mu.Lock()
	entry, exists := t.entries[ip]
	if !exists {
		entry = &TarpitEntry{
			IP:      ip,
			DelayMs: t.baseMs,
		}
		t.entries[ip] = entry
	}

	entry.HitCount++
	entry.AppliedAt = time.Now()

	delay := entry.DelayMs
	entry.DelayMs = min(entry.DelayMs*2, t.maxMs)
	t.mu.Unlock()

	log.Info().
		Str("ip", ip).
		Int("delay_ms", delay).
		Int("hit_count", entry.HitCount).
		Msg("Tarpit applied")

	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (t *Tarpit) IsTarpitted(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[ip]
	return ok
}

func (t *Tarpit) Release(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
	log.Info().Str("ip", ip).Msg("IP released from tarpit")
}

func (t *Tarpit) Cleanup(olderThan time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	for ip, entry := range t.entries {
		if entry.AppliedAt.Before(cutoff) {
			delete(t.entries, ip)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}