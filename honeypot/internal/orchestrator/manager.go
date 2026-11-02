package orchestrator

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type InstanceStatus string

const (
	StatusRunning  InstanceStatus = "running"
	StatusStopped  InstanceStatus = "stopped"
	StatusSpawning InstanceStatus = "spawning"
)

type HoneypotInstance struct {
	ID        string
	Type      string
	Port      int
	Status    InstanceStatus
	CreatedAt time.Time
	LastHit   time.Time
	HitCount  int
}

type Manager struct {
	mu        sync.RWMutex
	instances map[string]*HoneypotInstance
	spawner   *Spawner
}

func NewManager(spawner *Spawner) *Manager {
	return &Manager{
		instances: make(map[string]*HoneypotInstance),
		spawner:   spawner,
	}
}

func (m *Manager) Register(id, instanceType string, port int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.instances[id] = &HoneypotInstance{
		ID:        id,
		Type:      instanceType,
		Port:      port,
		Status:    StatusRunning,
		CreatedAt: time.Now(),
	}

	log.Info().
		Str("id", id).
		Str("type", instanceType).
		Int("port", port).
		Msg("Honeypot instance registered")
}

func (m *Manager) RecordHit(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inst, ok := m.instances[id]
	if !ok {
		return
	}

	inst.HitCount++
	inst.LastHit = time.Now()

	if inst.HitCount%10 == 0 {
		log.Info().
			Str("id", id).
			Int("hits", inst.HitCount).
			Msg("High activity — considering spawn")

		go m.spawner.SpawnIfNeeded(inst.Type, inst.Port+1)
	}
}

func (m *Manager) GetAll() []*HoneypotInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*HoneypotInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		list = append(list, inst)
	}
	return list
}

func (m *Manager) GetByID(id string) *HoneypotInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.instances[id]
}

func (m *Manager) SetStatus(id string, status InstanceStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if inst, ok := m.instances[id]; ok {
		inst.Status = status
		log.Info().
			Str("id", id).
			Str("status", string(status)).
			Msg("Instance status updated")
	}
}

func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.instances, id)
	log.Info().Str("id", id).Msg("Instance removed")
}

func (m *Manager) Stats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := len(m.instances)
	running := 0
	totalHits := 0

	for _, inst := range m.instances {
		if inst.Status == StatusRunning {
			running++
		}
		totalHits += inst.HitCount
	}

	return map[string]any{
		"total_instances": total,
		"running":         running,
		"total_hits":      totalHits,
	}
}