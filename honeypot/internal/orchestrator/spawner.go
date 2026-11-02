package orchestrator

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type SpawnRecord struct {
	Type      string
	Port      int
	SpawnedAt time.Time
}

type Spawner struct {
	mu          sync.Mutex
	spawned     map[int]*SpawnRecord
	backendURL  string
	maxInstances int
}

func NewSpawner(backendURL string, maxInstances int) *Spawner {
	return &Spawner{
		spawned:      make(map[int]*SpawnRecord),
		backendURL:   backendURL,
		maxInstances: maxInstances,
	}
}

func (s *Spawner) SpawnIfNeeded(instanceType string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.spawned) >= s.maxInstances {
		log.Debug().
			Int("current", len(s.spawned)).
			Int("max", s.maxInstances).
			Msg("Max instances reached, skip spawn")
		return
	}

	if _, exists := s.spawned[port]; exists {
		log.Debug().Int("port", port).Msg("Instance already running on port")
		return
	}

	log.Info().
		Str("type", instanceType).
		Int("port", port).
		Msg("Spawning new honeypot instance")

	if err := s.spawn(instanceType, port); err != nil {
		log.Error().Err(err).Msg("Failed to spawn instance")
		return
	}

	s.spawned[port] = &SpawnRecord{
		Type:      instanceType,
		Port:      port,
		SpawnedAt: time.Now(),
	}

	log.Info().
		Str("type", instanceType).
		Int("port", port).
		Msg("New honeypot instance spawned")
}

func (s *Spawner) spawn(instanceType string, port int) error {
	containerName := fmt.Sprintf("rajawali_honeypot_%s_%d", instanceType, port)

	args := []string{
		"run", "-d",
		"--name", containerName,
		"--network", "rajawali_net",
		"-e", fmt.Sprintf("BACKEND_URL=%s", s.backendURL),
		"-e", fmt.Sprintf("SSH_PORT=%d", port),
		"-e", fmt.Sprintf("HTTP_PORT=%d", port+1000),
		"-p", fmt.Sprintf("%d:%d", port, port),
		"rajawali_honeypot",
	}

	cmd := exec.Command("docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run failed: %w — output: %s", err, string(output))
	}

	return nil
}

func (s *Spawner) Terminate(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.spawned[port]
	if !ok {
		return fmt.Errorf("no instance on port %d", port)
	}

	containerName := fmt.Sprintf("rajawali_honeypot_%s_%d", record.Type, port)

	stopCmd := exec.Command("docker", "stop", containerName)
	if err := stopCmd.Run(); err != nil {
		log.Warn().Err(err).Str("container", containerName).Msg("Failed to stop container")
	}

	rmCmd := exec.Command("docker", "rm", containerName)
	if err := rmCmd.Run(); err != nil {
		log.Warn().Err(err).Str("container", containerName).Msg("Failed to remove container")
	}

	delete(s.spawned, port)
	log.Info().Int("port", port).Msg("Instance terminated")
	return nil
}

func (s *Spawner) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.spawned)
}