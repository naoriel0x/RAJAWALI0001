package sandbox

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type IsolationLevel string

const (
	LevelNone      IsolationLevel = "none"
	LevelNetwork   IsolationLevel = "network"
	LevelContainer IsolationLevel = "container"
)

type IsolatedSession struct {
	ID          string
	AttackerIP  string
	Level       IsolationLevel
	ContainerID string
	CreatedAt   time.Time
	Active      bool
}

type Isolator struct {
	mu       sync.Mutex
	sessions map[string]*IsolatedSession
	level    IsolationLevel
}

func NewIsolator(level IsolationLevel) *Isolator {
	return &Isolator{
		sessions: make(map[string]*IsolatedSession),
		level:    level,
	}
}

func (iso *Isolator) CreateSession(attackerIP string) (*IsolatedSession, error) {
	sessionID := fmt.Sprintf("session_%s_%d", sanitizeIP(attackerIP), time.Now().UnixNano())

	session := &IsolatedSession{
		ID:         sessionID,
		AttackerIP: attackerIP,
		Level:      iso.level,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	switch iso.level {
	case LevelContainer:
		containerID, err := iso.spawnContainer(sessionID, attackerIP)
		if err != nil {
			log.Warn().Err(err).Str("ip", attackerIP).Msg("Container isolation failed, falling back to network")
			session.Level = LevelNetwork
		} else {
			session.ContainerID = containerID
		}

	case LevelNetwork:
		if err := iso.applyNetworkIsolation(attackerIP); err != nil {
			log.Warn().Err(err).Str("ip", attackerIP).Msg("Network isolation failed")
		}
	}

	iso.mu.Lock()
	iso.sessions[sessionID] = session
	iso.mu.Unlock()

	log.Info().
		Str("session_id", sessionID).
		Str("ip", attackerIP).
		Str("level", string(session.Level)).
		Msg("Isolated session created")

	return session, nil
}

func (iso *Isolator) TerminateSession(sessionID string) error {
	iso.mu.Lock()
	session, ok := iso.sessions[sessionID]
	if !ok {
		iso.mu.Unlock()
		return fmt.Errorf("session %s not found", sessionID)
	}
	session.Active = false
	iso.mu.Unlock()

	if session.ContainerID != "" {
		exec.Command("docker", "stop", session.ContainerID).Run()
		exec.Command("docker", "rm", session.ContainerID).Run()
		log.Info().Str("container", session.ContainerID).Msg("Isolated container terminated")
	}

	return nil
}

func (iso *Isolator) GetSession(sessionID string) *IsolatedSession {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	return iso.sessions[sessionID]
}

func (iso *Isolator) ActiveSessions() int {
	iso.mu.Lock()
	defer iso.mu.Unlock()

	count := 0
	for _, s := range iso.sessions {
		if s.Active {
			count++
		}
	}
	return count
}

func (iso *Isolator) spawnContainer(sessionID, attackerIP string) (string, error) {
	containerName := fmt.Sprintf("rajawali_sandbox_%s", sessionID[:12])

	cmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"--network", "none",
		"--memory", "64m",
		"--cpus", "0.1",
		"--read-only",
		"alpine",
		"sleep", "3600",
	)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("spawn container: %w", err)
	}

	containerID := string(output[:12])
	log.Info().
		Str("container", containerID).
		Str("ip", attackerIP).
		Msg("Sandbox container spawned")

	return containerID, nil
}

func (iso *Isolator) applyNetworkIsolation(ip string) error {
	cmd := exec.Command("iptables",
		"-A", "FORWARD",
		"-s", ip,
		"-d", "10.0.0.0/8",
		"-j", "DROP",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables rule: %w", err)
	}

	log.Info().Str("ip", ip).Msg("Network isolation applied")
	return nil
}

func sanitizeIP(ip string) string {
	result := ""
	for _, c := range ip {
		if (c >= '0' && c <= '9') || c == '_' {
			result += string(c)
		} else {
			result += "_"
		}
	}
	return result
}