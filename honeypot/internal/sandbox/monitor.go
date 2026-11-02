package sandbox

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type ActivityType string

const (
	ActivityCommand    ActivityType = "command"
	ActivityFileAccess ActivityType = "file_access"
	ActivityNetwork    ActivityType = "network"
	ActivityProcess    ActivityType = "process"
)

type Activity struct {
	SessionID    string
	AttackerIP   string
	Type         ActivityType
	Detail       string
	Timestamp    time.Time
	RiskScore    int
}

type SessionReport struct {
	SessionID     string
	AttackerIP    string
	Duration      time.Duration
	TotalActivity int
	RiskScore     int
	Activities    []Activity
	StartedAt     time.Time
	EndedAt       time.Time
}

type Monitor struct {
	mu         sync.Mutex
	activities map[string][]Activity
	startTimes map[string]time.Time
	alerter    func(ip string, score int)
}

func NewMonitor(alerter func(ip string, score int)) *Monitor {
	return &Monitor{
		activities: make(map[string][]Activity),
		startTimes: make(map[string]time.Time),
		alerter:    alerter,
	}
}

func (m *Monitor) StartTracking(sessionID, attackerIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activities[sessionID] = []Activity{}
	m.startTimes[sessionID] = time.Now()

	log.Info().
		Str("session", sessionID).
		Str("ip", attackerIP).
		Msg("Sandbox monitoring started")
}

func (m *Monitor) Record(sessionID, attackerIP string, actType ActivityType, detail string) {
	riskScore := riskScoreFor(actType, detail)

	activity := Activity{
		SessionID:  sessionID,
		AttackerIP: attackerIP,
		Type:       actType,
		Detail:     detail,
		Timestamp:  time.Now(),
		RiskScore:  riskScore,
	}

	m.mu.Lock()
	m.activities[sessionID] = append(m.activities[sessionID], activity)
	totalRisk := m.calcTotalRisk(sessionID)
	m.mu.Unlock()

	log.Debug().
		Str("session", sessionID).
		Str("type", string(actType)).
		Str("detail", detail).
		Int("risk", riskScore).
		Msg("Activity recorded")

	if totalRisk >= 80 && m.alerter != nil {
		m.alerter(attackerIP, totalRisk)
	}
}

func (m *Monitor) GenerateReport(sessionID, attackerIP string) *SessionReport {
	m.mu.Lock()
	defer m.mu.Unlock()

	activities := m.activities[sessionID]
	startedAt := m.startTimes[sessionID]
	endedAt := time.Now()

	totalRisk := m.calcTotalRisk(sessionID)

	return &SessionReport{
		SessionID:     sessionID,
		AttackerIP:    attackerIP,
		Duration:      endedAt.Sub(startedAt),
		TotalActivity: len(activities),
		RiskScore:     totalRisk,
		Activities:    activities,
		StartedAt:     startedAt,
		EndedAt:       endedAt,
	}
}

func (m *Monitor) StopTracking(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.activities, sessionID)
	delete(m.startTimes, sessionID)

	log.Info().Str("session", sessionID).Msg("Sandbox monitoring stopped")
}

func (m *Monitor) calcTotalRisk(sessionID string) int {
	total := 0
	for _, a := range m.activities[sessionID] {
		total += a.RiskScore
	}
	if total > 100 {
		return 100
	}
	return total
}

func riskScoreFor(actType ActivityType, detail string) int {
	base := map[ActivityType]int{
		ActivityCommand:    10,
		ActivityFileAccess: 8,
		ActivityNetwork:    15,
		ActivityProcess:    12,
	}

	score := base[actType]

	highRiskKeywords := []string{
		"wget", "curl", "chmod", "passwd", "shadow",
		"nc ", "netcat", "/etc/", "id_rsa", "authorized_keys",
		"python", "perl", "bash -i", "/dev/tcp",
	}

	for _, kw := range highRiskKeywords {
		if len(detail) > 0 {
			for i := 0; i <= len(detail)-len(kw); i++ {
				if detail[i:i+len(kw)] == kw {
					score += 15
					break
				}
			}
		}
	}

	return score
}