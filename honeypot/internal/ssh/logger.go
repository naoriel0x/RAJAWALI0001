package ssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type EventPayload struct {
	EventType    string         `json:"event_type"`
	SrcIP        string         `json:"src_ip"`
	SrcPort      int            `json:"src_port"`
	DstPort      int            `json:"dst_port"`
	Protocol     string         `json:"protocol"`
	Username     string         `json:"username,omitempty"`
	Password     string         `json:"password,omitempty"`
	Command      string         `json:"command,omitempty"`
	RawPayload   string         `json:"raw_payload,omitempty"`
	ParsedData   map[string]any `json:"parsed_data,omitempty"`
	ToolDetected string         `json:"tool_detected,omitempty"`
}

type Logger struct {
	backendURL    string
	honeypotToken string
	client        *http.Client
	dstPort       int
}

func NewLogger(backendURL, honeypotToken string, dstPort int) *Logger {
	return &Logger{
		backendURL:    backendURL,
		honeypotToken: honeypotToken,
		dstPort:       dstPort,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (l *Logger) Send(payload EventPayload) {
	payload.DstPort = l.dstPort
	payload.Protocol = "tcp"

	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal event payload")
			return
		}

		url := fmt.Sprintf("%s/api/logs/ingest", l.backendURL)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Honeypot-Token", l.honeypotToken)
		}
		var resp *http.Response
		if err == nil {
			resp, err = l.client.Do(req)
		}
		if err != nil {
			log.Error().Err(err).Str("url", url).Msg("Failed to send event to backend")
			return
		}
		defer resp.Body.Close()

		log.Debug().
			Str("event_type", payload.EventType).
			Str("src_ip", payload.SrcIP).
			Int("status", resp.StatusCode).
			Msg("Event sent to backend")
	}()
}

func (l *Logger) LogConnect(srcIP string, srcPort int, clientVersion string) {
	l.Send(EventPayload{
		EventType:  "ssh_connect",
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		RawPayload: clientVersion,
		ParsedData: map[string]any{
			"client_version": clientVersion,
		},
	})
}

func (l *Logger) LogLoginAttempt(srcIP string, srcPort int, user, pass string, success bool) {
	l.Send(EventPayload{
		EventType: "ssh_login",
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		Username:  user,
		Password:  pass,
		ParsedData: map[string]any{
			"success": success,
		},
	})
}

func (l *Logger) LogCommand(srcIP string, srcPort int, user, command string) {
	l.Send(EventPayload{
		EventType: "ssh_command",
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		Username:  user,
		Command:   command,
		ParsedData: map[string]any{
			"command": command,
		},
	})
}
