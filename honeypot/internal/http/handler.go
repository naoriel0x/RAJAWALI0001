package http

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
	HTTPMethod   string         `json:"http_method,omitempty"`
	HTTPPath     string         `json:"http_path,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	RawPayload   string         `json:"raw_payload,omitempty"`
	ParsedData   map[string]any `json:"parsed_data,omitempty"`
	Headers      map[string]any `json:"headers,omitempty"`
	ToolDetected string         `json:"tool_detected,omitempty"`
}

type Logger struct {
	backendURL    string
	honeypotToken string
	dstPort       int
	client        *http.Client
}

func NewLogger(backendURL, honeypotToken string, dstPort int) *Logger {
	return &Logger{
		backendURL:    backendURL,
		honeypotToken: honeypotToken,
		dstPort:       dstPort,
		client:        &http.Client{Timeout: 5 * time.Second},
	}
}

func (l *Logger) Send(payload EventPayload) {
	payload.DstPort = l.dstPort
	payload.Protocol = "tcp"

	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal HTTP event")
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
			log.Error().Err(err).Msg("Failed to send HTTP event to backend")
			return
		}
		defer resp.Body.Close()

		log.Debug().
			Str("event_type", payload.EventType).
			Str("src_ip", payload.SrcIP).
			Int("status", resp.StatusCode).
			Msg("HTTP event sent to backend")
	}()
}

func (l *Logger) LogRequest(srcIP string, srcPort int, method, path, userAgent string, headers map[string]any) {
	l.Send(EventPayload{
		EventType:  "http_request",
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		HTTPMethod: method,
		HTTPPath:   path,
		UserAgent:  userAgent,
		Headers:    headers,
		ParsedData: map[string]any{
			"method":     method,
			"path":       path,
			"user_agent": userAgent,
		},
	})
}

func (l *Logger) LogCrawl(srcIP string, srcPort int, path, userAgent string) {
	l.Send(EventPayload{
		EventType: "http_crawl",
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		HTTPPath:  path,
		UserAgent: userAgent,
		ParsedData: map[string]any{
			"path":       path,
			"user_agent": userAgent,
		},
	})
}

func (l *Logger) LogLureAccess(srcIP string, srcPort int, path string) {
	l.Send(EventPayload{
		EventType: "lure_access",
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		HTTPPath:  path,
		ParsedData: map[string]any{
			"path":    path,
			"message": "Attacker accessed fake lure document",
		},
	})
}
