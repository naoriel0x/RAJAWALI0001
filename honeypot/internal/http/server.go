package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rajawali/honeypot/config"
	"github.com/rs/zerolog/log"
)

type Server struct {
	cfg        *config.Config
	logger     *Logger
	handler    *Handler
	httpServer *http.Server
	quit       chan struct{}
}

func NewServer(cfg *config.Config) *Server {
	logger := NewLogger(cfg.BackendURL, cfg.HoneypotToken, cfg.HTTPPort)
	handler := NewHandler(logger)

	return &Server{
		cfg:     cfg,
		logger:  logger,
		handler: handler,
		quit:    make(chan struct{}),
	}
}

func (s *Server) Start() {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.HTTPPort)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Info().Str("addr", addr).Msg("HTTP Honeypot listening")

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("HTTP server error")
	}
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("HTTP server shutdown error")
		}
	}

	log.Info().Msg("HTTP Honeypot stopped")
}
