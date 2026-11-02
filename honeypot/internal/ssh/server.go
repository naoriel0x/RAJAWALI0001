package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/rajawali/honeypot/config"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

type Server struct {
	cfg      *config.Config
	logger   *Logger
	handler  *Handler
	listener net.Listener
	quit     chan struct{}
}

func NewServer(cfg *config.Config) *Server {
	logger := NewLogger(cfg.BackendURL, cfg.HoneypotToken, cfg.SSHPort)
	handler := NewHandler(logger, cfg.SSHHostname)

	return &Server{
		cfg:     cfg,
		logger:  logger,
		handler: handler,
		quit:    make(chan struct{}),
	}
}

func (s *Server) Start() {
	hostKey, err := generateHostKey()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate SSH host key")
	}

	sshConfig := &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			srcIP, srcPort := parseAddr(conn.RemoteAddr().String())
			user := conn.User()
			pass := string(password)

			log.Info().
				Str("ip", srcIP).
				Str("user", user).
				Str("pass", pass).
				Msg("SSH login attempt")

			s.logger.LogLoginAttempt(srcIP, srcPort, user, pass, false)

			return nil, fmt.Errorf("invalid credentials")
		},
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			srcIP, srcPort := parseAddr(conn.RemoteAddr().String())

			log.Info().
				Str("ip", srcIP).
				Str("user", conn.User()).
				Str("key_type", key.Type()).
				Msg("SSH pubkey attempt")

			s.logger.LogLoginAttempt(srcIP, srcPort, conn.User(), "[pubkey:"+key.Type()+"]", false)

			if s.cfg.Env == "development" {
				return &gossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}

	sshConfig.AddHostKey(hostKey)

	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.SSHPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", addr).Msg("Failed to listen on SSH port")
	}
	s.listener = listener

	log.Info().Str("addr", addr).Msg("SSH Honeypot listening")

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Error().Err(err).Msg("SSH accept error")
				continue
			}
		}

		go s.handleConn(conn, sshConfig)
	}
}

func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	log.Info().Msg("SSH Honeypot stopped")
}

func (s *Server) handleConn(conn net.Conn, sshConfig *gossh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := gossh.NewServerConn(conn, sshConfig)
	if err != nil {
		srcIP, _ := parseAddr(conn.RemoteAddr().String())
		log.Debug().Err(err).Str("ip", srcIP).Msg("SSH handshake failed")
		return
	}
	defer sshConn.Close()

	s.handler.HandleConn(conn, sshConn, chans, reqs)
}

func generateHostKey() (gossh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	signer, err := gossh.ParsePrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return signer, nil
}
