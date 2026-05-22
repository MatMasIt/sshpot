// Package server implements the fake SSH server.
//
// Each inbound TCP connection gets its own freshly-generated ed25519 host key,
// so every handshake presents a distinct fingerprint. This defeats scanner
// key-pinning and makes the honeypot harder to fingerprint as non-OpenSSH.
//
// The server accepts every password authentication attempt, logs the
// credentials, then immediately closes the TCP connection before any SSH
// channel is opened.
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/matmasit/sshpot/internal/config"
	"github.com/matmasit/sshpot/internal/logger"
	"github.com/matmasit/sshpot/internal/ratelimit"
)

// Server is the honeypot listener.
type Server struct {
	cfg  *config.Config
	gate *ratelimit.Gate
	log  *logger.Logger
	slog *slog.Logger
	sem  chan struct{}
}

// New constructs a Server from the supplied dependencies.
func New(cfg *config.Config, gate *ratelimit.Gate, l *logger.Logger, sl *slog.Logger) *Server {
	return &Server{cfg: cfg, gate: gate, log: l, slog: sl, sem: make(chan struct{}, cfg.Server.MaxConnections)}
}

// Listen binds the configured address and returns a ready listener.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.Server.Listen, err)
	}
	return ln, nil
}

// Serve accepts connections on an already-open listener until the listener is
// closed or an unrecoverable error occurs.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()

	banner, err := s.cfg.Server.RenderBanner()
	if err != nil {
		return fmt.Errorf("render banner: %w", err)
	}

	s.slog.Info("honeypot listening",
		"addr", s.cfg.Server.Listen,
		"banner", banner,
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		s.slog.Info("new connection", "remote", conn.RemoteAddr())
		select {
		// if there is room in the semaphore, accept the connection and handle it in a new goroutine.
		case s.sem <- struct{}{}:
			go func() {
				// Release the semaphore when the connection is done being handled.
				defer func() { <-s.sem }()
				s.handle(conn)
			}()
		default:
			// If the semaphore is full, refuse the connection immediately.
			s.slog.Debug("max connections reached, refusing new connection", "remote", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// handle processes a single TCP connection.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	defer s.slog.Info("connection closed", "remote", conn.RemoteAddr())

	if !s.gate.Allow(conn.RemoteAddr()) {
		s.slog.Debug("rate limited", "remote", conn.RemoteAddr())
		return
	}

	hostKey, err := generateHostKey()
	if err != nil {
		s.slog.Error("key generation failed", "err", err)
		return
	}

	banner, err := s.cfg.Server.RenderBanner()
	if err != nil {
		s.slog.Error("render banner failed", "err", err)
		return
	}

	sshCfg := &ssh.ServerConfig{
		ServerVersion:    banner,
		PasswordCallback: s.onPassword,
	}
	sshCfg.AddHostKey(hostKey)

	conn.SetDeadline(time.Now().Add(s.cfg.Server.HandshakeTimeout.TimeDuration()))

	srvConn, chans, reqs, err := ssh.NewServerConn(conn, sshCfg)
	if err != nil {
		return
	}
	defer srvConn.Close()
	conn.SetDeadline(time.Time{})

	go ssh.DiscardRequests(reqs)
	s.handleSession(chans)
}

// handleSession waits for the client to open a session channel, prints a
// fake Ubuntu MOTD, then closes the connection.
func (s *Server) handleSession(chans <-chan ssh.NewChannel) {
	var newChan ssh.NewChannel
	for {
		chanCandidate, ok := <-chans
		if !ok {
			return
		}
		if chanCandidate.ChannelType() != "session" {
			continue
		}
		newChan = chanCandidate
		break
	}

	ch, requests, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	shellRequested := make(chan struct{})

	// Consume channel requests in the background; accept shell/pty so the
	// client believes it has a real terminal.
	go func() {
		for req := range requests {
			if req.Type == "shell" {
				select {
				case <-shellRequested:
				default:
					close(shellRequested)
				}
			}
			req.Reply(req.Type == "shell" || req.Type == "pty-req", nil)
		}
	}()

	// Brief pause so the client terminal is ready to render output.
	select {
	case <-shellRequested:
	case <-time.After(s.cfg.Server.ShellRequestTimeout.TimeDuration()):
	}
	time.Sleep(s.cfg.Server.PreOutputDelay.TimeDuration())
	outputText, err := s.cfg.Server.RenderOutputText()
	if err != nil {
		s.slog.Error("render output text failed", "err", err)
		return
	}
	fmt.Fprint(ch, outputText)
	time.Sleep(s.cfg.Server.PostOutputDelay.TimeDuration())

	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

// onPassword is invoked by the SSH library for every password auth attempt.
func (s *Server) onPassword(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ip, _, _ := net.SplitHostPort(meta.RemoteAddr().String())

	entry := logger.Entry{
		Time:       time.Now().UTC(),
		IP:         ip,
		Username:   meta.User(),
		Password:   string(password),
		SSHVersion: string(meta.ClientVersion()),
	}

	if err := s.log.Write(entry); err != nil {
		s.slog.Error("log write failed", "err", err)
	}

	s.slog.Info("login attempt",
		"ip", ip,
		"client", string(meta.ClientVersion()),
	)

	// Return nil,nil (accepted) so the library sends AUTH_SUCCESS before we
	// tear down TCP  slightly more realistic than an auth failure loop.
	return nil, nil
}

// generateHostKey creates a fresh ephemeral ed25519 signing key.
func generateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
