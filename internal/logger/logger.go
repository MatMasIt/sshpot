// Package logger provides a thread-safe, append-only CSV sink for honeypot events.
package logger

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/matmasit/sshpot/internal/config"
	"github.com/matmasit/sshpot/internal/passwordsecrets"
)

var (
	PLAIN                       = "plain"
	HASH                        = "hash"
	NONE                        = "none"
	ENC_X25519_AES256GCM        = "enc_x25519_aes256gcm"
	ENC_X25519_CHACHA20POLY1305 = "enc_x25519_chacha20poly1305"
)

var csvHeader = []string{"timestamp", "ip", "mode", "username", "password", "remote_ssh_version"}

// Entry is a single captured login attempt.
type Entry struct {
	Time       time.Time
	IP         string
	Username   string
	Password   string
	SSHVersion string
}

// Logger writes honeypot entries to a CSV file.
type Logger struct {
	mu           sync.Mutex
	out          *os.File
	mode         string
	recipientPub *ecdh.PublicKey
}

// New opens (or creates) the file at path and returns a ready Logger.
// The caller must call Close when done.
func New(cfg config.Logging) (*Logger, error) {
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log %q: %w", cfg.Path, err)
	}

	logger := &Logger{out: f, mode: passwordsecrets.NormalizeMode(cfg.SecretsMode)}
	if passwordsecrets.IsEncryptedMode(logger.mode) {
		recipientPub, err := passwordsecrets.LoadX25519PublicKeyPEM(cfg.SecretsPubKey)
		if err != nil {
			f.Close()
			return nil, err
		}
		logger.recipientPub = recipientPub
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log %q: %w", cfg.Path, err)
	}
	if info.Size() == 0 {
		if err := writeCSVRecord(f, csvHeader); err != nil {
			f.Close()
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
	}

	return logger, nil
}

// Write records one login attempt. Safe for concurrent use.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	password, err := l.formatPassword(e.Password)
	if err != nil {
		return err
	}

	if err := writeCSVRecord(l.out, []string{
		e.Time.UTC().Format(time.RFC3339),
		e.IP,
		l.mode,
		e.Username,
		password,
		e.SSHVersion,
	}); err != nil {
		return err
	}
	return nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out.Close()
}

func (l *Logger) formatPassword(password string) (string, error) {
	switch l.mode {
	case "", PLAIN:
		return truncateBytes(password, 100), nil
	case HASH:
		sum := sha256.Sum256([]byte(password))
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	case NONE:
		return "", nil
	case ENC_X25519_AES256GCM, ENC_X25519_CHACHA20POLY1305:
		return passwordsecrets.EncryptPassword(l.mode, l.recipientPub, password)
	default:
		return "", fmt.Errorf("unsupported secrets mode %q", l.mode)
	}
}

func truncateBytes(value string, limit int) string {
	data := []byte(value)
	if len(data) <= limit {
		return value
	}
	return string(data[:limit])
}

func writeCSVRecord(w io.Writer, record []string) error {
	for index, field := range record {
		if index > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}

		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
		for i := 0; i < len(field); i++ {
			if field[i] == '"' {
				if _, err := io.WriteString(w, "\"\""); err != nil {
					return err
				}
				continue
			}
			if _, err := io.WriteString(w, field[i:i+1]); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
	}

	_, err := io.WriteString(w, "\n")
	return err
}
