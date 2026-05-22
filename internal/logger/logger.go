// Package logger provides a thread-safe, append-only CSV sink for honeypot events.
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var csvHeader = []string{"timestamp", "ip", "username", "password", "remote_ssh_version"}

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
	mu  sync.Mutex
	out *os.File
}

// New opens (or creates) the file at path and returns a ready Logger.
// The caller must call Close when done.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log %q: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log %q: %w", path, err)
	}
	if info.Size() == 0 {
		if err := writeCSVRecord(f, csvHeader); err != nil {
			f.Close()
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
	}

	return &Logger{out: f}, nil
}

// Write records one login attempt. Safe for concurrent use.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := writeCSVRecord(l.out, []string{
		e.Time.UTC().Format(time.RFC3339Nano),
		e.IP,
		e.Username,
		e.Password,
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
