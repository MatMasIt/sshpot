package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/matmasit/sshpot/internal/config"
	"github.com/matmasit/sshpot/internal/logger"
	"github.com/matmasit/sshpot/internal/ratelimit"
	"github.com/matmasit/sshpot/internal/server"
)

var ErrRunningAsRoot = errors.New("refusing to run as root without privilege drop")

func main() {
	cfgPath := flag.String("config", "/etc/sshpot/config.toml", "path to config file")
	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	sl := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(sl)

	// Load config, falling back to defaults if the file is absent.
	cfg, err := loadConfig(*cfgPath, sl)
	if err != nil {
		sl.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Open the log file while we still have the original uid/capabilities,
	// so the file descriptor survives the privilege drop below.
	l, err := logger.New(cfg.Logging)
	if err != nil {
		sl.Error("cannot open log", "path", cfg.Logging.Path, "err", err)
		os.Exit(1)
	}
	defer l.Close()

	gate := ratelimit.New(ratelimit.Config{
		BucketCount:  cfg.RateLimit.BucketCount,
		RestInterval: cfg.RateLimit.RestInterval.TimeDuration(),
	})

	srv := server.New(cfg, gate, l, sl)

	ln, err := srv.Listen()
	if err != nil {
		sl.Error("server listen failed", "err", err)
		os.Exit(1)
	}

	// Drop privileges AFTER opening the log fd, BEFORE accepting connections.
	// Sequence matters: clear supplementary groups, drop GID, drop UID.
	// Once UID is dropped we can no longer regain any privilege.
	uid, gid, err := cfg.Process.Resolve()
	if err != nil {
		sl.Error("failed to resolve process user/group", "err", err)
		os.Exit(1)
	}
	if err := dropPrivileges(gid, uid, sl); err != nil {
		sl.Error("privilege drop failed", "err", err)
		os.Exit(1)
	}

	errc := make(chan error, 1)
	// Start the server in a goroutine, so we can listen for shutdown signals in the main goroutine.
	go func() { errc <- srv.Serve(ln) }()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigc:
		sl.Info("shutting down", "signal", sig.String())
	case err := <-errc:
		sl.Error("server error", "err", err)
		os.Exit(1)
	}
}

// loadConfig tries to load the file at path; if the file does not exist it
// logs a notice and returns the compiled-in defaults.
func loadConfig(path string, sl *slog.Logger) (*config.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		sl.Error("config file not found, using defaults", "path", path)
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	sl.Info("config loaded", "path", path)
	return cfg, nil
}

// dropPrivileges clears supplementary groups, sets GID, then sets UID.
// GID must be set before UID because after losing root we cannot change groups.
// uid or gid of 0 is not allowed.
func dropPrivileges(gid, uid int, sl *slog.Logger) error {
	currentUID := os.Geteuid()
	currentGID := os.Getegid()

	if currentUID != 0 {
		if currentUID == uid && currentGID == gid {
			sl.Info("running without privilege drop", "uid", uid, "gid", gid)
			return nil
		}
		return fmt.Errorf("cannot drop privileges to uid=%d gid=%d without root; current uid=%d gid=%d", uid, gid, currentUID, currentGID)
	}

	if gid == 0 || uid == 0 {
		return ErrRunningAsRoot
	}
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}

	sl.Info("privileges dropped", "uid", uid, "gid", gid)
	return nil
}
