// Package svc installs the agent as a background service that starts with
// the machine: a Windows service, a launchd daemon on macOS, or a systemd
// unit on Linux (kardianos/service picks the right one).
package svc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"

	"github.com/Haphior/seredina-agent/internal/agent"
)

// Name is the service name on every OS.
const Name = "seredina-agent"

// InstallPath is where `install` puts the binary, so the service keeps
// working if the downloaded file is deleted.
func InstallPath() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramFiles")
		if base == "" {
			base = `C:\Program Files`
		}
		return filepath.Join(base, "Seredina Agent", "seredina-agent.exe")
	default:
		return "/usr/local/bin/seredina-agent"
	}
}

type program struct {
	store    agent.Store
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
	logger   *log.Logger
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		agent.Run(ctx, p.store, p.interval, p.logger)
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(20 * time.Second):
		}
	}
	return nil
}

func newService(store agent.Store, interval time.Duration, logger *log.Logger) (service.Service, *program, error) {
	prg := &program{store: store, interval: interval, logger: logger}
	cfg := &service.Config{
		Name:        Name,
		DisplayName: "Seredina Agent",
		Description: "Reports this computer's hardware and software inventory to Seredina.",
		Executable:  InstallPath(),
		Arguments:   []string{"run", "--config-dir", store.Dir, "--interval", interval.String()},
		Option: service.KeyValue{
			// Windows: start automatically and restart after a crash.
			"StartType":              "automatic",
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "1m",
			// systemd: restart on failure, and wait for the network.
			"Restart": "on-failure",
			// launchd: run at boot and keep alive.
			"KeepAlive": true,
			"RunAtLoad": true,
		},
	}
	if runtime.GOOS == "linux" {
		cfg.Dependencies = []string{"Wants=network-online.target", "After=network-online.target"}
	}
	s, err := service.New(prg, cfg)
	return s, prg, err
}

// Install copies this binary to InstallPath, registers the service and starts
// it. Running it again upgrades in place: the old service is stopped and
// replaced.
func Install(store agent.Store, interval time.Duration) error {
	if !agent.IsAdmin() {
		return errors.New("installing the service needs administrator rights: run it from an elevated prompt (Windows) or with sudo (macOS/Linux)")
	}
	if _, _, err := store.Load(); err != nil {
		return err
	}
	s, _, err := newService(store, interval, log.Default())
	if err != nil {
		return err
	}
	// Upgrade path: stop and remove what's there, ignoring "not installed".
	if status, err := s.Status(); err == nil && status != service.StatusUnknown {
		_ = s.Stop()
		_ = s.Uninstall()
	}
	if err := copySelf(InstallPath()); err != nil {
		return fmt.Errorf("could not copy the agent to %s: %w", InstallPath(), err)
	}
	if err := s.Install(); err != nil {
		return err
	}
	// Remembered so `update` (and a later `install` without --interval)
	// keeps the same schedule.
	if err := store.SaveInterval(interval); err != nil {
		return err
	}
	return s.Start()
}

// Uninstall stops and removes the service. With purge, it also deletes the
// installed binary and the stored credential.
func Uninstall(store agent.Store, purge bool) error {
	if !agent.IsAdmin() {
		return errors.New("removing the service needs administrator rights: run it from an elevated prompt (Windows) or with sudo (macOS/Linux)")
	}
	s, _, err := newService(store, agent.DefaultInterval, log.Default())
	if err != nil {
		return err
	}
	_ = s.Stop()
	if err := s.Uninstall(); err != nil && !isNotInstalled(err) {
		return err
	}
	if purge {
		if err := store.Remove(); err != nil {
			return err
		}
		self, _ := os.Executable()
		if self != InstallPath() {
			_ = os.Remove(InstallPath())
		}
	}
	return nil
}

// Status is the service's state, in words.
func Status(store agent.Store) string {
	s, _, err := newService(store, agent.DefaultInterval, log.Default())
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	st, err := s.Status()
	switch {
	case err != nil && isNotInstalled(err):
		return "not installed"
	case err != nil:
		return "unknown (" + err.Error() + ")"
	case st == service.StatusRunning:
		return "running"
	case st == service.StatusStopped:
		return "stopped"
	}
	return "unknown"
}

// RunService is the entry point when the OS's service manager starts the
// agent; interactively it just runs in the foreground until Ctrl+C.
func RunService(store agent.Store, interval time.Duration) error {
	s, prg, err := newService(store, interval, nil)
	if err != nil {
		return err
	}
	prg.logger = serviceLogger(s)
	return s.Run()
}

// Interactive is true when started from a terminal rather than by the
// service manager.
func Interactive() bool { return service.Interactive() }

func isNotInstalled(err error) bool {
	return errors.Is(err, service.ErrNotInstalled)
}

// serviceLogger sends log lines to the Windows event log, syslog/journald or
// launchd's log, and to stderr when run by hand.
func serviceLogger(s service.Service) *log.Logger {
	if service.Interactive() {
		return log.New(os.Stderr, "", log.LstdFlags)
	}
	sl, err := s.Logger(nil)
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags)
	}
	return log.New(writerFunc(func(p []byte) (int, error) {
		return len(p), sl.Info(string(p))
	}), "", 0)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

var _ io.Writer = writerFunc(nil)

// copySelf copies the running binary to dst (via a temp file and rename).
func copySelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if abs, err := filepath.Abs(dst); err == nil && abs == self {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// On Windows a running .exe can't be overwritten but can be renamed away.
	if runtime.GOOS == "windows" {
		old := dst + ".old"
		_ = os.Remove(old)
		_ = os.Rename(dst, old)
	}
	return os.Rename(tmp, dst)
}
