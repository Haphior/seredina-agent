// Package sysinfo holds the small helpers the inventory and network
// collectors share: running a native command with a timeout, and reading the
// first file that exists out of a list.
package sysinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CommandTimeout bounds every native command the agent runs, so one hung
// tool (a stuck network drive in df, a slow PowerShell) can't stall a
// check-in forever.
const CommandTimeout = 30 * time.Second

// Run executes a command and returns its trimmed stdout, or ok=false if it's
// missing, fails, or times out. The agent treats every native command as
// best effort: a machine without lsblk still checks in, just without that
// field.
func Run(name string, args ...string) (string, bool) {
	return RunTimeout(CommandTimeout, name, args...)
}

// RunTimeout is Run with its own time limit, for the few collectors that are
// slow by nature (the Windows inventory script, macOS's system_profiler).
func RunTimeout(timeout time.Duration, name string, args ...string) (string, bool) {
	out, code, ok := RunExit(timeout, name, args...)
	return out, ok && code == 0
}

// RunExit runs a command and also reports its exit code, for tools that
// answer through it (`dnf check-update` exits 100 when updates are pending,
// `needs-restarting -r` exits 1 when a reboot is). ok is false only when the
// command is missing, can't start, or times out.
func RunExit(timeout time.Duration, name string, args ...string) (out string, code int, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	prepare(cmd)
	b, err := cmd.Output()
	out = strings.TrimSpace(string(b))
	if err == nil {
		return out, 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return out, exitErr.ExitCode(), true
	}
	return out, -1, false
}

// ReadFirst returns the trimmed contents of the first readable, non-empty
// file in paths.
func ReadFirst(paths ...string) (string, bool) {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, true
		}
	}
	return "", false
}

// Exists reports whether a path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Lines splits command output into lines, tolerating Windows line endings.
func Lines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
