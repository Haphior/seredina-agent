// Package sysinfo holds the small helpers the inventory and network
// collectors share: running a native command with a timeout, and reading the
// first file that exists out of a list.
package sysinfo

import (
	"context"
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
	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
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

// Lines splits command output into lines, tolerating Windows line endings.
func Lines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
