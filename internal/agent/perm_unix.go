//go:build !windows

package agent

import "os"

// IsAdmin reports whether the agent runs as root.
func IsAdmin() bool { return os.Geteuid() == 0 }

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }
