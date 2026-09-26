//go:build !windows

package sysinfo

import (
	"os"
	"os/exec"
)

// prepare runs every tool in the C locale, so what the parsers read (df's
// header, lscpu's labels, systemctl's states) never depends on the
// machine's language.
func prepare(cmd *exec.Cmd) {
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
}
