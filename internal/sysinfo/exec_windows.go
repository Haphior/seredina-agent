package sysinfo

import (
	"os/exec"
	"syscall"
)

// prepare keeps PowerShell and friends from flashing a console window when
// the agent runs as a service or from a scheduled context.
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
