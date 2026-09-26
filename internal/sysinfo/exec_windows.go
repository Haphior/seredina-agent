package sysinfo

import (
	"os/exec"
	"syscall"
)

// hideWindow keeps PowerShell and friends from flashing a console window
// when the agent runs as a service or from a scheduled context.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
