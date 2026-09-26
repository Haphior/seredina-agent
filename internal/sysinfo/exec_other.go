//go:build !windows

package sysinfo

import "os/exec"

func hideWindow(*exec.Cmd) {}
