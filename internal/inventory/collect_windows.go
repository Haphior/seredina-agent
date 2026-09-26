package inventory

import (
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Details {
	out, ok := sysinfo.RunTimeout(3*time.Minute, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", WindowsEncodedCommand())
	if !ok {
		return ParseWindowsReport("")
	}
	d := ParseWindowsReport(out)
	d.VirtualMachines = append(d.VirtualMachines, containerGuests()...)
	return d
}
