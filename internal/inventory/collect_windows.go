package inventory

import (
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Details {
	// Usually about ten seconds; the first run after boot, loading the CIM
	// and storage modules cold, can take two minutes.
	out, ok := sysinfo.RunTimeout(5*time.Minute, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", WindowsEncodedCommand())
	if !ok {
		return ParseWindowsReport("")
	}
	d := ParseWindowsReport(out)
	d.VirtualMachines = append(d.VirtualMachines, containerGuests()...)
	return d
}
