package inventory

import "github.com/Haphior/seredina-agent/internal/sysinfo"

func collect() Inventory {
	out, ok := sysinfo.Run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WindowsScript)
	if !ok {
		return Inventory{OSVersion: "Windows", AntivirusStatus: "unknown"}
	}
	return ParseWindowsReport(out)
}
