package network

import "github.com/Haphior/seredina-agent/internal/sysinfo"

func rawMachineID() string {
	id, _ := sysinfo.ReadFirst("/etc/machine-id", "/var/lib/dbus/machine-id")
	return id
}

// /proc/net/arp needs neither root nor an extra binary.
func rawNeighbors() []Neighbor {
	text, ok := sysinfo.ReadFirst("/proc/net/arp")
	if !ok {
		return nil
	}
	return ParseProcNetARP(text)
}
