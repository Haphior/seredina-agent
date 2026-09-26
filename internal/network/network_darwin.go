package network

import (
	"regexp"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

var platformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

func rawMachineID() string {
	out, ok := sysinfo.Run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if !ok {
		return ""
	}
	if m := platformUUID.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func rawNeighbors() []Neighbor {
	out, ok := sysinfo.Run("arp", "-an")
	if !ok {
		return nil
	}
	return ParseBSDArp(out)
}
