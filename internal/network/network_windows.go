package network

import (
	"encoding/json"

	"golang.org/x/sys/windows/registry"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

// Read from the registry directly rather than parsing `reg query`, whose
// output is localized.
func rawMachineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return v
}

// Get-NetNeighbor reports states as enum names, which aren't localized, so it
// works the same on a Spanish or English Windows. `arp -a` is the fallback
// for systems without the NetTCPIP module.
const neighborScript = `$ErrorActionPreference='Stop'
Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe') } |
  ForEach-Object { [pscustomobject]@{ ip = $_.IPAddress; mac = $_.LinkLayerAddress } } |
  ConvertTo-Json -Compress`

func rawNeighbors() []Neighbor {
	if out, ok := sysinfo.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", neighborScript); ok && out != "" {
		var list []Neighbor
		// ConvertTo-Json emits an object instead of an array for one item.
		if json.Unmarshal([]byte(out), &list) == nil {
			return list
		}
		var one Neighbor
		if json.Unmarshal([]byte(out), &one) == nil {
			return []Neighbor{one}
		}
	}
	out, ok := sysinfo.Run("arp", "-a")
	if !ok {
		return nil
	}
	return ParseWindowsArp(out)
}
