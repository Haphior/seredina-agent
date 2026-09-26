// Package network gives the agent its machine identity and its passive view
// of the local network (docs/adr/0055-agent-based-discovery.md in the
// Seredina repository). Nothing here sends a packet: the fingerprint comes
// from the OS's own machine id, and neighbors come from the ARP/neighbor
// cache the OS already keeps.
package network

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
)

// MaxNeighbors matches the server's own cap per check-in.
const MaxNeighbors = 512

// Neighbor is one entry of the OS's ARP cache: a device this machine talked
// to recently on its LAN.
type Neighbor struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// Fingerprint turns the OS machine id into the value the server stores. The
// raw id never leaves the machine; the prefix and lowercasing match the
// original Node.js agent, so a machine keeps the same CMDB record when it
// switches agents.
func Fingerprint(rawMachineID string) string {
	raw := strings.TrimSpace(rawMachineID)
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("seredina-machine:" + strings.ToLower(raw)))
	return hex.EncodeToString(sum[:])
}

// MachineFingerprint is Fingerprint of this machine's OS id, or "" when the
// OS doesn't give one (the server then treats the enrollment as a new device).
func MachineFingerprint() string {
	return Fingerprint(rawMachineID())
}

// Interfaces that exist on the machine but aren't how it shows up on the LAN:
// loopback, containers, VMs, VPNs, Bluetooth. Other agents would never see
// these MACs in their ARP cache.
var virtualInterface = regexp.MustCompile(`(?i)^(lo|docker|br-|veth|virbr|vmnet|vboxnet|tun|tap|utun|wg|zt|tailscale|awdl|llw|bridge|anpi|gif|stf)|vethernet|virtualbox|vmware|hyper-v|loopback|bluetooth|tailscale|zerotier|wireguard|vpn`)

// PrimaryMAC is the MAC this machine most likely shows on its LAN: the first
// up, physical-looking interface with a non-loopback IPv4 address.
func PrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if virtualInterface.MatchString(iface.Name) || len(iface.HardwareAddr) != 6 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac == "00:00:00:00:00:00" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
				return mac
			}
		}
	}
	return ""
}

var (
	ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	macRe  = regexp.MustCompile(`(?i)^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$`)
)

// NormalizeMAC pads each octet (macOS's arp prints "0:1b:2c:…") and returns
// lowercase colon form, or "" if it isn't a MAC.
func NormalizeMAC(mac string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(mac), func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		if len(p) != 2 {
			return ""
		}
		parts[i] = strings.ToLower(p)
	}
	out := strings.Join(parts, ":")
	if !macRe.MatchString(out) {
		return ""
	}
	return out
}

// isRealHost drops broadcast, multicast and empty addresses: ARP-cache
// bookkeeping, not devices.
func isRealHost(mac string) bool {
	switch {
	case mac == "ff:ff:ff:ff:ff:ff", mac == "00:00:00:00:00:00":
		return false
	case strings.HasPrefix(mac, "01:00:5e"), strings.HasPrefix(mac, "33:33"):
		return false
	}
	return true
}

// clean validates, normalizes, de-duplicates and caps a neighbor list.
func clean(raw []Neighbor) []Neighbor {
	seen := map[string]bool{}
	out := make([]Neighbor, 0, len(raw))
	for _, n := range raw {
		mac := NormalizeMAC(n.MAC)
		if mac == "" || !ipv4Re.MatchString(n.IP) || !isRealHost(mac) || seen[n.IP+mac] {
			continue
		}
		seen[n.IP+mac] = true
		out = append(out, Neighbor{IP: n.IP, MAC: mac})
		if len(out) == MaxNeighbors {
			break
		}
	}
	return out
}

// Neighbors is this machine's ARP cache, cleaned for the server.
func Neighbors() []Neighbor {
	return clean(rawNeighbors())
}

// ParseProcNetARP parses Linux's /proc/net/arp:
//
//	IP address  HW type  Flags  HW address  Mask  Device
//
// Flags 0x0 is an incomplete entry.
func ParseProcNetARP(text string) []Neighbor {
	var out []Neighbor
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			continue
		}
		cols := strings.Fields(line)
		if len(cols) < 6 || cols[2] == "0x0" {
			continue
		}
		out = append(out, Neighbor{IP: cols[0], MAC: cols[3]})
	}
	return out
}

var bsdARPLine = regexp.MustCompile(`(?i)\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-f:]+) `)

// ParseBSDArp parses macOS's `arp -an`:
//
//	? (192.168.1.1) at a0:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]
//
// "(incomplete)" entries don't match.
func ParseBSDArp(text string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(text, "\n") {
		if m := bsdARPLine.FindStringSubmatch(line); m != nil {
			out = append(out, Neighbor{IP: m[1], MAC: m[2]})
		}
	}
	return out
}

var windowsARPLine = regexp.MustCompile(`(?i)^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+\S+`)

// ParseWindowsArp parses `arp -a`, the fallback when Get-NetNeighbor isn't
// available:
//
//	192.168.1.1           a0-b1-c2-d3-e4-f5     dynamic
//
// The type column is localized ("dinámico", "dynamique"), so it isn't
// matched on; broadcast and multicast entries are dropped by MAC instead.
func ParseWindowsArp(text string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if m := windowsARPLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			out = append(out, Neighbor{IP: m[1], MAC: m[2]})
		}
	}
	return out
}
