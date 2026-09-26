// Package inventory collects the hardware and software inventory the agent
// reports on every check-in, by asking each OS's own tools, the same way
// GLPI-Agent does. Every field is best effort: a missing tool leaves its
// field empty instead of failing the check-in.
package inventory

import (
	"math"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// MaxPackages caps the installed-software list; the server accepts up to 2000.
const MaxPackages = 2000

// Disk is one mounted volume.
type Disk struct {
	Mount   string  `json:"mount"`
	TotalGb float64 `json:"totalGb"`
	FreeGb  float64 `json:"freeGb"`
}

// Package is one installed program.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Inventory is the check-in payload's inventory part. Field names match the
// server's API exactly.
type Inventory struct {
	Hostname          string    `json:"hostname"`
	Platform          string    `json:"platform"`
	CPUModel          string    `json:"cpuModel,omitempty"`
	MemoryTotalMb     int64     `json:"memoryTotalMb,omitempty"`
	DiskSummary       []Disk    `json:"diskSummary"`
	OSVersion         string    `json:"osVersion,omitempty"`
	DiskEncrypted     *bool     `json:"diskEncrypted,omitempty"`
	AntivirusStatus   string    `json:"antivirusStatus,omitempty"`
	InstalledPackages []Package `json:"installedPackages"`
	// Details is the full inventory (schema 2). Servers that predate it
	// ignore the field and keep using the summary fields above.
	Details *Details `json:"inventory,omitempty"`
}

// Platform is the server's name for this OS. It keeps Node.js's names
// ("win32", not "windows") because that's what the API validates.
func Platform() string {
	if runtime.GOOS == "windows" {
		return "win32"
	}
	return runtime.GOOS
}

// Hostname is the machine name, or "unknown" rather than an empty string the
// server would reject.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "unknown"
	}
	return h
}

// Collect gathers everything for one check-in: the details, and the
// summary fields derived from them.
func Collect() Inventory {
	d := collect()
	d.finish()
	inv := d.legacy()
	inv.Details = &d
	inv.Hostname = Hostname()
	inv.Platform = Platform()
	if inv.DiskSummary == nil {
		inv.DiskSummary = []Disk{}
	}
	if inv.InstalledPackages == nil {
		inv.InstalledPackages = []Package{}
	}
	if len(inv.InstalledPackages) > MaxPackages {
		inv.InstalledPackages = inv.InstalledPackages[:MaxPackages]
	}
	inv.CPUModel = truncate(inv.CPUModel, 200)
	inv.OSVersion = truncate(inv.OSVersion, 200)
	return inv
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Pseudo filesystems and OS-internal volumes that aren't storage anyone
// manages: skipped by mount point.
var skipMountPrefixes = []string{"/proc", "/sys", "/dev", "/run", "/snap", "/boot/efi", "/private/var/vm", "/System/Volumes/VM",
	"/System/Volumes/Preboot", "/System/Volumes/Update", "/System/Volumes/xarts", "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware"}

func skipMount(mount, filesystem string) bool {
	if filesystem == "devfs" || strings.HasPrefix(filesystem, "map ") || filesystem == "tmpfs" || filesystem == "overlay" {
		return true
	}
	for _, p := range skipMountPrefixes {
		if mount == p || strings.HasPrefix(mount, p+"/") {
			return true
		}
	}
	return false
}

// ParseDfPortable parses `df -kP` (POSIX output, the same six columns on
// Linux and macOS):
//
//	Filesystem 1024-blocks Used Available Capacity Mounted on
//
// A mount point may contain spaces, so it's everything from the sixth field
// on. Plain `df -k` on macOS adds inode columns, which is why -P matters.
func ParseDfPortable(text string) []Disk {
	var disks []Disk
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// "map auto_home" style filesystem names contain a space too.
		fsName := fields[0]
		if fsName == "map" && len(fields) >= 7 {
			fsName = fields[0] + " " + fields[1]
			fields = append([]string{fsName}, fields[2:]...)
		}
		mount := strings.Join(fields[5:], " ")
		if skipMount(mount, fsName) || seen[mount] {
			continue
		}
		total, err1 := strconv.ParseFloat(fields[1], 64)
		free, err2 := strconv.ParseFloat(fields[3], 64)
		// Tiny volumes (read-only images, empty mounts) round to 0 GB and say nothing.
		if err1 != nil || err2 != nil || round1(total/1024/1024) == 0 {
			continue
		}
		seen[mount] = true
		disks = append(disks, Disk{Mount: mount, TotalGb: round1(total / 1024 / 1024), FreeGb: round1(free / 1024 / 1024)})
	}
	return disks
}

// ParseTabbedPackages parses "name<TAB>version" lines (dpkg-query, rpm).
func ParseTabbedPackages(text string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, _ := strings.Cut(line, "\t")
		if name = strings.TrimSpace(name); name != "" {
			pkgs = append(pkgs, Package{Name: name, Version: strings.TrimSpace(version)})
		}
	}
	return pkgs
}

// ParseKeyValue reads "Key: value" / "Key = value" style output (lscpu,
// /proc/cpuinfo, /proc/meminfo, os-release) and returns the first value for key.
func ParseKeyValue(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			k, v, ok = strings.Cut(line, "=")
		}
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func boolPtr(b bool) *bool { return &b }

var apkVersion = regexp.MustCompile(`^(.+)-(\d[^-]*-r\d+)$`)

// ParseAPKPackages parses Alpine's `apk info -v` ("musl-1.2.4-r2").
func ParseAPKPackages(text string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := apkVersion.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Package{Name: m[1], Version: m[2]})
		} else {
			pkgs = append(pkgs, Package{Name: line})
		}
	}
	return pkgs
}
