package inventory

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Inventory {
	return Inventory{
		CPUModel:          linuxCPU(),
		MemoryTotalMb:     linuxMemoryMb(),
		DiskSummary:       linuxDisks(),
		OSVersion:         linuxOSVersion(),
		DiskEncrypted:     linuxDiskEncrypted(),
		AntivirusStatus:   "not_applicable", // no OS-level antivirus concept on Linux
		InstalledPackages: linuxPackages(),
	}
}

func linuxCPU() string {
	if text, ok := sysinfo.ReadFirst("/proc/cpuinfo"); ok {
		for _, key := range []string{"model name", "Model", "Hardware", "cpu model"} {
			if v := ParseKeyValue(text, key); v != "" {
				return v
			}
		}
	}
	if out, ok := sysinfo.Run("lscpu"); ok {
		return ParseKeyValue(out, "Model name")
	}
	return ""
}

func linuxMemoryMb() int64 {
	text, ok := sysinfo.ReadFirst("/proc/meminfo")
	if !ok {
		return 0
	}
	fields := strings.Fields(ParseKeyValue(text, "MemTotal")) // "16318088 kB"
	if len(fields) == 0 {
		return 0
	}
	kb, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return kb / 1024
}

func linuxOSVersion() string {
	name := ""
	if text, ok := sysinfo.ReadFirst("/etc/os-release", "/usr/lib/os-release"); ok {
		name = ParseKeyValue(text, "PRETTY_NAME")
	}
	kernel, _ := sysinfo.Run("uname", "-r")
	switch {
	case name != "" && kernel != "":
		return name + " (kernel " + kernel + ")"
	case name != "":
		return name
	case kernel != "":
		return "Linux " + kernel
	}
	return "Linux"
}

func linuxDisks() []Disk {
	// GNU df can drop pseudo filesystems by type; fall back to plain -kP.
	out, ok := sysinfo.Run("df", "-kP", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
	if !ok {
		out, ok = sysinfo.Run("df", "-kP")
	}
	if !ok {
		return nil
	}
	return ParseDfPortable(out)
}

var cryptType = regexp.MustCompile(`(?im)\bcrypt\b`)

// A "crypt" device in lsblk means at least one LUKS/dm-crypt volume exists:
// the common case, named as a heuristic.
func linuxDiskEncrypted() *bool {
	out, ok := sysinfo.Run("lsblk", "-o", "NAME,TYPE")
	if !ok {
		return nil
	}
	return boolPtr(cryptType.MatchString(out))
}

func linuxPackages() []Package {
	if out, ok := sysinfo.Run("dpkg-query", "-W", "-f=${Package}\t${Version}\n"); ok {
		return ParseTabbedPackages(out)
	}
	if out, ok := sysinfo.Run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"); ok {
		return ParseTabbedPackages(out)
	}
	if out, ok := sysinfo.Run("pacman", "-Q"); ok {
		return ParseTabbedPackages(strings.ReplaceAll(out, " ", "\t"))
	}
	if out, ok := sysinfo.Run("apk", "info", "-v"); ok {
		return ParseAPKPackages(out)
	}
	return nil
}
