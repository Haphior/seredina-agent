package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Inventory {
	return Inventory{
		CPUModel:          macCPU(),
		MemoryTotalMb:     macMemoryMb(),
		DiskSummary:       macDisks(),
		OSVersion:         macOSVersion(),
		DiskEncrypted:     macFileVault(),
		AntivirusStatus:   "xprotect_builtin", // XProtect is always on; third-party products aren't detected
		InstalledPackages: macApplications(),
	}
}

func macCPU() string {
	out, _ := sysinfo.Run("sysctl", "-n", "machdep.cpu.brand_string") // "Apple M2" or an Intel model
	return out
}

func macMemoryMb() int64 {
	out, ok := sysinfo.Run("sysctl", "-n", "hw.memsize")
	if !ok {
		return 0
	}
	bytes, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		return 0
	}
	return bytes / 1024 / 1024
}

func macOSVersion() string {
	version, ok := sysinfo.Run("sw_vers", "-productVersion")
	if !ok {
		out, _ := sysinfo.Run("uname", "-r")
		return "Darwin " + out
	}
	if build, ok := sysinfo.Run("sw_vers", "-buildVersion"); ok {
		return "macOS " + version + " (" + build + ")"
	}
	return "macOS " + version
}

func macDisks() []Disk {
	out, ok := sysinfo.Run("df", "-kP")
	if !ok {
		return nil
	}
	return ParseDfPortable(out)
}

var fileVaultOn = regexp.MustCompile(`(?i)FileVault is On`)

func macFileVault() *bool {
	out, ok := sysinfo.Run("fdesetup", "status")
	if !ok {
		return nil
	}
	return boolPtr(fileVaultOn.MatchString(out))
}

// The .app bundles in /Applications (and its first-level folders, where
// suites like Microsoft Office live), with the version from Info.plist when
// `defaults` can read it.
func macApplications() []Package {
	var apps []string
	for _, pattern := range []string{"/Applications/*.app", "/Applications/*/*.app"} {
		matches, _ := filepath.Glob(pattern)
		apps = append(apps, matches...)
	}
	sort.Strings(apps)
	var pkgs []Package
	for _, app := range apps {
		if len(pkgs) == MaxPackages {
			break
		}
		name := strings.TrimSuffix(filepath.Base(app), ".app")
		version := ""
		if _, err := os.Stat(filepath.Join(app, "Contents", "Info.plist")); err == nil {
			version, _ = sysinfo.Run("defaults", "read", filepath.Join(app, "Contents", "Info"), "CFBundleShortVersionString")
		}
		pkgs = append(pkgs, Package{Name: name, Version: version})
	}
	return pkgs
}
