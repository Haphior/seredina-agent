package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Details {
	d := Details{}
	if out, ok := sysinfo.RunTimeout(90*time.Second, "system_profiler", append([]string{"-json"}, MacProfilerTypes...)...); ok {
		d = ParseMacProfiler(out)
	}
	processes := macProcesses()

	macSystem(&d)
	macOS(&d)
	macCPUAndMemory(&d)
	if len(d.Volumes) == 0 {
		if out, ok := sysinfo.Run("df", "-kP"); ok {
			for _, disk := range ParseDfPortable(out) {
				d.Volumes = append(d.Volumes, Volume{Mount: disk.Mount, TotalGb: disk.TotalGb, FreeGb: disk.FreeGb})
			}
		}
	}
	d.Network = macNetwork()
	macUsers(&d)
	macSecurity(&d, processes)

	d.Software = nil
	if out, ok := sysinfo.RunTimeout(180*time.Second, "system_profiler", "-json", "-detailLevel", "mini", "SPApplicationsDataType"); ok {
		d.Software = ParseMacApplications(out)
	}
	if len(d.Software) == 0 {
		d.Software = macApplicationsFallback()
	}
	if out, ok := sysinfo.Run("softwareupdate", "--history"); ok {
		d.Updates.Installed = ParseSoftwareUpdateHistory(out)
		if len(d.Updates.Installed) > 0 {
			d.Updates.LastInstalled = d.Updates.Installed[0].InstalledOn
		}
	}
	if out, ok := sysinfo.Run("launchctl", "list"); ok {
		d.Services = ParseLaunchctlList(out)
	}
	if out, ok := sysinfo.Run("lsof", "-nP", "-iTCP", "-sTCP:LISTEN"); ok {
		d.Ports = ParseLsof(out)
	}
	d.VirtualMachines = containerGuests()
	d.ServerRoles = DetectServerSoftware(d.Services, processes)
	return d
}

func macProcesses() []string {
	out, ok := sysinfo.Run("ps", "-axco", "comm=")
	if !ok {
		return nil
	}
	return strings.Split(out, "\n")
}

func macSystem(d *Details) {
	s := &d.System
	if v, _ := sysinfo.Run("sysctl", "-n", "kern.hv_vmm_present"); v == "1" {
		s.Virtual = true
		if s.Hypervisor == "" {
			s.Hypervisor = guessHypervisorMac(s.Model)
		}
	}
	s.Role = "workstation"
	if out, ok := sysinfo.Run("dsconfigad", "-show"); ok {
		s.Domain = ParseKeyValue(strings.ReplaceAll(out, " = ", ":"), "Active Directory Domain")
	}
	s.Timezone = unixTimezone()
}

func guessHypervisorMac(model string) string {
	switch m := strings.ToLower(model); {
	case strings.Contains(m, "vmware"):
		return "VMware"
	case strings.Contains(m, "parallels"):
		return "Parallels"
	case strings.Contains(m, "virtualbox"):
		return "VirtualBox"
	}
	return "Apple Virtualization"
}

func macOS(d *Details) {
	o := &d.OS
	version, _ := sysinfo.Run("sw_vers", "-productVersion")
	build, _ := sysinfo.Run("sw_vers", "-buildVersion")
	name, _ := sysinfo.Run("sw_vers", "-productName")
	if o.Name == "" {
		o.Name = strings.TrimSpace(firstNonEmpty(name, "macOS") + " " + version)
	}
	o.Version, o.Build = version, build
	if o.Kernel == "" {
		o.Kernel, _ = sysinfo.Run("uname", "-r")
	}
	o.Arch, _ = sysinfo.Run("uname", "-m")
	// "{ sec = 1718000000, usec = 0 } Mon Jun 10 ..."
	if out, ok := sysinfo.Run("sysctl", "-n", "kern.boottime"); ok {
		if m := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(out); m != nil {
			sec, _ := strconv.ParseInt(m[1], 10, 64)
			o.LastBoot = unixTime(sec)
		}
	}
	if info, err := os.Stat("/var/db/.AppleSetupDone"); err == nil {
		o.InstallDate = info.ModTime().UTC().Format("2006-01-02")
	}
	switch {
	case version != "" && build != "":
		d.legacyOS = "macOS " + version + " (" + build + ")"
	case version != "":
		d.legacyOS = "macOS " + version
	default:
		d.legacyOS = "Darwin " + o.Kernel
	}
}

func macCPUAndMemory(d *Details) {
	sysctl := func(key string) string { v, _ := sysinfo.Run("sysctl", "-n", key); return v }
	atoi := func(key string) int { n, _ := strconv.Atoi(sysctl(key)); return n }
	if d.CPU.Model == "" {
		d.CPU.Model = sysctl("machdep.cpu.brand_string")
	}
	if n := atoi("hw.physicalcpu"); n > 0 {
		d.CPU.Cores = n
	}
	if n := atoi("hw.logicalcpu"); n > 0 {
		d.CPU.Threads = n
	}
	if n := atoi("hw.packages"); n > 0 {
		d.CPU.Sockets = n
	}
	if hz, err := strconv.ParseInt(sysctl("hw.cpufrequency_max"), 10, 64); err == nil && hz > 0 {
		d.CPU.SpeedMhz = int(hz / 1e6)
	}
	if bytes, err := strconv.ParseInt(sysctl("hw.memsize"), 10, 64); err == nil && bytes > 0 {
		d.Memory.TotalMb = bytes / 1024 / 1024
	}
}

func macNetwork() []NetInterface {
	list := goInterfaces()
	// "Hardware Port: Wi-Fi / Device: en0" pairs name the adapters.
	if out, ok := sysinfo.Run("networksetup", "-listallhardwareports"); ok {
		port := ""
		names := map[string]string{}
		for _, line := range sysinfo.Lines(out) {
			if v, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
				port = v
			} else if v, ok := strings.CutPrefix(line, "Device: "); ok && port != "" {
				names[strings.TrimSpace(v)] = port
			}
		}
		for i := range list {
			if desc, ok := names[list[i].Name]; ok {
				list[i].Description = desc
				list[i].Virtual = false
			} else if !strings.HasPrefix(list[i].Name, "en") {
				list[i].Virtual = true
			}
		}
	}
	iface, gateway := "", ""
	if out, ok := sysinfo.Run("route", "-n", "get", "default"); ok {
		gateway = ParseKeyValue(out, "gateway")
		iface = ParseKeyValue(out, "interface")
	}
	var dns []string
	if out, ok := sysinfo.Run("scutil", "--dns"); ok {
		seen := map[string]bool{}
		for _, line := range sysinfo.Lines(out) {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.HasPrefix(strings.TrimSpace(k), "nameserver[") {
				if v = strings.TrimSpace(v); !seen[v] {
					seen[v] = true
					dns = append(dns, v)
				}
			}
		}
	}
	return withGateway(list, iface, gateway, dns)
}

func macUsers(d *Details) {
	if out, ok := sysinfo.Run("who"); ok {
		d.Users.LoggedOn = append(ParseWho(out), d.Users.LoggedOn...)
	}
	if out, ok := sysinfo.Run("stat", "-f", "%Su", "/dev/console"); ok && out != "root" {
		d.Users.LastLogon = out
	}
	if out, ok := sysinfo.Run("dscl", ".", "-read", "/Groups/admin", "GroupMembership"); ok {
		d.Users.LocalAdmins = strings.Fields(strings.TrimPrefix(out, "GroupMembership:"))
	}
	if out, ok := sysinfo.Run("dscl", ".", "-list", "/Users", "UniqueID"); ok {
		for _, line := range sysinfo.Lines(out) {
			f := strings.Fields(line)
			if len(f) == 2 {
				if uid, err := strconv.Atoi(f[1]); err == nil && uid >= 500 && !strings.HasPrefix(f[0], "_") {
					d.Users.LocalUsers = append(d.Users.LocalUsers, f[0])
				}
			}
		}
	}
}

func macSecurity(d *Details, processes []string) {
	sec := &d.Security
	sec.Features = map[string]string{}
	if out, ok := sysinfo.Run("fdesetup", "status"); ok {
		on := strings.Contains(out, "FileVault is On")
		sec.SystemDiskEncrypted = boolPtr(on)
		if on {
			sec.EncryptionMethod = "FileVault"
		}
	}
	if out, ok := sysinfo.Run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); ok {
		sec.FirewallEnabled = boolPtr(strings.Contains(out, "enabled") || strings.Contains(out, "State = 1") || strings.Contains(out, "State = 2"))
	}
	if out, _, ok := sysinfo.RunExit(sysinfo.CommandTimeout, "spctl", "--status"); ok {
		if strings.Contains(out, "enabled") {
			sec.Features["gatekeeper"] = "enabled"
		} else if strings.Contains(out, "disabled") {
			sec.Features["gatekeeper"] = "disabled"
		}
	}
	if out, ok := sysinfo.Run("csrutil", "status"); ok {
		if strings.Contains(out, "enabled") {
			sec.Features["sip"] = "enabled"
		} else if strings.Contains(out, "disabled") {
			sec.Features["sip"] = "disabled"
		}
	}
	xprotect := Antivirus{Name: "XProtect", Enabled: boolPtr(true)}
	xprotect.Version, _ = sysinfo.Run("defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString")
	sec.Antivirus = []Antivirus{xprotect}
	sec.Agents = DetectAgents(processes)
	for _, a := range sec.Agents {
		sec.Antivirus = append(sec.Antivirus, Antivirus{Name: a, Enabled: boolPtr(true)})
	}
	d.legacyAV = "xprotect_builtin" // XProtect is always on
}

// macApplicationsFallback lists /Applications' bundles, reading each
// version with `defaults`, for when system_profiler fails.
func macApplicationsFallback() []Software {
	var apps []string
	for _, pattern := range []string{"/Applications/*.app", "/Applications/*/*.app"} {
		matches, _ := filepath.Glob(pattern)
		apps = append(apps, matches...)
	}
	sort.Strings(apps)
	var out []Software
	for _, app := range apps {
		version := ""
		if sysinfo.Exists(filepath.Join(app, "Contents", "Info.plist")) {
			version, _ = sysinfo.Run("defaults", "read", filepath.Join(app, "Contents", "Info"), "CFBundleShortVersionString")
		}
		out = append(out, Software{Name: strings.TrimSuffix(filepath.Base(app), ".app"), Version: version, Source: "app"})
	}
	return out
}
