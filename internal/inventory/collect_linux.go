package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

func collect() Details {
	var d Details
	processes := linuxProcesses()

	linuxSystem(&d, processes)
	linuxOS(&d)
	d.CPU = linuxCPU()
	linuxMemory(&d)
	if out, ok := sysinfo.Run("lsblk", "-J", "-b", "-d", "-o", "NAME,MODEL,VENDOR,SERIAL,SIZE,ROTA,TRAN,TYPE"); ok {
		d.Disks = ParseLsblkDisks(out)
	}
	linuxVolumes(&d)
	d.Network = linuxNetwork()
	if out, ok := sysinfo.Run("lspci", "-mm"); ok {
		d.GPUs = ParseLspciGPUs(out)
	}
	d.Monitors = linuxMonitors()
	d.Batteries = linuxBatteries()
	if out, ok := sysinfo.Run("lpstat", "-v"); ok {
		def, _ := sysinfo.Run("lpstat", "-d")
		d.Printers = ParseLpstat(out, def)
	}
	linuxUsers(&d)
	linuxSecurity(&d, processes)
	d.Software = linuxSoftware()
	d.Updates = linuxUpdates()
	d.Services = linuxServices()
	d.Ports = linuxPorts()
	d.VirtualMachines = linuxGuests()
	d.ServerRoles = DetectServerSoftware(d.Services, processes)
	return d
}

// linuxProcesses lists the running processes' names from /proc.
func linuxProcesses() []string {
	matches, _ := filepath.Glob("/proc/[0-9]*/comm")
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func dmi(name string) string {
	v, _ := sysinfo.ReadFirst("/sys/class/dmi/id/" + name)
	return v
}

var hypervisorNames = map[string]string{
	"kvm": "KVM", "qemu": "QEMU", "vmware": "VMware", "microsoft": "Hyper-V", "oracle": "VirtualBox", "xen": "Xen",
	"amazon": "Amazon EC2", "google": "Google Compute Engine", "parallels": "Parallels", "bhyve": "bhyve",
	"apple": "Apple Virtualization", "powervm": "PowerVM", "zvm": "z/VM", "acrn": "ACRN", "bochs": "Bochs",
	"docker": "Docker (container)", "podman": "Podman (container)", "lxc": "LXC (container)", "lxc-libvirt": "LXC (container)",
	"openvz": "OpenVZ (container)", "systemd-nspawn": "systemd-nspawn (container)", "wsl": "WSL", "rkt": "rkt (container)",
}

// Display managers and desktop shells: a Linux machine running one is
// somebody's workstation; one without is a server. (The default systemd
// target doesn't tell: Ubuntu Server ships with graphical.target too.)
var desktopProcess = regexp.MustCompile(`^(gdm|gdm3|gdm-session-wor|sddm|lightdm|xdm|lxdm|gnome-shell|plasmashell|kwin_x11|kwin_wayland|xfce4-session|cinnamon|mate-session|Xorg|Xwayland)$`)

func linuxSystem(d *Details, processes []string) {
	s := &d.System
	s.Manufacturer = dmi("sys_vendor")
	s.Model = dmi("product_name")
	if v := dmi("product_version"); v != "" && !isPlaceholder(v) && strings.EqualFold(s.Manufacturer, "LENOVO") {
		s.Model = v + " (" + s.Model + ")" // Lenovo puts the marketing name in product_version
	}
	s.SerialNumber = dmi("product_serial")
	if s.SerialNumber == "" || isPlaceholder(s.SerialNumber) {
		s.SerialNumber = dmi("chassis_serial")
	}
	s.UUID = dmi("product_uuid")
	s.BIOSVendor, s.BIOSVersion = dmi("bios_vendor"), dmi("bios_version")
	s.BIOSDate = usDate(dmi("bios_date"))
	if n, err := strconv.Atoi(dmi("chassis_type")); err == nil {
		s.FormFactor = FormFactorFromChassis(n)
	}
	// Raspberry Pi and other boards without DMI.
	if s.Model == "" {
		if model, ok := sysinfo.ReadFirst("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"); ok {
			s.Model = strings.TrimRight(model, "\x00")
		}
	}

	if out, code, ok := sysinfo.RunExit(sysinfo.CommandTimeout, "systemd-detect-virt"); ok && code == 0 && out != "none" {
		s.Virtual = true
		s.Hypervisor = hypervisorNames[out]
		if s.Hypervisor == "" {
			s.Hypervisor = out
		}
	} else if cpuinfo, ok := sysinfo.ReadFirst("/proc/cpuinfo"); ok && regexp.MustCompile(`(?m)^flags\s*:.*\bhypervisor\b`).MatchString(cpuinfo) {
		s.Virtual = true
		s.Hypervisor = guessHypervisor(s.Manufacturer + " " + s.Model)
	}

	desktop := false
	for _, p := range processes {
		if desktopProcess.MatchString(p) {
			desktop = true
			break
		}
	}
	switch {
	case s.FormFactor == "laptop" || s.FormFactor == "tablet" || desktop:
		s.Role = "workstation"
	default:
		s.Role = "server"
	}

	if out, ok := sysinfo.Run("realm", "list"); ok {
		s.Domain = ParseKeyValue(out, "domain-name")
	}
	if s.Domain == "" {
		if out, ok := sysinfo.Run("dnsdomainname"); ok && !strings.Contains(out, " ") {
			s.Domain = out
		}
	}
	s.Timezone = unixTimezone()
}

func guessHypervisor(text string) string {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "vmware"):
		return "VMware"
	case strings.Contains(t, "virtualbox"):
		return "VirtualBox"
	case strings.Contains(t, "microsoft") && strings.Contains(t, "virtual"):
		return "Hyper-V"
	case strings.Contains(t, "qemu") || strings.Contains(t, "kvm"):
		return "KVM"
	case strings.Contains(t, "xen"):
		return "Xen"
	case strings.Contains(t, "amazon"):
		return "Amazon EC2"
	case strings.Contains(t, "google"):
		return "Google Compute Engine"
	}
	return ""
}

// usDate turns firmware's MM/DD/YYYY into YYYY-MM-DD.
func usDate(v string) string {
	if t, err := time.Parse("01/02/2006", strings.TrimSpace(v)); err == nil {
		return t.Format("2006-01-02")
	}
	return v
}

func linuxOS(d *Details) {
	o := &d.OS
	release := map[string]string{}
	if text, ok := sysinfo.ReadFirst("/etc/os-release", "/usr/lib/os-release"); ok {
		release = ParseOSRelease(text)
	}
	o.Name = firstNonEmpty(release["PRETTY_NAME"], strings.TrimSpace(release["NAME"]+" "+release["VERSION"]), "Linux")
	o.Version = release["VERSION_ID"]
	o.Build = release["BUILD_ID"]
	o.Kernel, _ = sysinfo.Run("uname", "-r")
	o.Arch, _ = sysinfo.Run("uname", "-m")
	if o.Arch == "" {
		o.Arch = runtimeArch()
	}
	if stat, ok := sysinfo.ReadFirst("/proc/stat"); ok {
		if sec, err := strconv.ParseInt(ParseKeyValue(strings.ReplaceAll(stat, "btime ", "btime:"), "btime"), 10, 64); err == nil {
			o.LastBoot = unixTime(sec)
		}
	}
	// The root filesystem's birth time, where the kernel and fs record it.
	if out, ok := sysinfo.Run("stat", "-c", "%W", "/"); ok {
		if sec, err := strconv.ParseInt(out, 10, 64); err == nil && sec > 0 {
			o.InstallDate = dateOnly(unixTime(sec))
		}
	}
	if o.InstallDate == "" {
		for _, p := range []string{"/var/log/installer", "/root/anaconda-ks.cfg", "/var/log/anaconda"} {
			if info, err := os.Stat(p); err == nil {
				o.InstallDate = info.ModTime().UTC().Format("2006-01-02")
				break
			}
		}
	}
	switch {
	case sysinfo.Exists("/var/run/reboot-required"):
		o.PendingReboot = boolPtr(true)
	case sysinfo.Exists("/usr/bin/dpkg"):
		o.PendingReboot = boolPtr(false)
	default:
		if _, code, ok := sysinfo.RunExit(sysinfo.CommandTimeout, "needs-restarting", "-r"); ok && (code == 0 || code == 1) {
			o.PendingReboot = boolPtr(code == 1)
		}
	}

	kernel := o.Kernel
	switch {
	case o.Name != "" && kernel != "":
		d.legacyOS = o.Name + " (kernel " + kernel + ")"
	case kernel != "":
		d.legacyOS = "Linux " + kernel
	default:
		d.legacyOS = o.Name
	}
}

func linuxCPU() CPU {
	var c CPU
	if out, ok := sysinfo.Run("lscpu"); ok {
		c = ParseLscpu(out)
	}
	if text, ok := sysinfo.ReadFirst("/proc/cpuinfo"); ok {
		info := ParseCPUInfo(text)
		if c.Model == "" {
			c.Model = info.Model
		}
		if c.Vendor == "" {
			c.Vendor = info.Vendor
		}
		if c.Threads == 0 {
			c.Threads = info.Threads
		}
		if c.Cores == 0 {
			c.Cores = info.Cores
		}
		if c.Sockets == 0 {
			c.Sockets = info.Sockets
		}
		if c.SpeedMhz == 0 {
			c.SpeedMhz = info.SpeedMhz
		}
	}
	if khz, ok := sysinfo.ReadFirst("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"); ok {
		if n, err := strconv.Atoi(khz); err == nil && n > 0 {
			c.SpeedMhz = n / 1000
		}
	}
	return c
}

func linuxMemory(d *Details) {
	if text, ok := sysinfo.ReadFirst("/proc/meminfo"); ok {
		if f := strings.Fields(ParseKeyValue(text, "MemTotal")); len(f) > 0 {
			if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				d.Memory.TotalMb = kb / 1024
			}
		}
	}
	// dmidecode needs root, which the service has.
	if out, ok := sysinfo.Run("dmidecode", "-t", "17"); ok {
		d.Memory.Modules, d.Memory.Slots = ParseDmidecodeMemory(out)
	}
}

func linuxVolumes(d *Details) {
	// GNU df can drop pseudo filesystems by type; fall back to plain -kP.
	out, ok := sysinfo.Run("df", "-kP", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
	if !ok {
		out, ok = sysinfo.Run("df", "-kP")
	}
	info, anyCrypt := map[string]volumeInfo{}, false
	if tree, ok := sysinfo.Run("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,LABEL,MOUNTPOINT"); ok {
		info, anyCrypt = ParseLsblkTree(tree)
	}
	if ok {
		for _, disk := range ParseDfPortable(out) {
			v := Volume{Mount: disk.Mount, TotalGb: disk.TotalGb, FreeGb: disk.FreeGb}
			if i, known := info[disk.Mount]; known {
				v.FileSystem, v.Label, v.Encrypted = i.FileSystem, i.Label, boolPtr(i.Encrypted)
			}
			d.Volumes = append(d.Volumes, v)
		}
	}
	if len(info) > 0 || anyCrypt {
		if root, known := info["/"]; known {
			d.Security.SystemDiskEncrypted = boolPtr(root.Encrypted)
		} else {
			d.Security.SystemDiskEncrypted = boolPtr(anyCrypt)
		}
		if anyCrypt {
			d.Security.EncryptionMethod = "LUKS"
		}
	}
}

func linuxNetwork() []NetInterface {
	list := goInterfaces()
	for i := range list {
		base := "/sys/class/net/" + list[i].Name
		if !sysinfo.Exists(base + "/device") {
			list[i].Virtual = true // bridges, veth pairs, tunnels have no hardware device
		}
		if v, ok := sysinfo.ReadFirst(base + "/speed"); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				list[i].SpeedMbps = n
			}
		}
	}
	iface, gateway := "", ""
	if text, ok := sysinfo.ReadFirst("/proc/net/route"); ok {
		iface, gateway = ParseProcNetRoute(text)
	}
	var dns []string
	// systemd-resolved's stub (127.0.0.53) hides the real servers; its
	// upstream list is in this file.
	if text, ok := sysinfo.ReadFirst("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"); ok {
		dns = ParseResolvConf(text)
	}
	return withGateway(list, iface, gateway, dns)
}

func linuxMonitors() []Monitor {
	var out []Monitor
	matches, _ := filepath.Glob("/sys/class/drm/*/edid")
	for _, path := range matches {
		if status, _ := sysinfo.ReadFirst(filepath.Join(filepath.Dir(path), "status")); status != "connected" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if m, ok := ParseEDID(b); ok {
			out = append(out, m)
		}
	}
	return out
}

func linuxBatteries() []Battery {
	var out []Battery
	matches, _ := filepath.Glob("/sys/class/power_supply/*")
	for _, dir := range matches {
		if kind, _ := sysinfo.ReadFirst(dir + "/type"); kind != "Battery" {
			continue
		}
		read := func(name string) int64 {
			v, _ := sysinfo.ReadFirst(dir + "/" + name)
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		b := Battery{Name: filepath.Base(dir)}
		b.Manufacturer, _ = sysinfo.ReadFirst(dir + "/manufacturer")
		if model, ok := sysinfo.ReadFirst(dir + "/model_name"); ok {
			b.Name = model
		}
		b.Chemistry, _ = sysinfo.ReadFirst(dir + "/technology")
		b.CycleCount = int(read("cycle_count"))
		// energy_* is in µWh; charge_* in µAh, converted with the design voltage.
		if design := read("energy_full_design"); design > 0 {
			b.DesignCapacityMwh, b.FullCapacityMwh = design/1000, read("energy_full")/1000
		} else if design := read("charge_full_design"); design > 0 {
			volts := read("voltage_min_design")
			if volts == 0 {
				volts = read("voltage_now")
			}
			if volts > 0 {
				b.DesignCapacityMwh = design * volts / 1e9
				b.FullCapacityMwh = read("charge_full") * volts / 1e9
			} else if full := read("charge_full"); full > 0 {
				b.HealthPercent = int(full * 100 / design)
			}
		}
		out = append(out, b)
	}
	return out
}

func linuxUsers(d *Details) {
	if out, ok := sysinfo.Run("who"); ok {
		d.Users.LoggedOn = ParseWho(out)
	}
	if out, ok := sysinfo.Run("last", "-n", "1", "-w"); ok {
		for _, line := range sysinfo.Lines(out) {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] != "reboot" && f[0] != "wtmp" {
				d.Users.LastLogon = f[0]
				break
			}
		}
	}
	if text, ok := sysinfo.ReadFirst("/etc/group"); ok {
		d.Users.LocalAdmins = append([]string{"root"}, ParseGroupMembers(text, "sudo", "wheel", "admin")...)
	}
	if text, ok := sysinfo.ReadFirst("/etc/passwd"); ok {
		d.Users.LocalUsers = ParsePasswdUsers(text)
	}
}

func linuxSecurity(d *Details, processes []string) {
	sec := &d.Security
	sec.Features = map[string]string{}
	switch {
	case commandSays("ufw", []string{"status"}, "Status: active", "Status: inactive", &sec.FirewallEnabled):
	case commandSays("firewall-cmd", []string{"--state"}, "running", "not running", &sec.FirewallEnabled):
	default:
		if out, ok := sysinfo.Run("nft", "list", "ruleset"); ok {
			sec.FirewallEnabled = boolPtr(strings.Contains(out, "hook input") && (strings.Contains(out, "policy drop") || strings.Count(out, "\n") > 10))
		} else if out, ok := sysinfo.Run("iptables", "-S", "INPUT"); ok {
			sec.FirewallEnabled = boolPtr(strings.Contains(out, "-P INPUT DROP") || strings.Count(out, "-A INPUT") > 0)
		}
	}
	if out, ok := sysinfo.Run("getenforce"); ok {
		sec.Features["selinux"] = strings.ToLower(out)
	}
	if v, ok := sysinfo.ReadFirst("/sys/module/apparmor/parameters/enabled"); ok {
		if v == "Y" {
			sec.Features["apparmor"] = "enabled"
		} else {
			sec.Features["apparmor"] = "disabled"
		}
	}
	// The SecureBoot EFI variable: 4 bytes of attributes, then 1 = on.
	if matches, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*"); len(matches) > 0 {
		if b, err := os.ReadFile(matches[0]); err == nil && len(b) >= 5 {
			sec.SecureBoot = boolPtr(b[4] == 1)
		}
	} else if sysinfo.Exists("/sys/firmware/efi") {
		sec.SecureBoot = boolPtr(false)
	}
	if sysinfo.Exists("/sys/class/tpm/tpm0") {
		sec.TPMPresent = boolPtr(true)
		if v, ok := sysinfo.ReadFirst("/sys/class/tpm/tpm0/tpm_version_major"); ok {
			sec.TPMVersion = v + ".0"
		}
	} else {
		sec.TPMPresent = boolPtr(false)
	}
	sec.Agents = DetectAgents(processes)
	for _, a := range sec.Agents {
		sec.Antivirus = append(sec.Antivirus, Antivirus{Name: a, Enabled: boolPtr(true)})
	}
	d.legacyAV = "not_applicable"
	if len(sec.Agents) > 0 {
		d.legacyAV = "enabled"
	}
}

// commandSays sets *dst when a command's output contains on or off, and
// reports whether the command gave an answer.
func commandSays(name string, args []string, on, off string, dst **bool) bool {
	out, _, ok := sysinfo.RunExit(sysinfo.CommandTimeout, name, args...)
	if !ok {
		return false
	}
	switch {
	case strings.Contains(out, off):
		*dst = boolPtr(false)
	case strings.Contains(out, on):
		*dst = boolPtr(true)
	default:
		return false
	}
	return true
}

func linuxSoftware() []Software {
	var out []Software
	if text, ok := sysinfo.Run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\n"); ok {
		out = ParseDpkgSoftware(text)
	} else if text, ok := sysinfo.Run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\n"); ok {
		out = ParseRpmSoftware(text)
	} else if text, ok := sysinfo.Run("pacman", "-Q"); ok {
		out = packagesToSoftware(ParseTabbedPackages(strings.ReplaceAll(text, " ", "\t")), "pacman")
	} else if text, ok := sysinfo.Run("apk", "info", "-v"); ok {
		out = packagesToSoftware(ParseAPKPackages(text), "apk")
	}
	if text, ok := sysinfo.Run("snap", "list"); ok {
		out = append(out, ParseSnapList(text)...)
	}
	if text, ok := sysinfo.Run("flatpak", "list", "--app", "--columns=name,version,origin"); ok {
		out = append(out, ParseFlatpakList(text)...)
	}
	return out
}

// linuxUpdates counts pending updates from the package manager's local
// cache only: the agent never refreshes repositories or downloads anything.
func linuxUpdates() Updates {
	var u Updates
	if sysinfo.Exists("/usr/bin/apt-get") {
		if out, ok := sysinfo.Run("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"); ok {
			total, security := ParseAptSimulate(out)
			u.Pending, u.PendingSecurity = &total, &security
		}
		if info, err := os.Stat("/var/log/dpkg.log"); err == nil {
			u.LastInstalled = info.ModTime().UTC().Format("2006-01-02")
		}
	} else if sysinfo.Exists("/usr/bin/dnf") || sysinfo.Exists("/usr/bin/yum") {
		tool := "dnf"
		if !sysinfo.Exists("/usr/bin/dnf") {
			tool = "yum"
		}
		if out, code, ok := sysinfo.RunExit(sysinfo.CommandTimeout, tool, "-q", "--cacheonly", "check-update"); ok && (code == 0 || code == 100) {
			n := ParseDnfCheckUpdate(out)
			u.Pending = &n
		}
		if out, ok := sysinfo.Run("rpm", "-qa", "--last", "--qf", "%{INSTALLTIME}\n"); ok {
			if f := strings.Fields(out); len(f) > 0 {
				if sec, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					u.LastInstalled = dateOnly(unixTime(sec))
				}
			}
		}
	}
	return u
}

func linuxServices() []Service {
	units, ok := sysinfo.Run("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
	if !ok {
		return nil
	}
	files, _ := sysinfo.Run("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	return ParseSystemctl(units, files)
}

func linuxPorts() []Port {
	if out, ok := sysinfo.Run("ss", "-H", "-tulnp"); ok {
		return ParseSS(out)
	}
	if out, ok := sysinfo.Run("ss", "-tulnp"); ok {
		return ParseSS(out)
	}
	return nil
}

func linuxGuests() []Guest {
	out := containerGuests()
	if text, ok := sysinfo.Run("virsh", "list", "--all"); ok {
		out = append(out, ParseVirshList(text)...)
	}
	if text, ok := sysinfo.Run("qm", "list"); ok {
		out = append(out, ParseProxmoxList(text, false)...)
	}
	if text, ok := sysinfo.Run("pct", "list"); ok {
		out = append(out, ParseProxmoxList(text, true)...)
	}
	return out
}
