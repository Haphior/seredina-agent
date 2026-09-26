package inventory

import (
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the version of the Details layout, sent as
// inventory.schema so the server can tell layouts apart.
const SchemaVersion = 2

// Caps on every list, well above a real machine, so one odd device can't
// send an unbounded payload. The server enforces the same limits.
const (
	maxSoftware  = 2000
	maxServices  = 1000
	maxPorts     = 500
	maxUpdates   = 500
	maxGuests    = 500
	maxNetwork   = 64
	maxDisks     = 64
	maxVolumes   = 128
	maxModules   = 64
	maxSmall     = 32 // GPUs, monitors, batteries, CPUs' sockets...
	maxPrinters  = 100
	maxUsers     = 200
	maxRoles     = 100
	maxAgents    = 50
	maxTextShort = 200
	maxTextLong  = 500
)

// Details is the full inventory, the counterpart of what GLPI-Agent or
// Lansweeper collect: hardware down to memory modules and disk serials, the
// OS, software with publishers, security posture, and for servers their
// services, listening ports, roles and guests. Every part is best effort:
// what a tool or permission doesn't give stays empty.
type Details struct {
	Schema          int            `json:"schema"`
	CollectedAt     string         `json:"collectedAt"`
	System          System         `json:"system"`
	OS              OSInfo         `json:"os"`
	CPU             CPU            `json:"cpu"`
	Memory          Memory         `json:"memory"`
	Disks           []PhysicalDisk `json:"disks"`
	Volumes         []Volume       `json:"volumes"`
	Network         []NetInterface `json:"network"`
	GPUs            []GPU          `json:"gpus"`
	Monitors        []Monitor      `json:"monitors"`
	Batteries       []Battery      `json:"batteries"`
	Printers        []Printer      `json:"printers"`
	Users           Users          `json:"users"`
	Security        Security       `json:"security"`
	Software        []Software     `json:"software"`
	Updates         Updates        `json:"updates"`
	Services        []Service      `json:"services"`
	Ports           []Port         `json:"ports"`
	ServerRoles     []string       `json:"serverRoles"`
	VirtualMachines []Guest        `json:"virtualMachines"`

	// The pre-schema-2 summary strings, kept for older servers.
	legacyOS string
	legacyAV string
}

// System is the machine itself.
type System struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	// FormFactor: laptop, desktop, server, virtual, tablet or other.
	FormFactor string `json:"formFactor,omitempty"`
	// Role: server or workstation. Seredina files the asset by it.
	Role        string `json:"role,omitempty"`
	Virtual     bool   `json:"virtual"`
	Hypervisor  string `json:"hypervisor,omitempty"`
	BIOSVendor  string `json:"biosVendor,omitempty"`
	BIOSVersion string `json:"biosVersion,omitempty"`
	BIOSDate    string `json:"biosDate,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
}

// OSInfo is the operating system.
type OSInfo struct {
	Name          string `json:"name,omitempty"`
	Version       string `json:"version,omitempty"`
	Build         string `json:"build,omitempty"`
	Arch          string `json:"arch,omitempty"`
	Kernel        string `json:"kernel,omitempty"`
	InstallDate   string `json:"installDate,omitempty"`
	LastBoot      string `json:"lastBoot,omitempty"`
	PendingReboot *bool  `json:"pendingReboot,omitempty"`
}

// CPU sums up the processors.
type CPU struct {
	Model    string `json:"model,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Sockets  int    `json:"sockets,omitempty"`
	Cores    int    `json:"cores,omitempty"`
	Threads  int    `json:"threads,omitempty"`
	SpeedMhz int    `json:"speedMhz,omitempty"`
}

// Memory is the RAM and, where the firmware tells, each module.
type Memory struct {
	TotalMb int64          `json:"totalMb,omitempty"`
	Slots   int            `json:"slots,omitempty"`
	Modules []MemoryModule `json:"modules"`
}

// MemoryModule is one installed memory module.
type MemoryModule struct {
	Slot         string `json:"slot,omitempty"`
	SizeMb       int64  `json:"sizeMb,omitempty"`
	Type         string `json:"type,omitempty"`
	SpeedMhz     int    `json:"speedMhz,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	PartNumber   string `json:"partNumber,omitempty"`
}

// PhysicalDisk is a drive, not a partition.
type PhysicalDisk struct {
	Name         string  `json:"name,omitempty"`
	Model        string  `json:"model,omitempty"`
	SerialNumber string  `json:"serialNumber,omitempty"`
	SizeGb       float64 `json:"sizeGb,omitempty"`
	// Type: ssd, hdd, nvme, virtual or unknown.
	Type      string `json:"type,omitempty"`
	Interface string `json:"interface,omitempty"`
	Health    string `json:"health,omitempty"`
}

// Volume is a mounted filesystem.
type Volume struct {
	Mount      string  `json:"mount"`
	Label      string  `json:"label,omitempty"`
	FileSystem string  `json:"fileSystem,omitempty"`
	TotalGb    float64 `json:"totalGb"`
	FreeGb     float64 `json:"freeGb"`
	Encrypted  *bool   `json:"encrypted,omitempty"`
}

// NetInterface is a network adapter with its addresses.
type NetInterface struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	Gateway     string   `json:"gateway,omitempty"`
	DNS         []string `json:"dns"`
	DHCP        *bool    `json:"dhcp,omitempty"`
	SpeedMbps   int      `json:"speedMbps,omitempty"`
	Up          bool     `json:"up"`
	Virtual     bool     `json:"virtual"`
}

// GPU is a graphics adapter.
type GPU struct {
	Name          string `json:"name,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	DriverVersion string `json:"driverVersion,omitempty"`
	MemoryMb      int64  `json:"memoryMb,omitempty"`
}

// Monitor is a connected display.
type Monitor struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	Year         int    `json:"year,omitempty"`
}

// Battery is a laptop battery and its wear.
type Battery struct {
	Name              string `json:"name,omitempty"`
	Manufacturer      string `json:"manufacturer,omitempty"`
	Chemistry         string `json:"chemistry,omitempty"`
	DesignCapacityMwh int64  `json:"designCapacityMwh,omitempty"`
	FullCapacityMwh   int64  `json:"fullCapacityMwh,omitempty"`
	HealthPercent     int    `json:"healthPercent,omitempty"`
	CycleCount        int    `json:"cycleCount,omitempty"`
}

// Printer is a printer queue configured on the machine.
type Printer struct {
	Name    string `json:"name"`
	Driver  string `json:"driver,omitempty"`
	Port    string `json:"port,omitempty"`
	Shared  bool   `json:"shared"`
	Network bool   `json:"network"`
	Default bool   `json:"default"`
}

// Users is who uses the machine and who administers it.
type Users struct {
	LoggedOn    []string `json:"loggedOn"`
	LastLogon   string   `json:"lastLogon,omitempty"`
	LocalAdmins []string `json:"localAdmins"`
	LocalUsers  []string `json:"localUsers"`
}

// Security is the machine's protection.
type Security struct {
	Antivirus           []Antivirus `json:"antivirus"`
	FirewallEnabled     *bool       `json:"firewallEnabled,omitempty"`
	SystemDiskEncrypted *bool       `json:"systemDiskEncrypted,omitempty"`
	EncryptionMethod    string      `json:"encryptionMethod,omitempty"`
	SecureBoot          *bool       `json:"secureBoot,omitempty"`
	TPMPresent          *bool       `json:"tpmPresent,omitempty"`
	TPMVersion          string      `json:"tpmVersion,omitempty"`
	// Other OS protections by name: uac, selinux, apparmor, gatekeeper, sip.
	Features map[string]string `json:"features,omitempty"`
	// Security products found running (EDR, antivirus), by product name.
	Agents []string `json:"agents"`
}

// Antivirus is one antivirus product and its state.
type Antivirus struct {
	Name     string `json:"name"`
	Enabled  *bool  `json:"enabled,omitempty"`
	UpToDate *bool  `json:"upToDate,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Software is one installed program.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"installDate,omitempty"`
	Arch        string `json:"arch,omitempty"`
	// Source: registry, dpkg, rpm, pacman, apk, snap, flatpak or app.
	Source string `json:"source,omitempty"`
}

// Updates is the OS's update state.
type Updates struct {
	Installed []Hotfix `json:"installed"`
	// Pending counts updates the package manager already knows about
	// (from its local cache: the agent never downloads anything).
	Pending         *int   `json:"pending,omitempty"`
	PendingSecurity *int   `json:"pendingSecurity,omitempty"`
	LastInstalled   string `json:"lastInstalled,omitempty"`
}

// Hotfix is one installed update (Windows KBs).
type Hotfix struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	InstalledOn string `json:"installedOn,omitempty"`
}

// Service is a system service or daemon.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	// State: running, stopped, failed or other.
	State string `json:"state,omitempty"`
	// StartMode: auto, manual, disabled or other.
	StartMode string `json:"startMode,omitempty"`
}

// Port is a listening socket.
type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

// Guest is a virtual machine or container this machine hosts.
type Guest struct {
	Name string `json:"name"`
	// Type: hyperv, docker, podman, libvirt or proxmox.
	Type  string `json:"type"`
	State string `json:"state,omitempty"`
	Image string `json:"image,omitempty"`
}

// finish trims every text field, drops empty entries and duplicates, caps
// every list, and makes nil lists empty ones, so the JSON always has the
// same shape.
func (d *Details) finish() {
	d.Schema = SchemaVersion
	d.CollectedAt = time.Now().UTC().Format(time.RFC3339)

	s := &d.System
	for _, p := range []*string{&s.Manufacturer, &s.Model, &s.SerialNumber, &s.UUID, &s.Hypervisor, &s.BIOSVendor, &s.BIOSVersion, &s.BIOSDate, &s.Domain, &s.Timezone} {
		*p = cleanText(*p, maxTextShort)
	}
	s.SerialNumber = realSerial(s.SerialNumber)
	s.UUID = realSerial(s.UUID)
	if s.Manufacturer == "" || isPlaceholder(s.Manufacturer) {
		s.Manufacturer = ""
	}
	if isPlaceholder(s.Model) {
		s.Model = ""
	}
	if s.FormFactor == "" {
		s.FormFactor = "other"
	}
	if s.Virtual && s.FormFactor != "virtual" {
		s.FormFactor = "virtual"
	}
	if s.Role == "" {
		s.Role = "workstation"
		if s.FormFactor == "server" {
			s.Role = "server"
		}
	}

	o := &d.OS
	for _, p := range []*string{&o.Name, &o.Version, &o.Build, &o.Arch, &o.Kernel, &o.InstallDate, &o.LastBoot} {
		*p = cleanText(*p, maxTextShort)
	}
	d.CPU.Model = cleanText(d.CPU.Model, maxTextShort)
	d.CPU.Vendor = cleanText(d.CPU.Vendor, maxTextShort)

	d.Memory.Modules = capList(filter(d.Memory.Modules, func(m *MemoryModule) bool {
		m.Slot, m.Type, m.Manufacturer = cleanText(m.Slot, maxTextShort), cleanText(m.Type, 50), cleanText(m.Manufacturer, maxTextShort)
		m.SerialNumber, m.PartNumber = realSerial(cleanText(m.SerialNumber, maxTextShort)), cleanText(m.PartNumber, maxTextShort)
		return m.SizeMb > 0
	}), maxModules)
	d.Disks = capList(filter(d.Disks, func(x *PhysicalDisk) bool {
		x.Name, x.Model, x.Interface, x.Health = cleanText(x.Name, maxTextShort), cleanText(x.Model, maxTextShort), cleanText(x.Interface, 50), cleanText(x.Health, 50)
		x.SerialNumber = realSerial(cleanText(x.SerialNumber, maxTextShort))
		if x.Type == "" {
			x.Type = "unknown"
		}
		return x.Name != "" || x.Model != ""
	}), maxDisks)
	seenMount := map[string]bool{}
	d.Volumes = capList(filter(d.Volumes, func(v *Volume) bool {
		v.Mount, v.Label, v.FileSystem = cleanText(v.Mount, maxTextLong), cleanText(v.Label, maxTextShort), cleanText(v.FileSystem, 50)
		if v.Mount == "" || seenMount[v.Mount] || v.TotalGb <= 0 {
			return false
		}
		seenMount[v.Mount] = true
		return true
	}), maxVolumes)
	d.Network = capList(filter(d.Network, func(n *NetInterface) bool {
		n.Name, n.Description, n.Gateway = cleanText(n.Name, maxTextShort), cleanText(n.Description, maxTextShort), cleanText(n.Gateway, 100)
		n.IPv4, n.IPv6, n.DNS = cleanList(n.IPv4, 32), cleanList(n.IPv6, 32), cleanList(n.DNS, 16)
		return n.Name != "" || n.MAC != ""
	}), maxNetwork)
	d.GPUs = capList(filter(d.GPUs, func(g *GPU) bool {
		g.Name, g.Vendor, g.DriverVersion = cleanText(g.Name, maxTextShort), cleanText(g.Vendor, maxTextShort), cleanText(g.DriverVersion, 100)
		return g.Name != ""
	}), maxSmall)
	d.Monitors = capList(filter(d.Monitors, func(m *Monitor) bool {
		m.Manufacturer, m.Model, m.SerialNumber = cleanText(m.Manufacturer, maxTextShort), cleanText(m.Model, maxTextShort), realSerial(cleanText(m.SerialNumber, maxTextShort))
		return m.Model != "" || m.Manufacturer != ""
	}), maxSmall)
	d.Batteries = capList(filter(d.Batteries, func(b *Battery) bool {
		b.Name, b.Manufacturer, b.Chemistry = cleanText(b.Name, maxTextShort), cleanText(b.Manufacturer, maxTextShort), cleanText(b.Chemistry, 50)
		if b.HealthPercent == 0 && b.DesignCapacityMwh > 0 && b.FullCapacityMwh > 0 {
			b.HealthPercent = int(b.FullCapacityMwh * 100 / b.DesignCapacityMwh)
		}
		if b.HealthPercent > 100 {
			b.HealthPercent = 100
		}
		return true
	}), maxSmall)
	d.Printers = capList(filter(d.Printers, func(p *Printer) bool {
		p.Name, p.Driver, p.Port = cleanText(p.Name, maxTextShort), cleanText(p.Driver, maxTextShort), cleanText(p.Port, maxTextShort)
		return p.Name != ""
	}), maxPrinters)

	u := &d.Users
	u.LoggedOn, u.LocalAdmins, u.LocalUsers = cleanList(u.LoggedOn, maxUsers), cleanList(u.LocalAdmins, maxUsers), cleanList(u.LocalUsers, maxUsers)
	u.LastLogon = cleanText(u.LastLogon, maxTextShort)

	sec := &d.Security
	seenAV := map[string]bool{}
	sec.Antivirus = capList(filter(sec.Antivirus, func(a *Antivirus) bool {
		a.Name, a.Version = cleanText(a.Name, maxTextShort), cleanText(a.Version, 100)
		if a.Name == "" || seenAV[strings.ToLower(a.Name)] {
			return false
		}
		seenAV[strings.ToLower(a.Name)] = true
		return true
	}), maxSmall)
	sec.Agents = cleanList(sec.Agents, maxAgents)
	sec.TPMVersion = cleanText(sec.TPMVersion, 50)
	sec.EncryptionMethod = cleanText(sec.EncryptionMethod, 50)
	for k, v := range sec.Features {
		if v = cleanText(v, 100); v == "" {
			delete(sec.Features, k)
		} else {
			sec.Features[k] = v
		}
	}

	seenSW := map[string]bool{}
	d.Software = filter(d.Software, func(x *Software) bool {
		x.Name, x.Version, x.Publisher = cleanText(x.Name, maxTextShort), cleanText(x.Version, 100), cleanText(x.Publisher, maxTextShort)
		x.InstallDate, x.Arch, x.Source = cleanText(x.InstallDate, 30), cleanText(x.Arch, 30), cleanText(x.Source, 30)
		key := strings.ToLower(x.Name + "\x00" + x.Version + "\x00" + x.Arch)
		if x.Name == "" || seenSW[key] {
			return false
		}
		seenSW[key] = true
		return true
	})
	sort.SliceStable(d.Software, func(i, j int) bool { return strings.ToLower(d.Software[i].Name) < strings.ToLower(d.Software[j].Name) })
	d.Software = capList(d.Software, maxSoftware)

	d.Updates.Installed = capList(filter(d.Updates.Installed, func(h *Hotfix) bool {
		h.ID, h.Description, h.InstalledOn = cleanText(h.ID, 100), cleanText(h.Description, maxTextShort), cleanText(h.InstalledOn, 30)
		return h.ID != ""
	}), maxUpdates)
	d.Updates.LastInstalled = cleanText(d.Updates.LastInstalled, 30)

	d.Services = capList(filter(d.Services, func(x *Service) bool {
		x.Name, x.DisplayName = cleanText(x.Name, maxTextShort), cleanText(x.DisplayName, maxTextShort)
		return x.Name != ""
	}), maxServices)
	seenPort := map[string]bool{}
	d.Ports = filter(d.Ports, func(p *Port) bool {
		p.Address, p.Process = cleanText(p.Address, 100), cleanText(p.Process, maxTextShort)
		key := p.Protocol + "/" + p.Address + "/" + itoa(p.Port)
		if p.Port <= 0 || p.Port > 65535 || seenPort[key] {
			return false
		}
		seenPort[key] = true
		return true
	})
	sort.SliceStable(d.Ports, func(i, j int) bool {
		if d.Ports[i].Port != d.Ports[j].Port {
			return d.Ports[i].Port < d.Ports[j].Port
		}
		return d.Ports[i].Protocol < d.Ports[j].Protocol
	})
	d.Ports = capList(d.Ports, maxPorts)
	d.ServerRoles = cleanList(d.ServerRoles, maxRoles)
	d.VirtualMachines = capList(filter(d.VirtualMachines, func(g *Guest) bool {
		g.Name, g.State, g.Image = cleanText(g.Name, maxTextShort), cleanText(g.State, 50), cleanText(g.Image, maxTextShort)
		return g.Name != ""
	}), maxGuests)

	if d.Security.Agents == nil {
		d.Security.Agents = []string{}
	}
	if d.Updates.Installed == nil {
		d.Updates.Installed = []Hotfix{}
	}
}

// legacy fills the pre-schema-2 fields from the details, so a server that
// doesn't know "inventory" still gets what it did before.
func (d *Details) legacy() Inventory {
	inv := Inventory{
		CPUModel:        d.CPU.Model,
		MemoryTotalMb:   d.Memory.TotalMb,
		OSVersion:       d.legacyOS,
		DiskEncrypted:   d.Security.SystemDiskEncrypted,
		AntivirusStatus: d.legacyAV,
	}
	if inv.OSVersion == "" {
		inv.OSVersion = strings.TrimSpace(d.OS.Name + " " + d.OS.Version)
	}
	for _, v := range d.Volumes {
		inv.DiskSummary = append(inv.DiskSummary, Disk{Mount: v.Mount, TotalGb: v.TotalGb, FreeGb: v.FreeGb})
	}
	for _, s := range d.Software {
		inv.InstalledPackages = append(inv.InstalledPackages, Package{Name: s.Name, Version: s.Version})
	}
	return inv
}

// cleanText trims, removes control characters and caps the length at a
// rune boundary.
func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := 0
	for i := range s {
		if i > n {
			break
		}
		cut = i
	}
	return strings.TrimSpace(s[:cut])
}

// cleanList trims, drops empties and duplicates, and caps a string list.
func cleanList(list []string, n int) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range list {
		v = cleanText(v, maxTextShort)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
		if len(out) == n {
			break
		}
	}
	return out
}

func filter[T any](list []T, keep func(*T) bool) []T {
	out := make([]T, 0, len(list))
	for i := range list {
		if keep(&list[i]) {
			out = append(out, list[i])
		}
	}
	return out
}

func capList[T any](list []T, n int) []T {
	if list == nil {
		return []T{}
	}
	if len(list) > n {
		return list[:n]
	}
	return list
}

// Firmware placeholders that mean "no value": vendors ship these instead of
// leaving the field empty.
var placeholders = map[string]bool{
	"": true, "0": true, "none": true, "n/a": true, "na": true, "null": true, "unknown": true, "not specified": true,
	"not available": true, "not applicable": true, "default string": true, "to be filled by o.e.m.": true,
	"to be filled by oem": true, "system serial number": true, "system product name": true, "system manufacturer": true,
	"chassis serial number": true, "base board serial number": true, "0123456789": true, "123456789": true,
	"oem": true, "o.e.m.": true, "xxxxxxxxxxxx": true, "system version": true, "invalid": true,
	"00000000-0000-0000-0000-000000000000": true, "ffffffff-ffff-ffff-ffff-ffffffffffff": true, "sernum": true,
}

func isPlaceholder(v string) bool {
	return placeholders[strings.ToLower(strings.TrimSpace(v))]
}

// realSerial drops placeholder serial numbers and all-zero or all-space
// values, which several vendors report for "none".
func realSerial(v string) string {
	v = strings.TrimSpace(v)
	if isPlaceholder(v) || strings.Trim(v, "0-. ") == "" {
		return ""
	}
	return v
}

// FormFactorFromChassis maps SMBIOS chassis types (the same numbers on
// every OS) to a form factor.
func FormFactorFromChassis(chassis int) string {
	switch chassis {
	case 8, 9, 10, 14:
		return "laptop"
	case 30, 31, 32:
		return "tablet"
	case 3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36:
		return "desktop"
	case 17, 23, 25, 28, 29:
		return "server"
	}
	return ""
}

func itoa(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
