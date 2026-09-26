package inventory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

// MacProfilerTypes are the system_profiler data types the agent reads in
// one run. Applications are read separately: that one is slow.
var MacProfilerTypes = []string{
	"SPHardwareDataType", "SPSoftwareDataType", "SPMemoryDataType", "SPStorageDataType", "SPNVMeDataType",
	"SPSerialATADataType", "SPDisplaysDataType", "SPPowerDataType", "SPPrintersDataType",
}

type profilerDoc map[string][]map[string]any

// ParseMacProfiler reads `system_profiler -json <MacProfilerTypes>` into
// the parts of Details it covers.
func ParseMacProfiler(text string) Details {
	var d Details
	var doc profilerDoc
	if json.Unmarshal([]byte(text), &doc) != nil {
		return d
	}

	if hw := first(doc["SPHardwareDataType"]); hw != nil {
		name := str(hw, "machine_name")
		d.System.Manufacturer = "Apple"
		d.System.Model = name
		if id := str(hw, "machine_model"); id != "" {
			d.System.Model = strings.TrimSpace(name + " (" + id + ")")
		}
		d.System.SerialNumber = str(hw, "serial_number")
		d.System.UUID = str(hw, "platform_UUID")
		d.System.BIOSVendor = "Apple"
		d.System.BIOSVersion = str(hw, "boot_rom_version")
		switch lower := strings.ToLower(name); {
		case strings.Contains(lower, "macbook"):
			d.System.FormFactor = "laptop"
		case strings.Contains(lower, "virtual"):
			d.System.FormFactor = "virtual"
			d.System.Virtual = true
			d.System.Hypervisor = "Apple Virtualization"
		case name != "":
			d.System.FormFactor = "desktop"
		}
		d.CPU.Model = firstNonEmpty(str(hw, "chip_type"), str(hw, "cpu_type"))
		d.CPU.Vendor = "Apple"
		if strings.Contains(d.CPU.Model, "Intel") {
			d.CPU.Vendor = "Intel"
		}
		// "proc 12:8:4" on Apple silicon (total:performance:efficiency).
		if procs := str(hw, "number_processors"); strings.HasPrefix(procs, "proc ") {
			n, _ := strconv.Atoi(strings.Split(strings.TrimPrefix(procs, "proc "), ":")[0])
			d.CPU.Cores, d.CPU.Threads = n, n
		} else if n := num(hw, "number_processors"); n > 0 {
			d.CPU.Cores = int(n)
		}
		d.CPU.Sockets = int(num(hw, "packages"))
		if d.CPU.Sockets == 0 {
			d.CPU.Sockets = 1
		}
		if ghz := strings.Fields(str(hw, "current_processor_speed")); len(ghz) == 2 {
			if f, err := strconv.ParseFloat(strings.ReplaceAll(ghz[0], ",", "."), 64); err == nil {
				d.CPU.SpeedMhz = int(f * 1000)
			}
		}
		d.Memory.TotalMb = parseSizeMb(str(hw, "physical_memory"))
	}

	if sw := first(doc["SPSoftwareDataType"]); sw != nil {
		d.OS.Name = str(sw, "os_version") // "macOS 14.5 (23F79)"
		d.OS.Kernel = strings.TrimPrefix(str(sw, "kernel_version"), "Darwin ")
		if user := str(sw, "user_name"); user != "" {
			d.Users.LoggedOn = []string{user}
		}
	}

	for _, m := range doc["SPMemoryDataType"] {
		// Apple silicon: one unified memory entry.
		if size := str(m, "SPMemoryDataType"); size != "" {
			d.Memory.Modules = append(d.Memory.Modules, MemoryModule{
				Slot: "Unified", SizeMb: parseSizeMb(size), Type: str(m, "dimm_type"), Manufacturer: str(m, "dimm_manufacturer"),
			})
			continue
		}
		// Intel: slots under _items.
		for _, dimm := range items(m) {
			d.Memory.Slots++
			size := parseSizeMb(str(dimm, "dimm_size"))
			if size == 0 {
				continue
			}
			speed, _ := strconv.Atoi(strings.Fields(str(dimm, "dimm_speed") + " 0")[0])
			d.Memory.Modules = append(d.Memory.Modules, MemoryModule{
				Slot: str(dimm, "_name"), SizeMb: size, Type: str(dimm, "dimm_type"), SpeedMhz: speed,
				Manufacturer: str(dimm, "dimm_manufacturer"), SerialNumber: str(dimm, "dimm_serial_number"),
				PartNumber: str(dimm, "dimm_part_number"),
			})
		}
	}

	serials := map[string]string{}
	var collectSerials func(list []map[string]any)
	collectSerials = func(list []map[string]any) {
		for _, m := range list {
			if serial := str(m, "device_serial"); serial != "" {
				serials[firstNonEmpty(str(m, "device_model"), str(m, "_name"))] = serial
			}
			collectSerials(items(m))
		}
	}
	collectSerials(doc["SPNVMeDataType"])
	collectSerials(doc["SPSerialATADataType"])

	seenDrive := map[string]bool{}
	for _, v := range doc["SPStorageDataType"] {
		mount := str(v, "mount_point")
		total, free := num(v, "size_in_bytes"), num(v, "free_space_in_bytes")
		if mount != "" && !skipMount(mount, "") && total > 0 {
			d.Volumes = append(d.Volumes, Volume{
				Mount: mount, Label: str(v, "_name"), FileSystem: str(v, "file_system"),
				TotalGb: round1(total / 1e9), FreeGb: round1(free / 1e9),
			})
		}
		drive, _ := v["physical_drive"].(map[string]any)
		name := str(drive, "device_name")
		if name == "" || seenDrive[name] {
			continue
		}
		seenDrive[name] = true
		kind := strings.ToLower(str(drive, "medium_type"))
		if kind == "rotational" {
			kind = "hdd"
		}
		if strings.Contains(strings.ToLower(name), "virtual") || strings.Contains(strings.ToLower(name), "vmware") {
			kind = "virtual"
		}
		d.Disks = append(d.Disks, PhysicalDisk{
			Name: name, Model: name, SerialNumber: serials[name], Type: kind,
			Interface: str(drive, "protocol"), Health: str(drive, "smart_status"),
		})
	}

	for _, g := range doc["SPDisplaysDataType"] {
		gpu := GPU{
			Name:   firstNonEmpty(str(g, "sppci_model"), str(g, "_name")),
			Vendor: strings.TrimPrefix(str(g, "sppci_vendor"), "sppci_vendor_"),
		}
		gpu.MemoryMb = parseSizeMb(firstNonEmpty(str(g, "spdisplays_vram"), str(g, "spdisplays_vram_shared"), str(g, "_spdisplays_vram")))
		d.GPUs = append(d.GPUs, gpu)
		screens, _ := g["spdisplays_ndrvs"].([]any)
		for _, s := range screens {
			sm, _ := s.(map[string]any)
			mon := Monitor{Model: str(sm, "_name")}
			for k, v := range sm {
				val, _ := v.(string)
				switch {
				case strings.Contains(k, "serial"):
					mon.SerialNumber = val
				case strings.Contains(k, "year"):
					mon.Year, _ = strconv.Atoi(val)
				case strings.Contains(k, "vendor-id") || strings.Contains(k, "vendor_id"):
					mon.Manufacturer = pnpVendor(val)
				}
			}
			if strings.Contains(str(sm, "spdisplays_display_type"), "built-in") || strings.Contains(strings.ToLower(str(sm, "spdisplays_connection_type")), "internal") {
				mon.Manufacturer = "Apple"
			}
			d.Monitors = append(d.Monitors, mon)
		}
	}

	for _, p := range doc["SPPowerDataType"] {
		if str(p, "_name") != "spbattery_information" {
			continue
		}
		health, _ := p["sppower_battery_health_info"].(map[string]any)
		model, _ := p["sppower_battery_model_info"].(map[string]any)
		b := Battery{
			Name:         firstNonEmpty(str(model, "sppower_battery_device_name"), "Battery"),
			Manufacturer: str(model, "sppower_battery_manufacturer"),
			CycleCount:   int(num(health, "sppower_battery_cycle_count")),
		}
		if pct := strings.TrimSuffix(str(health, "sppower_battery_health_maximum_capacity"), "%"); pct != "" {
			b.HealthPercent, _ = strconv.Atoi(pct)
		}
		d.Batteries = append(d.Batteries, b)
	}

	for _, p := range doc["SPPrintersDataType"] {
		uri := str(p, "uri")
		d.Printers = append(d.Printers, Printer{
			Name: str(p, "_name"), Driver: firstNonEmpty(str(p, "ppd"), str(p, "driverversion")), Port: uri,
			Shared: str(p, "shared") == "yes", Default: str(p, "default") == "yes",
			Network: strings.Contains(uri, "://") && !strings.HasPrefix(uri, "usb:"),
		})
	}
	return d
}

var signedBy = regexp.MustCompile(`^(?:Developer ID Application|Apple Mac OS Application Signing|Apple Distribution|Mac App Distribution|3rd Party Mac Developer Application): (.+?)(?: \([A-Z0-9]+\))?$`)

// ParseMacApplications reads `system_profiler -json SPApplicationsDataType`.
// Helper apps nested inside other apps and the OS's internal ones are left
// out; the publisher comes from the code signature.
func ParseMacApplications(text string) []Software {
	var doc profilerDoc
	if json.Unmarshal([]byte(text), &doc) != nil {
		return nil
	}
	var out []Software
	for _, a := range doc["SPApplicationsDataType"] {
		path := str(a, "path")
		if strings.Contains(path, ".app/") || strings.HasPrefix(path, "/System/Library/") || strings.HasPrefix(path, "/Library/Apple/") ||
			strings.HasPrefix(path, "/usr/") || strings.Contains(path, "/Library/Developer/") {
			continue
		}
		s := Software{Name: str(a, "_name"), Version: str(a, "version"), Source: "app"}
		if signers, ok := a["signed_by"].([]any); ok && len(signers) > 0 {
			if first, _ := signers[0].(string); first != "" {
				if m := signedBy.FindStringSubmatch(first); m != nil {
					s.Publisher = m[1]
				} else if strings.HasPrefix(first, "Software Signing") || str(a, "obtained_from") == "apple" {
					s.Publisher = "Apple"
				}
			}
		} else if str(a, "obtained_from") == "apple" {
			s.Publisher = "Apple"
		}
		if t, err := time.Parse(time.RFC3339, str(a, "lastModified")); err == nil {
			s.InstallDate = t.UTC().Format("2006-01-02")
		}
		switch str(a, "arch_kind") {
		case "arch_arm_i64", "arch_arm":
			s.Arch = "arm64"
		case "arch_i64":
			s.Arch = "x86_64"
		case "arch_arm_i64_i32", "arch_i64_i32":
			s.Arch = "universal"
		}
		out = append(out, s)
	}
	return out
}

var historyColumns = regexp.MustCompile(`\s{2,}`)

// ParseSoftwareUpdateHistory reads `softwareupdate --history`:
// "Display Name   Version   Date" columns separated by runs of spaces.
func ParseSoftwareUpdateHistory(text string) []Hotfix {
	var out []Hotfix
	for _, line := range sysinfo.Lines(text) {
		f := historyColumns.Split(strings.TrimSpace(line), -1)
		if len(f) < 3 || f[0] == "Display Name" || strings.HasPrefix(f[0], "---") {
			continue
		}
		h := Hotfix{ID: f[0] + " " + f[1], Description: f[0]}
		date := strings.Split(f[2], ",")[0]
		if t, err := time.Parse("01/02/2006", strings.TrimSpace(date)); err == nil {
			h.InstalledOn = t.Format("2006-01-02")
		}
		out = append(out, h)
	}
	// Newest first, as Windows' list reads.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ParseLaunchctlList reads `launchctl list` (PID Status Label), keeping
// third-party jobs: Apple's own hundreds say nothing about the machine.
func ParseLaunchctlList(text string) []Service {
	var out []Service
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] == "PID" || strings.HasPrefix(f[2], "com.apple.") || strings.HasPrefix(f[2], "application.") {
			continue
		}
		state := "stopped"
		if f[0] != "-" {
			state = "running"
		} else if f[1] != "0" {
			state = "failed"
		}
		out = append(out, Service{Name: f[2], State: state, StartMode: "auto"})
	}
	return out
}

// pnpVendor decodes a display's vendor id ("10ac") into the EDID
// manufacturer code (DEL) and its name.
func pnpVendor(hex string) string {
	id, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(hex), "0x"), 16, 16)
	if err != nil || id == 0 {
		return ""
	}
	code := string([]byte{byte('A' - 1 + (id>>10)&0x1f), byte('A' - 1 + (id>>5)&0x1f), byte('A' - 1 + id&0x1f)})
	if name := edidVendors[code]; name != "" {
		return name
	}
	return code
}

func first(list []map[string]any) map[string]any {
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

func items(m map[string]any) []map[string]any {
	raw, _ := m["_items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if mm, ok := r.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func num(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	}
	return 0
}
