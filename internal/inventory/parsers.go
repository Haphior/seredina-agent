package inventory

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

// The parsers for Unix tools' output live here, free of build tags, so the
// tests exercise them on any OS with captured sample output.

// ParseOSRelease reads /etc/os-release into a map.
func ParseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range sysinfo.Lines(text) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

// ParseCPUInfo reads /proc/cpuinfo: the model, and sockets, cores and
// threads from the processor entries' "physical id" and "core id".
func ParseCPUInfo(text string) CPU {
	var c CPU
	sockets := map[string]bool{}
	cores := map[string]bool{}
	for _, block := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		if !strings.Contains(block, "processor") {
			continue
		}
		c.Threads++
		phys, core := ParseKeyValue(block, "physical id"), ParseKeyValue(block, "core id")
		if phys != "" {
			sockets[phys] = true
			cores[phys+"/"+core] = true
		}
		if c.Model == "" {
			for _, key := range []string{"model name", "Model", "Hardware", "cpu model"} {
				if v := ParseKeyValue(block, key); v != "" {
					c.Model = v
					break
				}
			}
		}
		if c.Vendor == "" {
			c.Vendor = cpuVendor(ParseKeyValue(block, "vendor_id"))
		}
		if c.SpeedMhz == 0 {
			if f, err := strconv.ParseFloat(ParseKeyValue(block, "cpu MHz"), 64); err == nil {
				c.SpeedMhz = int(f)
			}
		}
	}
	c.Sockets = len(sockets)
	c.Cores = len(cores)
	if c.Sockets == 0 && c.Threads > 0 {
		c.Sockets = 1
	}
	if c.Cores == 0 {
		c.Cores = c.Threads
	}
	return c
}

// ParseLscpu reads `lscpu` (C locale), which knows ARM machines' models and
// the real core counts better than /proc/cpuinfo.
func ParseLscpu(text string) CPU {
	num := func(key string) int {
		n, _ := strconv.Atoi(strings.Fields(ParseKeyValue(text, key) + " 0")[0])
		return n
	}
	c := CPU{
		Model:   ParseKeyValue(text, "Model name"),
		Vendor:  cpuVendor(ParseKeyValue(text, "Vendor ID")),
		Threads: num("CPU(s)"),
		Sockets: num("Socket(s)"),
	}
	// ARM machines count cores per cluster, and may print "-" for sockets.
	per := num("Core(s) per socket")
	if per == 0 {
		per = num("Core(s) per cluster")
	}
	if c.Sockets == 0 {
		c.Sockets = 1
	}
	if per > 0 {
		groups := c.Sockets
		if clusters := num("Cluster(s)"); clusters > 0 && num("Core(s) per socket") == 0 {
			groups = clusters
		}
		c.Cores = per * groups
	}
	if f, err := strconv.ParseFloat(ParseKeyValue(text, "CPU max MHz"), 64); err == nil {
		c.SpeedMhz = int(f)
	}
	return c
}

func cpuVendor(id string) string {
	switch strings.TrimSpace(id) {
	case "GenuineIntel":
		return "Intel"
	case "AuthenticAMD":
		return "AMD"
	case "ARM":
		return "ARM"
	case "Apple":
		return "Apple"
	}
	return strings.TrimSpace(id)
}

// ParseDmidecodeMemory reads `dmidecode -t 17`: one "Memory Device" block
// per slot, empty or not.
func ParseDmidecodeMemory(text string) (modules []MemoryModule, slots int) {
	for _, block := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		if !strings.Contains(block, "Memory Device") {
			continue
		}
		slots++
		size := parseSizeMb(ParseKeyValue(block, "Size"))
		if size == 0 {
			continue
		}
		speed, _ := strconv.Atoi(strings.Fields(ParseKeyValue(block, "Configured Memory Speed") + " " + ParseKeyValue(block, "Speed") + " 0")[0])
		if speed == 0 {
			speed, _ = strconv.Atoi(strings.Fields(ParseKeyValue(block, "Speed") + " 0")[0])
		}
		modules = append(modules, MemoryModule{
			Slot:         firstNonEmpty(ParseKeyValue(block, "Locator"), ParseKeyValue(block, "Bank Locator")),
			SizeMb:       size,
			Type:         ParseKeyValue(block, "Type"),
			SpeedMhz:     speed,
			Manufacturer: ParseKeyValue(block, "Manufacturer"),
			SerialNumber: ParseKeyValue(block, "Serial Number"),
			PartNumber:   ParseKeyValue(block, "Part Number"),
		})
	}
	return modules, slots
}

// parseSizeMb reads sizes like "16 GB", "8192 MB", "16384 kB", "1 TB".
func parseSizeMb(v string) int64 {
	f := strings.Fields(v)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	switch strings.ToUpper(f[1]) {
	case "KB":
		return int64(n / 1024)
	case "MB":
		return int64(n)
	case "GB":
		return int64(n * 1024)
	case "TB":
		return int64(n * 1024 * 1024)
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// flexString accepts a JSON string, number, bool or null: lsblk changed its
// JSON types between versions ("rota": "1" became "rota": true).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case nil:
		*f = ""
	case string:
		*f = flexString(t)
	case bool:
		if t {
			*f = "1"
		} else {
			*f = "0"
		}
	default:
		*f = flexString(fmt.Sprint(t))
	}
	return nil
}

type lsblkDevice struct {
	Name       flexString    `json:"name"`
	Model      flexString    `json:"model"`
	Vendor     flexString    `json:"vendor"`
	Serial     flexString    `json:"serial"`
	Size       flexString    `json:"size"`
	Rota       flexString    `json:"rota"`
	Tran       flexString    `json:"tran"`
	Type       flexString    `json:"type"`
	FSType     flexString    `json:"fstype"`
	Label      flexString    `json:"label"`
	Mountpoint flexString    `json:"mountpoint"`
	Children   []lsblkDevice `json:"children"`
}

var virtualDiskModel = regexp.MustCompile(`(?i)qemu|vbox|virtual|vmware|msft|xen|red hat|google persistent|amazon elastic|nutanix`)

// ParseLsblkDisks reads `lsblk -J -b -d -o NAME,MODEL,VENDOR,SERIAL,SIZE,ROTA,TRAN,TYPE`:
// the physical drives.
func ParseLsblkDisks(text string) []PhysicalDisk {
	var doc struct {
		Blockdevices []lsblkDevice `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(text), &doc) != nil {
		return nil
	}
	var out []PhysicalDisk
	for _, d := range doc.Blockdevices {
		name := string(d.Name)
		if string(d.Type) != "disk" || strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "loop") {
			continue
		}
		size, _ := strconv.ParseFloat(string(d.Size), 64)
		vendor := strings.TrimSpace(string(d.Vendor))
		if strings.HasPrefix(vendor, "0x") || strings.EqualFold(vendor, "ATA") {
			vendor = "" // a PCI id or the bus name, not a maker
		}
		model := strings.TrimSpace(vendor + " " + strings.TrimSpace(string(d.Model)))
		kind := "unknown"
		switch {
		case virtualDiskModel.MatchString(model) || string(d.Tran) == "virtio" || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd"):
			kind = "virtual"
		case strings.HasPrefix(name, "nvme") || string(d.Tran) == "nvme":
			kind = "nvme"
		case string(d.Rota) == "0":
			kind = "ssd"
		case string(d.Rota) == "1":
			kind = "hdd"
		}
		out = append(out, PhysicalDisk{
			Name: name, Model: model, SerialNumber: string(d.Serial), SizeGb: round1(size / 1e9),
			Type: kind, Interface: string(d.Tran),
		})
	}
	return out
}

// volumeInfo is what lsblk knows about a mounted filesystem.
type volumeInfo struct {
	FileSystem string
	Label      string
	Encrypted  bool
}

// ParseLsblkTree reads `lsblk -J -o NAME,TYPE,FSTYPE,LABEL,MOUNTPOINT`, a tree
// of disks, partitions, LVM and dm-crypt devices, and tells for each mount
// point its filesystem and whether a "crypt" device sits under it.
func ParseLsblkTree(text string) (byMount map[string]volumeInfo, anyCrypt bool) {
	var doc struct {
		Blockdevices []lsblkDevice `json:"blockdevices"`
	}
	byMount = map[string]volumeInfo{}
	if json.Unmarshal([]byte(text), &doc) != nil {
		return byMount, false
	}
	var walk func(list []lsblkDevice, underCrypt bool)
	walk = func(list []lsblkDevice, underCrypt bool) {
		for _, d := range list {
			crypt := underCrypt || string(d.Type) == "crypt"
			if string(d.Type) == "crypt" {
				anyCrypt = true
			}
			if mp := string(d.Mountpoint); mp != "" && !strings.HasPrefix(mp, "[") {
				byMount[mp] = volumeInfo{FileSystem: string(d.FSType), Label: string(d.Label), Encrypted: crypt}
			}
			walk(d.Children, crypt)
		}
	}
	walk(doc.Blockdevices, false)
	return byMount, anyCrypt
}

// ParseProcNetRoute finds the default route in /proc/net/route: the
// interface and the gateway (little-endian hex).
func ParseProcNetRoute(text string) (iface, gateway string) {
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(v))
		return f[0], ip.String()
	}
	return "", ""
}

// ParseResolvConf lists the nameservers in a resolv.conf.
func ParseResolvConf(text string) []string {
	var out []string
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// ParseLspciGPUs reads `lspci -mm`: quoted fields slot, class, vendor, device.
func ParseLspciGPUs(text string) []GPU {
	quoted := regexp.MustCompile(`"([^"]*)"`)
	var out []GPU
	for _, line := range sysinfo.Lines(text) {
		m := quoted.FindAllStringSubmatch(line, -1)
		if len(m) < 3 {
			continue
		}
		class := m[0][1]
		if !strings.Contains(class, "VGA") && !strings.Contains(class, "3D") && !strings.Contains(class, "Display") {
			continue
		}
		out = append(out, GPU{Name: m[2][1], Vendor: m[1][1]})
	}
	return out
}

// ParseEDID reads a monitor's EDID block: the three-letter manufacturer
// code, and the name and serial descriptors.
func ParseEDID(b []byte) (Monitor, bool) {
	if len(b) < 128 || b[0] != 0x00 || b[1] != 0xff || b[7] != 0x00 {
		return Monitor{}, false
	}
	id := uint16(b[8])<<8 | uint16(b[9])
	mfg := string([]byte{byte('A' - 1 + (id>>10)&0x1f), byte('A' - 1 + (id>>5)&0x1f), byte('A' - 1 + id&0x1f)})
	m := Monitor{Manufacturer: edidVendors[mfg]}
	if m.Manufacturer == "" {
		m.Manufacturer = mfg
	}
	if year := int(b[17]); year > 0 && year < 0xff {
		m.Year = 1990 + year
	}
	for i := 54; i+18 <= 126; i += 18 {
		d := b[i : i+18]
		if d[0] != 0 || d[1] != 0 {
			continue
		}
		text := strings.TrimSpace(strings.SplitN(string(d[5:18]), "\n", 2)[0])
		switch d[3] {
		case 0xfc:
			m.Model = text
		case 0xff:
			m.SerialNumber = text
		}
	}
	if m.SerialNumber == "" {
		if serial := binary.LittleEndian.Uint32(b[12:16]); serial != 0 {
			m.SerialNumber = strconv.FormatUint(uint64(serial), 10)
		}
	}
	return m, true
}

// Common EDID manufacturer codes.
var edidVendors = map[string]string{
	"ACI": "ASUS", "ACR": "Acer", "AOC": "AOC", "APP": "Apple", "AUO": "AU Optronics", "BNQ": "BenQ", "BOE": "BOE",
	"CMN": "Chimei Innolux", "DEL": "Dell", "ENC": "Eizo", "GSM": "LG", "HPN": "HP", "HWP": "HP", "IVM": "Iiyama",
	"LEN": "Lenovo", "LGD": "LG Display", "MEI": "Panasonic", "NEC": "NEC", "PHL": "Philips", "SAM": "Samsung",
	"SDC": "Samsung Display", "SEC": "Samsung", "SHP": "Sharp", "SNY": "Sony", "VSC": "ViewSonic", "MSI": "MSI",
	"GBT": "Gigabyte", "HKC": "HKC", "FUS": "Fujitsu", "TSB": "Toshiba", "XMI": "Xiaomi", "HIQ": "Hyundai",
}

// ParseLpstat reads `lpstat -v` ("device for NAME: URI") and the default
// printer from `lpstat -d`.
func ParseLpstat(devices, def string) []Printer {
	defaultName := ""
	if _, after, ok := strings.Cut(def, ":"); ok {
		defaultName = strings.TrimSpace(after)
	}
	var out []Printer
	for _, line := range sysinfo.Lines(devices) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "device for ")
		if !ok {
			continue
		}
		name, uri, _ := strings.Cut(rest, ": ")
		name = strings.TrimSuffix(name, ":")
		out = append(out, Printer{
			Name: name, Port: uri, Default: name == defaultName,
			Network: strings.Contains(uri, "://") && !strings.HasPrefix(uri, "usb:") && !strings.HasPrefix(uri, "file:"),
		})
	}
	return out
}

// ParseWho lists the distinct users in `who` output.
func ParseWho(text string) []string {
	var out []string
	for _, line := range sysinfo.Lines(text) {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// ParseGroupMembers lists the members of the named groups in /etc/group.
func ParseGroupMembers(text string, groups ...string) []string {
	want := map[string]bool{}
	for _, g := range groups {
		want[g] = true
	}
	var out []string
	for _, line := range sysinfo.Lines(text) {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || !want[f[0]] {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out = append(out, m)
			}
		}
	}
	return out
}

// ParsePasswdUsers lists people's accounts in /etc/passwd: root and
// uid >= 1000 with a login shell, not system accounts.
func ParsePasswdUsers(text string) []string {
	var out []string
	for _, line := range sysinfo.Lines(text) {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		shell := f[6]
		if err != nil || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") || shell == "" {
			continue
		}
		if uid == 0 || (uid >= 1000 && uid < 60000) {
			out = append(out, f[0])
		}
	}
	return out
}

// ParseSystemctl merges `systemctl list-units --type=service --all
// --no-legend --plain` (UNIT LOAD ACTIVE SUB DESCRIPTION) with
// `systemctl list-unit-files --type=service --no-legend` (UNIT STATE ...).
func ParseSystemctl(units, files string) []Service {
	startMode := map[string]string{}
	for _, line := range sysinfo.Lines(files) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[1] {
		case "enabled", "enabled-runtime", "alias":
			startMode[f[0]] = "auto"
		case "disabled":
			startMode[f[0]] = "manual"
		case "masked", "masked-runtime":
			startMode[f[0]] = "disabled"
		case "static", "indirect", "generated", "transient":
			startMode[f[0]] = "other"
		}
	}
	var out []Service
	for _, line := range sysinfo.Lines(units) {
		f := strings.Fields(strings.TrimLeft(line, "●* "))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || f[1] == "not-found" {
			continue
		}
		state := "other"
		switch {
		case f[3] == "running":
			state = "running"
		case f[2] == "failed":
			state = "failed"
		case f[2] == "inactive" || f[3] == "dead" || f[3] == "exited":
			state = "stopped"
		}
		mode := startMode[f[0]]
		if mode == "" {
			mode = "other"
		}
		out = append(out, Service{
			Name: strings.TrimSuffix(f[0], ".service"), DisplayName: strings.Join(f[4:], " "), State: state, StartMode: mode,
		})
	}
	return out
}

var ssProcess = regexp.MustCompile(`users:\(\("([^"]+)"`)

// ParseSS reads `ss -H -tulnp` (or without -H: the header is skipped):
// Netid State Recv-Q Send-Q Local:Port Peer:Port [Process].
func ParseSS(text string) []Port {
	var out []Port
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		if f[0] == "tcp" && f[1] != "LISTEN" {
			continue
		}
		addr, port := splitHostPort(f[4])
		if port == 0 {
			continue
		}
		p := Port{Protocol: f[0], Address: addr, Port: port}
		if m := ssProcess.FindStringSubmatch(line); m != nil {
			p.Process = m[1]
		}
		out = append(out, p)
	}
	return out
}

// ParseLsof reads `lsof -nP -iTCP -sTCP:LISTEN` (macOS):
// COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME.
func ParseLsof(text string) []Port {
	var out []Port
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		name := f[len(f)-1]
		if name == "(LISTEN)" {
			name = f[len(f)-2]
		}
		addr, port := splitHostPort(name)
		if port == 0 {
			continue
		}
		out = append(out, Port{Protocol: "tcp", Address: addr, Port: port, Process: strings.ReplaceAll(f[0], `\x20`, " ")})
	}
	return out
}

// splitHostPort splits "0.0.0.0:22", "[::]:22", "*:22", "127.0.0.53%lo:53".
func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0
	}
	host := strings.Trim(s[:i], "[]")
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	if host == "*" || host == "" {
		host = "0.0.0.0"
	}
	return host, port
}

// ParseVirshList reads `virsh list --all` (C locale): Id Name State.
func ParseVirshList(text string) []Guest {
	var out []Guest
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "Id" || strings.HasPrefix(f[0], "---") {
			continue
		}
		out = append(out, Guest{Name: f[1], Type: "libvirt", State: strings.Join(f[2:], " ")})
	}
	return out
}

// ParseProxmoxList reads `qm list` (VMID NAME STATUS ...) and `pct list`
// (VMID Status [Lock] Name).
func ParseProxmoxList(text string, containers bool) []Guest {
	var out []Guest
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "VMID" {
			continue
		}
		if containers {
			out = append(out, Guest{Name: f[len(f)-1] + " (" + f[0] + ")", Type: "proxmox-lxc", State: f[1]})
		} else {
			out = append(out, Guest{Name: f[1] + " (" + f[0] + ")", Type: "proxmox", State: f[2]})
		}
	}
	return out
}

// ParseAptSimulate counts `apt-get -s upgrade`'s "Inst" lines, and those
// coming from a -security pocket.
func ParseAptSimulate(text string) (total, security int) {
	for _, line := range sysinfo.Lines(text) {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		total++
		if strings.Contains(line, "-security") {
			security++
		}
	}
	return total, security
}

// ParseDnfCheckUpdate counts packages in `dnf check-update` output (exit
// code 100 means there are some): "name.arch  version  repo" lines.
func ParseDnfCheckUpdate(text string) int {
	n := 0
	for _, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasPrefix(line, " ") {
			n++
		}
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
	}
	return n
}

// ParseDpkgSoftware reads `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Maintainer}\n'`.
func ParseDpkgSoftware(text string) []Software {
	var out []Software
	for _, line := range sysinfo.Lines(text) {
		f := strings.Split(line, "\t")
		if len(f) < 2 || strings.TrimSpace(f[0]) == "" {
			continue
		}
		s := Software{Name: f[0], Version: f[1], Source: "dpkg"}
		if len(f) > 2 {
			s.Arch = f[2]
		}
		if len(f) > 3 {
			s.Publisher = stripEmail(f[3])
		}
		out = append(out, s)
	}
	return out
}

// ParseRpmSoftware reads `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\n'`.
func ParseRpmSoftware(text string) []Software {
	var out []Software
	for _, line := range sysinfo.Lines(text) {
		f := strings.Split(line, "\t")
		if len(f) < 2 || strings.TrimSpace(f[0]) == "" || f[0] == "gpg-pubkey" {
			continue
		}
		s := Software{Name: f[0], Version: f[1], Source: "rpm"}
		if len(f) > 2 && f[2] != "(none)" {
			s.Arch = f[2]
		}
		if len(f) > 3 && f[3] != "(none)" {
			s.Publisher = f[3]
		}
		if len(f) > 4 {
			if sec, err := strconv.ParseInt(strings.TrimSpace(f[4]), 10, 64); err == nil {
				s.InstallDate = dateOnly(unixTime(sec))
			}
		}
		out = append(out, s)
	}
	return out
}

// ParseSnapList reads `snap list`: Name Version Rev Tracking Publisher Notes.
func ParseSnapList(text string) []Software {
	var out []Software
	for i, line := range sysinfo.Lines(text) {
		f := strings.Fields(line)
		if i == 0 || len(f) < 5 {
			continue
		}
		out = append(out, Software{Name: f[0], Version: f[1], Publisher: strings.TrimSuffix(strings.TrimSuffix(f[4], "✓"), "*"), Source: "snap"})
	}
	return out
}

// ParseFlatpakList reads `flatpak list --app --columns=name,version,origin`.
func ParseFlatpakList(text string) []Software {
	var out []Software
	for _, line := range sysinfo.Lines(text) {
		f := strings.Split(line, "\t")
		if len(f) < 1 || strings.TrimSpace(f[0]) == "" {
			continue
		}
		s := Software{Name: f[0], Source: "flatpak"}
		if len(f) > 1 {
			s.Version = f[1]
		}
		if len(f) > 2 {
			s.Publisher = f[2]
		}
		out = append(out, s)
	}
	return out
}

func stripEmail(s string) string {
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// packagesToSoftware converts the simple name/version lists (pacman, apk).
func packagesToSoftware(pkgs []Package, source string) []Software {
	out := make([]Software, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, Software{Name: p.Name, Version: p.Version, Source: source})
	}
	return out
}
