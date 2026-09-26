package inventory

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf16"
)

// WindowsScript collects the whole Windows inventory in one PowerShell run
// (starting PowerShell costs about a second, so one run beats twenty). It
// uses CIM and registry reads that exist from Windows 8 / Server 2012 on,
// and every part is wrapped so a missing cmdlet (no BitLocker module on
// Home editions, no Get-WindowsFeature on workstations) leaves that part
// empty instead of failing the rest. Output is JSON, in UTF-8, so nothing
// depends on the display language.
const WindowsScript = `$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
function S($v) { if ($null -eq $v) { '' } else { ([string]$v).Trim() } }
function D($v) { if ($v) { try { ([datetime]$v).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { '' } } else { '' } }
function W($a) { if ($a) { -join ($a | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { '' } }
$r = [ordered]@{}
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$prod = Get-CimInstance Win32_ComputerSystemProduct
$encl = @(Get-CimInstance Win32_SystemEnclosure)[0]
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r.system = [ordered]@{ manufacturer = S $cs.Manufacturer; model = S $cs.Model; productVersion = S $prod.Version; serial = S $bios.SerialNumber; uuid = S $prod.UUID
  chassis = @($encl.ChassisTypes | ForEach-Object { [int]$_ }); pcSystemType = [int]$cs.PCSystemType
  domain = S $cs.Domain; partOfDomain = [bool]$cs.PartOfDomain; biosVendor = S $bios.Manufacturer; biosVersion = S $bios.SMBIOSBIOSVersion
  biosDate = D $bios.ReleaseDate; timezone = S ([TimeZoneInfo]::Local.Id); memoryBytes = [int64]$cs.TotalPhysicalMemory; consoleUser = S $cs.UserName }
$r.os = [ordered]@{ caption = S $os.Caption; version = S $os.Version; build = S $os.BuildNumber; ubr = [int]$cv.UBR; displayVersion = S $cv.DisplayVersion
  arch = S $os.OSArchitecture; installDate = D $os.InstallDate; lastBoot = D $os.LastBootUpTime; productType = [int]$os.ProductType
  pendingReboot = [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) }
try { $cpus = @(Get-CimInstance Win32_Processor)
  $r.cpu = [ordered]@{ name = S $cpus[0].Name; vendor = S $cpus[0].Manufacturer; sockets = $cpus.Count; cores = [int](($cpus | Measure-Object NumberOfCores -Sum).Sum); threads = [int](($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum); mhz = [int]$cpus[0].MaxClockSpeed } } catch {}
try { $r.memorySlots = [int]((Get-CimInstance Win32_PhysicalMemoryArray | Measure-Object MemoryDevices -Sum).Sum) } catch {}
try { $r.memory = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [ordered]@{ slot = S $_.DeviceLocator; size = [int64]$_.Capacity; type = [int]$_.SMBIOSMemoryType
  speed = [int]$(if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } else { $_.Speed }); manufacturer = S $_.Manufacturer; serial = S $_.SerialNumber; part = S $_.PartNumber } }) } catch {}
try { $r.disks = @(Get-PhysicalDisk | ForEach-Object { [ordered]@{ name = S $_.FriendlyName; serial = S $_.SerialNumber; size = [int64]$_.Size; media = S $_.MediaType; bus = S $_.BusType; health = S $_.HealthStatus } }) } catch {}
if (-not $r.disks) { try { $r.disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { [ordered]@{ name = S $_.Model; serial = S $_.SerialNumber; size = [int64]$_.Size; media = S $_.MediaType; bus = S $_.InterfaceType; health = S $_.Status } }) } catch {} }
$bl = @{}
try { Get-BitLockerVolume | ForEach-Object { $bl[[string]$_.MountPoint] = [int]$_.ProtectionStatus } } catch {}
$r.systemDrive = S $env:SystemDrive
try { $r.volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ mount = S $_.DeviceID; label = S $_.VolumeName; fs = S $_.FileSystem
  size = [int64]$_.Size; free = [int64]$_.FreeSpace; bitlocker = $(if ($bl.ContainsKey([string]$_.DeviceID)) { $bl[[string]$_.DeviceID] } else { -1 }) } }) } catch {}
try { $r.network = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { $a = Get-CimInstance Win32_NetworkAdapter -Filter "Index=$($_.Index)"
  [ordered]@{ name = S $a.NetConnectionID; description = S $_.Description; mac = S $_.MACAddress; ips = @($_.IPAddress | ForEach-Object { S $_ }); gateway = S (@($_.DefaultIPGateway)[0])
    dns = @($_.DNSServerSearchOrder | ForEach-Object { S $_ }); dhcp = [bool]$_.DHCPEnabled; speed = [int64]$a.Speed; up = [bool]$a.NetEnabled; physical = [bool]$a.PhysicalAdapter } }) } catch {}
try { $r.gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { [ordered]@{ name = S $_.Name; vendor = S $_.AdapterCompatibility; driver = S $_.DriverVersion; ram = [int64]$_.AdapterRAM } }) } catch {}
try { $r.monitors = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID | ForEach-Object { [ordered]@{ manufacturer = W $_.ManufacturerName; model = W $_.UserFriendlyName; serial = W $_.SerialNumberID; year = [int]$_.YearOfManufacture } }) } catch {}
try { $r.batteries = @(Get-CimInstance Win32_Battery | ForEach-Object { [ordered]@{ name = S $_.Name; chemistry = [int]$_.Chemistry } }) } catch {}
try { $bs = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData); $bf = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity); $bc = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount)
  $r.batteryDetails = @(for ($i = 0; $i -lt $bs.Count; $i++) { [ordered]@{ name = S $bs[$i].DeviceName; manufacturer = S $bs[$i].ManufactureName; design = [int64]$bs[$i].DesignedCapacity; full = [int64]$bf[$i].FullChargedCapacity; cycles = [int]$bc[$i].CycleCount } }) } catch {}
try { $r.printers = @(Get-CimInstance Win32_Printer | ForEach-Object { [ordered]@{ name = S $_.Name; driver = S $_.DriverName; port = S $_.PortName; shared = [bool]$_.Shared; network = [bool]$_.Network; default = [bool]$_.Default } }) } catch {}
try { $r.loggedOn = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; if ($o.User) { (S $o.Domain) + '\' + (S $o.User) } } | Sort-Object -Unique) } catch {}
try { $r.lastLogon = S (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI').LastLoggedOnUser } catch {}
try { $r.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { S $_.Name }) } catch {
  try { $g = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"; $r.admins = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser | ForEach-Object { (S $_.Domain) + '\' + (S $_.Name) }) } catch {} }
try { $r.localUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False' | ForEach-Object { S $_.Name }) } catch {}
try { $r.av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name = S $_.displayName; state = [int64]$_.productState } }) } catch {}
try { $mp = Get-MpComputerStatus -ErrorAction Stop; $r.defender = [ordered]@{ enabled = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; signatureAge = [int]$mp.AntivirusSignatureAge; version = S $mp.AMProductVersion } } catch {}
try { $r.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [string]$_.Enabled -eq 'True' }) } catch {}
try { $r.secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
try { $tpm = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
  $r.tpm = [ordered]@{ present = [bool]$tpm; version = S ((S $tpm.SpecVersion) -split ',')[0] } } catch {}
try { $r.uac = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA } catch {}
$procs = @{}
try { Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName } } catch {}
$r.processes = @($procs.Values | Sort-Object -Unique)
$arch = $(if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' })
$keys = @(@{ p = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; a = $arch }, @{ p = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; a = 'x86' },
  @{ p = 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; a = 'user' })
try { $r.software = @(foreach ($k in $keys) { Get-ItemProperty $k.p | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName -and (S $_.ReleaseType) -notin @('Update', 'Hotfix', 'Security Update') } |
  ForEach-Object { [ordered]@{ name = S $_.DisplayName; version = S $_.DisplayVersion; publisher = S $_.Publisher; date = S $_.InstallDate; arch = $k.a } } }) } catch {}
try { $r.hotfixes = @(Get-HotFix | ForEach-Object { [ordered]@{ id = S $_.HotFixID; description = S $_.Description; installedOn = $(try { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } catch { '' }) } }) } catch {}
try { $r.services = @(Get-CimInstance Win32_Service | ForEach-Object { [ordered]@{ name = S $_.Name; display = S $_.DisplayName; state = S $_.State; mode = S $_.StartMode } }) } catch {}
try { $r.tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { [ordered]@{ address = S $_.LocalAddress; port = [int]$_.LocalPort; process = S $procs[[int]$_.OwningProcess] } }) } catch {}
try { $r.udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object { [ordered]@{ address = S $_.LocalAddress; port = [int]$_.LocalPort; process = S $procs[[int]$_.OwningProcess] } }) } catch {}
if ($os.ProductType -ne 1) {
  try { $r.roles = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { S $_.DisplayName }) } catch {
    try { $r.roles = @(Get-CimInstance Win32_ServerFeature | Where-Object { $_.ParentID -eq 0 } | ForEach-Object { S $_.Name }) } catch {} } }
try { $r.hyperv = @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -ErrorAction Stop | Where-Object { $_.Name -match '^[0-9A-Fa-f-]{36}$' } | ForEach-Object { [ordered]@{ name = S $_.ElementName; state = [int]$_.EnabledState } }) } catch {}
$r | ConvertTo-Json -Depth 6 -Compress`

// WindowsEncodedCommand is WindowsScript for powershell -EncodedCommand:
// base64 of UTF-16LE, so no character in the script depends on how the
// command line gets quoted.
func WindowsEncodedCommand() string {
	u := utf16.Encode([]rune(WindowsScript))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

type windowsSocket struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

type windowsReport struct {
	System struct {
		Manufacturer   string `json:"manufacturer"`
		Model          string `json:"model"`
		ProductVersion string `json:"productVersion"`
		Serial         string `json:"serial"`
		UUID           string `json:"uuid"`
		Chassis        []int  `json:"chassis"`
		PCSystemType   int    `json:"pcSystemType"`
		Domain         string `json:"domain"`
		PartOfDomain   bool   `json:"partOfDomain"`
		BIOSVendor     string `json:"biosVendor"`
		BIOSVersion    string `json:"biosVersion"`
		BIOSDate       string `json:"biosDate"`
		Timezone       string `json:"timezone"`
		MemoryBytes    int64  `json:"memoryBytes"`
		ConsoleUser    string `json:"consoleUser"`
	} `json:"system"`
	OS struct {
		Caption        string `json:"caption"`
		Version        string `json:"version"`
		Build          string `json:"build"`
		UBR            int    `json:"ubr"`
		DisplayVersion string `json:"displayVersion"`
		Arch           string `json:"arch"`
		InstallDate    string `json:"installDate"`
		LastBoot       string `json:"lastBoot"`
		ProductType    int    `json:"productType"`
		PendingReboot  bool   `json:"pendingReboot"`
	} `json:"os"`
	CPU struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor"`
		Sockets int    `json:"sockets"`
		Cores   int    `json:"cores"`
		Threads int    `json:"threads"`
		MHz     int    `json:"mhz"`
	} `json:"cpu"`
	MemorySlots int `json:"memorySlots"`
	Memory      []struct {
		Slot         string `json:"slot"`
		Size         int64  `json:"size"`
		Type         int    `json:"type"`
		Speed        int    `json:"speed"`
		Manufacturer string `json:"manufacturer"`
		Serial       string `json:"serial"`
		Part         string `json:"part"`
	} `json:"memory"`
	Disks []struct {
		Name   string  `json:"name"`
		Serial string  `json:"serial"`
		Size   float64 `json:"size"`
		Media  string  `json:"media"`
		Bus    string  `json:"bus"`
		Health string  `json:"health"`
	} `json:"disks"`
	SystemDrive string `json:"systemDrive"`
	Volumes     []struct {
		Mount     string  `json:"mount"`
		Label     string  `json:"label"`
		FS        string  `json:"fs"`
		Size      float64 `json:"size"`
		Free      float64 `json:"free"`
		BitLocker int     `json:"bitlocker"`
	} `json:"volumes"`
	Network []struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		MAC         string   `json:"mac"`
		IPs         []string `json:"ips"`
		Gateway     string   `json:"gateway"`
		DNS         []string `json:"dns"`
		DHCP        bool     `json:"dhcp"`
		Speed       float64  `json:"speed"`
		Up          bool     `json:"up"`
		Physical    bool     `json:"physical"`
	} `json:"network"`
	GPUs []struct {
		Name   string  `json:"name"`
		Vendor string  `json:"vendor"`
		Driver string  `json:"driver"`
		RAM    float64 `json:"ram"`
	} `json:"gpus"`
	Monitors []struct {
		Manufacturer string `json:"manufacturer"`
		Model        string `json:"model"`
		Serial       string `json:"serial"`
		Year         int    `json:"year"`
	} `json:"monitors"`
	Batteries []struct {
		Name      string `json:"name"`
		Chemistry int    `json:"chemistry"`
	} `json:"batteries"`
	BatteryDetails []struct {
		Name         string `json:"name"`
		Manufacturer string `json:"manufacturer"`
		Design       int64  `json:"design"`
		Full         int64  `json:"full"`
		Cycles       int    `json:"cycles"`
	} `json:"batteryDetails"`
	Printers []struct {
		Name    string `json:"name"`
		Driver  string `json:"driver"`
		Port    string `json:"port"`
		Shared  bool   `json:"shared"`
		Network bool   `json:"network"`
		Default bool   `json:"default"`
	} `json:"printers"`
	LoggedOn   []string `json:"loggedOn"`
	LastLogon  string   `json:"lastLogon"`
	Admins     []string `json:"admins"`
	LocalUsers []string `json:"localUsers"`
	AV         []struct {
		Name  string `json:"name"`
		State int64  `json:"state"`
	} `json:"av"`
	Defender *struct {
		Enabled      bool   `json:"enabled"`
		Realtime     bool   `json:"realtime"`
		SignatureAge int    `json:"signatureAge"`
		Version      string `json:"version"`
	} `json:"defender"`
	Firewall   []bool `json:"firewall"`
	SecureBoot *bool  `json:"secureBoot"`
	TPM        *struct {
		Present bool   `json:"present"`
		Version string `json:"version"`
	} `json:"tpm"`
	UAC       *int     `json:"uac"`
	Processes []string `json:"processes"`
	Software  []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Publisher string `json:"publisher"`
		Date      string `json:"date"`
		Arch      string `json:"arch"`
	} `json:"software"`
	Hotfixes []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		InstalledOn string `json:"installedOn"`
	} `json:"hotfixes"`
	Services []struct {
		Name    string `json:"name"`
		Display string `json:"display"`
		State   string `json:"state"`
		Mode    string `json:"mode"`
	} `json:"services"`
	TCP    []windowsSocket `json:"tcp"`
	UDP    []windowsSocket `json:"udp"`
	Roles  []string        `json:"roles"`
	HyperV []struct {
		Name  string `json:"name"`
		State int    `json:"state"`
	} `json:"hyperv"`
}

var memoryTypes = map[int]string{20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3", 30: "LPDDR4", 34: "DDR5", 35: "LPDDR5"}
var batteryChemistry = map[int]string{3: "Lead acid", 4: "NiCd", 5: "NiMH", 6: "Li-ion", 7: "Zinc air", 8: "Li-polymer"}
var hyperVStates = map[int]string{2: "running", 3: "off", 6: "saved", 9: "paused", 32768: "paused", 32769: "saved", 32770: "starting", 32773: "saving", 32774: "stopping"}

// Printer queues Windows creates on its own, which aren't printers.
var virtualPrinterPorts = map[string]bool{"PORTPROMPT:": true, "SHRFAX:": true, "nul:": true, "XPSPort:": true}

// ParseWindowsReport turns WindowsScript's JSON into Details.
func ParseWindowsReport(text string) Details {
	var d Details
	var r windowsReport
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		d.legacyOS, d.legacyAV = "Windows", "unknown"
		d.OS.Name = "Windows"
		return d
	}

	s := &d.System
	s.Manufacturer, s.Model, s.SerialNumber, s.UUID = r.System.Manufacturer, r.System.Model, r.System.Serial, r.System.UUID
	// Lenovo puts the marketing name ("ThinkPad T14 Gen 3") in the product
	// version and a part number in the model.
	if strings.EqualFold(s.Manufacturer, "LENOVO") && r.System.ProductVersion != "" && !isPlaceholder(r.System.ProductVersion) {
		s.Model = r.System.ProductVersion + " (" + s.Model + ")"
	}
	s.BIOSVendor, s.BIOSVersion, s.BIOSDate = r.System.BIOSVendor, r.System.BIOSVersion, dateOnly(r.System.BIOSDate)
	s.Timezone = r.System.Timezone
	if r.System.PartOfDomain {
		s.Domain = r.System.Domain
	}
	for _, c := range r.System.Chassis {
		if f := FormFactorFromChassis(c); f != "" {
			s.FormFactor = f
			break
		}
	}
	if s.FormFactor == "" && r.System.PCSystemType == 2 {
		s.FormFactor = "laptop"
	}
	if hv := guessWindowsHypervisor(s.Manufacturer, r.System.Model, s.BIOSVersion); hv != "" {
		s.Virtual, s.Hypervisor = true, hv
	}
	s.Role = "workstation"
	if r.OS.ProductType == 2 || r.OS.ProductType == 3 {
		s.Role = "server"
	}

	o := &d.OS
	o.Name, o.Version, o.Arch = r.OS.Caption, r.OS.Version, r.OS.Arch
	if r.OS.DisplayVersion != "" {
		o.Version = r.OS.DisplayVersion + " (" + r.OS.Version + ")"
	}
	o.Build = r.OS.Build
	if r.OS.UBR > 0 {
		o.Build = r.OS.Build + "." + itoa(r.OS.UBR)
	}
	o.Kernel = r.OS.Version
	o.InstallDate, o.LastBoot = dateOnly(r.OS.InstallDate), r.OS.LastBoot
	o.PendingReboot = boolPtr(r.OS.PendingReboot)
	d.legacyOS = strings.TrimSpace(r.OS.Caption + " " + r.OS.Version)

	d.CPU = CPU{Model: r.CPU.Name, Vendor: cpuVendor(r.CPU.Vendor), Sockets: r.CPU.Sockets, Cores: r.CPU.Cores, Threads: r.CPU.Threads, SpeedMhz: r.CPU.MHz}
	d.Memory.TotalMb = r.System.MemoryBytes / 1024 / 1024
	d.Memory.Slots = r.MemorySlots
	for _, m := range r.Memory {
		d.Memory.Modules = append(d.Memory.Modules, MemoryModule{
			Slot: m.Slot, SizeMb: m.Size / 1024 / 1024, Type: memoryTypes[m.Type], SpeedMhz: m.Speed,
			Manufacturer: m.Manufacturer, SerialNumber: m.Serial, PartNumber: m.Part,
		})
	}

	for _, x := range r.Disks {
		kind := "unknown"
		switch {
		case strings.Contains(strings.ToLower(x.Bus), "virtual") || virtualDiskModel.MatchString(x.Name):
			kind = "virtual"
		case strings.EqualFold(x.Bus, "NVMe"):
			kind = "nvme"
		case strings.EqualFold(x.Media, "SSD"):
			kind = "ssd"
		case strings.EqualFold(x.Media, "HDD") || strings.Contains(x.Media, "Fixed hard disk"):
			kind = "hdd"
		}
		d.Disks = append(d.Disks, PhysicalDisk{
			Name: x.Name, Model: x.Name, SerialNumber: x.Serial, SizeGb: round1(x.Size / 1e9), Type: kind, Interface: x.Bus, Health: x.Health,
		})
	}

	var anyProtected, knownBitLocker bool
	for _, v := range r.Volumes {
		vol := Volume{Mount: v.Mount, Label: v.Label, FileSystem: v.FS, TotalGb: round1(v.Size / 1024 / 1024 / 1024), FreeGb: round1(v.Free / 1024 / 1024 / 1024)}
		// ProtectionStatus: 1 = on, 0 = off, -1 = unknown (no BitLocker cmdlet).
		if v.BitLocker >= 0 {
			knownBitLocker = true
			vol.Encrypted = boolPtr(v.BitLocker == 1)
			anyProtected = anyProtected || v.BitLocker == 1
			if strings.EqualFold(v.Mount, r.SystemDrive) {
				d.Security.SystemDiskEncrypted = boolPtr(v.BitLocker == 1)
			}
		}
		d.Volumes = append(d.Volumes, vol)
	}
	if d.Security.SystemDiskEncrypted == nil && knownBitLocker {
		d.Security.SystemDiskEncrypted = boolPtr(anyProtected)
	}
	if anyProtected {
		d.Security.EncryptionMethod = "BitLocker"
	}

	for _, n := range r.Network {
		ni := NetInterface{
			Name: firstNonEmpty(n.Name, n.Description), Description: n.Description, MAC: strings.ToLower(strings.ReplaceAll(n.MAC, "-", ":")),
			Gateway: n.Gateway, DNS: n.DNS, DHCP: boolPtr(n.DHCP), SpeedMbps: int(n.Speed / 1e6), Up: n.Up,
			Virtual: !n.Physical || virtualInterface.MatchString(n.Name) || strings.Contains(strings.ToLower(n.Description), "virtual"),
		}
		for _, ip := range n.IPs {
			if strings.Contains(ip, ":") {
				if !strings.HasPrefix(strings.ToLower(ip), "fe80") {
					ni.IPv6 = append(ni.IPv6, ip)
				}
			} else {
				ni.IPv4 = append(ni.IPv4, ip)
			}
		}
		d.Network = append(d.Network, ni)
	}

	for _, g := range r.GPUs {
		if strings.Contains(g.Name, "Remote Display") || strings.Contains(g.Name, "Indirect Display") {
			continue
		}
		gpu := GPU{Name: g.Name, Vendor: g.Vendor, DriverVersion: g.Driver}
		if g.RAM > 0 {
			gpu.MemoryMb = int64(g.RAM / 1024 / 1024)
		}
		d.GPUs = append(d.GPUs, gpu)
	}
	for _, m := range r.Monitors {
		mon := Monitor{Manufacturer: m.Manufacturer, Model: m.Model, SerialNumber: m.Serial, Year: m.Year}
		if name := edidVendors[strings.ToUpper(m.Manufacturer)]; name != "" {
			mon.Manufacturer = name
		}
		d.Monitors = append(d.Monitors, mon)
	}
	if len(r.BatteryDetails) > 0 {
		for i, b := range r.BatteryDetails {
			bat := Battery{Name: b.Name, Manufacturer: b.Manufacturer, DesignCapacityMwh: b.Design, FullCapacityMwh: b.Full, CycleCount: b.Cycles}
			if i < len(r.Batteries) {
				bat.Chemistry = batteryChemistry[r.Batteries[i].Chemistry]
			}
			d.Batteries = append(d.Batteries, bat)
		}
	} else {
		for _, b := range r.Batteries {
			d.Batteries = append(d.Batteries, Battery{Name: b.Name, Chemistry: batteryChemistry[b.Chemistry]})
		}
	}
	for _, p := range r.Printers {
		if virtualPrinterPorts[p.Port] || strings.HasPrefix(p.Name, "OneNote") {
			continue
		}
		d.Printers = append(d.Printers, Printer{Name: p.Name, Driver: p.Driver, Port: p.Port, Shared: p.Shared, Network: p.Network, Default: p.Default})
	}

	d.Users.LoggedOn = r.LoggedOn
	if len(d.Users.LoggedOn) == 0 && r.System.ConsoleUser != "" {
		d.Users.LoggedOn = []string{r.System.ConsoleUser}
	}
	d.Users.LastLogon, d.Users.LocalAdmins, d.Users.LocalUsers = r.LastLogon, r.Admins, r.LocalUsers

	sec := &d.Security
	sec.Features = map[string]string{}
	anyEnabled := false
	for _, a := range r.AV {
		// productState: bit 12 = enabled, bits 4-7 = 0 when definitions are current.
		on := a.State&0x1000 != 0
		anyEnabled = anyEnabled || on
		sec.Antivirus = append(sec.Antivirus, Antivirus{Name: a.Name, Enabled: boolPtr(on), UpToDate: boolPtr(a.State&0xf0 == 0)})
	}
	if r.Defender != nil && (len(r.AV) == 0 || r.Defender.Enabled) {
		// Installed but without real-time protection isn't protecting.
		on := r.Defender.Enabled && r.Defender.Realtime
		anyEnabled = anyEnabled || on
		// Defender signatures older than a week are out of date.
		sec.Antivirus = append(sec.Antivirus, Antivirus{
			Name: "Microsoft Defender Antivirus", Enabled: boolPtr(on),
			UpToDate: boolPtr(r.Defender.SignatureAge <= 7), Version: r.Defender.Version,
		})
	}
	switch {
	case anyEnabled:
		d.legacyAV = "enabled"
	case len(r.AV) > 0 || r.Defender != nil:
		d.legacyAV = "disabled"
	default:
		d.legacyAV = "unknown"
	}
	if len(r.Firewall) > 0 {
		all := true
		for _, on := range r.Firewall {
			all = all && on
		}
		sec.FirewallEnabled = boolPtr(all)
	}
	sec.SecureBoot = r.SecureBoot
	if r.TPM != nil {
		sec.TPMPresent = boolPtr(r.TPM.Present)
		sec.TPMVersion = r.TPM.Version
	}
	if r.UAC != nil {
		if *r.UAC == 1 {
			sec.Features["uac"] = "enabled"
		} else {
			sec.Features["uac"] = "disabled"
		}
	}
	sec.Agents = DetectAgents(r.Processes)

	for _, x := range r.Software {
		d.Software = append(d.Software, Software{
			Name: x.Name, Version: x.Version, Publisher: x.Publisher, InstallDate: compactDate(x.Date), Arch: x.Arch, Source: "registry",
		})
	}
	for _, h := range r.Hotfixes {
		d.Updates.Installed = append(d.Updates.Installed, Hotfix{ID: h.ID, Description: h.Description, InstalledOn: h.InstalledOn})
		if h.InstalledOn > d.Updates.LastInstalled {
			d.Updates.LastInstalled = h.InstalledOn
		}
	}
	for _, x := range r.Services {
		d.Services = append(d.Services, Service{Name: x.Name, DisplayName: x.Display, State: windowsServiceState(x.State), StartMode: windowsStartMode(x.Mode)})
	}
	for _, p := range r.TCP {
		d.Ports = append(d.Ports, Port{Protocol: "tcp", Address: p.Address, Port: p.Port, Process: p.Process})
	}
	for _, p := range r.UDP {
		d.Ports = append(d.Ports, Port{Protocol: "udp", Address: p.Address, Port: p.Port, Process: p.Process})
	}
	d.ServerRoles = append(r.Roles, DetectServerSoftware(d.Services, r.Processes)...)
	for _, g := range r.HyperV {
		state := hyperVStates[g.State]
		if state == "" {
			state = "other"
		}
		d.VirtualMachines = append(d.VirtualMachines, Guest{Name: g.Name, Type: "hyperv", State: state})
	}
	return d
}

// guessWindowsHypervisor recognizes a virtual machine by what its firmware
// says it is. (HypervisorPresent can't tell: it's also true on a physical
// host running Hyper-V or virtualization-based security.)
func guessWindowsHypervisor(manufacturer, model, bios string) string {
	all := strings.ToLower(manufacturer + " " + model + " " + bios)
	switch {
	case strings.Contains(all, "vmware"):
		return "VMware"
	case strings.Contains(all, "virtualbox") || strings.Contains(all, "innotek"):
		return "VirtualBox"
	case strings.Contains(all, "microsoft") && strings.Contains(all, "virtual machine"):
		return "Hyper-V"
	case strings.Contains(all, "qemu") || strings.Contains(all, "kvm") || strings.Contains(all, "standard pc (") || strings.Contains(all, "red hat"):
		return "KVM"
	case strings.Contains(all, "xen") || strings.Contains(all, "hvm domu"):
		return "Xen"
	case strings.Contains(all, "amazon ec2"):
		return "Amazon EC2"
	case strings.Contains(all, "google compute engine"):
		return "Google Compute Engine"
	case strings.Contains(all, "parallels"):
		return "Parallels"
	case strings.Contains(all, "nutanix"):
		return "Nutanix AHV"
	}
	return ""
}

func windowsServiceState(s string) string {
	switch strings.ToLower(s) {
	case "running":
		return "running"
	case "stopped":
		return "stopped"
	}
	return "other"
}

func windowsStartMode(s string) string {
	switch strings.ToLower(s) {
	case "auto", "boot", "system":
		return "auto"
	case "manual":
		return "manual"
	case "disabled":
		return "disabled"
	}
	return "other"
}

// compactDate turns the registry's InstallDate ("20240315") into 2024-03-15.
func compactDate(v string) string {
	v = strings.TrimSpace(v)
	if len(v) == 8 && strings.Trim(v, "0123456789") == "" {
		return v[:4] + "-" + v[4:6] + "-" + v[6:]
	}
	return ""
}
