package inventory

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// A Windows Server 2022 Hyper-V host on Spanish Windows, the shape
// WindowsScript prints.
const windowsSample = `{"system":{"manufacturer":"Dell Inc.","model":"PowerEdge R650","productVersion":"","serial":"7XK2JQ3","uuid":"4C4C4544-0058-4B10-8032-B7C04F4A5133",
"chassis":[23],"pcSystemType":4,"domain":"corp.example.cl","partOfDomain":true,"biosVendor":"Dell Inc.","biosVersion":"1.10.2","biosDate":"2023-05-10T00:00:00Z",
"timezone":"Pacific SA Standard Time","memoryBytes":274877906944,"consoleUser":""},
"os":{"caption":"Microsoft Windows Server 2022 Standard","version":"10.0.20348","build":"20348","ubr":2582,"displayVersion":"21H2","arch":"64 bits",
"installDate":"2023-06-01T14:00:00Z","lastBoot":"2026-09-20T03:00:00Z","productType":3,"pendingReboot":true},
"cpu":{"name":"Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz","vendor":"GenuineIntel","sockets":2,"cores":64,"threads":128,"mhz":2001},
"memorySlots":32,"memory":[{"slot":"A1","size":34359738368,"type":26,"speed":3200,"manufacturer":"Hynix","serial":"80AD0123","part":"HMA84GR7DJR4N-XN"},
{"slot":"A2","size":34359738368,"type":26,"speed":3200,"manufacturer":"Hynix","serial":"00000000","part":"HMA84GR7DJR4N-XN"}],
"disks":[{"name":"DELL PERC H755","serial":"00a1b2c3","size":1919850381312,"media":"SSD","bus":"RAID","health":"Healthy"},
{"name":"Msft Virtual Disk","serial":"","size":137438953472,"media":"Unspecified","bus":"File Backed Virtual","health":"Healthy"}],
"systemDrive":"C:","volumes":[{"mount":"C:","label":"","fs":"NTFS","size":510770802688,"free":214748364800,"bitlocker":1},{"mount":"D:","label":"Datos","fs":"ReFS","size":1099511627776,"free":549755813888,"bitlocker":0}],
"network":[{"name":"Ethernet","description":"Broadcom NetXtreme E-Series","mac":"B0:26:28:AA:BB:CC","ips":["10.0.0.20","fe80::1","2001:db8::20"],"gateway":"10.0.0.1","dns":["10.0.0.10","10.0.0.11"],"dhcp":false,"speed":10000000000,"up":true,"physical":true},
{"name":"vEthernet (Default Switch)","description":"Hyper-V Virtual Ethernet Adapter","mac":"00:15:5D:01:02:03","ips":["172.20.0.1"],"gateway":"","dns":[],"dhcp":false,"speed":10000000000,"up":true,"physical":false}],
"gpus":[{"name":"Matrox G200eW3 (Nuvoton)","vendor":"Matrox","driver":"10.0.20348.1","ram":16777216},{"name":"Microsoft Remote Display Adapter","vendor":"Microsoft","driver":"","ram":0}],
"monitors":[{"manufacturer":"DEL","model":"DELL P2422H","serial":"CN0ABC123","year":2022}],
"batteries":[],"printers":[{"name":"Microsoft Print to PDF","driver":"Microsoft Print To PDF","port":"PORTPROMPT:","shared":false,"network":false,"default":false},
{"name":"HP LaserJet Contabilidad","driver":"HP Universal Printing PCL 6","port":"10.0.0.50","shared":true,"network":false,"default":true}],
"loggedOn":["CORP\\admin.ti"],"lastLogon":"CORP\\admin.ti","admins":["CORP\\Domain Admins","SERVER01\\Administrador"],"localUsers":["Administrador"],
"defender":{"enabled":true,"realtime":true,"signatureAge":1,"version":"4.18.24080.9"},"firewall":[true,true,false],"secureBoot":true,
"tpm":{"present":true,"version":"2.0"},"uac":1,"processes":["MsMpEng","CSFalconService","sqlservr","System","vmms"],
"software":[{"name":"Microsoft SQL Server 2019 (64-bit)","version":"15.0.2000.5","publisher":"Microsoft Corporation","date":"20230602","arch":"x64"},
{"name":"7-Zip 23.01 (x64)","version":"23.01","publisher":"Igor Pavlov","date":"","arch":"x64"},{"name":"  ","version":"","publisher":"","date":"","arch":"x86"}],
"hotfixes":[{"id":"KB5041160","description":"Security Update","installedOn":"2024-08-14"},{"id":"KB5040437","description":"Update","installedOn":"2024-07-10"}],
"services":[{"name":"MSSQLSERVER","display":"SQL Server (MSSQLSERVER)","state":"Running","mode":"Auto"},{"name":"Spooler","display":"Cola de impresión","state":"Stopped","mode":"Disabled"}],
"tcp":[{"address":"0.0.0.0","port":1433,"process":"sqlservr"},{"address":"::","port":3389,"process":"svchost"},{"address":"0.0.0.0","port":1433,"process":"sqlservr"}],
"udp":[{"address":"0.0.0.0","port":161,"process":"snmp"}],
"roles":["Hyper-V","Servicios de archivos y almacenamiento"],"hyperv":[{"name":"APP01","state":2},{"name":"TEST","state":3}]}`

func TestParseWindowsReportServer(t *testing.T) {
	d := ParseWindowsReport(windowsSample)
	d.finish()
	s := d.System
	if s.Manufacturer != "Dell Inc." || s.Model != "PowerEdge R650" || s.SerialNumber != "7XK2JQ3" || s.FormFactor != "server" || s.Role != "server" || s.Virtual {
		t.Fatalf("system: %+v", s)
	}
	if s.Domain != "corp.example.cl" || s.BIOSDate != "2023-05-10" {
		t.Fatalf("domain/bios: %+v", s)
	}
	if d.OS.Name != "Microsoft Windows Server 2022 Standard" || d.OS.Version != "21H2 (10.0.20348)" || d.OS.Build != "20348.2582" || d.OS.InstallDate != "2023-06-01" || !*d.OS.PendingReboot {
		t.Fatalf("os: %+v", d.OS)
	}
	if d.CPU.Vendor != "Intel" || d.CPU.Sockets != 2 || d.CPU.Cores != 64 || d.CPU.Threads != 128 {
		t.Fatalf("cpu: %+v", d.CPU)
	}
	if d.Memory.TotalMb != 262144 || d.Memory.Slots != 32 || len(d.Memory.Modules) != 2 || d.Memory.Modules[0].Type != "DDR4" || d.Memory.Modules[0].SizeMb != 32768 {
		t.Fatalf("memory: %+v", d.Memory)
	}
	if d.Memory.Modules[1].SerialNumber != "" {
		t.Fatal("an all-zero module serial means none")
	}
	if d.Disks[0].Type != "ssd" || d.Disks[1].Type != "virtual" || d.Disks[0].SizeGb != 1919.9 {
		t.Fatalf("disks: %+v", d.Disks)
	}
	if !*d.Volumes[0].Encrypted || *d.Volumes[1].Encrypted || d.Volumes[1].Label != "Datos" || !*d.Security.SystemDiskEncrypted || d.Security.EncryptionMethod != "BitLocker" {
		t.Fatalf("volumes: %+v / %+v", d.Volumes, d.Security)
	}
	eth := d.Network[0]
	if eth.MAC != "b0:26:28:aa:bb:cc" || !reflect.DeepEqual(eth.IPv4, []string{"10.0.0.20"}) || !reflect.DeepEqual(eth.IPv6, []string{"2001:db8::20"}) ||
		eth.SpeedMbps != 10000 || eth.Virtual || *eth.DHCP || eth.Gateway != "10.0.0.1" {
		t.Fatalf("nic: %+v", eth)
	}
	if !d.Network[1].Virtual {
		t.Fatal("a Hyper-V vEthernet is virtual")
	}
	if len(d.GPUs) != 1 || d.GPUs[0].MemoryMb != 16 {
		t.Fatalf("the RDP display adapter isn't a GPU: %+v", d.GPUs)
	}
	if d.Monitors[0].Manufacturer != "Dell" || d.Monitors[0].SerialNumber != "CN0ABC123" {
		t.Fatalf("monitors: %+v", d.Monitors)
	}
	if len(d.Printers) != 1 || !d.Printers[0].Default || !d.Printers[0].Shared {
		t.Fatalf("Print to PDF isn't a printer: %+v", d.Printers)
	}
	if !reflect.DeepEqual(d.Users.LoggedOn, []string{`CORP\admin.ti`}) || len(d.Users.LocalAdmins) != 2 {
		t.Fatalf("users: %+v", d.Users)
	}
	av := d.Security.Antivirus
	if len(av) != 1 || av[0].Name != "Microsoft Defender Antivirus" || !*av[0].Enabled || !*av[0].UpToDate || d.legacyAV != "enabled" {
		t.Fatalf("antivirus: %+v %s", av, d.legacyAV)
	}
	if *d.Security.FirewallEnabled {
		t.Fatal("one profile off means the firewall isn't fully on")
	}
	if !*d.Security.SecureBoot || !*d.Security.TPMPresent || d.Security.TPMVersion != "2.0" || d.Security.Features["uac"] != "enabled" {
		t.Fatalf("security: %+v", d.Security)
	}
	if !reflect.DeepEqual(d.Security.Agents, []string{"CrowdStrike Falcon", "Microsoft Defender Antivirus"}) {
		t.Fatalf("agents: %v", d.Security.Agents)
	}
	if len(d.Software) != 2 || d.Software[1].InstallDate != "2023-06-02" || d.Software[1].Publisher != "Microsoft Corporation" {
		t.Fatalf("software: %+v", d.Software)
	}
	if d.Updates.LastInstalled != "2024-08-14" || len(d.Updates.Installed) != 2 {
		t.Fatalf("updates: %+v", d.Updates)
	}
	if d.Services[0].State != "running" || d.Services[0].StartMode != "auto" || d.Services[1].StartMode != "disabled" || d.Services[1].DisplayName != "Cola de impresión" {
		t.Fatalf("services: %+v", d.Services)
	}
	if len(d.Ports) != 3 || d.Ports[0].Port != 161 || d.Ports[1].Process != "sqlservr" {
		t.Fatalf("ports (deduplicated, sorted): %+v", d.Ports)
	}
	for _, want := range []string{"Hyper-V", "Servicios de archivos y almacenamiento", "SQL Server"} {
		if !contains(d.ServerRoles, want) {
			t.Errorf("roles %v lack %q", d.ServerRoles, want)
		}
	}
	if len(d.VirtualMachines) != 2 || d.VirtualMachines[0].State != "running" || d.VirtualMachines[1].State != "off" {
		t.Fatalf("guests: %+v", d.VirtualMachines)
	}
	inv := d.legacy()
	if inv.OSVersion != "Microsoft Windows Server 2022 Standard 10.0.20348" || inv.AntivirusStatus != "enabled" || !*inv.DiskEncrypted || len(inv.InstalledPackages) != 2 {
		t.Fatalf("legacy fields: %+v", inv)
	}
}

func TestParseWindowsReportLaptopAndVM(t *testing.T) {
	laptop := ParseWindowsReport(`{"system":{"manufacturer":"LENOVO","model":"21AH00BXUS","productVersion":"ThinkPad T14 Gen 3","serial":"PF3ABCDE","chassis":[10]},
"os":{"caption":"Microsoft Windows 11 Pro","version":"10.0.22631","productType":1},"av":[{"name":"Windows Defender","state":397568},{"name":"Old AV","state":393472}],
"batteries":[{"name":"5B10W51867","chemistry":6}],"batteryDetails":[{"name":"5B10W51867","manufacturer":"SMP","design":57000,"full":51300,"cycles":142}]}`)
	laptop.finish()
	if laptop.System.Model != "ThinkPad T14 Gen 3 (21AH00BXUS)" || laptop.System.FormFactor != "laptop" || laptop.System.Role != "workstation" {
		t.Fatalf("laptop: %+v", laptop.System)
	}
	b := laptop.Batteries[0]
	if b.HealthPercent != 90 || b.Chemistry != "Li-ion" || b.CycleCount != 142 {
		t.Fatalf("battery: %+v", b)
	}
	// 397568 = 0x61100: on, up to date. 393472 = 0x60100: off.
	if !*laptop.Security.Antivirus[0].Enabled || !*laptop.Security.Antivirus[0].UpToDate || *laptop.Security.Antivirus[1].Enabled {
		t.Fatalf("productState decoding: %+v", laptop.Security.Antivirus)
	}
	vm := ParseWindowsReport(`{"system":{"manufacturer":"Microsoft Corporation","model":"Virtual Machine","serial":"0000-0000","chassis":[3]},"os":{"productType":3}}`)
	vm.finish()
	if !vm.System.Virtual || vm.System.Hypervisor != "Hyper-V" || vm.System.FormFactor != "virtual" || vm.System.Role != "server" || vm.System.SerialNumber != "" {
		t.Fatalf("vm: %+v", vm.System)
	}
	bad := ParseWindowsReport("not json")
	bad.finish()
	if bad.OS.Name != "Windows" || bad.legacy().AntivirusStatus != "unknown" {
		t.Fatalf("garbage: %+v", bad)
	}
}

func TestWindowsEncodedCommandRoundTrips(t *testing.T) {
	enc := WindowsEncodedCommand()
	// The Windows command line limit is 32,767 characters, all arguments included.
	if len(enc) > 30000 {
		t.Fatalf("encoded script is %d characters, too close to the command line limit", len(enc))
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if string(utf16.Decode(u)) != WindowsScript {
		t.Fatal("round trip changed the script")
	}
}

const macSample = `{"SPHardwareDataType":[{"machine_name":"MacBook Pro","machine_model":"Mac14,9","chip_type":"Apple M2 Pro","number_processors":"proc 10:6:4",
"physical_memory":"16 GB","serial_number":"H4XJ2N6QWV","platform_UUID":"5E2A8F3C-1111-2222-3333-444455556666","boot_rom_version":"10151.140.19"}],
"SPSoftwareDataType":[{"os_version":"macOS 14.6.1 (23G93)","kernel_version":"Darwin 23.6.0","user_name":"Ana Pérez (ana)"}],
"SPMemoryDataType":[{"SPMemoryDataType":"16 GB","dimm_manufacturer":"Hynix","dimm_type":"LPDDR5"}],
"SPStorageDataType":[{"_name":"Macintosh HD - Data","mount_point":"/System/Volumes/Data","file_system":"APFS","size_in_bytes":494384795648,"free_space_in_bytes":300000000000,
"physical_drive":{"device_name":"APPLE SSD AP0512Z","medium_type":"ssd","protocol":"Apple Fabric","smart_status":"Verified"}},
{"_name":"Macintosh HD","mount_point":"/","file_system":"APFS","size_in_bytes":494384795648,"free_space_in_bytes":300000000000,"physical_drive":{"device_name":"APPLE SSD AP0512Z","medium_type":"ssd"}},
{"_name":"VM","mount_point":"/System/Volumes/VM","size_in_bytes":494384795648,"free_space_in_bytes":1}],
"SPNVMeDataType":[{"_name":"Apple SSD Controller","_items":[{"_name":"APPLE SSD AP0512Z","device_model":"APPLE SSD AP0512Z","device_serial":"0ba01234abcd"}]}],
"SPDisplaysDataType":[{"_name":"Apple M2 Pro","sppci_model":"Apple M2 Pro","sppci_vendor":"sppci_vendor_Apple","spdisplays_ndrvs":[
{"_name":"Color LCD","spdisplays_display_type":"spdisplays_built-in-retinaLCD"},
{"_name":"DELL U2723QE","_spdisplays_display-serial-number":"1ABC234","_spdisplays_display-vendor-id":"10ac","_spdisplays_display-year":"2023"}]}],
"SPPowerDataType":[{"_name":"spbattery_information","sppower_battery_health_info":{"sppower_battery_cycle_count":87,"sppower_battery_health":"Good","sppower_battery_health_maximum_capacity":"96%"},
"sppower_battery_model_info":{"sppower_battery_device_name":"bq40z651","sppower_battery_manufacturer":"SMP"}},{"_name":"sppower_ac_charger_information"}],
"SPPrintersDataType":[{"_name":"Oficina","default":"yes","shared":"no","uri":"ipp://10.0.0.50/ipp/print","ppd":"HP LaserJet"}]}`

func TestParseMacProfiler(t *testing.T) {
	d := ParseMacProfiler(macSample)
	d.finish()
	if d.System.Model != "MacBook Pro (Mac14,9)" || d.System.FormFactor != "laptop" || d.System.SerialNumber != "H4XJ2N6QWV" || d.System.Manufacturer != "Apple" {
		t.Fatalf("system: %+v", d.System)
	}
	if d.CPU.Model != "Apple M2 Pro" || d.CPU.Cores != 10 || d.Memory.TotalMb != 16384 || d.Memory.Modules[0].Type != "LPDDR5" {
		t.Fatalf("cpu/memory: %+v %+v", d.CPU, d.Memory)
	}
	if d.OS.Name != "macOS 14.6.1 (23G93)" || d.OS.Kernel != "23.6.0" || d.Users.LoggedOn[0] != "Ana Pérez (ana)" {
		t.Fatalf("os: %+v %+v", d.OS, d.Users)
	}
	if len(d.Volumes) != 2 || len(d.Disks) != 1 || d.Disks[0].SerialNumber != "0ba01234abcd" || d.Disks[0].Type != "ssd" {
		t.Fatalf("storage: %+v %+v", d.Volumes, d.Disks)
	}
	if len(d.Monitors) != 2 || d.Monitors[0].Manufacturer != "Apple" || d.Monitors[1].Manufacturer != "Dell" || d.Monitors[1].Year != 2023 || d.Monitors[1].SerialNumber != "1ABC234" {
		t.Fatalf("monitors: %+v", d.Monitors)
	}
	if len(d.Batteries) != 1 || d.Batteries[0].HealthPercent != 96 || d.Batteries[0].CycleCount != 87 {
		t.Fatalf("battery: %+v", d.Batteries)
	}
	if !d.Printers[0].Default || !d.Printers[0].Network {
		t.Fatalf("printers: %+v", d.Printers)
	}
}

func TestParseMacApplications(t *testing.T) {
	text := `{"SPApplicationsDataType":[
{"_name":"Google Chrome","version":"129.0.6668.59","path":"/Applications/Google Chrome.app","lastModified":"2024-09-20T10:00:00Z","obtained_from":"identified_developer","signed_by":["Developer ID Application: Google LLC (EQHXZ8M8AV)","Developer ID Certification Authority","Apple Root CA"],"arch_kind":"arch_arm_i64"},
{"_name":"Safari","version":"17.6","path":"/Applications/Safari.app","obtained_from":"apple","signed_by":["Software Signing","Apple Code Signing Certification Authority"]},
{"_name":"Helper","path":"/Applications/Google Chrome.app/Contents/Frameworks/Helper.app"},
{"_name":"Ticket Viewer","path":"/System/Library/CoreServices/Ticket Viewer.app"}]}`
	got := ParseMacApplications(text)
	if len(got) != 2 || got[0].Publisher != "Google LLC" || got[0].InstallDate != "2024-09-20" || got[0].Arch != "arm64" || got[1].Publisher != "Apple" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseSoftwareUpdateHistoryAndLaunchctl(t *testing.T) {
	history := `Display Name                                       Version    Date
------------                                       -------    ----
XProtectPlistConfigData                            5272       08/01/2024, 10:12:13
macOS Sonoma 14.6.1                                14.6.1     08/08/2024, 09:00:00`
	got := ParseSoftwareUpdateHistory(history)
	if len(got) != 2 || got[0].Description != "macOS Sonoma 14.6.1" || got[0].InstalledOn != "2024-08-08" {
		t.Fatalf("history: %+v", got)
	}
	services := ParseLaunchctlList("PID\tStatus\tLabel\n312\t0\tcom.microsoft.teams.TeamsUpdaterDaemon\n-\t0\tcom.apple.xpc.launchd\n-\t78\torg.postgresql.postgres\n")
	if len(services) != 2 || services[0].State != "running" || services[1].State != "failed" {
		t.Fatalf("launchctl: %+v", services)
	}
}

func TestParseCPUInfoTwoSockets(t *testing.T) {
	block := func(proc, phys, core string) string {
		return "processor\t: " + proc + "\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Silver 4210R\ncpu MHz\t\t: 2400.000\nphysical id\t: " + phys + "\ncore id\t\t: " + core + "\n"
	}
	text := strings.Join([]string{block("0", "0", "0"), block("1", "0", "1"), block("2", "1", "0"), block("3", "1", "1"), block("4", "0", "0")}, "\n")
	c := ParseCPUInfo(text)
	if c.Sockets != 2 || c.Cores != 4 || c.Threads != 5 || c.Vendor != "Intel" || c.SpeedMhz != 2400 {
		t.Fatalf("got %+v", c)
	}
	arm := ParseLscpu("Architecture:        aarch64\nCPU(s):              4\nVendor ID:           ARM\nModel name:          Cortex-A72\nThread(s) per core:  1\nCore(s) per cluster: 4\nSocket(s):           -\nCluster(s):          1\nCPU max MHz:         1800.0000\n")
	if arm.Model != "Cortex-A72" || arm.Cores != 4 || arm.Threads != 4 || arm.SpeedMhz != 1800 {
		t.Fatalf("lscpu arm: %+v", arm)
	}
}

func TestParseDmidecodeMemory(t *testing.T) {
	text := `# dmidecode 3.5
Handle 0x0040, DMI type 17, 92 bytes
Memory Device
	Size: 16 GB
	Locator: DIMM A1
	Bank Locator: BANK 0
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 1234ABCD
	Part Number: M378A2K43EB1-CWE
	Configured Memory Speed: 2933 MT/s

Handle 0x0041, DMI type 17, 92 bytes
Memory Device
	Size: No Module Installed
	Locator: DIMM A2
	Type: Unknown
`
	mods, slots := ParseDmidecodeMemory(text)
	if slots != 2 || len(mods) != 1 || mods[0].SizeMb != 16384 || mods[0].SpeedMhz != 2933 || mods[0].Slot != "DIMM A1" || mods[0].PartNumber != "M378A2K43EB1-CWE" {
		t.Fatalf("got %d slots, %+v", slots, mods)
	}
}

func TestParseLsblk(t *testing.T) {
	// util-linux 2.37+ (booleans, numbers) and older (strings) both parse.
	newer := `{"blockdevices":[{"name":"nvme0n1","model":"Samsung SSD 980 PRO 1TB","vendor":null,"serial":"S5GXNX0T123","size":1000204886016,"rota":false,"tran":"nvme","type":"disk"},
{"name":"sda","model":"ST4000NM000A-2HZ1","vendor":"ATA     ","serial":"WJG1ABCD","size":4000787030016,"rota":true,"tran":"sata","type":"disk"},
{"name":"loop0","size":"1000","rota":false,"type":"loop"},{"name":"zram0","size":8000000000,"type":"disk"}]}`
	older := `{"blockdevices":[{"name":"sdb","model":"Samsung SSD 870","serial":"S6P","size":"500107862016","rota":"0","tran":"sata","type":"disk"},
{"name":"vda","model":null,"vendor":"0x1af4","size":"53687091200","rota":"1","tran":"virtio","type":"disk"}]}`
	got := append(ParseLsblkDisks(newer), ParseLsblkDisks(older)...)
	want := []string{"nvme0n1:nvme", "sda:hdd", "sdb:ssd", "vda:virtual"}
	var have []string
	for _, d := range got {
		have = append(have, d.Name+":"+d.Type)
	}
	if !reflect.DeepEqual(have, want) || got[0].SizeGb != 1000.2 || got[1].Model != "ST4000NM000A-2HZ1" || got[3].Model != "" {
		t.Fatalf("got %v %+v", have, got)
	}

	tree := `{"blockdevices":[{"name":"nvme0n1","type":"disk","children":[
{"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoint":"/boot/efi"},
{"name":"nvme0n1p3","type":"part","fstype":"crypto_LUKS","children":[{"name":"luks-root","type":"crypt","fstype":"LVM2_member","children":[
{"name":"vg-root","type":"lvm","fstype":"ext4","label":"root","mountpoint":"/"},{"name":"vg-swap","type":"lvm","fstype":"swap","mountpoint":"[SWAP]"}]}]}]},
{"name":"sda","type":"disk","children":[{"name":"sda1","type":"part","fstype":"xfs","mountpoint":"/srv/data"}]}]}`
	byMount, anyCrypt := ParseLsblkTree(tree)
	if !anyCrypt || !byMount["/"].Encrypted || byMount["/srv/data"].Encrypted || byMount["/"].FileSystem != "ext4" || byMount["/"].Label != "root" {
		t.Fatalf("tree: %+v %v", byMount, anyCrypt)
	}
	if _, swap := byMount["[SWAP]"]; swap {
		t.Fatal("swap isn't a mount point")
	}
}

func TestParseNetworkFiles(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	if iface, gw := ParseProcNetRoute(route); iface != "eth0" || gw != "192.168.1.1" {
		t.Fatalf("route: %s %s", iface, gw)
	}
	if dns := ParseResolvConf("# generated\nnameserver 10.0.0.10\nnameserver 1.1.1.1\nsearch corp.example.cl\n"); !reflect.DeepEqual(dns, []string{"10.0.0.10", "1.1.1.1"}) {
		t.Fatalf("dns: %v", dns)
	}
	gpus := ParseLspciGPUs(`00:02.0 "VGA compatible controller" "Intel Corporation" "Alder Lake-P GT2 [Iris Xe Graphics]" -r0c "Lenovo" "Device 22e4"
01:00.0 "3D controller" "NVIDIA Corporation" "GA107M [GeForce RTX 3050 Mobile]" -ra1 "Lenovo" "Device 22e4"
00:1f.3 "Audio device" "Intel Corporation" "Alder Lake PCH-P High Definition Audio Controller" -r01 "Lenovo" "Device 22e4"`)
	if len(gpus) != 2 || gpus[1].Vendor != "NVIDIA Corporation" {
		t.Fatalf("gpus: %+v", gpus)
	}
}

func TestParseEDID(t *testing.T) {
	b := make([]byte, 128)
	copy(b, []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00})
	b[8], b[9] = 0x10, 0xac // DEL
	b[17] = 32              // 1990 + 32
	name := []byte{0, 0, 0, 0xfc, 0, 'D', 'E', 'L', 'L', ' ', 'P', '2', '4', '2', '2', 'H', '\n', ' '}
	serial := []byte{0, 0, 0, 0xff, 0, 'C', 'N', '0', 'A', 'B', 'C', '1', '2', '3', '\n', ' ', ' ', ' '}
	copy(b[54:], name)
	copy(b[72:], serial)
	m, ok := ParseEDID(b)
	if !ok || m.Manufacturer != "Dell" || m.Model != "DELL P2422H" || m.SerialNumber != "CN0ABC123" || m.Year != 2022 {
		t.Fatalf("got %+v %v", m, ok)
	}
	if _, ok := ParseEDID([]byte("nope")); ok {
		t.Fatal("garbage isn't an EDID")
	}
}

func TestParseServicesAndPorts(t *testing.T) {
	units := `ssh.service                 loaded    active   running OpenBSD Secure Shell server
postgresql@16-main.service  loaded    active   running PostgreSQL Cluster 16-main
apt-daily.service           loaded    inactive dead    Daily apt download activities
nginx.service               loaded    failed   failed  A high performance web server
ghost.service               not-found inactive dead    ghost.service`
	files := "ssh.service enabled enabled\npostgresql@.service indirect enabled\napt-daily.service static -\nnginx.service enabled enabled\n"
	got := ParseSystemctl(units, files)
	if len(got) != 4 || got[0].Name != "ssh" || got[0].State != "running" || got[0].StartMode != "auto" || got[2].State != "stopped" || got[3].State != "failed" {
		t.Fatalf("systemctl: %+v", got)
	}
	roles := DetectServerSoftware(got, []string{"dockerd"})
	if !reflect.DeepEqual(roles, []string{"Docker", "PostgreSQL"}) {
		t.Fatalf("roles: %v (a failed nginx isn't running)", roles)
	}

	ss := `tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=14))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=900,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=900,fd=4))
tcp   ESTAB  0      0         10.0.0.5:22      10.0.0.9:51000
udp   UNCONN 0      0            0.0.0.0:161       0.0.0.0:*    users:(("snmpd",pid=1000,fd=6))`
	ports := ParseSS(ss)
	if len(ports) != 4 || ports[0].Address != "127.0.0.53" || ports[0].Port != 53 || ports[1].Process != "sshd" || ports[2].Address != "::" {
		t.Fatalf("ss: %+v", ports)
	}
	lsof := `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd     1 root   25u  IPv6 0x1234      0t0  TCP *:22 (LISTEN)
postgres  510 ana     7u  IPv4 0x5678      0t0  TCP 127.0.0.1:5432 (LISTEN)`
	if got := ParseLsof(lsof); len(got) != 2 || got[0].Address != "0.0.0.0" || got[1].Port != 5432 || got[1].Process != "postgres" {
		t.Fatalf("lsof: %+v", got)
	}
}

func TestParseGuests(t *testing.T) {
	docker := `{"Command":"\"nginx\"","ID":"abc","Image":"nginx:1.27","Names":"web","State":"running","Status":"Up 3 days"}
{"ID":"def","Image":"postgres:16","Names":["db"],"State":"exited"}`
	got := ParseContainerLines(docker, "docker")
	if len(got) != 2 || got[0].Name != "web" || got[0].State != "running" || got[1].Name != "db" || got[1].Image != "postgres:16" {
		t.Fatalf("docker: %+v", got)
	}
	virsh := " Id   Name        State\n------------------------------\n 1    app01       running\n -    win2022     shut off\n"
	if got := ParseVirshList(virsh); len(got) != 2 || got[1].State != "shut off" {
		t.Fatalf("virsh: %+v", got)
	}
	qm := "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n       100 dc01                 running    4096              60.00 1234\n"
	pct := "VMID       Status     Lock         Name\n200        running                 proxy01\n"
	vms, cts := ParseProxmoxList(qm, false), ParseProxmoxList(pct, true)
	if len(vms) != 1 || vms[0].Name != "dc01 (100)" || vms[0].State != "running" || len(cts) != 1 || cts[0].Name != "proxy01 (200)" {
		t.Fatalf("proxmox: %+v %+v", vms, cts)
	}
}

func TestParsePackageManagers(t *testing.T) {
	apt := "Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])\nInst tzdata [2024a] (2024b Ubuntu:22.04/jammy-updates [all])\nConf libssl3 (3.0.2)\n"
	if total, security := ParseAptSimulate(apt); total != 2 || security != 1 {
		t.Fatalf("apt: %d %d", total, security)
	}
	dnf := "\nkernel.x86_64                    5.14.0-427.el9            baseos\nopenssl.x86_64                   1:3.0.7-28.el9            baseos\nObsoleting Packages\nfoo.x86_64  1  bar\n"
	if n := ParseDnfCheckUpdate(dnf); n != 2 {
		t.Fatalf("dnf: %d", n)
	}
	rpm := ParseRpmSoftware("bash\t5.1.8-9.el9\tx86_64\tRed Hat, Inc.\t1714000000\ngpg-pubkey\t1-1\t(none)\t(none)\t0\nfoo\t1-1\t(none)\t(none)\t0\n")
	if len(rpm) != 2 || rpm[0].Publisher != "Red Hat, Inc." || rpm[0].InstallDate != "2024-04-24" || rpm[1].Arch != "" || rpm[1].InstallDate != "" {
		t.Fatalf("rpm: %+v", rpm)
	}
	dpkg := ParseDpkgSoftware("bash\t5.2.21-2ubuntu4\tamd64\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n")
	if dpkg[0].Publisher != "Ubuntu Developers" || dpkg[0].Arch != "amd64" {
		t.Fatalf("dpkg: %+v", dpkg)
	}
	snap := ParseSnapList("Name      Version    Rev    Tracking       Publisher     Notes\nfirefox   130.0      4848   latest/stable  mozilla✓      -\n")
	if len(snap) != 1 || snap[0].Publisher != "mozilla" {
		t.Fatalf("snap: %+v", snap)
	}
}

func TestParseUsersAndPrinters(t *testing.T) {
	if got := ParseGroupMembers("root:x:0:\nsudo:x:27:ana,luis\nwheel:x:10:\nusers:x:100:ana\n", "sudo", "wheel"); !reflect.DeepEqual(got, []string{"ana", "luis"}) {
		t.Fatalf("groups: %v", got)
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nana:x:1000:1000:Ana:/home/ana:/bin/bash\nnobody:x:65534:65534::/:/usr/sbin/nologin\nsvc:x:1001:1001::/srv:/bin/false\n"
	if got := ParsePasswdUsers(passwd); !reflect.DeepEqual(got, []string{"root", "ana"}) {
		t.Fatalf("passwd: %v", got)
	}
	if got := ParseWho("ana      tty2         2024-09-26 08:00 (tty2)\nana      pts/0        2024-09-26 09:00\n"); len(got) != 2 {
		t.Fatalf("who: %v", got)
	}
	printers := ParseLpstat("device for Oficina: ipp://10.0.0.50/ipp/print\ndevice for Etiquetas: usb://Zebra/ZD420\n", "system default destination: Oficina")
	if len(printers) != 2 || !printers[0].Default || !printers[0].Network || printers[1].Network {
		t.Fatalf("lpstat: %+v", printers)
	}
}

func TestDetectAgents(t *testing.T) {
	got := DetectAgents([]string{"/opt/CrowdStrike/falcond", "MsMpEng.exe", "sshd", "SentinelAgent", "ossec-agentd"})
	want := []string{"CrowdStrike Falcon", "Microsoft Defender Antivirus", "SentinelOne", "Wazuh"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestFinishCleansAndCaps(t *testing.T) {
	d := Details{
		System:   System{Manufacturer: "To Be Filled By O.E.M.", Model: "System Product Name", SerialNumber: "Default string"},
		Software: make([]Software, 0, 2100),
		Volumes:  []Volume{{Mount: "/", TotalGb: 10}, {Mount: "/", TotalGb: 10}, {Mount: "/empty", TotalGb: 0}},
		Network:  []NetInterface{{Name: "eth0", IPv4: []string{"10.0.0.1", "10.0.0.1"}}},
		Users:    Users{LoggedOn: []string{"ana", "ANA", ""}},
	}
	for i := 0; i < 2100; i++ {
		d.Software = append(d.Software, Software{Name: "pkg" + itoa(i), Version: "1"})
	}
	d.Software = append(d.Software, Software{Name: "pkg1", Version: "1"}, Software{Name: "bad\x00name ", Version: strings.Repeat("9", 500)})
	d.finish()
	if d.System.Manufacturer != "" || d.System.Model != "" || d.System.SerialNumber != "" || d.System.Role != "workstation" || d.System.FormFactor != "other" {
		t.Fatalf("placeholders should be dropped: %+v", d.System)
	}
	if len(d.Software) != maxSoftware || len(d.Volumes) != 1 || len(d.Network[0].IPv4) != 1 || len(d.Users.LoggedOn) != 1 {
		t.Fatalf("caps/dedup: %d apps, %d volumes, %v, %v", len(d.Software), len(d.Volumes), d.Network[0].IPv4, d.Users.LoggedOn)
	}
	for _, s := range d.Software {
		if len(s.Version) > 100 || strings.ContainsRune(s.Name, 0) {
			t.Fatalf("not cleaned: %+v", s)
		}
	}
	b, _ := json.Marshal(d)
	for _, key := range []string{`"gpus":[]`, `"printers":[]`, `"virtualMachines":[]`, `"serverRoles":[]`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("%s: empty lists must be [] not null", key)
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
