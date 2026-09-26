package inventory

import (
	"encoding/json"
	"strings"
)

// WindowsScript collects the whole Windows inventory in one PowerShell run
// (starting PowerShell costs about a second, so one run beats seven). Each
// part is wrapped so a missing cmdlet (no BitLocker module on Home editions,
// Defender replaced by another product) leaves that field null instead of
// failing the rest. Output is JSON, so nothing depends on the display
// language.
const WindowsScript = `$ErrorActionPreference = 'SilentlyContinue'
$r = [ordered]@{}
try { $r.cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name } catch {}
try { $r.memoryBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory } catch {}
try { $os = Get-CimInstance Win32_OperatingSystem; $r.os = "$($os.Caption) $($os.Version)" } catch {}
try { $r.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ mount = $_.DeviceID; size = [int64]$_.Size; free = [int64]$_.FreeSpace } }) } catch {}
try { $r.bitlocker = @(Get-BitLockerVolume | ForEach-Object { [int]$_.ProtectionStatus }) } catch {}
try { $r.defender = [bool](Get-MpComputerStatus).AntivirusEnabled } catch {}
try {
  $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $r.apps = @(Get-ItemProperty $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Sort-Object DisplayName -Unique | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion } })
} catch {}
$r | ConvertTo-Json -Depth 4 -Compress`

type windowsReport struct {
	CPU         string `json:"cpu"`
	MemoryBytes int64  `json:"memoryBytes"`
	OS          string `json:"os"`
	Disks       []struct {
		Mount string  `json:"mount"`
		Size  float64 `json:"size"`
		Free  float64 `json:"free"`
	} `json:"disks"`
	BitLocker []int `json:"bitlocker"`
	Defender  *bool `json:"defender"`
	Apps      []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"apps"`
}

// ParseWindowsReport turns WindowsScript's JSON into an Inventory.
func ParseWindowsReport(text string) Inventory {
	var r windowsReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &r); err != nil {
		return Inventory{AntivirusStatus: "unknown"}
	}
	inv := Inventory{
		CPUModel:      strings.TrimSpace(r.CPU),
		MemoryTotalMb: r.MemoryBytes / 1024 / 1024,
		OSVersion:     strings.TrimSpace(r.OS),
	}
	for _, d := range r.Disks {
		if d.Size <= 0 {
			continue
		}
		inv.DiskSummary = append(inv.DiskSummary, Disk{Mount: d.Mount, TotalGb: round1(d.Size / 1024 / 1024 / 1024), FreeGb: round1(d.Free / 1024 / 1024 / 1024)})
	}
	// ProtectionStatus 1 = protection on. Any protected volume counts, same
	// heuristic as the other platforms.
	if r.BitLocker != nil {
		on := false
		for _, s := range r.BitLocker {
			if s == 1 {
				on = true
			}
		}
		inv.DiskEncrypted = boolPtr(on)
	}
	switch {
	case r.Defender == nil:
		inv.AntivirusStatus = "unknown"
	case *r.Defender:
		inv.AntivirusStatus = "enabled"
	default:
		inv.AntivirusStatus = "disabled"
	}
	for _, a := range r.Apps {
		if name := strings.TrimSpace(a.Name); name != "" {
			inv.InstalledPackages = append(inv.InstalledPackages, Package{Name: name, Version: strings.TrimSpace(a.Version)})
		}
	}
	return inv
}
