package inventory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseDfPortableLinux(t *testing.T) {
	text := `Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/nvme0n1p2   491134216 201234560 264890112      44% /
/dev/nvme0n1p1      523248      6220    517028       2% /boot/efi
/dev/sdb1       1921802432 102400000 1721802432      6% /mnt/Data Disk
/dev/loop5             1024      1024         0     100% /opt/tiny
tmpfs              8159044         0   8159044       0% /run/user/1000`
	got := ParseDfPortable(text)
	want := []Disk{{"/", 468.4, 252.6}, {"/mnt/Data Disk", 1832.8, 1642.0}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseDfPortableMac(t *testing.T) {
	// `df -kP` on macOS: same six columns as Linux, unlike plain `df -k`.
	text := `Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   482797652  10485760 285212672     4%    /
devfs                  204       204         0   100%    /dev
/dev/disk3s6     482797652   2097152 285212672     1%    /System/Volumes/VM
/dev/disk3s5     482797652 180355072 285212672    39%    /System/Volumes/Data
map auto_home            0         0         0   100%    /System/Volumes/Data/home`
	got := ParseDfPortable(text)
	want := []Disk{{"/", 460.4, 272.0}, {"/System/Volumes/Data", 460.4, 272.0}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseTabbedPackages(t *testing.T) {
	got := ParseTabbedPackages("bash\t5.2.15-2\ncurl\t7.88.1\n\nnoversion\n")
	want := []Package{{"bash", "5.2.15-2"}, {"curl", "7.88.1"}, {"noversion", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseAPKPackages(t *testing.T) {
	got := ParseAPKPackages("musl-1.2.4-r2\nbusybox-1.36.1-r15\nweird\n")
	want := []Package{{"musl", "1.2.4-r2"}, {"busybox", "1.36.1-r15"}, {"weird", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseKeyValue(t *testing.T) {
	cpuinfo := "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i7-1165G7 @ 2.80GHz\n"
	if got := ParseKeyValue(cpuinfo, "model name"); got != "Intel(R) Core(TM) i7-1165G7 @ 2.80GHz" {
		t.Fatalf("cpuinfo: %q", got)
	}
	osRelease := "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"
	if got := ParseKeyValue(osRelease, "PRETTY_NAME"); got != "Ubuntu 24.04.1 LTS" {
		t.Fatalf("os-release: %q", got)
	}
}

func TestCollectOnThisMachine(t *testing.T) {
	inv := Collect()
	if inv.Hostname == "" || inv.Platform == "" || inv.DiskSummary == nil || inv.InstalledPackages == nil || inv.Details == nil {
		t.Fatalf("incomplete inventory: %+v", inv)
	}
	if len(inv.InstalledPackages) > MaxPackages {
		t.Fatalf("%d packages, cap is %d", len(inv.InstalledPackages), MaxPackages)
	}
	d := inv.Details
	if d.Schema != SchemaVersion || d.OS.Name == "" || d.CPU.Model == "" || d.Memory.TotalMb == 0 || d.System.Role == "" {
		t.Fatalf("details missing basics: %+v", d)
	}
	// Every list is present, even empty, so the JSON has one shape.
	b, _ := json.Marshal(d)
	for _, key := range []string{`"disks":[`, `"volumes":[`, `"network":[`, `"software":[`, `"services":[`, `"ports":[`, `"agents":[`, `"installed":[`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("%s missing from %s", key, b)
		}
	}
	t.Logf("%s %s | %s | %s %s (%s, %s) | %s | %d MB, %d modules | %d disks, %d volumes | %d NICs | %d apps | %d services | %d ports | roles %v | %d guests | AV %v | agents %v | legacy AV %s, encrypted %v",
		inv.Platform, inv.Hostname, d.OS.Name, d.System.Manufacturer, d.System.Model, d.System.FormFactor, d.System.Role, d.CPU.Model,
		d.Memory.TotalMb, len(d.Memory.Modules), len(d.Disks), len(d.Volumes), len(d.Network), len(d.Software), len(d.Services), len(d.Ports),
		d.ServerRoles, len(d.VirtualMachines), d.Security.Antivirus, d.Security.Agents, inv.AntivirusStatus, inv.DiskEncrypted)
}
