package inventory

import (
	"reflect"
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

func TestParseWindowsReport(t *testing.T) {
	text := `{"cpu":"Intel(R) Core(TM) i5-10310U CPU @ 1.70GHz","memoryBytes":17179869184,"os":"Microsoft Windows 11 Pro 10.0.22631",
"disks":[{"mount":"C:","size":510770802688,"free":214748364800},{"mount":"D:","size":0,"free":0}],
"bitlocker":[0,1],"defender":true,
"apps":[{"name":"Google Chrome","version":"129.0.6668.59"},{"name":"  ","version":""},{"name":"7-Zip 23.01 (x64)","version":""}]}`
	got := ParseWindowsReport(text)
	if got.CPUModel != "Intel(R) Core(TM) i5-10310U CPU @ 1.70GHz" || got.MemoryTotalMb != 16384 || got.OSVersion != "Microsoft Windows 11 Pro 10.0.22631" {
		t.Fatalf("basics: %+v", got)
	}
	if !reflect.DeepEqual(got.DiskSummary, []Disk{{"C:", 475.7, 200.0}}) {
		t.Fatalf("disks: %+v", got.DiskSummary)
	}
	if got.DiskEncrypted == nil || !*got.DiskEncrypted {
		t.Fatal("one protected BitLocker volume should count as encrypted")
	}
	if got.AntivirusStatus != "enabled" {
		t.Fatalf("antivirus: %q", got.AntivirusStatus)
	}
	if !reflect.DeepEqual(got.InstalledPackages, []Package{{"Google Chrome", "129.0.6668.59"}, {"7-Zip 23.01 (x64)", ""}}) {
		t.Fatalf("apps: %+v", got.InstalledPackages)
	}
}

func TestParseWindowsReportWithoutOptionalParts(t *testing.T) {
	// Home editions have no BitLocker cmdlet; another antivirus replaces Defender.
	got := ParseWindowsReport(`{"cpu":"x","memoryBytes":0,"os":"Windows 10 Home 10.0.19045"}`)
	if got.DiskEncrypted != nil || got.AntivirusStatus != "unknown" {
		t.Fatalf("got %+v", got)
	}
	if bad := ParseWindowsReport("not json"); bad.AntivirusStatus != "unknown" {
		t.Fatalf("garbage should not panic: %+v", bad)
	}
}

func TestCollectOnThisMachine(t *testing.T) {
	inv := Collect()
	if inv.Hostname == "" || inv.Platform == "" || inv.DiskSummary == nil || inv.InstalledPackages == nil {
		t.Fatalf("incomplete inventory: %+v", inv)
	}
	if len(inv.InstalledPackages) > MaxPackages {
		t.Fatalf("%d packages, cap is %d", len(inv.InstalledPackages), MaxPackages)
	}
	t.Logf("%s %s | %s | %d MB | %d disks | %d packages | encrypted=%v | av=%s",
		inv.Platform, inv.Hostname, inv.OSVersion, inv.MemoryTotalMb, len(inv.DiskSummary), len(inv.InstalledPackages), inv.DiskEncrypted, inv.AntivirusStatus)
}
