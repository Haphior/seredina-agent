package network

import (
	"reflect"
	"testing"
)

func TestFingerprintMatchesTheNodeAgent(t *testing.T) {
	// Computed with the original Node.js agent's code:
	// sha256("seredina-machine:" + raw.toLowerCase())
	want := "697581c0b7724560481fea0396fa6e8d1d6eb1fd06e641c8607106c88eb2b084"
	if got := Fingerprint("ABCD-1234-ef"); got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
	if Fingerprint("  ") != "" {
		t.Fatal("an empty machine id must give no fingerprint")
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"A0:B1:C2:D3:E4:F5": "a0:b1:c2:d3:e4:f5",
		"a0-b1-c2-d3-e4-f5": "a0:b1:c2:d3:e4:f5",
		"0:1b:2c:3:4d:5e":   "00:1b:2c:03:4d:5e", // macOS drops leading zeros
		"(incomplete)":      "",
		"a0:b1:c2":          "",
		"zz:b1:c2:d3:e4:f5": "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseProcNetARP(t *testing.T) {
	text := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a0:b1:c2:d3:e4:f5     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.30     0x1         0x2         11:22:33:44:55:66     *        eth0`
	got := clean(ParseProcNetARP(text))
	want := []Neighbor{{"192.168.1.1", "a0:b1:c2:d3:e4:f5"}, {"192.168.1.30", "11:22:33:44:55:66"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseBSDArp(t *testing.T) {
	text := `? (192.168.1.1) at a0:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]
? (192.168.1.44) at 0:1b:2c:3:4d:5e on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]`
	got := clean(ParseBSDArp(text))
	want := []Neighbor{{"192.168.1.1", "a0:b1:c2:d3:e4:f5"}, {"192.168.1.44", "00:1b:2c:03:4d:5e"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseWindowsArpInAnyLanguage(t *testing.T) {
	// A Spanish Windows says "dinámico"/"estático"; the type column isn't
	// matched on, so broadcast/multicast are dropped by MAC instead.
	text := "\r\nInterfaz: 192.168.1.10 --- 0xb\r\n" +
		"  Dirección de Internet          Dirección física      Tipo\r\n" +
		"  192.168.1.1           a0-b1-c2-d3-e4-f5     dinámico\r\n" +
		"  192.168.1.25          11-22-33-44-55-66     dinámico\r\n" +
		"  192.168.1.255         ff-ff-ff-ff-ff-ff     estático\r\n" +
		"  224.0.0.22            01-00-5e-00-00-16     estático\r\n"
	got := clean(ParseWindowsArp(text))
	want := []Neighbor{{"192.168.1.1", "a0:b1:c2:d3:e4:f5"}, {"192.168.1.25", "11:22:33:44:55:66"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCleanCapsAndDeduplicates(t *testing.T) {
	var raw []Neighbor
	for i := 0; i < MaxNeighbors+50; i++ {
		raw = append(raw, Neighbor{IP: "10.0." + itoa(i/250) + "." + itoa(i%250), MAC: "02:00:00:00:00:01"})
	}
	raw = append([]Neighbor{raw[0]}, raw...) // a duplicate
	if got := clean(raw); len(got) != MaxNeighbors {
		t.Fatalf("got %d neighbors, want %d", len(got), MaxNeighbors)
	}
}

func itoa(i int) string {
	return string(rune('0'+i/100)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}
