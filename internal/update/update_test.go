package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func tarGz(t *testing.T, name string, body []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"LICENSE", []byte("AGPL")}, {name, body}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipped(t *testing.T, name string, body []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(body)
	zw.Close()
	return buf.Bytes()
}

// release serves a fake release folder: VERSION, SHA256SUMS and this
// platform's archive.
func release(t *testing.T, version string, tamper bool) (*httptest.Server, []byte) {
	binary := []byte("#!/bin/sh\necho new agent\n")
	name := ArchiveName(runtime.GOOS, runtime.GOARCH)
	var archive []byte
	if runtime.GOOS == "windows" {
		archive = zipped(t, "seredina-agent.exe", binary)
	} else {
		archive = tarGz(t, "seredina-agent", binary)
	}
	sum := sha256.Sum256(archive)
	sums := fmt.Sprintf("%s  %s\n%s  other.zip\n", hex.EncodeToString(sum[:]), name, strings.Repeat("0", 64))
	if tamper {
		archive = append(archive, 0)
	}
	mux := http.NewServeMux()
	if version != "" {
		mux.HandleFunc("/rel/VERSION", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, version) })
	}
	mux.HandleFunc("/rel/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(sums)) })
	mux.HandleFunc("/rel/"+name, func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) })
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, binary
}

// pinned trusts the test server's certificate the way a mirror behind the
// Seredina server's internal CA is trusted.
func pinned(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestDownloadVerifiesAndExtracts(t *testing.T) {
	srv, binary := release(t, "v0.3.0", false)
	src := Source{Base: srv.URL + "/rel/", ExtraCA: pinned(srv)}
	if v, err := src.AvailableVersion(); err != nil || v != "v0.3.0" {
		t.Fatalf("version %q %v", v, err)
	}
	path, err := src.Download(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, binary) {
		t.Fatalf("extracted %q", got)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		t.Fatal("the binary must be executable")
	}
}

func TestTamperedArchiveIsRefused(t *testing.T) {
	srv, _ := release(t, "v0.3.0", true)
	_, err := Source{Base: srv.URL + "/rel", ExtraCA: pinned(srv)}.Download(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("a tampered archive must be refused, got %v", err)
	}
}

func TestReleaseWithoutVersionFile(t *testing.T) {
	// Releases before v0.3.0 carry no VERSION: not an error, just unknown.
	srv, _ := release(t, "", false)
	if v, err := (Source{Base: srv.URL + "/rel", ExtraCA: pinned(srv)}).AvailableVersion(); err != nil || v != "" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestUntrustedServerIsRefused(t *testing.T) {
	srv, _ := release(t, "v0.3.0", false)
	if _, err := (Source{Base: srv.URL + "/rel"}).AvailableVersion(); err == nil {
		t.Fatal("a certificate nobody trusts must be refused")
	}
}

func TestBaseURL(t *testing.T) {
	cases := []struct {
		src  Source
		want string
	}{
		{Source{}, Releases + "/latest/download"},
		{Source{Version: "latest"}, Releases + "/latest/download"},
		{Source{Version: "v0.3.0"}, Releases + "/download/v0.3.0"},
		{Source{Base: "https://mirror/agent/"}, "https://mirror/agent"},
	}
	for _, c := range cases {
		if got := c.src.BaseURL(); got != c.want {
			t.Errorf("%+v: %s, want %s", c.src, got, c.want)
		}
	}
	if ArchiveName("windows", "arm64") != "seredina-agent_windows_arm64.zip" || ArchiveName("darwin", "amd64") != "seredina-agent_darwin_amd64.tar.gz" {
		t.Fatal("archive names must match scripts/build.sh")
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte(strings.Repeat("a", 64) + "  seredina-agent_linux_amd64.tar.gz\n" + strings.Repeat("B", 64) + " *seredina-agent_windows_amd64.zip\n")
	if s, err := ChecksumFor(sums, "seredina-agent_windows_amd64.zip"); err != nil || s != strings.Repeat("b", 64) {
		t.Fatalf("%s %v", s, err)
	}
	if _, err := ChecksumFor(sums, "seredina-agent_linux_arm64.tar.gz"); err == nil {
		t.Fatal("a missing entry is an error")
	}
}

func TestExtractZip(t *testing.T) {
	archive := zipped(t, "seredina-agent.exe", []byte("MZ"))
	if b, err := Extract(archive, "x.zip", "seredina-agent.exe"); err != nil || string(b) != "MZ" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := Extract(archive, "x.zip", "other"); err == nil {
		t.Fatal("missing file is an error")
	}
}
