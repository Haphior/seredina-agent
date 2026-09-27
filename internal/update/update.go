// Package update fetches a newer agent release: the archive for this OS and
// architecture, checked against the release's SHA256SUMS before anything
// from it runs. Installing it is left to the new binary's own `install`
// command, the same path a fresh install takes.
package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Releases is where the official archives are published.
const Releases = "https://github.com/Haphior/seredina-agent/releases"

// maxArchive bounds a download: the archives are about 3 MB.
const maxArchive = 100 << 20

// Source says where to download from.
type Source struct {
	// Version to fetch ("v0.3.0"), or "" for the latest release.
	Version string
	// Base overrides the download folder, for an internal mirror holding a
	// copy of a release's files.
	Base string
	// ExtraCA is added to the system's trusted roots, so a mirror behind the
	// same internal CA as the Seredina server is trusted too.
	ExtraCA []byte
}

// BaseURL is the folder the release files are read from.
func (s Source) BaseURL() string {
	switch {
	case s.Base != "":
		return strings.TrimRight(s.Base, "/")
	case s.Version == "" || s.Version == "latest":
		return Releases + "/latest/download"
	default:
		return Releases + "/download/" + s.Version
	}
}

// ArchiveName is the release archive for this OS and architecture.
func ArchiveName(goos, goarch string) string {
	if goos == "windows" {
		return "seredina-agent_windows_" + goarch + ".zip"
	}
	return "seredina-agent_" + goos + "_" + goarch + ".tar.gz"
}

func (s Source) client() (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(s.ExtraCA) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(s.ExtraCA)
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Minute}, nil
}

func (s Source) get(name string, limit int64) ([]byte, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	url := s.BaseURL() + "/" + name
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", url, errNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than expected", url)
	}
	return b, nil
}

var errNotFound = errors.New("not found")

var versionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// AvailableVersion reads the release's VERSION file. Releases before v0.3.0
// have none: then it returns "" and no error, and the caller can't tell
// whether it's already current.
func (s Source) AvailableVersion() (string, error) {
	b, err := s.get("VERSION", 100)
	if errors.Is(err, errNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if !versionPattern.MatchString(v) {
		return "", fmt.Errorf("the release's VERSION file says %q, which isn't a version", v)
	}
	return v, nil
}

// Download fetches this platform's archive, checks it against SHA256SUMS,
// and writes the agent binary from it into dir. It returns the binary's
// path.
func (s Source) Download(dir string) (string, error) {
	name := ArchiveName(runtime.GOOS, runtime.GOARCH)
	sums, err := s.get("SHA256SUMS", 1<<16)
	if err != nil {
		return "", err
	}
	want, err := ChecksumFor(sums, name)
	if err != nil {
		return "", err
	}
	archive, err := s.get(name, maxArchive)
	if err != nil {
		return "", err
	}
	if got := sha256.Sum256(archive); hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s: refusing to install it", name)
	}
	exe := "seredina-agent"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	bin, err := Extract(archive, name, exe)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, exe)
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// ChecksumFor finds an archive's hash in a SHA256SUMS file
// ("<hex>  <name>" or "<hex> *<name>" lines).
func ChecksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s is not listed in SHA256SUMS", name)
}

// Extract pulls one file (by base name) out of a .zip or .tar.gz archive.
func Extract(archive []byte, archiveName, file string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) != file {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxArchive))
		}
		return nil, fmt.Errorf("%s has no %s", archiveName, file)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s has no %s", archiveName, file)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == file {
			return io.ReadAll(io.LimitReader(tr, maxArchive))
		}
	}
}
