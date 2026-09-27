package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Credentials is what enrollment leaves on disk: the server address and this
// device's permanent bearer credential. Same file format as the original
// Node.js agent, so a machine enrolled with it keeps working.
type Credentials struct {
	URL        string `json:"url"`
	Credential string `json:"credential"`
}

// Store is the agent's config directory: credentials.json and, for a server
// whose certificate isn't publicly trusted, the pinned ca.pem.
type Store struct {
	Dir string
}

const (
	credentialsFile = "credentials.json"
	caFile          = "ca.pem"
)

// ErrNotEnrolled means there's no credentials.json yet.
var ErrNotEnrolled = errors.New("not enrolled yet: run `seredina-agent enroll --url <server> --token <token>` first")

// SystemDir is where the agent keeps its files when it runs as a service
// (root / SYSTEM), readable only by administrators.
func SystemDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Seredina", "Agent")
	case "darwin":
		return "/Library/Application Support/Seredina Agent"
	default:
		return "/etc/seredina-agent"
	}
}

// UserDir is where a non-administrator run keeps its files: the same place
// the original Node.js agent used.
func UserDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".seredina-agent")
}

// DefaultDir picks the directory: an explicit override, then the system
// directory for an administrator (so the service finds what `enroll`
// wrote), then the per-user directory.
func DefaultDir(override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("SEREDINA_AGENT_CONFIG_DIR"); env != "" {
		return env
	}
	if IsAdmin() {
		return SystemDir()
	}
	return UserDir()
}

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Load reads the credentials, and the pinned CA if there is one.
func (s Store) Load() (Credentials, []byte, error) {
	b, err := os.ReadFile(s.path(credentialsFile))
	if errors.Is(err, os.ErrNotExist) {
		return Credentials{}, nil, ErrNotEnrolled
	}
	if err != nil {
		return Credentials{}, nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, nil, fmt.Errorf("%s is damaged: %w", s.path(credentialsFile), err)
	}
	if c.URL == "" || c.Credential == "" {
		return Credentials{}, nil, fmt.Errorf("%s is incomplete: enroll again", s.path(credentialsFile))
	}
	ca, err := os.ReadFile(s.path(caFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil, nil
	}
	return c, ca, err
}

// Save writes the credentials and pins (or unpins) the CA. The credential is
// a permanent secret, so the directory and files are private to the owner
// (on Windows, to SYSTEM and Administrators).
func (s Store) Save(c Credentials, ca []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := restrictDir(s.Dir); err != nil {
		return fmt.Errorf("could not restrict access to %s: %w", s.Dir, err)
	}
	if ca != nil {
		if err := writePrivate(s.path(caFile), ca); err != nil {
			return err
		}
	} else if err := os.Remove(s.path(caFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Re-enrolling against a publicly trusted server drops an old pin.
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(s.path(credentialsFile), b)
}

// Remove deletes everything the agent stored.
func (s Store) Remove() error {
	return os.RemoveAll(s.Dir)
}

// CredentialsPath is shown to the user after enrolling.
func (s Store) CredentialsPath() string { return s.path(credentialsFile) }

// writePrivate writes via a temp file and rename, so a crash never leaves a
// half-written credential behind.
func writePrivate(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o600)
}

const settingsFile = "service.json"

type serviceSettings struct {
	Interval string `json:"interval"`
}

// SaveInterval remembers the check-in interval the service was installed
// with, so an update or a reinstall keeps it.
func (s Store) SaveInterval(d time.Duration) error {
	b, err := json.Marshal(serviceSettings{Interval: d.String()})
	if err != nil {
		return err
	}
	return writePrivate(s.path(settingsFile), b)
}

// LoadInterval returns the interval saved by SaveInterval, if any.
func (s Store) LoadInterval() (time.Duration, bool) {
	b, err := os.ReadFile(s.path(settingsFile))
	if err != nil {
		return 0, false
	}
	var st serviceSettings
	if json.Unmarshal(b, &st) != nil {
		return 0, false
	}
	d, err := time.ParseDuration(st.Interval)
	if err != nil || d < time.Minute {
		return 0, false
	}
	return d, true
}
