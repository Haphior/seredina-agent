package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeServer struct {
	*httptest.Server
	enrollBody  map[string]any
	checkinBody map[string]any
	checkinAuth string
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/devices/enroll", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &f.enrollBody)
		if f.enrollBody["enrollmentToken"] != "good-token" {
			http.Error(w, `{"error":"invalid or expired enrollment token"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"deviceId":"d1","credential":"secret-credential","reenrolled":false}`))
	})
	mux.HandleFunc("/api/v1/devices/checkin", func(w http.ResponseWriter, r *http.Request) {
		f.checkinAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &f.checkinBody)
		w.Write([]byte(`{"neighbors":{"created":2,"updated":1}}`))
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

// caPEM is the test server's certificate as PEM, which is also its CA.
func (f *fakeServer) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw})
}

func TestEnrollAndCheckinWithPinnedCA(t *testing.T) {
	f := newFakeServer(t)
	store := Store{Dir: filepath.Join(t.TempDir(), "cfg")}
	ca, err := ResolveCA(base64.StdEncoding.EncodeToString(f.caPEM()), "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Enroll(store, EnrollOptions{URL: f.URL + "/api", Token: "wrong", CA: ca}); err == nil {
		t.Fatal("a bad token must fail")
	}
	reenrolled, err := Enroll(store, EnrollOptions{URL: f.URL + "/api", Token: "good-token", CA: ca})
	if err != nil || reenrolled {
		t.Fatalf("enroll: %v %v", reenrolled, err)
	}
	// The server receives exactly the fields it validates.
	wantPlatform := map[string]string{"windows": "win32"}[runtime.GOOS]
	if wantPlatform == "" {
		wantPlatform = runtime.GOOS
	}
	if f.enrollBody["platform"] != wantPlatform || f.enrollBody["hostname"] == "" || f.enrollBody["agentVersion"] == nil {
		t.Fatalf("enroll body: %v", f.enrollBody)
	}
	if fp, ok := f.enrollBody["machineFingerprint"].(string); ok && len(fp) != 64 {
		t.Fatalf("fingerprint must be a sha256 hex digest: %q", fp)
	}

	creds, pinned, err := store.Load()
	if err != nil || creds.Credential != "secret-credential" || creds.URL != f.URL+"/api" || pinned == nil {
		t.Fatalf("stored: %+v pinned=%v err=%v", creds, pinned != nil, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(store.CredentialsPath())
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credentials.json is %v, want 0600", info.Mode().Perm())
		}
	}

	res, err := Checkin(store)
	if err != nil {
		t.Fatal(err)
	}
	if f.checkinAuth != "Bearer secret-credential" || res.NeighborsCreated != 2 {
		t.Fatalf("auth %q, result %+v", f.checkinAuth, res)
	}
	for _, key := range []string{"diskSummary", "installedPackages", "neighbors", "osVersion"} {
		if _, ok := f.checkinBody[key]; !ok {
			t.Errorf("check-in is missing %q: %v", key, f.checkinBody)
		}
	}
}

func TestPinnedCARejectsAnyOtherServer(t *testing.T) {
	trusted := newFakeServer(t)
	// httptest servers all share one built-in certificate, so this one gets
	// its own self-signed certificate for 127.0.0.1.
	other := httptest.NewUnstartedServer(http.NotFoundHandler())
	other.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	other.StartTLS()
	t.Cleanup(other.Close)
	client, err := NewClient(other.URL, trusted.caPEM())
	if err != nil {
		t.Fatal(err)
	}
	err = client.post("/api/v1/devices/checkin", "x", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a server not signed by the pinned CA must be refused, got %v", err)
	}
	// And without a pin, a self-signed server isn't trusted either: the agent
	// never turns verification off.
	plain, _ := NewClient(trusted.URL, nil)
	if err := plain.post("/api/v1/devices/checkin", "x", map[string]string{}, nil); err == nil {
		t.Fatal("an untrusted certificate must be refused")
	}
}

func TestReenrollingAgainstPublicServerDropsThePin(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	if err := store.Save(Credentials{URL: "https://a", Credential: "c"}, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Credentials{URL: "https://b", Credential: "d"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ca, _ := store.Load(); ca != nil {
		t.Fatal("the old CA pin should be gone")
	}
}

func TestReadsCredentialsWrittenByTheNodeAgent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("{\n  \"url\": \"https://desk.example.com/api\",\n  \"credential\": \"abc\"\n}"), 0o600)
	creds, _, err := Store{Dir: dir}.Load()
	if err != nil || creds.URL != "https://desk.example.com/api" || creds.Credential != "abc" {
		t.Fatalf("%+v %v", creds, err)
	}
	if _, _, err := (Store{Dir: filepath.Join(dir, "missing")}).Load(); err != ErrNotEnrolled {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	if u, w, err := NormalizeServerURL("https://desk.example.com/api/"); err != nil || u != "https://desk.example.com/api" || w != "" {
		t.Fatalf("%q %q %v", u, w, err)
	}
	if _, w, _ := NormalizeServerURL("http://10.0.0.5:4000"); w == "" {
		t.Fatal("plain http to a LAN address should warn")
	}
	if _, w, _ := NormalizeServerURL("http://localhost:4000"); w != "" {
		t.Fatal("localhost should not warn")
	}
	for _, bad := range []string{"desk.example.com", "ftp://x", ""} {
		if _, _, err := NormalizeServerURL(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestResolveCARefusesKeysAndGarbage(t *testing.T) {
	if _, err := ResolveCA(base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\n...")), ""); err == nil {
		t.Fatal("a private key must be refused")
	}
	if _, err := ResolveCA("%%%", ""); err == nil {
		t.Fatal("bad base64 must be refused")
	}
	if ca, err := ResolveCA("", ""); ca != nil || err != nil {
		t.Fatal("no CA given means no pin")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "impostor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestIntervalIsRemembered(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	if _, ok := store.LoadInterval(); ok {
		t.Fatal("nothing saved yet")
	}
	if err := store.SaveInterval(30 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if d, ok := store.LoadInterval(); !ok || d != 30*time.Minute {
		t.Fatalf("%v %v", d, ok)
	}
}
