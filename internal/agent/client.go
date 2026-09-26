package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Version is the agent's version, set at build time.
var Version = "dev"

// NormalizeServerURL checks the server address and drops a trailing slash.
// It returns a warning for plain http:// outside localhost.
func NormalizeServerURL(value string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a valid server address: expected e.g. https://helpdesk.example.com/api", value)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", "", errors.New("the server address must start with https:// (or http://)")
	}
	warning := ""
	if u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			warning = "this server address uses http://, so the agent credential and inventory travel unencrypted. Use https:// outside a test setup."
		}
	}
	return strings.TrimRight(u.String(), "/"), warning, nil
}

// ResolveCA returns the CA to pin for a server whose certificate isn't
// publicly trusted: base64 PEM from the enrollment command (--ca-pem), or a
// local file (--ca). It arrives with the command rather than from the
// server, so the agent never has to trust a server it can't verify yet.
func ResolveCA(caPemBase64, caFile string) ([]byte, error) {
	var pem []byte
	switch {
	case caPemBase64 != "":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(caPemBase64))
		if err != nil {
			return nil, errors.New("the --ca-pem value isn't valid base64: copy the enrollment command from the console again")
		}
		pem = b
	case caFile != "":
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pem = b
	default:
		return nil, nil
	}
	if !bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Contains(pem, []byte("PRIVATE KEY")) {
		return nil, errors.New("the CA given is not a PEM certificate: copy the enrollment command from the console again")
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return nil, errors.New("the CA given could not be parsed as a certificate")
	}
	return pem, nil
}

// Client talks to the Seredina API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient builds a client for baseURL. With a pinned CA, that CA is the
// ONLY one trusted for this server; the system roots are not consulted.
// Certificate verification is never turned off.
func NewClient(baseURL string, ca []byte) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone() // keeps HTTPS_PROXY support
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("the pinned CA could not be parsed")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 60 * time.Second, Transport: transport}}, nil
}

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) post(path, bearer string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("seredina-agent/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return &APIError{Status: res.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
