// Package agent implements enrollment and check-ins against a Seredina
// server (docs/adr/0047-endpoint-agents-v1.md and 0055-agent-based-discovery.md
// in the Seredina repository). Inventory only: the agent never runs remote
// commands and never installs software.
package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Haphior/seredina-agent/internal/inventory"
	"github.com/Haphior/seredina-agent/internal/network"
)

// DefaultInterval between check-ins: inventory doesn't change minute to minute.
const DefaultInterval = time.Hour

// EnrollOptions are the enrollment command's arguments.
type EnrollOptions struct {
	URL   string
	Token string
	CA    []byte // nil = the server's certificate is publicly trusted
}

type enrollRequest struct {
	EnrollmentToken    string `json:"enrollmentToken"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`
	AgentVersion       string `json:"agentVersion"`
	MachineFingerprint string `json:"machineFingerprint,omitempty"`
	MACAddress         string `json:"macAddress,omitempty"`
}

type enrollResponse struct {
	Credential string `json:"credential"`
	Reenrolled bool   `json:"reenrolled"`
}

// Enroll trades a one-time enrollment token for this device's permanent
// credential and saves it. It reports whether the server reused an existing
// record (same machine fingerprint).
func Enroll(store Store, opts EnrollOptions) (bool, error) {
	client, err := NewClient(opts.URL, opts.CA)
	if err != nil {
		return false, err
	}
	var res enrollResponse
	err = client.post("/v1/devices/enroll", "", enrollRequest{
		EnrollmentToken:    opts.Token,
		Hostname:           inventory.Hostname(),
		Platform:           inventory.Platform(),
		AgentVersion:       Version,
		MachineFingerprint: network.MachineFingerprint(),
		MACAddress:         network.PrimaryMAC(),
	}, &res)
	if err != nil {
		return false, err
	}
	if res.Credential == "" {
		return false, fmt.Errorf("the server didn't return a credential")
	}
	if err := store.Save(Credentials{URL: opts.URL, Credential: res.Credential}, opts.CA); err != nil {
		return false, err
	}
	return res.Reenrolled, nil
}

type checkinRequest struct {
	inventory.Inventory
	MACAddress string             `json:"macAddress,omitempty"`
	Neighbors  []network.Neighbor `json:"neighbors"`
}

type checkinResponse struct {
	Neighbors *struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	} `json:"neighbors"`
	// "stored", or "rejected" with the reason when the server couldn't take
	// the detailed inventory (the summary fields are stored either way).
	// Servers older than the detailed inventory don't send it.
	Inventory      string `json:"inventory"`
	InventoryError string `json:"inventoryError"`
}

// CheckinResult summarizes one check-in for the log.
type CheckinResult struct {
	Hostname         string
	Platform         string
	Role             string
	Packages         int
	Neighbors        int
	NeighborsCreated int
	// InventoryRejected is the server's reason for not storing the detailed
	// inventory, if it gave one.
	InventoryRejected string
}

// Checkin sends the current inventory and ARP neighbors.
func Checkin(store Store) (CheckinResult, error) {
	creds, ca, err := store.Load()
	if err != nil {
		return CheckinResult{}, err
	}
	client, err := NewClient(creds.URL, ca)
	if err != nil {
		return CheckinResult{}, err
	}
	inv := inventory.Collect()
	neighbors := network.Neighbors()
	var res checkinResponse
	if err := client.post("/v1/devices/checkin", creds.Credential, checkinRequest{
		Inventory:  inv,
		MACAddress: network.PrimaryMAC(),
		Neighbors:  neighbors,
	}, &res); err != nil {
		return CheckinResult{}, err
	}
	out := CheckinResult{Hostname: inv.Hostname, Platform: inv.Platform, Packages: len(inv.InstalledPackages), Neighbors: len(neighbors)}
	if inv.Details != nil {
		out.Role = inv.Details.System.Role
	}
	if res.Neighbors != nil {
		out.NeighborsCreated = res.Neighbors.Created
	}
	if res.Inventory == "rejected" {
		out.InventoryRejected = firstNonEmpty(res.InventoryError, "no reason given")
	}
	return out, nil
}

// Run checks in now and then every interval until ctx is cancelled. A failed
// check-in is logged and retried at the next tick; a revoked credential
// (401) is logged loudly, since only re-enrolling fixes it.
func Run(ctx context.Context, store Store, interval time.Duration, logger *log.Logger) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	for {
		res, err := Checkin(store)
		switch {
		case err == nil:
			logger.Printf("checked in: %s (%s, %s), %d packages, %d neighbors (%d new)", res.Hostname, res.Platform, res.Role, res.Packages, res.Neighbors, res.NeighborsCreated)
			if res.InventoryRejected != "" {
				logger.Printf("the server kept the summary but not the detailed inventory: %s", res.InventoryRejected)
			}
		case isUnauthorized(err):
			logger.Printf("check-in refused (401): this device's credential was revoked or the device was deleted. Enroll it again from the Devices page.")
		default:
			logger.Printf("check-in failed, retrying in %s: %v", interval, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func isUnauthorized(err error) bool {
	apiErr, ok := err.(*APIError)
	return ok && apiErr.Status == 401
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
