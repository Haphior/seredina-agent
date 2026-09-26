// Command seredina-agent reports a computer's hardware and software inventory
// to a Seredina helpdesk. See README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/Haphior/seredina-agent/internal/agent"
	"github.com/Haphior/seredina-agent/internal/inventory"
	"github.com/Haphior/seredina-agent/internal/svc"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `Seredina agent %s: reports this computer's inventory to Seredina.

Usage:
  seredina-agent enroll --url <server> --token <token> [--ca-pem <base64> | --ca <file.pem>] [--install]
  seredina-agent install [--interval 1h]     run as a background service (needs admin)
  seredina-agent uninstall [--purge]         remove the service (--purge also deletes the credential)
  seredina-agent status                      is it enrolled, and is the service running?
  seredina-agent checkin                     send the inventory once, now
  seredina-agent run [--interval 1h]         check in periodically in the foreground
  seredina-agent version

Copy the enrollment command from Seredina's Devices page: it already carries
the right server address, a one-time token and, if needed, the CA to trust.

Every command also takes --config-dir <dir> (default: %s as administrator,
%s otherwise).
`

func main() {
	agent.Version = version
	if len(os.Args) < 2 {
		printUsage(os.Stdout)
		os.Exit(2)
	}
	if err := dispatch(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, usage, version, agent.SystemDir(), agent.UserDir())
}

func dispatch(command string, args []string) error {
	switch command {
	case "enroll":
		return cmdEnroll(args)
	case "checkin":
		return cmdCheckin(args)
	case "run":
		return cmdRun(args)
	case "install":
		return cmdInstall(args)
	case "uninstall":
		return cmdUninstall(args)
	case "status":
		return cmdStatus(args)
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	}
	printUsage(os.Stderr)
	return fmt.Errorf("unknown command %q", command)
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := fs.String("config-dir", "", "where the credential is stored")
	return fs, dir
}

// interval accepts seconds ("3600", as the original agent did) or a Go
// duration ("1h", "30m").
type interval struct{ d time.Duration }

func (i *interval) String() string { return i.d.String() }
func (i *interval) Set(v string) error {
	if secs, err := strconv.Atoi(v); err == nil {
		i.d = time.Duration(secs) * time.Second
	} else if d, err := time.ParseDuration(v); err == nil {
		i.d = d
	} else {
		return fmt.Errorf("use seconds (3600) or a duration (1h)")
	}
	if i.d < time.Minute {
		return errors.New("the interval must be at least one minute")
	}
	return nil
}

func cmdEnroll(args []string) error {
	fs, dir := newFlags("enroll")
	url := fs.String("url", "", "the server address from the Devices page")
	token := fs.String("token", "", "the one-time enrollment token")
	caPem := fs.String("ca-pem", "", "CA certificate to trust, base64 (from the enrollment command)")
	caFile := fs.String("ca", "", "CA certificate file to trust")
	install := fs.Bool("install", false, "also install and start the background service")
	every := &interval{agent.DefaultInterval}
	fs.Var(every, "interval", "check-in interval for --install")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *token == "" {
		return errors.New("usage: seredina-agent enroll --url <server> --token <token> [--ca-pem <base64> | --ca <file.pem>]")
	}
	server, warning, err := agent.NormalizeServerURL(*url)
	if err != nil {
		return err
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "Warning:", warning)
	}
	ca, err := agent.ResolveCA(*caPem, *caFile)
	if err != nil {
		return err
	}
	store := agent.Store{Dir: agent.DefaultDir(*dir)}
	reenrolled, err := agent.Enroll(store, agent.EnrollOptions{URL: server, Token: *token, CA: ca})
	if err != nil {
		return err
	}
	if reenrolled {
		fmt.Printf("Re-enrolled (the existing record for this computer was reused). Credential saved to %s\n", store.CredentialsPath())
	} else {
		fmt.Printf("Enrolled. Credential saved to %s\n", store.CredentialsPath())
	}
	if *install {
		if err := svc.Install(store, every.d); err != nil {
			return err
		}
		fmt.Printf("Service installed and started: it checks in every %s.\n", every.d)
	}
	return nil
}

func cmdCheckin(args []string) error {
	fs, dir := newFlags("checkin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := agent.Checkin(agent.Store{Dir: agent.DefaultDir(*dir)})
	if err != nil {
		return err
	}
	fmt.Printf("Checked in: %s (%s), %d packages, %d neighbors (%d new)\n", res.Hostname, res.Platform, res.Packages, res.Neighbors, res.NeighborsCreated)
	return nil
}

func cmdRun(args []string) error {
	fs, dir := newFlags("run")
	every := &interval{agent.DefaultInterval}
	fs.Var(every, "interval", "time between check-ins")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := agent.Store{Dir: agent.DefaultDir(*dir)}
	if _, _, err := store.Load(); err != nil {
		return err
	}
	if svc.Interactive() {
		fmt.Printf("Running in the foreground, checking in every %s. Ctrl+C to stop.\n", every.d)
	}
	return svc.RunService(store, every.d)
}

func cmdInstall(args []string) error {
	fs, dir := newFlags("install")
	every := &interval{agent.DefaultInterval}
	fs.Var(every, "interval", "time between check-ins")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := agent.Store{Dir: agent.DefaultDir(*dir)}
	if err := svc.Install(store, every.d); err != nil {
		return err
	}
	fmt.Printf("Service installed and started: %s checks in every %s.\n", svc.InstallPath(), every.d)
	return nil
}

func cmdUninstall(args []string) error {
	fs, dir := newFlags("uninstall")
	purge := fs.Bool("purge", false, "also delete the stored credential and the installed binary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := svc.Uninstall(agent.Store{Dir: agent.DefaultDir(*dir)}, *purge); err != nil {
		return err
	}
	if *purge {
		fmt.Println("Service removed, and the credential deleted. Delete the device in Seredina too if it's gone for good.")
	} else {
		fmt.Println("Service removed. The credential is kept: `seredina-agent install` brings it back.")
	}
	return nil
}

func cmdStatus(args []string) error {
	fs, dir := newFlags("status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := agent.Store{Dir: agent.DefaultDir(*dir)}
	fmt.Printf("Agent:     %s (%s)\n", version, inventory.Platform())
	creds, ca, err := store.Load()
	switch {
	case errors.Is(err, agent.ErrNotEnrolled):
		fmt.Printf("Enrolled:  no (looked in %s)\n", store.Dir)
	case err != nil:
		fmt.Printf("Enrolled:  error: %v\n", err)
	default:
		pinned := "publicly trusted certificate"
		if ca != nil {
			pinned = "pinned CA"
		}
		fmt.Printf("Enrolled:  yes, to %s (%s)\n", creds.URL, pinned)
	}
	fmt.Printf("Service:   %s\n", svc.Status(store))
	return nil
}
