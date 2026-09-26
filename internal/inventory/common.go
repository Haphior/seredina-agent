package inventory

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Haphior/seredina-agent/internal/sysinfo"
)

// goInterfaces lists the network adapters with Go's own view of them: name,
// MAC, addresses and whether they're up. Each OS then adds what only it
// knows (gateway, DNS, speed, a friendly description).
func goInterfaces() []NetInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetInterface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := NetInterface{
			Name:    ifc.Name,
			MAC:     strings.ToLower(ifc.HardwareAddr.String()),
			Up:      ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0,
			Virtual: virtualInterface.MatchString(ifc.Name),
			IPv4:    []string{},
			IPv6:    []string{},
			DNS:     []string{},
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				n.IPv4 = append(n.IPv4, v4.String())
			} else if !ipnet.IP.IsLinkLocalUnicast() {
				n.IPv6 = append(n.IPv6, ipnet.IP.String())
			}
		}
		// Tunnels and such with neither a MAC nor an address say nothing.
		if n.MAC == "" && len(n.IPv4) == 0 && len(n.IPv6) == 0 {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Interface names that are virtual whatever the OS: container bridges,
// hypervisor switches, VPN tunnels.
var virtualInterface = regexp.MustCompile(`(?i)^(docker|br-|veth|virbr|vnet|vmnet|vboxnet|cni|flannel|cali|tun|tap|wg|utun|awdl|llw|bridge|anpi|ap\d|gif|stf|zt|tailscale|lxc|lxd|kube|podman|vEthernet)`)

// withGateway puts the default gateway and the DNS servers on the adapter
// that carries the default route.
func withGateway(list []NetInterface, iface, gateway string, dns []string) []NetInterface {
	for i := range list {
		if iface != "" && list[i].Name == iface {
			list[i].Gateway = gateway
			list[i].DNS = dns
		}
	}
	return list
}

// containerGuests lists Docker and Podman containers, when either CLI is
// installed and its daemon answers. Hosts of any OS can run them.
func containerGuests() []Guest {
	var out []Guest
	for _, tool := range []string{"docker", "podman"} {
		if text, ok := sysinfo.Run(tool, "ps", "-a", "--no-trunc", "--format", "{{json .}}"); ok {
			out = append(out, ParseContainerLines(text, tool)...)
		}
	}
	return out
}

// ParseContainerLines parses `docker ps --format '{{json .}}'` (and Podman's
// look-alike): one JSON object per line.
func ParseContainerLines(text, tool string) []Guest {
	var out []Guest
	for _, line := range sysinfo.Lines(text) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var c map[string]any
		if json.Unmarshal([]byte(line), &c) != nil {
			continue
		}
		name := firstString(c, "Names")
		if name == "" {
			if list, ok := c["Names"].([]any); ok && len(list) > 0 {
				name, _ = list[0].(string)
			}
		}
		state := strings.ToLower(firstString(c, "State"))
		if state == "" {
			state = strings.ToLower(firstString(c, "Status"))
		}
		out = append(out, Guest{Name: strings.TrimPrefix(name, "/"), Type: tool, State: state, Image: firstString(c, "Image")})
	}
	return out
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Security products recognized by their process names (lowercase, without
// ".exe"). Listing them tells an admin which machines lack the company's EDR.
var securityProducts = map[string]string{
	"msmpeng": "Microsoft Defender Antivirus", "mssense": "Microsoft Defender for Endpoint",
	"wdavdaemon": "Microsoft Defender for Endpoint", "mdatp": "Microsoft Defender for Endpoint",
	"csfalconservice": "CrowdStrike Falcon", "falcond": "CrowdStrike Falcon", "falcon-sensor": "CrowdStrike Falcon",
	"com.crowdstrike.falcon.agent": "CrowdStrike Falcon",
	"sentinelagent":                "SentinelOne", "sentinelservicehost": "SentinelOne", "sentinelone": "SentinelOne", "s1-agent": "SentinelOne",
	"sentineld": "SentinelOne",
	"cbdefense": "VMware Carbon Black", "repmgr": "VMware Carbon Black", "cbagentd": "VMware Carbon Black", "cbdaemon": "VMware Carbon Black",
	"savservice": "Sophos", "sophosfilescanner": "Sophos", "sophosav": "Sophos", "sophos endpoint defense": "Sophos",
	"sophosntpservice": "Sophos", "sophosscand": "Sophos", "sophoshealthd": "Sophos",
	"ekrn": "ESET", "esets_daemon": "ESET", "esets": "ESET", "oaeventd": "ESET",
	"ccsvchst": "Symantec Endpoint Protection", "rtvscan": "Symantec Endpoint Protection", "sepservice": "Symantec Endpoint Protection",
	"mcshield": "Trellix (McAfee)", "masvc": "Trellix (McAfee)", "macmnsvc": "Trellix (McAfee)", "mfetp": "Trellix (McAfee)",
	"ntrtscan": "Trend Micro", "ds_agent": "Trend Micro Deep Security", "coreserviceshell": "Trend Micro",
	"avp": "Kaspersky", "kesl": "Kaspersky", "klnagent": "Kaspersky",
	"bdagent": "Bitdefender", "bdservicehost": "Bitdefender", "bdsec": "Bitdefender", "epsecurityservice": "Bitdefender",
	"clamd": "ClamAV", "freshclam": "ClamAV",
	"wazuh-agentd": "Wazuh", "ossec-agentd": "Wazuh",
	"elastic-endpoint": "Elastic Defend", "elastic-agent": "Elastic Agent",
	"cylancesvc": "Cylance", "avastsvc": "Avast", "avgsvc": "AVG", "mbamservice": "Malwarebytes",
	"cyserver": "Palo Alto Cortex XDR", "traps_pmd": "Palo Alto Cortex XDR", "cortex-xdr-payload": "Palo Alto Cortex XDR",
	"fortiedr": "FortiEDR", "fortiesnac": "FortiClient", "fctdaemon": "FortiClient",
	"huntressagent": "Huntress", "xagt": "Trellix HX (FireEye)", "qualys-cloud-agent": "Qualys Cloud Agent",
	"qualysagent": "Qualys Cloud Agent", "tenable_nessus_agent": "Tenable Nessus Agent", "nessusagent": "Tenable Nessus Agent",
	"nessus-agent": "Tenable Nessus Agent", "rapid7_agent_core": "Rapid7 Insight Agent", "ir_agent": "Rapid7 Insight Agent",
}

// DetectAgents names the security products among running processes.
func DetectAgents(processes []string) []string {
	found := map[string]bool{}
	for _, p := range processes {
		name := strings.ToLower(strings.TrimSpace(filepath.Base(p)))
		name = strings.TrimSuffix(name, ".exe")
		if product, ok := securityProducts[name]; ok {
			found[product] = true
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Server software recognized by its service or process name. Names are
// product names, so they read the same in every language.
var serverSoftware = []struct {
	pattern *regexp.Regexp
	role    string
}{
	{regexp.MustCompile(`(?i)^nginx$`), "nginx"},
	{regexp.MustCompile(`(?i)^(apache2|httpd)$`), "Apache HTTP Server"},
	{regexp.MustCompile(`(?i)^w3svc$`), "IIS"},
	{regexp.MustCompile(`(?i)^caddy$`), "Caddy"},
	{regexp.MustCompile(`(?i)^traefik$`), "Traefik"},
	{regexp.MustCompile(`(?i)^haproxy$`), "HAProxy"},
	{regexp.MustCompile(`(?i)^squid$`), "Squid proxy"},
	{regexp.MustCompile(`(?i)^(mysql|mysqld)$`), "MySQL"},
	{regexp.MustCompile(`(?i)^(mariadb|mariadbd)$`), "MariaDB"},
	{regexp.MustCompile(`(?i)^(postgresql|postgres|postgresql-x64-\d+|postgresql@.*)$`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)^(mssqlserver|mssql\$.*|sqlservr)$`), "SQL Server"},
	{regexp.MustCompile(`(?i)^(oracleservice.*|ora_pmon_.*)$`), "Oracle Database"},
	{regexp.MustCompile(`(?i)^(mongod|mongodb)$`), "MongoDB"},
	{regexp.MustCompile(`(?i)^(redis|redis-server)$`), "Redis"},
	{regexp.MustCompile(`(?i)^elasticsearch$`), "Elasticsearch"},
	{regexp.MustCompile(`(?i)^opensearch$`), "OpenSearch"},
	{regexp.MustCompile(`(?i)^(rabbitmq-server|rabbitmq)$`), "RabbitMQ"},
	{regexp.MustCompile(`(?i)^(docker|dockerd|com.docker.service)$`), "Docker"},
	{regexp.MustCompile(`(?i)^(containerd)$`), "containerd"},
	{regexp.MustCompile(`(?i)^(kubelet|k3s|rke2-server|rke2-agent)$`), "Kubernetes"},
	{regexp.MustCompile(`(?i)^(vmms)$`), "Hyper-V"},
	{regexp.MustCompile(`(?i)^(libvirtd|virtqemud)$`), "KVM (libvirt)"},
	{regexp.MustCompile(`(?i)^(pve-cluster|pvedaemon)$`), "Proxmox VE"},
	{regexp.MustCompile(`(?i)^(ntds)$`), "Active Directory Domain Services"},
	{regexp.MustCompile(`(?i)^(samba-ad-dc)$`), "Samba AD DC"},
	{regexp.MustCompile(`(?i)^(smbd|smb)$`), "Samba file server"},
	{regexp.MustCompile(`(?i)^(nfs-server|nfsd|nfs-kernel-server)$`), "NFS server"},
	{regexp.MustCompile(`(?i)^(named|bind9|dns|unbound|dnsmasq)$`), "DNS server"},
	{regexp.MustCompile(`(?i)^(dhcpserver|isc-dhcp-server|dhcpd|kea-dhcp4|kea-dhcp4-server)$`), "DHCP server"},
	{regexp.MustCompile(`(?i)^(slapd)$`), "OpenLDAP"},
	{regexp.MustCompile(`(?i)^(postfix|exim4|exim|sendmail)$`), "Mail server (SMTP)"},
	{regexp.MustCompile(`(?i)^(msexchangeis|msexchangetransport)$`), "Microsoft Exchange"},
	{regexp.MustCompile(`(?i)^(dovecot)$`), "Dovecot (IMAP)"},
	{regexp.MustCompile(`(?i)^(openvpn|openvpn-server@.*|openvpnserver|wg-quick@.*)$`), "VPN server"},
	{regexp.MustCompile(`(?i)^(zabbix-server|zabbix_server)$`), "Zabbix server"},
	{regexp.MustCompile(`(?i)^(jenkins)$`), "Jenkins"},
	{regexp.MustCompile(`(?i)^(tomcat\d*)$`), "Apache Tomcat"},
	{regexp.MustCompile(`(?i)^(php\d*(\.\d+)?-fpm|php-fpm)$`), "PHP-FPM"},
	{regexp.MustCompile(`(?i)^(gitlab-runsvdir|gitlab-runner)$`), "GitLab"},
	{regexp.MustCompile(`(?i)^(veeambackupsvc|veeamtransportsvc)$`), "Veeam Backup"},
}

// DetectServerSoftware names the server products among running services
// (by service name) and processes.
func DetectServerSoftware(services []Service, processes []string) []string {
	names := make([]string, 0, len(services)+len(processes))
	for _, s := range services {
		if s.State == "running" {
			names = append(names, strings.TrimSuffix(s.Name, ".service"))
		}
	}
	for _, p := range processes {
		names = append(names, strings.TrimSuffix(strings.ToLower(filepath.Base(p)), ".exe"))
	}
	found := map[string]bool{}
	for _, n := range names {
		for _, s := range serverSoftware {
			if s.pattern.MatchString(n) {
				found[s.role] = true
				break
			}
		}
	}
	out := make([]string, 0, len(found))
	for r := range found {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// unixTimezone reads the IANA zone from /etc/localtime's symlink target
// (Linux and macOS), falling back to Go's zone abbreviation.
func unixTimezone() string {
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
	}
	if tz, ok := sysinfo.ReadFirst("/etc/timezone"); ok {
		return tz
	}
	name, _ := time.Now().Zone()
	return name
}

// runtimeArch is the Go architecture in the names people use.
func runtimeArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "x86"
	}
	return runtime.GOARCH
}

func unixTime(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// dateOnly keeps the YYYY-MM-DD part of an RFC 3339 timestamp.
func dateOnly(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	return ts[:10]
}
