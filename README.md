# Seredina agent

The endpoint agent for [Seredina](https://github.com/Haphior/helpdesk-seredina), the open-source helpdesk.
It runs on a computer or a server and reports what's in it to Seredina's
CMDB, about as much as GLPI-Agent or Lansweeper collect:

- Hardware down to serial numbers, memory modules and disk models.
- Software with publishers.
- Updates.
- Security: antivirus and EDR, disk encryption, firewall, Secure Boot,
  TPM.
- For servers: services, listening ports, roles, and the VMs and
  containers they host.

It also reports the devices it can see on its local network.

It's one self-contained binary for Windows, macOS and Linux (x86-64 and
ARM64), with no runtime to install. It runs as a Windows service, a
launchd daemon or a systemd unit, and checks in once an hour.

> **Español:** instrucciones de uso [más abajo](#en-español).

## Install

Open **Devices → Enroll a device** in Seredina. The page gives you a
ready-made command with the server address, a one-time token, and the CA
to trust if your server uses a private certificate. Run it on the computer:

**Windows** (PowerShell as administrator):

```powershell
& ([scriptblock]::Create((irm https://github.com/Haphior/seredina-agent/releases/latest/download/install.ps1))) -Url https://helpdesk.example.com/api -Token <token>
```

**macOS / Linux**:

```sh
curl -fsSL https://github.com/Haphior/seredina-agent/releases/latest/download/install.sh | sudo sh -s -- --url https://helpdesk.example.com/api --token <token>
```

The script:

1. Downloads the right archive for this OS and architecture from the latest release.
2. Checks it against `SHA256SUMS`.
3. Enrolls the computer.
4. Installs the service and starts it.

Pass `--version v0.1.0` (`-Version` on Windows) to pin a release.

### Manual install

Download the archive for your platform from [Releases](https://github.com/Haphior/seredina-agent/releases), check its sha256 against `SHA256SUMS`, unpack it, and run, as administrator/root:

```sh
./seredina-agent enroll --url https://helpdesk.example.com/api --token <token> --install
```

`--install` copies the binary to `C:\Program Files\Seredina Agent\` or
`/usr/local/bin/`, registers the service, and starts it.

## Commands

| Command | What it does |
|---|---|
| `enroll --url U --token T [--ca-pem B64 \| --ca FILE] [--install]` | Trades the one-time token for this computer's credential. |
| `install [--interval 1h]` | Installs and starts the background service. Needs admin. |
| `uninstall [--purge]` | Removes the service. `--purge` also deletes the credential and the installed binary. |
| `status` | Shows whether it's enrolled, to which server, and whether the service is running. |
| `checkin` | Sends the inventory once, now. |
| `update [--check] [--version vX.Y.Z] [--download-base URL]` | Updates the installed agent to the latest release (or the one given), keeping its enrollment and check-in interval. `--check` only says whether there's a newer one. Needs admin. |
| `inventory [--out file.json]` | Prints the full inventory as JSON without sending it anywhere. Run it as administrator/root to see everything the service sees. |
| `run [--interval 1h]` | Checks in periodically in the foreground. |
| `version` | Prints the version. |

Every command takes `--config-dir DIR`. The credential is kept in:

| | As administrator/root (the service) | As a normal user |
|---|---|---|
| Windows | `C:\ProgramData\Seredina\Agent\` (SYSTEM and Administrators only) | `%USERPROFILE%\.seredina-agent\` |
| macOS | `/Library/Application Support/Seredina Agent/` | `~/.seredina-agent/` |
| Linux | `/etc/seredina-agent/` (mode 0700) | `~/.seredina-agent/` |

The `SEREDINA_AGENT_CONFIG_DIR` environment variable overrides the default.

## Updating

The agent doesn't update itself. You choose when, and no enrollment token
is needed: the computer keeps its enrollment, its pinned CA and its
check-in interval.

On one computer, as administrator/root:

```sh
seredina-agent update --check    # is there a newer release?
seredina-agent update            # install it
```

On Windows the agent lives in `C:\Program Files\Seredina Agent\seredina-agent.exe`.

`update` does the following:

1. Reads the release's `VERSION`, and stops if the agent is already on it.
2. Downloads the archive for this OS and architecture.
3. Checks it against `SHA256SUMS`.
4. Has the new binary reinstall the service.

A failed download or checksum leaves the installed agent untouched.

For computers with a broken or very old agent, the install scripts do the
same with `--update` (`-Update` on Windows):

```sh
curl -fsSL https://github.com/Haphior/seredina-agent/releases/latest/download/install.sh | sudo sh -s -- --update
```

```powershell
& ([scriptblock]::Create((irm https://github.com/Haphior/seredina-agent/releases/latest/download/install.ps1))) -Update
```

### Many computers at once

Run the update from the tool you already manage computers with, as
SYSTEM or root:

- **Intune:** a platform script.
- **GPO:** a startup script.
- **Jamf:** a policy.
- **Ansible:** a task.

For example, on Windows:

```powershell
& "$env:ProgramFiles\Seredina Agent\seredina-agent.exe" update
```

It's safe to run on a schedule: it does nothing when the agent is
already current. Updating on your own schedule is deliberate. Because the
releases aren't code-signed yet, you choose when a new version runs on
your fleet.

To pin a version, pass `--version v0.3.0`. If your computers can't
reach GitHub:

1. Copy a release's files (including `VERSION`) to an internal web server
   or a network share.
2. Pass `--download-base` with the web address
   (`https://files.example.com/seredina-agent`) or the folder
   (`\\fileserver\it\seredina-agent`, `/mnt/it/seredina-agent`).

A web mirror behind the same internal CA as your Seredina server is
trusted automatically. Wherever the files come from, the archive must
match `SHA256SUMS` before anything runs.

Agent and server versions don't have to match. A newer agent works with
an older Seredina, which ignores the fields it doesn't know, and an
older agent works with a newer Seredina.

## Private certificates

If Seredina is served with a certificate from an internal CA, or from
the self-signed CA that Seredina's setup script creates, the Devices page
adds `--ca-pem <base64>` to the command. The agent then trusts **only**
that CA for this server, and stores it next to the credential. It never
turns off certificate verification. If there's no pin, it uses the
operating system's trusted roots. HTTP proxies are honored through
`HTTPS_PROXY`.

## What is sent

It sends only inventory, never files, documents, browsing data or
passwords. Run `seredina-agent inventory` to see exactly what it would
send.

| Part | Windows | macOS | Linux |
|---|---|---|---|
| System: manufacturer, model, serial, UUID, BIOS, form factor, virtualization, domain | CIM (Win32_ComputerSystem, BIOS, enclosure) | system_profiler | /sys/class/dmi, systemd-detect-virt, realm |
| OS: version, build, install date, last boot, pending reboot | CIM, registry | sw_vers, sysctl | os-release, /proc/stat, needs-restarting |
| CPU sockets/cores/threads, memory modules (slot, size, type, speed, serial, part number) | Win32_Processor, Win32_PhysicalMemory | system_profiler, sysctl | lscpu, dmidecode |
| Physical disks (SSD/HDD/NVMe, bus, serial, health) and volumes (filesystem, free space, encryption) | Get-PhysicalDisk, BitLocker | system_profiler, FileVault | lsblk, df, LUKS |
| Network adapters: MAC, IPs, gateway, DNS, DHCP, speed | Win32_NetworkAdapterConfiguration | Go, networksetup, scutil | Go, /sys/class/net, /proc/net/route |
| GPUs, monitors (with serial), batteries (health, cycles), printers | CIM, WmiMonitorID | system_profiler | lspci, EDID, /sys/class/power_supply, CUPS |
| Users: logged on, last logon, local administrators, local accounts | CIM, LogonUI | who, dscl | who, last, /etc/group |
| Security: antivirus and its state, EDR/security agents running, firewall, Secure Boot, TPM, UAC/SELinux/AppArmor/Gatekeeper/SIP | SecurityCenter2, Defender, NetFirewall | XProtect, socketfilterfw, spctl, csrutil | ufw/firewalld/nftables, getenforce, efivars |
| Software with version, publisher, install date, architecture | Uninstall registry keys (machine and per-user) | Applications, with signer as publisher | dpkg, rpm, pacman, apk, snap, flatpak |
| Updates: installed and pending | Get-HotFix | softwareupdate --history | apt, dnf/yum (local cache only) |
| Services, listening ports with process | Win32_Service, Get-NetTCPConnection | launchctl, lsof | systemctl, ss |
| Server roles and hosted guests | Get-WindowsFeature, Hyper-V | Docker | recognized services, libvirt, Proxmox, Docker, Podman |

It also sends:

- The primary MAC address, and the IP and MAC of up to 512 neighbors in
  the ARP table.
- A machine fingerprint (the SHA-256 of the OS machine ID), so a
  reinstalled agent finds the same record.

Every list is capped (2,000 programs, 1,000 services, 500 ports...), and
every text field is trimmed. The agent never refreshes package
repositories or downloads updates: pending updates come from the package
manager's local cache.

The summary fields Seredina's older servers read (CPU model, memory,
disks, OS version, encryption, antivirus, packages) are still sent,
derived from the same data.

### Servers

The agent is the same on servers: Windows Server 2012 or later, and any
Linux with systemd. Seredina files a machine as a server when the agent
reports its role as one:

- **Windows:** the Server editions.
- **Linux:** a machine without a graphical session.

## Build from source

Go 1.24 or later:

```sh
go test ./...
go build -o seredina-agent .
scripts/build.sh v0.1.0   # all six release archives + SHA256SUMS in dist/
```

## Moving from the Node.js agent

This agent replaces `apps/agent` from the Seredina repository. The credential
format, its location for a normal user (`~/.seredina-agent`), and the
machine fingerprint are the same. An already-enrolled computer keeps
its record: install this agent and run `seredina-agent install` as admin.
Or re-enroll with a new token, and its record is reused.

## Code signing

Releases are not code-signed yet:

- **Windows:** SmartScreen may warn when you open the binary from Explorer. The install script isn't affected.
- **macOS:** Gatekeeper blocks a binary downloaded through a browser. Remove the quarantine attribute with `xattr -d com.apple.quarantine seredina-agent`, or use the install script, whose `curl` download doesn't add it.

Signing hooks are marked in `scripts/build.sh` and in `.github/workflows/release.yml`.

## License

[AGPL-3.0](LICENSE), same as Seredina.

---

## En español

El agente de Seredina informa el inventario de un equipo o un servidor a
la CMDB de Seredina, con un nivel de detalle similar al de GLPI-Agent o
Lansweeper:

- Hardware hasta el número de serie, los módulos de memoria y el modelo
  de cada disco.
- Software con su fabricante.
- Actualizaciones.
- Seguridad: antivirus y EDR, cifrado, firewall, Secure Boot, TPM.
- En servidores: servicios, puertos en escucha, roles, y las VMs y
  contenedores que aloja.

También informa los equipos vecinos de su red local.

Es un solo ejecutable para Windows, macOS y Linux, y funciona igual en
servidores (Windows Server 2012 o posterior, y Linux con systemd). Corre
como servicio y hace check-in cada hora.

**Instalación:** en Seredina, ve a **Dispositivos → Inscribir un
dispositivo** y copia el comando para tu sistema:

- **Windows:** PowerShell como administrador.
- **macOS/Linux:** con `sudo`.

El script:

1. Descarga la versión correcta.
2. Verifica el SHA-256.
3. Inscribe el equipo.
4. Deja el servicio corriendo.

**Comandos útiles:**

- `seredina-agent status`: si está inscrito y si el servicio corre.
- `seredina-agent checkin`: envía el inventario ahora.
- `seredina-agent update`: actualiza el agente a la última versión, sin
  token, conservando la inscripción y el intervalo. `--check` solo avisa
  si hay una versión nueva. Para muchos equipos, ejecútalo desde Intune,
  GPO, Jamf o Ansible; no hace nada si ya está al día.
- `seredina-agent inventory`: muestra el inventario completo en JSON, sin
  enviarlo. Ejecútalo como administrador para ver todo lo que ve el
  servicio.
- `seredina-agent uninstall --purge`: quita el servicio y la credencial.

**Certificados internos:** si tu servidor usa una CA interna, el comando
incluye `--ca-pem`. El agente confía solo en esa CA y nunca desactiva la
verificación TLS.

**Firma de código:** las versiones aún no están firmadas.

- En Windows puede aparecer SmartScreen si abres el `.exe` desde el Explorador.
- En macOS usa el script de instalación, o quita la cuarentena con `xattr -d com.apple.quarantine seredina-agent`.
