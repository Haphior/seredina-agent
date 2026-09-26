# Seredina agent

The endpoint agent for [Seredina](https://github.com/Haphior/helpdesk-seredina), the open-source helpdesk.
It runs on a computer and reports what's in it to Seredina's CMDB. It
reports hardware, disks, operating system, installed software, disk
encryption, antivirus, and the devices it can see on its local network.

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
| `run [--interval 1h]` | Checks in periodically in the foreground. |
| `version` | Prints the version. |

Every command takes `--config-dir DIR`. The credential is kept in:

| | As administrator/root (the service) | As a normal user |
|---|---|---|
| Windows | `C:\ProgramData\Seredina\Agent\` (SYSTEM and Administrators only) | `%USERPROFILE%\.seredina-agent\` |
| macOS | `/Library/Application Support/Seredina Agent/` | `~/.seredina-agent/` |
| Linux | `/etc/seredina-agent/` (mode 0700) | `~/.seredina-agent/` |

The `SEREDINA_AGENT_CONFIG_DIR` environment variable overrides the default.

To update the agent, run the install command again. A new enrollment
token for the same computer reuses its existing record in Seredina.

## Private certificates

If Seredina is served with a certificate from an internal CA, or from
the self-signed CA that Seredina's setup script creates, the Devices page
adds `--ca-pem <base64>` to the command. The agent then trusts **only**
that CA for this server, and stores it next to the credential. It never
turns off certificate verification. If there's no pin, it uses the
operating system's trusted roots. HTTP proxies are honored through
`HTTPS_PROXY`.

## What is sent

It sends only inventory, never files, documents or browsing data:

- Hostname and platform.
- CPU model, memory, disks (size and free space), and OS version.
- Whether the system disk is encrypted:
  - Windows: BitLocker.
  - macOS: FileVault.
  - Linux: LUKS.
- Antivirus status (Windows: Defender).
- Up to 500 installed packages or applications with their versions.
- The primary MAC address.
- The IP and MAC of up to 512 neighbors in the ARP table.

It also sends a machine fingerprint, which is the SHA-256 of the OS machine ID, so a reinstalled agent finds the same record.

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

El agente de Seredina informa el inventario de un equipo a la CMDB de
Seredina. Informa:

- Hardware, discos y sistema operativo.
- Software instalado.
- Cifrado de disco y antivirus.
- Los equipos vecinos de su red local.

Es un solo ejecutable para Windows, macOS y Linux. Funciona como servicio
y hace check-in cada hora.

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
- `seredina-agent uninstall --purge`: quita el servicio y la credencial.

**Certificados internos:** si tu servidor usa una CA interna, el comando
incluye `--ca-pem`. El agente confía solo en esa CA y nunca desactiva la
verificación TLS.

**Firma de código:** las versiones aún no están firmadas.

- En Windows puede aparecer SmartScreen si abres el `.exe` desde el Explorador.
- En macOS usa el script de instalación, o quita la cuarentena con `xattr -d com.apple.quarantine seredina-agent`.
