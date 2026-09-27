<#
.SYNOPSIS
Installs the Seredina agent on Windows: downloads the release for this
architecture, checks its SHA-256, enrolls the computer and starts the service.

.EXAMPLE
To update an enrolled computer (no token needed; it keeps its enrollment and check-in interval):

& ([scriptblock]::Create((irm https://github.com/Haphior/seredina-agent/releases/latest/download/install.ps1))) -Update

.EXAMPLE
Run in PowerShell as administrator:

& ([scriptblock]::Create((irm https://github.com/Haphior/seredina-agent/releases/latest/download/install.ps1))) -Url https://helpdesk.example.com/api -Token <token>
#>
param(
    [string]$Url = "",
    [string]$Token = "",
    [switch]$Update,
    [string]$CaPem = "",
    [string]$Version = "latest",
    [string]$Interval = "",
    # Fetch the archives from a mirror instead of GitHub.
    [string]$DownloadBase = ""
)

$ErrorActionPreference = "Stop"
if (-not $Update -and (-not $Url -or -not $Token)) {
    throw "Usage: install.ps1 -Url <server> -Token <token> [-CaPem <base64>], or install.ps1 -Update"
}
$ProgressPreference = "SilentlyContinue"  # Invoke-WebRequest is much faster without it
$repo = "Haphior/seredina-agent"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as administrator."
}

# Windows PowerShell 5.1 may default to TLS 1.0.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported architecture $($env:PROCESSOR_ARCHITECTURE)." }
}
# A 32-bit PowerShell on 64-bit Windows reports x86; the real one is here.
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") { $arch = "amd64" }
if ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { $arch = "arm64" }

if (-not $DownloadBase) {
    $DownloadBase = if ($Version -eq "latest") {
        "https://github.com/$repo/releases/latest/download"
    } else {
        "https://github.com/$repo/releases/download/$Version"
    }
}

$archive = "seredina-agent_windows_$arch.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("seredina-agent-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $archive ($Version)..."
    Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/$archive" -OutFile "$tmp\$archive"
    Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"

    $expected = $null
    foreach ($line in Get-Content "$tmp\SHA256SUMS") {
        $parts = $line -split "\s+", 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart("*") -eq $archive) { $expected = $parts[0] }
    }
    if (-not $expected) { throw "$archive is not listed in SHA256SUMS." }
    $actual = (Get-FileHash -Algorithm SHA256 "$tmp\$archive").Hash
    if ($actual -ne $expected) { throw "Checksum mismatch for ${archive}: refusing to install." }

    Expand-Archive -Path "$tmp\$archive" -DestinationPath $tmp -Force
    $exe = "$tmp\seredina-agent.exe"
    Unblock-File $exe

    if ($Update) {
        # Reuses the stored credential; the saved interval is kept unless given.
        $agentArgs = @("install")
    } else {
        $agentArgs = @("enroll", "--url", $Url, "--token", $Token, "--install")
        if ($CaPem) { $agentArgs += @("--ca-pem", $CaPem) }
    }
    if ($Interval) { $agentArgs += @("--interval", $Interval) }
    # enroll --install copies the binary to Program Files and starts the service.
    & $exe @agentArgs
    if ($LASTEXITCODE -ne 0) { throw "The agent exited with code $LASTEXITCODE." }
    Write-Host "Done. Check it with: & '$env:ProgramFiles\Seredina Agent\seredina-agent.exe' status"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
