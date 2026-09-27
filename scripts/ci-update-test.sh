#!/usr/bin/env bash
# End-to-end test of `seredina-agent update` on a CI runner (Linux, macOS or
# Windows under Git Bash), as administrator/root: an "old" agent updates
# itself from a local fake release, the new binary installs and starts the
# real service (systemd, launchd or a Windows service), and a second update
# finds nothing to do. Then everything is removed.
set -euo pipefail
cd "$(dirname "$0")/.."

goos="$(go env GOOS)" goarch="$(go env GOARCH)"
exe="" sudo="sudo" installed="/usr/local/bin/seredina-agent"
if [ "$goos" = windows ]; then
  exe=".exe" sudo=""
  installed="$(cygpath -u "$PROGRAMFILES")/Seredina Agent/seredina-agent.exe"
fi
py="$(command -v python3 || command -v python)"
work="$(mktemp -d)"
rel="$work/rel" cfg="$work/cfg"
mkdir -p "$rel" "$cfg"
cfg_native="$cfg"
[ "$goos" = windows ] && cfg_native="$(cygpath -w "$cfg")"

go build -ldflags "-X main.version=v0.0.1-ci" -o "$work/old$exe" .
go build -ldflags "-X main.version=v0.0.2-ci" -o "$work/seredina-agent$exe" .

# The release folder: this platform's archive, SHA256SUMS and VERSION.
"$py" - "$work" "$goos" "$goarch" "$exe" <<'EOF'
import hashlib, os, sys, tarfile, zipfile
work, goos, goarch, exe = sys.argv[1:]
binary = os.path.join(work, "seredina-agent" + exe)
rel = os.path.join(work, "rel")
if goos == "windows":
    name = f"seredina-agent_{goos}_{goarch}.zip"
    with zipfile.ZipFile(os.path.join(rel, name), "w") as z:
        z.write(binary, "seredina-agent.exe")
else:
    name = f"seredina-agent_{goos}_{goarch}.tar.gz"
    with tarfile.open(os.path.join(rel, name), "w:gz") as t:
        t.add(binary, "seredina-agent")
digest = hashlib.sha256(open(os.path.join(rel, name), "rb").read()).hexdigest()
open(os.path.join(rel, "SHA256SUMS"), "w").write(f"{digest}  {name}\n")
open(os.path.join(rel, "VERSION"), "w").write("v0.0.2-ci\n")
EOF

# An enrolled agent: the server is unreachable, which the service survives.
printf '{"url":"https://127.0.0.1:9/api","credential":"ci"}' > "$cfg/credentials.json"

cleanup() {
  $sudo "$installed" uninstall --purge --config-dir "$cfg_native" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The release is read from a folder, as from a network share. (Downloads
# over HTTPS are covered by the Go tests.)
base="$rel"
[ "$goos" = windows ] && base="$(cygpath -w "$rel")"
check="$($sudo "$work/old$exe" update --check --config-dir "$cfg_native" --download-base "$base")"
echo "$check"
grep -q "Available: v0.0.2-ci" <<<"$check"

# The old version runs as a service with a custom interval, as in the field.
$sudo "$work/old$exe" install --config-dir "$cfg_native" --interval 30m
$sudo "$work/old$exe" update --config-dir "$cfg_native" --download-base "$base"

version="$("$installed" version)"
echo "installed: $version"
[ "$version" = v0.0.2-ci ]

sleep 3
status="$($sudo "$installed" status --config-dir "$cfg_native")"
echo "$status"
grep -q "Service:   running" <<<"$status"
$sudo cat "$cfg/service.json" | grep -q '"interval":"30m0s"' || { echo "the custom interval was lost"; exit 1; }

again="$($sudo "$installed" update --config-dir "$cfg_native" --download-base "$base")"
echo "$again"
grep -q "Already up to date (v0.0.2-ci)" <<<"$again"
echo "update test passed on $goos/$goarch"
