#!/bin/sh
# Installs the Seredina agent on Linux or macOS: downloads the release for
# this OS/architecture, checks its SHA-256, enrolls the computer and starts
# the service. Run as root:
#
#   curl -fsSL https://github.com/Haphior/seredina-agent/releases/latest/download/install.sh \
#     | sudo sh -s -- --url https://helpdesk.example.com/api --token <token> [--ca-pem <base64>]
#
# To update an enrolled computer (no token needed; it keeps its enrollment
# and check-in interval):
#
#   curl -fsSL https://github.com/Haphior/seredina-agent/releases/latest/download/install.sh | sudo sh -s -- --update
#
# Options: --version vX.Y.Z pins a release (default: latest);
#          --interval 1h sets the check-in interval;
#          --download-base URL fetches the archives from a mirror instead of GitHub.
set -eu

repo="Haphior/seredina-agent"
url="" token="" ca_pem="" version="latest" interval="" base="" update=""

die() { echo "seredina-agent install: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="${2:-}"; shift 2 ;;
    --token) token="${2:-}"; shift 2 ;;
    --ca-pem) ca_pem="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --interval) interval="${2:-}"; shift 2 ;;
    --download-base) base="${2:-}"; shift 2 ;;
    --update) update=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$update" ] || { [ -n "$url" ] && [ -n "$token" ]; } || die "usage: install.sh --url <server> --token <token> [--ca-pem <base64>], or install.sh --update"
[ "$(id -u)" = 0 ] || die "run it as root (sudo)"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); use install.ps1 on Windows" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$base" ]; then
  if [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
  else
    base="https://github.com/$repo/releases/download/$version"
  fi
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "needs curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
archive="seredina-agent_${os}_${arch}.tar.gz"

echo "Downloading $archive ($version)..."
fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

expected="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || die "$archive is not listed in SHA256SUMS"
[ "$(sha256 "$tmp/$archive")" = "$expected" ] || die "checksum mismatch for $archive: refusing to install"

tar -xzf "$tmp/$archive" -C "$tmp" seredina-agent
chmod 755 "$tmp/seredina-agent"

if [ -n "$update" ]; then
  # Reuses the stored credential; the saved interval is kept unless given.
  set -- install
else
  set -- enroll --url "$url" --token "$token" --install
  [ -n "$ca_pem" ] && set -- "$@" --ca-pem "$ca_pem"
fi
[ -n "$interval" ] && set -- "$@" --interval "$interval"
# Both copy the binary to /usr/local/bin and (re)start the service.
"$tmp/seredina-agent" "$@"

echo "Done. Check it with: seredina-agent status"
