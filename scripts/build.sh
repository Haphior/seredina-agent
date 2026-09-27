#!/usr/bin/env bash
# Builds the release archives into dist/: one per OS/architecture, plus
# SHA256SUMS. Usage: scripts/build.sh [version]   (default: git describe)
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf dist && mkdir -p dist
for target in $targets; do
  os="${target%/*}" arch="${target#*/}"
  name="seredina-agent_${os}_${arch}"
  exe="seredina-agent"; [ "$os" = windows ] && exe="seredina-agent.exe"
  work="dist/$name" && mkdir -p "$work"
  echo "building $name ($version)"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$work/$exe" .
  cp LICENSE README.md "$work/"
  # Code signing hook: when signing is set up, sign "$work/$exe" here
  # (signtool for Windows, codesign + notarytool for macOS) before archiving.
  if [ "$os" = windows ]; then
    (cd "$work" && zip -qX "../$name.zip" "$exe" LICENSE README.md)
  else
    tar -C "$work" -czf "dist/$name.tar.gz" --owner=0 --group=0 "$exe" LICENSE README.md
  fi
  rm -rf "$work"
done
(cd dist && sha256sum seredina-agent_* > SHA256SUMS)
# `seredina-agent update` reads this to tell whether it's already current.
echo "$version" > dist/VERSION
cat dist/SHA256SUMS
