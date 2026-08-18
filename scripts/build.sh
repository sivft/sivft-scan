#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-v0.1.0}"
OUT="${OUT:-dist}"
mkdir -p "$OUT"

build() {
  local os="$1" arch="$2"
  local name="sivft-scan-${os}-${arch}"
  echo "building ${name}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/$name" .
}

build darwin arm64
build darwin amd64
build linux amd64
build linux arm64

echo ""
echo "done:"
ls -lh "$OUT"