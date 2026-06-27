#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-target}"
OUT="${2:-hashes}"
mkdir -p "$OUT"
find "$SRC" -type f -maxdepth 5 -print0 | sort -z | xargs -0 sha256sum > "$OUT/artifacts.sha256"
