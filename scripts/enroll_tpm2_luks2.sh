#!/usr/bin/env bash
set -euo pipefail
DEV="${1:-}"
if [ -z "$DEV" ]; then echo "usage: $0 /dev/XYZ" >&2; exit 2; fi
systemd-cryptenroll --recovery-key "$DEV"
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 --tpm2-with-pin=yes "$DEV"
