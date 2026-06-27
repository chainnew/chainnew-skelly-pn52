#!/usr/bin/env bash
set -euo pipefail
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}"
qemu-system-x86_64 \
  -machine q35,accel=kvm:tcg \
  -cpu host,+svm \
  -m 2048 \
  -bios "$OVMF_CODE" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive format=raw,file=fat:rw:esp \
  -serial stdio
