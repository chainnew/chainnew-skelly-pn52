#!/usr/bin/env bash
set -euo pipefail
cargo build -p hyper-uefi-probe --target x86_64-unknown-uefi
mkdir -p esp/EFI/BOOT
cp target/x86_64-unknown-uefi/debug/hyper-uefi-probe.efi esp/EFI/BOOT/BOOTX64.EFI
echo "UEFI app staged at esp/EFI/BOOT/BOOTX64.EFI"
