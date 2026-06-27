#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-pn52-research/firmware}"
mkdir -p "$OUT"

if printf '%s\n' "$*" | grep -Eq '(^|[[:space:]])-w([[:space:]]|$)|--write'; then
  echo "Refusing: this script is read-only and never accepts flashrom -w." >&2
  exit 2
fi

echo "[+] Identifying flash chip"
sudo flashrom -p internal --flash-name | tee "$OUT/flash-name.txt" || true
sudo flashrom -p internal --flash-size | tee "$OUT/flash-size.txt" || true

echo "[+] Read #1"
sudo flashrom -p internal -r "$OUT/pn52-spi-1.bin"
sync

echo "[+] Read #2"
sudo flashrom -p internal -r "$OUT/pn52-spi-2.bin"
sync

sha256sum "$OUT"/pn52-spi-*.bin | tee "$OUT/pn52-spi-reads.sha256"
cmp "$OUT/pn52-spi-1.bin" "$OUT/pn52-spi-2.bin"
cp "$OUT/pn52-spi-1.bin" "$OUT/pn52-spi-verified-$(date -u +%Y%m%dT%H%M%SZ).bin"
sha256sum "$OUT"/pn52-spi-verified-*.bin > "$OUT/pn52-spi-verified.sha256"
echo "[+] Verified read-only SPI dump complete. No writes performed."
