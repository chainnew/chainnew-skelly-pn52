#!/usr/bin/env bash
set -euo pipefail
DEV="${1:-}"
if [ -z "$DEV" ]; then echo "usage: ALLOW_DESTRUCTIVE=YES $0 /dev/XYZ" >&2; exit 2; fi
if [ "${ALLOW_DESTRUCTIVE:-NO}" != "YES" ]; then
  echo "Refusing destructive LUKS format. Set ALLOW_DESTRUCTIVE=YES explicitly." >&2
  exit 3
fi
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id "$DEV"
cryptsetup open "$DEV" cryptroot
