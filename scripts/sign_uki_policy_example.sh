#!/usr/bin/env bash
set -euo pipefail
cat <<'EOF'
Example only. Use systemd-measure/ukify on the target distro to sign expected PCR11 values.

systemd-measure calculate --linux=/boot/vmlinuz --initrd=/boot/initrd.img --cmdline=@/etc/kernel/cmdline
systemd-measure sign --linux=/boot/vmlinuz --initrd=/boot/initrd.img --cmdline=@/etc/kernel/cmdline \
  --private-key=pcr11.key --public-key=pcr11.pub
EOF
