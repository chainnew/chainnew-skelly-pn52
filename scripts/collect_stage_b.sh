#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-pn52-research}"
mkdir -p "$OUT"/{firmware,acpi,pci,usb,dmi,logs,nvme,network,secureboot,iommu,cpuid}

echo "[+] Collecting DMI/SMBIOS"
sudo dmidecode > "$OUT/dmi/dmidecode.txt" || true
for t in 0 1 2 4 9 17; do sudo dmidecode -t "$t" > "$OUT/dmi/dmidecode-t${t}.txt" || true; done
lscpu > "$OUT/dmi/lscpu.txt" || true
cat /proc/cpuinfo > "$OUT/dmi/cpuinfo.txt" || true
cat /proc/meminfo > "$OUT/dmi/meminfo.txt" || true

echo "[+] Collecting PCI/USB"
sudo lspci -nnvvv > "$OUT/pci/lspci-nnvvv.txt" || true
sudo lspci -xxxx > "$OUT/pci/lspci-config-space.txt" || true
sudo lspci -t > "$OUT/pci/lspci-tree.txt" || true
lsusb -tv > "$OUT/usb/lsusb-tree.txt" || true
sudo lsusb -v > "$OUT/usb/lsusb-v.txt" || true

echo "[+] Collecting ACPI"
sudo acpidump -o "$OUT/acpi/acpi.dat" || true
for sig in RSDP XSDT FACP APIC MCFG HPET IVRS SSDT DSDT TPM2 BGRT FPDT; do
  sudo acpidump -n "$sig" -b > "$OUT/acpi/$(echo "$sig" | tr A-Z a-z).aml" 2>/dev/null || true
done

echo "[+] Collecting logs and firmware state"
sudo dmesg -T > "$OUT/logs/dmesg.txt" || true
sudo journalctl -b > "$OUT/logs/journalctl-b.txt" || true
sudo efibootmgr -v > "$OUT/firmware/efibootmgr-v.txt" || true
sudo efivar -L > "$OUT/firmware/efivar-list.txt" || true
mokutil --sb-state > "$OUT/secureboot/secureboot.txt" || true
sudo mokutil --list-enrolled > "$OUT/secureboot/enrolled-keys.txt" || true
sudo mokutil --list-revoked > "$OUT/secureboot/revoked-keys.txt" || true

echo "[+] Collecting NVMe/network/IOMMU/cpuid"
sudo nvme list > "$OUT/nvme/nvme-list.txt" || true
for dev in /dev/nvme[0-9]; do [ -e "$dev" ] && sudo nvme id-ctrl "$dev" > "$OUT/nvme/$(basename "$dev")-id-ctrl.txt" || true; done
ip link > "$OUT/network/ip-link.txt" || true
ip addr > "$OUT/network/ip-addr.txt" || true
for i in /sys/class/net/*; do iface=$(basename "$i"); [ "$iface" = lo ] && continue; sudo ethtool -i "$iface" >> "$OUT/network/ethtool-i.txt" 2>/dev/null || true; done
for g in /sys/kernel/iommu_groups/*/devices/*; do group=$(basename "$(dirname "$g")"); bdf=$(basename "$g"); echo "$group $bdf $(lspci -nn -s "$bdf")"; done | sort -V > "$OUT/iommu/iommu-groups.txt" 2>/dev/null || true
for leaf in 0 1 7 0x80000001 0x80000007 0x80000008 0x8000000A; do cpuid -r -l "$leaf",0 > "$OUT/cpuid/cpuid-${leaf}.txt" 2>/dev/null || true; done

tar czf "${OUT}-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" "$OUT"
sha256sum "${OUT}-"*.tar.gz
