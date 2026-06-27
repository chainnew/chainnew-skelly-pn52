# Test Plan

## Unit tests

- parse dmidecode fixture;
- parse lspci fixture;
- parse lsusb fixture;
- parse acpidump inventory;
- parse IVRS fixture;
- validate manifest schema examples;
- reject firmware write without recovery readiness;
- verify VMCB layout offsets.

## Integration tests

- UEFI app prints on QEMU OVMF;
- UEFI app prints on PN52 GOP;
- no_std handoff logs after `ExitBootServices()`;
- PCI walker matches Linux `lspci -t`;
- SVM detection sets EFER.SVME;
- first VMRUN exits cleanly;
- NVMe read-only first 4 KiB hash matches Linux `dd`.
