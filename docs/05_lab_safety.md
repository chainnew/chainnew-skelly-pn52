# Lab Safety

No SPI writes. No PSP modification. No AGESA modification. No EC firmware modification. No SMM handler work.

Firmware workflow:

```text
A. Archive official BIOS/drivers/manuals.
B. Boot Linux live USB and collect dmidecode/lspci/lsusb/acpidump/cpuid/iommu groups.
C. Read-only SPI dump twice; SHA-256 must match.
D. External recovery: programmer, correct voltage, SOIC clip, spare chip, known-good dump.
E. Only after D is tested may any firmware-write experiment be discussed.
```

This skeleton defaults to read-only tooling and refuses destructive scripts unless explicit environment variables are set.
