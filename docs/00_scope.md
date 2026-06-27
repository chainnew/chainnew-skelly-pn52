# Scope

Target: ASUS ExpertCenter PN52 / AMD Ryzen 5000H Cezanne mini-PC as a Rust Type-1 hypervisor lab.

Out of scope for the skeleton:

- replacing ASUS BIOS/UEFI;
- writing SPI flash;
- modifying AMD PSP, AGESA, SMU, EC, SMM, or vendor DXE modules;
- production guest isolation claims;
- FIPS validation claims;
- PQC-in-firmware claims.

In scope:

- Rust UEFI app;
- no_std handoff;
- AMD SVM first guest launch;
- AMD-Vi/IOMMU discovery;
- encrypted-storage control-plane design;
- LUKS2/TPM2/FIDO2/measured-boot integration for management/root OS;
- hybrid classical + ML-KEM metadata model for future remote unlock.
