#![no_main]
#![no_std]

use uefi::prelude::*;

#[entry]
fn main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
    let _ = uefi_services::init(&mut st);
    log::info!("chain.new hyper-slate UEFI probe starting");

    let caps = hyper_x86::cpu::detect_cpu_caps();
    log::info!("cpu caps: svm={} invariant_tsc={} x2apic={}", caps.svm, caps.invariant_tsc, caps.x2apic);

    // TODO: print memory map, ACPI RSDP pointer, SMBIOS pointer, GOP mode.
    Status::SUCCESS
}
