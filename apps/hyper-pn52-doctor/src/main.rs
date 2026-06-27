use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "hyper-pn52-doctor")]
#[command(about = "PN52 inventory and safety doctor")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a quick skeleton report from a Stage B directory.
    Report { stage_b_dir: PathBuf },
    /// Refuse firmware writes unless recovery prerequisites are explicit.
    SafetyGate,
}

fn main() -> anyhow_free::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Report { stage_b_dir } => {
            let lscpu = fs::read_to_string(stage_b_dir.join("dmi/lscpu.txt")).unwrap_or_default();
            let cpu = hyper_pn52::inventory::parse_lscpu(&lscpu);
            println!("# PN52 Doctor Report\n");
            println!("CPU: {}", if cpu.sku.is_empty() { "unknown" } else { &cpu.sku });
            println!("Threads: {:?}", cpu.threads);
            println!("Next: parse lspci/acpi/secureboot and emit full JSON.");
        }
        Command::SafetyGate => {
            eprintln!("Firmware write safety gate: DENY by default. Use read-only pipeline only.");
            std::process::exit(10);
        }
    }
    Ok(())
}

mod anyhow_free {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
}
