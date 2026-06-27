//! hyperctl — the local CLI front-end for the hyper-slate control plane (§11).
//!
//! Every subcommand drives the in-memory, deny-by-default [`hyper_control::Control`].
//! There is no network server and no persistence: each invocation builds a fresh
//! local control plane, runs one command and prints the result. The full
//! define -> verify -> launch -> ... flow is exercised end-to-end in the
//! `hyper-control` library tests.

use std::{fs, process};

use clap::{Parser, Subcommand};

use hyper_control::Control;

#[derive(Parser)]
#[command(name = "hyperctl")]
#[command(about = "Local control plane for the hyper-slate runtime (deny-by-default)")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Slate-runtime maintenance commands.
    #[command(subcommand)]
    Slate(SlateCmd),
    /// VM lifecycle commands.
    #[command(subcommand)]
    Vm(VmCmd),
    /// Policy commands.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Audit receipt commands.
    #[command(subcommand)]
    Receipts(ReceiptsCmd),
}

#[derive(Subcommand)]
enum SlateCmd {
    /// Print a deterministic health report of the control plane.
    Doctor,
}

#[derive(Subcommand)]
enum VmCmd {
    /// Verify + admit a capsule descriptor file (`-> Defined`).
    Define {
        /// Path to a `chain.control.capsule.v1` JSON descriptor.
        file: String,
    },
    /// Run manifest verification + the launch gate (`Defined -> Verified`).
    Verify {
        /// VM id.
        id: String,
    },
    /// Drive a verified VM to `Running` (prepare/unlock/attach/run).
    Launch {
        /// VM id.
        id: String,
    },
    /// Pause a running guest (`Running -> Paused`).
    Pause {
        /// VM id.
        id: String,
    },
    /// Snapshot a paused (or running) guest.
    Snapshot {
        /// VM id.
        id: String,
        /// Name to record the snapshot under.
        #[arg(long)]
        name: String,
    },
    /// Stop a running guest (`Running -> Stopped`).
    Stop {
        /// VM id.
        id: String,
    },
    /// Zeroize + release a stopped guest. Requires explicit confirmation.
    Destroy {
        /// VM id.
        id: String,
        /// Confirm zeroization of guest memory + key material.
        #[arg(long)]
        wipe: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the active policy document + posture as JSON.
    Inspect,
}

#[derive(Subcommand)]
enum ReceiptsCmd {
    /// Verify the shared audit chain (optionally scoped to one VM).
    Verify {
        /// Restrict the report to a single VM id.
        #[arg(long)]
        vm: Option<String>,
    },
}

fn run() -> Result<String, String> {
    let cli = Cli::parse();
    let mut control = Control::new_local();

    match cli.cmd {
        Command::Slate(SlateCmd::Doctor) => Ok(control.slate_doctor()),
        Command::Vm(vm) => match vm {
            VmCmd::Define { file } => {
                let json = fs::read_to_string(&file)
                    .map_err(|e| format!("cannot read {file}: {e}"))?;
                control.vm_define(&json).map_err(|e| e.to_string())
            }
            VmCmd::Verify { id } => control.vm_verify(&id).map_err(|e| e.to_string()),
            VmCmd::Launch { id } => control.vm_launch(&id).map_err(|e| e.to_string()),
            VmCmd::Pause { id } => control.vm_pause(&id).map_err(|e| e.to_string()),
            VmCmd::Snapshot { id, name } => {
                control.vm_snapshot(&id, &name).map_err(|e| e.to_string())
            }
            VmCmd::Stop { id } => control.vm_stop(&id).map_err(|e| e.to_string()),
            VmCmd::Destroy { id, wipe } => {
                control.vm_destroy(&id, wipe).map_err(|e| e.to_string())
            }
        },
        Command::Policy(PolicyCmd::Inspect) => Ok(control.policy_inspect()),
        Command::Receipts(ReceiptsCmd::Verify { vm }) => {
            control.receipts_verify(vm.as_deref()).map_err(|e| e.to_string())
        }
    }
}

fn main() {
    match run() {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("hyperctl: {e}");
            process::exit(1);
        }
    }
}
