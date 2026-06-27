# CI Gate Plan

A GitHub Actions workflow was intentionally not committed by the connector during this session. Keep the CI plan here until a human operator adds the workflow file directly.

## Required gates

```bash
cargo fmt --all -- --check

cargo clippy \
  -p hyper-slate-core \
  -p hyper-pn52 \
  -p hyper-storage \
  -p hyper-pn52-doctor \
  -p hyper-slate-kms-prototype \
  --all-targets -- -D warnings

cargo check -p hyper-x86 --target x86_64-unknown-none
cargo check -p hyper-amd-svm --target x86_64-unknown-none
cargo check -p hyper-uefi-probe --target x86_64-unknown-uefi
```

## Required Rust targets

```bash
rustup target add x86_64-unknown-none
rustup target add x86_64-unknown-uefi
```

## Why split the checks?

The workspace has three different classes of crate:

1. host-side tooling;
2. `no_std` x86 substrate crates;
3. UEFI application crate.

A single naive `cargo test --workspace` is the wrong gate for this repository because the UEFI and bare-metal crates are not normal host binaries.

## Current known gap

`hyper-slate-core` advertises a no-std mode, but `manifest.rs` still uses `String` and `Vec`. The next cleanup should import `alloc::{string::String, vec::Vec}` under `not(feature = "std")`, then add this check:

```bash
cargo check -p hyper-slate-core --no-default-features --target x86_64-unknown-none
```
