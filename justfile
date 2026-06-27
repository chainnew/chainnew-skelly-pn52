set shell := ["bash", "-euo", "pipefail", "-c"]

fmt:
    cargo fmt --all

check-host:
    cargo check -p hyper-pn52-doctor

check-uefi:
    cargo check -p hyper-uefi-probe --target x86_64-unknown-uefi

check-nostd:
    cargo check -p hyper-x86 --target x86_64-unknown-none
    cargo check -p hyper-amd-svm --target x86_64-unknown-none

test-host:
    cargo test -p hyper-pn52
    cargo test -p hyper-storage

hash:
    scripts/hash_artifacts.sh target hashes
