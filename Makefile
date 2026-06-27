.PHONY: fmt check test uefi doctor
fmt:
	cargo fmt --all
check:
	cargo check --workspace --exclude hyper-uefi-probe
uefi:
	cargo build -p hyper-uefi-probe --target x86_64-unknown-uefi
doctor:
	cargo build -p hyper-pn52-doctor
test:
	cargo test -p hyper-pn52 -p hyper-storage
