# hyper-vm invariants

`DefinedVm::verify` must chain the manifest-verification receipt after the `vm_define` receipt.

Implementation rule:

```text
req.previous_receipt_hash = self.receipts.last_hash()
```

The public crate re-exports `model.rs`, where this handoff is implemented before capsule verification creates the manifest-verification receipt.
