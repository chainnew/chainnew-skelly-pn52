# hyper-vm invariants

`DefinedVm::verify` must chain the manifest-verification receipt after the `vm_define` receipt.

Implementation rule:

```text
req.previous_receipt_hash = self.receipts.last_hash()
```

Then capsule verification may create a manifest-verification receipt that appends cleanly to the chain.

This file exists because a direct source patch was blocked during initial branch construction. The source should be updated before merge if CI catches the receipt-chain handoff issue.
