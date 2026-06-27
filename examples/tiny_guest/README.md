# Tiny Guest

Stage 1 guest should be the smallest possible payload:

```asm
start:
    hlt
    jmp start
```

Expected host behavior: one clean VMEXIT for HLT, log exit code, terminate guest or resume.
