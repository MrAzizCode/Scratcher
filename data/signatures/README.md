# Scratcher signature database

This starter database contains two four-byte x86 PIC register thunks documented by the Android platform source. It is deliberately small. A matching pattern is evidence for a candidate, not proof of compiler version or library provenance. The same instructions may appear in unrelated programs. Full-length starter patterns require a known four-byte function boundary.

Train signatures from binaries you control with `train_library_signature`, or add a pattern with `add_library_signature`. Relative immediates, mapped-address immediates and RIP/absolute memory displacement operands can be masked during training. This does not claim complete relocation coverage. Patterns accept hexadecimal bytes and wildcard nibbles (`E8 ?? ?? ?? ??`, `4?`). At least 32 fixed bits and one fully fixed byte are required. Keep library/version/build provenance in `source`.

Import/export uses versioned JSON (`scratcher_signatures: 1`). Limits: 10,000 records, 4,096 bytes per pattern and 8 MiB per database. Recognition checks indexed function starts only and returns explicit continuation cursors and cancellation/budget status. It never automatically renames functions or skips analysis. Distinct matching names/libraries are reported as ambiguous. Even strong matches are not identity guarantees.

Source: https://android.googlesource.com/platform/bionic/+/master/libc/arch-x86/bionic/__x86.get_pc_thunk.S
