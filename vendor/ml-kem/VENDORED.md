# ml-kem (vendored)

RustCrypto's `ml-kem` at KEMs commit 99493f301c8c (2026-06-05, "Bump `sha3`
to v0.12; use `shake` v0.1", #326), which is 0.3.2 plus that bump and the
Rust 1.96 build fix (#320). Unreleased on crates.io as of 2026-10-15.

Why: x-wing 0.1.1 and hpke 0.14.1 are on sha3 0.12 while the released ml-kem
0.3.2 is on sha3 0.11, so pqcrypta-hpke-pq compiled two SHA-3s and
cargo-deny's `multiple-versions = "deny"` refused the tree. This copy is what
the next ml-kem release contains; when it is published, delete this
directory and its `[patch.crates-io]` entry.

Changes from upstream: the crate's `[lints] workspace = true` and its benches
are dropped (there is no RustCrypto workspace here). Sources are unmodified.
