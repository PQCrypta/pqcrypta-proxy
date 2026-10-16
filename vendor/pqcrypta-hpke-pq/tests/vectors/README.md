# HPKE test vectors

`draft-ietf-hpke-pq.json`: the base-mode vectors for the three suites this
crate checks, taken unchanged (fields trimmed to those the test reads) from
`test-vectors/pq-6433c8f.json` in RustCrypto's `hpke` 0.14.1, which carries
the HPKE working group's draft-ietf-hpke-pq vectors at commit 6433c8f.

| KEM | KDF | AEAD |
|---|---|---|
| ML-KEM-768 (0x0041) | HKDF-SHA256 | AES-128-GCM |
| ML-KEM-1024 (0x0042) | HKDF-SHA384 | AES-256-GCM |
| X-Wing (0x647A) | HKDF-SHA256 | ChaCha20Poly1305 |

The recipient private keys in it are the drafts' published test keys.
