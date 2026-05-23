# Changelog

## 0.1.0 — 2026-05-23

Initial release.

### Added
- `kxco-vault keygen` — generate ML-KEM-768 identity keypair
- `kxco-vault encrypt` — encrypt files for one or more recipients (ML-KEM-768 + AES-256-GCM)
- `kxco-vault decrypt` — decrypt with identity file
- `kxco-vault recipient` — extract public recipient string from identity file
- `kxco-vault inspect` — print envelope header info without decrypting
- `.kxco` envelope format v1.0 with plain-text inspectable header and binary ciphertext
- Multi-recipient support (each recipient gets an independent ML-KEM encapsulation of the same DEK)
- Deterministic keygen from `--master` + `--label` via HKDF (matches `kxco-post-quantum` derivation pattern)
- `@keyfile` recipient shorthand (reads `kxco1...` public string from identity file)
- Header bytes used as AES-GCM additional data — tampering any header field fails authentication
- 25+ tests: envelope round-trips, crypto primitives, end-to-end encrypt/decrypt, tamper detection
