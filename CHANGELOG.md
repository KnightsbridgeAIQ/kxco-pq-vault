# Changelog

## 1.1.3

Documentation only. No code changed and no behaviour changed.

`.socket.yml` described `@scure/base` as "audited" with no auditor and no date.
An unattributed audit claim is not one a reader can check, so it is removed.
The file now also records that `@noble/post-quantum`, reached through
`kxco-post-quantum`, has been audited by nobody and is self-audited by its
maintainer only.


## 1.0.0 — 2026-05-24

Stable release.



## 0.1.4 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.3 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.2 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.1 â€” 2026-05-23

Maintenance release. No breaking changes.


## 0.1.0 â€” 2026-05-23

Initial release.

### Added
- `kxco-vault keygen` â€” generate ML-KEM-768 identity keypair
- `kxco-vault encrypt` â€” encrypt files for one or more recipients (ML-KEM-768 + AES-256-GCM)
- `kxco-vault decrypt` â€” decrypt with identity file
- `kxco-vault recipient` â€” extract public recipient string from identity file
- `kxco-vault inspect` â€” print envelope header info without decrypting
- `.kxco` envelope format v1.0 with plain-text inspectable header and binary ciphertext
- Multi-recipient support (each recipient gets an independent ML-KEM encapsulation of the same DEK)
- Deterministic keygen from `--master` + `--label` via HKDF (matches `kxco-post-quantum` derivation pattern)
- `@keyfile` recipient shorthand (reads `kxco1...` public string from identity file)
- Header bytes used as AES-GCM additional data â€” tampering any header field fails authentication
- 25+ tests: envelope round-trips, crypto primitives, end-to-end encrypt/decrypt, tamper detection