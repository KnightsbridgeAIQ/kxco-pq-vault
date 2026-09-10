# Changelog

## 1.1.5

Documentation. No source change.

**ASSESSMENT.md rewritten.** The previous version led with what the package
does not do and worked back from there, which described the product as a set of
gaps and buried what it actually proves. It now states the capabilities, the
evidence behind them, and where each concern is owned across the stack.

Nothing has been softened away. Facts a buyer needs are still here, stated as
scope rather than deficiency: which package owns what, what a deployment has to
supply, and what a claim is measured against. The change is which way round they
are told.

## 1.1.4

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**An evidence bundle.** `npm run evidence` records identity, this package's own
tests, its SBOM, registry signature verification, and the `kxco-post-quantum`
version actually installed rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.4.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

## 1.1.3

Documentation only. No code changed and no behaviour changed.

`.socket.yml` described `@scure/base` as "audited" with no auditor and no date.
An unattributed audit claim is not one a reader can check, so it is removed.
The file now records the upstream audit history instead: `@noble/hashes`
Cure53 Jan 2022, `@noble/curves` Trail of Bits / Kudelski / Cure53 2023-2024,
`@noble/ciphers` Cure53 Sep 2024, `@noble/post-quantum` maintainer-audited.


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