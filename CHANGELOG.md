# Changelog

## 2.0.0 (2026-10-10)

**Breaking changes**

- New keys default to ML-KEM-1024 (keygen output grows from 1184 to 1568 bytes).
- `keygen --master --label` without `--algorithm` now derives an ML-KEM-1024 key; pass `--algorithm ml-kem-768` to re-derive a key made before 2.0.0.
- `serializeHeader` throws on disagreeing or mixed inputs that 1.3.0 accepted and turned into unreadable headers.

**What does not change**

- Every 1.x envelope and identity decrypts.
- `--algorithm ml-kem-768` still makes an ML-KEM-768 identity.

**Detail**

- An ML-KEM-1024 secret key is 3168 bytes (ML-KEM-768: 2400), and each recipient's encapsulated key in an envelope is 1568 bytes (ML-KEM-768: 1088).
- The key, not the default, decides the parameter set, as it has since 1.2.0, so nothing a 1.x release wrote changes meaning.
- `keygen --master` without `--algorithm` prints one line to stderr saying the default changed. Stdout is unchanged, so a script that reads it gets the same bytes.
- With no `algorithm`, `serializeHeader` takes the set from the encapsulated keys' length, and it also refuses a key of neither length. The header is the AES-GCM additional data, so a wrong algorithm line could never be corrected. The CLI always passed the right `algorithm`, so CLI users were never exposed.
- The evidence is in `test/fixtures`: an identity, an envelope and a `--master` key made by the latest release of each 1.x line (1.0.8, 1.1.8, 1.2.0 and 1.3.0) with its own CLI, plus 1.2.0's ML-KEM-1024 ones. The tests open every envelope byte for byte and derive every `--master` key again, and 1.3.0 opens an envelope 2.0.0 seals to its key.
- The README and typings lead with ML-KEM-1024, SECURITY.md and ASSESSMENT.md name both sets, and SECURITY.md lists 2.0.x as the supported line.

## 1.3.0 (2026-10-09)

Runtime support. No change to the API or its behaviour.

**Node.js 22.12 or later is required.** `engines.node` moves from `>=20.19`
to `>=22.12`. Node 20 reached end of life on 30 April 2026. 22.12 is the
first Node 22 release that loads ES modules through `require()` without a
flag, the same property the 20.19 floor provided.

**CI tests every change on Node 22, 24 and 26.** It tested Node 20, 22 and 24 before.

**Releases are built on Node 26**, where they were built on Node 22.
Node 26 ships npm 11.20, which already carries Trusted Publishing, so the
release job no longer downloads npm 11 separately.

## 1.2.0
**ML-KEM-1024 envelopes.** `kxco-vault keygen --algorithm ml-kem-1024` makes a
Category 5 identity, and an envelope sealed to such keys carries
`algorithm: ml-kem-1024+aes-256-gcm` with a 1568-byte encapsulated key per
recipient. The recipient's key decides the parameter set: `kxco1...` strings for
both sets share the prefix and are told apart by length (1184 or 1568 bytes).
The algorithm line is inside the header, which is the AES-GCM additional data,
so it is authenticated with the payload.

ML-KEM-768 stays the default. Envelopes and identity files written by earlier
versions open unchanged, and a test opens an envelope sealed by 1.1.8.

A key of one set is never tried on the other. An envelope cannot mix recipients
from both sets, decrypt refuses an identity whose set differs from the one the
envelope names, and an identity file whose `algorithm:` line disagrees with its
key is refused. An identity file with no `algorithm:` line is read by its key.

`serializeHeader` takes an optional `algorithm`, and `readIdentity` returns the
identity's parameter set as `algorithm`.

## 1.1.8

Every malformed recipient string, envelope field and decryption input throws
KxcoVaultError, as the README states, and decrypt reports a damaged identity
secret key the same way. The header parser checks each hex field against its
documented length. parseEnvelope accepts a Uint8Array.

The npm page quotes OMB M-26-15 on re-encrypting long-lived sensitive data under
PQC keys, and shows the five commands that re-encrypt an archive.

## 1.1.7

Documentation. No source change.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 1.1.6

Documentation. No source change.

**The npm page leads with what the package proves.** The first screen now says why
encrypted data is the asset a harvest-now-decrypt-later adversary keeps, in
the words of Executive Order 14412, how one envelope serves many recipients, the
evidence underneath it and the migration dates set by NIST, Executive Order
14412, OMB M-26-15 and the UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The library quick start now reads the recipient's public key from their identity
file with `resolveRecipient`, so it runs as written after the CLI `keygen` step.
The Knightsbridge Law link now points at knightsbridgelaw.com.

Every GitHub Action in CI is now pinned by commit SHA, as the page states.

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