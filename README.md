# kxco-pq-vault

**Post-quantum file encryption, like PGP: ML-KEM-1024 envelopes that one recipient or many can open, each with their own key.**

[![npm](https://img.shields.io/npm/v/kxco-pq-vault?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-vault)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-vault?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-vault)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-vault)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-vault)](https://socket.dev/npm/package/kxco-pq-vault)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-vault.svg)](https://nodejs.org)

Post-quantum file and envelope encryption. Encrypts data to one or more ML-KEM-1024 public keys, like PGP, with post-quantum key encapsulation. The encrypted envelope can only be decrypted by the holder of the matching private key. New keys made with kxco-pq-vault use ML-KEM-1024 (FIPS 203, Category 5); ML-KEM-768 keys made earlier keep decrypting.

- **Built for harvest-now, decrypt-later.** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks) names adversaries "collecting United States information now, and decrypting it later once large-scale quantum computers are operational". A vault envelope is pure ML-KEM, ML-KEM-1024 by default, with no classical step, so a copy taken today holds no classical key exchange to break later.
- **The requirement it answers.** [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) tells agencies to prioritise "re-encrypting long-lived sensitive data using keys protected by PQC mechanisms". Archives, backups and ledgers are re-encrypted from the terminal in five lines, shown under [Re-encrypting an archive](#re-encrypting-an-archive).
- **One envelope, many recipients.** A random 32-byte data key per envelope is wrapped to each recipient's ML-KEM shared secret, so each recipient opens the same plaintext with their own key and nobody shares a secret.
- **Tampering fails before disclosure.** The whole header is the AES-256-GCM additional authenticated data, so a changed nonce, algorithm line or recipient entry fails decryption before any plaintext is released.
- **The envelope says what it is.** `KXCO-VAULT/1.0`, an explicit algorithm line and a key id per recipient, so a holder of several keys knows which one applies and a reader years from now knows what produced the file.
- **A CLI and a library over the same code.** Recipient strings are bech32m, safe to paste into a ticket or an email, and nothing in `src/` opens a socket, so an envelope can be made and opened on an air-gapped machine.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.1.1, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [CLI reference](#cli-reference) · [Envelope format](#envelope-format) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

- Encrypting documents for storage or sharing between institutions
- Encrypted data export (patient records, financial statements, legal files)
- Anywhere you would use PGP but need quantum resistance
- Multi-recipient envelopes where each party holds their own key

It encrypts payloads at rest or as opaque blobs. For session-layer encryption, use [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls). To prove who sent a payload as well as that it arrived intact, sign it with [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) before it is encrypted.

Protect identity files with filesystem permissions or a secrets manager, or hold the key in hardware with [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm).

## Install

```sh
npm install kxco-pq-vault
```

Or as a CLI tool:

```sh
npm install -g kxco-pq-vault
```

## Quick start

### CLI

```sh
# Generate a keypair
kxco-vault keygen --out alice.kxco

# Print your recipient string (share this with anyone who needs to encrypt to you)
kxco-vault recipient alice.kxco
# → kxco1qvp93xj...

# Encrypt a file
kxco-vault encrypt report.pdf --recipient kxco1qvp93xj... --out report.pdf.kxco

# Decrypt it
kxco-vault decrypt report.pdf.kxco --identity alice.kxco --out report.pdf
```

### Re-encrypting an archive

The long-lived data OMB M-26-15 names, moved under ML-KEM-1024 in five commands:

```bash
npx kxco-vault keygen --out archive.kxco
RECIPIENT=$(npx kxco-vault recipient archive.kxco)   # the public recipient string, to share
npx kxco-vault encrypt ledger-2019.csv --recipient "$RECIPIENT" --out ledger-2019.csv.kxco
npx kxco-vault inspect ledger-2019.csv.kxco
npx kxco-vault decrypt ledger-2019.csv.kxco --identity archive.kxco --out restored.csv
```

```text
version:    KXCO-VAULT/1.0
algorithm:  ml-kem-1024+aes-256-gcm
recipients: 1
```

`restored.csv` comes back byte-identical, and the envelope opens for the identity it was made for and no other. Pass `--recipient` once per key to make one archive readable by a key in each region, with no key shared.

### Library

```js
import { readFileSync, writeFileSync } from 'node:fs'
import { mlKem, mlKem1024 } from 'kxco-post-quantum'
import {
  encodePublicKey, decodePublicKey,
  generateDek, generateNonce, computeKid,
  wrapDek, unwrapDek,
  serializeHeader, parseEnvelope,
  encryptPayload, decryptPayload,
  readIdentity, resolveRecipient,
  KxcoVaultError,
} from 'kxco-pq-vault'

// --- ENCRYPT ---

// Recipient's public key: from their identity file, or
// decodePublicKey('kxco1...') for a recipient string they shared. Its length
// gives its set: 1568 bytes is ML-KEM-1024, what keygen makes; 1184 is ML-KEM-768.
const recipientPubkey = resolveRecipient('@alice.kxco')
const kem = recipientPubkey.length === 1568 ? mlKem1024 : mlKem

const dek     = generateDek()    // 32-byte random data encryption key
const nonce   = generateNonce()  // 12-byte random GCM nonce
const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')

// Encapsulate: produces an ML-KEM ciphertext and a shared secret
const { ciphertext: mlKemCt, sharedSecret: ss } = kem.encapsulate(recipientPubkey)
const kid        = computeKid(recipientPubkey)
const wrappedDek = wrapDek(Buffer.from(ss), kid, dek)

const recipients = [{
  kid,
  encapsulatedKey: Buffer.from(mlKemCt).toString('hex'),
  wrappedDek:      wrappedDek.toString('hex'),
}]

// The encapsulated key's length tells serializeHeader which algorithm line to write
const headerText      = serializeHeader({ recipients, nonce: nonce.toString('hex'), created })
const canonicalHeader = Buffer.from(headerText, 'utf-8')
const separator       = Buffer.from('--- BEGIN CIPHERTEXT ---\n', 'utf-8')
const plaintext       = readFileSync('report.pdf')
const payload         = encryptPayload(dek, nonce, canonicalHeader, plaintext)

writeFileSync('report.pdf.kxco', Buffer.concat([canonicalHeader, separator, payload]))

// --- DECRYPT ---

const { publicKey, secretKey, algorithm } = readIdentity('alice.kxco')
const myKem = algorithm === 'ml-kem-1024' ? mlKem1024 : mlKem
const myKid = computeKid(publicKey)

const buf = readFileSync('report.pdf.kxco')
const { header, canonicalHeader: aad, ciphertext } = parseEnvelope(buf)

const block = header.recipients.find(r => r.kid === myKid)
if (!block) throw new KxcoVaultError('not a recipient in this envelope')

const ss2       = Buffer.from(myKem.decapsulate(Buffer.from(block.encapsulatedKey, 'hex'), secretKey))
const dek2      = unwrapDek(ss2, myKid, Buffer.from(block.wrappedDek, 'hex'))
const decrypted = decryptPayload(dek2, Buffer.from(header.nonce, 'hex'), aad, ciphertext)

writeFileSync('report.pdf', decrypted)
```

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

All exports are named. Import what you need from `kxco-pq-vault`.

### Key encoding

#### `encodePublicKey(pubkeyBytes: Buffer): string`

Encodes a 1568-byte ML-KEM-1024 or 1184-byte ML-KEM-768 public key as a `kxco1...` bech32m string suitable for sharing as a recipient identifier. The two sets share the prefix; the decoded length says which one a key is.

#### `decodePublicKey(str: string): Buffer`

Decodes a `kxco1...` bech32m string back to raw public key bytes. Throws `KxcoVaultError` if the string is malformed or decodes to neither 1568 (ML-KEM-1024) nor 1184 (ML-KEM-768) bytes.

### Crypto primitives

#### `generateDek(): Buffer`

Returns 32 cryptographically random bytes for use as a data encryption key.

#### `generateNonce(): Buffer`

Returns 12 cryptographically random bytes for use as a GCM nonce.

#### `computeKid(pubkeyBytes: Buffer): string`

Returns the first 8 bytes of `SHA-256(pubkey)` as a 16-character lowercase hex string. Used to match recipients in an envelope without revealing the full public key.

#### `wrapDek(ss: Buffer, kid: string, dek: Buffer): Buffer`

Wraps a 32-byte DEK using an ML-KEM shared secret (`ss`) as an AES-256-GCM key. `kid` is used as additional authenticated data for domain separation. Returns 48 bytes (32-byte ciphertext + 16-byte auth tag).

#### `unwrapDek(ss: Buffer, kid: string, wrappedDek: Buffer): Buffer`

Unwraps a DEK produced by `wrapDek`. Throws `KxcoVaultError` if authentication fails.

#### `encryptPayload(dek: Buffer, nonce: Buffer, ad: Buffer, plaintext: Buffer): Buffer`

Encrypts `plaintext` with AES-256-GCM. `ad` is the canonical envelope header bound as additional authenticated data. Returns `ciphertext || 16-byte auth tag`.

#### `decryptPayload(dek: Buffer, nonce: Buffer, ad: Buffer, payload: Buffer): Buffer`

Decrypts a payload produced by `encryptPayload`. Throws `KxcoVaultError` if authentication fails.

### Envelope helpers

#### `serializeHeader({ recipients, nonce, created, algorithm? }): string`

Produces the canonical plain-text header for an envelope. `recipients` is an array of `{ kid, encapsulatedKey, wrappedDek }` (all hex strings). `nonce` and `created` are hex and ISO 8601 strings respectively. `algorithm` is optional: the length of the encapsulated keys decides it, 1568 bytes giving `'ml-kem-1024+aes-256-gcm'` and 1088 giving `'ml-kem-768+aes-256-gcm'`. The header is the AES-GCM additional data, so an algorithm line that named the wrong set could never be corrected once a payload was sealed under it. A passed `algorithm` that disagrees with the keys, recipients that mix the two sets, and an encapsulated key of any other length all throw `KxcoVaultError`.

#### `parseEnvelope(buf: Buffer): { header, canonicalHeader, ciphertext }`

Splits an envelope buffer, the bytes of a `.kxco` file, into its parsed header object, the raw canonical header bytes (for use as GCM AAD), and the raw ciphertext. Throws `KxcoVaultError` if the separator is missing or the header is malformed.

#### `parseHeaderText(text: string): object`

Parses just the text portion of a header (without the binary ciphertext). Useful for inspection without decryption. Each `encapsulated_key` is checked against the length its algorithm line fixes: 1568 bytes for ML-KEM-1024, 1088 for ML-KEM-768.

### Identity and recipient helpers

#### `readIdentity(path: string): { publicKey: Buffer, secretKey: Buffer, algorithm: 'ml-kem-1024' | 'ml-kem-768' }`

Reads an identity file such as `keypair.kxco` and returns the parsed public and secret key buffers and the parameter set, which the public key's length decides. Throws `KxcoVaultError` if the file is missing, malformed, contains a key of the wrong length, or names the other set on its `algorithm:` line. A file with no `algorithm:` line is read by its key alone.

#### `resolveRecipient(str: string): Buffer`

Resolves a recipient string to raw public key bytes. Accepts:
- A `kxco1...` bech32m string
- `@/path/to/keypair.kxco`, which reads the public key from an identity file

### Error class

#### `KxcoVaultError`

All errors thrown by this library use `KxcoVaultError` (extends `Error`, `name === 'KxcoVaultError'`). Authentication failures, malformed envelopes, bad key lengths, and missing recipients all throw this class.

## CLI reference

### `keygen`

```sh
kxco-vault keygen --out <keypair.kxco>
kxco-vault keygen --out <keypair.kxco> --master <hex> --label <string>
kxco-vault keygen --out <keypair.kxco> --algorithm ml-kem-768
```

Generates an ML-KEM-1024 keypair, or an ML-KEM-768 one with `--algorithm ml-kem-768`, and writes it to an identity file. With `--master` and `--label`, derivation is deterministic: the same inputs and the same `--algorithm` always produce the same keypair. A key that version 1.3.0 or earlier derived without `--algorithm` is ML-KEM-768, so pass `--algorithm ml-kem-768` to derive it again.

### `recipient`

```sh
kxco-vault recipient <keypair.kxco>
```

Prints the `kxco1...` recipient string from an identity file.

### `encrypt`

```sh
kxco-vault encrypt <file> --recipient <kxco1...|@keyfile> [--recipient ...] [--out <file.kxco>]
```

Encrypts a file for one or more recipients. Multiple `--recipient` flags produce a multi-recipient envelope; each recipient can independently decrypt the same plaintext. The recipients' keys decide the algorithm line: ML-KEM-1024 keys give `ml-kem-1024+aes-256-gcm`, ML-KEM-768 keys give `ml-kem-768+aes-256-gcm`. An envelope names one parameter set, so recipients from both sets are refused; encrypt once for each.

### `decrypt`

```sh
kxco-vault decrypt <file.kxco> --identity <keypair.kxco> [--out <file>]
```

Decrypts an envelope. Fails cleanly if the identity is not a recipient, if its key is of the other parameter set from the one the envelope names, or if the envelope has been tampered with.

### `inspect`

```sh
kxco-vault inspect <file.kxco>
```

Prints the envelope header without decrypting: algorithm, recipient count, key IDs, nonce, timestamp, and ciphertext size.

## Envelope format

`.kxco` files have a plain-text header followed by raw binary ciphertext:

```
KXCO-VAULT/1.0
algorithm: ml-kem-1024+aes-256-gcm
recipients: 1
recipient[0].kid: <16 hex chars>
recipient[0].encapsulated_key: <hex: 1568-byte ML-KEM-1024 ciphertext, or 1088 bytes under ml-kem-768+aes-256-gcm>
recipient[0].wrapped_dek: <hex: 48 bytes>
nonce: <hex: 12 bytes>
created: 2026-05-28T00:00:00Z
--- BEGIN CIPHERTEXT ---
<binary: AES-256-GCM ciphertext + 16-byte auth tag>
```

The entire header is used as GCM additional authenticated data. Modifying any field, including the nonce, the algorithm line or a recipient entry, causes decryption to fail before any plaintext is released.

## Crypto design

- **ML-KEM-1024** (NIST FIPS 203), the default. New keys made with kxco-pq-vault use ML-KEM-1024 (FIPS 203, Category 5); ML-KEM-768 keys made earlier keep decrypting. Pure post-quantum, with no classical fallback by design, so an envelope is never downgraded to something a quantum adversary can open.
- **ML-KEM-768** (NIST FIPS 203): Security Category 3, equivalent to AES-192. Chosen by the recipient's key (`keygen --algorithm ml-kem-768`, or any key made by 1.3.0 or earlier without `--algorithm`), named on the envelope's algorithm line as `ml-kem-768+aes-256-gcm`, and otherwise the same construction. Identities and envelopes written by earlier versions open exactly as before.
- **AES-256-GCM**: AEAD symmetric encryption of the payload.
- **DEK wrapping**: a random 32-byte data encryption key is generated per envelope. Each recipient's ML-KEM shared secret wraps the DEK independently. All recipients decrypt the same plaintext.
- **Header integrity**: the full canonical header is bound as GCM additional authenticated data, linking header and ciphertext together.

Key encapsulation runs through [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), on the OpenSSL 3.5 primitives where the runtime provides them and on [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) elsewhere.

## The KXCO post-quantum family

This package encrypts, so only the recipients you name can open a payload. The
rest of the family covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

[kxco.ai](https://kxco.ai) · [Knightsbridge Law](https://knightsbridgelaw.com) · [target150.com](https://target150.com)

## Release integrity

Every release since 1.1.1 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-vault@<version>`. A CycloneDX
SBOM is published, from v1.1.1, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-KEM-1024** by default, and **ML-KEM-768** for keys made with it (both NIST FIPS 203), via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them, with AES-256-GCM from Node's own `crypto`. No custom primitives.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.1: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.1
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-vault/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
