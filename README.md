# kxco-pq-vault

[![npm](https://img.shields.io/npm/v/kxco-pq-vault?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-vault)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-vault)](https://socket.dev/npm/package/kxco-pq-vault)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-vault.svg)](https://nodejs.org)

Post-quantum file and envelope encryption. Encrypts data to one or more ML-KEM-768 public keys — like PGP, but quantum-safe. The encrypted envelope can only be decrypted by the holder of the matching private key.

---

## When to use this

- Encrypting documents for storage or sharing between institutions
- Encrypted data export (patient records, financial statements, legal files)
- Anywhere you would use PGP but need quantum resistance
- Multi-recipient envelopes where each party holds their own key

This package is **not** a communication channel. It encrypts payloads at rest or as opaque blobs. For session-layer encryption see `kxco-pq-tls`. For signing and attestation see `kxco-pq-attest`.

---

## Install

```sh
npm install kxco-pq-vault
```

Or as a CLI tool:

```sh
npm install -g kxco-pq-vault
```

---

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

### Library

```js
import { readFileSync, writeFileSync } from 'node:fs'
import { mlKem } from 'kxco-post-quantum'
import {
  encodePublicKey, decodePublicKey,
  generateDek, generateNonce, computeKid,
  wrapDek, unwrapDek,
  serializeHeader, parseEnvelope,
  encryptPayload, decryptPayload,
  readIdentity,
  KxcoVaultError,
} from 'kxco-pq-vault'

// --- ENCRYPT ---

// Recipient's public key (1184 bytes, ML-KEM-768)
const recipientPubkey = decodePublicKey('kxco1qvp93xj...')

const dek     = generateDek()    // 32-byte random data encryption key
const nonce   = generateNonce()  // 12-byte random GCM nonce
const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')

// Encapsulate: produces an ML-KEM ciphertext and a shared secret
const { ciphertext: mlKemCt, sharedSecret: ss } = mlKem.encapsulate(recipientPubkey)
const kid        = computeKid(recipientPubkey)
const wrappedDek = wrapDek(Buffer.from(ss), kid, dek)

const recipients = [{
  kid,
  encapsulatedKey: Buffer.from(mlKemCt).toString('hex'),
  wrappedDek:      wrappedDek.toString('hex'),
}]

const headerText      = serializeHeader({ recipients, nonce: nonce.toString('hex'), created })
const canonicalHeader = Buffer.from(headerText, 'utf-8')
const separator       = Buffer.from('--- BEGIN CIPHERTEXT ---\n', 'utf-8')
const plaintext       = readFileSync('report.pdf')
const payload         = encryptPayload(dek, nonce, canonicalHeader, plaintext)

writeFileSync('report.pdf.kxco', Buffer.concat([canonicalHeader, separator, payload]))

// --- DECRYPT ---

const { publicKey, secretKey } = readIdentity('alice.kxco')
const myKid = computeKid(publicKey)

const buf = readFileSync('report.pdf.kxco')
const { header, canonicalHeader: aad, ciphertext } = parseEnvelope(buf)

const block = header.recipients.find(r => r.kid === myKid)
if (!block) throw new KxcoVaultError('not a recipient in this envelope')

const ss2       = Buffer.from(mlKem.decapsulate(Buffer.from(block.encapsulatedKey, 'hex'), secretKey))
const dek2      = unwrapDek(ss2, myKid, Buffer.from(block.wrappedDek, 'hex'))
const decrypted = decryptPayload(dek2, Buffer.from(header.nonce, 'hex'), aad, ciphertext)

writeFileSync('report.pdf', decrypted)
```

---

## API

All exports are named. Import what you need from `kxco-pq-vault`.

### Key encoding

#### `encodePublicKey(pubkeyBytes: Buffer): string`

Encodes a 1184-byte ML-KEM-768 public key as a `kxco1...` bech32m string suitable for sharing as a recipient identifier.

#### `decodePublicKey(str: string): Buffer`

Decodes a `kxco1...` bech32m string back to raw public key bytes. Throws `KxcoVaultError` if the string is malformed or the wrong length.

---

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

---

### Envelope format

#### `serializeHeader({ recipients, nonce, created }): string`

Produces the canonical plain-text header for an envelope. `recipients` is an array of `{ kid, encapsulatedKey, wrappedDek }` (all hex strings). `nonce` and `created` are hex and ISO 8601 strings respectively.

#### `parseEnvelope(buf: Buffer): { header, canonicalHeader, ciphertext }`

Splits a `.kxco` envelope buffer into its parsed header object, the raw canonical header bytes (for use as GCM AAD), and the raw ciphertext. Throws `KxcoVaultError` if the separator is missing or the header is malformed.

#### `parseHeaderText(text: string): object`

Parses just the text portion of a header (without the binary ciphertext). Useful for inspection without decryption.

---

### Identity and recipient helpers

#### `readIdentity(path: string): { publicKey: Buffer, secretKey: Buffer }`

Reads a `keypair.kxco` identity file and returns the parsed public and secret key buffers. Throws `KxcoVaultError` if the file is missing, malformed, or contains a key of the wrong length.

#### `resolveRecipient(str: string): Buffer`

Resolves a recipient string to raw public key bytes. Accepts:
- A `kxco1...` bech32m string
- `@/path/to/keypair.kxco` — reads the public key from an identity file

---

### Error class

#### `KxcoVaultError`

All errors thrown by this library use `KxcoVaultError` (extends `Error`, `name === 'KxcoVaultError'`). Authentication failures, malformed envelopes, bad key lengths, and missing recipients all throw this class.

---

## CLI reference

### `keygen`

```sh
kxco-vault keygen --out <keypair.kxco>
kxco-vault keygen --out <keypair.kxco> --master <hex> --label <string>
```

Generates an ML-KEM-768 keypair and writes it to an identity file. With `--master` and `--label`, derivation is deterministic — the same inputs always produce the same keypair.

### `recipient`

```sh
kxco-vault recipient <keypair.kxco>
```

Prints the `kxco1...` recipient string from an identity file.

### `encrypt`

```sh
kxco-vault encrypt <file> --recipient <kxco1...|@keyfile> [--recipient ...] [--out <file.kxco>]
```

Encrypts a file for one or more recipients. Multiple `--recipient` flags produce a multi-recipient envelope; each recipient can independently decrypt the same plaintext.

### `decrypt`

```sh
kxco-vault decrypt <file.kxco> --identity <keypair.kxco> [--out <file>]
```

Decrypts an envelope. Fails cleanly if the identity is not a recipient or the envelope has been tampered with.

### `inspect`

```sh
kxco-vault inspect <file.kxco>
```

Prints the envelope header without decrypting: algorithm, recipient count, key IDs, nonce, timestamp, and ciphertext size.

---

## Envelope format

`.kxco` files have a plain-text header followed by raw binary ciphertext:

```
KXCO-VAULT/1.0
algorithm: ml-kem-768+aes-256-gcm
recipients: 1
recipient[0].kid: <16 hex chars>
recipient[0].encapsulated_key: <hex — 1088-byte ML-KEM-768 ciphertext>
recipient[0].wrapped_dek: <hex — 48 bytes>
nonce: <hex — 12 bytes>
created: 2026-05-28T00:00:00Z
--- BEGIN CIPHERTEXT ---
<binary — AES-256-GCM ciphertext + 16-byte auth tag>
```

The entire header is used as GCM additional authenticated data. Modifying any field — including the nonce, algorithm line, or recipient entries — causes decryption to fail before any plaintext is released.

---

## What this does NOT do

**Communication channel encryption** — this package encrypts payloads at rest or as blobs. It does not handle TLS, session keys, or forward secrecy. Use `kxco-pq-tls` for transport-layer encryption.

**Signing and attestation** — there is no signature over the plaintext or sender identity. An encrypted envelope proves only that the sender knew the recipient's public key. Use `kxco-pq-attest` for signing and verification.

**Passphrase protection of identity files** — identity files are not passphrase-encrypted in v1. Protect them using filesystem permissions or a secrets manager.

**Classical/hybrid fallback** — this is pure ML-KEM-768 with no X25519 hybrid. Envelopes cannot be decrypted by recipients without PQC support.

---

## Crypto design

- **ML-KEM-768** (NIST FIPS 203) — Security Category 3, equivalent to AES-192. Pure post-quantum; no classical fallback by design.
- **AES-256-GCM** — AEAD symmetric encryption of the payload.
- **DEK wrapping** — A random 32-byte data encryption key is generated per envelope. Each recipient's ML-KEM shared secret wraps the DEK independently. All recipients decrypt the same plaintext.
- **Header integrity** — The full canonical header is bound as GCM additional authenticated data, linking header and ciphertext together.

Key encapsulation uses [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum) (ML-KEM-768, FIPS 203 final).

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-vault/security/advisories/new) or email **security@kxco.ai**.

---

## Part of the KXCO stack

| Package | Purpose |
|---|---|
| `kxco-post-quantum` | ML-KEM-768 and ML-DSA primitives |
| `kxco-pq-vault` | File and envelope encryption (this package) |
| `kxco-pq-tls` | Post-quantum transport-layer encryption |
| `kxco-pq-attest` | Signing and attestation |

[kxco.ai](https://kxco.ai) · [Knightsbridge Law](https://knightsbridge.law) · [target150.com](https://target150.com)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Authors

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)
