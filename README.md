# kxco-pq-vault

Post-quantum file encryption CLI and library. Uses **ML-KEM-768** (NIST FIPS 203) for key encapsulation and **AES-256-GCM** for symmetric encryption.

A direct answer to "harvest now, decrypt later" attacks: files encrypted today cannot be broken even by a future quantum computer.

```
npm install -g kxco-pq-vault
```

---

## Quick start

```sh
# 1. Generate a keypair
kxco-vault keygen --out alice.kxco

# 2. Share your recipient string with senders
kxco-vault recipient alice.kxco
# → kxco1qvp93xj...  (paste this to anyone who needs to encrypt to you)

# 3. Encrypt a file
kxco-vault encrypt secret.txt --recipient kxco1qvp93xj... --out secret.txt.kxco

# 4. Decrypt it
kxco-vault decrypt secret.txt.kxco --identity alice.kxco --out secret.txt
```

---

## Commands

### `keygen`

```
kxco-vault keygen --out <keypair.kxco>
kxco-vault keygen --out <keypair.kxco> --master <hex> --label <string>
```

Generates an ML-KEM-768 keypair. The identity file contains both public and secret key material — keep it private.

With `--master` + `--label`, derivation is deterministic (same inputs always produce the same keypair). Different labels under the same master produce different keypairs.

### `recipient`

```
kxco-vault recipient <keypair.kxco>
```

Prints the `kxco1...` bech32m recipient string from an identity file. Share this string with anyone who needs to encrypt files to you.

### `encrypt`

```
kxco-vault encrypt <file> --recipient <kxco1...|@keyfile> [--recipient ...] [--out <file.kxco>]
```

Encrypts a file for one or more recipients. Each recipient can independently decrypt using their identity file.

`--recipient` accepts either a `kxco1...` bech32m string or `@/path/to/keypair.kxco`.

Multiple `--recipient` flags produce a multi-recipient envelope. All recipients decrypt the same plaintext.

### `decrypt`

```
kxco-vault decrypt <file.kxco> --identity <keypair.kxco> [--out <file>]
```

Decrypts an envelope using your identity file. Fails cleanly if your identity is not a recipient in the envelope, or if the envelope has been tampered with.

### `inspect`

```
kxco-vault inspect <file.kxco>
```

Prints the envelope header without decrypting: algorithm, recipient count, recipient key IDs, nonce, created timestamp, and ciphertext size.

---

## Envelope format

`.kxco` files have a plain-text header (readable with `cat`/`less`) followed by raw binary ciphertext:

```
KXCO-VAULT/1.0
algorithm: ml-kem-768+aes-256-gcm
recipients: 1
recipient[0].kid: <16 hex chars — first 8 bytes of SHA-256(pubkey)>
recipient[0].encapsulated_key: <hex — 1088-byte ML-KEM-768 ciphertext>
recipient[0].wrapped_dek: <hex — 48 bytes: AES-256-GCM(ss, nonce=0, ad=kid).encrypt(dek)>
nonce: <hex — 12-byte GCM nonce>
created: 2026-05-23T00:00:00Z
--- BEGIN CIPHERTEXT ---
<binary — AES-256-GCM ciphertext + 16-byte auth tag>
```

The entire header (everything before `--- BEGIN CIPHERTEXT ---`) is used as **additional authenticated data** in the GCM call. Tampering with any header field — including the nonce, recipient entries, or algorithm line — causes decryption to fail with an authentication error.

---

## Crypto design

- **ML-KEM-768** (FIPS 203 final) — Security Category 3, ~AES-192 equivalent. Pure post-quantum; no classical fallback by design.
- **AES-256-GCM** — AEAD symmetric encryption of the file payload.
- **DEK wrapping** — A random 32-byte data encryption key (DEK) is generated per file. Each recipient's ML-KEM shared secret is used directly as a per-recipient AES-256-GCM key to wrap the DEK.
- **Header integrity** — The full canonical header is the GCM additional data, binding header + ciphertext together.

---

## Identity file format

```
KXCO-VAULT-IDENTITY/1.0
algorithm: ml-kem-768
created: 2026-05-23T00:00:00Z
public: kxco1<bech32m of 1184-byte ML-KEM-768 public key>
secret: <hex of 2400-byte ML-KEM-768 secret key>
```

The identity file is the only secret. The `public:` field can be shared freely. There is no passphrase protection in v1 (v0.2.0).

---

## Library usage

```js
import {
  encodePublicKey, decodePublicKey,
  serializeHeader, parseEnvelope,
  computeKid, generateDek, generateNonce,
  wrapDek, unwrapDek, encryptPayload, decryptPayload,
  KxcoVaultError,
} from 'kxco-pq-vault'
```

---

## Why not hybrid X25519+ML-KEM?

This is a deliberate v1 choice. ML-KEM-768 is FIPS 203 final. Files encrypted here cannot be broken by a quantum computer. A hybrid adds implementation complexity without meaningful security gain over a finalized PQC standard. Hybrid support (defense-in-depth for non-PQ-capable recipients) is planned for v0.2.0.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
