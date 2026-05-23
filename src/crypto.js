import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto'
import { KxcoVaultError } from './errors.js'

export function generateDek() { return randomBytes(32) }
export function generateNonce() { return randomBytes(12) }

// kid = first 8 bytes of SHA-256(pubkey), as 16-char lowercase hex
export function computeKid(pubkeyBytes) {
  return createHash('sha256').update(pubkeyBytes).digest().slice(0, 8).toString('hex')
}

// Wrap DEK with the ML-KEM shared secret (32 bytes = AES-256 key).
// nonce = 12 zero bytes (ss is fresh per encapsulation, reuse-safe).
// ad = raw kid bytes (8 bytes) for domain separation.
// Output: 48 bytes (32-byte ciphertext + 16-byte GCM auth tag).
export function wrapDek(ss, kid, dek) {
  const cipher = createCipheriv('aes-256-gcm', ss, Buffer.alloc(12))
  cipher.setAAD(Buffer.from(kid, 'hex'))
  const ct = Buffer.concat([cipher.update(dek), cipher.final()])
  return Buffer.concat([ct, cipher.getAuthTag()])
}

// Unwrap DEK. Throws KxcoVaultError if auth fails.
export function unwrapDek(ss, kid, wrappedDek) {
  if (wrappedDek.length !== 48) throw new KxcoVaultError('authentication failed: invalid wrapped_dek length')
  const decipher = createDecipheriv('aes-256-gcm', ss, Buffer.alloc(12))
  decipher.setAAD(Buffer.from(kid, 'hex'))
  decipher.setAuthTag(wrappedDek.slice(32))
  try {
    return Buffer.concat([decipher.update(wrappedDek.slice(0, 32)), decipher.final()])
  } catch {
    throw new KxcoVaultError('authentication failed')
  }
}

// Encrypt plaintext. Returns ciphertext||tag (payload.length = plaintext.length + 16).
// ad = canonicalHeader bytes.
export function encryptPayload(dek, nonce, ad, plaintext) {
  const cipher = createCipheriv('aes-256-gcm', dek, nonce)
  cipher.setAAD(ad)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([ct, cipher.getAuthTag()])
}

// Decrypt payload (ciphertext||tag). Throws KxcoVaultError if auth fails.
export function decryptPayload(dek, nonce, ad, payload) {
  if (payload.length < 16) throw new KxcoVaultError('authentication failed: ciphertext too short')
  const decipher = createDecipheriv('aes-256-gcm', dek, nonce)
  decipher.setAAD(ad)
  decipher.setAuthTag(payload.slice(-16))
  try {
    return Buffer.concat([decipher.update(payload.slice(0, -16)), decipher.final()])
  } catch {
    throw new KxcoVaultError('authentication failed')
  }
}
