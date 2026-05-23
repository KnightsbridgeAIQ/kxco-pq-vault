import { bech32m } from '@scure/base'
import { KxcoVaultError } from './errors.js'

const HRP = 'kxco'
const PUBKEY_BYTES = 1184 // ML-KEM-768 public key
const LIMIT = false      // disable default 90-char cap

export function encodePublicKey(pubkeyBytes) {
  const words = bech32m.toWords(pubkeyBytes)
  return bech32m.encode(HRP, words, LIMIT)
}

export function decodePublicKey(str) {
  let decoded
  try {
    decoded = bech32m.decode(str, LIMIT)
  } catch (e) {
    throw new KxcoVaultError(`invalid recipient string: ${e.message}`)
  }
  if (decoded.prefix !== HRP) {
    throw new KxcoVaultError(`invalid recipient prefix: expected "${HRP}", got "${decoded.prefix}"`)
  }
  const bytes = Buffer.from(bech32m.fromWords(decoded.words))
  if (bytes.length !== PUBKEY_BYTES) {
    throw new KxcoVaultError(`invalid recipient: expected ${PUBKEY_BYTES} bytes, got ${bytes.length}`)
  }
  return bytes
}
