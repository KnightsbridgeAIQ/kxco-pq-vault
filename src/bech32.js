import { bech32m } from '@scure/base'
import { KxcoVaultError } from './errors.js'
import { kemForPublicKey } from './kem.js'

// One prefix for both parameter sets: the decoded length says which one a key
// is, 1184 bytes for ML-KEM-768 and 1568 for ML-KEM-1024.
const HRP = 'kxco'
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
  // A string can carry a valid checksum and still not turn back into bytes,
  // when its padding bits are wrong.
  let bytes
  try {
    bytes = Buffer.from(bech32m.fromWords(decoded.words))
  } catch (e) {
    throw new KxcoVaultError(`invalid recipient string: ${e.message}`)
  }
  kemForPublicKey(bytes)
  return bytes
}
