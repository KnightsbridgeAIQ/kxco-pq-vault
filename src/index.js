// Library entry point — re-exports all public primitives.
export { encodePublicKey, decodePublicKey } from './bech32.js'
export { serializeHeader, parseEnvelope, parseHeaderText } from './envelope.js'
export {
  generateDek,
  generateNonce,
  computeKid,
  wrapDek,
  unwrapDek,
  encryptPayload,
  decryptPayload,
} from './crypto.js'
export { resolveRecipient, readIdentity } from './util.js'
export { KxcoVaultError } from './errors.js'
