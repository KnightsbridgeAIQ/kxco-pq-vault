import { readFileSync } from 'node:fs'
import { decodePublicKey } from './bech32.js'
import { KxcoVaultError } from './errors.js'

export function readFileBytes(path) {
  try {
    return readFileSync(path)
  } catch (e) {
    throw new KxcoVaultError(`cannot read file "${path}": ${e.message}`)
  }
}

export function readFileText(path) {
  return readFileBytes(path).toString('utf-8')
}

// Resolve a --recipient value to raw pubkey bytes.
// Accepts: "kxco1..." bech32m string, or "@/path/to/file"
export function resolveRecipient(str) {
  if (str.startsWith('@')) {
    const content = readFileText(str.slice(1)).trim()
    if (content.startsWith('KXCO-VAULT-IDENTITY/')) {
      const match = content.match(/^public:\s*(kxco1\S+)/m)
      if (!match) throw new KxcoVaultError('identity file missing public key')
      return decodePublicKey(match[1])
    }
    return decodePublicKey(content)
  }
  return decodePublicKey(str)
}

// Parse an identity file (keypair.kxco) and return { publicKey, secretKey }
export function readIdentity(path) {
  const content = readFileText(path)
  if (!content.startsWith('KXCO-VAULT-IDENTITY/')) {
    throw new KxcoVaultError(`not a kxco-vault identity file: ${path}`)
  }
  const pubMatch = content.match(/^public:\s*(kxco1\S+)/m)
  const secMatch = content.match(/^secret:\s*([0-9a-fA-F]+)/m)
  if (!pubMatch || !secMatch) throw new KxcoVaultError(`malformed identity file: ${path}`)
  const publicKey = decodePublicKey(pubMatch[1])
  const secretKey = Buffer.from(secMatch[1], 'hex')
  if (secretKey.length !== 2400) {
    throw new KxcoVaultError(`invalid secret key length in ${path}: expected 2400 bytes, got ${secretKey.length}`)
  }
  return { publicKey, secretKey }
}
