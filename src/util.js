import { readFileSync } from 'node:fs'
import { decodePublicKey } from './bech32.js'
import { KxcoVaultError } from './errors.js'
import { KEMS, kemForPublicKey } from './kem.js'

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

// Parse an identity file (keypair.kxco) and return
// { publicKey, secretKey, algorithm }, where algorithm is 'ml-kem-768' or
// 'ml-kem-1024'. The public key decides the parameter set; an `algorithm:`
// line that names the other one is refused, and a file without the line is
// read by its key alone.
export function readIdentity(path) {
  const content = readFileText(path)
  if (!content.startsWith('KXCO-VAULT-IDENTITY/')) {
    throw new KxcoVaultError(`not a kxco-vault identity file: ${path}`)
  }
  const pubMatch = content.match(/^public:\s*(kxco1\S+)/m)
  const secMatch = content.match(/^secret:\s*([0-9a-fA-F]+)/m)
  if (!pubMatch || !secMatch) throw new KxcoVaultError(`malformed identity file: ${path}`)
  const publicKey = decodePublicKey(pubMatch[1])
  const algorithm = kemForPublicKey(publicKey)
  const algMatch = content.match(/^algorithm:\s*(\S+)/m)
  if (algMatch && algMatch[1] !== algorithm) {
    throw new KxcoVaultError(
      `identity file ${path} says ${algMatch[1]} but its public key is ${algorithm}`,
    )
  }
  const secretKey = Buffer.from(secMatch[1], 'hex')
  const expected = KEMS[algorithm].secretKeyBytes
  if (secretKey.length !== expected) {
    throw new KxcoVaultError(`invalid secret key length in ${path}: expected ${expected} bytes, got ${secretKey.length}`)
  }
  return { publicKey, secretKey, algorithm }
}
