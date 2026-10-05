import { mlKem, mlKem1024 } from 'kxco-post-quantum'
import { KxcoVaultError } from './errors.js'

// The two ML-KEM parameter sets a vault key can be, and what each one fixes.
// The key decides: a public key's length says which set it belongs to, and
// that set decides the envelope's algorithm line and the size of every field
// it writes. ML-KEM-768 is the default, so an identity or envelope made before
// ML-KEM-1024 existed here reads exactly as it always did.
export const KEMS = Object.freeze({
  'ml-kem-768': Object.freeze({
    module: mlKem,
    suite: 'ml-kem-768+aes-256-gcm',
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
    ciphertextBytes: 1088,
  }),
  'ml-kem-1024': Object.freeze({
    module: mlKem1024,
    suite: 'ml-kem-1024+aes-256-gcm',
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
    ciphertextBytes: 1568,
  }),
})

export const DEFAULT_KEM = 'ml-kem-768'

/** The parameter set a public key of this length belongs to. */
export function kemForPublicKey(publicKey) {
  for (const [name, kem] of Object.entries(KEMS)) {
    if (publicKey.length === kem.publicKeyBytes) return name
  }
  throw new KxcoVaultError(
    `invalid recipient: expected ${KEMS['ml-kem-768'].publicKeyBytes} (ML-KEM-768) or ` +
    `${KEMS['ml-kem-1024'].publicKeyBytes} (ML-KEM-1024) bytes, got ${publicKey.length}`,
  )
}

/** The parameter set an envelope's algorithm line names. */
export function kemForSuite(suite) {
  for (const [name, kem] of Object.entries(KEMS)) {
    if (kem.suite === suite) return name
  }
  throw new KxcoVaultError(`unsupported algorithm: ${suite}`)
}
