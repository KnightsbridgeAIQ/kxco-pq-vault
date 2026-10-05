import { KxcoVaultError } from './errors.js'
import { KEMS, DEFAULT_KEM, kemForSuite } from './kem.js'

const SEPARATOR = '--- BEGIN CIPHERTEXT ---\n'
const VERSION = 'KXCO-VAULT/1.0'

// Field sizes, in bytes, as the README's envelope format gives them. The
// encapsulated key is the ML-KEM ciphertext, so its size comes from the
// parameter set the algorithm line names: 1088 for ML-KEM-768, 1568 for
// ML-KEM-1024.
const KID_BYTES = 8
const WRAPPED_DEK_BYTES = 48        // 32-byte DEK + 16-byte GCM tag
const NONCE_BYTES = 12

// Serialize a header object to a UTF-8 string (no separator line).
// recipients: [{ kid, encapsulatedKey, wrappedDek }]   (all hex strings)
// nonce: hex string (24 chars = 12 bytes)
// created: ISO 8601 string
// algorithm: 'ml-kem-768+aes-256-gcm' (the default) or 'ml-kem-1024+aes-256-gcm'
export function serializeHeader({ recipients, nonce, created, algorithm = KEMS[DEFAULT_KEM].suite }) {
  kemForSuite(algorithm)
  const lines = [
    VERSION,
    `algorithm: ${algorithm}`,
    `recipients: ${recipients.length}`,
  ]
  for (let i = 0; i < recipients.length; i++) {
    const r = recipients[i]
    lines.push(`recipient[${i}].kid: ${r.kid}`)
    lines.push(`recipient[${i}].encapsulated_key: ${r.encapsulatedKey}`)
    lines.push(`recipient[${i}].wrapped_dek: ${r.wrappedDek}`)
  }
  lines.push(`nonce: ${nonce}`)
  lines.push(`created: ${created}`)
  return lines.join('\n') + '\n'
}

// Parse a full envelope Buffer into { header, canonicalHeader, ciphertext }.
// canonicalHeader is the raw bytes used as GCM AAD.
export function parseEnvelope(buf) {
  // A plain Uint8Array is read through a Buffer over the same bytes: its own
  // indexOf looks for one element, not for a run of bytes.
  if (buf instanceof Uint8Array && !Buffer.isBuffer(buf)) {
    buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)
  }
  const sepBytes = Buffer.from(SEPARATOR, 'utf-8')
  const sepIdx = buf.indexOf(sepBytes)
  if (sepIdx === -1) throw new KxcoVaultError('invalid envelope: missing ciphertext separator')

  const canonicalHeader = buf.slice(0, sepIdx)
  const ciphertext = buf.slice(sepIdx + sepBytes.length)

  const header = parseHeaderText(canonicalHeader.toString('utf-8'))
  return { header, canonicalHeader, ciphertext }
}

// Parse just the text portion of a header (for inspect).
export function parseHeaderText(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0)
  if (lines[0] !== VERSION) throw new KxcoVaultError(`unsupported vault version: ${lines[0]}`)

  const get = (key) => {
    const line = lines.find(l => l.startsWith(`${key}: `))
    if (!line) throw new KxcoVaultError(`missing header field: ${key}`)
    return line.slice(key.length + 2)
  }

  // The algorithm line is inside the header, and the header is the AES-GCM
  // additional data, so a line changed to name the other parameter set is
  // refused, by the field lengths below or by authentication, rather than
  // being believed.
  const algorithm = get('algorithm')
  const encapsulatedKeyBytes = KEMS[kemForSuite(algorithm)].ciphertextBytes

  const nRecipients = parseInt(get('recipients'), 10)
  if (!Number.isFinite(nRecipients) || nRecipients < 1) {
    throw new KxcoVaultError(`invalid recipients count: ${get('recipients')}`)
  }

  // The hex fields are read at the lengths the envelope format documents.
  // Buffer.from(hex, 'hex') stops quietly at the first character that is not
  // hex, so without this a damaged field would reach ML-KEM or AES-GCM short
  // and fail there, with their errors rather than this package's.
  const hexField = (key, bytes) => {
    const value = get(key)
    if (value.length !== bytes * 2 || !/^[0-9a-fA-F]*$/.test(value)) {
      throw new KxcoVaultError(`invalid header field: ${key} must be ${bytes * 2} hex characters`)
    }
    return value
  }

  const recipients = []
  for (let i = 0; i < nRecipients; i++) {
    const kid = hexField(`recipient[${i}].kid`, KID_BYTES)
    const encapsulatedKey = hexField(`recipient[${i}].encapsulated_key`, encapsulatedKeyBytes)
    const wrappedDek = hexField(`recipient[${i}].wrapped_dek`, WRAPPED_DEK_BYTES)
    recipients.push({ kid, encapsulatedKey, wrappedDek })
  }

  const nonce = hexField('nonce', NONCE_BYTES)
  const created = get('created')

  return { algorithm, recipients, nonce, created }
}
