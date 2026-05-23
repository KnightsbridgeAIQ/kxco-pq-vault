import { KxcoVaultError } from './errors.js'

const SEPARATOR = '--- BEGIN CIPHERTEXT ---\n'
const VERSION = 'KXCO-VAULT/1.0'
const ALGORITHM = 'ml-kem-768+aes-256-gcm'

// Serialize a header object to a UTF-8 string (no separator line).
// recipients: [{ kid, encapsulatedKey, wrappedDek }]   (all hex strings)
// nonce: hex string (24 chars = 12 bytes)
// created: ISO 8601 string
export function serializeHeader({ recipients, nonce, created }) {
  const lines = [
    VERSION,
    `algorithm: ${ALGORITHM}`,
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

  const algorithm = get('algorithm')
  if (algorithm !== ALGORITHM) throw new KxcoVaultError(`unsupported algorithm: ${algorithm}`)

  const nRecipients = parseInt(get('recipients'), 10)
  if (!Number.isFinite(nRecipients) || nRecipients < 1) {
    throw new KxcoVaultError(`invalid recipients count: ${get('recipients')}`)
  }

  const recipients = []
  for (let i = 0; i < nRecipients; i++) {
    const kid = get(`recipient[${i}].kid`)
    const encapsulatedKey = get(`recipient[${i}].encapsulated_key`)
    const wrappedDek = get(`recipient[${i}].wrapped_dek`)
    recipients.push({ kid, encapsulatedKey, wrappedDek })
  }

  const nonce = get('nonce')
  const created = get('created')

  return { algorithm, recipients, nonce, created }
}
