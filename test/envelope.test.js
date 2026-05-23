import { test } from 'node:test'
import assert from 'node:assert/strict'
import { serializeHeader, parseEnvelope, parseHeaderText } from '../src/envelope.js'
import { KxcoVaultError } from '../src/errors.js'

const SAMPLE_RECIPIENTS = [
  {
    kid: 'aabbccdd11223344',
    encapsulatedKey: 'aa'.repeat(1088),
    wrappedDek: 'bb'.repeat(48),
  },
]
const SAMPLE_NONCE = 'cc'.repeat(12)
const SAMPLE_CREATED = '2026-05-23T00:00:00Z'

test('serializeHeader: produces correct structure', () => {
  const text = serializeHeader({
    recipients: SAMPLE_RECIPIENTS,
    nonce: SAMPLE_NONCE,
    created: SAMPLE_CREATED,
  })
  assert.ok(text.startsWith('KXCO-VAULT/1.0\n'))
  assert.ok(text.includes('algorithm: ml-kem-768+aes-256-gcm\n'))
  assert.ok(text.includes('recipients: 1\n'))
  assert.ok(text.includes(`recipient[0].kid: ${SAMPLE_RECIPIENTS[0].kid}\n`))
  assert.ok(text.includes(`recipient[0].encapsulated_key: ${SAMPLE_RECIPIENTS[0].encapsulatedKey}\n`))
  assert.ok(text.includes(`recipient[0].wrapped_dek: ${SAMPLE_RECIPIENTS[0].wrappedDek}\n`))
  assert.ok(text.includes(`nonce: ${SAMPLE_NONCE}\n`))
  assert.ok(text.includes(`created: ${SAMPLE_CREATED}\n`))
})

test('parseHeaderText: round-trips single recipient', () => {
  const text = serializeHeader({
    recipients: SAMPLE_RECIPIENTS,
    nonce: SAMPLE_NONCE,
    created: SAMPLE_CREATED,
  })
  const h = parseHeaderText(text)
  assert.equal(h.algorithm, 'ml-kem-768+aes-256-gcm')
  assert.equal(h.recipients.length, 1)
  assert.equal(h.recipients[0].kid, SAMPLE_RECIPIENTS[0].kid)
  assert.equal(h.recipients[0].encapsulatedKey, SAMPLE_RECIPIENTS[0].encapsulatedKey)
  assert.equal(h.recipients[0].wrappedDek, SAMPLE_RECIPIENTS[0].wrappedDek)
  assert.equal(h.nonce, SAMPLE_NONCE)
  assert.equal(h.created, SAMPLE_CREATED)
})

test('parseHeaderText: round-trips multiple recipients', () => {
  const twoRecipients = [
    { kid: '1111111111111111', encapsulatedKey: 'aa'.repeat(1088), wrappedDek: 'bb'.repeat(48) },
    { kid: '2222222222222222', encapsulatedKey: 'cc'.repeat(1088), wrappedDek: 'dd'.repeat(48) },
  ]
  const text = serializeHeader({ recipients: twoRecipients, nonce: SAMPLE_NONCE, created: SAMPLE_CREATED })
  const h = parseHeaderText(text)
  assert.equal(h.recipients.length, 2)
  assert.equal(h.recipients[1].kid, '2222222222222222')
})

test('parseEnvelope: splits header and ciphertext correctly', () => {
  const headerText = serializeHeader({
    recipients: SAMPLE_RECIPIENTS,
    nonce: SAMPLE_NONCE,
    created: SAMPLE_CREATED,
  })
  const sep = Buffer.from('--- BEGIN CIPHERTEXT ---\n', 'utf-8')
  const ciphertextBytes = Buffer.from([1, 2, 3, 4, 5])
  const buf = Buffer.concat([Buffer.from(headerText, 'utf-8'), sep, ciphertextBytes])

  const { header, canonicalHeader, ciphertext } = parseEnvelope(buf)
  assert.equal(header.nonce, SAMPLE_NONCE)
  assert.deepEqual(ciphertext, ciphertextBytes)
  assert.equal(canonicalHeader.toString('utf-8'), headerText)
})

test('parseEnvelope: throws on missing separator', () => {
  const buf = Buffer.from('KXCO-VAULT/1.0\njunk\n', 'utf-8')
  assert.throws(() => parseEnvelope(buf), (err) => {
    assert.ok(err instanceof KxcoVaultError)
    assert.ok(err.message.includes('missing ciphertext separator'))
    return true
  })
})

test('parseHeaderText: throws on wrong version', () => {
  const bad = 'KXCO-VAULT/2.0\nalgorithm: ml-kem-768+aes-256-gcm\nrecipients: 0\n'
  assert.throws(() => parseHeaderText(bad), KxcoVaultError)
})
