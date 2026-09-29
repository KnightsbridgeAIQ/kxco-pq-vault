// Property-based tests with fast-check.
//
// The example tests next to this file check one envelope at a time. These ask
// the general question: for ANY payload and ANY set of recipients, does an
// envelope do what the README says? Every recipient opens it with their own
// key, a key that was not named cannot, and a change to any byte of the
// envelope fails before a single byte of plaintext is released. fast-check
// generates the inputs and, when a property breaks, shrinks the failing case
// to the smallest one that still breaks it, so a failure arrives as a minimal
// reproduction rather than a random blob.
//
// Envelopes are sealed and opened exactly as the README's library example
// does it, from this package's own exports. Nothing here touches the file
// system or the network. Runs on whichever kxco-post-quantum backend is live.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mlKem } from 'kxco-post-quantum'
import {
  encodePublicKey, decodePublicKey,
  serializeHeader, parseEnvelope, parseHeaderText,
  generateDek, generateNonce, computeKid,
  wrapDek, unwrapDek,
  encryptPayload, decryptPayload,
  KxcoVaultError,
} from '../src/index.js'

// Each case encapsulates to up to four keys and opens once per recipient, so a
// modest run count keeps the suite fast while covering a spread of payloads.
const RUNS = { numRuns: 40 }

const SEPARATOR = Buffer.from('--- BEGIN CIPHERTEXT ---\n', 'utf-8')
const CREATED = '2026-09-29T00:00:00Z'

// Key generation is the slow step, so a fixed pool is derived once and each
// case picks its recipients from it.
const POOL = Array.from({ length: 5 }, (_, i) =>
  mlKem.keypairFromMaster(new Uint8Array(32).fill(i + 1), 'kxco-pq-vault/property-tests/v1'))

// Seal to the given public keys, as the README's ENCRYPT example does.
function seal(plaintext, publicKeys) {
  const dek = generateDek()
  const nonce = generateNonce()
  const recipients = publicKeys.map((pk) => {
    const kid = computeKid(pk)
    const { ciphertext, sharedSecret } = mlKem.encapsulate(pk)
    return {
      kid,
      encapsulatedKey: Buffer.from(ciphertext).toString('hex'),
      wrappedDek: wrapDek(Buffer.from(sharedSecret), kid, dek).toString('hex'),
    }
  })
  const header = Buffer.from(serializeHeader({ recipients, nonce: nonce.toString('hex'), created: CREATED }), 'utf-8')
  return Buffer.concat([header, SEPARATOR, encryptPayload(dek, nonce, header, plaintext)])
}

// Open with one keypair, as the README's DECRYPT example does. Returns the
// plaintext or throws; there is no third outcome.
function open(envelope, key) {
  const myKid = computeKid(key.publicKey)
  const { header, canonicalHeader, ciphertext } = parseEnvelope(envelope)
  const block = header.recipients.find((r) => r.kid === myKid)
  if (!block) throw new KxcoVaultError('not a recipient in this envelope')
  const ss = Buffer.from(mlKem.decapsulate(Buffer.from(block.encapsulatedKey, 'hex'), key.secretKey))
  const dek = unwrapDek(ss, myKid, Buffer.from(block.wrappedDek, 'hex'))
  return decryptPayload(dek, Buffer.from(header.nonce, 'hex'), canonicalHeader, ciphertext)
}

// `size: 'max'` spreads lengths over the whole range; fast-check's default
// keeps them near ten.
const payload = fc.oneof(
  fc.uint8Array({ maxLength: 64, size: 'max' }),
  fc.uint8Array({ maxLength: 70_000, size: 'max' }),
  fc.string({ unit: 'binary', maxLength: 512, size: 'max' }).map((s) => Buffer.from(s, 'utf-8')),
)
// One to four distinct recipients, always leaving at least one pool key out.
const recipientSet = fc.uniqueArray(fc.integer({ min: 0, max: POOL.length - 1 }), { minLength: 1, maxLength: POOL.length - 1 })
const hex = (bytes) => fc.uint8Array({ minLength: bytes, maxLength: bytes }).map((b) => Buffer.from(b).toString('hex'))

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('envelope: every recipient opens any payload with their own key and gets it back byte for byte', () => {
  fc.assert(fc.property(payload, recipientSet, (plain, picks) => {
    const envelope = seal(plain, picks.map((i) => POOL[i].publicKey))
    return picks.every((i) => open(envelope, POOL[i]).equals(Buffer.from(plain)))
  }), RUNS)
})

test('envelope: a key that was not named cannot open it, even tried against every recipient block', () => {
  fc.assert(fc.property(payload, recipientSet, (plain, picks) => {
    const outsider = POOL[[...POOL.keys()].find((i) => !picks.includes(i))]
    const envelope = seal(plain, picks.map((i) => POOL[i].publicKey))
    assert.throws(() => open(envelope, outsider), KxcoVaultError)
    // Not only is its kid absent: its secret key unwraps no recipient's data key.
    const { header } = parseEnvelope(envelope)
    for (const block of header.recipients) {
      const ss = Buffer.from(mlKem.decapsulate(Buffer.from(block.encapsulatedKey, 'hex'), outsider.secretKey))
      assert.throws(() => unwrapDek(ss, block.kid, Buffer.from(block.wrappedDek, 'hex')), KxcoVaultError)
    }
    return true
  }), RUNS)
})

test('envelope: changing any one byte of the header, separator or ciphertext fails before plaintext is released', () => {
  fc.assert(fc.property(payload, recipientSet, fc.nat(), fc.integer({ min: 1, max: 255 }), (plain, picks, at, mask) => {
    const envelope = seal(plain, picks.map((i) => POOL[i].publicKey))
    const tampered = Buffer.from(envelope)
    tampered[at % tampered.length] ^= mask
    for (const i of picks) assert.throws(() => open(tampered, POOL[i]))
    return true
  }), RUNS)
})

test('recipient strings: encodePublicKey then decodePublicKey gives back the same key', () => {
  fc.assert(fc.property(fc.uint8Array({ minLength: 1184, maxLength: 1184 }), (key) => {
    const str = encodePublicKey(key)
    return str.startsWith('kxco1') && Buffer.from(decodePublicKey(str)).equals(Buffer.from(key))
  }), { numRuns: 200 })
})

test('recipient strings: a key of any other length is refused with KxcoVaultError', () => {
  // Any length up to twice a key, with extra weight just either side of 1184.
  const length = fc.oneof(fc.integer({ min: 0, max: 2400 }), fc.integer({ min: 1180, max: 1188 }))
  const wrongSize = length.filter((n) => n !== 1184).chain((n) => fc.uint8Array({ minLength: n, maxLength: n }))
  fc.assert(fc.property(wrongSize, (bytes) => {
    assert.throws(() => decodePublicKey(encodePublicKey(bytes)), KxcoVaultError)
    return true
  }), { numRuns: 200 })
})

test('header: serializeHeader then parseHeaderText gives back every field', () => {
  const recipient = fc.record({ kid: hex(8), encapsulatedKey: hex(1088), wrappedDek: hex(48) }, { noNullPrototype: true })
  const created = fc.date({ min: new Date('2000-01-01T00:00:00Z'), max: new Date('2100-01-01T00:00:00Z'), noInvalidDate: true })
    .map((d) => d.toISOString().replace(/\.\d+Z$/, 'Z'))
  fc.assert(fc.property(fc.array(recipient, { minLength: 1, maxLength: 5 }), hex(12), created, (recipients, nonce, when) => {
    const h = parseHeaderText(serializeHeader({ recipients, nonce, created: when }))
    assert.equal(h.algorithm, 'ml-kem-768+aes-256-gcm')
    assert.deepEqual(h.recipients, recipients)
    assert.equal(h.nonce, nonce)
    assert.equal(h.created, when)
    return true
  }), { numRuns: 100 })
})

test('parseEnvelope: arbitrary text or bytes either parse or throw KxcoVaultError, never anything else', () => {
  // Header fragments, so generated input reaches past the version and
  // separator checks into the field parsing rather than failing on line one.
  const fragment = fc.oneof(
    fc.constantFrom(
      'KXCO-VAULT/1.0\n', 'algorithm: ml-kem-768+aes-256-gcm\n', 'recipients: ',
      'recipient[0].kid: ', 'recipient[0].encapsulated_key: ', 'recipient[0].wrapped_dek: ',
      'recipient[1].kid: ', 'nonce: ', 'created: ', '--- BEGIN CIPHERTEXT ---\n', '\n', ': ',
    ),
    fc.oneof(fc.integer({ min: -3, max: 6 }), fc.maxSafeInteger()).map(String),
    fc.string({ unit: 'binary', maxLength: 40, size: 'max' }),
  )
  const input = fc.oneof(
    fc.array(fragment, { maxLength: 30, size: 'max' }).map((parts) => Buffer.from(parts.join(''), 'utf-8')),
    fc.string({ unit: 'binary', maxLength: 300, size: 'max' }).map((s) => Buffer.from(s, 'utf-8')),
    fc.uint8Array({ maxLength: 300, size: 'max' }).map((b) => Buffer.from(b)),
  )
  fc.assert(fc.property(input, (buf) => {
    let parsed
    try {
      parsed = parseEnvelope(buf)
    } catch (err) {
      return err instanceof KxcoVaultError
    }
    return Array.isArray(parsed.header.recipients) && parsed.header.recipients.length >= 1 && Buffer.isBuffer(parsed.ciphertext)
  }), { numRuns: 2000 })
})
