import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import {
  generateDek,
  generateNonce,
  computeKid,
  wrapDek,
  unwrapDek,
  encryptPayload,
  decryptPayload,
} from '../src/crypto.js'
import { KxcoVaultError } from '../src/errors.js'

test('generateDek: produces 32 random bytes', () => {
  const dek = generateDek()
  assert.equal(dek.length, 32)
  assert.notDeepEqual(dek, generateDek()) // statistically impossible collision
})

test('generateNonce: produces 12 random bytes', () => {
  const n = generateNonce()
  assert.equal(n.length, 12)
})

test('computeKid: 16 hex chars, deterministic', () => {
  const pk = randomBytes(1184)
  const kid1 = computeKid(pk)
  const kid2 = computeKid(pk)
  assert.equal(kid1.length, 16)
  assert.match(kid1, /^[0-9a-f]{16}$/)
  assert.equal(kid1, kid2)
})

test('computeKid: different keys produce different kids', () => {
  const kid1 = computeKid(randomBytes(1184))
  const kid2 = computeKid(randomBytes(1184))
  assert.notEqual(kid1, kid2)
})

test('wrapDek / unwrapDek: round-trip', () => {
  const ss = randomBytes(32)
  const kid = randomBytes(8).toString('hex')
  const dek = randomBytes(32)
  const wrapped = wrapDek(ss, kid, dek)
  assert.equal(wrapped.length, 48)
  const recovered = unwrapDek(ss, kid, wrapped)
  assert.deepEqual(recovered, dek)
})

test('unwrapDek: throws on tampered ciphertext', () => {
  const ss = randomBytes(32)
  const kid = randomBytes(8).toString('hex')
  const dek = randomBytes(32)
  const wrapped = wrapDek(ss, kid, dek)
  wrapped[0] ^= 0xff
  assert.throws(() => unwrapDek(ss, kid, wrapped), KxcoVaultError)
})

test('unwrapDek: throws on wrong ss', () => {
  const ss = randomBytes(32)
  const wrongSs = randomBytes(32)
  const kid = randomBytes(8).toString('hex')
  const dek = randomBytes(32)
  const wrapped = wrapDek(ss, kid, dek)
  assert.throws(() => unwrapDek(wrongSs, kid, wrapped), KxcoVaultError)
})

test('encryptPayload / decryptPayload: round-trip', () => {
  const dek = randomBytes(32)
  const nonce = randomBytes(12)
  const ad = Buffer.from('canonical-header', 'utf-8')
  const plaintext = Buffer.from('hello, post-quantum world')
  const payload = encryptPayload(dek, nonce, ad, plaintext)
  assert.equal(payload.length, plaintext.length + 16) // +16 auth tag
  const recovered = decryptPayload(dek, nonce, ad, payload)
  assert.deepEqual(recovered, plaintext)
})

test('decryptPayload: throws on tampered ciphertext', () => {
  const dek = randomBytes(32)
  const nonce = randomBytes(12)
  const ad = Buffer.from('header', 'utf-8')
  const payload = encryptPayload(dek, nonce, ad, Buffer.from('secret'))
  payload[0] ^= 0x01
  assert.throws(() => decryptPayload(dek, nonce, ad, payload), KxcoVaultError)
})

test('decryptPayload: throws on tampered ad (header)', () => {
  const dek = randomBytes(32)
  const nonce = randomBytes(12)
  const ad = Buffer.from('original-header', 'utf-8')
  const payload = encryptPayload(dek, nonce, ad, Buffer.from('secret'))
  const tamperedAd = Buffer.from('tampered-header', 'utf-8')
  assert.throws(() => decryptPayload(dek, nonce, tamperedAd, payload), KxcoVaultError)
})

test('decryptPayload: throws on wrong nonce', () => {
  const dek = randomBytes(32)
  const nonce = randomBytes(12)
  const wrongNonce = randomBytes(12)
  const ad = Buffer.from('header', 'utf-8')
  const payload = encryptPayload(dek, nonce, ad, Buffer.from('secret'))
  assert.throws(() => decryptPayload(dek, wrongNonce, ad, payload), KxcoVaultError)
})
