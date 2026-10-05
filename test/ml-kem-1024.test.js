import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { keygen } from '../src/commands/keygen.js'
import { encrypt } from '../src/commands/encrypt.js'
import { decrypt } from '../src/commands/decrypt.js'
import { inspect } from '../src/commands/inspect.js'
import { serializeHeader, parseEnvelope, parseHeaderText } from '../src/envelope.js'
import { encodePublicKey, decodePublicKey } from '../src/bech32.js'
import { readIdentity } from '../src/util.js'
import { KxcoVaultError } from '../src/errors.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-768.json', import.meta.url), 'utf-8'))

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

async function makeKeypair(dir, name, extra = []) {
  const path = join(dir, name)
  await captureStdout(() => keygen([`--out=${path}`, ...extra]))
  const content = readFileSync(path, 'utf-8')
  return { path, content, recipient: content.match(/^public: (kxco1\S+)/m)[1] }
}

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-1024-'))
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }))
}

async function seal(dir, recipients, text = 'category five') {
  const plain = join(dir, 'plain.txt')
  const sealed = join(dir, 'plain.txt.kxco')
  writeFileSync(plain, text, 'utf-8')
  await captureStdout(() => encrypt([plain, ...recipients.map((r) => `--recipient=${r}`), `--out=${sealed}`]))
  return sealed
}

test('keygen --algorithm ml-kem-1024: writes an ML-KEM-1024 identity', () => withDir(async (dir) => {
  const { path, content } = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-1024'])
  assert.ok(content.includes('algorithm: ml-kem-1024\n'))
  assert.match(content, /^secret: [0-9a-f]{6336}\n/m) // 3168 bytes hex
  const id = readIdentity(path)
  assert.equal(id.algorithm, 'ml-kem-1024')
  assert.equal(id.publicKey.length, 1568)
  assert.equal(id.secretKey.length, 3168)
}))

test('keygen: ML-KEM-768 stays the default', () => withDir(async (dir) => {
  const { path, content } = await makeKeypair(dir, 'k.kxco')
  assert.ok(content.includes('algorithm: ml-kem-768\n'))
  assert.equal(readIdentity(path).algorithm, 'ml-kem-768')
  assert.equal(readIdentity(path).publicKey.length, 1184)
}))

test('keygen: an unknown --algorithm is refused', async () => {
  await assert.rejects(() => keygen(['--out=x.kxco', '--algorithm=ml-kem-512']), KxcoVaultError)
})

test('keygen --master --algorithm ml-kem-1024: deterministic, and unrelated to the ML-KEM-768 key', () => withDir(async (dir) => {
  const master = 'ab'.repeat(32)
  const flags = [`--master=${master}`, '--label=archive']
  const a = await makeKeypair(dir, 'a.kxco', [...flags, '--algorithm=ml-kem-1024'])
  const b = await makeKeypair(dir, 'b.kxco', [...flags, '--algorithm=ml-kem-1024'])
  const c = await makeKeypair(dir, 'c.kxco', flags)
  assert.equal(a.recipient, b.recipient)
  assert.notEqual(a.recipient, c.recipient)
}))

test('encrypt + decrypt: an ML-KEM-1024 recipient round-trips and the header names ML-KEM-1024', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-1024'])
  const sealed = await seal(dir, [id.recipient], 'harvest now, decrypt never')
  const { header } = parseEnvelope(readFileSync(sealed))
  assert.equal(header.algorithm, 'ml-kem-1024+aes-256-gcm')
  assert.equal(header.recipients[0].encapsulatedKey.length, 1568 * 2)

  const out = join(dir, 'out.txt')
  const { rc } = await captureStdout(() => decrypt([sealed, `--identity=${id.path}`, `--out=${out}`]))
  assert.equal(rc, 0)
  assert.equal(readFileSync(out, 'utf-8'), 'harvest now, decrypt never')

  const { out: shown } = await captureStdout(() => inspect([sealed]))
  assert.match(shown, /algorithm: {2}ml-kem-1024\+aes-256-gcm/)
}))

test('multi-recipient ML-KEM-1024: each recipient opens the same envelope', () => withDir(async (dir) => {
  const alice = await makeKeypair(dir, 'alice.kxco', ['--algorithm=ml-kem-1024'])
  const bob = await makeKeypair(dir, 'bob.kxco', ['--algorithm=ml-kem-1024'])
  const sealed = await seal(dir, [alice.recipient, `@${bob.path}`], 'for both')
  for (const who of [alice, bob]) {
    const out = join(dir, 'out.txt')
    await captureStdout(() => decrypt([sealed, `--identity=${who.path}`, `--out=${out}`]))
    assert.equal(readFileSync(out, 'utf-8'), 'for both')
  }
}))

test('encrypt: recipients from both parameter sets in one envelope are refused', () => withDir(async (dir) => {
  const a = await makeKeypair(dir, 'a.kxco')
  const b = await makeKeypair(dir, 'b.kxco', ['--algorithm=ml-kem-1024'])
  writeFileSync(join(dir, 'p.txt'), 'x')
  await assert.rejects(
    () => encrypt([join(dir, 'p.txt'), `--recipient=${a.recipient}`, `--recipient=${b.recipient}`]),
    (err) => err instanceof KxcoVaultError && /mix ML-KEM-768 and ML-KEM-1024/.test(err.message),
  )
}))

test('decrypt: an identity of one parameter set is refused on an envelope of the other', () => withDir(async (dir) => {
  const k768 = await makeKeypair(dir, 'k768.kxco')
  const k1024 = await makeKeypair(dir, 'k1024.kxco', ['--algorithm=ml-kem-1024'])
  const sealed1024 = await seal(dir, [k1024.recipient])
  await assert.rejects(
    () => decrypt([sealed1024, `--identity=${k768.path}`, `--out=${join(dir, 'o')}`]),
    (err) => err instanceof KxcoVaultError &&
      err.message === 'identity is ml-kem-768 but the envelope is ml-kem-1024+aes-256-gcm',
  )
  const sealed768 = await seal(dir, [k768.recipient])
  await assert.rejects(
    () => decrypt([sealed768, `--identity=${k1024.path}`, `--out=${join(dir, 'o')}`]),
    (err) => err instanceof KxcoVaultError &&
      err.message === 'identity is ml-kem-1024 but the envelope is ml-kem-768+aes-256-gcm',
  )
}))

test('decrypt: an ML-KEM-768 envelope relabelled as ML-KEM-1024 is refused', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco')
  const sealed = await seal(dir, [id.recipient])
  const bytes = readFileSync(sealed)
  const relabelled = Buffer.from(bytes.toString('latin1')
    .replace('algorithm: ml-kem-768+aes-256-gcm', 'algorithm: ml-kem-1024+aes-256-gcm'), 'latin1')
  assert.notDeepEqual(relabelled, bytes)
  writeFileSync(sealed, relabelled)
  await assert.rejects(
    () => decrypt([sealed, `--identity=${id.path}`, `--out=${join(dir, 'o')}`]),
    KxcoVaultError,
  )
}))

test('readIdentity: an algorithm line that disagrees with the key is refused', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-1024'])
  writeFileSync(id.path, id.content.replace('algorithm: ml-kem-1024', 'algorithm: ml-kem-768'))
  assert.throws(() => readIdentity(id.path),
    (err) => err instanceof KxcoVaultError && /says ml-kem-768 but its public key is ml-kem-1024/.test(err.message))
}))

test('readIdentity: a file without an algorithm line is read by its key', () => withDir(async (dir) => {
  for (const extra of [[], ['--algorithm=ml-kem-1024']]) {
    const id = await makeKeypair(dir, 'k.kxco', extra)
    writeFileSync(id.path, id.content.replace(/^algorithm: .*\n/m, ''))
    assert.equal(readIdentity(id.path).algorithm, extra.length ? 'ml-kem-1024' : 'ml-kem-768')
  }
}))

test('readIdentity: an ML-KEM-1024 key with an ML-KEM-768-sized secret is refused', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-1024'])
  writeFileSync(id.path, id.content.replace(/^secret: ([0-9a-f]+)$/m, (_, hex) => `secret: ${hex.slice(0, 4800)}`))
  assert.throws(() => readIdentity(id.path),
    (err) => err instanceof KxcoVaultError && /expected 3168 bytes, got 2400/.test(err.message))
}))

test('recipient strings: a 1568-byte ML-KEM-1024 key round-trips', () => {
  const key = Buffer.alloc(1568, 7)
  assert.deepEqual(Buffer.from(decodePublicKey(encodePublicKey(key))), key)
})

test('header: each algorithm line fixes its own encapsulated key length', () => {
  const base = { nonce: 'cc'.repeat(12), created: '2026-10-05T00:00:00Z' }
  const r = (bytes) => [{ kid: 'aa'.repeat(8), encapsulatedKey: 'bb'.repeat(bytes), wrappedDek: 'dd'.repeat(48) }]
  const h = parseHeaderText(serializeHeader({ ...base, recipients: r(1568), algorithm: 'ml-kem-1024+aes-256-gcm' }))
  assert.equal(h.algorithm, 'ml-kem-1024+aes-256-gcm')
  assert.throws(() => parseHeaderText(serializeHeader({ ...base, recipients: r(1088), algorithm: 'ml-kem-1024+aes-256-gcm' })),
    KxcoVaultError)
  assert.throws(() => parseHeaderText(serializeHeader({ ...base, recipients: r(1568) })), KxcoVaultError)
  assert.throws(() => serializeHeader({ ...base, recipients: r(1088), algorithm: 'ml-kem-512+aes-256-gcm' }),
    KxcoVaultError)
})

// Bytes written by kxco-pq-vault 1.1.8, before ML-KEM-1024 was added here.
// They have to open exactly as they did.
test('an envelope sealed by 1.1.8 still opens, byte for byte', () => withDir(async (dir) => {
  const identity = join(dir, 'legacy.kxco')
  const sealed = join(dir, 'legacy.txt.kxco')
  const out = join(dir, 'legacy.txt')
  writeFileSync(identity, LEGACY.identity, 'utf-8')
  writeFileSync(sealed, Buffer.from(LEGACY.envelopeBase64, 'base64'))
  assert.equal(parseEnvelope(readFileSync(sealed)).header.algorithm, 'ml-kem-768+aes-256-gcm')
  const { rc } = await captureStdout(() => decrypt([sealed, `--identity=${identity}`, `--out=${out}`]))
  assert.equal(rc, 0)
  assert.equal(readFileSync(out, 'utf-8'), LEGACY.plaintext)
}))
