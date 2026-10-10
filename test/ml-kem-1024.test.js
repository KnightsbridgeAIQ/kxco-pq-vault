import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { keygen } from '../src/commands/keygen.js'
import { encrypt } from '../src/commands/encrypt.js'
import { decrypt } from '../src/commands/decrypt.js'
import { inspect } from '../src/commands/inspect.js'
import { serializeHeader, parseEnvelope, parseHeaderText } from '../src/envelope.js'
import { encodePublicKey, decodePublicKey } from '../src/bech32.js'
import { readIdentity } from '../src/util.js'
import { KxcoVaultError } from '../src/errors.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-768.json', import.meta.url), 'utf-8'))
// Made by the released kxco-pq-vault 1.3.0 from npm, with test/fixtures/make-vault-1.3.0.mjs.
const V130 = JSON.parse(readFileSync(new URL('./fixtures/vault-1.3.0-ml-kem-768.json', import.meta.url), 'utf-8'))

// stderr is collected too, so keygen's --master notice stays out of the test log.
function captureStdout(fn) {
  const chunks = []
  const errChunks = []
  const orig = process.stdout.write.bind(process.stdout)
  const origErr = process.stderr.write.bind(process.stderr)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  process.stderr.write = (chunk) => { errChunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig; process.stderr.write = origErr })
    .then((rc) => ({ rc, out: chunks.join(''), err: errChunks.join('') }))
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

test('keygen: ML-KEM-1024 is the default, a 1568-byte key that seals ml-kem-1024+aes-256-gcm and round-trips', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco')
  assert.ok(id.content.includes('algorithm: ml-kem-1024\n'))
  const { algorithm, publicKey, secretKey } = readIdentity(id.path)
  assert.equal(algorithm, 'ml-kem-1024')
  assert.equal(publicKey.length, 1568)
  assert.equal(secretKey.length, 3168)
  assert.equal(decodePublicKey(id.recipient).length, 1568)

  const sealed = await seal(dir, [id.recipient], 'the default')
  const { header } = parseEnvelope(readFileSync(sealed))
  assert.equal(header.algorithm, 'ml-kem-1024+aes-256-gcm')
  assert.equal(header.recipients[0].encapsulatedKey.length, 1568 * 2)
  const out = join(dir, 'out.txt')
  await captureStdout(() => decrypt([sealed, `--identity=${id.path}`, `--out=${out}`]))
  assert.equal(readFileSync(out, 'utf-8'), 'the default')
}))

test('keygen --algorithm ml-kem-768: still makes an ML-KEM-768 identity, and it round-trips', () => withDir(async (dir) => {
  const id = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-768'])
  assert.ok(id.content.includes('algorithm: ml-kem-768\n'))
  assert.equal(readIdentity(id.path).publicKey.length, 1184)

  const sealed = await seal(dir, [id.recipient], 'chosen on purpose')
  const { header } = parseEnvelope(readFileSync(sealed))
  assert.equal(header.algorithm, 'ml-kem-768+aes-256-gcm')
  assert.equal(header.recipients[0].encapsulatedKey.length, 1088 * 2)
  const out = join(dir, 'out.txt')
  await captureStdout(() => decrypt([sealed, `--identity=${id.path}`, `--out=${out}`]))
  assert.equal(readFileSync(out, 'utf-8'), 'chosen on purpose')
}))

test('keygen: an unknown --algorithm is refused', async () => {
  await assert.rejects(() => keygen(['--out=x.kxco', '--algorithm=ml-kem-512']), KxcoVaultError)
})

test('keygen --master --algorithm ml-kem-1024: deterministic, and unrelated to the ML-KEM-768 key', () => withDir(async (dir) => {
  const master = 'ab'.repeat(32)
  const flags = [`--master=${master}`, '--label=archive']
  const a = await makeKeypair(dir, 'a.kxco', [...flags, '--algorithm=ml-kem-1024'])
  const b = await makeKeypair(dir, 'b.kxco', [...flags, '--algorithm=ml-kem-1024'])
  const c = await makeKeypair(dir, 'c.kxco', [...flags, '--algorithm=ml-kem-768'])
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
  const a = await makeKeypair(dir, 'a.kxco', ['--algorithm=ml-kem-768'])
  const b = await makeKeypair(dir, 'b.kxco', ['--algorithm=ml-kem-1024'])
  writeFileSync(join(dir, 'p.txt'), 'x')
  await assert.rejects(
    () => encrypt([join(dir, 'p.txt'), `--recipient=${a.recipient}`, `--recipient=${b.recipient}`]),
    (err) => err instanceof KxcoVaultError && /mix ML-KEM-768 and ML-KEM-1024/.test(err.message),
  )
}))

test('decrypt: an identity of one parameter set is refused on an envelope of the other', () => withDir(async (dir) => {
  const k768 = await makeKeypair(dir, 'k768.kxco', ['--algorithm=ml-kem-768'])
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
  const id = await makeKeypair(dir, 'k.kxco', ['--algorithm=ml-kem-768'])
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
  for (const want of ['ml-kem-768', 'ml-kem-1024']) {
    const id = await makeKeypair(dir, 'k.kxco', [`--algorithm=${want}`])
    writeFileSync(id.path, id.content.replace(/^algorithm: .*\n/m, ''))
    assert.equal(readIdentity(id.path).algorithm, want)
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
  // A line changed to name the other set after the header was written is
  // refused by the parser, on the encapsulated key's length.
  const relabel = (text, from, to) => {
    const out = text.replace(`algorithm: ${from}`, `algorithm: ${to}`)
    assert.notEqual(out, text)
    return out
  }
  const h768 = serializeHeader({ ...base, recipients: r(1088) })
  const h1024 = serializeHeader({ ...base, recipients: r(1568) })
  assert.throws(() => parseHeaderText(relabel(h768, 'ml-kem-768+', 'ml-kem-1024+')), KxcoVaultError)
  assert.throws(() => parseHeaderText(relabel(h1024, 'ml-kem-1024+', 'ml-kem-768+')), KxcoVaultError)
  assert.throws(() => serializeHeader({ ...base, recipients: r(1088), algorithm: 'ml-kem-512+aes-256-gcm' }),
    KxcoVaultError)
})

const HEADER = { nonce: 'cc'.repeat(12), created: '2026-10-10T00:00:00Z' }
const recipientsOf = (...sizes) => sizes.map((bytes, i) => ({
  kid: String(i).repeat(16), encapsulatedKey: 'bb'.repeat(bytes), wrappedDek: 'dd'.repeat(48),
}))

// The header is the AES-GCM additional data, so a wrong algorithm line can
// never be corrected once a payload is sealed under it. serializeHeader takes
// the set from the encapsulated keys rather than from a default.
test('serializeHeader: with no algorithm, the encapsulated keys decide the line', () => {
  const line = (recipients) => serializeHeader({ ...HEADER, recipients }).split('\n')[1]
  assert.equal(line(recipientsOf(1088)), 'algorithm: ml-kem-768+aes-256-gcm')
  assert.equal(line(recipientsOf(1088, 1088)), 'algorithm: ml-kem-768+aes-256-gcm')
  assert.equal(line(recipientsOf(1568)), 'algorithm: ml-kem-1024+aes-256-gcm')
  assert.equal(line(recipientsOf(1568, 1568)), 'algorithm: ml-kem-1024+aes-256-gcm')
  for (const [size, algorithm] of [[1088, 'ml-kem-768+aes-256-gcm'], [1568, 'ml-kem-1024+aes-256-gcm']]) {
    assert.equal(serializeHeader({ ...HEADER, recipients: recipientsOf(size), algorithm }),
      serializeHeader({ ...HEADER, recipients: recipientsOf(size) }))
  }
})

test('serializeHeader: an algorithm that disagrees with the encapsulated keys is refused', () => {
  for (const [size, algorithm, keys] of [
    [1088, 'ml-kem-1024+aes-256-gcm', 'ml-kem-768+aes-256-gcm'],
    [1568, 'ml-kem-768+aes-256-gcm', 'ml-kem-1024+aes-256-gcm'],
  ]) {
    assert.throws(() => serializeHeader({ ...HEADER, recipients: recipientsOf(size), algorithm }),
      (err) => err instanceof KxcoVaultError && err.message ===
        `serializeHeader: algorithm ${algorithm} disagrees with the encapsulated keys, which are ${keys}`)
  }
})

test('serializeHeader: recipients from both parameter sets are refused, with or without an algorithm', () => {
  for (const algorithm of [undefined, 'ml-kem-768+aes-256-gcm', 'ml-kem-1024+aes-256-gcm']) {
    assert.throws(() => serializeHeader({ ...HEADER, recipients: recipientsOf(1088, 1568), algorithm }),
      (err) => err instanceof KxcoVaultError && /recipients mix ML-KEM-768 and ML-KEM-1024/.test(err.message))
  }
})

test('serializeHeader: an encapsulated key of neither length, or no recipient at all, is refused', () => {
  for (const recipients of [recipientsOf(1087), recipientsOf(1569), recipientsOf(1184), []]) {
    assert.throws(() => serializeHeader({ ...HEADER, recipients }), KxcoVaultError)
  }
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

// Bytes written by the released kxco-pq-vault 1.3.0, the last version whose
// keygen made ML-KEM-768 keys by default. They have to open exactly as they did.
test('an identity and envelope made by kxco-pq-vault 1.3.0 open under this version, byte for byte', () => withDir(async (dir) => {
  assert.equal(V130.madeBy, 'kxco-pq-vault@1.3.0')
  const identity = join(dir, 'v130.kxco')
  const sealed = join(dir, 'v130.bin.kxco')
  const out = join(dir, 'v130.bin')
  writeFileSync(identity, V130.identity, 'utf-8')
  writeFileSync(sealed, Buffer.from(V130.envelopeBase64, 'base64'))
  const id = readIdentity(identity)
  assert.equal(id.algorithm, 'ml-kem-768')
  assert.equal(id.publicKey.length, 1184)
  const { header } = parseEnvelope(readFileSync(sealed))
  assert.equal(header.algorithm, 'ml-kem-768+aes-256-gcm')
  assert.equal(header.recipients[0].encapsulatedKey.length, 1088 * 2)
  const { rc } = await captureStdout(() => decrypt([sealed, `--identity=${identity}`, `--out=${out}`]))
  assert.equal(rc, 0)
  assert.deepEqual(readFileSync(out), Buffer.from(V130.plaintextBase64, 'base64'))
}))

test('the 1.3.0 envelope relabelled as ML-KEM-1024 is refused', () => withDir(async (dir) => {
  const identity = join(dir, 'v130.kxco')
  const sealed = join(dir, 'v130.bin.kxco')
  writeFileSync(identity, V130.identity, 'utf-8')
  const bytes = Buffer.from(V130.envelopeBase64, 'base64')
  const relabelled = Buffer.from(bytes.toString('latin1')
    .replace('algorithm: ml-kem-768+aes-256-gcm', 'algorithm: ml-kem-1024+aes-256-gcm'), 'latin1')
  assert.notDeepEqual(relabelled, bytes)
  writeFileSync(sealed, relabelled)
  await assert.rejects(
    () => decrypt([sealed, `--identity=${identity}`, `--out=${join(dir, 'o')}`]),
    (err) => err instanceof KxcoVaultError && /encapsulated_key must be 3136 hex characters/.test(err.message),
  )
}))

test('keygen --master with --algorithm ml-kem-768 re-derives the key 1.3.0 derived; without it, ML-KEM-1024', () => withDir(async (dir) => {
  const { master, label, identity } = V130.derived
  const flags = [`--master=${master}`, `--label=${label}`]
  const again = await makeKeypair(dir, 'a.kxco', [...flags, '--algorithm=ml-kem-768'])
  assert.equal(again.recipient, identity.match(/^public: (kxco1\S+)/m)[1])
  assert.equal(again.content.match(/^secret: .*$/m)[0], identity.match(/^secret: .*$/m)[0])
  const fresh = await makeKeypair(dir, 'b.kxco', flags)
  assert.equal(readIdentity(fresh.path).algorithm, 'ml-kem-1024')
}))

// The other direction: an envelope this version seals to an ML-KEM-768 key
// opens under the released 1.3.0, so a recipient who has not upgraded can
// still read it.
test('an envelope this version seals to the 1.3.0 identity opens under kxco-pq-vault 1.3.0', () => withDir(async (dir) => {
  const bin = fileURLToPath(new URL('../node_modules/kxco-pq-vault-130/bin/kxco-vault.js', import.meta.url))
  assert.equal(execFileSync(process.execPath, [bin, '--version'], { encoding: 'utf-8' }), 'kxco-pq-vault 1.3.0\n')
  const identity = join(dir, 'v130.kxco')
  writeFileSync(identity, V130.identity, 'utf-8')
  const sealed = await seal(dir, [`@${identity}`], 'from 2.0.0 to 1.3.0')
  assert.equal(parseEnvelope(readFileSync(sealed)).header.algorithm, 'ml-kem-768+aes-256-gcm')
  const out = join(dir, 'out.txt')
  execFileSync(process.execPath, [bin, 'decrypt', sealed, '--identity', identity, '--out', out])
  assert.equal(readFileSync(out, 'utf-8'), 'from 2.0.0 to 1.3.0')
}))
