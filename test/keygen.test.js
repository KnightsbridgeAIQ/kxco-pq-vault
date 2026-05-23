import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { keygen } from '../src/commands/keygen.js'
import { recipient } from '../src/commands/recipient.js'

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

test('keygen: creates valid identity file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const out = join(dir, 'keypair.kxco')
    const { rc } = await captureStdout(() => keygen([`--out=${out}`]))
    assert.equal(rc, 0)
    const content = readFileSync(out, 'utf-8')
    assert.ok(content.startsWith('KXCO-VAULT-IDENTITY/1.0\n'))
    assert.ok(content.includes('algorithm: ml-kem-768\n'))
    assert.match(content, /^public: kxco1/m)
    assert.match(content, /^secret: [0-9a-f]{4800}\n/m) // 2400 bytes hex
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('keygen: random keygen produces unique keypairs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const out1 = join(dir, 'kp1.kxco')
    const out2 = join(dir, 'kp2.kxco')
    await captureStdout(() => keygen([`--out=${out1}`]))
    await captureStdout(() => keygen([`--out=${out2}`]))
    const pk1 = readFileSync(out1, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    const pk2 = readFileSync(out2, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    assert.notEqual(pk1, pk2)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('keygen --master: deterministic from same master + label', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const master = 'a'.repeat(64) // 32 hex bytes
    const out1 = join(dir, 'kp1.kxco')
    const out2 = join(dir, 'kp2.kxco')
    await captureStdout(() => keygen([`--out=${out1}`, `--master=${master}`, '--label=test-label']))
    await captureStdout(() => keygen([`--out=${out2}`, `--master=${master}`, '--label=test-label']))
    const pk1 = readFileSync(out1, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    const pk2 = readFileSync(out2, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    assert.equal(pk1, pk2) // same master+label → same keypair
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('keygen --master: different labels produce different keypairs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const master = 'b'.repeat(64)
    const out1 = join(dir, 'kp1.kxco')
    const out2 = join(dir, 'kp2.kxco')
    await captureStdout(() => keygen([`--out=${out1}`, `--master=${master}`, '--label=labelA']))
    await captureStdout(() => keygen([`--out=${out2}`, `--master=${master}`, '--label=labelB']))
    const pk1 = readFileSync(out1, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    const pk2 = readFileSync(out2, 'utf-8').match(/^public: (kxco1\S+)/m)[1]
    assert.notEqual(pk1, pk2)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('recipient: prints kxco1... from identity file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const out = join(dir, 'keypair.kxco')
    await captureStdout(() => keygen([`--out=${out}`]))

    const { rc, out: stdout } = await captureStdout(() => recipient([out]))
    assert.equal(rc, 0)
    assert.match(stdout.trim(), /^kxco1/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('recipient: output matches public field in identity file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const keyfile = join(dir, 'keypair.kxco')
    await captureStdout(() => keygen([`--out=${keyfile}`]))

    const { out: stdout } = await captureStdout(() => recipient([keyfile]))
    const fileContent = readFileSync(keyfile, 'utf-8')
    const filePub = fileContent.match(/^public: (kxco1\S+)/m)[1]
    assert.equal(stdout.trim(), filePub)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
