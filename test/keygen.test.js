import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { keygen } from '../src/commands/keygen.js'
import { recipient } from '../src/commands/recipient.js'
import { bech32m } from '@scure/base'
import { decodePublicKey } from '../src/bech32.js'
import { KxcoVaultError } from '../src/errors.js'

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

test('keygen: creates valid identity file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const out = join(dir, 'keypair.kxco')
    const { rc } = await captureStdout(() => keygen([`--out=${out}`]))
    assert.equal(rc, 0)
    const content = readFileSync(out, 'utf-8')
    assert.ok(content.startsWith('KXCO-VAULT-IDENTITY/1.0\n'))
    assert.ok(content.includes('algorithm: ml-kem-1024\n'))
    assert.match(content, /^public: kxco1/m)
    assert.match(content, /^secret: [0-9a-f]{6336}\n/m) // 3168 bytes hex
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

test('decodePublicKey: a checksum-valid kxco1 string whose padding is wrong throws KxcoVaultError', () => {
  // Checksums hold, so the failure is in turning 5-bit words back into bytes.
  for (const words of [[31], [1, 1], [...Array(1894).fill(0), 1]]) {
    assert.throws(() => decodePublicKey(bech32m.encode('kxco', words, false)), KxcoVaultError, JSON.stringify(words.slice(-2)))
  }
})

// The CLI binary, run as a script would run it, so stdout and stderr are the
// real separate streams.
const BIN = fileURLToPath(new URL('../bin/kxco-vault.js', import.meta.url))
const MASTER_NOTICE =
  'kxco-vault: --master without --algorithm derives an ML-KEM-1024 key from 2.0.0; ' +
  'pass --algorithm ml-kem-768 to re-derive a key made earlier\n'

function runKeygen(out, extra) {
  const r = spawnSync(process.execPath, [BIN, 'keygen', '--out', out, ...extra])
  assert.equal(r.status, 0, r.stderr.toString('utf-8'))
  return { stdout: r.stdout, stderr: r.stderr.toString('utf-8') }
}

test('keygen --master without --algorithm: exactly one notice line on stderr, and stdout byte-identical to the silent path', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const out = join(dir, 'kp.kxco')
    const flags = ['--master', 'c'.repeat(64), '--label', 'notice']
    const bare = runKeygen(out, flags)
    assert.equal(bare.stderr, MASTER_NOTICE)
    assert.equal(bare.stderr.split('\n').length, 2)
    // Same master, label and set with --algorithm given: no notice, and the
    // bytes a script reads from stdout do not change.
    const explicit = runKeygen(out, [...flags, '--algorithm', 'ml-kem-1024'])
    assert.equal(explicit.stderr, '')
    assert.ok(bare.stdout.length > 0)
    assert.ok(bare.stdout.equals(explicit.stdout))
    assert.ok(!bare.stdout.toString('utf-8').includes('--algorithm'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('keygen: no notice when --algorithm is given, or when there is no --master', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-test-'))
  try {
    const master = ['--master', 'd'.repeat(64), '--label', 'quiet']
    for (const extra of [
      [...master, '--algorithm', 'ml-kem-768'],
      [...master, '--algorithm', 'ml-kem-1024'],
      ['--algorithm', 'ml-kem-768'],
      [],
    ]) {
      assert.equal(runKeygen(join(dir, 'kp.kxco'), extra).stderr, '', JSON.stringify(extra))
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
