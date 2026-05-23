import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { keygen } from '../src/commands/keygen.js'
import { encrypt } from '../src/commands/encrypt.js'
import { decrypt } from '../src/commands/decrypt.js'
import { inspect } from '../src/commands/inspect.js'
import { KxcoVaultError } from '../src/errors.js'

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

async function makeKeypair(dir, name = 'keypair.kxco') {
  const path = join(dir, name)
  await captureStdout(() => keygen([`--out=${path}`]))
  const content = readFileSync(path, 'utf-8')
  const pubMatch = content.match(/^public: (kxco1\S+)/m)
  return { path, recipient: pubMatch[1] }
}

test('encrypt + decrypt: single recipient, byte-for-byte recovery', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity, recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    const decFile = join(dir, 'secret.dec.txt')
    const original = 'harvest now, decrypt never — post-quantum.'
    writeFileSync(plainFile, original, 'utf-8')

    const { rc: encRc } = await captureStdout(() =>
      encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]),
    )
    assert.equal(encRc, 0)

    const { rc: decRc } = await captureStdout(() =>
      decrypt([cipherFile, `--identity=${identity}`, `--out=${decFile}`]),
    )
    assert.equal(decRc, 0)
    assert.equal(readFileSync(decFile, 'utf-8'), original)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('encrypt + decrypt: binary file round-trip', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity, recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'data.bin')
    const cipherFile = join(dir, 'data.bin.kxco')
    const decFile = join(dir, 'data.dec.bin')
    const original = Buffer.from([0x00, 0xff, 0x01, 0xfe, 0x42, 0xde, 0xad, 0xbe, 0xef])
    writeFileSync(plainFile, original)

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))
    await captureStdout(() => decrypt([cipherFile, `--identity=${identity}`, `--out=${decFile}`]))
    assert.deepEqual(readFileSync(decFile), original)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('decrypt: wrong identity throws KxcoVaultError (kid not in envelope)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { recipient: recipientStr } = await makeKeypair(dir, 'alice.kxco')
    const { path: bobIdentity } = await makeKeypair(dir, 'bob.kxco')
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    writeFileSync(plainFile, 'secret message', 'utf-8')

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))

    await assert.rejects(
      () => captureStdout(() => decrypt([cipherFile, `--identity=${bobIdentity}`, `--out=${join(dir, 'out.txt')}`])),
      (err) => {
        assert.ok(err instanceof KxcoVaultError)
        assert.equal(err.message, 'recipient kid not in envelope')
        return true
      },
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('decrypt: tampered ciphertext fails authentication', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity, recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    writeFileSync(plainFile, 'top secret', 'utf-8')

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))

    // Flip a byte in the ciphertext portion (last 100 bytes, well past the header)
    const buf = readFileSync(cipherFile)
    buf[buf.length - 1] ^= 0xff
    writeFileSync(cipherFile, buf)

    await assert.rejects(
      () => captureStdout(() => decrypt([cipherFile, `--identity=${identity}`, `--out=${join(dir, 'out.txt')}`])),
      (err) => {
        assert.ok(err instanceof KxcoVaultError)
        assert.ok(err.message.includes('authentication failed'))
        return true
      },
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('decrypt: tampered header (nonce swap) fails authentication', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity, recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    writeFileSync(plainFile, 'header-protected data', 'utf-8')

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))

    // Flip a byte in the nonce header field
    const content = readFileSync(cipherFile, 'utf-8')
    const tampered = content.replace(/^(nonce: )([0-9a-f]+)/m, (_, prefix, hex) => {
      const arr = [...hex]
      arr[0] = arr[0] === 'a' ? 'b' : 'a'
      return prefix + arr.join('')
    })
    writeFileSync(cipherFile, tampered, 'utf-8')

    await assert.rejects(
      () => captureStdout(() => decrypt([cipherFile, `--identity=${identity}`, `--out=${join(dir, 'out.txt')}`])),
      (err) => {
        assert.ok(err instanceof KxcoVaultError)
        assert.ok(err.message.includes('authentication failed'))
        return true
      },
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('multi-recipient: both alice and bob can decrypt', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: aliceId, recipient: aliceRec } = await makeKeypair(dir, 'alice.kxco')
    const { path: bobId, recipient: bobRec } = await makeKeypair(dir, 'bob.kxco')
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    const original = 'shared secret for alice and bob'
    writeFileSync(plainFile, original, 'utf-8')

    await captureStdout(() =>
      encrypt([plainFile, `--recipient=${aliceRec}`, `--recipient=${bobRec}`, `--out=${cipherFile}`]),
    )

    const aliceOut = join(dir, 'alice.dec.txt')
    const bobOut = join(dir, 'bob.dec.txt')

    const { rc: aliceRc } = await captureStdout(() =>
      decrypt([cipherFile, `--identity=${aliceId}`, `--out=${aliceOut}`]),
    )
    const { rc: bobRc } = await captureStdout(() =>
      decrypt([cipherFile, `--identity=${bobId}`, `--out=${bobOut}`]),
    )

    assert.equal(aliceRc, 0)
    assert.equal(bobRc, 0)
    assert.equal(readFileSync(aliceOut, 'utf-8'), original)
    assert.equal(readFileSync(bobOut, 'utf-8'), original)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('inspect: shows correct header info', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'file.txt')
    const cipherFile = join(dir, 'file.txt.kxco')
    writeFileSync(plainFile, 'inspect me', 'utf-8')

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))

    const { rc, out } = await captureStdout(() => inspect([cipherFile]))
    assert.equal(rc, 0)
    assert.ok(out.includes('KXCO-VAULT/1.0'))
    assert.ok(out.includes('ml-kem-768+aes-256-gcm'))
    assert.ok(out.includes('recipients: 1'))
    assert.ok(out.includes('ciphertext:'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('encrypt: @keyfile recipient resolves from identity file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity } = await makeKeypair(dir)
    const plainFile = join(dir, 'secret.txt')
    const cipherFile = join(dir, 'secret.txt.kxco')
    const decFile = join(dir, 'secret.dec.txt')
    writeFileSync(plainFile, 'via @keyfile', 'utf-8')

    // Use @keyfile syntax instead of bech32m string
    const { rc: encRc } = await captureStdout(() =>
      encrypt([plainFile, `--recipient=@${identity}`, `--out=${cipherFile}`]),
    )
    assert.equal(encRc, 0)

    const { rc: decRc } = await captureStdout(() =>
      decrypt([cipherFile, `--identity=${identity}`, `--out=${decFile}`]),
    )
    assert.equal(decRc, 0)
    assert.equal(readFileSync(decFile, 'utf-8'), 'via @keyfile')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('encrypt + decrypt: empty file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-e2e-'))
  try {
    const { path: identity, recipient: recipientStr } = await makeKeypair(dir)
    const plainFile = join(dir, 'empty.txt')
    const cipherFile = join(dir, 'empty.txt.kxco')
    const decFile = join(dir, 'empty.dec.txt')
    writeFileSync(plainFile, '', 'utf-8')

    await captureStdout(() => encrypt([plainFile, `--recipient=${recipientStr}`, `--out=${cipherFile}`]))
    await captureStdout(() => decrypt([cipherFile, `--identity=${identity}`, `--out=${decFile}`]))
    assert.equal(readFileSync(decFile, 'utf-8'), '')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
