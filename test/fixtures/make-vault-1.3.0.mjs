// Makes test/fixtures/vault-1.3.0-ml-kem-768.json with the RELEASED
// kxco-pq-vault 1.3.0 from npm, installed as the devDependency alias
// kxco-pq-vault-130 (npm:kxco-pq-vault@1.3.0). Nothing here uses this
// repository's src/, so the fixture is what 1.3.0 wrote, not what the current
// code thinks 1.3.0 wrote.
//
//   npm ci
//   node test/fixtures/make-vault-1.3.0.mjs
//
// Test keys only. The envelope and plaintext are stored as base64 so that
// line-ending conversion cannot alter the authenticated header.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ALIAS = 'kxco-pq-vault-130'
const root = fileURLToPath(new URL('../../', import.meta.url))
const pkgDir = join(root, 'node_modules', ALIAS)
const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf-8'))
if (pkg.name !== 'kxco-pq-vault' || pkg.version !== '1.3.0') {
  throw new Error(`${ALIAS} is ${pkg.name}@${pkg.version}, not kxco-pq-vault@1.3.0; run npm ci`)
}
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf-8'))
const locked = lock.packages[`node_modules/${ALIAS}`]

const bin = join(pkgDir, pkg.bin['kxco-vault'])
const vault = (...args) => execFileSync(process.execPath, [bin, ...args], { encoding: 'utf-8' })

// A fixed, public test master, so the derived identity can be re-derived.
const MASTER = '6b78636f2d70712d7661756c742d312e332e302d746573742d6d61737465722e'
const LABEL = 'fixture'

const dir = mkdtempSync(join(tmpdir(), 'kxco-vault-130-'))
try {
  const identity = join(dir, 'identity.kxco')
  const derived = join(dir, 'derived.kxco')
  const plain = join(dir, 'plain.bin')
  const sealed = join(dir, 'plain.bin.kxco')
  const opened = join(dir, 'opened.bin')

  // Text, a CRLF, a lone CR and bytes that are not UTF-8, so "byte for byte"
  // means something.
  const plaintext = Buffer.concat([
    Buffer.from('Sealed by kxco-pq-vault 1.3.0 under ML-KEM-768.\r\nline two\r', 'utf-8'),
    Buffer.from([0x00, 0xff, 0x80, 0x0a, 0xfe]),
  ])
  writeFileSync(plain, plaintext)

  vault('keygen', '--out', identity)
  vault('keygen', '--out', derived, '--master', MASTER, '--label', LABEL)
  vault('encrypt', plain, '--recipient', `@${identity}`, '--out', sealed)
  vault('decrypt', sealed, '--identity', identity, '--out', opened)
  if (!readFileSync(opened).equals(plaintext)) throw new Error('1.3.0 did not open its own envelope')

  const identityText = readFileSync(identity, 'utf-8')
  const derivedText = readFileSync(derived, 'utf-8')
  for (const text of [identityText, derivedText]) {
    if (!text.includes('\nalgorithm: ml-kem-768\n')) throw new Error('1.3.0 did not make an ML-KEM-768 identity')
  }

  const fixture = {
    note: 'Made by the released kxco-pq-vault 1.3.0 from npm (devDependency alias ' +
      `${ALIAS}), with test/fixtures/make-vault-1.3.0.mjs: kxco-vault keygen; ` +
      'kxco-vault keygen --master --label; kxco-vault encrypt. Test keys only.',
    madeBy: `${pkg.name}@${pkg.version}`,
    resolved: locked.resolved,
    integrity: locked.integrity,
    node: process.version,
    identity: identityText,
    envelopeBase64: readFileSync(sealed).toString('base64'),
    plaintextBase64: plaintext.toString('base64'),
    derived: { master: MASTER, label: LABEL, identity: derivedText },
  }
  const out = join(root, 'test', 'fixtures', 'vault-1.3.0-ml-kem-768.json')
  writeFileSync(out, JSON.stringify(fixture, null, 2) + '\n', 'utf-8')
  process.stdout.write(`wrote ${out}\n`)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
