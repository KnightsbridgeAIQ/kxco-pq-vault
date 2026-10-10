// Makes test/fixtures/vault-<version>-ml-kem-768.json, and for releases from
// 1.2.0 on vault-<version>-ml-kem-1024.json, with each RELEASED kxco-pq-vault
// named on the command line. Each release comes from npm as a pinned
// devDependency alias, kxco-pq-vault-<digits> (kxco-pq-vault-108 is 1.0.8).
// Nothing here uses this repository's src/, so a fixture is what that release
// wrote, not what the current code thinks it wrote.
//
//   npm ci
//   node test/fixtures/make-vault-fixtures.mjs 1.0.8 1.1.8 1.2.0
//
// Each fixture holds a random identity and an envelope sealed to it, and the
// identity `keygen --master --label` derives from a fixed public test master.
// vault-1.3.0-ml-kem-768.json was made at commit e6a2629 by make-vault-1.3.0.mjs,
// the single-release form of this script.
//
// Test keys only. Envelopes and plaintexts are base64 so that line-ending
// conversion cannot alter the authenticated header.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../../', import.meta.url))
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf-8'))
const compareVersions = (v, min) => {
  const [a, b] = [v, min].map((s) => s.split('.').map(Number))
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2]
}

const versions = process.argv.slice(2)
if (versions.length === 0) throw new Error('usage: node test/fixtures/make-vault-fixtures.mjs <version> [...]')

for (const version of versions) {
  const alias = `kxco-pq-vault-${version.replaceAll('.', '')}`
  const pkgDir = join(root, 'node_modules', alias)
  const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf-8'))
  if (pkg.name !== 'kxco-pq-vault' || pkg.version !== version) {
    throw new Error(`${alias} is ${pkg.name}@${pkg.version}, not kxco-pq-vault@${version}; run npm ci`)
  }
  const locked = lock.packages[`node_modules/${alias}`]
  const pq = JSON.parse(readFileSync(join(root, 'node_modules', 'kxco-post-quantum', 'package.json'), 'utf-8'))
  const bin = join(pkgDir, typeof pkg.bin === 'string' ? pkg.bin : pkg.bin['kxco-vault'])
  const vault = (...args) => execFileSync(process.execPath, [bin, ...args], { encoding: 'utf-8' })

  // A fixed, public test master per release, so the derived key can be
  // derived again: the UTF-8 bytes of "kxco-pq-vault-<version>-test-master.".
  const master = Buffer.from(`kxco-pq-vault-${version}-test-master.`, 'utf-8')
  if (master.length !== 32) throw new Error(`test master for ${version} is ${master.length} bytes, not 32`)
  const label = 'fixture'

  // ML-KEM-768 is each 1.x release's default; ML-KEM-1024 exists from 1.2.0.
  const sets = compareVersions(version, '1.2.0') >= 0 ? [null, 'ml-kem-1024'] : [null]
  for (const set of sets) {
    const kem = set ?? 'ml-kem-768'
    const algorithmArgs = set ? ['--algorithm', set] : []
    const dir = mkdtempSync(join(tmpdir(), `kxco-vault-${version}-`))
    try {
      const identity = join(dir, 'identity.kxco')
      const derived = join(dir, 'derived.kxco')
      const plain = join(dir, 'plain.bin')
      const sealed = join(dir, 'plain.bin.kxco')
      const opened = join(dir, 'opened.bin')

      // Text, a CRLF, a lone CR and bytes that are not UTF-8, so "byte for
      // byte" means something.
      const plaintext = Buffer.concat([
        Buffer.from(`Sealed by kxco-pq-vault ${version} under ${kem.toUpperCase()}.\r\nline two\r`, 'utf-8'),
        Buffer.from([0x00, 0xff, 0x80, 0x0a, 0xfe]),
      ])
      writeFileSync(plain, plaintext)

      vault('keygen', '--out', identity, ...algorithmArgs)
      vault('keygen', '--out', derived, '--master', master.toString('hex'), '--label', label, ...algorithmArgs)
      const identityText = readFileSync(identity, 'utf-8')
      const derivedText = readFileSync(derived, 'utf-8')
      for (const text of [identityText, derivedText]) {
        if (!text.includes(`\nalgorithm: ${kem}\n`)) throw new Error(`${version} did not make an ${kem} identity`)
      }
      // The recipient string, not @file, works on every 1.x release.
      const recipient = identityText.match(/^public: (kxco1\S+)$/m)[1]
      vault('encrypt', plain, '--recipient', recipient, '--out', sealed)
      vault('decrypt', sealed, '--identity', identity, '--out', opened)
      if (!readFileSync(opened).equals(plaintext)) throw new Error(`${version} did not open its own envelope`)

      const fixture = {
        note: `Made by the released kxco-pq-vault ${version} from npm (devDependency alias ${alias}), ` +
          'with test/fixtures/make-vault-fixtures.mjs: kxco-vault keygen; kxco-vault keygen --master --label; ' +
          'kxco-vault encrypt. Test keys only.',
        madeBy: `${pkg.name}@${pkg.version}`,
        resolved: locked.resolved,
        integrity: locked.integrity,
        kxcoPostQuantum: pq.version,
        node: process.version,
        identity: identityText,
        envelopeBase64: readFileSync(sealed).toString('base64'),
        plaintextBase64: plaintext.toString('base64'),
        derived: { master: master.toString('hex'), label, algorithm: set, identity: derivedText },
      }
      const out = join(root, 'test', 'fixtures', `vault-${version}-${kem}.json`)
      writeFileSync(out, JSON.stringify(fixture, null, 2) + '\n', 'utf-8')
      process.stdout.write(`wrote ${out}\n`)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
}
