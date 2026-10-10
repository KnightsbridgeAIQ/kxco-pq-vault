import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { encodePublicKey } from '../bech32.js'
import { KxcoVaultError } from '../errors.js'
import { KEMS, DEFAULT_KEM } from '../kem.js'

const FLAGS = new Set(['out', 'master', 'label', 'algorithm'])

// The info string random keygen derives under. ML-KEM-768 keeps the one it has
// always used; ML-KEM-1024 gets its own.
const RANDOM_INFO = {
  'ml-kem-768': 'kxco-vault/keygen/v1',
  'ml-kem-1024': 'kxco-vault/keygen/ml-kem-1024/v1',
}

function parseFlags(args) {
  const flags = {}
  let i = 0
  while (i < args.length) {
    const arg = args[i]
    if (!arg.startsWith('--')) throw new KxcoVaultError(`unexpected argument: ${arg}`)
    let key, val
    if (arg.includes('=')) {
      const eq = arg.indexOf('=')
      key = arg.slice(2, eq)
      val = arg.slice(eq + 1)
      i++
    } else {
      key = arg.slice(2)
      if (i + 1 >= args.length || args[i + 1].startsWith('--')) {
        throw new KxcoVaultError(`--${key} requires a value`)
      }
      val = args[i + 1]
      i += 2
    }
    if (!FLAGS.has(key)) throw new KxcoVaultError(`unknown flag --${key}`)
    flags[key] = val
  }
  return flags
}

export async function keygen(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      `usage: kxco-vault keygen --out <keypair.kxco> [--master <hex> --label <string>] [--algorithm ml-kem-1024|ml-kem-768]\n`,
    )
    return 0
  }

  const flags = parseFlags(args)
  if (!flags.out) throw new KxcoVaultError('keygen: --out is required')
  const algorithm = flags.algorithm ?? DEFAULT_KEM
  if (!Object.hasOwn(KEMS, algorithm)) {
    throw new KxcoVaultError(`keygen: --algorithm must be ml-kem-768 or ml-kem-1024, got ${algorithm}`)
  }
  const kem = KEMS[algorithm].module

  let publicKey, secretKey

  if (flags.master) {
    // Deterministic derivation
    if (!flags.label) throw new KxcoVaultError('keygen: --label is required with --master')
    if (!/^[0-9a-fA-F]+$/.test(flags.master) || flags.master.length < 32) {
      throw new KxcoVaultError('keygen: --master must be at least 16 hex bytes')
    }
    const masterBytes = Buffer.from(flags.master, 'hex')
    const result = kem.keypairFromMaster(masterBytes, flags.label)
    publicKey = result.publicKey
    secretKey = result.secretKey
  } else {
    // Random keygen: generate 32-byte random master, derive 64-byte seed
    const randomMaster = randomBytes(32)
    const result = kem.keypairFromMaster(randomMaster, RANDOM_INFO[algorithm])
    publicKey = result.publicKey
    secretKey = result.secretKey
  }

  const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
  const recipient = encodePublicKey(Buffer.from(publicKey))

  const identity = [
    'KXCO-VAULT-IDENTITY/1.0',
    `algorithm: ${algorithm}`,
    `created: ${created}`,
    `public: ${recipient}`,
    `secret: ${Buffer.from(secretKey).toString('hex')}`,
    '',
  ].join('\n')

  writeFileSync(flags.out, identity, 'utf-8')
  process.stdout.write(`identity: ${flags.out}\n`)
  process.stdout.write(`recipient: ${recipient}\n`)
  return 0
}
