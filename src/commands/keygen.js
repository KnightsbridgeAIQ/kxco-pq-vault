import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { mlKem, deriveSeed } from 'kxco-post-quantum'
import { encodePublicKey } from '../bech32.js'
import { KxcoVaultError } from '../errors.js'

const FLAGS = new Set(['out', 'master', 'label'])

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
    process.stdout.write(`usage: kxco-vault keygen --out <keypair.kxco> [--master <hex> --label <string>]\n`)
    return 0
  }

  const flags = parseFlags(args)
  if (!flags.out) throw new KxcoVaultError('keygen: --out is required')

  let publicKey, secretKey

  if (flags.master) {
    // Deterministic derivation
    if (!flags.label) throw new KxcoVaultError('keygen: --label is required with --master')
    if (!/^[0-9a-fA-F]+$/.test(flags.master) || flags.master.length < 32) {
      throw new KxcoVaultError('keygen: --master must be at least 16 hex bytes')
    }
    const masterBytes = Buffer.from(flags.master, 'hex')
    const result = mlKem.keypairFromMaster(masterBytes, flags.label)
    publicKey = result.publicKey
    secretKey = result.secretKey
  } else {
    // Random keygen: generate 32-byte random master, derive 64-byte seed
    const randomMaster = randomBytes(32)
    const result = mlKem.keypairFromMaster(randomMaster, 'kxco-vault/keygen/v1')
    publicKey = result.publicKey
    secretKey = result.secretKey
  }

  const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
  const recipient = encodePublicKey(Buffer.from(publicKey))

  const identity = [
    'KXCO-VAULT-IDENTITY/1.0',
    'algorithm: ml-kem-768',
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
