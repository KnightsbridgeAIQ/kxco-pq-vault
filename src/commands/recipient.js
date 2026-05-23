import { readFileText } from '../util.js'
import { decodePublicKey, encodePublicKey } from '../bech32.js'
import { KxcoVaultError } from '../errors.js'

export async function recipient(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`usage: kxco-vault recipient <keypair.kxco>\n`)
    return 0
  }

  const keyfile = args.find(a => !a.startsWith('--'))
  if (!keyfile) throw new KxcoVaultError('recipient: identity file argument required')

  const content = readFileText(keyfile)
  if (!content.startsWith('KXCO-VAULT-IDENTITY/')) {
    throw new KxcoVaultError(`not a kxco-vault identity file: ${keyfile}`)
  }

  const match = content.match(/^public:\s*(kxco1\S+)/m)
  if (!match) throw new KxcoVaultError(`identity file missing public key: ${keyfile}`)

  // Validate bech32m round-trip
  const pubkeyBytes = decodePublicKey(match[1])
  const recipient = encodePublicKey(pubkeyBytes)

  process.stdout.write(`${recipient}\n`)
  return 0
}
