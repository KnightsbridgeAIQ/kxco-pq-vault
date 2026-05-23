import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const USAGE = `
kxco-vault — post-quantum file encryption (ML-KEM-768 + AES-256-GCM)

commands:
  keygen     generate an ML-KEM-768 identity keypair
  encrypt    encrypt a file for one or more recipients
  decrypt    decrypt a file with your identity
  recipient  extract the public recipient string from an identity file
  inspect    show envelope header info

run 'kxco-vault <command> --help' for command-specific usage
`.trim()

export async function run(argv) {
  const [cmd, ...args] = argv

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(USAGE + '\n')
    return 0
  }

  if (cmd === '--version' || cmd === '-v') {
    const pkg = JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf-8'),
    )
    process.stdout.write(`${pkg.name} ${pkg.version}\n`)
    return 0
  }

  switch (cmd) {
    case 'keygen': {
      const { keygen } = await import('./commands/keygen.js')
      return keygen(args)
    }
    case 'encrypt': {
      const { encrypt } = await import('./commands/encrypt.js')
      return encrypt(args)
    }
    case 'decrypt': {
      const { decrypt } = await import('./commands/decrypt.js')
      return decrypt(args)
    }
    case 'recipient': {
      const { recipient } = await import('./commands/recipient.js')
      return recipient(args)
    }
    case 'inspect': {
      const { inspect } = await import('./commands/inspect.js')
      return inspect(args)
    }
    default:
      process.stderr.write(`kxco-vault: unknown command "${cmd}"\n${USAGE}\n`)
      return 2
  }
}
