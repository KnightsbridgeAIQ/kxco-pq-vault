import { readFileSync } from 'node:fs'
import { parseHeaderText } from '../envelope.js'
import { KxcoVaultError } from '../errors.js'

const SEPARATOR = '--- BEGIN CIPHERTEXT ---\n'

export async function inspect(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`usage: kxco-vault inspect <file.kxco>\n`)
    return 0
  }

  const inputFile = args.find(a => !a.startsWith('--'))
  if (!inputFile) throw new KxcoVaultError('inspect: input file required')

  let buf
  try {
    buf = readFileSync(inputFile)
  } catch (e) {
    throw new KxcoVaultError(`cannot read "${inputFile}": ${e.message}`)
  }

  const text = buf.toString('utf-8')
  const sepIdx = text.indexOf(SEPARATOR)
  if (sepIdx === -1) throw new KxcoVaultError('invalid envelope: missing ciphertext separator')

  const headerText = text.slice(0, sepIdx)
  const ciphertextBytes = buf.length - sepIdx - Buffer.byteLength(SEPARATOR)

  const header = parseHeaderText(headerText)

  process.stdout.write(`version:    KXCO-VAULT/1.0\n`)
  process.stdout.write(`algorithm:  ${header.algorithm}\n`)
  process.stdout.write(`recipients: ${header.recipients.length}\n`)
  for (let i = 0; i < header.recipients.length; i++) {
    process.stdout.write(`  [${i}] kid: ${header.recipients[i].kid}\n`)
  }
  process.stdout.write(`nonce:      ${header.nonce}\n`)
  process.stdout.write(`created:    ${header.created}\n`)
  process.stdout.write(`ciphertext: ${ciphertextBytes} bytes\n`)
  return 0
}
