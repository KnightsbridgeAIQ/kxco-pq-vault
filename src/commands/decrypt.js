import { writeFileSync } from 'node:fs'
import { mlKem } from 'kxco-post-quantum'
import { parseEnvelope } from '../envelope.js'
import { computeKid, unwrapDek, decryptPayload } from '../crypto.js'
import { readFileBytes, readIdentity } from '../util.js'
import { KxcoVaultError } from '../errors.js'

function parseArgs(args) {
  let inputFile = null
  let identityPath = null
  let outPath = null
  let i = 0
  while (i < args.length) {
    const arg = args[i]
    if (arg === '--identity') {
      if (!args[i + 1]) throw new KxcoVaultError('--identity requires a value')
      identityPath = args[i + 1]
      i += 2
    } else if (arg.startsWith('--identity=')) {
      identityPath = arg.slice('--identity='.length)
      i++
    } else if (arg === '--out') {
      if (!args[i + 1]) throw new KxcoVaultError('--out requires a value')
      outPath = args[i + 1]
      i += 2
    } else if (arg.startsWith('--out=')) {
      outPath = arg.slice('--out='.length)
      i++
    } else if (!arg.startsWith('--')) {
      inputFile = arg
      i++
    } else {
      throw new KxcoVaultError(`unknown flag: ${arg}`)
    }
  }
  return { inputFile, identityPath, outPath }
}

export async function decrypt(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      `usage: kxco-vault decrypt <file.kxco> --identity <keypair.kxco> [--out <file>]\n`,
    )
    return 0
  }

  const { inputFile, identityPath, outPath } = parseArgs(args)

  if (!inputFile) throw new KxcoVaultError('decrypt: input file required')
  if (!identityPath) throw new KxcoVaultError('decrypt: --identity is required')

  const { publicKey, secretKey } = readIdentity(identityPath)
  const myKid = computeKid(publicKey)

  const buf = readFileBytes(inputFile)
  const { header, canonicalHeader, ciphertext } = parseEnvelope(buf)

  const recipientBlock = header.recipients.find(r => r.kid === myKid)
  if (!recipientBlock) throw new KxcoVaultError('recipient kid not in envelope')

  const mlKemCt = Buffer.from(recipientBlock.encapsulatedKey, 'hex')
  const ss = Buffer.from(mlKem.decapsulate(mlKemCt, secretKey))
  const wrappedDek = Buffer.from(recipientBlock.wrappedDek, 'hex')
  const dek = unwrapDek(ss, myKid, wrappedDek)

  const nonce = Buffer.from(header.nonce, 'hex')
  const plaintext = decryptPayload(dek, nonce, canonicalHeader, ciphertext)

  const defaultOut = inputFile.endsWith('.kxco') ? inputFile.slice(0, -5) : `${inputFile}.dec`
  const outFile = outPath || defaultOut

  writeFileSync(outFile, plaintext)
  process.stdout.write(`decrypted: ${outFile}\n`)
  return 0
}
