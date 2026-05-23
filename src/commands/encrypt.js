import { readFileSync, writeFileSync } from 'node:fs'
import { mlKem } from 'kxco-post-quantum'
import { serializeHeader } from '../envelope.js'
import { generateDek, generateNonce, computeKid, wrapDek, encryptPayload } from '../crypto.js'
import { resolveRecipient } from '../util.js'
import { KxcoVaultError } from '../errors.js'

const SEPARATOR = Buffer.from('--- BEGIN CIPHERTEXT ---\n', 'utf-8')

function parseArgs(args) {
  const recipients = []
  let inputFile = null
  let outPath = null
  let i = 0
  while (i < args.length) {
    const arg = args[i]
    if (arg === '--recipient') {
      if (!args[i + 1]) throw new KxcoVaultError('--recipient requires a value')
      recipients.push(args[i + 1])
      i += 2
    } else if (arg.startsWith('--recipient=')) {
      recipients.push(arg.slice('--recipient='.length))
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
  return { inputFile, recipients, outPath }
}

export async function encrypt(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      `usage: kxco-vault encrypt <file> --recipient <kxco1...|@keyfile> [--recipient ...] [--out <file.kxco>]\n`,
    )
    return 0
  }

  const { inputFile, recipients: recipientStrs, outPath } = parseArgs(args)

  if (!inputFile) throw new KxcoVaultError('encrypt: input file required')
  if (recipientStrs.length === 0) throw new KxcoVaultError('encrypt: at least one --recipient required')

  const outFile = outPath || `${inputFile}.kxco`

  let plaintext
  try {
    plaintext = readFileSync(inputFile)
  } catch (e) {
    throw new KxcoVaultError(`cannot read "${inputFile}": ${e.message}`)
  }

  const dek = generateDek()
  const nonce = generateNonce()
  const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')

  const recipientBlocks = recipientStrs.map((str) => {
    const pubkeyBytes = resolveRecipient(str)
    const kid = computeKid(pubkeyBytes)
    const { ciphertext: mlKemCt, sharedSecret: ss } = mlKem.encapsulate(pubkeyBytes)
    const wrappedDek = wrapDek(Buffer.from(ss), kid, dek)
    return {
      kid,
      encapsulatedKey: Buffer.from(mlKemCt).toString('hex'),
      wrappedDek: wrappedDek.toString('hex'),
    }
  })

  const headerText = serializeHeader({ recipients: recipientBlocks, nonce: nonce.toString('hex'), created })
  const canonicalHeader = Buffer.from(headerText, 'utf-8')
  const payload = encryptPayload(dek, nonce, canonicalHeader, plaintext)

  writeFileSync(outFile, Buffer.concat([canonicalHeader, SEPARATOR, payload]))

  process.stdout.write(`encrypted: ${outFile}\n`)
  process.stdout.write(`recipients: ${recipientBlocks.length}\n`)
  return 0
}
