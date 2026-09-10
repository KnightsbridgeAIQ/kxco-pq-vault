# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

File and envelope encryption to one or more ML-KEM-768 public keys. Like PGP,
quantum-safe.

**This is the package the harvest-now-decrypt-later argument is actually
about.** Everywhere else in the stack, a break years from now meets data whose
moment has passed: a session that ended, a signature already checked. Here the
plaintext is the asset and an adversary can hold the ciphertext indefinitely.
That is the one place where the timeline genuinely does not forgive waiting, and
it is why this package makes the choice it does.

**Pure post-quantum, no classical fallback.** There is no hybrid step and no
option to add one. Compare
[`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls), which always mixes
X25519 into its key schedule: a session key that matters for minutes can afford
a classical belt, and a file that must stay secret for twenty years cannot
inherit a classical break. Two opposite choices, each correct for what it
protects, and both deliberate.

**Multi-recipient by construction.** A random 32-byte data encryption key per
envelope, wrapped independently to each recipient's ML-KEM shared secret. Every
recipient opens the same plaintext with their own key, nobody shares a secret
with anybody, and adding a recipient costs 1088 bytes of ciphertext plus a
wrapped key rather than a second copy of the payload. Large files are an
AES-256-GCM cost, not a lattice cost.

**The header is bound to the ciphertext.** The entire canonical header is the
GCM additional authenticated data, so altering any field — the nonce, the
algorithm line, a recipient entry — makes decryption fail before a single byte
of plaintext is released. Tamper evidence that fires before disclosure, not
after.

**The envelope says what it is.** `KXCO-VAULT/1.0`, an explicit `algorithm:
ml-kem-768+aes-256-gcm` line, and a `kid` per recipient. A holder of several
keys knows which one applies; a reader in five years knows what produced the
file without having to guess.

## Scope

This package provides confidentiality and tamper evidence. Successful decryption
proves the envelope was made for you and has not been modified since.

Authorship is a separate question with a separate answer:
[`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) signs a payload
before it is encrypted, which is the composition to use when the recipient needs
to know who sent it as well as that it arrived intact. Keeping the two apart is
what lets an envelope be addressed to someone without the sender's identity
being disclosed to anyone who intercepts it.

Key distribution and custody are likewise deliberate omissions:
[`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) is where a key lives.
Nothing in `src/` opens a socket, so an envelope can be produced and opened on an
air-gapped machine.

**Encrypt to a second key you hold elsewhere.** The multi-recipient design is
the recovery story, and it is chosen at encryption time. That is a property of
envelope encryption rather than a quirk of this implementation, and it is worth
deciding once, at the point the archive policy is written.

## Agility

**Inherited.** Parameter sets and the two interchangeable backends belong to
`kxco-post-quantum`.

**Versioned and self-describing.** The header carries both a format version and
the algorithm suite, so a v2 envelope is distinguishable from a v1 without
ambiguity and a reader never has to assume. That is the mechanism a format
migration needs, present before it is needed.

**Archive migration is a decrypt-and-re-encrypt pass**, which is inherent to
authenticated encryption rather than particular to this format: the header is
the AAD, so changing the recipient set changes what the tag covers. `unwrapDek`
and `wrapDek` are the primitives that pass needs, and one existing recipient's
key is enough to run it without going back to the original plaintext source.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.
`@scure/base` is pinned exactly.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware ceiling. ML-KEM-768 work is per recipient, not per byte,
so envelope size and encryption time are dominated by AES-256-GCM over the
payload. Many recipients on one envelope scale linearly and cheaply.

**Interfaces.** A library and a CLI over the same code, with bech32m recipient
strings that are safe to paste into a ticket or an email.

## Correcting this document

Every claim here is checkable against `src/` and the envelope format in the
README. If one does not match, that is a defect worth reporting through the
repository's issues.
