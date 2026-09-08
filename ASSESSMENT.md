# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** A library and a CLI that produce and consume
`.kxco` envelopes: a plain-text header, then AES-256-GCM ciphertext, with the
data encryption key wrapped independently to each recipient under ML-KEM-768.

**This is the package the harvest-now-decrypt-later argument is actually
about.** A captured ciphertext stays captured. Everything else in the family
protects something that is verified at the time it is used, where a break years
from now is survivable. Here the plaintext is the asset, an adversary can hold
the file indefinitely, and the ML-KEM-768 wrapping is what stands between them
and it. That is why the design choice below is the right one and worth stating
as a boundary rather than a feature.

**Pure post-quantum, with no classical fallback, deliberately.** There is no
hybrid step. Contrast this with
[`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls), which always mixes
X25519 into its key schedule and cannot be run PQ-only. The two make opposite
choices and both are correct for what they protect: a session key that matters
for minutes can afford a classical belt, and a file that must stay secret for
twenty years cannot afford to inherit a classical break. A buyer comparing the
two should read the difference as intentional.

**Operate: no network, no key management.** Nothing in `src/` opens a socket.
The package encrypts to recipient public keys the caller supplies and decrypts
with a secret key the caller holds. Where those keys live, how they are
distributed and whether a given recipient key is the right one are all outside
this package. `kxco-pq-hsm` is the custody answer; there is no directory here.

**Confidentiality, not authenticity. This is the boundary most likely to be
misread.** The header is bound as GCM additional authenticated data, so nothing
in it can be altered without decryption failing. That is integrity of the
envelope against tampering. It is not authenticity of the sender: an envelope
carries no signature, and anyone holding a recipient's public key can produce a
well-formed envelope addressed to them. Successful decryption proves the
envelope was made for you and has not been modified. It does not prove who made
it. If you need that, sign the payload with
[`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) before
encrypting it.

**Start and update.** No release signing of its own. Published through CI with
npm provenance.

**Protect records and enforce policy.** Neither applies. No logs, no policy
engine.

**Retain history: the recipient key is the whole retention problem.** An
envelope is decryptable for exactly as long as a recipient secret key survives
and no longer. There is no escrow, no recovery path and no re-wrapping
mechanism, so losing the key loses the plaintext. The multi-recipient design is
the mitigation actually available: encrypt to a second key held somewhere else
at the time of encryption. It cannot be added afterwards without the plaintext.

The envelope records a `kid` per recipient, so a holder of several keys can
tell which one applies. That is key selection, which is more than
`kxco-pq-audit` has, and it is not key validity: nothing here says whether a
key was still trusted at a given time.

## Agility

**Inherited.** Parameter sets and backends belong to `kxco-post-quantum`. See
that package's `AGILITY.md`.

**The addition: the format names its own algorithms and version.** The header
begins `KXCO-VAULT/1.0` and carries an explicit `algorithm:
ml-kem-768+aes-256-gcm` line. So an envelope states what produced it rather
than requiring a reader to assume, and a v2 format with a different parameter
set can be introduced without ambiguity. That is the mechanism a format
migration needs.

**The limit: reading is not negotiation, and old files do not move.** The
algorithm line is descriptive. This package implements one suite, and a
different one is a release rather than a configuration. More importantly,
migrating a parameter set does not migrate the archive: existing envelopes stay
wrapped under ML-KEM-768 until someone decrypts and re-encrypts them, which
requires the keys and the plaintext. Any migration plan for data at rest has to
budget for that pass, and nothing here performs it.

## Lifecycle

**Supported versions.** One line moving forward, matching the family.

**Pin inconsistency.** `@scure/base` is declared exactly; `kxco-post-quantum` is
declared `^1.3.0`, and the tree the evidence bundle was last built from resolved
it to **1.4.0** against a current primitives release of 1.7.2.
`02-primitives.json` records the resolved version. The primitives package pins
its own dependencies exactly and explains why; that rule is not applied here,
and changing it costs a release of this package per primitives release.

**Ceiling.** No hardware ceiling. ML-KEM-768 operations are per recipient, not
per byte, so envelope size is dominated by AES-256-GCM and large files are not
a cryptographic problem. Many recipients on one envelope is the cost that
scales, and it scales linearly: 1088 bytes of ciphertext plus a wrapped key
each.

**Roadmap.** No external audit of this package, no bug bounty, no formal
analysis of the envelope format.

## Correcting this document

Every claim here is checkable against `src/` and the envelope format in the
README. If one does not match, that is a defect worth reporting through the
repository's issues.
