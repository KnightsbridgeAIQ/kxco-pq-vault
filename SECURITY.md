# Security Policy

## Reporting a vulnerability
Email **john@knightsbridgelaw.com**. Do not open public issues for security reports.
PGP key available on request. We credit reporters in `CHANGELOG.md` unless they
request otherwise.

Acknowledgement within **2 business days**. Triage decision within **5 business days**.

Full policy: <https://kxco.ai/security>

## Safe harbour
If you make a good-faith effort to comply with this policy, we will treat your
research as authorised, and we will not pursue or support legal action against
you. Good faith means: do not access, modify, exfiltrate, or destroy data that
is not yours; use test accounts where possible; do not degrade service for
others; and stop and report as soon as you have established that a
vulnerability exists. This cannot bind third parties, and it does not cover
extortion, data sale, or public disclosure ahead of the window below.

## Scope
In scope:
- Cryptographic correctness of the envelope construction (ML-KEM-768 key
  encapsulation, AES-GCM content encryption, and how the two are bound)
- Multi-recipient handling: whether one recipient can recover another
  recipient's key material, or alter the recipient set undetected
- Whether a modified ciphertext, header or recipient block is detected on
  decrypt rather than silently accepted
- Bech32m encoding and decoding of vault identifiers
- Key material handling in the CLI: argument, environment and file paths

Out of scope (report upstream to <https://github.com/paulmillr/noble-post-quantum>):
- Bugs in the underlying ML-KEM-768 primitive

Out of scope (report upstream to <https://github.com/paulmillr/scure-base>):
- Bugs in the underlying Bech32m implementation

## What this package does not claim

**Constant-time execution.** This is a JavaScript library and it cannot
guarantee constant-time execution of cryptographic primitives. JIT compilation
changes emitted machine code based on observed values, engines switch numeric
representations dynamically, and garbage collection timing correlates with
allocation. None of this is controllable from library code.

Constant-time *comparison* of authentication tags is achievable and is used.
The distinction matters: if your threat model includes local timing or power
side-channel attacks against key material, a JavaScript library is not the right
tool, and never was. That work belongs in a native module or an HSM.

**Protection against a compromised host.** A vault protects data at rest. It
does not protect against an attacker who can read process memory or the
plaintext before encryption.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | yes |
| 1.0.x | security fixes only |
| < 1.0 | no |

## Disclosure window
We ask for **90 days** before public disclosure, or until a fix ships if
sooner. We will keep you informed of progress and will not ask for an extension
without explaining why.
