# Key Custody Service — Threat Model

A design you can't threat-model is a design you don't understand. Here is what
each secret is worth to an attacker and what the service does about it.

## If a DEK leaks (a wrapped DEK is unwrapped, or a plaintext DEK is scraped)
Blast radius: ONLY the ciphertext that DEK wrapped. In this service a DEK is
generated fresh per SealEnvelope call, so a leaked DEK exposes exactly one
envelope's plaintext. It cannot decrypt any other object. This is the entire
reason the DEK tier exists — the many cheap keys absorb the small leaks.
Mitigation in code: fresh DEK per message; plaintext DEK zeroed after use.

## If the MASTER KEY leaks
Catastrophe: every wrapped DEK can be unwrapped, so every envelope is readable.
The master key is the crown jewel. That is why it never touches bulk data (only
DEKs), why in production it lives in an HSM or a hardened KMS and never in the
application's own storage, and why rotating it is the most carefully-planned
operation there is. This service keeps the master key out of the store entirely.

## Nonce reuse (the fatal GCM mistake)
Reusing a (key, nonce) pair under GCM leaks the XOR of the two plaintexts and
enables tag forgery. Defended by generating a fresh random 96-bit nonce on every
Seal and never deriving it from predictable state.

## Replay / cross-context confusion
An attacker takes tenant A's ciphertext and asks to decrypt it as tenant B, or
under a different key. Defended by binding the key id and tenant into the AEAD's
AAD: the bytes decrypt only under the exact key and tenant they were sealed for.

## What this design does NOT defend against
- A compromised, fully-privileged application process holding the master key in
  memory. Custody protects data at rest and enforces policy; it is not a defense
  against an attacker who already IS the trusted service.
- The audit log is tamper-EVIDENT, not tamper-proof: detection requires an
  independent copy or a published chain head the attacker cannot also rewrite.
