# Key Custody Service — Architecture

## What this is
The service every other service calls before it writes a secret to disk. A
caller hands us plaintext and a key id; we hand back a ciphertext blob it can
store anywhere. Later it hands the blob back and we return the plaintext — but
only if its identity is allowed to use that key. We never store the caller's
plaintext, and we never hand out raw key material.

## Envelope encryption — the whole idea
We do NOT encrypt the caller's data directly under one big key. Instead:

1. A **data-encryption key (DEK)** — a fresh 256-bit AES key — encrypts the
   caller's plaintext.
2. A **master key (the KEK, key-encryption key)** encrypts the DEK itself.
3. We store the ciphertext next to the **wrapped DEK**. We store the DEK's
   plaintext form NOWHERE. To decrypt, we unwrap the DEK with the master key,
   use it, then zero it from memory.

The stored blob is an "envelope": ciphertext + the sealed DEK that opens it.

## Why two tiers and not one key
- The master key is small, rarely used, and can live in an HSM or a locked-down
  store. It only ever touches DEKs, never bulk data.
- DEKs are cheap and many — one per object, per tenant, per whatever. A leaked
  DEK compromises only what that DEK wrapped. A leaked master key is the
  catastrophe, which is exactly why the master key is the thing you protect
  hardest and rotate most carefully.

## The operations contract
- CreateKey(tenant)            -> a new logical key with an active version
- Encrypt(principal, key, pt)  -> {ciphertext, wrapped_dek, key_version}
- Decrypt(principal, envelope) -> plaintext (authorization checked first)
- RotateKey(principal, key)    -> a new active version; old versions still decrypt

## What stays true no matter what changes underneath
- The DEK's plaintext is never written to storage or logs.
- Every ciphertext is bound to its key id and tenant, so it can't be replayed
  under a different key or account.
- Every operation is authorized before any key material is touched, and every
  operation is written to a tamper-evident audit log.
