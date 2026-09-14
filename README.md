# Coinbase | Key Custody Service — Envelope Encryption, Key Hierarchy, and IAM-Scoped Access in Go

An advanced security capstone on the service a platform team at Coinbase actually owns — the thing every other service calls before it writes a secret to disk. You build a key-management service in idiomatic Go around envelope encryption: a root master key wraps short-lived per-tenant data-encryption keys, so plaintext bytes are protected by a DEK the caller never sees and the DEK itself is protected by a master key that never leaves the service. You encrypt with AES-256-GCM using a fresh nonce per message and additional authenticated data that binds each ciphertext to its key id and tenant, so a blob can't be replayed under a different key or account. You give keys versions and implement rotation that issues a new active version while every old version still decrypts, then re-wraps lazily on read. You put IAM-scoped authorization in front of every Encrypt, Decrypt, and CreateKey call — a principal maps to allowed key ids and actions, least privilege, deny by default. And you make the whole thing accountable with an append-only, hash-chained audit log where editing or deleting one entry breaks the chain. The discipline is security engineering — correct cryptographic primitives used correctly, a threat model you can state out loud, and a service another team can trust with its secrets.

Built step-by-step with [KhwajaLabs Build](https://khwajalabs.com).

## Stack
- Go
- AES-256-GCM
- envelope encryption
- RBAC
- SHA-256
- SQLite
