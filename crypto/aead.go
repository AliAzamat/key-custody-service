// Package crypto wraps AES-256-GCM behind an API that is hard to misuse.
//
// GCM is authenticated encryption: Seal produces ciphertext PLUS an
// authentication tag, and Open refuses to return plaintext unless the tag (and
// the associated data) verify. That gives us confidentiality AND integrity in
// one primitive. Two rules make or break it:
//
//  1. NEVER reuse a (key, nonce) pair. Nonce reuse under GCM is catastrophic:
//     it leaks the XOR of two plaintexts and, worse, lets an attacker forge
//     tags. We use a fresh 12 random bytes every call.
//  2. Bind CONTEXT with additional authenticated data (AAD). The AAD is not
//     encrypted, but it is authenticated: change it and Open fails. We use it
//     to tie a ciphertext to its key id and tenant.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// NonceSize is GCM's standard 96-bit nonce. Twelve random bytes per message.
const NonceSize = 12

// ErrDecrypt is returned for ANY open failure. We never say whether the tag,
// the nonce, or the AAD was the problem — a padding-oracle-style leak starts
// with a chatty error.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Seal encrypts plaintext under a 32-byte key, authenticating aad. It returns
// nonce || ciphertext-with-tag, so the caller stores one opaque blob.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to its first argument, so passing nonce
	// as the prefix yields nonce||ciphertext in one allocation.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. It splits the nonce back off, then verifies the tag and
// the aad before returning any plaintext.
func Open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < NonceSize {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:NonceSize], blob[NonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
