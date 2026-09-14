// Package crypto — the envelope layer. This turns the raw AEAD into the
// two-tier hierarchy: a fresh DEK encrypts the caller's plaintext, and the
// master key wraps the DEK. The plaintext DEK is created, used, and zeroed
// without ever being returned to a caller or written to storage.
package crypto

import "crypto/rand"

// DEKSize is 32 bytes — a 256-bit AES key.
const DEKSize = 32

// Envelope is what we persist: the wrapped DEK and the data ciphertext. Neither
// field is the plaintext DEK; that never leaves this process.
type Envelope struct {
	WrappedDEK []byte // the DEK, encrypted under the master key (nonce||ct||tag)
	Ciphertext []byte // the caller's plaintext, encrypted under the DEK
}

// SealEnvelope generates a fresh DEK, encrypts plaintext under it, wraps the DEK
// under masterKey, and zeros the plaintext DEK before returning. Both the wrap
// and the data encryption are bound to aad (the key id + tenant).
func SealEnvelope(masterKey, plaintext, aad []byte) (*Envelope, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	// The plaintext DEK must not outlive this function.
	defer zero(dek)

	ct, err := Seal(dek, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := Seal(masterKey, dek, aad)
	if err != nil {
		return nil, err
	}
	return &Envelope{WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// OpenEnvelope unwraps the DEK with the master key, decrypts the data, and zeros
// the recovered DEK before returning. The same aad must be supplied or both
// opens fail.
func OpenEnvelope(masterKey []byte, env *Envelope, aad []byte) ([]byte, error) {
	dek, err := Open(masterKey, env.WrappedDEK, aad)
	if err != nil {
		return nil, err
	}
	defer zero(dek)

	return Open(dek, env.Ciphertext, aad)
}

// zero overwrites a key buffer so a recovered key does not linger in memory
// after use. It is written to resist being optimized away.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
