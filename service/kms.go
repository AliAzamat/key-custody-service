// Package service composes the layers into the Key Custody Service. Every
// public method follows the same spine: authorize FIRST, touch key material
// only if allowed, and audit the attempt either way — including denials.
package service

import (
	"fmt"

	"example.com/kcs/audit"
	"example.com/kcs/crypto"
	"example.com/kcs/iam"
	"example.com/kcs/store"
)

type KMS struct {
	master []byte // the master key; in production this lives in an HSM/KMS
	store  *store.Store
	log    *audit.Log
}

func New(master []byte, st *store.Store, log *audit.Log) *KMS {
	return &KMS{master: master, store: st, log: log}
}

// aad binds a ciphertext to its key id and tenant so it cannot be replayed
// under a different key or account.
func aad(keyID, tenant string) []byte {
	return []byte(keyID + "|" + tenant)
}

// Encrypt authorizes, then seals the plaintext in an envelope bound to the key.
func (k *KMS) Encrypt(p iam.Principal, keyID string, pt []byte) (*crypto.Envelope, error) {
	rec, err := k.store.Get(keyID)
	if err != nil {
		return nil, err
	}
	if err := iam.Authorize(p, iam.Encrypt, keyID, rec.Tenant); err != nil {
		k.log.Append(p.ID, string(iam.Encrypt), keyID, false)
		return nil, err
	}
	env, err := crypto.SealEnvelope(k.master, pt, aad(keyID, rec.Tenant))
	if err != nil {
		return nil, err
	}
	k.log.Append(p.ID, string(iam.Encrypt), keyID, true)
	return env, nil
}

// Decrypt authorizes, then opens the envelope with the same bound AAD.
func (k *KMS) Decrypt(p iam.Principal, keyID string, env *crypto.Envelope) ([]byte, error) {
	rec, err := k.store.Get(keyID)
	if err != nil {
		return nil, err
	}
	if err := iam.Authorize(p, iam.Decrypt, keyID, rec.Tenant); err != nil {
		k.log.Append(p.ID, string(iam.Decrypt), keyID, false)
		return nil, err
	}
	pt, err := crypto.OpenEnvelope(k.master, env, aad(keyID, rec.Tenant))
	if err != nil {
		k.log.Append(p.ID, string(iam.Decrypt), keyID, true)
		return nil, fmt.Errorf("decrypt %s: %w", keyID, err)
	}
	k.log.Append(p.ID, string(iam.Decrypt), keyID, true)
	return pt, nil
}

// CreateKey authorizes against the tenant, then creates the logical key.
func (k *KMS) CreateKey(p iam.Principal, keyID string) error {
	if err := iam.Authorize(p, iam.CreateKey, keyID, p.Tenant); err != nil {
		k.log.Append(p.ID, string(iam.CreateKey), keyID, false)
		return err
	}
	if err := k.store.CreateKey(keyID, p.Tenant); err != nil {
		return err
	}
	k.log.Append(p.ID, string(iam.CreateKey), keyID, true)
	return nil
}
