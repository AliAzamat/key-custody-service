// Package store persists logical keys and their versions. It never stores a
// plaintext DEK — DEKs live inside envelopes the caller holds. What it stores
// is the key's identity, its versions, and which version is currently active.
package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrKeyNotFound = errors.New("store: key not found")

type KeyRecord struct {
	ID        string
	Tenant    string
	ActiveVer int
}

type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

// CreateKey inserts a logical key with version 1 active.
func (s *Store) CreateKey(id, tenant string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO keys(id, tenant, active_ver, created_at) VALUES(?,?,1,?)`,
		id, tenant, now); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO key_versions(key_id, version, created_at) VALUES(?,1,?)`,
		id, now); err != nil {
		return err
	}
	return tx.Commit()
}

// Get returns the logical key and its active version.
func (s *Store) Get(id string) (*KeyRecord, error) {
	row := s.db.QueryRow(
		`SELECT id, tenant, active_ver FROM keys WHERE id = ?`, id)
	var k KeyRecord
	switch err := row.Scan(&k.ID, &k.Tenant, &k.ActiveVer); err {
	case nil:
		return &k, nil
	case sql.ErrNoRows:
		return nil, ErrKeyNotFound
	default:
		return nil, err
	}
}

// VersionExists reports whether a (key, version) pair is known, so a decrypt
// can accept any historical version, not only the active one.
func (s *Store) VersionExists(id string, version int) (bool, error) {
	row := s.db.QueryRow(
		`SELECT 1 FROM key_versions WHERE key_id = ? AND version = ?`,
		id, version)
	var one int
	switch err := row.Scan(&one); err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}
