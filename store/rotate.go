package store

import "time"

// Rotate adds a new version to a key and makes it active. The previously-active
// version is marked retired (retired_at set) but is NOT deleted — ciphertext
// written under it must keep decrypting. Rotation is cheap: it touches only the
// key's metadata, never the data encrypted under it.
func (s *Store) Rotate(id string) (newVersion int, err error) {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var active int
	if err := tx.QueryRow(
		`SELECT active_ver FROM keys WHERE id = ?`, id).Scan(&active); err != nil {
		return 0, err
	}
	newVersion = active + 1

	// Retire the old version — superseded, still decrypts.
	if _, err := tx.Exec(
		`UPDATE key_versions SET retired_at = ? WHERE key_id = ? AND version = ?`,
		now, id, active); err != nil {
		return 0, err
	}
	// Add the new version and point the key at it.
	if _, err := tx.Exec(
		`INSERT INTO key_versions(key_id, version, created_at) VALUES(?,?,?)`,
		id, newVersion, now); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(
		`UPDATE keys SET active_ver = ? WHERE id = ?`, newVersion, id); err != nil {
		return 0, err
	}
	return newVersion, tx.Commit()
}
