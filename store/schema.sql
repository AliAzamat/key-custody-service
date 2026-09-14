-- A logical key belongs to a tenant and points at one ACTIVE version.
-- Rotation adds a version and moves the pointer; it never deletes a version.
CREATE TABLE keys (
    id          TEXT PRIMARY KEY,   -- logical key id, e.g. "wallet-signing"
    tenant      TEXT NOT NULL,
    active_ver  INTEGER NOT NULL,   -- which version new Encrypts use
    created_at  TEXT NOT NULL
);

-- Every version of every key. Old versions are kept forever so ciphertext
-- written under them still decrypts. We store only wrapped/derived material
-- here for the model where versions are derived; the master key is external.
CREATE TABLE key_versions (
    key_id      TEXT NOT NULL,
    version     INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    retired_at  TEXT,               -- set when superseded; still decrypts
    PRIMARY KEY (key_id, version),
    FOREIGN KEY (key_id) REFERENCES keys(id)
);
