// Package audit records every key operation in an append-only, hash-chained
// log. Each entry's hash covers the entry's fields AND the previous entry's
// hash, so the entries form a chain: change or remove any past entry and every
// later hash no longer matches. You cannot quietly rewrite history.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Entry is one recorded operation. PrevHash links it to the entry before it;
// Hash commits to this entry's contents plus PrevHash.
type Entry struct {
	Seq       int
	Time      string
	Principal string
	Action    string
	KeyID     string
	Allowed   bool
	PrevHash  string
	Hash      string
}

// GenesisHash seeds the chain — the PrevHash of the first entry.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// computeHash hashes the entry's fields together with prevHash. Any change to
// any field, or to the link, changes this hash.
func computeHash(e Entry, prevHash string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%t|%s",
		e.Seq, e.Time, e.Principal, e.Action, e.KeyID, e.Allowed, prevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// Log is an append-only chain of entries held in order.
type Log struct{ entries []Entry }

func (l *Log) last() string {
	if len(l.entries) == 0 {
		return GenesisHash
	}
	return l.entries[len(l.entries)-1].Hash
}

// Append records an operation, linking it to the current chain head.
func (l *Log) Append(principal, action, keyID string, allowed bool) Entry {
	e := Entry{
		Seq:       len(l.entries) + 1,
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Principal: principal,
		Action:    action,
		KeyID:     keyID,
		Allowed:   allowed,
		PrevHash:  l.last(),
	}
	e.Hash = computeHash(e, e.PrevHash)
	l.entries = append(l.entries, e)
	return e
}

// Verify re-walks the chain and returns the sequence number of the first entry
// whose stored hash or link does not recompute — 0 means the chain is intact.
func (l *Log) Verify() int {
	prev := GenesisHash
	for _, e := range l.entries {
		if e.PrevHash != prev {
			return e.Seq
		}
		if computeHash(e, prev) != e.Hash {
			return e.Seq
		}
		prev = e.Hash
	}
	return 0
}
