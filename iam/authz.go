// Package iam authorizes every key operation. The rule is DENY BY DEFAULT:
// unless a principal has an explicit grant for this action on this key, the
// request is refused. There is no implicit "owner can do anything."
package iam

import (
	"errors"
	"slices"
)

var ErrForbidden = errors.New("iam: forbidden")

// Action is a key operation a grant can allow.
type Action string

const (
	Encrypt   Action = "encrypt"
	Decrypt   Action = "decrypt"
	CreateKey Action = "create_key"
	Rotate    Action = "rotate"
)

// Principal is the authenticated caller. Tenant scopes it; Grants are its
// explicit allowances. An empty Grants slice can do nothing.
type Principal struct {
	ID      string
	Tenant  string
	Grants  []Grant
}

// Grant allows a set of Actions on a set of key ids. "*" as a key id means any
// key WITHIN the principal's tenant — never across tenants.
type Grant struct {
	KeyIDs  []string
	Actions []Action
}

// Authorize returns nil only if the principal has an explicit grant for action
// on keyID within its own tenant. Everything else is ErrForbidden.
func Authorize(p Principal, action Action, keyID, keyTenant string) error {
	// Tenant isolation is not a grant — it is a hard wall. A principal can
	// never touch another tenant's key, whatever its grants say.
	if p.Tenant != keyTenant {
		return ErrForbidden
	}
	for _, g := range p.Grants {
		if !slices.Contains(g.Actions, action) {
			continue
		}
		if slices.Contains(g.KeyIDs, keyID) || slices.Contains(g.KeyIDs, "*") {
			return nil
		}
	}
	return ErrForbidden
}
