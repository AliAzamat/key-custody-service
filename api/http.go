// Package api exposes the KMS over HTTP. It translates an authenticated request
// into an iam.Principal (the auth middleware is assumed upstream — see the
// backend-go-oauth and auth-oauth-rbac prereqs), calls the service, and maps
// domain errors to status codes WITHOUT echoing key material or plaintext.
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"example.com/kcs/crypto"
	"example.com/kcs/iam"
	"example.com/kcs/service"
	"example.com/kcs/store"
)

type Handler struct{ kms *service.KMS }

func NewHandler(kms *service.KMS) *Handler { return &Handler{kms: kms} }

type encryptReq struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"` // base64
}
type encryptResp struct {
	WrappedDEK string `json:"wrapped_dek"` // base64
	Ciphertext string `json:"ciphertext"`  // base64
}

// Encrypt handles POST /encrypt. The Principal comes from the auth middleware.
func (h *Handler) Encrypt(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	var req encryptReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	env, err := h.kms.Encrypt(p, req.KeyID, pt)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, encryptResp{
		WrappedDEK: base64.StdEncoding.EncodeToString(env.WrappedDEK),
		Ciphertext: base64.StdEncoding.EncodeToString(env.Ciphertext),
	})
}

// writeErr maps domain errors to status codes. A forbidden request and a
// missing key are the two the caller sees distinctly; a decrypt failure is a
// generic 400 so we never confirm whether a blob was "close."
func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, iam.ErrForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, store.ErrKeyNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, crypto.ErrDecrypt):
		http.Error(w, "bad request", http.StatusBadRequest)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// principalFrom builds the caller identity from context the auth middleware set.
func principalFrom(r *http.Request) iam.Principal {
	if p, ok := r.Context().Value(principalKey).(iam.Principal); ok {
		return p
	}
	return iam.Principal{} // empty principal — no grants, denied everywhere
}

type ctxKey int

const principalKey ctxKey = 0
