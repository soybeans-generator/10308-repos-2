package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// newPKCE generates a code verifier and its S256 code challenge, the way the
// app does it for the Auth0 authorization-code + PKCE flow.
func newPKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf) // 43 chars
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
