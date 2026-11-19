package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	snapshotDomain = "vuka-config snapshot v1\n"
	envDomain      = "vuka-config env v1\n"
)

// Canonical returns the bytes a snapshot's signature covers: the snapshot as
// JSON without its "signature" member, every object's keys sorted bytewise,
// no whitespace, strings escaped as encoding/json does with HTML escaping
// off, preceded by the line "vuka-config snapshot v1". raw is any JSON
// object; members the reader doesn't know are covered too.
func Canonical(raw []byte) ([]byte, error) {
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("config: snapshot: %w", err)
	}
	delete(v, "signature")
	var b bytes.Buffer
	b.WriteString(snapshotDomain)
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Sign sets s.Signature.
func (s *Snapshot) Sign(key ed25519.PrivateKey) error {
	s.Signature = ""
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	msg, err := Canonical(raw)
	if err != nil {
		return err
	}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	return nil
}

// ErrSignature is returned for a snapshot whose signature doesn't verify.
var ErrSignature = errors.New("config: bad snapshot signature")

// Verify checks the signature of the JSON snapshot raw against pub and
// returns the snapshot.
func Verify(raw []byte, pub ed25519.PublicKey) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("config: snapshot: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	msg, err := Canonical(raw)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, ErrSignature
	}
	return &s, nil
}

// SignEnv signs the body of an .env response.
func SignEnv(key ed25519.PrivateKey, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(envDomain), body...)))
}

// VerifyEnv checks the signature of an .env response body.
func VerifyEnv(pub ed25519.PublicKey, body []byte, sig string) bool {
	b, err := base64.StdEncoding.DecodeString(sig)
	return err == nil && ed25519.Verify(pub, append([]byte(envDomain), body...), b)
}

// ParsePublicKey reads a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("config: not a base64 ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey reads a base64 ed25519 seed.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("config: not a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(b), nil
}
