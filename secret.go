package config

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// CipherPrefix starts an encrypted value: {cipher}v1:<key-id>:<base64url>.
const CipherPrefix = "{cipher}"

const (
	cipherVersion = "v1"
	cipherInfo    = "vuka-config cipher v1"
	keyDomain     = "vuka-config key v1\n"
)

var (
	// ErrNoKey is returned when no key matches the key-id of a value.
	ErrNoKey = errors.New("no key for its key-id")
	// ErrDecrypt is returned for a value that doesn't open: tampered, or
	// encrypted for another app or another variable.
	ErrDecrypt = errors.New("does not open (altered, or made for another app or variable)")
	// ErrMalformed is returned for a value that is not in the cipher format.
	ErrMalformed = errors.New("not a valid cipher value")
	// ErrSharedSecret is returned for a cipher value in a file every app reads.
	ErrSharedSecret = errors.New("config: a cipher value can't be in a shared file")
)

func kem() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

// IsCipher reports whether v is written as an encrypted value.
func IsCipher(v string) bool { return strings.HasPrefix(v, CipherPrefix) }

// SecretKey is the private half of an app's key pair (or the server's
// decryption key).
type SecretKey struct {
	k  hpke.PrivateKey
	id string
}

// SecretPublicKey is the public half, which values are encrypted to.
type SecretPublicKey struct {
	k  hpke.PublicKey
	id string
}

func keyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:6])
}

// GenerateSecretKey makes a new X25519 key pair.
func GenerateSecretKey() (*SecretKey, error) {
	k, err := kem().GenerateKey()
	if err != nil {
		return nil, err
	}
	return &SecretKey{k, keyID(k.PublicKey().Bytes())}, nil
}

// ParseSecretKey reads a base64 private key.
func ParseSecretKey(s string) (*SecretKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("not a base64 secret key")
	}
	k, err := kem().NewPrivateKey(b)
	if err != nil {
		return nil, errors.New("not a base64 secret key")
	}
	return &SecretKey{k, keyID(k.PublicKey().Bytes())}, nil
}

// ParseSecretKeys reads comma-separated base64 private keys, as
// VUKA_CONFIG_SECRET_KEY lists them during a rotation.
func ParseSecretKeys(s string) ([]*SecretKey, error) {
	var keys []*SecretKey
	for _, e := range strings.Split(s, ",") {
		if strings.TrimSpace(e) == "" {
			continue
		}
		k, err := ParseSecretKey(e)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ParseSecretPublicKey reads a base64 public key.
func ParseSecretPublicKey(s string) (*SecretPublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("not a base64 public key")
	}
	k, err := kem().NewPublicKey(b)
	if err != nil {
		return nil, errors.New("not a base64 public key")
	}
	return &SecretPublicKey{k, keyID(b)}, nil
}

// String is the base64 private key. Printing a SecretKey is only for
// handing it to the operator; use ID in logs.
func (k *SecretKey) String() string {
	b, _ := k.k.Bytes()
	return base64.StdEncoding.EncodeToString(b)
}

// ID is the short fingerprint of the public key that values carry.
func (k *SecretKey) ID() string { return k.id }

// Public returns the public key.
func (k *SecretKey) Public() *SecretPublicKey {
	return &SecretPublicKey{k.k.PublicKey(), k.id}
}

// String is the base64 public key.
func (p *SecretPublicKey) String() string { return base64.StdEncoding.EncodeToString(p.k.Bytes()) }

// ID is the key's short fingerprint.
func (p *SecretPublicKey) ID() string { return p.id }

func cipherAAD(app, name string) []byte {
	return []byte(cipherInfo + "\x00" + app + "\x00" + name)
}

// Encrypt returns the {cipher} value of plaintext for variable name of app,
// encrypted to pub. The ciphertext is bound to the format version, app and
// name: it opens nowhere else.
func Encrypt(pub *SecretPublicKey, app, name string, plaintext []byte) (string, error) {
	enc, s, err := hpke.NewSender(pub.k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(cipherInfo))
	if err != nil {
		return "", err
	}
	ct, err := s.Seal(cipherAAD(app, name), plaintext)
	if err != nil {
		return "", err
	}
	return CipherPrefix + cipherVersion + ":" + pub.id + ":" + base64.RawURLEncoding.EncodeToString(append(enc, ct...)), nil
}

// CipherKeyID returns the key-id a cipher value was encrypted to.
func CipherKeyID(v string) (string, error) {
	id, _, err := splitCipher(v)
	return id, err
}

func splitCipher(v string) (id string, body []byte, err error) {
	rest, ok := strings.CutPrefix(v, CipherPrefix+cipherVersion+":")
	if !ok {
		return "", nil, ErrMalformed
	}
	id, enc, ok := strings.Cut(rest, ":")
	if !ok || id == "" {
		return "", nil, ErrMalformed
	}
	body, err = base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(body) < 32+16 {
		return "", nil, ErrMalformed
	}
	return id, body, nil
}

// Decrypt opens the cipher value v of variable name of app with the key
// whose id it carries. Errors never include the value.
func Decrypt(keys []*SecretKey, app, name, v string) (string, error) {
	id, body, err := splitCipher(v)
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if k.id != id {
			continue
		}
		r, err := hpke.NewRecipient(body[:32], k.k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(cipherInfo))
		if err != nil {
			return "", ErrDecrypt
		}
		pt, err := r.Open(cipherAAD(app, name), body[32:])
		if err != nil {
			return "", ErrDecrypt
		}
		return string(pt), nil
	}
	return "", fmt.Errorf("%w (%s)", ErrNoKey, id)
}

// ParseAppKeys reads app=<base64 public key> entries, one per line or
// separated by commas; blank lines and # comments are ignored. An app
// listed twice is an error.
func ParseAppKeys(text string) (map[string]*SecretPublicKey, error) {
	out := map[string]*SecretPublicKey{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e == "" {
				continue
			}
			app, key, ok := strings.Cut(e, "=")
			app = strings.TrimSpace(app)
			pub, err := ParseSecretPublicKey(key)
			if !ok || err != nil || !ValidApp(app) {
				return nil, fmt.Errorf("config: app keys: want app=<base64 public key>, got an entry for %q", app)
			}
			if _, dup := out[app]; dup {
				return nil, fmt.Errorf("config: app keys: %q is listed twice", app)
			}
			out[app] = pub
		}
	}
	return out, sc.Err()
}

func keyMessage(subject string, pub *SecretPublicKey) []byte {
	return []byte(keyDomain + subject + "\n" + pub.String())
}

// KeyResponse is what GET /_keys/{app} (and GET /_keys, the server's
// decryption key) returns: a public key and the server's signature over it
// and who it is for.
type KeyResponse struct {
	// Subject is "app <name>" or "server".
	Subject   string `json:"subject"`
	Key       string `json:"key"`
	ID        string `json:"id"`
	Signature string `json:"signature"`
}

// AppSubject and ServerSubject name whose key a KeyResponse carries.
func AppSubject(app string) string { return "app " + app }

// ServerSubject is the subject of the server's decryption key.
const ServerSubject = "server"

func signKey(priv ed25519.PrivateKey, subject string, pub *SecretPublicKey) KeyResponse {
	sig := ed25519.Sign(priv, keyMessage(subject, pub))
	return KeyResponse{Subject: subject, Key: pub.String(), ID: pub.id, Signature: base64.StdEncoding.EncodeToString(sig)}
}

// VerifyKey checks a KeyResponse against the server's signing key and the
// subject that was asked for, and returns the public key.
func VerifyKey(r KeyResponse, subject string, pub ed25519.PublicKey) (*SecretPublicKey, error) {
	k, err := ParseSecretPublicKey(r.Key)
	sig, serr := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || serr != nil || r.Subject != subject || r.ID != k.id ||
		len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, keyMessage(subject, k), sig) {
		return nil, ErrSignature
	}
	return k, nil
}
