// Package client fetches the app's configuration from a config server when
// the program starts. Import it for its effect:
//
//	import _ "github.com/vuka-lang/config/v2/client"
//
// When VUKA_CONFIG_URI is set, the package's initialisation, which runs
// after web has read the env files, fetches the snapshot of the app
// (VUKA_APP) in the profile VUKA_ENV (default "default") and sets its values
// in the process environment, so every web.Env call sees them. The real
// environment keeps the last word; the server's values replace those from
// env files; code defaults come last. Without VUKA_CONFIG_URI the package
// does nothing.
//
// The environment variables are:
//
//	VUKA_CONFIG_URI        the server's base URL
//	VUKA_CONFIG_TOKEN      the app's token
//	VUKA_CONFIG_KEY        the server's base64 ed25519 public key
//	VUKA_APP, VUKA_ENV     the app and profile
//	VUKA_CONFIG_LABEL      a branch, tag or commit; default the server's
//	VUKA_CONFIG_CACHE      the file holding the last snapshot received
//	VUKA_CONFIG_FAIL_FAST  1: exit unless a fresh snapshot was fetched
package client

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/web/v2"
)

func init() {
	if os.Getenv("VUKA_CONFIG_URI") == "" {
		return
	}
	if err := Start(FromEnv()); err != nil && os.Getenv("VUKA_CONFIG_FAIL_FAST") == "1" {
		log.Printf("config: %v", err)
		os.Exit(1)
	}
}

// Config is what the client needs to fetch a snapshot.
type Config struct {
	URI, Token, App, Profile, Label string
	// Key is the base64 public key the snapshot's signature is checked against.
	Key string
	// Cache is the file holding the sealed last snapshot; empty is the
	// user cache directory.
	Cache string
	// Backoff lists the waits between attempts; nil is 250ms, 500ms, 1s and 2s.
	Backoff []time.Duration
	// Timeout bounds one attempt; zero is 3s.
	Timeout time.Duration
	// FailFast makes Start return an error unless the snapshot is fresh.
	FailFast bool
}

// FromEnv reads Config from the VUKA_ environment variables.
func FromEnv() Config {
	c := Config{
		URI:      os.Getenv("VUKA_CONFIG_URI"),
		Token:    os.Getenv("VUKA_CONFIG_TOKEN"),
		Key:      os.Getenv("VUKA_CONFIG_KEY"),
		App:      os.Getenv("VUKA_APP"),
		Profile:  os.Getenv("VUKA_ENV"),
		Label:    os.Getenv("VUKA_CONFIG_LABEL"),
		Cache:    os.Getenv("VUKA_CONFIG_CACHE"),
		FailFast: os.Getenv("VUKA_CONFIG_FAIL_FAST") == "1",
	}
	if c.Profile == "" {
		c.Profile = "default"
	}
	return c
}

// Start fetches the snapshot and applies it, falling back to the cached one
// (see the package comment). It returns an error when it could not use a
// fresh snapshot and c.FailFast is set; otherwise it logs and returns nil.
func Start(c Config) error {
	snap, raw, err := fetch(c)
	if err == nil {
		apply(snap)
		if err := writeCache(c, raw); err != nil {
			log.Printf("config: not caching the snapshot: %v", err)
		}
		return nil
	}
	where := server(c.URI)
	if c.FailFast {
		return fmt.Errorf("%s: no fresh snapshot: %w", where, err)
	}
	if cached, cerr := readCache(c); cerr == nil {
		apply(cached)
		log.Printf("config: %s: %v; using the cached snapshot %.12s", where, err, cached.Version)
		return nil
	} else if !errors.Is(cerr, os.ErrNotExist) {
		log.Printf("config: ignoring the cached snapshot: %v", cerr)
	}
	log.Printf("config: error: %s: %v; starting with env files and defaults", where, err)
	return nil
}

func server(uri string) string {
	if u, err := url.Parse(uri); err == nil && u.Host != "" {
		return u.Host
	}
	return "config server"
}

func publicKey(c Config) (ed25519.PublicKey, error) {
	if c.Key == "" {
		return nil, errors.New("VUKA_CONFIG_KEY is not set")
	}
	return config.ParsePublicKey(c.Key)
}

func fetch(c Config) (*config.Snapshot, []byte, error) {
	pub, err := publicKey(c)
	if err != nil {
		return nil, nil, err
	}
	if c.App == "" || c.Token == "" {
		return nil, nil, errors.New("VUKA_APP and VUKA_CONFIG_TOKEN must be set")
	}
	u, err := url.Parse(c.URI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, errors.New("VUKA_CONFIG_URI is not an http(s) URL")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + url.PathEscape(c.App) + "/" + url.PathEscape(c.Profile)
	if c.Label != "" {
		u.Path += "/" + url.PathEscape(c.Label)
	}
	backoff := c.Backoff
	if backoff == nil {
		backoff = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	for i := 0; ; i++ {
		raw, retry, err := get(u.String(), c.Token, timeout)
		if err == nil {
			snap, err := config.Verify(raw, pub)
			if err != nil {
				return nil, nil, err
			}
			if err := check(c, snap); err != nil {
				return nil, nil, err
			}
			return snap, raw, nil
		}
		if !retry || i >= len(backoff) {
			return nil, nil, err
		}
		time.Sleep(backoff[i])
	}
}

func check(c Config, s *config.Snapshot) error {
	if s.App != c.App || s.Profile != c.Profile || (c.Label != "" && s.Label != c.Label) {
		return errors.New("the snapshot is for another app, profile or label")
	}
	return nil
}

func get(rawURL, token string, timeout time.Duration) (body []byte, retry bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, true, errors.New("unreachable")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, true, fmt.Errorf("server error: %s", resp.Status)
	default:
		return nil, false, fmt.Errorf("refused: %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, true, errors.New("reading the snapshot failed")
	}
	return body, false, nil
}

// apply sets the snapshot's values in the process environment, except where
// the real environment has the key. Keys web reserves (VUKA_*) are never set.
func apply(s *config.Snapshot) {
	for k, v := range s.Values {
		if strings.HasPrefix(k, "VUKA_") {
			continue
		}
		if _, set := os.LookupEnv(k); set && !web.EnvFromFile(k) {
			continue
		}
		os.Setenv(k, v)
	}
}

func cachePath(c Config) (string, error) {
	if c.Cache != "" {
		return c.Cache, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	name := c.App + "-" + c.Profile
	if c.Label != "" {
		name += "-" + url.PathEscape(c.Label)
	}
	return filepath.Join(dir, "vuka-config", name+".snapshot"), nil
}

func sealKey(token string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, []byte(token), nil, "vuka-config cache v1", 32)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func cacheAAD(c Config) []byte { return []byte(c.App + "\x00" + c.Profile + "\x00" + c.Label) }

func writeCache(c Config, raw []byte) error {
	path, err := cachePath(c)
	if err != nil {
		return err
	}
	gcm, err := sealKey(c.Token)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	sealed := gcm.Seal(nonce, nonce, raw, cacheAAD(c))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(sealed)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return werr
	}
	return os.Rename(tmp.Name(), path)
}

// readCache opens the cached snapshot: decrypted with the token's key and
// checked against the server's signature.
func readCache(c Config) (*config.Snapshot, error) {
	path, err := cachePath(c)
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := publicKey(c)
	if err != nil {
		return nil, err
	}
	gcm, err := sealKey(c.Token)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("cache file is truncated")
	}
	raw, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], cacheAAD(c))
	if err != nil {
		return nil, errors.New("cache file does not open with this token")
	}
	snap, err := config.Verify(raw, pub)
	if err != nil {
		return nil, err
	}
	return snap, check(c, snap)
}
