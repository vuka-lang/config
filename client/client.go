// Package client fetches the app's configuration from a config server when
// the program starts. Import it for its effect:
//
//	import _ "github.com/vuka-lang/config/v2/client"
//
// When VUKA_CONFIG_URI is set, the package's initialisation, which runs
// after web has read the env files, fetches the snapshot of the app
// (VUKA_APP) in the profile VUKA_ENV (none if unset) and sets its values
// in the process environment, so every web.Env call sees them. The real
// environment keeps the last word; the server's values replace those from
// env files; code defaults come last. Without VUKA_CONFIG_URI the package
// does nothing.
//
// A {cipher} value is decrypted with the app's secret keys after the
// signature has been checked, before it is applied. One that cannot be
// decrypted is never applied as it is: the start fails with an error naming
// the variable, whatever VUKA_CONFIG_FAIL_FAST says (that variable is about
// the server being unreachable; a secret the app can't open is a
// misconfiguration, and running without it is worse than not running). A key
// the real environment already sets is not decrypted and so can't fail.
//
// After start the client follows the snapshot: it holds a stream open to the
// server's /watch endpoint (reconnecting with backoff) and also checks the
// version every 30 s, so a lost stream costs at most that. A new version is
// fetched, its signature checked and its {cipher} values decrypted, and only
// then applied with web.ApplyEnv: web.Env reads the new value at its next
// call, web.Hot handles stay current and web.OnEnvChange callbacks run. A
// snapshot that fails any of those checks is not applied: the app keeps the
// values it has, the error is logged naming the server and the variables
// (never a value), and the client goes on following. A client that started
// without any snapshot keeps trying and applies the first it gets. Applied
// changes are logged by key only. VUKA_CONFIG_WATCH=0 turns following off.
//
// The environment variables are:
//
//	VUKA_CONFIG_URI        the server's base URL
//	VUKA_CONFIG_TOKEN      the app's token
//	VUKA_CONFIG_KEY        the server's base64 ed25519 public key
//	VUKA_CONFIG_SECRET_KEY the app's base64 private key(s), comma-separated
//	                       during a rotation; removed from the environment
//	                       once read
//	VUKA_APP, VUKA_ENV     the app and profile
//	VUKA_CONFIG_LABEL      a branch, tag or commit; default the server's
//	VUKA_CONFIG_CACHE      the file holding the last snapshot received
//	VUKA_CONFIG_FAIL_FAST  1: exit unless a fresh snapshot was fetched
//	VUKA_CONFIG_WATCH      0: fetch at start only, don't follow changes
package client

import (
	"bufio"
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
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/web/v2"
)

func init() {
	if os.Getenv("VUKA_CONFIG_URI") == "" {
		return
	}
	c := FromEnv()
	os.Unsetenv("VUKA_CONFIG_SECRET_KEY")
	if err := Start(c); err != nil {
		log.Printf("config: %v", err)
		os.Exit(1)
	}
}

// Config is what the client needs to fetch a snapshot.
type Config struct {
	URI, Token, App, Profile, Label string
	// Key is the base64 public key the snapshot's signature is checked against.
	Key string
	// SecretKeys is the app's base64 private key, or several comma-separated.
	SecretKeys string
	// Cache is the file holding the sealed last snapshot; empty is the
	// user cache directory.
	Cache string
	// Backoff lists the waits between attempts; nil is 250ms, 500ms, 1s and 2s.
	Backoff []time.Duration
	// Timeout bounds one attempt; zero is 3s.
	Timeout time.Duration
	// FailFast makes Start return an error unless the snapshot is fresh.
	FailFast bool
	// NoWatch makes the client fetch at start only.
	NoWatch bool
	// Poll is how often the version is checked besides the stream; zero is 30s.
	Poll time.Duration
	// Reconnect is the first wait before the stream is opened again, doubling
	// to thirty times that; zero is 1s.
	Reconnect time.Duration
}

// FromEnv reads Config from the VUKA_ environment variables.
func FromEnv() Config {
	c := Config{
		URI:        os.Getenv("VUKA_CONFIG_URI"),
		Token:      os.Getenv("VUKA_CONFIG_TOKEN"),
		Key:        os.Getenv("VUKA_CONFIG_KEY"),
		SecretKeys: os.Getenv("VUKA_CONFIG_SECRET_KEY"),
		App:        os.Getenv("VUKA_APP"),
		Profile:    os.Getenv("VUKA_ENV"),
		Label:      os.Getenv("VUKA_CONFIG_LABEL"),
		Cache:      os.Getenv("VUKA_CONFIG_CACHE"),
		FailFast:   os.Getenv("VUKA_CONFIG_FAIL_FAST") == "1",
		NoWatch:    os.Getenv("VUKA_CONFIG_WATCH") == "0",
	}
	return c
}

// Client is a started client: the snapshot it applied and, unless Config
// said otherwise, the goroutines that follow the server.
type Client struct {
	c      Config
	cancel context.CancelFunc
	ctx    context.Context
	wg     sync.WaitGroup
	hints  chan string
	once   sync.Once

	// owned by the start-up, then by the loop goroutine
	applied map[string]string
	version string
	have    bool
	failed  string
	logged  string
}

// Start fetches the snapshot and applies it, falling back to the cached one
// (see the package comment), then follows the server for the life of the
// process. It returns an error when it could not use a fresh snapshot and
// c.FailFast is set, or when a {cipher} value can't be decrypted; otherwise
// it logs and returns nil.
func Start(c Config) error {
	_, err := Open(c)
	return err
}

// Open is Start that returns the Client, to stop its following.
func Open(c Config) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &Client{c: c, ctx: ctx, cancel: cancel, hints: make(chan string, 1), applied: map[string]string{}}
	if err := cl.start(); err != nil {
		cancel()
		return nil, err
	}
	if !c.NoWatch {
		cl.wg.Add(2)
		go cl.loop()
		go cl.stream()
	}
	return cl, nil
}

// Stop ends the following and waits for it. It must not be called from an
// OnEnvChange callback, which runs in the following goroutine.
func (cl *Client) Stop() {
	cl.once.Do(cl.cancel)
	cl.wg.Wait()
}

func (cl *Client) start() error {
	c := cl.c
	snap, raw, err := fetch(cl.ctx, c)
	if err == nil {
		values, err := cl.resolve(snap)
		if err != nil {
			return err
		}
		cl.apply(values, snap.Version)
		if err := writeCache(c, raw); err != nil {
			log.Printf("config: not caching the snapshot: %v", err)
		}
		return nil
	}
	fetchErr := err
	where := server(c.URI)
	if c.FailFast {
		return fmt.Errorf("%s: no fresh snapshot: %w", where, fetchErr)
	}
	if cached, cerr := readCache(c); cerr == nil {
		values, err := cl.resolve(cached)
		if err != nil {
			return err
		}
		cl.apply(values, cached.Version)
		log.Printf("config: %s: %v; using the cached snapshot %.12s", where, fetchErr, cached.Version)
		return nil
	} else if !errors.Is(cerr, os.ErrNotExist) {
		log.Printf("config: ignoring the cached snapshot: %v", cerr)
	}
	log.Printf("config: error: %s: %v; starting with env files and defaults", where, fetchErr)
	return nil
}

func (cl *Client) apply(values map[string]string, version string) []web.EnvChange {
	cl.applied, cl.version, cl.have = values, version, true
	return web.ApplyEnv("config", values)
}

// loop applies new versions: when the stream hints at one, when the periodic
// check finds one, and, while there is no snapshot at all, on a backoff.
func (cl *Client) loop() {
	defer cl.wg.Done()
	retry := cl.reconnect()
	t := time.NewTimer(0)
	defer t.Stop()
	<-t.C
	for {
		wait := jitter(capDuration(cl.c.Poll, 30*time.Second))
		if !cl.have {
			wait = jitter(retry)
			retry = min(retry*2, 30*cl.reconnect())
		}
		t.Reset(wait)
		hint := ""
		select {
		case <-cl.ctx.Done():
			return
		case hint = <-cl.hints:
		case <-t.C:
		}
		cl.refresh(hint)
	}
}

func (cl *Client) refresh(hint string) {
	where := server(cl.c.URI)
	switch {
	case hint != "" && (hint == cl.version || hint == cl.failed):
		return
	case hint == "" && cl.have:
		v, err := head(cl.ctx, cl.c)
		if err != nil {
			cl.report(where, err)
			return
		}
		if v == cl.version || v == cl.failed {
			cl.logged = ""
			return
		}
	}
	c := cl.c
	c.Backoff = []time.Duration{}
	snap, raw, err := fetch(cl.ctx, c)
	if err != nil {
		cl.report(where, err)
		return
	}
	cl.logged = ""
	if snap.Version == cl.version {
		return
	}
	values, err := cl.resolve(snap)
	if err != nil {
		cl.failed = snap.Version
		log.Printf("config: error: %s: not applying version %.12s, keeping the current values: %v", where, snap.Version, err)
		return
	}
	cl.failed = ""
	changes := cl.apply(values, snap.Version)
	if err := writeCache(c, raw); err != nil {
		log.Printf("config: not caching the snapshot: %v", err)
	}
	if n := len(changes); n > 0 {
		keys := make([]string, n)
		for i, ch := range changes {
			keys[i] = ch.Key
		}
		noun := "changes"
		if n == 1 {
			noun = "change"
		}
		log.Printf("config: applied %d %s (version %.12s): %s", n, noun, snap.Version, strings.Join(keys, ", "))
	}
}

// report logs a failed fetch once until a fetch works again.
func (cl *Client) report(where string, err error) {
	if cl.ctx.Err() != nil || err.Error() == cl.logged {
		return
	}
	cl.logged = err.Error()
	log.Printf("config: error: %s: not applying an update: %v", where, err)
}

func (cl *Client) reconnect() time.Duration { return capDuration(cl.c.Reconnect, time.Second) }

func capDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func jitter(d time.Duration) time.Duration {
	return d/2 + mrand.N(d/2+1)
}

const streamIdle = 90 * time.Second

// stream keeps the /watch stream open and passes each version it announces
// to loop.
func (cl *Client) stream() {
	defer cl.wg.Done()
	base := cl.reconnect()
	delay := base
	for cl.ctx.Err() == nil {
		start := time.Now()
		if cl.watchOnce() || time.Since(start) > 10*time.Second {
			delay = base
		}
		select {
		case <-cl.ctx.Done():
			return
		case <-time.After(jitter(delay)):
		}
		delay = min(delay*2, 30*base)
	}
}

// watchOnce reads one stream until it ends; it reports whether the stream
// announced a version.
func (cl *Client) watchOnce() bool {
	u, err := endpoint(cl.c, true)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithCancel(cl.ctx)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+cl.c.Token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return false
	}
	idle := time.AfterFunc(streamIdle, cancel)
	defer idle.Stop()
	got := false
	event := ""
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		idle.Reset(streamIdle)
		line := sc.Text()
		switch {
		case line == "":
			event = ""
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:") && event == "version":
			got = true
			select {
			case <-cl.hints:
			default:
			}
			cl.hints <- strings.TrimSpace(line[len("data:"):])
		}
	}
	return got
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

// endpoint is the URL of the snapshot, or of its watch stream.
func endpoint(c Config, watch bool) (string, error) {
	u, err := url.Parse(c.URI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("VUKA_CONFIG_URI is not an http(s) URL")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + url.PathEscape(c.App) + "/" + profileSegment(c.Profile)
	switch {
	case watch:
		u.Path += "/watch"
		if c.Label != "" {
			u.RawQuery = url.Values{"label": {c.Label}}.Encode()
		}
	case c.Label != "":
		u.Path += "/" + url.PathEscape(c.Label)
	}
	return u.String(), nil
}

func fetch(ctx context.Context, c Config) (*config.Snapshot, []byte, error) {
	pub, err := publicKey(c)
	if err != nil {
		return nil, nil, err
	}
	if c.App == "" || c.Token == "" {
		return nil, nil, errors.New("VUKA_APP and VUKA_CONFIG_TOKEN must be set")
	}
	u, err := endpoint(c, false)
	if err != nil {
		return nil, nil, err
	}
	backoff := c.Backoff
	if backoff == nil {
		backoff = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}
	}
	for i := 0; ; i++ {
		raw, _, retry, err := get(ctx, http.MethodGet, u, c.Token, timeoutOf(c))
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
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(backoff[i]):
		}
	}
}

func timeoutOf(c Config) time.Duration { return capDuration(c.Timeout, 3*time.Second) }

// head asks for the snapshot's version without its body. The header is a
// hint that a fetch is worth making; only a verified snapshot is applied.
func head(ctx context.Context, c Config) (string, error) {
	u, err := endpoint(c, false)
	if err != nil {
		return "", err
	}
	_, hdr, _, err := get(ctx, http.MethodHead, u, c.Token, timeoutOf(c))
	if err != nil {
		return "", err
	}
	return hdr.Get("X-Config-Version"), nil
}

func profileSegment(p string) string {
	if p == "" {
		return config.NoProfile
	}
	return url.PathEscape(p)
}

func check(c Config, s *config.Snapshot) error {
	if s.App != c.App || s.Profile != c.Profile || (c.Label != "" && s.Label != c.Label) {
		return errors.New("the snapshot is for another app, profile or label")
	}
	return nil
}

func get(ctx context.Context, method, rawURL, token string, timeout time.Duration) (body []byte, hdr http.Header, retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, true, errors.New("unreachable")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, nil, true, fmt.Errorf("server error: %s", resp.Status)
	default:
		return nil, nil, false, fmt.Errorf("refused: %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, true, errors.New("reading the snapshot failed")
	}
	return body, resp.Header, false, nil
}

// wanted reports whether the snapshot's value for k would be applied: not a
// key web reserves (VUKA_*), and not one the real environment has. A key
// holding the value the client applied last is the client's own.
func (cl *Client) wanted(k string) bool {
	if strings.HasPrefix(k, "VUKA_") {
		return false
	}
	cur, set := os.LookupEnv(k)
	if prev, ok := cl.applied[k]; ok && set && cur == prev {
		return true
	}
	return !set || web.EnvFromFile(k)
}

// resolve returns the values to apply, with every {cipher} value decrypted
// for the snapshot's app. If any can't be, the error names them, never
// their values.
func (cl *Client) resolve(s *config.Snapshot) (map[string]string, error) {
	c := cl.c
	out := make(map[string]string, len(s.Values))
	var secrets []string
	for k, v := range s.Values {
		if !cl.wanted(k) {
			continue
		}
		out[k] = v
		if config.IsCipher(v) {
			secrets = append(secrets, k)
		}
	}
	if len(secrets) == 0 {
		return out, nil
	}
	sort.Strings(secrets)
	keys, kerr := config.ParseSecretKeys(c.SecretKeys)
	var failed []string
	for _, k := range secrets {
		var err error
		switch {
		case c.SecretKeys == "":
			err = errors.New("VUKA_CONFIG_SECRET_KEY is not set")
		case kerr != nil:
			err = errors.New("VUKA_CONFIG_SECRET_KEY is not a valid key list")
		default:
			out[k], err = config.Decrypt(keys, s.App, k, s.Values[k])
		}
		if err != nil {
			failed = append(failed, k+" ("+err.Error()+")")
		}
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("cannot decrypt %s", strings.Join(failed, ", "))
	}
	return out, nil
}

func cachePath(c Config) (string, error) {
	if c.Cache != "" {
		return c.Cache, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	name := profileSegment(c.Profile)
	if c.Label != "" {
		name += "@" + url.PathEscape(c.Label)
	}
	return filepath.Join(dir, "vuka-config", url.PathEscape(c.App), name+".snapshot"), nil
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
