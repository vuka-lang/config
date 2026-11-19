package client_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/vuka-lang/config/v2"
)

const plainSecret = "s3cret-db-pw-9d1f"

func mkKey(t *testing.T) *config.SecretKey {
	t.Helper()
	k, err := config.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, k *config.SecretKey, app, name, value string) string {
	t.Helper()
	v, err := config.Encrypt(k.Public(), app, name, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func secretRun(t *testing.T, files map[string]string, key string) (*server, *run) {
	t.Helper()
	s := newServer(t, files, nil)
	r := newRun(t, s)
	r.env["CLIENT_PROBE"] = "DB_PASSWORD,API_KEY,PLAIN,A"
	if key != "" {
		r.env["VUKA_CONFIG_SECRET_KEY"] = key
	}
	return s, r
}

func noLeak(t *testing.T, res result, secrets ...string) {
	t.Helper()
	checkLogs(t, res)
	for _, s := range append(secrets, plainSecret) {
		if strings.Contains(res.stderr, s) {
			t.Errorf("the log holds %q:\n%s", s, res.stderr)
		}
	}
}

func failsNaming(t *testing.T, res result, vars ...string) {
	t.Helper()
	if res.code == 0 {
		t.Fatalf("started: %v", res.env)
	}
	if !strings.Contains(res.stderr, "cannot decrypt") {
		t.Errorf("log: %q", res.stderr)
	}
	for _, v := range vars {
		if !strings.Contains(res.stderr, v) {
			t.Errorf("the log doesn't name %s: %q", v, res.stderr)
		}
	}
	noLeak(t, res)
}

func TestSecretRoundTripAndPrecedence(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	files := map[string]string{
		".env":                   "A=server-shared\n",
		"orders/.env.production": "DB_PASSWORD=" + seal(t, k, "orders", "DB_PASSWORD", plainSecret) + "\nPLAIN=x\n",
	}
	_, r := secretRun(t, files, k.String())
	os.WriteFile(r.dir+"/.env", []byte("A=file\nDB_PASSWORD=from-file\n"), 0o644)
	res := r.exec(t)
	want(t, res, map[string]string{"DB_PASSWORD": plainSecret, "web:DB_PASSWORD": plainSecret, "PLAIN": "x", "A": "server-shared"})
	noLeak(t, res)

	// the real environment still has the last word, and then nothing is decrypted
	r.env["DB_PASSWORD"] = "real"
	delete(r.env, "VUKA_CONFIG_SECRET_KEY")
	res = r.exec(t)
	want(t, res, map[string]string{"DB_PASSWORD": "real", "A": "server-shared"})
	if res.code != 0 {
		t.Errorf("a pinned key needed the secret key: %s", res.stderr)
	}
}

func TestSecretKeyLeavesTheEnvironment(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	_, r := secretRun(t, map[string]string{"orders/.env.production": "PLAIN=x\n"}, k.String())
	r.env["CLIENT_PROBE"] = "PLAIN,VUKA_CONFIG_SECRET_KEY"
	res := r.exec(t)
	if res.env["VUKA_CONFIG_SECRET_KEY"] != "" || res.env["PLAIN"] != "x" {
		t.Errorf("%v", res.env)
	}
}

func TestSecretBoundToApp(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	// orders' ciphertext copied into billing's folder, read by billing holding the same key
	files := map[string]string{"billing/.env.production": "DB_PASSWORD=" + seal(t, k, "orders", "DB_PASSWORD", plainSecret) + "\n"}
	_, r := secretRun(t, files, k.String())
	r.env["VUKA_APP"], r.env["VUKA_CONFIG_TOKEN"] = "billing", billingToken
	failsNaming(t, r.exec(t), "DB_PASSWORD")
}

func TestSecretBoundToVariable(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	files := map[string]string{"orders/.env.production": "API_KEY=" + seal(t, k, "orders", "DB_PASSWORD", plainSecret) + "\nPLAIN=x\n"}
	_, r := secretRun(t, files, k.String())
	failsNaming(t, r.exec(t), "API_KEY")
}

func TestSecretRotation(t *testing.T) {
	t.Parallel()
	old, cur := mkKey(t), mkKey(t)
	files := map[string]string{"orders/.env.production": "DB_PASSWORD=" + seal(t, old, "orders", "DB_PASSWORD", plainSecret) +
		"\nAPI_KEY=" + seal(t, cur, "orders", "API_KEY", "new-api-key") + "\n"}
	_, r := secretRun(t, files, cur.String()+","+old.String())
	want(t, r.exec(t), map[string]string{"DB_PASSWORD": plainSecret, "API_KEY": "new-api-key"})

	r.env["VUKA_CONFIG_SECRET_KEY"] = cur.String() // the old key is gone
	res := r.exec(t)
	failsNaming(t, res, "DB_PASSWORD")
	if strings.Contains(res.stderr, "API_KEY") {
		t.Errorf("a value under the current key failed: %q", res.stderr)
	}
}

func TestSecretFailsClosed(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	good := seal(t, k, "orders", "DB_PASSWORD", plainSecret)
	tampered := []byte(good)
	tampered[len(tampered)-4] ^= 0x02
	for name, c := range map[string]struct {
		file, key string
		vars      []string
	}{
		"no key":        {"DB_PASSWORD=" + good, "", []string{"DB_PASSWORD"}},
		"another key":   {"DB_PASSWORD=" + good, mkKey(t).String(), []string{"DB_PASSWORD"}},
		"junk key":      {"DB_PASSWORD=" + good, "not-a-key", []string{"DB_PASSWORD"}},
		"tampered":      {"DB_PASSWORD=" + string(tampered), k.String(), []string{"DB_PASSWORD"}},
		"malformed":     {"DB_PASSWORD={cipher}v1:abc", k.String(), []string{"DB_PASSWORD"}},
		"two of three":  {"DB_PASSWORD=" + good + "\nAPI_KEY={cipher}v1:abc\nPLAIN={cipher}zzz", k.String(), []string{"API_KEY", "PLAIN"}},
		"plain looking": {"DB_PASSWORD={cipher}" + plainSecret, k.String(), []string{"DB_PASSWORD"}},
	} {
		_, r := secretRun(t, map[string]string{"orders/.env.production": c.file + "\n"}, c.key)
		res := r.exec(t)
		t.Run(name, func(t *testing.T) {
			failsNaming(t, res, c.vars...)
			if strings.Contains(res.stderr, good) || strings.Contains(res.stderr, string(tampered)) {
				t.Errorf("the log holds a ciphertext: %q", res.stderr)
			}
		})
	}
}

func TestSecretFailsWhateverFailFastSays(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	files := map[string]string{"orders/.env.production": "DB_PASSWORD=" + seal(t, k, "orders", "DB_PASSWORD", plainSecret) + "\n"}
	_, r := secretRun(t, files, "")
	for _, ff := range []string{"-", "1"} {
		r.env["VUKA_CONFIG_FAIL_FAST"] = ff
		failsNaming(t, r.exec(t), "DB_PASSWORD")
	}
}

func TestSecretFromTheCache(t *testing.T) {
	t.Parallel()
	k := mkKey(t)
	files := map[string]string{"orders/.env.production": "DB_PASSWORD=" + seal(t, k, "orders", "DB_PASSWORD", plainSecret) + "\n"}
	s, r := secretRun(t, files, k.String())
	r.exec(t)
	sealed, err := os.ReadFile(r.cache)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(plainSecret)) {
		t.Error("the plaintext is in the cache file")
	}
	s.Close()
	res := r.exec(t)
	want(t, res, map[string]string{"DB_PASSWORD": plainSecret})
	if !strings.Contains(res.stderr, "cached snapshot") {
		t.Errorf("log: %q", res.stderr)
	}
	noLeak(t, res)

	delete(r.env, "VUKA_CONFIG_SECRET_KEY") // a cached secret without its key fails closed too
	failsNaming(t, r.exec(t), "DB_PASSWORD")
}

func TestServerDecryptedValuesArriveAndAreCached(t *testing.T) {
	t.Parallel()
	srvKey := mkKey(t)
	files := map[string]string{"orders/.env.production": "DB_PASSWORD=" + seal(t, srvKey, "orders", "DB_PASSWORD", plainSecret) + "\n"}
	s := newServerCfg(t, files, nil, func(c *config.ServerConfig) { c.DecryptKey = srvKey })
	r := newRun(t, s)
	r.env["CLIENT_PROBE"] = "DB_PASSWORD"
	res := r.exec(t) // no secret key at the client: the server did the work
	want(t, res, map[string]string{"DB_PASSWORD": plainSecret})
	noLeak(t, res)
}
