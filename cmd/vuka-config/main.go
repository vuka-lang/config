// Command vuka-config runs the Vuka config server and makes its keys and
// tokens.
//
//	vuka-config serve --git URL | --dir PATH [flags]
//	vuka-config keygen [--out FILE]
//	vuka-config keygen-app APP | --server [--out FILE]
//	vuka-config encrypt (--app APP | --server-key) --var NAME (--server URL | --pub KEY)
//	vuka-config token APP
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/vuka-lang/config/v2"
	"github.com/vuka-lang/config/v2/source/dirsrc"
	"github.com/vuka-lang/config/v2/source/gitsrc"
)

const usage = `usage:
  vuka-config serve --git URL | --dir PATH [flags]
  vuka-config keygen [--out FILE]
  vuka-config keygen-app APP | --server [--out FILE]
  vuka-config encrypt (--app APP | --server-key) --var NAME (--server URL | --pub KEY) [--key SIGNING_PUB]
  vuka-config token APP
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "keygen-app":
		err = keygenApp(os.Args[2:], os.Stdout)
	case "encrypt":
		err = encrypt(os.Args[2:], os.Stdin, os.Stdout)
	case "token":
		err = token(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vuka-config:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	gitURL := fs.String("git", "", "serve the repository at this URL")
	dir := fs.String("dir", "", "serve the files of this directory")
	addr := fs.String("addr", ":8888", "listen address")
	tokensFile := fs.String("tokens", "", "file of app=sha256 token entries (else $VUKA_CONFIG_TOKENS)")
	keyFile := fs.String("key", "", "file holding the base64 ed25519 signing seed (else $VUKA_CONFIG_SIGNING_KEY; none: a key for this run only)")
	data := fs.String("data", "", "where the git mirror is kept (default: the user cache directory)")
	poll := fs.Duration("poll", 30*time.Second, "how often to fetch from git")
	sshKey := fs.String("ssh-key", "", "private key for an ssh repository URL")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	appKeys := fs.String("app-keys", "", "file of app=public-key entries (else $VUKA_CONFIG_APP_KEYS)")
	decrypt := fs.Bool("decrypt", false, "decrypt values encrypted to the server's key before serving (the server can then read them)")
	decryptKey := fs.String("decrypt-key", "", "file holding the server's decryption key (else $VUKA_CONFIG_DECRYPT_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*gitURL == "") == (*dir == "") {
		return errors.New("serve takes one of --git and --dir")
	}
	log := slog.Default()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tokens, err := loadTokens(*tokensFile)
	if err != nil {
		return err
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "public key (VUKA_CONFIG_KEY): %s\n", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))

	keys, err := loadAppKeys(*appKeys)
	if err != nil {
		return err
	}
	var dk *config.SecretKey
	if *decrypt {
		if dk, err = loadDecryptKey(*decryptKey); err != nil {
			return err
		}
	}

	var src config.Source
	if *dir != "" {
		if src, err = dirsrc.New(*dir); err != nil {
			return err
		}
	} else {
		mirror := *data
		if mirror == "" {
			cache, err := os.UserCacheDir()
			if err != nil {
				return err
			}
			sum := sha256.Sum256([]byte(*gitURL))
			mirror = filepath.Join(cache, "vuka-config", hex.EncodeToString(sum[:6]))
		}
		g, err := gitsrc.Open(ctx, gitsrc.Options{URL: *gitURL, Dir: mirror, SSHKey: *sshKey, Token: os.Getenv("VUKA_CONFIG_GIT_TOKEN"), Log: log})
		if err != nil {
			return err
		}
		go g.Poll(ctx, *poll)
		src = g
	}
	h, err := config.Server(config.ServerConfig{Source: src, Key: key, Tokens: tokens, HookSecret: os.Getenv("VUKA_CONFIG_HOOK_SECRET"), AppKeys: keys, DecryptKey: dk, Logger: log})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("config server listening", "addr", *addr, "apps", len(tokens), "app-keys", len(keys), "decrypt", dk != nil)
	if *tlsCert != "" {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func loadTokens(file string) (map[string]string, error) {
	text := os.Getenv("VUKA_CONFIG_TOKENS")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("no app tokens: give --tokens or $VUKA_CONFIG_TOKENS (make one with: vuka-config token APP)")
	}
	return config.ParseTokens(text)
}

func readSetting(file, env string) (string, error) {
	text := os.Getenv(env)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		text = string(b)
	}
	return text, nil
}

func loadAppKeys(file string) (map[string]*config.SecretPublicKey, error) {
	text, err := readSetting(file, "VUKA_CONFIG_APP_KEYS")
	if err != nil {
		return nil, err
	}
	return config.ParseAppKeys(text)
}

func loadDecryptKey(file string) (*config.SecretKey, error) {
	text, err := readSetting(file, "VUKA_CONFIG_DECRYPT_KEY")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("--decrypt needs a decryption key: --decrypt-key or $VUKA_CONFIG_DECRYPT_KEY (make one with: vuka-config keygen-app --server)")
	}
	return config.ParseSecretKey(text)
}

func loadKey(file string) (ed25519.PrivateKey, error) {
	text := os.Getenv("VUKA_CONFIG_SIGNING_KEY")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		text = string(b)
	}
	if text = strings.TrimSpace(text); text != "" {
		return config.ParsePrivateKey(text)
	}
	fmt.Fprintln(os.Stderr, "vuka-config: no signing key given; using one for this run only (make one with: vuka-config keygen)")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "write the signing seed to this file (default: print it)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	if *out == "" {
		fmt.Printf("signing key (VUKA_CONFIG_SIGNING_KEY): %s\n", seed)
	} else {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(f, seed); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("signing key written to %s\n", *out)
	}
	fmt.Printf("public key (VUKA_CONFIG_KEY):  %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func token(args []string) error {
	if len(args) != 1 || !config.ValidApp(args[0]) {
		return errors.New("token takes one app name (letters, digits, hyphens and underscores)")
	}
	tok := config.NewToken()
	fmt.Printf("token (VUKA_CONFIG_TOKEN):         %s\n", tok)
	fmt.Printf("server entry (--tokens file):      %s=%s\n", args[0], config.HashToken(tok))
	return nil
}

func writeSecret(out, label, value string, w io.Writer) error {
	if out == "" {
		fmt.Fprintf(w, "%s %s\n", label, value)
		return nil
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, value); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(w, "secret key written to %s\n", out)
	return nil
}

func keygenApp(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("keygen-app", flag.ContinueOnError)
	out := fs.String("out", "", "write the secret key to this file (default: print it)")
	server := fs.Bool("server", false, "make the server's decryption key (for serve --decrypt) instead of an app's")
	if err := fs.Parse(args); err != nil {
		return err
	}
	app := ""
	switch {
	case *server && fs.NArg() == 0:
	case !*server && fs.NArg() == 1 && config.ValidApp(fs.Arg(0)):
		app = fs.Arg(0)
	default:
		return errors.New("keygen-app takes one app name, or --server")
	}
	k, err := config.GenerateSecretKey()
	if err != nil {
		return err
	}
	if *server {
		if err := writeSecret(*out, "decryption key (VUKA_CONFIG_DECRYPT_KEY): ", k.String(), w); err != nil {
			return err
		}
		fmt.Fprintf(w, "public key (encrypt --server-key --pub):     %s\n", k.Public())
		return nil
	}
	if err := writeSecret(*out, "secret key (VUKA_CONFIG_SECRET_KEY):", k.String(), w); err != nil {
		return err
	}
	fmt.Fprintf(w, "app key line (--app-keys file):           %s=%s\n", app, k.Public())
	return nil
}

const maxSecret = 64 << 10

func encrypt(args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	app := fs.String("app", "", "the app the value is for")
	name := fs.String("var", "", "the variable the value is for")
	serverKey := fs.Bool("server-key", false, "encrypt to the server's decryption key (for serve --decrypt), not an app's")
	serverURL := fs.String("server", "", "fetch the public key from this config server")
	pubKey := fs.String("pub", "", "the base64 public key to encrypt to")
	sigKey := fs.String("key", os.Getenv("VUKA_CONFIG_KEY"), "the server's signing public key, to verify --server (default $VUKA_CONFIG_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("encrypt takes no value as an argument: the value is read from standard input")
	}
	if !config.ValidApp(*app) || *name == "" || !validVar(*name) {
		return errors.New("encrypt needs --app (a valid app name) and --var (an environment variable name)")
	}
	if (*serverURL == "") == (*pubKey == "") {
		return errors.New("encrypt takes one of --server and --pub")
	}
	var pub *config.SecretPublicKey
	var err error
	if *pubKey != "" {
		pub, err = config.ParseSecretPublicKey(*pubKey)
	} else {
		pub, err = fetchKey(*serverURL, *sigKey, *app, *serverKey)
	}
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxSecret+1))
	if err != nil {
		return err
	}
	if len(b) > maxSecret {
		return errors.New("the value is too long")
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	if len(b) == 0 {
		return errors.New("no value on standard input")
	}
	v, err := config.Encrypt(pub, *app, *name, b)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, v)
	return nil
}

func validVar(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && !('a' <= c && c <= 'z') && !('A' <= c && c <= 'Z') && !(i > 0 && ('0' <= c && c <= '9' || c == '.')) {
			return false
		}
	}
	return s != ""
}

func fetchKey(server, sigKey, app string, serverKey bool) (*config.SecretPublicKey, error) {
	signing, err := config.ParsePublicKey(sigKey)
	if err != nil {
		return nil, errors.New("--server needs the server's signing public key: --key or $VUKA_CONFIG_KEY")
	}
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("--server is not an http(s) URL")
	}
	subject := config.AppSubject(app)
	u.Path = strings.TrimSuffix(u.Path, "/") + "/_keys"
	if serverKey {
		subject = config.ServerSubject
	} else {
		u.Path += "/" + url.PathEscape(app)
	}
	hc := http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("fetching the public key from %s failed", u.Host)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s has no such key: %s", u.Host, resp.Status)
	}
	var kr config.KeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&kr); err != nil {
		return nil, errors.New("the key response is not valid")
	}
	return config.VerifyKey(kr, subject, signing)
}
