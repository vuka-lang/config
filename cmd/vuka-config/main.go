// Command vuka-config runs the Vuka config server and makes its keys and
// tokens.
//
//	vuka-config serve --git URL | --dir PATH [flags]
//	vuka-config keygen [--out FILE]
//	vuka-config token APP
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
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
	h, err := config.Server(config.ServerConfig{Source: src, Key: key, Tokens: tokens, HookSecret: os.Getenv("VUKA_CONFIG_HOOK_SECRET"), Logger: log})
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
	log.Info("config server listening", "addr", *addr, "apps", len(tokens))
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
