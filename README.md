# config

A config server for [Vuka](https://vuka-lang.github.io) apps: each app's
configuration in one place — a git repository or a local directory — with
history, values shared between apps, secrets encrypted where they are stored,
and changes that reach running apps.

An app uses it with no code beyond one import: set `VUKA_CONFIG_URI`, and the
values arrive before `main` runs, read with `web.Env` as before.

Status: phase 1 of the [proposal](docs/rfc/config-server.md) is built: the git
and directory sources, the layout and precedence of §4.3, the JSON and `.env`
endpoints, app tokens, signed snapshots, the client's fetch at start-up, the
sealed cached snapshot and `VUKA_CONFIG_FAIL_FAST`. Phase 2, secrets, is built
too: `{cipher}` values decrypted by the client with per-app keys, `keygen-app`
and `encrypt`, and the server-side `--decrypt` option. Not yet: `/watch` and
changes while an app runs, the check and pull tools, and `vuka config serve`
(the server is `vuka-config serve` for now).

## Run it

Make a signing key and a token for each app:

```sh
go run github.com/vuka-lang/config/v2/cmd/vuka-config keygen --out signing.key
go run github.com/vuka-lang/config/v2/cmd/vuka-config token orders
```

`keygen` prints the public key (`VUKA_CONFIG_KEY`); `token` prints the app's
token (`VUKA_CONFIG_TOKEN`) and the hashed entry for the server's tokens file,
one `app=hash` per line. Serve a repository or a directory laid out as in
§4.3 (`.env`, `.env.production`, `orders/.env`, `orders/.env.production`):

```sh
vuka-config serve --git https://example.com/acme/config.git --tokens tokens --key signing.key
vuka-config serve --dir /etc/acme-config --tokens tokens --key signing.key
```

The server listens on `:8888` (`--addr`). Its other settings are
`VUKA_CONFIG_HOOK_SECRET` (enables `POST /_hooks/git`, which fetches at
once; the repository is also fetched every `--poll`, 30 s),
`VUKA_CONFIG_GIT_TOKEN` or `--ssh-key` for a private repository, and
`VUKA_CONFIG_TOKENS` and `VUKA_CONFIG_SIGNING_KEY` in place of the files.
`GET /{app}/{profile}[/{label}]` returns the signed snapshot, with `.env`
after the last segment the merged values as an env file. App and profile
names are letters, digits, `-` and `_` (a profile may also hold `.`; neither
starts with `-` or `.`). An app has a folder, so a hyphen in its name is never
ambiguous, and its files are named as a project's own env files. With no
profile the segment is `-` (only `.env` and `orders/.env` apply). A token
reads its own folder and the root `.env` and `.env.<profile>`, nothing else.

An app imports the client for its effect, and sets the variables:

```go
import _ "github.com/vuka-lang/config/v2/client"
```

| Variable | |
|---|---|
| `VUKA_CONFIG_URI` | the server's URL; unset, the client does nothing |
| `VUKA_CONFIG_TOKEN` | the app's token |
| `VUKA_CONFIG_KEY` | the server's public key |
| `VUKA_APP`, `VUKA_ENV` | the app and its profile (none without `VUKA_ENV`) |
| `VUKA_CONFIG_LABEL` | a branch, tag or commit; default the repository's default branch |
| `VUKA_CONFIG_CACHE` | the file for the sealed last snapshot; default the user cache directory |
| `VUKA_CONFIG_FAIL_FAST` | `1`: exit unless a fresh snapshot was fetched |
| `VUKA_CONFIG_WATCH` | `0`: fetch at start only, don't follow changes |
| `VUKA_CONFIG_RESTART` | `1`: restart the app when a change reaches a key it reads only at start |

The real environment wins over the server, the server over env files, env
files over the defaults in code. If the server can't be reached, the client
uses the last snapshot it received, or starts without one and logs an error
naming the server.

## Changes while running

After start the client follows the server: it holds `GET
/{app}/{profile}/watch[?label=…]` open (a stream of the snapshot's version,
sent on connect and on every change; no values travel on it) and also checks
the version every 30 s, so a lost stream costs at most that. On a new version
it fetches the signed snapshot, checks it, decrypts its secrets and applies it;
a change in the repository or the directory reaches the instances in seconds.

```go
// read where you use it: always current
if web.Env[bool]("MAINTENANCE") { … }

// a handle that stays current
limit := web.Hot[int]("RATE_LIMIT", 100)
… limit.Get() …

// a value you keep: be told when it changes
web.OnEnvChange("POOL_SIZE", func(old, new string) { pool.Resize(new) })
```

A snapshot that doesn't verify, or has a secret the app can't decrypt, is not
applied, not even in part: the app keeps the values it has, an error naming the
server and the variable (never a value) is logged, and the client keeps
following. Applied changes are logged by key: `config: applied 3 changes
(version 3f2a1c9e0b1d): KEY1, KEY2, KEY3`. A key the source stops providing
goes back to its env-file value; the real environment still wins. An app that
started with no server and no cache keeps trying and applies the first
snapshot it gets. `VUKA_CONFIG_WATCH=0` turns following off.

The server shares one computation per app, profile and label between all its
watchers (a directory's files are hashed, a git label's commit read, every
`WatchInterval`, 3 s; a git push hook makes it immediate) and caps the streams
at 16 per token and 2000 in all, answering `429` or `503` with `Retry-After`.
In Go, `config.Server` returns a `*config.Handler`; `http.Server.RegisterOnShutdown(h.Close)`
ends the streams when the server shuts down (`vuka-config serve` does).
Values that cannot change while an app runs (a listen address, a database URL
read once to open a pool) are found by the compiler, which records the keys
the program reads while it starts (RFC §7.3). A change to one is logged by key,
`config: KEY1, KEY2 changed and take effect on restart`, and the applied line
ends with `; restart needed for KEY1, KEY2`. With `VUKA_CONFIG_RESTART=1` the
app also drains and exits with status 75 so its supervisor starts it with the
new values; that needs a supervisor that restarts it, and instances restart
one at a time only if the supervisor staggers them. Keys the compiler cannot
read (not string constants), and calls in dependencies, are not classified:
`vuka vet` counts the first (W0405).

## Secrets

A value written `{cipher}v1:<key-id>:<ciphertext>` is encrypted to one app's
key, so neither the repository nor the server can read it. Make the app's key
pair; the private half is for the app's deploy, the line for the server:

```sh
vuka-config keygen-app orders
# secret key (VUKA_CONFIG_SECRET_KEY): …
# app key line (--app-keys file):      orders=…
```

Give the server the lines (`--app-keys FILE` or `VUKA_CONFIG_APP_KEYS`), then
encrypt a value from standard input, so it never lands in shell history, and
put the result in the app's folder, such as `orders/.env.production`:

```sh
printf %s "$PASSWORD" | vuka-config encrypt --app orders --var DB_PASSWORD \
    --server https://config.internal --key "$VUKA_CONFIG_KEY"
# DB_PASSWORD={cipher}v1:…
```

`--server` fetches the app's public key from `GET /_keys/orders`, signed with
the server's signing key, which `--key` (or `VUKA_CONFIG_KEY`) verifies; or
give the public key with `--pub`. A value is bound to its app and its
variable: copied to another app's folder or another name, it won't decrypt.

The app's private key is the one secret a deploy must still deliver: set
`VUKA_CONFIG_SECRET_KEY` to it, next to `VUKA_CONFIG_TOKEN`. The client
decrypts after checking the signature, and removes the variable from the
process environment. Several keys, comma-separated, are accepted during a
rotation; each value names its key by id. A `{cipher}` value the client can't
decrypt is never applied as text: the start fails with an error naming the
variable, whatever `VUKA_CONFIG_FAIL_FAST` is. The sealed cache keeps the
ciphertext. Secrets can't go in the root `.env` or `.env.<profile>`, which
every app reads: the server answers 500 for them, naming the file and the
variable.

For clients that aren't Vuka apps, `serve --decrypt` decrypts values
encrypted to the server's own key before serving them (`keygen-app --server`
makes it; `--decrypt-key` or `VUKA_CONFIG_DECRYPT_KEY` gives it to the
server; `encrypt --server-key` encrypts to it). That means the server can read
those secrets; it is off by default.

## License

MIT
