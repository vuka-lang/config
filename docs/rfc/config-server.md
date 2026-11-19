# RFC: A config server for Vuka apps

Status: draft. No code accompanies this document; it lands in the phases of
§9.

## 1. Problem

A Vuka app reads its configuration from the environment: `web.Env("KEY",
def)` and `web.MustEnv`, with env files (`.env`, `.env.<VUKA_ENV>`,
`.env.local`) read when the program starts. That works for one app on one
machine. With several apps and environments it leaves gaps:

- the same value (a mail host, a feature switch, an upstream URL) is copied
  into every app's environment, and they drift;
- a change has no history: who set it, when, what it was before, how to put
  it back;
- a change reaches a running app only by restarting it;
- secrets sit in plain text wherever the environment is kept;
- nothing checks that the values an environment provides are the ones the
  app reads, until the app fails at start, or later.

This RFC proposes `github.com/vuka-lang/config/v2`: a server that serves each
app its configuration from one place, and a client built into how Vuka apps
already read the environment, so an app needs no code to use it.

## 2. Goals and non-goals

Goals:

- one place for every app's configuration, with history and rollback;
- values shared between apps written once;
- no code in the app: setting one environment variable turns the client on;
- a change reaches running apps without a restart where the app allows it,
  and says so where it doesn't;
- secrets encrypted where they are stored, and readable only by the app
  they belong to;
- values checked against what each app reads, before a deploy.

Non-goals:

- replacing the environment: real environment variables keep working and
  win;
- service discovery, feature-flag targeting by user, or a UI for editing
  values. Edits are commits or file changes; a UI can come later over the
  same sources.

## 3. Concepts

- **App**: the name an app is served by, `VUKA_APP`.
- **Profile**: the environment it runs in, `VUKA_ENV` (`production`,
  `staging`, …): the same variable that already picks a Vuka app's env files.
- **Label**: a version of the configuration: a git branch, tag or commit,
  defaulting to the source's default branch. A directory source has one
  label.
- **Snapshot**: the merged values one app gets for one profile and label,
  with the source of each value and a version.

## 4. Sources

The server reads configuration from a source. Two are supported.

### 4.1 Git

A git repository, cloned by the server and kept current:

```sh
vuka config serve --git https://example.com/acme/config.git
```

- Every change is a commit: its author, its diff and its rollback (a revert)
  come from git.
- A label is any branch, tag or commit; an app can pin one
  (`VUKA_CONFIG_LABEL=v42`) and a deploy can move it.
- The server fetches on a push webhook (`POST /_hooks/git`, verified by a
  shared secret) and every 30 s as a fallback.
- Private repositories authenticate with an SSH key or an HTTPS token given
  to the server.
- A snapshot's version is the commit hash.

### 4.2 Local directory

A directory on the server's machine:

```sh
vuka config serve --dir /etc/acme-config
```

- For a single machine, for development and for tests.
- A saved file is served at once (it is read on every request), and watchers of the snapshot are told within a few seconds (§7).
- A snapshot's version is a hash of the files that make it up.
- History is whatever the directory has; pointing the server at a git
  working copy without `--git` serves its files as they are on disk.

### 4.3 Layout and precedence

Both sources have the same layout:

```text
.env                    every app, every profile
.env.production         every app, in production
orders/.env             the orders app, every profile
orders/.env.production  orders, in production
```

For app `orders` in profile `production` the values merge in this order,
the later winning: `.env`, `.env.production`, `orders/.env`,
`orders/.env.production`. With no profile (`VUKA_ENV` unset) only `.env` and
`orders/.env` apply.

Inside an app's folder the files have the names a Vuka project's own env
files have (`.env`, `.env.<profile>`), so a project's files copy into the
repository unchanged. An app name is a single directory name of letters,
digits, `-` and `_`, not starting with `-` or `.`; a profile holds letters,
digits, `-`, `_` and `.`, not starting with `-` or `.`. The server reads
only these four paths, never follows a symbolic link, and doesn't treat
`.git` or any other dot-directory as an app.

Files are env files in the syntax Vuka already reads (`KEY=value`, quotes,
comments), so a file moves between a project and the repository unchanged.

Each app has a folder, rather than a flat name like `orders-production.env`,
because a flat `app-profile.env` is ambiguous when names contain hyphens:
`a-b-c.env` would be app `a` in profile `b-c` or app `a-b` in profile `c`,
and one app's token could read the other's file.

## 5. The server

The server ships two ways: as `vuka config serve`, a process of its own,
and as `config.Server(...)`, a handler any Vuka app can mount.

### 5.1 Endpoints

| Endpoint | Returns |
|---|---|
| `GET /{app}/{profile}[/{label}]` | the snapshot as JSON: each source (file and version) with its values, the merged values, the version |
| `GET /{app}/{profile}[/{label}].env` | the merged values as an env file, for scripts and for apps not built with Vuka |
| `GET /{app}/{profile}/watch[?label=…]` | a stream of the snapshot's version, now and on every change (§7); the label is a query parameter because `watch` can't be a label |
| `GET /_keys/{app}` | the public key `{cipher}` values for the app are encrypted to (§8), signed with the server's signing key; public, no token |
| `GET /_keys` | the same for the server's decryption key, when `--decrypt` is on |

With no profile, the profile segment is `-`, which no profile can be.
`_hooks` and `_keys` are the server's own paths and are not app names. An
app with no key, an unknown app and a reserved name get the same 404 from
`/_keys/{app}`; `vuka config encrypt --server` checks the signature against
`VUKA_CONFIG_KEY`, so a key substituted on the way is refused.

### 5.2 Access

- Each app has its own token. A token reads its app's folder and the shared
  root `.env` and `.env.<profile>` (§4.3), nothing else: never another app's folder.
- Tokens are listed in the server's own configuration (a file or the
  environment), hashed; the server never logs one.
- The server can require client certificates instead of, or as well as,
  tokens.

### 5.3 Signed snapshots

Every snapshot is signed with the server's ed25519 key, and the client
checks it against the public key it was given. A proxy, a cache or anyone
on the path between them can't change a value. The signing key can be held
apart from the server's other secrets, so a compromise of the server's
storage or of the repository alone can't sign a forged snapshot.

## 6. The client

### 6.1 No code

Vuka reads env files when the program starts, before `main` builds the
app's options. The client runs at the same point: when `VUKA_CONFIG_URI` is
set, it fetches the app's snapshot there, so every option and every
`web.Env` call sees the values.

```sh
VUKA_CONFIG_URI=https://config.internal  VUKA_APP=orders  VUKA_ENV=production  ./orders
```

The token is `VUKA_CONFIG_TOKEN` and the server's public key
`VUKA_CONFIG_KEY`. Without `VUKA_CONFIG_URI` nothing changes.

The client is linked by one blank import in the app's main package
(`_ "github.com/vuka-lang/config/v2/client"`), which `vuka add config`
writes. Its package initialises after `web`'s, which has read the env files
by then; `web` records which keys came from files, so the client overrides
those and leaves the real environment alone (§6.2).

### 6.2 Precedence

Highest first:

1. the real environment of the process;
2. the config server;
3. env files;
4. the default in code (`web.Env`'s second argument).

A value set in one instance's real environment still overrides the server,
so an operator can pin a value on one machine.

### 6.3 When the server can't be reached

- The client retries with backoff for a few seconds.
- Then it uses the last snapshot it received, kept on disk, encrypted with a
  key derived from the app's token and checked against the server's
  signature on load.
- With no snapshot on disk, it starts with env files and defaults, logs an
  error naming the server, and keeps trying in the background.
- `VUKA_CONFIG_FAIL_FAST=1` makes a start without a fresh snapshot fail
  instead.

## 7. Changes while an app runs

Each instance follows its snapshot's `/watch` stream; there is no broker in
between. On a new version it fetches the snapshot, checks the signature,
decrypts the `{cipher}` values (§8), and applies the changed values with
`web.ApplyEnv`: below the real environment and above the env files, the same
rule as at start. A key the source no longer provides goes back to the value
an env file gave it, or is unset.

- **Code that reads a value when it uses it** (`web.Env` in a handler) sees
  the new value at its next call, with nothing else to do.
- **Code that keeps a value it read at start** gets it in one of two ways:
  - `web.OnEnvChange("RATE_LIMIT", func(old, new string) { … })`, run after
    the change;
  - a handle, `limit := web.Hot[int]("RATE_LIMIT", 100)`, whose `Get` is
    always current.
- **Values that can't change while the app runs** (a listen address, a
  database URL read once to open a pool): the compiler sees each `web.Env`
  call and where it runs, so it records the keys read while the app starts
  (§7.3). A change to one of those is logged as needing a restart, by key,
  and the app can opt in to restarting itself: it drains and exits so its
  supervisor starts it with the new values.

### 7.1 The stream

`GET /{app}/{profile}/watch` (no profile: `-`; a label: `?label=v42`) takes
the token of the snapshot endpoint, reads the same files for the same app
and answers the same 404 for an unknown app, label or another app's token,
and 401 without a valid token. The response is a long-lived `200
text/event-stream` (server-sent events, plain HTTP):

```text
event: version
data: 3f2a1c9e…

: keepalive

event: version
data: 8b0d7e44…
```

- The current version is sent on connect, and again whenever it changes.
  Only the version travels, never a value: the client fetches the signed
  snapshot, so the stream needs no signature of its own and a forged event
  can at most cause a fetch.
- A comment line (`: keepalive`) every 25 s keeps proxies from cutting an
  idle stream. A client that hears nothing for 90 s treats the stream as
  lost.
- A version is the snapshot's: the commit for git, a hash of the files
  that make the snapshot for a directory.
- Only `GET` is served (405 otherwise). Shutdown ends every stream cleanly
  (`config.Handler.Close`, which `vuka-config serve` registers with
  `http.Server.RegisterOnShutdown`), and the client reconnects.

**One computation per snapshot.** Watchers of the same app, profile and label
share a single goroutine, started with the first and stopped with the last,
that reads the snapshot's version and hands a new one to each of them: a
thousand instances cost one read per interval, not a thousand. It reads every
`WatchInterval` (3 s): for a directory that is the hash of the (at most four)
files, which needs no file-system notifications; for git, the label's commit
in the mirror, so a commit shows up as soon as the mirror fetches it. A
`POST /_hooks/git` that refreshed the mirror makes every watched snapshot be
read at once, so a push reaches the instances in about the time of the fetch.
A read that fails (the source is down, a file is invalid) is logged once, and
the last version stands until a read works.

**Caps.** A token holds at most 16 streams and the server 2000
(`WatchPerApp`, `WatchTotal`; negative for no cap). Beyond the first it
answers `429` with `Retry-After`, beyond the second `503` with `Retry-After`.
Requests that fail authentication or name another app's snapshot are refused
before the caps are looked at.

### 7.2 What the client does

- **Following.** After the start-up fetch the client holds the stream open,
  reconnecting with jittered, doubling backoff (1 s to 30 s). It also checks
  the version every 30 s (a `HEAD` of the snapshot), so a lost stream, or a
  server or proxy that has no `/watch`, costs at most that.
- **Fail-safe at runtime.** A snapshot that fails the signature check, names
  another app, or has a `{cipher}` value the client can't decrypt is not
  applied, not even in part: the app keeps the values it has, an error is
  logged naming the server and, for a secret, the variables (never a value),
  and the client keeps following; a later good version is applied. Each
  refused version is reported once. This is the reverse of the start-up
  rule of §8, which fails closed: at start there are no values yet and
  running without a secret is worse than not running; later the app already
  runs with a complete configuration, and a half-applied or lost one is
  worse than the one it has.
- **Logging.** `config: applied 3 changes (version 3f2a1c9e0b1d): KEY1,
  KEY2, KEY3`: keys only. When some of them are restart-only keys (§7.3) the
  line ends with `; restart needed for KEY1, KEY2` and a line of its own
  follows: `config: KEY1, KEY2 changed and take effect on restart`.
- **A start with no snapshot** (no server, no cache) goes on trying in the
  background, with the same backoff, and applies the first snapshot it gets.
  A start from the cache applies a newer version when the server answers.
- **Each applied snapshot replaces the sealed cache** (§6.3).
- **Opt-out.** `VUKA_CONFIG_WATCH=0` fetches at start only.
- **Restart-only keys.** After each apply the client asks `web.NeedsRestart`
  about every key that changed (§7.3).
- **Applying** is one call to `web.ApplyEnv` from one goroutine, so
  `OnEnvChange` callbacks run there, one after another.

### 7.3 Restart-only keys

A value the program reads once and keeps (a listen address, a database URL
given to a pool, a field set in a constructor) isn't touched by a change:
`web.Env` has already returned. `vuka build`, `run`, `test` and `vet` find
those keys and write, into each main package, a generated file
`vuka_restart_gen.go` (`vuka gen` writes it to disk for plain go tools):

```go
func init() {
	vukaweb.RestartOnlyEnv(
		"DATABASE_URL",
		"LISTEN_ADDR",
	)
}
```

`web.NeedsRestart(key)` reports whether a key was recorded; the config
client asks it for each key an apply changed. The file is written only when
the web package the module builds with has `RestartOnlyEnv`: an app on an
older web is built as before, and its changes are applied without a report.

**The classification.** The analysis is syntactic, over the module's Go (its
`.go` files and the Go the compiler writes for `.vuka` and `.vuka.html`
files), and errs toward flagging a key: a false "needs restart" costs a log
line, a missed one silently ignores a change.

- A *read* is a call of `web.Env`, `web.MustEnv` or `web.Require` whose key is
  a string constant: a literal, a constant of the package or of another
  package of the module, or a concatenation of those. A read is *at start*
  when its function is reached by calls from a root: the package variable
  initialisers, `init`, `main` (in a main package), and the `Start` method of
  any type (what `web` calls when the app starts).
- A call is resolved by name: `f()`, `pkg.F()` for a package of the module,
  and `x.M()` for every method of the module named `M`. A function value
  runs only when it is a function literal called on the spot, a local
  variable holding one that is called, or an argument of `Provide`, `Eager`,
  `Service`, `Controller`, `OnStart` or `Check`, which build or start it
  once. Any other function value (a handler given to `Get`, a cron's
  function, a closure returned or stored) doesn't run at start, however it
  is registered, so a live page's `Render`, its events, `Update`, and
  `Mount` (which runs for each page, not once) are live.
- `web.Require` checks when the app is built: its keys are always at start.
- A key is **restart-only** when any read of it is at start, unless the
  module also names it in `web.Hot` or `web.OnEnvChange`: the app handles its
  changes, so it isn't flagged. A helper called both from `main` and from a
  handler makes its key restart-only, since the read at start keeps its value.

**Limits.**

- A read whose key isn't a string constant (a variable, a parameter, the
  result of a call) can't be classified and is skipped. `vuka vet` counts
  them in a warning, W0405, naming the first. A helper such as
  `func setting(name string) string { return web.Env[string](name) }` hides
  every key passed through it.
- Only the module being built is read. Calls in dependencies, other modules
  of a workspace included, are not.
- Only the web package's reads count; `os.Getenv` and `os.LookupEnv` are not
  read.
- The whole module is analysed for each main package: a key read at start
  only by another main's packages is registered too.

**What the client does.** A changed key for which `web.NeedsRestart` is true
is logged by key only (§7.2). With `VUKA_CONFIG_RESTART=1` the client then
calls `web.Restart`: the running app stops as on `SIGTERM` (`Run` stops
accepting, drains its connections for up to ten seconds, stops its services)
and the process exits with status 75 (`web.RestartStatus`, `EX_TEMPFAIL`) so
a supervisor can tell it from a failure (1) and a stop (0). The client logs
`config: restarting to apply KEY1, KEY2`; with no app running (`App.Run`
isn't in use) it says so and does nothing else. It asks once per process.

This needs a supervisor that starts the program again after it exits: systemd
(`Restart=always`, or `on-failure`: 75 is a failure status), a container platform's
restart policy, a Nomad or Kubernetes restart. Nothing here builds a
restart: with `VUKA_CONFIG_RESTART` unset the program only logs. With
several instances, they all see the new version at about the same time and
each restarts as soon as it has drained; they restart one at a time only if
the supervisor staggers them (a rolling update does, a restart policy does
not). The server does no coordination, so an operator who wants a rolling
restart uses the supervisor's.

The restarted program fetches the new snapshot at start, so the keys it
restarted for no longer change and it doesn't restart again.

## 8. Secrets

- A value written as `{cipher}…` is encrypted. `vuka config encrypt --app
  orders --var DB_PASSWORD` reads the value from standard input (never
  from an argument, which would land in the shell's history) and prints one;
  it runs on an operator's machine, not as an endpoint.
- **Decrypted by the client, by default.** Each app has its own key pair;
  a value is encrypted to the app's public key and the server passes the
  ciphertext through, covered by the snapshot's signature like every other
  value. Neither the repository nor the server can read it, so a leak of
  either leaks no secret.
- **The app's private key** reaches the app as `VUKA_CONFIG_SECRET_KEY`
  (base64). It is the one secret a deploy must still deliver, by whatever
  delivers the app's other secrets; the client removes it from the process
  environment once read. `vuka config keygen-app orders` makes the pair and
  prints the line for the server's app-keys file (`orders=<public key>`, one
  per line, `--app-keys` or `VUKA_CONFIG_APP_KEYS`).
- **Construction.** HPKE (RFC 9180, base mode) with DHKEM(X25519,
  HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, from the standard library's
  `crypto/hpke`: a fresh ephemeral key per value, so equal values encrypt
  differently and anyone with the public key can encrypt but not read.
- **Wire format.** `{cipher}v1:<key-id>:<base64url>`: the key-id is the
  first 6 bytes of the SHA-256 of the app's public key, base64url (8
  characters); the body is the HPKE encapsulated key (32 bytes) followed by
  the ciphertext and tag, base64url without padding.
- **Binding.** The HPKE `info` is `vuka-config cipher v1` and the
  associated data is `vuka-config cipher v1`, NUL, the app name, NUL, the
  variable name. A ciphertext copied to another app's folder, or under
  another variable, fails to decrypt.
- **Rotation.** `VUKA_CONFIG_SECRET_KEY` may list several private keys,
  comma-separated; the client picks by key-id. Rotate by publishing the new
  public key in the app-keys file, giving the app both private keys,
  re-encrypting the values, and then dropping the old private key.
- **Fail closed.** After the signature is checked and before values are
  applied, the client decrypts every `{cipher}` value it would apply. One it
  can't (no key, a key-id it has no key for, tampered, bound to another app
  or variable) is never applied as text: the start fails with an error
  naming the variable, never the value, and it does so whatever
  `VUKA_CONFIG_FAIL_FAST` says. That setting is about a server that can't be
  reached, where starting with defaults is a considered degradation; here the
  server answered, the secret is part of the app's configuration, and an app
  running without it is worse than one that isn't running. A key the real
  environment already sets is not applied from the server and so not
  decrypted. The sealed cache (§6.3) keeps the ciphertext, so secrets stay
  encrypted at rest there too, and decrypts on load, with the same rule.
- **No secrets in shared files.** A `{cipher}` value in the root `.env` or
  `.env.<profile>`, which every app reads, is an error: with a key per app no
  single ciphertext is readable by all of them. The server logs it and
  answers 500 for every snapshot that file is part of, naming the file and
  the variable and serving nothing; both sources enforce it. A cipher value
  can't be interpolated into another value (`${PW}`) either.
- **Decrypting on the server instead** is an option (`--decrypt`, with a
  separate X25519 decryption key, `--decrypt-key` or
  `VUKA_CONFIG_DECRYPT_KEY`; never the signing key), for clients that aren't
  Vuka apps and read the `.env` form. `vuka config encrypt --server-key`
  encrypts to it. A value whose key-id is the server's is decrypted before
  the snapshot is signed and served; one made for an app key passes through
  even then. It is off by default, and turning it on means the server can
  read those secrets, and so can anyone who can read its memory or its key.
  A value the server can't decrypt is a 500, never served as ciphertext.
- Secret values are never logged, masked in every report, and left out of
  `vuka config pull` (§9) unless asked for. A snapshot that is printed shows
  its keys, never their values.

## 9. Tools

- **`vuka config check <source>`**: the compiler knows every
  `web.Env("KEY", def)` an app makes with its type, every `MustEnv` and
  every `web.Require`. The check reads the apps in a workspace and the
  source, and reports, per app and profile:
  - a required key that no file provides;
  - a value that doesn't convert to the type the app reads it as;
  - a key in the source that no app reads (often a typo).

  It runs in the configuration repository's CI.
- **Where each value came from**: a panel in the development toolbar and an
  endpoint an app can mount (`/debug/env`, behind the app's own gate) show
  each key's value (masked if secret) and its source: the real environment,
  `orders/.env.production@3f2a1c`, `.env`, or the default.
- **`vuka config pull orders production`** writes `.env.local` from the
  server, so a developer can run with an environment's values. Secrets stay
  out unless `--secrets` is given and the token may read them.
- **`vuka config encrypt`** and **`keygen-app`** as in §8.

## 10. Phases

1. **Server and start-up fetch.** The git and directory sources, the layout
   and precedence of §4.3, the JSON and `.env` endpoints, app tokens, signed
   snapshots, the client's fetch at program start, the cached snapshot and
   `VUKA_CONFIG_FAIL_FAST`. This alone gives one place, history, rollback
   and shared values.
2. **Secrets.** `{cipher}` values decrypted by the client, per-app keys,
   `vuka config encrypt`, and the server-side option.
3. **Changes while running.** `/watch`, `web.OnEnvChange`, `web.Hot`, the
   compiler's restart-only keys (§7.3) and the opt-in restart
   (`VUKA_CONFIG_RESTART`) (done).
4. **Checks and reports.** `vuka config check`, the toolbar panel and
   `/debug/env`, `vuka config pull`.

## 11. Compatibility

Everything is additive. An app without `VUKA_CONFIG_URI` behaves as today;
env files and the real environment keep their meaning, and the real
environment keeps the last word. `web.OnEnvChange` and `web.Hot` are new
names in `web`; the server and client live in `github.com/vuka-lang/config`
and versions with the rest of the set.

## 12. Open questions

1. **File format.** Env files only (proposed: the format apps already use),
   or TOML as well for nested values?
2. **Restart-only keys.** Report the change only (proposed default), or have
   apps restart themselves by default?
3. **Signing key custody.** Kept on the server's machine apart from its
   other secrets (proposed), or on an operator's machine, signing each
   snapshot version offline before it can be served?
4. **Shared secrets: a key shared by a group of apps?** A secret every app in a group needs (a mail
   password) must be written once per app, since per-app keys leave no
   ciphertext readable by all (§8). A key shared by a group of apps, or a
   server-decrypted value allowed in shared files, could avoid the copies.
