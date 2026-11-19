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
- The server watches it and serves a change when a file is saved.
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
| `GET /{app}/{profile}/watch` | a stream of the snapshot's new versions (§7) |

With no profile, the profile segment is `-`, which no profile can be.

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
and sets the changed values in the process environment.

- **Code that reads a value when it uses it** (`web.Env` in a handler) sees
  the new value at its next call, with nothing else to do.
- **Code that keeps a value it read at start** gets it in one of two ways:
  - `web.OnEnvChange("RATE_LIMIT", func(old, new string) { … })`, run after
    the change;
  - a handle, `limit := web.Hot[int]("RATE_LIMIT", 100)`, whose `Get` is
    always current.
- **Values that can't change while the app runs** (a listen address, a
  database URL read once to open a pool): the compiler sees each `web.Env`
  call and where it runs, so it records the keys read only while the app
  starts. A change to one of those is logged as needing a restart, and the
  snapshot's report says so. An app can opt in to restarting itself: it
  drains and exits so its supervisor starts it with the new values, one
  instance at a time.

The `/watch` stream is a long-lived HTTP response; it reconnects with
backoff, and the client also polls the version every 30 s, so a lost
stream costs at most that.

## 8. Secrets

- A value written as `{cipher}…` is encrypted.
  `vuka config encrypt --app orders <value>` prints one; it runs on an
  operator's machine, not as an endpoint.
- **Decrypted by the client, by default.** Each app has its own key pair;
  a value is encrypted to the app's public key and the server passes the
  ciphertext through. Neither the repository nor the server can read it,
  so a leak of either leaks no secret.
- Decrypting on the server instead, with one server key, is an option
  (`--decrypt`) for clients that aren't Vuka apps and read the `.env` form.
- Secret values are never logged, masked in every report, and left out of
  `vuka config pull` (§9) unless asked for.

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
- **`vuka config encrypt`** as in §8.

## 10. Phases

1. **Server and start-up fetch.** The git and directory sources, the layout
   and precedence of §4.3, the JSON and `.env` endpoints, app tokens, signed
   snapshots, the client's fetch at program start, the cached snapshot and
   `VUKA_CONFIG_FAIL_FAST`. This alone gives one place, history, rollback
   and shared values.
2. **Secrets.** `{cipher}` values decrypted by the client, per-app keys,
   `vuka config encrypt`, and the server-side option.
3. **Changes while running.** `/watch`, `web.OnEnvChange`, `web.Hot`, the
   compiler's start-only keys and the opt-in restart.
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
