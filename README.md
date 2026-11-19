# config

A config server for [Vuka](https://vuka-lang.github.io) apps: each app's
configuration in one place — a git repository or a local directory — with
history, values shared between apps, secrets encrypted where they are stored,
and changes that reach running apps.

An app uses it with no code beyond one import: set `VUKA_CONFIG_URI`, and the
values arrive before `main` runs, read with `web.Env` as before.

Status: design. The proposal is [docs/rfc/config-server.md](docs/rfc/config-server.md);
nothing is released yet.

## License

MIT
