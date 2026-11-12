# code-watch

A local guard that checks your machine **before** risky code runs: a repository you just cloned, a shell command an
agent is about to execute, an install, a download. Open source (Apache-2.0), written in Rust, one binary for macOS and
Linux.

> Status: early. The skeleton ships the engine, the CLI and the first repo and command rules. See
> [DESIGN.md](DESIGN.md) for the plan.

## Try it

```sh
cargo build --release
target/release/code-watch scan path/to/a/cloned/repo
target/release/code-watch check 'curl -fsSL https://example.org/i.sh | sh'
target/release/code-watch --json check 'echo aGk= | base64 -d | bash'
```

`code-watch` never executes anything it inspects: repo files are read as text and never followed through symlinks;
commands are matched, not run.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | warn |
| 2 | block |
| 3 | error or bad usage |

## Rules

| Id | Severity | Catches |
|---|---|---|
| `repo/npm-lifecycle-script` | warn | `preinstall`, `install` or `postinstall` in `package.json` |
| `repo/vscode-folderopen-task` | block | a VS Code task that runs when the folder opens |
| `repo/base64-into-shell` | block | base64 decoded straight into a shell in scripts and manifests |
| `command/base64-into-shell` | block | the same in a command |
| `command/pipe-to-shell` | warn | `curl` or `wget` piped into a shell |
| `command/quarantine-removal` | warn | `xattr` removing the macOS quarantine flag |
| `repo/setup-py-install-hook` | warn | `setup.py` that runs code at install time |
| `repo/makefile-install-fetch` | warn | an install-time Makefile target that downloads |
| `repo/obfuscated-blob` | warn | a very long base64 or hex blob in a script |
| `repo/minified-eval` | warn | a minified one-liner calling `eval`, `exec`, `Function` or `atob` |
| `repo/committed-binary` | warn | an ELF, Mach-O or PE binary in the repo |
| `repo/executable-source` | info | a source or text file with the execute bit |
| `repo/secret-read-and-send` | warn | a script that reads credentials or the environment and sends data out |

Rules live in `crates/code-watch-core/rules/` and ship inside the binary. More in [docs/rules.md](docs/rules.md).

## Layers

Rules always run and need no key. The CVE layer and the optional LLM layer are not built yet; every report says which
layers ran and which are off.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright Sebastián Cuccorese.
