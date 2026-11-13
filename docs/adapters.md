# Agent adapters

`code-watch adapter <claude-code|cursor|codex>` reads one agent's pre-command hook JSON on stdin, runs the same check as
`code-watch check` (with the user allowlist only: the agent can write a repo's `.code-watch.toml`, so the repo file never changes the
reply), and answers in that agent's format. Stdout carries only the reply; messages go to stderr. The exit code is 0 so
the agent reads the JSON, except when a fail-closed adapter cannot decide (below). Tool calls that are not shell
commands are left alone.

`code-watch install-adapter <agent>` prints the settings snippet for that agent and says which file it belongs in.
It edits nothing: merge the snippet into your existing `hooks` object yourself.

| Verdict | Claude Code | Cursor | Codex CLI |
|---|---|---|---|
| clean | empty reply (Claude Code's own permission flow decides) | `ask` (`--cursor-clean allow`: `allow`) | empty reply |
| warn | `permissionDecision: "ask"` | `permission: "ask"` | `deny` that says only that the user can allow it (`--codex-warn allow`: empty reply, reason on stderr) |
| block | `permissionDecision: "deny"` | `permission: "deny"` | `deny` |

The reason names the rule titles. How to allow a command (the `[[allow]]` entry and the file) is never put in text the
model reads: Cursor shows it in `user_message` only, Codex has one channel so its deny does not carry it. "No findings" never means "approved to run": where an agent has a no-opinion reply,
a clean command gets it.

## Claude Code

Hook `PreToolUse`, matcher `Bash`, in `~/.claude/settings.json`. The snippet sets `onFailure: "block"` (Claude Code
2.1.295 or newer), so a crash or timeout of the hook blocks instead of letting the command through.

## Cursor

Hook `beforeShellExecution` in `~/.cursor/hooks.json`, with `"version": 1` and `failClosed: true`. Cursor has no "no
opinion" reply (anything that is not a valid permission blocks), and an `allow` may skip Cursor's own approval prompt, so
a clean command is answered `ask` by default and still goes through Cursor's prompt. If you run Cursor in auto-run
mode, add `--cursor-clean allow` to the hook command.

## Codex CLI

Hook `PreToolUse`, matcher `^Bash$`, in `~/.codex/hooks.json`. Codex parses `ask` but does not support it yet, so a
warning is answered with a deny that says the user can allow the command in their code-watch settings (the entry stays
out, because the model reads it). Retrying the same command is denied again. With `--codex-warn allow` a warning runs and the reason goes to
stderr.

## When the adapter cannot decide

Empty or invalid input, a missing command field, input over 1 MiB, a broken user allowlist or an internal error follow
the fail mode. **`--fail-closed` is the default**: the command is denied with a message that says why and names
`--fail-open`, the reason is also written to stderr and the exit code is 2, because Codex and older Claude Code
versions treat every other non-zero code as "let it run". The same exit 2 applies to a usage error (a bad flag in the
hook command) and to a reply that cannot be written to stdout. With `--fail-open` the command is allowed (the empty reply, or Cursor's `--cursor-clean` answer) and the reason goes to
stderr. Codex has no fail-closed setting for a missing or moved binary (the shell's 127 does not block); keep the hook command
pointing at an installed path. A fail-closed adapter is loud when an agent changes its hook format; a fail-open one stops guarding quietly.

A `cwd` that is missing, not a directory or absent is treated as outside a repository: only the user allowlist applies.
