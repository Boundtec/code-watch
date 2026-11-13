# Agent adapters

`code-watch adapter <claude-code|cursor|codex>` reads one agent's pre-command hook JSON on stdin, runs the same check as
`code-watch check` (including the user and repo allowlists of the hook's `cwd`), and answers in that agent's format.
Stdout carries only the reply; messages go to stderr. The exit code is 0 so the agent reads the JSON. Tool calls that
are not shell commands are left alone.

`code-watch install-adapter <agent>` prints the settings snippet for that agent and says which file it belongs in.
It edits nothing: merge the snippet into your existing `hooks` object yourself.

| Verdict | Claude Code | Cursor | Codex CLI |
|---|---|---|---|
| clean | empty reply (Claude Code's own permission flow decides) | `{"permission":"allow"}` | empty reply |
| warn | `permissionDecision: "ask"` | `permission: "ask"` | `deny` that says how to allow it (`--codex-warn allow`: empty reply, reason on stderr) |
| block | `permissionDecision: "deny"` | `permission: "deny"` | `deny` |

The reason names the rule titles. "No findings" never means "approved to run": where an agent has a no-opinion reply,
a clean command gets it.

## Claude Code

Hook `PreToolUse`, matcher `Bash`, in `~/.claude/settings.json`. The snippet sets `onFailure: "block"` (Claude Code
2.1.295 or newer), so a crash or timeout of the hook blocks instead of letting the command through.

## Cursor

Hook `beforeShellExecution` in `~/.cursor/hooks.json`, with `"version": 1` and `failClosed: true`. Cursor's hook
documentation has no "no opinion" reply: anything that is not a valid permission blocks the action. A clean command is
therefore answered `{"permission":"allow"}`, which the documentation describes as approving the command; it does not say
whether that also skips Cursor's own approval prompt. If it does, code-watch auto-approves clean commands in Cursor.
To limit that, set a `matcher` regex in `hooks.json` so the hook only sees the commands you want it to judge.

## Codex CLI

Hook `PreToolUse`, matcher `^Bash$`, in `~/.codex/hooks.json`. Codex parses `ask` but does not support it yet, so a
warning is answered with a deny whose reason lists the rule ids and the `allow.toml` entry that lets the command
through. Retrying the same command is denied again. With `--codex-warn allow` a warning runs and the reason goes to
stderr.

## When the adapter cannot decide

Empty or invalid input, a missing command field, input over 1 MiB, a broken user allowlist or an internal error follow
the fail mode. **`--fail-closed` is the default**: the command is denied with a message that says why and names
`--fail-open`. With `--fail-open` the command is allowed (the empty reply, or Cursor's allow) and the reason goes to
stderr. A fail-closed adapter is loud when an agent changes its hook format; a fail-open one stops guarding quietly.

A `cwd` that is missing, not a directory or absent is treated as outside a repository: only the user allowlist applies.
