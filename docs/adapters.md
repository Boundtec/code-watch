# Agent adapters

`code-watch adapter <claude-code|cursor|codex|gemini|opencode>` reads one agent's pre-command hook JSON on stdin, runs the same check as
`code-watch check` (including the user and repo allowlists of the hook's `cwd`), and answers in that agent's format.
Stdout carries only the reply; messages go to stderr. The exit code is 0 so the agent reads the JSON. Tool calls that
are not shell commands are left alone.

`code-watch install-adapter <agent>` prints the settings snippet for that agent and says which file it belongs in.
It edits nothing: merge the snippet into your existing `hooks` object yourself.

| Verdict | Claude Code | Cursor | Codex CLI | Gemini CLI, OpenCode |
|---|---|---|---|---|
| clean | empty reply (Claude Code's own permission flow decides) | `ask` (`--cursor-clean allow`: `allow`) | empty reply | empty reply |
| warn | `permissionDecision: "ask"` | `permission: "ask"` | `deny` that says how to allow it (`--codex-warn allow`: empty reply, reason on stderr) | `deny` that says how to allow it (`--gemini-warn allow`: empty reply, reason on stderr) |
| block | `permissionDecision: "deny"` | `permission: "deny"` | `deny` | `{"decision": "deny", "reason": ...}` |

The reason names the rule titles. "No findings" never means "approved to run": where an agent has a no-opinion reply,
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
warning is answered with a deny whose reason lists the rule ids and the `allow.toml` entry that lets the command
through. Retrying the same command is denied again. With `--codex-warn allow` a warning runs and the reason goes to
stderr.

## Gemini CLI

Hook `BeforeTool`, matcher `run_shell_command`, in `~/.gemini/settings.json`. Gemini has no ask, so a warning is denied
with the allowlist entry that lets it through. The adapter always exits 0 and prints only the JSON reply on stdout,
as Gemini requires.

## OpenCode

OpenCode has no command-hook setting: it loads JavaScript plugins. `code-watch install-adapter opencode <path>` writes
one (for example `~/.config/opencode/plugins/code-watch.js` or `.opencode/plugins/code-watch.js` in a project; the
directory must exist). `--print` prints it instead, `--fail-open` bakes the fail mode in. A file that does not start
with the code-watch marker line is never overwritten; one that does is replaced, so rerun the command after moving or
upgrading the binary.

The plugin hooks `tool.execute.before` for `bash`, starts `code-watch adapter opencode` with an argument array (the
binary by absolute path, never a shell string), sends it the command and directory as JSON, and throws on a deny.
**It is untested against a live OpenCode**: it follows the hook shape that third-party plugins use, while the current
OpenCode docs describe a different plugin API without hook details. Check it against a real OpenCode before relying on it.

## When the adapter cannot decide

Empty or invalid input, a missing command field, input over 1 MiB, a broken user allowlist or an internal error follow
the fail mode. **`--fail-closed` is the default**: the command is denied with a message that says why and names
`--fail-open`. With `--fail-open` the command is allowed (the empty reply, or Cursor's `--cursor-clean` answer) and the reason goes to
stderr. A fail-closed adapter is loud when an agent changes its hook format; a fail-open one stops guarding quietly.

A `cwd` that is missing, not a directory or absent is treated as outside a repository: only the user allowlist applies.
