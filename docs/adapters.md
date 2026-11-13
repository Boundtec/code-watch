# Agent adapters

`code-watch adapter <claude-code|cursor|codex|gemini|opencode>` reads one agent's pre-command hook JSON on stdin, runs the same check as
`code-watch check` (with the user allowlist only: the agent can write a repo's `.code-watch.toml`, so the repo file never changes the
reply), and answers in that agent's format. Stdout carries only the reply; messages go to stderr. The exit code is 0 so
the agent reads the JSON, except when a fail-closed adapter cannot decide (below). Tool calls that are not shell
commands are left alone.

`code-watch install-adapter <agent>` prints the settings snippet for that agent and says which file it belongs in.
It edits nothing: merge the snippet into your existing `hooks` object yourself.

| Verdict | Claude Code | Cursor | Codex CLI | Gemini CLI, OpenCode |
|---|---|---|---|---|
| clean | empty reply (Claude Code's own permission flow decides) | `ask` (`--cursor-clean allow`: `allow`) | empty reply | empty reply |
| warn | `permissionDecision: "ask"` | `permission: "ask"` | `deny` that tells the model to ask the user (`--codex-warn allow`: empty reply, reason on stderr) | `deny` that tells the model to ask the user (`--gemini-warn allow` for Gemini, `--opencode-warn allow` for OpenCode: empty reply, reason on stderr) |
| block | `permissionDecision: "deny"` | `permission: "deny"` | `deny` | `{"decision": "deny", "reason": ...}` |

The reason names the rule titles. How to allow a command (the `[[allow]]` entry and the file) is never put in text the
model reads: Cursor shows it in `user_message` only, Codex has one channel so its deny does not carry it.
The same holds for internal failures: the flag, file paths and parse errors appear only in Cursor's `user_message`, never in
a field or stderr line the model reads. With stdout closed or sent to `/dev/null` the reply cannot be delivered, so a
fail-closed adapter exits 2. "No findings" never means "approved to run": where an agent has a no-opinion reply,
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
warning is answered with a deny that tells the model to ask the user (how to allow it stays out, because the model reads it). Retrying the same command is denied again. With `--codex-warn allow` a warning runs and the reason goes to
stderr.

## Gemini CLI

Hook `BeforeTool`, matcher `run_shell_command`, in `~/.gemini/settings.json`. Gemini has no ask, so a warning is denied
with a text that tells the model to ask the user. The adapter exits 0 and prints only the JSON reply on stdout, as Gemini
requires, except when a fail-closed adapter cannot decide: then it exits 2. The OpenCode plugin answers an internal
failure with the same fixed text.

## OpenCode

OpenCode has no command-hook setting: it loads JavaScript plugins. `code-watch install-adapter opencode <path>` writes
one (for example `~/.config/opencode/plugins/code-watch.js` or `.opencode/plugins/code-watch.js` in a project; the
directory must exist). `--print` prints it instead, `--fail-open` bakes the fail mode in, `--opencode-warn allow` bakes in "run a warning and
report it" (the default denies it). A file that does not start with the code-watch marker line, or is a symbolic link,
is never written; one that does is replaced in one step, so rerun the command after moving or upgrading the binary.

The plugin hooks `tool.execute.before` for `bash`, starts `code-watch adapter opencode` with an argument array (the
binary by absolute path, never a shell string), sends it the command and directory as JSON (the plugin context `directory`; the OpenCode docs do not name a per-call
working directory), and throws on a deny. Only an empty reply or an explicit allow lets the command through; any other
answer, a non-zero exit or no answer within 10 seconds is an error that follows the fail mode.
**It is untested against a live OpenCode**: it follows the hook shape that third-party plugins use, while the current
OpenCode docs describe a different plugin API without hook details. Check it against a real OpenCode before relying on it.

## When the adapter cannot decide

Empty or invalid input, a missing command field, input over 1 MiB, a broken user allowlist or an internal error follow
the fail mode. **`--fail-closed` is the default**: the command is denied with a fixed message ("code-watch could not check this command, so it was blocked. Ask the user to check their code-watch setup."), the same text goes to stderr and the exit code is 2, because Codex and older Claude Code
versions treat every other non-zero code as "let it run". The same exit 2 applies to a usage error (a bad flag in the
hook command) and to a reply that cannot be written to stdout. With `--fail-open` the command is allowed (the empty reply, or Cursor's `--cursor-clean` answer) and the reason goes to
stderr. Codex has no fail-closed setting for a missing or moved binary (the shell's 127 does not block); keep the hook command
pointing at an installed path. A fail-closed adapter is loud when an agent changes its hook format; a fail-open one stops guarding quietly.

A `cwd` that is missing, not a directory or absent is treated as outside a repository: only the user allowlist applies.

## PATH shims

`code-watch shims install <dir>` is the fallback for agents with no hook. A shim sees one tool's argv, so pipeline rules
never fire and a warning only prints on stderr before the tool runs; only a block stops it (exit 2). Shims do not turn a
warning into a block because the argv alone rarely gives a pipeline's context. A shim can be avoided with an absolute
path, `command -p`, `env PATH=...`, `env -i`, or a sandbox that resets `PATH`. After an upgrade run `shims install`
again; `shims status <dir>` shows which links are dangling or point at another binary.
