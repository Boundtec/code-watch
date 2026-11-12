# Rules format

Rules are TOML files in `crates/code-watch-core/rules/`, embedded in the binary at build time. A file starts with
`schema = 1`; a binary refuses a newer schema. Rule ids are unique across files.

```toml
[[rule]]
id = "repo/npm-lifecycle-script"
severity = "warn"            # info | warn | block
title = "What was found"
remediation = "What to do instead"
match = { kind = "json_pointer", files = ["**/package.json"], pointers = ["/scripts/postinstall"] }
```

| `kind` | Applies to | Fields |
|---|---|---|
| `json_pointer` | repo files | `files` (globs), `pointers` (RFC 6901; fires when the pointer exists) |
| `file_regex` | repo files | `files` (globs), `pattern` (one finding per file, at the first match) |
| `command_regex` | a command string | `pattern` |

Patterns use the Rust `regex` crate (linear time, safe on hostile input).

## Adding a rule

1. Add it to the right file.
2. Add `tests/fixtures/<id with / replaced by __>/` in `crates/code-watch-core`: for repo rules a `positive/` and a
   `negative/` directory, for command rules `positive.txt` and `negative.txt` (one command per line). Fixtures are inert
   text: no real malware, secrets or tokens.
3. `cargo test` fails if a rule has no fixtures or does not fire / fires on the wrong one.

## Rules built in Rust

Rules that need the command split into words (lookalike domains, `osascript`, `LaunchAgents` writes) live in
`crates/code-watch-core/src/command/` and are listed in `command::RULES`. They are not in the TOML files. Their
fixtures work like command-regex fixtures (`positive.txt` / `negative.txt`, one command per line) and the fixture test
runs them with the macOS-only rules enabled on every platform. `--json` carries `skipped_rules`: the ids of rules that
exist but are not active on this platform.
