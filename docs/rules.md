# Rules format

Rules are TOML files in `crates/code-watch-core/rules/` (`repo.toml`, `command.toml`), embedded in the binary at build
time. No hosted feed: rules change with each release.

## File and rule fields

A file starts with `schema = <number>`. The binary refuses a file with a schema newer than it supports and says so;
adding a matcher `kind` or an optional field keeps the number, changing the meaning of an existing field raises it.
Unknown fields in a rule are an error, and rule ids are unique across files.

```toml
schema = 1

[[rule]]
id = "repo/npm-lifecycle-script"   # <layer>/<name>, also the fixture directory name
severity = "warn"                  # info | warn | block
title = "What was found"
remediation = "What to do instead"
match = { kind = "json_pointer", files = ["**/package.json"], pointers = ["/scripts/postinstall"] }
```

## Matchers (`match.kind`)

| `kind` | Applies to | Fields | Fires when |
|---|---|---|---|
| `json_pointer` | repo files | `files` (globs), `pointers` (RFC 6901) | a pointer exists in the JSON file |
| `file_regex` | repo files | `files`, `pattern` | the pattern matches; one finding per file, at the first match |
| `all_regex` | repo files | `files`, `patterns` (list) | every pattern matches somewhere in the same file; the finding points at the first pattern's line |
| `binary_file` | repo files | `files`, `formats` (`elf`, `mach_o`, `pe`) | the file starts with that format's magic bytes; the file is also scanned as text when it is valid UTF-8 (a script starting with `MZ` is not a PE file); a recognised binary is never reported as unreadable. PE needs the DOS header's `e_lfanew` to point at `PE\0\0`, and fat Mach-O needs an architecture count of 1 to 20 (a Java class file has the same `cafebabe` magic) |
| `executable_file` | repo files | `files` | the file has a unix execute bit (never fires on non-unix hosts) |
| `command_regex` | a command string | `pattern` | the pattern matches the command |

Globs are matched against the path relative to the scanned root; braces work (`**/*.{js,py}`). Patterns use the Rust
`regex` crate: linear time, safe on hostile input, no look-around. `all_regex` is how "reads credentials **and** sends
them out" is expressed: each half alone does not fire.

## Repo layer rules

| Id | Severity | Catches |
|---|---|---|
| `repo/setup-py-install-hook` | warn | `cmdclass`, `subprocess`, `__import__`, `urlopen`, `urlretrieve`, `system(`, `os.popen(`, `exec(` or `eval(` in `setup.py` |
| `repo/makefile-install-fetch` | warn | an `all`, `install`, `setup` or `bootstrap` target whose recipe runs `curl` or `wget`. Limit: a prerequisite target that fetches (`install: fetch`, `fetch:` runs `curl`) is not followed |
| `repo/makefile-shell-fetch` | warn | a top-level `$(shell ... curl ...)` or `!=` assignment, which runs on every make invocation |
| `repo/obfuscated-blob` | warn | 240+ base64 or hex characters in a script, also when wrapped over lines or split into quoted, `+` or `\` joined pieces; a data URI or an embedded PEM in a script warns too, which is acceptable for a warn (lockfile hashes and `.pem` files are not scripts and are not scanned) |
| `repo/minified-eval` | warn | a line of 400+ characters that calls `eval`, `exec`, `Function` or `atob` (method calls such as `re.exec(` are ignored; `window.`, `globalThis.` and `self.` receivers are not) |
| `repo/committed-binary` | warn | an ELF, Mach-O or PE file in the repo |
| `repo/executable-source` | info | a source, data or text file with the execute bit |
| `repo/secret-read-and-send` | warn | one script that reads `.ssh`, `.aws`, `.kube`, `.gnupg`, `.npmrc`, `.netrc`, `.git-credentials`, Docker config, the keychain or the whole environment and also makes a network call; warn because legitimate deploy scripts do both |

## Adding a rule

1. Add it to the right file, with the next free `<layer>/<name>` id.
2. Add `crates/code-watch-core/tests/fixtures/<id with / replaced by __>/`: for repo rules a `positive/` and a
   `negative/` directory (the negative must be a near miss, for example one half of an `all_regex`), for command rules
   `positive.txt` and `negative.txt` with one command per line. Fixtures are inert text: no real malware, secrets or tokens.
3. `cargo test` fails if a rule has no fixtures, does not fire on the positive, or fires on the negative.
4. Add a row to the table in the README.
5. A regex with alternatives needs a positive fixture per alternative: every file in `positive/` must fire on its own, so deleting an alternative turns a fixture red.

## Rules built in Rust

Rules that need the command split into words (lookalike domains, `osascript`, `LaunchAgents` writes) live in
`crates/code-watch-core/src/command/` and are listed in `command::RULES`. They are not in the TOML files. Their
fixtures work like command-regex fixtures (`positive.txt` / `negative.txt`, one command per line) and the fixture test
runs them with the macOS-only rules enabled on every platform. `--json` carries `skipped_rules`: the ids of rules that
exist but are not active on this platform.
