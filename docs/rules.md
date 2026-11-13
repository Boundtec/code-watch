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
| `binary_file` | repo files | `files`, `formats` (`elf`, `mach_o`, `pe`) | the file starts with that format's magic bytes; the file is also scanned as text, with invalid UTF-8 decoded lossily (a script starting with `MZ` is not a PE file); a recognised binary is never reported as unreadable. PE needs the DOS header's `e_lfanew` to point at `PE\0\0`, and fat Mach-O needs an architecture count of 1 to 20 (a Java class file has the same `cafebabe` magic) |
| `executable_file` | repo files | `files` | the file has a unix execute bit (never fires on non-unix hosts) |
| `command_regex` | a command string | `pattern` | the pattern matches the command |

The `command_regex` matcher tests the raw command text. No embedded rule uses it any more: the command rules need the command
parsed and live in Rust (below), so a quoted or printed `curl x | sh` is not a finding.

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

## What a scan reads

Files up to 1 MiB are decoded as text; bytes that are not valid UTF-8 become U+FFFD and the text rules still run. A symlink
that resolves inside the scanned directory is followed and named by its link path (npm and VS Code follow it too). A link
that resolves outside it is never read: a directory link, or a file link a text rule targets, is listed as not scanned
(`symlink_outside_repo`), and so is a dangling link a text rule targets. The `check` command argument must be valid UTF-8;
otherwise `code-watch` exits 3.

## Adding a rule

1. Add it to the right file, with the next free `<layer>/<name>` id.
2. Add `crates/code-watch-core/tests/fixtures/<id with / replaced by __>/`: for repo rules a `positive/` and a
   `negative/` directory (the negative must be a near miss, for example one half of an `all_regex`), for command rules
   `positive.txt` and `negative.txt` with one command per line. Fixtures are inert text: no real malware, secrets or tokens.
3. `cargo test` fails if a rule has no fixtures, does not fire on the positive, or fires on the negative.
4. Add a row to the table in the README.
5. A regex with alternatives needs a positive fixture per alternative: every file in `positive/` must fire on its own, so deleting an alternative turns a fixture red.

## Rules built in Rust

Rules that need the command split into words (lookalike domains, a hidden program name piped into a shell, `osascript`, `LaunchAgents` and `LaunchDaemons` writes) live in
`crates/code-watch-core/src/command/` and are listed in `command::RULES`. They are not in the TOML files. Their
fixtures work like command-regex fixtures (`positive.txt` / `negative.txt`, one command per line) and the fixture test
runs them with the macOS-only rules enabled on every platform. `--json` carries `skipped_rules`: the ids of rules that
exist but are not active on this platform.

The command is parsed with `brush-parser` and every simple command of every list, pipeline, subshell, brace group, `if`/`while`/`for`/`case`,
`$(...)`, backtick and `<(...)` is judged on its parsed words, wherever it is nested. One table (`command/readers.rs`) says what runs text as a
script: a shell (by name or path, also through `sudo`, `doas`, `env`, `busybox`, `nohup`, `exec`, `command`, `xargs`, `time`, `nice`), an
interpreter (`python*`, `perl`, `ruby`, `node`) with no script file or with inline code (`-c`, `-e`, `-pe`), `source`/`.` of `/dev/stdin`, a
`tee >(...)` whose body holds one, and a group with one inside. A download or a base64/`xxd -r` decoder whose output reaches one of these, in the
same pipeline or because it sits inside the `$(...)` that is the whole text of `sh -c`/`eval`, or inside a `<(...)` or here-string a shell reads,
is judged as running.

- `command/pipe-to-shell` (warn): a `curl` or `wget` whose output is run as a script. Piping into an interpreter that runs inline code
  (`python3 -c ...`) counts: the downloaded text goes into an interpreter that executes code, and the code can run what it reads.
- `command/base64-into-shell` (block): a decoder (`base64 -d`, `-D`, `-di`, `--decode`, `xxd -r`) whose output is run the same way, including
  `eval "$(... | base64 -d)"`, `eval $(...)` and `sh -c "$(...)"`.
- `command/quarantine-removal` (warn): `xattr` with `-c`, or with `-d`/`-w` and the `com.apple.quarantine` word.
- `command/unparsable` (warn): text the parser rejects (an unterminated quote or `$(`, a dangling `||`), or longer than 64 KiB. Warn, not block:
  the checker may lack a bash feature, and a shell would reject most of these too. The command is never reported clean.
- `command/nesting-too-deep` (warn; block when the text left at the limit holds a shell, `eval` or script reader): `$(...)`, `<(...)`, `sh -c`
  and `eval` text nested more than three levels.
- `command/hidden-program-into-shell` (warn) fires when a pipeline ends in a script reader and a command's program word still holds a `$`
  or a backtick after unquoting (`$'\x63url'`, `$c`, `$(echo curl)`, also a `$HOME/bin/tool` prefix), and when `eval` gets a variable
  (`eval "$x"`). `eval "$(...)"` does not fire: the substitution is analysed as its own text.
- `command/launchagent-write` matches `Library/LaunchAgents` and `Library/LaunchDaemons` as path components, not as a substring.

What they do not see, by design: variables (`$c x`), command substitutions inside `${...}` defaults and `[[ ]]` tests, fetchers other than `curl` and `wget`, and the script an `osascript` reads from a file or
standard input. A lookalike is one edit away (or the same name under another suffix, or the same Unicode skeleton) from
the known list; `SIBLINGS` in `domains.rs` lists real sites that must never be flagged, so a new known domain that
collides with a real one gets a negative fixture and a sibling entry.
