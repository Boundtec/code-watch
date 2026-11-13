# Allowlists

An allowlist entry hides a finding of the rules layer or the OSV layer from the verdict. It never turns a
layer off, and hidden findings stay visible: `--json` lists them under `suppressed` (schema stays 1) and the human
output ends with `N findings suppressed by allowlists`.

## Files

| File | Where | Can allow |
|---|---|---|
| User (decides) | `$XDG_CONFIG_HOME/code-watch/allow.toml`, else `~/.config/code-watch/allow.toml` | any rule, including `block` ones |
| Per repo (advisory) | `.code-watch.toml` at the repo root | `warn` and `info` findings; a `block` finding only if the user file also lists that rule id |

A cloned repo is untrusted, so it cannot allow itself past a block. When it tries, the finding stays and
`allowlist/repo-block-override-refused` is added. `check <command>` reads the repo file only when the working
directory is inside a git work tree (a `.git` directory or file above it); elsewhere only the user file applies.

```toml
schema = 1

[[allow]]
rule = "repo/npm-lifecycle-script"   # required: an exact rule id, no wildcard
path = "packages/**/package.json"    # optional glob on the finding's file, relative to the scanned root
domain = "example.org"               # optional: the host a command finding is about
package = "left-pad"                 # optional: the package an OSV finding is about
reason = "internal build step"       # optional, echoed in --json
```

All narrowers on an entry must match. `path` uses `*` within one directory (it does not cross `/`; use `**`), and a
finding with no file never matches a path entry. `domain` and `package` compare against fields the rule itself sets,
case-insensitively and exactly: `example.org` does not cover `cdn.example.org`, and the finding's excerpt is never
consulted.

A finding has a `domain` only when it is about a download and the command is unambiguous: the finding is
`command/pipe-to-shell` (the host is taken from its URL) or `command/lookalike-download-domain` (the host it flagged).
For `command/pipe-to-shell` the whole command must also hold exactly one `curl` or `wget`, with one absolute URL
(`https://...`) and only flags this build knows take no address. A bare host, `--url`, `-K`/`--config`,
`-i`/`--input-file`, an unknown flag, a second fetch anywhere (another pipeline, `;`/`&&`, `sh -c`, `$(...)`) or any
other mention of `curl` or `wget` leaves the finding without a domain, so a `domain` entry does not match it. Findings
of other rules (base64 into a shell, quarantine removal) never have a domain.

Listing a rule in the user file also lets repo files allow it, whatever the narrowers of the user entry: a user entry
with `path = "vendor/**"` for a `block` rule still unlocks every repo entry for that rule. That is the delegation: the
user file says "this rule may be decided by repos".

## Errors and warnings

| Case | Result |
|---|---|
| user file malformed, unknown key, missing or newer `schema` | exit 3 with the path and the reason |
| repo file malformed, unknown key, newer schema, over 64 KiB, a symlink or a FIFO or other non-regular file | ignored; `allowlist/repo-file-invalid` is added (warn) |
| an entry names a rule id this build does not have (or `*`) | a warning line and `allowlist_warnings` in `--json`; nothing is suppressed by it |

`allowlist/*` findings, `repo/unscanned-target`, `osv/unparsed-lockfile`, `osv/unchecked-packages` and LLM findings can never be allowed.
