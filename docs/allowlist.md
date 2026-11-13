# Allowlists

An allowlist entry hides a finding of the rules layer or the OSV layer from the verdict. It never turns a
layer off, and hidden findings stay visible: `--json` lists them under `suppressed` (schema stays 1) and the human
output ends with `N findings suppressed by allowlists`.

## Files

| File | Where | Can allow |
|---|---|---|
| User (decides) | `$XDG_CONFIG_HOME/code-watch/allow.toml`, else `~/.config/code-watch/allow.toml` | any rule, including `block` ones |
| Per repo (advisory) | `.code-watch.toml` at the repo root | `warn` and `info` findings of repo rules (`repo/*`); never a `block` finding and never a `command/*` or `install/*` rule |

A repository file is untrusted: a cloned repo, or an agent writing files in it, could otherwise allow itself past the
guard. A repo entry that would hide a `block` finding leaves the finding and adds `allowlist/repo-block-override-refused`;
one that would hide a `command/*` finding leaves the finding and adds `allowlist/repo-command-override-refused` (only
when it matches an actual finding, so a clean command stays clean). The agent adapters and the clone-time scan
(`scan --user-allow-only`, what `install-hook` installs) read the user file only; hooks installed earlier call plain
`scan .`, so run `install-hook` again (it says "updated from an older version"); a copy of the hook already
in a clone's `.git/hooks` is not touched, so run `install-hook` again and re-create the hook there. `check <command>` reads the repo file only to report such an attempt, and only
when the working directory is inside a git work tree; `scan <dir>` run by hand still honours `repo/*` warnings from
`<dir>/.code-watch.toml`.

```toml
schema = 1

[[allow]]
rule = "repo/npm-lifecycle-script"   # required: an exact rule id, no wildcard
path = "packages/**/package.json"    # optional glob on the finding's file, relative to the scanned root
domain = "example.org"               # optional: the host a command finding is about
package = "left-pad"                 # optional glob: the package an OSV or install finding is about (`@scope/*`)
reason = "internal build step"       # optional, echoed in --json
```

All narrowers on an entry must match. `path` uses `*` within one directory (it does not cross `/`; use `**`), and a
finding with no file never matches a path entry. `domain` and `package` compare against fields the rule itself sets,
case-insensitively (`package` is a glob, `domain` is exact): `example.org` does not cover `cdn.example.org`, and the finding's excerpt is never
consulted. The `package` narrower was an exact match before install findings existed: a name with a glob character (`[`, `*`, `?`) now matches as a pattern and differing case now matches, so an existing OSV allow entry with such a name covers more than before.

A finding has a `domain` only when it is about a download and the command is unambiguous: the finding is
`command/pipe-to-shell` (the host is taken from its URL) or `command/lookalike-download-domain` (the host it flagged).
For `command/pipe-to-shell` the whole command must also hold exactly one `curl` or `wget`, with one absolute URL
(`https://...`) and only flags this build knows take no address. A bare host, `--url`, `-K`/`--config`,
`-i`/`--input-file`, an unknown flag, a second fetch anywhere (another pipeline, `;`/`&&`, `sh -c`, `$(...)`) or any
other mention of `curl` or `wget` leaves the finding without a domain, so a `domain` entry does not match it. Findings
of other rules (base64 into a shell, quarantine removal) never have a domain.

A repo entry never lifts a block, whatever the user file lists: there is no delegation, so a user entry narrowed to one
host or path cannot be widened by a repo file.

## Errors and warnings

| Case | Result |
|---|---|
| user file malformed, unknown key, missing or newer `schema` | exit 3 with the path and the reason |
| repo file malformed, unknown key, newer schema, over 64 KiB, a symlink or a FIFO or other non-regular file | ignored; `allowlist/repo-file-invalid` is added (warn) |
| an entry names a rule id this build does not have (or `*`) | a warning line and `allowlist_warnings` in `--json`; nothing is suppressed by it |

`allowlist/*` findings, `repo/unscanned-target`, `osv/unparsed-lockfile`, `osv/unchecked-packages` and LLM findings can never be allowed.
