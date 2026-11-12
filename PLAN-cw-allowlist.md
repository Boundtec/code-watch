# Plan: allowlists (CUC-337)

## File format (same for both files)
```toml
schema = 1

[[allow]]
rule = "repo/npm-lifecycle-script"   # required, exact rule id
path = "packages/**/package.json"    # optional glob, relative to the scanned root (globset)
domain = "example.org"               # optional, matches the host of a command finding
package = "left-pad"                 # optional, matches the package of an OSV finding
reason = "why"                       # optional, free text, shown in --json
```
`toml` + `serde` with `deny_unknown_fields`; `globset` for `path`. Crates already in the workspace, plus `dirs` (named in DESIGN s.2) in the bin crate.
Newer `schema` than supported is an error. Several narrowers on one entry must all match.
Domain/package match the finding's evidence excerpt as whole tokens (case-insensitive); there is no new Finding field, so the OSV layer must put the package name in its excerpt (documented in docs/allowlist.md).

## Locations
- User: `$XDG_CONFIG_HOME/code-watch/allow.toml`, else `dirs::config_dir()/code-watch/allow.toml`. The CLI resolves the dir and injects it into the core (`Allowlists::load(user_dir, repo_root)`), so tests never touch the real home.
- Repo: `<scanned root>/.code-watch.toml` for `scan`. `check <command>` loads it only when the cwd is inside a git work tree (walk up to a `.git`); outside any repo: user file only.
- Missing file = empty list. Repo file read like the scan reads files: `symlink_metadata`, a symlink or non-regular file is not followed, size cap 64 KiB (`MAX_FILE_BYTES` style), must live directly in the root.

## Precedence
1. Collect user entries (can allow anything) and repo entries.
2. A repo entry suppresses a finding only if the finding is not `block`, OR some user entry also names that same rule id (user entry need not match the same narrowers: "lists that rule").
3. A repo entry that matches a `block` finding without user backing does not suppress; the report adds `allowlist/repo-block-override-refused` (severity warn, layer rules) naming the rule id. One per rule id.
4. Only rules-layer and OSV-layer findings are suppressible. Llm findings and the engine's own (`repo/unscanned-target`, `allowlist/*`) never are. An entry never touches layers: `layers` is unchanged.

## Where it sits
`Engine` stays as is. New `allow` module in core: `Allowlists`, `Allowlists::apply(findings) -> (kept, Vec<Suppressed>, extra findings)`. Applied in `Engine::scan_dir_with` / `check_command_with` (new `Allowlists` argument; the old signatures keep an empty list) after rules ran and before `Report` is built. `Report` gets `suppressed: Vec<Suppressed>` (finding + `reason` + `source: user|repo`) and `allow_warnings: Vec<String>`; verdict is still derived from `findings` only. Report fields stay private.
Output: `--json` gets additive `suppressed` and `allowlist_warnings` keys (schema stays 1); human footer: `N finding(s) suppressed by allowlists` and `allowlist: unknown rule id "x" in <file>`.

## Open rows, decided
- Malformed repo file: **warn and ignore it** (recommended): a hostile or stale file in a cloned repo must not be able to deny the scan, and ignoring it can only produce more findings. A warn finding `allowlist/repo-file-invalid` is added so it is visible. User file malformed / unknown key / newer schema: exit 3 with the path and the toml error.
- Unknown rule id: warning line + `allowlist_warnings`, not an error. Known ids come from the loaded `RuleSet` plus engine/Rust command rule ids.
- Symlink, outside root, huge repo file: ignored with the same `allowlist/repo-file-invalid` warn finding (reason in evidence).

## Tests (each one goes red if its line is removed)
Core unit (tempdirs, injected dirs): no files; user malformed / unknown key / newer schema (error); repo malformed (warn finding, nothing suppressed); repo allows warn rule (suppressed, in `suppressed`); repo allows block rule without user (kept + refusal finding); with user listing it (suppressed); user allows block alone; path / domain / package narrowed, finding outside (kept) and inside (suppressed); repo symlink, huge file; `check` with no repo (user only); unknown rule id warning; llm-layer and `repo/unscanned-target` findings never suppressed; layers unchanged after suppression; verdict drops only when suppressed.
Render: json additive keys, schema 1; human footer count.
CLI (assert_cmd, `XDG_CONFIG_HOME` pointed at a tempdir): malformed user file exits 3 with message; suppression end to end exit code 0.
Docs: docs/allowlist.md, README section, DESIGN row 3 untouched.
