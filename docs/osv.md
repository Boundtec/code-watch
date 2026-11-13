# Known vulnerabilities (OSV)

`code-watch scan <dir>` reads the lockfiles in a repository, asks [OSV](https://osv.dev) which of the pinned
packages have published advisories, and reports them. It never installs or runs anything.

## What it reads

| Ecosystem (OSV name) | Files | Packages taken |
|---|---|---|
| `npm` | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and berry) | resolved from the public npm registry |
| `PyPI` | `requirements.txt`, `poetry.lock`, `uv.lock` | exact `==` pins; lock entries from PyPI |
| `crates.io` | `Cargo.lock` | entries from crates.io |
| `Go` | `go.mod` | `require` lines, direct and indirect, with `replace` applied |

Only packages from the public registry are looked up, so a local crate or a private package never matches a published
one of the same name: path, git, workspace, `file:`, `link:` and private-registry entries are dropped. `go.sum` is not
read, because it keeps versions the build does not use. Names in PyPI files are normalised (PEP 503). A
`requirements.txt` line that is not an exact pin (a range, a URL, `-e`, an option) names no single version and is
ignored. Lockfiles inside `node_modules` and `.git` are not read.

A lockfile that is a symlink (never followed), larger than 16 MiB, not UTF-8 or not parseable is skipped and reported
as `osv/unparsed-lockfile` (warn).

## What is sent

Package names, versions and ecosystems, nothing else: no paths, no repository name, no file content. Two calls go to
`api.osv.dev`: `POST /v1/querybatch` (up to 1000 packages per request) and `GET /v1/vulns/<id>` once per advisory.
Requests time out after 10 seconds.

## Findings

| Rule | Severity | Meaning |
|---|---|---|
| `osv/malicious-package` | block | an advisory whose id starts with `MAL-` |
| `osv/known-vulnerability` | warn, or info | the severity label of the advisory: CRITICAL and HIGH warn, MODERATE and LOW inform; an advisory with no label (only a CVSS vector) warns, because unknown is not downgraded |
| `osv/unchecked-packages` | warn | packages that could not be looked up (OSV unreachable, an error status, a partial answer, or offline with no fresh cache); it names a few |
| `osv/unparsed-lockfile` | warn | a lockfile that could not be read |

A finding carries the advisory id, the fixed versions OSV lists (at most three), the lockfile and line when the format
has one, and the package name, so `package = "..."` in an allowlist entry matches it. The same package in two lockfiles
is queried once and reported in both. The two warnings about unchecked and unparsed input can never be allowed.

A failed lookup is never a clean result. When nothing could be looked up at all, `layers.osv` is `skipped` and
`skipped_layers.osv` in `--json` (and the footer) says why; when only some packages failed it is `ran` and the
`osv/unchecked-packages` warning names them. `off` means the layer was not asked for (`--no-osv`, or `check`).

## Cache and running offline

Answers are cached under `$XDG_CACHE_HOME/code-watch/osv/`, else `~/.cache/code-watch/osv/`: one JSON file per
package version, named by a hash of the key, valid for 24 hours. A stale entry is never used, because an advisory
published after it was written would give a false "clean". A damaged, foreign or newer-format file is ignored and
overwritten by the next lookup. The cache never deletes anything.

| Command | Behaviour |
|---|---|
| `code-watch scan <dir>` | fresh cache first, OSV for the rest |
| `code-watch scan --offline <dir>` | fresh cache only, no network; the rest is reported as unchecked |
| `code-watch scan --no-osv <dir>` | the layer is off, no lockfile is read |

To work offline, run a normal scan once while online (it fills the cache), then use `--offline` within 24 hours.
