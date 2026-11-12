# Plan: git hook (CUC-338)

## What install writes
- Template dir `$XDG_DATA_HOME/code-watch/git-template` (default `~/.local/share/...`) with `hooks/post-checkout`, mode 0755.
- `git config --global init.templateDir <that dir>` (git picks the right global file itself).
- The hook is a `/bin/sh` script with a marker line `# code-watch managed hook`. It runs only when the first argument
  (previous HEAD) is the null ref, which is a clone or `worktree add`. Branch and file checkouts are skipped: scanning on
  every `git switch` is slow and noisy, and the code was already scanned on clone. (Row: branch checkout = skip.)
- It runs `<abs path of the installing binary> scan .`; if that path is gone it falls back to `code-watch` on PATH; if
  neither exists it prints "code-watch not found, run `code-watch install-hook` again" to stderr and exits 0. (Row:
  binary moved = fails visibly, never silently and never blocking the clone.)
- On a non-clean verdict the hook prints a closing line: warn = "review the findings before running anything here"; block
  = "do not open or run anything here; delete it with `rm -rf <dir>`". Exit code = scan's (0/1/2/3), as in DESIGN; git
  ignores it for clone, the clone stays on disk.

## Ownership and uninstall
Ours = `init.templateDir` equals our dir. Uninstall: if it does, `git config --global --unset init.templateDir`, delete our
hook if it still has the marker, remove our dir if it is then empty. Otherwise it changes nothing and says "templateDir is
not ours (or not set); nothing to do" (exit 0).

## Open rows
- User already has a templateDir (not ours): **refuse**, exit 3, message names their dir and how to add the hook by hand.
  We never edit or copy a dir we do not own, so their post-checkout is never lost. Chaining (copy theirs) goes stale, so no.
- `core.hooksPath` set globally: **refuse**, exit 3, "git ignores templateDir hooks while core.hooksPath is set". Nothing
  written, so install never reports a guard that cannot fire.
- Install twice: same dir, same marker: rewrite the hook, config unchanged, "already installed".
- git not on PATH: exit 3 with a clear message.

## Code
`crates/code-watch/src/hook.rs` (std only, `std::process::Command` for git) and two subcommands in `main.rs`
(`InstallHook`, `UninstallHook`; they print text and return their own exit code, outside the Report path). No changes to
core, report or render. README section + `docs/git-hook.md`.

## Tests (every git call under a tempdir HOME, XDG_*, GIT_CONFIG_GLOBAL; real `~/.gitconfig` hash checked before/after)
1. install on clean config sets ours; uninstall leaves the global file byte-identical to before.
2. user templateDir: refused, their config and files untouched.
3. user hook in their dir: still byte-identical after refused install.
4. install twice: idempotent (file and config identical).
5. uninstall without install; uninstall after user changed templateDir: nothing changed, says so.
6. git not on PATH: exit 3.
7. moved binary: hook with dead path and no PATH fallback prints the visible message.
8. real `git clone` of a local repo with a lifecycle script: hook output shows verdict; block repo prints the delete advice; clone dir stays.
9. branch checkout does not scan.
10. core.hooksPath set: install refuses, writes nothing.
