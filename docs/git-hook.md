# Scan on clone: the git hook

`code-watch install-hook` makes every new `git clone` (and `git worktree add`) run `code-watch scan .` in the new
checkout. It does this with a global git template: a `post-checkout` hook in
`$XDG_DATA_HOME/code-watch/git-template/hooks` (default `~/.local/share/...`), and `init.templateDir` in your global
git config pointing at that folder. Nothing else is touched.

```sh
code-watch install-hook     # turn it on
code-watch uninstall-hook   # turn it off; your git config is as it was before
```

## What you see

- Clean repo: nothing extra.
- Warnings: the findings, then a line telling you to review them. The clone succeeds (exit 0).
- Block: the findings, then "BLOCK. Do not open or run anything in this directory" and the directory path on its own
  line (control characters removed; it is never printed as a command, because the folder name can be chosen by the
  repo's owner). git cannot undo a clone from this hook, so the clone stays on disk and `git clone` exits with the
  hook's code 2. Delete the directory yourself.
  Warnings exit 0 on purpose: a failing hook makes git report a failed checkout, which would make every warning look
  like a broken clone.
- Branch switches and file checkouts are not scanned; only a clone or a new worktree is.
- If the `code-watch` binary was moved, the hook tries the `code-watch` on your PATH; if there is none it says so on
  every clone and lets the clone through. Run `code-watch install-hook` again after moving it.

## When install refuses (exit 3, nothing written)

| Situation | Why |
|---|---|
| `init.templateDir` already points elsewhere | we never edit or copy a folder that is not ours; add `code-watch scan .` to your own `post-checkout` there |
| `core.hooksPath` is set | git ignores template hooks while it is |
| `GIT_TEMPLATE_DIR` is set, or another setting overrides ours | the hook would never run |
| `git` is not on PATH | nothing to configure |

## After uninstall

git copies the hook into each clone's `.git/hooks/post-checkout`, with the absolute path of the binary baked in. Clones
made while the hook was installed keep that copy after `uninstall-hook` (it fires again on `git worktree add`). To remove
it from a clone, delete `.git/hooks/post-checkout` there if it contains the line `# code-watch managed hook`.

Install also refuses if `post-checkout` in our template folder exists and was not written by code-watch, or is a symlink.
Uninstall only acts when `init.templateDir` is exactly ours; otherwise it says so and changes nothing. It removes our template folder and the empty `code-watch` folder above it. If you had no
global git config file, git leaves an empty one after install and uninstall. Tested with git 2.48, which removes the
empty `[init]` section on unset.
