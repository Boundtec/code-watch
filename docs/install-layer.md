# Before an install

When a command is an install, code-watch shows what it would run, before it runs. It only reads files on disk:
it never runs a package manager, never fetches a registry and never changes a file. Whatever it cannot read is
reported as `install/unchecked` (warn), never as clean. Every file read is size-capped (1 MiB, lockfiles 16 MiB).

| Command | What is shown | What is read |
|---|---|---|
| `npm install`, `i`, `ci`, `add` | the project's `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare` scripts (warn, one each, with line and text); workspace members too; dependencies that run scripts, grouped (warn) | `package.json`, `package-lock.json` or `npm-shrinkwrap.json` (`hasInstallScript`), `node_modules/.package-lock.json`, `.npmrc`; the manifest of an installed dependency |
| `pnpm install`, `add` | the same own scripts; dependencies with build scripts, only when pnpm will run them | `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json` (`pnpm` key, `packageManager`), installed manifests in `node_modules/.pnpm` |
| `yarn`, `yarn install`, `yarn add` | the same own scripts | `yarn.lock`, `.yarnrc.yml` |
| `pip install`, `python -m pip install`, `pip3.X` | a local directory, a VCS address or a source archive, and `--no-binary` (warn); `--only-binary :all:` (info) | requirements files (`-r`, three levels), `pyproject.toml`, `setup.py` of a local directory |
| `brew install`, `reinstall`, `upgrade`, `tap` | a formula or tap outside `homebrew/*`, or a `.rb` file or URL (warn) | nothing |

A script whose text downloads and runs code, or decodes and runs it, is a **block**; every other script is a warn;
none found is info. The text is judged by the same command rules as `check`.

- **Scripts off.** `--ignore-scripts` (not `=false`), or `ignore-scripts=true` in the project's `.npmrc` (last line
  wins), or `ignoreScripts: true` in `pnpm-workspace.yaml` for pnpm: nothing runs and it says so (`install/no-scripts`).
  Only the project's own settings are read, never `~/.npmrc` or the environment.
- **pnpm 10 and later do not run dependency build scripts unless allowed** (`onlyBuiltDependencies`, `allowBuilds`
  or `dangerouslyAllowAllBuilds` in `pnpm-workspace.yaml` or the `pnpm` key of `package.json`). Allowed ones are listed
  as running; the rest are one info line, "blocked by pnpm unless allowed". The version comes from `packageManager`;
  when it is missing the packages "may run" (warn). The pnpm 10 lockfile does not record which packages build, so a
  package counts when its installed manifest has an install script; with nothing installed it says it cannot tell.
- **Yarn.** Yarn 4 runs no dependency scripts unless `enableScripts` is on; the lockfile does not list them, so it
  says so. Yarn 1 runs them and does not list them either.
- **Where it runs.** `check`, the agent adapters and the `npm`/`pnpm`/`yarn`/`pip`/`brew` shims judge an install against
  the directory they are called from, and find it anywhere the command parser looks (`cd x && npm i`, `sh -c '...'`,
  `$(...)`). A caller with no directory (the library's `check_command`) gets no install findings.
- **Directory.** `--prefix`, `-C`, `--dir`, `--cwd` and a `cd x &&` before the install move where it is judged.
- **Global installs** (`npm i -g x`, `pnpm add -g`, `yarn global add`) give `install/global-package` (warn) per
  package, with the package name, so the user allowlist can trust one: `package = "@scope/*"` (a glob, case-insensitive).
- **Allowlist.** Rule ids are `install/*`. The user file can allow any of them; a repository file never can, as for
  command rules. `install/unchecked` cannot be allowed.

Not covered: `uv pip install`, `bun install`, `npx`, `npm exec` and `brew bundle` (not recognised, no finding). A bare
`pip install name` gets no finding: pip may still build it from source when the index has no wheel, which would need a
network lookup. Dependency lockfiles of yarn and npm v1 do not record install scripts, so those are said to be unknown.
Docs checked 2026-11-13: npm (using-npm/scripts), pnpm (settings/build), Yarn (yarnrc `enableScripts`), pip (`pip install`).
