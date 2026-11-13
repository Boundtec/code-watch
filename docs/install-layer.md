# Before an install

When a command is an install, code-watch shows what it would run, before it runs. It only reads files on disk:
it never runs a package manager, never fetches a registry and never changes a file. Whatever it cannot read is
reported as `install/unchecked` (warn), never as clean. The rule throughout: when the layer cannot know what runs, it says
"may run" or "not checked" with a warn, never "nothing runs". Every file read is size-capped (1 MiB, lockfiles 16 MiB).

| Command | What is shown | What is read |
|---|---|---|
| `npm install`, `i`, `ci`, `add` and their aliases (`ic`, `install-clean`, `it`, `cit`, `install-ci-test`), also behind `corepack` | the project's `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare` scripts (warn, one each, with line and text); workspace members too; dependencies that run scripts, grouped (warn) | `package.json`, `package-lock.json` or `npm-shrinkwrap.json` (`hasInstallScript`), `node_modules/.package-lock.json`, `.npmrc`; the manifest of an installed dependency |
| `pnpm install`, `i`, `add`, `it`, `install-test` | the same own scripts; dependencies with build scripts, only when pnpm will run them | `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json` (`pnpm` key, `packageManager`), installed manifests in `node_modules/.pnpm` |
| `yarn`, `yarn install`, `yarn add` | the same own scripts | `yarn.lock`, `.yarnrc.yml` |
| `pip install`, `python [flags] -m pip install`, `pip3.X` | a local directory (also without `./`), a VCS address, any non-wheel URL, a PEP 508 `name @ url`, a source archive, `--no-binary`, and named packages that "may build from source" (warn); `--only-binary :all:` with no such target (info) | requirements files (`-r`, three levels), `pyproject.toml`, `setup.py` of a local directory |
| `brew install`, `reinstall`, `upgrade`, `tap` | a formula or tap outside `homebrew/*`, or a `.rb` file or URL (warn) | nothing |

A script whose text downloads and runs code, or decodes and runs it, is a **block**; every other script is a warn.
The text is judged by the same command rules as `check`.

- **None found is info, and rare.** `install/no-script-found` appears only when the lockfile was read and lists every
  dependency in `package.json` (and the workspace members), the project has no install script and nothing is named on
  the command line. A named package (`npm i x`, `yarn add x`, `pnpm add x`), a missing or stale lockfile, a lockfile that
  does not record scripts (npm v1, yarn 1), a pnpm project with packages not installed, or an unreadable file each give a
  warn that dependencies "may run" install scripts (`install/dependency-scripts` or `install/dependency-scripts-unknown`).
- **Scripts off.** `--ignore-scripts` (`--ignore-scripts false`, `=false` and `--no-ignore-scripts` are not off, and
  beat a project setting; a flag after `--` is a package argument), `ignore-scripts=true` in the project's `.npmrc`
  (last line wins) or `ignoreScripts: true` in `pnpm-workspace.yaml` for pnpm give
  `install/no-scripts`: lifecycle scripts are off. It does not say nothing runs. Only the project's own settings are read,
  never `~/.npmrc` or the environment, and an environment setting such as `npm_config_ignore_scripts=false` overrides the
  project. Yarn 2 and later have no `--ignore-scripts` and do not read `.npmrc`; their config is `.yarnrc.yml`.
- **Repository code that runs anyway.** A `.pnpmfile.cjs` (or `pnpmfile` setting), and for yarn a `yarnPath` or `plugins`
  in `.yarnrc.yml` (or `yarn-path` in `.yarnrc`), run on every install whatever `ignore-scripts` says:
  `install/repo-code-at-install` (warn).
- **Dependencies from git or a URL.** A `package.json` spec such as `github:`, `git+`, `http(s):`, `file:`, `link:` or
  `owner/repo`, and a lockfile entry that is not a registry tarball, may run `prepare` as well as install scripts, which
  lockfiles do not flag: one warn per dependency, with credentials in the address removed.
- **pnpm 10 and later do not run dependency build scripts unless allowed** (`onlyBuiltDependencies`,
  `onlyBuiltDependenciesFile`, `allowBuilds` or `dangerouslyAllowAllBuilds` in `pnpm-workspace.yaml` or the `pnpm` key of
  `package.json`). Allowed ones are listed as running; the rest are one info line, "blocked by pnpm unless allowed". An
  `onlyBuiltDependenciesFile` is read when it resolves to a file inside the project (symlinks followed); otherwise the
  packages "may run". The version comes from `packageManager`; when it is missing the packages "may run" (warn). When
  it is 10 or later and nothing is allowed, the result is one info line: no dependency build runs. The lockfile
  (version 9, written by pnpm 9 and 10) has no `requiresBuild` or other marker of packages that build (pnpm's lockfile
  specification lists none), so a package counts when its installed manifest has an install script or a `binding.gyp`.
- **Yarn.** Yarn 2 and later run dependency build scripts unless `enableScripts` is false (it defaults to true), and the
  lockfile does not list them: a project without the setting gets a warn that they may run. `enableScripts: false` or
  `--mode=skip-build` gives an info. Yarn 1 runs them and does not list them either (warn).
- **Where it runs.** `check`, the agent adapters and the PATH shims judge an install against the directory they are
  called from, and find it anywhere the command parser looks (`cd x && npm i`, `sh -c '...'`, `$(...)`). A caller with no
  directory (the library's `check_command`) gets no install findings. The shims cover exactly `git`, `npm`, `pnpm`,
  `yarn`, `pip`, `brew` and `curl`: not `pip3`, `python -m pip`, `npx` or `pnpx`, which are judged only through `check` and
  the adapters.
- **Directory.** `--prefix`, `-C`, `--dir`, `--cwd` and a `cd x &&` before the install move where it is judged. The
  lockfile and settings are read from the project directory, or from the nearest ancestor that has one and lists the
  project in its `workspaces` (or `pnpm-workspace.yaml` `packages`), up to the repository root; the lockfile of an
  unrelated parent project is not used.
- **Global installs** (`npm i -g x`, `pnpm add -g`, `yarn global add`) give `install/global-package` (warn) per
  package, with the package name, so the user allowlist can trust one: `package = "@scope/*"` (a glob, case-insensitive).
- **Allowlist.** Rule ids are `install/*`. The user file can allow any of them; a repository file never can, as for
  command rules. `install/unchecked` cannot be allowed.
- **Not checked.** These run code at install time and are reported as `install/unchecked` ("not checked: ..."), not
  analysed: `npm update|rebuild|link|dedupe|exec`, `npx`, `pnpx`, `pnpm update|rebuild|dlx|approve-builds|recursive`,
  `yarn up|dlx|workspace|workspaces`, `uv pip install`, `uv sync`, `uvx`, `bun install`, `bunx`, `pipx`, `poetry install`
  and `brew bundle`.

## What it says for everyday commands

| Command (clean project) | Verdict |
|---|---|
| `pip install requests`, `-U pip`, `--user black pytest`, `-r requirements.txt` (index names only), `--require-hashes -r ...` | info: "may build from source if no wheel fits; not checked offline" |
| `pip install --extra-index-url ... requests`, `-i`, `--index-url`, `-f`, `--find-links`, `--trusted-host` (on the command or in a requirements file) | warn: the packages may come from a source other than PyPI |
| `pip install ./dir`, a VCS address, a URL or an archive | warn |
| `pip install --only-binary :all: requests` | info (wheels only) |
| `pip list`, `pip freeze`, `brew install jq`, `brew install node git` | nothing |
| `npm ci`, `npm i` with a lockfile that lists every dependency and no install script | info: none found |
| `npm i lodash`, `npm install -D typescript`, `npm i` with no lockfile | warn: scripts certainly run |
| `pnpm install`, pnpm 10 or later in `packageManager`, nothing allowed to build | info: builds are blocked |
| the same with `--dangerously-allow-all-builds`, `--config.dangerously-allow-all-builds`, `--allow-build`, `--config.only-built-dependencies`, or such a key in `.npmrc` | warn: the builds run |
| `pnpm install`, pnpm version unknown | warn |
| `yarn install`, yarn 1 or yarn 2+ without `enableScripts: false` | warn |

Not covered: a registry in `.npmrc` or `--registry` for npm, pnpm and yarn is not reported; this layer shows what runs,
not where those packages come from. A pip index or link source (`--index-url`, `--extra-index-url`, `--find-links`) is
reported as a warn, because a named package from it can be a source distribution that builds. `pip download` and `pip wheel` are not
recognised. Lockfile versions are not compared with the ranges in `package.json`, only names. A named pip package is
reported as "may build from source" because whether pip builds it depends on the index, which is never fetched.
Docs checked 2026-11-13: npm (using-npm/scripts), pnpm (settings/build), Yarn (yarnrc `enableScripts`), pip (`pip install`).
