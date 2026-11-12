# code-watch: design and build plan

code-watch is an open-source (Apache-2.0) local guard. It checks a developer's machine before risky code runs: a repo
on clone, dependencies with known CVEs or malicious packages, installs, shell commands, downloads. Rust, one static
binary for macOS and Linux. Crate and hook data below was checked on 2026-11-12.

## 1. Architecture

One core, thin entry points. Everything that decides lives in the core; adapters and shims only translate.

```
 git hook ─┐
 scan <dir>─┤
 agent     ─┼─> code-watch check|scan ─> Engine ─> Report (findings + verdict) ─> human | --json | exit code
 adapters  ─┤                              │
 PATH shims─┘                  rules layer (always) ──┐
                               osv layer (live+cache) ─┼─> findings only ever added
                               llm layer (optional) ───┘
```

### Core types

| Type | What it is |
|---|---|
| `Finding` | `rule_id`, `severity` (info / warn / block), `layer` (rules / osv / llm), `title`, `evidence` (file, line, excerpt, truncated), `remediation` |
| `Target` | What is checked: `Repo(path)`, `Command(argv + cwd)`, `Install(manager, args, cwd)`, `Download(path)` |
| `Verdict` | `Allow` / `Warn` / `Block`, derived from the findings, never stored on its own |
| `Report` | Findings plus the derived verdict plus which layers ran (so "LLM layer off" is always said) |
| `Layer` | Trait `fn analyze(&self, &Target, &Ctx) -> Vec<Finding>`; the five product layers are modules that provide rules or sources for it |

### The five product layers as modules

| Layer | Module | Target | Notes |
|---|---|---|---|
| 1 Repo on clone | `repo` | `Repo` | lifecycle scripts, `.vscode/tasks.json` folderOpen, obfuscation, committed binaries, secret-reading code |
| 2 Known vulnerabilities | `osv` | `Repo` | lockfile parsers to package list, OSV batch query, offline cache |
| 3 Before install | `install` | `Install` | resolves what will run (lifecycle scripts, unknown tap) before it runs |
| 4 Before a command | `command` | `Command` | `curl \| sh` lookalike domains, base64 into a shell, quarantine removal, `osascript` password prompt, LaunchAgents writes |
| 5 Downloads | `download` | `Download` | quarantine, signature, notarization (macOS only) |

macOS-only checks are compiled everywhere and registered only when `cfg!(target_os = "macos")`; on Linux they are absent
and `--json` lists them under `skipped_layers`.

### Rules format

Versioned TOML files in `rules/` of the repo, embedded with `include_dir`-style build-time embedding (a small
`build.rs` or `include_str!` list). One file per layer. Each rule: `id`, `severity`, `title`, `remediation` and a `match` table whose `kind` is `json_pointer`, `file_regex` or `command_regex` (the target, repo or command, follows from the kind; there is no per-rule `since`, only the file-level schema). The file
carries `schema = 1`; the binary refuses newer schemas and says so. No hosted feed: rules update with each release.
Each rule needs a positive and a negative fixture; a test fails if a rule has none.

### Allowlists and precedence

The user file decides. The per-repo file is a convenience for teams and can never override it.

| File | Location | What it can do |
|---|---|---|
| User (decides) | `~/.config/code-watch/allow.toml` (`$XDG_CONFIG_HOME` honoured) | allow any rule, including `block`-severity ones |
| Per-repo (advisory) | `.code-watch.toml` at the repo root (a team can commit it) | allow only non-`block` rules; a `block` rule is allowed only if the user file also lists that rule id |

Entries allow by `rule_id` plus an optional path glob / domain / package. Allow only suppresses findings of the rules
layer and the OSV layer, by id; it never turns off a layer. Why the per-repo file is limited: a cloned repo is untrusted
input and must not be able to whitelist itself.

### The LLM layer behind one trait

```rust
trait LlmProvider { fn complete(&self, req: &LlmRequest) -> Result<LlmReply>; }
```

One HTTP client per API shape, not per vendor: `openai_compat` (OpenAI, OpenRouter, Ollama, LM Studio, vLLM),
`anthropic`, plus `local` (the OpenAI-compatible shape pointed at localhost). Config in `~/.config/code-watch/config.toml`
holds `provider`, `base_url`, `model`, `api_key_env` (the name of an environment variable; the key is never stored in
the file). No key configured: the layer is off and every report says `llm: off`.

**"The LLM only adds findings" is enforced by types, not by convention:**

| Mechanism | Effect |
|---|---|
| The LLM layer returns `LlmFindings(Vec<Finding>)`, a newtype whose only constructor stamps `layer = Llm` | it cannot forge a rules finding |
| `Report::new(rules: RulesFindings)` then `report.with_llm(LlmFindings)`; the only mutation is `extend`. `Report` fields are private and there is no remove, clear or replace | nothing can drop a rules finding |
| The verdict is a pure function of all findings, monotonic (more findings never lower it) | adding cannot downgrade |
| The model's reply is parsed into a schema with only `findings[]`; there is no verdict / allow / clear field, unknown fields are rejected | a prompt-injected "this repo is safe" has nowhere to land |
| Repo content goes in a delimited data block, with a fixed system prompt that says the block is untrusted data; the reply is never executed, interpolated or used to pick files | prompt injection can at worst add a finding |
| A property test with a fake provider returning "everything is fine" / garbage: the rules findings and verdict are unchanged | proves it |

### Entry points are thin

`code-watch check <command...>` is the one hot path: it parses the command, builds the right `Target`, runs the engine
and exits. Adapters and shims contain no rules.

| Entry | What it is |
|---|---|
| git hook | `code-watch install-hook` sets a global `init.templateDir` with `post-checkout` that runs `code-watch scan .` |
| agent adapters | each one is a tiny `code-watch adapter <agent>` subcommand that reads that agent's hook JSON on stdin, calls `check`, and prints that agent's response format |
| PATH shims | generated scripts in `~/.local/share/code-watch/shims/` for `git`, `npm`, `pnpm`, `yarn`, `pip`, `brew`, `curl`; each runs `code-watch check <name> "$@"` then execs the real binary found past the shim dir |

Adding an agent = one new adapter module implementing `trait Adapter { fn parse(stdin) -> Command; fn render(Report) -> Output; }`.

### Exit codes and output

| Exit | Meaning |
|---|---|
| 0 | clean (info only) |
| 1 | warn |
| 2 | block |
| 3 | internal or usage error (clap's usage error is mapped to 3 so 2 always means block); `--fail-open` / `--fail-closed` decides what adapters do with it |

Human output: one line per finding (`BLOCK repo/npm-lifecycle-script package.json:12 ...`), a footer with layers that
ran and layers that are off. `--json`: `{ "verdict", "layers": {rules, osv, llm: "ran"|"off"|"skipped"}, "findings": [...] }`
with a `schema` number; the finding shape above is the public contract.

## 2. Crate survey

Licenses are all Apache-2.0-compatible. Downloads are all-time / last 90 days. Last release is the crates.io `updated_at`.

| Layer / need | Crate | Version | Last release | Downloads | License | Why |
|---|---|---|---|---|---|---|
| CLI | `clap` (derive) | 4.6.7 | 2026-09-14 | 1.33 B / 287 M | MIT OR Apache-2.0 | the standard |
| Config, rules, allowlists | `toml` + `serde` | 1.2.1 / 1.0.229 | 2026-11-06 | 1.13 B / 314 M | MIT OR Apache-2.0 | one format everywhere |
| JSON out, agent hook I/O, `package-lock.json` | `serde_json` | 1.0.154 | current | huge | MIT OR Apache-2.0 | npm lockfile and `package.json` are plain JSON structs |
| Errors | `thiserror` (lib), `anyhow` (main) | 2.0.21 / 1.0.104 | current | huge | MIT OR Apache-2.0 | standard |
| Git hook install | none (write the hook file and run `git config --global init.templateDir` via `std::process::Command`) | n/a | n/a | n/a | n/a | it is a file plus one config key; `gix` (0.90.0, 2026-10-22, 56 M) and `git2` (0.21.0, 2026-10-06, 127 M, links libgit2) are heavy for that |
| OSV client | none; thin client on `POST /v1/querybatch` with `serde` types | n/a | n/a | n/a | n/a | the `osv` crate is 0.3.0 (Apache-2.0, last 2026-04-02, 73 k downloads): too small and stale to depend on for a core path |
| OSV offline cache | JSON files per (ecosystem, name, version) under `~/.cache/code-watch/osv/` with a TTL | n/a | n/a | n/a | n/a | no DB engine; `rusqlite` (0.42.0, 2026-11-11, MIT) would bundle C SQLite for a key-value need; `redb` (4.5.0, 2026-11-05) is the fallback if the files get slow |
| Package URLs (OSV ecosystems) | `purl` | 0.1.6 | 2025-03-13 | 4.4 M | MIT | optional; skip unless mapping gets messy |
| npm / pnpm / yarn | `serde_json` (npm); `serde_norway` (pnpm, yarn berry YAML; 0.9.42, 2024-12-21, 20 M, MIT OR Apache-2.0); `yarn-lock-parser` (yarn v1; 0.14.0, 2026-02-08, 341 k, MIT) | | | | | `serde_yaml` is archived (`0.9.34+deprecated`), so `serde_norway` is the maintained fork; `serde_yml` (0.0.13, 2026-05-27) is avoided, run `cargo audit` on it before ever choosing it |
| pip / poetry / uv | `toml` for `poetry.lock` / `uv.lock`; `pep508_rs` (0.9.2, 2025-01-02, 16.8 M, Apache-2.0 OR BSD-2-Clause) for `requirements.txt` lines | | | | | `pep508_rs` is stale but a complete PEP 508 parser; fallback is a small line regex (`name==version`), which is all OSV needs. `uv-lock` (0.0.100) is an internal uv crate: not used |
| cargo | `cargo-lock` | 11.1.0 | 2026-07-24 | 43 M / 8.3 M | Apache-2.0 OR MIT | RustSec's own parser |
| go | `gomod-parser` (go.mod; 0.6.0, 2026-10-01, 1.26 M, Apache-2.0); `go.sum` is `module version hash` lines | | | | | small, recent |
| Shell command parsing | `shlex` | 2.0.1 | 2026-05-17 | 1.08 B / 355 M | MIT OR Apache-2.0 | tokenise `check <command>` without a hand-rolled parser; pipelines are split on `\|` `;` `&&` after tokenising. `brush-parser` (0.4.0, MIT, 926 k) and `tree-sitter-bash` (0.25.1, 2025-12-02, MIT) are real bash parsers: held back for later if `shlex` misses cases |
| Lookalike domains | `idna` (1.1.0, 2025-08-21, 1.15 B) for punycode/IDNA; `psl` (2.1.252, 2026-11-12, 39 M) for the registrable domain; `unicode-security` (0.1.3, 2026-11-02, 18.7 M) for confusable skeletons; `strsim` (0.11.1, 1.27 B) for edit distance against an embedded list of known domains (`brew.sh`, `github.com`, ...) | | | | | all MIT / Apache-2.0, all well used |
| File walking, globs | `ignore` + `globset` | 0.4.34 / 0.4.21 | 2026-10-27 | 212 M / 291 M | Unlicense OR MIT | ripgrep's own; respects `.gitignore` but we also scan ignored files where it matters (opt-out per rule) |
| Regex | `regex` | 1.13.1 | 2026-07-15 | 1.38 B | MIT OR Apache-2.0 | linear-time, safe against ReDoS on hostile input |
| Base64 detection | `base64` | 0.23.1 | current | huge | MIT OR Apache-2.0 | decode candidate blobs |
| Hash | `sha2` | 0.11.1 | current | huge | MIT OR Apache-2.0 | allowlist pins, cache keys |
| XDG dirs | `dirs` | 7.0.0 | 2026-09-05 | 407 M | MIT OR Apache-2.0 | |
| macOS signature / notarization | shell out to `codesign --verify --deep --strict`, `spctl --assess --type open --context context:primary-signature` and `xattr` | | | | | present on every Mac (`/usr/bin/codesign`, `/usr/sbin/spctl` confirmed here); `apple-codesign` (0.29.0, 2024-11-29, MPL-2.0) is a signing tool, stale, and MPL is a weaker fit for Apache-2.0; `security-framework` (3.7.0, MIT OR Apache-2.0) has no notarization check |
| HTTP client for OSV + LLM | `ureq` | 3.5.2 | 2026-11-12 | 265 M / 86 M | MIT OR Apache-2.0 | blocking, small, no async runtime in a CLI that exits in milliseconds; `reqwest` (0.13.5, 2026-09-08, 905 M) works but pulls `tokio`. TLS via rustls |
| Tests | `assert_cmd` 2.2.2, `insta` 1.49.0 (Apache-2.0), `tempfile` 3.27.0, `rstest` 0.28.0 | | | | | all current |

No async runtime anywhere. `cargo-deny` runs in CI to keep the license list honest.

## 3. Agent hook APIs (read 2026-11-12)

All five let the adapter block before a shell command runs except where noted. Each adapter is `code-watch adapter <name>`:
read the JSON on stdin, extract the command, run `code-watch check`, translate the verdict back.

| Agent | Hook | Doc | Adapter |
|---|---|---|---|
| Claude Code | `PreToolUse` with matcher `Bash` in `~/.claude/settings.json`; stdin has `tool_name`, `tool_input.command`, `cwd` | [hooks](https://code.claude.com/docs/en/hooks) | read `tool_input.command`; block = exit 2 with the reason on stderr, or JSON `hookSpecificOutput.permissionDecision = "deny"`; warn = `"ask"` |
| Cursor | `beforeShellExecution` in `~/.cursor/hooks.json` (or per project); stdin has `command`, `cwd`, `sandbox` | [hooks](https://cursor.com/docs/hooks) | read `command`; reply JSON `{"permission": "allow"\|"deny"\|"ask", "user_message", "agent_message"}`; set `failClosed: true` |
| Codex CLI | `PreToolUse` hooks in `~/.codex/hooks.json` or `config.toml` `[hooks]`, matcher on `tool_name` (shell is `Bash`); stdin has `tool_name`, `tool_input`, `cwd`, `turn_id` | [hooks](https://learn.chatgpt.com/docs/hooks) (the old `developers.openai.com/codex/hooks` URL redirects here) | same shape as Claude Code: `permissionDecision` deny/ask or exit 2 |
| Gemini CLI | `BeforeTool` in `~/.gemini/settings.json`, matcher `run_shell_command`; stdin has `tool_name`, `tool_input.command`, `cwd` | [hooks](https://geminicli.com/docs/hooks/), [reference](https://geminicli.com/docs/hooks/reference/) | block = exit 2 (stderr is the reason) or stdout JSON `{"decision": "deny", "reason": ...}`; stdout must be only that JSON |
| OpenCode | no command-hook config: a JS/TS plugin in `.opencode/plugins/` or `~/.config/opencode/plugins/` with `tool.execute.before(input, output)`; for `input.tool === "bash"` the command is `output.args.command`; throwing blocks it | [plugins](https://opencode.ai/docs/plugins/) | `code-watch install-adapter opencode` writes a ~15-line plugin that runs `code-watch check` via `Bun.spawn` and throws on exit 2; the plugin is the only non-Rust file we ship |

Where a hook does not exist: none of the five lacks one today, but the OpenCode one is a plugin and not a config
entry. Any other agent or harness (Aider, Zed, a custom script, a plain terminal) falls back to the PATH shims. Shims
also cover commands an agent runs through paths the hook does not see.

Gotcha shared by all: hook exit codes other than the documented block code fail open, so adapters wrap `check` so that
an internal error (exit 3) follows `--fail-open` / `--fail-closed` explicitly instead of by accident.

## 4. Build plan

Each slice is about one worker-day, one reviewable PR, with its tests and its README/docs part. Docs are part of done.

| # | Slice | Contents |
|---|---|---|
| 1 | Skeleton | Cargo workspace (`code-watch-core`, `code-watch` bin), `LICENSE` (Apache-2.0), `NOTICE` ("Created by Sebastián Cuccorese at Boundtec"), copyright "Copyright Sebastián Cuccorese", README outline, `scan <dir>` and `check <command>` returning the Finding model (human + `--json`, exit codes), rules engine with embedded TOML rules and 3 to 5 repo-on-clone rules (npm lifecycle scripts, VS Code `folderOpen` tasks, base64 into a shell, plus one or two), `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, GitHub Actions `ci.yaml` on `pull_request` only |
| 2 | Repo layer, rest | `setup.py`, Makefile targets, committed binaries / obfuscation, secret-reading-and-sending patterns; rules schema docs |
| 3 | Allowlists | user and per-repo files, precedence, the "repo cannot allow itself" rule, `docs/allowlist.md` |
| 4 | Git hook | `install-hook` / `uninstall-hook`, global template dir, `post-checkout` scan on clone |
| 5 | Command layer | `shlex`-based parsing, `curl \| sh`, base64 into shell, quarantine removal, `osascript` password, LaunchAgents writes, lookalike-domain check (`idna`, `psl`, `unicode-security`, `strsim`) |
| 6 | Lockfiles + OSV | parsers per ecosystem behind one `PackageSource` trait, OSV client behind a trait with a fake, offline cache with injected clock |
| 7 | Install layer | `npm/pnpm/yarn install`, `pip install`, `brew install` unknown tap: shows what will run before it runs |
| 8 | Downloads layer | `.dmg` / `.pkg` quarantine, `codesign` / `spctl` shell-out behind a trait with a fake, macOS only |
| 9 | LLM layer | provider trait, openai_compat + anthropic + local, `LlmFindings` newtype, the "only adds" property test, prompt-injection fixtures, `docs/llm-layer.md` |
| 10 | Adapters 1 | `adapter` subcommand, Claude Code, Cursor, Codex CLI, with fixtures of each agent's stdin JSON |
| 11 | Adapters 2 + shims | Gemini CLI, OpenCode plugin, PATH shims generator, `docs/adding-an-adapter.md` |
| 12 | Release | install script and Homebrew tap, `cargo-deny`, release workflow (static binaries macOS arm64/x86_64, Linux musl), SECURITY.md, final README |

Slices 2 to 4 and 5 to 6 are independent once slice 1 lands, so two workers can run in parallel.

Test rules for every slice: every rule has a positive and a negative fixture; fixtures are inert text (no real malware,
secrets or tokens); no sleeps or real time (clock injected); no network in unit tests (OSV, LLM and `codesign` behind
traits with fakes); repo content is never executed or interpolated into a shell.

## 5. Open points for Sebas

| Point | Recommendation |
|---|---|
| Should `check` block by default or only warn for `warn`-severity findings in agent adapters? | Block on `block` only; `warn` becomes the agent's "ask" so a human decides; a `--strict` flag turns warnings into blocks |
| Crate layout: one crate or a workspace (`core` + `bin`) | Workspace: lets someone embed the engine; costs nothing now |
| MSRV | Latest stable minus two; today most deps need 1.85 to 1.90. CI and `rust-toolchain.toml` pin the exact toolchain (1.94.0) |
| Crate name on crates.io | Reserve `code-watch` when the GitHub repo is created |
