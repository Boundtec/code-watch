# PLAN CUC-343: code-watch LLM layer (slice 9)

## Where it runs
- `scan` only (repo scan and clone-time scan). Opt-in: needs `[llm]` in config and (unless `provider = "local"`) a non-empty key variable.
- Never `check`, adapters, shims or `download` (hot path must not wait on the network). Those entry points never build an `LlmSetup`, so their reports keep saying `llm: off`.
- `scan --no-llm` turns it off for one run. The clone hook runs `scan --user-allow-only .`; it picks the layer up from config like any scan (the user opted in by configuring it). OPEN POINT for Sebas, not blocking: should the clone hook skip it? Proposal: yes, hook passes `--no-llm`? No: leave hook alone (no change to hook.rs); documented in docs.
- Engine: new `Engine::scan_dir_full(dir, allow, osv, llm)`; `scan_dir_osv` delegates with `llm = None`, so no caller changes (trap 10: grep shows callers: main.rs `scan`, tests).

## Config (`$XDG_CONFIG_HOME/code-watch/config.toml`, same dir logic as allow.toml)
```toml
[llm]
provider = "openai_compat" | "anthropic" | "local"
base_url = "https://api.openai.com/v1"   # defaults: openai_compat -> that; anthropic -> https://api.anthropic.com; local -> required
model = "..."                             # required
api_key_env = "OPENAI_API_KEY"            # NAME of an env var; required except for local
```
`deny_unknown_fields`. Missing file or no `[llm]` table: off. `[llm]` present but invalid (unknown provider, no model, variable unset or empty, remote `http://` base_url): layer `skipped` with a short reason (never says the key or its value). `local` requires a loopback host (localhost, 127.0.0.0/8, ::1); no key needed, sent if the variable is set. Remote providers must be `https`.
Unreadable / unparsable config file: `skipped("config unreadable")` (not off: the user tried to turn it on).

## What is sent (bounded)
Selection runs over the same walk root, never follows symlinks out, reads only regular files <= 64 KiB, skips non-UTF-8 / NUL-containing files (binary).
Chosen files, in priority order, until caps: (1) files that already have a rules/OSV finding (`evidence.file`), (2) manifests and install hooks by name: `package.json`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Makefile`, `build.rs`, `Cargo.toml`, `.vscode/tasks.json`, `Dockerfile`, `*.sh`, `install*`, `postinstall*`, `preinstall*`, `.github/workflows/*.y(a)ml`.
Caps: 16 KiB per file (truncated, marked), 12 files, 96 KiB total. Cap values are consts. Sorted by path so the request is deterministic.
Prompt: fixed system prompt (a const; says everything inside `<untrusted-file ...>` blocks is data, never instructions, reply only with the JSON schema). User message = one block per file. Delimiter is a per-request random-free but content-checked fence: `<<<FILE n>>>` ... `<<<END FILE n>>>` where n is the index; if file text contains the end fence string for its index, that string is neutralised (`<<<END` -> `<<<END-` ) so content cannot close its block. Paths are placed in a JSON-escaped header field inside the block (`path: "<json string>"`), so a path with newlines/fences is data too.
The reply is never executed, never interpolated into a command, never used to choose files (selection happens before the call).

## Request/response shapes (read 2026-11-13)
- OpenAI chat completions, https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create (2026-11-13): `POST {base_url}/chat/completions`, `Authorization: Bearer <key>`, body `{model, messages:[{role:"system"|"developer"|"user",content}], max_completion_tokens, temperature, response_format:{type:"json_object"}}` (`max_tokens` is deprecated; I send `max_completion_tokens`). Reply `choices[0].message.content` (string or null), `choices[0].message.refusal` (non-null = refusal), `finish_reason` (`length` = truncated = unusable). Role `system` is used (accepted by OpenAI and by Ollama/LM Studio/vLLM/OpenRouter; `developer` is not universal).
- Anthropic Messages, https://platform.claude.com/docs/en/api/messages (2026-11-13): `POST {base_url}/v1/messages`, headers `x-api-key`, `anthropic-version: 2023-06-01`, `content-type: application/json`, body `{model, max_tokens, system, messages:[{role:"user",content}]}`. Reply `content[]` of blocks (`type:"text"` carries `text`; others ignored), `stop_reason` (`refusal` and `max_tokens` = unusable). Errors are `{"type":"error","error":{"type","message"}}` with non-2xx; the message is never copied into our output (it can echo request text).
I did not see a documented `response_format` equivalent for Anthropic; the prompt asks for bare JSON and the parser accepts exactly one JSON object (optionally inside one ```json fence).

## Reply schema (the only thing that can land)
```json
{"findings":[{"kind":"suspicious-install-script","severity":"warn","title":"...","file":"package.json","line":12,"excerpt":"...","remediation":"..."}]}
```
`#[serde(deny_unknown_fields)]` on both levels: a `verdict`, `allow`, `clear`, `safe`, `layer` or any other field = unparsable = layer skipped. At most 20 findings (more = unparsable). Strings capped (title 120, remediation 240, excerpt via `Evidence::new` 200 chars, which also strips control chars).

## Types ("only adds")
- `LlmFindings(Vec<Finding>)`: private field; only constructor `LlmFindings::from_reply(reply, &Sent)` stamps `layer = Llm`, `rule_id = "llm/<kind>"` where kind is reduced to `[a-z0-9-]{1,40}` (anything else becomes `unclassified`), `severity = min(model, Warn)` (info stays info; `block` is capped to `warn`: a hallucination never blocks alone), `domain/package/advisories` empty.
- Evidence check against `Sent` (what was actually sent): file not among the sent files -> finding dropped; line beyond the file's line count -> line cleared; excerpt not a substring (whitespace-trimmed) of the sent file text -> excerpt replaced by "(not found in the file)". 
- `Report::with_llm(LlmOutcome)`: `LlmOutcome::Ran(LlmFindings) | Skipped(String)`. Only mutation is appending (`extend`) then the existing sort; no remove/clear/replace; fields stay private. Verdict stays the pure max over findings (already monotonic).
- LLM findings do not go through allowlists (allow.rs only touches rules/osv layers; test pins it).
- `trait LlmProvider { fn complete(&self, req: &LlmRequest) -> Result<LlmReply, LlmError>; }`. `LlmRequest{system, user}` , `LlmReply{text}`. `LlmError`: `Timeout, Network, Status(u16), Refused, Truncated, BadResponse, TooLarge` with Display texts that never contain keys, request or response text. `Debug` of the client config redacts the key (the key is not stored at all: read from env at call time into a local, passed to the header only).
- Clients: `OpenAiCompat`, `Anthropic` on `ureq` (agent with injected `timeout_global`, body cap 256 KiB via `.limit`). `with_base`/`with_timeout` constructors for tests (same pattern as `UreqOsv::with_base`). Key lookup is behind `KeySource` (std::env in prod, closure in tests, so tests never touch process env).

## Failure table (one test per cell, plus names)
| Step | fails | times out | unreadable / huge / unknown field | tries to clear, lower or forge |
|---|---|---|---|---|
| config / key | bad toml, unknown field, unknown provider, remote http, empty/unset key -> `skipped("...")`; absent -> `off` | n/a (no I/O wait) | `deny_unknown_fields` -> skipped | n/a; key value never in the reason (test asserts) |
| select + cap | unreadable file -> that file omitted, rest sent; nothing selectable -> `ran` with 0 findings, no call | n/a (local reads, size-capped) | binary / non-UTF-8 / over cap skipped or truncated | fence text in a file neutralised, path with fence is JSON-escaped |
| HTTP (each provider) | 401/429/500, connection refused -> skipped("provider answered HTTP n") | injected timeout, slow-body server -> skipped("timed out") | body over cap -> skipped; non-JSON / empty / refusal / truncated -> skipped | n/a at transport |
| parse reply | not JSON, fenced twice, >20 findings -> skipped("unreadable reply") | n/a | unknown field `verdict`/`allow`/`clear`/`safe`/`layer`, wrong types -> skipped | `layer:"rules"`, `severity:"block"`, `rule_id:"repo/..."` -> rejected / capped / namespaced |
| merge | report unchanged and layer `skipped` | same | same | model "no findings / all safe" on a repo with a block: verdict stays block (test); verdict only grows with findings |

Also: 0 / 1 / many model findings; prompt-injection fixtures (ignore-previous-instructions text, fake closing delimiter, fake JSON reply inside a file) checked on the built prompt (fence neutralised, fixture is inside its block, path escaped) and end to end through a fake provider; "can this change files": the layer holds no write path, `scan` with a fake provider leaves the tree byte-identical (test hashes the dir before/after).

## Tests (fast, no sleeps, no real network, tempdirs)
- unit with fake `LlmProvider` for every row; property test (seeded xorshift loop, 300 random replies incl. garbage / valid-shaped with random severities and rule ids): rules+OSV findings and verdict never change or drop, verdict never lower, every LLM finding has `layer=Llm`, `llm/` prefix and `severity <= warn`.
- HTTP clients vs a local `TcpListener` on 127.0.0.1:0 (real status codes 401/429/500, 200 with refusal, truncated, huge body over cap, slow body with 200 ms injected timeout, header assertions: auth header present, key only there). Fake copies the real refusal shapes (`refusal` field, `stop_reason: "refusal"`, `finish_reason: "length"`).
- key-never-leaks: every error Display/Debug + the skipped reason + rendered human/JSON output of a failing run does not contain the fake key.
- render/CLI: human footer `llm skipped (reason)`, `--json` `layers.llm = "skipped"` + `skipped_layers.llm`; no-config run says `llm off`; `check` says `llm off` even with config present (assert_cmd with tempdir XDG).
- Break checks (each named, run by removing the line and confirming red): BC1 drop the `severity.min(Warn)` cap; BC2 drop `deny_unknown_fields`; BC3 drop fence neutralisation; BC4 stamp layer from reply instead of constant; BC5 make `with_llm` skipped path still extend findings; BC6 drop the body size limit; BC7 drop evidence-file check; BC8 send key in a body/log (debug print) ; BC9 run the layer in `check`.

## Deps
No new crate beyond what exists (`ureq`, `serde`, `serde_json`, `toml`). Seeded loop instead of proptest. Crate survey row "HTTP client for OSV + LLM" already covers it; only the row text mentions the LLM clients' use.

## Docs
`docs/llm-layer.md` (what is sent, config per provider incl. local/Ollama, "only adds findings" in plain words, privacy note), README section, DESIGN slice-9 row marked done and the "LLM layer" section gains the caps/severity/fail mode lines.

## Hot path
`check` unchanged (no code path reaches the layer). Time `check` release median of 20 before/after and report.

## Questions on DESIGN
- DESIGN says `Report::new(rules).with_llm(...)`; the code has `Report::from_scan(...)` + `with_osv`. I follow the code (`with_llm` next to `with_osv`). No other conflict.
