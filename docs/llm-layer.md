# The LLM layer (optional)

`code-watch scan <dir>` can ask a language model to read the files most likely to matter (manifests, install and CI
scripts, and any file the rules already flagged) and report concerns the rules do not cover. It is off until you
configure it, and it can only **add** findings.

## Privacy

**For a remote provider, the text of those files leaves your machine.** Nothing is sent unless you configure a
provider. The request carries at most 12 files, 16 KiB each and 96 KiB in total; binary and non-UTF-8 files, symlinks
and `node_modules` are never sent. With `provider = "local"` the traffic stays on your machine.

## Configure

`~/.config/code-watch/config.toml` (`$XDG_CONFIG_HOME` is honoured):

```toml
[llm]
provider = "openai_compat"          # or "anthropic", or "local"
model = "gpt-5-mini"
api_key_env = "OPENAI_API_KEY"      # the NAME of an environment variable; the key is never stored in the file
# base_url = "https://openrouter.ai/api/v1"   # optional for openai_compat and anthropic
# timeout_secs = 20                 # whole call, 1 to 120, default 20
# clone_hook = false                # see below
```

| Provider | API shape | Default `base_url` | Key |
|---|---|---|---|
| `openai_compat` | chat completions (OpenAI, OpenRouter, ...) | `https://api.openai.com/v1` | required |
| `anthropic` | Messages API | `https://api.anthropic.com` | required |
| `local` | chat completions (Ollama, LM Studio, vLLM) | `base_url` is required, e.g. `http://localhost:11434/v1` | optional |

A remote provider must use `https`. `local` accepts only a loopback address (`localhost`, `127.0.0.1`, `::1`), because
it is the one provider allowed to use plain `http` and to run without a key, and that is only safe when the traffic
never leaves the machine.

## When it runs

Only on `scan`. Never on `check`, the agent hooks or the PATH shims, which must answer without waiting on the network.
The clone hook (`install-hook`, which runs `scan --user-allow-only`) does **not** run it by default: every checkout would
wait on the network and could send a private repository to a remote provider you did not pick for that. Set
`clone_hook = true` to opt in. `scan --no-llm` turns it off for one run. `scan --offline` means no network at all, so it covers both network layers
(OSV and LLM) and the LLM layer reports `skipped (offline)`. `--user-allow-only` is what the clone hook passes, and it
keeps the LLM layer off unless `clone_hook = true`.

No config means every report says `llm off`. If it is configured but cannot run (no key, unreadable config, provider
error, timeout, refusal, an answer that does not parse) the report says `llm skipped (reason)`, `--json` shows
`"llm": "skipped"` with the reason under `skipped_layers`, and the findings, verdict and exit code are exactly what they
would have been without it. One call, no retry.

## Only adds findings

- The reply is parsed into a list of findings and nothing else. A reply with any other field (`verdict`, `allow`,
  `clear`, ...) is thrown away whole.
- Every model finding is stamped as layer `llm`, its rule id is `llm/<name>`, and its severity is at most `warn`: a wrong
  answer never blocks on its own. A finding that names a file that was not sent is dropped; a line or excerpt that is
  not in the file is cleared.
- The report only grows. The rules and OSV findings cannot be removed, lowered or replaced, and the verdict is the
  highest severity of all findings, so adding one never lowers it. Allowlists do not apply to model findings.
- Files go to the model in delimited blocks marked as untrusted data. Text inside a file that looks like an instruction,
  a closing delimiter or a fake reply stays data. The reply is never run, never put into a command and never used to
  choose files, and the layer has no way to change a file.
- Text from the model is stripped of control and escape characters before it reaches the terminal or `--json`.
- The key is read from the environment at call time and sent only in the request header. It is not logged and never
  appears in an error message or in the output.
