# Adding an adapter

An adapter translates one agent's pre-command hook into a `code-watch check` and the verdict back. It holds no rules.
The code is in `crates/code-watch/src/adapter/`; `gemini.rs` and `cursor.rs` are the shortest examples.

## The trait

```rust
pub trait Adapter {
    fn parse(&self, stdin: &[u8]) -> anyhow::Result<Call>;
    fn reply(&self, decision: Decision, policy: &Policy) -> Reply;
}
```

- `parse` reads the agent's JSON. Return `Call::Skip` for a tool call that is not a shell command, `Call::Shell`
  with the command and `cwd` otherwise, and an error for input that is empty, not JSON or has no command.
- `reply` turns a `Decision` (`Allow`, `Ask`, `Deny`) into the agent's answer: the JSON for stdout (none = the
  agent's "no opinion") and an optional note for stderr. Where the agent cannot ask, answer `Ask` with a deny that
  includes the `allow_hint`, or, behind a flag, with the empty reply.

Everything else is shared: the input cap, the fail mode (errors and panics become a deny or, with `--fail-open`, an
allow), the allowlists of the hook's `cwd`, and exit code 0 so the agent reads the JSON. Stdout carries only the reply.

## Checklist

1. Re-read the agent's hook docs and write down the date and any difference in `DESIGN.md` section 3.
2. Add a variant to `Agent` and to `adapter_for`, a module with the trait implementation, and, if the agent needs a
   flag for how to answer a warning, a field in `Policy`.
3. Add the settings snippet in `install.rs` (and its test: the command is one shell-quoted string, no `args` key).
4. Add fixtures under `crates/code-watch/tests/fixtures/<agent>/`: `allow`, `warn`, `block` and `other_tool`, copied
   from the agent's documented input, with inert commands only.
5. Add binary tests in `tests/adapter.rs` for each verdict, the non-shell call, bad input in both fail modes, and
   any flag. The shared `AGENTS` list already runs the bad-input test for every agent.
6. Document the hook, the file it goes in and the reply per verdict in `docs/adapters.md` and the README.
7. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --locked`.

An agent without a command hook (a plugin system, like OpenCode) gets a small generated file instead of a snippet:
keep it a template with one placeholder, run `code-watch` with an argument array, and test it by structure.
An agent with no hook at all is covered by the PATH shims (`code-watch shims install`).
