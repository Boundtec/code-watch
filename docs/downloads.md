# Downloads

`code-watch download <path>` checks a downloaded file before you open it. It only reads: it never changes the file,
removes the quarantine mark or mounts a disk image. macOS only; on Linux the layer is reported as skipped
(`download skipped (macOS only)`, exit 0), never as passed.

## What it checks

| Kind | Signature | Gatekeeper (`spctl`) |
|---|---|---|
| `.app` bundle | `codesign --verify --deep --strict` | `--type execute` |
| executable (Mach-O) | `codesign --verify --deep --strict` | `--type open --context context:primary-signature` |
| `.dmg` | `codesign --verify --deep --strict` | `--type open --context context:primary-signature` |
| `.pkg` | `pkgutil --check-signature` | `--type install` |

The quarantine mark is read with `xattr -p com.apple.quarantine`. The tools are called by absolute path
(`/usr/bin`, `/usr/sbin`), without a shell, with the file's resolved path as one argument, a few seconds each and with
their output capped. Any other file type gets one info note and is allowed.

## Findings

| Rule | Severity | Meaning |
|---|---|---|
| `download/unsigned` | block | no code signature |
| `download/bad-signature` | block | the signature does not verify |
| `download/not-accepted` | block | signed, but Gatekeeper would not open it (not notarized, revoked) |
| `download/unsigned-image` | warn | an unsigned `.dmg`; the app inside is not checked, so open it and run `code-watch download` on the `.app` |
| `download/unchecked` | warn | a tool was missing, too slow or gave no usable answer; the verdict says nothing about that check |
| `download/no-quarantine` | info | no quarantine mark, so macOS would not check the file on open |
| `download/not-checked-kind` | info | not a kind this layer checks |

Exit codes are those of `check`: 0 allow, 1 warn, 2 block, 3 error (for example a path that does not exist).

## Allowing a finding

The user allowlist can allow a rule for a path, as for the other layers
([allowlist.md](allowlist.md)). The path is the file's resolved absolute path:

```toml
[[allow]]
rule = "download/not-accepted"
path = "/Users/me/Downloads/internal-tool.app"
```
