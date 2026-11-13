# Releasing

A release is a version tag. The `release` workflow does the rest.

1. Set `version` in the workspace `Cargo.toml`, merge it to `main`.
2. Push the tag `v<version>` (for example `v0.1.0`). The workflow refuses if the tag and the crate version differ, or
   if the tagged commit is not on `main`. Tags are also protected by a tag ruleset (a repository setting the owner adds).
3. The workflow builds `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl`, checks the Linux binaries are static, packs
   `code-watch-<version>-<target>.tar.gz`, writes one `SHA256SUMS`, attests the archives' build provenance and creates
   the GitHub release with all of them. Only that last job has write access.
4. A tag pushed twice fails the second run: the existing release and its assets stay as they are. To redo a release,
   delete it and the tag by hand first.

Check a download: `sha256sum -c SHA256SUMS --ignore-missing` (Linux) or `shasum -a 256 -c SHA256SUMS --ignore-missing`
(macOS), and `gh attestation verify <archive> -R Boundtec/code-watch`.

Pull requests that touch the release files build the four targets without publishing.
