# Security policy

code-watch is a security tool, so reports about it are welcome.

## Reporting

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a
vulnerability**. Please do not open a public issue for it.

## In scope

- A finding the tool should give and does not (a risky repo, command, install or download that comes back clean).
- A way to make it allow something it should block, including through the allowlists, adapters, shims or the git hook.
- A leak of API keys or of the user's code from the LLM layer.
- A flaw in the release binaries, the checksums or `install.sh`.

## Supported versions

Only the latest release gets fixes.
