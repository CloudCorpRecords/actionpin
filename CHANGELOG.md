# Changelog

## 0.1.1 (2026-10-21)

Hardening release. An adversarial battery of 31 cases (64 tests total, all passing) found and fixed five real bugs. No new features.

- Fix mode corrupted quoted uses values: the version comment landed inside the quotes (`uses: "actions/checkout@<sha> # v4"`). The comment now goes after the closing quote for both single and double quoted values, and the rewritten line round-trips through the parser.
- Fix mode silently stripped CRLF line endings from rewritten lines in Windows-style workflow files, leaving mixed endings. The original line ending is now preserved per line.
- Refs containing slashes (`release/v1`, `feature/new-thing`) could never be resolved: the ref was percent-encoded into the GitHub git-ref API path. Each ref segment is now encoded separately so slashes survive.
- Dynamic uses values (`${{ matrix.action }}`, `actions/checkout@${{ inputs.ref }}`) were reported as fabricated actions with nonsense refs. They are now skipped entirely and documented in the README limits, because they cannot be classified statically.
- `uses :` with a space before the colon (valid YAML) was not parsed at all. It now is.
- README gained a Limits section pinning the audited scope: workflow files only during directory audits (composite action.yml parses when passed directly), short SHAs never count as pinned, flow-style YAML is not detected, docker refs are reported but never rewritten.

## 0.1.0 (2026-10-21)

First release. Part of the security wave, the detection and hardening counterpart to Greenlight.

- `actionpin audit [path]`: scans .github/workflows for every uses: reference, classifies each as PINNED, MUTABLE, BRANCH, or LOCAL, labels official, third-party, docker, and local owners, and returns a PINNED, EXPOSED, or PARTIAL verdict with file and line evidence.
- `actionpin fix [path] [--dry-run]`: resolves mutable and branch refs to commit SHAs through the GitHub API and rewrites the uses: line in place to owner/repo@SHA with the original ref kept as a comment, preserving formatting line-wise. Local refs are never rewritten, and a failed resolution leaves the line unchanged.
- MCP server with `audit_workflows` and `pin_plan` tools. pin_plan returns the full fix plan without writing any files.
