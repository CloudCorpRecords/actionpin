# Changelog

## 0.1.0 (2026-10-21)

First release. Part of the security wave, the detection and hardening counterpart to Greenlight.

- `actionpin audit [path]`: scans .github/workflows for every uses: reference, classifies each as PINNED, MUTABLE, BRANCH, or LOCAL, labels official, third-party, docker, and local owners, and returns a PINNED, EXPOSED, or PARTIAL verdict with file and line evidence.
- `actionpin fix [path] [--dry-run]`: resolves mutable and branch refs to commit SHAs through the GitHub API and rewrites the uses: line in place to owner/repo@SHA with the original ref kept as a comment, preserving formatting line-wise. Local refs are never rewritten, and a failed resolution leaves the line unchanged.
- MCP server with `audit_workflows` and `pin_plan` tools. pin_plan returns the full fix plan without writing any files.
