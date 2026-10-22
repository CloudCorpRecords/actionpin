# Changelog

## 0.1.3 (2026-10-21)

Fix release from the overnight flywheel Wave A evasion hunt. No new features. 93 tests (72 prior plus 21 new in test/wavea.test.ts), every new test failed against the published 0.1.2 binary first. Hunt report: ~/workspace/security-wave/overnight/waves/waveA-actionpin/HUNT.md.

- Docker refs were classified PINNED on the shape of the string, not on validity: a truncated sha256 digest (sha256:abcd1234), a 64-character non-hex digest, and a mutable tag spelled as 40 hex characters (docker://myimage:<40 hex>) all counted as pinned, so a repo whose only container line carried an invalid digest verdicted PINNED with exit 0. A container image now counts as PINNED only with a full sha256 (64 hex) or sha512 (128 hex) content digest; every other docker ref is MUTABLE.
- YAML anchors and aliases (supported by GitHub Actions since September 2025) were mishandled three ways. A value anchor (uses: &name owner/repo@ref) was reported as a fabricated action named after the anchor token, and an alias (uses: *name) as a fabricated action named after the alias, so an anchored pinned action and its alias reported MUTABLE third-party instead of PINNED official. Anchors and aliases now resolve within the file: alias lines inherit the anchored classification and are flagged viaAlias in the report.
- A step anchor between the dash and the uses key (- &step uses: owner/repo@ref) made the line invisible: a workflow whose only step was written that way reported total 0 and PINNED. Step anchors in that position, anchors alone on the dash line, and step aliases (- *name) are now inventoried.
- Fix mode never rewrites an alias line: the plan marks it failed with an explanation that it is pinned when its anchor definition line is pinned, and pinning the definition line alone brings an anchored workflow to PINNED.
- Quoted uses values containing a space (a trailing space before the closing quote, or a comment inside the quotes) were cut at the space, leaving the action name with a stray leading quote and mislabeling official actions as third-party, which flipped PARTIAL verdicts to EXPOSED. The quoted scalar is now read to its closing quote.
- Version tags with an uppercase V (V4, V1.2.3) were classified BRANCH instead of MUTABLE because the version pattern only accepted a lowercase v. The pattern is now case-insensitive.

## 0.1.2 (2026-10-21)

Fix release from Round 1 real-repo validation. No new features.

- P-001 (REAL): piped output no longer truncates. The CLI called process.exit() immediately after printing, which cut stdout at exactly 65,536 bytes whenever a report was read through a pipe and still exited 0, handing agents and CI a corrupt JSON prefix with a success code. Six of the ten Round 1 corpus repos produced reports over that limit (the largest was about 696 KB). Every report now goes through an emit path that resolves only after stdout has flushed, and the exit code is applied with process.exitCode so the process ends naturally after delivery. If the reader closes the pipe early, the process exits 141 (128 + SIGPIPE) rather than reporting success for undelivered output. Regression tests pipe reports over 200 KiB through a real child process and parse them.
- P-014 (COSMETIC): an audit that finds no workflows now says so plainly. The report and plan carry a note stating that nothing was audited and the verdict covers an empty estate, instead of a bare PINNED with total 0 that read as an all-clear (the kubernetes/kubernetes case in Round 1).

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
