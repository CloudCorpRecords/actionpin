# actionpin

**A version tag is a promise anyone can break. A commit SHA is not.**

GitHub Actions are executable supply chain. When a workflow says `uses: actions/checkout@v4`, that tag can move. When a third-party action tag moves to a compromised commit, every workflow that trusts the tag runs the new code with that workflow's tokens. Pinning to a full 40-character commit SHA is the standard defense, and almost nobody does it consistently, because doing it by hand across every workflow is tedious and easy to get wrong.

actionpin audits every workflow in a repo, reports exactly which actions are pinned and which are not, and can rewrite the unpinned ones to SHAs for you, keeping the original tag as a comment so the pin stays readable.

## Why this exists

GitHub Actions are the second largest confirmed open source supply-chain attack surface of the last year, behind only npm. Maintainer accounts and action tags have been hijacked before, and a mutable tag means the code your CI runs today is not guaranteed to be the code you reviewed. The fix is known and boring: pin to a SHA. actionpin makes the boring fix one command, and makes the audit callable by agents through MCP so it can run inside contribution and release workflows, not just by hand.

## What it checks

For every `uses:` line in `.github/workflows/*.yml` and `*.yaml`:

| classification | meaning |
| --- | --- |
| `PINNED` | Ref is a full 40-character commit SHA (or a sha256 digest for a container image) |
| `MUTABLE` | Ref is a version tag such as `v4` or `v4.2.1`. The tag can move. |
| `BRANCH` | Ref is a branch such as `main`, `master`, or `HEAD`. It moves by design. |
| `LOCAL` | A local path such as `./local/action`. Never rewritten. |

Owner types: `official` for actions owned by `actions` or `github`, `third-party` for everyone else, `docker` for `docker://` container actions, and `local` for local paths.

Verdict rules:

- **PINNED**: every non-local action is pinned to a full SHA. Exit code 0.
- **EXPOSED**: at least one third-party or container action uses a mutable tag or a branch. Exit code 1.
- **PARTIAL**: only official actions are unpinned. Exit code 1.
- **Usage errors** exit with code 2.

Fix mode resolves a tag or branch to its commit SHA through the GitHub API and rewrites the line to `owner/repo@<sha> # <original ref>`, preserving indentation and all other content. Files are edited line-wise; YAML is never parsed and re-emitted, so formatting survives. If a ref cannot be resolved, its line is left unchanged and the failure is reported. Docker image refs are reported but not rewritten; pin those by digest.

## Usage

### CLI

```bash
# Audit the current repo
npx @reneturcios/actionpin audit

# Audit another path, machine readable
npx @reneturcios/actionpin audit ~/src/my-repo --json

# Preview the pinning plan without writing
npx @reneturcios/actionpin fix --dry-run

# Pin everything resolvable, in place
npx @reneturcios/actionpin fix
```

Example output:

```
actionpin audit .: EXPOSED
  workflows: 2, actions: 6, pinned: 1, mutable: 4, branch: 1, local: 0
  [PINNED] .github/workflows/ci.yml:12 actions/checkout@0123456789abcdef0123456789abcdef01234567 (official)
  [MUTABLE] .github/workflows/ci.yml:13 actions/setup-node@v4 (official)
  [MUTABLE] .github/workflows/publish.yml:20 docker/build-push-action@v6 (third-party)
EXPOSED: at least one third-party or container action uses a mutable tag or branch ref.
```

Set `GITHUB_TOKEN` for the higher authenticated GitHub API rate limit during fix mode. Auditing needs no credentials and no network.

### MCP server

Add to your MCP client config:

```json
{
  "mcpServers": {
    "actionpin": {
      "command": "npx",
      "args": ["-y", "@reneturcios/actionpin", "mcp"]
    }
  }
}
```

Tools:

- `audit_workflows`: audit a repo path and return every action with its classification, owner type, file, and line, plus the verdict.
- `pin_plan`: return the full SHA pinning plan for a path without writing any files.

### Docker

```bash
docker run -i ghcr.io/cloudcorprecords/actionpin mcp
docker run --rm -v "$PWD:/work" -w /work ghcr.io/cloudcorprecords/actionpin audit .
```

## Limits (pinned by the hardening battery)

These behaviors are deliberate, tested, and stated plainly so a green report is never misread:

- **Scope is workflow files.** A directory audit scans `.github/workflows/*.yml` and `*.yaml` only. Composite action files (`action.yml`, `action.yaml`) are not scanned during a directory audit; pass an `action.yml` file path directly and it is parsed like any other file. Job-level `uses:` lines (reusable workflow calls) are in scope and are audited and pinned like step-level ones.
- **Dynamic values are skipped, not guessed.** A `uses:` value that contains a GitHub expression (`${{ matrix.action }}`, `actions/checkout@${{ inputs.ref }}`) is decided at run time and cannot be classified statically. actionpin skips it entirely instead of inventing an action or a verdict for it. Audit the matrix or input values themselves if a workflow builds its actions dynamically.
- **Short SHAs never count as pinned.** Only a full 40-character SHA (or a sha256 digest for `docker://` images) is `PINNED`. A short SHA such as `abc1234` is reported in the `BRANCH` bucket and fails the verdict, because a short prefix is not a stable pin.
- **Refs containing slashes** (`release/v1`, `feature/new-thing`) are reported as `BRANCH` bucket moving refs. Fix mode resolves them through the git-ref API with the slash preserved.
- **Line-wise parsing.** Flow-style YAML on one line (for example `steps: [{ uses: actions/checkout@v4 }]`) is not detected, and commented-out `uses:` lines are ignored.
- **Docker refs are reported, never rewritten.** Pin container images by digest yourself; fix mode leaves `docker://` lines unchanged and says so in the plan.
- **Empty estates say so.** When no workflows are found under the audited path, the report carries a plain note that nothing was audited. The verdict is computed over zero actions and is not an all-clear for that path.
- **Piped output is delivered whole, or the run fails.** Reports are written through a flush-aware emit path, so a report of any size arrives complete through a pipe, the way agents, scripts, and CI consume it. If the reader closes the pipe before the report is delivered, actionpin exits 141 (the shell-visible equivalent of SIGPIPE) instead of reporting success for output nobody received. Fixed in 0.1.2 after Round 1 real-repo validation caught silent truncation at exactly 65,536 bytes with a success exit code.

## The toolkit

actionpin is part of a family of small, single-purpose developer tools by the same author, all built the same way: one bin that serves a CLI and an MCP server, deterministic checks with evidence, no invented answers.

- [greenlight](https://github.com/CloudCorpRecords/greenlight): pre-flight checks for open-source contributions: is this issue actually landable?
- [shipcheck](https://github.com/CloudCorpRecords/shipcheck): verify a release actually shipped across git, npm, the MCP Registry, and GHCR.
- [hookcheck](https://github.com/CloudCorpRecords/hookcheck): audit auto-exec hooks in a repo for persistence-style risks.

## Development

```bash
npm install
npm run build
npm test
```

Tests run on fixtures with an injected fetch function; no test touches the network.

## License

MIT
