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
| `PINNED` | Ref is a full 40-character commit SHA (or a full sha256 or sha512 content digest for a container image) |
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

- **Scope is workflow files plus in-repo composite actions.** A directory audit scans `.github/workflows/*.yml` and `*.yaml`, and also the action definitions that live inside the scanned repo: the root-level `action.yml` or `action.yaml` (the scanned repo's own published action definition, scanned whether or not a workflow references it, which is the normal shape for a repo that ships an action), every `action.yml` and `action.yaml` under `.github/actions/`, plus any local action directory a workflow references with a `./` uses path. Their internal steps are inventoried and classified like workflow steps, flagged as composite action refs, and drive the verdict the same way. A root action whose steps reference the repo's own action (via `./` or via its published name) is scanned exactly once; self-reference never recurses or double counts. The report lists how many composite files were scanned, and names any action files found elsewhere in the repo that were not scanned (not the root action file, outside `.github/actions`, and not referenced by a workflow), so coverage is never implied beyond what was audited. Passing an `action.yml` file path directly also parses it like any other file. Job-level `uses:` lines (reusable workflow calls) are in scope and are audited and pinned like step-level ones.
- **A local path with a malformed prefix is local, and the typo stays visible.** A uses value such as `$/.github/actions/issues-helper` (a stray character where the dot of the `./` prefix belongs, shipped by real repos) names no remote repository, so it is classified LOCAL and is never resolved against the GitHub API in fix mode. The finding carries a note that the prefix is not a valid remote reference and looks like a local path typo, because the spelling is a real defect in the target repo even though it is not a pinning exposure.
- **Dynamic values are skipped, not guessed.** A `uses:` value that contains a GitHub expression (`${{ matrix.action }}`, `actions/checkout@${{ inputs.ref }}`) is decided at run time and cannot be classified statically. actionpin skips it entirely instead of inventing an action or a verdict for it. Audit the matrix or input values themselves if a workflow builds its actions dynamically.
- **Short SHAs never count as pinned.** Only a full 40-character SHA (or a full sha256 or sha512 digest for `docker://` images) is `PINNED`. A short SHA such as `abc1234` is reported in the `BRANCH` bucket and fails the verdict, because a short prefix is not a stable pin.
- **Container tags never count as pinned.** For `docker://` images only a full content digest counts. A tag spelled as 40 hex characters is still a tag and can be re-pushed, and a truncated or non-hex digest is not a digest; both are `MUTABLE`.
- **YAML anchors and aliases are resolved within the file.** GitHub Actions has supported them since September 2025. An anchored `uses:` value is classified by the value itself, an alias line (`uses: *name`, or a step alias `- *name`) inherits the anchored classification and is flagged `viaAlias`, and anchors must be defined before use in the same file, matching GitHub. Fix mode pins the anchor definition line and never rewrites an alias line.
- **Refs containing slashes** (`release/v1`, `feature/new-thing`) are reported as `BRANCH` bucket moving refs. Fix mode resolves them through the git-ref API with the slash preserved.
- **Block and flow style are both inventoried.** Parsing is line-wise so fix mode can preserve formatting, and a quote-aware flow scanner inventories `uses:` entries written in YAML flow style (for example `steps: [{uses: 'actions/checkout@v4'}]`), including several entries sharing one line, flow collections split across lines, and quoted (JSON-shaped) keys. Commented-out `uses:` lines are ignored, and a `uses:` word inside a quoted string or a run command invents no action. Fix mode pins a flow entry without adding a version comment on the shared line, because a comment would eat the rest of that line.
- **A file that cannot be fully parsed is reported, never silent.** When a workflow or composite file carries a `uses:` key whose value cannot be extracted, the report names the file in `unparsedWorkflows`, carries a note saying it could not be fully parsed, and floors the verdict at PARTIAL, so the file never silently contributes zero actions to a PINNED verdict.
- **Docker refs are reported, never rewritten.** Pin container images by digest yourself; fix mode leaves `docker://` lines unchanged and says so in the plan.
- **Empty estates say so.** When no workflows and no action definitions are found under the audited path, the report carries a plain note that nothing was audited. The verdict is computed over zero actions and is not an all-clear for that path. A repo whose only auditable surface is its root action definition is audited on that definition and carries no empty-estate note.
- **Missing or wrong-type targets are usage errors, never a verdict.** A path that does not exist exits 2 with an error on stderr and no report, matching hookcheck and injectcheck, so CI wired to a mistyped path fails instead of going green on nothing. Passing a single file audits it only when it is a `.yml` or `.yaml` file; any other regular file (a `package.json`, a README) is a usage error exit 2, not a workflow. A target that is neither a file nor a directory is a usage error too.
- **Non-regular files are never opened.** Discovery stats every candidate before opening it and skips anything that is not a regular file, so a FIFO (named pipe), socket, or device planted at a workflow or action file path cannot hang or block the audit; the regular files around it are audited normally.
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

---

Built by [Rene Turcios](https://github.com/CloudCorpRecords) - vibe coder / agent-native dev building in public in SF. If actionpin saved you time, star this repo and [follow @CloudCorpRecords](https://github.com/CloudCorpRecords) for the next tool.
The family: [greenlight](https://github.com/CloudCorpRecords/greenlight) · [hookcheck](https://github.com/CloudCorpRecords/hookcheck) · [injectcheck](https://github.com/CloudCorpRecords/injectcheck) · [shipcheck](https://github.com/CloudCorpRecords/shipcheck) - all on npm under `@reneturcios/` and in the official MCP Registry.
