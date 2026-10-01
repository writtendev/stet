# Agent brief

stet is a git-native Go CLI for physical human attestation of code merges.
Its entire data model is one namespaced writ object: a signer, a content hash,
and a timestamp. A human taps a hardware security key (YubiKey via
WebAuthn/CTAP2) to sign a specific diff; the product claim is "a human was
physically present when this diff was signed." The core `sign`, `verify`, and
`audit` commands operate completely offline against local git repositories and
append-only writ stores with zero SaaS dependency.

`CLAUDE.md` and `GEMINI.md` are one-line `@AGENTS.md` imports, so every
toolchain reads the same text and there is nothing to keep in sync. Edit
AGENTS.md; leave the two stubs alone. Same pattern as the rest of writtendev.

## Orchestrate

The `factory` pipeline — `orchestrate`, `implement-ticket`,
`adversarial-review`, `merge-queue`, `decision-queue` — reads this section
for its repo-specific configuration. The skills are maintained in
`mattwalters/skills` and installed once per machine at user scope
(`claude plugin install factory@mattwalters --scope user`).
`.claude/settings.json` declares the `mattwalters` marketplace so Claude
Code knows where it lives; it deliberately does not enable or pin the
plugin. A field left unfilled is not a default — the skills are required
to stop and say which one is missing rather than guess.

- **Linear team key**: `STET` (ticket ids are `STET-<n>`)
- **Check command**: `./scripts/check.sh`, which runs `make build test lint`
- **Base branch**: `main`
- **Worktrees**: `$HOME/ops/worktrees/writtendev/stet/` — one worktree per
  ticket, named for it, outside the repo
- **Review invariants**: `### Review invariants` below
- **Stop-list**: `### Stop-list` below
- **Write window**: `none`

Expand `$HOME` to an absolute path before writing the worktrees value into
a prompt or using it in a file operation; a shell expands it, but
Read/Edit/Write calls and prompt placeholders do not.

Statuses are Linear's stock ones — `Todo` -> `In Progress` -> `In Review` ->
`Done` — with two workspace labels doing the rest: `approved-to-merge` on a
ticket in `In Review` means a human has approved its merge and it is in the
merge queue; `needs-attention` means it needs a human and keeps whatever
status it already had. `Backlog` is off-limits to orchestrate: promoting a
ticket to `Todo` is the only signal that it is available to work.

### Review invariants

The invariants a reviewer of a change to this repo should be adversarial
about. A diff that breaks one of these is a major finding, not a nit.

- **Paper-and-ink aesthetic.** Output formatting follows a restrained
  paper-and-ink visual standard (monochrome/ink palette, subtle borders, high
  legibility on light and dark terminals). No garish colors, flashing spinners,
  or gamified animations.
- **Machine-readable parity (`--json`).** Every CLI command producing
  human-readable output must accept `--json` and output deterministic, stable
  JSON matching its domain structure.
- **Fully offline core.** Commands `sign`, `verify`, and `audit` must function
  entirely offline against local git state and credentials without calling
  external SaaS services or hosted APIs.
- **Content tree hash binding.** Attestations bind to the complete content
  tree hash with a single signature (no per-chunk signing), ensuring the
  attestation survives git rebases and force-pushes.
- **No history rewriting.** Stet records are append-only. Reversals are
  appends; keys are revoked, never deleted.
- **A `Signed-off-by` trailer on every commit** (DCO, enforced by CI).
- **A branch rebased onto current `origin/main`** before its PR is opened or
  force-pushed.

### Stop-list

A change touching any of these waits for a human to merge it, whatever mode
the run is in. Each is either what the product claim rests on or a rule
about when a run stops, and a change that loosens one should not approve
itself.

- **CI and release**: `.github/workflows/`, `.goreleaser.yaml`, and
  `scripts/release/`.
- **The DCO setup**: `.githooks/` and the `Signed-off-by` invariant above.
- **Credential handling**: `internal/github/` token resolution and the
  device-code flow (`token.go`, `device.go`), or anything else that reads,
  stores or sends a credential.
- **Trust anchors**: the embedded roots and AAGUID metadata
  (`internal/attest/roots/`, `internal/attest/metadata/`,
  `scripts/gen-mds-aaguids/`) and trust policy (`internal/trust/`).
- **Attestation and signature verification**: `internal/attest/` and
  `internal/fido/` — what counts as a valid hardware-key signature.
- **The attestation record's shape**: what a signed record contains and
  what it binds to (signer, content tree hash, timestamp).
- **The pipeline's own configuration**: this `## Orchestrate` section (its
  fields, `### Review invariants`, and this stop-list),
  `scripts/check.sh`, and `.claude/settings.json`.
