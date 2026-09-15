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
AGENTS.md; leave the two stubs alone. Same pattern as the rest of the studio.

## Dispatch

The per-repo configuration the `dispatch`, `implement-ticket`,
`adversarial-review` and `merge-queue` skills read. Those skills are
maintained once in the parent studio repo and are repo-generic; this section
is how this repo opts into them. A field left unfilled is not a default —
the skills are required to stop and say which one is missing rather than
guess.

- **Linear team key**: `STET` (ticket ids are `STET-<n>`)
- **Check command**: `make build test lint`
- **Base branch**: `main`
- **Worktrees**: `.claude/worktrees/` — one worktree per ticket, named for it
- **Run manifest**: `.claude/worktrees/dispatch-manifest.md`

Statuses are Linear's stock ones — `Todo` -> `In Progress` -> `In Review` ->
`Done` — with two workspace labels doing the rest: `approved-to-merge` on a
ticket in `In Review` means a human has approved its merge and it is in the
merge queue; `needs-attention` means it needs a human and keeps whatever
status it already had. `Backlog` is off-limits to dispatch: promoting a
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
