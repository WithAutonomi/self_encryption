# ADR Tooling and AI Harness Setup

We use ADRs as engineering memory, not paperwork. They capture *why* a decision was made, what alternatives were rejected, and what consequences we accept.

## Install `adrs`

`adrs` is the preferred local CLI for creating, searching, and checking ADRs.

```bash
cargo install adrs
# or, if the repo has a Rust toolchain wrapper, use that wrapper's cargo equivalent.
```

Useful commands:

```bash
adrs list
adrs search "post-quantum"
adrs doctor
```

## Install `adr-kit`

`adr-kit` is used for agent-aware ADR analysis and policy/lint generation where available.

Recommended isolated install:

```bash
uv tool install adr-kit
# fallback
uvx adr-kit --help
```

If the published package name differs on your machine, install from the project source used by the team and keep it isolated with `uv tool` or `pipx` rather than a global Python environment.

## AI harness guidance: pi, Codex, Claude Code, OpenCode

Add this project instruction to every AI coding harness profile (`AGENTS.md`, `CLAUDE.md`, Codex/OpenCode project rules, pi harness prompts, etc.):

```text
Before changing architecture, protocols, storage formats, crypto, network behaviour, public APIs, data models, or operational invariants, inspect docs/adr/.
If the change creates or changes an architectural decision, draft or update a Proposed ADR using docs/adr/TEMPLATE.md.
Never edit an Accepted ADR. Create a superseding ADR instead.
Never mark an ADR Accepted autonomously; that requires human engineering review and debate.
During review, check ADR correctness, rejected alternatives, evidence, consequences, and immutable-Accepted compliance.
```

## Review standard

Do **not** "vibe code" ADRs. A useful ADR must show clear thinking: context, options, trade-offs, consequences, and validation. AI can help prepare a draft, but humans must debate and own the decision.
