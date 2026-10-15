# ADR-0001: Adopt Architecture Decision Records

- **Status:** Accepted
- **Date:** 2026-06-01
- **Decision owners:** Engineering team
- **Reviewers:** Engineering team
- **Supersedes:** none
- **Superseded by:** none
- **Related:** Portfolio ADR governance rollout

## Context

This repository participates in a wider Autonomi/Saorsa engineering portfolio where architectural decisions affect protocols, storage behaviour, cryptography, APIs, operations, and long-term maintenance. AI-assisted coding makes it easier to generate large changes quickly, but it also increases the risk that design intent, trade-offs, and constraints are lost.

## Decision Drivers

- Preserve the reasoning behind architectural choices.
- Make trade-offs visible during code review.
- Give humans and AI coding tools a reliable source of architectural context.
- Prevent silent drift from accepted engineering decisions.
- Support cross-repository consistency across Autonomi and Saorsa projects.

## Considered Options

1. Keep architecture reasoning only in PR descriptions and issues.
2. Maintain informal design notes without lifecycle governance.
3. Adopt version-controlled Architecture Decision Records with CI governance.

## Decision

We will maintain Architecture Decision Records in `docs/adr/` using the repository template. New decisions start as `Proposed`; once reviewed and agreed, they may be marked `Accepted`. Accepted ADRs are immutable: if the decision changes, a new superseding ADR must be created rather than editing the accepted record.

## Consequences

### Positive

- Architectural intent becomes searchable and reviewable.
- AI coding agents have explicit project constraints to inspect before changing code.
- Reviews can check decision quality, not just implementation mechanics.
- Supersession creates an audit trail instead of rewriting history.

### Negative / Trade-offs

- Design work becomes more explicit and may slow rushed changes.
- Engineers must keep ADRs aligned with meaningful architectural changes.

### Neutral / Operational

- CI enforces ADR format and immutable Accepted status.
- Reviewers should reject architectural PRs with weak, missing, or AI-generated-without-debate ADRs.

## Validation

The ADR governance CI job must pass on every PR. Reviewers should verify that architectural changes include appropriate ADR coverage and that accepted ADRs are not modified in-place.
