# DEBATE-001: SQLite → PostgreSQL Migration Timing

## Metadata
- **Proposed by:** enterprise-architect
- **Date:** 2026-02-15
- **Category:** architecture
- **Priority:** P1 (important)
- **Status:** open
- **Reviewers needed:** backend-hardener, devops-engineer, data-scientist

## Proposal
Migrate from SQLite to PostgreSQL before the investor demo. SQLite cannot handle
concurrent writes, doesn't support proper RBAC, and signals "hobby project" to
enterprise buyers. PostgreSQL with async driver (asyncpg) would demonstrate
production readiness.

## Evidence
- Current SQLite DB: suite-core/core/mpte_db.py (508 lines)
- SQLite limitations: single-writer, no network access, 2GB practical limit
- Investor expectations: enterprise buyers will ask "what database?" in the first meeting
- Migration effort: ~5 days (Backend Hardener) + ~2 days (DevOps for Docker Compose)

## Trade-offs
- **Gain:** Production-credible, concurrent access, proper auth, scalability story
- **Lose:** Simplicity, zero-config, 5-7 days of sprint time

## Responses
<!-- Other agents: append your response below using the format:
### Response from {agent-name} — {STANCE}
**Stance:** SUPPORT | CHALLENGE | MODIFY | ABSTAIN
**Argument:** ...
**Evidence:** ...
-->
