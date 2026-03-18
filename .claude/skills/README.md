# ALdeci Claude Code Skills

> Skills encode reusable domain expertise as executable recipes. Every agent and session loads these automatically via CLAUDE.md reference.

## Skill Index

| Skill | Purpose | Used By |
|-------|---------|---------|
| `codebase-navigation.md` | Import system, file locations, how to find anything | ALL agents |
| `database-migration.md` | How to migrate sqlite3/PersistentDict → DatabaseManager | backend-hardener, enterprise-architect |
| `multi-tenancy.md` | How to add org_id tenant isolation to any endpoint | security-analyst, backend-hardener |
| `error-handling.md` | Exception hierarchy, how to replace bare except Exception | ALL agents |
| `endpoint-hardening.md` | The mandatory checklist for every API endpoint | ALL agents |
| `testing-patterns.md` | How to write tests, fix collection errors, raise coverage | qa-engineer |
| `knowledge-graph.md` | How to build, query, and extend the security knowledge graph | data-scientist, threat-architect |
| `scanner-development.md` | How to harden and extend the 8 native scanners | backend-hardener, security-analyst |
| `observability.md` | OpenTelemetry, Prometheus, structured logging patterns | devops-engineer |
| `acquisition-readiness.md` | Due-diligence checklist, documentation standards | technical-writer, enterprise-architect |

## How Skills Work

1. Every agent reads `CLAUDE.md` which references these skills
2. Before working on a domain, the agent reads the relevant skill file
3. Skills contain exact code patterns, file paths, and validation commands
4. Skills are updated as the codebase evolves — context-engineer maintains them
