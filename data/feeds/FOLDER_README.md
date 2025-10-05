# data/feeds/

**Purpose:** Contains reference threat feeds (e.g., CISA Known Exploited Vulnerabilities) used by tests
and demo scenarios to emulate CVE ingestion.

**Key Files**
- `kev.json` — Snapshot of KEV records for regression tests.

**Data Handling**
- Files are read-only; do not edit manually unless updating the snapshot with a smaller curated feed.
- Large upstream feeds should be trimmed before committing to keep repo size manageable.

**Gotchas**
- Tests expect deterministic content; update fixtures alongside any feed refresh to prevent failures.
