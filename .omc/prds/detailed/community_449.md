# PRD — Community 449: Threat Feed Base — Parse Feed Data Method

## Master Goal Mapping
- **Platform Goal**: Abstract feed data parser — converts raw HTTP feed responses into typed VulnerabilityRecord objects
- **Persona**: System (feed ingestion pipeline), Security Engineer adding new feeds
- **ALDECI Pillar**: Threat Intelligence / Feed Normalisation
- **Backend**: `suite-evidence-risk/risk/feeds/base.py`

## Architecture Diagram
```mermaid
graph TD
    A[ThreatFeed subclass] --> B[parse_feed_data(raw_data: bytes) → List VulnerabilityRecord]
    B --> C[NVDFeed.parse: JSON → CVE records]
    B --> D[OSVFeed.parse: JSON → OSV records]
    B --> E[AbuseIPDBFeed.parse: JSON → IP reputation records]
    B --> F[URLhausFeed.parse: CSV → URL threat records]
    C --> G[VulnerabilityRecord unified schema]
    D --> G
    E --> G
    F --> G
    G --> H[ThreatFeedAggregator: merge + dedup]
```

## Code Proof
- **File**: `suite-evidence-risk/risk/feeds/base.py`
- **Node label** (from graph): `"Parse raw feed data into vulnerability records. Parameters ----"`
- **@abstractmethod**: `parse_feed_data(self, raw_data: bytes) -> List[VulnerabilityRecord]`
- **VulnerabilityRecord fields**: id, source, severity, cvss_score, cvss_vector, description, published, modified, affected_packages, affected_versions + more
- **default_fetcher**: `urlopen(url, timeout=30)` with `# nosec` comment

## Inter-Dependencies
- **Upstream**: `fetch_feed()` calls `default_fetcher(url)` → passes bytes to `parse_feed_data`
- **Downstream**: `VulnerabilityRecord` list fed to `ThreatFeedAggregator`
- **28+ implementations**: Each feed parses its own schema (JSON/CSV/XML/STIX) into unified record
- **Normalisation**: Maps vendor-specific severity to ALDECI severity levels (critical/high/medium/low)

## Data Flow
```
Scheduled fetch → default_fetcher(feed_url) → raw bytes →
parse_feed_data(raw_bytes) →
[VulnerabilityRecord(id='CVE-2024-1234', source='nvd', cvss_score=9.8,
                     severity='critical', affected_packages=['openssl'])] →
Aggregator deduplicates by id+source → stores to SQLite
```

## Referenced Docs
- FEEDS_DIR: `data/feeds/` (Path constant)
- `suite-feeds/` — 28+ feed implementations
- CLAUDE.md: "28+ threat intelligence feeds, 32 scanner normalizers"

## Acceptance Criteria
- [ ] @abstractmethod enforced — all 28+ feed classes implement this
- [ ] Returns `List[VulnerabilityRecord]` (never None)
- [ ] CVSS score normalised to 0.0-10.0
- [ ] Severity mapped to: critical/high/medium/low/info
- [ ] Malformed feed data returns empty list with logged error (not crash)
- [ ] published/modified dates in ISO format
- [ ] affected_packages list populated (not empty string)

## Effort Estimate
**S** — 1 day per feed implementation (complete for all 28+)

## Status
**DONE** — Core feed normalisation interface, all 28+ feeds implemented
