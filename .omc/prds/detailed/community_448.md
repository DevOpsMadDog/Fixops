# PRD — Community 448: Threat Feed Base — Get Feed Name Method

## Master Goal Mapping
- **Platform Goal**: Return the canonical name of a threat intelligence feed — used for deduplication, logging, and UI display
- **Persona**: System (used by feed aggregator), Security Engineer configuring feeds
- **ALDECI Pillar**: Threat Intelligence / Feed Management
- **Backend**: `suite-evidence-risk/risk/feeds/base.py`

## Architecture Diagram
```mermaid
graph TD
    A[ThreatFeed subclass] --> B[get_feed_name() → str]
    B --> C[Returns: e.g. 'nvd', 'abuse_ipdb', 'otx_alienvault']
    C --> D[threat_feed_aggregator: dedup by source name]
    C --> E[ThreatFeedSubscriptionEngine: match subscription by name]
    C --> F[UI: feed source label in IntelligenceHub]
```

## Code Proof
- **File**: `suite-evidence-risk/risk/feeds/base.py`
- **Node label** (from graph): `"Return the feed name."`
- **Base class**: `class ThreatFeed(ABC)` with `@abstractmethod get_feed_name()`
- **Fetcher type**: `Callable[[str], bytes]` for HTTP fetching
- **VulnerabilityRecord**: `{ id, source, severity, cvss_score, description, published, affected_packages... }`

## Inter-Dependencies
- **Upstream**: `ThreatFeedAggregator` iterates `feed.get_feed_name()` for logging
- **Downstream**: `VulnerabilityRecord.source` set to `get_feed_name()` value
- **28+ implementations**: NVD, OSV, EPSS, KEV, AbuseIPDB, OTX, URLhaus, GreyNoise, Shodan, etc.
- **Subscription engine**: `ThreatFeedSubscriptionEngine` matches by name

## Data Flow
```
ThreatFeedAggregator.aggregate() →
for feed in self.feeds: feed.get_feed_name() →
logger.info(f"Fetching {feed_name}") →
VulnerabilityRecord(source=feed.get_feed_name(), ...) →
Stored with source attribution for dedup
```

## Acceptance Criteria
- [ ] Returns lowercase string with underscores (e.g., 'nvd', 'otx_alienvault')
- [ ] Unique across all 28+ feed implementations
- [ ] @abstractmethod enforced — subclasses must implement
- [ ] Used consistently as `VulnerabilityRecord.source`
- [ ] No spaces or special chars in returned name

## Effort Estimate
**XS** — 0.25 days (complete)

## Status
**DONE** — Core feed identification method
