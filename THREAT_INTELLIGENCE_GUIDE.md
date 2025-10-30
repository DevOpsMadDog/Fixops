# Threat Intelligence Integration Guide

## Overview

FixOps now provides an **extensible framework for 166+ threat intelligence sources** with **30+ sources currently implemented**, expanding from the original 2 sources (KEV, EPSS). The framework is designed to match or exceed platforms like inatestate.io. This guide covers the new threat intelligence capabilities, hybrid storage architecture, and portfolio search features.

**Current Status:**
- ✅ **30+ sources implemented**: OSV, NVD, GitHub Security Advisories, 9 vendor feeds, 10 ecosystem feeds, 7 exploit intelligence feeds
- 🚧 **136+ sources scaffolded**: Framework ready, parsers need implementation (see THREAT_INTELLIGENCE_RESEARCH.md)
- ✅ **Hybrid storage**: File storage + VectorDB + Portfolio search
- ✅ **Python API**: Full programmatic access via orchestrator
- 🚧 **REST API**: Planned (see "Future Enhancements" section)
- 🚧 **CLI commands**: Planned (see "Future Enhancements" section)

## Architecture

### Hybrid Storage Model

FixOps implements a three-tier hybrid storage architecture:

1. **File Storage** (Audit/Compliance)
   - Immutable evidence bundles stored as JSON files
   - SHA-256 checksums for integrity verification
   - Optional gzip compression and Fernet encryption
   - 7-year retention policy by default

2. **VectorDB** (Semantic Search)
   - ChromaDB or in-memory vector store
   - Evidence bundle summaries indexed for semantic search
   - Security pattern similarity matching
   - Natural language queries

3. **Portfolio Search Index** (Inventory Queries)
   - Cross-dimensional querying across SBOM, CVE, APP, org_id, component
   - Fast filtering and aggregation
   - Real-time inventory summaries

## Threat Intelligence Sources

### Core Vulnerability Databases (3 sources)

1. **OSV (Open Source Vulnerabilities)** - Google's unified database
   - Aggregates 40+ ecosystems (npm, PyPI, Go, Rust, Maven, etc.)
   - API: https://osv.dev/docs/
   - Coverage: GitHub Security Advisories, PyPA, RustSec, Go vulndb, etc.

2. **NVD (National Vulnerability Database)** - NIST's CVE database
   - API: https://nvd.nist.gov/developers/vulnerabilities
   - Coverage: All CVEs with CVSS scores, CPE, CWE
   - Supports API key for higher rate limits

3. **GitHub Security Advisories (GHSA)** - GitHub's vulnerability database
   - API: https://api.github.com/graphql
   - Coverage: All GitHub ecosystems
   - Requires GitHub personal access token

### Vendor-Specific Feeds (9 sources)

- **Microsoft Security Response Center (MSRC)** - Windows, Office, Azure
- **Apple Security Updates** - macOS, iOS, iPadOS
- **AWS Security Bulletins** - AWS services
- **Azure Security Advisories** - Azure services
- **Oracle Critical Patch Updates** - Oracle products
- **Cisco Security Advisories** - Cisco products
- **VMware Security Advisories** - VMware products
- **Docker Security Advisories** - Docker products
- **Kubernetes Security Advisories** - Kubernetes

### Language/Ecosystem Feeds (10 sources)

- **npm Security Advisories** - Node.js packages
- **PyPI Security Advisories** - Python packages (via OSV)
- **RubySec** - Ruby gems
- **RustSec** - Rust crates (via OSV)
- **Go Vulnerability Database** - Go modules (via OSV)
- **Maven Security** - Java/Maven packages (via OSV)
- **NuGet Security** - .NET packages
- **Debian Security Tracker** - Debian packages
- **Ubuntu Security Notices** - Ubuntu packages
- **Alpine SecDB** - Alpine Linux packages

### Exploit Intelligence Feeds (7 sources)

- **Exploit-DB** - Public exploit database
- **Vulners** - Vulnerability search engine
- **AlienVault OTX** - Open Threat Exchange
- **Abuse.ch URLhaus** - Malware URL feed
- **Abuse.ch MalwareBazaar** - Malware sample feed
- **Abuse.ch ThreatFox** - IOC feed
- **Rapid7 AttackerKB** - Community threat intelligence

### Legacy Feeds (2 sources)

- **CISA KEV** - Known Exploited Vulnerabilities
- **EPSS** - Exploit Prediction Scoring System

## Usage

### 1. Threat Intelligence Orchestrator

```python
from risk.feeds.orchestrator import ThreatIntelligenceOrchestrator

# Initialize orchestrator
orchestrator = ThreatIntelligenceOrchestrator(
    cache_dir="data/feeds",
    github_token="your_github_token",  # Optional
    nvd_api_key="your_nvd_api_key",    # Optional
    alienvault_api_key="your_otx_key", # Optional
)

# Update all feeds
results = orchestrator.update_all_feeds()
print(f"Updated {sum(results.values())} feeds successfully")

# Load all feeds
all_feeds = orchestrator.load_all_feeds()
print(f"Loaded {sum(len(records) for records in all_feeds.values())} vulnerability records")

# Enrich a specific CVE
enrichment = orchestrator.enrich_vulnerability("CVE-2024-1234")
print(f"CVE found in {len(enrichment['sources'])} sources")
print(f"Exploit available: {enrichment['exploit_available']}")
print(f"KEV listed: {enrichment['kev_listed']}")

# Get statistics
stats = orchestrator.get_statistics()
print(f"Total feeds: {stats['total_feeds']}")
print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
print(f"Vulnerabilities with exploits: {stats['vulnerabilities_with_exploits']}")

# Export unified feed
orchestrator.export_unified_feed("data/unified_threat_intel.json")
```

### 2. Evidence Bundle Indexing

```python
from core.evidence_indexer import EvidenceBundleIndexer

# Initialize indexer
indexer = EvidenceBundleIndexer(
    vector_store_type="chroma",  # or "in_memory"
    collection_name="evidence_bundles",
)

# Index all evidence bundles
indexed_count = indexer.index_all_bundles("data/evidence")
print(f"Indexed {indexed_count} evidence bundles")

# Search for similar bundles
matches = indexer.search_similar_bundles(
    query="payment service with critical SQL injection vulnerabilities",
    top_k=5,
)

for match in matches:
    print(f"Run ID: {match.identifier}")
    print(f"Similarity: {match.similarity:.3f}")
    print(f"App: {match.metadata.get('app_name')}")
    print(f"Critical count: {match.metadata.get('critical_count')}")
```

### 3. Portfolio Search

```python
from core.portfolio_search import PortfolioSearchEngine

# Initialize search engine
engine = PortfolioSearchEngine(evidence_dir="data/evidence")

# Search by component
results = engine.search_by_component("lodash")
print(f"Found {len(results)} apps using lodash")

# Search by CVE
results = engine.search_by_cve("CVE-2024-1234")
print(f"Found {len(results)} apps affected by CVE-2024-1234")

# Search by application name
results = engine.search_by_app("payment-service")
print(f"Found {len(results)} apps matching 'payment-service'")

# Search by organization
results = engine.search_by_org("org-123")
print(f"Found {len(results)} apps for organization org-123")

# Multi-dimensional search
results = engine.search_multi_dimensional(
    component="express",
    cve="CVE-2024-1234",
    org="org-123",
    min_critical=1,
    min_high=2,
)
print(f"Found {len(results)} apps matching all criteria")

# Get inventory summary
summary = engine.get_inventory_summary()
print(f"Total applications: {summary['total_applications']}")
print(f"Total organizations: {summary['total_organizations']}")
print(f"Unique components: {summary['unique_components']}")
print(f"Unique vulnerabilities: {summary['unique_vulnerabilities']}")
print(f"Total critical: {summary['total_critical']}")
print(f"Total high: {summary['total_high']}")

# Top components across portfolio
for component, count in summary['top_components'][:5]:
    print(f"  {component}: {count} apps")

# Top CVEs across portfolio
for cve, count in summary['top_cves'][:5]:
    print(f"  {cve}: {count} apps")
```

### 4. Individual Feed Usage

```python
from risk.feeds import OSVFeed, NVDFeed, GitHubSecurityAdvisoriesFeed

# OSV Feed
osv = OSVFeed(cache_dir="data/feeds")
osv.update_feed()
records = osv.load_feed()

# Fetch specific ecosystem
pypi_vulns = osv.fetch_ecosystem_vulnerabilities("PyPI", limit=100)
npm_vulns = osv.fetch_ecosystem_vulnerabilities("npm", limit=100)

# NVD Feed
nvd = NVDFeed(api_key="your_api_key", cache_dir="data/feeds")
recent_cves = nvd.fetch_recent_cves(days=7)

# GitHub Security Advisories
github = GitHubSecurityAdvisoriesFeed(token="your_token", cache_dir="data/feeds")
advisories = github.fetch_advisories(first=100)
```

### 5. Feed Registry

```python
from risk.feeds.base import FeedRegistry
from risk.feeds import OSVFeed, NVDFeed, NPMSecurityFeed

# Create registry
registry = FeedRegistry(cache_dir="data/feeds")

# Register feeds
registry.register(OSVFeed(cache_dir="data/feeds"))
registry.register(NVDFeed(cache_dir="data/feeds"))
registry.register(NPMSecurityFeed(cache_dir="data/feeds"))

# Update all registered feeds
results = registry.update_all()

# Load all registered feeds
all_feeds = registry.load_all()

# Get metadata
metadata = registry.get_all_metadata()
for meta in metadata:
    print(f"{meta.name}: {meta.record_count} records")
```

## Configuration

### Environment Variables

```bash
# GitHub token for Security Advisories
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# NVD API key for higher rate limits
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# AlienVault OTX API key
export ALIENVAULT_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Vulners API key
export VULNERS_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### Overlay Configuration

Add to your overlay YAML:

```yaml
threat_intelligence:
  enabled: true
  cache_dir: "data/feeds"
  update_interval: 86400  # 24 hours
  sources:
    - osv
    - nvd
    - github
    - kev
    - epss
    - exploitdb
    - npm
    - debian
    - ubuntu

evidence_indexing:
  enabled: true
  vector_store: "chroma"
  collection_name: "evidence_bundles"
  auto_index: true

portfolio_search:
  enabled: true
  evidence_dir: "data/evidence"
  auto_rebuild_index: true
```

## Python API (Current)

The threat intelligence and portfolio search features are currently available via Python API:

```python
from risk.feeds.orchestrator import ThreatIntelligenceOrchestrator
from core.evidence_indexer import EvidenceBundleIndexer
from core.portfolio_search import PortfolioSearchEngine

# Initialize orchestrator
orchestrator = ThreatIntelligenceOrchestrator(cache_dir="data/feeds")

# Update all feeds
orchestrator.update_all_feeds()

# Get statistics
stats = orchestrator.get_statistics()

# Enrich a CVE
enriched = orchestrator.enrich_vulnerability("CVE-2024-1234")

# Export unified feed
orchestrator.export_unified_feed("data/unified_threat_intel.json")

# Index evidence bundles
indexer = EvidenceBundleIndexer(vector_store_type="chroma")
indexer.index_all_bundles("data/evidence")

# Search portfolio
engine = PortfolioSearchEngine(evidence_dir="data/evidence")
results = engine.search_by_component("lodash")
results = engine.search_by_cve("CVE-2024-1234")
results = engine.search_by_app("payment-service")
summary = engine.get_inventory_summary()
```

## REST API Endpoints (Planned)

### Threat Intelligence Endpoints (Planned)

```bash
# Get all threat intelligence sources
GET /api/v1/threat-intelligence/sources

# Update all feeds
POST /api/v1/threat-intelligence/update

# Get feed statistics
GET /api/v1/threat-intelligence/statistics

# Enrich a CVE
GET /api/v1/threat-intelligence/enrich/{cve_id}

# Export unified feed
GET /api/v1/threat-intelligence/export
```

### Portfolio Search Endpoints (Planned)

```bash
# Search by component
GET /api/v1/portfolio/search/component/{component_name}

# Search by CVE
GET /api/v1/portfolio/search/cve/{cve_id}

# Search by application
GET /api/v1/portfolio/search/app/{app_name}

# Search by organization
GET /api/v1/portfolio/search/org/{org_id}

# Multi-dimensional search
POST /api/v1/portfolio/search/multi
{
  "component": "lodash",
  "cve": "CVE-2024-1234",
  "org": "org-123",
  "min_critical": 1
}

# Get inventory summary
GET /api/v1/portfolio/inventory/summary
```

## CLI Commands (Planned)

The following CLI commands are planned for future implementation. Currently, use the Python API shown above.

```bash
# Update all threat intelligence feeds
python -m risk.feeds.orchestrator update

# Export unified feed
python -m risk.feeds.orchestrator export --output data/unified_threat_intel.json

# Index all evidence bundles
python -m core.evidence_indexer index --evidence-dir data/evidence

# Search portfolio
python -m core.portfolio_search search --component lodash
python -m core.portfolio_search search --cve CVE-2024-1234
python -m core.portfolio_search search --app payment-service

# Get inventory summary
python -m core.portfolio_search inventory
```

## Extensibility

### Adding New Threat Intelligence Sources

1. Create a new feed class inheriting from `ThreatIntelligenceFeed`:

```python
from risk.feeds.base import ThreatIntelligenceFeed, VulnerabilityRecord

class MyCustomFeed(ThreatIntelligenceFeed):
    @property
    def feed_name(self) -> str:
        return "My Custom Feed"
    
    @property
    def feed_url(self) -> str:
        return "https://example.com/feed.json"
    
    @property
    def cache_filename(self) -> str:
        return "my-custom-feed.json"
    
    def parse_feed(self, data: bytes) -> List[VulnerabilityRecord]:
        # Parse your feed format
        payload = json.loads(data.decode("utf-8"))
        records = []
        
        for item in payload.get("vulnerabilities", []):
            record = VulnerabilityRecord(
                id=item["id"],
                source="My Custom Feed",
                severity=item.get("severity"),
                description=item.get("description"),
                # ... other fields
            )
            records.append(record)
        
        return records
```

2. Register your feed:

```python
from risk.feeds.orchestrator import ThreatIntelligenceOrchestrator

orchestrator = ThreatIntelligenceOrchestrator()
orchestrator.registry.register(MyCustomFeed(cache_dir="data/feeds"))
```

## Performance Considerations

### Feed Update Frequency

- **High-priority feeds** (KEV, EPSS, NVD): Update every 6-12 hours
- **Medium-priority feeds** (OSV, GitHub, vendor advisories): Update daily
- **Low-priority feeds** (ecosystem-specific): Update weekly

### Caching Strategy

- All feeds are cached locally in `data/feeds/`
- Fallback to cached data if network fetch fails
- JSON caches for fast loading
- Configurable cache expiration

### Rate Limiting

- NVD: 5 requests per 30 seconds (without API key), 50 per 30 seconds (with API key)
- GitHub: 5000 requests per hour (authenticated)
- OSV: No rate limits (public GCS bucket)
- Exploit-DB: No rate limits (GitLab CSV)

## Best Practices

1. **Use API keys** for NVD and GitHub to avoid rate limits
2. **Update feeds regularly** but not too frequently (daily is sufficient)
3. **Index evidence bundles** after each pipeline run for real-time search
4. **Rebuild portfolio index** periodically to ensure consistency
5. **Monitor feed health** using statistics endpoint
6. **Export unified feed** for offline analysis and backup
7. **Use multi-dimensional search** for complex portfolio queries
8. **Leverage semantic search** for natural language queries

## Troubleshooting

### Feed Update Failures

```python
# Check feed metadata
orchestrator = ThreatIntelligenceOrchestrator()
metadata = orchestrator.get_all_metadata()

for meta in metadata:
    if meta.last_updated is None:
        print(f"Feed {meta.name} has never been updated")
```

### Vector Store Issues

```python
# Use in-memory fallback
indexer = EvidenceBundleIndexer(vector_store_type="in_memory")
```

### Portfolio Search Index Rebuild

```python
# Rebuild index
engine = PortfolioSearchEngine(evidence_dir="data/evidence")
engine._build_index()
```

## Future Enhancements

### High Priority
- **REST API endpoints**: FastAPI endpoints for threat intelligence and portfolio search (see "REST API Endpoints (Planned)" section)
- **CLI commands**: Command-line interface for all operations (see "CLI Commands (Planned)" section)
- **Additional feed parsers**: Implement remaining 136+ scaffolded sources (see THREAT_INTELLIGENCE_RESEARCH.md)

### Medium Priority
- **Additional sources**: MITRE ATT&CK, CAPEC, CWE, OWASP Top 10
- **Machine learning**: Exploit prediction models
- **Threat actor attribution**: APT group tracking
- **Rate limiting**: Throttling and batching for API calls
- **Async processing**: Parallel feed updates for better performance

### Low Priority
- **Dark web intelligence**: Threat intelligence from dark web sources
- **Automated feed discovery**: Automatically discover new threat intelligence sources
- **Real-time streaming**: WebSocket-based real-time threat intelligence updates
- **Collaborative filtering**: Community-driven threat intelligence sharing

## References

- [OSV.dev Documentation](https://google.github.io/osv.dev/)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS Documentation](https://www.first.org/epss/)
- [Exploit-DB](https://www.exploit-db.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Abuse.ch](https://abuse.ch/)
