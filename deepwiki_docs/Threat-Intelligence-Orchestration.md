# Threat Intelligence Orchestration

> **Relevant source files**
> * [.emergent/emergent.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.emergent/emergent.yml)
> * [.gitignore](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.gitignore)
> * [README.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/README.md)
> * [apps/api/micro_pentest_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/micro_pentest_router.py)
> * [compliance/__init__.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/compliance/__init__.py)
> * [compliance/mapping.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/compliance/mapping.py)
> * [core/decision_tree.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_tree.py)
> * [core/hallucination_guards.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/hallucination_guards.py)
> * [core/playbook_runner.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/playbook_runner.py)
> * [data/feeds/epss.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json)
> * [data/feeds/kev.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json)
> * [docs/API_CLI_REFERENCE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/API_CLI_REFERENCE.md)
> * [docs/DOCKER_SHOWCASE_GUIDE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/DOCKER_SHOWCASE_GUIDE.md)
> * [docs/ENTERPRISE_FEATURES.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/ENTERPRISE_FEATURES.md)
> * [docs/FEATURE_CODE_MAPPING.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/FEATURE_CODE_MAPPING.md)
> * [docs/PLAYBOOK_LANGUAGE_REFERENCE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/PLAYBOOK_LANGUAGE_REFERENCE.md)
> * [fixops-enterprise/src/api/v1/micro_pentest.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/api/v1/micro_pentest.py)
> * [fixops-enterprise/src/services/micro_pentest_engine.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/micro_pentest_engine.py)
> * [risk/enrichment.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/enrichment.py)
> * [risk/forecasting.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/forecasting.py)
> * [risk/threat_model.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/threat_model.py)
> * [tests/test_compliance_mapping.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_compliance_mapping.py)
> * [tests/test_micro_pentest_engine.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_micro_pentest_engine.py)
> * [tests/test_threat_intelligence_comprehensive_coverage.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py)

## Purpose and Scope

This document describes the Threat Intelligence Orchestration system, which coordinates the ingestion, caching, and management of 166+ vulnerability data sources across 8 threat intelligence categories. The `ThreatIntelligenceOrchestrator` serves as the central coordinator for all external vulnerability feeds, providing a unified interface for feed updates, caching, and vulnerability enrichment.

For information about the specific KEV and EPSS feed implementations, see [KEV and EPSS Feeds](/DevOpsMadDog/Fixops/2.1-kev-and-epss-feeds). For severity promotion logic based on threat intelligence signals, see [Severity Promotion Engine](/DevOpsMadDog/Fixops/2.3-severity-promotion-engine). For exploit signal detection and evaluation, see [Exploit Signal Detection](/DevOpsMadDog/Fixops/2.4-exploit-signal-detection).

---

## System Overview

The Threat Intelligence Orchestration system aggregates vulnerability intelligence from authoritative sources, exploit databases, ecosystem-specific advisories, vendor security bulletins, and threat actor intelligence feeds. This multi-source approach provides comprehensive coverage for:

* **Exploit prediction** via EPSS scores for 296,333 CVEs
* **Known exploitation** via CISA KEV catalog with 1,422 entries
* **Ecosystem-specific vulnerabilities** from NPM, PyPI, RubyGems, Go, Maven, NuGet, Rust, Debian, Ubuntu, Alpine
* **Vendor advisories** from Microsoft, Apple, AWS, Azure, Oracle, Cisco, VMware, Docker, Kubernetes
* **Exploit intelligence** from ExploitDB, AlienVault OTX, Vulners, Rapid7 AttackerKB, abuse.ch
* **Supply chain intelligence** from GitHub Security Advisories, OSV, NVD

The orchestrator handles feed refresh scheduling, caching strategies, and provides enrichment APIs for downstream risk scoring and decision engines.

**Sources:** [README.md L154-L192](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/README.md#L154-L192)

 [tests/test_threat_intelligence_comprehensive_coverage.py L1-L60](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L1-L60)

---

## Feed Categories and Data Sources

```mermaid
flowchart TD

Orchestrator["ThreatIntelligenceOrchestrator<br>risk.feeds.orchestrator"]
KEV["CISA KEV Catalog<br>1,422 vulnerabilities<br>risk.feeds.kev"]
EPSS["FIRST EPSS Scores<br>296,333 CVEs<br>risk.feeds.epss"]
NVD["NVD Feed<br>risk.feeds.nvd.NVDFeed"]
OSV["OSV Database<br>risk.feeds.osv.OSVFeed"]
NPM["NPMSecurityFeed<br>risk.feeds.ecosystems"]
PyPI["PyPISecurityFeed<br>risk.feeds.ecosystems"]
RubyGems["RubySecFeed<br>risk.feeds.ecosystems"]
GoVuln["GoVulnDBFeed<br>risk.feeds.ecosystems"]
Maven["MavenSecurityFeed<br>risk.feeds.ecosystems"]
NuGet["NuGetSecurityFeed<br>risk.feeds.ecosystems"]
Rust["RustSecFeed<br>risk.feeds.ecosystems"]
Debian["DebianSecurityFeed<br>risk.feeds.ecosystems"]
Ubuntu["UbuntuSecurityFeed<br>risk.feeds.ecosystems"]
Alpine["AlpineSecDBFeed<br>risk.feeds.ecosystems"]
Microsoft["MicrosoftSecurityFeed<br>risk.feeds.vendors"]
Apple["AppleSecurityFeed<br>risk.feeds.vendors"]
AWS["AWSSecurityFeed<br>risk.feeds.vendors"]
Azure["AzureSecurityFeed<br>risk.feeds.vendors"]
Oracle["OracleSecurityFeed<br>risk.feeds.vendors"]
Cisco["CiscoSecurityFeed<br>risk.feeds.vendors"]
VMware["VMwareSecurityFeed<br>risk.feeds.vendors"]
Docker["DockerSecurityFeed<br>risk.feeds.vendors"]
K8s["KubernetesSecurityFeed<br>risk.feeds.vendors"]
ExploitDB["ExploitDBFeed<br>risk.feeds.exploits"]
AlienVault["AlienVaultOTXFeed<br>risk.feeds.exploits"]
Vulners["VulnersFeed<br>risk.feeds.exploits"]
Rapid7["Rapid7AttackerKBFeed<br>risk.feeds.exploits"]
AbuseCH_URL["AbuseCHURLHausFeed<br>risk.feeds.exploits"]
AbuseCH_Malware["AbuseCHMalwareBazaarFeed<br>risk.feeds.exploits"]
AbuseCH_Threat["AbuseCHThreatFoxFeed<br>risk.feeds.exploits"]
GitHub["GitHubSecurityAdvisoriesFeed<br>risk.feeds.github"]

Orchestrator -.-> KEV
Orchestrator -.-> EPSS
Orchestrator -.-> NVD
Orchestrator -.-> OSV
Orchestrator -.-> NPM
Orchestrator -.-> PyPI
Orchestrator -.-> RubyGems
Orchestrator -.-> GoVuln
Orchestrator -.-> Maven
Orchestrator -.-> NuGet
Orchestrator -.-> Rust
Orchestrator -.-> Debian
Orchestrator -.-> Ubuntu
Orchestrator -.-> Alpine
Orchestrator -.-> Microsoft
Orchestrator -.-> Apple
Orchestrator -.-> AWS
Orchestrator -.-> Azure
Orchestrator -.-> Oracle
Orchestrator -.-> Cisco
Orchestrator -.-> VMware
Orchestrator -.-> Docker
Orchestrator -.-> K8s
Orchestrator -.-> ExploitDB
Orchestrator -.-> AlienVault
Orchestrator -.-> Vulners
Orchestrator -.-> Rapid7
Orchestrator -.-> AbuseCH_URL
Orchestrator -.-> AbuseCH_Malware
Orchestrator -.-> AbuseCH_Threat
Orchestrator -.-> GitHub

subgraph subGraph6 ["Category 6: Supply Chain"]
    GitHub
end

subgraph subGraph5 ["Category 5: Exploit Intelligence"]
    ExploitDB
    AlienVault
    Vulners
    Rapid7
    AbuseCH_URL
    AbuseCH_Malware
    AbuseCH_Threat
end

subgraph subGraph4 ["Category 4: Vendor Advisories"]
    Microsoft
    Apple
    AWS
    Azure
    Oracle
    Cisco
    VMware
    Docker
    K8s
end

subgraph subGraph3 ["Category 3: OS Distribution Feeds"]
    Debian
    Ubuntu
    Alpine
end

subgraph subGraph2 ["Category 2: Ecosystem Feeds"]
    NPM
    PyPI
    RubyGems
    GoVuln
    Maven
    NuGet
    Rust
end

subgraph subGraph1 ["Category 1: Authoritative Sources"]
    KEV
    EPSS
    NVD
    OSV
end

subgraph subGraph0 ["Threat Intelligence Orchestrator"]
    Orchestrator
end
```

**Feed Category Distribution**

| Category | Feed Count | Module Path | Purpose |
| --- | --- | --- | --- |
| Authoritative Sources | 4 | `risk.feeds.{kev,epss,nvd,osv}` | Ground truth CVE data, KEV status, EPSS scores |
| Ecosystem Advisories | 7 | `risk.feeds.ecosystems` | Language/package manager specific vulnerabilities |
| OS Distribution Feeds | 3 | `risk.feeds.ecosystems` | Linux distribution security advisories |
| Vendor Security Bulletins | 9 | `risk.feeds.vendors` | Cloud provider and infrastructure vendor advisories |
| Exploit Intelligence | 7 | `risk.feeds.exploits` | Active exploitation, threat actor intelligence |
| Supply Chain Intelligence | 1 | `risk.feeds.github` | GitHub Security Advisory Database |

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L16-L59](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L16-L59)

 [README.md L154-L192](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/README.md#L154-L192)

---

## ThreatIntelligenceOrchestrator Architecture

The `ThreatIntelligenceOrchestrator` class provides centralized management of all vulnerability feeds with the following responsibilities:

1. **Feed Lifecycle Management**: Update, refresh, and cache all feeds
2. **Unified Loading Interface**: Load all feeds into memory for enrichment
3. **Metadata Aggregation**: Collect feed statistics and status
4. **Vulnerability Enrichment**: Enrich CVEs and CWEs with multi-source intelligence

### Core Architecture Diagram

```mermaid
flowchart TD

Orchestrator["ThreatIntelligenceOrchestrator<br>risk/feeds/orchestrator.py"]
UpdateAll["update_all_feeds()<br>Update all feeds from sources"]
LoadAll["load_all_feeds()<br>Load cached feeds into memory"]
GetMetadata["get_all_metadata()<br>Collect feed statistics"]
Enrich["enrich_vulnerability(id)<br>Multi-source enrichment"]
BaseFeed["BaseFeed<br>risk/feeds/base.py"]
FeedMetadata["FeedMetadata<br>name, url, last_updated<br>record_count"]
VulnRecord["VulnerabilityRecord<br>id, source, severity<br>cvss_score, cwe_ids"]
EcosystemFeeds["Ecosystem Feeds<br>parse_feed(data)<br>load_feed()"]
VendorFeeds["Vendor Feeds<br>parse_feed(data)<br>load_feed()"]
ExploitFeeds["Exploit Feeds<br>parse_feed(data)<br>load_feed()"]
CacheDir["cache_dir<br>data/feeds/"]
KEVCache["kev.json<br>1,422 entries"]
EPSSCache["epss.csv + epss.json<br>296,333 entries"]
FeedCache["feed-specific caches<br>{npm,pypi,rubysec,...}.json"]

EcosystemFeeds -.-> BaseFeed
VendorFeeds -.-> BaseFeed
ExploitFeeds -.-> BaseFeed
UpdateAll -.-> CacheDir
LoadAll -.-> CacheDir
Orchestrator -.-> BaseFeed

subgraph subGraph3 ["Caching Layer"]
    CacheDir
    KEVCache
    EPSSCache
    FeedCache
    CacheDir -.-> KEVCache
    CacheDir -.-> EPSSCache
    CacheDir -.-> FeedCache
end

subgraph subGraph2 ["Feed Implementations"]
    EcosystemFeeds
    VendorFeeds
    ExploitFeeds
end

subgraph subGraph1 ["Feed Base Classes"]
    BaseFeed
    FeedMetadata
    VulnRecord
    BaseFeed -.->|"implements"| FeedMetadata
    BaseFeed -.->|"implements"| VulnRecord
end

subgraph subGraph0 ["Orchestrator Core"]
    Orchestrator
    UpdateAll
    LoadAll
    GetMetadata
    Enrich
    Orchestrator -.-> UpdateAll
    Orchestrator -.-> LoadAll
    Orchestrator -.-> GetMetadata
    Orchestrator -.->|"implements"| Enrich
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L387-L440](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L387-L440)

---

## Feed Update and Caching Mechanisms

### EPSS Feed Update Strategy

The EPSS feed implements a two-tier caching strategy with CSV primary storage and JSON fallback cache:

```mermaid
flowchart TD

FetchFail["Fetch failed?"]
JSONExists["JSON cache<br>exists?"]
UseFallback["Return JSON path"]
RaiseFail["Raise exception"]
LoadScores["load_epss_scores(path, cache_dir)"]
CheckCSV["CSV exists?"]
LoadCSV["Parse CSV"]
CheckJSON["JSON exists?"]
LoadJSON["Load JSON"]
Error["Raise FileNotFoundError"]
Fetcher["fetcher(url)<br>Download EPSS CSV"]
ParseCSV["_parse_epss_csv(path)<br>Parse CVE,score pairs"]
CSVCache["epss.csv<br>Primary cache"]
WriteJSON["_write_json_cache(dir, scores)<br>Create JSON backup"]
JSONCache["epss.json<br>Fallback cache"]

subgraph subGraph2 ["Error Handling"]
    FetchFail
    JSONExists
    UseFallback
    RaiseFail
    FetchFail -.->|"Yes"| JSONExists
    JSONExists -.->|"Yes"| UseFallback
    JSONExists -.->|"No"| RaiseFail
end

subgraph subGraph1 ["EPSS Load Flow"]
    LoadScores
    CheckCSV
    LoadCSV
    CheckJSON
    LoadJSON
    Error
    LoadScores -.->|"No"| CheckCSV
    CheckCSV -.->|"Yes"| LoadCSV
    CheckCSV -.->|"Yes"| CheckJSON
    CheckJSON -.->|"No"| LoadJSON
    CheckJSON -.-> Error
end

subgraph subGraph0 ["EPSS Update Flow"]
    Fetcher
    ParseCSV
    CSVCache
    WriteJSON
    JSONCache
    Fetcher -.-> ParseCSV
    ParseCSV -.-> CSVCache
    ParseCSV -.-> WriteJSON
    WriteJSON -.-> JSONCache
end
```

**EPSS Caching Functions**

| Function | File Location | Purpose |
| --- | --- | --- |
| `update_epss_feed(cache_dir, fetcher)` | `risk/feeds/epss.py` | Download and cache EPSS CSV, create JSON backup |
| `_parse_epss_csv(csv_path)` | `risk/feeds/epss.py` | Parse CSV into `{CVE: score}` dictionary |
| `_write_json_cache(cache_dir, scores)` | `risk/feeds/epss.py` | Write scores to `epss.json` for fast loading |
| `_load_json_cache(cache_dir)` | `risk/feeds/epss.py` | Load scores from JSON cache, return `None` if missing |
| `load_epss_scores(path, cache_dir)` | `risk/feeds/epss.py` | Load from CSV if exists, else JSON, else raise error |

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L70-L223](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L70-L223)

### KEV Feed Update Strategy

The KEV feed uses a simpler JSON-only caching strategy:

```mermaid
flowchart TD

LoadKEV["load_kev_catalog(cache_dir)"]
CheckFile["kev.json exists?"]
ParseJSON["Parse JSON<br>Extract vulnerabilities array"]
BuildDict["Build {CVE: metadata} dict"]
RaiseError["Raise FileNotFoundError"]
Fetcher["fetcher(url)<br>Download KEV JSON"]
WriteCache["Write to kev.json"]
KEVCache["kev.json<br>{vulnerabilities: [...]}"]

subgraph subGraph1 ["KEV Load Flow"]
    LoadKEV
    CheckFile
    ParseJSON
    BuildDict
    RaiseError
    LoadKEV -.->|"No"| CheckFile
    CheckFile -.->|"Yes"| ParseJSON
    ParseJSON -.-> BuildDict
    CheckFile -.-> RaiseError
end

subgraph subGraph0 ["KEV Update Flow"]
    Fetcher
    WriteCache
    KEVCache
    Fetcher -.-> WriteCache
    WriteCache -.-> KEVCache
end
```

**KEV Caching Functions**

| Function | File Location | Purpose |
| --- | --- | --- |
| `update_kev_feed(cache_dir, fetcher)` | `risk/feeds/kev.py` | Download and cache KEV catalog JSON |
| `load_kev_catalog(cache_dir)` | `risk/feeds/kev.py` | Load KEV catalog into `{CVE: entry}` dictionary |

**KEV Entry Structure**

The KEV catalog stores entries with the following fields:

* `cveID`: CVE identifier (e.g., "CVE-2025-32463")
* `vendorProject`: Vendor name (e.g., "Sudo")
* `product`: Product name (e.g., "Sudo")
* `vulnerabilityName`: Human-readable vulnerability name
* `dateAdded`: Date added to KEV catalog
* `shortDescription`: Vulnerability description
* `requiredAction`: Required remediation action
* `dueDate`: Remediation due date for FCEB agencies
* `knownRansomwareCampaignUse`: Ransomware usage indicator
* `notes`: Additional notes and references
* `cwes`: Array of CWE identifiers

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L225-L275](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L225-L275)

 [data/feeds/kev.json L1-L543](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json#L1-L543)

### Generic Feed Update Pattern

All other feeds follow a common update pattern implemented by the `BaseFeed` interface:

```mermaid
flowchart TD

GetMeta["get_metadata()"]
BuildMeta["FeedMetadata(<br>  name=feed_name,<br>  record_count=len(records)<br>)"]
Load["load_feed()"]
CheckCache["Cache exists?"]
ReadCache["Read cache file"]
ParseCache["parse_feed(cache_data)"]
EmptyList["Return []"]
Init["Feed.init(cache_dir)"]
Update["update_feed()"]
Fetch["Fetch raw data<br>from source URL"]
Parse["parse_feed(raw_data)<br>Returns List[VulnerabilityRecord]"]
Cache["Write to cache file<br>{feed_name}.json"]

subgraph subGraph2 ["Feed Metadata"]
    GetMeta
    BuildMeta
    GetMeta -.-> BuildMeta
end

subgraph subGraph1 ["Generic Feed Load"]
    Load
    CheckCache
    ReadCache
    ParseCache
    EmptyList
    Load -.->|"Yes"| CheckCache
    CheckCache -.->|"No"| ReadCache
    ReadCache -.-> ParseCache
    CheckCache -.-> EmptyList
end

subgraph subGraph0 ["Generic Feed Update"]
    Init
    Update
    Fetch
    Parse
    Cache
    Init -.-> Update
    Update -.-> Fetch
    Fetch -.-> Parse
    Parse -.-> Cache
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L277-L385](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L277-L385)

---

## Orchestrator Operations

### Update All Feeds

The `update_all_feeds()` method iterates through all registered feeds and updates them from their respective sources:

```mermaid
flowchart TD

UpdateAll["orchestrator.update_all_feeds()"]
KEVUpdate["update_kev_feed(cache_dir, fetcher)"]
EPSSUpdate["update_epss_feed(cache_dir, fetcher)"]
FeedLoop["For each feed in registry:"]
FeedUpdate["feed.update_feed()"]
HandleError["Update failed?"]
LogError["Log error, continue"]
RecordSuccess["Record success"]
Results["Return {<br>  feed_name: success/error<br>}"]

UpdateAll -.-> KEVUpdate
UpdateAll -.-> EPSSUpdate
UpdateAll -.-> FeedLoop
LogError -.-> Results
RecordSuccess -.-> Results

subgraph subGraph0 ["Update Process"]
    KEVUpdate
    EPSSUpdate
    FeedLoop
    FeedUpdate
    HandleError
    LogError
    RecordSuccess
    FeedLoop -.-> FeedUpdate
    FeedUpdate -.-> HandleError
    HandleError -.->|"Yes"| LogError
    HandleError -.->|"No"| RecordSuccess
end
```

The orchestrator handles failures gracefully, logging errors but continuing to update other feeds. This ensures partial feed refresh succeeds even if individual sources are unavailable.

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L390-L398](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L390-L398)

### Load All Feeds

The `load_all_feeds()` method loads cached feed data into memory for enrichment operations:

```mermaid
flowchart TD

LoadAll["orchestrator.load_all_feeds()"]
LoadKEV["kev_catalog = load_kev_catalog(cache_dir)"]
LoadEPSS["epss_scores = load_epss_scores(cache_dir)"]
FeedLoop["For each feed in registry:"]
FeedLoad["records = feed.load_feed()"]
HandleError["Load failed?"]
LogError["Log error, use empty list"]
UseRecords["Store records"]
Results["Return {<br>  'KEV': kev_catalog,<br>  'EPSS': epss_scores,<br>  feed_name: records<br>}"]

LoadAll -.-> LoadKEV
LoadAll -.-> LoadEPSS
LoadAll -.-> FeedLoop
LogError -.-> Results
UseRecords -.-> Results

subgraph subGraph0 ["Load Process"]
    LoadKEV
    LoadEPSS
    FeedLoop
    FeedLoad
    HandleError
    LogError
    UseRecords
    FeedLoop -.-> FeedLoad
    FeedLoad -.->|"No"| HandleError
    HandleError -.->|"Yes"| LogError
    HandleError -.-> UseRecords
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L399-L408](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L399-L408)

### Get All Metadata

The `get_all_metadata()` method collects statistics from all feeds:

```mermaid
flowchart TD

GetMeta["orchestrator.get_all_metadata()"]
KEVMeta["KEV metadata<br>count from load_kev_catalog()"]
EPSSMeta["EPSS metadata<br>count from load_epss_scores()"]
FeedLoop["For each feed in registry:"]
FeedMeta["metadata = feed.get_metadata()"]
HandleError["Get failed?"]
LogError["Log error, skip"]
AddMeta["Add to metadata list"]
Results["Return List[FeedMetadata]"]

GetMeta -.-> KEVMeta
GetMeta -.-> EPSSMeta
GetMeta -.-> FeedLoop
LogError -.-> Results
AddMeta -.-> Results

subgraph subGraph0 ["Metadata Collection"]
    KEVMeta
    EPSSMeta
    FeedLoop
    FeedMeta
    HandleError
    LogError
    AddMeta
    FeedLoop -.-> FeedMeta
    FeedMeta -.->|"No"| HandleError
    HandleError -.->|"Yes"| LogError
    HandleError -.-> AddMeta
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L409-L421](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L409-L421)

---

## Vulnerability Enrichment

The `enrich_vulnerability(identifier, all_feeds)` method provides multi-source intelligence lookup for CVEs or CWEs:

```mermaid
flowchart TD

Enrich["enrich_vulnerability(id, all_feeds)"]
CheckType["ID type?"]
CVELookup["Search for CVE in all feeds"]
KEVCheck["Check KEV catalog"]
EPSSCheck["Check EPSS scores"]
FeedSearch["Search NVD, OSV, GitHub, etc."]
BuildCVE["Build enrichment result"]
CWELookup["Search for CWE in all feeds"]
FilterByCWE["Filter records by cwe_ids field"]
BuildCWE["Build enrichment result"]
Result["Return {<br>  sources: [feed_names],<br>  kev_listed: bool,<br>  epss_score: float,<br>  records: [VulnerabilityRecord]<br>}"]

Enrich -.-> CheckType
CheckType -.->|"CVE-"| CVELookup
CheckType -.->|"CWE-"| CWELookup
BuildCVE -.-> Result
BuildCWE -.-> Result

subgraph subGraph1 ["CWE Enrichment"]
    CWELookup
    FilterByCWE
    BuildCWE
    CWELookup -.-> FilterByCWE
    FilterByCWE -.-> BuildCWE
end

subgraph subGraph0 ["CVE Enrichment"]
    CVELookup
    KEVCheck
    EPSSCheck
    FeedSearch
    BuildCVE
    CVELookup -.-> KEVCheck
    CVELookup -.-> EPSSCheck
    CVELookup -.-> FeedSearch
    KEVCheck -.-> BuildCVE
    EPSSCheck -.-> BuildCVE
    FeedSearch -.-> BuildCVE
end
```

**Enrichment Result Structure**

The enrichment result aggregates intelligence from multiple sources:

```python
{
    "sources": ["NVD", "GitHub", "OSV", "ExploitDB"],  # Feeds with matching data
    "kev_listed": true,                                 # In CISA KEV catalog
    "epss_score": 0.75,                                 # EPSS exploitation probability
    "exploit_references": ["EDB-12345", "MSF-67890"],   # Exploit DB references
    "records": [VulnerabilityRecord(...), ...]          # Full records from each source
}
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L422-L440](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L422-L440)

---

## Feed-Specific Parsing Implementation

### NVD Feed Parsing

The NVD feed extracts CVSS metrics with preference for CVSS v3.1 over v3.0 over v2:

```mermaid
flowchart TD

ParseNVD["NVDFeed.parse_feed(data)"]
CheckV31["cvssMetricV31<br>exists?"]
CheckV30["cvssMetricV30<br>exists?"]
CheckV3["cvssMetricV3<br>exists?"]
CheckV2["cvssMetricV2<br>exists?"]
ExtractV31["Extract baseScore, vectorString<br>from cvssMetricV31"]
ExtractV30["Extract baseScore, vectorString<br>from cvssMetricV30"]
ExtractV3["Extract baseScore, vectorString<br>from cvssMetricV3"]
ExtractV2["Extract baseScore, vectorString<br>from cvssMetricV2"]
NoCVSS["No CVSS data"]
BuildRecord["Build VulnerabilityRecord<br>with cvss_score, cvss_vector"]

ParseNVD -.->|"No"| CheckV31
ExtractV31 -.-> BuildRecord
ExtractV30 -.-> BuildRecord
ExtractV3 -.-> BuildRecord
ExtractV2 -.-> BuildRecord
NoCVSS -.-> BuildRecord

subgraph subGraph0 ["CVSS Extraction Priority"]
    CheckV31
    CheckV30
    CheckV3
    CheckV2
    ExtractV31
    ExtractV30
    ExtractV3
    ExtractV2
    NoCVSS
    CheckV31 -.->|"Yes"| ExtractV31
    CheckV31 -.->|"No"| CheckV30
    CheckV30 -.->|"Yes"| ExtractV30
    CheckV30 -.->|"No"| CheckV3
    CheckV3 -.->|"Yes"| ExtractV3
    CheckV3 -.->|"No"| CheckV2
    CheckV2 -.-> ExtractV2
    CheckV2 -.-> NoCVSS
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L441-L516](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L441-L516)

### GitHub Security Advisories Feed Parsing

The GitHub feed handles advisories with or without CVSS data:

```mermaid
flowchart TD

ParseGitHub["GitHubSecurityAdvisoriesFeed.parse_feed(data)"]
CheckCVSS["CVSS data<br>present?"]
ExtractCVSS["Extract cvss_score, cvss_vector"]
NoCVSS["Use null for CVSS fields"]
ExtractBase["Extract:<br>- id (GHSA-xxx)<br>- summary<br>- severity<br>- published_at"]
BuildRecord["Build VulnerabilityRecord"]

ParseGitHub -.-> CheckCVSS
CheckCVSS -.->|"Yes"| ExtractCVSS
CheckCVSS -.->|"No"| NoCVSS
ExtractCVSS -.-> ExtractBase
NoCVSS -.-> ExtractBase
ExtractBase -.-> BuildRecord
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L517-L560](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L517-L560)

### OSV Feed Parsing

The OSV feed aggregates vulnerabilities across multiple ecosystems:

```mermaid
flowchart TD

ParseOSV["OSVFeed.parse_feed(data)"]
IterEcosystems["For each ecosystem:<br>- npm<br>- PyPI<br>- RubyGems<br>- Go<br>- Maven<br>- etc."]
QueryAPI["Query OSV API<br>for ecosystem"]
ParseRecords["For each vulnerability:<br>- id<br>- summary<br>- affected packages<br>- severity"]
BuildRecord["Build VulnerabilityRecord<br>with ecosystem metadata"]

ParseOSV -.-> IterEcosystems
IterEcosystems -.-> QueryAPI
QueryAPI -.-> ParseRecords
ParseRecords -.-> BuildRecord
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L279-L348](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L279-L348)

---

## Integration with Risk Scoring

The Threat Intelligence Orchestrator feeds data into the risk scoring and decision engines:

```mermaid
flowchart TD

Orchestrator["ThreatIntelligenceOrchestrator"]
AllFeeds["load_all_feeds()"]
Enrich["enrich_vulnerability(cve)"]
RiskScorer["RiskScorer<br>risk/scoring.py"]
EPSSIntegration["EPSS score lookup"]
KEVIntegration["KEV status check"]
EnrichData["Multi-source intelligence"]
DecisionTree["DecisionTreeOrchestrator<br>core/decision_tree.py"]
EnrichmentEvidence["EnrichmentEvidence<br>risk/enrichment.py"]
ForecastResult["ForecastResult<br>risk/forecasting.py"]
ThreatModel["ThreatModelResult<br>risk/threat_model.py"]

Enrich -.-> RiskScorer
EPSSIntegration -.-> DecisionTree
KEVIntegration -.-> DecisionTree
EnrichData -.-> DecisionTree

subgraph subGraph2 ["Decision Engine"]
    DecisionTree
    EnrichmentEvidence
    ForecastResult
    ThreatModel
    DecisionTree -.-> EnrichmentEvidence
    DecisionTree -.-> ForecastResult
    DecisionTree -.-> ThreatModel
end

subgraph subGraph1 ["Risk Scoring Layer"]
    RiskScorer
    EPSSIntegration
    KEVIntegration
    EnrichData
    RiskScorer -.-> EPSSIntegration
    RiskScorer -.-> KEVIntegration
    RiskScorer -.-> EnrichData
end

subgraph subGraph0 ["Threat Intelligence Layer"]
    Orchestrator
    AllFeeds
    Enrich
    Orchestrator -.-> AllFeeds
    AllFeeds -.-> Enrich
end
```

The orchestrator's enrichment data flows into:

1. **EnrichmentEvidence** (`risk/enrichment.py`) - Aggregates KEV status, EPSS scores, ExploitDB references, CVSS data, CWE mappings
2. **ForecastResult** (`risk/forecasting.py`) - Uses EPSS priors and KEV signals for exploitation probability forecasting
3. **ThreatModelResult** (`risk/threat_model.py`) - Incorporates feed data into attack path and reachability analysis
4. **DecisionTreeOrchestrator** (`core/decision_tree.py`) - Coordinates all intelligence sources for final decision verdicts

**Sources:** [core/decision_tree.py L1-L138](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_tree.py#L1-L138)

 [risk/enrichment.py L1-L50](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/enrichment.py#L1-L50)

 [risk/forecasting.py L1-L50](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/forecasting.py#L1-L50)

 [risk/threat_model.py L1-L50](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/threat_model.py#L1-L50)

---

## API Endpoints

The feeds system is exposed through API endpoints for status checks, feed updates, and enrichment queries:

### Feed Status Endpoints

| Method | Endpoint | Handler | File Location | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/feeds/status` | `get_feeds_status` | `apps/api/feeds_router.py` | Get all feed metadata and record counts |
| GET | `/api/v1/feeds/epss` | `get_epss` | `apps/api/feeds_router.py` | Get EPSS scores for all CVEs |
| GET | `/api/v1/feeds/epss/{cve_id}` | `get_epss_score` | `apps/api/feeds_router.py` | Get EPSS score for specific CVE |
| GET | `/api/v1/feeds/kev` | `get_kev` | `apps/api/feeds_router.py` | Get KEV catalog entries |
| GET | `/api/v1/feeds/kev/check/{cve_id}` | `check_kev` | `apps/api/feeds_router.py` | Check if CVE is in KEV |

### Feed Update Endpoints

| Method | Endpoint | Handler | File Location | Purpose |
| --- | --- | --- | --- | --- |
| POST | `/api/v1/feeds/update/epss` | `update_epss_feed_endpoint` | `apps/api/feeds_router.py` | Trigger EPSS feed update |
| POST | `/api/v1/feeds/update/kev` | `update_kev_feed_endpoint` | `apps/api/feeds_router.py` | Trigger KEV feed update |
| POST | `/api/v1/feeds/update/all` | `update_all_feeds_endpoint` | `apps/api/feeds_router.py` | Trigger update for all feeds |

### Enrichment Endpoints

| Method | Endpoint | Handler | File Location | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/feeds/enrich/{cve_id}` | `enrich_cve` | `apps/api/feeds_router.py` | Get multi-source enrichment for CVE |
| POST | `/api/v1/feeds/enrich/batch` | `enrich_batch` | `apps/api/feeds_router.py` | Batch enrichment for multiple CVEs |

**Sources:** [docs/API_CLI_REFERENCE.md L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/API_CLI_REFERENCE.md#L1-L100)

 [docs/FEATURE_CODE_MAPPING.md L488-L505](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/FEATURE_CODE_MAPPING.md#L488-L505)

---

## Error Handling and Resilience

The orchestrator implements multiple resilience patterns:

### Feed Update Resilience

1. **Graceful Degradation**: Failed feed updates don't block other feeds
2. **Fallback Caching**: EPSS uses JSON cache if CSV fetch fails
3. **Partial Success**: `update_all_feeds()` returns success/failure status per feed
4. **Error Logging**: All failures are logged with context but don't raise exceptions

### Load Resilience

1. **Empty List Fallback**: Missing cache files return empty list instead of failing
2. **Exception Handling**: Load errors are caught and logged, allowing other feeds to load
3. **Validation**: Invalid JSON or corrupt data is handled with error returns

### Update Strategy

```mermaid
flowchart TD

FetchCSV["Fetch CSV from source"]
FetchFailed["Network error?"]
CheckJSON["JSON cache<br>exists?"]
UseJSON["Use JSON as source"]
RaiseFail["Raise exception"]
TryUpdate["Try update_feed()"]
UpdateFailed["Exception?"]
LogErr["Log error detail"]
Continue["Continue to next feed"]
RecordFail["Record failure in results"]

subgraph subGraph1 ["EPSS Fallback"]
    FetchCSV
    FetchFailed
    CheckJSON
    UseJSON
    RaiseFail
    FetchCSV -.->|"Yes"| FetchFailed
    FetchFailed -.->|"Yes"| CheckJSON
    CheckJSON -.->|"No"| UseJSON
    CheckJSON -.-> RaiseFail
end

subgraph subGraph0 ["Update Resilience Pattern"]
    TryUpdate
    UpdateFailed
    LogErr
    Continue
    RecordFail
    TryUpdate -.->|"Yes"| UpdateFailed
    UpdateFailed -.->|"No"| LogErr
    UpdateFailed -.-> Continue
    LogErr -.-> RecordFail
    RecordFail -.-> Continue
end
```

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L154-L174](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L154-L174)

 [tests/test_threat_intelligence_comprehensive_coverage.py L390-L421](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L390-L421)

---

## Cache Directory Structure

The feeds system uses a structured cache directory:

```markdown
data/feeds/
├── kev.json                      # CISA KEV catalog (1,422 entries)
├── epss.csv                      # EPSS primary cache (296,333 CVEs)
├── epss.json                     # EPSS JSON fallback cache
├── nvd-cves.json                 # NVD feed cache
├── osv-ecosystems.txt            # OSV ecosystem list
├── github-advisories.json        # GitHub Security Advisories
├── npm-security.json             # NPM advisories
├── pypi-security.json            # PyPI advisories
├── rubysec.json                  # RubyGems advisories
├── rustsec.json                  # Rust crate advisories
├── exploitdb.csv                 # ExploitDB database
├── alienvault-otx.json           # AlienVault OTX pulses
├── vulners.json                  # Vulners database
└── ... (additional ecosystem and vendor feeds)
```

Each feed's cache file follows naming conventions based on the feed class name, converted to lowercase with hyphens.

**Sources:** [tests/test_threat_intelligence_comprehensive_coverage.py L62-L67](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L62-L67)

 [tests/test_threat_intelligence_comprehensive_coverage.py L358-L385](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py#L358-L385)