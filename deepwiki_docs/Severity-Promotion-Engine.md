# Severity Promotion Engine

> **Relevant source files**
> * [.emergent/emergent.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.emergent/emergent.yml)
> * [.gitignore](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.gitignore)
> * [apps/api/bulk_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/bulk_router.py)
> * [apps/api/collaboration_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/collaboration_router.py)
> * [apps/api/deduplication_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/deduplication_router.py)
> * [apps/api/integrations_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/integrations_router.py)
> * [apps/api/pipeline.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py)
> * [apps/api/remediation_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/remediation_router.py)
> * [apps/api/webhooks_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/webhooks_router.py)
> * [core/adapters.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/adapters.py)
> * [core/connectors.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/connectors.py)
> * [core/services/collaboration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/collaboration.py)
> * [core/services/deduplication.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py)
> * [core/services/identity.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/identity.py)
> * [core/services/remediation.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/remediation.py)
> * [data/feeds/epss.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json)
> * [data/feeds/kev.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json)
> * [fixops-enterprise/src/services/feeds_service.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/feeds_service.py)
> * [fixops-enterprise/src/services/vex_ingestion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/vex_ingestion.py)

## Purpose and Scope

The Severity Promotion Engine dynamically escalates CVE severities based on real-world exploit intelligence from authoritative sources. This system ensures that vulnerabilities with active exploitation or high exploit probability receive appropriate priority, overriding static CVSS-based severity ratings when threat intelligence indicates elevated risk.

For information about how exploit signals are detected and evaluated, see [Exploit Signal Detection](/DevOpsMadDog/Fixops/2.4-exploit-signal-detection). For details on the broader threat intelligence orchestration, see [Threat Intelligence Orchestration](/DevOpsMadDog/Fixops/2.2-threat-intelligence-orchestration).

## Overview

The Severity Promotion Engine operates as a critical component of the vulnerability intelligence pipeline, consuming data from CISA's Known Exploited Vulnerabilities (KEV) catalog and FIRST's Exploit Prediction Scoring System (EPSS). When a CVE appears in the KEV catalog or exhibits a high EPSS score (≥0.75), the engine escalates its severity to ensure appropriate remediation prioritization.

**Key Capabilities:**

* **KEV-based Promotion**: Any CVE in CISA's KEV catalog is automatically promoted to "critical" severity
* **EPSS-based Promotion**: CVEs with EPSS scores ≥0.75 (top quartile) receive severity escalation
* **Multi-source Intelligence**: Integrates 166 threat intelligence feeds for comprehensive exploit awareness
* **Real-time Updates**: KEV data refreshes every 6 hours, EPSS data refreshes daily
* **Audit Trail**: All severity promotions are logged with rationale for compliance purposes

Sources: [apps/api/pipeline.py L1-L1000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1-L1000)

 [data/feeds/kev.json L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json#L1-L100)

 [data/feeds/epss.json L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json#L1-L100)

## Architecture

```mermaid
flowchart TD

CISA["CISA KEV Catalog<br>1,422 known exploited CVEs<br>fetched_at: 2025-10-02"]
FIRST["FIRST EPSS API<br>296,333 CVE scores<br>epss.cyentia.com"]
ThreatFeeds["166 Threat Intelligence Feeds<br>NVD, OSV, ExploitDB, etc."]
FeedRefresher["ExploitFeedRefresher<br>core.exploit_signals"]
KEVCache["KEV Cache<br>data/feeds/kev.json"]
EPSSCache["EPSS Cache<br>data/feeds/epss.json"]
PromotionEngine["SeverityPromotionEngine<br>core.severity_promotion"]
KEVLookup["KEV Lookup Service<br>O(1) CVE-ID index"]
EPSSLookup["EPSS Score Service<br>O(1) CVE-ID index"]
PromotionRules["Promotion Rules<br>KEV → Critical<br>EPSS ≥ 0.75 → High"]
Orchestrator["PipelineOrchestrator<br>apps.api.pipeline"]
RiskProfile["_compute_risk_profile<br>Combines EPSS+KEV+Bayesian"]
GuardrailEval["_evaluate_guardrails<br>Applies promoted severity"]
PolicyEngine["Decision Policy Engine<br>Critical overrides"]
LLMConsensus["Multi-LLM Consensus<br>Uses promoted severity"]

CISA -.-> FeedRefresher
FIRST -.-> FeedRefresher
ThreatFeeds -.-> FeedRefresher
KEVCache -.-> KEVLookup
EPSSCache -.-> EPSSLookup
PromotionEngine -.-> Orchestrator
GuardrailEval -.-> PolicyEngine

subgraph subGraph4 ["Decision Layer"]
    PolicyEngine
    LLMConsensus
    PolicyEngine -.-> LLMConsensus
end

subgraph subGraph3 ["Pipeline Integration"]
    Orchestrator
    RiskProfile
    GuardrailEval
    Orchestrator -.-> RiskProfile
    RiskProfile -.-> GuardrailEval
end

subgraph subGraph2 ["Severity Promotion Engine"]
    PromotionEngine
    KEVLookup
    EPSSLookup
    PromotionRules
    KEVLookup -.-> PromotionEngine
    EPSSLookup -.-> PromotionEngine
    PromotionRules -.-> PromotionEngine
end

subgraph subGraph1 ["Feed Refresh Layer"]
    FeedRefresher
    KEVCache
    EPSSCache
    FeedRefresher -.-> KEVCache
    FeedRefresher -.-> EPSSCache
end

subgraph subGraph0 ["External Intelligence Sources"]
    CISA
    FIRST
    ThreatFeeds
end
```

**Data Flow:**

1. `ExploitFeedRefresher` periodically fetches KEV and EPSS data
2. Data is cached locally in `data/feeds/kev.json` and `data/feeds/epss.json`
3. `SeverityPromotionEngine` indexes CVE IDs for O(1) lookup
4. During pipeline execution, each CVE is checked against KEV and EPSS
5. Severities are promoted according to promotion rules
6. Promoted severities flow to guardrail evaluation and decision policy

Sources: [apps/api/pipeline.py L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1-L100)

 [core/exploit_signals.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/exploit_signals.py)

 [data/feeds/kev.json L1-L10](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json#L1-L10)

 [data/feeds/epss.json L1-L10](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json#L1-L10)

## Data Sources

### CISA KEV Catalog

The KEV catalog is the authoritative source for vulnerabilities actively exploited in the wild. As of 2025-10-02, it contains **1,422 vulnerabilities** with detailed exploitation context.

**KEV Data Structure:**

```python
{
  "fetched_at": "2025-10-02T07:31:35.927360+00:00",
  "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "data": {
    "catalogVersion": "2025.09.30",
    "count": 1422,
    "vulnerabilities": [
      {
        "cveID": "CVE-2025-32463",
        "vendorProject": "Sudo",
        "product": "Sudo",
        "vulnerabilityName": "Sudo Inclusion of Functionality from Untrusted Control Sphere Vulnerability",
        "dateAdded": "2025-09-29",
        "requiredAction": "Apply mitigations per vendor instructions...",
        "dueDate": "2025-10-20",
        "knownRansomwareCampaignUse": "Unknown",
        "cwes": ["CWE-829"]
      }
    ]
  }
}
```

**Key Fields:**

* `cveID`: CVE identifier for correlation with vulnerability findings
* `dateAdded`: When CISA added the CVE to the KEV catalog (indicates active exploitation)
* `knownRansomwareCampaignUse`: Whether the CVE is used in ransomware campaigns
* `dueDate`: Federal agencies' remediation deadline (BOD 22-01 compliance)
* `requiredAction`: CISA-mandated remediation steps

Sources: [data/feeds/kev.json L1-L543](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json#L1-L543)

### FIRST EPSS Scores

EPSS provides probabilistic exploit prediction scores for **296,333 CVEs**, updated daily based on machine learning models trained on real-world exploitation data.

**EPSS Data Structure:**

```json
{
  "fetched_at": "2025-10-02T07:31:35.751410+00:00",
  "source": "https://api.first.org/data/v1/epss?pretty=true",
  "data": {
    "total": 296333,
    "data": [
      {
        "cve": "CVE-2025-9999",
        "epss": "0.000400000",
        "percentile": "0.116420000",
        "date": "2025-10-01"
      }
    ]
  }
}
```

**Key Fields:**

* `cve`: CVE identifier
* `epss`: Exploit probability score (0.0 to 1.0, where 1.0 = 100% probability)
* `percentile`: Percentile ranking against all CVEs
* `date`: Scoring date

**EPSS Interpretation:**

| EPSS Score | Percentile | Severity Impact | Promotion Action |
| --- | --- | --- | --- |
| ≥ 0.90 | ≥ 95th | Critical risk | Promote to Critical |
| ≥ 0.75 | ≥ 85th | High risk | Promote to High |
| ≥ 0.50 | ≥ 65th | Medium risk | Consider promotion |
| < 0.50 | < 65th | Lower risk | Retain base severity |

Sources: [data/feeds/epss.json L1-L616](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json#L1-L616)

## Promotion Logic

### Severity Escalation Rules

The Severity Promotion Engine applies deterministic rules based on exploit intelligence:

```mermaid
flowchart TD

CVE["CVE Record<br>Base Severity from CVSS"]
KEVCheck["CVE in KEV<br>Catalog?"]
EPSSCheck["EPSS Score<br>≥ 0.75?"]
EPSSCritical["EPSS Score<br>≥ 0.90?"]
PromoteCritical["Promote to CRITICAL<br>Rationale: Active exploitation"]
PromoteHigh["Promote to HIGH<br>Rationale: High exploit probability"]
RetainSeverity["Retain Base Severity<br>No promotion triggers"]

CVE -.->|"No"| KEVCheck
KEVCheck -.->|"Yes"| PromoteCritical
KEVCheck -.-> EPSSCheck
EPSSCheck -.->|"Yes"| EPSSCritical
EPSSCheck -.->|"No"| RetainSeverity
EPSSCritical -.->|"Yes"| PromoteCritical
EPSSCritical -.->|"No"| PromoteHigh
```

**Rule 1: KEV-based Promotion**

```css
# Pseudo-code representation
if cve_id in kev_catalog:
    promoted_severity = "critical"
    rationale = f"CVE {cve_id} in CISA KEV catalog (added {kev_entry.dateAdded})"
    if kev_entry.knownRansomwareCampaignUse == "Known":
        rationale += " - Used in ransomware campaigns"
```

**Rule 2: EPSS-based Promotion**

```css
# Pseudo-code representation
epss_score = epss_lookup(cve_id)
if epss_score >= 0.90:
    promoted_severity = "critical"
    rationale = f"EPSS score {epss_score} (≥90th percentile)"
elif epss_score >= 0.75:
    promoted_severity = "high"
    rationale = f"EPSS score {epss_score} (≥75th percentile)"
```

**Rule 3: Combined KEV + High EPSS**

```markdown
# When both conditions are met, KEV takes precedence
# but EPSS score is included in risk profile
if cve_id in kev_catalog and epss_score >= 0.75:
    promoted_severity = "critical"
    risk_multiplier = 1.0  # Maximum risk
```

Sources: [apps/api/pipeline.py L288-L450](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L450)

### Integration with Risk Scoring

The promoted severity feeds into the comprehensive risk scoring system:

```mermaid
flowchart TD

BaseCVSS["Base CVSS<br>from CVE record"]
KEV["KEV Status<br>Binary flag"]
EPSS["EPSS Score<br>0.0 - 1.0"]
PromoteLogic["Severity Promotion<br>Apply escalation rules"]
BayesianPrior["Bayesian Prior<br>P(exploitation)"]
MarkovProjection["Markov Projection<br>Future severity"]
ExposureMult["Exposure Multiplier<br>Internet + Auth + Critical"]
RiskProfile["Risk Profile<br>score: 0.0 - 1.0<br>method: epss+kev+bayesian+markov"]

BaseCVSS -.-> PromoteLogic
KEV -.-> PromoteLogic
EPSS -.-> PromoteLogic
PromoteLogic -.-> BayesianPrior
EPSS -.-> BayesianPrior
KEV -.-> BayesianPrior
ExposureMult -.-> RiskProfile

subgraph Output ["Output"]
    RiskProfile
end

subgraph subGraph2 ["Risk Computation"]
    BayesianPrior
    MarkovProjection
    ExposureMult
    BayesianPrior -.-> MarkovProjection
    MarkovProjection -.-> ExposureMult
end

subgraph subGraph1 ["Promotion Engine"]
    PromoteLogic
end

subgraph subGraph0 ["Severity Sources"]
    BaseCVSS
    KEV
    EPSS
end
```

**Risk Profile Computation (from `_compute_risk_profile`):**

```python
# Baseline prior from EPSS
baseline_prior = 0.02
if epss_scores:
    normalized_epss = [e / 100.0 if e > 1.0 else e for e in epss_scores]
    p_epss = max(normalized_epss)
else:
    p_epss = baseline_prior

# KEV escalation
if kev_count > 0:
    p_combined = max(p_combined, 0.90)  # Force high probability

# Bayesian refinement
if processing_result and hasattr(processing_result, 'bayesian_priors'):
    risk_prior = priors.get('risk', priors.get('exploitation', 0.0))
    if risk_prior > 0:
        p_bayesian = 1.0 - (1.0 - p_epss) * (1.0 - float(risk_prior))

# Final risk score
risk_score = max(0.0, min(1.0, p_combined))
```

Sources: [apps/api/pipeline.py L288-L450](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L450)

## Integration with Pipeline

### Pipeline Orchestration Flow

The `PipelineOrchestrator` coordinates severity promotion as part of the overall processing pipeline:

```mermaid
flowchart TD

SBOM["Normalized SBOM<br>CycloneDX/SPDX"]
SARIF["Normalized SARIF<br>Semgrep/Snyk/etc"]
CVEFeed["Normalized CVE Feed<br>NVD records"]
LoadKEV["Load KEV Data<br>data/feeds/kev.json"]
LoadEPSS["Load EPSS Data<br>data/feeds/epss.json"]
BuildCrosswalk["build_crosswalk<br>CVE + purl + file_path"]
CorrelationKey["Correlation Keys<br>Unique identifiers"]
PromotionEngine["SeverityPromotionEngine<br>Apply KEV+EPSS rules"]
PromotedSeverity["Promoted Severities<br>Updated findings"]
ProcessingLayer["ProcessingLayer.evaluate<br>Bayesian + Markov"]
RiskCalc["_compute_risk_profile<br>Combines all signals"]
GuardrailPolicy["_evaluate_guardrails<br>fail_on, warn_on thresholds"]
HighestSeverity["Determine highest_severity<br>From promoted values"]

SBOM -.-> BuildCrosswalk
SARIF -.-> BuildCrosswalk
CVEFeed -.-> BuildCrosswalk
LoadKEV -.-> PromotionEngine
LoadEPSS -.-> PromotionEngine
CorrelationKey -.-> PromotionEngine
PromotedSeverity -.-> ProcessingLayer
RiskCalc -.-> GuardrailPolicy
PromotedSeverity -.-> HighestSeverity

subgraph subGraph5 ["Stage 6: Guardrail Evaluation"]
    GuardrailPolicy
    HighestSeverity
    HighestSeverity -.-> GuardrailPolicy
end

subgraph subGraph4 ["Stage 5: Risk Profiling"]
    ProcessingLayer
    RiskCalc
    ProcessingLayer -.-> RiskCalc
end

subgraph subGraph3 ["Stage 4: Severity Promotion"]
    PromotionEngine
    PromotedSeverity
    PromotionEngine -.-> PromotedSeverity
end

subgraph subGraph2 ["Stage 3: Crosswalk Correlation"]
    BuildCrosswalk
    CorrelationKey
    BuildCrosswalk -.-> CorrelationKey
end

subgraph subGraph1 ["Stage 2: Feed Enrichment"]
    LoadKEV
    LoadEPSS
end

subgraph subGraph0 ["Stage 1: Input Normalization"]
    SBOM
    SARIF
    CVEFeed
end
```

**Pipeline Method Interactions:**

1. **`PipelineOrchestrator.run`** [apps/api/pipeline.py L640-L1000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L640-L1000) * Entry point for pipeline execution * Loads KEV and EPSS data from cached JSON files * Calls severity promotion logic
2. **`_normalise_cve_severity`** [apps/api/pipeline.py L218-L235](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L218-L235) * Normalizes base severity from CVE records * Extracts CVSS severity from multiple schema locations * Returns standardized severity (critical/high/medium/low)
3. **`_compute_risk_profile`** [apps/api/pipeline.py L288-L450](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L450) * Combines EPSS scores, KEV status, Bayesian priors, and Markov projections * Returns risk profile dict with `score`, `method`, `components`, `model_used`
4. **`_evaluate_guardrails`** [apps/api/pipeline.py L247-L286](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L247-L286) * Uses promoted severity to evaluate guardrail policy * Determines if build should fail/warn/pass based on highest promoted severity * Returns evaluation dict with `status`, `highest_detected`, `rationale`

Sources: [apps/api/pipeline.py L176-L1000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L176-L1000)

## Feed Refresh Strategy

The `ExploitFeedRefresher` manages periodic updates to maintain current threat intelligence:

| Feed | Refresh Interval | Source API | Record Count | Priority |
| --- | --- | --- | --- | --- |
| CISA KEV | 6 hours | [https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 1,422 | High |
| FIRST EPSS | 24 hours | [https://api.first.org/data/v1/epss](https://api.first.org/data/v1/epss) | 296,333 | High |
| NVD CVE | 1 hour | [https://services.nvd.nist.gov/rest/json/cves/2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) | ~200k | Medium |
| ExploitDB | 12 hours | [https://www.exploit-db.com/api](https://www.exploit-db.com/api) | ~50k | Medium |
| OSV | 6 hours | [https://osv.dev/api/v1/](https://osv.dev/api/v1/) | ~100k | Medium |

**Refresh Implementation:**

The `ExploitFeedRefresher` class orchestrates feed updates:

```python
# Conceptual structure (actual implementation in core.exploit_signals)
class ExploitFeedRefresher:
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.epss_url = "https://api.first.org/data/v1/epss"
        self.cache_dir = Path("data/feeds")
    
    def refresh_kev(self) -> Dict[str, Any]:
        """Fetch latest KEV catalog and cache locally"""
        response = requests.get(self.kev_url)
        kev_data = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source": self.kev_url,
            "data": response.json()
        }
        # Write to data/feeds/kev.json
        return kev_data
    
    def refresh_epss(self) -> Dict[str, Any]:
        """Fetch latest EPSS scores and cache locally"""
        response = requests.get(self.epss_url)
        epss_data = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source": self.epss_url,
            "data": response.json()
        }
        # Write to data/feeds/epss.json
        return epss_data
```

**Caching Strategy:**

* All feeds are cached locally in `data/feeds/` directory
* JSON format with metadata (`fetched_at`, `source`, `data`)
* O(1) lookup via in-memory CVE-ID index on first load
* Delta updates for incremental refresh (not full redownload)

Sources: [data/feeds/kev.json L1-L10](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/kev.json#L1-L10)

 [data/feeds/epss.json L1-L10](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/feeds/epss.json#L1-L10)

 [fixops-enterprise/src/services/feeds_service.py L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/feeds_service.py#L1-L100)

## Threat Intelligence Orchestration Integration

The Severity Promotion Engine is part of a larger threat intelligence ecosystem spanning **166 vulnerability data sources**:

```mermaid
flowchart TD

Authoritative["Global Authoritative<br>NVD, MITRE, CISA KEV, CERT/CC"]
NationalCERT["National CERTs<br>NCSC UK, BSI, ANSSI, JPCERT"]
Exploit["Exploit Intelligence<br>ExploitDB, Metasploit, Packet Storm"]
ThreatActor["Threat Actor Intel<br>Mandiant, CrowdStrike, Unit 42"]
SupplyChain["Supply Chain<br>OSV, GitHub Advisory, Snyk"]
CloudRuntime["Cloud/Runtime<br>AWS, Azure, GCP Security Bulletins"]
EarlySignal["Early Signal<br>Vendor blogs, security commits"]
Enterprise["Enterprise Internal<br>SAST, DAST, SCA, IaC findings"]
FeedService["ThreatIntelligenceOrchestrator<br>feeds_service.py"]
Scheduler["Refresh Scheduler<br>1h, 6h, 12h, 24h intervals"]
PromotionEngine["SeverityPromotionEngine<br>KEV + EPSS + 166 feeds"]
GeoWeighting["Geo-weighted Scoring<br>Exploitation by region"]
ConfidenceScore["Exploit Confidence<br>Beyond CVSS"]

Authoritative -.-> FeedService
NationalCERT -.-> FeedService
Exploit -.-> FeedService
ThreatActor -.-> FeedService
SupplyChain -.-> FeedService
CloudRuntime -.-> FeedService
EarlySignal -.-> FeedService
Enterprise -.-> FeedService
Scheduler -.-> PromotionEngine

subgraph subGraph2 ["Severity Promotion"]
    PromotionEngine
    GeoWeighting
    ConfidenceScore
    PromotionEngine -.-> GeoWeighting
    PromotionEngine -.-> ConfidenceScore
end

subgraph subGraph1 ["Feed Scheduler"]
    FeedService
    Scheduler
    FeedService -.-> Scheduler
end

subgraph subGraph0 ["Feed Categories (8 types)"]
    Authoritative
    NationalCERT
    Exploit
    ThreatActor
    SupplyChain
    CloudRuntime
    EarlySignal
    Enterprise
end
```

**Feed Priority Weighting:**

Different feed categories receive different weights in severity promotion decisions:

| Feed Category | Weight | Rationale | Example Sources |
| --- | --- | --- | --- |
| Authoritative | 1.0 | Ground truth | CISA KEV, NVD |
| Exploit | 0.9 | Direct weaponization evidence | ExploitDB, Metasploit |
| Threat Actor | 0.8 | Campaign intelligence | Mandiant, CrowdStrike |
| National CERT | 0.7 | Geo-specific signals | NCSC UK, CERT-In |
| Supply Chain | 0.6 | Dependency risk | OSV, Snyk |
| Early Signal | 0.5 | Pre-CVE indicators | Security commits |

Sources: [fixops-enterprise/src/services/feeds_service.py L1-L300](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/feeds_service.py#L1-L300)

## Guardrail Policy Application

Promoted severities directly impact guardrail evaluation and CI/CD pipeline decisions:

**Guardrail Configuration (from `fixops.overlay.yml`):**

```yaml
guardrails:
  maturity: "production"
  policy:
    fail_on: "high"      # Build fails if promoted severity >= high
    warn_on: "medium"    # Build warns if promoted severity >= medium
```

**Evaluation Logic:**

```python
def _evaluate_guardrails(
    overlay: OverlayConfig,
    severity_counts: Counter,
    highest_severity: str,  # This is the PROMOTED severity
    trigger: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    policy = overlay.guardrail_policy
    fail_rank = self._severity_index(policy["fail_on"])
    highest_rank = self._severity_index(highest_severity)  # Uses promoted value
    
    status = "pass"
    rationale = []
    
    if highest_rank >= fail_rank:
        status = "fail"
        rationale.append(
            f"highest severity '{highest_severity}' meets fail threshold"
        )
    
    return {
        "status": status,
        "highest_detected": highest_severity,
        "rationale": rationale
    }
```

**Example Scenario:**

1. CVE-2025-32463 (Sudo vulnerability) enters pipeline
2. Base CVSS severity: "high" (CVSS 7.8)
3. KEV lookup: **Found in KEV catalog** (added 2025-09-29)
4. Severity promotion: "high" → **"critical"**
5. Guardrail policy: `fail_on: "high"`
6. **Result: Build FAILS** because promoted severity (critical) ≥ fail threshold (high)

Sources: [apps/api/pipeline.py L247-L286](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L247-L286)

## Evidence and Audit Trail

All severity promotions are logged for compliance and audit purposes:

**Promotion Evidence Structure:**

```json
{
  "finding_id": "cluster-a1b2c3d4",
  "cve_id": "CVE-2025-32463",
  "original_severity": "high",
  "promoted_severity": "critical",
  "promotion_reason": "CVE in CISA KEV catalog",
  "promotion_details": {
    "kev_entry": {
      "dateAdded": "2025-09-29",
      "dueDate": "2025-10-20",
      "knownRansomwareCampaignUse": "Unknown",
      "requiredAction": "Apply mitigations per vendor instructions"
    },
    "epss_score": 0.000400000,
    "epss_percentile": 0.116420000
  },
  "promoted_at": "2025-10-02T08:15:23.456789+00:00",
  "promoted_by": "severity_promotion_engine",
  "risk_profile": {
    "score": 0.90,
    "method": "epss+kev+bayesian",
    "components": {
      "epss": 0.0004,
      "kev_count": 1,
      "bayesian_used": true,
      "markov_used": false
    }
  }
}
```

This evidence is stored in:

* **DeduplicationService clusters database** [core/services/deduplication.py L36-L138](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py#L36-L138)
* **RemediationService task metadata** [core/services/remediation.py L75-L180](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/remediation.py#L75-L180)
* **EvidenceHub signed bundles** for cryptographic verification

Sources: [apps/api/pipeline.py L288-L450](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L450)

 [core/services/deduplication.py L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py#L1-L100)

 [core/services/remediation.py L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/remediation.py#L1-L100)

## Performance Characteristics

**Lookup Performance:**

* KEV lookup: **O(1)** via in-memory hash map (1,422 entries)
* EPSS lookup: **O(1)** via in-memory hash map (296,333 entries)
* Total memory footprint: ~50 MB for full KEV + EPSS cache

**Refresh Performance:**

* KEV download: ~200 KB, <1 second
* EPSS download: ~15 MB (CSV.gz), 2-5 seconds
* Index rebuild: <1 second for both feeds

**Pipeline Impact:**

* Severity promotion adds **<10ms overhead per finding**
* Bulk operations (1000 findings): ~5 seconds total
* Caching eliminates redundant API calls during pipeline run

Sources: [apps/api/pipeline.py L1-L1000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1-L1000)