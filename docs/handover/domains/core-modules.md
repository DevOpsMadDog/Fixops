# Core Modules Documentation

## Overview

The `core/` directory contains the business logic, CLI commands, and data processing modules for FixOps. This documentation covers all 85 Python files in the core module.

## Module Categories

### Configuration & Runtime

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `configuration.py` | Overlay configuration system | `OverlayConfig`, `load_overlay()` |
| `overlay_runtime.py` | Runtime overlay preparation | `prepare_overlay()` |
| `paths.py` | Secure path handling | `ensure_secure_directory()`, `verify_allowlisted_path()` |
| `logging_config.py` | Logging configuration | Logger setup |

### CLI Commands

| File | Purpose | Key Functions |
|------|---------|---------------|
| `cli.py` | Main CLI entry point | `main()`, `build_parser()`, 25+ command handlers |
| `demo_runner.py` | Demo mode execution | `run_demo_pipeline()` |

### Decision Engine

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `enhanced_decision.py` | Multi-LLM consensus | `EnhancedDecisionEngine` |
| `decision_policy.py` | Policy-based decisions | Decision policy evaluation |
| `decision_tree.py` | Decision tree logic | Decision tree implementation |
| `context_engine.py` | Context-aware decisions | Context engine |

### Processing & Analytics

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `processing_layer.py` | Data processing | `ProcessingLayer` |
| `probabilistic.py` | Bayesian/Markov models | `ProbabilisticForecastEngine` |
| `analytics.py` | Analytics store | `AnalyticsStore` |
| `analytics_db.py` | Analytics database | Database operations |
| `analytics_models.py` | Analytics data models | Data structures |

### Evidence & Compliance

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `evidence.py` | Evidence bundle generation | `EvidenceHub` |
| `evidence_indexer.py` | Evidence indexing | Evidence search |
| `compliance.py` | Compliance framework mapping | Compliance logic |

### Risk & Vulnerability

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `exploit_signals.py` | KEV/EPSS enrichment | `ExploitSignalEvaluator` |
| `severity_promotion.py` | Severity adjustment | Severity promotion logic |
| `exploit_generator.py` | Exploit generation | Exploit code generation |

### Storage & Persistence

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `storage.py` | Artifact archive | `ArtefactArchive` |
| `feedback.py` | Feedback recording | `FeedbackRecorder` |

### Domain-Specific Modules

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `pentagi_db.py` | Pentagi database | SQLite operations |
| `pentagi_models.py` | Pentagi data models | Request/Result models |
| `pentagi_advanced.py` | Advanced pentest | Advanced pentest logic |
| `policy_db.py` | Policy database | SQLite operations |
| `policy_models.py` | Policy data models | Policy structures |
| `policy.py` | Policy engine | Policy evaluation |
| `report_db.py` | Report database | SQLite operations |
| `report_models.py` | Report data models | Report structures |
| `user_db.py` | User database | SQLite operations |
| `user_models.py` | User data models | User structures |
| `audit_db.py` | Audit database | SQLite operations |
| `audit_models.py` | Audit data models | Log entry structures |
| `inventory_db.py` | Inventory database | SQLite operations |
| `inventory_models.py` | Inventory data models | Application/service models |
| `integration_db.py` | Integration database | SQLite operations |
| `integration_models.py` | Integration data models | Integration structures |
| `workflow_db.py` | Workflow database | SQLite operations |
| `workflow_models.py` | Workflow data models | Workflow structures |
| `secrets_db.py` | Secrets database | SQLite operations |
| `secrets_models.py` | Secrets data models | Secret structures |
| `iac_db.py` | IaC database | SQLite operations |
| `iac_models.py` | IaC data models | IaC finding structures |
| `iac.py` | IaC scanning | IaC analysis logic |

### AI & LLM

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `llm_providers.py` | LLM provider abstraction | Provider implementations |
| `ai_agents.py` | AI agent framework | Agent implementations |
| `hallucination_guards.py` | LLM output validation | Guard implementations |
| `model_factory.py` | Model instantiation | Factory pattern |
| `model_registry.py` | Model registration | Registry pattern |

### Models (Subdirectory)

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `models/bayesian_network.py` | Bayesian network | BN implementation |
| `models/bn_lr_hybrid.py` | BN-LR hybrid model | Hybrid risk model |
| `models/weighted_scoring.py` | Weighted scoring | Scoring algorithms |

### Feature Flags

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `flags/base.py` | Base flag provider | `FlagProvider` base class |
| `flags/local_provider.py` | Local flag provider | File-based flags |
| `flags/ld_provider.py` | LaunchDarkly provider | LD integration |
| `flags/combined.py` | Combined provider | Multi-source flags |
| `flags/provider_factory.py` | Provider factory | `create_flag_provider()` |
| `flags/registry.py` | Flag registry | Flag registration |
| `flags/namespace_adapter.py` | Namespace adapter | Namespace handling |

### Services (Subdirectory)

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `services/history.py` | History service | Historical data |
| `services/identity.py` | Identity service | User identity |
| `services/vector_store.py` | Vector store | Embedding storage |

### Other Modules

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `business_context.py` | Business context | Context handling |
| `design_context_injector.py` | Design context | Context injection |
| `sarif_canon.py` | SARIF canonicalization | SARIF normalization |
| `connectors.py` | External connectors | Jira, Slack, etc. |
| `continuous_validation.py` | Continuous validation | Validation logic |
| `onboarding.py` | Onboarding flow | User onboarding |
| `tenancy.py` | Multi-tenancy | Tenant isolation |
| `performance.py` | Performance monitoring | Metrics collection |
| `ssdlc.py` | SSDLC integration | Secure SDLC |
| `modules.py` | Module management | Module loading |
| `stage_runner.py` | Stage execution | `StageRunner` |
| `feature_matrix.py` | Feature matrix | Feature tracking |
| `portfolio_search.py` | Portfolio search | Search functionality |
| `vector_store.py` | Vector store | Embedding operations |
| `oss_fallback.py` | OSS fallback | Open source fallback |
| `bn_lr.py` | BN-LR utilities | Utility functions |
| `automated_remediation.py` | Auto-remediation | Remediation automation |
| `error_responses.py` | Error responses | Error handling |

## CLI Command Reference

### Main Commands

```bash
# Run full pipeline
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --design samples/design.csv \
  --sbom samples/sbom.json \
  --sarif samples/scan.sarif \
  --cve samples/cve.json \
  --output out/pipeline.json

# Run demo mode
python -m core.cli demo --mode demo

# Analyze findings
python -m core.cli analyze --sarif samples/scan.sarif

# Make decision (CI/CD integration)
python -m core.cli make-decision \
  --sbom samples/sbom.json \
  --sarif samples/scan.sarif \
  --cve samples/cve.json

# Get evidence
python -m core.cli get-evidence --run out/pipeline.json

# Copy evidence to handoff directory
python -m core.cli copy-evidence --run out/pipeline.json --target ./handoff/

# Show overlay configuration
python -m core.cli show-overlay --overlay config/fixops.overlay.yml

# Health check
python -m core.cli health --url http://127.0.0.1:8000
```

### Domain Commands

```bash
# Teams management
python -m core.cli teams list
python -m core.cli teams create --name "Security Team"
python -m core.cli teams get --id team-001
python -m core.cli teams delete --id team-001

# Users management
python -m core.cli users list
python -m core.cli users create --email user@example.com --name "John Doe"
python -m core.cli users get --id user-001

# Pentagi (AI pentest)
python -m core.cli pentagi list
python -m core.cli pentagi run --finding-id finding-001
python -m core.cli pentagi results --request-id req-001

# Compliance
python -m core.cli compliance list
python -m core.cli compliance assess --framework soc2
python -m core.cli compliance gaps --framework soc2

# Reports
python -m core.cli reports list
python -m core.cli reports generate --type executive --format pdf
python -m core.cli reports download --id report-001

# Inventory
python -m core.cli inventory list
python -m core.cli inventory add --name "API Gateway" --type service

# Policies
python -m core.cli policies list
python -m core.cli policies create --name "Critical SLA" --type sla

# Integrations
python -m core.cli integrations list
python -m core.cli integrations add --type jira --config config.json

# Analytics
python -m core.cli analytics dashboard
python -m core.cli analytics roi

# Audit
python -m core.cli audit list --limit 100

# Workflows
python -m core.cli workflows list
python -m core.cli workflows create --name "Auto-assign" --trigger finding.created

# Advanced pentest
python -m core.cli advanced-pentest --target https://api.example.com

# Reachability analysis
python -m core.cli reachability analyze --target 10.0.0.0/24

# Train forecast model
python -m core.cli train-forecast --history incidents.json

# BN-LR model commands
python -m core.cli train-bn-lr --data training.json
python -m core.cli predict-bn-lr --model model.pkl --input finding.json
python -m core.cli backtest-bn-lr --model model.pkl --data test.json
```

## Key Classes

### OverlayConfig (`configuration.py`)

```python
class OverlayConfig:
    """Configuration loaded from overlay YAML file."""
    
    mode: str  # "demo" or "enterprise"
    auth: Dict[str, Any]  # Authentication settings
    auth_tokens: Tuple[str, ...]  # Valid API tokens
    modules: Dict[str, Any]  # Module toggles
    required_inputs: List[str]  # Required artifacts
    data_directories: Dict[str, Path]  # Storage paths
    allowed_data_roots: Tuple[Path, ...]  # Allowed paths
    guardrails: Dict[str, Any]  # Guardrail settings
    limits: Dict[str, Any]  # Upload limits
    exploit_signals: Dict[str, Any]  # KEV/EPSS settings
    enhanced_decision_settings: Dict[str, Any]  # LLM settings
    
    def upload_limit(self, stage: str) -> int:
        """Get upload limit for a stage."""
    
    def to_sanitised_dict(self) -> Dict[str, Any]:
        """Return config without secrets."""
```

### PipelineOrchestrator (`apps/api/pipeline.py`)

```python
class PipelineOrchestrator:
    """Orchestrates the security analysis pipeline."""
    
    def run(
        self,
        overlay: OverlayConfig,
        design_dataset: Dict[str, Any],
        sbom: NormalizedSBOM,
        sarif: NormalizedSARIF,
        cve: NormalizedCVEFeed,
        vex: Optional[NormalizedVEX] = None,
        cnapp: Optional[NormalizedCNAPP] = None,
        context: Optional[NormalizedBusinessContext] = None,
    ) -> Dict[str, Any]:
        """Execute full pipeline and return results."""
```

### EnhancedDecisionEngine (`enhanced_decision.py`)

```python
class EnhancedDecisionEngine:
    """Multi-LLM consensus decision engine."""
    
    def __init__(self, settings: Dict[str, Any]):
        """Initialize with LLM provider settings."""
    
    def make_decision(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Get consensus decision from multiple LLMs."""
```

### EvidenceHub (`evidence.py`)

```python
class EvidenceHub:
    """Generates cryptographically-signed evidence bundles."""
    
    def generate_bundle(
        self,
        finding: Dict[str, Any],
        decision: Dict[str, Any],
        signals: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate signed evidence bundle."""
```

### AnalyticsStore (`analytics.py`)

```python
class AnalyticsStore:
    """Stores analytics data and metrics."""
    
    def __init__(self, directory: Path, allowlist: Tuple[Path, ...]):
        """Initialize with storage directory."""
    
    def record_run(self, run_data: Dict[str, Any]) -> None:
        """Record pipeline run metrics."""
    
    def get_roi(self) -> Dict[str, Any]:
        """Calculate ROI metrics."""
```

### ArtefactArchive (`storage.py`)

```python
class ArtefactArchive:
    """Persists normalized artifacts with metadata."""
    
    def __init__(self, directory: Path, allowlist: Tuple[Path, ...]):
        """Initialize with storage directory."""
    
    def persist(
        self,
        stage: str,
        data: Any,
        original_filename: str,
        raw_bytes: bytes,
    ) -> Dict[str, Any]:
        """Persist artifact and return metadata."""
    
    @staticmethod
    def summarise(records: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize archived artifacts."""
```

## Data Flow

### CLI Pipeline Flow

```
1. python -m core.cli run --sbom X --sarif Y --cve Z
   |
2. cli.py:main() parses arguments
   |
3. build_parser() creates argparse parser
   |
4. _handle_run() is called
   |
5. _build_pipeline_result() executes:
   |
   5a. prepare_overlay() loads config
   |
   5b. InputNormalizer() created
   |
   5c. _load_inputs() reads files:
       - _load_design() -> design CSV
       - normalizer.load_sbom() -> NormalizedSBOM
       - normalizer.load_sarif() -> NormalizedSARIF
       - normalizer.load_cve_feed() -> NormalizedCVEFeed
   |
   5d. PipelineOrchestrator() created
   |
   5e. orchestrator.run() executes pipeline:
       - Correlates CVEs with SBOM components
       - Calculates risk scores (BN-LR hybrid)
       - Generates SSVC decisions
       - Creates evidence bundles
   |
6. Result written to --output file
   |
7. Evidence copied to --evidence-dir
```

### Decision Flow

```
1. Finding received from pipeline
   |
2. EnhancedDecisionEngine.make_decision()
   |
3. Query multiple LLM providers:
   - OpenAI GPT-4
   - Anthropic Claude
   - Google Gemini
   - Sentinel (fallback)
   |
4. Aggregate responses with voting
   |
5. Calculate consensus confidence
   |
6. Return decision:
   - verdict: allow/block/defer
   - confidence: 0-1
   - rationale: explanation
   - signals: contributing factors
```

## Module Toggles

Modules can be enabled/disabled via overlay configuration:

```yaml
# config/fixops.overlay.yml
modules:
  guardrails:
    enabled: true
  probabilistic:
    enabled: true
  exploit_signals:
    enabled: true
  enhanced_decision:
    enabled: true
  ai_agents:
    enabled: false
  evidence:
    enabled: true
  policy_automation:
    enabled: false
  compliance:
    enabled: true
  iac_posture:
    enabled: false
  analytics:
    enabled: true
```

Or via CLI flags:

```bash
python -m core.cli run \
  --enable probabilistic \
  --enable compliance \
  --disable ai_agents
```

## Extension Points

### Adding a New CLI Command

1. Add handler function in `cli.py`:
```python
def _handle_mycommand(args: argparse.Namespace) -> int:
    """Handle mycommand."""
    # Implementation
    return 0
```

2. Add subparser in `build_parser()`:
```python
mycommand_parser = subparsers.add_parser("mycommand", help="My command")
mycommand_parser.add_argument("--option", help="Option")
mycommand_parser.set_defaults(func=_handle_mycommand)
```

### Adding a New Module

1. Create `core/{module}_db.py` for database operations
2. Create `core/{module}_models.py` for data models
3. Create `core/{module}.py` for business logic
4. Add module toggle in overlay configuration
5. Integrate with pipeline if needed

### Adding a New LLM Provider

1. Add provider class in `llm_providers.py`
2. Register in `model_registry.py`
3. Add to `EnhancedDecisionEngine` voting
