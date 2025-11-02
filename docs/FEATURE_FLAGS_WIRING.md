# Feature Flag System - Wiring Guide

This document provides concrete examples of how to wire the feature flag system into FixOps components.

## Table of Contents

1. [App Initialization](#app-initialization)
2. [Pipeline Orchestrator](#pipeline-orchestrator)
3. [Decision Engine](#decision-engine)
4. [External Connectors](#external-connectors)
5. [CLI Commands](#cli-commands)
6. [Evidence Generation](#evidence-generation)

---

## App Initialization

### FastAPI App Startup

Wire the flag provider into the FastAPI app at startup:

```python
# apps/api/app.py

from core.flags.provider_factory import create_flag_provider
from core.flags import EvaluationContext

def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(title="FixOps API")
    
    # Load overlay configuration
    overlay = load_overlay()
    
    # Initialize feature flag provider
    flag_provider = create_flag_provider(overlay.raw_config)
    
    # Store in app state for dependency injection
    app.state.flag_provider = flag_provider
    app.state.overlay = overlay
    
    # ... rest of app initialization
    
    return app

# Dependency for flag provider
async def get_flag_provider(request: Request) -> FeatureFlagProvider:
    """Get flag provider from app state."""
    return request.app.state.flag_provider

# Dependency for evaluation context
async def get_flag_context(request: Request) -> EvaluationContext:
    """Build evaluation context from request."""
    return EvaluationContext(
        tenant_id=request.headers.get("X-Tenant-ID"),
        environment=request.app.state.overlay.mode,
        plan=request.headers.get("X-Plan"),
        region=request.headers.get("X-Region"),
        service_name="fixops-api",
        request_id=request.state.correlation_id,
    )
```

### Configuration Integration

Update `core/configuration.py` to include flag provider:

```python
# core/configuration.py

from core.flags.provider_factory import create_flag_provider

class OverlayConfig:
    """Configuration with feature flag support."""
    
    def __init__(self, config_dict: Dict[str, Any]):
        self.raw_config = config_dict
        self._flag_provider = None
        # ... existing initialization
    
    @property
    def flag_provider(self):
        """Lazy-initialize flag provider."""
        if self._flag_provider is None:
            self._flag_provider = create_flag_provider(self.raw_config)
        return self._flag_provider
    
    def is_module_enabled(self, module_name: str, context: Optional[EvaluationContext] = None) -> bool:
        """Check if module is enabled via feature flags."""
        flag_key = f"fixops.module.{module_name}.enabled"
        
        # Try feature flag first
        enabled = self.flag_provider.bool(flag_key, default=True, context=context)
        
        # Fallback to legacy overlay check if flag returns default
        if enabled == True:  # noqa: E712
            legacy_enabled = self.module_matrix.get(module_name, {}).get("enabled", True)
            return legacy_enabled
        
        return enabled
```

---

## Pipeline Orchestrator

### Module Enablement with Flags

Update `apps/api/pipeline.py` to use feature flags:

```python
# apps/api/pipeline.py

from core.flags import EvaluationContext

class PipelineOrchestrator:
    """Pipeline orchestrator with feature flag support."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
    
    async def run(
        self,
        design_records: List[Dict],
        sbom_data: Optional[NormalizedSBOM],
        sarif_data: Optional[NormalizedSARIF],
        cve_feed: Optional[NormalizedCVEFeed],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Execute pipeline with feature flag checks."""
        
        # Check global kill switch
        if self.flag_provider.bool("fixops.ops.kill_switch", False, context):
            return {
                "status": "blocked",
                "reason": "Global kill switch activated",
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        result = {
            "modules": {},
            "flags_evaluated": {},
        }
        
        # Guardrails module
        if self.flag_provider.bool("fixops.module.guardrails.enabled", True, context):
            result["modules"]["guardrails"] = await self._run_guardrails(...)
            result["flags_evaluated"]["fixops.module.guardrails.enabled"] = True
        
        # Compliance module
        if self.flag_provider.bool("fixops.module.compliance.enabled", True, context):
            result["modules"]["compliance"] = await self._run_compliance(...)
            result["flags_evaluated"]["fixops.module.compliance.enabled"] = True
        
        # Policy automation module
        if self.flag_provider.bool("fixops.module.policy_automation.enabled", True, context):
            result["modules"]["policy_automation"] = await self._run_policy_automation(...)
            result["flags_evaluated"]["fixops.module.policy_automation.enabled"] = True
        
        # Evidence module
        if self.flag_provider.bool("fixops.module.evidence.enabled", True, context):
            result["modules"]["evidence"] = await self._run_evidence(...)
            result["flags_evaluated"]["fixops.module.evidence.enabled"] = True
        
        # Exploit signals module
        if self.flag_provider.bool("fixops.module.exploit_signals.enabled", True, context):
            result["modules"]["exploit_signals"] = await self._run_exploit_signals(...)
            result["flags_evaluated"]["fixops.module.exploit_signals.enabled"] = True
        
        # Probabilistic forecasting module
        if self.flag_provider.bool("fixops.module.probabilistic.enabled", True, context):
            result["modules"]["probabilistic"] = await self._run_probabilistic(...)
            result["flags_evaluated"]["fixops.module.probabilistic.enabled"] = True
        
        # Enhanced decision module
        if self.flag_provider.bool("fixops.module.enhanced_decision.enabled", True, context):
            result["modules"]["enhanced_decision"] = await self._run_enhanced_decision(...)
            result["flags_evaluated"]["fixops.module.enhanced_decision.enabled"] = True
        
        # Context engine module
        if self.flag_provider.bool("fixops.module.context_engine.enabled", True, context):
            result["modules"]["context_engine"] = await self._run_context_engine(...)
            result["flags_evaluated"]["fixops.module.context_engine.enabled"] = True
        
        # SSDLC module
        if self.flag_provider.bool("fixops.module.ssdlc.enabled", True, context):
            result["modules"]["ssdlc"] = await self._run_ssdlc(...)
            result["flags_evaluated"]["fixops.module.ssdlc.enabled"] = True
        
        # IaC posture module
        if self.flag_provider.bool("fixops.module.iac_posture.enabled", True, context):
            result["modules"]["iac_posture"] = await self._run_iac_posture(...)
            result["flags_evaluated"]["fixops.module.iac_posture.enabled"] = True
        
        # Analytics module
        if self.flag_provider.bool("fixops.module.analytics.enabled", True, context):
            result["modules"]["analytics"] = await self._run_analytics(...)
            result["flags_evaluated"]["fixops.module.analytics.enabled"] = True
        
        return result
```

---

## Decision Engine

### Risk Model Selection with Flags

Update `fixops-blended-enterprise/src/services/decision_engine.py`:

```python
# fixops-blended-enterprise/src/services/decision_engine.py

from core.flags import EvaluationContext
from core.model_registry import get_registry as get_model_registry

class DecisionEngine:
    """Decision engine with switchable risk models."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
        self.model_registry = get_model_registry()
    
    async def evaluate(
        self,
        findings: List[Dict],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate findings with feature-flagged risk model."""
        
        # Check if risk models are enabled
        if not self.flag_provider.bool("fixops.model.risk.enabled", True, context):
            return self._fallback_evaluation(findings)
        
        # Get risk model via A/B test
        variant = self.flag_provider.variant(
            "fixops.model.risk.ab_test",
            default="control",
            context=context,
        )
        
        # Map variant to model ID
        model_map = {
            "control": "weighted_scoring_v1",
            "treatment": "bn_lr_hybrid_v1",
            "variant_c": "bayesian_network_v1",
        }
        model_id = model_map.get(variant, "weighted_scoring_v1")
        
        # Get model from registry
        model = self.model_registry.get(model_id)
        if not model or not model.metadata.enabled:
            # Fallback to default
            default_id = self.flag_provider.string(
                "fixops.model.risk.default",
                default="weighted_scoring_v1",
                context=context,
            )
            model = self.model_registry.get(default_id)
        
        # Evaluate with selected model
        result = await model.evaluate(findings)
        result["model_id"] = model_id
        result["variant"] = variant
        result["flags_evaluated"] = {
            "fixops.model.risk.enabled": True,
            "fixops.model.risk.ab_test": variant,
        }
        
        return result
```

### LLM Provider Selection with Flags

Update `fixops-blended-enterprise/src/services/enhanced_decision_engine.py`:

```python
# fixops-blended-enterprise/src/services/enhanced_decision_engine.py

from core.flags import EvaluationContext

class EnhancedDecisionEngine:
    """Enhanced decision engine with LLM provider flags."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
    
    async def evaluate(
        self,
        findings: List[Dict],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Evaluate with multi-LLM consensus using feature flags."""
        
        # Determine which LLM providers to use
        providers = []
        
        if self.flag_provider.bool("fixops.feature.llm.openai", True, context):
            providers.append("gpt-5")
        
        if self.flag_provider.bool("fixops.feature.llm.anthropic", True, context):
            providers.append("claude-3")
        
        if self.flag_provider.bool("fixops.feature.llm.google", True, context):
            providers.append("gemini-2")
        
        if self.flag_provider.bool("fixops.feature.llm.sentinel", False, context):
            providers.append("sentinel-cyber")
        
        if not providers:
            return {"error": "No LLM providers enabled"}
        
        # Query all enabled providers
        responses = await self._query_providers(providers, findings)
        
        # Compute consensus
        result = self._compute_consensus(responses)
        result["providers_used"] = providers
        result["flags_evaluated"] = {
            "fixops.feature.llm.openai": "gpt-5" in providers,
            "fixops.feature.llm.anthropic": "claude-3" in providers,
            "fixops.feature.llm.google": "gemini-2" in providers,
            "fixops.feature.llm.sentinel": "sentinel-cyber" in providers,
        }
        
        return result
```

---

## External Connectors

### Circuit Breaker with Flags

Update `core/policy.py`:

```python
# core/policy.py

from core.flags import EvaluationContext

class PolicyEngine:
    """Policy engine with feature-flagged connectors."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
        self._circuit_breakers = {}
    
    async def execute_action(
        self,
        action: str,
        payload: Dict,
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        """Execute policy action with feature flag checks."""
        
        # Check circuit breaker flag
        if self.flag_provider.bool("fixops.ops.connector.circuit_breaker", True, context):
            if self._is_circuit_open(action):
                return {
                    "status": "skipped",
                    "reason": f"Circuit breaker open for {action}",
                }
        
        # Check connector-specific flags
        if action.startswith("jira:"):
            if not self.flag_provider.bool("fixops.feature.connector.jira", True, context):
                return {"status": "skipped", "reason": "Jira connector disabled"}
            return await self._execute_jira_action(action, payload)
        
        elif action.startswith("confluence:"):
            if not self.flag_provider.bool("fixops.feature.connector.confluence", True, context):
                return {"status": "skipped", "reason": "Confluence connector disabled"}
            return await self._execute_confluence_action(action, payload)
        
        elif action.startswith("slack:"):
            if not self.flag_provider.bool("fixops.feature.connector.slack", True, context):
                return {"status": "skipped", "reason": "Slack connector disabled"}
            return await self._execute_slack_action(action, payload)
        
        return {"status": "error", "reason": f"Unknown action: {action}"}
```

---

## CLI Commands

### CLI with Feature Flags

Update `core/cli.py`:

```python
# core/cli.py

from core.flags import EvaluationContext
from core.flags.provider_factory import create_flag_provider

def _handle_run(args):
    """Handle run command with feature flags."""
    
    # Load overlay
    overlay = load_overlay(args.overlay)
    
    # Create evaluation context
    context = EvaluationContext(
        environment=overlay.mode,
        service_name="fixops-cli",
    )
    
    # Check offline mode flag
    if overlay.flag_provider.bool("fixops.cli.offline_mode", False, context):
        print("Running in offline mode (no external API calls)")
        # Disable feed refresh, external connectors, etc.
    
    # Check dry-run flag
    if overlay.flag_provider.bool("fixops.ops.dry_run", False, context):
        print("Running in dry-run mode (no side effects)")
        # Skip evidence persistence, connector actions, etc.
    
    # Run pipeline with context
    result = run_pipeline(
        overlay=overlay,
        design_file=args.design,
        sbom_file=args.sbom,
        sarif_file=args.sarif,
        cve_file=args.cve,
        context=context,
    )
    
    # Include evaluated flags in output
    if args.verbose:
        print(f"Flags evaluated: {result.get('flags_evaluated', {})}")
    
    return result
```

---

## Evidence Generation

### Evidence with Flag Metadata

Update `core/evidence.py`:

```python
# core/evidence.py

from core.flags import EvaluationContext

class EvidenceHub:
    """Evidence hub with feature flag metadata."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
    
    async def persist(
        self,
        verdict: str,
        findings: List[Dict],
        metadata: Dict,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Persist evidence with flag metadata."""
        
        # Check if evidence encryption is enabled
        encrypt = self.flag_provider.bool(
            "fixops.feature.evidence.encryption",
            False,
            context,
        )
        
        # Get retention period
        retention_days = self.flag_provider.number(
            "fixops.feature.evidence.retention_days",
            90,
            context,
        )
        
        # Build evidence bundle
        evidence = {
            "verdict": verdict,
            "findings": findings,
            "metadata": metadata,
            "flags_evaluated": {
                "fixops.feature.evidence.encryption": encrypt,
                "fixops.feature.evidence.retention_days": retention_days,
            },
            "context": context.to_dict() if context else {},
            "timestamp": datetime.utcnow().isoformat(),
            "retention_until": (
                datetime.utcnow() + timedelta(days=retention_days)
            ).isoformat(),
        }
        
        # Persist with optional encryption
        if encrypt:
            bundle_path = await self._persist_encrypted(evidence)
        else:
            bundle_path = await self._persist_plaintext(evidence)
        
        return bundle_path
```

---

## Testing Integration

### Test with FakeFlagProvider

```python
# tests/test_pipeline.py

from core.flags.base import FeatureFlagProvider, EvaluationContext

class FakeFlagProvider(FeatureFlagProvider):
    """Deterministic provider for testing."""
    
    def __init__(self, flags: dict):
        self.flags = flags
    
    def bool(self, key: str, default: bool, context=None) -> bool:
        return self.flags.get(key, default)
    
    # ... implement other methods

def test_pipeline_with_flags_disabled():
    """Test pipeline with all modules disabled."""
    
    # Create fake provider with all modules disabled
    fake_provider = FakeFlagProvider({
        "fixops.module.guardrails.enabled": False,
        "fixops.module.compliance.enabled": False,
        "fixops.module.policy_automation.enabled": False,
    })
    
    # Inject into overlay
    overlay = load_overlay()
    overlay._flag_provider = fake_provider
    
    # Run pipeline
    orchestrator = PipelineOrchestrator(overlay)
    result = await orchestrator.run(...)
    
    # Verify no modules ran
    assert "guardrails" not in result["modules"]
    assert "compliance" not in result["modules"]
    assert "policy_automation" not in result["modules"]

def test_pipeline_with_kill_switch():
    """Test pipeline with global kill switch."""
    
    fake_provider = FakeFlagProvider({
        "fixops.ops.kill_switch": True,
    })
    
    overlay = load_overlay()
    overlay._flag_provider = fake_provider
    
    orchestrator = PipelineOrchestrator(overlay)
    result = await orchestrator.run(...)
    
    assert result["status"] == "blocked"
    assert "kill switch" in result["reason"].lower()
```

---

## Branding & Customization

### Dynamic Product Branding

Wire branding flags into high-impact UX touchpoints to enable dynamic rebranding (e.g., "FixOps" → "Aldeci").

#### FastAPI App Branding

Update `apps/api/app.py` to use branding flags:

```python
# apps/api/app.py

from core.flags.provider_factory import create_flag_provider

def create_app() -> FastAPI:
    """Create and configure FastAPI application with dynamic branding."""
    
    # Load overlay configuration
    overlay = load_overlay()
    
    # Initialize feature flag provider
    flag_provider = create_flag_provider(overlay.raw_config)
    
    # Resolve branding once at startup (cached)
    branding = flag_provider.json("fixops.branding", default={
        "product_name": "FixOps",
        "short_name": "FixOps",
        "org_name": "FixOps",
        "support_url": "",
        "privacy_url": "",
        "legal_name": "FixOps",
        "telemetry_namespace": "fixops",
    })
    
    # Create app with branded title/description
    app = FastAPI(
        title=f"{branding['product_name']} API",
        description=f"Security decision engine by {branding['org_name']}",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    # Store branding in app state for request handlers
    app.state.branding = branding
    app.state.flag_provider = flag_provider
    app.state.overlay = overlay
    
    # Add middleware to inject X-Product-Name header
    @app.middleware("http")
    async def add_product_header(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Product-Name"] = branding["product_name"]
        response.headers["X-Product-Version"] = "1.0.0"
        return response
    
    # ... rest of app initialization
    
    return app

# Use branding in endpoints
@app.get("/")
async def root(request: Request):
    """Root endpoint with branded response."""
    branding = request.app.state.branding
    return {
        "product": branding["product_name"],
        "organization": branding["org_name"],
        "support_url": branding["support_url"],
        "privacy_url": branding["privacy_url"],
    }
```

#### CLI Branding

Update `core/cli.py` to use branding flags:

```python
# core/cli.py

from core.flags.provider_factory import create_flag_provider

def print_banner(overlay: OverlayConfig):
    """Print branded CLI banner."""
    
    # Get branding config
    branding = overlay.flag_provider.json("fixops.branding", default={
        "product_name": "FixOps",
        "short_name": "FixOps",
    })
    
    product_name = branding["product_name"]
    short_name = branding["short_name"]
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   {product_name:^53}   ║
║   Security Decision & Verification Engine                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
""")

def _handle_run(args):
    """Handle run command with branded output."""
    
    # Load overlay
    overlay = load_overlay(args.overlay)
    
    # Print branded banner
    print_banner(overlay)
    
    # Get branding for output
    branding = overlay.flag_provider.json("fixops.branding", default={
        "product_name": "FixOps",
    })
    
    # Run pipeline
    result = run_pipeline(...)
    
    # Print branded summary
    print(f"\n{branding['product_name']} Pipeline Summary:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Findings: {len(result['findings'])}")
    
    return result

def _handle_demo(args):
    """Handle demo command with branded output."""
    
    overlay = load_overlay_for_mode(args.mode)
    
    # Print branded banner
    print_banner(overlay)
    
    branding = overlay.flag_provider.json("fixops.branding", default={
        "product_name": "FixOps",
    })
    
    print(f"\n{branding['product_name']} Demo Mode: {args.mode}")
    print("=" * 60)
    
    # ... rest of demo logic
```

#### Evidence Bundle Branding

Update `core/evidence.py` to use branding in producer metadata:

```python
# core/evidence.py

from core.flags import EvaluationContext

class EvidenceHub:
    """Evidence hub with branded producer metadata."""
    
    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.flag_provider = overlay.flag_provider
        
        # Resolve branding once at initialization
        self.branding = self.flag_provider.json("fixops.branding", default={
            "product_name": "FixOps",
            "legal_name": "FixOps",
        })
    
    async def persist(
        self,
        verdict: str,
        findings: List[Dict],
        metadata: Dict,
        context: Optional[EvaluationContext] = None,
    ) -> str:
        """Persist evidence with branded producer metadata."""
        
        # Build evidence bundle with branded producer
        evidence = {
            "verdict": verdict,
            "findings": findings,
            "metadata": metadata,
            "producer": {
                "name": self.branding["product_name"],
                "legal_name": self.branding["legal_name"],
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat(),
            },
            "context": context.to_dict() if context else {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Sign and persist
        bundle_path = await self._persist_signed(evidence)
        
        return bundle_path
```

#### Telemetry Namespace Branding

Update telemetry configuration to use branded namespace:

```python
# fixops-blended-enterprise/src/services/metrics.py

from core.flags.provider_factory import create_flag_provider

class FixOpsMetrics:
    """Metrics with branded telemetry namespace."""
    
    _branding = None
    
    @classmethod
    def initialize(cls, overlay: OverlayConfig):
        """Initialize metrics with branded namespace."""
        cls._branding = overlay.flag_provider.json("fixops.branding", default={
            "telemetry_namespace": "fixops",
        })
    
    @classmethod
    def get_namespace(cls) -> str:
        """Get branded telemetry namespace."""
        if cls._branding:
            return cls._branding["telemetry_namespace"]
        return "fixops"
    
    @classmethod
    def record_latency(cls, operation: str, latency_ms: float):
        """Record latency with branded namespace."""
        namespace = cls.get_namespace()
        metric_name = f"{namespace}.{operation}.latency_ms"
        # ... record metric

# In app initialization
def create_app() -> FastAPI:
    overlay = load_overlay()
    FixOpsMetrics.initialize(overlay)
    # ... rest of initialization
```

#### Frontend Branding (React)

Update React frontend to use branding from API:

```javascript
// fixops-blended-enterprise/frontend/src/App.jsx

import { useEffect, useState } from 'react';

function App() {
  const [branding, setBranding] = useState({
    product_name: 'FixOps',
    logo_url: '',
    primary_color: '#0f62fe',
  });
  
  useEffect(() => {
    // Fetch branding from API
    fetch('/api/v1/branding')
      .then(res => res.json())
      .then(data => setBranding(data))
      .catch(err => console.error('Failed to load branding:', err));
  }, []);
  
  return (
    <div className="app" style={{ '--primary-color': branding.primary_color }}>
      <header>
        {branding.logo_url && (
          <img src={branding.logo_url} alt={branding.product_name} />
        )}
        <h1>{branding.product_name}</h1>
      </header>
      {/* ... rest of app */}
    </div>
  );
}

// Add API endpoint to serve branding
// apps/api/app.py

@app.get("/api/v1/branding")
async def get_branding(request: Request):
    """Get branding configuration for frontend."""
    branding = request.app.state.branding
    return {
        "product_name": branding["product_name"],
        "short_name": branding["short_name"],
        "logo_url": branding["logo_url"],
        "favicon_url": branding["favicon_url"],
        "primary_color": branding["primary_color"],
        "secondary_color": branding["secondary_color"],
        "org_name": branding["org_name"],
        "support_url": branding["support_url"],
        "privacy_url": branding["privacy_url"],
    }
```

### Branding Best Practices

1. **Cache at Startup**: Resolve branding once during app initialization, not on every request
2. **UX Strings Only**: Don't try to rename package names, module paths, or binary names
3. **Consistent Naming**: Use `product_name` consistently across API, CLI, evidence, and telemetry
4. **Fallback Defaults**: Always provide sensible defaults in case flags are unavailable
5. **Testing**: Use FakeFlagProvider to test different branding configurations

### Example: Rebrand to "Aldeci"

To rebrand the entire product to "Aldeci", add to `config/fixops.overlay.yml`:

```yaml
feature_flags:
  fixops.branding:
    product_name: "Aldeci"
    short_name: "Aldeci"
    logo_url: "https://cdn.example.com/aldeci/logo.svg"
    favicon_url: "https://cdn.example.com/aldeci/favicon.ico"
    primary_color: "#6B5AED"
    secondary_color: "#0F172A"
    org_name: "Aldeci Inc."
    support_url: "https://support.aldeci.com"
    privacy_url: "https://aldeci.com/privacy"
    legal_name: "Aldeci Inc."
    telemetry_namespace: "aldeci"
```

This will update:
- API title/description: "Aldeci API"
- CLI banner: "Aldeci Security Decision & Verification Engine"
- Evidence producer: `{"name": "Aldeci", "legal_name": "Aldeci Inc."}`
- Telemetry namespace: `aldeci.pipeline.latency_ms`
- Response headers: `X-Product-Name: Aldeci`

---

## Summary

This wiring guide demonstrates how to integrate the feature flag system into:

1. **App Initialization**: FastAPI startup with dependency injection
2. **Pipeline Orchestrator**: Module enablement with per-request context
3. **Decision Engine**: Risk model selection via A/B testing
4. **External Connectors**: Circuit breakers and connector toggles
5. **CLI Commands**: Offline mode and dry-run flags
6. **Evidence Generation**: Encryption and retention flags
7. **Branding & Customization**: Dynamic product rebranding (FixOps → Aldeci)

For complete examples, see:
- `docs/FEATURE_FLAGS.md` - Usage guide
- `config/feature_flags.example.yml` - Configuration examples
- `tests/test_flags.py` - Test examples
