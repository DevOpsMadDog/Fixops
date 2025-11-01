# FixOps Feature Flag System

## Overview

FixOps uses a comprehensive, LaunchDarkly-compatible feature flag system that enables:

- **Dynamic feature control** without code deployments
- **Gradual rollouts** with percentage-based targeting
- **A/B testing** with multi-variant experiments
- **Per-tenant targeting** based on plan, environment, region, etc.
- **Graceful fallback** from LaunchDarkly → Local Overlay → Registry Defaults

## Architecture

### Provider Stack

The feature flag system uses a layered provider architecture:

```
┌─────────────────────────────────────┐
│   Application Code                  │
│   (calls provider.bool/string/etc)  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   CombinedProvider                  │
│   (orchestrates fallback chain)     │
└──────────────┬──────────────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
┌──────────────┐  ┌──────────────┐
│ LaunchDarkly │  │ Local Overlay│
│ Provider     │  │ Provider     │
│ (primary)    │  │ (fallback)   │
└──────────────┘  └──────────────┘
        │             │
        └──────┬──────┘
               ▼
        ┌──────────────┐
        │   Registry   │
        │   Defaults   │
        └──────────────┘
```

### Evaluation Flow

1. **Primary (LaunchDarkly)**: If available and not offline, evaluate flag via LaunchDarkly SDK
2. **Fallback (Local Overlay)**: If LD unavailable or returns error, use local `fixops.overlay.yml`
3. **Default (Registry)**: If both fail, use hardcoded default from flag registry

## Configuration

### Local Overlay Configuration

Add a `feature_flags` section to your `config/fixops.overlay.yml`:

```yaml
feature_flags:
  # Simple boolean flags
  fixops.module.guardrails.enabled: true
  
  # Percentage-based rollouts
  fixops.feature.llm.sentinel:
    percentage: 50
    value: true
    hash_key: tenant_id
  
  # Multi-variant experiments
  fixops.model.risk.ab_test:
    variants:
      control: 50
      treatment: 30
      variant_c: 20
    hash_key: tenant_id
```

### LaunchDarkly Configuration

Set environment variables:

```bash
# Required for LaunchDarkly
export LAUNCHDARKLY_SDK_KEY="sdk-key-123..."

# Optional: Disable LaunchDarkly (use local only)
export LAUNCHDARKLY_DISABLED=1

# Optional: Force offline mode (for CI/testing)
export LAUNCHDARKLY_OFFLINE=1
```

## Usage

### Basic Flag Evaluation

```python
from core.flags import create_flag_provider, EvaluationContext

# Initialize provider (typically done at app startup)
provider = create_flag_provider(overlay_config)

# Simple boolean flag
if provider.bool("fixops.module.guardrails.enabled", default=True):
    # Run guardrails module
    pass

# String flag
model_id = provider.string("fixops.model.risk.default", default="weighted_scoring_v1")

# Numeric flag
retention_days = provider.number("fixops.feature.evidence.retention_days", default=90)

# JSON flag
config = provider.json("fixops.module.compliance.config", default={})

# Multi-variant flag (for A/B testing)
variant = provider.variant("fixops.model.risk.ab_test", default="control")
```

### Evaluation Context for Targeting

```python
from core.flags import EvaluationContext

# Create context with targeting attributes
context = EvaluationContext(
    tenant_id="acme-corp",
    environment="production",
    plan="enterprise",
    region="us-east-1",
    service_name="fixops-api",
)

# Evaluate flag with context (enables per-tenant targeting)
enabled = provider.bool(
    "fixops.entitle.multi_llm_consensus",
    default=False,
    context=context,
)
```

### Request-Scoped Context (FastAPI)

```python
from fastapi import Request
from core.flags import EvaluationContext

async def get_flag_context(request: Request) -> EvaluationContext:
    """Extract evaluation context from request."""
    return EvaluationContext(
        tenant_id=request.headers.get("X-Tenant-ID"),
        environment=app.state.overlay.mode,
        plan=request.headers.get("X-Plan"),
        request_id=request.state.correlation_id,
    )

@app.post("/pipeline/run")
async def run_pipeline(
    request: Request,
    context: EvaluationContext = Depends(get_flag_context),
):
    provider = request.app.state.flag_provider
    
    # Evaluate flags with request context
    if provider.bool("fixops.module.guardrails.enabled", True, context):
        # Run guardrails
        pass
```

## Flag Registry

All feature flags are registered in `core/flags/registry.py` with metadata:

```python
from core.flags.registry import FlagMetadata, FlagType, get_registry

# Register a new flag
registry = get_registry()
registry.register(FlagMetadata(
    key="fixops.feature.new_capability",
    flag_type=FlagType.BOOL,
    default=False,
    description="Enable new capability",
    owner="platform-team",
    tags=["feature", "preview"],
    expiry="2026-12-31",  # When to remove this flag
))
```

### Flag Naming Convention

Flags follow a hierarchical naming convention:

- **Module toggles**: `fixops.module.<name>.enabled`
- **Feature toggles**: `fixops.feature.<area>.<capability>`
- **Operational toggles**: `fixops.ops.<area>.<toggle>`
- **Experiments**: `fixops.exp.<area>.<name>`
- **Entitlements**: `fixops.entitle.<feature>`

## Percentage Rollouts

Percentage-based rollouts use consistent hashing to ensure stable assignments:

```yaml
feature_flags:
  fixops.feature.llm.sentinel:
    percentage: 25  # 25% of tenants get this feature
    value: true
    hash_key: tenant_id  # Hash on tenant_id for consistency
```

The same tenant will always get the same assignment (deterministic).

### Hash Keys

- `tenant_id`: Per-tenant rollout (recommended)
- `user_email`: Per-user rollout
- `cve_id`: Per-CVE rollout
- `component_id`: Per-component rollout
- `request_id`: Per-request rollout (non-deterministic)

## Multi-Variant Experiments

A/B/C testing with multiple variants:

```yaml
feature_flags:
  fixops.model.risk.ab_test:
    variants:
      control: 50        # 50% get control
      treatment_a: 30    # 30% get treatment A
      treatment_b: 20    # 20% get treatment B
    hash_key: tenant_id
```

Usage:

```python
variant = provider.variant("fixops.model.risk.ab_test", default="control", context=context)

if variant == "control":
    model = "weighted_scoring_v1"
elif variant == "treatment_a":
    model = "bayesian_network_v1"
elif variant == "treatment_b":
    model = "bn_lr_hybrid_v1"
```

## LaunchDarkly Integration

### Setup

1. Install LaunchDarkly SDK:
   ```bash
   pip install launchdarkly-server-sdk
   ```

2. Set SDK key:
   ```bash
   export LAUNCHDARKLY_SDK_KEY="sdk-key-123..."
   ```

3. Create flags in LaunchDarkly dashboard with same keys as registry

### Targeting Rules

In LaunchDarkly dashboard, create targeting rules:

- **Per-tenant**: `tenant_id = "acme-corp"` → serve variant "treatment"
- **Per-plan**: `plan = "enterprise"` → enable feature
- **Per-region**: `region = "eu-west-1"` → enable compliance framework
- **Per-environment**: `environment = "production"` → disable preview features

### PII Redaction

The LaunchDarkly provider automatically redacts PII:

- ✅ Included: `tenant_id`, `environment`, `region`, `plan`, `service_name`
- ❌ Excluded: `user_email`, `cve_id`, `component_id` (PII)

If you need to target by user, hash the email first:

```python
import hashlib

context = EvaluationContext(
    tenant_id="acme-corp",
    custom={"user_hash": hashlib.sha256(user_email.encode()).hexdigest()},
)
```

## Testing

### FakeFlagProvider for Tests

```python
from core.flags.base import FeatureFlagProvider, EvaluationContext

class FakeFlagProvider(FeatureFlagProvider):
    """Deterministic provider for testing."""
    
    def __init__(self, flags: dict):
        self.flags = flags
    
    def bool(self, key: str, default: bool, context=None) -> bool:
        return self.flags.get(key, default)
    
    # ... implement other methods

# In tests
provider = FakeFlagProvider({
    "fixops.module.guardrails.enabled": True,
    "fixops.feature.llm.sentinel": False,
})

assert provider.bool("fixops.module.guardrails.enabled", False) == True
```

### CI/Testing

In CI, the system automatically runs in offline mode (no LaunchDarkly network calls):

```bash
# Automatically set in CI environments
export LAUNCHDARKLY_OFFLINE=1
```

## Best Practices

### 1. Always Use Registry

Register all flags in `core/flags/registry.py` with metadata:

```python
registry.register(FlagMetadata(
    key="fixops.feature.new_capability",
    flag_type=FlagType.BOOL,
    default=False,
    description="Enable new capability",
    owner="platform-team",
    tags=["feature"],
    expiry="2026-12-31",  # Set expiry date
))
```

### 2. Set Expiry Dates

All flags should have an expiry date. Expired flags should be removed from code.

### 3. Cache Per-Request

Don't evaluate flags in tight loops. Cache per-request or per-stage:

```python
# ❌ Bad: Evaluate in loop
for item in items:
    if provider.bool("fixops.feature.x", False, context):
        process(item)

# ✅ Good: Evaluate once, cache result
feature_enabled = provider.bool("fixops.feature.x", False, context)
for item in items:
    if feature_enabled:
        process(item)
```

### 4. Include in Evidence

Record evaluated flags in evidence bundles for audit trails:

```python
evidence = {
    "verdict": "allow",
    "flags_evaluated": {
        "fixops.module.guardrails.enabled": True,
        "fixops.model.risk.ab_test": "treatment",
    },
}
```

### 5. Monitor Flag Usage

Add metrics for flag evaluations:

```python
from core.analytics import AnalyticsStore

analytics.increment(f"flag.{key}.{value}")
analytics.increment(f"flag.{key}.variant.{variant}")
```

## Governance

### Flag Lifecycle

1. **Creation**: Register in registry with owner and expiry
2. **Rollout**: Start at 0%, gradually increase to 100%
3. **Stabilization**: Monitor for 30 days at 100%
4. **Cleanup**: Remove flag from code, update registry
5. **Archival**: Document decision in CHANGELOG.md

### Ownership

Each flag must have an owner (team or person) responsible for:

- Monitoring flag usage
- Deciding when to increase rollout percentage
- Cleaning up flag after stabilization

### Expiry Policy

- **Experiments**: 90 days max
- **Operational toggles**: No expiry (permanent)
- **Feature toggles**: 180 days max (should become permanent or removed)
- **Preview features**: 365 days max

## Troubleshooting

### Flag Not Working

1. Check flag key spelling (case-sensitive)
2. Verify flag is registered in registry
3. Check LaunchDarkly dashboard for targeting rules
4. Verify evaluation context has required attributes
5. Check logs for provider errors

### LaunchDarkly Not Connecting

1. Verify `LAUNCHDARKLY_SDK_KEY` is set
2. Check network connectivity
3. Verify SDK is installed: `pip list | grep launchdarkly`
4. Check logs for initialization errors
5. Try offline mode: `export LAUNCHDARKLY_OFFLINE=1`

### Inconsistent Rollout

1. Verify `hash_key` is set correctly
2. Check that hash input (e.g., `tenant_id`) is stable
3. Verify percentage adds up to 100 for variants
4. Check LaunchDarkly dashboard for conflicting rules

## Migration Guide

### From Overlay Toggles to Feature Flags

**Before:**
```python
if overlay.is_module_enabled("guardrails"):
    run_guardrails()
```

**After:**
```python
if provider.bool("fixops.module.guardrails.enabled", True, context):
    run_guardrails()
```

### From Hardcoded Config to Flags

**Before:**
```python
RETENTION_DAYS = 90
```

**After:**
```python
retention_days = provider.number(
    "fixops.feature.evidence.retention_days",
    default=90,
    context=context,
)
```

## Branding & Customization

### Dynamic Product Branding

FixOps supports dynamic branding via feature flags, allowing you to rebrand the product (e.g., from "FixOps" to "Aldeci") without code changes.

**Available branding flags:**

1. **Simple name override**: `fixops.branding.product_name` (string)
2. **Full branding config**: `fixops.branding` (json)

### Branding Configuration

```yaml
feature_flags:
  # Simple product name override
  fixops.branding.product_name: "Aldeci"
  
  # Full branding configuration
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

### What Gets Branded

Branding flags update:

- **API**: FastAPI title/description, `X-Product-Name` response header
- **CLI**: Banner text, summary output
- **Evidence bundles**: Producer name field
- **Telemetry**: Namespace for metrics/traces

### What Doesn't Change

**Important**: Branding flags change UX strings only, not:
- Package names (`pip install fixops` remains the same)
- Module paths (`from core.flags import ...` remains the same)
- Repository name or folder structure
- Binary/executable names

### Usage Example

```python
from core.flags import create_flag_provider

# Initialize provider
provider = create_flag_provider(overlay_config)

# Get branding config
branding = provider.json("fixops.branding", default={
    "product_name": "FixOps",
    "telemetry_namespace": "fixops",
})

# Use in API
app = FastAPI(
    title=f"{branding['product_name']} API",
    description=f"Security decision engine by {branding['org_name']}",
)

# Use in CLI
print(f"=== {branding['product_name']} Pipeline ===")

# Use in evidence
evidence = {
    "producer": {
        "name": branding['product_name'],
        "version": "1.0.0",
    }
}

# Use in telemetry
tracer = trace.get_tracer(branding['telemetry_namespace'])
```

### Caching Branding

**Best practice**: Resolve branding once at startup, not on every request:

```python
# At app startup
app.state.branding = provider.json("fixops.branding", default={...})

# In request handlers
@app.get("/")
async def root(request: Request):
    branding = request.app.state.branding
    return {"product": branding["product_name"]}
```

## Examples

See `config/feature_flags.example.yml` for comprehensive examples of:

- Simple boolean flags
- Percentage-based rollouts
- Multi-variant experiments
- Per-tenant targeting
- Branding/rebranding (FixOps → Aldeci)

## Support

For questions or issues with the feature flag system:

1. Check this documentation
2. Review flag registry in `core/flags/registry.py`
3. Check LaunchDarkly dashboard
4. Contact platform-team

## References

- [LaunchDarkly Python SDK](https://docs.launchdarkly.com/sdk/server-side/python)
- [Feature Flag Best Practices](https://launchdarkly.com/blog/feature-flag-best-practices/)
- [FixOps Flag Registry](../core/flags/registry.py)
- [Example Configuration](../config/feature_flags.example.yml)
