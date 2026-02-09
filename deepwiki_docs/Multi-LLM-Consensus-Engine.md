# Multi-LLM Consensus Engine

> **Relevant source files**
> * [README.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/README.md)
> * [apps/api/micro_pentest_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/micro_pentest_router.py)
> * [backend_test.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/backend_test.py)
> * [core/analytics.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/analytics.py)
> * [core/compliance.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/compliance.py)
> * [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)
> * [core/decision_policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_policy.py)
> * [core/enhanced_decision.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py)
> * [core/llm_providers.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py)
> * [core/playbook_runner.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/playbook_runner.py)
> * [demo_ssdlc_stages/03_code_development.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/03_code_development.json)
> * [demo_ssdlc_stages/04_build_ci.yaml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/04_build_ci.yaml)
> * [demo_ssdlc_stages/06_deploy_production.yaml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/06_deploy_production.yaml)
> * [docs/API_CLI_REFERENCE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/API_CLI_REFERENCE.md)
> * [docs/DOCKER_SHOWCASE_GUIDE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/DOCKER_SHOWCASE_GUIDE.md)
> * [docs/ENTERPRISE_FEATURES.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/ENTERPRISE_FEATURES.md)
> * [docs/FEATURE_CODE_MAPPING.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/FEATURE_CODE_MAPPING.md)
> * [docs/PLAYBOOK_LANGUAGE_REFERENCE.md](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/PLAYBOOK_LANGUAGE_REFERENCE.md)
> * [fixops-enterprise/src/api/v1/micro_pentest.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/api/v1/micro_pentest.py)
> * [fixops-enterprise/src/services/micro_pentest_engine.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/micro_pentest_engine.py)
> * [tests/e2e/test_critical_decision_policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/e2e/test_critical_decision_policy.py)
> * [tests/test_comprehensive_e2e.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_comprehensive_e2e.py)
> * [tests/test_data_generator.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_data_generator.py)
> * [tests/test_enhanced_api.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enhanced_api.py)
> * [tests/test_micro_pentest_engine.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_micro_pentest_engine.py)

## Purpose and Scope

The Multi-LLM Consensus Engine orchestrates decision-making across multiple AI providers to produce high-confidence security verdicts. This system queries GPT, Claude, Gemini, and Sentinel providers in parallel, aggregates their responses using weighted voting, and applies policy-based overrides to produce final Allow/Review/Block verdicts.

This page covers the consensus engine architecture, provider adapters, voting mechanisms, and configuration. For the broader decision pipeline that uses this engine, see [Decision Engine](/DevOpsMadDog/Fixops/4-decision-engine). For policy override rules, see [Decision Policy Engine](/DevOpsMadDog/Fixops/4.2-decision-policy-engine). For risk-based profiling that feeds into consensus, see [Risk-Based Profiling](/DevOpsMadDog/Fixops/4.3-risk-based-profiling).

---

## Architecture Overview

The consensus engine implements a three-layer architecture: provider invocation, response normalization, and weighted aggregation.

```mermaid
flowchart TD

Input["Security Findings<br>+ Business Context"]
Evaluate["evaluate()"]
RiskProfile["_risk_based_profile()<br>or _base_profile()"]
PolicyPre["Policy Pre-Consensus<br>(if enabled)"]
GPT["OpenAIChatProvider<br>weight: 1.0<br>style: strategist"]
Claude["AnthropicMessagesProvider<br>weight: 0.95<br>style: analyst"]
Gemini["GeminiProvider<br>weight: 0.9<br>style: signals"]
Sentinel["SentinelCyberProvider<br>weight: 0.85<br>style: threat"]
Normalize["Normalize to LLMResponse"]
Aggregate["_aggregate_analyses()"]
ConsensusCheck["Consensus Threshold Check<br>(default: 85%)"]
ExpertFlag["Expert Review Flag<br>(if low confidence)"]
Output["MultiLLMResult<br>(final_decision, confidence,<br>individual_analyses)"]

Input -.-> Evaluate
ExpertFlag -.-> Output

subgraph MultiLLMConsensusEngine ["MultiLLMConsensusEngine"]
    Evaluate
    RiskProfile
    PolicyPre
    Normalize
    Aggregate
    ConsensusCheck
    ExpertFlag
    Evaluate -.-> RiskProfile
    RiskProfile -.-> PolicyPre
    PolicyPre -.-> GPT
    PolicyPre -.-> Claude
    PolicyPre -.-> Gemini
    PolicyPre -.-> Sentinel
    GPT -.-> Normalize
    Claude -.-> Normalize
    Gemini -.-> Normalize
    Sentinel -.-> Normalize
    Normalize -.-> Aggregate
    Aggregate -.-> ConsensusCheck
    ConsensusCheck -.-> ExpertFlag

subgraph subGraph0 ["Provider Layer"]
    GPT
    Claude
    Gemini
    Sentinel
end
end
```

**Sources:** [core/enhanced_decision.py L127-L318](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L127-L318)

---

## Core Components

### MultiLLMConsensusEngine Class

The `MultiLLMConsensusEngine` class in [core/enhanced_decision.py L127-L318](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L127-L318)

 orchestrates the entire consensus process. Key responsibilities:

* **Provider management**: Initializes and manages 4 LLM providers with configurable weights
* **Risk assessment**: Computes base verdicts using risk scores or heuristics
* **Policy integration**: Applies pre-consensus policy overrides via `DecisionPolicyEngine`
* **Parallel invocation**: Queries all enabled providers concurrently
* **Weighted aggregation**: Combines responses using provider-specific weights
* **Consensus validation**: Ensures responses meet the configured threshold (default 85%)

```mermaid
flowchart TD

Settings["settings dict"]
Providers["Load ProviderSpec list"]
EnvCheck["Check FIXOPS_ENABLE_* env vars"]
Clients["Build provider_clients map"]
OpenAI["OpenAIChatProvider<br>model: gpt-4o-mini"]
Anthropic["AnthropicMessagesProvider<br>model: claude-3-5-sonnet"]
Google["GeminiProvider<br>model: gemini-2.0-flash"]
Custom["SentinelCyberProvider<br>(custom endpoint)"]
Fallback["DeterministicLLMProvider<br>(always enabled)"]

Clients -.-> OpenAI
Clients -.-> Anthropic
Clients -.-> Google
Clients -.-> Custom
Clients -.-> Fallback

subgraph subGraph1 ["Provider Clients"]
    OpenAI
    Anthropic
    Google
    Custom
    Fallback
end

subgraph Initialization ["Initialization"]
    Settings
    Providers
    EnvCheck
    Clients
    Settings -.-> Providers
    Providers -.-> EnvCheck
    EnvCheck -.-> Clients
end
```

**Key Methods:**

| Method | Purpose | Returns |
| --- | --- | --- |
| `evaluate()` | Main entry point for consensus decision | `MultiLLMResult` |
| `_risk_based_profile()` | Compute base verdict using risk scoring | tuple of (action, confidence, mitre, adjusted_risk, multiplier) |
| `_base_profile()` | Compute base verdict using severity heuristics | tuple of (action, confidence, mitre) |
| `_aggregate_analyses()` | Combine provider responses with weights | `MultiLLMResult` |
| `_build_prompt()` | Construct LLM prompt from context | str |

**Sources:** [core/enhanced_decision.py L127-L318](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L127-L318)

 [core/enhanced_decision.py L319-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L319-L582)

---

## Provider System

### Provider Specifications

Each provider is defined by a `ProviderSpec` dataclass [core/enhanced_decision.py L62-L67](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L62-L67)

:

```python
@dataclass
class ProviderSpec:
    name: str
    weight: float = 1.0
    style: str = "consensus"
    focus: List[str] = field(default_factory=list)
```

**Default Provider Configuration:**

| Provider | Weight | Style | Focus Areas | Model |
| --- | --- | --- | --- | --- |
| GPT-5 | 1.0 | strategist | mitre, context | gpt-4o-mini |
| Claude-3 | 0.95 | analyst | compliance, guardrails | claude-3-5-sonnet |
| Gemini-2 | 0.9 | signals | exploit, cnapp | gemini-2.0-flash |
| Sentinel | 0.85 | threat | marketplace, agents | custom endpoint |

**Sources:** [core/enhanced_decision.py L130-L146](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L130-L146)

### Provider Adapters

All providers implement the `BaseLLMProvider` interface [core/llm_providers.py L27-L67](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L27-L67)

:

```mermaid
classDiagram
    class BaseLLMProvider {
        +name: str
        +style: str
        +focus: List[str]
        +analyse() : LLMResponse
    }
    class OpenAIChatProvider {
        +model: str
        +api_key: str
        +timeout: float
        +_session: requests.Session
        +analyse() : LLMResponse
        +_resolve_api_key() : str
    }
    class AnthropicMessagesProvider {
        +model: str
        +api_key: str
        +timeout: float
        +_session: requests.Session
        +analyse() : LLMResponse
    }
    class GeminiProvider {
        +model: str
        +api_key: str
        +timeout: float
        +analyse() : LLMResponse
    }
    class SentinelCyberProvider {
        +endpoint: str
        +api_key: str
        +timeout: float
        +_session: requests.Session
        +analyse() : LLMResponse
    }
    class DeterministicLLMProvider {
        +analyse() : LLMResponse
    }
    BaseLLMProvider <|-- OpenAIChatProvider
    BaseLLMProvider <|-- AnthropicMessagesProvider
    BaseLLMProvider <|-- GeminiProvider
    BaseLLMProvider <|-- SentinelCyberProvider
    BaseLLMProvider <|-- DeterministicLLMProvider
```

**Sources:** [core/llm_providers.py L27-L67](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L27-L67)

 [core/llm_providers.py L73-L131](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L73-L131)

 [core/llm_providers.py L134-L208](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L134-L208)

 [core/llm_providers.py L211-L285](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L211-L285)

 [core/llm_providers.py L288-L373](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L288-L373)

 [core/llm_providers.py L69-L71](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L69-L71)

### LLMResponse Schema

All providers normalize their outputs to the `LLMResponse` dataclass [core/llm_providers.py L14-L25](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L14-L25)

:

```python
@dataclass
class LLMResponse:
    recommended_action: str          # "allow", "review", "block"
    confidence: float                # 0.0 to 1.0
    reasoning: str                   # Natural language explanation
    mitre_techniques: Sequence[str]  # MITRE ATT&CK technique IDs
    compliance_concerns: Sequence[str]
    attack_vectors: Sequence[str]
    metadata: Dict[str, Any]         # Provider-specific data
```

**Sources:** [core/llm_providers.py L14-L25](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L14-L25)

---

## Consensus Mechanism

### Weighted Aggregation

The `_aggregate_analyses()` method [core/enhanced_decision.py L583-L753](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L583-L753)

 implements weighted voting:

```mermaid
flowchart TD

Analyses["Individual ModelAnalysis objects"]
CountVotes["Count votes per action<br>(allow/review/block)"]
ApplyWeights["Multiply by provider weights"]
Normalize["Normalize to percentages"]
Threshold["Check consensus threshold<br>(default: 0.85)"]
ConfidenceScores["Extract confidence scores"]
WeightedAvg["Weighted average"]
AdjustForDisagreement["Reduce if split decision"]
CompareActions["Compare recommended actions"]
CheckPolicyOverride["Check for policy override"]
FlagSplits["Flag for expert review"]
Result["MultiLLMResult"]

Analyses -.-> CountVotes
Analyses -.-> ConfidenceScores
Analyses -.-> CompareActions
Threshold -.-> Result
AdjustForDisagreement -.-> Result
FlagSplits -.-> Result

subgraph subGraph2 ["Disagreement Detection"]
    CompareActions
    CheckPolicyOverride
    FlagSplits
    CompareActions -.-> CheckPolicyOverride
    CheckPolicyOverride -.-> FlagSplits
end

subgraph subGraph1 ["Confidence Calculation"]
    ConfidenceScores
    WeightedAvg
    AdjustForDisagreement
    ConfidenceScores -.-> WeightedAvg
    WeightedAvg -.-> AdjustForDisagreement
end

subgraph subGraph0 ["Voting Process"]
    CountVotes
    ApplyWeights
    Normalize
    Threshold
    CountVotes -.-> ApplyWeights
    ApplyWeights -.-> Normalize
    Normalize -.-> Threshold
end
```

**Algorithm:**

1. **Vote Collection**: Each provider's `recommended_action` is recorded with its weight
2. **Vote Aggregation**: Sum weights for each action (allow/review/block)
3. **Winner Selection**: Action with highest weighted sum becomes `final_decision`
4. **Consensus Check**: Winner must have ≥85% of total weight (configurable)
5. **Confidence Calculation**: Weighted average of individual confidence scores
6. **Disagreement Flagging**: If providers split significantly, flag for expert review

**Sources:** [core/enhanced_decision.py L583-L753](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L583-L753)

### Expert Review Triggers

The system flags decisions for human review when:

* Consensus percentage < threshold (default 85%)
* Weighted confidence < 0.65
* Policy override occurred (documented in `disagreement_areas`)
* Split decision (e.g., 2 providers say "block", 2 say "allow")

**Sources:** [core/enhanced_decision.py L700-L753](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L700-L753)

---

## Risk Integration

### Risk-Based Profiling

When `use_risk_engine=True` (default), the engine computes base verdicts using risk scores [core/enhanced_decision.py L397-L476](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L397-L476)

:

```mermaid
flowchart TD

RiskScore["risk_profile.score"]
ExploitStats["Exploit stats<br>(KEV, EPSS)"]
Exposures["Exposures<br>(internet-facing, auth)"]
Severity["Severity level"]
CheckInternet["Internet-facing?"]
CheckAuth["Auth service?"]
CheckCritical["Critical severity?"]
Multiply["Apply multiplier<br>(1.0 to 1.5)"]
BaseRisk["risk_score"]
AdjRisk["adjusted_risk = risk_score * multiplier"]
BlockThreshold["≥0.85: BLOCK"]
ReviewThreshold["≥0.60: REVIEW"]
AllowThreshold["<0.60: ALLOW"]

RiskScore -.-> BaseRisk
ExploitStats -.-> CheckInternet
Exposures -.-> CheckAuth
Severity -.-> CheckCritical
Multiply -.-> AdjRisk
AdjRisk -.-> BlockThreshold
AdjRisk -.-> ReviewThreshold
AdjRisk -.-> AllowThreshold

subgraph subGraph2 ["Verdict Mapping"]
    BlockThreshold
    ReviewThreshold
    AllowThreshold
end

subgraph subGraph1 ["Adjusted Risk"]
    BaseRisk
    AdjRisk
    BaseRisk -.-> AdjRisk
end

subgraph subGraph0 ["Exposure Multiplier"]
    CheckInternet
    CheckAuth
    CheckCritical
    Multiply
    CheckInternet -.-> Multiply
    CheckAuth -.-> Multiply
    CheckCritical -.-> Multiply
end
```

**Exposure Multipliers:**

| Condition | Multiplier |
| --- | --- |
| Internet-facing + Critical | 1.5 |
| Internet-facing OR Auth service + High | 1.3 |
| Internal + Low KEV activity | 1.0 |

**Sources:** [core/enhanced_decision.py L397-L476](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L397-L476)

### Severity-Based Heuristics

When `use_risk_engine=False`, the engine falls back to severity heuristics [core/enhanced_decision.py L478-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L478-L582)

:

| Severity | Total Findings | Action | Confidence |
| --- | --- | --- | --- |
| Critical | Any | BLOCK | 0.92 |
| High | ≥5 | BLOCK | 0.85 |
| High | 1-4 | REVIEW | 0.78 |
| Medium | ≥10 | REVIEW | 0.72 |
| Medium | <10 | ALLOW | 0.65 |
| Low | Any | ALLOW | 0.88 |

**Sources:** [core/enhanced_decision.py L478-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L478-L582)

---

## Policy Pre-Consensus

When `policy_pre_consensus=True` (default), critical policy rules override base verdicts before LLM queries [core/enhanced_decision.py L295-L315](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L295-L315)

:

```mermaid
flowchart TD

BaseVerdict["Base Verdict<br>(from risk/severity)"]
PolicyEngine["DecisionPolicyEngine"]
Rule1["Internet-facing + SQL Injection<br>→ BLOCK"]
Rule2["Auth service + SQL Injection<br>→ BLOCK"]
Rule3["Critical + Internet-facing<br>→ BLOCK"]
Override["PolicyOverride<br>(triggered, new_verdict,<br>confidence_boost)"]
BoostConfidence["Boost confidence<br>(min 0.99)"]
LLMQueries["Query LLM Providers<br>(with boosted base)"]

BaseVerdict -.-> PolicyEngine
PolicyEngine -.-> Rule1
PolicyEngine -.-> Rule2
PolicyEngine -.-> Rule3
Rule1 -.-> Override
Rule2 -.-> Override
Rule3 -.-> Override
Override -.-> BoostConfidence
BoostConfidence -.-> LLMQueries

subgraph subGraph0 ["Critical Rules"]
    Rule1
    Rule2
    Rule3
end
```

**Sources:** [core/enhanced_decision.py L295-L315](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L295-L315)

 [core/decision_policy.py L1-L328](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_policy.py#L1-L328)

---

## Configuration

### Environment Variables

Provider enablement is controlled via environment variables [core/enhanced_decision.py L169-L209](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L169-L209)

:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FIXOPS_ENABLE_OPENAI` | true | Enable GPT provider |
| `FIXOPS_ENABLE_ANTHROPIC` | true | Enable Claude provider |
| `FIXOPS_ENABLE_GEMINI` | true | Enable Gemini provider |
| `FIXOPS_ENABLE_SENTINEL` | true | Enable Sentinel provider |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | - | Anthropic API key |
| `GOOGLE_API_KEY` | - | Google API key |
| `FIXOPS_CONSENSUS_THRESHOLD` | 0.85 | Consensus percentage threshold |

### Overlay Configuration

The consensus engine accepts configuration via the `enhanced_decision` overlay section [core/configuration.py L1-L1355](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L1-L1355)

:

```yaml
enhanced_decision:
  providers:
    - name: "gpt-5"
      weight: 1.0
      style: "strategist"
      focus: ["mitre", "context"]
    - name: "claude-3"
      weight: 0.95
      style: "analyst"
      focus: ["compliance", "guardrails"]
  baseline_confidence: 0.78
  consensus_threshold: 0.85
  
decision:
  use_risk_engine: true
  policy_pre_consensus: true
  risk_block_threshold: 0.85
  risk_review_threshold: 0.60
```

**Sources:** [core/configuration.py L1-L1355](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L1-L1355)

 [core/enhanced_decision.py L148-L238](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L148-L238)

---

## API Integration

### Enhanced Decision Endpoints

The consensus engine is exposed via three API endpoints [apps/api/routes/enhanced.py L1-L110](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/routes/enhanced.py#L1-L110)

:

```mermaid
flowchart TD

Analysis["POST /api/v1/enhanced/analysis"]
Compare["POST /api/v1/enhanced/compare-llms"]
Capabilities["GET /api/v1/enhanced/capabilities"]
Validate["Validate input"]
BuildContext["Build context dict"]
CallEngine["MultiLLMConsensusEngine.evaluate()"]
Result["MultiLLMResult"]
Serialize["Serialize to JSON"]

Compare -.-> Validate
CallEngine -.-> Result

subgraph Response ["Response"]
    Result
    Serialize
    Result -.-> Serialize
end

subgraph subGraph1 ["Request Processing"]
    Validate
    BuildContext
    CallEngine
    Validate -.-> BuildContext
    BuildContext -.-> CallEngine
end

subgraph subGraph0 ["API Routes"]
    Analysis
    Compare
    Capabilities
end
```

**Endpoint Details:**

| Endpoint | Method | Purpose | Response |
| --- | --- | --- | --- |
| `/api/v1/enhanced/compare-llms` | POST | Compare recommendations from all providers | `MultiLLMResult` with individual analyses |
| `/api/v1/enhanced/analysis` | POST | Get single consensus decision | `MultiLLMResult` |
| `/api/v1/enhanced/capabilities` | GET | List enabled providers and features | Provider metadata |

**Request Payload:**

```json
{
  "service_name": "payment-api",
  "security_findings": [
    {
      "rule_id": "SQL_INJECTION_001",
      "severity": "high",
      "description": "SQL injection in login handler"
    }
  ],
  "business_context": {
    "environment": "production",
    "criticality": "high",
    "data_classification": "pci",
    "exposure": "internet-facing"
  }
}
```

**Sources:** [apps/api/routes/enhanced.py L40-L102](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/routes/enhanced.py#L40-L102)

 [docs/FEATURE_CODE_MAPPING.md L572-L597](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/FEATURE_CODE_MAPPING.md#L572-L597)

---

## Fallback Mechanisms

### Deterministic Fallback

When no LLM providers are available or all API calls fail, the system falls back to the `DeterministicLLMProvider` [core/llm_providers.py L69-L71](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L69-L71)

:

```mermaid
flowchart TD

APICall["Provider API Call"]
Timeout["Timeout?"]
Error["HTTP Error?"]
NoAPIKey["No API Key?"]
FallbackProvider["DeterministicLLMProvider"]
HeuristicLogic["Use risk-based profile<br>or severity heuristics"]
Response["LLMResponse with<br>mode: 'deterministic'"]

APICall -.-> Timeout
APICall -.-> Error
APICall -.-> NoAPIKey
Timeout -.-> FallbackProvider
Error -.-> FallbackProvider
NoAPIKey -.-> FallbackProvider
FallbackProvider -.-> HeuristicLogic
HeuristicLogic -.-> Response
```

The deterministic provider returns the base verdict computed before LLM queries, ensuring the system always produces a decision even without external API access.

**Sources:** [core/llm_providers.py L69-L71](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L69-L71)

 [core/llm_providers.py L27-L67](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L27-L67)

### Retry Logic

Each provider implements exponential backoff retry [core/llm_providers.py L73-L131](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L73-L131)

 [core/llm_providers.py L134-L208](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L134-L208)

:

1. **Initial attempt**: Timeout = 30s (configurable)
2. **Retry 1**: Wait 1s, timeout = 30s
3. **Retry 2**: Wait 2s, timeout = 30s
4. **Retry 3**: Wait 4s, timeout = 30s
5. **Fallback**: Return deterministic response

**Sources:** [core/llm_providers.py L73-L131](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L73-L131)

 [core/llm_providers.py L134-L208](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L134-L208)

 [core/llm_providers.py L211-L285](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L211-L285)

 [core/llm_providers.py L288-L373](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py#L288-L373)

---

## Data Flow

### Complete Evaluation Flow

```mermaid
flowchart TD

Start["evaluate() called"]
ParseSeverity["Parse severity_overview"]
ParseGuardrail["Parse guardrail status"]
ParseCompliance["Parse compliance_status"]
ParseCNAPP["Parse cnapp_summary"]
ParseExploit["Parse exploitability"]
ParseRisk["Parse risk_profile"]
UseRiskEngine["use_risk_engine?"]
RiskProfile["_risk_based_profile()"]
BaseProfile["_base_profile()"]
PolicyPreConsensus["policy_pre_consensus?"]
PolicyEval["DecisionPolicyEngine.evaluate_overrides()"]
ApplyOverride["Apply policy override"]
BuildPrompt["_build_prompt()"]
QueryGPT["OpenAIChatProvider.analyse()"]
QueryClaude["AnthropicMessagesProvider.analyse()"]
QueryGemini["GeminiProvider.analyse()"]
QuerySentinel["SentinelCyberProvider.analyse()"]
Aggregate["_aggregate_analyses()"]
CheckConsensus["Check threshold (85%)"]
FlagExpert["Flag expert_validation_required"]
Output["MultiLLMResult"]

Start -.-> ParseSeverity
ParseRisk -.-> UseRiskEngine
RiskProfile -.-> PolicyPreConsensus
BaseProfile -.-> PolicyPreConsensus
PolicyPreConsensus -.-> BuildPrompt
ApplyOverride -.-> BuildPrompt
QueryGPT -.-> Aggregate
QueryClaude -.-> Aggregate
QueryGemini -.-> Aggregate
QuerySentinel -.-> Aggregate
FlagExpert -.-> Output

subgraph Consensus ["Consensus"]
    Aggregate
    CheckConsensus
    FlagExpert
    Aggregate -.-> CheckConsensus
    CheckConsensus -.-> FlagExpert
end

subgraph subGraph3 ["Provider Queries"]
    BuildPrompt
    QueryGPT
    QueryClaude
    QueryGemini
    QuerySentinel
    BuildPrompt -.-> QueryGPT
    BuildPrompt -.-> QueryClaude
    BuildPrompt -.-> QueryGemini
    BuildPrompt -.-> QuerySentinel
end

subgraph subGraph2 ["Policy Layer"]
    PolicyPreConsensus
    PolicyEval
    ApplyOverride
    PolicyPreConsensus -.-> PolicyEval
    PolicyEval -.-> ApplyOverride
end

subgraph subGraph1 ["Base Verdict Computation"]
    UseRiskEngine
    RiskProfile
    BaseProfile
    UseRiskEngine -.->|"Yes"| RiskProfile
    UseRiskEngine -.->|"No"| BaseProfile
end

subgraph subGraph0 ["Input Processing"]
    ParseSeverity
    ParseGuardrail
    ParseCompliance
    ParseCNAPP
    ParseExploit
    ParseRisk
    ParseSeverity -.-> ParseGuardrail
    ParseGuardrail -.-> ParseCompliance
    ParseCompliance -.->|"Yes"| ParseCNAPP
    ParseCNAPP -.->|"No"| ParseExploit
    ParseExploit -.-> ParseRisk
end
```

**Sources:** [core/enhanced_decision.py L242-L318](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L242-L318)

 [core/enhanced_decision.py L319-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L319-L582)

 [core/enhanced_decision.py L583-L753](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L583-L753)

---

## Output Schema

### MultiLLMResult

The consensus engine returns a `MultiLLMResult` dataclass [core/enhanced_decision.py L100-L124](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L100-L124)

:

```python
@dataclass
class MultiLLMResult:
    final_decision: str                      # "allow", "review", "block"
    consensus_confidence: float              # Weighted average confidence
    method: str                              # "multi_llm_consensus"
    individual_analyses: List[ModelAnalysis] # Per-provider results
    disagreement_areas: List[str]            # Split decisions, policy overrides
    expert_validation_required: bool         # True if flagged for review
    summary: str                             # Natural language explanation
    telemetry: Dict[str, Any]                # Execution metrics
    signals: Dict[str, Any]                  # Risk/exploit signals
```

### ModelAnalysis

Each provider's response is stored as a `ModelAnalysis` [core/enhanced_decision.py L70-L96](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L70-L96)

:

```python
@dataclass
class ModelAnalysis:
    provider: str                      # Provider name
    recommended_action: str            # "allow", "review", "block"
    confidence: float                  # Provider confidence
    reasoning: str                     # Natural language explanation
    mitre_techniques: List[str]        # MITRE ATT&CK technique IDs
    attack_vectors: List[str]          # Attack vector classifications
    compliance_concerns: List[str]     # Compliance framework gaps
    evidence: List[Dict[str, Any]]     # Supporting evidence
    processing_time_ms: int            # API call duration
    cost_usd: float                    # Estimated API cost
    risk_assessment: str               # "low", "moderate", "high", "critical"
```

**Sources:** [core/enhanced_decision.py L70-L96](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L70-L96)

 [core/enhanced_decision.py L100-L124](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py#L100-L124)

---

## CLI Integration

The consensus engine is invoked automatically by the `run` command [core/cli.py L1-L5000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/cli.py#L1-L5000)

 when processing security findings. Users can also query provider capabilities:

```css
# Run full pipeline with multi-LLM consensus
python -m core.cli run --overlay config/fixops.overlay.yml

# Get LLM provider capabilities
curl -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/enhanced/capabilities

# Compare LLM recommendations (direct API call)
curl -H "X-API-Key: $TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"service_name":"app","security_findings":[...]}' \
  http://localhost:8000/api/v1/enhanced/compare-llms
```

**Sources:** [core/cli.py L403-L417](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/cli.py#L403-L417)

 [docs/DOCKER_SHOWCASE_GUIDE.md L1-L1000](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/DOCKER_SHOWCASE_GUIDE.md#L1-L1000)

 [docs/API_CLI_REFERENCE.md L62-L83](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/API_CLI_REFERENCE.md#L62-L83)

---

## Testing

The consensus engine is tested via:

* **Unit tests**: [tests/test_enhanced_api.py L1-L150](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enhanced_api.py#L1-L150)  - API endpoint regression tests
* **E2E tests**: [tests/e2e/test_critical_decision_policy.py L1-L400](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/e2e/test_critical_decision_policy.py#L1-L400)  - Policy override validation
* **Integration tests**: [backend_test.py L23-L782](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/backend_test.py#L23-L782)  - Full pipeline execution

**Sources:** [tests/test_enhanced_api.py L1-L150](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enhanced_api.py#L1-L150)

 [tests/e2e/test_critical_decision_policy.py L1-L400](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/e2e/test_critical_decision_policy.py#L1-L400)

 [backend_test.py L23-L782](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/backend_test.py#L23-L782)