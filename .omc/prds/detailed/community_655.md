# Community 655 PRD — LLM Backend Metadata

## Master Goal Mapping
- **ALDECI Domain**: LLM Backend Metadata
- **Module**: `BaseInferenceBackend (ABC)`
- **Source**: `suite-core/core/single_agent.py:L122`
- **Function/Method**: `model_info`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `model_info` within the LLM Backend Metadata subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["model_info()"]
    B --> C[BaseInferenceBackend (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/single_agent.py` — **Line**: `L122`

**Signature**: `abstractmethod def model_info(self) -> Dict[str, Any]`

```python
"""Get backend/model information."""
```

## Inter-Dependencies

- `VLLMBackend.model_info`
- `OllamaBackend.model_info`
- `ai_security_advisor_engine.py`

## Data Flow

no input → backend metadata query → Dict with name/version/context_window

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/single_agent.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns dict with at least 'name' key
- [ ] Includes context window size
- [ ] Used for capability routing decisions

## Effort Estimate

**XS**

## Status

**Implemented**
