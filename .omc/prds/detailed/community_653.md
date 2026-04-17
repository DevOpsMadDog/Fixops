# Community 653 PRD — LLM Inference / Single Agent

## Master Goal Mapping
- **ALDECI Domain**: LLM Inference / Single Agent
- **Module**: `BaseInferenceBackend (ABC)`
- **Source**: `suite-core/core/single_agent.py:L114`
- **Function/Method**: `generate`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `generate` within the LLM Inference / Single Agent subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["generate()"]
    B --> C[BaseInferenceBackend (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/single_agent.py` — **Line**: `L114`

**Signature**: `abstractmethod def generate(prompt, system_prompt, max_tokens, temperature) -> Tuple[str, int]`

```python
"""Generate text. Returns (response_text, tokens_used)."""
```

## Inter-Dependencies

- `VLLMBackend.generate`
- `OllamaBackend.generate`
- `OpenAIBackend.generate`
- `SingleAgent.run()`

## Data Flow

prompt + system_prompt → backend HTTP/local call → (response_text: str, tokens_used: int)

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/single_agent.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns (str, int) tuple
- [ ] Respects max_tokens limit
- [ ] Uses temperature for sampling
- [ ] Backend-agnostic interface

## Effort Estimate

**S (per-backend implementation)**

## Status

**Implemented**
