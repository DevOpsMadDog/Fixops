# LLM Council Setup Guide

The ALdeci LLM Council implements Andrej Karpathy's 3-stage decision synthesis pattern
(Independent Analysis → Anonymous Peer Review → Chairman Synthesis). For consensus to
work, at least **2 providers** must be configured.

## Supported Providers

| Provider | Env Var(s) | Free Tier | Notes |
|---|---|---|---|
| Anthropic (Claude) | `ANTHROPIC_API_KEY` or `FIXOPS_ANTHROPIC_KEY` | No | Strongest for threat modeling + regulatory. Claude Opus/Sonnet. |
| OpenAI (GPT-5) | `OPENAI_API_KEY` or `FIXOPS_OPENAI_KEY` | No | Strongest for exploit/vulnerability assessment. |
| Google (Gemini) | `GOOGLE_API_KEY` or `FIXOPS_GEMINI_KEY` | Yes | Free tier available at aistudio.google.com. Good for compliance mapping. |
| OpenRouter | `OPENROUTER_API_KEY` or `FIXOPS_OPENROUTER_KEY` | Yes | Free models available (DeepSeek, Qwen, Llama). Sign up at openrouter.ai. |
| MuleRouter | `MULEROUTER_API_KEY` | Yes | mulerouter.ai — OpenRouter-compatible, Qwen3-6b-Max. Primary free council member. |
| Ollama (self-hosted) | None (URL: `FIXOPS_OLLAMA_URL`) | Yes | Air-gapped. Defaults to `http://localhost:11434`. Run `ollama pull codellama:13b`. |
| vLLM (self-hosted) | `FIXOPS_VLLM_API_KEY` (URL: `FIXOPS_VLLM_URL`) | Yes | Air-gapped. Defaults to `http://localhost:8001/v1`. |

## Minimum for Consensus

Set **at least 2** of the above. The cheapest all-free path:

```bash
# .env additions
OPENROUTER_API_KEY=sk-or-...   # free at openrouter.ai — DeepSeek/Qwen/Llama free models
MULEROUTER_API_KEY=...          # free at mulerouter.ai — Qwen3-6b-Max
```

With those two keys plus Ollama/vLLM self-hosted (always available), the council
has 4 members and full disagreement-resolution is active.

## Checking Council Status

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
     http://localhost:8000/api/v1/llm/council/status | jq .
```

Response fields:

| Field | Meaning |
|---|---|
| `configured_providers` | List of providers that have keys set |
| `member_count` | Number of active council members |
| `consensus_enabled` | `true` when `member_count >= 2` |
| `warning` | Human-readable degradation message if `consensus_enabled=false` |
| `recent_verdict` | Shape of last verdict (confidence, action distribution) |

## Startup Warning

If the council has fewer than 2 members at startup, this warning is logged:

```
LLM council has 1 member — disagreement-resolution disabled. Add a second LLM key to .env
to enable multi-LLM consensus. See docs/llm_council_setup.md for env-var names.
```

## Model Overrides

Each provider respects an optional model override env-var:

| Provider | Model override env-var | Default |
|---|---|---|
| OpenAI | `FIXOPS_OPENAI_MODEL` | `gpt-5.2` |
| Anthropic | `FIXOPS_ANTHROPIC_MODEL` | `claude-opus-4-1-20250805` |
| Gemini | (no override — uses API default) | Gemini Flash |
| OpenRouter | `FIXOPS_OPENROUTER_MODEL` | `deepseek/deepseek-chat-v3-0324:free` |
| MuleRouter | `FIXOPS_MULEROUTER_MODEL` | `qwen/qwen3-6b-max` |
| Ollama | `FIXOPS_OLLAMA_MODEL` | `codellama:13b` |
| Ollama URL | `FIXOPS_OLLAMA_URL` | `http://localhost:11434` |
| vLLM URL | `FIXOPS_VLLM_URL` | `http://localhost:8001/v1` |

## How the Council Decides

1. **Stage 1 — Independent Analysis**: Each member analyses the finding independently (parallel, no cross-talk).
2. **Stage 2 — Anonymous Peer Review**: Each member reviews others' analyses anonymously and can revise their position.
3. **Stage 3 — Chairman Synthesis**: The strongest model synthesises all positions into a final `CouncilVerdict`.
4. **Escalation**: If confidence < threshold OR dissenters > max_disagreement, Claude Opus is invoked as tie-breaker.

With only 1 member there is no peer review and no disagreement-resolution — the single member's verdict is returned with confidence capped at 0.5 and action defaulting to `review` (boilerplate escalation path).
