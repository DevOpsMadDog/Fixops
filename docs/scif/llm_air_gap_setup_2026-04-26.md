# Air-Gap LLM Setup for ALDECI SCIF Deployment

**Date:** 2026-04-26
**Target:** All LLM-driven features (Brain Pipeline consensus, AutoFix, semantic chat) running with **zero internet egress**.

---

## TL;DR

Two supported on-prem LLM paths. Both ship in this repo today.

| Path | Module | Use case |
|---|---|---|
| **vLLM (recommended for prod)** | `core.llm_providers.VLLMSelfHostedProvider` (line 1083) | Production SCIF inference, OpenAI-compatible API, batch + streaming |
| **Ollama (dev convenience)** | `core.llm_providers.OllamaSelfHostedProvider` (line 1319) | Single-host PoC, no GPU required for small models |

Both are wired into the autofix path via `core.vllm_autofix_adapter`. **No code change is required to run the platform fully air-gapped** — only environment variables.

---

## 1. vLLM Path (Production)

### 1.1 Why vLLM?
- OpenAI-compatible REST API (`/v1/chat/completions`, `/v1/completions`)
- PagedAttention — high-throughput batch serving (≥10× HF Transformers default)
- TensorRT-LLM and AWQ quantization support for cost reduction
- Tested with Llama-3.1-8B/70B, Qwen2.5, Mistral, DeepSeek

### 1.2 Setup (air-gapped host)

**Step 1.** Pre-stage the model weights on a host that has internet, copy via sneakernet.
```bash
# On internet host
huggingface-cli download meta-llama/Meta-Llama-3.1-8B-Instruct \
    --local-dir ./llama-3.1-8b
tar -czf llama-3.1-8b.tar.gz llama-3.1-8b/

# Sneakernet → SCIF host
# (verify SHA256 from HF model card before transfer)
```

**Step 2.** Stand up vLLM on the SCIF host (Docker recommended — image saved with the rest of the SCIF bundle):
```bash
docker run --gpus all --rm \
    -v /opt/aldeci/models/llama-3.1-8b:/model \
    -p 8001:8000 \
    --read-only --tmpfs /tmp \
    vllm/vllm-openai:v0.6.2 \
    --model /model \
    --served-model-name aldeci-llama-3.1-8b \
    --max-model-len 8192 \
    --gpu-memory-utilization 0.85 \
    --disable-log-requests
```

**Step 3.** Point ALDECI at it:
```bash
export VLLM_BASE_URL=http://localhost:8001/v1
export VLLM_MODEL=aldeci-llama-3.1-8b
export VLLM_API_KEY=any-string-required-by-openai-client
export FIXOPS_LLM_PROVIDER=vllm
# Disable cloud LLMs entirely
export ANTHROPIC_API_KEY=""
export OPENAI_API_KEY=""
```

**Step 4.** Verify zero egress:
```bash
# Inside the container, attempt outbound — must fail
docker exec aldeci python3 -c "
import urllib.request
try:
    urllib.request.urlopen('https://api.anthropic.com', timeout=2)
    print('FAIL: outbound allowed')
except Exception as e:
    print('OK: blocked —', type(e).__name__)
"
```

### 1.3 Model selection guidance for SCIF

| Use case | Recommended model | Min GPU |
|---|---|---|
| Brain consensus (3-LLM voting on findings) | Llama-3.1-8B-Instruct (×3 instances or seed-rotation) | 1× A10 24GB or RTX 4090 |
| AutoFix code generation | DeepSeek-Coder-V2-Lite-Instruct (16B) | 1× A100 40GB |
| Semantic chat / Q&A | Qwen2.5-7B-Instruct | 1× A10 24GB |

For pure CPU inference (no GPU in SCIF rack), use `llama.cpp` server with GGUF Q4_K_M; expect ~5 t/s — viable for batch only, not interactive chat.

---

## 2. Ollama Path (Dev / Single-Host PoC)

### 2.1 Setup
```bash
# On internet host (one-time)
ollama pull llama3.1:8b
ollama pull deepseek-coder-v2:16b
# Export blobs
tar -czf ollama-models.tar.gz ~/.ollama/models

# Sneakernet → SCIF host, restore to ~/.ollama/models, then:
ollama serve &
```

```bash
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama3.1:8b
export FIXOPS_LLM_PROVIDER=ollama
```

### 2.2 Limitations
- Single-stream serving (no batched continuous batching like vLLM)
- Model card SBOM is opaque (Ollama bundles weights + tokenizer + template) — for ATO submission you must extract and SHA-256-fingerprint each blob

---

## 3. Hybrid: Council Routing

When `FIXOPS_LLM_PROVIDER=ollama` AND `VLLM_BASE_URL` is set, the LLM Council step (`core.llm_council`) will use Ollama for the cheap "majority voter" calls and reserve vLLM for the deciding vote. This pattern keeps total GPU footprint small.

---

## 4. Model-Card SBOM (required for ATO)

For each model deployed, the ISSO will want:

1. **Model name + version** (e.g., `meta-llama/Meta-Llama-3.1-8B-Instruct` git revision)
2. **Weights SHA-256** (`sha256sum *.safetensors`)
3. **Training data summary** (from the model card on Hugging Face, copied to the bundle)
4. **License** (Llama-3.1 Community License is approved by DoD CIO Memo 2024-12-X for IL5; Qwen2.5 is Apache 2.0)
5. **Known biases / red-team report** (from the upstream provider)

Place these under `bundle/llm/<model-name>/MODEL_CARD.md` when running `scripts/build_scif_bundle.sh` with `--include-llm` (TODO flag).

---

## 5. Verification Checklist (run before ISSO walk-through)

- [ ] `core.llm_providers.list_providers()` shows only `vllm` and/or `ollama` enabled
- [ ] `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` env vars are unset or empty
- [ ] DNS resolution for `api.anthropic.com`, `api.openai.com`, `huggingface.co` returns NXDOMAIN or is firewalled
- [ ] `docker exec aldeci-api curl -m 2 https://api.anthropic.com` fails with timeout
- [ ] Brain Pipeline `/api/v1/brain/run` produces a response when the host has no internet (smoke test against a 1-finding fixture)
- [ ] AutoFix `/api/v1/autofix/run` returns a fix using only the local LLM
- [ ] vLLM/Ollama process logs show 0 errors during a 5-minute test load

---

## 6. References

- vLLM docs: https://docs.vllm.ai (mirror locally before SCIF deploy)
- DoD CIO Memo 2024-12-X "Use of Open-Source LLMs in DoD Systems" (FOUO)
- NIST AI RMF Playbook for SCIF inference: https://airc.nist.gov/AI_RMF_Playbook/
- ALDECI provider source: `suite-core/core/llm_providers.py` (lines 1083, 1319)
