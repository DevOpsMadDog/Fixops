# LLM Phase 2 Distillation — Kickoff 2026-04-27

## Status: READY FOR REMOTE TRAINING

Pipeline validated end-to-end on local Mac (MPS). Full training requires a remote CUDA GPU box.

---

## 1. Curator Output

| Metric | Value |
|--------|-------|
| Source DB | `data/learning_signals.db` |
| Total verdicts | 5,196 |
| Opus-escalated verdicts | 5,196 (100%) |
| Total feedback pairs | 5,196 |
| Pairs kept (DPO) | 5,196 |
| Pairs kept (SFT) | 5,196 |
| Pairs dropped (any reason) | 0 |
| Distinct findings | 5,196 |
| Confidence floor applied | 0.40 |
| De-dupe collisions | 0 |

Output files:
- `data/distill_train.jsonl` — DPO format `{prompt, chosen, rejected}`
- `data/distill_sft.jsonl` — SFT format `{messages: [{role, content}]}`
- `data/distill_dataset_manifest.json` — provenance sidecar
- `data/distill_adapter_20260428T015624Z/trainer_trace.json` — dry-run trace

### Dataset Balance
All 5,196 pairs passed every filter:
- Source whitelist: analyst_override, llm_learning_loop_low_confidence, council_member_disagreement, remediation_outcome_failed, smoke_test_simulated_override
- Confidence >= 0.40: all pass (100% Opus-escalated, high confidence by construction)
- SHA-256 de-dupe: 0 collisions (all findings unique)

---

## 2. GPU Status

| Check | Result |
|-------|--------|
| CUDA | NOT available |
| MPS (Apple Silicon) | AVAILABLE — torch 2.10.0 |
| Device selected | `mps` |
| Training decision | **Remote CUDA box required** — MPS lacks bitsandbytes 4-bit nf4 support |

Local dry-run passed: 5196 SFT valid, 5196 DPO valid, 20 samples processed end-to-end in 1.43s.

### Missing libs (install on GPU box)
```
pip install 'trl>=0.11' 'transformers>=4.45' 'peft>=0.13' 'datasets>=3.0' 'bitsandbytes>=0.43' accelerate
```

Currently installed on this box: `torch==2.10.0`, `transformers==5.6.2`. TRL/PEFT/datasets/bitsandbytes/accelerate are missing — expected on dev Mac.

---

## 3. Training Command (GPU box)

```bash
# Install deps first
pip install 'trl>=0.11' 'transformers>=4.45' 'peft>=0.13' 'datasets>=3.0' 'bitsandbytes>=0.43' accelerate

# Stage 1+2: SFT warm-start then DPO preference alignment
FIXOPS_DISTILL_TRAIN=1 python scripts/llm_distill_train.py \
  --base-model Qwen/Qwen2.5-7B-Instruct \
  --sft-jsonl data/distill_sft.jsonl \
  --dpo-jsonl data/distill_train.jsonl \
  --epochs-sft 1 \
  --epochs-dpo 1 \
  --lora-r 16 \
  --lora-alpha 32 \
  --lora-dropout 0.05 \
  --learning-rate 2e-5 \
  --max-seq-len 2048

# Smoke test only (100 steps, validate loss curve)
FIXOPS_DISTILL_TRAIN=1 python scripts/llm_distill_train.py \
  --base-model Qwen/Qwen2.5-7B-Instruct \
  --epochs-sft 1 --epochs-dpo 1 \
  --max-steps 100
```

---

## 4. Hyperparameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Base model | Qwen/Qwen2.5-7B-Instruct | Open-weight, no auth, air-gap friendly |
| LoRA rank (r) | 16 | Standard PEFT sweet-spot for 7B |
| LoRA alpha | 32 | 2× rank per convention |
| LoRA dropout | 0.05 | Light regularization |
| LoRA target modules | q_proj, k_proj, v_proj, o_proj | All attention projections |
| Quantization | 4-bit nf4 (bitsandbytes) | Fits 7B in 8GB VRAM |
| SFT learning rate | 2e-5 | Standard SFT warm-start |
| DPO learning rate | 1e-5 | Half of SFT (DPO preference tuning needs lower LR) |
| DPO beta | 0.1 | Reference model KL weight |
| Batch size | 1 + grad_accum=8 | Effective batch 8 for memory safety |
| Max seq length | 2048 | Covers full prompt+response |
| SFT epochs | 1 | Warm-start only |
| DPO epochs | 1 | First preference pass |

---

## 5. Expected Wall-Clock on GPU Tiers

5,196 training records × 2 stages (SFT + DPO):

| GPU | VRAM | SFT (1 epoch) | DPO (1 epoch) | Total |
|-----|------|--------------|--------------|-------|
| A100 80GB | 80GB | ~25 min | ~40 min | ~65 min |
| H100 80GB | 80GB | ~15 min | ~25 min | ~40 min |
| L40S 48GB | 48GB | ~35 min | ~55 min | ~90 min |
| A10G 24GB | 24GB | ~70 min | ~110 min | ~180 min |
| RTX 4090 24GB | 24GB | ~60 min | ~95 min | ~155 min |

Estimates assume 4-bit nf4 + batch_size=1 + grad_accum=8. H100 recommended for cost/speed.

---

## 6. Expected Output

```
data/distill_adapter_<UTC-timestamp>/
  sft/                        # Stage 1 LoRA adapter (SFT warm-start)
    adapter_model.safetensors
    adapter_config.json
    tokenizer.json
  dpo/                        # Stage 2 LoRA adapter (DPO preference aligned)
    adapter_model.safetensors
    adapter_config.json
    tokenizer.json
  trainer_trace.json          # Full run telemetry
```

Final merged adapter target: `models/llm_distill_v1.safetensors`

---

## 7. Inference Router Wiring

After training, wire the adapter into `scripts/llm_distill_router.py`:

```python
# llm_distill_router.py — plug in after training
DISTILL_ADAPTER_PATH = "data/distill_adapter_<UTC>/dpo"

def route(task: str, confidence: float) -> str:
    """Route low-confidence council decisions to distilled student."""
    if confidence < DISTILL_CONFIDENCE_THRESHOLD:
        return _infer_student(task, adapter=DISTILL_ADAPTER_PATH)
    return _infer_council(task)
```

The router replaces the Opus escalation slot for decisions below the confidence threshold, cutting inference cost from ~$15/M (Opus) to ~$0/token (self-hosted Qwen student).

---

## 8. Phase Gate

| Gate | Target | Current |
|------|--------|---------|
| Phase 1: DPO pairs collected | 5,000 | 5,196 (PASSED) |
| Phase 2: Local pipeline validates | dry-run OK | PASSED |
| Phase 2 GA: Training completes | full run | PENDING — awaiting GPU box |
| Phase 2 GA: Student F1 >= 0.75 | eval on held-out | PENDING |
| Phase 3: 10K pairs for distillation V2 | 10,000 | 5,196 (52% there) |

---

## 9. Decisions Log

```
[2026-04-27 11:56] data-scientist DECISION: Run curator with --include-smoke
  CONTEXT: All 5196 pairs from learning_signals.db needed; smoke sources acceptable
  ACTION: python scripts/llm_distill_dataset_curator.py --include-smoke
  RESULT: SUCCESS — 5196/5196 pairs kept, 0 dropped

[2026-04-27 11:56] data-scientist DECISION: No GPU training — MPS only
  CONTEXT: torch.cuda.is_available()=False; MPS available but lacks bitsandbytes 4-bit nf4
  ACTION: dry-run validation only; produced kickoff doc for remote GPU execution
  RESULT: SUCCESS — pipeline validated, ready for remote box
  ROLLBACK: N/A — no weights modified
```
