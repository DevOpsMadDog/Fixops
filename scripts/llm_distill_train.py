#!/usr/bin/env python3
"""LLM Distillation Phase 2 — Trainer (SFT then DPO).

Two-stage student fine-tuning on Opus reasoning captured by the Phase 1 closed
loop:

1. **SFT warm-start** (``trl.SFTTrainer`` over ``data/distill_sft.jsonl``) —
   teaches the student to produce action+reasoning in the canonical format.
2. **DPO preference alignment** (``trl.DPOTrainer`` over
   ``data/distill_train.jsonl``) — pulls the student toward Opus-chosen
   responses and away from rejected ones.

Default base model: ``Qwen/Qwen2.5-7B-Instruct`` (open weight on HF hub, no
auth required for download). Override with ``--base-model``.

LoRA-only (4-bit nf4 via ``bitsandbytes`` when CUDA is present, else float16
on CPU/MPS for the dry-run path). Adapter outputs land at
``data/distill_adapter_<UTC-timestamp>/``.

GATING (cost-guard):

    Full training requires ``FIXOPS_DISTILL_TRAIN=1`` in env. Without it the
    script refuses to spend GPU time and exits 2 unless ``--dry-run`` is set.

DRY-RUN mode:

    --dry-run boots the dataset loader, validates JSONL schema, optionally
    instantiates a tiny tokenizer, processes ``--dry-run-samples`` records
    (default 10) end-to-end through the trainer **wiring** (no gradient
    steps, no GPU). Validates the pipeline on a CPU/Mac in seconds.

Examples:

    # Pipeline validation — no training, no GPU, no env var needed
    python scripts/llm_distill_train.py --dry-run

    # Real training (requires GPU + env var + libs)
    FIXOPS_DISTILL_TRAIN=1 python scripts/llm_distill_train.py \\
        --base-model Qwen/Qwen2.5-7B-Instruct \\
        --epochs-sft 1 --epochs-dpo 1
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DPO_JSONL = ROOT / "data" / "distill_train.jsonl"
DEFAULT_SFT_JSONL = ROOT / "data" / "distill_sft.jsonl"
DEFAULT_ADAPTER_BASE = ROOT / "data"

logging.basicConfig(
    level=os.environ.get("FIXOPS_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("distill-train")

DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"
GATING_ENV_VAR = "FIXOPS_DISTILL_TRAIN"
LIB_HINT_PIP = "pip install 'trl>=0.11' 'transformers>=4.45' 'peft>=0.13' 'datasets>=3.0' 'bitsandbytes>=0.43' accelerate"

# Minimum schema requirements per record type
SFT_REQUIRED_KEYS = {"messages"}
DPO_REQUIRED_KEYS = {"prompt", "chosen", "rejected"}


# ---------------------------------------------------------------------------
# Trace + dataset helpers
# ---------------------------------------------------------------------------


@dataclass
class TrainerTrace:
    """Captures dry-run / real-run telemetry for the run manifest."""

    started_at: str = ""
    finished_at: str = ""
    mode: str = "dry-run"
    base_model: str = ""
    sft_path: str = ""
    dpo_path: str = ""
    sft_records_seen: int = 0
    dpo_records_seen: int = 0
    sft_records_valid: int = 0
    dpo_records_valid: int = 0
    sft_records_invalid: int = 0
    dpo_records_invalid: int = 0
    library_status: Dict[str, str] = field(default_factory=dict)
    device: str = ""
    output_dir: str = ""
    notes: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                log.warning("%s:%d malformed JSON, skipping: %s", path.name, line_no, exc)
    return out


def _validate_sft(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    valid: List[Dict[str, Any]] = []
    invalid = 0
    for rec in records:
        if not isinstance(rec, dict) or not SFT_REQUIRED_KEYS.issubset(rec.keys()):
            invalid += 1
            continue
        msgs = rec.get("messages")
        if not isinstance(msgs, list) or not msgs:
            invalid += 1
            continue
        if not all(isinstance(m, dict) and "role" in m and "content" in m for m in msgs):
            invalid += 1
            continue
        # require an assistant turn (the training target)
        if not any(m["role"] == "assistant" for m in msgs):
            invalid += 1
            continue
        valid.append(rec)
    return valid, invalid


def _validate_dpo(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    valid: List[Dict[str, Any]] = []
    invalid = 0
    for rec in records:
        if not isinstance(rec, dict) or not DPO_REQUIRED_KEYS.issubset(rec.keys()):
            invalid += 1
            continue
        if not all(isinstance(rec[k], str) and rec[k].strip() for k in DPO_REQUIRED_KEYS):
            invalid += 1
            continue
        if rec["chosen"] == rec["rejected"]:
            invalid += 1
            continue
        valid.append(rec)
    return valid, invalid


# ---------------------------------------------------------------------------
# Optional library probing
# ---------------------------------------------------------------------------


def _probe_libraries() -> Dict[str, str]:
    status: Dict[str, str] = {}
    for mod in ("torch", "transformers", "trl", "peft", "datasets", "bitsandbytes", "accelerate"):
        try:
            m = __import__(mod)
            status[mod] = getattr(m, "__version__", "present")
        except ImportError:
            status[mod] = "MISSING"
    return status


def _detect_device(torch_mod: Any) -> str:
    try:
        if torch_mod.cuda.is_available():
            return "cuda"
        if hasattr(torch_mod.backends, "mps") and torch_mod.backends.mps.is_available():
            return "mps"
    except (AttributeError, RuntimeError):
        pass
    return "cpu"


# ---------------------------------------------------------------------------
# Dry-run pipeline
# ---------------------------------------------------------------------------


def run_dry(
    sft_path: Path,
    dpo_path: Path,
    *,
    base_model: str,
    sample_n: int,
    output_dir: Path,
) -> TrainerTrace:
    trace = TrainerTrace(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="dry-run",
        base_model=base_model,
        sft_path=str(sft_path),
        dpo_path=str(dpo_path),
        output_dir=str(output_dir),
    )
    t_start = time.perf_counter()

    sft_raw = _read_jsonl(sft_path)
    dpo_raw = _read_jsonl(dpo_path)
    trace.sft_records_seen = len(sft_raw)
    trace.dpo_records_seen = len(dpo_raw)

    sft_valid, sft_invalid = _validate_sft(sft_raw)
    dpo_valid, dpo_invalid = _validate_dpo(dpo_raw)
    trace.sft_records_valid = len(sft_valid)
    trace.sft_records_invalid = sft_invalid
    trace.dpo_records_valid = len(dpo_valid)
    trace.dpo_records_invalid = dpo_invalid

    log.info(
        "SFT dataset: %d total / %d valid / %d invalid",
        trace.sft_records_seen, trace.sft_records_valid, trace.sft_records_invalid,
    )
    log.info(
        "DPO dataset: %d total / %d valid / %d invalid",
        trace.dpo_records_seen, trace.dpo_records_valid, trace.dpo_records_invalid,
    )

    trace.library_status = _probe_libraries()
    trace.notes.append(f"library_status={trace.library_status}")

    # Try to detect device. Soft-fail on missing torch.
    device = "cpu"
    try:
        import torch  # type: ignore
        device = _detect_device(torch)
    except ImportError:
        trace.notes.append("torch not installed; device=cpu by default")
    trace.device = device

    # Walk through `sample_n` records (or all if fewer) to confirm the structure
    # is trainer-ready. We do not actually load the base model in dry-run —
    # downloading 7B weights is not appropriate for dry-run. We DO validate
    # schema-level transforms.
    sample_n = max(0, min(sample_n, max(trace.sft_records_valid, trace.dpo_records_valid)))
    processed = 0
    for i in range(sample_n):
        if i < len(sft_valid):
            rec = sft_valid[i]
            assert isinstance(rec["messages"], list) and rec["messages"]
            processed += 1
        if i < len(dpo_valid):
            rec = dpo_valid[i]
            assert rec["chosen"] != rec["rejected"]
            processed += 1
    trace.notes.append(f"sample_processed={processed}")

    # Try the real trl import path so the user knows whether the next step would
    # crash. Any ImportError is captured but does not fail the dry-run — the
    # whole point of dry-run is "boots without GPU/libs."
    try:
        from trl import DPOTrainer  # noqa: F401  # type: ignore
        from trl import SFTTrainer  # noqa: F401  # type: ignore

        trace.notes.append("trl.DPOTrainer + trl.SFTTrainer importable")
    except ImportError as exc:
        trace.notes.append(f"trl import deferred (expected on dev box): {exc}")

    output_dir.mkdir(parents=True, exist_ok=True)
    trace.elapsed_seconds = round(time.perf_counter() - t_start, 3)
    trace.finished_at = datetime.now(timezone.utc).isoformat()
    return trace


# ---------------------------------------------------------------------------
# Real training entrypoint (gated)
# ---------------------------------------------------------------------------


def run_full(
    sft_path: Path,
    dpo_path: Path,
    *,
    base_model: str,
    output_dir: Path,
    epochs_sft: int,
    epochs_dpo: int,
    learning_rate: float,
    lora_r: int,
    lora_alpha: int,
    lora_dropout: float,
    load_in_4bit: bool,
    max_seq_len: int,
) -> TrainerTrace:
    """Real training pipeline. Will error out cleanly if libs are missing."""
    trace = TrainerTrace(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="full-train",
        base_model=base_model,
        sft_path=str(sft_path),
        dpo_path=str(dpo_path),
        output_dir=str(output_dir),
    )
    t_start = time.perf_counter()
    trace.library_status = _probe_libraries()
    missing = [k for k, v in trace.library_status.items() if v == "MISSING" and k != "bitsandbytes"]
    if missing:
        raise RuntimeError(
            f"Cannot run full training; missing required libs: {missing}. "
            f"Install with: {LIB_HINT_PIP}"
        )

    # Imports are deferred so the dry-run path doesn't require these libs.
    import torch  # type: ignore
    from datasets import Dataset  # type: ignore
    from peft import LoraConfig  # type: ignore
    from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
    from trl import DPOConfig, DPOTrainer, SFTConfig, SFTTrainer  # type: ignore

    device = _detect_device(torch)
    trace.device = device
    log.info("Device: %s | base model: %s", device, base_model)

    sft_raw = _read_jsonl(sft_path)
    dpo_raw = _read_jsonl(dpo_path)
    sft_valid, _ = _validate_sft(sft_raw)
    dpo_valid, _ = _validate_dpo(dpo_raw)
    trace.sft_records_seen = len(sft_raw)
    trace.dpo_records_seen = len(dpo_raw)
    trace.sft_records_valid = len(sft_valid)
    trace.dpo_records_valid = len(dpo_valid)

    if not sft_valid and not dpo_valid:
        raise RuntimeError("No valid SFT or DPO records — refusing to train on empty data.")

    # ---- Tokenizer + model ------------------------------------------------
    log.info("Loading tokenizer…")
    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    log.info("Loading base model (load_in_4bit=%s)…", load_in_4bit)
    model_kwargs: Dict[str, Any] = {"torch_dtype": torch.float16}
    if load_in_4bit and device == "cuda":
        try:
            from transformers import BitsAndBytesConfig  # type: ignore

            model_kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
        except ImportError:
            log.warning("bitsandbytes unavailable; falling back to fp16 full-weight load.")
    base = AutoModelForCausalLM.from_pretrained(base_model, **model_kwargs)

    lora_cfg = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        bias="none",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        task_type="CAUSAL_LM",
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    sft_dir = output_dir / "sft"
    dpo_dir = output_dir / "dpo"

    # ---- Stage 1: SFT -----------------------------------------------------
    if sft_valid:
        log.info("Stage 1 — SFT over %d records", len(sft_valid))
        sft_ds = Dataset.from_list(sft_valid)
        sft_cfg = SFTConfig(
            output_dir=str(sft_dir),
            num_train_epochs=epochs_sft,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            learning_rate=learning_rate,
            logging_steps=10,
            save_strategy="epoch",
            max_seq_length=max_seq_len,
            report_to=[],
        )
        sft_trainer = SFTTrainer(
            model=base,
            args=sft_cfg,
            train_dataset=sft_ds,
            peft_config=lora_cfg,
            tokenizer=tokenizer,
        )
        sft_trainer.train()
        sft_trainer.save_model(str(sft_dir))
        trace.notes.append(f"sft_completed; adapter@{sft_dir}")

    # ---- Stage 2: DPO -----------------------------------------------------
    if dpo_valid:
        log.info("Stage 2 — DPO over %d preference pairs", len(dpo_valid))
        dpo_ds = Dataset.from_list(dpo_valid)
        dpo_cfg = DPOConfig(
            output_dir=str(dpo_dir),
            num_train_epochs=epochs_dpo,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            learning_rate=learning_rate / 2,  # DPO typically wants a lower LR
            logging_steps=10,
            save_strategy="epoch",
            beta=0.1,
            max_length=max_seq_len,
            max_prompt_length=max_seq_len // 2,
            report_to=[],
        )
        dpo_trainer = DPOTrainer(
            model=base,
            args=dpo_cfg,
            train_dataset=dpo_ds,
            peft_config=lora_cfg,
            tokenizer=tokenizer,
        )
        dpo_trainer.train()
        dpo_trainer.save_model(str(dpo_dir))
        trace.notes.append(f"dpo_completed; adapter@{dpo_dir}")

    trace.elapsed_seconds = round(time.perf_counter() - t_start, 3)
    trace.finished_at = datetime.now(timezone.utc).isoformat()
    return trace


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _timestamp_dir(base: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return base / f"distill_adapter_{ts}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sft-jsonl", type=Path, default=DEFAULT_SFT_JSONL)
    parser.add_argument("--dpo-jsonl", type=Path, default=DEFAULT_DPO_JSONL)
    parser.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Adapter output directory (default: data/distill_adapter_<UTC>)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate pipeline without training.")
    parser.add_argument("--dry-run-samples", type=int, default=10)
    parser.add_argument("--epochs-sft", type=int, default=1)
    parser.add_argument("--epochs-dpo", type=int, default=1)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--no-4bit", action="store_true", help="Disable 4-bit quantisation (uses fp16).")
    parser.add_argument("--max-seq-len", type=int, default=2048)
    args = parser.parse_args(argv)

    output_dir = args.output_dir or _timestamp_dir(DEFAULT_ADAPTER_BASE)

    if args.dry_run:
        log.info("DRY-RUN: validating pipeline; no training, no GPU.")
        trace = run_dry(
            args.sft_jsonl,
            args.dpo_jsonl,
            base_model=args.base_model,
            sample_n=args.dry_run_samples,
            output_dir=output_dir,
        )
    else:
        gating = os.environ.get(GATING_ENV_VAR, "")
        if gating not in ("1", "true", "yes"):
            log.error(
                "Cost-guard refused: %s is not set. To run real training, "
                "explicitly set %s=1 (this prevents accidental cloud-GPU spend).",
                GATING_ENV_VAR, GATING_ENV_VAR,
            )
            log.error("Use --dry-run to validate the pipeline without training.")
            return 2
        log.info("Cost-guard cleared (%s=%s). Beginning real training.", GATING_ENV_VAR, gating)
        trace = run_full(
            args.sft_jsonl,
            args.dpo_jsonl,
            base_model=args.base_model,
            output_dir=output_dir,
            epochs_sft=args.epochs_sft,
            epochs_dpo=args.epochs_dpo,
            learning_rate=args.learning_rate,
            lora_r=args.lora_r,
            lora_alpha=args.lora_alpha,
            lora_dropout=args.lora_dropout,
            load_in_4bit=not args.no_4bit,
            max_seq_len=args.max_seq_len,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / "trainer_trace.json"
    trace_path.write_text(json.dumps(trace.as_dict(), indent=2), encoding="utf-8")
    log.info("Wrote trace: %s", trace_path)
    log.info("Trace summary: mode=%s elapsed=%.3fs sft_valid=%d dpo_valid=%d device=%s",
             trace.mode, trace.elapsed_seconds, trace.sft_records_valid,
             trace.dpo_records_valid, trace.device)
    return 0


if __name__ == "__main__":
    sys.exit(main())
