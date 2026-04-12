#!/usr/bin/env python3
"""Free Model Worker — routes code generation to local Ollama or OpenRouter.

Usage:
    python scripts/free_model_worker.py --task "Write pytest tests for X" --output tests/test_x.py
    python scripts/free_model_worker.py --task "Write FastAPI router for Y" --output suite-api/apps/api/y_router.py
    python scripts/free_model_worker.py --task-file prompts/task.txt --output output.py

Models (in priority order):
    1. Local Ollama (gemma3:4b) — fastest, $0
    2. OpenRouter (qwen/qwen3-coder:free) — best quality, $0 but rate-limited
    3. OpenRouter (qwen/qwen3-next-80b-a3b-instruct:free) — fallback, $0
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

OPENROUTER_KEY = os.environ.get(
    "OPENROUTER_API_KEY",
    "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",
)

OLLAMA_MODELS = ["gemma4", "gemma3:4b", "gemma:7b"]
OPENROUTER_MODELS = [
    "qwen/qwen3-coder:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
]


def call_ollama(prompt: str, model: str = "gemma3:4b") -> str | None:
    """Call local Ollama model."""
    try:
        result = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def call_openrouter(prompt: str, model: str) -> str | None:
    """Call OpenRouter API."""
    try:
        import urllib.request

        data = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
        }).encode()

        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
            },
        )

        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            if "choices" in result:
                return result["choices"][0]["message"]["content"]
    except Exception:
        pass
    return None


def extract_code(response: str) -> str:
    """Extract code from markdown code blocks if present."""
    lines = response.split("\n")
    in_block = False
    code_lines = []

    for line in lines:
        if line.strip().startswith("```") and not in_block:
            in_block = True
            continue
        elif line.strip() == "```" and in_block:
            in_block = False
            continue
        elif in_block:
            code_lines.append(line)

    return "\n".join(code_lines) if code_lines else response


def generate(prompt: str) -> str | None:
    """Try models in priority order until one succeeds."""
    # 1. Try local Ollama first ($0, fastest)
    for model in OLLAMA_MODELS:
        print(f"  Trying Ollama {model}...", end=" ", flush=True)
        result = call_ollama(prompt, model)
        if result:
            print("OK")
            return result
        print("failed")

    # 2. Try OpenRouter free models
    for model in OPENROUTER_MODELS:
        print(f"  Trying OpenRouter {model}...", end=" ", flush=True)
        result = call_openrouter(prompt, model)
        if result:
            print("OK")
            return result
        print("failed (rate limited?)")
        time.sleep(2)

    return None


def main():
    parser = argparse.ArgumentParser(description="Free Model Worker")
    parser.add_argument("--task", help="Task description")
    parser.add_argument("--task-file", help="File containing task description")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--model", default="auto", help="Model to use (default: auto)")
    args = parser.parse_args()

    if args.task_file:
        prompt = Path(args.task_file).read_text()
    elif args.task:
        prompt = args.task
    else:
        print("Error: provide --task or --task-file")
        sys.exit(1)

    print(f"[Free Model Worker] Generating: {args.output}")
    result = generate(prompt)

    if result:
        code = extract_code(result)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(code + "\n")
        print(f"[Free Model Worker] Written to {args.output} ({len(code)} chars)")
    else:
        print("[Free Model Worker] All models failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
