#!/usr/bin/env python3
"""Deep audit script to find EventBus, KnowledgeBrain, and other integration usage."""
import os
import re

PROJECT = "/Users/devops.ai/developement/fixops/Fixops"
SKIP = {"__pycache__", "node_modules", ".git", "archive", ".vite", "dist"}


def walk_py(base_dirs):
    """Yield (rel_path, content) for all .py files in suite-* directories."""
    for bd in base_dirs:
        full = os.path.join(PROJECT, bd)
        if not os.path.isdir(full):
            continue
        for root, dirs, files in os.walk(full):
            dirs[:] = [d for d in dirs if d not in SKIP]
            for f in files:
                if not f.endswith(".py"):
                    continue
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, PROJECT)
                try:
                    content = open(fp, encoding="utf-8", errors="replace").read()
                    yield rel, content
                except Exception:
                    pass


suites = [
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
]

print("=" * 80)
print("SECTION 1: Files that import/use EventBus")
print("=" * 80)
bus_files = []
for path, txt in walk_py(suites):
    if "event_bus" in path:
        continue
    if "get_event_bus" in txt or "EventBus" in txt or "event_bus" in txt:
        bus_files.append(path)
        # Check if actually calling emit or subscribe
        has_emit = "bus.emit" in txt or ".emit(" in txt
        has_sub = "bus.subscribe" in txt or "bus.on(" in txt or ".on(EventType" in txt
        has_import_only = not has_emit and not has_sub
        tag = "EMIT" if has_emit else ("SUB" if has_sub else "IMPORT-ONLY")
        print(f"  [{tag}] {path}")

print(f"\nTotal files using EventBus: {len(bus_files)}")

print("\n" + "=" * 80)
print("SECTION 2: Files that import/use KnowledgeBrain / get_brain")
print("=" * 80)
brain_files = []
for path, txt in walk_py(suites):
    if "knowledge_brain" in path:
        continue
    if "get_brain" in txt or "KnowledgeBrain" in txt or "knowledge_brain" in txt:
        brain_files.append(path)
        has_call = "get_brain()" in txt or "brain." in txt
        tag = "ACTIVE" if has_call else "IMPORT-ONLY"
        print(f"  [{tag}] {path}")

print(f"\nTotal files using KnowledgeBrain: {len(brain_files)}")

print("\n" + "=" * 80)
print("SECTION 3: Inter-service HTTP calls (httpx/requests/aiohttp)")
print("=" * 80)
for path, txt in walk_py(suites):
    patterns = [
        "httpx",
        "requests.get",
        "requests.post",
        "aiohttp.ClientSession",
        "urllib.request",
        "http.client",
    ]
    found = [p for p in patterns if p in txt]
    if found:
        print(f"  {path}: {', '.join(found)}")

print("\n" + "=" * 80)
print("SECTION 4: Hardcoded secrets / API keys / passwords")
print("=" * 80)
secret_patterns = [
    (r'api[_-]?key\s*=\s*["\'][^"\']{10,}', "API_KEY"),
    (r'password\s*=\s*["\'][^"\']{3,}', "PASSWORD"),
    (r'secret\s*=\s*["\'][^"\']{5,}', "SECRET"),
    (r'token\s*=\s*["\'][^"\']{10,}', "TOKEN"),
    (r"sk-[a-zA-Z0-9]{20,}", "OPENAI_KEY"),
    (r"ghp_[a-zA-Z0-9]{36}", "GITHUB_TOKEN"),
]
for path, txt in walk_py(suites):
    for pat, label in secret_patterns:
        matches = re.findall(pat, txt, re.IGNORECASE)
        for m in matches:
            if "os.getenv" in m or "os.environ" in m or "env" in m.lower():
                continue
            print(f"  [{label}] {path}: {m[:80]}")

print("\n" + "=" * 80)
print("SECTION 5: CLI commands and their API targets")
print("=" * 80)
for path, txt in walk_py(suites):
    if "cli" in path.lower():
        # Find function defs
        funcs = re.findall(r"def\s+(\w+)\(", txt)
        urls = re.findall(r'["\'](?:http[s]?://[^"\']+|/api/v1/[^"\']+)["\']', txt)
        print(f"  {path}: {len(funcs)} functions, {len(urls)} URL refs")
        for u in urls[:10]:
            print(f"    URL: {u}")

print("\n" + "=" * 80)
print("SECTION 6: Brain Pipeline Orchestrator steps")
print("=" * 80)
for path, txt in walk_py(suites):
    if "pipeline_orchestrator" in path or "brain_pipeline" in path:
        steps = re.findall(
            r"(?:step|phase|stage)[_\s]*(\d+|[a-z_]+)", txt, re.IGNORECASE
        )
        print(f"  {path}: step refs = {steps[:20]}")
        # Check for stub indicators
        stubs = re.findall(
            r"pass\s*$|NotImplemented|TODO|FIXME|STUB",
            txt,
            re.IGNORECASE | re.MULTILINE,
        )
        print(f"    Stub indicators: {len(stubs)} found")
        stubbed = re.findall(
            r".*(pass\s*$|NotImplemented|TODO|FIXME|STUB).*",
            txt,
            re.IGNORECASE | re.MULTILINE,
        )
        for s in stubbed[:10]:
            print(f"      {s.strip()[:100]}")

print("\nDONE")
