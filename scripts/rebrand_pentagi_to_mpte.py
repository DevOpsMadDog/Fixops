#!/usr/bin/env python3
"""Rebrand MPTE → MPTE across the entire codebase.

Phase 5 of FixOps Transformation Plan.
Renames files, updates imports, class names, API paths, comments.
"""
import os
import re
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"archive", "node_modules", "__pycache__", ".next", ".git", "dist", ".turbo"}
EXTENSIONS = {".py", ".ts", ".tsx", ".md", ".yml", ".yaml", ".json"}

# Order matters — longer/more specific patterns first to avoid partial matches
CONTENT_REPLACEMENTS = [
    # Class names (most specific first)
    ("AdvancedMPTEService", "AdvancedMPTEService"),
    ("AdvancedMPTEClient", "AdvancedMPTEClient"),
    ("MPTEDecisionIntegration", "MPTEDecisionIntegration"),
    ("MPTETestResult", "MPTETestResult"),
    ("MPTETestType", "MPTETestType"),
    ("MPTEFinding", "MPTEFinding"),
    ("MPTESeverity", "MPTESeverity"),
    ("MPTEClient", "MPTEClient"),
    ("MPTEDB", "MPTEDB"),
    ("MultiAIOrchestrator", "MultiAIOrchestrator"),  # keep as-is
    # Module/import paths (before generic mpte)
    ("mpte_router", "mpte_router"),
    ("mpte_decision_integration", "mpte_decision_integration"),
    ("mpte_integration", "mpte_integration"),
    ("mpte_advanced", "mpte_advanced"),
    ("mpte_service", "mpte_service"),
    ("mpte_client", "mpte_client"),
    ("mpte_models", "mpte_models"),
    ("mpte_db", "mpte_db"),
    # API path prefixes
    ('prefix="/api/v1/mpte"', 'prefix="/api/v1/mpte"'),
    ('prefix="/mpte"', 'prefix="/mpte"'),
    ("/api/v1/mpte/", "/api/v1/mpte/"),
    ("/api/v1/mpte", "/api/v1/mpte"),
    # Router tags
    ('tags=["mpte"]', 'tags=["mpte"]'),
    ('tags=["MPTE Integration"]', 'tags=["MPTE Integration"]'),
    ('tags=["MPTE"]', 'tags=["MPTE"]'),
    # Env vars
    ("MPTE_BASE_URL", "MPTE_BASE_URL"),
    ("MPTE_URL", "MPTE_URL"),
    # Docker/compose service names and directories
    ("mpte-service", "mpte-service"),
    ("mpte-aldeci", "mpte-aldeci"),
    # Generic brand replacements (order: MPTE → MPTE → mpte → MPTE)
    ("MPTE", "MPTE"),
    ("MPTE", "MPTE"),
    # Be careful with lowercase — only in non-URL contexts
    # We already handled module paths above, so remaining are comments/strings
]

# Lowercase mpte handled separately to avoid re-replacing mpte paths
LOWERCASE_REPLACEMENTS = [
    ("mpte", "mpte"),
    ("MPTE", "MPTE"),
]

# File renames: (old_relative_path, new_relative_path)
FILE_RENAMES = [
    ("suite-attack/api/mpte_router.py", "suite-attack/api/mpte_router.py"),
    ("suite-core/core/mpte_advanced.py", "suite-core/core/mpte_advanced.py"),
    ("suite-core/core/mpte_db.py", "suite-core/core/mpte_db.py"),
    ("suite-core/core/mpte_models.py", "suite-core/core/mpte_models.py"),
    ("suite-integrations/integrations/mpte_client.py", "suite-integrations/integrations/mpte_client.py"),
    ("suite-integrations/integrations/mpte_decision_integration.py", "suite-integrations/integrations/mpte_decision_integration.py"),
    ("suite-integrations/integrations/mpte_service.py", "suite-integrations/integrations/mpte_service.py"),
    ("suite-api/apps/mpte_integration.py", "suite-api/apps/mpte_integration.py"),
    ("suite-ui/aldeci/src/components/attack/MPTEChat.tsx", "suite-ui/aldeci/src/components/attack/MPTEChat.tsx"),
    ("suite-ui/aldeci/src/pages/attack/MPTEConsole.tsx", "suite-ui/aldeci/src/pages/attack/MPTEConsole.tsx"),
    ("docker-compose.mpte.yml", "docker-compose.mpte.yml"),
    ("docs/MPTE_INTEGRATION.md", "docs/MPTE_INTEGRATION.md"),
]

# Directory renames
DIR_RENAMES = [
    ("suite-integrations/mpte-aldeci", "suite-integrations/mpte-aldeci"),
]


def should_process(path: str) -> bool:
    parts = path.split(os.sep)
    return not any(skip in parts for skip in SKIP_DIRS)


def replace_content(text: str) -> str:
    for old, new in CONTENT_REPLACEMENTS:
        text = text.replace(old, new)
    for old, new in LOWERCASE_REPLACEMENTS:
        text = text.replace(old, new)
    return text


def main():
    # Step 0: Rename directories
    print("=== Step 0: Renaming directories ===")
    for old_rel, new_rel in DIR_RENAMES:
        old_abs = os.path.join(ROOT, old_rel)
        new_abs = os.path.join(ROOT, new_rel)
        if os.path.isdir(old_abs):
            shutil.move(old_abs, new_abs)
            print(f"  RENAMED DIR: {old_rel} -> {new_rel}")
        else:
            print(f"  SKIP DIR (not found): {old_rel}")

    # Step 1: Rename files
    print("\n=== Step 1: Renaming files ===")
    for old_rel, new_rel in FILE_RENAMES:
        old_abs = os.path.join(ROOT, old_rel)
        new_abs = os.path.join(ROOT, new_rel)
        if os.path.exists(old_abs):
            os.makedirs(os.path.dirname(new_abs), exist_ok=True)
            shutil.move(old_abs, new_abs)
            print(f"  RENAMED: {old_rel} -> {new_rel}")
        else:
            print(f"  SKIP (not found): {old_rel}")

    # Step 2: Update file contents
    print("\n=== Step 2: Updating file contents ===")
    changed_files = 0
    total_replacements = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1]
            if ext not in EXTENSIONS:
                continue
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, ROOT)
            if not should_process(rel):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    original = f.read()
            except Exception:
                continue
            updated = replace_content(original)
            if updated != original:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(updated)
                count = sum(1 for a, b in zip(original, updated) if a != b)
                changed_files += 1
                total_replacements += original.count("mpte") + original.count("MPTE") + original.count("MPTE") + original.count("MPTE")
                print(f"  UPDATED: {rel}")

    print(f"\n=== Summary ===")
    print(f"Files renamed: {sum(1 for o, _ in FILE_RENAMES if os.path.exists(os.path.join(ROOT, _.replace(o, ''))) or True)}")
    print(f"Files content-updated: {changed_files}")
    print(f"Approximate replacements: {total_replacements}")


if __name__ == "__main__":
    main()

