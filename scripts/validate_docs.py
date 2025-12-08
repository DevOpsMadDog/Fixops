#!/usr/bin/env python3
"""Validate documentation file references.

This script checks that all file references in markdown documentation files
actually exist in the codebase. It helps catch errors like referencing
non-existent files (e.g., lib4sbom/quality.py when only normalizer.py exists).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

# Pattern to match file references in markdown
# Matches patterns like: `path/to/file.py`, `lib4sbom/normalizer.py`, etc.
FILE_REF_PATTERN = re.compile(r"`([a-zA-Z0-9_\-./]+\.(py|js|jsx|ts|tsx|yaml|yml|json|md|rego|psl))`")


def find_file_references(content: str) -> List[str]:
    """Extract file references from markdown content."""
    references = []
    for match in FILE_REF_PATTERN.finditer(content):
        file_path = match.group(1)
        # Skip URLs and external references
        if not file_path.startswith("http") and "/" in file_path:
            references.append(file_path)
    return references


def validate_file_exists(file_path: str, workspace_root: Path) -> Tuple[bool, str]:
    """Check if a file exists in the workspace."""
    full_path = workspace_root / file_path
    if full_path.exists():
        return True, ""
    return False, f"File not found: {file_path}"


def validate_documentation_file(doc_path: Path, workspace_root: Path) -> List[str]:
    """Validate all file references in a documentation file."""
    errors = []
    try:
        content = doc_path.read_text(encoding="utf-8")
        references = find_file_references(content)
        
        for ref in references:
            exists, error_msg = validate_file_exists(ref, workspace_root)
            if not exists:
                errors.append(f"{doc_path.relative_to(workspace_root)}: {error_msg}")
    except Exception as e:
        errors.append(f"{doc_path.relative_to(workspace_root)}: Error reading file: {e}")
    
    return errors


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate file references in documentation"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["analysis", "docs"],
        help="Directories or files to check (default: analysis docs)",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path.cwd(),
        help="Workspace root directory (default: current directory)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error code if any issues found",
    )
    
    args = parser.parse_args()
    workspace_root = args.workspace_root.resolve()
    
    # Collect all markdown files
    markdown_files = []
    for path_arg in args.paths:
        path = Path(path_arg)
        if not path.is_absolute():
            path = workspace_root / path
        
        if path.is_file() and path.suffix == ".md":
            markdown_files.append(path)
        elif path.is_dir():
            markdown_files.extend(path.rglob("*.md"))
    
    # Validate each file
    all_errors = []
    for doc_file in sorted(markdown_files):
        errors = validate_documentation_file(doc_file, workspace_root)
        all_errors.extend(errors)
    
    # Report results
    if all_errors:
        print("❌ Documentation validation found issues:\n", file=sys.stderr)
        for error in all_errors:
            print(f"  {error}", file=sys.stderr)
        if args.strict:
            sys.exit(1)
        else:
            print(f"\n⚠️  Found {len(all_errors)} issue(s)", file=sys.stderr)
            sys.exit(0)
    else:
        print("✅ All file references are valid!")
        sys.exit(0)


if __name__ == "__main__":
    main()
