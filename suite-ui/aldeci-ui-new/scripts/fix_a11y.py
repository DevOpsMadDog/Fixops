#!/usr/bin/env python3
"""
WCAG 2.1 AA accessibility fixer for ALDECI frontend.

Fixes:
1. <table> → <table role="table">
2. Loading/error state divs → add aria-live="polite" + role="status"
3. Icon-only buttons (RefreshCw, X, etc.) → add aria-label
4. Inputs without aria-label/id → add aria-label from placeholder
5. Sort buttons → add aria-label
6. Tab buttons → add aria-label (already have visible text but let's be explicit)
"""

import os
import re
import sys

PAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "pages")

# Patterns for icon-only refresh/reload buttons that have no text
RELOAD_BUTTON_PATTERNS = [
    # <button ... onClick={...window.location.reload()...} className="...">
    (
        r'(<button\b(?![^>]*aria-label)[^>]*onClick=\{[^}]*(?:window\.location\.reload|loadData|fetchData|refetch|refresh)[^}]*\}[^>]*)>',
        lambda m: m.group(1) + ' aria-label="Refresh data">',
    ),
]

# Patterns for sort toggle buttons in table headers
SORT_BUTTON_PATTERN = re.compile(
    r'(<button\b(?![^>]*aria-label)[^>]*onClick=\{[^}]*toggle[Ss]ort\("([^"]+)"\)[^}]*\}[^>]*)>',
)

# Loading/error wrapper patterns - add aria-live + role="status"
LOADING_DIV_PATTERN = re.compile(
    r'(<div\b(?![^>]*aria-live)(?![^>]*role=)[^>]*className=["\'][^"\']*(?:loading|spinner|skeleton)[^"\']*["\'][^>]*)>',
    re.IGNORECASE,
)

ERROR_BANNER_PATTERN = re.compile(
    r'(<div\b(?![^>]*aria-live)(?![^>]*role=)[^>]*className=["\'][^"\']*(?:text-red|bg-red|error|alert)[^"\']*["\'][^>]*)>',
    re.IGNORECASE,
)

# Table pattern - add role="table"
TABLE_PATTERN = re.compile(r'<table\b(?![^>]*role=)([^>]*)>')

# Input without aria-label - add from placeholder
INPUT_PATTERN = re.compile(
    r'(<input\b(?![^>]*aria-label)(?![^>]*/?>)[^>]*placeholder="([^"]+)"[^>]*)(/?>)'
)

# Select without aria-label
SELECT_PATTERN = re.compile(
    r'(<select\b(?![^>]*aria-label)[^>]*)>'
)

def fix_tables(content: str) -> tuple[str, int]:
    """Add role="table" to <table> elements missing it."""
    count = 0
    def replacer(m):
        nonlocal count
        count += 1
        attrs = m.group(1)
        return f'<table role="table"{attrs}>'
    result = TABLE_PATTERN.sub(replacer, content)
    return result, count

def fix_inputs(content: str) -> tuple[str, int]:
    """Add aria-label from placeholder to inputs missing labels."""
    count = 0
    def replacer(m):
        nonlocal count
        count += 1
        tag_start = m.group(1)
        placeholder = m.group(2)
        close = m.group(3)
        return f'{tag_start} aria-label="{placeholder}"{close}'
    result = INPUT_PATTERN.sub(replacer, content)
    return result, count

def fix_sort_buttons(content: str) -> tuple[str, int]:
    """Add aria-label to sort toggle buttons."""
    count = 0
    def replacer(m):
        nonlocal count
        count += 1
        tag = m.group(1)
        field = m.group(2)
        label = f"Sort by {field.replace('_', ' ').title()}"
        return f'{tag} aria-label="{label}">'
    result = SORT_BUTTON_PATTERN.sub(replacer, content)
    return result, count

def fix_reload_buttons(content: str) -> tuple[str, int]:
    """Add aria-label to reload/refresh buttons."""
    count = 0
    pattern = re.compile(
        r'(<button\b(?![^>]*aria-label)[^>]*onClick=\{[^}]*(?:window\.location\.reload|loadData|fetchData|refetch|refresh|setRefresh)[^}]*\}[^>]*)>',
        re.DOTALL
    )
    def replacer(m):
        nonlocal count
        count += 1
        return m.group(1) + ' aria-label="Refresh data">'
    result = pattern.sub(replacer, content)
    return result, count

def fix_error_loading_divs(content: str) -> tuple[str, int]:
    """Add aria-live="polite" role="status" to error/loading divs."""
    count = 0

    # Error banners (text-red, bg-red, border-red patterns in className)
    err_pat = re.compile(
        r'(<div\b(?![^>]*aria-live)(?![^>]*role=)[^>]*className=\{?["\'][^"\']*(?:text-red|bg-red|border-red|error)[^"\']*["\'][^>]*)>',
        re.IGNORECASE,
    )
    def err_replacer(m):
        nonlocal count
        count += 1
        return m.group(1) + ' role="status" aria-live="polite">'
    result = err_pat.sub(err_replacer, content)

    # Loading spinners
    load_pat = re.compile(
        r'(<div\b(?![^>]*aria-live)(?![^>]*role=)[^>]*className=\{?["\'][^"\']*(?:animate-spin|loading|skeleton)[^"\']*["\'][^>]*)>',
        re.IGNORECASE,
    )
    def load_replacer(m):
        nonlocal count
        count += 1
        return m.group(1) + ' role="status" aria-live="polite">'
    result = load_pat.sub(load_replacer, result)

    return result, count

def fix_icon_only_buttons(content: str) -> tuple[str, int]:
    """
    Add aria-label to common icon-only button patterns.
    These are buttons whose body contains ONLY an icon component and no text.
    We detect them by looking at the button tag's className for known icon-button patterns.
    """
    count = 0

    # Pattern: <button ... className="...icon..."> with known icon names inside
    # We match single-line button+icon pairs
    patterns = [
        # Copy button pattern
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:Copy|ClipboardCopy)[^/]*/?>)\s*(</button>)'),
         'Copy to clipboard'),
        # Close/X button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<X\b[^/]*/?>)\s*(</button>)'),
         'Close'),
        # Trash/Delete button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:Trash|Trash2)\b[^/]*/?>)\s*(</button>)'),
         'Delete'),
        # Edit button (icon-only)
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:Edit|Edit2|Pencil)\b[^/]*/?>)\s*(</button>)'),
         'Edit'),
        # Eye/view button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Eye\b[^/]*/?>)\s*(</button>)'),
         'View details'),
        # Download button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Download\b[^/]*/?>)\s*(</button>)'),
         'Download'),
        # Search button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Search\b[^/]*/?>)\s*(</button>)'),
         'Search'),
        # Filter button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:Filter|SlidersHorizontal)\b[^/]*/?>)\s*(</button>)'),
         'Filter'),
        # Settings/gear button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:Settings|Gear|Cog)\b[^/]*/?>)\s*(</button>)'),
         'Settings'),
        # Plus/Add button (icon-only)
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Plus\b[^/]*/?>)\s*(</button>)'),
         'Add item'),
        # RefreshCw icon-only button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<RefreshCw\b[^/]*/?>)\s*(</button>)'),
         'Refresh'),
        # ChevronDown/Up (expand/collapse)
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<ChevronDown\b[^/]*/?>)\s*(</button>)'),
         'Expand'),
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<ChevronUp\b[^/]*/?>)\s*(</button>)'),
         'Collapse'),
        # Info button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Info\b[^/]*/?>)\s*(</button>)'),
         'More information'),
        # External link button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<ExternalLink\b[^/]*/?>)\s*(</button>)'),
         'Open in new window'),
        # Bell/notification button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Bell\b[^/]*/?>)\s*(</button>)'),
         'Notifications'),
        # Share button
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<Share\b[^/]*/?>)\s*(</button>)'),
         'Share'),
        # MoreVertical / MoreHorizontal (kebab menu)
        (re.compile(r'(<button\b(?![^>]*aria-label)[^>]*>)\s*(<(?:MoreVertical|MoreHorizontal|Ellipsis)\b[^/]*/?>)\s*(</button>)'),
         'More options'),
    ]

    for pat, label in patterns:
        def make_replacer(lbl):
            def replacer(m):
                nonlocal count
                # Insert aria-label into the opening button tag
                opening = m.group(1)
                # Find end of opening tag and insert aria-label before >
                opening_fixed = re.sub(r'>$', f' aria-label="{lbl}">', opening)
                count += 1
                return opening_fixed + m.group(2) + m.group(3)
            return replacer
        result = pat.sub(make_replacer(label), content)
        content = result

    return content, count

def process_file(filepath: str) -> dict:
    """Process a single TSX file and return stats."""
    with open(filepath, 'r', encoding='utf-8') as f:
        original = f.read()

    content = original
    stats = {}

    content, n = fix_tables(content)
    stats['tables'] = n

    content, n = fix_inputs(content)
    stats['inputs'] = n

    content, n = fix_sort_buttons(content)
    stats['sort_buttons'] = n

    content, n = fix_reload_buttons(content)
    stats['reload_buttons'] = n

    content, n = fix_error_loading_divs(content)
    stats['error_loading'] = n

    content, n = fix_icon_only_buttons(content)
    stats['icon_buttons'] = n

    stats['total'] = sum(stats.values())

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        stats['changed'] = True
    else:
        stats['changed'] = False

    return stats

def main():
    total_files = 0
    total_changed = 0
    total_fixes = 0
    all_stats = {}

    for root, dirs, files in os.walk(PAGES_DIR):
        # Skip node_modules etc
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', 'dist')]
        for fname in files:
            if not fname.endswith('.tsx'):
                continue
            filepath = os.path.join(root, fname)
            rel = os.path.relpath(filepath, PAGES_DIR)
            total_files += 1
            stats = process_file(filepath)
            if stats['changed']:
                total_changed += 1
                total_fixes += stats['total']
                all_stats[rel] = stats

    print(f"\nAccessibility fixes complete:")
    print(f"  Files processed:  {total_files}")
    print(f"  Files changed:    {total_changed}")
    print(f"  Total fixes:      {total_fixes}")
    print(f"\nBreakdown by file:")
    for rel, s in sorted(all_stats.items(), key=lambda x: -x[1]['total'])[:40]:
        parts = []
        if s['tables']:       parts.append(f"tables:{s['tables']}")
        if s['inputs']:       parts.append(f"inputs:{s['inputs']}")
        if s['sort_buttons']: parts.append(f"sort:{s['sort_buttons']}")
        if s['reload_buttons']: parts.append(f"reload:{s['reload_buttons']}")
        if s['error_loading']: parts.append(f"err/load:{s['error_loading']}")
        if s['icon_buttons']: parts.append(f"icons:{s['icon_buttons']}")
        print(f"  {rel}: {s['total']} ({', '.join(parts)})")

if __name__ == '__main__':
    main()
