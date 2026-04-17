# PRD — Community 610: SAST Engine — Supported Languages Registry

## Master Goal Mapping
**ALDECI Pillar:** Static Application Security Testing (SAST) — returns a structured registry of all supported programming languages with rule counts and file extensions, powering the developer portal language coverage display.

## Architecture Diagram
```mermaid
graph LR
    A[SAST_RULES + _EXTRA_RULES] --> B[get_supported_languages]
    A2[EXT_TO_LANG mapping] --> B
    B -->|aggregate per lang| C[rule_count per language]
    B -->|group by lang| D[extensions per language]
    C & D --> E[languages registry dict]
    E --> F[/api/v1/sast/languages endpoint]
```

## Code Proof
**File:** `suite-core/core/sast_engine.py:L1810`  
**Module:** `sast_engine.SASTEngine.get_supported_languages`

```python
@staticmethod
def get_supported_languages() -> Dict[str, Any]:
    """Return supported languages with rule counts and file extensions."""
    lang_rules: Dict[str, int] = {}
    for r in list(SAST_RULES) + list(_EXTRA_RULES):
        for lang in r[7]:
            lang_rules[lang] = lang_rules.get(lang, 0) + 1
    lang_exts: Dict[str, List[str]] = {}
    for ext, lang in EXT_TO_LANG.items():
        lang_exts.setdefault(lang.value, []).append(ext)
    result = {}
    for lang in Language:
        if lang == Language.UNKNOWN: continue
        # build result entry per language
    return result
```

## Inter-Dependencies
- `SAST_RULES` / `_EXTRA_RULES` — tuples defining all SAST rules
- `EXT_TO_LANG` — maps file extensions to `Language` enum
- `Language` enum — all supported languages
- C611 `get_rule_count` — total count (companion)
- `/api/v1/sast` router — serves language list

## Data Flow
SAST rules list + extension map → aggregate rule count per language → group extensions per language → combined registry dict.

## Referenced Docs
- ALDECI Rearchitecture v2 §SAST Engine
- OWASP Source Code Analysis Tools
- Language extension registry

## Acceptance Criteria
- [ ] All non-UNKNOWN languages included
- [ ] `rule_count` matches actual rules for that language
- [ ] `extensions` contains all mapped extensions
- [ ] No `UNKNOWN` language in output
- [ ] Result is serializable dict

## Effort Estimate
S — 1 day (implemented; add language coverage assertion test)

## Status
DONE — implemented at L1810
