#!/usr/bin/env python3
"""Patch docs/API_REFERENCE.md from v5.0 to v5.1.

Changes:
  1. Header: version 5.0 → 5.1, date → 2026-03-08, endpoint count 784 → 774,
     suite-integrations 59 → 49
  2. CTEM lifecycle diagram: 784 → 774, Intelligence 237 → 226
  3. MCP Server section: Add deprecation notice (NOT MOUNTED)
  4. Insert new section 9.5: vLLM Self-Hosted LLM (6 endpoints)
  5. Appendix A: Remove MCP Server row, adjust Intelligence subtotal,
     correct grand total to 774
  6. Footer: Update version, date, counts

Run:
    python scripts/patch_api_reference_v51.py
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
API_REF = REPO_ROOT / "docs" / "API_REFERENCE.md"


def patch():
    text = API_REF.read_text(encoding="utf-8")
    original = text

    # ── 1. Header ──────────────────────────────────────────────────────
    text = text.replace(
        "**Version**: 5.0 — Post-Demo Hardened Edition (Sprint 2, Day 4+)",
        "**Version**: 5.1 — DEMO-008 Audit Edition (Sprint 2, Day 5)",
    )
    text = text.replace(
        "**Last updated**: 2026-03-07",
        "**Last updated**: 2026-03-08",
    )
    text = text.replace(
        "**Total endpoints**: 784 across 72 router files + 2 dynamic routers + 25 inline @app (verified via grep 2026-03-07)",
        "**Total endpoints**: 774 mounted across 72 router files + 2 dynamic routers + 25 inline @app (verified via grep 2026-03-08)",
    )
    text = text.replace(
        "**Total routes mounted**: 784 routes, 77+ unique prefixes",
        "**Total routes mounted**: 774 routes, 77+ unique prefixes",
    )
    text = text.replace(
        "suite-integrations (59)",
        "suite-integrations (49)",
    )
    # v5.0 changes line — append v5.1 changes
    text = text.replace(
        '> **v5.0 changes**: Post-demo endpoint audit (verified 784 via code grep 2026-03-07). +3 new endpoints: Brain `/trends`, MCP Protocol `/stats`, Self-Learning `/stats`. Suite-core 253→256. Validation section corrected. 41+ curl examples. Appendix A reconciled.',
        '> **v5.1 changes**: Corrected mounted count 784→774 (MCP Server Integration unmounted — commented out in app.py). Added vLLM Self-Hosted LLM section (9.5, 6 endpoints). suite-integrations 59→49. 43+ curl examples.\n> **v5.0 changes**: Post-demo endpoint audit. +3 new endpoints: Brain `/trends`, MCP Protocol `/stats`, Self-Learning `/stats`. Suite-core 253→256. Validation section corrected. 41+ curl examples. Appendix A reconciled.',
    )

    # ── 2. CTEM lifecycle diagram ──────────────────────────────────────
    text = text.replace(
        "ALdeci organizes its 784 endpoints",
        "ALdeci organizes its 774 endpoints",
    )
    text = text.replace(
        "│ 237 endpoints      │",
        "│ 226 endpoints      │",
    )

    # ── 3. MCP Gateway auto-discovered route count ─────────────────────
    text = text.replace(
        "List all MCP-available tools (auto-discovered from 784 routes)",
        "List all MCP-available tools (auto-discovered from 774 routes)",
    )

    # ── 4. MCP Server section — deprecation notice ─────────────────────
    old_mcp = (
        "#### MCP Server — External Agent Gateway [V7]\n"
        "\n"
        "**Prefix**: `/api/v1/mcp` · **Source**: `suite-integrations/api/mcp_router.py` (468 LOC) · **10 endpoints**\n"
        "\n"
        "Low-level MCP server management — client connections, tool registry, and server configuration for external AI agents."
    )
    new_mcp = (
        "#### MCP Server — External Agent Gateway [V7] ⚠️ DEPRECATED\n"
        "\n"
        "> **⚠️ NOT MOUNTED** — This router is commented out in `app.py` (lines 1361-1365).\n"
        "> Superseded by MCP Auto-Discovery router (`suite-api/apps/api/mcp_router.py`, section 7.3).\n"
        "> These 10 endpoints are **not accessible** at runtime. Retained here for migration reference.\n"
        "\n"
        "**Prefix**: `/api/v1/mcp` · **Source**: `suite-integrations/api/mcp_router.py` (468 LOC) · **10 endpoints (UNMOUNTED)**\n"
        "\n"
        "Low-level MCP server management — client connections, tool registry, and server configuration for external AI agents."
    )
    text = text.replace(old_mcp, new_mcp)

    # ── 5. Insert vLLM section 9.5 after section 9.4 ──────────────────
    vllm_section = '''\

### 9.5 Self-Hosted LLM Engine (vLLM / Ollama) [V9]

**Prefix**: `/api/v1/vllm` · **Source**: `suite-core/api/vllm_router.py` (275 LOC) · **Engine**: `suite-core/core/vllm_autofix_adapter.py` (530 LOC) + `suite-core/core/llm_providers.py` (1,077 LOC) · **6 endpoints**

> **Air-Gapped Operation**: Enables the Brain Pipeline, AutoFix engine, and LLM Consensus to operate without external API keys using self-hosted vLLM or Ollama backends.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vllm/health` | Health check for self-hosted LLM engine |
| `GET` | `/api/v1/vllm/status` | Status of all self-hosted LLM backends (vLLM, Ollama) |
| `GET` | `/api/v1/vllm/models` | List available models across all backends |
| `POST` | `/api/v1/vllm/test-inference` | Test inference round-trip with timing metrics |
| `GET` | `/api/v1/vllm/autofix-status` | AutoFix self-hosted adapter status |
| `POST` | `/api/v1/vllm/generate-fix` | Generate security fix using self-hosted LLM |

**Recommended Models**:
- **vLLM** (production): `deepseek-ai/deepseek-coder-33b-instruct` (~20GB VRAM), `codellama/CodeLlama-34b-Instruct-hf`, `meta-llama/Llama-3.1-70B-Instruct`
- **Ollama** (development): `codellama:13b` (~8GB RAM), `deepseek-coder:33b` (~20GB), `llama3.1:8b` (~5GB)

**Example — Check air-gapped readiness:**

```bash
curl -s http://localhost:8000/api/v1/vllm/status \\
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

```json
{
  "status": "operational",
  "air_gapped_ready": true,
  "active_backend": "vllm",
  "vllm_available": true,
  "ollama_available": false,
  "all_providers": [
    {"name": "vllm", "type": "VLLMProvider", "air_gapped": true},
    {"name": "ollama", "type": "OllamaProvider", "air_gapped": true},
    {"name": "openai", "type": "OpenAIProvider", "air_gapped": false}
  ],
  "recommendation": "✅ vLLM is active — full air-gapped operation ready"
}
```

**Example — Test inference round-trip:**

```bash
curl -X POST http://localhost:8000/api/v1/vllm/test-inference \\
  -H "X-API-Key: $FIXOPS_API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"prompt": "Explain SQL injection in one sentence.", "backend": "vllm"}'
```

**Example — Generate a fix without external API keys:**

```bash
curl -X POST http://localhost:8000/api/v1/vllm/generate-fix \\
  -H "X-API-Key: $FIXOPS_API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "finding": {
      "id": "finding-abc123",
      "title": "SQL Injection in login endpoint",
      "cwe": "CWE-89",
      "severity": "CRITICAL"
    },
    "source_code": "query = f\\"SELECT * FROM users WHERE name=\\'{username}\\'\\""
  }'
```

```json
{
  "success": true,
  "fix": {
    "code": "query = \\"SELECT * FROM users WHERE name=?\\"\\ncursor.execute(query, (username,))",
    "explanation": "Use parameterized queries to prevent SQL injection",
    "confidence": 0.91,
    "unified_diff": "--- a/login.py\\n+++ b/login.py\\n@@ -1 +1,2 @@\\n-query = f\\"SELECT * FROM users WHERE name=\\'{username}\\'\\""
  },
  "backend": "vllm",
  "model": "deepseek-ai/deepseek-coder-33b-instruct",
  "duration_ms": 1250.5,
  "error": null
}
```
'''

    # Insert after section 9.4's last line (the "---" separator before section 10)
    anchor = "| `DELETE` | `/api/v1/ai-agent/cache` | Clear inference cache |\n\n---\n\n## 10. Error Codes"
    replacement = "| `DELETE` | `/api/v1/ai-agent/cache` | Clear inference cache |\n" + vllm_section + "\n---\n\n## 10. Error Codes"
    text = text.replace(anchor, replacement)

    # ── 6. Appendix A — Remove MCP Server row, adjust subtotals ────────
    text = text.replace(
        '| **Intelligence** | MCP Server Integration | 10 | 1 |\n',
        '| **Intelligence** | ~~MCP Server Integration~~ | ~~10~~ | ~~1~~ | ⚠️ NOT MOUNTED (superseded by MCP Auto-Discovery §7.3) |\n',
    )
    text = text.replace(
        '| | **Intelligence Subtotal** | **236** | **20** |',
        '| | **Intelligence Subtotal** | **226** | **19** | (MCP Server 10 endpoints unmounted) |',
    )
    # Add vLLM row to Vision
    text = text.replace(
        '| **Vision** | Self-Hosted AI Agent (V4) | 7 | 1 |\n| | **Vision Subtotal** | **40** | **4** |',
        '| **Vision** | Self-Hosted AI Agent (V4) | 7 | 1 |\n| **Vision** | Self-Hosted LLM — vLLM/Ollama (V9) | 6 | 1 |\n| | **Vision Subtotal** | **46** | **5** |',
    )
    # Grand total
    text = text.replace(
        '| | **GRAND TOTAL** | **784** | **72 routers + 2 dynamic + inline** |',
        '| | **GRAND TOTAL** | **774** | **72 routers + 2 dynamic + inline** | (verified via grep 2026-03-08) |',
    )

    # ── 7. Appendix C security hardening ───────────────────────────────
    text = text.replace(
        "All 784 endpoints",
        "All 774 endpoints",
    )

    # ── 8. Footer ──────────────────────────────────────────────────────
    text = text.replace(
        "*Generated by ALdeci Technical Writer Agent · v5.0 · 2026-03-07 · Sprint 2 Day 4+ Post-Demo · Pillar [V3][V5][V7][V10]*",
        "*Generated by ALdeci Technical Writer Agent · v5.1 · 2026-03-08 · Sprint 2 Day 5 DEMO-008 · Pillar [V3][V5][V7][V9][V10]*",
    )
    text = text.replace(
        "*Suites: suite-api (238) · suite-core (256) · suite-attack (106) · suite-feeds (31) · suite-evidence-risk (56) · suite-integrations (59) · sandbox (8) · logs (5) · inline @app (25)*",
        "*Suites: suite-api (238) · suite-core (256) · suite-attack (106) · suite-feeds (31) · suite-evidence-risk (56) · suite-integrations (49) · sandbox (8) · logs (5) · inline @app (25)*",
    )
    text = text.replace(
        "*Verified: grep-audited 2026-03-07, 784 routes mounted, 77+ unique prefixes*",
        "*Verified: grep-audited 2026-03-08, 774 routes mounted, 77+ unique prefixes*",
    )

    # ── Verify changes were applied ────────────────────────────────────
    if text == original:
        print("ERROR: No changes were applied — anchor text not found.")
        sys.exit(1)

    changes = []
    if "5.1" in text[:200]:
        changes.append("header version")
    if "774 mounted" in text[:500]:
        changes.append("endpoint count")
    if "NOT MOUNTED" in text:
        changes.append("MCP deprecation")
    if "vllm" in text.lower() and "vllm_router" in text:
        changes.append("vLLM section")
    if "226" in text and "Intelligence Subtotal" in text:
        changes.append("appendix A")

    API_REF.write_text(text, encoding="utf-8")
    print("✅ Patched docs/API_REFERENCE.md → v5.1")
    print(f"   Changes applied: {', '.join(changes)}")
    print(f"   File size: {len(text):,} chars, {text.count(chr(10)):,} lines")


if __name__ == "__main__":
    patch()
