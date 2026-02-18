#!/usr/bin/env python3
"""Run a live micropentest and save results to cache for report generation."""
import asyncio
import json
import sys

from dotenv import load_dotenv

# Load environment variables from .env BEFORE importing anything else
load_dotenv()

sys.path.insert(0, "suite-core")

from core.micro_pentest import run_micro_pentest


async def main():
    result = await run_micro_pentest(
        cve_ids=["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-4966"],
        target_urls=["https://httpbin.org", "https://example.com"],
    )
    data = result.to_dict()
    with open(".fixops_data/pentest_report_data.json", "w") as f:
        json.dump(data, f, indent=2, default=str)

    meta = data.get("scan_metadata", {})
    print("=== SCAN COMPLETE ===")
    print(f"CVE results: {len(data.get('cve_results', []))}")
    print(f"Findings: {len(data.get('findings', []))}")
    profiles = meta.get("architecture_profiles", {})
    print(f"Architecture profiles: {list(profiles.keys())}")
    for url, p in profiles.items():
        print(
            f"  {url}: OS={p.get('os_fingerprint',{}).get('os','?')} cloud={p.get('cloud_provider',{}).get('provider','?')} arch={p.get('architecture_class','?')}"
        )
    # Check enrichment
    for f in data.get("findings", [])[:3]:
        src = f.get("source_file", "")
        fn = f.get("source_function", "")
        lines = f.get("source_lines", "")
        print(f"  Finding: {f.get('title','')} | {src}:{fn}() L{lines}")
    risk = meta.get("risk_score", {})
    print(f"Risk: {risk.get('score', 0)}/10 {risk.get('level', '?')}")

    # AI engine stats
    ai = meta.get("ai_analysis", {})
    print(f"\n=== AI ENGINE ===")
    print(f"AI enabled: {ai.get('ai_enabled', False)}")
    print(f"Providers: {json.dumps(ai.get('providers_available', {}))}")
    print(f"Consensus decisions: {ai.get('consensus_decisions', 0)}")
    print(f"Total LLM calls: {ai.get('total_llm_calls', 0)}")
    print(f"Successful LLM calls: {ai.get('successful_llm_calls', 0)}")
    print(f"Fallback LLM calls: {ai.get('fallback_llm_calls', 0)}")
    print(f"Exploit strategies: {ai.get('exploit_strategies_generated', 0)}")
    print(f"Engine: {meta.get('engine', '?')}")
    print(f"Duration: {ai.get('duration_seconds', 0)}s")


asyncio.run(main())
