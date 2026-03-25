#!/usr/bin/env python3
"""Debug: what does the LLM actually return for eval-detected finding?"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from core.llm_providers import LLMProviderManager

llm = LLMProviderManager()

prompt = (
    "You are a senior security engineer. Generate a precise code fix.\n\n"
    "VULNERABILITY:\n"
    "- Title: eval-detected: Detected eval usage\n"
    "- CWE: CWE-94\n"
    "- Severity: error\n"
    "- Description: Detected eval usage leading to code injection\n"
    "- File: routes/vulnCodeSnippet.ts\n"
    "- Language: typescript\n\n"
    "SOURCE CODE:\n"
    "```typescript\n"
    "const result = eval(req.body.code);\n"
    "```\n\n"
    "Generate a JSON response with:\n"
    '{"title":"Brief fix title","description":"Detailed description",'
    '"patches":[{"file_path":"routes/vulnCodeSnippet.ts",'
    '"old_code":"const result = eval(req.body.code);",'
    '"new_code":"// Use safe alternative instead of eval",'
    '"explanation":"Removes eval to prevent code injection"}],'
    '"testing_guidance":"Run security tests",'
    '"rollback_steps":"Revert the commit",'
    '"risk_assessment":"Low risk",'
    '"effort_minutes":15,'
    '"recommended_action":"code_patch",'
    '"confidence":0.9,'
    '"reasoning":"Eval allows arbitrary code execution",'
    '"mitre_techniques":["T1190"],'
    '"compliance":["CWE-94","OWASP A03"]}\n\n'
    "Provide ONLY valid JSON."
)

response = llm.analyse(
    "openai",
    prompt=prompt,
    context={"finding": {"title": "eval-detected"}},
    default_action="code_patch",
    default_confidence=0.7,
    default_reasoning="Generated code patch for vulnerability fix",
)

print(f"Mode: {response.metadata.get('mode')}")
print(f"Provider: {response.metadata.get('provider')}")
print(f"Error: {response.metadata.get('error', 'NONE')}")
print(f"Confidence: {response.confidence}")
print(f"Action: {response.recommended_action}")
print()

raw = response.metadata.get("raw_payload")
if raw:
    print(f"raw_payload keys: {list(raw.keys())}")
    has_patches = "patches" in raw
    print(f"Has patches: {has_patches}")
    if has_patches:
        print(f"Patches count: {len(raw['patches'])}")
    print(f"\nFull raw_payload:\n{json.dumps(raw, indent=2)[:2000]}")
else:
    print("NO raw_payload in metadata")
    print(f"\nReasoning (first 500 chars):\n{response.reasoning[:500]}")
    print(f"\nFull metadata: {json.dumps(response.metadata, indent=2, default=str)[:1000]}")

