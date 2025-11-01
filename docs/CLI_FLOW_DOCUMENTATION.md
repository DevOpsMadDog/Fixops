# CLI Command Flow Documentation

**Generated:** 2025-11-01
**Purpose:** Document complete program flow for all CLI commands

## Command: `show-overlay`

**Entry Point:** `core/cli.py:_handle_show_overlay()`

**Flow:** CLI → load_overlay() → Display configuration

**Result:** success

**Output Sample:**
```
{"mode": "enterprise", "jira": {"url": "https://jira.example.com", "project_key": "SEC", "default_issue_type": "Task", "user_email": "bot@fixops.local", "token_env": "***"}, "confluence": {"base_url": "https://confluence.example.com", "space_key": "SECOPS", "user": "fixops-bot", "token_env": "***"}, "git": {}, "ci": {}, "auth": {"strategy": "token", "token_env": "***", "header": "X-API-Key"}, "data": {"design_context_dir": "data/design_context", "evidence_dir": "data/evidence", "archive_dir": "d
```

---

## Command: `health`

**Entry Point:** `core/cli.py:_handle_health()`

**Flow:** CLI → Health checks → Status report

**Result:** success

**Output Sample:**
```
{"status": "ok", "checks": {"overlay_mode": "enterprise", "pgmpy_available": true, "pomegranate_available": false, "mchmm_available": false, "evidence_ready": true, "evidence_retention_days": 2555, "opa_configured": false}}

```

---

## Command: `demo --mode enterprise`

**Entry Point:** `core/cli.py:_handle_demo()`

**Flow:** CLI → run_demo_pipeline() → PipelineOrchestrator → Evidence

**Result:** success

**Output Sample:**
```
FixOps Enterprise mode summary:
  Highest severity: critical
  Guardrail status: fail
  Compliance frameworks: framework
  Modules executed: exploit_signals, guardrails, context_engine, onboarding, compliance, policy_automation, vector_store, ssdlc, ai_agents, probabilistic, analytics, tenancy, performance, enhanced_decision, iac_posture, evidence, pricing
  Active pricing plan: Enterprise
  Result saved to: /home/ubuntu/repos/Fixops/tests/e2e_real_data/results/demo_enterprise_result.json
  Evid
```

---

## Command: `make-decision`

**Entry Point:** `core/cli.py:_handle_make_decision()`

**Flow:** CLI → DecisionEngine → Exit code (0=allow, 1=review, 2=block)

**Result:** exit_code=2

**Output Sample:**
```
{"decision": "review", "exit_code": 2, "confidence": 0.723, "severity": "high", "guardrail": "fail"}

```

---

## Command: `ingest`

**Entry Point:** `core/cli.py:_handle_ingest()`

**Flow:** CLI → ArtefactArchive.persist() → Storage

**Result:** failed

**Output Sample:**
```
usage: cli.py ingest [-h] [--overlay OVERLAY] [--design DESIGN] --sbom SBOM
                     --sarif SARIF --cve CVE [--vex VEX] [--cnapp CNAPP]
                     [--context CONTEXT] [--output OUTPUT] [--pretty]
                     [--include-overlay] [--disable MODULE] [--enable MODULE]
                     [--env KEY=VALUE] [--offline]
                     [--signing-provider {env,aws_kms,azure_key_vault}]
                     [--signing-key-id SIGNING_KEY_ID]
                     [--s
```

---
