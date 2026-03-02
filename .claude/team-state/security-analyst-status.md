# security-analyst Status
- **Status:** ✅ Completed
- **Runtime:** claude-opus-4-6-fast (CTEM+ Swarm)
- **Mode:** Standard
- **Date:** 2026-03-02
- **Duration:** 390s (6m 30s)
- **Attempts:** 1/3
- **Run ID:** swarm-2026-03-02_00-05-50
- **Log:** logs/ai-team/2026-03-02_security-analyst_swarm-2026-03-02_00-05-50.log
- **Output:** 4218 bytes

## Summary
- **Bandit SAST**: 475 findings (412 LOW, 63 MEDIUM, 0 HIGH/CRITICAL) — STABLE
- **Secrets**: 0 hardcoded in source; CRITICAL advisory OPEN for .env keys
- **DEMO-011**: Evidence export verified (RSA-SHA256 signing, 6 compliance frameworks)
- **Security tests**: 159/159 PASS (1.57s)
- **Scanner engines**: 8/8 compile OK (sast, dast, secrets, container, cspm, crypto, parsers, evidence)
- **Compliance**: PCI-DSS, SOC2, OWASP Top 10, HIPAA — all mapped
- **Pillars served**: V3, V5, V7, V10
