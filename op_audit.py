#!/usr/bin/env python3
"""Operational audit - engines, app startup, route count."""
import sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
for p in ['suite-core','suite-api','suite-attack','suite-feeds','suite-evidence-risk','suite-integrations','.']:
    sys.path.insert(0, p)

engines = [
    ('BrainPipeline', 'core.brain_pipeline', 'BrainPipeline'),
    ('AutoFixEngine', 'core.autofix_engine', 'AutoFixEngine'),
    ('FAILEngine', 'core.fail_engine', 'FAILEngine'),
    ('MicroPentest', 'core.micro_pentest', 'run_micro_pentest'),
    ('RuntimeProtection', 'core.runtime_protection', 'RuntimeProtectionEngine'),
    ('ThreatModeling', 'core.threat_modeling', 'ThreatModelingEngine'),
    ('AICodeGuardian', 'core.ai_code_guardian', 'AICodeGuardian'),
    ('SASTEngine', 'core.sast_engine', 'SASTEngine'),
    ('DASTEngine', 'core.dast_engine', 'DASTEngine'),
    ('SecretsScanner', 'core.secrets_scanner', 'SecretsScanner'),
    ('ContainerScanner', 'core.container_scanner', 'ContainerImageScanner'),
    ('IaCScanner', 'core.iac_scanner', 'IaCScanner'),
    ('CSPMEngine', 'core.cspm_engine', 'CSPMEngine'),
    ('RealScanner', 'core.real_scanner', 'RealVulnerabilityScanner'),
    ('RiskScorer', 'core.ml.risk_scorer', 'RiskScoringModel'),
    ('PredictiveScorer', 'core.ml.predictive_scorer', 'PredictiveScorer'),
    ('ContinuousValidation', 'core.continuous_validation', 'ContinuousValidationEngine'),
    ('ScannerParsers', 'core.scanner_parsers', 'register_scanner_normalizers'),
    ('Connectors', 'core.connectors', 'AutomationConnectors'),
    ('SecurityConnectors', 'core.security_connectors', 'SnykConnector'),
    ('CLI', 'core.cli', None),
    ('Crypto', 'core.crypto', 'RSASigner'),
    ('SecurityHardening', 'core.security_hardening', 'RateLimiter'),
    ('LLMGuard', 'core.llm_guard_service', 'LLMGuardService'),
    ('ContextCompression', 'core.context_compression', 'compress_prompt'),
    ('CybersecSkills', 'core.cybersec_skills_loader', 'CybersecSkillsLoader'),
    ('AutofixVerifier', 'core.autofix_verifier', 'AutoFixVerifier'),
    ('SBOMCorrelator', 'core.sbom_runtime_correlator', 'SBOMRuntimeCorrelator'),
    ('EventBus', 'core.event_bus', 'EventBus'),
    ('SSDLC', 'core.ssdlc', 'SSDLCEvaluator'),
    ('IntelligentSecurity', 'core.intelligent_security_engine', 'IntelligentSecurityEngine'),
]

print("=" * 60)
print("ENGINE IMPORT AUDIT")
print("=" * 60)
ok = 0
fail = 0
failures = []
for name, mod, cls in engines:
    try:
        m = __import__(mod, fromlist=[cls] if cls else ['__name__'])
        if cls:
            getattr(m, cls)
        ok += 1
        print("  OK   %s" % name)
    except Exception as e:
        fail += 1
        failures.append((name, str(e)[:150]))
        print("  FAIL %s: %s" % (name, str(e)[:100]))

print("\n%d/%d engines import OK" % (ok, ok+fail))

print("\n" + "=" * 60)
print("FASTAPI APP STARTUP")
print("=" * 60)
try:
    from apps.api.app import create_app
    app = create_app()
    routes = [r for r in app.routes if hasattr(r, 'methods')]
    print("  App created: %d routes mounted" % len(routes))
    print("  App startup: SUCCESS")
except Exception as e:
    print("  App startup FAILED: %s" % str(e)[:200])

if failures:
    print("\n" + "=" * 60)
    print("FAILURES TO FIX:")
    print("=" * 60)
    for n, e in failures:
        print("  %s: %s" % (n, e))

