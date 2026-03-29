import sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
for p in ['suite-core','suite-api','suite-attack','suite-feeds','suite-evidence-risk','suite-integrations']:
    sys.path.insert(0, p)

outfile = open('verify_out2.txt', 'w')
def out(s):
    print(s)
    outfile.write(s + '\n')

mods = [
    ('SAST', 'core.sast_engine'),
    ('DAST', 'core.dast_engine'),
    ('Secrets', 'core.secrets_scanner'),
    ('Container', 'core.container_scanner'),
    ('CSPM', 'core.cspm_engine'),
    ('IaC', 'core.iac_scanner'),
    ('Malware', 'core.malware_detector'),
    ('API Fuzzer', 'core.api_fuzzer'),
    ('SBOM', 'risk.sbom.generator'),
    ('Supply Chain', 'core.supply_chain_engine'),
    ('Runtime', 'core.runtime_protection'),
    ('Threat Model', 'core.threat_modeling'),
    ('Attack Surface', 'core.attack_surface_discovery'),
    ('Brain Pipeline', 'core.brain_pipeline'),
    ('AutoFix', 'core.autofix_engine'),
    ('FAIL Engine', 'core.fail_engine'),
    ('Micro Pentest', 'core.micro_pentest'),
    ('Knowledge Graph', 'core.knowledge_brain'),
    ('Self Learning', 'core.self_learning'),
    ('LLM Guard', 'core.llm_guard_service'),
    ('License', 'risk.license_compliance'),
    ('Dev Risk', 'core.developer_risk_profiler'),
    ('Compression', 'core.context_compression'),
    ('Cybersec', 'core.cybersec_skills_loader'),
    ('LLM Providers', 'core.llm_providers'),
    ('Crypto', 'core.crypto'),
    ('Parsers', 'core.scanner_parsers'),
    ('Connectors', 'core.connectors'),
    ('Sec Connectors', 'core.security_connectors'),
    ('Audit Log', 'core.audit_logger'),
    ('Event Bus', 'core.event_bus'),
]

import traceback
out("TIMESTAMP: " + str(__import__('time').time()))
ok = fail = 0
for name, mod in mods:
    try:
        __import__(mod)
        out("[OK] " + name)
        ok += 1
    except Exception as e:
        out("[FAIL] " + name + ": " + type(e).__name__ + ": " + str(e))
        traceback.print_exc()
        fail += 1

out("")
out(str(ok) + "/" + str(ok + fail) + " engines imported successfully")
outfile.close()

