#!/usr/bin/env python3
"""Test all O/P/Q/R router endpoints against live ALDECI API."""
import json
import subprocess
import time
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://localhost:8000"
TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG_ID = "org_test_opqr"

# All endpoints extracted from O/P/Q/R router files
# Format: (METHOD, path, optional_json_body)
# Path params replaced with test values

ENDPOINTS = [
    # === DELETE endpoints ===
    ("DELETE", "/api/v1/observability/alerts/rules/test-rule", None),
    ("DELETE", "/api/v1/pentest/schedules/sched-1", None),
    ("DELETE", "/api/v1/pentest/targets/tgt-1", None),
    ("DELETE", "/api/v1/policies/pol-1", None),
    ("DELETE", "/api/v1/policy-engine/policies/pol-1", None),
    ("DELETE", "/api/v1/queue/clear", None),
    ("DELETE", "/api/v1/rbac/revoke", None),
    ("DELETE", "/api/v1/report-builder/templates/tmpl-1", None),
    ("DELETE", "/api/v1/reports/schedules/sched-1", None),
    ("DELETE", "/api/v1/retention/policies/pol-1", None),
    ("DELETE", "/api/v1/risks/risk-1/controls/ctrl-1", None),
    ("DELETE", "/api/v1/risks/risk-1", None),

    # === GET endpoints ===
    ("GET", "/api/v1/brain/evidence/packs/pack-1", None),
    ("GET", "/api/v1/brain/evidence/packs", None),
    ("GET", "/api/v1/brain/health", None),
    ("GET", "/api/v1/brain/pipeline/runs/run-1", None),
    ("GET", "/api/v1/brain/pipeline/runs", None),
    ("GET", "/api/v1/brain/status", None),
    ("GET", "/api/v1/observability/alerts/history", None),
    ("GET", "/api/v1/observability/alerts/rules", None),
    ("GET", "/api/v1/observability/alerts", None),
    ("GET", "/api/v1/observability/healthz", None),
    ("GET", "/api/v1/observability/logs/stats", None),
    ("GET", "/api/v1/observability/logs", None),
    ("GET", "/api/v1/observability/metrics/json", None),
    ("GET", "/api/v1/observability/metrics", None),
    ("GET", "/api/v1/observability/readyz", None),
    ("GET", "/api/v1/observability/startupz", None),
    ("GET", "/api/v1/observability/traces/trace-1", None),
    ("GET", "/api/v1/observability/traces", None),
    ("GET", "/api/v1/onboarding/checklist", None),
    ("GET", "/api/v1/onboarding/list", None),
    ("GET", "/api/v1/onboarding/progress", None),
    ("GET", "/api/v1/onboarding/steps/api_keys/config", None),
    ("GET", "/api/v1/openclaw/campaigns/camp-1/tasks", None),
    ("GET", "/api/v1/openclaw/campaigns/camp-1", None),
    ("GET", "/api/v1/openclaw/campaigns", None),
    ("GET", "/api/v1/openclaw/findings", None),
    ("GET", "/api/v1/openclaw/results", None),
    ("GET", "/api/v1/openclaw/stats", None),
    ("GET", "/api/v1/openclaw/status", None),
    ("GET", "/api/v1/orgs/org-1/summary", None),
    ("GET", "/api/v1/orgs", None),
    ("GET", "/api/v1/ot-sec/assets/asset-1", None),
    ("GET", "/api/v1/ot-sec/assets", None),
    ("GET", "/api/v1/ot-sec/incidents", None),
    ("GET", "/api/v1/ot-sec/stats", None),
    ("GET", "/api/v1/ot-sec/zones", None),
    ("GET", "/api/v1/ot-security/anomalies", None),
    ("GET", "/api/v1/ot-security/assets/asset-1", None),
    ("GET", "/api/v1/ot-security/assets", None),
    ("GET", "/api/v1/ot-security/stats", None),
    ("GET", "/api/v1/pag/accounts/acct-1", None),
    ("GET", "/api/v1/pag/accounts", None),
    ("GET", "/api/v1/pag/anomalies", None),
    ("GET", "/api/v1/pag/sessions", None),
    ("GET", "/api/v1/pag/stats", None),
    ("GET", "/api/v1/pagerduty/escalation-policies", None),
    ("GET", "/api/v1/pagerduty/incidents/inc-1", None),
    ("GET", "/api/v1/pagerduty/incidents", None),
    ("GET", "/api/v1/pagerduty/schedules", None),
    ("GET", "/api/v1/pagerduty/services", None),
    ("GET", "/api/v1/pagerduty/status", None),
    ("GET", "/api/v1/pam/accounts", None),
    ("GET", "/api/v1/pam/policies", None),
    ("GET", "/api/v1/pam/sessions", None),
    ("GET", "/api/v1/pam/stats", None),
    ("GET", "/api/v1/passive-dns/domains/example.com/fast-flux", None),
    ("GET", "/api/v1/passive-dns/domains/example.com/history", None),
    ("GET", "/api/v1/passive-dns/domains/example.com/reputation", None),
    ("GET", "/api/v1/passive-dns/ips/192.168.1.1/history", None),
    ("GET", "/api/v1/passive-dns/resolutions", None),
    ("GET", "/api/v1/passive-dns/stats", None),
    ("GET", "/api/v1/passive-dns/threats", None),
    ("GET", "/api/v1/password-policy/audits", None),
    ("GET", "/api/v1/password-policy/policies", None),
    ("GET", "/api/v1/password-policy/stats", None),
    ("GET", "/api/v1/password-policy/violations", None),
    ("GET", "/api/v1/patch-automation/cve/CVE-2024-1234/patches", None),
    ("GET", "/api/v1/patch-automation/deployments", None),
    ("GET", "/api/v1/patch-automation/exceptions", None),
    ("GET", "/api/v1/patch-automation/patches", None),
    ("GET", "/api/v1/patch-automation/stats", None),
    ("GET", "/api/v1/patch-automation/windows", None),
    ("GET", "/api/v1/patch-management/", None),
    ("GET", "/api/v1/patch-management/deployments", None),
    ("GET", "/api/v1/patch-management/patches/patch-1", None),
    ("GET", "/api/v1/patch-management/patches", None),
    ("GET", "/api/v1/patch-management/stats", None),
    ("GET", "/api/v1/patch-priority/kev/CVE-2024-1234", None),
    ("GET", "/api/v1/patch-priority/plans/plan-1", None),
    ("GET", "/api/v1/patch-priority/plans", None),
    ("GET", "/api/v1/patch-priority/stats", None),
    ("GET", "/api/v1/patches/patch-1", None),
    ("GET", "/api/v1/patches/compliance", None),
    ("GET", "/api/v1/patches/overdue", None),
    ("GET", "/api/v1/patches/stats", None),
    ("GET", "/api/v1/patches/velocity", None),
    ("GET", "/api/v1/patches", None),
    ("GET", "/api/v1/pentest-mgmt/engagements/eng-1/targets", None),
    ("GET", "/api/v1/pentest-mgmt/engagements/eng-1", None),
    ("GET", "/api/v1/pentest-mgmt/engagements", None),
    ("GET", "/api/v1/pentest-mgmt/findings", None),
    ("GET", "/api/v1/pentest-mgmt/stats", None),
    ("GET", "/api/v1/pentest/runs/run-1/report", None),
    ("GET", "/api/v1/pentest/runs/run-1", None),
    ("GET", "/api/v1/pentest/runs", None),
    ("GET", "/api/v1/pentest/schedules", None),
    ("GET", "/api/v1/pentest/stats", None),
    ("GET", "/api/v1/pentest/targets/tgt-1", None),
    ("GET", "/api/v1/pentest/targets", None),
    ("GET", "/api/v1/phishing/campaigns/camp-1/stats", None),
    ("GET", "/api/v1/phishing/campaigns/camp-1/targets", None),
    ("GET", "/api/v1/phishing/campaigns/camp-1", None),
    ("GET", "/api/v1/phishing/campaigns", None),
    ("GET", f"/api/v1/phishing/orgs/{ORG_ID}/history", None),
    ("GET", f"/api/v1/phishing/orgs/{ORG_ID}/risk", None),
    ("GET", "/api/v1/phishing/stats", None),
    ("GET", "/api/v1/phishing/templates", None),
    ("GET", "/api/v1/phishing/users/susceptibility", None),
    ("GET", "/api/v1/physical-security/events", None),
    ("GET", "/api/v1/physical-security/locations/loc-1", None),
    ("GET", "/api/v1/physical-security/locations", None),
    ("GET", "/api/v1/physical-security/stats", None),
    ("GET", "/api/v1/pki/audit-log", None),
    ("GET", "/api/v1/pki/cas", None),
    ("GET", "/api/v1/pki/certificates/cert-1", None),
    ("GET", "/api/v1/pki/certificates/expiring", None),
    ("GET", "/api/v1/pki/certificates", None),
    ("GET", "/api/v1/pki/stats", None),
    ("GET", "/api/v1/platform/health", None),
    ("GET", "/api/v1/playbooks/pb-1", None),
    ("GET", "/api/v1/playbooks/builtin", None),
    ("GET", "/api/v1/playbooks/executions/exec-1", None),
    ("GET", "/api/v1/playbooks/executions", None),
    ("GET", "/api/v1/playbooks", None),
    ("GET", "/api/v1/policies/pol-1/violations", None),
    ("GET", "/api/v1/policies/pol-1", None),
    ("GET", "/api/v1/policies/conflicts", None),
    ("GET", "/api/v1/policies/history", None),
    ("GET", "/api/v1/policies/stats", None),
    ("GET", "/api/v1/policies/violations", None),
    ("GET", "/api/v1/policies", None),
    ("GET", "/api/v1/policy-enforcement/exceptions", None),
    ("GET", "/api/v1/policy-enforcement/policies/pol-1", None),
    ("GET", "/api/v1/policy-enforcement/policies", None),
    ("GET", "/api/v1/policy-enforcement/stats", None),
    ("GET", "/api/v1/policy-engine/export", None),
    ("GET", "/api/v1/policy-engine/history", None),
    ("GET", "/api/v1/policy-engine/policies/pol-1", None),
    ("GET", "/api/v1/policy-engine/policies", None),
    ("GET", "/api/v1/policy-engine/stats", None),
    ("GET", "/api/v1/policy-generator/policies/pol-1/export", None),
    ("GET", "/api/v1/policy-generator/policies/pol-1", None),
    ("GET", "/api/v1/policy-generator/policies/due-review", None),
    ("GET", "/api/v1/policy-generator/policies", None),
    ("GET", "/api/v1/posture-advisor/analyze", None),
    ("GET", "/api/v1/posture-advisor/components", None),
    ("GET", "/api/v1/posture-advisor/recommendations/rec-1", None),
    ("GET", "/api/v1/posture-advisor/recommendations", None),
    ("GET", "/api/v1/posture-advisor/roadmap", None),
    ("GET", "/api/v1/posture-advisor/score", None),
    ("GET", "/api/v1/posture-advisor/stats", None),
    ("GET", "/api/v1/posture-benchmark/history", None),
    ("GET", "/api/v1/posture-benchmark/improvement-priorities", None),
    ("GET", "/api/v1/posture-benchmark/industry-averages", None),
    ("GET", "/api/v1/posture-benchmark/latest", None),
    ("GET", "/api/v1/posture-benchmark/percentile", None),
    ("GET", "/api/v1/posture-score/benchmarks", None),
    ("GET", "/api/v1/posture-score/components", None),
    ("GET", "/api/v1/posture-score/current", None),
    ("GET", "/api/v1/posture-score/history", None),
    ("GET", "/api/v1/posture-score/stats", None),
    ("GET", "/api/v1/posture/components", None),
    ("GET", "/api/v1/posture/current", None),
    ("GET", "/api/v1/posture/history", None),
    ("GET", "/api/v1/posture/tracker/compare", None),
    ("GET", "/api/v1/posture/tracker/current", None),
    ("GET", "/api/v1/posture/tracker/trend", None),
    ("GET", "/api/v1/posture/trend", None),
    ("GET", "/api/v1/pr-gate/history", None),
    ("GET", "/api/v1/pr-gate/policy", None),
    ("GET", "/api/v1/predictions/health", None),
    ("GET", "/api/v1/predictions/markov/states", None),
    ("GET", "/api/v1/predictions/markov/transitions", None),
    ("GET", "/api/v1/predictions/status", None),
    ("GET", "/api/v1/prioritize/stats", None),
    ("GET", "/api/v1/prioritize/top", None),
    ("GET", "/api/v1/prioritize/weights", None),
    ("GET", "/api/v1/privacy-impact/", None),
    ("GET", "/api/v1/privacy-impact/assessments/asmt-1", None),
    ("GET", "/api/v1/privacy-impact/assessments", None),
    ("GET", "/api/v1/privacy-impact/high-risk", None),
    ("GET", "/api/v1/privacy-impact/summary", None),
    ("GET", "/api/v1/privacy/consents", None),
    ("GET", "/api/v1/privacy/dsrs", None),
    ("GET", "/api/v1/privacy/incidents", None),
    ("GET", "/api/v1/privacy/processing-activities", None),
    ("GET", "/api/v1/privacy/stats", None),
    ("GET", "/api/v1/privilege-escalation/events/evt-1/detect", None),
    ("GET", "/api/v1/privilege-escalation/events", None),
    ("GET", "/api/v1/privilege-escalation/heatmap", None),
    ("GET", "/api/v1/privilege-escalation/rules", None),
    ("GET", "/api/v1/privilege-escalation/stats", None),
    ("GET", "/api/v1/privileged-identity/accounts/acct-1/sessions", None),
    ("GET", "/api/v1/privileged-identity/high-risk", None),
    ("GET", "/api/v1/privileged-identity/sessions/active", None),
    ("GET", "/api/v1/privileged-identity/summary", None),
    ("GET", "/api/v1/purple-team/exercises/ex-1/report", None),
    ("GET", "/api/v1/purple-team/exercises/ex-1", None),
    ("GET", "/api/v1/purple-team/exercises", None),
    ("GET", "/api/v1/purple-team/scenarios", None),
    ("GET", "/api/v1/quantum-crypto/assessments", None),
    ("GET", "/api/v1/quantum-crypto/assets/asset-1", None),
    ("GET", "/api/v1/quantum-crypto/assets", None),
    ("GET", "/api/v1/quantum-crypto/health", None),
    ("GET", "/api/v1/quantum-crypto/keys", None),
    ("GET", "/api/v1/quantum-crypto/migrations", None),
    ("GET", "/api/v1/quantum-crypto/stats", None),
    ("GET", "/api/v1/quantum-crypto/status", None),
    ("GET", "/api/v1/questionnaires/q-1/export", None),
    ("GET", "/api/v1/questionnaires/q-1", None),
    ("GET", "/api/v1/questionnaires/answer-bank", None),
    ("GET", "/api/v1/questionnaires/templates", None),
    ("GET", "/api/v1/questionnaires", None),
    ("GET", "/api/v1/queue/peek", None),
    ("GET", "/api/v1/queue/status", None),
    ("GET", "/api/v1/ransomware-protection/", None),
    ("GET", "/api/v1/ransomware-protection/backups", None),
    ("GET", "/api/v1/ransomware-protection/detections", None),
    ("GET", "/api/v1/ransomware-protection/status", None),
    ("GET", "/api/v1/ransomware-protection/summary", None),
    ("GET", "/api/v1/ransomware-protection/unvalidated-backups", None),
    ("GET", "/api/v1/rasp/attackers", None),
    ("GET", "/api/v1/rasp/config", None),
    ("GET", "/api/v1/rasp/rules", None),
    ("GET", "/api/v1/rasp/status", None),
    ("GET", "/api/v1/rasp/threats", None),
    ("GET", "/api/v1/rate-limits/config", None),
    ("GET", "/api/v1/rate-limits/dashboard", None),
    ("GET", "/api/v1/rate-limits/stats", None),
    ("GET", "/api/v1/rbac/audit", None),
    ("GET", f"/api/v1/rbac/org/{ORG_ID}/users", None),
    ("GET", "/api/v1/rbac/roles", None),
    ("GET", "/api/v1/rbac/users/user-1/roles", None),
    ("GET", "/api/v1/rbac/users/user-1/scopes", None),
    ("GET", "/api/v1/red-team/attack-surface-score", None),
    ("GET", "/api/v1/red-team/engagements/eng-1/findings", None),
    ("GET", "/api/v1/red-team/engagements/eng-1/ttps", None),
    ("GET", "/api/v1/red-team/engagements/eng-1", None),
    ("GET", "/api/v1/red-team/engagements", None),
    ("GET", "/api/v1/red-team/mitre-coverage", None),
    ("GET", "/api/v1/red-team/operators", None),
    ("GET", "/api/v1/red-team/simulations/sim-1/results", None),
    ("GET", "/api/v1/red-team/simulations", None),
    ("GET", "/api/v1/red-team/stats", None),
    ("GET", "/api/v1/regulatory-reporting/regulations", None),
    ("GET", "/api/v1/regulatory-reporting/reports", None),
    ("GET", "/api/v1/regulatory-reporting/stats", None),
    ("GET", "/api/v1/regulatory-tracker/changes/upcoming", None),
    ("GET", "/api/v1/regulatory-tracker/changes", None),
    ("GET", "/api/v1/regulatory-tracker/obligations", None),
    ("GET", "/api/v1/regulatory-tracker/regulations", None),
    ("GET", "/api/v1/regulatory-tracker/stats", None),
    ("GET", "/api/v1/regulatory/action-plan/reg-1", None),
    ("GET", "/api/v1/regulatory/impact/summary", None),
    ("GET", "/api/v1/regulatory/regulations/active", None),
    ("GET", "/api/v1/regulatory/regulations/timeline", None),
    ("GET", "/api/v1/regulatory/regulations/upcoming", None),
    ("GET", "/api/v1/regulatory/stats", None),
    ("GET", "/api/v1/remediation-board/board", None),
    ("GET", "/api/v1/remediation-board/cards/card-1", None),
    ("GET", "/api/v1/remediation-board/metrics", None),
    ("GET", "/api/v1/remediation-board/overdue", None),
    ("GET", "/api/v1/remediation-board/workload", None),
    ("GET", "/api/v1/remediation/backlog", None),
    ("GET", "/api/v1/remediation/cwe-templates", None),
    ("GET", f"/api/v1/remediation/metrics/{ORG_ID}", None),
    ("GET", "/api/v1/remediation/metrics", None),
    ("GET", "/api/v1/remediation/plans", None),
    ("GET", "/api/v1/remediation/prs/pr-1", None),
    ("GET", "/api/v1/remediation/prs", None),
    ("GET", "/api/v1/remediation/queue", None),
    ("GET", "/api/v1/remediation/sla", None),
    ("GET", "/api/v1/remediation/stats", None),
    ("GET", "/api/v1/remediation/statuses", None),
    ("GET", "/api/v1/remediation/summary", None),
    ("GET", "/api/v1/remediation/tasks/task-1/autofix/suggestions", None),
    ("GET", "/api/v1/remediation/tasks/task-1/timeline", None),
    ("GET", "/api/v1/remediation/tasks/task-1", None),
    ("GET", "/api/v1/remediation/tasks", None),
    ("GET", "/api/v1/report-builder/meta/data-sources", None),
    ("GET", "/api/v1/report-builder/meta/section-types", None),
    ("GET", "/api/v1/report-builder/reports/rpt-1/export", None),
    ("GET", "/api/v1/report-builder/reports/rpt-1", None),
    ("GET", "/api/v1/report-builder/reports", None),
    ("GET", "/api/v1/report-builder/stats", None),
    ("GET", "/api/v1/report-builder/templates/tmpl-1", None),
    ("GET", "/api/v1/report-builder/templates", None),
    ("GET", "/api/v1/reports/rpt-1/download", None),
    ("GET", "/api/v1/reports/rpt-1/file", None),
    ("GET", "/api/v1/reports/rpt-1", None),
    ("GET", "/api/v1/reports/export/csv/exp-1/download", None),
    ("GET", "/api/v1/reports/export/json", None),
    ("GET", "/api/v1/reports/history", None),
    ("GET", "/api/v1/reports/schedules/sched-1/preview", None),
    ("GET", "/api/v1/reports/schedules/list", None),
    ("GET", "/api/v1/reports/schedules", None),
    ("GET", "/api/v1/reports/stats", None),
    ("GET", "/api/v1/reports/templates/list", None),
    ("GET", "/api/v1/reports/templates", None),
    ("GET", "/api/v1/reports", None),
    ("GET", "/api/v1/retention/dashboard", None),
    ("GET", "/api/v1/retention/defaults", None),
    ("GET", "/api/v1/retention/erasure", None),
    ("GET", "/api/v1/retention/history", None),
    ("GET", "/api/v1/retention/policies", None),
    ("GET", "/api/v1/retention/purgeable", None),
    ("GET", "/api/v1/risk-acceptance/acc-1/history", None),
    ("GET", "/api/v1/risk-acceptance/acc-1", None),
    ("GET", "/api/v1/risk-acceptance/expiring", None),
    ("GET", "/api/v1/risk-acceptance/pending", None),
    ("GET", "/api/v1/risk-acceptance/stats", None),
    ("GET", "/api/v1/risk-acceptance", None),
    ("GET", "/api/v1/risk-aggregator/heatmap", None),
    ("GET", "/api/v1/risk-aggregator/org-score", None),
    ("GET", "/api/v1/risk-aggregator/scores/entity/ent-1", None),
    ("GET", "/api/v1/risk-aggregator/scores", None),
    ("GET", "/api/v1/risk-aggregator/stats", None),
    ("GET", "/api/v1/risk-aggregator/thresholds", None),
    ("GET", "/api/v1/risk-aggregator/top-risks", None),
    ("GET", "/api/v1/risk-quant/history", None),
    ("GET", "/api/v1/risk-quant/roi-analysis", None),
    ("GET", "/api/v1/risk-quant/scenarios/sc-1", None),
    ("GET", "/api/v1/risk-quant/summary", None),
    ("GET", "/api/v1/risk-quantification/financial-impacts", None),
    ("GET", "/api/v1/risk-quantification/scenarios", None),
    ("GET", "/api/v1/risk-quantification/stats", None),
    ("GET", "/api/v1/risk-quantification/treatments", None),
    ("GET", "/api/v1/risk-quantifier/asset-templates", None),
    ("GET", "/api/v1/risk-quantifier/health", None),
    ("GET", "/api/v1/risk-quantifier/heatmap", None),
    ("GET", "/api/v1/risk-quantifier/portfolio", None),
    ("GET", "/api/v1/risk-quantifier/roi", None),
    ("GET", "/api/v1/risk-quantifier/scenarios/sc-1", None),
    ("GET", "/api/v1/risk-quantifier/scenarios", None),
    ("GET", "/api/v1/risk-register-engine/risks/risk-1/context", None),
    ("GET", "/api/v1/risk-register-engine/risks/risk-1", None),
    ("GET", "/api/v1/risk-register-engine/risks", None),
    ("GET", "/api/v1/risk-register-engine/stats", None),
    ("GET", "/api/v1/risk-register-engine/treatments", None),
    ("GET", "/api/v1/risk-scenarios/risk-reduction", None),
    ("GET", "/api/v1/risk-scenarios/scenarios/sc-1", None),
    ("GET", "/api/v1/risk-scenarios/scenarios", None),
    ("GET", "/api/v1/risk-scenarios/stats", None),
    ("GET", "/api/v1/risk-scenarios/top-risks", None),
    ("GET", "/api/v1/risk-scenarios", None),
    ("GET", "/api/v1/risk-treatment/stats", None),
    ("GET", "/api/v1/risk-treatment/treatments/treat-1/notes", None),
    ("GET", "/api/v1/risk-treatment/treatments/treat-1", None),
    ("GET", "/api/v1/risk-treatment/treatments", None),
    ("GET", "/api/v1/risk/exposure/asset-1", None),
    ("GET", "/api/v1/risk/exposure/org", None),
    ("GET", "/api/v1/risk/exposure/trend", None),
    ("GET", "/api/v1/risks/risk-1/treatments", None),
    ("GET", "/api/v1/risks/risk-1", None),
    ("GET", "/api/v1/risks/appetite/list", None),
    ("GET", "/api/v1/risks/controls/list", None),
    ("GET", "/api/v1/risks/heatmap", None),
    ("GET", "/api/v1/risks/kris/list", None),
    ("GET", "/api/v1/risks/report/board", None),
    ("GET", "/api/v1/risks", None),
    ("GET", "/api/v1/runtime/alerts", None),
    ("GET", "/api/v1/runtime/anomalies", None),
    ("GET", "/api/v1/runtime/hosts/host-1/process-tree", None),
    ("GET", "/api/v1/runtime/policies", None),
    ("GET", "/api/v1/runtime/stats", None),
    ("GET", "/api/v1/runtime/threats", None),
    ("GET", "/api/v1/session-recording/alerts", None),
    ("GET", "/api/v1/session-recording/sessions/sess-1", None),
    ("GET", "/api/v1/session-recording/sessions", None),
    ("GET", "/api/v1/session-recording/stats", None),
    ("GET", "/api/v1/verify/health", None),
    ("GET", "/api/v1/verify/history", None),
    ("GET", "/api/v1/verify/stats", None),
    ("GET", "/api/v1/verify/supported-languages", None),
    ("GET", "/playbook-marketplace/pb-1/export", None),
    ("GET", "/playbook-marketplace/pb-1", None),
    ("GET", f"/playbook-marketplace/installed/{ORG_ID}", None),
    ("GET", "/playbook-marketplace/list", None),
    ("GET", "/playbook-marketplace/popular", None),
    ("GET", "/playbook-marketplace/stats", None),
    ("GET", "/provenance/test-artifact", None),
    ("GET", "/provenance/", None),
    ("GET", "/provenance/chains", None),
    ("GET", "/provenance/health", None),
    ("GET", "/provenance/status", None),
    ("GET", "/risk/", None),
    ("GET", "/risk/component/webapp", None),
    ("GET", "/risk/cve/CVE-2024-1234", None),
    ("GET", "/risk/health", None),
    ("GET", "/risk/overview", None),
    ("GET", "/risk/score", None),
    ("GET", "/risk/scores", None),
    ("GET", "/risk/status", None),

    # === PATCH endpoints ===
    ("PATCH", "/api/v1/openclaw/findings/find-1/status", {"status": "resolved"}),
    ("PATCH", "/api/v1/pagerduty/incidents/inc-1", {"status": "acknowledged"}),
    ("PATCH", "/api/v1/patch-automation/deployments/dep-1/status", {"status": "completed"}),
    ("PATCH", "/api/v1/patch-automation/patches/patch-1/approve", None),
    ("PATCH", "/api/v1/patch-management/patches/patch-1/status", {"status": "approved"}),
    ("PATCH", "/api/v1/policies/pol-1", {"name": "updated-policy"}),
    ("PATCH", "/api/v1/privacy-impact/risks/risk-1/status", {"status": "mitigated"}),
    ("PATCH", "/api/v1/privacy/dsrs/req-1/status", {"status": "in_progress"}),
    ("PATCH", "/api/v1/privacy/incidents/inc-1/status", {"status": "investigating"}),
    ("PATCH", "/api/v1/questionnaires/q-1/questions/q1", {"response": "Yes", "score": 4}),
    ("PATCH", "/api/v1/red-team/engagements/eng-1/status", {"status": "active"}),
    ("PATCH", "/api/v1/regulatory-tracker/obligations/obl-1/status", {"status": "compliant"}),
    ("PATCH", "/api/v1/remediation-board/cards/card-1/assign", {"assignee": "user-1"}),
    ("PATCH", "/api/v1/remediation-board/cards/card-1/move", {"column": "in_progress"}),
    ("PATCH", "/api/v1/risk-quantification/scenarios/sc-1", {"name": "updated"}),
    ("PATCH", "/api/v1/risk-register-engine/risks/risk-1/status", {"status": "mitigated"}),
    ("PATCH", "/api/v1/risk-treatment/treatments/treat-1/status", {"status": "completed"}),
    ("PATCH", "/api/v1/risks/risk-1", {"title": "updated"}),
    ("PATCH", "/api/v1/risks/kris/kri-1/value", {"value": 42}),
    ("PATCH", "/api/v1/risks/treatments/plan-1/status", {"status": "active"}),

    # === POST endpoints ===
    ("POST", "/api/v1/brain/evidence/generate", {"org_id": ORG_ID, "frameworks": ["SOC2"]}),
    ("POST", "/api/v1/brain/pipeline/run", {"org_id": ORG_ID, "target": "test"}),
    ("POST", "/api/v1/oauth2/token", {"grant_type": "client_credentials", "client_id": "test", "client_secret": "test"}),
    ("POST", "/api/v1/observability/alerts/rules", {"name": "test-rule", "condition": "cpu > 90", "severity": "high"}),
    ("POST", "/api/v1/onboarding/reset", None),
    ("POST", "/api/v1/onboarding/start", {"org_id": ORG_ID}),
    ("POST", "/api/v1/onboarding/steps/api_keys/complete", None),
    ("POST", "/api/v1/onboarding/steps/api_keys/skip", None),
    ("POST", "/api/v1/openclaw/campaigns/camp-1/advance", None),
    ("POST", "/api/v1/openclaw/campaigns/camp-1/complete", None),
    ("POST", "/api/v1/openclaw/campaigns/camp-1/pause", None),
    ("POST", "/api/v1/openclaw/campaigns/camp-1/start", None),
    ("POST", "/api/v1/openclaw/campaigns", {"name": "test-campaign", "target": "http://localhost", "org_id": ORG_ID}),
    ("POST", "/api/v1/openclaw/scan", {"target_url": "http://example.com", "org_id": ORG_ID}),
    ("POST", "/api/v1/orgs", {"name": "test-org", "org_id": ORG_ID}),
    ("POST", "/api/v1/ot-sec/assets", {"name": "plc-1", "asset_type": "plc", "org_id": ORG_ID}),
    ("POST", "/api/v1/ot-sec/incidents", {"title": "test", "severity": "high", "org_id": ORG_ID}),
    ("POST", "/api/v1/ot-sec/zones", {"name": "zone-1", "purdue_level": 1, "org_id": ORG_ID}),
    ("POST", "/api/v1/ot-security/anomalies", {"asset_id": "asset-1", "anomaly_type": "protocol_violation", "severity": "high", "org_id": ORG_ID}),
    ("POST", "/api/v1/ot-security/assets", {"name": "plc-2", "asset_type": "plc", "category": "ics", "org_id": ORG_ID}),
    ("POST", "/api/v1/pag/accounts/acct-1/anomalies", {"anomaly_type": "unusual_access", "org_id": ORG_ID}),
    ("POST", "/api/v1/pag/accounts/acct-1/sessions", {"session_type": "ssh", "org_id": ORG_ID}),
    ("POST", "/api/v1/pag/accounts", {"username": "admin", "account_type": "service", "org_id": ORG_ID}),
    ("POST", "/api/v1/pagerduty/incidents", {"title": "test-incident", "service_id": "svc-1", "urgency": "high"}),
    ("POST", "/api/v1/pam/accounts", {"username": "svc-admin", "account_type": "service", "target_system": "db-prod"}),
    ("POST", "/api/v1/pam/policies", {"name": "mfa-required", "rules": [{"type": "mfa", "required": True}]}),
    ("POST", "/api/v1/pam/sessions/sess-1/approve", None),
    ("POST", "/api/v1/pam/sessions/sess-1/end", None),
    ("POST", "/api/v1/pam/sessions", {"account_id": "acct-1", "target_system": "db-prod", "session_type": "ssh"}),
    ("POST", "/api/v1/passive-dns/resolutions", {"domain": "example.com", "ip": "1.2.3.4", "org_id": ORG_ID}),
    ("POST", "/api/v1/passive-dns/threats", {"domain": "malware.bad", "threat_type": "malware", "org_id": ORG_ID}),
    ("POST", "/api/v1/password-policy/audits", {"org_id": ORG_ID}),
    ("POST", "/api/v1/password-policy/policies/pol-1/evaluate", {"password": "Test1234!@#$"}),
    ("POST", "/api/v1/password-policy/policies", {"name": "strong", "min_length": 12, "org_id": ORG_ID}),
    ("POST", "/api/v1/password-policy/violations/viol-1/remediate", None),
    ("POST", "/api/v1/password-policy/violations", {"user_id": "user-1", "violation_type": "weak_password", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-automation/deployments", {"patch_id": "patch-1", "target_hosts": ["host-1"], "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-automation/exceptions", {"patch_id": "patch-1", "reason": "legacy system", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-automation/patches", {"name": "KB1234", "severity": "critical", "cve_ids": ["CVE-2024-1234"], "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-automation/windows", {"name": "weekly", "start_time": "02:00", "end_time": "06:00", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-management/patches/patch-1/deployments", {"target": "host-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-management/patches", {"name": "patch-test", "severity": "high", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-priority/batch", {"cve_ids": ["CVE-2024-1234", "CVE-2024-5678"], "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-priority/plans/plan-1/patch/CVE-2024-1234", None),
    ("POST", "/api/v1/patch-priority/plans", {"name": "Q1-patch-plan", "org_id": ORG_ID}),
    ("POST", "/api/v1/patch-priority/score", {"cve_id": "CVE-2024-1234", "org_id": ORG_ID}),
    ("POST", "/api/v1/patches/patch-1/deploy", {"target_hosts": ["host-1"]}),
    ("POST", "/api/v1/patches/patch-1/rollback", None),
    ("POST", "/api/v1/patches/patch-1/schedule", {"scheduled_date": "2026-05-01"}),
    ("POST", "/api/v1/patches/discover", {"scan_target": "network"}),
    ("POST", "/api/v1/patches", {"name": "KB5678", "severity": "critical", "cve_id": "CVE-2024-5678"}),
    ("POST", "/api/v1/pentest-mgmt/engagements/eng-1/findings", {"title": "SQLi", "severity": "critical", "org_id": ORG_ID}),
    ("POST", "/api/v1/pentest-mgmt/engagements/eng-1/targets", {"target": "api.example.com", "org_id": ORG_ID}),
    ("POST", "/api/v1/pentest-mgmt/engagements", {"name": "Q1-pentest", "scope": "api", "org_id": ORG_ID}),
    ("POST", "/api/v1/pentest-mgmt/findings/find-1/retests", {"result": "pass", "org_id": ORG_ID}),
    ("POST", "/api/v1/pentest/run/tgt-1", None),
    ("POST", "/api/v1/pentest/schedules", {"target_id": "tgt-1", "frequency": "weekly"}),
    ("POST", "/api/v1/pentest/targets", {"url": "https://example.com", "name": "test-target"}),
    ("POST", "/api/v1/phishing/campaigns/camp-1/click", None),
    ("POST", "/api/v1/phishing/campaigns/camp-1/open", None),
    ("POST", "/api/v1/phishing/campaigns/camp-1/report", None),
    ("POST", "/api/v1/phishing/campaigns/camp-1/targets", {"targets": [{"email": "user@test.com"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/phishing/campaigns", {"name": "Q1-phishing-test", "template_id": "tmpl-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/phishing/targets/tgt-1/result", {"result": "clicked", "org_id": ORG_ID}),
    ("POST", "/api/v1/phishing/templates", {"name": "fake-invoice", "subject": "Invoice Due", "body": "Click here", "org_id": ORG_ID}),
    ("POST", "/api/v1/physical-security/events", {"location_id": "loc-1", "event_type": "access_granted", "org_id": ORG_ID}),
    ("POST", "/api/v1/physical-security/incidents", {"location_id": "loc-1", "incident_type": "tailgating", "severity": "medium", "org_id": ORG_ID}),
    ("POST", "/api/v1/physical-security/locations", {"name": "HQ", "address": "123 Main St", "org_id": ORG_ID}),
    ("POST", "/api/v1/pki/cas", {"name": "root-ca", "org_id": ORG_ID}),
    ("POST", "/api/v1/pki/certificates", {"common_name": "api.example.com", "org_id": ORG_ID}),
    ("POST", "/api/v1/playbooks/pb-1/execute", {"org_id": ORG_ID}),
    ("POST", "/api/v1/playbooks", {"name": "incident-response", "steps": [{"name": "isolate", "action": "network_isolate"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/policies/pol-1/enforce", None),
    ("POST", "/api/v1/policies/pol-1/test", {"target": "test-resource"}),
    ("POST", "/api/v1/policies/pol-1/validate", None),
    ("POST", "/api/v1/policies/evaluate/batch", {"targets": ["res-1", "res-2"], "org_id": ORG_ID}),
    ("POST", "/api/v1/policies/evaluate", {"target": "test-resource", "org_id": ORG_ID}),
    ("POST", "/api/v1/policies/simulate", {"policy": {"name": "test"}, "target": "res-1"}),
    ("POST", "/api/v1/policies", {"name": "no-public-s3", "type": "preventive", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-enforcement/exceptions", {"policy_id": "pol-1", "reason": "legacy", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-enforcement/policies/pol-1/version", {"content": "updated", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-enforcement/policies", {"name": "no-root-login", "type": "preventive", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-engine/evaluate/batch", {"targets": ["res-1"], "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-engine/evaluate", {"target": "res-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-engine/import", {"policies": [{"name": "test"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-engine/policies", {"name": "mfa-enforced", "rules": [], "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-engine/test", {"policy_id": "pol-1", "test_data": {}, "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-generator/generate", {"framework": "SOC2", "domain": "access_control", "org_id": ORG_ID}),
    ("POST", "/api/v1/policy-generator/policies/pol-1/approve", None),
    ("POST", "/api/v1/policy-generator/policies/pol-1/archive", None),
    ("POST", "/api/v1/posture-advisor/analyze", {"org_id": ORG_ID}),
    ("POST", "/api/v1/posture-advisor/recommendations/rec-1/accept", None),
    ("POST", "/api/v1/posture-advisor/recommendations/rec-1/complete", None),
    ("POST", "/api/v1/posture-advisor/recommendations/rec-1/dismiss", None),
    ("POST", "/api/v1/posture-benchmark/generate", {"org_id": ORG_ID, "industry": "technology"}),
    ("POST", "/api/v1/posture-score/benchmarks", {"name": "industry-avg", "score": 75, "org_id": ORG_ID}),
    ("POST", "/api/v1/posture-score/components/network", {"score": 85, "org_id": ORG_ID}),
    ("POST", "/api/v1/posture-score/compute", {"org_id": ORG_ID}),
    ("POST", "/api/v1/posture/calculate", {"org_id": ORG_ID}),
    ("POST", "/api/v1/posture/compare", {"org_ids": [ORG_ID]}),
    ("POST", "/api/v1/posture/tracker/calculate", {"org_id": ORG_ID}),
    ("POST", "/api/v1/pr-gate/ci-gate", {"repo": "test/repo", "pr_number": 1, "org_id": ORG_ID}),
    ("POST", "/api/v1/pr-gate/evaluate", {"repo": "test/repo", "pr_number": 1, "org_id": ORG_ID}),
    ("POST", "/api/v1/pr-gate/report", {"repo": "test/repo", "pr_number": 1, "org_id": ORG_ID}),
    ("POST", "/api/v1/pr-gate/scan", {"repo": "test/repo", "pr_number": 1, "org_id": ORG_ID}),
    ("POST", "/api/v1/predictions/attack-chain", {"org_id": ORG_ID, "target": "web-server"}),
    ("POST", "/api/v1/predictions/bayesian/risk-assessment", {"org_id": ORG_ID, "evidence": {}}),
    ("POST", "/api/v1/predictions/bayesian/update", {"org_id": ORG_ID, "evidence": {"type": "malware"}}),
    ("POST", "/api/v1/predictions/combined-analysis", {"org_id": ORG_ID}),
    ("POST", "/api/v1/predictions/risk-trajectory", {"org_id": ORG_ID}),
    ("POST", "/api/v1/predictions/simulate-attack", {"org_id": ORG_ID, "attack_type": "ransomware"}),
    ("POST", "/api/v1/prioritize/compare", {"finding_ids": ["f1", "f2"]}),
    ("POST", "/api/v1/prioritize/explain/find-1", None),
    ("POST", "/api/v1/prioritize/feedback", {"finding_id": "find-1", "correct": True}),
    ("POST", "/api/v1/prioritize/top", {"findings": [{"id": "f1", "severity": "critical"}]}),
    ("POST", "/api/v1/prioritize", {"findings": [{"id": "f1", "severity": "critical", "cvss": 9.8}]}),
    ("POST", "/api/v1/privacy-impact/assessments/asmt-1/approve", {"approved_by": "dpo@test.com"}),
    ("POST", "/api/v1/privacy-impact/assessments/asmt-1/consultations", {"consultant": "dpa@gov", "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy-impact/assessments/asmt-1/risks", {"risk_type": "data_breach", "likelihood": 3, "impact": 4, "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy-impact/assessments", {"name": "marketing-pia", "data_types": ["email", "name"], "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy-impact/consultations/cons-1/complete", {"outcome": "approved"}),
    ("POST", "/api/v1/privacy/consents/consent-1/withdraw", None),
    ("POST", "/api/v1/privacy/consents", {"subject_id": "user-1", "purpose": "marketing", "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy/dsrs/req-1/fulfill", None),
    ("POST", "/api/v1/privacy/dsrs", {"subject_email": "user@test.com", "request_type": "access", "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy/incidents/inc-1/notify-dpa", None),
    ("POST", "/api/v1/privacy/incidents", {"title": "data-leak", "severity": "high", "org_id": ORG_ID}),
    ("POST", "/api/v1/privacy/processing-activities", {"name": "email-marketing", "lawful_basis": "consent", "org_id": ORG_ID}),
    ("POST", "/api/v1/privilege-escalation/events", {"user_id": "user-1", "action": "sudo", "target": "root", "org_id": ORG_ID}),
    ("POST", "/api/v1/privilege-escalation/rules", {"name": "no-sudo", "pattern": "sudo *", "org_id": ORG_ID}),
    ("POST", "/api/v1/privileged-identity/accounts/acct-1/certify", {"certified_by": "manager@test.com", "org_id": ORG_ID}),
    ("POST", "/api/v1/privileged-identity/accounts", {"username": "svc-admin", "account_type": "service", "org_id": ORG_ID}),
    ("POST", "/api/v1/privileged-identity/sessions", {"account_id": "acct-1", "session_type": "ssh", "org_id": ORG_ID}),
    ("POST", "/api/v1/purple-team/exercises/ex-1/complete", None),
    ("POST", "/api/v1/purple-team/exercises/ex-1/response", {"response_type": "detection", "details": "Alert triggered"}),
    ("POST", "/api/v1/purple-team/exercises/ex-1/run", None),
    ("POST", "/api/v1/purple-team/exercises/ex-1/steps/0", {"result": "success"}),
    ("POST", "/api/v1/purple-team/exercises", {"name": "test-exercise", "scenario_id": "sc-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/quantum-crypto/assessments", {"asset_id": "asset-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/quantum-crypto/assets", {"name": "rsa-key-prod", "algorithm": "RSA-2048", "org_id": ORG_ID}),
    ("POST", "/api/v1/quantum-crypto/keys/rotate", None),
    ("POST", "/api/v1/quantum-crypto/migrations", {"asset_id": "asset-1", "target_algorithm": "CRYSTALS-Kyber", "org_id": ORG_ID}),
    ("POST", "/api/v1/quantum-crypto/sign", {"message": "test-data", "algorithm": "dilithium"}),
    ("POST", "/api/v1/quantum-crypto/verify", {"message": "test-data", "signature": "abc123", "algorithm": "dilithium"}),
    ("POST", "/api/v1/questionnaires/q-1/auto-answer", None),
    ("POST", "/api/v1/questionnaires/q-1/submit", None),
    ("POST", "/api/v1/questionnaires/answer-bank", {"question": "Do you encrypt at rest?", "answer": "Yes", "org_id": ORG_ID}),
    ("POST", "/api/v1/questionnaires", {"name": "SOC2-assessment", "framework": "SOC2", "org_id": ORG_ID}),
    ("POST", "/api/v1/queue/enqueue", {"task_type": "scan", "payload": {"target": "test"}}),
    ("POST", "/api/v1/ransomware-protection/backups/bk-1/validate", None),
    ("POST", "/api/v1/ransomware-protection/backups", {"name": "db-backup", "backup_type": "full", "org_id": ORG_ID}),
    ("POST", "/api/v1/ransomware-protection/detections/det-1/contain", None),
    ("POST", "/api/v1/ransomware-protection/detections", {"pattern_type": "file_encryption", "source": "edr-agent", "org_id": ORG_ID}),
    ("POST", "/api/v1/ransomware-protection/playbooks/pb-1/execute", None),
    ("POST", "/api/v1/ransomware-protection/playbooks", {"name": "ransomware-ir", "steps": ["isolate", "investigate"], "org_id": ORG_ID}),
    ("POST", "/api/v1/rate-limits/reset/key-1", None),
    ("POST", "/api/v1/rbac/assign", {"user_id": "user-1", "role": "analyst", "org_id": ORG_ID}),
    ("POST", "/api/v1/rbac/check", {"user_id": "user-1", "permission": "read:vulnerabilities", "org_id": ORG_ID}),
    ("POST", "/api/v1/red-team/engagements/eng-1/findings", {"title": "RCE via deserialization", "severity": "critical", "org_id": ORG_ID}),
    ("POST", "/api/v1/red-team/engagements/eng-1/ttps", {"tactic": "initial_access", "technique": "T1190", "org_id": ORG_ID}),
    ("POST", "/api/v1/red-team/engagements", {"name": "Q1-red-team", "scope": "external", "org_id": ORG_ID}),
    ("POST", "/api/v1/red-team/operators", {"name": "operator-1", "specialization": "web", "org_id": ORG_ID}),
    ("POST", "/api/v1/red-team/simulations/sim-1/run", None),
    ("POST", "/api/v1/red-team/simulations", {"name": "lateral-movement", "attack_type": "apt", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-reporting/regulations", {"name": "GDPR", "jurisdiction": "EU", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-reporting/reports", {"regulation_id": "reg-1", "report_type": "annual", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-tracker/assessments", {"regulation_id": "reg-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-tracker/obligations", {"regulation_id": "reg-1", "title": "data-breach-notification", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-tracker/regulations/reg-1/changes", {"title": "amendment-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory-tracker/regulations", {"name": "CCPA", "jurisdiction": "California", "org_id": ORG_ID}),
    ("POST", "/api/v1/regulatory/impact/reg-1", {"assessment": "high"}),
    ("POST", "/api/v1/regulatory/regulations", {"name": "PCI-DSS", "category": "financial", "effective_date": "2026-01-01"}),
    ("POST", "/api/v1/remediation-board/cards/card-1/comments", {"comment": "Investigating", "author": "user-1"}),
    ("POST", "/api/v1/remediation-board/cards/bulk", {"cards": [{"title": "Fix SQLi", "severity": "critical"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation-board/cards", {"title": "Fix XSS", "severity": "high", "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/plan", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/prs/batch", {"finding_ids": ["f1", "f2"], "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/prs/generate", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/sla/check", {"org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/suggest-fix", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/tasks/task-1/autofix", None),
    ("POST", "/api/v1/remediation/tasks/task-1/verification", {"verified": True}),
    ("POST", "/api/v1/remediation/tasks/task-1/verify", {"verified": True}),
    ("POST", "/api/v1/remediation/tasks", {"title": "Fix SQLi", "finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/remediation/verify", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/report-builder/templates/tmpl-1/clone", None),
    ("POST", "/api/v1/report-builder/templates/tmpl-1/generate", {"org_id": ORG_ID}),
    ("POST", "/api/v1/report-builder/templates", {"name": "monthly-exec", "sections": ["summary", "risks"], "org_id": ORG_ID}),
    ("POST", "/api/v1/reports/export/csv", {"report_id": "rpt-1"}),
    ("POST", "/api/v1/reports/export/sarif", {"report_id": "rpt-1"}),
    ("POST", "/api/v1/reports/generate", {"type": "executive", "org_id": ORG_ID}),
    ("POST", "/api/v1/reports/schedule", {"report_type": "weekly", "org_id": ORG_ID}),
    ("POST", "/api/v1/reports/schedules/sched-1/trigger", None),
    ("POST", "/api/v1/reports/schedules", {"name": "weekly-report", "frequency": "weekly", "org_id": ORG_ID}),
    ("POST", "/api/v1/reports/send-now", {"report_id": "rpt-1", "recipients": ["admin@test.com"]}),
    ("POST", "/api/v1/reports", {"title": "Q1-security-report", "type": "quarterly", "org_id": ORG_ID}),
    ("POST", "/api/v1/retention/erasure/req-1/process", None),
    ("POST", "/api/v1/retention/erasure", {"subject_id": "user-1", "reason": "gdpr_request", "org_id": ORG_ID}),
    ("POST", "/api/v1/retention/policies", {"name": "90-day-logs", "retention_days": 90, "category": "logs", "org_id": ORG_ID}),
    ("POST", "/api/v1/retention/purge-all", {"org_id": ORG_ID}),
    ("POST", "/api/v1/retention/purge/logs", {"org_id": ORG_ID}),
    ("POST", "/api/v1/risk-acceptance/acc-1/approve", {"approved_by": "ciso@test.com"}),
    ("POST", "/api/v1/risk-acceptance/acc-1/reject", {"rejected_by": "ciso@test.com"}),
    ("POST", "/api/v1/risk-acceptance/acc-1/revoke", None),
    ("POST", "/api/v1/risk-acceptance/expire", {"org_id": ORG_ID}),
    ("POST", "/api/v1/risk-acceptance/request", {"risk_id": "risk-1", "justification": "Low impact", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-aggregator/scores", {"entity_id": "ent-1", "entity_type": "asset", "risk_score": 75, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-aggregator/sync", {"org_id": ORG_ID}),
    ("POST", "/api/v1/risk-aggregator/thresholds", {"level": "critical", "min_score": 90, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quant/scenarios/sc-1/controls", {"control_name": "WAF", "annual_cost": 10000, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quant/scenarios", {"name": "data-breach", "asset_value": 1000000, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quant/snapshots", {"org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quantification/financial-impacts", {"scenario_id": "sc-1", "amount": 500000, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quantification/scenarios/sc-1/monte-carlo", {"iterations": 1000}),
    ("POST", "/api/v1/risk-quantification/scenarios", {"name": "ransomware", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quantification/treatments", {"scenario_id": "sc-1", "name": "EDR", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quantifier/compare", {"scenario_ids": ["sc-1", "sc-2"]}),
    ("POST", "/api/v1/risk-quantifier/findings/quantify", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-quantifier/scenarios/sc-1/quantify", None),
    ("POST", "/api/v1/risk-quantifier/scenarios", {"name": "apt-attack", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-register-engine/risks/risk-1/treatments", {"name": "patch", "type": "mitigate", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-register-engine/risks", {"title": "unpatched-server", "likelihood": 4, "impact": 5, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-scenarios/scenarios/sc-1/mitigations/mit-1/implement", None),
    ("POST", "/api/v1/risk-scenarios/scenarios/sc-1/mitigations", {"name": "WAF", "effectiveness": 0.7, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-scenarios/scenarios/sc-1/reviews", {"reviewer": "ciso@test.com", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-scenarios/scenarios", {"name": "insider-threat", "likelihood": 3, "impact": 4, "org_id": ORG_ID}),
    ("POST", "/api/v1/risk-treatment/treatments/treat-1/notes", {"note": "Progress update", "author": "analyst-1"}),
    ("POST", "/api/v1/risk-treatment/treatments", {"risk_id": "risk-1", "treatment_type": "mitigate", "name": "Deploy WAF", "org_id": ORG_ID}),
    ("POST", "/api/v1/risk/rank", {"findings": [{"id": "f1", "cvss": 9.8}], "org_id": ORG_ID}),
    ("POST", "/api/v1/risk/score", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/risks/risk-1/controls/map", {"control_id": "ctrl-1"}),
    ("POST", "/api/v1/risks/appetite", {"risk_category": "operational", "tolerance": "medium", "org_id": ORG_ID}),
    ("POST", "/api/v1/risks/controls", {"name": "WAF", "type": "preventive", "org_id": ORG_ID}),
    ("POST", "/api/v1/risks/kris", {"name": "patch-compliance", "threshold": 95, "org_id": ORG_ID}),
    ("POST", "/api/v1/risks/treatments", {"risk_id": "risk-1", "type": "mitigate", "org_id": ORG_ID}),
    ("POST", "/api/v1/risks", {"title": "data-breach-risk", "category": "operational", "likelihood": 3, "impact": 5, "org_id": ORG_ID}),
    ("POST", "/api/v1/runtime/alerts/alert-1/ack", None),
    ("POST", "/api/v1/runtime/events/evaluate", {"events": [{"type": "process_exec", "command": "whoami"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/runtime/events", {"host": "host-1", "event_type": "process_exec", "details": {"command": "whoami"}, "org_id": ORG_ID}),
    ("POST", "/api/v1/runtime/policies", {"name": "no-crypto-mining", "rules": [{"type": "process", "pattern": "*miner*"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/session-recording/sessions/sess-1/alerts", {"alert_type": "suspicious_command", "org_id": ORG_ID}),
    ("POST", "/api/v1/session-recording/sessions/sess-1/end", None),
    ("POST", "/api/v1/session-recording/sessions", {"user_id": "user-1", "session_type": "ssh", "target": "db-prod", "org_id": ORG_ID}),
    ("POST", "/api/v1/verify/bulk", {"fixes": [{"finding_id": "f1", "code": "patched"}], "org_id": ORG_ID}),
    ("POST", "/api/v1/verify/fix", {"finding_id": "find-1", "code_before": "eval(input)", "code_after": "safe_eval(input)", "org_id": ORG_ID}),
    ("POST", "/api/v1/verify/mpte-retest", {"finding_id": "find-1", "org_id": ORG_ID}),
    ("POST", "/api/v1/verify/regression", {"finding_id": "find-1", "code": "safe_eval(input)", "org_id": ORG_ID}),
    ("POST", "/playbook-marketplace/pb-1/install", {"org_id": ORG_ID}),
    ("POST", "/playbook-marketplace/pb-1/rate", {"rating": 5, "org_id": ORG_ID}),
    ("POST", "/playbook-marketplace/import", {"playbook": {"name": "test", "steps": []}, "org_id": ORG_ID}),
    ("POST", "/playbook-marketplace/publish", {"name": "my-playbook", "description": "test", "steps": [], "org_id": ORG_ID}),

    # === PUT endpoints ===
    ("PUT", "/api/v1/ot-sec/assets/asset-1/status", {"status": "active"}),
    ("PUT", "/api/v1/ot-sec/incidents/inc-1/status", {"status": "resolved"}),
    ("PUT", "/api/v1/ot-security/anomalies/anom-1/resolve", None),
    ("PUT", "/api/v1/pentest-mgmt/engagements/eng-1/status", {"status": "active"}),
    ("PUT", "/api/v1/pentest-mgmt/findings/find-1/status", {"status": "remediated"}),
    ("PUT", "/api/v1/physical-security/incidents/inc-1/resolve", {"resolution": "false alarm"}),
    ("PUT", "/api/v1/pki/certificates/cert-1/revoke", {"reason": "key_compromise"}),
    ("PUT", "/api/v1/policies/pol-1/enable", None),
    ("PUT", "/api/v1/policies/pol-1", {"name": "updated", "type": "preventive"}),
    ("PUT", "/api/v1/policy-enforcement/exceptions/exc-1/approve", {"approved_by": "admin"}),
    ("PUT", "/api/v1/policy-engine/policies/pol-1", {"name": "updated", "rules": []}),
    ("PUT", "/api/v1/policy-generator/policies/pol-1/content", {"content": "Updated policy content"}),
    ("PUT", "/api/v1/pr-gate/policy", {"min_score": 80, "block_critical": True}),
    ("PUT", "/api/v1/prioritize/weights", {"cvss": 0.4, "epss": 0.3, "kev": 0.3}),
    ("PUT", "/api/v1/privileged-identity/accounts/acct-1/risk", {"risk_level": "high"}),
    ("PUT", "/api/v1/privileged-identity/accounts/acct-1/rotate", None),
    ("PUT", "/api/v1/privileged-identity/sessions/sess-1/close", None),
    ("PUT", "/api/v1/quantum-crypto/assessments/asmt-1/complete", {"findings": []}),
    ("PUT", "/api/v1/quantum-crypto/assets/asset-1/migration-status", {"status": "in_progress"}),
    ("PUT", "/api/v1/rasp/mode", {"mode": "block"}),
    ("PUT", "/api/v1/rasp/rules/rule-1", {"enabled": True, "action": "block"}),
    ("PUT", "/api/v1/rate-limits/config", {"requests_per_minute": 100, "burst": 20}),
    ("PUT", "/api/v1/regulatory-reporting/regulations/reg-1/compliance-score", {"score": 85}),
    ("PUT", "/api/v1/regulatory-reporting/reports/rpt-1/submit", None),
    ("PUT", "/api/v1/remediation/plan-1/status", {"status": "in_progress"}),
    ("PUT", "/api/v1/remediation/tasks/task-1/assign", {"assignee": "user-1"}),
    ("PUT", "/api/v1/remediation/tasks/task-1/status", {"status": "in_progress"}),
    ("PUT", "/api/v1/remediation/tasks/task-1/ticket", {"ticket_id": "JIRA-123"}),
    ("PUT", "/api/v1/remediation/tasks/task-1/transition", {"status": "in_progress"}),
    ("PUT", "/api/v1/report-builder/templates/tmpl-1", {"name": "updated-template", "sections": ["summary"]}),
    ("PUT", "/api/v1/risk-quant/scenarios/sc-1/rates", {"aro": 0.5, "sle": 500000}),
]


def run_test(endpoint):
    method, path, body = endpoint
    url = f"{BASE}{path}"
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "-X", method,
        "-H", f"X-API-Key: {TOKEN}",
        "-H", "Content-Type: application/json",
        "--connect-timeout", "5",
        "--max-time", "10",
        url,
    ]
    if body is not None:
        cmd.extend(["-d", json.dumps(body)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        status = result.stdout.strip()
        return (method, path, status, body is not None)
    except Exception as e:
        return (method, path, f"ERR:{type(e).__name__}", body is not None)


def main():
    print(f"Testing {len(ENDPOINTS)} endpoints against {BASE}")
    print(f"Token: {TOKEN[:20]}...")
    print("=" * 80)

    results = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(run_test, ep): ep for ep in ENDPOINTS}
        done = 0
        for future in as_completed(futures):
            done += 1
            r = future.result()
            results.append(r)
            if done % 50 == 0:
                print(f"  Progress: {done}/{len(ENDPOINTS)}")

    elapsed = time.time() - start

    # Sort by router path
    results.sort(key=lambda x: (x[0], x[1]))

    # Tally
    status_counts = defaultdict(int)
    for _, _, status, _ in results:
        status_counts[status] += 1

    # Group by status bucket
    ok_2xx = []
    client_4xx = []
    server_5xx = []
    other = []
    for r in results:
        s = r[2]
        if s.startswith("2"):
            ok_2xx.append(r)
        elif s.startswith("4"):
            client_4xx.append(r)
        elif s.startswith("5"):
            server_5xx.append(r)
        else:
            other.append(r)

    # Build report
    report = []
    report.append("# API Test Report: O/P/Q/R Router Endpoints")
    report.append(f"\n**Date**: 2026-04-22")
    report.append(f"**Base URL**: {BASE}")
    report.append(f"**Total Endpoints Tested**: {len(results)}")
    report.append(f"**Elapsed**: {elapsed:.1f}s")
    report.append(f"**Router Files**: 78 (oauth2 through runtime_protection)")
    report.append("")
    report.append("## Summary")
    report.append("")
    report.append("| Status | Count | Pct |")
    report.append("|--------|-------|-----|")
    report.append(f"| 2xx (OK) | {len(ok_2xx)} | {len(ok_2xx)*100//len(results)}% |")
    report.append(f"| 4xx (Client) | {len(client_4xx)} | {len(client_4xx)*100//len(results)}% |")
    report.append(f"| 5xx (Server) | {len(server_5xx)} | {len(server_5xx)*100//len(results)}% |")
    report.append(f"| Other/Error | {len(other)} | {len(other)*100//len(results)}% |")
    report.append("")

    report.append("### Status Code Breakdown")
    report.append("")
    report.append("| Code | Count |")
    report.append("|------|-------|")
    for code in sorted(status_counts.keys()):
        report.append(f"| {code} | {status_counts[code]} |")
    report.append("")

    # 5xx errors (bugs)
    if server_5xx:
        report.append(f"## 5xx Server Errors ({len(server_5xx)} endpoints) -- BUGS")
        report.append("")
        report.append("| Method | Path | Status | Has Body |")
        report.append("|--------|------|--------|----------|")
        for method, path, status, has_body in server_5xx:
            report.append(f"| {method} | `{path}` | {status} | {'Yes' if has_body else 'No'} |")
        report.append("")

    # Connection/timeout errors
    if other:
        report.append(f"## Connection/Timeout Errors ({len(other)} endpoints)")
        report.append("")
        report.append("| Method | Path | Status | Has Body |")
        report.append("|--------|------|--------|----------|")
        for method, path, status, has_body in other:
            report.append(f"| {method} | `{path}` | {status} | {'Yes' if has_body else 'No'} |")
        report.append("")

    # 4xx errors (expected for missing resources, auth issues)
    if client_4xx:
        report.append(f"## 4xx Client Errors ({len(client_4xx)} endpoints)")
        report.append("")
        report.append("| Method | Path | Status | Has Body |")
        report.append("|--------|------|--------|----------|")
        for method, path, status, has_body in client_4xx:
            report.append(f"| {method} | `{path}` | {status} | {'Yes' if has_body else 'No'} |")
        report.append("")

    # 2xx successes
    if ok_2xx:
        report.append(f"## 2xx Successes ({len(ok_2xx)} endpoints)")
        report.append("")
        report.append("| Method | Path | Status | Has Body |")
        report.append("|--------|------|--------|----------|")
        for method, path, status, has_body in ok_2xx:
            report.append(f"| {method} | `{path}` | {status} | {'Yes' if has_body else 'No'} |")
        report.append("")

    # Write report
    report_text = "\n".join(report)
    report_path = "/Users/devops.ai/fixops/Fixops/.omc/reports/api_test_batch_OR.md"
    with open(report_path, "w") as f:
        f.write(report_text)

    # Also print summary to stdout
    print(f"\n{'='*80}")
    print(f"DONE: {len(results)} endpoints tested in {elapsed:.1f}s")
    print(f"  2xx: {len(ok_2xx)}")
    print(f"  4xx: {len(client_4xx)}")
    print(f"  5xx: {len(server_5xx)} {'<-- BUGS!' if server_5xx else ''}")
    print(f"  Other: {len(other)}")
    print(f"\nReport: {report_path}")

    if server_5xx:
        print(f"\n--- 5xx BUGS ({len(server_5xx)}) ---")
        for method, path, status, _ in server_5xx:
            print(f"  {method} {path} -> {status}")

    if other:
        print(f"\n--- Connection/Timeout errors ({len(other)}) ---")
        for method, path, status, _ in other[:10]:
            print(f"  {method} {path} -> {status}")
        if len(other) > 10:
            print(f"  ... and {len(other)-10} more")


if __name__ == "__main__":
    main()
