# Router Dedup Worksheet — 2026-07-10

Auto-generated from AST scan of app.py + 5 registrars. 64 multi-mounted routers.
Rule: FastAPI serves the FIRST-registered mount. Keep the authenticated first mount; remove the rest. Verify boot + route-count delta + zero-unauth-survivors after each.

## SAFE — all-auth redundant (autonomous: remove all but first mount) (42)

All mounts authenticated -> pure redundancy. Behaviour-preserving.

- `analytics_dashboard_router` ×2 — platform_app.py:1124  platform_app.py:1817
- `analytics_routes_router` ×2 — platform_app.py:1133  platform_app.py:1827
- `api_analytics_router` ×2 — app.py:3418  platform_app.py:1183
- `api_gateway_router` ×2 — app.py:3426  platform_app.py:1192
- `app_config_router` ×2 — app.py:3481  platform_app.py:1536
- `backup_router` ×2 — platform_app.py:1309  platform_app.py:1843
- `changelog_router` ×2 — platform_app.py:1318  platform_app.py:1863
- `compliance_automation_router` ×2 — app.py:6546  grc_app.py:312
- `compliance_planner_router` ×2 — grc_app.py:156  grc_app.py:1354
- `compliance_reports_router` ×2 — app.py:3407  grc_app.py:130
- `council_enhanced_router` ×2 — app.py:3359  platform_app.py:1489
- `ctem_pipeline_router` ×2 — app.py:3343  ctem_app.py:70
- `dashboard_builder_router` ×2 — platform_app.py:1165  platform_app.py:1873
- `duckdb_analytics_router` ×2 — platform_app.py:1142  platform_app.py:2113
- `evidence_chain_router` ×2 — app.py:3516  grc_app.py:142
- `evidence_collector_router` ×2 — grc_app.py:170  grc_app.py:1364
- `exception_policy_router` ×2 — grc_app.py:182  grc_app.py:1374
- `exec_security_reports_router` ×2 — grc_app.py:208  grc_app.py:1394
- `executive_report_router` ×2 — grc_app.py:194  grc_app.py:1384
- `feed_registry_router` ×2 — app.py:3566  platform_app.py:1909
- `fix_engine_router` ×2 — app.py:7131  aspm_app.py:805
- `graphrag_router` ×2 — platform_app.py:1149  platform_app.py:2103
- `incident_response_router` ×2 — app.py:7127  ctem_app.py:1466
- `integration_health_router` ×2 — platform_app.py:631  platform_app.py:1929
- `ir_playbook_router` ×2 — ctem_app.py:130  grc_app.py:90
- `ir_playbook_runner_router` ×2 — ctem_app.py:144  grc_app.py:104
- `llm_council_router` ×2 — app.py:3367  platform_app.py:1498
- `llm_loop_metrics_router` ×2 — platform_app.py:1448  platform_app.py:1751
- `metrics_aggregator_router` ×2 — platform_app.py:1206  platform_app.py:1939
- `notification_router` ×2 — platform_app.py:1224  platform_app.py:1949
- `policy_generator_router` ×2 — app.py:3397  grc_app.py:116
- `rate_limit_router` ×2 — platform_app.py:1242  platform_app.py:2005
- `regulatory_tracker_engine_router` ×2 — grc_app.py:222  grc_app.py:1463
- `risk_register_router` ×2 — app.py:3327  grc_app.py:78
- `siem_router` ×2 — app.py:7217  platform_app.py:1805
- `tag_router` ×2 — platform_app.py:1332  platform_app.py:2053
- `tenant_rate_limiter_router` ×2 — platform_app.py:1251  platform_app.py:2015
- `threat_intel_sharing_router` ×2 — app.py:7060  ctem_app.py:404
- `user_analytics_router` ×2 — platform_app.py:1457  platform_app.py:2063
- `vendor_scorecard_router` ×2 — grc_app.py:234  grc_app.py:1433
- `webhook_events_router` ×2 — platform_app.py:1527  platform_app.py:2085
- `workflow_engine_router` ×2 — platform_app.py:1507  platform_app.py:2095

## REVIEW — mixed auth/unauth (HUMAN: is the unauth mount intentional?) (14)

One mount has NO auth. If unauth is intentional (webhooks/slack/public) LEAVE it; else remove the unauth shadow (security fix).

- `iot_security_router` ×3 — app.py:5768  app.py:6492 [NOAUTH]  ctem_app.py:213
- `versioning_router` ×3 — app.py:7118 [NOAUTH]  platform_app.py:1517  platform_app.py:2074
- `anomaly_ml_router` ×2 — app.py:6788 [NOAUTH]  ctem_app.py:168
- `compliance_seed_router` ×2 — app.py:6554 [NOAUTH]  grc_app.py:927
- `gcp_scc_router` ×2 — cspm_app.py:573 [NOAUTH]  platform_app.py:3000
- `greynoise_router` ×2 — app.py:7012 [NOAUTH]  platform_app.py:3259
- `pipeline_bom_router` ×2 — app.py:7135  aspm_app.py:460 [NOAUTH]
- `security_findings_router` ×2 — app.py:3303  aspm_app.py:423 [NOAUTH]
- `semantic_analyzer_router` ×2 — app.py:6983  aspm_app.py:569 [NOAUTH]
- `slack_bot_router` ×2 — platform_app.py:1061 [NOAUTH]  platform_app.py:2035
- `threat_brief_router` ×2 — app.py:7031  ctem_app.py:900 [NOAUTH]
- `threat_landscape_router` ×2 — app.py:7023  ctem_app.py:918 [NOAUTH]
- `webhooks_router` ×2 — platform_app.py:607 [NOAUTH]  platform_app.py:1781
- `zero_day_intelligence_router` ×2 — app.py:7052  ctem_app.py:760 [NOAUTH]

## REVIEW — all-unauth doubles (8)

Confirm the endpoint is meant to be public before dedup.

- `_legacy_versions_router` ×3 — app.py:7121 [NOAUTH]  platform_app.py:1518 [NOAUTH]  platform_app.py:2075 [NOAUTH]
- `billing_router` ×2 — app.py:7151 [NOAUTH]  platform_app.py:4158 [NOAUTH]
- `code_to_runtime_router` ×2 — app.py:7140 [NOAUTH]  aspm_app.py:551 [NOAUTH]
- `metrics_timeseries_router` ×2 — app.py:6648 [NOAUTH]  platform_app.py:1215 [NOAUTH]
- `security_registry_router` ×2 — app.py:6634 [NOAUTH]  platform_app.py:1398 [NOAUTH]
- `security_telemetry_router` ×2 — app.py:6599 [NOAUTH]  platform_app.py:1389 [NOAUTH]
- `slsa_provenance_router` ×2 — app.py:7105 [NOAUTH]  aspm_app.py:492 [NOAUTH]
- `upgrade_path_router` ×2 — app.py:7098 [NOAUTH]  platform_app.py:1466 [NOAUTH]
