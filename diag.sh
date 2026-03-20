#!/usr/bin/env bash
set -e
export PYTHONPATH=suite-api:suite-core:suite-evidence-risk:suite-attack:suite-feeds:suite-integrations:.
echo "=== CMD1: isolation test ==="
python -m pytest tests/test_reports_router_unit.py --timeout=10 --tb=short -q 2>&1 | tail -20
echo "=== CMD1 done ==="
