#!/usr/bin/env bash
export PYTHONPATH=suite-api:suite-core:suite-evidence-risk:suite-attack:suite-feeds:suite-integrations:.
python -m pytest tests/test_pentagi_api.py tests/test_reports_router_unit.py --timeout=10 --tb=line -q 2>&1 | tail -30
echo "EXIT=$?"
