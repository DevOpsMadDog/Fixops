#!/usr/bin/env bash
export PYTHONPATH=suite-api:suite-core:suite-evidence-risk:suite-attack:suite-feeds:suite-integrations:.
python -c "
import sys
sys.path.insert(0, 'suite-api')
sys.path.insert(0, 'suite-core')
from apps.api.app import create_app
app = create_app()
import apps.api.reports_router as r
print('Module name:', r.__name__)
print('DB type:', type(r.db))
print('DB path:', getattr(r.db, 'db_path', 'no db_path attr'))
" 2>&1
echo "EXIT=$?"
