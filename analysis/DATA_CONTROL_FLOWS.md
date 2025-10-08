# Data & Control Flows

This document is generated automatically from the source tree.

## Inbound Interfaces

- `apps/api/__init__.py`
- `apps/api/app.py`
- `apps/api/normalizers.py`
- `apps/api/pipeline.py`
- `prototypes/decider/__init__.py`
- `prototypes/decider/api.py`
- `prototypes/decider/processing/__init__.py`
- `prototypes/decider/processing/bayesian.py`
- `prototypes/decider/processing/explanation.py`
- `prototypes/decider/processing/knowledge_graph.py`
- `prototypes/decider/processing/sarif.py`

## Persistence Layers

- `core/storage.py`
- `enterprise/src/models/__init__.py`
- `enterprise/src/models/base.py`
- `enterprise/src/models/base_sqlite.py`
- `enterprise/src/models/security.py`
- `enterprise/src/models/security_sqlite.py`
- `enterprise/src/models/user.py`
- `enterprise/src/models/user_sqlite.py`
- `enterprise/src/models/waivers.py`
- `tests/test_storage_security.py`

## Configuration & Secrets

- `core/configuration.py`
- `enterprise/src/config/settings.py`
- `tests/test_overlay_configuration.py`

## Error Handling & Retry Semantics

- See individual modules listed in `FILE_SUMMARIES.csv` for TODO markers.
