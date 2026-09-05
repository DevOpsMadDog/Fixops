# Retired routers

Routers moved here are no longer imported or mounted by the application. They
are kept rather than deleted so the integration work is recoverable if the
vendor or capability comes back.

| Router | Why it is here |
|---|---|
| `orca_router.py` | Orca Security connector, retired from the mounted set |
| `commercial_vendor_router.py` | commercial vendor index, retired |
| `gcp_cloudkms_router.py` | GCP Cloud KMS, retired |
| `llm_distill_router.py` | LLM distillation, retired |
| `mitre_navigator_router.py` | MITRE Navigator export, retired |

## Tests that referenced them

Retiring a router without retiring its tests leaves the suite erroring at
COLLECTION, which is worse than a failure: an import error produces no signal
and buries the results of everything collected alongside it. Measured here —
32 errors from `apps.api.orca_router` alone.

The convention, already used by `tests/test_gcp_cloudkms_router.py`:

```python
pytest.importorskip("apps.api.<name>_router", reason="retired to archive/dead_routers/")
```

`importorskip` rather than an unconditional skip, so restoring a router revives
its tests with no further edit.

Where a single retired router sits inside a test file covering many live ones
(`tests/test_legacy_connectors_smoke.py`), skip only the affected class. A
module-level guard there would take the other twenty-odd live connectors down
with it — trading a dead test for real lost coverage.
