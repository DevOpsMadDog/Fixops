# Migration Notes

## Repository restructure

The codebase now follows an explicit boundary between the lightweight demo pipeline, the reusable core
libraries, the enterprise reference stack, and archived prototypes.

| Previous location | New location |
| ----------------- | ------------ |
| `backend/` | `apps/api/` |
| `fixops/` | `core/` |
| `fixops-blended-enterprise/` | `enterprise/` |
| `new_backend/` | `prototypes/decider/` |

### Git move history

```
git mv backend apps/api
git mv fixops core
git mv fixops-blended-enterprise enterprise
git mv new_backend prototypes/decider
```

### Import path updates

* FastAPI ingestion imports now live under `apps.api.*`.
* Shared libraries import from `core.*`.
* Enterprise adapters continue to resolve under `enterprise/src/...`.
* Prototype decider services live under `prototypes.decider.*`.

Existing code should replace statements such as `from backend.app import create_app` with
`from apps.api.app import create_app`.  Likewise, any `fixops.` imports should be migrated to `core.`.

### Developer workflow changes

* Local type checks: `mypy core apps tests`
* CLI entry point: `python -m core.cli`
* Demo helpers: `make demo` and `make demo-enterprise` target the new module paths.
* Bootstrap scripts and CI workflows now install dependencies from `apps/api/requirements.txt` and
  (optionally) `enterprise/requirements.txt`.

## Overlay compatibility

Overlay files continue to support the optional `guardrails` block introduced previously. If the key is
absent, defaults are applied automatically (`maturity=scaling`, fail on `high`, warn on `medium`).

When upgrading, pull the latest `config/fixops.overlay.yml` only if you want the example evidence
directories and guardrail profiles that the CVE simulation writes to. Custom overlays continue to work
without modification.
