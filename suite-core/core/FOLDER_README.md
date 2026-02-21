# core/

**Purpose:** Shared libraries for FixOps. Hosts the overlay configuration loader and
SSVC design context injector.

**Key Files**
- `configuration.py` — Overlay loader and dataclass.
- `design_context_injector.py` — Maps design CSV context into SSVC priors.

**Module API**
- `load_overlay(path=None)` returns an `OverlayConfig` with merged profile overrides.
- `DesignContextInjector.calculate_priors()` converts design context rows into probability weights.

**Data In/Out**
- Reads overlay YAML/JSON.
- Emits sanitized overlay metadata and SSVC probability structures.

**Gotchas**
- Overlay loader defaults to Enterprise mode; ensure `FIXOPS_MODE` env var is set appropriately.
- SSVC injector requires methodology-specific plugins from the `ssvc` package.
