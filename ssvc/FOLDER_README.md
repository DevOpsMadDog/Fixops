# ssvc/

**Purpose:** Bundled SSVC (Stakeholder-Specific Vulnerability Categorization) implementation used by
the design context injector to compute probability priors.

**Gotchas**
- Ensure methodology plugins exist under `ssvc/plugins/` before running `DesignContextInjector`.
- Treat as third-party code; keep in sync with upstream releases if relying on new methodologies.
