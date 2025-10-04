**Purpose:** Scenario simulations that demonstrate FixOps contextual risk processing.

**Key Files:**
- `cve_scenario/` — runnable CVE-2021-44228 simulation exercising demo and enterprise overlays.

**Data In/Out:**
- Inputs: Overlay configuration, synthetic design/SBOM/SARIF/CVE payloads.
- Outputs: Evidence bundles and contextual scorecards written to overlay data directories.

**Gotchas:**
- Simulations write to directories declared in the overlay; point them at temporary folders for automated tests.
