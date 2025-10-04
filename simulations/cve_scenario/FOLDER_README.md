**Purpose:** Demonstrates contextual rescoring for CVE-2021-44228 (Log4Shell) across Demo and Enterprise overlays, referencing the [NVD advisory](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

**Key Files:**
- `runner.py` — executable entry-point that orchestrates pipeline processing, contextual scoring, and evidence generation.
- `contexts.json` — business context definitions for each mode.
- `__init__.py` — exposes helper APIs for tests and scripts.

**Data In/Out:**
- Inputs: Overlay configuration plus synthetic design rows, SBOM component list, SARIF findings, and CVE feed defined inline.
- Outputs: Scorecards (`*-scores.json`) and evidence bundles (`*-evidence.json`) written to the overlay evidence directory, each annotated with severity overviews and guardrail evaluations.

**Gotchas:**
- Ensure overlay directories exist or let the runner create them before execution.
- The runner imports the contextual risk scorer from `fixops-blended-enterprise`; keep that repository directory available on `sys.path`.
