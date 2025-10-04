# data/

**Purpose:** Sample datasets used by the demo pipelines (design context, KEV feed snapshots, uploads,
marketplace samples).

**Key Files/Dirs**
- `feeds/` — JSON feeds (e.g., CISA KEV snapshot) used for CVE ingestion tests.
- `uploads/` — Placeholder directory for manual uploads during demos.
- `marketplace/` — Sample catalogue entries powering marketplace narratives.

**Data In/Out**
- Read by tests and manual demos; not modified automatically except for overlay-created directories
  under `data/design_context/*` and `data/evidence/*`.

**Gotchas**
- Large JSON files are static snapshots; update them cautiously to avoid bloating the repo.
- Overlay startup may create subdirectories under `data/` — ensure they are gitignored if ephemeral.
