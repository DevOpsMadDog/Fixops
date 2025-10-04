# config/

**Purpose:** Holds overlay configuration files that control runtime behaviour for Demo and Enterprise
modes.

**Key Files**
- `fixops.overlay.yml` — Default overlay containing Demo settings plus Enterprise overrides.

**Usage**
- Edit the overlay to change integration endpoints or toggles.
- Set `FIXOPS_OVERLAY_PATH` to point to alternative overlays per environment.

**Gotchas**
- File is JSON-compatible; keep syntax valid for both JSON and YAML parsers.
- Avoid storing raw secrets. Reference environment variables via `auth.token_env` instead.
