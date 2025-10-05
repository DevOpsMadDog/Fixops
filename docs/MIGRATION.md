# Migration Notes

No breaking changes were introduced in this iteration. The ingestion API and overlay schema remain backwards compatible; new simulation utilities live under `simulations/` and consume the existing `OverlayConfig` interface.

Overlay files now support an optional `guardrails` block. If the key is absent, defaults are applied automatically (`maturity=scaling`, fail on `high`, warn on `medium`). Existing overlays therefore require no updates unless you want to opt into the maturity-specific thresholds shown in `config/fixops.overlay.yml`.

When upgrading, pull the latest `config/fixops.overlay.yml` only if you want the example evidence directories and guardrail profiles that the CVE simulation writes to. Custom overlays continue to work without modification.
