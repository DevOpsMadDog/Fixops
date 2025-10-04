# Migration Notes

No breaking changes were introduced in this iteration. The ingestion API and overlay schema remain backwards compatible; new simulation utilities live under `simulations/` and consume the existing `OverlayConfig` interface.

When upgrading, pull the latest `config/fixops.overlay.yml` only if you want the example evidence directories that the CVE simulation writes to. Custom overlays continue to work without modification.
