# EPSS & KEV Ingestion Runbook

This runbook describes how operators enable, verify, and troubleshoot the EPSS and CISA KEV ingestion pipeline that powers DecisionFactory-aligned scoring inside FixOps.

## 1. Enable the feeds

1. Configure the deployment with the desired feed flags:
   - Set `ENABLED_EPSS=true` and/or `ENABLED_KEV=true` in the application environment.
   - Optionally override `FIXOPS_FEEDS_DIR` to point at a persistent volume if `/app/data/feeds` is not durable in your Kubernetes runtime.
2. Deploy the updated `fixops-config` ConfigMap so the scheduler inside `FeedsService` boots with the flags enabled.
3. Bounce the workload (`kubectl rollout restart deployment/fixops-backend`) to trigger the feed scheduler start-up task.

## 2. Validate ingestion success

- Call `GET /api/v1/feeds/status` or check the dashboard entry in `/api/v1/enhanced/overview` to see the `last_updated_*` timestamps and the number of records pulled from EPSS/KEV.
- Inspect the stored snapshots in `$FIXOPS_FEEDS_DIR/epss.json` and `$FIXOPS_FEEDS_DIR/kev.json` to confirm that the latest payloads have been written.
- Tail the application logs for messages emitted by `FeedsService.scheduler` for additional context when the nightly refresh job runs.

## 3. Monitor runtime utilisation

- The `/metrics` endpoint now exposes `fixops_hot_path_latency_us{endpoint="decision"}` and `fixops_http_requests_total` so you can wire Prometheus alerts around feed availability.
- Decision engine traces include `kev_flag` and `epss_score` once enrichment has been applied, making it straightforward to confirm that evidence objects contain the expected intel.
- When the optional scientific stack (`pgmpy`, `pomegranate`, `mchmm`) is missing, the Processing Layer falls back to deterministic heuristics. The `tests/test_processing_layer_fallbacks.py` regression suite covers this path so operators can rely on consistent behaviour across constrained environments.

## 4. Troubleshooting

| Symptom | Recommended action |
| --- | --- |
| `fixops_http_error_ratio{family="feeds"}` rises above 0 | Review upstream connectivity, then manually invoke `POST /api/v1/feeds/refresh-*` to replay the ingestion. |
| Feed snapshot files stop updating | Check that the Kubernetes volume mounted at `/app/data/feeds` is writable by the application user. |
| Decision responses lack `epss_score`/`kev_flag` | Verify that the stored feed data contains the relevant CVE identifiers and that the requests include `cve_id` fields that match the feed format. |

## 5. Rollback plan

Disable the feed flags (`ENABLED_EPSS` / `ENABLED_KEV`) and redeploy. The scheduler stops automatically and existing snapshots are ignored while the platform reverts to the static heuristics baked into the Processing Layer.
