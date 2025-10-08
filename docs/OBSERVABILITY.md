# Observability Enablement

The FixOps Blended Enterprise deployment ships with Prometheus-friendly metrics and a ready-made Grafana dashboard. Use this guide to instrument the stack in staging and production.

## Import the Grafana Dashboard
1. Open your Grafana instance and navigate to **Dashboards → Import**.
2. Upload `docs/decisionfactory_alignment/fixops-observability-dashboard.json` or paste its JSON content.
3. Select the Prometheus data source that scrapes the FixOps metrics endpoint.
4. Click **Import** to load the dashboard panels (latency, scheduler health, policy blocks, SSDLC stage throughput).

## Prometheus Scrape Configuration
Add the FixOps API service to your Prometheus targets:
```yaml
scrape_configs:
  - job_name: fixops-api
    metrics_path: /metrics
    scrape_interval: 15s
    static_configs:
      - targets:
          - fixops-api.internal:8000
```

## Key PromQL Queries
| Insight | Query |
| --- | --- |
| P95 request latency | `histogram_quantile(0.95, sum(rate(fixops_request_latency_seconds_bucket[5m])) by (le))` |
| Error ratio | `sum(rate(fixops_request_failures_total[5m])) / sum(rate(fixops_request_total[5m]))` |
| Policy block ratio | `sum(rate(fixops_policy_block_total[5m])) / sum(rate(fixops_policy_evaluations_total[5m]))` |
| Rate limit activations | `sum(rate(fixops_rate_limit_trigger_total[5m]))` |
| Scheduler heartbeat delay | `max(fixops_scheduler_last_run_timestamp) by (job)` |

## Alerting Suggestions
- Trigger alerts if `fixops_scheduler_last_run_timestamp` is stale for more than 2 intervals.
- Page the on-call if policy block ratio exceeds 0.4 for 15 minutes.
- Create dashboards for SSDLC simulation output freshness by watching artifact timestamps.

## Next Steps
- Extend dashboards with logs from Loki or Elastic to correlate policy decisions with pipeline events.
- Add SLO annotations to highlight deploy freezes triggered by the decision engine.
