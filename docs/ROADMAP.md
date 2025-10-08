# FixOps Roadmap

## Now (P0)
- Finalize the SSDLC simulation runner to provide deterministic artifacts for every lifecycle stage and unblock downstream analytics.
- Land continuous integration with pytest coverage gating at 75% to protect regression quality.
- Ship FastAPI rate limiting with secure defaults so production deployments throttle abusive clients safely.
- Publish the dashboard deployment guide and align observability defaults with the bundled Grafana dashboard.

## Next (P1)
- Add marketplace automation hooks so partner integrations can subscribe to decision events and share remediation context.
- Deepen infrastructure-as-code posture analysis with additional policy packs and environment-specific control baselines.
- Introduce asynchronous webhooks for decision outcomes to decouple pipeline notifications from the main request path.

## Later (P2)
- Layer in a Redis-backed cache for SSDLC decision reuse and reduced compute on repeated policy evaluations.
- Expand live threat intelligence ingestion (EPSS deltas, exploit chatter) for richer operate-stage recommendations.
- Harden enterprise posture reporting with cross-account analytics and retention tuning for audit artifacts.
