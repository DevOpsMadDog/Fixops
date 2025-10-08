# FixOps Roadmap

## P0 (Immediate)
- Harden CORS/JWT configuration and roll out environment-based secrets in all deployments.
- Enable automated KEV/EPSS refresh with retry/backoff and logging.
- Finalise compliance control mapping and surface coverage in pipeline responses.

## P1 (Near-term)
- Expand marketplace integrations in `enterprise/src/services` and align CLI parity.
- Deepen IaC posture analysis (multi-cloud baselines, drift detection, remediation playbooks).
- Add SSDLC simulation automation to CI to ensure fixture freshness.

## P2 (Future)
- Introduce async decision webhooks backed by Redis/Task queues.
- Provide configurable rate limiting and tenant-aware quotas.
- Explore machine learning heuristics for exploit prediction beyond EPSS.
