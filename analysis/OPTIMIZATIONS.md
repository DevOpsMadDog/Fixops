# Performance, Reliability, and Security Optimisations

## Performance
- Cached overlay configuration reads to avoid repeated disk access when the ingestion API reloads settings during tests and CLI runs. 【F:core/configuration.py†L1-L28】
- Added LRU caches for lower-cased component tokens and compiled regex patterns inside the pipeline orchestrator to eliminate redundant computations across batched artefacts. 【F:apps/api/pipeline.py†L20-L212】

## Reliability
- Configured the exploit feed refresher to use HTTP retries with exponential backoff for KEV/EPSS downloads, reducing transient network failures. 【F:core/exploit_signals.py†L23-L71】
- Ensured evidence bundles and manifests write atomically to disk to prevent partial files during unexpected interruptions. 【F:core/evidence.py†L18-L120】

## Security
- Atomic evidence writes reuse allowlisted directories and avoid exposing partially written bundle contents, complementing existing encryption support. 【F:core/evidence.py†L18-L120】
