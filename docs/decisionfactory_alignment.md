# DecisionFactory.ai Alignment Status

This document tracks the implementation status of the DecisionFactory.ai requirements across the FixOps codebase. To reduce cognitive load, the alignment work is now split into three parts that can be reviewed independently:

- **Part 1 – Implemented capabilities:** Everything DecisionFactory.ai already gets out-of-the-box.
- **Part 2 – Partially implemented capabilities:** Workstreams that are in motion but still have visible gaps.
- **Part 3 – Missing capabilities:** Features that have not yet been started.

---

## Part 1 – Implemented capabilities ✅

See [`Part 1 – Implemented capabilities`](decisionfactory_alignment/part-1-implemented.md) for the full breakdown of production-ready features.

---

## Part 2 – Partially implemented capabilities ⚠️

See [`Part 2 – Partially implemented capabilities`](decisionfactory_alignment/part-2-partial.md) for the detailed list of in-flight workstreams and the remaining gaps to close.

---

## Part 3 – Missing capabilities ❌

See [`Part 3 – Missing capabilities`](decisionfactory_alignment/part-3-missing.md) for the six DecisionFactory.ai requirements that still need to be built from scratch.

---

### Summary
RSA signing is fully aligned today. The remaining work concentrates on production OPA/Rego enforcement, net-new explainability and RL automation, VEX ingestion, richer evidence exports, and operational surface area (policy gating, EPSS/KEV-aware scoring hardening, key management backends, observability, CLI/Kubernetes configurability, and CI/CD test coverage).
