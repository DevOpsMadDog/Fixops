# FixOps Enterprise Demo Readiness Review

_Date:_ 2024-09-05  
_Author:_ Internal QA (ChatGPT)

## Summary

The FixOps repository already contains a rich set of demo artefacts (under `demo/fixtures`) and enterprise-focused services (`fixops-blended-enterprise/src/services`). However, investor-ready execution requires stronger guardrails around environment setup, reproducibility, and removal of placeholder logic. This review highlights the most impactful fixes prior to merging an "Enterprise Demo" pull request.

## Critical findings

1. **Environment setup lacks automation**  
   - There is no Makefile or bootstrap helper. New contributors manually install dependencies scattered across `requirements.txt`, `backend/requirements.txt`, and `fixops-blended-enterprise/requirements.txt`.  
   - _Recommendation:_ Provide a `Makefile` and `scripts/bootstrap.sh` that installs runtime + dev dependencies and configures pre-commit.

2. **Missing contribution guardrails**  
   - No repository-level PR checklist or contributor guide.  
   - _Recommendation:_ Add `CONTRIBUTING.md` and a reusable checklist reminding authors to run lint, type, test, and demo commands, plus secret scanning.

3. **Secrets appear inline in docs and scripts**  
   - Example: `fixops/configuration.py` references `FIXOPS_EVIDENCE_KEY`, while docs such as `docs/PLATFORM_RUNBOOK.md` include production-looking tokens.  
   - _Recommendation:_ Ship a `.env.example` and rely on `dotenv`/environment variables everywhere; add automated secret detection through pre-commit.

4. **Duplicate dependency pins and untracked dev tooling**  
   - `requirements.txt` and `backend/requirements.txt` overlap (both pin FastAPI). There is no pinned location for dev tools like Ruff/Black/Mypy.  
   - _Recommendation:_ Introduce `requirements.dev.txt` and ensure bootstrap installs all requirements deterministically.

5. **Enterprise overlays exist but lack documented entry points**  
   - `fixops/demo_runner.py` supports `mode="enterprise"`, yet no CLI or documentation exposes how to run the enterprise path.  
   - _Recommendation:_ Ensure `fixops.cli` (or a Makefile target) exposes `demo-enterprise` for investor demos.

## Additional observations

- `fixops-blended-enterprise/src/services/correlation_engine.py` depends on optional LLM credentials. Provide a clear failure mode when `get_primary_llm_api_key()` returns `None`.  
- Some tests (e.g., `tests/test_golden_regression.py`) still contain placeholder asserts and need deterministic fixtures.  
- Terraform/Docker stubs exist but are not wired into documentation; consider surfacing them in a separate infra README once stabilised.

## Acceptance criteria for the upcoming PR

- [ ] Automated environment setup (`make bootstrap` and/or `./scripts/bootstrap.sh`).
- [ ] Pre-commit with lint/format/type/secrets hooks configured and documented.
- [ ] Demo + enterprise execution paths documented and runnable via a single command.
- [ ] Contributor and PR guidelines committed to the repo.
- [ ] Sample `.env` file published with safe placeholder values.

Addressing these will materially increase reviewer confidence and reduce onboarding friction for enterprise-mode demos.
