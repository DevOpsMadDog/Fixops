# WIP to Main Codebase Migration Plan

## Objective
Migrate valuable features from WIP folder to main codebase while preserving ALL current functionality.

## Guiding Principles
1. **Zero Breaking Changes** - All existing tests must continue to pass
2. **Incremental Migration** - One feature at a time with validation
3. **Backward Compatibility** - New features are additive, not replacements
4. **Test Coverage** - Add tests for new features before integration
5. **Documentation** - Update docs for each new feature

---

## Phase 1: Frontend Migration (HIGH VALUE, LOW RISK)
**Status:** READY TO START
**Risk Level:** LOW (frontend is currently empty)
**Value:** HIGH (production-ready UI)

### Steps:
1. Copy WIP frontend structure to main codebase
2. Update API endpoints to match current backend
3. Add frontend to docker-compose
4. Test all dashboards independently
5. Verify no backend changes required

### Files to Migrate:
- `WIP/code/enterprise_legacy/frontend/` → `frontend/`
- Keep: package.json, vite.config.js, tailwind.config.js
- Pages: CommandCenter.jsx, EnhancedDashboard.jsx, CISODashboard.jsx
- Components: Layout.jsx, SecurityLayout.jsx, ModeToggle.jsx, Tooltip.jsx
- Utils: api.js

### Validation:
- [ ] Frontend builds successfully
- [ ] All pages render without errors
- [ ] API calls connect to current backend
- [ ] No backend functionality affected

---

## Phase 2: Correlation Engine (HIGH VALUE, MEDIUM RISK)
**Status:** PENDING PHASE 1
**Risk Level:** MEDIUM (new module, needs integration)
**Value:** HIGH (35% noise reduction)

### Steps:
1. Create new module: `fixops-enterprise/src/services/correlation_engine.py`
2. Add as OPTIONAL feature (disabled by default)
3. Add configuration flag: `ENABLE_CORRELATION_ENGINE=false`
4. Add database models for FindingCorrelation
5. Add API endpoints: `/api/v1/correlation/*`
6. Add tests for correlation strategies
7. Enable via overlay configuration

### Files to Migrate:
- `WIP/code/enterprise_legacy/src/services/correlation_engine.py` → `fixops-enterprise/src/services/correlation_engine.py`
- Add database models to `fixops-enterprise/src/models/security_sqlite.py`

### Integration Points:
- Hook into decision engine (optional)
- Add to system health checks
- Add metrics to monitoring

### Validation:
- [ ] All existing tests pass
- [ ] Correlation engine tests pass
- [ ] Can be disabled without affecting existing functionality
- [ ] Performance benchmarks show acceptable overhead

---

## Phase 3: Enhanced Multi-LLM with MITRE (MEDIUM VALUE, MEDIUM RISK)
**Status:** PENDING PHASE 2
**Risk Level:** MEDIUM (modifies existing service)
**Value:** MEDIUM (enhances existing feature)

### Steps:
1. Backup current enhanced_decision_engine.py
2. Add MITRE ATT&CK mapping functions (non-breaking)
3. Add compliance framework analysis (non-breaking)
4. Add business risk amplification (non-breaking)
5. Make new features opt-in via configuration
6. Add tests for new functions
7. Update API responses to include new fields (backward compatible)

### Files to Enhance:
- `fixops-enterprise/src/services/enhanced_decision_engine.py`
- Add MITRE mapping from WIP version
- Add compliance analysis from WIP version

### Configuration:
- `ENABLE_MITRE_MAPPING=false` (default)
- `ENABLE_COMPLIANCE_ANALYSIS=false` (default)
- `ENABLE_RISK_AMPLIFICATION=false` (default)

### Validation:
- [ ] All existing tests pass
- [ ] New features can be disabled
- [ ] API responses are backward compatible
- [ ] Performance is acceptable

---

## Phase 4: CTINexus Entity Extraction (MEDIUM VALUE, LOW RISK)
**Status:** PENDING PHASE 3
**Risk Level:** LOW (enhancement to existing graph service)
**Value:** MEDIUM (automated entity recognition)

### Steps:
1. Add CTINexusEntityExtractor class to knowledge graph
2. Make it optional (fallback to existing extraction)
3. Add configuration: `ENABLE_CTINEXUS_EXTRACTION=false`
4. Add tests for entity extraction
5. Update graph API to expose new entities

### Files to Enhance:
- `services/graph/` - add CTINexus extraction
- Copy logic from `WIP/code/enterprise_legacy/src/services/knowledge_graph.py`

### Validation:
- [ ] All existing tests pass
- [ ] Existing graph functionality unchanged
- [ ] New extraction can be disabled
- [ ] LLM API key is optional

---

## Phase 5: Infrastructure & Tooling (LOW RISK, HIGH UTILITY)
**Status:** PENDING PHASE 4
**Risk Level:** VERY LOW (no code changes)
**Value:** HIGH (developer experience)

### Steps:
1. Copy Postman collections to `postman/`
2. Copy Kubernetes manifests to `kubernetes/`
3. Copy Terraform modules to `terraform/`
4. Add performance benchmarks to `benchmarks/`
5. Update documentation

### Files to Copy:
- `WIP/code/enterprise_legacy/postman/` → `postman/`
- `WIP/code/enterprise_legacy/kubernetes/` → `kubernetes/`
- `WIP/code/enterprise_legacy/terraform/` → `terraform/`
- `WIP/code/perf_experiments/` → `benchmarks/`

### Validation:
- [ ] Postman collections work with current API
- [ ] Kubernetes manifests are valid
- [ ] Terraform modules are valid
- [ ] Benchmarks can be run

---

## Testing Strategy

### Before Each Phase:
1. Run full test suite: `pytest tests/`
2. Run backend tests: `python backend_test.py`
3. Run component tests: `python real_components_test.py`
4. Document baseline metrics

### After Each Phase:
1. Run full test suite again
2. Verify all tests pass
3. Run new feature tests
4. Compare performance metrics
5. Manual smoke testing

### Rollback Plan:
- Each phase is in a separate git commit
- Can revert individual commits if issues arise
- Feature flags allow disabling new features

---

## Success Criteria

### Phase 1 (Frontend):
- ✅ Frontend builds and runs
- ✅ All dashboards accessible
- ✅ API integration works
- ✅ No backend changes required

### Phase 2 (Correlation):
- ✅ Correlation engine reduces noise
- ✅ Can be disabled without issues
- ✅ Performance overhead < 10%
- ✅ All existing tests pass

### Phase 3 (Enhanced Multi-LLM):
- ✅ MITRE mapping works correctly
- ✅ Compliance analysis accurate
- ✅ Backward compatible API
- ✅ All existing tests pass

### Phase 4 (CTINexus):
- ✅ Entity extraction works
- ✅ Fallback to existing method
- ✅ Graph functionality unchanged
- ✅ All existing tests pass

### Phase 5 (Infrastructure):
- ✅ Postman collections work
- ✅ K8s manifests valid
- ✅ Terraform modules valid
- ✅ Benchmarks runnable

---

## Timeline Estimate
- Phase 1: 2-3 hours (frontend setup)
- Phase 2: 3-4 hours (correlation engine)
- Phase 3: 2-3 hours (enhanced multi-LLM)
- Phase 4: 2-3 hours (CTINexus)
- Phase 5: 1-2 hours (infrastructure)

**Total: 10-15 hours of careful, incremental work**

---

## Risk Mitigation
1. **Git branches** - Each phase in separate branch
2. **Feature flags** - All new features can be disabled
3. **Comprehensive testing** - Test before and after each phase
4. **Documentation** - Update docs as we go
5. **Rollback ready** - Can revert any phase independently

---

## Current Status: PHASE 1 READY TO START
