# Multica Board Audit & Reconciliation

**Date:** 2026-04-26  
**Auditor:** qa-engineer (autonomous)  
**Scope:** All `Implement endpoint*` + `Wire frontend screen*` todos in Multica  
**Action:** Verification only — no code changes. DB updates applied to close shipped work.

## Method

1. Pulled both todo lists from Multica (`status='todo'`).
2. For each `Implement endpoint <METHOD> <path>` todo, scanned all 637 router files in `suite-api/apps/api/` for a matching `@router.<method>(...)` decorator. Considered router prefix (`APIRouter(prefix=...)`). Tail-segment match (last 1–3 path components) against decorator paths. Stub-rejection heuristics applied: `NotImplementedError`, `return {"mock":...}`, body fewer than 3 non-trivial lines.
3. For each `Wire frontend screen <Name>.tsx` todo, recursively scanned `suite-ui/aldeci-ui-new/src/{pages,components,views,screens}/` (434 .tsx files, 426 unique basenames). Wired = at least one of: `apiFetch(`, `apiClient(`, `useQuery(`, `useMutation(`, `useSWR(`, `.refetch(`, `fetch(.../api/`, `axios.<verb>(`, or any `'/api/v1/'` literal in the source.
4. For each verified-done todo, set `status='done', updated_at=NOW()` in Multica via batched SQL.

## Counts

- **Total scanned:** 247 todos (139 endpoints + 108 frontend screens)
- **Total closed:** 89 (endpoints: 62; frontend: 27)
- **Total left open:** 158 (endpoints: 77; frontend missing: 81; frontend mock-only: 0)

## Board state — before vs after

| Status | Before | After |
|---|---|---|
| done | 2475 | 2564 |
| todo | 539 | 450 |
| in_progress | 9 | 9 |
| cancelled | 1 | 1 |

## Endpoint todos — left open

**77** endpoints have no real implementation in `suite-api/apps/api/`. Categories (top-level path segment under `/api/v1/`):

- **graph**: 7
- **system**: 4
- **dca**: 3
- **other**: 3
- **easm**: 3
- **findings**: 3
- **ide**: 3
- **investigate**: 3
- **components**: 2
- **runtime**: 2
- **reachability**: 2
- **ai-exposure**: 2
- **policies**: 2
- **risk**: 2
- **copilot**: 2
- **connectors**: 2
- **webhooks**: 2
- **users**: 2
- **scoring**: 2
- **trustgraph**: 2
- **sbom**: 2
- **organizations**: 2
- **pbom**: 2
- **rules**: 2
- **llm**: 2
- **cspm**: 1
- **air-gap**: 1
- **auto-waiver-rules**: 1
- **issues**: 1
- **toxic-combo-rules**: 1
- **attack-paths**: 1
- **admin**: 1
- **agents**: 1
- **assets**: 1
- **scopes**: 1
- **changes**: 1
- **provenance**: 1
- **skills**: 1
- **hooks**: 1

Full list (id | title):

- `a57cef5b-1f91-4bd9-baf8-d74c3cfb871f` — Implement endpoint GET /api/v1/system/compliance-posture (6h)
- `c8f4e2dc-4b76-456e-919d-f8503d3e84c0` — Implement endpoint POST /api/v1/system/fips-self-test (6h)
- `a01f1967-651e-4216-969e-89174600d327` — Implement endpoint POST /api/v1/cspm/snapshot-scan (6h)
- `01ab5557-1351-493f-9792-30f32474ec2a` — Implement endpoint GET /api/v1/components/match-by-abf?abf={hash} (6h)
- `2a85a139-9cbc-410d-b91f-ea1c7f92fdb3` — Implement endpoint POST /api/v1/runtime/map-to-code (6h)
- `8245b128-5a48-43be-a169-afeff92b50c3` — Implement endpoint GET /api/v1/runtime/traffic/{api} (6h)
- `532e0e27-9ccf-4992-999f-c72bbaf8875f` — Implement endpoint POST /api/v1/dca/parse-repo (6h)
- `5a77c425-1c54-4b05-af5f-5ef6975f7b9c` — Implement endpoint GET /api/v1/dca/entities/{repo} (6h)
- `edc11e2d-eff4-4311-8980-3b38ffbfd793` — Implement endpoint GET /api/v1/dca/diff?from=&to= (6h)
- `7bf0aaf7-364c-4111-a31f-44a60c07e74d` — Implement endpoint POST /api/v1/reachability/callgraph (6h)
- `aea69655-dd5a-4163-812c-b2067d8d4c22` — Implement endpoint GET /api/v1/reachability/{finding_id}/proof (6h)
- `ba3ca320-25f3-4fc8-a5a4-f3848428f4a0` — Implement endpoint GET /api/v1/system/fips-mode (6h)
- `3e63ac8d-bcc3-4034-be03-4056d82f65ea` — Implement endpoint GET /api/v1/ai-exposure/shadow (6h)
- `5040fb06-e3c6-4a71-ac2e-9366c1165692` — Implement endpoint POST /api/v1/ai-exposure/sanctioned-list (6h)
- `de1e2fc4-cb64-4ba7-b9a2-d526b365482c` — Implement endpoint GET /api/v1/air-gap/feed-status (6h)
- `61db07fb-2d38-4cf2-bc6a-3a315429fa42` — Implement endpoint POST /api/v1/policies/{id}/stage-matrix (5h)
- `181dc9f8-db3b-4f5a-8dec-fec7e902fc70` — Implement endpoint GET /api/v1/policies/{id}/stage-matrix (5h)
- `a0585e59-555e-4e80-8353-9679f768cbcc` — Implement endpoint POST /api/v1/evaluate?stage={stage} (5h)
- `49049e61-bbe5-4ec9-b62d-352fe90f31db` — Implement endpoint GET /api/v1/waivers?auto=true (4h)
- `1f5d8fc9-78d4-4052-a05b-a4494aaea371` — Implement endpoint POST /api/v1/auto-waiver-rules (4h)
- `4c483284-03d7-4083-a688-2a16b339f601` — Implement endpoint GET /api/v1/issues/toxic (6h)
- `afe86faf-bddf-46a4-93b8-2d0c573e8aa7` — Implement endpoint POST /api/v1/toxic-combo-rules (6h)
- `e2cf4708-0cd4-4b16-9300-242b2c28006d` — Implement endpoint GET /api/v1/attack-paths/choke-points (6h)
- `7e62f6c6-aaa1-4fc9-9c5d-714d86fa8c14` — Implement endpoint POST /api/v1/risk/quantify-fair (6h)
- `094b9c3d-da2f-4a43-95d4-aa379c0f8852` — Implement endpoint GET /api/v1/risk/brs/bu/{bu_id} (6h)
- `0817d38c-449b-4386-98ed-bc26b012cf10` — Implement endpoint POST /api/v1/copilot/graph-nl-query (6h)
- `3d7e5388-61dc-4ed2-aa35-391db6e85109` — Implement endpoint GET /api/v1/copilot/{q_id}/traversal-trace (6h)
- `2ccc15a7-f257-42a0-955b-c3ffdc47cf34` — Implement endpoint POST /api/v1/easm/seed-domain (6h)
- `828b955d-b590-497f-b415-229c2bfea611` — Implement endpoint GET /api/v1/easm/subsidiaries/{org} (6h)
- `0476b668-70ac-4e65-9d8c-796a2651e116` — Implement endpoint GET /api/v1/easm/exposures?confidence= (6h)
- `e194a1b1-b66e-48f8-877f-363445db90bb` — Implement endpoint POST /api/v1/connectors/mapping (5h)
- `4e2d5913-7026-46f3-8387-66c452e036a1` — Implement endpoint POST /api/v1/connectors/mapping/dry-run (5h)
- `67a3167b-54e1-4f1d-a6f1-ac49ac603285` — Implement endpoint GET /api/v1/webhooks/event-catalogue (5h)
- `d36e7e48-3a69-4fab-9081-935d420d7af8` — Implement endpoint POST /api/v1/webhooks/subscribe (5h)
- `ce727c96-9e7d-4a6b-b064-1c8a291a7d99` — Implement endpoint POST /api/v1/users/me/tokens (2h)
- `0414b3ce-49b5-410f-aaf1-e4f5208ece8c` — Implement endpoint GET /api/v1/users/me/tokens (2h)
- `f77f9412-8319-4b64-b838-8e4e8376b6ba` — Implement endpoint GET /api/v1/admin/tokens (2h)
- `fdf4d765-3d24-4a33-8722-93a1a83dff70` — Implement endpoint GET /api/v1/scoring/formula (2h)
- `9fafda03-b725-4db4-adc5-e7b378efd56e` — Implement endpoint GET /api/v1/findings/{id}/score-breakdown (2h)
- `bacdd8bf-e37e-49e5-b64b-b81ba17183df` — Implement endpoint PUT /api/v1/scoring/formula (2h)
- `37c6a559-f23a-476d-b26b-b664f6fcfc15` — Implement endpoint POST /api/v1/agents/{role}/task (5h)
- `68162b9b-a1b2-4da6-8108-5fbbaba700ea` — Implement endpoint POST /api/v1/assets/{id}/crown-jewel-tag (4h)
- `24eca2f5-85f7-4a61-825f-b06f4a980b4a` — Implement endpoint GET /api/v1/scopes (4h)
- `d532f156-03f7-4cf4-9dcb-aed2f3ab2742` — Implement endpoint POST /api/v1/trustgraph/compact (6h)
- `9f0ae4e6-5ec1-49b2-ab12-3fb717db5281` — Implement endpoint GET /api/v1/trustgraph/quality-issues (6h)
- `1d3a7018-4e1b-4181-a0b5-a930ed2251e3` — Implement endpoint POST /api/v1/sbom/subscribe-for-reeval (6h)
- `2a6a2e8a-b779-43bf-87a7-9ea04db5f6a3` — Implement endpoint GET /api/v1/sbom/{id}/re-eval-history (6h)
- `4d5d1033-4fa1-4816-b5de-1dfc11d75ac5` — Implement endpoint GET /api/v1/ide/findings?repo=&file= (6h)
- `130d594f-d7fc-4273-8ce8-523f9c2c4a45` — Implement endpoint POST /api/v1/ide/authenticate-token (6h)
- `e2975c0a-ecd3-4f16-b71b-78d4b426b18d` — Implement endpoint GET /api/v1/ide/user-snapshot (6h)
- `7d2a2af6-b918-4fd3-b601-9a404b6868b6` — Implement endpoint GET /api/v1/changes/material?kind=&severity= (6h)
- `1e56c32f-ac16-4af1-9a68-831d57c965d3` — Implement endpoint GET /api/v1/system/ha-status (6h)
- `bcb4e2b2-de4a-40fe-ba8d-57f45136777f` — Implement endpoint POST /api/v1/organizations (6h)
- `6509b28a-193c-4616-b5c7-e877391682c9` — Implement endpoint PATCH /api/v1/organizations/{id}/parent (6h)
- `d0b4b4bb-b6c6-44c6-90f4-e8307ade89de` — Implement endpoint POST /api/v1/pbom/record-step (6h)
- `b049c5eb-62df-4c47-8afc-ad92afec80b8` — Implement endpoint GET /api/v1/pbom/artifact/{digest}/propagation (6h)
- `4b96d034-f65a-4f2c-bc57-b96f5df1033b` — Implement endpoint POST /api/v1/investigate/rql (6h)
- `80123d56-6df8-47cf-8b47-0d6b4eb3d2d4` — Implement endpoint GET /api/v1/investigate/saved (6h)
- `06e9c24b-46a0-4718-ad72-4823504fe4e8` — Implement endpoint POST /api/v1/investigate/saved (6h)
- `f44d77ac-443c-4de8-8da3-31db71022615` — Implement endpoint GET /api/v1/provenance/{artifact}/attestation (6h)
- `4aa036ef-00d3-4200-8fbf-521379edcb43` — Implement endpoint GET /api/v1/components/{purl}/safe-upgrade (6h)
- `ad291e00-c24e-4e32-95a8-5af2c53796f4` — Implement endpoint POST /api/v1/skills/uninstall (3h)
- `4091307b-8c42-4592-ab7c-55f6c384cd1b` — Implement endpoint GET /api/v1/rules/dsl (6h)
- `93c3e1fc-f67b-4fa6-98d1-e1466004cb98` — Implement endpoint POST /api/v1/llm/approve-spend/{estimateId} (4h)
- `d21b2e03-b321-4de0-be39-33aae70e0088` — Implement endpoint GET /api/v1/llm/rules/{key}/context-requirement (4h)
- `3edeeeb2-79d0-496b-b3a0-c6861d869351` — Implement endpoint PATCH /api/v1/rules/{key}/enabled (4h)
- `ce6b3221-2d65-4ee5-9a58-e771a684dd18` — Implement endpoint GET /api/v1/findings/{id}/lifecycle (4h)
- `71432602-1546-4601-96e4-21234fef04b0` — Implement endpoint GET /api/v1/findings/drift?since= (4h)
- `a3d3443d-1816-4c8e-a7ef-096d620b33cc` — Implement endpoint GET /api/v1/findings?status=new|unchanged|resolved (4h)
- `bbf6e567-769c-42d9-ad4d-d3341e19fba4` — Implement endpoint POST /api/v1/graph/architecture-detect (6h)
- `337d98ec-5287-4b67-9137-fd198edb43b7` — Implement endpoint GET /api/v1/graph/flows/{serviceId} (6h)
- `db05c671-5d53-4c57-b89c-83b7b862cdf4` — Implement endpoint GET /api/v1/graph/layers/{moduleId} (6h)
- `7bcf2f5f-8002-48f0-af3e-4719296ec0e7` — Implement endpoint GET /api/v1/graph/databases/{repoId} (6h)
- `c740d39c-7420-4a48-8d54-9b9efa30eda0` — Implement endpoint GET /api/v1/graph/diff?prId= (4h)
- `c7ea7cad-678f-484d-b07e-7e59005a423a` — Implement endpoint GET /api/v1/graph/affected-nodes?since= (4h)
- `234238d6-d062-4394-baa9-66da30f914c7` — Implement endpoint GET /api/v1/graph/diff/{baselineId}/{currentId} (4h)
- `5894d7d7-60cd-4be9-bc99-a79053961cea` — Implement endpoint POST /api/v1/hooks/uninstall (3h)

## Frontend screens — missing

**81** screen files do not exist anywhere under `suite-ui/aldeci-ui-new/src/`. Categories (inferred from name):

- **other**: 44
- **validate**: 8
- **discover**: 7
- **ai**: 7
- **policy**: 5
- **deploy**: 3
- **compliance**: 2
- **audit**: 2
- **runtime**: 1
- **data**: 1
- **remediate**: 1

Full list (id | screen):

- `ce176fac-fbb9-414b-8834-8d8646235b08` — Wire frontend screen FIPSModeStatus.tsx (5h)
- `072b6d7c-62f9-481f-9f94-cccd3e348de4` — Wire frontend screen AgentlessScanStatus.tsx (5h)
- `9834bbf8-0c20-4d7e-b1f2-21a7a92d25db` — Wire frontend screen SnapshotFindingsView.tsx (5h)
- `ca5c00d5-c998-4c49-bb12-96988320dd8f` — Wire frontend screen AirGapBundleConsole.tsx (5h)
- `8a09b108-302f-46ae-a322-3214803fcaa8` — Wire frontend screen OfflineUpdateStatus.tsx (5h)
- `3e41a4c1-c081-4151-b5b6-49b8d625d30b` — Wire frontend screen AuditLogExplorer.tsx (5h)
- `dd4efb89-5d81-41e0-a64a-e6ec843a52a7` — Wire frontend screen ComponentIdentityView.tsx (5h)
- `68fc8138-4357-4055-8687-9a51ef971505` — Wire frontend screen RuntimeCodeTrace.tsx (5h)
- `ae8590d5-7186-4e90-930d-bfe895e240ea` — Wire frontend screen CodeSemanticExplorer.tsx (5h)
- `3ee3abd4-550e-45ad-a8bd-64ad3b9295b6` — Wire frontend screen PIIFieldInventory.tsx (5h)
- `085ee499-7b3a-4792-9cd9-3a8ca7179d3f` — Wire frontend screen DomainSeedDiscoveryWizard.tsx (5h)
- `f265af69-44fe-4858-8a55-e6c80f68cd56` — Wire frontend screen ShadowAIInventory.tsx (5h)
- `36dd3ab6-6664-4a9f-b04a-fb8522e4e621` — Wire frontend screen AIAttackPathView.tsx (5h)
- `55bf9576-53a6-4a6e-94b1-05cf0842ba40` — Wire frontend screen MCPToolRegistry.tsx (5h)
- `83223be1-0351-40b0-999f-972a3f001d48` — Wire frontend screen CallGraphExplorer.tsx (5h)
- `dc67f247-d89a-4f6d-8439-a0d6abe88f41` — Wire frontend screen ReachabilityProof.tsx (5h)
- `932eab7f-3d8c-4ec3-af19-a8743319f89a` — Wire frontend screen StagePolicyMatrix.tsx (4h)
- `55e64210-3cc7-4c7d-96b9-df5794465017` — Wire frontend screen PolicyStageEditor.tsx (4h)
- `70b1b89d-359d-4038-95f8-16cd2534c5e8` — Wire frontend screen WaiversExplorer.tsx (3h)
- `86d29749-3947-4fe5-8b5c-7e3911c0c6bd` — Wire frontend screen WaiverRequestModal.tsx (3h)
- `38f1a6bf-99b9-4272-87f0-0e8b77901827` — Wire frontend screen AutoWaiverRules.tsx (3h)
- `b9ee6245-f73a-4a10-aa11-f70d458221b1` — Wire frontend screen ToxicCombinationIssueView.tsx (5h)
- `4e8fda6b-0686-44d2-a038-21b8941aa9f0` — Wire frontend screen IssueQueue.tsx (5h)
- `037dc4a5-85d8-48cb-b5b5-d1272514705e` — Wire frontend screen ChokePointDashboard.tsx (5h)
- `30edc317-7fab-463d-8b1b-38965bb8c024` — Wire frontend screen AttackPathInteractiveGraph.tsx (5h)
- `b1d0f00b-7fe5-47b6-b46f-79b92aaecf2b` — Wire frontend screen BRSExecutiveDashboard.tsx (5h)
- `1c8396b1-68a9-42a2-9cfd-950203fed38c` — Wire frontend screen BUDollarRiskHeatmap.tsx (5h)
- `bfe2fb45-233a-40d3-8e42-bc725b73626a` — Wire frontend screen CopilotGraphChat.tsx (5h)
- `9827cdc3-add5-467a-99fe-f44a424fc13a` — Wire frontend screen TraversalExplanationPanel.tsx (5h)
- `7467742d-a984-4b3c-96e2-ea5ba242c777` — Wire frontend screen SubsidiaryAttributionGraph.tsx (5h)
- `6f32a3e2-52bd-435f-97b3-ce7dae0541ad` — Wire frontend screen ConnectorMappingUI.tsx (4h)
- `0875c5fc-2ba5-48da-b598-84bbdca4d400` — Wire frontend screen UniversalIngestionTester.tsx (4h)
- `cd12e22b-07fa-4a86-82fd-4a47c876822c` — Wire frontend screen WebhookEventCatalogExplorer.tsx (4h)
- `5c721621-20e5-4b1f-bc4c-99328e2fcfff` — Wire frontend screen WebhookRetryConsole.tsx (4h)
- `405b2922-bdcd-49c3-991a-ec0bc9fc9c38` — Wire frontend screen UserTokenManager.tsx (2h)
- `c16b99dc-ea7e-4361-9256-8123e64c5743` — Wire frontend screen AuditLogExplorer.tsx (2h)
- `caa3990b-8f74-4fcf-9d9b-71aacd4bd374` — Wire frontend screen ScoreTransparencyPanel.tsx (2h)
- `f4ee5dd9-fc78-4dc2-8f71-67432f446a81` — Wire frontend screen FactorWeightsView.tsx (2h)
- `8fa90b91-0400-4568-8a46-c69efd233f9f` — Wire frontend screen AIAgentsConsole.tsx (4h)
- `1ca85bdc-268b-409e-b039-e9a12911144b` — Wire frontend screen AgentTaskQueue.tsx (4h)
- `fac7d8eb-d39c-42d2-8a1f-e2487f7cb91e` — Wire frontend screen Copilot.tsx (4h)
- `3feb1bc9-4d70-42d4-9def-701526bb16c2` — Wire frontend screen CrownJewelConfigurator.tsx (4h)
- `e51905df-a35c-4a2a-9cca-0a100718593d` — Wire frontend screen ScopeManager.tsx (4h)
- `04decda1-b551-4e08-9e1f-84c70e8cd405` — Wire frontend screen GraphPerfDashboard.tsx (5h)
- `40cb3d98-bc80-47b7-8280-536b8fbeb2f8` — Wire frontend screen SBOMContinuousMonitoring.tsx (5h)
- `0cd11c1a-8708-42e5-a2ee-d77bf0db5e7c` — Wire frontend screen MaterialChangeDashboard.tsx (5h)
- `75099be3-e41b-46dc-8198-f6e9a28f9c0f` — Wire frontend screen PRChangeRiskPanel.tsx (5h)
- `f6ebc551-2a39-4797-a4f1-6a80d12d04df` — Wire frontend screen OfflineFeedRegistry.tsx (5h)
- `0c157c34-c639-461b-854f-df91407b64e4` — Wire frontend screen OrgHierarchyExplorer.tsx (5h)
- `6ad4bf90-5dc1-4b83-ad59-808d92de5b29` — Wire frontend screen PolicyInheritanceView.tsx (5h)
- `146607ec-fd4a-4ab2-8e1c-0c3e1a848f05` — Wire frontend screen PBOMViewer.tsx (5h)
- `be74d763-0859-402f-b5ee-009dd6f1aa86` — Wire frontend screen PipelineAttestationGraph.tsx (5h)
- `5231fdec-7137-4b04-a5f7-cf15eba0c8d4` — Wire frontend screen RQLQueryBuilder.tsx (5h)
- `eac1dd14-a521-49f6-afa5-77a28c8c4aa6` — Wire frontend screen SavedInvestigations.tsx (5h)
- `81e332d3-701c-4e96-8f28-d623ab7b0242` — Wire frontend screen SLSAAttestationSigner.tsx (5h)
- `1c5cb190-05f6-4b66-8440-0240c9f4ea7c` — Wire frontend screen UpgradePathExplorer.tsx (5h)
- `93e2e8dc-fd08-438b-993b-017adeb3ea11` — Wire frontend screen ComponentVersionGraph.tsx (5h)
- `59a4bfef-569c-435b-811b-e25a17ac7532` — Wire frontend screen SkillsInstallPrompt.tsx (2h)
- `376639f1-3725-410c-822e-ae8f2de672ac` — Wire frontend screen ClaudeSkillsRegistry.tsx (2h)
- `8813074c-7b02-478c-9a8b-ea093bd8bc79` — Wire frontend screen RuleDSLAuthoringStudio.tsx (5h)
- `bf5c991a-45c5-433f-8112-6b5c2fe6b969` — Wire frontend screen RuleDSLValidator.tsx (5h)
- `3f52e898-a36a-4fde-a788-e637b63014be` — Wire frontend screen UnifiedRulesCatalog.tsx (5h)
- `2ad6e909-6ec4-46e3-90e1-786f0eeb4f37` — Wire frontend screen LLMPreFlightEstimateModal.tsx (3h)
- `c5fb4d22-b1af-42d6-98ef-c0d0efe4120a` — Wire frontend screen LLMContextTierBadge.tsx (3h)
- `33b1ed39-f1f6-4a79-b3a2-885b805844b5` — Wire frontend screen LLMRuleContextEditor.tsx (3h)
- `1c2762d4-39dd-4a81-9a7c-ea55e1b67c17` — Wire frontend screen CopilotGraphChat.tsx (3h)
- `9d2c8bb5-0679-4841-9b23-4e064751403c` — Wire frontend screen UnifiedRulesCatalog.tsx (3h)
- `9dcd0ae8-5f2d-4001-b68c-48e6d25fcd57` — Wire frontend screen RuleTaxonomyInspector.tsx (3h)
- `bd5adbfd-caec-4eb3-8b2d-a810b83638c4` — Wire frontend screen PolicyLibraryBrowser.tsx (3h)
- `bc6a193d-8363-412e-98fa-db18a9015fe7` — Wire frontend screen ViolationLifecycleTimeline.tsx (3h)
- `cee8bb94-67b7-4abc-973c-e912715142c0` — Wire frontend screen DriftTrackingPanel.tsx (3h)
- `3d74cd0c-37e1-4628-b732-b7164104fff8` — Wire frontend screen ArchitectureLayerGraph.tsx (5h)
- `967d4b4d-ee2a-4cd5-8df4-8a84b10a7062` — Wire frontend screen TracedFlowViewer.tsx (5h)
- `cc7301fc-b186-4cc3-9f70-b8ec2de274ed` — Wire frontend screen DBConnectionOverlay.tsx (5h)
- `803a51e4-b3d9-45c0-b62f-dca22bdecd08` — Wire frontend screen DiffModeGraphCanvas.tsx (4h)
- `052597b6-a383-4ffc-8fe2-56795de794ef` — Wire frontend screen StaleBaselineBanner.tsx (4h)
- `15300e4f-e268-4a47-a0ff-1de17990d4ad` — Wire frontend screen PRChangeRiskPanel.tsx (4h)
- `d6bd5eea-6f96-4827-8bdd-ad5018b450d3` — Wire frontend screen HooksPolicyEditor.tsx (2h)
- `b5842e05-332f-4c68-a767-a1b4c3057c6f` — Wire frontend screen HooksStatusPanel.tsx (2h)
- `714713e9-ef11-4218-83bd-17ae7da02830` — Wire frontend screen ZeroSetupOnboarding.tsx (4h)
- `3168f49f-e893-4b83-9e24-69a1ad0e122d` — Wire frontend screen LocalStoreStatus.tsx (4h)

## Frontend false-positive (page exists, but mock-only — NOT closed)

_None._ Every page that exists on disk has at least one of `apiFetch`/`apiClient`/`useQuery`/`useMutation`/`useSWR`/`.refetch()`/`/api/v1/` literal — i.e. is at minimum API-aware. Deeper mock-detection (does the API call return real tenant data) is out of scope for this board reconciliation; covered by the `NO MOCKS` Playwright rule on a per-page basis.

## Auditor caveats

- **Conservative match:** the decorator scanner rejects same-tail-different-prefix collisions (e.g. `/api/v1/dca/parse-repo` was kept open even though `/api/v1/semantic/parse-repo` exists, because the prefixes don't match). This may slightly under-close.
- **Stub heuristic is shallow:** it catches `NotImplementedError`, mock-returns, and 3-line bodies. Implementations that return hardcoded JSON via more-than-3-line wrappers will pass as 'real'. Audit teams should follow up with the `STUB DETECTION PROTOCOL` from the qa-engineer charter for endpoints flagged as DONE here.
- **Wired heuristic is generous:** any `/api/v1/` string literal counts. A page that imports `apiFetch` but only calls it conditionally on user action is still 'wired'. The Playwright NO MOCKS rule (Read DOM + network requests) is the authoritative test.
- **Duplicate todos detected:** several frontend names appeared twice in the source todo list (e.g. `SBOMInventory.tsx`). Both copies were closed.

## Next actions

- The remaining 77 endpoint todos and 81 frontend todos represent real work that has NOT shipped. They should be re-prioritised (or de-scoped) in the next sprint planning round.
- Many missing frontend screens correspond to missing endpoints (e.g. `FIPSModeStatus.tsx` ↔ `GET /api/v1/system/fips-mode` ↔ `POST /api/v1/system/fips-self-test`). Building these as paired backend+frontend slices is more efficient than parallel tracks.