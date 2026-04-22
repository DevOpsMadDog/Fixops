# `terraform-provider-fixops`

**Status:** Go sub-project skeleton (GAP-036 KILL replacement, 2026-04-22). Supersedes the former `terraform_provider_engine` PRD — this is a Terraform provider binary destined for [registry.terraform.io](https://registry.terraform.io), not a Python engine inside `suite-core/core/`.

## Why this is not a Python engine

Terraform providers are Go plug-ins that implement the Terraform Plugin Framework (SDK v2). The plug-in is launched as a subprocess by `terraform` and communicates over gRPC. A Python FastAPI engine cannot fulfil this contract — only a Go binary published to the Terraform Registry can.

## Layout

```
deploy/terraform-provider/
├── README.md            # this file
├── main.go              # provider entrypoint skeleton
├── go.mod               # Go module definition
├── internal/
│   └── provider/
│       └── provider.go  # (Sprint 3) provider schema + resources
└── examples/
    └── main.tf          # (Sprint 3) consumer example
```

Only `README.md`, `main.go`, and `go.mod` are created today. `internal/provider/*.go`, resource schemas, acceptance tests, and examples land in Sprint 3.

## Planned resources (`fixops_*`)

| Resource | API-surface it wraps | Fixops engine |
|---|---|---|
| `fixops_policy` | `POST /api/v1/policies`, `PATCH /api/v1/policies/{id}` | `policy_engine`, `policy_enforcement_engine` |
| `fixops_dashboard` | `POST /api/v1/metrics-dashboard/dashboards` | `security_metrics_dashboard_engine` |
| `fixops_integration_jira` | `POST /api/v1/connectors/jira` | `connectors_router` |
| `fixops_integration_slack` | `POST /api/v1/connectors/slack` | `connectors_router` |
| `fixops_framework_mapping` | `POST /api/v1/compliance-mapping` | `compliance_mapping_engine` |
| `fixops_waiver_rule` | `POST /api/v1/waivers/auto-rules` | `security_exception_workflow_engine`, `vuln_exception_engine` |
| `fixops_scheduled_report` | `POST /api/v1/scheduled-reports/jobs` | `scheduled_reports_engine` |
| `fixops_rbac_role_binding` | `POST /api/v1/rbac/role-bindings` | `rbac_router` |
| `fixops_webhook_subscription` | `POST /api/v1/webhooks/subscribe` | `webhook_router`, `webhook_events_router` |

## Auth

Provider reads `FIXOPS_API_KEY` and `FIXOPS_ENDPOINT` from env, or from provider block:

```hcl
provider "fixops" {
  endpoint = "https://fixops.example.com"
  api_key  = var.fixops_api_key
}
```

Uses the same API-key header as the Fixops Python SDK (see `sdk/aldeci_sdk.py`).

## Publishing workflow

1. **Tag**: `git tag v0.1.0 && git push --tags`
2. **Sign**: `gpg --detach-sign --armor terraform-provider-fixops_0.1.0_linux_amd64.zip`
3. **Release**: `goreleaser release --clean` (config in Sprint 3) builds cross-platform binaries (darwin/linux/windows × amd64/arm64) + SHA256SUMS + GPG signature.
4. **Register**: Log in to [registry.terraform.io](https://registry.terraform.io) with `DevOpsMadDog` GitHub. Add the `terraform-provider-fixops` repo (sub-directory layout is supported via `.goreleaser.yml` `dist` override).
5. **Verify**: After the webhook fires, registry publishes `hashicorp/fixops` provider (or `devopsmaddog/fixops` depending on final namespace decision).

## Build (after Sprint 3 implementation)

```bash
cd deploy/terraform-provider
go mod tidy
go build -o terraform-provider-fixops
# or, full cross-platform:
goreleaser build --snapshot --clean
```

## Current state

`main.go` is a compilable skeleton registering an empty provider schema. `go build` succeeds; no resources wired yet. Sprint 3 backlog:

- [ ] Implement `internal/provider/provider.go` — schema, configure() with API-key auth
- [ ] Implement `fixops_policy` resource (CRUD + import)
- [ ] Implement `fixops_dashboard` resource
- [ ] Implement remaining resources in priority order (see table above)
- [ ] Acceptance tests (`TF_ACC=1 go test ./...` against a running Fixops)
- [ ] `.goreleaser.yml` + signing key + registry metadata
- [ ] User-facing docs in `docs/terraform-provider/`

## References

- Terraform Plugin Framework: https://developer.hashicorp.com/terraform/plugin/framework
- Publishing a provider: https://developer.hashicorp.com/terraform/registry/providers/publishing
- GAP-036 (original gap): `raw/competitive/gap-matrix.md`
- GAP-036 KILL record: `docs/GAP_PRD_RECONCILE_2026-04-22.md`

---

*This sub-project replaces the Python engine/router that was formerly tracked as `terraform_provider_engine` (GAP-036 KILL, 2026-04-22). The capability is a Go binary on the Terraform Registry, not a Python FastAPI engine.*
