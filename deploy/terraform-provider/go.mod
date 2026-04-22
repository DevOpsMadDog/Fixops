module github.com/DevOpsMadDog/Fixops/deploy/terraform-provider

go 1.22

// Dependencies land in Sprint 3 via `go mod tidy`.
// The intended imports are:
//   github.com/hashicorp/terraform-plugin-framework
//   github.com/hashicorp/terraform-plugin-go
//   github.com/hashicorp/terraform-plugin-log
//
// Supersedes: terraform_provider_engine (GAP-036 KILL 2026-04-22).
