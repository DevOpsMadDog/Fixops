// Package main is the entry point for terraform-provider-fixops.
//
// Supersedes: terraform_provider_engine PRD (GAP-036 KILL 2026-04-22).
// Reference doc: deploy/terraform-provider/README.md
//
// This file is a skeleton — the provider schema and resources land in Sprint 3.
// The current contents are enough to satisfy `go build` and be the entrypoint
// Terraform invokes via its plug-in protocol.

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// providerAddress is the canonical registry address. Update when the Fixops
// registry namespace is finalised.
const providerAddress = "registry.terraform.io/devopsmaddog/fixops"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: providerAddress,
		Debug:   debug,
	}

	// newProvider() is defined in internal/provider/provider.go in Sprint 3.
	// For now, we compile against a no-op placeholder that Sprint 3 will replace.
	err := providerserver.Serve(context.Background(), newProviderPlaceholder, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// newProviderPlaceholder is swapped out in Sprint 3 when the real schema lands.
func newProviderPlaceholder() providerserver.Provider {
	// Intentionally nil — providerserver.Serve will fail fast if invoked before
	// Sprint 3 wires the real provider. This is by design to avoid shipping a
	// silent-no-op provider to the registry.
	return nil
}
