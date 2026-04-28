/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__supply_chain_security__PolicyAction } from './core__supply_chain_security__PolicyAction';
import type { ProvenanceLevel } from './ProvenanceLevel';
/**
 * Request body for creating or updating a supply chain policy.
 */
export type apps__api__supply_chain_router__CreatePolicyRequest = {
    /**
     * Policy name
     */
    name: string;
    /**
     * Policy description
     */
    description?: string;
    enabled?: boolean;
    action?: core__supply_chain_security__PolicyAction;
    org_id?: string;
    /**
     * SPDX license IDs to block. Defaults to GPL-2.0, GPL-3.0, AGPL-3.0, LGPL variants.
     */
    blocked_licenses?: (Array<string> | null);
    require_sbom?: boolean;
    max_transitive_depth?: (number | null);
    required_provenance_level?: ProvenanceLevel;
    max_critical_cves?: number;
    max_overall_risk_score?: number;
};

