/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__supply_chain_security__PolicyAction } from './core__supply_chain_security__PolicyAction';
import type { ProvenanceLevel } from './ProvenanceLevel';
/**
 * Configurable supply chain security policy.
 */
export type SupplyChainPolicy = {
    id?: string;
    /**
     * Human-readable policy name
     */
    name: string;
    description?: string;
    enabled?: boolean;
    action?: core__supply_chain_security__PolicyAction;
    org_id?: string;
    /**
     * SPDX IDs of licenses to block
     */
    blocked_licenses?: Array<string>;
    /**
     * Block deployments without SBOM
     */
    require_sbom?: boolean;
    /**
     * Block if transitive dependency depth exceeds this
     */
    max_transitive_depth?: (number | null);
    /**
     * Minimum SLSA level required
     */
    required_provenance_level?: ProvenanceLevel;
    /**
     * Block if component has more critical CVEs
     */
    max_critical_cves?: number;
    /**
     * Block if score exceeds this
     */
    max_overall_risk_score?: number;
    created_at?: string;
    updated_at?: string;
};

