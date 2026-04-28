/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GateSeverity } from './GateSeverity';
/**
 * Configurable severity thresholds for gate decisions.
 */
export type PolicyThresholds = {
    /**
     * Severities that cause a gate FAIL
     */
    fail_on?: Array<GateSeverity>;
    /**
     * Severities that produce warnings but don't block
     */
    warn_on?: Array<GateSeverity>;
    /**
     * Max critical findings before FAIL
     */
    max_critical?: number;
    /**
     * Max high findings before FAIL
     */
    max_high?: number;
    /**
     * Max medium findings (None = unlimited)
     */
    max_medium?: (number | null);
    /**
     * Max total findings (None = unlimited)
     */
    max_total?: (number | null);
    /**
     * Require SBOM presence to pass
     */
    require_sbom?: boolean;
    /**
     * Block if license violations found
     */
    block_on_license_violation?: boolean;
};

