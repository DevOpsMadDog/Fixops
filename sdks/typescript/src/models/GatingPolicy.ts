/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__Severity } from './apps__api__pr_gate_router__Severity';
/**
 * Policy that determines pass/fail for PR and CI/CD gates.
 */
export type GatingPolicy = {
    /**
     * Fail the gate if any finding at this severity or above exists
     */
    fail_on?: apps__api__pr_gate_router__Severity;
    /**
     * Warn (but don't fail) for findings at this severity
     */
    warn_on?: apps__api__pr_gate_router__Severity;
    /**
     * Maximum allowed critical findings
     */
    max_critical?: number;
    /**
     * Maximum allowed high findings
     */
    max_high?: number;
    /**
     * Maximum allowed medium findings (None = unlimited)
     */
    max_medium?: (number | null);
    /**
     * Always block if secrets detected
     */
    block_secrets?: boolean;
    /**
     * Block on unreachable findings too (default: skip them)
     */
    block_unreachable?: boolean;
    /**
     * Require SBOM in gate evaluation
     */
    require_sbom?: boolean;
    /**
     * Finding categories to evaluate
     */
    categories?: Array<string>;
};

